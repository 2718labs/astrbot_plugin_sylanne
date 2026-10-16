"""Current shared-DB reads for D01 value evaluation and natural growth.

Only installed readers are accepted here. Input originals are signed by D11
after their producing operation committed; hashes check integrity, not truth.
The current source/access/correction family closure is always reread in W01's
transaction. This module opens no database and never commits or calls RPC.
"""
from __future__ import annotations

from ..runtime_storage_v3 import read_graph_row_v3, read_graph_rows_v3

from dataclasses import dataclass, replace
import json
import sqlite3

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..domains.d01 import GrowthProposal, PersonaDomain
from ..domains.d01.production_operations_v1 import (
    AdoptCurrentGrowthRequestV1, CurrentGrowthInputsV1, CurrentValuesInputsV1,
    EvaluateCurrentValuesRequestV1, compile_adopt_current_growth_v1,
    compile_evaluate_current_values_v1, current_frame_guard_v1, plain_v1,
    stage_result_v1, verify_d01_production_stage_v1, MethodStrategyProjectionV1, MethodStrategyProjectionV2,
)
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOriginalRefV1
from .domain_production_contracts_v1 import ProductionReadPlanV1
from .issuers import D11BudgetJobIssuer


class MissingProductionOriginalV1(ValueError):
    def __init__(self, *missing, continuation=None):
        super().__init__(", ".join(missing))
        self.missing_inputs, self.continuation_ref = tuple(missing), continuation


def table_exists_v1(db, table):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


class CurrentDomainReadV1:
    """Common bounded reader, deliberately containing no write capability."""
    def __new__(cls, frame):
        if cls is CurrentDomainReadV1:
            from ..authority_service.named_joint_binding_body_v1 import named_joint_core_read_for_frame_v1
            actual = named_joint_core_read_for_frame_v1(frame)
            if actual is not None:
                return actual
        return super().__new__(cls)
    def __init__(self, frame):
        from .domain_production_contracts_v1 import CurrentOwnerStopProjectionFrameV1, require_owner_stop_projection_frame_v1
        if type(frame) is CurrentOwnerStopProjectionFrameV1:
            require_owner_stop_projection_frame_v1(frame)
        else:
            current_frame_guard_v1(frame)
        self.frame = frame

    def check(self, db):
        if type(db) is not sqlite3.Connection or not db.in_transaction:
            raise ValueError("production reader requires W01 current business transaction")
        frame, ns = self.frame, self.frame.envelope.authority.namespace
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        if epoch != (frame.snapshot.epochs[0].revision,):
            raise ValueError("production current query epoch changed")
        rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                            ns.as_tuple).fetchone()
        guard = frame.envelope.version_guard
        if rights != (guard.access_epoch, guard.delete_epoch):
            raise ValueError("production source access/deletion barrier changed")
        for original in frame.snapshot.atoms:
            if self.head(db, original.key) != original:
                raise ValueError("production current head changed: " + original.key.type_name)
        grant = self.head(db, owner_grant_key(*ns.as_tuple))
        owner = frame.owner_guard
        if (not grant.valid or grant.revision != owner.grant_revision
                or grant.key.token != owner.grant_ref or canonical_digest(grant.value) != owner.grant_digest):
            raise ValueError("production Owner grant differs from current frame")
        return frame.snapshot

    def head(self, db, key, *, required=False):
        if type(key) is str:
            key = AtomKey.from_token(key)
        if NamespaceId.from_key(key) != self.frame.envelope.authority.namespace:
            raise ValueError("production original crossed namespace")
        from .current_method_learning_read_v3 import read_bound_method_post_commit_head_v3, read_bound_method_graph_atom_v3
        ns = self.frame.envelope.authority.namespace
        handled, atom = read_bound_method_post_commit_head_v3(db, namespace=ns, key=key)
        if not handled:
            handled, atom = read_bound_method_graph_atom_v3(db, ns, key)
        if not handled:
            from .domain_background_read_v3 import read_bound_background_graph_atom_v3
            handled, atom = read_bound_background_graph_atom_v3(db, ns, key)
        if not handled:
            row = read_graph_row_v3(db, ('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(key.token, *ns.as_tuple), history=False)
            atom = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
        if self.frame.snapshot.get(key) != atom:
            raise ValueError("production dependency is not an exact frame read: " + key.type_name)
        if required and (not atom.valid or atom.revision < 1):
            raise MissingProductionOriginalV1("current_" + key.type_name + ":" + key.name)
        return atom

    def original(self, ref, *, kind=None, digest=None):
        from ..authority_service.artifact_model_original_family_v3 import artifact_model_frame_original_v3
        artifact,value=artifact_model_frame_original_v3(self.frame,ref,kind=kind,digest=digest)
        if artifact:return value
        matches = tuple(original for original in self.frame.observed_originals if original.original_ref == ref)
        if len(matches) != 1:
            raise MissingProductionOriginalV1("authenticated_original:" + ref)
        found = matches[0]
        if ((kind is not None and found.kind != kind)
                or (digest is not None and found.original_digest != digest)):
            raise ValueError("authenticated production original differs")
        return found

    def complete_inventory(self, db, type_name):
        from ..authority_service.artifact_model_graph_v3 import read_bound_artifact_model_frame_inventory_v3
        artifact,values=read_bound_artifact_model_frame_inventory_v3(self.frame,db,type_name)
        if artifact:return values
        frame, ns = self.frame, self.frame.envelope.authority.namespace
        rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? "
            "ORDER BY token LIMIT ?", (*ns.as_tuple, type_name, frame.limits.max_query_rows + 1)).fetchall()
        pages = tuple(page for page in frame.query_coverage if page.type_id == type_name)
        if len(rows) > frame.limits.max_query_rows:
            continuation = next((page.continuation_ref for page in pages if page.continuation_ref),
                "production-query:" + canonical_digest((ns, type_name, frame.snapshot.epochs))[:48])
            raise MissingProductionOriginalV1("complete_current_inventory:" + type_name, continuation=continuation)
        versions = tuple(GraphVersion(AtomKey.from_token(token), rev) for token, rev in rows)
        if len(pages) != 1 or not pages[0].complete or pages[0].row_versions != versions:
            raise MissingProductionOriginalV1("current_query_coverage:" + type_name,
                continuation=pages[0].continuation_ref if len(pages) == 1 else None)
        if pages[0].epoch.revision != frame.snapshot.epochs[0].revision:
            raise ValueError("production scoped negative-query epoch changed")
        return tuple(self.head(db, version.key) for version in versions)

    def source_family(self, db, roots, *, purpose=None, audience=None, allow_corrected=False):
        """Read every parent plus its own access and correction head, bounded."""
        from ..authority_service.artifact_model_graph_v3 import require_artifact_model_frame_source_family_v3
        require_artifact_model_frame_source_family_v3(self.frame,db,roots,purpose=purpose,audience=audience)
        from .artifact_frame_control_reads_v3 import require_artifact_borrowed_frame_source_family_v3
        require_artifact_borrowed_frame_source_family_v3(self.frame,db,roots,purpose=purpose,audience=audience)
        frame, ns = self.frame, self.frame.envelope.authority.namespace
        if type(roots) is not tuple or not roots or len(roots) > frame.limits.max_source_roots:
            raise MissingProductionOriginalV1("bounded_source_roots")
        purpose = purpose or frame.envelope.authority.purpose
        audiences = (audience,) if audience is not None else frame.envelope.authority.audience
        active, done, records = set(), set(), {}

        def visit(ref):
            key = AtomKey.from_token(ref)
            if key != source_key(*ns.as_tuple, key.owner.subject or ""):
                raise ValueError("production source is not a D06 current namespace source")
            if ref in active:
                raise ValueError("production source family is cyclic")
            if ref in done:
                return
            if 3 * (len(active) + len(done) + 1) > frame.limits.max_graph_heads:
                raise MissingProductionOriginalV1("bounded_source_family_closure",
                    continuation="source-family:" + canonical_digest((ns, roots))[:48])
            source = self.head(db, key, required=True)
            access = self.head(db, access_key(*ns.as_tuple, key.owner.subject), required=True)
            correction = self.head(db, source_correction_head_key(ns, key.owner.subject))
            record = SourceRecord.from_dict(source.value)
            validate_access(access.value)
            if (record.source_id != key.owner.subject or access.value["source_id"] != record.source_id
                    or access.value["status"] != "active" or purpose not in record.purposes
                    or purpose not in access.value["purposes"]
                    or not set(audiences) <= set(record.audiences)
                    or not set(audiences) <= set(access.value["audiences"])
                    or (not allow_corrected and (correction.revision != 0 or correction.valid))):
                raise MissingProductionOriginalV1("current_source_family_permission:" + record.source_id)
            active.add(ref)
            for parent in record.parent_source_ids:
                visit(source_key(*ns.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
            records[ref] = record

        for root in roots:
            visit(root)
        return records

    def committed_operation(self, db, operation_id):
        from ..authority_service.artifact_model_graph_v3 import artifact_model_frame_committed_operation_v3
        artifact,row=artifact_model_frame_committed_operation_v3(self.frame,db,operation_id)
        if artifact:return row
        if not table_exists_v1(db, "graph_bundle_operations"):
            raise MissingProductionOriginalV1("committed_producing_operation")
        row = db.execute("SELECT digest,receipt_json,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?", (*self.frame.envelope.authority.namespace.as_tuple, operation_id)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("committed_producing_operation:" + operation_id)
        receipt = json.loads(row[1])
        if (type(row[2]) is not int or row[2] < 1
                or receipt.get("commit_seq") != row[2]
                or receipt.get("status", "committed") not in {"committed", "duplicate"}):
            raise ValueError("production input operation did not commit")
        return row

    def settled_cost_original(self, db, ref, *, activity_id, effect_id, operation_id=None):
        original = self.original(ref, kind="d11.cost_settlement")
        atom = self.head(db, ref, required=True)
        if atom.key.type_name != "runtime.cost_settlement":
            raise ValueError("paid resource original has another registered Graph type")
        from .d11_types import cost_settlement_from_runtime
        value = atom.value
        actual = cost_settlement_from_runtime(db, **{name: value[name] for name in (
            "bot_id", "persona_id", "activity_id", "bundle_operation_id", "effect_id", "settlement_id",
            "lease_id", "cost_operation_id", "budget_operation_id", "budget_phase", "prior_unknown_ref", "execution_revoked")})
        if (plain_v1(actual) != value or actual.activity_id != activity_id or actual.effect_id != effect_id
                or operation_id is not None and actual.cost_operation_id != operation_id):
            raise ValueError("paid resource original does not belong to the actual activity/effect/component operation")
        if actual.status not in {"settled", "overrun"} or actual.unconfirmed:
            raise MissingProductionOriginalV1("independently_known_actual_component_cost")
        return original

    def adopted_interpretation(self, db, ref, *, question_scope):
        """Read the current D07 semantic head and its actual graph adoption."""
        atom = self.head(db, ref, required=True)
        if atom.key.type_name != "d07.current_interpretation.v1":
            raise ValueError("semantic evidence must be an adopted D07 interpretation")
        from ..domains.d07 import D07DomainProvider
        next(spec for spec in D07DomainProvider.type_specs() if spec.name == atom.key.type_name).validator(atom.value)
        history = read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(atom.key.token, atom.revision), history=True)
        if history is None or history[2] != 1 or json.loads(history[1]) != atom.value:
            raise MissingProductionOriginalV1("actual_d07_interpretation_adoption")
        self.committed_operation(db, history[0])
        value = atom.value
        if (value["question_key"] != question_scope or value["stance"] != "support"
                or value["evidence_status"] != "supported" or value["meaningful_unknowns"]
                or value["current"] is not True):
            raise MissingProductionOriginalV1("explicit_current_semantic_scope:" + question_scope)
        records = self.source_family(db, tuple(value["source_refs"]))
        original = self.original(ref, digest=canonical_digest(value))
        return atom, original, records

    def actor_entity(self, db, source_ref, *, expected_entity):
        """Resolve an inbound speaker with D03's exact active account binding."""
        source = self.head(db, source_ref, required=True)
        record = SourceRecord.from_dict(source.value)
        from .ingress_observation import read_committed_ingress_identity
        ingress = read_committed_ingress_identity(db, self.frame.envelope.authority.namespace, record.source_id)
        if ingress is None:
            raise MissingProductionOriginalV1("original_inbound_host_actor_identity")
        identity = json.loads(ingress.identity_json)
        if identity["sender_ref"] != record.speaker_id:
            raise ValueError("inbound source speaker differs from original host identity")
        bindings = self.complete_inventory(db, "d03.account_binding")
        candidates = tuple(atom for atom in bindings if atom.valid
            and atom.value.get("platform_identifier") == identity["sender_ref"]
            and atom.value.get("platform_namespace") == identity["platform_ref"]
            and atom.value.get("entity_id") == expected_entity
            and atom.value.get("valid_from", float("inf")) <= self.frame.now_utc
            and (atom.value.get("valid_until") is None or self.frame.now_utc <= atom.value["valid_until"]))
        if len(candidates) != 1:
            raise MissingProductionOriginalV1("exact_current_d03_inbound_actor_binding")
        anchors = self.complete_inventory(db, "d03.entity_anchor")
        anchors = tuple(atom for atom in anchors if atom.valid and atom.value.get("entity_id") == expected_entity
                        and atom.value.get("status") == "active")
        if len(anchors) != 1:
            raise MissingProductionOriginalV1("exact_current_d03_actor_entity")
        return candidates[0], anchors[0]

    def adopted_outbound_observation(self, db, ref):
        """Actual D11 observation imported under W01's outbound fence.

        Natural outbound originals already keep the full independent receipt;
        their existence is different from a proposed D08 success predicate.
        """
        observation, original, source_ref = read_adopted_outbound_observation_original_v1(
            db, self.frame.envelope.authority.namespace, ref)
        self.original(ref)
        self.source_family(db, (source_ref,))
        return observation, original


def waiting_stage_v1(frame, domain, kind, request, missing):
    return stage_result_v1(frame, domain, kind, request, coverage=(
        "partial" if missing.continuation_ref else "waiting_for_original"),
        missing=missing.missing_inputs, continuation=missing.continuation_ref)


TABLE = "graph_d01_production_inputs_v1"
SIGN_KIND = "d11.d01-production-input.v1"
KINDS = frozenset({"values_candidates", "values_context", "growth_proposal", "growth_trial", "growth_counterevidence"})


def install_d01_production_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install D01 production schema before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d01_production_inputs_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,kind TEXT NOT NULL,"
        "producing_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,"
        "signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,PRIMARY KEY(bot,persona,original_ref))")


@dataclass(frozen=True, slots=True)
class FrozenValuesCandidateSetV1:
    candidates: tuple[tuple[str, tuple[str, ...]], ...]
    candidate_heads: tuple[GraphVersion, ...]
    plan_head: GraphVersion | None = None

    def __post_init__(self):
        if (type(self.candidates) is not tuple or not 1 <= len(self.candidates) <= 128
                or len({item[0] for item in self.candidates}) != len(self.candidates)
                or any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                       or not item[0] or type(item[1]) is not tuple or any(type(tag) is not str or not tag
                       for tag in item[1]) for item in self.candidates)
                or type(self.candidate_heads) is not tuple or len(self.candidate_heads) != len(self.candidates)
                or any(type(head) is not GraphVersion or head.revision < 1 for head in self.candidate_heads)):
            raise ValueError("values need a bounded exact frozen candidate set with real heads")
        if self.plan_head is not None and (type(self.plan_head) is not GraphVersion
                or self.plan_head.revision < 1 or self.plan_head.key.type_name != "d08.personal_plan.v1"):
            raise ValueError("method candidates must retain their actual personal plan head")


@dataclass(frozen=True, slots=True)
class FrozenValuesContextV1:
    context_tags: tuple[str, ...]
    context_heads: tuple[GraphVersion, ...]
    role_binding_complete: bool
    condition_heads: tuple[GraphVersion, ...] = ()
    condition_query_epoch: QueryEpoch | None = None


@dataclass(frozen=True, slots=True)
class GrowthIntentOriginalV1:
    proposal_id: str
    base_head: str
    target_block: str
    replacement_claim: str
    change_kind: str
    evidence_source_refs: tuple[str, ...]
    trigger_original_ref: str
    required_trial_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GrowthTrialOriginalV1:
    growth_proposal_ref: str
    settled_outcome_refs: tuple[str, ...]
    evidence_source_refs: tuple[str, ...]
    completed: bool


@dataclass(frozen=True, slots=True)
class GrowthCounterevidenceOriginalV1:
    growth_proposal_ref: str
    evidence_source_refs: tuple[str, ...]
    counterevidence_source_refs: tuple[str, ...]
    query_scope_ref: str
    query_epoch: int
    coverage_complete: bool
    conflict_found: bool


_ORIGINAL_TYPES = {"values_candidates": FrozenValuesCandidateSetV1, "values_context": FrozenValuesContextV1,
    "growth_proposal": GrowthIntentOriginalV1, "growth_trial": GrowthTrialOriginalV1,
    "growth_counterevidence": GrowthCounterevidenceOriginalV1}


def require_current_method_plan_v1(db, read, plan_head, candidate_refs):
    from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
    from ..domains.d08.execution import _decode_goal
    atom = read.head(db, plan_head.key, required=True)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, atom.value)
    goal_atom = read.head(db, plan.goal_ref, required=True)
    goal = _decode_goal(goal_atom.value)
    if (atom.revision != plan_head.revision or plan.state != "active" or goal.state != "active"
            or plan.goal_revision != goal.revision or plan.actor_ref != "persona:" + read.frame.envelope.authority.namespace.persona_id
            or set(plan.candidate_refs) != set(candidate_refs) or not plan.method_candidates):
        raise MissingProductionOriginalV1("current_exact_method_plan_and_goal")
    read.source_family(db, plan.source_refs)
    return plan, goal_atom


def scoped_method_condition_heads_v1(inventory, goal_ref, goal_revision):
    from ..domains.d07 import decode_method_condition_question_v1
    heads = []
    for atom in inventory:
        scope = decode_method_condition_question_v1(atom.value.get("question_key")) if atom.valid else None
        if scope is not None and (scope["goal_ref"], scope["goal_revision"]) == (goal_ref, goal_revision):
            heads.append(GraphVersion(atom.key, atom.revision))
    return tuple(sorted(heads, key=lambda v: v.key.token))


def validate_frozen_method_conditions_v1(db, read, heads, epoch):
    if (type(heads) is not tuple or len(heads) > 128 or len({v.key for v in heads}) != len(heads)
            or any(type(v) is not GraphVersion or v.key.type_name != "d07.current_interpretation.v1"
                or v.revision < 1 for v in heads)):
        raise ValueError("frozen method conditions require bounded distinct real heads")
    if epoch is None:
        if heads:
            raise ValueError("positive method heads cannot omit their negative scope epoch")
        return
    if (type(epoch) is not QueryEpoch or epoch.namespace != read.frame.envelope.authority.namespace
            or epoch.scope_ref != "namespace" or epoch.revision > read.frame.snapshot.epochs[0].revision):
        raise ValueError("method condition query epoch is outside its actual namespace")
    read.complete_inventory(db, "d07.current_interpretation.v1")
    for version in heads:
        if read.head(db, version.key, required=True).revision != version.revision:
            raise MissingProductionOriginalV1("current_frozen_method_condition")


def current_method_strategy_projection_v1(db, read, *, persona_plan, persona_head, plan_head, candidate_refs,
        condition_heads, condition_query_epoch):
    from ..domains.d01 import method_policy_state_v1, method_preference_edges_v1
    from ..domains.d07 import METHOD_CONDITION_IDS_V1, decode_method_condition_question_v1
    plan, goal_atom = require_current_method_plan_v1(db, read, plan_head, candidate_refs)
    inventory = read.complete_inventory(db, "d07.current_interpretation.v1")
    current_heads = scoped_method_condition_heads_v1(inventory, plan.goal_ref, plan.goal_revision)
    if current_heads != condition_heads:
        raise MissingProductionOriginalV1("current_complete_method_condition_scope")
    validate_frozen_method_conditions_v1(db, read, condition_heads, condition_query_epoch)
    blocks = tuple((block, method_policy_state_v1(block.claim)) for block in persona_plan.blocks
        if block.kind == "strategy" and method_policy_state_v1(block.claim) is not None)
    block, state = blocks[0] if len(blocks) == 1 else (None, None)
    values, originals, complete = {}, [], condition_query_epoch is not None
    for version in current_heads:
        atom = read.head(db, version.key, required=True)
        scope = decode_method_condition_question_v1(atom.value["question_key"])
        proposition = atom.value["proposition"]
        if proposition not in {"true", "false"}:
            complete = False
            continue
        try:
            _, original, _ = read.adopted_interpretation(db, atom.key.token,
                question_scope=atom.value["question_key"])
        except MissingProductionOriginalV1:
            complete = False
            continue
        originals.append(original)
        condition = scope["condition_id"]
        truth = proposition == "true"
        if condition in values and values[condition] != truth:
            complete = False
        values[condition] = truth
    complete = complete and set(values) == set(METHOD_CONDITION_IDS_V1)
    from .d01_method_learning_v1 import read_current_method_trial_projection_v1
    trial = read_current_method_trial_projection_v1(db, read, persona_plan=persona_plan, goal_ref=plan.goal_ref) if state == "ST0" else None
    applicability, edges = method_preference_edges_v1("ST2" if trial else state, plan.method_candidates,
        tuple(sorted(values.items())), complete=complete)
    projection_type = MethodStrategyProjectionV2 if trial else MethodStrategyProjectionV1
    trial_fields = {"trial_ref": trial[0], "trial_digest": trial[1]} if trial else {}
    return projection_type(read.frame.envelope.authority.namespace, persona_head, persona_plan.head_id,
        block.block_id if block else None, canonical_digest(block.claim) if block else None, state,
        plan_head, plan.revision, GraphVersion(goal_atom.key, goal_atom.revision), plan.goal_revision,
        plan.actor_ref, tuple(sorted(candidate_refs)), plan.method_candidates, current_heads, tuple(originals),
        condition_query_epoch, tuple(sorted(values.items())), edges, applicability, **trial_fields)


class InstalledD01ProductionReadersV1:
    def __init__(self, *, issuer: D11BudgetJobIssuer, owner_guard: OwnerAuthorizationGuardV1, role_clock_reader=None):
        if type(issuer) is not D11BudgetJobIssuer or type(owner_guard) is not OwnerAuthorizationGuardV1:
            raise TypeError("D01 requires installed D11 signer and fresh Authority Owner guard")
        self.issuer, self.owner_guard = issuer, owner_guard
        self.role_clock_reader = role_clock_reader

    def freeze_current_general_growth_after_commit_v1(self,db,*,frame,producing_operation_id,request,witness,receipt):
        from .d01_general_growth_v1 import freeze_current_general_growth_after_commit_v1
        return freeze_current_general_growth_after_commit_v1(self,db,frame=frame,producing_operation_id=producing_operation_id,request=request,witness=witness,receipt=receipt)

    def validate_current_general_growth_trial_start_v1(self,db,frame,request):
        from .d01_general_growth_v1 import validate_current_general_growth_trial_start_v1
        return validate_current_general_growth_trial_start_v1(self,db,frame,request)

    def start_current_general_growth_trial_after_commit_v1(self,db,*,frame,producing_operation_id,request,witness,receipt):
        from .d01_general_growth_v1 import start_current_general_growth_trial_after_commit_v1
        return start_current_general_growth_trial_after_commit_v1(self,db,frame=frame,producing_operation_id=producing_operation_id,request=request,witness=witness,receipt=receipt)

    def derive_current_general_growth_trial_from_adopted_progress_v1(self,db,*,frame,producing_operation_id,request,witness,receipt):
        from .d01_general_growth_v1 import derive_current_general_growth_trial_from_adopted_progress_v1
        return derive_current_general_growth_trial_from_adopted_progress_v1(self,db,frame=frame,producing_operation_id=producing_operation_id,request=request,witness=witness,receipt=receipt)

    def read_current_general_growth_v1(self,db,frame,request):
        from .d01_general_growth_v1 import read_current_general_growth_v1
        return read_current_general_growth_v1(self,db,frame,request)

    def _read(self, db, read, ref, kind):
        from .current_conditioned_self_read_v3 import read_bound_conditioned_d01_input_v3
        handled,result=read_bound_conditioned_d01_input_v3(db,read=read,ref=ref,kind=kind,issuer=self.issuer)
        if handled:return result
        if not table_exists_v1(db, TABLE):
            raise MissingProductionOriginalV1("d01_" + kind + "_original:" + ref)
        row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM "
            "graph_d01_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*read.frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("d01_" + kind + "_original:" + ref)
        accepted = {kind}
        if kind == "growth_proposal": accepted.add("growth_proposal_v2")
        if kind == "growth_trial": accepted.add("growth_trial_v2")
        if row[0] not in accepted:
            raise ValueError("D01 original kind differs")
        kind = row[0]
        self.issuer._signer.verify(SIGN_KIND, row[2], row[4])
        value = json.loads(row[2])
        if canonical_serialize(value) != row[2] or canonical_digest(value) != row[3]:
            raise ValueError("D01 signed original bytes changed")
        read.committed_operation(db, row[1])
        original = read.original(ref, kind="d01." + kind, digest=row[3])
        # Verify original signed bytes first. Legacy defaults are an in-memory
        # typed view; the persisted signature, digest and original stay intact.
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        value = plain_v1(decode_typed_production_value_v1(value, _ORIGINAL_TYPES[kind]))
        return value, original

    def record_input(self, db, *, frame, original_ref, producing_operation_id, kind, value):
        """Fixed typed input issuer for W01 after a real producing operation.

        This is not a public command. Growth eligibility is still derived from
        current D06 evidence and completed originals by the adoption reader.
        """
        if kind not in KINDS or type(value) is not _ORIGINAL_TYPES[kind]:
            raise TypeError("D01 input kind requires its exact typed issuer value")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.committed_operation(db, producing_operation_id)
        raw = plain_v1(value)
        roots = tuple(raw.get("evidence_source_refs", ())) + tuple(raw.get("counterevidence_source_refs", ()))
        if roots:
            read.source_family(db, tuple(dict.fromkeys(roots)), purpose="consolidation")
        if kind == "values_candidates":
            if value.plan_head is not None:
                require_current_method_plan_v1(db, read, value.plan_head,
                    tuple(ref for ref, _ in value.candidates))
            for version in value.candidate_heads:
                atom = read.head(db, version.key, required=True)
                if atom.revision != version.revision or not version.key.type_name.startswith(("d07.", "d08.")):
                    raise ValueError("D01 candidates need exact current D07/D08 heads")
        elif kind == "values_context":
            validate_frozen_method_conditions_v1(db, read, value.condition_heads, value.condition_query_epoch)
            if type(value.role_binding_complete) is not bool or not value.context_heads:
                raise ValueError("values context requires actual current scene heads")
            for version in value.context_heads:
                atom = read.head(db, version.key, required=True)
                if atom.revision != version.revision or not version.key.type_name.startswith("d03."):
                    raise ValueError("values context is not a current D03 original")
            if value.role_binding_complete and not any("role_binding" in version.key.type_name for version in value.context_heads):
                raise ValueError("social strategy completion requires actual D03 role resolution")
        elif kind in {"growth_trial", "growth_trial_v2"}:
            if type(value.completed) is not bool or not value.settled_outcome_refs:
                raise ValueError("growth trial cannot self-report completion without outcomes")
            for ref in value.settled_outcome_refs:
                read.original(ref)
        elif kind == "growth_counterevidence":
            pages = tuple(page for page in frame.query_coverage if page.type_id == value.query_scope_ref)
            if (type(value.coverage_complete) is not bool or type(value.conflict_found) is not bool
                    or value.query_scope_ref != "d07.current_interpretation.v1"
                    or len(pages) != 1 or pages[0].epoch.revision != value.query_epoch
                    or pages[0].complete != value.coverage_complete):
                raise ValueError("growth counterevidence must retain actual current query coverage")
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        expected = (kind, producing_operation_id, encoded, digest, self.issuer._signer.sign(SIGN_KIND, encoded))
        row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM "
            "graph_d01_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*frame.envelope.authority.namespace.as_tuple, original_ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("D01 original identity replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d01_production_inputs_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                (*frame.envelope.authority.namespace.as_tuple, original_ref, *expected,
                 canonical_serialize(roots)))
        return ProductionOriginalRefV1("d01." + kind, original_ref, digest, frame.snapshot.versions)

    def read_values(self, db, frame, request):
        owner_task_child = getattr(self, "_owner_task_values_child_v1", None)
        if owner_task_child is not None:
            from .owner_source_note_values_v1 import require_owner_task_values_evaluation_child_v1
            require_owner_task_values_evaluation_child_v1(db, frame=frame, request=request, child_reader=owner_task_child)
        read = CurrentDomainReadV1(frame)
        read.check(db)
        active = PersonaDomain().resolve_active_role(frame.snapshot,
            namespace=frame.envelope.authority.namespace, current_guard=self.owner_guard)
        candidates, candidate_original = self._read(db, read, request.candidate_set_ref, "values_candidates")
        context, context_original = self._read(db, read, request.context_ref, "values_context")
        for raw in (*candidates["candidate_heads"], *context["context_heads"]):
            atom = read.head(db, raw["key"], required=True)
            if atom.revision != raw["revision"]:
                raise ValueError("D01 frozen candidate/context changed")
        method_strategy = None
        if candidates["plan_head"] is not None:
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            plan_head = decode_typed_production_value_v1(candidates["plan_head"], GraphVersion)
            heads = decode_typed_production_value_v1(context["condition_heads"], tuple[GraphVersion, ...])
            epoch = decode_typed_production_value_v1(context["condition_query_epoch"], QueryEpoch | None)
            validate_frozen_method_conditions_v1(db, read, heads, epoch)
            method_strategy = current_method_strategy_projection_v1(db, read, persona_plan=active.plan,
                persona_head=next(v for v in active.read_versions if v.key.type_name == "d01.persona_plan.v1"),
                plan_head=plan_head, candidate_refs=tuple(item[0] for item in candidates["candidates"]),
                condition_heads=heads, condition_query_epoch=epoch)
        from ..domains.d01.identity_v3 import decode_semantic_identity_v3
        semantic_projection=None
        if any(block.kind=="semantic_identity" and decode_semantic_identity_v3(block.claim) is not None for block in active.plan.blocks):
            semantic_projection=self.read_self_model_v3(db,frame,ProjectSelfModelRequestV3())
        return CurrentValuesInputsV1(active.plan, self.owner_guard,
            tuple((item[0], tuple(item[1])) for item in candidates["candidates"]),
            tuple(context["context_tags"]), context["role_binding_complete"], candidate_original, context_original,
            method_strategy,semantic_projection)

    def read_growth(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        raw, original = self._read(db, read, request.growth_proposal_ref, "growth_proposal")
        from ..domains.d01 import method_policy_state_v1
        if method_policy_state_v1(raw["replacement_claim"]) == "ST2":
            raise MissingProductionOriginalV1("qualified_method_outcome_review_use_method_strategy_adoption")
        if raw["trigger_original_ref"] != request.trigger_original_ref:
            raise ValueError("growth trigger differs from its prepared original")
        originals = [original, read.original(request.trigger_original_ref)]
        roots = tuple(raw["evidence_source_refs"])
        records = read.source_family(db, roots, purpose="consolidation")
        sources = tuple(records[ref] for ref in roots)
        families = tuple(source.provenance_root for source in sources)
        if len(set(families)) != len(families):
            raise ValueError("growth evidence repeats a canonical family")
        if set(request.trial_original_refs) != set(raw["required_trial_refs"]):
            raise ValueError("growth request cannot omit or replace required trials")
        trials_complete = True
        for ref in request.trial_original_refs:
            try:
                trial, trial_original = self._read(db, read, ref, "growth_trial")
            except MissingProductionOriginalV1:
                trials_complete = False
                continue
            if trial["growth_proposal_ref"] != request.growth_proposal_ref:
                raise ValueError("growth trial belongs to a different proposal")
            read.source_family(db, tuple(trial["evidence_source_refs"]), purpose="consolidation")
            for outcome_ref in trial["settled_outcome_refs"]:
                originals.append(read.original(outcome_ref))
            trials_complete = trials_complete and trial["completed"] is True
            originals.append(trial_original)
        complete, conflict = False, False
        try:
            counter, counter_original = self._read(db, read, request.counterevidence_query_ref, "growth_counterevidence")
            if counter["growth_proposal_ref"] != request.growth_proposal_ref:
                raise ValueError("growth counterevidence belongs to another proposal")
            if counter["query_scope_ref"] != "d07.current_interpretation.v1":
                raise ValueError("growth counterevidence scope is not its fixed D07 interpretation inventory")
            active_counter_plan=PersonaDomain().resolve_active_role(frame.snapshot,
                namespace=frame.envelope.authority.namespace,current_guard=self.owner_guard)
            counter_target=next((block for block in active_counter_plan.plan.blocks if block.block_id==raw["target_block"]),None)
            if original.kind=="d01.growth_proposal" and counter_target is not None and counter_target.kind!="semantic_identity":
                if tuple(counter["evidence_source_refs"])!=roots:
                    raise ValueError("ordinary growth counter birth support differs from its signed proposal")
                current_complete,conflict,current_originals=self.current_general_growth_counter_scope_v3(db,read,raw)
                complete=counter["coverage_complete"] is True and current_complete
                originals.extend(current_originals)
            else:
                pages = tuple(page for page in frame.query_coverage if page.type_id == counter["query_scope_ref"])
                complete = (counter["coverage_complete"] is True and len(pages) == 1 and pages[0].complete
                            and pages[0].epoch.revision == counter["query_epoch"])
                counter_roots = tuple(counter["evidence_source_refs"]) + tuple(counter["counterevidence_source_refs"])
                if counter_roots:
                    read.source_family(db, tuple(dict.fromkeys(counter_roots)), purpose="consolidation")
                conflict = counter["conflict_found"] is True
            originals.append(counter_original)
        except MissingProductionOriginalV1:
            pass
        proposal = GrowthProposal(raw["proposal_id"], raw["base_head"], raw["target_block"],
            raw["replacement_claim"], families, complete, raw["change_kind"], "external")
        semantic = None
        active = PersonaDomain().resolve_active_role(frame.snapshot,
            namespace=frame.envelope.authority.namespace, current_guard=self.owner_guard)
        target = next((block for block in active.plan.blocks if block.block_id == proposal.target_block), None)
        if target is not None and target.kind == "semantic_identity":
            current_counter = self.current_semantic_counter_scope_v3(db,read,raw) if raw.get("schema")=="d01.growth-intent.v2" else None
            if current_counter is not None:
                complete=current_counter.complete
                conflict=current_counter.qualification=="opposition"
                proposal=replace(proposal,counterevidence_checked=current_counter.complete)
            proposal, semantic, deep_originals = self.qualify_semantic_growth_v3(db, read, request, raw,
                proposal, active, trials_complete=trials_complete, counter_complete=complete, counter_conflict=conflict,counter_scope=current_counter)
            originals.extend(deep_originals)
        return CurrentGrowthInputsV1(proposal, tuple(source.source_id for source in sources), self.owner_guard,
            tuple(originals), trials_complete, complete, conflict, semantic_qualification=semantic)


    def current_general_growth_counter_scope_v3(self, db, read, intent):
        """Current ordinary-block counter facts; the signed counter remains its birth evidence."""
        from ..domains.d07 import D07DomainProvider
        active=PersonaDomain().resolve_active_role(read.frame.snapshot,
            namespace=read.frame.envelope.authority.namespace,current_guard=self.owner_guard)
        target=next((block for block in active.plan.blocks if block.block_id==intent["target_block"]),None)
        if target is None or target.kind=="semantic_identity" or target.plasticity!="growth":
            raise MissingProductionOriginalV1("actual_current_ordinary_growth_block")
        scope="d01.growth:"+intent["target_block"]+":"+intent["change_kind"]
        inventory=read.complete_inventory(db,"d07.current_interpretation.v1")
        pages=tuple(page for page in read.frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
        if len(pages)!=1 or not pages[0].complete:
            raise MissingProductionOriginalV1("complete_current_general_growth_counter_inventory")
        originals=[];qualification="qualified";matched=False
        spec=next(item for item in D07DomainProvider.type_specs() if item.name=="d07.current_interpretation.v1")
        for atom in inventory:
            if not atom.valid or atom.value.get("question_key")!=scope or atom.value.get("current") is not True:
                continue
            matched=True;spec.validator(atom.value)
            history=read_graph_row_v3(db,("event_id","value","valid"),
                where="token=? AND revision=?",parameters=(atom.key.token,atom.revision),history=True)
            if history is None or history[2]!=1 or json.loads(history[1])!=atom.value:
                raise MissingProductionOriginalV1("actual_current_general_growth_counter_adoption")
            read.committed_operation(db,history[0])
            originals.append(read.original(atom.key.token,digest=canonical_digest(atom.value)))
            refs=tuple(atom.value["source_refs"])
            if not refs:
                if qualification!="opposition":qualification="unknown"
                continue
            read.source_family(db,refs,purpose="consolidation")
            for ref in refs:read.head(db,ref,required=True)
            if atom.value["stance"]=="oppose" and atom.value["evidence_status"]=="supported":
                qualification="opposition"
            elif qualification!="opposition" and (atom.value["stance"]!="support"
                    or atom.value["meaningful_unknowns"] or atom.value["evidence_status"]!="supported"):
                qualification="unknown"
        if not matched:qualification="unknown"
        return qualification=="qualified",qualification=="opposition",tuple(originals)

    def freeze_current_values_from_graph_v1(self, db, *, frame, producing_operation_id,
                                          candidate_set_ref, context_ref):
        """Concrete producer from the actual frozen D08 candidate inventory.

        Tags are registered ActionIntent fields. No prose interpretation or
        permission result is manufactured while assembling the values input.
        """
        owner_task_child = getattr(self, "_owner_task_values_child_v1", None)
        if owner_task_child is not None:
            from .owner_source_note_values_v1 import freeze_owner_task_values_from_parent_v1
            return freeze_owner_task_values_from_parent_v1(db, frame=frame,
                producing_operation_id=producing_operation_id, candidate_set_ref=candidate_set_ref,
                context_ref=context_ref, child_reader=owner_task_child, base_readers=self)
        read = CurrentDomainReadV1(frame)
        read.check(db)
        from ..domains.d08.execution import _decode_intent
        from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
        plans = tuple(atom for atom in read.complete_inventory(db, PLAN_TYPE) if atom.valid
            and atom.value["state"] == "active" and atom.value.get("method_candidates"))
        if len(plans) > 1:
            raise MissingProductionOriginalV1("unambiguous_actual_method_plan")
        plan_head = GraphVersion(plans[0].key, plans[0].revision) if plans else None
        if plan_head is not None:
            # Method alternatives exist before an ActionIntent is selected.
            # Their authority is this adopted plan, not previously executed
            # actions or unrelated namespace attention tickets.
            plan = decode_personal_plan_type_v1(PLAN_TYPE, plans[0].value)
            candidate_ids = plan.candidate_refs
            plan, _ = require_current_method_plan_v1(db, read, plan_head, candidate_ids)
            tags = tuple(sorted({"personal_plan", *(node.action_kind for node in plan.nodes)}))
            candidates = [(ref, tags) for ref in candidate_ids]
            heads = tuple(plans[0] for _ in candidate_ids)
        else:
            action_heads = tuple(atom for atom in read.complete_inventory(db, "d08.action_intent.v1") if atom.valid)
            attention_heads = tuple(atom for atom in read.complete_inventory(db, "d07.attention_ticket.v1") if atom.valid)
            heads = action_heads + attention_heads
            if not heads:
                raise MissingProductionOriginalV1("actual_frozen_d08_candidates")
            candidates = []
            for atom in action_heads:
                action = _decode_intent(atom.value)
                read.source_family(db, action.source_refs)
                candidates.append((action.action_id, tuple(dict.fromkeys((action.action_kind, action.purpose, *action.effect_scope)))))
            from ..domains.d07 import AttentionTicket, D07DomainProvider
            for atom in attention_heads:
                next(spec for spec in D07DomainProvider.type_specs() if spec.name == atom.key.type_name).validator(atom.value)
                ticket = AttentionTicket(**{**{name: value for name, value in atom.value.items() if name != "schema"},
                    "source_refs": tuple(atom.value["source_refs"]), "cancel_refs": tuple(atom.value["cancel_refs"])})
                read.source_family(db, ticket.source_refs)
                candidates.append((ticket.ticket_id, ("attention", ticket.category)))
            candidate_ids = tuple(ref for ref, _ in candidates)
        condition_heads, condition_epoch = (), None
        if plan_head is not None:
            plan, _ = require_current_method_plan_v1(db, read, plan_head, candidate_ids)
            inventory = read.complete_inventory(db, "d07.current_interpretation.v1")
            condition_heads = scoped_method_condition_heads_v1(inventory, plan.goal_ref, plan.goal_revision)
            condition_epoch = next(page.epoch for page in frame.query_coverage
                if page.type_id == "d07.current_interpretation.v1")
        frozen = FrozenValuesCandidateSetV1(tuple(candidates),
            tuple(GraphVersion(atom.key, atom.revision) for atom in heads), plan_head)
        candidate_sources = {ref for atom in heads for ref in atom.value.get("source_refs", ())}
        read.complete_inventory(db, "d03.role_binding")
        contexts = tuple(atom for atom in read.complete_inventory(db, "d03.world_event") if atom.valid
            and atom.value.get("source_refs") and set(atom.value["source_refs"]) <= candidate_sources)
        if not contexts:
            raise MissingProductionOriginalV1("actual_d03_candidate_context")
        tags = []
        for atom in contexts:
            roots = tuple(atom.value.get("source_refs", ()))
            if roots:
                read.source_family(db, roots)
            for name in ("kind", "reality", "social_role"):
                value = atom.value.get(name)
                if type(value) is str:
                    tags.append(value)
        context = FrozenValuesContextV1(tuple(sorted(set(tags))),
            tuple(GraphVersion(atom.key, atom.revision) for atom in contexts), False,
            condition_heads, condition_epoch)
        # Only the specific D03 RequiredCheck service may establish a resolved
        # social role. An inventory of bindings alone leaves strategy unknown.
        a = self.record_input(db, frame=frame, original_ref=candidate_set_ref,
            producing_operation_id=producing_operation_id, kind="values_candidates", value=frozen)
        b = self.record_input(db, frame=frame, original_ref=context_ref,
            producing_operation_id=producing_operation_id, kind="values_context", value=context)
        return a, b

    def freeze_current_growth_from_interpretation_v1(self, db, *, frame, producing_operation_id,
        interpretation_ref, trigger_original_ref, growth_proposal_ref, counterevidence_query_ref,
        required_trial_refs=()):
        """Concrete growth producer from D07's actually adopted growth judgment.

        The question scope is d01.growth:<block>:local|core. Claim text comes
        from that original, while evidence families/eligibility are rederived
        from D06. This never turns an internal judgment into external proof.
        """
        read = CurrentDomainReadV1(frame)
        read.check(db)
        active = PersonaDomain().resolve_active_role(frame.snapshot,
            namespace=frame.envelope.authority.namespace, current_guard=self.owner_guard)
        atom = read.head(db, interpretation_ref, required=True)
        scope = atom.value.get("question_key", "")
        if not scope.startswith("d01.growth:") or scope.rsplit(":", 1)[-1] not in {"local", "core"}:
            raise ValueError("growth producer needs an exact adopted D07 growth question")
        target, kind = scope[len("d01.growth:"):].rsplit(":", 1)
        if not any(block.block_id == target and block.plasticity == "growth" for block in active.plan.blocks):
            raise ValueError("growth judgment does not target a current plastic block")
        semantic, semantic_original, records = read.adopted_interpretation(db, interpretation_ref, question_scope=scope)
        roots = tuple(semantic.value["source_refs"])
        evidence = tuple(records[ref] for ref in roots)
        if any(source.source_kind != "observed" or source.assertion_status != "confirmed"
               or source.independence != "independent" or source.parent_source_ids for source in evidence):
            raise MissingProductionOriginalV1("confirmed_independent_observed_growth_evidence")
        read.original(trigger_original_ref)
        proposal_id = "growth:" + canonical_digest((active.head_id, semantic.key.token, semantic.revision))[:48]
        intent = GrowthIntentOriginalV1(proposal_id, active.head_id, target, semantic.value["proposition"], kind,
                                       roots, trigger_original_ref, tuple(required_trial_refs))
        inventory = read.complete_inventory(db, "d07.current_interpretation.v1")
        counters = tuple(atom for atom in inventory if atom.valid and atom.value.get("question_key") == scope
            and atom.value.get("stance") == "oppose" and atom.value.get("evidence_status") == "supported")
        counter_roots = tuple(dict.fromkeys(ref for atom in counters for ref in atom.value["source_refs"]))
        if counter_roots:
            read.source_family(db, counter_roots, purpose="consolidation")
        pages = tuple(page for page in frame.query_coverage if page.type_id == "d07.current_interpretation.v1")
        if len(pages) != 1 or not pages[0].complete:
            raise MissingProductionOriginalV1("complete_current_growth_counterevidence_inventory")
        counter = GrowthCounterevidenceOriginalV1(growth_proposal_ref, roots, counter_roots,
            pages[0].type_id, pages[0].epoch.revision, True, bool(counters))
        a = self.record_input(db, frame=frame, original_ref=growth_proposal_ref,
            producing_operation_id=producing_operation_id, kind="growth_proposal", value=intent)
        b = self.record_input(db, frame=frame, original_ref=counterevidence_query_ref,
            producing_operation_id=producing_operation_id, kind="growth_counterevidence", value=counter)
        return a, b, semantic_original

    def derive_current_growth_trial_from_adopted_progress_v1(self, db, *, frame, producing_operation_id,
            original_ref, growth_proposal_ref, settled_progress_ref, validate_only=False, adopted_at_utc=None):
        """Derive completion from actual adopted progress, never a caller flag."""
        read = CurrentDomainReadV1(frame)
        read.check(db)
        self._read(db, read, growth_proposal_ref, "growth_proposal")
        atom = read.head(db, settled_progress_ref, required=True)
        read.original(settled_progress_ref)
        history = read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(atom.key.token, atom.revision), history=True)
        if history is None or history[2] != 1 or json.loads(history[1]) != atom.value:
            raise ValueError("growth trial progress lost its actual adopted history")
        read.committed_operation(db, history[0])
        if atom.key.type_name == "d10.life_progress.v1":
            from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            progress = decode_typed_production_value_v1(atom.value, LifeProgressHeadV1)
            from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
            require_current_life_progress_v1(db,namespace=frame.envelope.authority.namespace,progress=progress,issuer=self.issuer,read=read)
            adoption = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, history[0])
            if (adoption is None or adoption["domain"] != "d10" or adoption["operation_kind"] != "advance_life"
                    or progress.reality != "real_execution" or progress.actuality != "completed"):
                raise MissingProductionOriginalV1("actual_completed_real_life_trial")
            settlements = tuple(version.key.token for version in adoption["receipt"].write_versions
                if version.key.type_name == "d02.settlement.v1")
            experiences = tuple(version.key.token for version in adoption["receipt"].write_versions
                if version.key.type_name == "memory.source")
            if not settlements or not experiences:
                raise MissingProductionOriginalV1("actual_atomic_life_body_experience_adoption")
            for ref in settlements:
                read.head(db, ref, required=True)
            roots = progress.source_refs
            outcomes = (settled_progress_ref,)
        elif atom.key.type_name == "d08.action_outcome.v1":
            from ..domains.d08.execution import _decode
            outcome = _decode("d08.action_outcome.v1", atom.value)
            if (outcome.result_level != "completed_verified" or outcome.unknown_effects
                    or outcome.effect_id not in outcome.completed_effects or not outcome.observation_refs):
                raise MissingProductionOriginalV1("actual_completed_verified_growth_trial_action")
            actions = tuple(candidate for candidate in read.complete_inventory(db, "d08.action_intent.v1")
                if candidate.valid and candidate.value["action_id"] == outcome.action_id
                and candidate.value["identity"]["effect_id"] == outcome.effect_id
                and candidate.value["identity"]["attempt_id"] == outcome.attempt_id)
            if len(actions) != 1:
                raise MissingProductionOriginalV1("exact_actual_growth_trial_action_identity")
            action = _decode("d08.action_intent.v1", actions[0].value)
            costs = tuple(candidate for candidate in read.complete_inventory(db, "runtime.cost_settlement")
                if candidate.valid and candidate.value["activity_id"] == action.identity.activity_id
                and candidate.value["effect_id"] == outcome.effect_id)
            if not costs:
                raise MissingProductionOriginalV1("actual_known_paid_growth_trial_action_cost")
            for cost in costs:
                read.settled_cost_original(db, cost.key.token, activity_id=action.identity.activity_id, effect_id=outcome.effect_id)
            for ref in outcome.observation_refs:
                observation = read.original(ref)
                if observation.kind not in {"d11.outbound_observation", "d11.role_segment_end", "d11.actual_artifact"}:
                    raise MissingProductionOriginalV1("independent_actual_growth_trial_effect_observation")
            roots, outcomes = action.source_refs, (settled_progress_ref,)
        else:
            raise ValueError("growth trial has another registered progress type")
        read.source_family(db, roots, purpose="consolidation")
        intent, _ = self._read(db, read, growth_proposal_ref, "growth_proposal")
        kind = "growth_trial"
        value = GrowthTrialOriginalV1(growth_proposal_ref, outcomes, tuple(roots), True)
        if intent.get("schema") == "d01.growth-intent.v2":
            start_ref, start, _ = self.current_semantic_trial_start_v3(db, read, growth_proposal_ref, original_ref)
            if adopted_at_utc is not None:
                if not validate_only:raise ValueError("historical adoption time is read-only evidence, never new trial issuance")
                mapping,digest,now_role=self._historical_identity_clock_v3(db,read,start,adopted_at_utc)
            else:
                mapping, digest, now_role = self._identity_clock_v3(db, read)
            from decimal import Decimal
            if (not _actual_trial_plan_matches_v3(start["planned_progress_ref"], atom)
                    or (mapping.mapping_id,mapping.version,digest)!=(start["clock_mapping_ref"],start["clock_mapping_version"],start["clock_original_digest"])
                    or not Decimal(start["started_role_cursor"])<=now_role<Decimal(start["observation_role_deadline"])):
                raise MissingProductionOriginalV1("deep_trial_actual_plan_outcome_or_original_role_deadline")
            value = GrowthTrialOriginalV2(growth_proposal_ref,outcomes,tuple(roots),True,start_ref)
            kind = "growth_trial_v2"
        if validate_only:
            return value
        return self.record_input(db, frame=frame, original_ref=original_ref,
            producing_operation_id=producing_operation_id, kind=kind, value=value)


    def _identity_policy_v3(self, db, read, ref, *, require_growth=False, qualification_at_utc=None):
        from ..domains.d01.identity_v3 import IdentityPlasticityPolicyV3, RuntimeIdentityRef
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        raw, original = self._read(db, read, ref, "identity_plasticity_policy_v3")
        policy = decode_typed_production_value_v1(raw, IdentityPlasticityPolicyV3)
        pins = tuple(pin for pin in read.frame.installed_policy_refs if pin.policy_ref == ref)
        ns=read.frame.envelope.authority.namespace
        at=read.frame.now_utc if qualification_at_utc is None else qualification_at_utc
        if (len(pins)!=1 or pins[0].revision!=policy.revision or pins[0].policy_digest!=original.original_digest
                or policy.runtime_identity!=RuntimeIdentityRef.from_owner_guard(ns,self.owner_guard)
                or not policy.valid_from_utc<=at<policy.valid_until_utc
                or require_growth and policy.mode!="growth"):
            raise MissingProductionOriginalV1("current_registered_deep_identity_plasticity_policy")
        if require_growth:
            observer=tuple(pin for pin in read.frame.installed_policy_refs if pin.policy_ref==policy.observer_policy_ref)
            if len(observer)!=1 or observer[0].policy_digest!=policy.observer_policy_digest:
                raise MissingProductionOriginalV1("actual_installed_deep_identity_observer_policy")
            from ..domains.d01.identity_v3 import IdentityTrialObservationPolicyV3
            observer_raw, observer_original = self._read(db,read,policy.observer_policy_ref,"identity_trial_observation_policy_v3")
            observed = decode_typed_production_value_v1(observer_raw,IdentityTrialObservationPolicyV3)
            if (observed.runtime_identity!=policy.runtime_identity or observed.scope_refs!=policy.scope_refs
                    or observed.exclusion_refs!=policy.exclusion_refs
                    or observer_original.original_digest!=policy.observer_policy_digest
                    or not observed.valid_from_utc<=at<observed.valid_until_utc
                    or policy.valid_from_utc<observed.valid_from_utc or policy.valid_until_utc>observed.valid_until_utc):
                raise MissingProductionOriginalV1("current_deep_trial_observer_scope_and_original_deadline")
        return policy, original

    def validate_identity_policy_registration_v3(self, db, frame, policy):
        from ..domains.d01.identity_v3 import IdentityPlasticityPolicyV3, IdentityTrialObservationPolicyV3, RuntimeIdentityRef
        if type(policy) not in {IdentityPlasticityPolicyV3, IdentityTrialObservationPolicyV3}:
            raise TypeError("Owner must supply the explicit typed deep identity policy")
        read=CurrentDomainReadV1(frame);read.check(db)
        ns=frame.envelope.authority.namespace
        active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=ns,current_guard=self.owner_guard)
        if (policy.namespace!=ns or policy.runtime_identity!=RuntimeIdentityRef.from_owner_guard(ns,self.owner_guard)
                or not policy.valid_from_utc<=frame.now_utc<policy.valid_until_utc
                or type(policy) is IdentityPlasticityPolicyV3 and not set(policy.target_block_ids)<=set(block.block_id for block in active.plan.blocks if block.kind=="semantic_identity")):
            raise ValueError("explicit Owner identity policy differs from current installed persona/targets")
        allowed={"d08.goal.v1","d08.personal_plan.v1","d08.action_intent.v1","d10.life_project.v1"}
        for ref in (*policy.scope_refs,*policy.exclusion_refs):
            key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=ns or key.type_name not in allowed:
                raise ValueError("deep identity policy scopes must be actual persona goal/plan/action/project locators")
            read.head(db,key,required=True)
        if len(canonical_serialize(plain_v1(policy)).encode())>65536:
            raise ValueError("deep identity policy exceeds current payload bound")
        return policy

    def register_identity_policy_after_commit_v3(self, db, *, frame, producing_operation_id, policy):
        self.validate_identity_policy_registration_v3(db,frame,policy)
        return self.record_input(db,frame=frame,original_ref=policy.policy_ref,
            producing_operation_id=producing_operation_id,kind=("identity_plasticity_policy_v3" if type(policy) is IdentityPlasticityPolicyV3 else "identity_trial_observation_policy_v3"),value=policy)

    def _identity_clock_v3(self, db, read):
        from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1, TABLE as CLOCK_TABLE
        from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        if type(self.role_clock_reader) is not InstalledD04SemanticMappingReaderV3:
            raise MissingProductionOriginalV1("actual_installed_deep_identity_role_clock_reader")
        mapping=read_current_role_clock_installation_v1(self.role_clock_reader,db,read.frame.envelope.authority.namespace)
        row=db.execute("SELECT original_digest FROM "+CLOCK_TABLE+" WHERE bot=? AND persona=? AND revision=?",
            (*read.frame.envelope.authority.namespace.as_tuple,mapping.version)).fetchone()
        if row is None:raise MissingProductionOriginalV1("signed_deep_identity_role_clock_original")
        from datetime import datetime, timezone
        wall=datetime.fromtimestamp(read.frame.now_utc,timezone.utc).isoformat().replace("+00:00","Z")
        return mapping, row[0], mapping.character_at(wall)

    def _historical_identity_clock_v3(self, db, read, start, adopted_at_utc):
        from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_SIGN_KIND
        from .clock import CharacterClockMapping
        from decimal import Decimal
        from datetime import datetime, timezone
        row=db.execute("SELECT original_json,original_digest,signature FROM "+CLOCK_TABLE+
            " WHERE bot=? AND persona=? AND revision=?",(*read.frame.envelope.authority.namespace.as_tuple,start["clock_mapping_version"])).fetchone()
        if row is None:raise MissingProductionOriginalV1("actual_historical_deep_trial_clock_original")
        self.issuer._signer.verify(CLOCK_SIGN_KIND,row[0],row[2]);body=json.loads(row[0])
        if canonical_serialize(body)!=row[0] or canonical_digest(body)!=row[1] or row[1]!=start["clock_original_digest"]:
            raise ValueError("historical deep trial clock original changed")
        values=dict(body["mapping"]);values["character_origin"]=Decimal(values["character_origin"]);values["rate"]=Decimal(values["rate"])
        mapping=CharacterClockMapping(**values)
        actual=db.execute("SELECT digest,mapping_id,version,mapping_json FROM runtime_clock_operations WHERE operation_id=?",
            (body["clock_operation_id"],)).fetchone()
        if (mapping.mapping_id!=start["clock_mapping_ref"] or mapping.version!=start["clock_mapping_version"]
                or actual is None or actual[:3]!=(body["clock_operation_digest"],mapping.mapping_id,mapping.version)
                or json.loads(actual[3])!=body["mapping"]):
            raise MissingProductionOriginalV1("actual_historical_deep_trial_clock_producer")
        wall=datetime.fromtimestamp(adopted_at_utc,timezone.utc).isoformat().replace("+00:00","Z")
        return mapping,row[1],mapping.character_at(wall)

    def current_semantic_counter_scope_v3(self, db, read, intent):
        from ..domains.d01.production_operations_v1 import SemanticCounterScopeV3
        from ..domains.d07 import D07DomainProvider
        scope="d01.growth:"+intent["target_block"]+":core"
        inventory=read.complete_inventory(db,"d07.current_interpretation.v1")
        pages=tuple(page for page in read.frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
        if len(pages)!=1:raise MissingProductionOriginalV1("actual_current_deep_counter_query_coverage")
        versions=[];digests=[];source_digests={};qualification="qualified"
        for atom in inventory:
            if not atom.valid or atom.value.get("question_key")!=scope or atom.value.get("current") is not True:continue
            next(spec for spec in D07DomainProvider.type_specs() if spec.name==atom.key.type_name).validator(atom.value)
            history=read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(atom.key.token,atom.revision), history=True)
            if history is None or history[2]!=1 or json.loads(history[1])!=atom.value:
                raise MissingProductionOriginalV1("actual_current_deep_counter_interpretation_adoption")
            read.committed_operation(db,history[0]);read.original(atom.key.token,digest=canonical_digest(atom.value))
            refs=tuple(atom.value["source_refs"])
            if refs:read.source_family(db,refs,purpose="consolidation")
            for ref in refs:source_digests[ref]=canonical_digest(read.head(db,ref,required=True).value)
            if atom.value["stance"]=="oppose" and atom.value["evidence_status"]=="supported":qualification="opposition"
            elif qualification!="opposition" and (atom.value["stance"]!="support" or atom.value["meaningful_unknowns"] or atom.value["evidence_status"]!="supported"):qualification="unknown"
            versions.append(GraphVersion(atom.key,atom.revision));digests.append((atom.key.token,canonical_digest(atom.value)))
        return SemanticCounterScopeV3(scope,pages[0],tuple(versions),tuple(digests),tuple(sorted(source_digests.items())),qualification)

    def validate_semantic_trial_plan_history_v3(self, db, read, start):
        head=_decode_identity_graph_version_v3(start["planned_progress_head"])
        read.head(db,head.key,required=True)
        history=read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(head.key.token,head.revision), history=True)
        if history is None or history[2]!=1 or canonical_digest(json.loads(history[1]))!=start["planned_progress_digest"]:
            raise MissingProductionOriginalV1("actual_frozen_deep_trial_plan_producer")
        read.committed_operation(db,history[0])
        return head

    def validate_semantic_trial_scope_v3(self, db, read, planned, policy):
        lineage={planned.key.token}
        if planned.key.type_name=="d08.action_intent.v1":
            goals=tuple(atom for atom in read.complete_inventory(db,"d08.goal.v1") if atom.valid and atom.key.name==planned.value["goal_ref"])
            if len(goals)!=1:raise MissingProductionOriginalV1("actual_deep_trial_goal_lineage")
            lineage.add(goals[0].key.token)
            for atom in read.complete_inventory(db,"d08.personal_plan.v1"):
                if atom.valid and atom.value.get("goal_ref")==goals[0].key.token:lineage.add(atom.key.token)
        if not lineage.intersection(policy.scope_refs) or lineage.intersection(policy.exclusion_refs):
            raise ValueError("actual deep trial plan lineage is outside explicit Owner scope")
        return lineage

    def current_semantic_trial_start_v3(self, db, read, proposal_ref, completed_ref):
        rows=db.execute("SELECT original_ref,payload_json FROM "+TABLE+" WHERE bot=? AND persona=? "
            "AND kind='identity_trial_start_v3' ORDER BY original_ref LIMIT 129",read.frame.envelope.authority.namespace.as_tuple).fetchall()
        if len(rows)>128:raise MissingProductionOriginalV1("bounded_deep_identity_trial_inventory")
        found=[]
        for ref, encoded in rows:
            raw=json.loads(encoded)
            if raw["growth_proposal_ref"]==proposal_ref and raw["completed_trial_ref"]==completed_ref:
                value, original=self._read(db,read,ref,"identity_trial_start_v3")
                found.append((ref,value,original))
        if len(found)!=1:raise MissingProductionOriginalV1("one_actual_deep_identity_trial_start")
        return found[0]

    def validate_semantic_trial_start_v3(self, db, frame, request):
        read=CurrentDomainReadV1(frame);read.check(db)
        intent,_=self._read(db,read,request.growth_proposal_ref,"growth_proposal")
        if intent.get("schema")!="d01.growth-intent.v2" or request.completed_trial_ref not in intent["required_trial_refs"]:
            raise ValueError("deep trial must belong to the exact V2 declared plan")
        policy,original=self._identity_policy_v3(db,read,intent["plasticity_policy_ref"],require_growth=True)
        prior=raw_registered_input_v1(db,TABLE,frame.envelope.authority.namespace,request.original_ref)
        if prior is not None:
            saved,_=self._read(db,read,request.original_ref,"identity_trial_start_v3")
            if (saved["growth_proposal_ref"],saved["completed_trial_ref"],saved["planned_progress_ref"])!=(
                    request.growth_proposal_ref,request.completed_trial_ref,request.planned_progress_ref):
                raise ValueError("deep trial original ID replay conflicts")
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            return decode_typed_production_value_v1(saved,IdentityTrialStartV3)
        mapping,clock_digest,now_role=self._identity_clock_v3(db,read)
        active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=frame.envelope.authority.namespace,current_guard=self.owner_guard)
        planned=read.head(db,request.planned_progress_ref,required=True)
        if planned.key.type_name not in {"d08.action_intent.v1","d10.life_project.v1"}:
            raise ValueError("identity trial needs the actual approved D08/D10 plan")
        history=read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(planned.key.token,planned.revision), history=True)
        if history is None or history[2]!=1 or json.loads(history[1])!=planned.value:
            raise MissingProductionOriginalV1("actual_adopted_identity_trial_plan")
        read.committed_operation(db,history[0]);read.original(request.planned_progress_ref)
        self.validate_semantic_trial_scope_v3(db,read,planned,policy)
        if active.head_id!=intent["base_head"] or len(intent["required_trial_refs"])>policy.maximum_trials:
            raise ValueError("identity trial base or maximum changed")
        outcomes=read.complete_inventory(db,"d08.action_outcome.v1" if planned.key.type_name=="d08.action_intent.v1" else "d10.life_progress.v1")
        if any(value.valid and _actual_trial_plan_matches_v3(planned.key.token,value) for value in outcomes):
            raise ValueError("deep trial cannot start after its actual completed outcome")
        from decimal import Decimal
        rows=db.execute("SELECT original_ref,payload_json FROM "+TABLE+" WHERE bot=? AND persona=? "
            "AND kind='identity_trial_start_v3' ORDER BY original_ref LIMIT 129",frame.envelope.authority.namespace.as_tuple).fetchall()
        if len(rows)>128:raise MissingProductionOriginalV1("bounded_deep_identity_trial_inventory")
        starts=0
        for ref, encoded in rows:
            value=json.loads(encoded)
            if value["growth_proposal_ref"]==request.growth_proposal_ref:starts+=1
            if ref==request.original_ref:continue
            self._read(db,read,ref,"identity_trial_start_v3")
            completed=raw_registered_input_v1(db,TABLE,frame.envelope.authority.namespace,value["completed_trial_ref"])
            if completed is not None:
                completed,_=self._read(db,read,value["completed_trial_ref"],"growth_trial")
                if completed["growth_proposal_ref"]!=value["growth_proposal_ref"] or completed["completed"] is not True:
                    raise ValueError("deep trial completion does not match its original start")
            if completed is None and value["clock_mapping_version"]==mapping.version and now_role<Decimal(value["observation_role_deadline"]):
                raise MissingProductionOriginalV1("one_active_identity_trial_per_persona")
            if value["clock_mapping_version"]!=mapping.version and completed is None:
                raise MissingProductionOriginalV1("legal_identity_trial_cross_mapping_continuity")
        prior=raw_registered_input_v1(db,TABLE,frame.envelope.authority.namespace,request.original_ref)
        if prior is None and starts>=policy.maximum_trials:raise ValueError("deep identity maximum trials reached")
        return IdentityTrialStartV3(request.growth_proposal_ref,request.completed_trial_ref,request.planned_progress_ref,
            active.head_id,policy.policy_ref,original.original_digest,mapping.mapping_id,mapping.version,clock_digest,
            frame.now_utc,str(now_role),str(now_role+Decimal(policy.observation_role_seconds)),
            GraphVersion(planned.key,planned.revision),canonical_digest(planned.value))

    def start_semantic_trial_after_commit_v3(self, db, *, frame, producing_operation_id, request):
        value=self.validate_semantic_trial_start_v3(db,frame,request)
        return self.record_input(db,frame=frame,original_ref=request.original_ref,
            producing_operation_id=producing_operation_id,kind="identity_trial_start_v3",value=value)

    def freeze_semantic_growth_after_commit_v3(self, db, *, frame, producing_operation_id, request):
        from ..domains.d01.identity_v3 import decode_semantic_identity_v3, SemanticIdentityRevisionRefV3
        read=CurrentDomainReadV1(frame);read.check(db)
        active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=frame.envelope.authority.namespace,current_guard=self.owner_guard)
        policy,policy_original=self._identity_policy_v3(db,read,request.plasticity_policy_ref,require_growth=True)
        atom=read.head(db,request.interpretation_ref,required=True)
        scope=atom.value.get("question_key","")
        if not scope.startswith("d01.growth:") or not scope.endswith(":core"):
            raise ValueError("semantic proposal needs actual adopted core growth judgment")
        target_id=scope[len("d01.growth:"):-len(":core")]
        target=next((block for block in active.plan.blocks if block.block_id==target_id and block.kind=="semantic_identity"),None)
        if target is None or target.plasticity!="growth" or target_id not in policy.target_block_ids:
            raise ValueError("semantic growth target has no installed explicit plasticity")
        base=decode_semantic_identity_v3(target.claim)
        if base is None:raise MissingProductionOriginalV1("semantic_identity_V3_migration_required")
        semantic,semantic_original,records=read.adopted_interpretation(db,request.interpretation_ref,question_scope=scope)
        roots=tuple(semantic.value["source_refs"])
        if any(records[ref].source_kind!="observed" or records[ref].assertion_status!="confirmed"
                or records[ref].independence!="independent" or records[ref].parent_source_ids for ref in roots):
            raise MissingProductionOriginalV1("confirmed_independent_observed_semantic_evidence")
        if not policy.required_completed_trials<=len(request.required_trial_refs)<=policy.maximum_trials:
            raise ValueError("deep growth must name its explicitly bounded trials")
        read.original(request.trigger_original_ref)
        proposal_id="semantic-growth:"+canonical_digest((active.head_id,semantic.key.token,semantic.revision))[:48]
        intent=GrowthIntentOriginalV2(proposal_id,active.head_id,target_id,semantic.value["proposition"],"core",roots,
            request.trigger_original_ref,request.required_trial_refs,
            SemanticIdentityRevisionRefV3(active.head_id,target_id,base.revision,canonical_digest(target.claim)),
            policy.policy_ref,policy_original.original_digest,base.continuity_anchor,policy.scope_refs,policy.exclusion_refs,
            policy.observer_policy_ref,policy.observer_policy_digest,frame.now_utc,policy.valid_until_utc,
            request.rollback_predicate_refs,request.continuity_interpretation_ref)
        inventory=read.complete_inventory(db,"d07.current_interpretation.v1")
        counters=tuple(value for value in inventory if value.valid and value.value.get("question_key")==scope
            and value.value.get("stance")=="oppose" and value.value.get("evidence_status")=="supported")
        counter_roots=tuple(dict.fromkeys(ref for value in counters for ref in value.value["source_refs"]))
        if counter_roots:read.source_family(db,counter_roots,purpose="consolidation")
        page=next(page for page in frame.query_coverage if page.type_id=="d07.current_interpretation.v1")
        counter=GrowthCounterevidenceOriginalV1(request.growth_proposal_ref,roots,counter_roots,page.type_id,page.epoch.revision,True,bool(counters))
        return (self.record_input(db,frame=frame,original_ref=request.growth_proposal_ref,
            producing_operation_id=producing_operation_id,kind="growth_proposal_v2",value=intent),
            self.record_input(db,frame=frame,original_ref=request.counterevidence_query_ref,
            producing_operation_id=producing_operation_id,kind="growth_counterevidence",value=counter),semantic_original)

    def qualify_semantic_growth_v3(self, db, read, request, raw, proposal, active,
            *, trials_complete, counter_complete, counter_conflict,counter_scope):
        from ..domains.d01.identity_v3 import (SemanticIdentityRevision, SemanticIdentityRevisionRefV3,
            RuntimeIdentityRef, decode_semantic_identity_v3, encode_semantic_identity_v3)
        from ..domains.d01.production_operations_v1 import SemanticGrowthQualificationV3
        if raw.get("schema")!="d01.growth-intent.v2" or proposal.change_kind!="core":
            raise MissingProductionOriginalV1("semantic_identity_requires_V2_core_intent_and_deep_policy")
        if counter_scope is None or not counter_scope.complete:
            state="unavailable" if counter_scope is None else counter_scope.qualification
            raise MissingProductionOriginalV1("current_deep_counter_scope:"+state)
        target=next(block for block in active.plan.blocks if block.block_id==proposal.target_block)
        base=decode_semantic_identity_v3(target.claim)
        if base is None:raise MissingProductionOriginalV1("semantic_identity_V3_migration_required")
        base_ref=SemanticIdentityRevisionRefV3(active.head_id,target.block_id,base.revision,canonical_digest(target.claim))
        if (raw["base_head"]!=active.head_id or raw["semantic_base_revision_ref"]!=plain_v1(base_ref)
                or raw["continuity_anchor"]!=plain_v1(base.continuity_anchor)):
            raise ValueError("deep identity exact semantic base/continuity anchor changed")
        policy,policy_original=self._identity_policy_v3(db,read,raw["plasticity_policy_ref"],require_growth=True)
        if (target.plasticity!="growth" or target.block_id not in policy.target_block_ids
                or (base.plasticity_policy_ref,base.plasticity_policy_digest)!=(policy.policy_ref,policy_original.original_digest)
                or raw["plasticity_policy_digest"]!=policy_original.original_digest
                or (raw["observer_policy_ref"],raw["observer_policy_digest"])!=(policy.observer_policy_ref,policy.observer_policy_digest)
                or tuple(raw["scope_refs"])!=policy.scope_refs or tuple(raw["exclusion_refs"])!=policy.exclusion_refs
                or not policy.valid_from_utc<=raw["valid_from"]<=read.frame.now_utc<raw["valid_until"]<=policy.valid_until_utc
                or len(proposal.source_families)<policy.required_independent_families
                or not policy.required_completed_trials<=len(request.trial_original_refs)<=policy.maximum_trials
                or not trials_complete or not counter_complete or counter_conflict):
            raise MissingProductionOriginalV1("complete_current_deep_policy_support_counter_and_real_trials")
        mapping,clock_digest,now_role=self._identity_clock_v3(db,read)
        originals=[policy_original];trial_pairs=[];support_pairs=[]
        for ref in request.trial_original_refs:
            trial,trial_original=self._read(db,read,ref,"growth_trial")
            if trial.get("schema")!="d01.growth-trial.v2":
                raise MissingProductionOriginalV1("actual_V2_deep_identity_trial_clock_and_outcome")
            start,start_original=self._read(db,read,trial["trial_start_ref"],"identity_trial_start_v3")
            from decimal import Decimal
            if ((start["policy_ref"],start["policy_digest"])!=(policy.policy_ref,policy_original.original_digest)
                    or start["growth_proposal_ref"]!=request.growth_proposal_ref
                    or start["completed_trial_ref"]!=ref or start["base_persona_head"]!=active.head_id
                    or (mapping.mapping_id,mapping.version,clock_digest)!=(start["clock_mapping_ref"],start["clock_mapping_version"],start["clock_original_digest"])
                    or not Decimal(start["started_role_cursor"])<=now_role<Decimal(start["observation_role_deadline"])
                    or trial["completed"] is not True):
                raise MissingProductionOriginalV1("original_deep_trial_clock_window_or_base_changed")
            for outcome_ref in trial["settled_outcome_refs"]:
                current_trial=self.derive_current_growth_trial_from_adopted_progress_v1(db,
                    frame=read.frame,producing_operation_id=None,original_ref=ref,
                    growth_proposal_ref=request.growth_proposal_ref,settled_progress_ref=outcome_ref,validate_only=True)
                if plain_v1(current_trial)!=trial:
                    raise MissingProductionOriginalV1("current_actual_deep_trial_effect_source_cost_changed")
            self.validate_semantic_trial_plan_history_v3(db,read,start)
            planned=read.head(db,start["planned_progress_ref"],required=True)
            self.validate_semantic_trial_scope_v3(db,read,planned,policy)
            originals.extend((start_original,trial_original));trial_pairs.append((ref,trial_original.original_digest))
        for ref in raw["evidence_source_refs"]:
            source=read.head(db,ref,required=True);support_pairs.append((ref,canonical_digest(source.value)))
        counter,counter_original=self._read(db,read,request.counterevidence_query_ref,"growth_counterevidence")
        diff=base.cumulative_diff+((canonical_digest(base.claim),canonical_digest(proposal.replacement_claim)),)
        if base.claim==proposal.replacement_claim or len(diff)>policy.maximum_revisions_since_continuity_anchor:
            raise MissingProductionOriginalV1("deep_identity_cumulative_diff_requires_new_continuity_anchor")
        originals.append(counter_original)
        question="d01.semantic-continuity.v3:"+canonical_digest({
            "proposal_digest":read.original(request.growth_proposal_ref).original_digest,
            "semantic_base":plain_v1(base_ref),"policy_digest":policy_original.original_digest,
            "continuity_anchor":plain_v1(base.continuity_anchor),"cumulative_diff":plain_v1(diff),
            "trial_originals":sorted(trial_pairs),"support_originals":sorted(support_pairs),
            "current_counter_scope":semantic_counter_binding_v3(counter_scope),
            "counter_original":(request.counterevidence_query_ref,counter_original.original_digest),
            "counter_sources":sorted((ref,canonical_digest(read.head(db,ref,required=True).value)) for ref in counter["counterevidence_source_refs"]),
            "scope_refs":policy.scope_refs,"exclusion_refs":policy.exclusion_refs})
        continuity,continuity_original,_=read.adopted_interpretation(db,raw["continuity_interpretation_ref"],question_scope=question)
        if continuity.value["proposition"]!="accepted":
            raise MissingProductionOriginalV1("explicit_adopted_deep_identity_continuity_acceptance")
        originals.append(continuity_original)
        semantic=SemanticIdentityRevision(RuntimeIdentityRef.from_owner_guard(active.namespace,self.owner_guard),
            target.block_id,base.revision+1,proposal.replacement_claim,base_ref,base.legacy_origin,base.continuity_anchor,
            canonical_digest(base.claim),diff,policy.policy_ref,policy_original.original_digest,
            tuple(raw["evidence_source_refs"]),request.counterevidence_query_ref,raw["continuity_interpretation_ref"],
            request.trial_original_refs,policy.scope_refs,policy.exclusion_refs,read.frame.now_utc,
            policy.readout_valid_until_utc,"growth",adopt_before=raw["valid_until"])
        encoded=encode_semantic_identity_v3(semantic)
        qualification=SemanticGrowthQualificationV3(active.head_id,target.block_id,encoded,tuple(originals))
        return replace(proposal,replacement_claim=encoded),qualification,tuple(originals)

    def semantic_producer_v3(self, db, read, block_id, encoded):
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        matches=[]
        for atom in read.complete_inventory(db,"d01.persona_revision.v1"):
            if not atom.valid or not any(block["block_id"]==block_id and block["claim"]==encoded for block in atom.value["blocks"]):continue
            history=read_graph_row_v3(db, ('event_id', 'value', 'valid'), where='token=? AND revision=?', parameters=(atom.key.token,atom.revision), history=True)
            if history is None or history[2]!=1 or json.loads(history[1])!=atom.value:continue
            read.committed_operation(db,history[0])
            adopted=read_adopted_domain_operation_v1(db,read.frame.envelope.authority.namespace,history[0])
            if adopted is None or adopted["domain"]!="d01":continue
            candidate=adopted["payload"]["provenance"].get("candidate")
            if candidate is None or candidate["revision"]!=atom.value:continue
            if adopted["operation_kind"]=="migrate_semantic_identity_v3":
                if block_id in adopted["payload"]["request"]["target_block_ids"]:matches.append(adopted)
            elif adopted["operation_kind"]=="adopt_growth":
                request=adopted["payload"]["request"]
                intent,_=self._read(db,read,request["growth_proposal_ref"],"growth_proposal")
                if intent.get("schema")=="d01.growth-intent.v2" and intent["target_block"]==block_id:matches.append(adopted)
        if len(matches)!=1:raise MissingProductionOriginalV1("one_actual_semantic_migration_or_growth_producer")
        return matches[0]

    def semantic_readout_evidence_v3(self, db, read, semantic, producer):
        if producer["payload"]["now_utc"]!=semantic.valid_from:
            raise MissingProductionOriginalV1("semantic_readout_actual_adopted_event_time")
        if semantic.plasticity_policy_ref is not None:
            policy,original=self._identity_policy_v3(db,read,semantic.plasticity_policy_ref,
                require_growth=semantic.revision_kind=="growth",qualification_at_utc=semantic.valid_from)
            if original.original_digest!=semantic.plasticity_policy_digest:
                raise MissingProductionOriginalV1("semantic_readout_actual_registered_policy_digest")
        if semantic.revision_kind!="growth":return
        if producer["operation_kind"]!="adopt_growth" or semantic.adopt_before is None or not semantic.valid_from<semantic.adopt_before:
            raise MissingProductionOriginalV1("semantic_readout_actual_deep_adoption_window")
        request=producer["payload"]["request"]
        intent,_=self._read(db,read,request["growth_proposal_ref"],"growth_proposal")
        if (intent.get("schema")!="d01.growth-intent.v2" or intent["replacement_claim"]!=semantic.claim
                or tuple(intent["evidence_source_refs"])!=semantic.support_original_refs
                or tuple(request["trial_original_refs"])!=semantic.trial_original_refs
                or request["counterevidence_query_ref"]!=semantic.counterevidence_original_ref
                or intent["continuity_interpretation_ref"]!=semantic.continuity_original_ref):
            raise MissingProductionOriginalV1("semantic_readout_actual_adopted_intent_membership")
        counter=self.current_semantic_counter_scope_v3(db,read,intent)
        if not counter.complete:raise MissingProductionOriginalV1("semantic_readout_current_counter_scope:"+counter.qualification)
        frozen,_=self._read(db,read,semantic.counterevidence_original_ref,"growth_counterevidence")
        roots=tuple(dict.fromkeys((*frozen["evidence_source_refs"],*frozen["counterevidence_source_refs"])))
        if roots:read.source_family(db,roots,purpose="consolidation")
        atom=read.head(db,semantic.continuity_original_ref,required=True)
        continuity,original,_=read.adopted_interpretation(db,semantic.continuity_original_ref,question_scope=atom.value["question_key"])
        expected=tuple(value for value in producer["payload"]["observed_originals"] if value["original_ref"]==semantic.continuity_original_ref)
        if len(expected)!=1 or expected[0]["original_digest"]!=original.original_digest or continuity.value["proposition"]!="accepted":
            raise MissingProductionOriginalV1("semantic_readout_actual_continuity_original_current_sources")
        for ref in semantic.trial_original_refs:
            trial,_=self._read(db,read,ref,"growth_trial")
            if trial.get("schema")!="d01.growth-trial.v2":raise MissingProductionOriginalV1("semantic_readout_actual_trial_V2")
            start,_=self._read(db,read,trial["trial_start_ref"],"identity_trial_start_v3")
            self.validate_semantic_trial_plan_history_v3(db,read,start)
            for outcome in trial["settled_outcome_refs"]:
                current=self.derive_current_growth_trial_from_adopted_progress_v1(db,frame=read.frame,
                    producing_operation_id=None,original_ref=ref,growth_proposal_ref=request["growth_proposal_ref"],
                    settled_progress_ref=outcome,validate_only=True,adopted_at_utc=semantic.valid_from)
                if plain_v1(current)!=trial:raise MissingProductionOriginalV1("semantic_readout_current_actual_trial_effect_source_cost")

    def semantic_readout_history_v3(self, db, read, block, semantic):
        from ..domains.d01.identity_v3 import decode_semantic_identity_v3
        current,encoded=semantic,block.claim;seen=set()
        for _ in range(128):
            if current.revision in seen:raise ValueError("semantic readout history is cyclic")
            seen.add(current.revision)
            producer=self.semantic_producer_v3(db,read,block.block_id,encoded)
            self.semantic_readout_evidence_v3(db,read,current,producer)
            if current.revision_kind in {"growth","legacy_migration"}:return
            if current.revision_kind!="administrative" or current.previous_revision is None or producer["operation_kind"]!="migrate_semantic_identity_v3":
                raise MissingProductionOriginalV1("actual_semantic_administrative_history")
            matches={}
            for atom in read.complete_inventory(db,"d01.persona_revision.v1"):
                if not atom.valid:continue
                for prior in atom.value["blocks"]:
                    if prior["block_id"]==block.block_id and canonical_digest(prior["claim"])==current.previous_revision.payload_digest:
                        value=decode_semantic_identity_v3(prior["claim"])
                        if value is not None and value.revision==current.previous_revision.revision:matches[prior["claim"]]=value
            if len(matches)!=1:raise MissingProductionOriginalV1("actual_semantic_administrative_predecessor")
            prior_encoded,prior=next(iter(matches.items()))
            if prior.claim!=current.claim or prior.cumulative_diff!=current.cumulative_diff or prior.runtime_identity!=current.runtime_identity:
                raise ValueError("administrative transition changed semantic meaning/history/runtime identity")
            current,encoded=prior,prior_encoded
        raise MissingProductionOriginalV1("bounded_semantic_administrative_history")

    def read_self_model_v3(self, db, frame, request):
        from ..domains.d01.identity_v3 import (RuntimeIdentityRef, SelfModelProjectionV3, SemanticIdentityProjectionV3,
            SemanticIdentityRevisionRefV3, decode_semantic_identity_v3)
        read=CurrentDomainReadV1(frame);read.check(db)
        ns=frame.envelope.authority.namespace
        active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=ns,current_guard=self.owner_guard)
        runtime=RuntimeIdentityRef.from_owner_guard(ns,self.owner_guard);rows=[]
        for block in active.plan.blocks:
            if block.kind!="semantic_identity" or request.block_ids and block.block_id not in request.block_ids:continue
            semantic=decode_semantic_identity_v3(block.claim)
            if semantic is None:
                rows.append(SemanticIdentityProjectionV3(runtime,block.block_id,block.claim,None,None,(),"legacy_read_only",()))
                continue
            if semantic.runtime_identity!=runtime:raise ValueError("semantic projection runtime identity differs")
            missing=[]
            try:self.semantic_readout_history_v3(db,read,block,semantic)
            except MissingProductionOriginalV1 as held:missing.extend(held.missing_inputs)
            if semantic.valid_until is not None and not semantic.valid_from<=frame.now_utc<semantic.valid_until:
                missing.append("current_semantic_identity_validity")
            if semantic.support_original_refs:
                try:read.source_family(db,semantic.support_original_refs,purpose="consolidation")
                except MissingProductionOriginalV1 as held:missing.extend(held.missing_inputs)
            rows.append(SemanticIdentityProjectionV3(runtime,block.block_id,None if missing else semantic.claim,
                SemanticIdentityRevisionRefV3(active.head_id,block.block_id,semantic.revision,canonical_digest(block.claim)),
                semantic.plasticity_policy_ref,semantic.scope_refs,"unavailable" if missing else "qualified",
                tuple(dict.fromkeys(missing))))
        result=SelfModelProjectionV3(runtime,active.head_id,tuple(rows),frame.snapshot.versions)
        if len(canonical_serialize(plain_v1(result)).encode())>65536:
            raise MissingProductionOriginalV1("bounded_self_model_projection_65536_bytes")
        return result


def stage_evaluate_current_values_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("installed D01 current readers required")
    try:
        stage = compile_evaluate_current_values_v1(frame, request, installed_readers.read_values(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d01", "evaluate_values", request, missing)
    return verify_d01_production_stage_v1(stage)


def stage_adopt_current_growth_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("installed D01 current readers required")
    try:
        stage = compile_adopt_current_growth_v1(frame, request, installed_readers.read_growth(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d01", "adopt_growth", request, missing)
    return verify_d01_production_stage_v1(stage)


prepare_current_growth_v1 = stage_adopt_current_growth_in_transaction_v1
adopt_current_growth_v1 = stage_adopt_current_growth_in_transaction_v1
evaluate_current_values_v1 = stage_evaluate_current_values_in_transaction_v1
D01_PRODUCTION_STORAGE_INVENTORY_V1 = {TABLE: {"namespace_columns": ("bot", "persona"),
    "content_columns": ("payload_json",), "source_closure_column": "source_refs_json",
    "operation_column": "producing_operation_id", "recovery": "revalidate_signed_input_and_producing_operation"}}


def production_read_plan_v1(types, keys=(), roots=(), originals=()):
    """A closed read plan may defer a large scope, never silently trim it."""
    keys = tuple(sorted(set(keys), key=lambda key: key.token))
    roots, originals = tuple(sorted(set(roots))), tuple(sorted(set(originals)))
    if len(keys) > 1024 or len(roots) > 32 or len(originals) > 128:
        raise MissingProductionOriginalV1("bounded_production_read_plan",
            continuation="production-read:" + canonical_digest((types, keys, roots, originals))[:48])
    return ProductionReadPlanV1(tuple(sorted(set(types))), keys, roots, originals)


def raw_registered_input_v1(db, table, namespace, ref):
    """Locator expansion only. The actual reader must authenticate it later."""
    allowed = {"graph_d01_production_inputs_v1", "graph_d05_boundary_intents_v1",
        "graph_d08_joint_plan_intents_v1", "graph_d08_party_consents_v1", "graph_d10_production_inputs_v1",
        "graph_d02_action_components_v1"}
    if table not in allowed:
        raise ValueError("unregistered production original locator table")
    if not table_exists_v1(db, table):
        return None
    from .domain_background_read_v3 import (read_bound_background_graph_attachment_v3,
        background_json_loads_v3)
    handled, row = read_bound_background_graph_attachment_v3(db, table=table,
        columns=("payload_json",), key_columns=("bot", "persona", "original_ref"),
        key=(*namespace.as_tuple, ref))
    if handled:
        return None if row is None else background_json_loads_v3(row[0])
    row = db.execute("SELECT payload_json FROM " + table + " WHERE bot=? AND persona=? AND original_ref=?",
                     (*namespace.as_tuple, ref)).fetchone()
    return None if row is None else json.loads(row[0])


def raw_head_value_v1(db, namespace, key):
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("production read-plan key crossed namespace")
    from .domain_background_read_v3 import (read_bound_background_graph_attachment_v3,
        background_json_loads_v3)
    handled, row = read_bound_background_graph_attachment_v3(db, table="graph_atoms",
        columns=("value", "valid"), key_columns=("token", "bot", "persona"),
        key=(key.token, *namespace.as_tuple))
    if handled:
        return None if row is None or row[1] != 1 else background_json_loads_v3(row[0])
    row = read_graph_row_v3(db, ('value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(key.token, *namespace.as_tuple), history=False)
    return None if row is None or row[1] != 1 else json.loads(row[0])


def method_condition_read_inputs_v1(db, namespace, goal_keys):
    """Locator expansion; adopted_interpretation rechecks truth/use eligibility."""
    from ..domains.d07 import decode_method_condition_question_v1
    goals = {}
    for key in goal_keys:
        value = raw_head_value_v1(db, namespace, key)
        if value is not None:
            goals[key.token] = value["revision"]
    rows = read_graph_rows_v3(db, ('token', 'value'), where="bot=? AND persona=? AND type_name='d07.current_interpretation.v1' AND valid=1", parameters=namespace.as_tuple, history=False, order_by=('token',), limit=129)
    if len(rows) > 128:
        raise MissingProductionOriginalV1("complete_method_condition_inventory")
    keys, roots, originals = [], [], []
    for token, encoded in rows:
        value = json.loads(encoded)
        scope = decode_method_condition_question_v1(value["question_key"])
        if scope is not None and goals.get(scope["goal_ref"]) == scope["goal_revision"]:
            keys.append(AtomKey.from_token(token))
            roots.extend(value["source_refs"])
            originals.append(token)
    return keys, roots, originals


def read_plan_current_d01_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("D01 fixed read planning requires current W01 transaction")
    from ..graph_types import Owner
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    types = ["d01.persona_activation.v1", "d01.persona_plan.v1", "d01.persona_revision.v1", "d01.growth_contribution.v1"]
    if operation_kind == "evaluate_values" and type(request) is EvaluateCurrentValuesRequestV1:
        originals.extend((request.candidate_set_ref, request.context_ref))
        for ref, table in ((request.candidate_set_ref, TABLE), (request.context_ref, TABLE)):
            raw = raw_registered_input_v1(db, table, namespace, ref)
            if raw:
                method_head = raw.get("plan_head")
                if method_head is not None:
                    plan_key = AtomKey.from_token(method_head["key"])
                    keys.append(plan_key)
                    plan_value = raw_head_value_v1(db, namespace, plan_key)
                    if plan_value:
                        keys.append(AtomKey.from_token(plan_value["goal_ref"]))
                        roots.extend(plan_value["source_refs"])
                if method_head is not None or raw.get("condition_query_epoch") is not None:
                    types.append("d07.current_interpretation.v1")
                for head in (*raw.get("candidate_heads", ()), *raw.get("context_heads", ()), *raw.get("condition_heads", ())):
                    key = AtomKey.from_token(head["key"])
                    keys.append(key)
                    value = raw_head_value_v1(db, namespace, key)
                    if value:
                        roots.extend(value.get("source_refs", ()))
    elif operation_kind == "adopt_growth" and type(request) is AdoptCurrentGrowthRequestV1:
        originals.extend((request.growth_proposal_ref, request.trigger_original_ref, request.counterevidence_query_ref,
                          *request.trial_original_refs))
        raw = raw_registered_input_v1(db, TABLE, namespace, request.growth_proposal_ref)
        ordinary_counter=False
        if raw is not None and set(raw)==set(GrowthIntentOriginalV1.__dataclass_fields__):
            activation_key=AtomKey(Owner("persona",*namespace.as_tuple),"d01.persona_activation.v1","current")
            activation=raw_head_value_v1(db,namespace,activation_key)
            if activation is not None:
                plan_key=AtomKey(Owner("persona",*namespace.as_tuple),"d01.persona_plan.v1",activation["plan_id"])
                current_plan=raw_head_value_v1(db,namespace,plan_key)
                if (current_plan is not None and current_plan["version"]==activation["plan_version"]
                        and str(current_plan["plan_id"])+"@"+str(current_plan["version"])==activation["head_id"]):
                    current_target=next((block for block in current_plan["blocks"] if block["block_id"]==raw["target_block"]),None)
                    ordinary_counter=current_target is not None and current_target["kind"]!="semantic_identity"
                    keys.extend((activation_key,plan_key))
        if raw:
            roots.extend(raw["evidence_source_refs"])
            if ordinary_counter:
                types.append("d07.current_interpretation.v1")
                question_scope="d01.growth:"+raw["target_block"]+":"+raw["change_kind"]
                current=read_graph_rows_v3(db,("token","value"),where="bot=? AND persona=? AND type_name='d07.current_interpretation.v1' AND valid=1",
                    parameters=namespace.as_tuple,history=False,order_by=("token",),limit=129)
                if len(current)>128:raise MissingProductionOriginalV1("complete_current_general_growth_counter_inventory")
                for ref,encoded in current:
                    value=json.loads(encoded)
                    if value.get("question_key")==question_scope and value.get("current") is True:
                        keys.append(AtomKey.from_token(ref));originals.append(ref);roots.extend(value["source_refs"])
            keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_revision.v1", raw["proposal_id"]))
            for ref in raw["evidence_source_refs"]:
                source = raw_head_value_v1(db, namespace, AtomKey.from_token(ref))
                if source:
                    contribution = PersonaDomain.contribution_key(raw["target_block"], source["provenance_root"], raw["change_kind"])
                    keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.growth_contribution.v1", contribution))
        for ref in (*request.trial_original_refs, request.counterevidence_query_ref):
            raw = raw_registered_input_v1(db, TABLE, namespace, ref)
            if raw:
                roots.extend(raw.get("evidence_source_refs", ()))
                if not (ordinary_counter and ref==request.counterevidence_query_ref):
                    roots.extend(raw.get("counterevidence_source_refs", ()))
                originals.extend(raw.get("settled_outcome_refs", ()))
    elif operation_kind == "migrate_semantic_identity_v3" and type(request) is MigrateSemanticIdentityRequestV3:
        keys.append(request.expected_plan_head.key)
        from ..domains.d01.production_operations_v1 import plain_v1
        revision_id="semantic-migration:"+canonical_digest(plain_v1(request))[:48]
        keys.append(AtomKey(Owner("persona",*namespace.as_tuple),"d01.persona_revision.v1",revision_id))
        if request.plasticity_policy_ref is not None:originals.append(request.plasticity_policy_ref)
    elif operation_kind == "project_self_model_v3" and type(request) is ProjectSelfModelRequestV3:
        types.append("d07.current_interpretation.v1")
        relevant=read_graph_rows_v3(db, ('token', 'value'), where="bot=? AND persona=? AND type_name='d07.current_interpretation.v1' AND valid=1", parameters=namespace.as_tuple, history=False, order_by=('token',), limit=129)
        if len(relevant)>128:raise MissingProductionOriginalV1("complete_semantic_readout_current_counter_inventory")
        for ref,encoded in relevant:
            value=json.loads(encoded)
            if value.get("question_key","").startswith(("d01.growth:","d01.semantic-continuity.v3:")):
                originals.append(ref);roots.extend(value["source_refs"])
        revs=db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d01.persona_revision.v1' AND valid=1 ORDER BY token LIMIT 129",namespace.as_tuple).fetchall()
        if len(revs)>128:raise MissingProductionOriginalV1("bounded_semantic_readout_revision_history")
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .domain_production_inputs_v1 import read_plan_current_domain_input_v1,DeriveCurrentGrowthTrialInputRequestV1
        for token,revision in revs:
            revision_value=raw_head_value_v1(db,namespace,AtomKey.from_token(token))
            if revision_value is not None:
                from ..domains.d01.identity_v3 import decode_semantic_identity_v3
                for block in revision_value["blocks"]:
                    if block["kind"]=="semantic_identity":
                        semantic=decode_semantic_identity_v3(block["claim"])
                        if semantic is not None:
                            roots.extend(semantic.support_original_refs)
                            if semantic.plasticity_policy_ref:originals.append(semantic.plasticity_policy_ref)
            history=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=? AND valid=1",(token,revision)).fetchone()
            if history is None:continue
            adopted=read_adopted_domain_operation_v1(db,namespace,history[0])
            if adopted is None or adopted["domain"]!="d01" or adopted["operation_kind"]!="adopt_growth":continue
            prior=adopted["payload"]["request"]
            intent=raw_registered_input_v1(db,TABLE,namespace,prior["growth_proposal_ref"])
            if intent is None or intent.get("schema")!="d01.growth-intent.v2":continue
            originals.extend((prior["growth_proposal_ref"],prior["counterevidence_query_ref"],
                intent["plasticity_policy_ref"],intent["observer_policy_ref"],intent["continuity_interpretation_ref"]))
            roots.extend(intent["evidence_source_refs"])
            counter=raw_registered_input_v1(db,TABLE,namespace,prior["counterevidence_query_ref"])
            if counter:roots.extend((*counter["evidence_source_refs"],*counter["counterevidence_source_refs"]))
            for ref in prior["trial_original_refs"]:
                originals.append(ref);trial=raw_registered_input_v1(db,TABLE,namespace,ref)
                if trial and trial.get("schema")=="d01.growth-trial.v2":
                    originals.append(trial["trial_start_ref"])
                    for outcome in trial["settled_outcome_refs"]:
                        actual=read_plan_current_domain_input_v1(db,namespace=namespace,activity_id=activity_id,
                            producer_kind="derive_growth_trial",request=DeriveCurrentGrowthTrialInputRequestV1(ref,prior["growth_proposal_ref"],outcome))
                        types.extend(actual.fixed_type_ids);keys.extend(actual.exact_keys)
                        roots.extend(actual.source_roots);originals.extend(actual.required_original_refs)
    else:
        raise ValueError("unregistered exact D01 production request")
    if "d07.current_interpretation.v1" in types and operation_kind == "evaluate_values":
        condition_keys, condition_roots, condition_originals = method_condition_read_inputs_v1(db, namespace,
            tuple(key for key in keys if key.type_name == "d08.goal.v1"))
        keys.extend(condition_keys)
        roots.extend(condition_roots)
        originals.extend(condition_originals)
        from .d01_method_learning_v1 import method_trial_read_inputs_v1
        trial_types, trial_keys, trial_roots, trial_originals = method_trial_read_inputs_v1(db, namespace)
        types.extend(trial_types); keys.extend(trial_keys); roots.extend(trial_roots); originals.extend(trial_originals)
    if operation_kind in {"adopt_growth","project_self_model_v3","migrate_semantic_identity_v3"}:
        from ..domains.d01.identity_v3 import decode_semantic_identity_v3
        rows=read_graph_rows_v3(db, ('value',), where="bot=? AND persona=? AND type_name='d01.persona_plan.v1' AND valid=1", parameters=namespace.as_tuple, history=False, order_by=('token',), limit=129)
        if len(rows)>128:raise MissingProductionOriginalV1("bounded_semantic_persona_plan_inventory")
        for row in rows:
            for block in json.loads(row[0])["blocks"]:
                if block["kind"]!="semantic_identity":continue
                value=decode_semantic_identity_v3(block["claim"])
                if value is not None:
                    roots.extend(value.support_original_refs)
                    if value.plasticity_policy_ref:originals.append(value.plasticity_policy_ref)
        if operation_kind=="adopt_growth":
            intent=raw_registered_input_v1(db,TABLE,namespace,request.growth_proposal_ref)
            if intent and intent.get("schema")=="d01.growth-intent.v2":
                types.append("d07.current_interpretation.v1")
                keys.append(AtomKey.from_token(intent["continuity_interpretation_ref"]))
                originals.extend((intent["plasticity_policy_ref"],intent["observer_policy_ref"],intent["continuity_interpretation_ref"]))
                scope="d01.growth:"+intent["target_block"]+":core"
                relevant=read_graph_rows_v3(db, ('token', 'value'), where="bot=? AND persona=? AND type_name='d07.current_interpretation.v1' AND valid=1", parameters=namespace.as_tuple, history=False, order_by=('token',), limit=129)
                if len(relevant)>128:raise MissingProductionOriginalV1("complete_current_deep_counter_scope_inventory")
                for ref,encoded in relevant:
                    value=json.loads(encoded)
                    if value.get("question_key")==scope and value.get("current") is True:
                        originals.append(ref);roots.extend(value["source_refs"])
                continuity=raw_head_value_v1(db,namespace,AtomKey.from_token(intent["continuity_interpretation_ref"]))
                if continuity:roots.extend(continuity["source_refs"])
                for ref in request.trial_original_refs:
                    trial=raw_registered_input_v1(db,TABLE,namespace,ref)
                    if trial and trial.get("schema")=="d01.growth-trial.v2":
                        originals.append(trial["trial_start_ref"])
                        start=raw_registered_input_v1(db,TABLE,namespace,trial["trial_start_ref"])
                        if start:
                            planned_key=AtomKey.from_token(start["planned_progress_ref"])
                            keys.append(planned_key)
                            if planned_key.type_name=="d08.action_intent.v1":types.extend(("d08.goal.v1","d08.personal_plan.v1"))
                        from .domain_production_inputs_v1 import read_plan_current_domain_input_v1, DeriveCurrentGrowthTrialInputRequestV1
                        for outcome_ref in trial["settled_outcome_refs"]:
                            actual_plan=read_plan_current_domain_input_v1(db,namespace=namespace,activity_id=activity_id,
                                producer_kind="derive_growth_trial",request=DeriveCurrentGrowthTrialInputRequestV1(ref,request.growth_proposal_ref,outcome_ref))
                            types.extend(actual_plan.fixed_type_ids);keys.extend(actual_plan.exact_keys)
                            roots.extend(actual_plan.source_roots);originals.extend(actual_plan.required_original_refs)
    if operation_kind=="evaluate_values":
        from ..domains.d01.identity_v3 import decode_semantic_identity_v3
        plans=db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.persona_plan.v1' "
            "AND valid=1 ORDER BY token LIMIT 129",namespace.as_tuple).fetchall()
        if len(plans)>128:raise MissingProductionOriginalV1("bounded_current_persona_projection_inventory")
        if any(block["kind"]=="semantic_identity" and decode_semantic_identity_v3(block["claim"]) is not None
                for row in plans for block in json.loads(row[0])["blocks"]):
            qualified=read_plan_current_d01_operation_v1(db,namespace=namespace,activity_id=activity_id,
                operation_kind="project_self_model_v3",request=ProjectSelfModelRequestV3())
            types.extend(qualified.fixed_type_ids);keys.extend(qualified.exact_keys)
            roots.extend(qualified.source_roots);originals.extend(qualified.required_original_refs)
    return production_read_plan_v1(types, keys, roots, originals)


def read_adopted_outbound_observation_original_v1(db, ns, ref):
    """Read the exact immutable original; current content authorization stays in the frame reader."""
    if not table_exists_v1(db, "graph_d13_outbound_observations_v1"):
        raise MissingProductionOriginalV1("durable_original_outbound_observation")
    rows = db.execute("SELECT final_operation_id,observation_digest,source_ref,observation_json,original_json,original_digest "
        "FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? "
        "AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3",
        (*ns.as_tuple, ref, ref, ref)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("unique_original_outbound_observation:" + ref)
    operation, observation_digest, source_ref, encoded, original_json, digest = rows[0]
    from ..authority_service.v2_contract import MutationReceiptV2, from_wire
    observation = from_wire(json.loads(encoded))
    original = json.loads(original_json)
    platform = observation.pending.platform_observation if type(observation) is MutationReceiptV2 else None
    binding = platform.binding if platform is not None else None
    origin = getattr(binding, "origin", binding)
    if (type(observation) is not MutationReceiptV2 or observation.durable_state != "committed"
            or canonical_digest(observation) != observation_digest
            or canonical_digest(original) != digest or original["observation_digest"] != observation_digest
            or original["source_ref"] != source_ref
            or observation.pending.phase != "observed"
            or origin is None or origin.operation_id != operation):
        raise ValueError("actual adopted outbound observation identity changed")
    return observation, ProductionOriginalRefV1("d11.outbound_observation", ref, observation_digest), source_ref


from ..domains.d01.identity_v3 import IdentityPlasticityPolicyV3, SemanticIdentityRevisionRefV3
from ..domains.d01.production_operations_v1 import MigrateSemanticIdentityRequestV3, ProjectSelfModelRequestV3

@dataclass(frozen=True, slots=True)
class GrowthIntentOriginalV2(GrowthIntentOriginalV1):
    semantic_base_revision_ref: SemanticIdentityRevisionRefV3
    plasticity_policy_ref: str
    plasticity_policy_digest: str
    continuity_anchor: GraphVersion
    scope_refs: tuple[str, ...]
    exclusion_refs: tuple[str, ...]
    observer_policy_ref: str
    observer_policy_digest: str
    valid_from: float
    valid_until: float
    rollback_predicate_refs: tuple[str, ...]
    continuity_interpretation_ref: str
    schema: str = "d01.growth-intent.v2"
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _text, _refs, _digest, _time_window
        if (self.schema!="d01.growth-intent.v2" or self.change_kind!="core"
                or type(self.semantic_base_revision_ref) is not SemanticIdentityRevisionRefV3
                or self.semantic_base_revision_ref.persona_head!=self.base_head
                or self.semantic_base_revision_ref.block_id!=self.target_block or type(self.continuity_anchor) is not GraphVersion):
            raise ValueError("semantic growth V2 requires exact core identity base")
        for value in (self.proposal_id,self.target_block,self.replacement_claim,self.plasticity_policy_ref,self.observer_policy_ref,self.trigger_original_ref,self.continuity_interpretation_ref):_text(value)
        for value in (self.plasticity_policy_digest,self.observer_policy_digest):_digest(value)
        for value in (self.evidence_source_refs,self.required_trial_refs,self.scope_refs,self.exclusion_refs,self.rollback_predicate_refs):_refs(value)
        if not 1<=len(self.required_trial_refs)<=3 or not self.evidence_source_refs or not self.scope_refs:
            raise ValueError("semantic V2 intent must retain explicit support, scope and bounded trials")
        _time_window(self.valid_from,self.valid_until)

@dataclass(frozen=True, slots=True)
class IdentityTrialStartV3:
    growth_proposal_ref: str
    completed_trial_ref: str
    planned_progress_ref: str
    base_persona_head: str
    policy_ref: str
    policy_digest: str
    clock_mapping_ref: str
    clock_mapping_version: int
    clock_original_digest: str
    started_at_utc: float
    started_role_cursor: str
    observation_role_deadline: str
    planned_progress_head: GraphVersion
    planned_progress_digest: str
    schema: str = "d01.identity-trial-start.v3"
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _text, _digest, _decimal, _time_window
        for value in (self.growth_proposal_ref,self.completed_trial_ref,self.planned_progress_ref,self.base_persona_head,self.policy_ref,self.clock_mapping_ref):_text(value)
        for value in (self.policy_digest,self.clock_original_digest,self.planned_progress_digest):_digest(value)
        if (self.schema!="d01.identity-trial-start.v3" or type(self.clock_mapping_version) is not int or self.clock_mapping_version<1
                or type(self.planned_progress_head) is not GraphVersion or self.planned_progress_head.revision<1
                or self.planned_progress_head.key.token!=self.planned_progress_ref
                or not 0<_decimal(self.observation_role_deadline)-_decimal(self.started_role_cursor)<=1209600):
            raise ValueError("identity trial keeps exact adopted plan and bounded original role clock")
        _time_window(self.started_at_utc,None)

@dataclass(frozen=True, slots=True)
class GrowthTrialOriginalV2(GrowthTrialOriginalV1):
    trial_start_ref: str
    schema: str = "d01.growth-trial.v2"
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _text, _refs
        _text(self.growth_proposal_ref);_text(self.trial_start_ref);_refs(self.settled_outcome_refs);_refs(self.evidence_source_refs)
        if self.schema!="d01.growth-trial.v2" or self.completed is not True or not self.settled_outcome_refs:
            raise ValueError("semantic trial V2 requires actual completed outcomes")

@dataclass(frozen=True, slots=True)
class RegisterIdentityPlasticityPolicyRequestV3:
    policy: IdentityPlasticityPolicyV3

@dataclass(frozen=True, slots=True)
class PrepareSemanticGrowthInputRequestV3:
    interpretation_ref: str
    trigger_original_ref: str
    growth_proposal_ref: str
    counterevidence_query_ref: str
    required_trial_refs: tuple[str, ...]
    plasticity_policy_ref: str
    continuity_interpretation_ref: str
    rollback_predicate_refs: tuple[str, ...] = ()
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _text, _refs
        for value in (self.interpretation_ref,self.trigger_original_ref,self.growth_proposal_ref,self.counterevidence_query_ref,self.plasticity_policy_ref,self.continuity_interpretation_ref):_text(value)
        _refs(self.required_trial_refs);_refs(self.rollback_predicate_refs)
        if not 1<=len(self.required_trial_refs)<=3:raise ValueError("explicit bounded semantic trials required")

@dataclass(frozen=True, slots=True)
class StartSemanticGrowthTrialRequestV3:
    original_ref: str
    growth_proposal_ref: str
    completed_trial_ref: str
    planned_progress_ref: str
    def __post_init__(self):
        from ..domains.d01.identity_v3 import _text
        for value in (self.original_ref,self.growth_proposal_ref,self.completed_trial_ref,self.planned_progress_ref):_text(value)
        if self.original_ref==self.completed_trial_ref:raise ValueError("trial start and completion are distinct originals")

_ORIGINAL_TYPES.update({"growth_proposal_v2":GrowthIntentOriginalV2,"growth_trial_v2":GrowthTrialOriginalV2,
    "identity_plasticity_policy_v3":IdentityPlasticityPolicyV3,"identity_trial_start_v3":IdentityTrialStartV3})
KINDS=frozenset(_ORIGINAL_TYPES)


def _actual_trial_plan_matches_v3(planned_ref, atom):
    key=AtomKey.from_token(planned_ref)
    if atom.key.type_name=="d08.action_outcome.v1":
        return key.type_name=="d08.action_intent.v1" and key.name==atom.value["action_id"]
    if atom.key.type_name=="d10.life_progress.v1":
        return planned_ref==atom.value["project_ref"]
    raise ValueError("deep identity trial outcome has another domain")


def _stage_migrate_semantic_identity_v3(db, *, frame, request, installed_readers):
    from ..domains.d01 import PersonaBlock, PersonaRevision, ContinuityRecord, GrowthAdoptionCandidate
    from ..domains.d01.identity_v3 import RuntimeIdentityRef, SemanticIdentityRevision, decode_semantic_identity_v3, encode_semantic_identity_v3
    if type(request) is not MigrateSemanticIdentityRequestV3 or type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("exact installed D01 semantic migration request/reader required")
    read=CurrentDomainReadV1(frame);read.check(db);domain=PersonaDomain();ns=frame.envelope.authority.namespace
    active=domain.resolve_active_role(frame.snapshot,namespace=ns,current_guard=installed_readers.owner_guard)
    current=read.head(db,request.expected_plan_head.key,required=True)
    if GraphVersion(current.key,current.revision)!=request.expected_plan_head or active.head_id!=request.expected_persona_head_id:
        raise ValueError("semantic migration exact persona base changed")
    runtime=RuntimeIdentityRef.from_owner_guard(ns,installed_readers.owner_guard)
    policy=None;originals=[]
    if request.plasticity_policy_ref is not None:
        policy,original=installed_readers._identity_policy_v3(db,read,request.plasticity_policy_ref)
        originals.append(original)
        if not set(request.target_block_ids)<=set(policy.target_block_ids):raise ValueError("migration policy excludes target")
    targets={block.block_id:block for block in active.plan.blocks if block.kind=="semantic_identity"}
    if not set(request.target_block_ids)<=set(targets):raise ValueError("semantic migration target is not current semantic block")
    changed={}
    for block_id in request.target_block_ids:
        block=targets[block_id]
        previous=decode_semantic_identity_v3(block.claim)
        if previous is not None:
            if policy is None or previous.runtime_identity!=runtime:
                raise ValueError("existing semantic V3 requires an explicit signed administrative policy transition")
            from ..domains.d01.identity_v3 import SemanticIdentityRevisionRefV3
            payload=replace(previous,revision=previous.revision+1,
                previous_revision=SemanticIdentityRevisionRefV3(active.head_id,block_id,previous.revision,canonical_digest(block.claim)),
                changed_from_claim_digest=canonical_digest(previous.claim),plasticity_policy_ref=policy.policy_ref,
                plasticity_policy_digest=canonical_digest(plain_v1(policy)),scope_refs=policy.scope_refs,
                exclusion_refs=policy.exclusion_refs,valid_from=frame.now_utc,valid_until=policy.readout_valid_until_utc,revision_kind="administrative",adopt_before=None)
            changed[block_id]=PersonaBlock(block_id,block.kind,encode_semantic_identity_v3(payload),policy.mode)
            continue
        payload=SemanticIdentityRevision(runtime,block_id,1,block.claim,None,request.expected_plan_head,
            request.expected_plan_head,canonical_digest(block.claim),(),None if policy is None else policy.policy_ref,
            None if policy is None else canonical_digest(plain_v1(policy)),(),None,None,(),
            () if policy is None else policy.scope_refs,() if policy is None else policy.exclusion_refs,
            frame.now_utc,None if policy is None else policy.readout_valid_until_utc,"legacy_migration")
        changed[block_id]=PersonaBlock(block_id,block.kind,encode_semantic_identity_v3(payload),
            block.plasticity if policy is None else policy.mode)
    blocks=tuple(changed.get(block.block_id,block) for block in active.plan.blocks)
    migration_id="semantic-migration:"+canonical_digest(plain_v1(request))[:48]
    plan=replace(active.plan,version=active.plan.version+1,blocks=blocks)
    revision=PersonaRevision(migration_id,active.head_id,plan.head_id,blocks,
        ContinuityRecord(active.head_id,tuple(block.block_id for block in active.plan.blocks if block.block_id not in changed),
            ",".join(request.target_block_ids),()))
    writes=(domain.plan_write(plan),domain.revision_write(ns,revision),
        domain.activation_write(plan,read.head(db,owner_grant_key(*ns.as_tuple),required=True),installed_readers.owner_guard))
    candidate=GrowthAdoptionCandidate(plan.head_id,revision,writes,frame.snapshot.versions)
    return verify_d01_production_stage_v1(stage_result_v1(frame,"d01","migrate_semantic_identity_v3",request,
        writes=writes,provenance={"candidate":candidate,"originals":tuple(originals)},
        receiver_events=(("d08","persona_schema_migrated"),("d10","persona_schema_migrated")),
        proposal_schema="d01.proposal.v1",proposal_hash=domain.descriptor.request_schema_hash))


def stage_project_self_model_v3(db, *, frame, request, installed_readers):
    if type(request) is not ProjectSelfModelRequestV3 or type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("exact installed D01 self projection required")
    try:
        result=installed_readers.read_self_model_v3(db,frame,request)
        stage=stage_result_v1(frame,"d01","project_self_model_v3",request,provenance={"self_model":result})
    except MissingProductionOriginalV1 as missing:
        stage=waiting_stage_v1(frame,"d01","project_self_model_v3",request,missing)
    return verify_d01_production_stage_v1(stage)


from ..domains.d01.identity_v3 import IdentityTrialObservationPolicyV3

@dataclass(frozen=True, slots=True)
class RegisterIdentityTrialObserverPolicyRequestV3:
    policy: IdentityTrialObservationPolicyV3

_ORIGINAL_TYPES["identity_trial_observation_policy_v3"]=IdentityTrialObservationPolicyV3
KINDS=frozenset(_ORIGINAL_TYPES)


def stage_migrate_semantic_identity_v3(db, *, frame, request, installed_readers):
    try:
        return _stage_migrate_semantic_identity_v3(db,frame=frame,request=request,installed_readers=installed_readers)
    except MissingProductionOriginalV1 as missing:
        return verify_d01_production_stage_v1(waiting_stage_v1(frame,"d01","migrate_semantic_identity_v3",request,missing))


IDENTITY_INPUT_KINDS_V3=frozenset({"register_identity_plasticity_policy_v3","register_identity_trial_observer_policy_v3",
    "prepare_semantic_growth_input_v3","start_semantic_growth_trial_v3"})


def read_plan_identity_input_v3(db, *, namespace, producer_kind, request):
    types=["d01.persona_activation.v1","d01.persona_plan.v1","d01.persona_revision.v1"]
    keys=[owner_grant_key(*namespace.as_tuple)];roots=[];originals=[]
    if producer_kind in {"register_identity_plasticity_policy_v3","register_identity_trial_observer_policy_v3"}:
        if raw_registered_input_v1(db,TABLE,namespace,request.policy.policy_ref):originals.append(request.policy.policy_ref)
        keys.extend(AtomKey.from_token(ref) for ref in (*request.policy.scope_refs,*request.policy.exclusion_refs))
        if type(request.policy) is IdentityPlasticityPolicyV3:originals.append(request.policy.observer_policy_ref)
    elif producer_kind=="prepare_semantic_growth_input_v3":
        types.append("d07.current_interpretation.v1")
        keys.append(AtomKey.from_token(request.interpretation_ref))
        originals.extend((request.interpretation_ref,request.trigger_original_ref,request.plasticity_policy_ref))
        policy=raw_registered_input_v1(db,TABLE,namespace,request.plasticity_policy_ref)
        if policy:originals.append(policy["observer_policy_ref"])
        raw=raw_head_value_v1(db,namespace,AtomKey.from_token(request.interpretation_ref))
        if raw:roots.extend(raw["source_refs"])
    elif producer_kind=="start_semantic_growth_trial_v3":
        originals.extend((request.growth_proposal_ref,request.planned_progress_ref))
        planned_key=AtomKey.from_token(request.planned_progress_ref)
        keys.append(planned_key)
        types.append("d08.action_outcome.v1" if planned_key.type_name=="d08.action_intent.v1" else "d10.life_progress.v1")
        if planned_key.type_name=="d08.action_intent.v1":types.extend(("d08.goal.v1","d08.personal_plan.v1"))
        intent=raw_registered_input_v1(db,TABLE,namespace,request.growth_proposal_ref)
        if intent:
            originals.append(intent["plasticity_policy_ref"])
            policy=raw_registered_input_v1(db,TABLE,namespace,intent["plasticity_policy_ref"])
            if policy:originals.append(policy["observer_policy_ref"])
            roots.extend(intent["evidence_source_refs"])
        rows=db.execute("SELECT original_ref,payload_json FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='identity_trial_start_v3' "
            "ORDER BY original_ref LIMIT 129",namespace.as_tuple).fetchall()
        if len(rows)>128:raise MissingProductionOriginalV1("bounded_deep_identity_trial_inventory")
        for ref,encoded in rows:
            originals.append(ref)
            prior=json.loads(encoded)
            if raw_registered_input_v1(db,TABLE,namespace,prior["completed_trial_ref"]):originals.append(prior["completed_trial_ref"])
    else:raise ValueError("unregistered deep identity producer")
    return production_read_plan_v1(types,keys,roots,originals)


def _decode_identity_graph_version_v3(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,GraphVersion)


def semantic_counter_binding_v3(counter):
    from ..domains.d01.production_operations_v1 import SemanticCounterScopeV3
    if type(counter) is not SemanticCounterScopeV3 or not counter.complete:
        raise MissingProductionOriginalV1("complete_current_scoped_deep_counter_binding")
    return {"question_scope":counter.question_scope,"interpretation_versions":plain_v1(counter.interpretation_versions),
        "interpretation_digests":plain_v1(counter.interpretation_digests),"source_digests":plain_v1(counter.source_digests)}


from .d01_general_growth_v1 import (GeneralGrowthIntentOriginalV1,GeneralGrowthTrialStartV1,GeneralGrowthTrialOriginalV1)
_GENERAL_ORIGINAL_TYPES_V1={"general_growth_intent_v1":GeneralGrowthIntentOriginalV1,
    "general_growth_trial_start_v1":GeneralGrowthTrialStartV1,"general_growth_trial_v1":GeneralGrowthTrialOriginalV1}
KINDS=frozenset((*KINDS,*_GENERAL_ORIGINAL_TYPES_V1))
_ORIGINAL_TYPES.update(_GENERAL_ORIGINAL_TYPES_V1)
