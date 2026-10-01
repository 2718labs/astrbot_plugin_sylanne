"""Current shared-DB reads for D01 value evaluation and natural growth.

Only installed readers are accepted here. Input originals are signed by D11
after their producing operation committed; hashes check integrity, not truth.
The current source/access/correction family closure is always reread in W01's
transaction. This module opens no database and never commits or calls RPC.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import sqlite3

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..domains.d01 import GrowthProposal, PersonaDomain
from ..domains.d01.production_operations_v1 import (
    AdoptCurrentGrowthRequestV1, CurrentGrowthInputsV1, CurrentValuesInputsV1,
    EvaluateCurrentValuesRequestV1, compile_adopt_current_growth_v1,
    compile_evaluate_current_values_v1, current_frame_guard_v1, plain_v1,
    stage_result_v1, verify_d01_production_stage_v1,
)
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
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
    def __init__(self, frame):
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
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token, *self.frame.envelope.authority.namespace.as_tuple)).fetchone()
        atom = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
        if self.frame.snapshot.get(key) != atom:
            raise ValueError("production dependency is not an exact frame read: " + key.type_name)
        if required and (not atom.valid or atom.revision < 1):
            raise MissingProductionOriginalV1("current_" + key.type_name + ":" + key.name)
        return atom

    def original(self, ref, *, kind=None, digest=None):
        matches = tuple(original for original in self.frame.observed_originals if original.original_ref == ref)
        if len(matches) != 1:
            raise MissingProductionOriginalV1("authenticated_original:" + ref)
        found = matches[0]
        if ((kind is not None and found.kind != kind)
                or (digest is not None and found.original_digest != digest)):
            raise ValueError("authenticated production original differs")
        return found

    def complete_inventory(self, db, type_name):
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
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                             (atom.key.token, atom.revision)).fetchone()
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
        if not table_exists_v1(db, "graph_d13_outbound_observations_v1"):
            raise MissingProductionOriginalV1("durable_original_outbound_observation")
        ns = self.frame.envelope.authority.namespace
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
        self.original(ref)
        self.source_family(db, (source_ref,))
        return observation, ProductionOriginalRefV1("d11.outbound_observation", ref, observation_digest)


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

    def __post_init__(self):
        if (type(self.candidates) is not tuple or not 1 <= len(self.candidates) <= 128
                or len({item[0] for item in self.candidates}) != len(self.candidates)
                or any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                       or not item[0] or type(item[1]) is not tuple or any(type(tag) is not str or not tag
                       for tag in item[1]) for item in self.candidates)
                or type(self.candidate_heads) is not tuple or len(self.candidate_heads) != len(self.candidates)
                or any(type(head) is not GraphVersion or head.revision < 1 for head in self.candidate_heads)):
            raise ValueError("values need a bounded exact frozen candidate set with real heads")


@dataclass(frozen=True, slots=True)
class FrozenValuesContextV1:
    context_tags: tuple[str, ...]
    context_heads: tuple[GraphVersion, ...]
    role_binding_complete: bool


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


class InstalledD01ProductionReadersV1:
    def __init__(self, *, issuer: D11BudgetJobIssuer, owner_guard: OwnerAuthorizationGuardV1):
        if type(issuer) is not D11BudgetJobIssuer or type(owner_guard) is not OwnerAuthorizationGuardV1:
            raise TypeError("D01 requires installed D11 signer and fresh Authority Owner guard")
        self.issuer, self.owner_guard = issuer, owner_guard

    def _read(self, db, read, ref, kind):
        if not table_exists_v1(db, TABLE):
            raise MissingProductionOriginalV1("d01_" + kind + "_original:" + ref)
        row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM "
            "graph_d01_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*read.frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("d01_" + kind + "_original:" + ref)
        if row[0] != kind:
            raise ValueError("D01 original kind differs")
        self.issuer._signer.verify(SIGN_KIND, row[2], row[4])
        value = json.loads(row[2])
        if canonical_serialize(value) != row[2] or canonical_digest(value) != row[3]:
            raise ValueError("D01 signed original bytes changed")
        read.committed_operation(db, row[1])
        original = read.original(ref, kind="d01." + kind, digest=row[3])
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
            for version in value.candidate_heads:
                atom = read.head(db, version.key, required=True)
                if atom.revision != version.revision or not version.key.type_name.startswith(("d07.", "d08.")):
                    raise ValueError("D01 candidates need exact current D07/D08 heads")
        elif kind == "values_context":
            if type(value.role_binding_complete) is not bool or not value.context_heads:
                raise ValueError("values context requires actual current scene heads")
            for version in value.context_heads:
                atom = read.head(db, version.key, required=True)
                if atom.revision != version.revision or not version.key.type_name.startswith("d03."):
                    raise ValueError("values context is not a current D03 original")
            if value.role_binding_complete and not any("role_binding" in version.key.type_name for version in value.context_heads):
                raise ValueError("social strategy completion requires actual D03 role resolution")
        elif kind == "growth_trial":
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
        return CurrentValuesInputsV1(active.plan, self.owner_guard,
            tuple((item[0], tuple(item[1])) for item in candidates["candidates"]),
            tuple(context["context_tags"]), context["role_binding_complete"], candidate_original, context_original)

    def read_growth(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        raw, original = self._read(db, read, request.growth_proposal_ref, "growth_proposal")
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
        return CurrentGrowthInputsV1(proposal, tuple(source.source_id for source in sources), self.owner_guard,
            tuple(originals), trials_complete, complete, conflict)

    def freeze_current_values_from_graph_v1(self, db, *, frame, producing_operation_id,
                                          candidate_set_ref, context_ref):
        """Concrete producer from the actual frozen D08 candidate inventory.

        Tags are registered ActionIntent fields. No prose interpretation or
        permission result is manufactured while assembling the values input.
        """
        read = CurrentDomainReadV1(frame)
        read.check(db)
        from ..domains.d08.execution import _decode_intent
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
        frozen = FrozenValuesCandidateSetV1(tuple(candidates), tuple(GraphVersion(atom.key, atom.revision) for atom in heads))
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
            tuple(GraphVersion(atom.key, atom.revision) for atom in contexts), False)
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
            original_ref, growth_proposal_ref, settled_progress_ref):
        """Derive completion from actual adopted progress, never a caller flag."""
        read = CurrentDomainReadV1(frame)
        read.check(db)
        self._read(db, read, growth_proposal_ref, "growth_proposal")
        atom = read.head(db, settled_progress_ref, required=True)
        read.original(settled_progress_ref)
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (atom.key.token, atom.revision)).fetchone()
        if history is None or history[2] != 1 or json.loads(history[1]) != atom.value:
            raise ValueError("growth trial progress lost its actual adopted history")
        read.committed_operation(db, history[0])
        if atom.key.type_name == "d10.life_progress.v1":
            from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            progress = decode_typed_production_value_v1(atom.value, LifeProgressHeadV1)
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
        value = GrowthTrialOriginalV1(growth_proposal_ref, outcomes, tuple(roots), True)
        return self.record_input(db, frame=frame, original_ref=original_ref,
            producing_operation_id=producing_operation_id, kind="growth_trial", value=value)


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
    row = db.execute("SELECT payload_json FROM " + table + " WHERE bot=? AND persona=? AND original_ref=?",
                     (*namespace.as_tuple, ref)).fetchone()
    return None if row is None else json.loads(row[0])


def raw_head_value_v1(db, namespace, key):
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("production read-plan key crossed namespace")
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone()
    return None if row is None or row[1] != 1 else json.loads(row[0])


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
                for head in (*raw.get("candidate_heads", ()), *raw.get("context_heads", ())):
                    key = AtomKey.from_token(head["key"])
                    keys.append(key)
                    value = raw_head_value_v1(db, namespace, key)
                    if value:
                        roots.extend(value.get("source_refs", ()))
    elif operation_kind == "adopt_growth" and type(request) is AdoptCurrentGrowthRequestV1:
        originals.extend((request.growth_proposal_ref, request.trigger_original_ref, request.counterevidence_query_ref,
                          *request.trial_original_refs))
        raw = raw_registered_input_v1(db, TABLE, namespace, request.growth_proposal_ref)
        if raw:
            roots.extend(raw["evidence_source_refs"])
            keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_revision.v1", raw["proposal_id"]))
            for ref in raw["evidence_source_refs"]:
                source = raw_head_value_v1(db, namespace, AtomKey.from_token(ref))
                if source:
                    contribution = PersonaDomain.contribution_key(raw["target_block"], source["provenance_root"], raw["change_kind"])
                    keys.append(AtomKey(Owner("persona", *namespace.as_tuple), "d01.growth_contribution.v1", contribution))
        for ref in (*request.trial_original_refs, request.counterevidence_query_ref):
            raw = raw_registered_input_v1(db, TABLE, namespace, ref)
            if raw:
                roots.extend((*raw.get("evidence_source_refs", ()), *raw.get("counterevidence_source_refs", ())))
                originals.extend(raw.get("settled_outcome_refs", ()))
    else:
        raise ValueError("unregistered exact D01 production request")
    return production_read_plan_v1(types, keys, roots, originals)
