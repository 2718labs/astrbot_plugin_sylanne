"""D07 uniquely adopts bounded C1 method candidates; no extra cognition call."""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d07 import (D07DomainProvider, CurrentInterpretationCandidate, Stance, EvidenceStatus,
    METHOD_CONDITION_IDS_V1, method_condition_question_v1)
from ..domains.d08.execution import _decode_goal
from ..graph_types import AtomKey, GraphVersion, Owner, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    production_read_plan_v1, waiting_stage_v1)
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read
from .issuers import D11BudgetJobIssuer

OPERATION = "adopt_current_c1_method_conditions_v1"
READINESS_OPERATION = "quote_current_method_choices_v1"
HARD_CONDITIONS = frozenset({"local_sample_permitted", "budget_deadline_feasible", "fact_permission_gap"})


@dataclass(frozen=True, slots=True)
class AdoptCurrentC1MethodConditionsRequestV1:
    c02_operation_id: str
    task_scope_ref: str
    goal_ref: str
    expected_goal_revision: int
    readiness_operation_id: str | None = None

    def __post_init__(self):
        if (type(self.c02_operation_id) is not str or not self.c02_operation_id
                or type(self.task_scope_ref) is not str or not self.task_scope_ref.startswith("artifact-task-scope:")
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or type(self.expected_goal_revision) is not int or self.expected_goal_revision < 1
                or self.readiness_operation_id is not None and (type(self.readiness_operation_id) is not str or not self.readiness_operation_id)):
            raise ValueError("method conditions require actual C02/task/Goal selectors")


class InstalledD07MethodConditionReadersV1:
    def __init__(self, *, issuer, installed_bundle=None):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("method conditions require the installed original issuer")
        self.issuer = issuer
        self.installed_bundle = installed_bundle


def _condition_key(namespace, activity_id, goal_ref, goal_revision, condition_id):
    identity = "d07-method-condition:" + canonical_digest((namespace, goal_ref, goal_revision, condition_id))[:48]
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d07.current_interpretation.v1", identity)


def _task_material(db, namespace, request, issuer):
    from .c1_artifact_task_intent_v1 import read_c1_method_context_original_v1
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV1,
        IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3, _decode, task_scope_ref_v1)
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    actual = read_c1_method_context_original_v1(db, namespace=namespace,
        c02_operation_id=request.c02_operation_id, issuer=issuer)
    if actual is None:
        raise MissingProductionOriginalV1("actual_versioned_C1_method_context_original")
    c1, candidate, source = actual
    scope_row = _read(db, issuer=issuer, namespace=namespace, kind="artifact_task_scope", ref=request.task_scope_ref)
    if scope_row is None:
        raise MissingProductionOriginalV1("actual_current_method_task_scope")
    scope = _decode(scope_row[0], IngressArtifactTaskScopeOriginalV1)
    if (scope.c02_operation_id != request.c02_operation_id or scope.namespace != namespace
            or scope.source_ref != c1.source_ref or scope.source_revision != c1.source_revision
            or scope.source_digest != c1.source_digest or scope.c1_intent_digest != canonical_digest(plain_v1(c1))
            or task_scope_ref_v1(scope.root.registration_ref) != request.task_scope_ref):
        raise ValueError("method C1 candidate cannot be assigned to another task scope")
    if type(scope) not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
        raise MissingProductionOriginalV1("actual_approved_method_task_scope")
    goal_key = AtomKey.from_token(request.goal_ref)
    if NamespaceId.from_key(goal_key) != namespace:
        raise ValueError("method Goal crossed namespace")
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (goal_key.token, *namespace.as_tuple)).fetchone()
    if row is None or row[2] != 1 or row[0] != request.expected_goal_revision:
        raise MissingProductionOriginalV1("actual_current_method_Goal_revision")
    goal = _decode_goal(json.loads(row[1]))
    objective_ref, objective = require_artifact_task_objective_original_v1(db, namespace=namespace,
        goal_ref=request.goal_ref, goal=goal, issuer=issuer)
    if (scope.objective_ref != objective_ref or scope.objective_digest != canonical_digest(objective)
            or goal.state != "active" or goal.revision != request.expected_goal_revision
            or (scope.task_kind != "continue" and objective["initial_c02_operation_id"] != request.c02_operation_id)):
        raise ValueError("method conditions do not belong to the actual active task Goal")
    return c1, candidate, source, scope, scope_row[1], objective_ref, objective, goal


def _read_readiness(db, read, request, *, scope, goal, issuer):
    """D02's prospective paired-count original is a hard predicate, never a C1 boolean."""
    if request.readiness_operation_id is None:
        return {}, None, ()
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, request.readiness_operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d02", READINESS_OPERATION):
        raise MissingProductionOriginalV1("actual_prospective_D02_method_readiness_original")
    from .d02_method_readiness_v1 import require_current_method_readiness_v1
    require_current_method_readiness_v1(db, frame=read.frame, operation_id=request.readiness_operation_id,
        issuer=issuer)
    payload = original["payload"]
    value = payload["provenance"].get("method_readiness")
    expected = {"schema", "c02_operation_id", "task_scope_ref", "task_scope_digest", "goal_ref", "goal_revision",
        "parent_budget_lease_ref", "valid_until_utc", "candidate_method_refs", "condition_values", "quote_original_refs"}
    if (type(value) is not dict or set(value) != expected or value["schema"] != "d02.method-readiness.v1"
            or value["c02_operation_id"] != request.c02_operation_id or value["task_scope_ref"] != request.task_scope_ref
            or value["task_scope_digest"] != canonical_digest(plain_v1(scope))
            or (value["goal_ref"], value["goal_revision"]) != (request.goal_ref, goal.revision)
            or value["parent_budget_lease_ref"] != read.frame.envelope.parent_budget_lease_ref
            or payload["coverage"] != "complete" or payload["owner_guard"] != plain_v1(read.frame.owner_guard)
            or read.frame.now_utc >= value["valid_until_utc"]):
        raise MissingProductionOriginalV1("current_same_task_parent_method_readiness")
    from ..domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
    if (set(value["candidate_method_refs"]) != {FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1}
            or set(value["condition_values"]) != HARD_CONDITIONS
            or any(type(v) is not bool for v in value["condition_values"].values())
            or type(value["quote_original_refs"]) is not list or not 1 <= len(value["quote_original_refs"]) <= 8):
        raise ValueError("D02 readiness does not cover both exact methods and mandatory predicates")
    current = {version.key: version.revision for version in read.frame.snapshot.versions}
    for version in original["read_versions"]:
        if current.get(version.key) != version.revision:
            raise MissingProductionOriginalV1("current_method_readiness_input_versions")
    for ref in value["quote_original_refs"]:
        read.original(ref)
    read.original("d02-current:" + original["original_digest"][:48],
        kind="d02.current-" + READINESS_OPERATION, digest=original["original_digest"])
    return value["condition_values"], original["original_digest"], original["read_versions"]


def stage_adopt_current_c1_method_conditions_v1(db, *, frame, request, installed_readers):
    if type(request) is not AdoptCurrentC1MethodConditionsRequestV1 or type(installed_readers) is not InstalledD07MethodConditionReadersV1:
        raise TypeError("exact installed C1 method condition operation required")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        ns = frame.envelope.authority.namespace
        c1, candidate, source, scope, scope_producer, objective_ref, objective, goal = _task_material(db, ns, request, installed_readers.issuer)
        from datetime import datetime
        from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
        from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
        authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=ns,scope=scope,
            objective=_decode(objective,ArtifactTaskObjectiveV1),issuer=installed_readers.issuer,
            bundle=installed_readers.installed_bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
            parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref)
        grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
        if ((scope.root.owner_grant_ref, scope.root.owner_grant_revision, scope.root.owner_grant_digest) !=
                (grant.key.token, grant.revision, canonical_digest(grant.value))
                or frame.now_utc >= min(datetime.fromisoformat(scope.root.valid_until_utc.replace("Z", "+00:00")).timestamp(), authorization_deadline)):
            raise MissingProductionOriginalV1("current_owner_and_original_method_task_deadline")
        source_atom = read.head(db, c1.source_ref, required=True)
        if source_atom.revision != c1.source_revision or canonical_digest(source_atom.value) != c1.source_digest:
            raise MissingProductionOriginalV1("current_C1_method_Source_version")
        sources = read.source_family(db, (c1.source_ref,), purpose="consolidation")
        read.head(db, request.goal_ref, required=True)
        read.committed_operation(db, scope_producer)
        from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
        read.original(c1_task_intent_ref_v1(ns, request.c02_operation_id), kind="d11.life_c1_task_intent", digest=canonical_digest(plain_v1(c1)))
        read.original(request.task_scope_ref, kind="d11.life_artifact_task_scope", digest=canonical_digest(plain_v1(scope)))
        read.original(objective_ref, kind="d11.life_artifact_task_objective", digest=canonical_digest(objective))
        readiness, readiness_digest, readiness_versions = _read_readiness(db, read, request, scope=scope, goal=goal, issuer=installed_readers.issuer)
        candidates = {row.condition_id: row for row in candidate.conditions}
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        dependencies = tuple(dict.fromkeys((AtomKey.from_token(request.goal_ref), *(key for ref, record in sources.items()
            for key in (AtomKey.from_token(ref), access_key(*ns.as_tuple, record.source_id), source_correction_head_key(ns, record.source_id))),
            *(v.key for v in readiness_versions))))
        writes, conclusions = [], []
        for condition in METHOD_CONDITION_IDS_V1:
            proposed = candidates.get(condition)
            if condition in HARD_CONDITIONS:
                value = "unknown" if condition not in readiness else ("true" if readiness[condition] else "false")
                unknowns = ("current_physical_method_readiness",) if value == "unknown" else ()
            elif proposed is None:
                value, unknowns = "unknown", ("missing_C1_method_condition",)
            elif proposed.meaningful_unknowns or proposed.counter_spans or proposed.proposed_value == "unknown" or not proposed.support_spans:
                value, unknowns = "unknown", tuple(proposed.meaningful_unknowns) or ("unresolved_C1_method_evidence",)
            else:
                value, unknowns = proposed.proposed_value, ()
            key = _condition_key(ns, frame.envelope.identity.activity_id, request.goal_ref, goal.revision, condition)
            prior = read.head(db, key)
            item = CurrentInterpretationCandidate(key.name, frame.envelope.identity.activity_id,
                method_condition_question_v1(request.goal_ref, goal.revision, condition), value,
                Stance.SUSPEND if unknowns else Stance.SUPPORT, 0.0,
                EvidenceStatus.INSUFFICIENT if unknowns else EvidenceStatus.SUPPORTED,
                (c1.source_ref,), (source.provenance_root,), unknowns)
            write = D07DomainProvider.current_interpretation_write(frame.envelope, item,
                source_dependencies=(AtomKey.from_token(c1.source_ref),))
            if not prior.valid or prior.value != write.value:
                writes.append(replace(write, dependencies=dependencies))
            conclusions.append((key.token, condition, value))
        provider = D07DomainProvider()
        return stage_result_v1(frame, "d07", OPERATION, request, writes=tuple(writes),
            provenance={"conditioned_source_roots":frame.envelope.source_qualification.source_refs,"conditioned_original_deadline_utc":frame.envelope.deadline_utc,
                "c1_original_ref": c1_task_intent_ref_v1(ns, request.c02_operation_id),
                "c1_original_digest": canonical_digest(plain_v1(c1)), "task_scope_ref": request.task_scope_ref,
                "task_scope_digest": canonical_digest(plain_v1(scope)), "goal_ref": request.goal_ref,
                "goal_revision": goal.revision, "conditions": tuple(conclusions), "readiness_original_digest": readiness_digest,
                "additional_model_calls": 0, "subjective_confidence_origin": "not_requested_by_C1_schema"},
            receiver_events=(("d01", "method_conditions_changed"),("d07","conditioned_conditions_committed_v1")), proposal_schema="d07.proposal.v1",
            proposal_hash=provider.descriptor.request_schema_hash)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d07", OPERATION, request, missing)


def read_plan_current_c1_method_conditions_v1(db, *, namespace, activity_id, operation_kind, request, installed_readers):
    if operation_kind != OPERATION or type(request) is not AdoptCurrentC1MethodConditionsRequestV1:
        raise ValueError("registered method condition read operation required")
    c1, candidate, source, scope, producer, objective_ref, objective, goal = _task_material(db, namespace, request, installed_readers.issuer)
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    types = ["d07.current_interpretation.v1"]
    keys = [owner_grant_key(*namespace.as_tuple), AtomKey.from_token(c1.source_ref), AtomKey.from_token(request.goal_ref)]
    keys.extend(_condition_key(namespace, activity_id, request.goal_ref, goal.revision, condition) for condition in METHOD_CONDITION_IDS_V1)
    originals = [c1_task_intent_ref_v1(namespace, request.c02_operation_id), request.task_scope_ref, objective_ref]
    roots = [c1.source_ref]
    if request.readiness_operation_id is not None:
        original = read_adopted_domain_operation_v1(db, namespace, request.readiness_operation_id)
        if original is not None and (original["domain"], original["operation_kind"]) == ("d02", READINESS_OPERATION):
            keys.extend(v.key for v in original["read_versions"])
            types.extend(page["type_id"] for page in original["payload"]["query_coverage"])
            value = original["payload"]["provenance"].get("method_readiness", {})
            originals.extend(value.get("quote_original_refs", ()))
            evidence = original["payload"]["provenance"].get("method_quote_evidence", {})
            originals.extend(choice["first_phase_price"]["original"]["original_ref"] for choice in evidence.get("choices", ()))
            originals.append("d02-current:" + original["original_digest"][:48])
            roots.extend(v.key.token for v in original["read_versions"] if v.key.type_name == "memory.source")
    return production_read_plan_v1(tuple(dict.fromkeys(types)), tuple(dict.fromkeys(keys)),
        tuple(dict.fromkeys(roots)), tuple(dict.fromkeys(originals)))


def read_adopted_c1_method_condition_original_v1(db, *, namespace, ref):
    from ..runtime_storage_v3 import read_graph_head_v3, read_graph_history_v3
    key = AtomKey.from_token(ref)
    if key.type_name != "d07.current_interpretation.v1" or NamespaceId.from_key(key) != namespace:
        return None
    row = read_graph_head_v3(db, ref, namespace=namespace.as_tuple)
    if row is None or row[2] != 1: return None
    history = read_graph_history_v3(db, ref, row[0], columns=("event_id", "value", "valid"), namespace=namespace.as_tuple)
    if history is None or history[1:] != row[1:]: return None
    original = read_adopted_domain_operation_v1(db, namespace, history[0])
    if original is None or (original["domain"], original["operation_kind"]) != ("d07", OPERATION): return None
    value = json.loads(row[1]); provenance = original["payload"]["provenance"]
    if (not any(item[0] == ref and item[2] == value["proposition"] for item in provenance["conditions"])
            or not any(v.key == key and v.revision == row[0] for v in original["receipt"].write_versions)):
        raise ValueError("C1 method condition lacks its exact committed D07 member")
    return ProductionOriginalRefV1("d07.actual-c1-method-condition", ref, canonical_digest(value), (GraphVersion(key, row[0]),))