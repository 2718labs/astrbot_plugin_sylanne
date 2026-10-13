"""D07 current-task-only history adoption from an actual C1 V4 and full ledger.

The original RecallNeed is preserved. This operation consumes no C3, grants no
permission and cannot change a task, Goal, budget, deadline or prior attempt.
"""
from dataclasses import dataclass, replace
from datetime import datetime
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d07 import IngressRecallNeedV1
from ..domains.d08.execution import _decode_goal
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1, ProductionOriginalRefV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d06_ingress_recall_v1 import (InstalledIngressRecallReadersV1, PrepareIngressRecallNeedRequestV1,
    LEDGER_TYPES, NEED_OPERATION, ingress_recall_need_operation_id_v1, read_plan_ingress_recall_need_v1,
    stage_ingress_recall_need_in_transaction_v1, read_adopted_ingress_recall_need_v1)
from .d11_life_preparation_v1 import _read

OPERATION = "adopt_current_task_no_search_v1"
SCHEMA = "d07.current-task-no-search.v1"


@dataclass(frozen=True, slots=True)
class AdoptCurrentTaskNoSearchRequestV1:
    c02_operation_id: str
    source_ref: str
    task_scope_ref: str
    goal_ref: str
    expected_goal_revision: int

    def __post_init__(self):
        if (type(self.c02_operation_id) is not str or not self.c02_operation_id
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or not self.task_scope_ref.startswith("artifact-task-scope:")
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or type(self.expected_goal_revision) is not int or self.expected_goal_revision < 1):
            raise ValueError("task no-search requires exact actual C02/Source/scope/Goal selectors")


@dataclass(frozen=True, slots=True)
class CurrentTaskNoSearchOriginalV1:
    namespace: NamespaceId
    request: AdoptCurrentTaskNoSearchRequestV1
    prior_need_ref: str
    prior_need_digest: str
    c1_original_ref: str
    c1_original_digest: str
    historical_candidate_digest: str
    task_scope_digest: str
    goal_head: GraphVersion
    goal_digest: str
    source_head: GraphVersion
    source_digest: str
    owner_guard: ProductionOwnerGuardV1
    need: IngressRecallNeedV1
    ledger_coverage: tuple[ProductionQueryCoverageV1, ...]
    original_deadline_utc: float
    adoption_operation_id: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.request) is not AdoptCurrentTaskNoSearchRequestV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1 or type(self.need) is not IngressRecallNeedV1
                or self.need.routing != "no_search" or self.need.triggers or self.need.required_checks or self.need.missing_items
                or self.need.c02_operation_id != self.request.c02_operation_id or self.need.source_ref != self.request.source_ref
                or self.goal_head.key.token != self.request.goal_ref or self.goal_head.revision != self.request.expected_goal_revision
                or self.source_head.key.token != self.request.source_ref or self.source_head.revision != self.need.source_revision
                or NamespaceId.from_key(self.goal_head.key) != self.namespace or NamespaceId.from_key(self.source_head.key) != self.namespace
                or type(self.ledger_coverage) is not tuple or {page.type_id for page in self.ledger_coverage} != set(LEDGER_TYPES)
                or len(self.ledger_coverage) != len(LEDGER_TYPES) or any(not page.complete for page in self.ledger_coverage)
                or self.adoption_operation_id != task_no_search_operation_id_v1(self.namespace, self.request.c02_operation_id)
                or self.original_deadline_utc > self.need.deadline_utc):
            raise ValueError("no-search is one bounded actual current-task D07 adoption with complete ledger evidence")
        for name in ("prior_need_digest", "c1_original_digest", "historical_candidate_digest", "task_scope_digest", "goal_digest", "source_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("no-search lost an exact original commitment")

    @property
    def digest(self): return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class CurrentTaskNoSearchDecisionV1:
    request: AdoptCurrentTaskNoSearchRequestV1
    c1_original_ref: str
    c1_original_digest: str
    historical_candidate_digest: str
    prior_need_ref: str
    prior_need_digest: str
    reason: str
    status: str = "not_applicable"
    schema: str = "d07.task-no-search-decision.v1"

    def __post_init__(self):
        if (self.schema != "d07.task-no-search-decision.v1" or self.status != "not_applicable"
                or type(self.request) is not AdoptCurrentTaskNoSearchRequestV1
                or self.reason not in {"requires_history", "unknown_history_dependency", "counterevidence", "missing_support"}):
            raise ValueError("closed current D07 non-adoption decision required")
        for value in (self.c1_original_digest, self.historical_candidate_digest, self.prior_need_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("non-adoption decision lost its real input originals")


def task_no_search_operation_id_v1(namespace, c02_operation_id):
    return "d07-task-no-search:" + canonical_digest((namespace, c02_operation_id))[:48]


def _prior_need(db, namespace, c02_operation_id):
    need = read_adopted_ingress_recall_need_v1(db, namespace=namespace, c02_operation_id=c02_operation_id)
    original = read_adopted_domain_operation_v1(db, namespace, ingress_recall_need_operation_id_v1(namespace, c02_operation_id))
    if need is None or original is None:
        raise MissingProductionOriginalV1("actual_prior_ingress_recall_need")
    if original["payload"]["coverage"] != "complete" or need.triggers or need.required_checks or need.missing_items:
        raise MissingProductionOriginalV1("complete_actual_task_ledger_without_required_checks_or_gaps")
    return need, original


def _no_prepared_c3(db, namespace, cycle_ref, activity_id, issuer):
    from .d07_execution_v1 import TABLE, read_prepared_d07_execution_v1
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND "
        "(json_extract(payload_json,'$.activity_id')=? OR json_extract(payload_json,'$.cycle_job_ref')=? "
        "OR json_extract(payload_json,'$.cycle_ref.key')=?) LIMIT 3", (*namespace.as_tuple, activity_id, cycle_ref, cycle_ref)).fetchall()
    for (ref,) in rows:
        if read_prepared_d07_execution_v1(db, issuer, namespace, ref) is not None:
            raise MissingProductionOriginalV1("task_no_search_cannot_hide_existing_actual_C3_preparation")


def _task_semantic_basis(db, *, namespace, request, issuer, require_no_search=True):
    from .c1_artifact_task_intent_v1 import read_c1_historical_dependency_original_v1, c1_task_intent_ref_v1
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1, IngressArtifactTaskScopeOriginalV2, _decode, task_scope_ref_v1
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    actual = read_c1_historical_dependency_original_v1(db, namespace=namespace, c02_operation_id=request.c02_operation_id, issuer=issuer)
    if actual is None: raise MissingProductionOriginalV1("actual_versioned_C1_historical_dependency_original")
    c1, candidate, source = actual
    if (candidate.intent_kind != "draft_then_corrected_revision" or c1.intent.kind != candidate.intent_kind
            or c1.source_ref != request.source_ref or require_no_search and (candidate.mode != "current_task_only"
                or candidate.counter_spans or candidate.meaningful_unknowns or not candidate.support_spans)):
        raise MissingProductionOriginalV1("explicit_grounded_new_task_only_historical_dependency")
    row = _read(db, issuer=issuer, namespace=namespace, kind="artifact_task_scope", ref=request.task_scope_ref)
    if row is None: raise MissingProductionOriginalV1("actual_approved_task_scope_before_no_search")
    scope = _decode(row[0], IngressArtifactTaskScopeOriginalV1)
    if (type(scope) is not IngressArtifactTaskScopeOriginalV2 or scope.task_kind != "draft_then_corrected_revision"
            or scope.c02_operation_id != request.c02_operation_id or scope.source_ref != request.source_ref
            or (scope.source_revision, scope.source_digest) != (c1.source_revision, c1.source_digest)
            or scope.c1_intent_digest != canonical_digest(plain_v1(c1))
            or request.task_scope_ref != task_scope_ref_v1(scope.root.registration_ref)):
        raise MissingProductionOriginalV1("same_actual_new_task_scope_C1_Source")
    goal_key = AtomKey.from_token(request.goal_ref)
    if NamespaceId.from_key(goal_key) != namespace: raise ValueError("no-search Goal crossed namespace")
    goal_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (request.goal_ref,)).fetchone()
    if goal_row is None or goal_row[2] != 1 or goal_row[0] != request.expected_goal_revision:
        raise MissingProductionOriginalV1("current_actual_task_no_search_Goal")
    goal = _decode_goal(json.loads(goal_row[1]))
    objective_ref, objective = require_artifact_task_objective_original_v1(db, namespace=namespace,
        goal_ref=request.goal_ref, goal=goal, issuer=issuer)
    if (goal.state != "active" or scope.objective_ref != objective_ref or scope.objective_digest != canonical_digest(objective)
            or objective["initial_c02_operation_id"] != request.c02_operation_id):
        raise MissingProductionOriginalV1("actual_new_active_task_objective_before_no_search")
    return c1, candidate, source, scope, objective_ref, objective


def stage_adopt_current_task_no_search_v1(db, *, frame, request, installed_readers):
    if type(request) is not AdoptCurrentTaskNoSearchRequestV1 or type(installed_readers) is not InstalledIngressRecallReadersV1:
        raise TypeError("exact actual installed D07 task no-search operation required")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db); ns = frame.envelope.authority.namespace
        if frame.envelope.identity.operation_id != task_no_search_operation_id_v1(ns, request.c02_operation_id):
            raise ValueError("no-search adoption cannot change its original deterministic operation")
        prior, original = _prior_need(db, ns, request.c02_operation_id)
        c1, candidate, _, scope, objective_ref, objective = _task_semantic_basis(db, namespace=ns, request=request, issuer=installed_readers.issuer, require_no_search=False)
        old_request = PrepareIngressRecallNeedRequestV1(prior.c02_operation_id, prior.source_ref, prior.cycle_job_ref, prior.policy_digest)
        current_stage = stage_ingress_recall_need_in_transaction_v1(db, frame=frame, request=old_request, installed_readers=installed_readers)
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        current_payload = json.loads(current_stage.original_payload_json)
        current = decode_typed_production_value_v1(current_payload["provenance"]["need"], IngressRecallNeedV1)
        if current != prior or current.triggers or current.required_checks or current.missing_items:
            raise MissingProductionOriginalV1("unchanged_complete_actual_ingress_ledger_before_no_search")
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
        from .jobs import get_job
        job = get_job(db, AtomKey.from_token(prior.cycle_job_ref).name)
        cycle = foreground_cycle_from_wire_v1(job.continuation)
        if any(attempt.slot == "C3" for attempt in cycle.call_plan.attempts):
            raise MissingProductionOriginalV1("task_no_search_cannot_erase_an_actual_C3_attempt")
        _no_prepared_c3(db, ns, prior.cycle_job_ref, job.activity_id, installed_readers.issuer)
        source = read.head(db, request.source_ref, required=True); goal = read.head(db, request.goal_ref, required=True)
        grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
        if ((source.revision, canonical_digest(source.value)) != (c1.source_revision, c1.source_digest)
                or (scope.root.owner_grant_ref, scope.root.owner_grant_revision, scope.root.owner_grant_digest) !=
                    (grant.key.token, grant.revision, canonical_digest(grant.value))):
            raise MissingProductionOriginalV1("current_same_Source_and_Owner_before_task_no_search")
        deadline = min(prior.deadline_utc, objective["valid_until_utc"],
            datetime.fromisoformat(scope.root.valid_until_utc.replace("Z", "+00:00")).timestamp())
        if frame.now_utc >= deadline: raise MissingProductionOriginalV1("original_task_no_search_deadline")
        from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
        c1_ref = c1_task_intent_ref_v1(ns, request.c02_operation_id)
        for ref, kind, digest in (("d07-current:" + original["original_digest"][:48], "d07.current-" + NEED_OPERATION, original["original_digest"]),
                (c1_ref, "d11.life_c1_task_intent", canonical_digest(plain_v1(c1))),
                (request.task_scope_ref, "d11.life_artifact_task_scope", canonical_digest(plain_v1(scope))),
                (objective_ref, "d11.life_artifact_task_objective", canonical_digest(objective))):
            read.original(ref, kind=kind, digest=digest)
        reason = ("requires_history" if candidate.mode == "requires_history" else
            "unknown_history_dependency" if candidate.mode == "unknown" or candidate.meaningful_unknowns else
            "counterevidence" if candidate.counter_spans else "missing_support" if not candidate.support_spans else None)
        if reason is not None:
            decision = CurrentTaskNoSearchDecisionV1(request, c1_ref, canonical_digest(plain_v1(c1)),
                canonical_digest(plain_v1(candidate)), "d07-current:" + original["original_digest"][:48], original["original_digest"], reason)
            return stage_result_v1(frame, "d07", OPERATION, request, provenance={"task_no_search_decision": decision})
        value = CurrentTaskNoSearchOriginalV1(ns, request, "d07-current:" + original["original_digest"][:48],
            original["original_digest"], c1_ref, canonical_digest(plain_v1(c1)), canonical_digest(plain_v1(candidate)),
            canonical_digest(plain_v1(scope)), GraphVersion(goal.key, goal.revision), canonical_digest(goal.value),
            GraphVersion(source.key, source.revision), canonical_digest(source.value), frame.owner_guard,
            replace(prior, routing="no_search"), tuple(page for page in frame.query_coverage if page.type_id in LEDGER_TYPES),
            deadline, frame.envelope.identity.operation_id)
        return stage_result_v1(frame, "d07", OPERATION, request, provenance={"task_no_search": value})
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d07", OPERATION, request, missing)


def read_plan_current_task_no_search_v1(db, *, namespace, activity_id, operation_kind, request, installed_readers):
    if operation_kind != OPERATION or type(request) is not AdoptCurrentTaskNoSearchRequestV1:
        raise TypeError("closed current task no-search read recipe required")
    prior, original = _prior_need(db, namespace, request.c02_operation_id)
    base = read_plan_ingress_recall_need_v1(db, namespace=namespace,
        request=PrepareIngressRecallNeedRequestV1(prior.c02_operation_id, prior.source_ref, prior.cycle_job_ref, prior.policy_digest),
        policy=installed_readers.installed_bundle.d06_recall)
    c1, _, _, scope, objective_ref, objective = _task_semantic_basis(db, namespace=namespace, request=request, issuer=installed_readers.issuer, require_no_search=False)
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    return production_read_plan_v1(base.fixed_type_ids,
        (*base.exact_keys, owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.goal_ref)),
        (*base.source_roots, request.source_ref), (*base.required_original_refs,
            "d07-current:" + original["original_digest"][:48], c1_task_intent_ref_v1(namespace, request.c02_operation_id),
            request.task_scope_ref, objective_ref))


def read_adopted_task_no_search_v1(db, *, namespace, c02_operation_id):
    original = read_adopted_domain_operation_v1(db, namespace, task_no_search_operation_id_v1(namespace, c02_operation_id))
    if original is None or original["payload"]["coverage"] != "complete": return None
    if (original["domain"], original["operation_kind"]) != ("d07", OPERATION):
        raise ValueError("task no-search original names another adopted operation")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if "task_no_search_decision" in original["payload"]["provenance"]:
        decode_typed_production_value_v1(original["payload"]["provenance"]["task_no_search_decision"], CurrentTaskNoSearchDecisionV1)
        return None
    value = decode_typed_production_value_v1(original["payload"]["provenance"]["task_no_search"], CurrentTaskNoSearchOriginalV1)
    if value.namespace != namespace or value.request.c02_operation_id != c02_operation_id:
        raise ValueError("task no-search original changed its actual C02 namespace")
    return value, original


def require_current_task_no_search_v1(db, *, frame, request, installed_readers):
    """Current read accepts cycle progress, never changed ledger/Goal/Source/Owner."""
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    found = read_adopted_task_no_search_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id)
    if found is None: raise MissingProductionOriginalV1("actual_adopted_task_no_search_original")
    value, original = found
    if value.request != request or value.owner_guard != frame.owner_guard or frame.now_utc >= value.original_deadline_utc:
        raise MissingProductionOriginalV1("current_same_task_no_search_scope_Owner_deadline")
    for version in original["read_versions"]:
        if version.key.token != value.need.cycle_job_ref and read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_task_no_search_hard_fact")
    for page in value.ledger_coverage:
        atoms = read.complete_inventory(db, page.type_id)
        if tuple(GraphVersion(atom.key, atom.revision) for atom in atoms) != page.row_versions:
            raise MissingProductionOriginalV1("complete_current_task_no_search_ledger")
    c1, candidate, _, scope, _, _ = _task_semantic_basis(db, namespace=ns, request=request, issuer=installed_readers.issuer)
    if (canonical_digest(plain_v1(c1)), canonical_digest(plain_v1(candidate)), canonical_digest(plain_v1(scope))) != (
            value.c1_original_digest, value.historical_candidate_digest, value.task_scope_digest):
        raise ValueError("current task no-search changed its actual semantic originals")
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, require_current_foreground_responsibility_v1
    from .d11_types import job_graph_write
    from .jobs import get_job
    job = get_job(db, AtomKey.from_token(value.need.cycle_job_ref).name)
    if read.head(db, value.need.cycle_job_ref, required=True).value != job_graph_write(job).value:
        raise MissingProductionOriginalV1("current_actual_task_no_search_cycle")
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    bundle = installed_readers.installed_bundle if type(installed_readers) is InstalledIngressRecallReadersV1 else installed_readers.current().bundle
    policy = bundle.d06_recall
    if policy is None or (policy.policy_ref, policy.policy_version, policy.policy_digest) != (
            value.need.policy_ref, value.need.policy_version, value.need.policy_digest):
        raise MissingProductionOriginalV1("current_installed_task_no_search_recall_policy")
    focus = read.head(db, value.need.focus_ref, required=True)
    ticket = read.head(db, value.need.attention_ticket_ref, required=True)
    if (focus.value["primary_ticket_ref"] != ticket.key.token or not ticket.value["eligible"]
            or not ticket.value["resources_available"] or ticket.value["cancel_refs"]
            or frame.now_utc >= ticket.value["valid_until"] or ticket.value["causal_root"] != request.source_ref):
        raise MissingProductionOriginalV1("current_task_no_search_attention")
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=job, installed_bundle=bundle,
        issuer=installed_readers.issuer, owner_guard=frame.owner_guard, purpose=frame.envelope.authority.purpose,
        audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
    if (responsibility is None or responsibility.digest != value.need.responsibility_digest
            or continuation.c02_operation_id != request.c02_operation_id or continuation.source_ref != request.source_ref
            or job.budget_ref != frame.envelope.parent_budget_lease_ref or job.cancel_epoch != value.need.cancel_generation
            or any(attempt.slot == "C3" for attempt in continuation.call_plan.attempts)):
        raise MissingProductionOriginalV1("current_task_no_search_responsibility_without_C3")
    _no_prepared_c3(db, ns, value.need.cycle_job_ref, job.activity_id, installed_readers.issuer)
    ref = "d07-current:" + original["original_digest"][:48]
    authenticated = read.original(ref, kind="d07.current-" + OPERATION, digest=original["original_digest"])
    return value, authenticated, original


@dataclass(frozen=True, slots=True)
class TaskNoSearchProbeV1:
    status: str
    reason: str | None
    request: AdoptCurrentTaskNoSearchRequestV1 | None

    def __post_init__(self):
        if (self.status not in {"candidate", "not_applicable"}
                or (self.status == "candidate") != (type(self.request) is AdoptCurrentTaskNoSearchRequestV1)
                or (self.status == "candidate") != (self.reason is None)):
            raise ValueError("closed metadata-only task history probe required")


def probe_task_no_search_metadata_v1(db, *, namespace, c02_operation_id, source_ref):
    """Caller first qualifies current Owner/Source/C09; SQL returns metadata only."""
    from ..model_broker.first_ingress_encoding import FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    row = db.execute("SELECT json_extract(evidence_json,'$.c1_task_result_v1.template_version'), "
        "json_type(json_extract(json_extract(evidence_json,'$.c1_task_result_v1.worker_read.observation.result_json'),'$.text'),'$.historical_dependency_candidate') "
        "FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, c02_operation_id)).fetchone()
    if row is None: raise MissingProductionOriginalV1("actual_committed_C02_metadata_before_history_probe")
    if row[0] != FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION:
        return TaskNoSearchProbeV1("not_applicable", "older_C1_template", None)
    if row[1] in {None, "null"}:
        return TaskNoSearchProbeV1("not_applicable", "no_historical_dependency_candidate", None)
    if row[1] != "object": raise ValueError("actual C1 v4 candidate metadata has an invalid type")
    rows = db.execute("SELECT original_ref,json_extract(payload_json,'$.task_kind'),json_extract(payload_json,'$.objective_ref') "
        "FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='artifact_task_scope' "
        "AND json_extract(payload_json,'$.c02_operation_id')=? AND json_extract(payload_json,'$.source_ref')=? LIMIT 2",
        (*namespace.as_tuple,c02_operation_id,source_ref)).fetchall()
    if not rows: return TaskNoSearchProbeV1("not_applicable", "no_actual_task_scope", None)
    if len(rows) != 1: raise ValueError("task history probe has ambiguous actual scope metadata")
    ref, kind, objective = rows[0]
    if kind != "draft_then_corrected_revision" or objective is None:
        return TaskNoSearchProbeV1("not_applicable", "not_an_initial_Goal_task", None)
    goal = db.execute("SELECT json_extract(payload_json,'$.goal_ref') FROM graph_d11_life_originals_v1 "
        "WHERE bot=? AND persona=? AND kind='artifact_task_objective' AND original_ref=?",
        (*namespace.as_tuple, objective)).fetchone()
    if goal is None: raise MissingProductionOriginalV1("actual_task_objective_metadata")
    head = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (goal[0], *namespace.as_tuple)).fetchone()
    if head is None: return TaskNoSearchProbeV1("not_applicable", "no_actual_task_Goal", None)
    if head[1] != 1: raise MissingProductionOriginalV1("current_valid_task_Goal_metadata")
    return TaskNoSearchProbeV1("candidate", None, AdoptCurrentTaskNoSearchRequestV1(c02_operation_id,source_ref,ref,goal[0],head[0]))
