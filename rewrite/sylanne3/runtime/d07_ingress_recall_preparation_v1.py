"""Self C3 preparation within the existing privately issued foreground W01.

This module prepares work only. Model admission, acquisition, result adoption
and terminal wake are deliberately not registered here.
"""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02 import BodyDomain
from ..domains.d03.self_perspective import self_mapping_key
from ..graph_types import AtomKey, Owner
from ..memory_types import SourceRecord
from ..model_broker.d07_cognition_v1 import (
    D07CognitionInstallationV1, D07IngressRecallInputV1, D07QualifiedSourceV1,
    RECALL_TEMPLATE_VERSION_V1, WORK_KIND, freeze_d07_ingress_recall_request_v1,
)
from ..runtime_contracts import (
    DependencySet, DomainBundle, DomainProposal, QueryEpoch, VersionedRef,
    canonical_digest, canonical_serialize,
)
from .budget import get_budget_lease, require_budget_family_admissible
from .d01_production_operations_v1 import (
    CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1,
)
from .d06_ingress_recall_v1 import (
    NEED_OPERATION, ingress_recall_need_operation_id_v1, read_adopted_ingress_recall_need_v1,
)
from .d07_execution_v1 import (
    D07_ACCOUNTING_FIELDS, D07ExecutionReadV1, D07IngressRecallPreparedV1,
    _clock_original, _prepare_d07_resources_in_transaction_v1,
    d07_execution_ids_v1, read_d07_original_v1, read_prepared_d07_execution_v1,
    record_d07_original_in_transaction_v1, require_current_d07_content_reads_v1,
)
from .d11_types import job_graph_write, runtime_job_key
from .domain_production_originals_v1 import (
    _receipt_wire, read_adopted_domain_operation_v1, record_adopted_domain_operation_v1,
)
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
from .foreground_call_plan_v1 import (
    MODEL_DIMENSIONS, ForegroundModelAttemptV1,
    resolve_current_foreground_reply_budget_v1,
)
from .foreground_cycle_v1 import (
    ForegroundWaitV1, foreground_cycle_from_wire_v1,
    foreground_responsibility_ref_v1, require_current_foreground_responsibility_v1,
)
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job, get_job, _save_job, _record_operation

OPERATION = "prepare_ingress_recall_model_v1"


@dataclass(frozen=True, slots=True)
class PrepareIngressRecallModelRequestV1:
    c02_operation_id: str
    source_ref: str
    job_ref: str
    policy_digest: str
    need_digest: str

    def __post_init__(self):
        from .d06_ingress_recall_v1 import PrepareIngressRecallNeedRequestV1
        PrepareIngressRecallNeedRequestV1(
            self.c02_operation_id, self.source_ref, self.job_ref, self.policy_digest)
        if (type(self.need_digest) is not str or len(self.need_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.need_digest)):
            raise ValueError("Self C3 needs its actual adopted Need commitment")


def ingress_recall_model_ids_v1(namespace, c02_operation_id):
    marker = canonical_digest((namespace, c02_operation_id, OPERATION))[:48]
    operation_id = "ingress-recall-model:" + marker
    return {**d07_execution_ids_v1(namespace, operation_id, "recall_need"),
        "prepare": operation_id, "adopt": "ingress-recall-adopt:" + marker,
        "effect": "ingress-recall-effect:" + marker, "attempt": operation_id}


@dataclass(frozen=True, slots=True)
class InstalledIngressRecallModelReadersV1:
    graph: object
    scope: object
    issued: object
    execution_reader: object

    @property
    def issuer(self):
        return self.execution_reader.d11_issuer

    @property
    def installed_bundle(self):
        return self.execution_reader.bundle


@dataclass(frozen=True, slots=True)
class D07IngressRecallPreparationStageV1:
    frame: object
    stage: object
    request: PrepareIngressRecallModelRequestV1
    need: object
    need_ref: str
    need_original_digest: str
    before_cycle: PersistentJob
    frozen: object
    workflow: object
    grant: object
    body_policy: object
    clock_mapping: object
    clock_digest: str
    deadline_utc: float


@dataclass(frozen=True, slots=True)
class D07IngressRecallMaterializedStageV1:
    pure: D07IngressRecallPreparationStageV1
    resources: object
    prepared: D07IngressRecallPreparedV1
    after_cycle: PersistentJob
    stage: object
    bundle: DomainBundle

    @property
    def frame(self):
        return self.resources.frame


def _need_original(db, namespace, request):
    original = read_adopted_domain_operation_v1(db, namespace,
        ingress_recall_need_operation_id_v1(namespace, request.c02_operation_id))
    need = read_adopted_ingress_recall_need_v1(
        db, namespace=namespace, c02_operation_id=request.c02_operation_id)
    if (original is None or need is None or canonical_digest(need) != request.need_digest
            or need.c02_operation_id != request.c02_operation_id
            or need.source_ref != request.source_ref or need.cycle_job_ref != request.job_ref
            or need.policy_digest != request.policy_digest):
        raise MissingProductionOriginalV1("actual_adopted_matching_ingress_recall_need")
    return need, original, "d07-current:" + original["original_digest"][:48]


def read_plan_ingress_recall_model_v1(db, *, namespace, activity_id, request, service):
    need, original, ref = _need_original(db, namespace, request)
    policy = service.bundle.d06_recall
    body = service.body_authority.policy(db, namespace,
        policy.cognition_body_policy_id, policy.cognition_body_policy_version)
    ids = ingress_recall_model_ids_v1(namespace, request.c02_operation_id)
    owner = Owner("activity", *namespace.as_tuple, activity_id)
    keys = (
        *(version.key for version in original["read_versions"]),
        AtomKey.from_token(request.job_ref), self_mapping_key(namespace),
        BodyDomain.profile_write(body.profile).key,
        BodyDomain.state_write(namespace, body.initial_state).key,
        runtime_job_key(*namespace.as_tuple, activity_id, ids["job"]),
        AtomKey(owner, "d02.reservation.v1", ids["reservation"]),
        AtomKey(owner, "d02.settlement.v1", ids["settlement"]),
    )
    return production_read_plan_v1(("d02.reservation.v1",),
        tuple(sorted(set(keys), key=lambda key: key.token)), (request.source_ref,), (ref,))


def _utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _qualified_plan(db, *, frame, request, readers):
    """Read-only; also used after reservation, so no new-budget-availability test."""
    from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
    from ..domains.d03.self_identity_qualification import SelfIdentityMapping
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if (type(request) is not PrepareIngressRecallModelRequestV1
            or type(readers) is not InstalledIngressRecallModelReadersV1
            or type(readers.execution_reader) is not InstalledD07ExecutionServiceV1
            or readers.execution_reader is not readers.graph._GraphCoordinator__d07_execution_service_v1
            or db is not readers.graph._GraphCoordinator__store._db):
        raise TypeError("Self C3 requires this installation's actual private readers")
    evidence = require_foreground_activity_issuance_v1(readers.issued, readers.graph, readers.scope)
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    ns, env = frame.envelope.authority.namespace, frame.envelope
    ids = ingress_recall_model_ids_v1(ns, request.c02_operation_id)
    if (evidence.request.operation_kind != OPERATION
            or evidence.request.request_digest != foreground_typed_command_digest_v1(installed_operation_v1(OPERATION), request)
            or (evidence.request.c02_operation_id, evidence.request.cue_source_ref, evidence.request.cycle_job_ref)
                != (request.c02_operation_id, request.source_ref, request.job_ref)
            or (env.identity.operation_id, env.identity.effect_id, env.identity.attempt_id)
                != (ids["prepare"], ids["effect"], ids["attempt"])
            or env.authority.actor != evidence.current_self.self_entity_ref
            or frame.owner_guard != evidence.owner_guard
            or env.authority.purpose != evidence.request.purpose):
        raise ValueError("Self C3 changed its independently issued command/actor/Owner constraints")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    need, original, need_ref = _need_original(db, ns, request)
    read.original(need_ref, kind="d07.current-" + NEED_OPERATION, digest=original["original_digest"])
    if need.routing == "no_search":
        raise MissingProductionOriginalV1("recall_need_does_not_require_a_c3_call")
    # Need is a historical routing original; recheck its actual bounded ledger
    # observation. Partial pages remain partial and cannot produce a PASS.
    for version in original["read_versions"]:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_recall_need_input_revision")
    for page in original["payload"]["query_coverage"]:
        expected = [(AtomKey.from_token(row["key"]).token, row["revision"])
            for row in page["row_versions"]]
        limit = len(expected) + 1 if page["complete"] else len(expected)
        current = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? "
            "ORDER BY token LIMIT ?", (*ns.as_tuple, page["type_id"], limit)).fetchall()
        if current != expected:
            raise MissingProductionOriginalV1("current_recall_need_query_coverage")
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    if read.head(db, request.job_ref, required=True).value != job_graph_write(cycle).value:
        raise ValueError("Self C3 SQL and Graph parent cycle differ")
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=cycle,
        installed_bundle=readers.installed_bundle, issuer=readers.issuer, owner_guard=frame.owner_guard,
        purpose=env.authority.purpose, audiences=env.authority.audience, now_utc=frame.now_utc)
    if (responsibility is None or responsibility.digest != need.responsibility_digest
            or need.responsibility_ref != foreground_responsibility_ref_v1(ns, request.c02_operation_id)
            or cycle.phase != "running" or cycle.lease_holder != env.authority.actor
            or cycle.activity_id != env.identity.activity_id
            or cycle.cancel_epoch != need.cancel_generation or cycle.cancel_epoch
            or continuation.cancel_generation or continuation.c02_operation_id != request.c02_operation_id
            or continuation.source_ref != request.source_ref
            or continuation.call_plan.parent_budget_lease_ref != env.parent_budget_lease_ref
            or any(attempt.slot == "C3" for attempt in continuation.call_plan.attempts)):
        raise MissingProductionOriginalV1("actual_running_unconsumed_self_c3_parent")
    resolve_current_foreground_reply_budget_v1(db, namespace=ns,
        c02_operation_id=request.c02_operation_id, source_ref=request.source_ref,
        issuer=readers.issuer, installed_bundle=readers.installed_bundle, now_utc=frame.now_utc)
    mapping_atom = read.head(db, self_mapping_key(ns), required=True)
    mapping = decode_typed_production_value_v1(mapping_atom.value, SelfIdentityMapping)
    if mapping.status != "active" or mapping.self_entity_ref != env.authority.actor:
        raise MissingProductionOriginalV1("actual_current_recall_self_mapping")
    read.source_family(db, (request.source_ref,), purpose=env.authority.purpose)
    cue = read.head(db, request.source_ref, required=True)
    if (cue.revision, canonical_digest(cue.value)) != (need.source_revision, need.source_digest):
        raise MissingProductionOriginalV1("current_recall_cue")
    bundle, service = readers.installed_bundle, readers.execution_reader
    policy, workflow = bundle.d06_recall, bundle.model_workflows.d07_cognition
    if (policy.policy_digest != request.policy_digest or workflow is None
            or workflow.template_version != RECALL_TEMPLATE_VERSION_V1
            or workflow.work_kind != WORK_KIND or workflow.purpose != "proposal"
            or not set(env.authority.audience) <= set(workflow.audiences)
            or set(workflow.quote_ceiling) != MODEL_DIMENSIONS
            or workflow.quote_ceiling["input_tokens"] > 6000
            or workflow.quote_ceiling["output_tokens"] > 1000
            or workflow.max_output_tokens > workflow.quote_ceiling["output_tokens"]):
        raise MissingProductionOriginalV1("explicit_installed_self_c3_workflow_and_four_dimension_quote")
    grant = readers.issuer.current_budget_grant(db, env.parent_budget_lease_ref)
    require_budget_family_admissible(db, grant.lease_id)
    if (WORK_KIND not in grant.allowed_work_kinds
            or (grant.bot_id, grant.persona_id) != ns.as_tuple
            or any(value > grant.max_ceiling.get(key, 0) for key, value in workflow.quote_ceiling.items())):
        raise MissingProductionOriginalV1("original_signed_parent_c3_budget")
    body = service.body_authority.policy(db, ns, policy.cognition_body_policy_id, policy.cognition_body_policy_version)
    if body.work_kind != WORK_KIND:
        raise ValueError("Self C3 requires its explicitly selected cognition BodyPolicy")
    clock_reader = readers.graph._GraphCoordinator__d04_semantic_mapping_reader
    clock = read_current_role_clock_installation_v1(clock_reader, db, ns)
    clock_digest = _clock_original(db, readers.issuer, ns, clock)
    clock.character_at(datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"))
    deadline = min(env.deadline_utc, need.deadline_utc, responsibility.deadline_utc,
        _utc(cycle.deadline_utc), grant.valid_until_utc, body.valid_until, _utc(clock.valid_until_utc))
    if frame.now_utc + workflow.timeout_seconds >= deadline:
        raise MissingProductionOriginalV1("unexpired_original_self_c3_deadline")
    model_input = D07IngressRecallInputV1(ns, cycle.activity_id, request.c02_operation_id,
        request.job_ref, need_ref, request.need_digest,
        D07QualifiedSourceV1(VersionedRef(request.source_ref, cue.revision), SourceRecord.from_dict(cue.value)),
        (), need.triggers, need.required_checks, need.missing_items,
        () if need.known_entity_ref is None else (need.known_entity_ref,))
    installation = D07CognitionInstallationV1(bundle.installation_policy.installation_id,
        workflow.provider_id, workflow.model_id, workflow.provider_config_ref,
        workflow.provider_config_digest, workflow.max_output_tokens)
    frozen = freeze_d07_ingress_recall_request_v1(model_input, installation)
    stage = stage_result_v1(frame, "d07", OPERATION, request,
        provenance={"need_ref": need_ref, "need_digest": request.need_digest},
        coverage="deferred", missing=("actual_self_c3_execution",), continuation=ids["job"])
    return D07IngressRecallPreparationStageV1(frame, stage, request, need, need_ref,
        original["original_digest"], cycle, frozen, workflow, grant, body, clock, clock_digest, deadline)


def prepare_current_ingress_recall_model_v1(db, *, frame, request, installed_readers):
    pure = _qualified_plan(db, frame=frame, request=request, readers=installed_readers)
    ns = frame.envelope.authority.namespace
    ids = ingress_recall_model_ids_v1(ns, request.c02_operation_id)
    if read_prepared_d07_execution_v1(db, installed_readers.issuer, ns, ids["job"]) is not None:
        raise ValueError("Self C3 must replay its original foreground receipt, not prepare again")
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    if lease.state != "active" or any(value > lease.available(key) for key, value in pure.workflow.quote_ceiling.items()):
        raise MissingProductionOriginalV1("actual_remaining_c3_budget_after_protected_reply_allocation")
    # Constructor enforces 6 calls / 2 auxiliaries / 48k input / 8k output before
    # resource mutation. The definitive reservation digest is materialized later.
    _after_cycle(pure, "pending:" + pure.frozen.input_digest, ids)
    return pure


def _continuation(pure, ids):
    return {"schema": "d07.ingress-recall-job.v1", "need_ref": pure.need_ref,
        "need_digest": pure.request.need_digest, "c02_operation_id": pure.request.c02_operation_id,
        "cycle_job_ref": pure.request.job_ref, "responsibility_ref": pure.need.responsibility_ref,
        "responsibility_digest": pure.need.responsibility_digest, "cancel_generation": pure.need.cancel_generation,
        "adoption_operation_id": ids["adopt"], "input_digest": pure.frozen.input_digest,
        "original_ref": "d07-prepared:" + ids["prepare"], "prepared_job_id": ids["job"],
        "quote_id": ids["quote"], "quote_version": 1, "call_id": ids["call"], "work_kind": "recall_need"}


def _after_cycle(pure, reservation_digest, ids):
    old = foreground_cycle_from_wire_v1(pure.before_cycle.continuation)
    ceiling = pure.workflow.quote_ceiling
    attempt = ForegroundModelAttemptV1("C3", ids["call"], None, ids["prepare"], reservation_digest,
        old.call_plan.parent_budget_lease_ref, ceiling["input_tokens"], ceiling["output_tokens"], "reserved")
    plan = replace(old.call_plan, attempts=(*old.call_plan.attempts, attempt))
    wait = ForegroundWaitV1("d07", "ingress_recall_model_terminal", (),
        QueryEpoch(pure.frame.envelope.authority.namespace, "foreground:" + pure.before_cycle.job_id,
            pure.frame.snapshot.epochs[0].revision),
        old.wait.consume_cursor if old.wait is not None else 0, None)
    continuation = replace(old, stage="recall", call_plan=plan, wait=wait)
    return replace(pure.before_cycle, phase="waiting", continuation=plain_v1(continuation),
        wake_condition=plain_v1(wait), lease_holder=None, lease_expires_utc=None)


def _prepared(pure, resources, ids):
    f, q, body = resources.frame, resources.resource_quote, resources.body_reservation
    identity, authority = f.envelope.identity, f.envelope.authority
    return D07IngressRecallPreparedV1(
        namespace=authority.namespace, operation_id=identity.operation_id, activity_id=identity.activity_id,
        effect_id=identity.effect_id, attempt_id=identity.attempt_id, job_id=resources.job.job_id,
        call_id=ids["call"], execution_id=ids["execution"], work_kind="recall_need",
        stage_input_digest=pure.frozen.input_digest, frozen_json=canonical_serialize(asdict(pure.frozen)),
        read_rows=resources.content_read_rows, query_inventory_json=resources.query_inventory_json,
        external_content_originals_json="[]", audience=authority.audience, purpose=authority.purpose,
        owner_guard_json=canonical_serialize(asdict(f.owner_guard)), self_authority_json=canonical_serialize(asdict(authority)),
        quote_id=q.quote_id, quote_version=q.version, quote_digest=canonical_digest(q),
        reservation_digest=resources.reservation_digest, body_policy_id=pure.body_policy.policy_id,
        body_policy_version=pure.body_policy.version, body_quote_ref=body.body_quote.quote_id,
        body_quote_version=body.body_quote_version, body_quote_digest=canonical_digest(body.body_quote),
        body_reservation_ref=body.reservation_write.key.token, body_state_ref=resources.body_state_ref,
        body_profile_ref=resources.body_profile_ref, component_id=resources.component_id,
        clock_mapping_json=resources.clock_mapping_json, clock_original_digest=resources.clock_original_digest,
        activation_generation=f.activation_generation, graph_epoch=f.snapshot.epochs[0].revision,
        access_epoch=f.envelope.version_guard.access_epoch, delete_epoch=f.envelope.version_guard.delete_epoch,
        need_ref=pure.need_ref, need_digest=pure.request.need_digest, c02_operation_id=pure.request.c02_operation_id,
        cycle_job_ref=pure.request.job_ref, responsibility_ref=pure.need.responsibility_ref,
        responsibility_digest=pure.need.responsibility_digest, recall_policy_digest=pure.request.policy_digest,
        cancel_generation=pure.need.cancel_generation, adoption_operation_id=ids["adopt"])


def materialize_ingress_recall_model_v1(db, *, pure, readers):
    if prepare_current_ingress_recall_model_v1(db, frame=pure.frame, request=pure.request, installed_readers=readers) != pure:
        raise ValueError("Self C3 read-only plan changed before once materialization")
    env = pure.frame.envelope
    effective = replace(env, deadline_utc=pure.deadline_utc,
        monotonic_deadline=env.monotonic_deadline - (env.deadline_utc - pure.deadline_utc))
    frame = replace(pure.frame, envelope=effective)
    ids = ingress_recall_model_ids_v1(env.authority.namespace, pure.request.c02_operation_id)
    service = readers.execution_reader
    resources = _prepare_d07_resources_in_transaction_v1(db, frame=frame, ids=ids,
        work_kind="recall_need", frozen=pure.frozen, stage_input_digest=pure.frozen.input_digest,
        job_continuation=_continuation(pure, ids), original_ref="d07-prepared:" + ids["prepare"],
        workflow=pure.workflow, lease=get_budget_lease(db, env.parent_budget_lease_ref),
        resource_issuer=service.resource_issuer, body_authority=service.body_authority,
        clock_mapping=pure.clock_mapping, clock_digest=pure.clock_digest, policy=pure.body_policy,
        body_policy_id=pure.body_policy.policy_id, body_policy_version=pure.body_policy.version)
    prepared = _prepared(pure, resources, ids)
    require_current_d07_content_reads_v1(db, prepared)
    record_d07_original_in_transaction_v1(db, readers.issuer, prepared.namespace, "prepared", prepared.job_id, asdict(prepared))
    record_d07_original_in_transaction_v1(db, readers.issuer, prepared.namespace, "accounting_prepared", prepared.job_id,
        {"schema": "d07.ingress-recall-accounting-prepared.v1", "prepared_digest": prepared.digest,
         "prepare_operation_id": prepared.prepare_operation_id,
         **{name: plain_v1(getattr(prepared, name)) for name in D07_ACCOUNTING_FIELDS}})
    create_job(db, resources.job, resources.job.operation_id, resources.reservation_digest)
    after = _after_cycle(pure, resources.reservation_digest, ids)
    writes = (*resources.writes, job_graph_write(after))
    proposals = []
    for domain, selected in (("d07", ()), ("d02", (resources.writes[0],)),
            ("d11", (resources.writes[1], writes[-1]))):
        registration = readers.graph._GraphCoordinator__providers[domain]
        proposals.append(DomainProposal(domain, registration[1], registration[2], resources.frame.envelope,
            selected, DependencySet(), (), ()))
    bundle = DomainBundle(resources.frame.envelope, tuple(proposals), (), (), (), (),
        (prepared.prepare_operation_id,), (job_graph_write(resources.job).key.token, job_graph_write(after).key.token), ())
    stage = stage_result_v1(resources.frame, "d07", OPERATION, pure.request,
        provenance={"prepared_job_id": prepared.job_id, "prepared_digest": prepared.digest,
            "need_ref": pure.need_ref, "need_digest": pure.request.need_digest,
            "before_cycle": pure.before_cycle, "after_cycle": after},
        coverage="deferred", missing=("actual_self_c3_execution",), continuation=prepared.job_id)
    payload = json.loads(stage.original_payload_json)
    payload["writes"] = plain_v1(writes)
    stage = replace(stage, proposals=bundle.proposals, read_versions=resources.read_versions,
        original_payload_json=canonical_serialize(payload), original_digest=canonical_digest(payload))
    return D07IngressRecallMaterializedStageV1(pure, resources, prepared, after, stage, bundle)


def verify_ingress_recall_model_commit_v1(witness, graph, db, bundle):
    from .domain_production_commit_v1 import _ACTIVE, _FOREGROUND_VALIDATED, _require_foreground_witness_v1
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    s = witness.stage
    if (type(s) is not D07IngressRecallMaterializedStageV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle != s.bundle or witness.frame != s.frame or witness.request != s.pure.request):
        raise ValueError("Self C3 commit lacks its exact private W01 witness")
    issued, evidence = _require_foreground_witness_v1(witness, graph, db, bundle)
    readers = installed_readers_for_operation_v1(graph, witness.operation, scope=witness.scope,
        owner_guard=evidence.owner_guard, foreground_issuance=issued)
    if _qualified_plan(db, frame=s.pure.frame, request=s.pure.request, readers=readers) != s.pure:
        raise ValueError("Self C3 current parent/Need/Source/Self/policies changed")
    p, r = s.prepared, s.resources
    ids = ingress_recall_model_ids_v1(p.namespace, p.c02_operation_id)
    quote = readers.execution_reader.resource_issuer.original_signed_quote(db, p.quote_id, p.quote_version)
    body = readers.execution_reader.body_authority.original_body_quote(db, p.body_quote_ref,
        p.body_quote_version, quote, p.operation_id)
    expected_job = PersistentJob(ids["job"], p.operation_id, p.activity_id, p.effect_id, *p.namespace.as_tuple,
        "d07-prepared:" + p.operation_id, "queued", "d07.recall_need", _continuation(s.pure, ids), None,
        datetime.fromtimestamp(s.pure.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        s.pure.frame.envelope.parent_budget_lease_ref, ids["quote"],
        {"executor": "d07.installed-cognition.v1", "policy": s.pure.workflow.template_version},
        None, None, 0, 0, {}, None)
    settlement = AtomKey(Owner("activity", *p.namespace.as_tuple, p.activity_id), "d02.settlement.v1", ids["settlement"])
    expected_quote = ResourceQuote(ids["quote"], 1, *p.namespace.as_tuple, p.activity_id, p.operation_id,
        p.effect_id, expected_job.budget_ref, WORK_KIND, "d07-input:" + s.pure.frozen.input_digest[:48],
        s.pure.deadline_utc, "d07-resource:" + canonical_digest(s.pure.workflow.provider_config_ref)[:48],
        job_graph_write(expected_job).key.token, (), (settlement.token,), dict(s.pure.workflow.quote_ceiling), None, s.pure.deadline_utc)
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (expected_job.budget_ref, p.operation_id)).fetchone()
    expected_reservation = canonical_digest({"schema": "d07.execution-reservation.v1",
        "frozen": s.pure.frozen, "stage_input_digest": s.pure.frozen.input_digest,
        "job": expected_job, "quote": expected_quote, "body_quote": body,
        "clock_digest": s.pure.clock_digest, "owner_guard": s.pure.frame.owner_guard})
    if (p.reservation_digest != expected_reservation or r.reservation_digest != expected_reservation
            or p != _prepared(s.pure, r, ids)
            or read_prepared_d07_execution_v1(db, readers.issuer, p.namespace, p.job_id) != p
            or get_job(db, p.job_id) != expected_job or r.job != expected_job
            or quote != expected_quote or r.resource_quote != expected_quote
            or canonical_digest(quote) != p.quote_digest or body != r.body_reservation.body_quote
            or canonical_digest(body) != p.body_quote_digest
            or reservation != (p.reservation_digest, canonical_serialize(dict(quote.ceiling)), "reserved")
            or r.writes != (r.body_reservation.reservation_write, job_graph_write(expected_job))
            or r.writes[0].key.token != p.body_reservation_ref
            or r.writes[0].value["effect_id"] != p.effect_id
            or s.after_cycle != _after_cycle(s.pure, p.reservation_digest, ids)
            or get_job(db, s.pure.before_cycle.job_id) != s.pure.before_cycle
            or tuple(w for proposal in bundle.proposals for w in proposal.typed_writes)
                != (*r.writes, job_graph_write(s.after_cycle))):
        raise ValueError("Self C3 signed resources/job/parent CallPlan do not match its fixed preparation")
    require_current_d07_content_reads_v1(db, p)
    _FOREGROUND_VALIDATED[id(witness)] = witness
    return witness


def apply_ingress_recall_cycle_once_v1(witness, graph, db):
    from .domain_production_commit_v1 import _ACTIVE, _FOREGROUND_VALIDATED, _FOREGROUND_APPLIED
    if (type(witness.stage) is not D07IngressRecallMaterializedStageV1
            or _ACTIVE.get(id(witness)) is not witness
            or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or id(witness) in _FOREGROUND_APPLIED):
        raise ValueError("Self C3 parent checkpoint requires its privately verified once witness")
    s = witness.stage
    if get_job(db, s.pure.before_cycle.job_id) != s.pure.before_cycle:
        raise ValueError("Self C3 parent changed before actual Graph CAS")
    _save_job(db, s.after_cycle)
    _record_operation(db, s.after_cycle, s.prepared.operation_id, "checkpoint", canonical_digest(plain_v1(s.after_cycle)))
    _FOREGROUND_APPLIED[id(witness)] = witness
    return True


def _record_prepare_commit(db, issuer, s, receipt):
    if receipt.status != "committed" or receipt.operation_id != s.prepared.prepare_operation_id:
        raise ValueError("Self C3 requires its original actual preparation CAS")
    writes = tuple(w for proposal in s.bundle.proposals for w in proposal.typed_writes)
    for write in writes:
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[1] != 1 or json.loads(row[0]) != write.value:
            raise ValueError("Self C3 preparation member is not actually adopted")
    rows = []
    for old in s.prepared.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (old.ref,)).fetchone()
        rows.append(old if row is None else D07ExecutionReadV1(old.ref, row[0], bool(row[2]), canonical_serialize(json.loads(row[1]))))
    # The only type inventory in this preparation is D02 reservations, excluded
    # from content currentness by the shared kernel. No invented current pages.
    if s.prepared.query_inventory_json != "[]":
        raise ValueError("Self C3 preparation unexpectedly gained a content query inventory")
    payload = {"schema": "d07.preparation-commit.v1", "prepared_digest": s.prepared.digest,
        "prepare_operation_id": s.prepared.prepare_operation_id, "graph_receipt_digest": canonical_digest(receipt),
        "writes_digest": canonical_digest(writes), "post_read_rows": plain_v1(tuple(rows)),
        "post_query_inventory_json": "[]"}
    return record_d07_original_in_transaction_v1(db, issuer, s.prepared.namespace, "prepare_commit", s.prepared.job_id, payload)


def commit_ingress_recall_preparation_v1(runtime, db, *, operation, request, preparation,
        readers, scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from .domain_production_commit_v1 import (
        _ProductionCommitWitnessV1, _ACTIVE, _FOREGROUND_VALIDATED, _FOREGROUND_APPLIED,
        foreground_domain_finish_digest_v1,
    )
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    evidence = require_foreground_activity_issuance_v1(runtime._active_foreground_issuance_v1, runtime.graph, scope)
    if owner is not None or preparation.request != request or evidence.owner_guard != preparation.frame.owner_guard:
        raise ValueError("Self C3 cannot use an Owner-shaped preparation")
    attempt = db.execute("SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*preparation.frame.envelope.authority.namespace.as_tuple, evidence.request.operation_id)).fetchone()
    if attempt != (canonical_digest(evidence.request), scope.operation_id):
        raise ValueError("Self C3 lost its actual original foreground selector/fence attempt")
    s = materialize_ingress_recall_model_v1(db, pure=preparation, readers=readers)
    witness = _ProductionCommitWitnessV1(runtime, runtime.graph, scope, s.frame,
        s, operation, request, None, guard, s.bundle, tuple(external_originals))
    _ACTIVE[id(witness)] = witness
    try:
        receipt = runtime.graph._commit_domain_bundle_fenced(s.bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, "finish:" + scope.operation_id,
                foreground_domain_finish_digest_v1(evidence.request, scope.permit), canonical_json(to_wire(scope.permit))),
            now_utc=s.frame.now_utc, domain_production_issuance_v1=witness)
        if _FOREGROUND_APPLIED.get(id(witness)) is not witness:
            raise ValueError("Self C3 parent checkpoint was not applied by the real W01 guard")
    finally:
        _ACTIVE.pop(id(witness), None)
        _FOREGROUND_VALIDATED.pop(id(witness), None)
        _FOREGROUND_APPLIED.pop(id(witness), None)
    prepared_digest = _record_prepare_commit(db, readers.issuer, s, receipt)
    original = record_adopted_domain_operation_v1(db, s.stage, receipt)
    return {"schema": "sylanne.domain-production-receipt.v1", "domain": "d07", "operation_kind": OPERATION,
        "operation_id": s.prepared.operation_id,
        "activity_id": s.prepared.activity_id, "original_ref": original.original_ref,
        "original_digest": original.original_digest, "receipt": _receipt_wire(receipt),
        "receipt_digest": canonical_digest(receipt), "job_states": [[s.resources.job.job_id, "queued"], [s.after_cycle.job_id, "waiting"]],
        "coverage": "deferred", "missing_inputs": ["actual_self_c3_execution"], "continuation_ref": s.prepared.job_id,
        "outbox": [], "produced_originals": [{"kind": "d07.prepare_commit", "original_ref": s.prepared.job_id,
            "original_digest": prepared_digest}]}


def read_current_ingress_recall_attempt_v1(db, *, namespace, continuation, attempt, issuer):
    """Read actual preparation/acquisition/terminal originals; running is not dispatch proof."""
    from .d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1, ACQUIRE_OPERATION
    from .d07_execution_v1 import read_original_d07_request_v1, decode_d07_execution_original_v1
    ids = ingress_recall_model_ids_v1(namespace, continuation.c02_operation_id)
    p = read_prepared_d07_execution_v1(db, issuer, namespace, ids["job"])
    if type(p) is not D07IngressRecallPreparedV1:
        raise MissingProductionOriginalV1("actual_signed_self_c3_preparation")
    original = read_adopted_domain_operation_v1(db, namespace, p.prepare_operation_id)
    committed = read_d07_original_v1(db, issuer, namespace, "prepare_commit", p.job_id)
    q = issuer.resource_issuer.original_signed_quote(db, p.quote_id, p.quote_version)
    job = get_job(db, p.job_id)
    reservation = db.execute("SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (q.parent_budget_lease_ref, p.operation_id)).fetchone()
    base = ForegroundModelAttemptV1("C3", p.call_id, None, p.operation_id, p.reservation_digest,
        q.parent_budget_lease_ref, q.ceiling["input_tokens"], q.ceiling["output_tokens"], "reserved")
    if (original is None or original["operation_kind"] != OPERATION
            or original["payload"]["provenance"]["prepared_digest"] != p.digest
            or committed is None or committed[0]["prepared_digest"] != p.digest
            or committed[0]["graph_receipt_digest"] != canonical_digest(original["receipt"])
            or p.c02_operation_id != continuation.c02_operation_id or p.call_id != ids["call"]
            or p.cancel_generation != continuation.cancel_generation
            or q.parent_budget_lease_ref != continuation.call_plan.parent_budget_lease_ref
            or canonical_digest(q) != p.quote_digest or q.work_kind != WORK_KIND
            or reservation is None or reservation[0] != p.reservation_digest
            or replace(attempt, state="reserved", terminal_ref=None) != base):
        raise ValueError("Self C3 current attempt differs from its exact parent/quote/reservation")
    state, terminal = "reserved", None
    if job.phase == "queued":
        if job.lease_holder is not None or job.fence or job.cancel_epoch or job.result_ref is not None:
            raise ValueError("Self C3 queued original has a fabricated worker/terminal")
    else:
        acquired = read_adopted_domain_operation_v1(db, namespace,
            ingress_recall_acquire_operation_id_v1(namespace, p.c02_operation_id))
        call = read_original_d07_request_v1(db, issuer, p)
        if (acquired is None or acquired["domain"] != "d11" or acquired["operation_kind"] != ACQUIRE_OPERATION
                or acquired["payload"]["provenance"]["prepared_digest"] != p.digest
                or acquired["payload"]["provenance"]["request_digest"] != call.digest
                or job.fence != 1 or call.envelope.authority.worker_fence != job.fence
                or job.phase == "running" and job.lease_holder != call.envelope.authority.actor):
            raise ValueError("Self C3 acquisition lacks its real adopted worker/request original")
        sealed = read_d07_original_v1(db, issuer, namespace, "call", job.job_id)
        paid = read_d07_original_v1(db, issuer, namespace, "paid_cost", job.job_id)
        execution = read_d07_original_v1(db, issuer, namespace, "execution", "d07-terminal:" + p.call_id)
        if execution is not None:
            actual = decode_d07_execution_original_v1(execution[0])
            body = read_d07_original_v1(db, issuer, namespace, "body_cost", job.job_id)
            if (job.phase != "completed" or job.result_ref != actual.terminal_ref
                    or paid is None or paid[0]["paid"] is not True or paid[0]["unknown_dimensions"]
                    or body is None or body[0]["unpaid_cost"]
                    or actual.prepared_digest != p.digest or actual.cost_receipt_refs != (paid[0]["cost_ref"],)):
                raise ValueError("Self C3 completed attempt lost its actual paid/body/terminal originals")
            state, terminal = "completed", actual.terminal_ref
        elif sealed is not None or paid is not None or reservation[1] in {"unknown", "partial_unknown", "unconfirmed"}:
            state = "unknown"
        elif job.phase in {"cancelled", "failed"}:
            state = "not_dispatched"
        elif job.phase != "running":
            raise MissingProductionOriginalV1("actual_self_c3_registered_worker_state")
    if reservation[1] in {"unknown", "partial_unknown", "unconfirmed"} and state != "completed":
        state = "unknown"
    return replace(base, state=state, terminal_ref=terminal)
