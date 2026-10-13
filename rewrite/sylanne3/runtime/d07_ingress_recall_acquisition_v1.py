"""Pure Self C3 worker acquisition through the existing foreground W01."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import stage_result_v1, plain_v1
from ..graph_types import GraphVersion
from ..runtime_contracts import QueryEpoch, VersionedRef
from ..model_broker.broker import ModelCallRequest
from ..model_broker.d07_cognition_v1 import (
    WORK_KIND, RECALL_TEMPLATE_DIGEST_V1, thaw_d07_ingress_recall_request_v1,
)
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d07_execution_v1 import (
    D07IngressRecallPreparedV1, read_prepared_d07_execution_v1,
    require_current_d07_content_reads_v1, seal_d07_request_in_transaction_v1,
)
from .d07_ingress_recall_preparation_v1 import (
    PrepareIngressRecallModelRequestV1, InstalledIngressRecallModelReadersV1,
    ingress_recall_model_ids_v1,
)
from .d11_types import job_graph_write
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
from .jobs import get_job, plan_job_acquire, _save_job, _record_operation
from ..runtime_contracts import canonical_digest, canonical_serialize

ACQUIRE_OPERATION = "acquire_ingress_recall_model_v1"


def ingress_recall_acquire_operation_id_v1(namespace, c02_operation_id):
    ids = ingress_recall_model_ids_v1(namespace, c02_operation_id)
    return "d07-acquire:" + canonical_digest((namespace, ids["prepare"]))[:48]


def _prepared(db, namespace, request, service):
    ids = ingress_recall_model_ids_v1(namespace, request.c02_operation_id)
    p = read_prepared_d07_execution_v1(db, service.d11_issuer, namespace, ids["job"])
    if (type(p) is not D07IngressRecallPreparedV1
            or (p.c02_operation_id, p.cycle_job_ref, p.need_digest, p.recall_policy_digest) !=
               (request.c02_operation_id, request.job_ref, request.need_digest, request.policy_digest)):
        raise MissingProductionOriginalV1("actual_self_c3_prepared_acquisition_input")
    return p


def read_plan_ingress_recall_acquire_v1(db, *, namespace, request, service):
    from ..graph_types import AtomKey
    from .d07_execution_v1 import read_d07_original_v1
    p = _prepared(db, namespace, request, service)
    committed = read_d07_original_v1(db, service.d11_issuer, namespace, "prepare_commit", p.job_id)
    if committed is None or committed[0]["prepared_digest"] != p.digest:
        raise MissingProductionOriginalV1("actual_self_c3_preparation_commit")
    keys = (*[AtomKey.from_token(row["ref"]) for row in committed[0]["post_read_rows"]],
        AtomKey.from_token(request.job_ref), job_graph_write(get_job(db, p.job_id)).key)
    return production_read_plan_v1((), tuple(sorted(set(keys), key=lambda key: key.token)),
        (request.source_ref,), (p.job_id,))


@dataclass(frozen=True, slots=True)
class D07IngressRecallAcquisitionStageV1:
    frame: object
    stage: object
    prepared: D07IngressRecallPreparedV1
    before_job: object
    after_job: object
    model_request: ModelCallRequest


def acquire_current_ingress_recall_model_v1(db, *, frame, request, installed_readers):
    from ..authority_service.d07_current_execution_v1 import _require_current_ingress_recall_parent_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    if type(request) is not PrepareIngressRecallModelRequestV1 or type(installed_readers) is not InstalledIngressRecallModelReadersV1:
        raise TypeError("Self C3 acquisition needs the actual installed private readers")
    readers = installed_readers
    evidence = require_foreground_activity_issuance_v1(readers.issued, readers.graph, readers.scope)
    ns, env = frame.envelope.authority.namespace, frame.envelope
    operation_id = ingress_recall_acquire_operation_id_v1(ns, request.c02_operation_id)
    if (evidence.request.operation_kind != ACQUIRE_OPERATION
            or evidence.request.request_digest != foreground_typed_command_digest_v1(
                installed_operation_v1(ACQUIRE_OPERATION), request)
            or evidence.current_self.self_entity_ref != env.authority.actor
            or frame.owner_guard != evidence.owner_guard
            or env.identity.operation_id != operation_id
            or (evidence.request.c02_operation_id, evidence.request.cue_source_ref, evidence.request.cycle_job_ref) !=
               (request.c02_operation_id, request.source_ref, request.job_ref)):
        raise ValueError("Self C3 acquisition changed its actual private issuance")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    p = _prepared(db, ns, request, readers.execution_reader)
    require_current_d07_content_reads_v1(db, p, issuer=readers.issuer)
    before = get_job(db, p.job_id)
    if (before.phase != "queued" or before.fence or before.cancel_epoch
            or before.lease_holder is not None or before.result_ref is not None
            or read.head(db, job_graph_write(before).key, required=True).value != job_graph_write(before).value):
        raise ValueError("Self C3 acquisition requires its once queued original SQL/Graph job")
    workflow = readers.installed_bundle.model_workflows.d07_cognition
    deadline = min(env.deadline_utc,
        datetime.fromisoformat(before.deadline_utc.replace("Z", "+00:00")).timestamp())
    remaining = deadline - frame.now_utc
    if remaining <= workflow.timeout_seconds or remaining < 1:
        raise MissingProductionOriginalV1("unexpired_original_self_c3_worker_deadline")
    holder = readers.graph._GraphCoordinator__content_fence_v2.installation_grant.subject
    after = plan_job_acquire(before, holder,
        now_utc=datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        lease_seconds=min(3600, int(workflow.timeout_seconds) + 120, int(remaining)))
    worker_deadline = datetime.fromisoformat(after.lease_expires_utc.replace("Z", "+00:00")).timestamp()
    deadline = min(deadline, worker_deadline)
    guard = replace(env.version_guard,
        read_versions=tuple(GraphVersion(v.key, v.revision + 1)
            if v.key == job_graph_write(after).key else v for v in frame.snapshot.versions),
        query_epochs=tuple(QueryEpoch(v.namespace, v.scope_ref, v.revision + 1)
            for v in env.version_guard.query_epochs),
        resource_lease_versions=(VersionedRef(p.quote_id, p.quote_version),))
    frozen = thaw_d07_ingress_recall_request_v1(json.loads(p.frozen_json))
    refs = tuple(dict.fromkeys(source.source_ref.ref for source in
        (frozen.input.cue, *frozen.input.known_sources)))
    model_envelope = replace(env, identity=replace(env.identity, phase=WORK_KIND,
            effect_id=p.effect_id, canonical_input_digest=canonical_digest({"input_refs": list(refs)})),
        authority=replace(env.authority, actor=holder, worker_fence=after.fence, purpose="proposal",
            policy_ref=workflow.provider_config_ref),
        version_guard=guard, input_refs=refs, deadline_utc=deadline,
        monotonic_deadline=env.monotonic_deadline - (env.deadline_utc - deadline))
    call = ModelCallRequest(model_envelope, p.call_id, workflow.provider_id, workflow.model_id,
        frozenset(workflow.required_capabilities), workflow.privacy_tier, RECALL_TEMPLATE_DIGEST_V1,
        json.loads(frozen.canonical_wire), workflow.timeout_seconds, workflow.max_output_tokens)
    _require_current_ingress_recall_parent_v1(db, prepared=p, frozen=frozen, request=call,
        issuer=readers.issuer, installed_bundle=readers.installed_bundle, now=frame.now_utc)
    if frame.owner_guard != decode_typed_production_value_v1(
                json.loads(p.owner_guard_json), type(frame.owner_guard)):
        raise ValueError("Self C3 acquisition changed its actual upstream Owner")
    registration = readers.graph._GraphCoordinator__providers["d11"]
    stage = stage_result_v1(frame, "d11", ACQUIRE_OPERATION, request,
        writes=(job_graph_write(after),), provenance={"prepared_digest": p.digest,
            "request_digest": call.digest, "job_id": p.job_id, "worker_holder": holder, "worker_fence": after.fence},
        proposal_schema=registration[1], proposal_hash=registration[2])
    return D07IngressRecallAcquisitionStageV1(frame, stage, p, before, after, call)


def apply_ingress_recall_acquisition_once_v1(witness, graph, db):
    from .domain_production_commit_v1 import _ACTIVE, _FOREGROUND_VALIDATED, _FOREGROUND_APPLIED, _require_foreground_witness_v1
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    if (type(witness.stage) is not D07IngressRecallAcquisitionStageV1
            or _ACTIVE.get(id(witness)) is not witness
            or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or id(witness) in _FOREGROUND_APPLIED):
        raise ValueError("Self C3 acquisition needs the privately validated once W01 witness")
    issued, evidence = _require_foreground_witness_v1(witness, graph, db, witness.bundle)
    readers = installed_readers_for_operation_v1(graph, witness.operation, scope=witness.scope,
        owner_guard=evidence.owner_guard, foreground_issuance=issued)
    s = witness.stage
    if acquire_current_ingress_recall_model_v1(db, frame=s.frame, request=witness.request, installed_readers=readers) != s:
        raise ValueError("Self C3 acquisition changed before its final once application")
    _save_job(db, s.after_job)
    _record_operation(db, s.after_job, s.model_request.identity.operation_id, "acquire", canonical_digest(plain_v1(s.after_job)))
    seal_d07_request_in_transaction_v1(db, readers.issuer, s.prepared, s.model_request)
    _FOREGROUND_APPLIED[id(witness)] = witness
    return True
