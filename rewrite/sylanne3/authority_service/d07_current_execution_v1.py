"""Independent exact D07 Graph proof and scoped Authority result contract."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2
from .d07_model_timing_v1 import D07ModelTimingOriginalV1

SCHEMA = "d07.authority-cognition-result-read.v1"


@dataclass(frozen=True, slots=True)
class D07CognitionResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = "d07_cognition_adoption"
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA or self.purpose != "d07_cognition_adoption" or type(self.namespace) is not NamespaceId:
            raise ValueError("D07 exact result read scope required")
        from .contract import identifier
        for name in ("authority_id", "authority_namespace", "installation_id", "job_id", "acquire_operation_id",
                "original_operation_id", "call_id", "consumer_operation_id", "read_attempt_id"):
            identifier(getattr(self, name), name)
        for digest in (self.binding_digest, self.model_request_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("D07 result original digest required")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D07CognitionResultReadV1:
    request: D07CognitionResultReadRequestV1
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    timing: D07ModelTimingOriginalV1
    schema: str = SCHEMA

    def __post_init__(self):
        r, o, t, timing = self.request, self.observation, self.terminal_receipt, self.timing
        if (self.schema != SCHEMA or type(r) is not D07CognitionResultReadRequestV1
                or type(o) is not ModelEgressObservationV1 or type(t) is not ModelTerminalReceiptV2
                or type(timing) is not D07ModelTimingOriginalV1 or o.status != "completed"
                or (o.authority_id, o.namespace, o.call_id, o.request_digest) !=
                   (r.authority_id, r.authority_namespace, r.call_id, r.model_request_digest)
                or (t.call_id, t.request_digest, t.observation_digest, t.installation_id) !=
                   (r.call_id, r.model_request_digest, o.digest, r.installation_id)
                or (timing.call_id, timing.admission_id, timing.request_digest, timing.binding_digest, timing.terminal_digest) !=
                   (r.call_id, t.admission_id, r.model_request_digest, r.binding_digest, canonical_digest(asdict(t)))):
            raise ValueError("D07 exact Authority output/time/terminal identity differs")

    def require_original(self, intent, prepared):
        r = self.request
        if (type(intent) is not ModelEgressIntentV1
                or (r.namespace, r.job_id, r.call_id, r.original_operation_id, r.binding_digest, r.model_request_digest) !=
                   (prepared.namespace, prepared.job_id, prepared.call_id, prepared.operation_id, prepared.digest, intent.request_digest)
                or (intent.job_id, intent.call_id, intent.binding_digest, intent.acquire_operation_id) !=
                   (r.job_id, r.call_id, r.binding_digest, r.acquire_operation_id)
                or (self.observation.subject, self.observation.operation_id) != (intent.subject, intent.operation_id)):
            raise ValueError("D07 scoped result differs from actual prepared call")


def read_current_d07_execution_graph_v1(db, intent, issuer, now, *, allow_unsealed_prepare=False, allow_accounted_result=False):
    """Current exact content, Owner, job, quote and reserve read; never RPC."""
    from ..runtime.d07_execution_v1 import (read_prepared_d07_execution_v1, read_d07_original_v1,
        read_original_d07_request_v1, require_current_d07_content_reads_v1, _clock_original, _clock_from_json)
    from ..runtime.jobs import get_job
    from ..runtime.d11_types import job_graph_write
    from ..runtime.budget import get_budget_lease, require_budget_family_admissible
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1, TEMPLATE_DIGEST, WORK_KIND
    from .v2_model_egress_wire import to_wire as intent_wire
    if not db.in_transaction or type(intent) is not ModelEgressIntentV1:
        raise ValueError("D07 pinned current original proof required")
    job = get_job(db, intent.job_id)
    namespace = NamespaceId(job.bot_id, job.persona_id)
    prepared = read_prepared_d07_execution_v1(db, issuer, namespace, job.job_id)
    if prepared is None:
        raise ValueError("D07 actual prepared original missing")
    request = read_original_d07_request_v1(db, issuer, prepared)
    sealed = read_d07_original_v1(db, issuer, namespace, "call", job.job_id)
    if ((sealed is None and not allow_unsealed_prepare) or sealed is not None and sealed[0] != intent_wire(intent)
            or (intent.binding_digest, intent.call_id, intent.request_digest) != (prepared.digest, prepared.call_id, request.digest)
            or job.work_kind != "d07." + prepared.work_kind or job.phase != "running" or job.cancel_epoch
            or job.result_ref is not None or job.fence != intent.worker_fence or job.lease_holder != intent.subject
            or job.lease_expires_utc is None
            or now >= min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())):
        raise ValueError("D07 once-only current worker/original differs")
    require_current_d07_content_reads_v1(db, prepared, issuer=issuer)
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
    if atom is None or atom[1] != 1 or json.loads(atom[0]) != job_graph_write(job).value:
        raise ValueError("D07 actual current Graph job projection differs")
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if rights != (intent.access_epoch, intent.delete_epoch) or rights != (prepared.access_epoch, prepared.delete_epoch):
        raise ValueError("D07 current source rights changed")
    metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if metadata is None:
        raise ValueError("D07 actual current Authority anchor absent")
    anchor = json.loads(metadata[0])
    expected = {"authority_id": intent.authority_id, "authority_namespace": intent.namespace,
        "activation_generation": intent.authority_activation_generation, "revocation_epoch": intent.authority_revocation_epoch,
        "deletion_seq": intent.authority_deletion_seq, "execution_seq": intent.authority_execution_seq}
    if any(anchor.get(k) != v for k, v in expected.items()) or prepared.activation_generation != intent.authority_activation_generation:
        raise ValueError("D07 actual Authority anchor/generation changed")
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    if (canonical_digest(quote) != prepared.quote_digest or quote.work_kind != WORK_KIND
            or (quote.operation_id, quote.parent_budget_lease_ref) != (prepared.operation_id, intent.budget_lease_id)
            or tuple(sorted(quote.ceiling.items())) != intent.budget_ceiling):
        raise ValueError("D07 actual signed quote differs")
    lease = get_budget_lease(db, intent.budget_lease_id)
    if not allow_accounted_result:
        require_budget_family_admissible(db, lease.lease_id)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise ValueError("D07 budget crosses namespace")
    reserved = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, prepared.operation_id)).fetchone()
    allowed = {"reserved", "settled", "overrun", "unknown", "partial_unknown", "partial_overrun"} if allow_accounted_result else {"reserved"}
    if reserved is None or reserved[0] != prepared.reservation_digest or reserved[2] not in allowed or json.loads(reserved[1]) != dict(quote.ceiling):
        raise ValueError("D07 actual reserved workflow budget unavailable")
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    if (request.call_id != prepared.call_id or request.prompt_template_digest != TEMPLATE_DIGEST
            or dict(request.payload) != json.loads(frozen.canonical_wire) or request.identity.phase != WORK_KIND
            or request.envelope.authority.namespace != namespace or request.envelope.authority.actor != intent.subject
            or request.envelope.authority.worker_fence != intent.worker_fence or request.identity.operation_id != intent.operation_id
            or request.envelope.parent_budget_lease_ref != intent.budget_lease_id
            or request.envelope.authority.audience != prepared.audience or request.envelope.authority.purpose != "proposal"
            or (intent.provider_id, intent.model_id, intent.provider_config_digest, intent.max_output_tokens) !=
               (frozen.installation.provider_id, frozen.installation.model_id,
                frozen.installation.provider_config_digest, frozen.installation.max_output_tokens)):
        raise ValueError("D07 actual typed model request differs from frozen installed wire")
    if _clock_original(db, issuer, namespace, _clock_from_json(prepared.clock_mapping_json)) != prepared.clock_original_digest:
        raise ValueError("D07 exact signed role clock original changed")
    return prepared, job, frozen


def to_wire(value):
    if type(value) not in {D07CognitionResultReadRequestV1, D07CognitionResultReadV1}:
        raise TypeError("D07 exact Authority result read required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw, kind):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("D07 result wire fields differ")
    data = dict(raw)
    if kind is D07CognitionResultReadRequestV1:
        data["namespace"] = NamespaceId(**data["namespace"])
    elif kind is D07CognitionResultReadV1:
        data["request"] = from_wire(data["request"], D07CognitionResultReadRequestV1)
        observation = dict(data["observation"])
        for name in ("usage", "cost"):
            observation[name] = tuple(tuple(p) for p in observation[name])
        data["observation"] = ModelEgressObservationV1(**observation)
        data["terminal_receipt"] = ModelTerminalReceiptV2(**data["terminal_receipt"])
        data["timing"] = D07ModelTimingOriginalV1(**data["timing"])
    else:
        raise ValueError("unsupported D07 exact result wire")
    result = kind(**data)
    if to_wire(result) != raw:
        raise ValueError("noncanonical D07 result wire")
    return result
