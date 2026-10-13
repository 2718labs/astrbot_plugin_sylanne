"""D04-specific current original and result reader contract for Authority.

The daemon authenticates the installed mTLS actor and original egress fence
before invoking this pinned graph reader. No other workflow's selector is used.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2

SCHEMA = "d04.appraisal_authority_result_read.v3"


@dataclass(frozen=True, slots=True)
class D04AppraisalResultReadRequestV3:
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
    purpose: str = "d04_appraisal_adoption"
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or self.purpose != "d04_appraisal_adoption"
                or type(self.namespace) is not NamespaceId):
            raise ValueError("D04 appraisal result scope differs")
        from .contract import identifier
        for name in ("authority_id", "authority_namespace", "installation_id", "job_id",
                     "acquire_operation_id", "original_operation_id", "call_id",
                     "consumer_operation_id", "read_attempt_id"):
            identifier(getattr(self, name), name)
        for digest in (self.binding_digest, self.model_request_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("D04 appraisal result digest differs")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04AppraisalResultReadV3:
    request: D04AppraisalResultReadRequestV3
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    schema: str = SCHEMA

    def __post_init__(self):
        request, observation, receipt = self.request, self.observation, self.terminal_receipt
        if (self.schema != SCHEMA or type(request) is not D04AppraisalResultReadRequestV3
                or type(observation) is not ModelEgressObservationV1
                or type(receipt) is not ModelTerminalReceiptV2 or observation.status != "completed"
                or (observation.authority_id, observation.namespace, observation.call_id, observation.request_digest) !=
                   (request.authority_id, request.authority_namespace, request.call_id, request.model_request_digest)
                or (receipt.call_id, receipt.request_digest, receipt.observation_digest, receipt.installation_id) !=
                   (request.call_id, request.model_request_digest, observation.digest, request.installation_id)):
            raise ValueError("D04 Authority completed result identity differs")

    def require_original(self, intent, original):
        if (type(intent) is not ModelEgressIntentV1
                or (self.request.job_id, self.request.call_id, self.request.original_operation_id,
                    self.request.binding_digest, self.request.model_request_digest) !=
                   (original.job_id, original.call_id, original.operation_id, original.digest,
                    intent.request_digest)
                or self.request.namespace != original.namespace
                or (intent.call_id, intent.job_id, intent.request_digest, intent.binding_digest,
                    intent.acquire_operation_id) !=
                   (original.call_id, original.job_id, self.request.model_request_digest, original.digest,
                    self.request.acquire_operation_id)
                or (self.observation.authority_id, self.observation.namespace, self.observation.subject,
                    self.observation.operation_id) !=
                   (intent.authority_id, intent.namespace, intent.subject, intent.operation_id)):
            raise ValueError("D04 Authority result differs from its immutable original")


def read_current_d04_appraisal_graph_v3(db, intent, issuer, now, *, allow_unsealed_prepare=False, allow_accounted_result=False):
    """Current pinned Graph proof for admission and content release, no RPC."""
    from ..runtime.d04_appraisal_driver_v3 import (
        read_current_d04_appraisal_original_v3, read_d04_original_v3,
        require_current_read_rows_v3, read_original_d04_request_v3,
    )
    from ..runtime.jobs import get_job
    from ..runtime.d11_types import job_graph_write
    from ..runtime.budget import get_budget_lease, require_budget_family_admissible
    from .v2_model_egress_wire import to_wire as intent_wire
    if not db.in_transaction or type(intent) is not ModelEgressIntentV1:
        raise ValueError("D04 current proof requires pinned graph transaction")
    job = get_job(db, intent.job_id)
    namespace = NamespaceId(job.bot_id, job.persona_id)
    original = read_current_d04_appraisal_original_v3(db, namespace, job.job_id)
    sealed = read_d04_original_v3(db, namespace, "appraisal_call", job.job_id)
    if original is None:
        raise ValueError("D04 appraisal prepared original absent")
    request = read_original_d04_request_v3(db, original)
    if (original is None or (sealed is None and not allow_unsealed_prepare)
            or (sealed is not None and sealed[0] != intent_wire(intent))
            or intent.binding_digest != original.digest or intent.call_id != original.call_id
            or intent.request_digest != request.digest
            or job.operation_id != original.operation_id or job.work_kind != "d04.appraisal"
            or job.phase != "running" or job.cancel_epoch or job.result_ref is not None
            or job.fence != intent.worker_fence or job.lease_holder != intent.subject
            or job.lease_expires_utc is None
            or now >= min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())):
        raise ValueError("D04 original current worker changed")
    require_current_read_rows_v3(db, original.read_rows, namespace)
    from ..runtime.d04_product_pipeline_v3 import scope_rows
    scope = read_d04_original_v3(db, namespace, "appraisal_scope", original.job_id)
    if scope is None or scope[0] != {"scope_digest": scope_rows(db, namespace)}:
        raise ValueError("D04 current negative social scope changed")
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
    if atom is None or atom[1] != 1 or json.loads(atom[0]) != job_graph_write(job).value:
        raise ValueError("D04 graph job projection differs")
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                        namespace.as_tuple).fetchone()
    if rights != (intent.access_epoch, intent.delete_epoch) or rights != (original.access_epoch, original.delete_epoch):
        raise ValueError("D04 source rights epoch changed")
    metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                         namespace.as_tuple).fetchone()
    if metadata is None:
        raise ValueError("D04 current Authority anchor absent")
    anchor = json.loads(metadata[0])
    expected = {"authority_id": intent.authority_id, "authority_namespace": intent.namespace,
        "activation_generation": intent.authority_activation_generation,
        "revocation_epoch": intent.authority_revocation_epoch,
        "deletion_seq": intent.authority_deletion_seq, "execution_seq": intent.authority_execution_seq}
    if any(anchor.get(k) != v for k, v in expected.items()) or original.activation_generation != intent.authority_activation_generation:
        raise ValueError("D04 Authority generation/anchor changed")
    quote = issuer.resource_issuer.original_signed_quote(db, original.quote_id, original.quote_version)
    if (canonical_digest(quote) != original.quote_digest or quote.work_kind != "d04.appraisal"
            or quote.operation_id != original.operation_id
            or quote.parent_budget_lease_ref != intent.budget_lease_id
            or tuple(sorted(quote.ceiling.items())) != intent.budget_ceiling):
        raise ValueError("D04 original signed quote differs")
    lease = get_budget_lease(db, intent.budget_lease_id)
    if not allow_accounted_result:
        require_budget_family_admissible(db, lease.lease_id)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise ValueError("D04 budget scope differs")
    reserved = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, original.operation_id)).fetchone()
    if (reserved is None or reserved[0] != original.reservation_digest
            or reserved[2] not in ({"reserved", "settled", "overrun", "unknown", "partial_unknown", "partial_overrun"} if allow_accounted_result else {"reserved"})
            or json.loads(reserved[1]) != dict(quote.ceiling)):
        raise ValueError("D04 original reservation unavailable")
    frozen = json.loads(original.frozen_json)
    from ..model_broker.d04_appraisal import thaw_appraisal_request_v1, TEMPLATE_DIGEST
    checked = thaw_appraisal_request_v1(frozen)
    if (checked.model_request_digest != original.model_request_digest
            or request.prompt_template_digest != TEMPLATE_DIGEST
            or dict(request.payload) != json.loads(checked.canonical_wire)
            or request.call_id != original.call_id
            or request.envelope.authority.namespace != namespace
            or request.envelope.authority.actor != intent.subject
            or request.envelope.authority.worker_fence != intent.worker_fence
            or request.identity.operation_id != intent.operation_id
            or request.identity.phase != "d04.appraisal"
            or request.envelope.parent_budget_lease_ref != intent.budget_lease_id):
        raise ValueError("D04 actual typed request differs from its frozen full wire")
    installation = frozen["installation"]
    if ((intent.provider_id, intent.model_id, intent.provider_config_digest, intent.max_output_tokens) !=
            (installation["provider_id"], installation["model_id"], installation["provider_config_digest"], installation["max_output_tokens"])):
        raise ValueError("D04 original installed provider differs")
    return original, job, frozen


def to_wire(value):
    if type(value) not in {D04AppraisalResultReadRequestV3, D04AppraisalResultReadV3}:
        raise TypeError("typed D04 appraisal Authority read required")
    data = json.loads(canonical_serialize(asdict(value)))
    if type(value) is D04AppraisalResultReadV3:
        from .v2_model_egress_contract import model_observation_to_wire_v1
        data["observation"] = model_observation_to_wire_v1(value.observation)
    return data


def from_wire(raw, kind):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("D04 appraisal Authority wire differs")
    data = dict(raw)
    if kind is D04AppraisalResultReadRequestV3:
        data["namespace"] = NamespaceId(**data["namespace"])
    elif kind is D04AppraisalResultReadV3:
        data["request"] = from_wire(data["request"], D04AppraisalResultReadRequestV3)
        from .v2_model_egress_contract import model_observation_from_wire_v1
        data["observation"] = model_observation_from_wire_v1(data["observation"])
        data["terminal_receipt"] = ModelTerminalReceiptV2(**data["terminal_receipt"])
    else:
        raise ValueError("unsupported D04 appraisal Authority read type")
    value = kind(**data)
    if to_wire(value) != raw:
        raise ValueError("noncanonical D04 appraisal Authority read")
    return value
