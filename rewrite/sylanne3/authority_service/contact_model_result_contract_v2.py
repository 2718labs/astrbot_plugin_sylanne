"""Closed current paid contact-result delivery, independent of responsive reply."""
from dataclasses import dataclass, fields
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import NamespaceId, canonical_digest
from .v2_model_egress_contract import ModelEgressObservationV1, ModelTerminalReceiptV2
from .v2_model_egress_wire import to_wire as model_wire, from_wire as model_unwire


@dataclass(frozen=True, slots=True)
class ContactModelResultReadRequestV2:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    contact_id: str
    phase: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = "contact_paid_expression_v2"
    schema: str = "d10.contact-model-result-read.v2"

    def __post_init__(self):
        from .contract import identifier
        if (self.phase not in {"contact_generation", "contact_review"} or self.purpose != "contact_paid_expression_v2"
                or self.schema != "d10.contact-model-result-read.v2" or type(self.namespace) is not NamespaceId):
            raise ValueError("contact result reader scope differs")
        for name in ("authority_id", "authority_namespace", "installation_id", "contact_id", "job_id", "call_id",
                "acquire_operation_id", "original_operation_id", "consumer_operation_id", "read_attempt_id"):
            identifier(getattr(self, name), name)
        for value in (self.binding_digest, self.model_request_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("contact result original commitment differs")


@dataclass(frozen=True, slots=True)
class ContactModelResultReadV2:
    request: ContactModelResultReadRequestV2
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    read_at_utc: float
    current_scope_digest: str
    schema: str = "d10.contact-model-result-read.v2"

    def __post_init__(self):
        import math
        request, observation, receipt = self.request, self.observation, self.terminal_receipt
        if (type(request) is not ContactModelResultReadRequestV2 or type(observation) is not ModelEgressObservationV1
                or type(receipt) is not ModelTerminalReceiptV2 or observation.status != "completed"
                or self.schema != "d10.contact-model-result-read.v2"
                or type(self.read_at_utc) not in (int, float) or not math.isfinite(self.read_at_utc)
                or self.read_at_utc <= 0 or type(self.current_scope_digest) is not str or len(self.current_scope_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.current_scope_digest)
                or (observation.authority_id, observation.namespace, observation.operation_id, observation.call_id, observation.request_digest) !=
                    (request.authority_id, request.authority_namespace, request.acquire_operation_id, request.call_id, request.model_request_digest)
                or (receipt.call_id, receipt.request_digest, receipt.observation_digest, receipt.installation_id) !=
                    (request.call_id, request.model_request_digest, observation.digest, request.installation_id)):
            raise ValueError("contact actual completed result and terminal differ")

    def require_original(self, intent, prepared):
        request = self.request
        if ((request.namespace, request.installation_id, request.contact_id, request.phase, request.job_id,
                request.original_operation_id, request.acquire_operation_id, request.call_id, request.binding_digest) !=
                (prepared.namespace, prepared.installation_id, prepared.contact_id, prepared.phase, prepared.job_id,
                 prepared.prepare_operation_id, prepared.acquire_operation_id, prepared.call_id, prepared.digest)
                or request.model_request_digest != intent.request_digest or intent.binding_digest != prepared.digest
                or intent.call_id != prepared.call_id or intent.job_id != prepared.job_id
                or intent.operation_id != prepared.acquire_operation_id or self.observation.subject != intent.subject):
            raise ValueError("contact delivered result differs from its exact actual prepared once call")


def contact_result_to_wire_v2(value):
    if type(value) is ContactModelResultReadRequestV2:
        return plain_v1(value)
    if type(value) is not ContactModelResultReadV2:
        raise TypeError("closed contact result DTO required")
    data = plain_v1(value)
    # Observations have a separate closed contract; the passive model wire
    # deliberately does not issue or decode Authority observation DTOs.
    data["observation"] = plain_v1(value.observation)
    data["terminal_receipt"] = model_wire(value.terminal_receipt)
    return data


def contact_result_from_wire_v2(raw, kind):
    if kind not in {ContactModelResultReadRequestV2, ContactModelResultReadV2} or type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("contact result exact fields differ")
    data = dict(raw)
    if kind is ContactModelResultReadRequestV2:
        data["namespace"] = NamespaceId(**data["namespace"])
    else:
        data["request"] = contact_result_from_wire_v2(data["request"], ContactModelResultReadRequestV2)
        observation = data["observation"]
        if (type(observation) is not dict
                or set(observation) != {f.name for f in fields(ModelEgressObservationV1)}):
            raise ValueError("contact observation exact fields differ")
        observation = dict(observation)
        for name in ("usage", "cost"):
            pairs = observation[name]
            if (type(pairs) is not list
                    or any(type(pair) is not list or len(pair) != 2
                           or type(pair[0]) is not str or type(pair[1]) is not int for pair in pairs)):
                raise ValueError("contact observation amount pairs differ")
            observation[name] = tuple(tuple(pair) for pair in pairs)
        data["observation"] = ModelEgressObservationV1(**observation)
        data["terminal_receipt"] = model_unwire(data["terminal_receipt"], ModelTerminalReceiptV2)
    result = kind(**data)
    if canonical_digest(contact_result_to_wire_v2(result)) != canonical_digest(raw):
        raise ValueError("contact result wire is noncanonical")
    return result
