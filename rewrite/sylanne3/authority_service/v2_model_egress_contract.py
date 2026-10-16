"""Passive v2 model-egress recovery identity. No field grants a provider call."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from .contract import identifier
from .v2_contract import _TOKEN
from ..runtime_contracts import canonical_digest, canonical_serialize


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: str, name: str) -> None:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise ValueError(f"invalid {name}")


def _integer(value: int, name: str, *, positive: bool = False) -> None:
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class ModelEgressIntentV1:
    """Exact proposed call and original limits; currentness requires future verification."""

    authority_id: str
    namespace: str
    subject: str
    operation_id: str
    call_id: str
    request_digest: str  # ModelCallRequest.digest, including the complete payload.
    job_id: str
    worker_fence: int
    fence_token: str
    fence_epoch: int
    fence_revision: int
    anchor_digest: str
    source_refs: tuple[str, ...]
    source_revisions: tuple[tuple[str, int], ...]
    access_revisions: tuple[tuple[str, int], ...]
    access_epoch: int
    delete_epoch: int
    graph_epoch: int
    graph_revision: int
    authority_activation_generation: int
    authority_revocation_epoch: int
    authority_deletion_seq: int
    authority_execution_seq: int
    budget_lease_id: str
    budget_reservation_operation_id: str
    budget_reservation_digest: str
    budget_ceiling: tuple[tuple[str, int], ...]
    provider_id: str
    model_id: str
    provider_config_digest: str
    max_output_tokens: int
    # V2 original-identity extension. Legacy rows have neither field and are
    # ineligible for original-intent lookup.
    acquire_operation_id: str | None = None
    binding_digest: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "authority_id", "namespace", "subject", "operation_id", "call_id",
            "job_id", "budget_lease_id",
            "budget_reservation_operation_id", "provider_id", "model_id",
        ):
            identifier(getattr(self, name), name)
        if type(self.fence_token) is not str or not _TOKEN.fullmatch(self.fence_token):
            raise ValueError("invalid fence_token")
        if self.operation_id == self.call_id:
            raise ValueError("call ID must differ from operation ID")
        for name in ("request_digest", "anchor_digest", "budget_reservation_digest",
                     "provider_config_digest"):
            _digest(getattr(self, name), name)
        if (self.acquire_operation_id is None) != (self.binding_digest is None):
            raise ValueError("incomplete original model binding")
        if self.acquire_operation_id is not None:
            identifier(self.acquire_operation_id, "acquire_operation_id")
            if self.acquire_operation_id != self.operation_id:
                raise ValueError("model operation differs from original acquire")
            _digest(self.binding_digest, "binding_digest")
        for name in (
            "worker_fence", "fence_epoch", "fence_revision", "access_epoch",
            "delete_epoch", "graph_epoch", "graph_revision",
            "authority_activation_generation", "authority_revocation_epoch",
            "authority_deletion_seq", "authority_execution_seq",
            "max_output_tokens",
        ):
            _integer(getattr(self, name), name, positive=name in {
                "worker_fence", "fence_epoch", "authority_activation_generation",
                "max_output_tokens"})
        if (type(self.source_refs) is not tuple or not self.source_refs
                or len(set(self.source_refs)) != len(self.source_refs)):
            raise ValueError("source references must be a nonempty unique tuple")
        for ref in self.source_refs:
            identifier(ref, "source_ref")
        if (type(self.source_revisions) is not tuple or not self.source_revisions
                or len({ref for ref, _ in self.source_revisions}) != len(self.source_revisions)):
            raise ValueError("source revisions must be unique")
        for ref, revision in self.source_revisions:
            identifier(ref, "source_revision_ref")
            _integer(revision, "source_revision", positive=True)
        if not set(self.source_refs) <= {ref for ref, _ in self.source_revisions}:
            raise ValueError("source revisions do not cover all source references")
        if (type(self.access_revisions) is not tuple or not self.access_revisions
                or len({ref for ref, _ in self.access_revisions}) != len(self.access_revisions)):
            raise ValueError("access revisions must be unique")
        for ref, revision in self.access_revisions:
            identifier(ref, "access_revision_ref")
            _integer(revision, "access_revision", positive=True)
        if type(self.budget_ceiling) is not tuple or not self.budget_ceiling:
            raise ValueError("original budget ceiling is required")
        if len({key for key, _ in self.budget_ceiling}) != len(self.budget_ceiling):
            raise ValueError("budget dimensions must be unique")
        for key, amount in self.budget_ceiling:
            identifier(key, "budget_dimension")
            _integer(amount, "budget_ceiling", positive=True)


@dataclass(frozen=True, slots=True)
class ModelEgressDraftV1:
    """Stable proposed call; Authority alone fills the new model fence fields."""

    authority_id: str
    namespace: str
    subject: str
    operation_id: str
    call_id: str
    request_digest: str
    job_id: str
    worker_fence: int
    source_refs: tuple[str, ...]
    source_revisions: tuple[tuple[str, int], ...]
    access_revisions: tuple[tuple[str, int], ...]
    access_epoch: int
    delete_epoch: int
    graph_epoch: int
    graph_revision: int
    authority_activation_generation: int
    authority_revocation_epoch: int
    authority_deletion_seq: int
    authority_execution_seq: int
    budget_lease_id: str
    budget_reservation_operation_id: str
    budget_reservation_digest: str
    budget_ceiling: tuple[tuple[str, int], ...]
    provider_id: str
    model_id: str
    provider_config_digest: str
    max_output_tokens: int
    acquire_operation_id: str | None = None
    binding_digest: str | None = None

    def __post_init__(self) -> None:
        # Keep one validation contract for the shared call fields. The dummy
        # fence values never leave this constructor or enter persistence.
        ModelEgressIntentV1(**asdict(self), fence_token="a" * 32,
                            fence_epoch=1, fence_revision=0,
                            anchor_digest="0" * 64)

    @classmethod
    def from_intent(cls, intent: ModelEgressIntentV1) -> ModelEgressDraftV1:
        if type(intent) is not ModelEgressIntentV1:
            raise ValueError("typed model egress intent required")
        return cls(**{field.name: getattr(intent, field.name) for field in fields(cls)})


@dataclass(frozen=True, slots=True)
class ModelEgressObservationV1:
    """Authority-owned, fully parsed provider observation bound to the original call."""

    authority_id: str
    namespace: str
    subject: str
    operation_id: str
    call_id: str
    request_digest: str
    status: str  # completed | unknown
    result_json: str | None
    usage: tuple[tuple[str, int], ...]
    cost: tuple[tuple[str, int], ...]
    provider_call_ref: str | None
    billing_receipt_json: str | None = None

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "subject", "operation_id", "call_id"):
            identifier(getattr(self, name), name)
        _digest(self.request_digest, "request_digest")
        if self.status not in {"completed", "unknown"}:
            raise ValueError("invalid provider observation status")
        if self.status == "completed":
            if type(self.result_json) is not str:
                raise ValueError("completed observation requires result JSON")
            try:
                result = json.loads(self.result_json)
                if type(result) is not dict or canonical_serialize(result) != self.result_json:
                    raise ValueError("noncanonical result JSON")
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid result JSON") from exc
        elif self.result_json is not None:
            raise ValueError("unknown observation has no eligible result")
        for name in ("usage", "cost"):
            amounts = getattr(self, name)
            if (type(amounts) is not tuple
                    or len({key for key, _ in amounts}) != len(amounts)
                    or tuple(sorted(amounts)) != amounts):
                raise ValueError(f"invalid {name}")
            for key, amount in amounts:
                if type(key) is not str or not key or len(key) > 256:
                    raise ValueError(f"invalid {name} key")
                _integer(amount, f"{name} amount")
        if self.provider_call_ref is not None:
            if (type(self.provider_call_ref) is not str or not self.provider_call_ref
                    or len(self.provider_call_ref) > 256):
                raise ValueError("invalid provider_call_ref")
        if self.billing_receipt_json is not None:
            if self.status != "completed":
                raise ValueError("billing receipt requires the original completed observation")
            _billing_observation_receipt_v1(self)

    @classmethod
    def from_response(cls, intent: ModelEgressIntentV1, response) -> ModelEgressObservationV1:
        """Internal executor adapter. Never accept a caller-supplied digest."""
        from ..model_broker.broker import ProviderResponse
        if type(intent) is not ModelEgressIntentV1 or type(response) is not ProviderResponse:
            raise ValueError("typed intent and parsed provider response required")
        if response.status == "not_dispatched":
            raise ValueError("dispatch_started cannot be reclassified as unsent")
        observation = cls(intent.authority_id, intent.namespace, intent.subject,
                   intent.operation_id, intent.call_id, intent.request_digest,
                   response.status,
                   canonical_serialize(dict(response.result)) if response.result is not None else None,
                   tuple(sorted(response.usage.items())), tuple(sorted(response.cost.items())),
                   response.provider_call_ref, response.billing_receipt_json)
        require_model_observation_billing_intent_v1(observation, intent)
        return observation

    @property
    def digest(self) -> str:
        return canonical_digest(model_observation_to_wire_v1(self))

    @property
    def result(self) -> dict | None:
        return json.loads(self.result_json) if self.result_json is not None else None


@dataclass(frozen=True, slots=True)
class ModelEgressRecoveryV1:
    """Content-free recovery. Provider result requires future qualified access."""

    intent: ModelEgressIntentV1
    state: str  # prepared | dispatch_started | observed | unknown
    observation_digest: str | None = None
    usage: tuple[tuple[str, int], ...] = ()
    cost: tuple[tuple[str, int], ...] = ()
    content_erased: bool = False

    def __post_init__(self) -> None:
        if type(self.intent) is not ModelEgressIntentV1:
            raise ValueError("invalid model egress intent")
        if self.state not in {"prepared", "dispatch_started", "observed", "unknown"}:
            raise ValueError("invalid model egress recovery state")
        if self.state in {"observed", "unknown"}:
            _digest(self.observation_digest, "observation_digest")
        elif (self.observation_digest is not None or self.usage or self.cost
              or self.content_erased):
            raise ValueError("unobserved egress cannot have observation metadata")
        if type(self.content_erased) is not bool:
            raise ValueError("invalid content erasure marker")
        for name in ("usage", "cost"):
            amounts = getattr(self, name)
            if (type(amounts) is not tuple or tuple(sorted(amounts)) != amounts
                    or len({key for key, _ in amounts}) != len(amounts)):
                raise ValueError(f"invalid {name}")
            for key, amount in amounts:
                if type(key) is not str or not key or len(key) > 256:
                    raise ValueError(f"invalid {name} key")
                _integer(amount, f"{name} amount")


@dataclass(frozen=True, slots=True)
class ModelAdmissionV2:
    """Authority-issued once-only marker for one installed host incarnation."""

    admission_id: str
    authority_id: str
    namespace: str
    subject: str
    operation_id: str
    call_id: str
    request_digest: str
    provider_config_digest: str
    installation_id: str
    observer_peer_sha256: str
    observer_profile_id: str
    manifest_digest: str
    host_incarnation: str

    def __post_init__(self) -> None:
        for name in ("admission_id", "request_digest", "provider_config_digest", "observer_peer_sha256",
                     "manifest_digest", "host_incarnation"):
            _digest(getattr(self, name), name)
        for name in ("authority_id", "namespace", "subject", "operation_id",
                     "call_id", "installation_id", "observer_profile_id"):
            identifier(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class HostObservedModelCompletionV2:
    """Full completed response asserted by the designated mTLS host adapter.

    Its transport proves the installed observer identity, not an independent
    HTTP/provider receipt. Unknown and not_dispatched are not terminal reports.
    """

    admission_id: str
    host_incarnation: str
    call_id: str
    request_digest: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    result_json: str
    usage: tuple[tuple[str, int], ...]
    cost: tuple[tuple[str, int], ...]
    provider_call_ref: str | None
    billing_receipt_json: str | None = None

    def __post_init__(self) -> None:
        for name in ("admission_id", "host_incarnation", "request_digest",
                     "provider_config_digest"):
            _digest(getattr(self, name), name)
        for name in ("call_id", "provider_id", "model_id"):
            identifier(getattr(self, name), name)
        if self.provider_call_ref is not None:
            identifier(self.provider_call_ref, "provider_call_ref")
        if type(self.result_json) is not str:
            raise ValueError("completed host observation requires result JSON")
        result = json.loads(self.result_json)
        if type(result) is not dict or canonical_serialize(result) != self.result_json:
            raise ValueError("noncanonical completed result JSON")
        for name in ("usage", "cost"):
            amounts = getattr(self, name)
            if (type(amounts) is not tuple or tuple(sorted(amounts)) != amounts
                    or len({key for key, _ in amounts}) != len(amounts)):
                raise ValueError(f"invalid {name}")
            for key, amount in amounts:
                identifier(key, name)
                _integer(amount, f"{name} amount")
        if self.billing_receipt_json is not None:
            receipt = _billing_observation_receipt_v1(self)
            if (receipt.provider_id, receipt.model_id, receipt.provider_config_digest) != (
                    self.provider_id, self.model_id, self.provider_config_digest):
                raise ValueError("billing receipt differs from the actual provider/model/configuration")

    @property
    def digest(self) -> str:
        return canonical_digest(host_model_completion_to_wire_v2(self))

    def observation_for(self, intent: ModelEgressIntentV1) -> ModelEgressObservationV1:
        if (type(intent) is not ModelEgressIntentV1
                or (self.call_id, self.request_digest, self.provider_id,
                    self.model_id, self.provider_config_digest) !=
                   (intent.call_id, intent.request_digest, intent.provider_id,
                    intent.model_id, intent.provider_config_digest)):
            raise ValueError("host completion differs from original model call")
        return ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", self.result_json, self.usage, self.cost,
            self.provider_call_ref, self.billing_receipt_json)


def _billing_observation_receipt_v1(value):
    from ..model_broker.provider_billing_receipt_v1 import provider_billing_receipt_from_json_v1
    receipt = provider_billing_receipt_from_json_v1(value.billing_receipt_json)
    if ((receipt.call_id, receipt.request_digest, receipt.provider_call_ref) != (
            value.call_id, value.request_digest, value.provider_call_ref)
            or receipt.usage != dict(value.usage)
            or dict(value.cost).get("model_microusd") != receipt.final_charged_amount):
        raise ValueError("billing receipt differs from original call/response/usage/final charge")
    return receipt


def require_model_observation_billing_intent_v1(observation, intent):
    if observation.billing_receipt_json is not None:
        receipt = _billing_observation_receipt_v1(observation)
        if (receipt.provider_id, receipt.model_id, receipt.provider_config_digest) != (
                intent.provider_id, intent.model_id, intent.provider_config_digest):
            raise ValueError("billing receipt differs from original model intent configuration")


def _model_observation_wire_v1(value, kind):
    if type(value) is not kind:
        raise TypeError("exact model observation/report required")
    data = asdict(value)
    if data["billing_receipt_json"] is None:
        del data["billing_receipt_json"]
    for name in ("usage", "cost"):
        data[name] = [list(pair) for pair in data[name]]
    return data


def _model_observation_unwire_v1(raw, kind):
    expected = set(kind.__dataclass_fields__)
    legacy = expected - {"billing_receipt_json"}
    if (type(raw) is not dict or set(raw) not in (legacy, expected)
            or "billing_receipt_json" in raw and type(raw["billing_receipt_json"]) is not str):
        raise ValueError("model observation/report exact legacy or billing fields required")
    data = dict(raw)
    for name in ("usage", "cost"):
        pairs = data[name]
        if (type(pairs) is not list or any(type(pair) is not list or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not int for pair in pairs)):
            raise ValueError("model observation/report amount pairs differ")
        data[name] = tuple(tuple(pair) for pair in pairs)
    result = kind(**data)
    if _model_observation_wire_v1(result, kind) != raw:
        raise ValueError("noncanonical model observation/report wire")
    return result


def model_observation_to_wire_v1(value):
    return _model_observation_wire_v1(value, ModelEgressObservationV1)


def model_observation_from_wire_v1(raw):
    return _model_observation_unwire_v1(raw, ModelEgressObservationV1)


def host_model_completion_to_wire_v2(value):
    return _model_observation_wire_v1(value, HostObservedModelCompletionV2)


def host_model_completion_from_wire_v2(raw):
    return _model_observation_unwire_v1(raw, HostObservedModelCompletionV2)


@dataclass(frozen=True, slots=True)
class ModelTerminalReceiptV2:
    """Content-free durable receipt for one bound host observation and finish."""

    admission_id: str
    call_id: str
    request_digest: str
    report_digest: str
    observation_digest: str
    finish_digest: str
    installation_id: str
    host_incarnation: str

    def __post_init__(self) -> None:
        for name in ("admission_id", "request_digest", "report_digest",
                     "observation_digest", "host_incarnation"):
            _digest(getattr(self, name), name)
        if (type(self.finish_digest) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.finish_digest)):
            raise ValueError("invalid terminal finish digest")
        for name in ("call_id", "installation_id"):
            identifier(getattr(self, name), name)


__all__ = [
    "ModelEgressDraftV1", "ModelEgressIntentV1", "ModelEgressObservationV1",
    "ModelEgressRecoveryV1", "ModelAdmissionV2", "HostObservedModelCompletionV2",
    "ModelTerminalReceiptV2",
    "model_observation_to_wire_v1", "model_observation_from_wire_v1",
    "host_model_completion_to_wire_v2", "host_model_completion_from_wire_v2",
    "require_model_observation_billing_intent_v1",
]

MODEL_NO_DISPATCH_SIGN_KIND_V1 = "authority.model-no-dispatch-witness.v1"


@dataclass(frozen=True, slots=True)
class ModelNoDispatchClosureRequestV1:
    intent: ModelEgressIntentV1
    installation_id: str
    holder: str
    expected_anchor: object
    requested_deadline_utc: str
    requested_cancel_cause_ref: str
    schema: str = "sylanne3.authority.model-no-dispatch-closure.v1"

    def __post_init__(self):
        from ..runtime.restore_anchor import RestoreAnchor
        from ..runtime.d11_offline_originals_v1 import _utc
        if (self.schema != "sylanne3.authority.model-no-dispatch-closure.v1"
                or type(self.intent) is not ModelEgressIntentV1
                or type(self.expected_anchor) is not RestoreAnchor
                or (self.expected_anchor.authority_id, self.expected_anchor.namespace) !=
                   (self.intent.authority_id, self.intent.namespace)
                or self.intent.acquire_operation_id is None or self.intent.binding_digest is None):
            raise ValueError("exact original installed unsent model request required")
        identifier(self.installation_id, "installation_id")
        identifier(self.holder, "holder")
        identifier(self.requested_cancel_cause_ref, "requested_cancel_cause_ref")
        _utc(self.requested_deadline_utc)

    @property
    def identity_digest(self):
        from dataclasses import asdict
        from ..runtime_contracts import canonical_digest
        return canonical_digest((self.schema, asdict(self.intent), self.installation_id,
            self.holder, self.requested_deadline_utc, self.requested_cancel_cause_ref))


@dataclass(frozen=True, slots=True)
class ModelNoDispatchWitnessV1:
    request: ModelNoDispatchClosureRequestV1
    original_permit: object
    namespace_epoch: int
    prepared_row_commitment: str
    finished_row_commitment: str
    absence_scope_commitment: str
    before_anchor: object
    after_anchor: object
    finish_request_id: str
    finish_digest: str
    witness_operation_id: str
    signature: str
    schema: str = "sylanne3.authority.model-no-dispatch-witness.v1"

    def __post_init__(self):
        from dataclasses import asdict
        from ..runtime.restore_anchor import RestoreAnchor
        from ..runtime_contracts import canonical_digest
        from .v2_contract import FencePermitV2
        from .v2_fence_store import AuthorityV2FenceStore
        r, p = self.request, self.original_permit
        if (self.schema != "sylanne3.authority.model-no-dispatch-witness.v1"
                or type(r) is not ModelNoDispatchClosureRequestV1 or type(p) is not FencePermitV2
                or type(self.before_anchor) is not RestoreAnchor or self.after_anchor != self.before_anchor
                or self.before_anchor != r.expected_anchor or type(self.namespace_epoch) is not int or self.namespace_epoch < 1
                or p.operation != "model_egress"
                or (p.authority_id, p.namespace, p.subject, p.holder, p.operation_id,
                    p.token, p.fence_epoch, p.revision, canonical_digest(asdict(p.pinned_anchor))) !=
                   (r.intent.authority_id, r.intent.namespace, r.intent.subject, r.holder, r.intent.operation_id,
                    r.intent.fence_token, r.intent.fence_epoch, r.intent.fence_revision, r.intent.anchor_digest)
                or self.finish_request_id != r.intent.call_id
                or self.finish_digest != AuthorityV2FenceStore.model_terminal_finish_digest(r.intent, p, "not_dispatched")
                or self.witness_operation_id != "model-no-dispatch:" + r.identity_digest):
            raise ValueError("Authority unsent witness changed its original exact fence/call")
        for name in ("prepared_row_commitment", "finished_row_commitment", "absence_scope_commitment"):
            _digest(getattr(self, name), name)
        if type(self.signature) is not str or not self.signature:
            raise ValueError("actual Authority producer signature required")

    @property
    def unsigned_wire(self):
        from dataclasses import asdict
        from .v2_contract import to_wire as permit_to_wire
        from .v2_model_egress_wire import to_wire as model_to_wire
        value = asdict(self)
        value["request"] = model_to_wire(self.request)
        value["original_permit"] = permit_to_wire(self.original_permit)
        value.pop("signature")
        return value

    @property
    def digest(self):
        from ..runtime_contracts import canonical_digest
        return canonical_digest(self.unsigned_wire)

    def require_signature_v1(self, signer):
        from ..runtime_contracts import canonical_serialize
        signer.verify(MODEL_NO_DISPATCH_SIGN_KIND_V1, canonical_serialize(self.unsigned_wire), self.signature)
        return self

