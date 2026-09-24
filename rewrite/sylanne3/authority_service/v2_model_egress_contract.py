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

    @classmethod
    def from_response(cls, intent: ModelEgressIntentV1, response) -> ModelEgressObservationV1:
        """Internal executor adapter. Never accept a caller-supplied digest."""
        from ..model_broker.broker import ProviderResponse
        if type(intent) is not ModelEgressIntentV1 or type(response) is not ProviderResponse:
            raise ValueError("typed intent and parsed provider response required")
        if response.status == "not_dispatched":
            raise ValueError("dispatch_started cannot be reclassified as unsent")
        return cls(intent.authority_id, intent.namespace, intent.subject,
                   intent.operation_id, intent.call_id, intent.request_digest,
                   response.status,
                   canonical_serialize(dict(response.result)) if response.result is not None else None,
                   tuple(sorted(response.usage.items())), tuple(sorted(response.cost.items())),
                   response.provider_call_ref)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @property
    def result(self) -> dict | None:
        return json.loads(self.result_json) if self.result_json is not None else None


@dataclass(frozen=True, slots=True)
class ModelEgressRecoveryV1:
    intent: ModelEgressIntentV1
    state: str  # prepared | dispatch_started | observed | unknown
    observation_digest: str | None = None
    observation: ModelEgressObservationV1 | None = None

    def __post_init__(self) -> None:
        if type(self.intent) is not ModelEgressIntentV1:
            raise ValueError("invalid model egress intent")
        if self.state not in {"prepared", "dispatch_started", "observed", "unknown"}:
            raise ValueError("invalid model egress recovery state")
        if self.state in {"observed", "unknown"}:
            _digest(self.observation_digest, "observation_digest")
        elif self.observation_digest is not None:
            raise ValueError("unobserved egress cannot have an observation digest")
        if self.observation is not None:
            if (type(self.observation) is not ModelEgressObservationV1
                    or self.observation.digest != self.observation_digest
                    or self.observation.status != ("completed" if self.state == "observed" else "unknown")
                    or (self.observation.authority_id, self.observation.namespace,
                        self.observation.subject, self.observation.operation_id,
                        self.observation.call_id, self.observation.request_digest) !=
                       (self.intent.authority_id, self.intent.namespace,
                        self.intent.subject, self.intent.operation_id,
                        self.intent.call_id, self.intent.request_digest)):
                raise ValueError("observation differs from original call")
        elif self.state == "observed":
            raise ValueError("observed egress requires complete durable observation")


__all__ = ["ModelEgressDraftV1", "ModelEgressIntentV1", "ModelEgressObservationV1", "ModelEgressRecoveryV1"]
