"""Passive v2 model-egress recovery identity. No field grants a provider call."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .contract import identifier


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

    def __post_init__(self) -> None:
        for name in (
            "authority_id", "namespace", "subject", "operation_id", "call_id",
            "job_id", "fence_token", "budget_lease_id",
            "budget_reservation_operation_id", "provider_id", "model_id",
        ):
            identifier(getattr(self, name), name)
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
        ):
            _integer(getattr(self, name), name, positive=name in {
                "worker_fence", "fence_epoch", "authority_activation_generation"})
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
class ModelEgressRecoveryV1:
    intent: ModelEgressIntentV1
    state: str  # prepared | dispatch_started | observed | unknown
    observation_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.intent) is not ModelEgressIntentV1:
            raise ValueError("invalid model egress intent")
        if self.state not in {"prepared", "dispatch_started", "observed", "unknown"}:
            raise ValueError("invalid model egress recovery state")
        if self.state in {"observed", "unknown"}:
            _digest(self.observation_digest, "observation_digest")
        elif self.observation_digest is not None:
            raise ValueError("unobserved egress cannot have an observation digest")


__all__ = ["ModelEgressIntentV1", "ModelEgressRecoveryV1"]
