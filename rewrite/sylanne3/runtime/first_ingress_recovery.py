"""Content-free identities for discovering original V3 encoding work after restart.

These records are navigation hints. They are never model-dispatch, result-read,
budget, or graph-write permits; every subsequent operation rechecks Authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..runtime_contracts import NamespaceId


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class FirstIngressRecoveryItemV1:
    namespace: NamespaceId
    installation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str
    job_phase: str
    original_worker_actor: str
    original_worker_fence: int
    original_worker_lease_expires_utc: str
    recovery_state: str
    c02_operation_digest: str | None
    c02_commit_seq: int | None
    schema: str = "sylanne3.runtime.first-ingress-recovery-item.v1"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or self.schema != (
                "sylanne3.runtime.first-ingress-recovery-item.v1"):
            raise ValueError("V3 recovery item identity is invalid")
        for name in (
                "installation_id", "job_id", "acquire_operation_id",
                "original_operation_id", "call_id", "consumer_operation_id",
                "original_worker_actor", "original_worker_lease_expires_utc",
        ):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} is required")
        for name in ("binding_digest", "model_request_digest"):
            if type(getattr(self, name)) is not str or not _DIGEST.fullmatch(
                    getattr(self, name)):
                raise ValueError(f"{name} must be SHA-256")
        if (type(self.original_worker_fence) is not int
                or self.original_worker_fence < 1
                or self.job_phase not in {"running", "completed"}
                or self.recovery_state not in {
                    "original_fence", "expired_lease_hold", "c02_pending_hold",
                    "c02_committed"}):
            raise ValueError("V3 recovery state is invalid")
        if self.recovery_state == "c02_pending_hold" and self.job_phase != "running":
            raise ValueError("pending C02 requires the original running job")
        if (self.c02_operation_digest is None) != (self.c02_commit_seq is None):
            raise ValueError("C02 receipt identity must be complete")
        if self.c02_operation_digest is not None and (
                not _DIGEST.fullmatch(self.c02_operation_digest)
                or type(self.c02_commit_seq) is not int
                or self.c02_commit_seq < 1
                or self.recovery_state != "c02_committed"):
            raise ValueError("C02 receipt identity is invalid")


@dataclass(frozen=True, slots=True)
class FirstIngressRecoveryPageV1:
    namespace: NamespaceId
    installation_id: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    items: tuple[FirstIngressRecoveryItemV1, ...]
    next_cursor: str | None
    schema: str = "sylanne3.runtime.first-ingress-recovery-page.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or self.schema != "sylanne3.runtime.first-ingress-recovery-page.v1"
                or type(self.installation_id) is not str or not self.installation_id
                or type(self.graph_incarnation) is not str or not self.graph_incarnation
                or type(self.graph_revision) is not int or self.graph_revision < 0
                or type(self.graph_epoch) is not int or self.graph_epoch < 0
                or type(self.items) is not tuple
                or any(type(item) is not FirstIngressRecoveryItemV1
                       or item.namespace != self.namespace
                       or item.installation_id != self.installation_id
                       for item in self.items)
                or self.next_cursor is not None and (
                    type(self.next_cursor) is not str or not self.next_cursor)):
            raise ValueError("V3 recovery page identity is invalid")


__all__ = ("FirstIngressRecoveryItemV1", "FirstIngressRecoveryPageV1")
