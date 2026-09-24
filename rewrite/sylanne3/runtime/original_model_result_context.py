"""Content-free graph context for a first-ingress worker's original result."""

from __future__ import annotations

from dataclasses import dataclass

from ..runtime_contracts import NamespaceId
from .restore_anchor import RestoreAnchor


@dataclass(frozen=True, slots=True)
class OriginalModelResultContextV1:
    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    installation_id: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    source_id: str
    source_revision: int
    access_revision: int
    worker_actor: str
    worker_fence: int
    worker_lease_expires_utc: str
    anchor: RestoreAnchor
    schema: str = "sylanne3.graph.original-model-result-context.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.anchor) is not RestoreAnchor
                or self.schema != "sylanne3.graph.original-model-result-context.v1"
                or (self.anchor.authority_id, self.anchor.namespace) !=
                   (self.authority_id, self.authority_namespace)):
            raise ValueError("original model result context identity differs")
        for name in (
                "installation_id", "graph_incarnation", "job_id", "acquire_operation_id",
                "original_operation_id", "call_id", "source_id",
                "worker_actor", "worker_lease_expires_utc"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} is required")
        for name in ("binding_digest", "model_request_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"{name} must be SHA-256")
        for name in ("graph_revision", "graph_epoch", "access_epoch", "delete_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be nonnegative")
        for name in ("source_revision", "access_revision", "worker_fence"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be positive")


__all__ = ("OriginalModelResultContextV1",)
