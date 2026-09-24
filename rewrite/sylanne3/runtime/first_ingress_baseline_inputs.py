"""Content-free, current C01 inputs for a future D04 baseline issuer."""

from __future__ import annotations

from dataclasses import dataclass

from ..runtime_contracts import NamespaceId, SourceQualification
from .restore_anchor import RestoreAnchor


@dataclass(frozen=True, slots=True)
class FirstIngressBaselineInputsV1:
    namespace: NamespaceId
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    job_id: str
    activity_id: str
    original_operation_id: str
    source_ref: str
    source_revision: int
    access_revision: int
    qualification: SourceQualification
    anchor: RestoreAnchor
    schema: str = "sylanne3.graph.first-ingress-baseline-inputs.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.anchor) is not RestoreAnchor
                or type(self.qualification) is not SourceQualification
                or self.schema != "sylanne3.graph.first-ingress-baseline-inputs.v1"):
            raise ValueError("baseline inputs require typed graph evidence")
        for name in ("graph_incarnation", "job_id", "activity_id",
                     "original_operation_id", "source_ref"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} is required")
        for name in ("graph_revision", "graph_epoch", "access_epoch", "delete_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be nonnegative")
        for name in ("source_revision", "access_revision"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.qualification.source_refs != (self.source_ref,):
            raise ValueError("baseline source differs from original qualification")


__all__ = ("FirstIngressBaselineInputsV1",)
