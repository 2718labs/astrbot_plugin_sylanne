"""Read-only startup hints for original C01 jobs awaiting their first V3 acquire.

The graph must prove the original installed ingress identity, active D06 access,
queued D11 job, committed D03/D04 baseline, and absence of a V3 acquire before
returning an item. These values grant no model, budget, or graph-write authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..host.d06_ingress import ingress_content_fingerprint
from ..host.ingress import HostIngressEnvelope
from ..runtime_contracts import NamespaceId
from .first_ingress_v2 import ingress_ids


@dataclass(frozen=True, slots=True)
class FirstIngressUnacquiredItemV1:
    namespace: NamespaceId
    installation_id: str
    job_id: str
    original_operation_id: str
    envelope: HostIngressEnvelope
    content_fingerprint: str
    bundle_digest: str
    job_phase: str = "queued"
    schema: str = "sylanne3.runtime.first-ingress-unacquired-item.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.envelope) is not HostIngressEnvelope
                or self.envelope.namespace != self.namespace
                or type(self.installation_id) is not str or not self.installation_id
                or type(self.original_operation_id) is not str
                or type(self.job_id) is not str
                or self.job_phase != "queued"
                or self.schema != "sylanne3.runtime.first-ingress-unacquired-item.v1"
                or any(type(value) is not str or len(value) != 64
                       or any(ch not in "0123456789abcdef" for ch in value)
                       for value in (self.content_fingerprint, self.bundle_digest))):
            raise ValueError("unacquired ingress identity is invalid")
        _, _, original, job, _, _ = ingress_ids(
            self.envelope.lineage.source_ref)
        if (self.original_operation_id != original or self.job_id != job
                or ingress_content_fingerprint(self.envelope)
                   != self.content_fingerprint):
            raise ValueError("unacquired ingress differs from original C01")


@dataclass(frozen=True, slots=True)
class FirstIngressUnacquiredPageV1:
    namespace: NamespaceId
    installation_id: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    items: tuple[FirstIngressUnacquiredItemV1, ...]
    next_after_job_id: str | None
    schema: str = "sylanne3.runtime.first-ingress-unacquired-page.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.installation_id) is not str or not self.installation_id
                or type(self.graph_incarnation) is not str or not self.graph_incarnation
                or type(self.graph_revision) is not int or self.graph_revision < 0
                or type(self.graph_epoch) is not int or self.graph_epoch < 0
                or type(self.items) is not tuple
                or any(type(item) is not FirstIngressUnacquiredItemV1
                       or item.namespace != self.namespace
                       or item.installation_id != self.installation_id
                       for item in self.items)
                or self.next_after_job_id is not None and (
                    type(self.next_after_job_id) is not str
                    or not self.next_after_job_id)
                or self.schema != "sylanne3.runtime.first-ingress-unacquired-page.v1"):
            raise ValueError("unacquired ingress page identity is invalid")


__all__ = ("FirstIngressUnacquiredItemV1", "FirstIngressUnacquiredPageV1")
