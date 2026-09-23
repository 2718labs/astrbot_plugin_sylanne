from __future__ import annotations

from dataclasses import dataclass
import math

from ..runtime_contracts import NamespaceId


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{label} must be a bounded nonempty string")
    return value


@dataclass(frozen=True)
class SourceLineage:
    source_ref: str
    source_kind: str
    provenance_family: str
    content_reality: str
    evidence_eligibility: str
    internal_activity_actuality: str = "not_applicable"

    def __post_init__(self) -> None:
        if len(self.source_ref) != 64 or any(ch not in "0123456789abcdef" for ch in self.source_ref):
            raise ValueError("source_ref must be a SHA256 identity")
        _identifier(self.provenance_family, "provenance_family")
        if self.source_kind != "reported":
            raise ValueError("host message lineage is a reported source")
        if self.content_reality != "external_report":
            raise ValueError("host messages cannot upgrade report reality")
        if self.evidence_eligibility != "reported_claim":
            raise ValueError("host messages cannot upgrade evidence eligibility")
        if self.internal_activity_actuality != "not_applicable":
            raise ValueError("external ingress is not internal activity")


@dataclass(frozen=True)
class HostIngressEnvelope:
    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    sender_ref: str
    message_id: str
    text: str
    occurred_at: float | None
    learned_at: float
    visibility: str
    lineage: SourceLineage

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if not isinstance(self.lineage, SourceLineage):
            raise TypeError("lineage must be SourceLineage")
        for field in ("platform_ref", "conversation_ref", "sender_ref", "message_id"):
            _identifier(getattr(self, field), field)
        if not isinstance(self.text, str) or not self.text or len(self.text) > 32_768:
            raise ValueError("text must contain 1..32768 characters")
        if not math.isfinite(self.learned_at) or self.learned_at <= 0:
            raise ValueError("learned_at must be finite and positive")
        if self.occurred_at is not None:
            if not math.isfinite(self.occurred_at) or self.occurred_at <= 0:
                raise ValueError("occurred_at must be finite and positive when known")
            if self.learned_at < self.occurred_at:
                raise ValueError("learned_at cannot precede occurred_at")
        if self.visibility not in {"private", "group", "other"}:
            raise ValueError("unsupported visibility")


@dataclass(frozen=True)
class IngressReceipt:
    status: str
    operation_id: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"accepted", "duplicate", "deferred", "unavailable", "rejected"}:
            raise ValueError("unknown ingress status")
        if self.status in {"accepted", "duplicate", "deferred"} and not self.operation_id:
            raise ValueError("durable ingress status requires an operation ID")
