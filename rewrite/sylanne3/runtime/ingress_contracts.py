"""Pure W01 ingress authority values shared by the host and runtime ledger."""

from __future__ import annotations

from dataclasses import dataclass
import math

from ..runtime_contracts import AuthorityContext, CommitReceipt, NamespaceId


@dataclass(frozen=True)
class CanonicalIngressObservation:
    operation_id: str
    content_fingerprint: str
    learned_at: float
    durable_record_ref: str

    def __post_init__(self) -> None:
        if not self.operation_id or not self.durable_record_ref:
            raise ValueError("canonical observation requires durable identity")
        if (
            len(self.content_fingerprint) != 64
            or any(ch not in "0123456789abcdef" for ch in self.content_fingerprint)
        ):
            raise ValueError("content fingerprint must be lowercase SHA-256")
        if not math.isfinite(self.learned_at) or self.learned_at <= 0:
            raise ValueError("canonical learned_at must be finite and positive")


@dataclass(frozen=True)
class IngressAuthoritySession:
    authority: AuthorityContext
    lease: object

    def __post_init__(self) -> None:
        if not isinstance(self.authority, AuthorityContext):
            raise TypeError("session authority must be AuthorityContext")
        if self.lease is None:
            raise ValueError("session coordinator lease is required")


@dataclass(frozen=True)
class IngressObservationContext:
    namespace: NamespaceId
    activation_generation: int
    actor: str
    capability_ref: str
    operation_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("observation namespace must be NamespaceId")
        if type(self.activation_generation) is not int or self.activation_generation < 0:
            raise ValueError("observation activation generation must be nonnegative")
        if not self.actor or not self.capability_ref or not self.operation_id:
            raise ValueError("observation context requires trusted operation identity")

    def require_session(self, session: IngressAuthoritySession) -> None:
        if not isinstance(session, IngressAuthoritySession):
            raise TypeError("observation requires IngressAuthoritySession")
        authority = session.authority
        if (
            self.namespace != authority.namespace
            or self.activation_generation != authority.activation_generation
            or self.actor != authority.actor
            or self.capability_ref != authority.capability_ref
        ):
            raise ValueError("observation context differs from opaque authority session")


@dataclass(frozen=True)
class CommittedIngressReplay:
    """A coordinator-confirmed prior commit paired with its first observation."""

    receipt: CommitReceipt
    observation: CanonicalIngressObservation
    session: IngressAuthoritySession

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, CommitReceipt) or self.receipt.status != "committed":
            raise ValueError("replay requires a committed coordinator receipt")
        if not isinstance(self.observation, CanonicalIngressObservation):
            raise TypeError("replay requires canonical first observation")
        if self.receipt.operation_id != self.observation.operation_id:
            raise ValueError("replay operation differs from first observation")
        if not isinstance(self.session, IngressAuthoritySession):
            raise TypeError("replay requires authenticated ingress session")


__all__ = (
    "CanonicalIngressObservation", "CommittedIngressReplay",
    "IngressAuthoritySession", "IngressObservationContext",
)
