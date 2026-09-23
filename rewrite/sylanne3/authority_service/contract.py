"""Transport-neutral contract for a separately deployed authority service.

``credential`` is opaque transport authentication material. Only a separately
installed server may choose the verifier. These Python types neither implement
TLS/pairing nor make an in-process plugin a trusted authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol


CONTENT_OPERATIONS = frozenset({
    "startup", "read", "subscribe", "download", "model_egress",
    "adopt", "write", "dispatch",
})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}$")
_DIGEST = re.compile(r"^(genesis|sha256:[0-9a-f]{64})$")


class AuthorityUnavailable(RuntimeError):
    """Current independent authority cannot grant the requested operation."""


def identifier(value: str, name: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class JournalHead:
    journal_id: str
    seq: int
    digest: str

    def __post_init__(self) -> None:
        identifier(self.journal_id, "journal_id")
        if type(self.seq) is not int or self.seq < 0:
            raise ValueError("journal sequence must be nonnegative")
        if type(self.digest) is not str or not _DIGEST.fullmatch(self.digest):
            raise ValueError("journal digest must be genesis or SHA-256")
        if (self.seq == 0) != (self.digest == "genesis"):
            raise ValueError("genesis digest must match sequence zero")


@dataclass(frozen=True)
class ContentPermit:
    token: str
    namespace: str
    holder: str
    generation: int
    operation: str


class ServerAuthorizer(Protocol):
    def __call__(self, credential: object, action: str, namespace: str,
                 holder: str | None) -> bool: ...


class JournalVerifier(Protocol):
    """Server-side current chain verification, never a client assertion."""

    def __call__(self, namespace: str, previous: JournalHead | None,
                 current: JournalHead, phase: str | None) -> bool: ...


class EffectVerifier(Protocol):
    """Server-side check against the execution journal's immutable footprint."""

    def __call__(self, namespace: str, effect_id: str, state: str,
                 conflict_keys: tuple[str, ...], head: JournalHead) -> bool: ...


class DispatchVerifier(Protocol):
    """D08/D10-signed exact opaque conflict set for a proposed effect."""

    def __call__(self, namespace: str, effect_id: str,
                 conflict_keys: tuple[str, ...]) -> bool: ...


__all__ = [
    "AuthorityUnavailable", "ContentPermit", "CONTENT_OPERATIONS",
    "DispatchVerifier", "EffectVerifier", "JournalHead", "JournalVerifier",
    "ServerAuthorizer", "identifier",
]
