"""Consume a current W01 owner grant without inventing a second authority.

The port is implemented by W01 on the graph worker. W01 must bind the returned
lease to a durable grant revision and recheck it inside each coordinator read's
content/activation fence. A dashboard login only identifies an actor; it never
issues an owner grant. This module does not persist grants or mint a
coordinator lease from a username.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..runtime_contracts import NamespaceId
from .issuer import CoordinatorGrant
from .service import AuthenticatedSession


@dataclass(frozen=True, slots=True)
class CurrentOwnerGrant:
    """W01's current, fenced resolution of one durable owner grant.

    ``grant`` contains the process lease W01 bound to this exact durable grant.
    ``issuer_ref`` identifies the trusted issuer recorded by W01, not a client
    claim or the dashboard account's administrator flag.
    """

    grant_id: str
    issuer_ref: str
    actor_id: str
    scope: str
    namespace: NamespaceId
    capabilities: frozenset[str]
    purposes: frozenset[str]
    audiences: frozenset[str]
    grant_revision: int
    revocation_epoch: int
    grant: CoordinatorGrant

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value for value in (
                self.grant_id, self.issuer_ref, self.actor_id, self.scope)):
            raise ValueError("owner grant requires durable identities")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("owner grant namespace is required")
        if any(not isinstance(getattr(self, name), frozenset)
               or not all(isinstance(item, str) and item for item in getattr(self, name))
               for name in ("capabilities", "purposes", "audiences")):
            raise TypeError("owner grant permissions must be typed sets")
        if (type(self.grant_revision) is not int or self.grant_revision < 1
                or type(self.revocation_epoch) is not int or self.revocation_epoch < 0):
            raise ValueError("owner grant requires current versions")
        if not isinstance(self.grant, CoordinatorGrant):
            raise TypeError("owner grant requires a coordinator lease")


class CurrentOwnerGrantPort(Protocol):
    """W01-only resolver, called on the graph worker for every content request.

    W01 must return ``None`` after revocation, activation change, unavailable
    issuer, or failed current content fence. Its coordinator must serialize
    revocation with every later query by checking the grant revision there;
    a cached row or process lease alone is insufficient.
    """

    def resolve_current_owner(self, *, actor_id: str, scope: str,
                              purpose: str, audience: str) -> CurrentOwnerGrant | None: ...


class DurableOwnerGrantResolver:
    """Validate W01's scoped result against the authenticated dashboard actor."""

    def __init__(self, port: CurrentOwnerGrantPort | None = None) -> None:
        self._port = port

    def resolve(self, *, session: AuthenticatedSession, scope: str,
                purpose: str, audience: str) -> CoordinatorGrant | None:
        if not isinstance(session, AuthenticatedSession) or not session.allows(
                scope, "workbench.read", purpose, audience):
            return None
        if self._port is None:
            return None
        current = self._port.resolve_current_owner(
            actor_id=session.actor_id, scope=scope, purpose=purpose,
            audience=audience,
        )
        if not isinstance(current, CurrentOwnerGrant):
            return None
        grant = current.grant
        authority = grant.authority
        if (current.actor_id != session.actor_id or current.scope != scope
                or grant.scope != scope or authority.actor != session.actor_id
                or authority.issuer_domain != "d12"
                or authority.namespace != current.namespace
                or "workbench.read" not in current.capabilities
                or purpose not in current.purposes
                or audience not in current.audiences
                or authority.purpose != purpose
                or audience not in authority.audience):
            return None
        return grant


__all__ = ("CurrentOwnerGrant", "CurrentOwnerGrantPort", "DurableOwnerGrantResolver")
