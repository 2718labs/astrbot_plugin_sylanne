"""Consume a current W01 owner grant without inventing a second authority.

The port is implemented by W01 on the graph worker. W01 must bind the returned
lease to a durable grant revision and recheck it inside each coordinator read's
content/activation fence. A dashboard login only identifies an actor; it never
issues an owner grant. This module does not persist grants or mint a
coordinator lease from a username.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator, Protocol

from ..contracts import StaleRead
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import GraphCoordinator, UnavailableGuard
from ..graph_types import owner_grant_key
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
    grant_digest: str | None = None

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
                              purpose: str, audience: str,
                              owner_session_token: str | None = None,
                              owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                              domains: tuple[str, ...] | None = None
                              ) -> CurrentOwnerGrant | None: ...



class _DetachedCurrentOwnerRequestLifetimeV3:
    def __init__(self,port,leases):
        self.port,self.leases=port,leases
    def close(self):
        leases,self.leases=self.leases,()
        failure=None
        for lease in reversed(leases):
            try:self.port._coordinator.release_current_owner_lease(self.port._bootstrap,lease)
            except BaseException as error:
                if failure is None:failure=error
        if failure is not None:raise failure

class _CurrentOwnerRequestScopeV3:
    def __init__(self,port,leases):
        self.port,self.leases,self.detached=port,leases,False

def detach_current_owner_request_lifetime_v3(scope):
    from contextlib import ExitStack
    if(type(scope)is not _CurrentOwnerRequestScopeV3 or scope.detached
            or scope.port._request_leases.get()is not scope.leases):
        raise ValueError("D07 classification requires its exact actual Owner request scope")
    retained=ExitStack()
    lifetime=_DetachedCurrentOwnerRequestLifetimeV3(scope.port,scope.leases)
    retained.callback(lifetime.close)
    scope.detached=True
    return retained

class GraphCurrentOwnerGrantPort:
    """Resolve D12 reads through the installed W01 graph and Authority heads."""

    def __init__(self, coordinator: GraphCoordinator, bootstrap: object, *,
                 namespace: NamespaceId, activation_generation: int,
                 domains: tuple[str, ...]) -> None:
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("graph coordinator is required")
        if not isinstance(namespace, NamespaceId):
            raise TypeError("Owner namespace is required")
        if type(activation_generation) is not int or activation_generation < 1:
            raise ValueError("Owner activation generation is required")
        if not domains or not all(isinstance(domain, str) and domain for domain in domains):
            raise ValueError("Owner view domains are required")
        self._coordinator = coordinator
        self._bootstrap = bootstrap
        self._namespace = namespace
        self._activation_generation = activation_generation
        self._domains = domains
        self._scope = f"{namespace.bot_id}/{namespace.persona_id}"
        self._request_leases: ContextVar[list[object] | None] = ContextVar(
            "owner_workbench_request_leases", default=None)

    @contextmanager
    def request_scope(self) -> Iterator[None]:
        leases: list[object] = []
        token=self._request_leases.set(leases)
        scope=_CurrentOwnerRequestScopeV3(self,leases)
        try:yield scope
        finally:
            try:
                if not scope.detached:_DetachedCurrentOwnerRequestLifetimeV3(self,leases).close()
            finally:self._request_leases.reset(token)

    def resolve_current_owner(self, *, actor_id: str, scope: str,
                              purpose: str, audience: str,
                              owner_session_token: str | None = None,
                              owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                              domains: tuple[str, ...] | None = None
                              ) -> CurrentOwnerGrant | None:
        leases = self._request_leases.get()
        if leases is None:
            return None
        if (scope != self._scope or not actor_id or not purpose or not audience
                or type(owner_session_token) is not str or not owner_session_token
                or type(owner_session_request) is not OwnerSessionLoginRequestV1):
            return None
        try:
            selected_domains = self._domains if domains is None else domains
            if (type(selected_domains) is not tuple or not selected_domains
                    or not set(selected_domains).issubset(self._domains)):
                return None
            # This is only an observed generation. W01 still reauthenticates
            # its current Authority fence, signed session and Owner grant.
            with self._coordinator._GraphCoordinator__store._lock:
                generation = self._coordinator._v2_graph_stamp(self._namespace)[0].requirements.activation_generation
            authority, lease, binding = self._coordinator.grant_current_owner(
                self._bootstrap, actor=actor_id, namespace=self._namespace,
                domains=selected_domains, purpose=purpose, audience=audience,
                activation_generation=generation,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request,
            )
        except (PermissionError, UnavailableGuard, StaleRead):
            return None
        leases.append(lease)
        if (binding.actor != actor_id or binding.namespace != self._namespace
                or binding.scope != self._scope or binding.purpose != purpose
                or binding.audience != audience):
            return None
        return CurrentOwnerGrant(
            binding.grant_id, binding.issuer_ref, actor_id, self._scope,
            self._namespace, binding.capabilities, binding.purposes,
            binding.audiences, binding.grant_revision, binding.revocation_epoch,
            CoordinatorGrant(self._scope, authority, lease), binding.grant_digest,
        )


class DurableOwnerGrantResolver:
    """Validate W01's scoped result against the authenticated dashboard actor."""

    def __init__(self, port: CurrentOwnerGrantPort | None = None) -> None:
        self._port = port

    @contextmanager
    def request_scope(self) -> Iterator[None]:
        if isinstance(self._port, GraphCurrentOwnerGrantPort):
            with self._port.request_scope()as scope:
                yield scope
        else:
            yield

    def resolve(self, *, session: AuthenticatedSession, scope: str,
                purpose: str, audience: str) -> CoordinatorGrant | None:
        return self._resolve(session=session, scope=scope, purpose=purpose,
                             audience=audience, domains=None)

    def resolve_for_domains(self, *, session: AuthenticatedSession, scope: str,
                            purpose: str, audience: str,
                            domains: tuple[str, ...]) -> CoordinatorGrant | None:
        return self._resolve(session=session, scope=scope, purpose=purpose,
                             audience=audience, domains=domains)

    def _resolve(self, *, session: AuthenticatedSession, scope: str,
                 purpose: str, audience: str,
                 domains: tuple[str, ...] | None) -> CoordinatorGrant | None:
        if not isinstance(session, AuthenticatedSession) or not session.allows(
                scope, "workbench.read", purpose, audience):
            return None
        if self._port is None:
            return None
        if domains is not None and not isinstance(self._port, GraphCurrentOwnerGrantPort):
            return None
        session_proof = {}
        if isinstance(self._port, GraphCurrentOwnerGrantPort):
            session_proof = {
                "owner_session_token": session.owner_session_token,
                "owner_session_request": session.owner_session_request,
            }
            if domains is not None:
                session_proof["domains"] = domains
        current = self._port.resolve_current_owner(
            actor_id=session.actor_id, scope=scope, purpose=purpose,
            audience=audience, **session_proof)
        if not isinstance(current, CurrentOwnerGrant):
            return None
        grant = current.grant
        authority = grant.authority
        if (current.actor_id != session.actor_id or current.scope != scope
                or grant.scope != scope or authority.actor != session.actor_id
                or authority.issuer_domain != "d12"
                or authority.namespace != current.namespace
                or scope != (f"{current.namespace.bot_id}/"
                             f"{current.namespace.persona_id}")
                or "workbench.read" not in current.capabilities
                or purpose not in current.purposes
                or audience not in current.audiences
                or authority.purpose != purpose
                or audience not in authority.audience):
            return None
        return CoordinatorGrant(
            grant.scope, grant.authority, grant.lease, current.capabilities,
            owner_grant_key(*current.namespace.as_tuple).token,
            current.grant_revision, current.grant_digest)


__all__ = ("CurrentOwnerGrant", "CurrentOwnerGrantPort",
           "GraphCurrentOwnerGrantPort", "DurableOwnerGrantResolver")
