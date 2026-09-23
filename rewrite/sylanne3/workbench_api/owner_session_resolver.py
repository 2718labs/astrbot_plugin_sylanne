"""Bind signed Owner logins to the Dashboard user that completed them.

The binding lives only for this plugin process. An Authority restart, Owner
logout or local revocation makes subsequent W11 requests fail. AstrBot's JWT
opens the page; it neither proves an Owner principal nor revokes this binding.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
from threading import RLock
from typing import Callable, Protocol

from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
)
from ..graph_coordinator import CurrentOwnerViewV1, namespace_ref
from ..graph_worker import GraphWorker
from ..runtime_contracts import NamespaceId
from .http_transport import (
    PluginRequest, VerifiedOwnerPairing,
)
from .service import AuthenticatedSession


_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class OwnerSessionAuthorityPort(Protocol):
    """The installation's paired V2FencePort, never a browser supplied port."""

    def begin_owner_session(self, *, namespace: NamespaceId,
                            authority_namespace: str,
                            request: OwnerSessionLoginRequestV1
                            ) -> OwnerSessionLoginChallengeV1: ...

    def accept_owner_session(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             challenge: OwnerSessionLoginChallengeV1,
                             signature: bytes) -> str: ...

    def describe_owner_session(self, *, namespace: NamespaceId,
                               authority_namespace: str,
                               token: str) -> OwnerSessionLoginRequestV1: ...

    def logout_owner_session(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             request: OwnerSessionLoginRequestV1,
                             token: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _Binding:
    username: str
    actor_id: str
    request: OwnerSessionLoginRequestV1
    session_id: str


@dataclass(frozen=True, slots=True)
class _Pending:
    username: str
    challenge: OwnerSessionLoginChallengeV1


class BoundOwnerSessions:
    """Trusted W11 backend for one installed Owner namespace.

    A host login handler calls ``complete_signed_login`` with AstrBot's
    authenticated PluginRequest after the browser signs an Authority challenge.
    It must set the returned token as an HttpOnly, Secure, SameSite=Strict cookie
    scoped to the workbench route. No browser route may call the binding store
    with an already issued token or choose its own actor.

    ``owner_actor`` is the installation-owned W01 actor selector. The graph
    coordinator independently verifies actor-to-principal pairing under its
    current read fence. Binding storage never grants graph capabilities.
    """

    def __init__(self, *, authority: OwnerSessionAuthorityPort,
                 worker: GraphWorker, bootstrap: object,
                 owner_actor: Callable[[OwnerPrincipalV1, NamespaceId], str | None],
                 namespace: NamespaceId, authority_id: str,
                 installation_id: str, origin: str) -> None:
        if (not all(callable(getattr(authority, name, None)) for name in (
                "begin_owner_session", "accept_owner_session", "describe_owner_session",
                "logout_owner_session"))
                or not isinstance(worker, GraphWorker)
                or bootstrap is None or not callable(owner_actor)
                or type(namespace) is not NamespaceId
                or not all(type(value) is str and value for value in (
                    authority_id, installation_id, origin))):
            raise TypeError("trusted Owner session dependencies are required")
        self._authority = authority
        self._worker = worker
        self._bootstrap = bootstrap
        self._owner_actor = owner_actor
        self._namespace = namespace
        self._authority_namespace = namespace_ref(namespace)
        self._authority_id = authority_id
        self._installation_id = installation_id
        self._origin = origin
        self._secret = secrets.token_bytes(32)
        self._lock = RLock()
        self._bindings: dict[bytes, _Binding] = {}
        self._revoked: set[bytes] = set()
        self._pending: dict[str, _Pending] = {}

    @property
    def origin(self) -> str:
        return self._origin

    def _key(self, token: str) -> bytes:
        if type(token) is not str or _TOKEN.fullmatch(token) is None:
            raise ValueError("invalid Owner session token")
        return hmac.new(self._secret, token.encode("ascii"), hashlib.sha256).digest()

    def _request_matches(self, request: OwnerSessionLoginRequestV1) -> bool:
        return (type(request) is OwnerSessionLoginRequestV1
                and request.authority_id == self._authority_id
                and request.authority_namespace == self._authority_namespace
                and request.installation_id == self._installation_id
                and request.dashboard_origin == self._origin
                and request.audience == "owner")

    async def _current_view(self, principal: OwnerPrincipalV1) -> tuple[str, CurrentOwnerViewV1]:
        def read(coordinator: object) -> tuple[str, CurrentOwnerViewV1]:
            actor = self._owner_actor(principal, self._namespace)
            if type(actor) is not str or not actor:
                raise RuntimeError("current Owner actor is unavailable")
            view = coordinator.read_current_owner_view(
                self._bootstrap, actor=actor, namespace=self._namespace,
                purpose="workbench_view", audience="owner",
                expected_principal=principal)
            return actor, view

        return await self._worker.call(read)

    def _view_matches(self, request: OwnerSessionLoginRequestV1,
                      actor: str, view: CurrentOwnerViewV1) -> bool:
        if type(view) is not CurrentOwnerViewV1:
            return False
        guard, binding = view.authority_guard, view.graph_binding
        return (guard.authority_id == request.authority_id
                and guard.installation_id == request.installation_id
                and guard.namespace == self._namespace
                and guard.pending_revoke_operation_id is None
                and binding.principal == request.principal
                and binding.actor == actor
                and binding.namespace == self._namespace
                and binding.scope == f"{self._namespace.bot_id}/{self._namespace.persona_id}"
                and binding.authorization_revision == guard.authorization_revision
                and binding.authorization_head == guard.authorization_head
                and binding.revocation_epoch == guard.minimum_revocation_epoch
                and "workbench.read" in binding.capabilities
                and "workbench_view" in binding.purposes
                and "owner" in binding.audiences)

    async def begin_signed_login(self, *, request: PluginRequest,
                                 login_request: OwnerSessionLoginRequestV1
                                 ) -> OwnerSessionLoginChallengeV1:
        """Start an Authority challenge for this authenticated Dashboard user."""
        if not self._origin.startswith("https://"):
            raise RuntimeError("HTTPS is required for Owner login")
        username = request.username
        if (type(username) is not str or not username
                or request.headers.get("origin") != self._origin
                or not self._request_matches(login_request)):
            raise ValueError("authenticated Owner login request is required")
        challenge = await asyncio.to_thread(
            self._authority.begin_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace,
            request=login_request)
        if (type(challenge) is not OwnerSessionLoginChallengeV1
                or challenge.request != login_request):
            raise RuntimeError("Authority Owner login challenge differs")
        with self._lock:
            if len(self._pending) >= 128:
                self._pending.pop(next(iter(self._pending)))
            self._pending[challenge.nonce] = _Pending(username, challenge)
        return challenge

    async def complete_signed_login(self, *, request: PluginRequest,
                                    challenge: OwnerSessionLoginChallengeV1,
                                    signature: bytes) -> str:
        """Accept one actual Authority signature, then bind its new token locally."""
        if not self._origin.startswith("https://"):
            raise RuntimeError("HTTPS is required for Owner login")
        username = request.username
        if (type(username) is not str or not username
                or request.headers.get("origin") != self._origin
                or type(challenge) is not OwnerSessionLoginChallengeV1
                or not self._request_matches(challenge.request)
                or type(signature) is not bytes):
            raise ValueError("authenticated signed Owner login is required")
        with self._lock:
            pending = self._pending.get(challenge.nonce)
            if pending is None or pending.username != username or pending.challenge != challenge:
                raise ValueError("Owner challenge must belong to the same Dashboard user")
            del self._pending[challenge.nonce]
        token = await asyncio.to_thread(
            self._authority.accept_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace,
            challenge=challenge, signature=signature)
        try:
            described = await asyncio.to_thread(
                self._authority.describe_owner_session,
                namespace=self._namespace, authority_namespace=self._authority_namespace,
                token=token)
            if described != challenge.request or not self._request_matches(described):
                raise RuntimeError("accepted Owner session identity differs")
            actor, view = await self._current_view(described.principal)
            if not self._view_matches(described, actor, view):
                raise RuntimeError("accepted Owner session differs from current graph grant")
            key = self._key(token)
            with self._lock:
                if key in self._revoked or key in self._bindings:
                    raise RuntimeError("Owner session was already bound or revoked")
                self._bindings[key] = _Binding(
                    username, actor, described, "owner:" + key.hex())
        except Exception:
            try:
                await asyncio.to_thread(
                    self._authority.logout_owner_session,
                    namespace=self._namespace, authority_namespace=self._authority_namespace,
                    request=challenge.request, token=token)
            except Exception:
                pass  # The bearer was never returned or bound to W11.
            raise
        return token

    async def resolve_current_owner_session(self, *, username: str,
                                            owner_session_token: str) -> VerifiedOwnerPairing | None:
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return None
        with self._lock:
            binding = self._bindings.get(key)
        if binding is None or binding.username != username:
            return None
        try:
            actor, view = await self._current_view(binding.request.principal)
            if actor != binding.actor_id or not self._view_matches(binding.request, actor, view):
                return None
            described = await asyncio.to_thread(
                self._authority.describe_owner_session,
                namespace=self._namespace, authority_namespace=self._authority_namespace,
                token=owner_session_token)
        except (RuntimeError, ValueError, TypeError, PermissionError):
            return None
        if described != binding.request or not self._request_matches(described):
            return None
        with self._lock:
            if self._bindings.get(key) != binding:
                return None
        graph = view.graph_binding
        scope = f"{self._namespace.bot_id}/{self._namespace.persona_id}"
        session = AuthenticatedSession(
            binding.actor_id, binding.session_id,
            {scope: graph.capabilities}, {scope: graph.audiences},
            {scope: graph.purposes}, host_username=binding.username)
        return VerifiedOwnerPairing(session, described.principal, view.authority_guard)

    async def revoke_bound_session(self, *, username: str, owner_session_token: str) -> bool:
        """Local logout locks W11 immediately; Authority logout follows."""
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return False
        with self._lock:
            binding = self._bindings.get(key)
            if binding is None or binding.username != username:
                return False
            del self._bindings[key]
            self._revoked.add(key)
        await asyncio.to_thread(
            self._authority.logout_owner_session,
            namespace=self._namespace, authority_namespace=self._authority_namespace,
            request=binding.request, token=owner_session_token)
        return True


__all__ = ("BoundOwnerSessions", "OwnerSessionAuthorityPort")
