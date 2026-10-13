"""Bind signed Owner logins to the Dashboard user that completed them.

The binding lives only for this plugin process. An Authority restart, Owner
logout or local revocation makes subsequent W11 requests fail. AstrBot's JWT
opens the page; it neither proves an Owner principal nor revokes this binding.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
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
from .installation_owner_sessions_v1 import InstallationOwnerSessionsV1


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
                 installation_id: str, origin: str, operation_status_port=None, package_maintenance_port=None, identity=None, reply_control_port=None) -> None:
        if (not all(callable(getattr(authority, name, None)) for name in (
                "begin_owner_session", "accept_owner_session", "describe_owner_session",
                "logout_owner_session"))
                or not isinstance(worker, GraphWorker)
                or bootstrap is None or not callable(owner_actor)
                or type(namespace) is not NamespaceId
                or not all(type(value) is str and value for value in (
                    authority_id, installation_id, origin))):
            raise TypeError("trusted Owner session dependencies are required")
        if reply_control_port is not None:
            from ..host.owner_stop_reply_port_v1 import InstalledOwnerStopReplyPortV1
            if (type(reply_control_port) is not InstalledOwnerStopReplyPortV1
                    or reply_control_port.namespace != namespace
                    or reply_control_port.bundle.installation_policy.installation_id != installation_id):
                raise TypeError("actual installed Owner reply control port required")
        self._reply_control_port = reply_control_port
        self._operation_status_port = operation_status_port
        from ..host.d12_package_workbench_port_v2 import InstalledD12PackageWorkbenchPortV2
        if package_maintenance_port is not None and type(package_maintenance_port) is not InstalledD12PackageWorkbenchPortV2:
            raise TypeError("actual installed paired package status port required")
        self._package_maintenance_port = package_maintenance_port
        self._authority = authority
        self._worker = worker
        self._bootstrap = bootstrap
        self._owner_actor = owner_actor
        self._namespace = namespace
        self._authority_namespace = namespace_ref(namespace)
        self._authority_id = authority_id
        self._installation_id = installation_id
        self._origin = origin
        self._lock = RLock()
        self._bindings: dict[bytes, _Binding] = {}  # Only actors proved by a current Graph read.
        self._identity = (InstallationOwnerSessionsV1(authority=authority,
            namespace=namespace, authority_id=authority_id, installation_id=installation_id, origin=origin)
            if identity is None else identity)
        if (type(self._identity) is not InstallationOwnerSessionsV1
                or self._identity.namespace != namespace or self._identity.origin != origin
                or self._identity._installation_id != installation_id
                or self._identity._authority_id != authority_id):
            raise ValueError("D12 adapter and Owner identity installation differ")

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def namespace(self) -> NamespaceId:
        return self._namespace

    def _key(self, token):
        return self._identity._key(token)

    def _request_matches(self, request):
        return self._identity._request_matches(request)

    async def _current_view(self, principal: OwnerPrincipalV1, *, token: str,
                            request: OwnerSessionLoginRequestV1
                            ) -> tuple[str, CurrentOwnerViewV1]:
        def read(coordinator: object) -> tuple[str, CurrentOwnerViewV1]:
            actor = self._owner_actor(principal, self._namespace)
            if type(actor) is not str or not actor:
                raise RuntimeError("current Owner actor is unavailable")
            view = coordinator.read_current_owner_view(
                self._bootstrap, actor=actor, namespace=self._namespace,
                purpose="workbench_view", audience="owner",
                expected_principal=principal, owner_session_token=token,
                owner_session_request=request)
            return actor, view

        return await self._worker.call(read)

    def _view_matches(self, request: OwnerSessionLoginRequestV1,
                      actor: str, view: CurrentOwnerViewV1) -> bool:
        if type(view) is not CurrentOwnerViewV1:
            return False
        guard, binding = view.authority_guard, view.graph_binding
        admission = getattr(binding, "target_admission", None)
        installation_matches = guard.installation_id == request.installation_id
        if admission is not None:
            from ..authority_service.d12_target_owner_admission_v1 import D12TargetOwnerAdmissionV1
            installation_matches = (type(admission) is D12TargetOwnerAdmissionV1
                and admission.source_owner_guard == guard
                and admission.target_installation_id == request.installation_id
                and admission.principal == request.principal
                and admission.target_actor_id == actor
                and admission.target_credential_id == request.credential_id
                and admission.target_credential_epoch == request.credential_epoch
                and admission.graph_incarnation == binding.graph_incarnation
                and admission.source_grant_digest == binding.grant_digest)
        storage = getattr(binding, "storage_admission", None)
        if storage is not None:
            from ..authority_service.d12_owner_storage_admission_v1 import D12OwnerStorageAdmissionV1
            installation_matches = (admission is None and type(storage) is D12OwnerStorageAdmissionV1
                and storage.source_owner_guard == guard
                and storage.installation_id == request.installation_id
                and storage.principal == request.principal
                and storage.current_graph_incarnation == binding.graph_incarnation
                and storage.source_grant_digest == binding.grant_digest)
        return (guard.authority_id == request.authority_id
                and installation_matches
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

    async def begin_signed_login(self, *, request, login_request):
        return await self._identity.begin_signed_login(request=request, login_request=login_request)

    async def complete_signed_login(self, *, request, challenge, signature):
        token = await self._identity.complete_signed_login(request=request,
            challenge=challenge, signature=signature)
        if await self.resolve_current_owner_session(username=request.username, owner_session_token=token) is None:
            await self._identity.revoke_bound_session(username=request.username, owner_session_token=token)
            raise RuntimeError("accepted Owner session differs from current graph grant")
        return token

    async def resolve_current_owner_session(self, *, username, owner_session_token):
        identity = await self._identity.resolve_current_identity(username=username,
            owner_session_token=owner_session_token)
        if identity is None:
            return None
        try:
            actor, view = await self._current_view(identity.request.principal,
                token=owner_session_token, request=identity.request)
        except (RuntimeError, ValueError, TypeError, PermissionError):
            return None
        if not self._view_matches(identity.request, actor, view):
            return None
        if await self._identity.resolve_current_identity(username=username,
                owner_session_token=owner_session_token) != identity:
            return None
        key = self._key(owner_session_token)
        binding = _Binding(username, actor, identity.request, identity.session_id)
        with self._lock:
            self._bindings[key] = binding
        graph = view.graph_binding
        scope = f"{self._namespace.bot_id}/{self._namespace.persona_id}"
        session = AuthenticatedSession(actor, identity.session_id,
            {scope: graph.capabilities}, {scope: graph.audiences}, {scope: graph.purposes},
            host_username=username, owner_session_token=owner_session_token,
            owner_session_request=identity.request)
        return VerifiedOwnerPairing(session, identity.request.principal, view.authority_guard)

    async def resolve_current_reply_control_session(self, *, username, owner_session_token):
        """Resolve metadata control directly through current Owner identity and Core."""
        port = self._reply_control_port
        if port is None:
            return None
        identity = await self._identity.resolve_current_identity(
            username=username, owner_session_token=owner_session_token)
        if identity is None:
            return None
        try:
            # The installed inverse actor binding is content-free; keep its
            # synchronous port on the actual Graph worker, without a read fence.
            actor = await self._worker.call(
                lambda _graph: self._owner_actor(identity.request.principal, self._namespace))
            if type(actor) is not str or not actor:
                return None
            scope = "/".join(self._namespace.as_tuple)
            session = AuthenticatedSession(actor, identity.session_id,
                {scope: frozenset({"workbench.control"})},
                {scope: frozenset({"owner"})},
                {scope: frozenset({"workbench_user_action"})},
                host_username=username, owner_session_token=owner_session_token,
                owner_session_request=identity.request)
            # The actual service verifies the current control grant as well as
            # signed Owner credentials; the local session DTO is not authority.
            await port.list_owner_reply_controls_v1(session=session)
        except (RuntimeError, ValueError, TypeError, PermissionError):
            return None
        if await self._identity.resolve_current_identity(
                username=username, owner_session_token=owner_session_token) != identity:
            return None
        return session

    async def resolve_current_package_status_session(self,*,username,owner_session_token,operation_id,purpose):
        """Explicit exact-operation auth after package admission closes."""
        if await self._identity.resolve_current_identity(username=username, owner_session_token=owner_session_token) is None:
            return None
        from uuid import UUID
        port=self._package_maintenance_port
        if port is None or purpose not in {"audit","workbench_view"}:return None
        try:
            operation=UUID(operation_id);key=self._key(owner_session_token)
            if operation.version!=4 or str(operation)!=operation_id:return None
        except (ValueError,TypeError,AttributeError):return None
        with self._lock:
            binding=self._bindings.get(key)
            if binding is None or binding.username!=username:return None
        if not self._request_matches(binding.request):return None
        scope="/".join(self._namespace.as_tuple)
        session=AuthenticatedSession(binding.actor_id,binding.session_id,
            {scope:frozenset({"workbench.package_status"})},{scope:frozenset({"owner"})},
            {scope:frozenset({"audit","workbench_view"})},host_username=binding.username,
            owner_session_token=owner_session_token,owner_session_request=binding.request,package_operation_id=operation_id)
        try:
            await asyncio.to_thread(port.read_session_package_operation_v2,session=session,scope=scope,operation_id=operation_id)
        except (RuntimeError,ValueError,TypeError,PermissionError,LookupError):return None
        with self._lock:
            if self._bindings.get(key)!=binding:return None
        if await self._identity.resolve_current_identity(username=username, owner_session_token=owner_session_token) is None:
            return None
        return session

    async def resolve_current_operation_status_session(self, *, username: str,
            owner_session_token: str, original_ref: str, purpose: str) -> AuthenticatedSession | None:
        """Authenticate exactly one content-free operation after source freeze.

        This is selected by the explicit status action before ordinary session
        resolution. It is never an error fallback or a content-capability lease.
        """
        if await self._identity.resolve_current_identity(username=username, owner_session_token=owner_session_token) is None:
            return None
        port = self._operation_status_port
        if (port is None or not callable(getattr(port, "read_session_operation_status_v1", None))
                or type(original_ref) is not str
                or re.fullmatch(r"d12authority:[0-9a-f]{64}", original_ref) is None
                or purpose not in {"audit", "workbench_view"}):
            return None
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return None
        with self._lock:
            binding = self._bindings.get(key)
            if binding is None or binding.username != username:
                return None
        if not self._request_matches(binding.request):
            return None
        scope = "/".join(self._namespace.as_tuple)
        session = AuthenticatedSession(binding.actor_id, binding.session_id,
            {scope: frozenset({"workbench.operation_status"})}, {scope: frozenset({"owner"})},
            {scope: frozenset({"audit", "workbench_view"})}, host_username=binding.username,
            owner_session_token=owner_session_token, owner_session_request=binding.request,
            backend_operation_ref=original_ref)
        try:
            original = await asyncio.to_thread(port.read_session_operation_status_v1,
                session=session, scope=scope, original_ref=original_ref, refresh=False)
        except (RuntimeError, ValueError, TypeError, PermissionError, LookupError):
            return None
        if original.namespace != self._namespace or original.original_ref != original_ref:
            return None
        with self._lock:
            if self._bindings.get(key) != binding:
                return None
        if await self._identity.resolve_current_identity(username=username, owner_session_token=owner_session_token) is None:
            return None
        return session

    async def revoke_bound_session(self, *, username, owner_session_token):
        try:
            key = self._key(owner_session_token)
        except ValueError:
            return False
        with self._lock:
            self._bindings.pop(key, None)
        return await self._identity.revoke_bound_session(username=username, owner_session_token=owner_session_token)


__all__ = ("BoundOwnerSessions", "OwnerSessionAuthorityPort")
