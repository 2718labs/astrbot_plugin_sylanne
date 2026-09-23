"""Synchronous graph-worker bridge to the authenticated v2 Authority channel."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
import hashlib
from threading import Event, RLock, Thread
from typing import Awaitable, Callable, Coroutine, Mapping, TypeVar

from ..authority_service.contract import CONTENT_OPERATIONS, identifier
from ..authority_service.v2_contract import FencePermitV2, SCHEMA as AUTHORITY_V2_PROTOCOL
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    FenceScope, InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
    RecoveryConstraintFootprint,
)
from .authority_client import AuthorityHandshake, AuthorityProvisioningRequest
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


_T = TypeVar("_T")
_CONTENT_OPERATIONS = CONTENT_OPERATIONS - {"dispatch"}
_REPAIRABLE_ERRORS = frozenset({
    "authority handshake channel is unavailable",
    "authority transport unavailable",
    "authority service unavailable",
})


class V2FenceOutcomeUnknown(RuntimeError):
    """The Authority may have committed a request whose response was lost."""


@dataclass
class _PendingBegin:
    namespace: NamespaceId
    authority_namespace: str
    holder: str
    generation: int
    operation: str
    operation_id: str
    expected_anchor: RestoreAnchor
    permit: FencePermitV2 | None = None

    @property
    def finish_identity(self) -> tuple[str, str]:
        digest = hashlib.sha256(
            ("sylanne3.abandoned_begin.v2:" + self.operation_id).encode("utf-8")
        ).hexdigest()
        return "abandoned-" + digest[:32], "sha256:" + digest


@dataclass(frozen=True)
class _PendingFinish:
    scope: FenceScope
    request_id: str
    request_digest: str


class V2FencePort:
    """Use only on a dedicated graph worker, never on an asyncio loop thread.

    The port creates and owns its transport, event loop, TLS session and worker
    thread. Namespace identity is checked against the Authority's authenticated
    mapping on each call, rather than accepted from the graph caller.
    """

    def __init__(
        self,
        request: AuthorityProvisioningRequest,
        profiles: Mapping[str, AuthorityTlsProfile],
        installation_grant: InstallationGrantV2,
        *,
        transport_factory: Callable[[Mapping[str, AuthorityTlsProfile]], MtlsAuthorityTransport] = MtlsAuthorityTransport,
    ) -> None:
        self._reject_event_loop()
        if type(request) is not AuthorityProvisioningRequest:
            raise TypeError("AuthorityProvisioningRequest is required")
        profile = profiles.get(request.profile_id)
        if type(profile) is not AuthorityTlsProfile:
            raise ValueError("request profile is not installed")
        if type(installation_grant) is not InstallationGrantV2:
            raise TypeError("verified InstallationGrantV2 is required")
        if (installation_grant.authority_id != profile.expected_authority_id
                or installation_grant.manifest_digest != request.publisher_package.manifest_sha256):
            raise RuntimeError("installation grant does not match the installed profile or package")
        self._request = request
        self._installation_grant = installation_grant
        self._timeout = 4 * profile.timeout_seconds + 1
        self._lock = RLock()
        self._ready = Event()
        self._loop = asyncio.new_event_loop()
        self._transport = transport_factory(profiles)
        self._handshake: AuthorityHandshake | None = None
        self._grant: InstallationGrantV2 | None = None
        self._mapped_namespaces: dict[NamespaceId, str] = {}
        self._pending_begin: _PendingBegin | None = None
        self._pending_finish: _PendingFinish | None = None
        self._closed = False
        self._thread = Thread(target=self._run_loop, name="sylanne-v2-authority", daemon=True)
        self._thread.start()
        self._ready.wait()
        try:
            self._submit(self._pair())
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _reject_event_loop() -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError("synchronous v2 fence port cannot run on an event loop thread")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    def _submit(self, coroutine: Coroutine[object, object, _T]) -> _T:
        try:
            self._reject_event_loop()
        except RuntimeError:
            coroutine.close()
            raise
        with self._lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("v2 fence port is closed")
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
            try:
                return future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                future.cancel()
                raise V2FenceOutcomeUnknown(
                    "v2 authority result unknown after timeout; reconcile or retry only "
                    "with the original operation_id or finish request_id and digest"
                ) from exc

    async def _pair(self) -> None:
        self._handshake = None
        self._grant = None
        self._mapped_namespaces.clear()
        handshake = await self._transport.handshake(self._request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await self._transport.installation_grant_v2(self._request, handshake)
        if not handshake.valid_pairing() or grant.channel_binding_sha256 != handshake.channel_binding_sha256:
            raise RuntimeError("v2 authority pairing is invalid")
        original = self._installation_grant
        for field in (
            "authority_id", "subject", "administrator_holder", "installation_id",
            "manifest_digest", "publisher_policy_ref", "service_capability_version", "schema",
        ):
            if getattr(grant, field) != getattr(original, field):
                raise RuntimeError("v2 authority installation identity changed")
        self._handshake = handshake
        self._grant = grant

    async def _with_session_repair(self, call: Callable[[], Awaitable[_T]]) -> _T:
        """Replay the same command once after session expiry or transport loss."""
        try:
            return await call()
        except RuntimeError as exc:
            if str(exc) not in _REPAIRABLE_ERRORS:
                raise
        await self._pair()
        return await call()

    def _identity(self) -> tuple[AuthorityHandshake, InstallationGrantV2]:
        if self._handshake is None or self._grant is None:
            raise RuntimeError("v2 authority pairing is unavailable")
        return self._handshake, self._grant

    @property
    def installation_grant(self) -> InstallationGrantV2:
        """The current paired grant, whose installation facts match the installed profile."""
        self._reject_event_loop()
        with self._lock:
            _, grant = self._identity()
            return grant

    def provision_namespace(self, *, namespace: NamespaceId,
                            request_id: str) -> NamespaceBootstrapV2:
        """Ask the administrator's paired Authority to create one v2 namespace."""
        with self._lock:
            self.recover_pending_finish()
            self.recover_pending_begin()
            try:
                return self._submit(self._with_session_repair(
                    lambda: self._provision_namespace(namespace, request_id)))
            except RuntimeError as exc:
                if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                    raise V2FenceOutcomeUnknown(
                        "v2 namespace genesis outcome unknown for request_id=" + request_id
                        + "; retry only with the original request_id"
                    ) from exc
                raise

    async def _provision_namespace(self, namespace: NamespaceId,
                                   request_id: str) -> NamespaceBootstrapV2:
        if type(namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        identifier(request_id, "request_id")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_genesis(
            self._request, handshake, namespace, request_id)
        anchor = observed.anchor if type(observed) is NamespaceBootstrapV2 else None
        if (type(observed) is not NamespaceBootstrapV2
                or observed.namespace != namespace
                or observed.authority_id != grant.authority_id
                or observed.holder != grant.administrator_holder
                or observed.phase != "active"
                or observed.state is not NamespaceRuntimeState.ACTIVE
                or observed.generation != 1
                or observed.blocking_reasons
                or type(anchor) is not RestoreAnchor
                or anchor.authority_id != grant.authority_id
                or anchor.namespace != observed.authority_namespace
                or anchor.activation_generation != 1
                or anchor.deletion_seq != 0 or anchor.deletion_digest != "genesis"
                or anchor.execution_seq != 0 or anchor.execution_digest != "genesis"
                or anchor.revocation_epoch != 0):
            raise RuntimeError("v2 namespace genesis response is invalid")
        return observed

    async def _mapped(self, namespace: NamespaceId, authority_namespace: str):
        if type(namespace) is not NamespaceId or type(authority_namespace) is not str or not authority_namespace:
            raise ValueError("v2 namespace identity is invalid")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or observed.state is not NamespaceRuntimeState.ACTIVE
                or observed.anchor is None):
            raise RuntimeError("v2 namespace is not active or mapped")
        self._mapped_namespaces[namespace] = authority_namespace
        return observed

    def current_anchor(self, *, namespace: NamespaceId, authority_namespace: str) -> RestoreAnchor:
        return self._submit(self._with_session_repair(
            lambda: self._current_anchor(namespace, authority_namespace)))

    async def _current_anchor(self, namespace: NamespaceId, authority_namespace: str) -> RestoreAnchor:
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        anchor = await self._transport.v2_current_anchor(self._request, handshake, authority_namespace)
        if anchor.authority_id != grant.authority_id or anchor.namespace != authority_namespace:
            raise RuntimeError("v2 anchor identity mismatch")
        return anchor

    def get_fence_operation(self, *, namespace: NamespaceId,
                            authority_namespace: str,
                            operation_id: str) -> tuple[FencePermitV2, str]:
        """Query a durable own-subject fence through the paired Authority channel."""
        return self._submit(self._with_session_repair(lambda: self._get_fence_operation(
            namespace, authority_namespace, operation_id)))

    async def _get_fence_operation(self, namespace: NamespaceId,
                                   authority_namespace: str,
                                   operation_id: str) -> tuple[FencePermitV2, str]:
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        permit, state = await self._transport.v2_get_content_fence_operation(
            self._request, handshake, namespace=authority_namespace,
            operation_id=operation_id)
        if (type(permit) is not FencePermitV2
                or permit.operation not in _CONTENT_OPERATIONS
                or permit.namespace != authority_namespace
                or permit.operation_id != operation_id
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject
                or state not in ("active", "finished")):
            raise RuntimeError("v2 fence status identity mismatch")
        return permit, state

    def begin_fence(
        self, *, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation: str, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str | None = None, command_digest: str | None = None,
        footprint: RecoveryConstraintFootprint | None = None,
        retain_on_unknown: bool = False,
    ) -> FencePermitV2:
        with self._lock:
            self.recover_pending_finish()
            self.recover_pending_begin()
            try:
                return self._submit(self._with_session_repair(lambda: self._begin_fence(
                    namespace, authority_namespace, holder, generation, operation,
                    operation_id, expected_anchor, effect_id, command_digest, footprint)))
            except RuntimeError as exc:
                if not isinstance(exc, V2FenceOutcomeUnknown) and str(exc) not in _REPAIRABLE_ERRORS:
                    raise
                if not retain_on_unknown and operation in _CONTENT_OPERATIONS and all(
                    value is None for value in (effect_id, command_digest, footprint)
                ):
                    self._pending_begin = _PendingBegin(
                        namespace, authority_namespace, holder, generation,
                        operation, operation_id, expected_anchor,
                    )
                if isinstance(exc, V2FenceOutcomeUnknown):
                    raise
                raise V2FenceOutcomeUnknown(
                    "v2 begin result unknown after transport loss for operation_id="
                    + operation_id + "; reconcile or retry only with the original operation_id"
                ) from exc

    def recover_pending_begin(self) -> None:
        """Reclaim an uncertain begin before admitting a different operation ID."""
        with self._lock:
            pending = self._pending_begin
            if pending is None:
                return
            try:
                if pending.permit is None:
                    pending.permit = self._submit(self._with_session_repair(lambda: self._begin_fence(
                        pending.namespace, pending.authority_namespace, pending.holder,
                        pending.generation, pending.operation, pending.operation_id,
                        pending.expected_anchor, None, None, None,
                    )))
                request_id, request_digest = pending.finish_identity
                self._submit(self._with_session_repair(lambda: self._transport.v2_finish_fence(
                    self._request, self._identity()[0], pending.permit,
                    request_id=request_id, request_digest=request_digest,
                )))
            except BaseException as exc:
                raise V2FenceOutcomeUnknown(
                    "v2 begin outcome remains unknown for operation_id="
                    + pending.operation_id + "; a new operation ID is blocked"
                ) from exc
            self._pending_begin = None

    def recover_pending_finish(self) -> None:
        """Replay the exact finish request before admitting another fence."""
        with self._lock:
            pending = self._pending_finish
            if pending is None:
                return
            try:
                self._submit(self._with_session_repair(lambda: self._finish_fence(
                    pending.scope, pending.request_id, pending.request_digest,
                )))
            except BaseException as exc:
                raise V2FenceOutcomeUnknown(
                    "v2 finish outcome remains unknown for operation_id="
                    + pending.scope.operation_id + "; a new operation ID is blocked"
                ) from exc
            self._pending_finish = None

    async def _begin_fence(
        self, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation: str, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str | None, command_digest: str | None,
        footprint: RecoveryConstraintFootprint | None,
    ) -> FencePermitV2:
        if type(operation) is not str or operation not in _CONTENT_OPERATIONS or any(
            value is not None for value in (effect_id, command_digest, footprint)
        ):
            raise ValueError("unsupported v2 content fence; dispatch requires a separate Authority RPC")
        identifier(holder, "holder")
        identifier(operation_id, "operation_id")
        if (type(generation) is not int or generation < 0
                or type(expected_anchor) is not RestoreAnchor
                or expected_anchor.namespace != authority_namespace
                or expected_anchor.activation_generation != generation):
            raise ValueError("v2 begin activation or anchor is invalid")
        observed = await self._mapped(namespace, authority_namespace)
        if (observed.holder != holder or observed.generation != generation
                or expected_anchor != observed.anchor):
            raise RuntimeError("v2 namespace activation or anchor changed")
        handshake, grant = self._identity()
        permit = await self._transport.v2_begin_content_fence(
            self._request, handshake, namespace=authority_namespace, holder=holder,
            operation=operation, operation_id=operation_id, expected_anchor=expected_anchor,
        )
        if permit.subject != grant.subject or permit.generation != generation:
            raise RuntimeError("v2 permit installation or generation mismatch")
        return permit

    def validate_fence(self, scope: FenceScope) -> FencePermitV2:
        return self._submit(self._with_session_repair(lambda: self._validate_fence(scope)))

    async def _check_scope(self, scope: FenceScope) -> tuple[AuthorityHandshake, InstallationGrantV2]:
        if type(scope) is not FenceScope or scope.operation not in _CONTENT_OPERATIONS:
            raise ValueError("unsupported v2 content fence scope")
        if self._mapped_namespaces.get(scope.namespace) != scope.authority_namespace:
            await self._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self._identity()
        if (scope.permit.subject != grant.subject
                or scope.permit.authority_id != grant.authority_id):
            raise RuntimeError("v2 fence scope installation or activation mismatch")
        return handshake, grant

    async def _validate_fence(self, scope: FenceScope) -> FencePermitV2:
        handshake, _ = await self._check_scope(scope)
        return await self._transport.v2_validate_fence(self._request, handshake, scope.permit)

    def finish_fence(self, scope: FenceScope, *, request_id: str, request_digest: str) -> None:
        with self._lock:
            self.recover_pending_finish()
            try:
                self._submit(self._with_session_repair(
                    lambda: self._finish_fence(scope, request_id, request_digest)))
            except RuntimeError:
                if type(scope) is FenceScope:
                    self._pending_finish = _PendingFinish(scope, request_id, request_digest)
                raise

    async def _finish_fence(self, scope: FenceScope, request_id: str, request_digest: str) -> None:
        handshake, _ = await self._check_scope(scope)
        await self._transport.v2_finish_fence(
            self._request, handshake, scope.permit,
            request_id=request_id, request_digest=request_digest,
        )

    def close(self) -> None:
        self._reject_event_loop()
        recovery_failure: V2FenceOutcomeUnknown | None = None
        try:
            self.recover_pending_finish()
            self.recover_pending_begin()
        except V2FenceOutcomeUnknown as exc:
            recovery_failure = exc
        failure: BaseException | None = None
        with self._lock:
            if self._closed:
                return
            try:
                future = asyncio.run_coroutine_threadsafe(self._transport.close(), self._loop)
                future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                future.cancel()
                failure = RuntimeError("v2 authority close timed out")
                failure.__cause__ = exc
            except BaseException as exc:
                failure = exc
            finally:
                self._closed = True
                self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=self._timeout)
        if self._thread.is_alive():
            raise RuntimeError("v2 authority thread did not stop")
        if failure is not None:
            raise failure
        if recovery_failure is not None:
            raise recovery_failure

    def __enter__(self) -> V2FencePort:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ("V2FenceOutcomeUnknown", "V2FencePort")
