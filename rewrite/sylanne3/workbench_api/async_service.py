"""Submit a complete workbench command to the graph's owning worker."""

from __future__ import annotations

from contextlib import nullcontext
import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any

from ..graph_worker import GraphWorker
from ..domains.d12.scheme_command import D12CreatorDraftReadPort
from .issuer import DomainViewRegistry, GrantResolver, GraphWorkbenchIssuer
from .onboarding import OnboardingPolicyResolver
from .service import ApiResponse, AuthenticatedSession, RequestContext, WorkbenchService


class AsyncGraphWorkbenchService:
    """Keep grant resolution, graph reads and projection on one worker thread."""

    def __init__(self, worker: GraphWorker, grants: GrantResolver,
                 view_registry: DomainViewRegistry,
                 onboarding: OnboardingPolicyResolver | None = None,
                 correction_installation_policy: object | None = None,
                 correction_admin_policy: object | None = None,
                 scheme_port: D12CreatorDraftReadPort | None = None,
                 d04_root_resource_resolver: object | None = None,
                 support_export_root: Path | None = None,
                 authority_client: object | None = None,
                 authority_bundle: object | None = None,
                 authority_grant: object | None = None,
                 authority_loop: asyncio.AbstractEventLoop | None = None,
                 backend_operation_port: object | None = None,
                 maintenance_port: object | None = None,
                 package_maintenance_port: object | None = None) -> None:
        self._worker = worker
        self._grants = grants
        self._view_registry = view_registry
        self._onboarding = onboarding
        self._correction_installation_policy = correction_installation_policy
        self._correction_admin_policy = correction_admin_policy
        self._scheme_port = scheme_port
        self._d04_root_resource_resolver = d04_root_resource_resolver
        self._support_export_root = support_export_root
        self._authority_client = authority_client
        self._authority_bundle = authority_bundle
        self._authority_grant = authority_grant
        self._authority_loop = authority_loop
        self._backend_operation_port = backend_operation_port
        self._maintenance_port = maintenance_port
        self._package_maintenance_port = package_maintenance_port

    async def handle(self, payload: Any, *, session: AuthenticatedSession | None,
                     context: RequestContext) -> ApiResponse:
        return await self._worker.call(self._handle_on_worker, payload, session, context)

    def _handle_on_worker(self, coordinator: object, payload: Any,
                          session: AuthenticatedSession | None,
                          context: RequestContext) -> ApiResponse:
        issuer = GraphWorkbenchIssuer(coordinator, self._grants, self._view_registry,
                                      self._onboarding,
                                      self._correction_installation_policy,
                                      self._correction_admin_policy,
                                      self._scheme_port,
                                      d04_root_resource_resolver=self._d04_root_resource_resolver,
                                      support_export_root=self._support_export_root,
                                      erasure_prepare=self._erasure_prepare_port(),
                                      erasure_accepted_read=self._erasure_accepted_read_port(),
                                      backend_operation_port=self._backend_operation_port,
                                      maintenance_port=self._maintenance_port,
                                      package_maintenance_port=self._package_maintenance_port)
        scope = getattr(self._grants, "request_scope", None)
        with scope() if callable(scope) else nullcontext():
            return WorkbenchService(issuer).handle(
                payload, session=session, context=context)

    def _erasure_prepare_port(self):
        client = self._authority_client
        bundle = self._authority_bundle
        grant = self._authority_grant
        loop = self._authority_loop
        if (client is None or bundle is None or grant is None or loop is None
                or loop.is_closed()
                or not callable(getattr(client, "prepare_current_erasure_v1", None))):
            return None

        def prepare(*, operation_id: str, source_id: str,
                    owner_actor_id: str, owner_session_token: str):
            if not loop.is_running():
                raise RuntimeError("paired Authority event loop is unavailable")
            future = asyncio.run_coroutine_threadsafe(
                client.prepare_current_erasure_v1(
                    bundle, grant, operation_id=operation_id,
                    source_id=source_id, owner_actor_id=owner_actor_id,
                    owner_session_token=owner_session_token), loop)
            try:
                return future.result(timeout=30)
            except FutureTimeout as exc:
                future.cancel()
                raise RuntimeError("Authority erasure prepare outcome is unresolved") from exc

        return prepare

    def _erasure_accepted_read_port(self):
        client = self._authority_client
        bundle = self._authority_bundle
        grant = self._authority_grant
        loop = self._authority_loop
        if (client is None or bundle is None or grant is None or loop is None
                or loop.is_closed()
                or not callable(getattr(client, "current_accepted_erasure_v1", None))):
            return None

        def read(*, operation_id: str, scope_digest: str, permit: object):
            if not loop.is_running():
                raise RuntimeError("paired Authority event loop is unavailable")
            future = asyncio.run_coroutine_threadsafe(
                client.current_accepted_erasure_v1(
                    bundle, grant, deletion_operation_id=operation_id,
                    scope_digest=scope_digest, permit=permit), loop)
            try:
                return future.result(timeout=30)
            except FutureTimeout as exc:
                future.cancel()
                raise RuntimeError("Authority accepted erasure read is unresolved") from exc

        return read


__all__ = ("AsyncGraphWorkbenchService",)
