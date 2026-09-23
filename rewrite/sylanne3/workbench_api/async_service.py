"""Submit a complete workbench command to the graph's owning worker."""

from __future__ import annotations

from typing import Any

from ..graph_worker import GraphWorker
from .issuer import DomainViewRegistry, GrantResolver, GraphWorkbenchIssuer
from .onboarding import OnboardingPolicyResolver
from .service import ApiResponse, AuthenticatedSession, RequestContext, WorkbenchService


class AsyncGraphWorkbenchService:
    """Keep grant resolution, graph reads and projection on one worker thread."""

    def __init__(self, worker: GraphWorker, grants: GrantResolver,
                 view_registry: DomainViewRegistry,
                 onboarding: OnboardingPolicyResolver | None = None) -> None:
        self._worker = worker
        self._grants = grants
        self._view_registry = view_registry
        self._onboarding = onboarding

    async def handle(self, payload: Any, *, session: AuthenticatedSession | None,
                     context: RequestContext) -> ApiResponse:
        return await self._worker.call(self._handle_on_worker, payload, session, context)

    def _handle_on_worker(self, coordinator: object, payload: Any,
                          session: AuthenticatedSession | None,
                          context: RequestContext) -> ApiResponse:
        issuer = GraphWorkbenchIssuer(coordinator, self._grants, self._view_registry,
                                      self._onboarding)
        return WorkbenchService(issuer).handle(payload, session=session, context=context)


__all__ = ("AsyncGraphWorkbenchService",)
