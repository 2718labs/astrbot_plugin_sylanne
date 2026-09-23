"""Worker-facing, read-only bridge to the installed AstrBot scene identity."""

from __future__ import annotations

import asyncio
from typing import Any

from ..runtime_contracts import NamespaceId
from .current_scene import CurrentHostScene, verify_current_host_scene
from .scene_candidates import SceneCandidateCatalog


class InstalledSceneIdentityPort:
    """Resolve a recent candidate only after current host-loop revalidation.

    This port is for the GraphWorker thread. It confers neither D03 policy nor
    graph write or platform send authority.
    """

    def __init__(self, *, context: Any, host_loop: asyncio.AbstractEventLoop,
                 candidates: SceneCandidateCatalog, timeout_seconds: float = 2.0) -> None:
        if (not isinstance(host_loop, asyncio.AbstractEventLoop)
                or not isinstance(candidates, SceneCandidateCatalog)
                or not 0 < timeout_seconds <= 10):
            raise ValueError("installed scene identity dependencies are invalid")
        self._context = context
        self._host_loop = host_loop
        self._candidates = candidates
        self._timeout_seconds = timeout_seconds

    async def _verify_on_host_loop(self, namespace: NamespaceId, scene_ref: str,
                                   visibility: str) -> CurrentHostScene | None:
        matching = tuple(candidate for candidate in self._candidates.for_namespace(namespace)
                         if candidate.scene_ref == scene_ref
                         and candidate.visibility == visibility)
        if len(matching) != 1:
            return None
        result = await verify_current_host_scene(self._context, matching[0])
        if (result is None or result.namespace != namespace
                or result.scene_ref != scene_ref or result.visibility != visibility):
            return None
        return result

    def verify(self, namespace: NamespaceId, scene_ref: str,
               visibility: str) -> CurrentHostScene | None:
        if (type(namespace) is not NamespaceId or type(scene_ref) is not str
                or not scene_ref or visibility not in {"private", "group"}):
            return None
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._host_loop or not self._host_loop.is_running():
            return None
        coro = self._verify_on_host_loop(namespace, scene_ref, visibility)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._host_loop)
        except RuntimeError:
            coro.close()
            return None
        try:
            return future.result(timeout=self._timeout_seconds)
        except Exception:
            future.cancel()
            return None


__all__ = ("InstalledSceneIdentityPort",)
