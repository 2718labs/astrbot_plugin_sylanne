"""Short-lived, read-only host scene observations for Owner onboarding."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Callable

from ..runtime.first_ingress_v2 import scene_ref_for_conversation
from ..runtime_contracts import NamespaceId
from .ingress import HostIngressEnvelope


@dataclass(frozen=True, slots=True)
class ObservedSceneCandidate:
    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    visibility: str
    scene_ref: str


class SceneCandidateCatalog:
    """Keep only recent scene identities; observations confer no authority."""

    def __init__(self, *, capacity: int = 64, ttl_seconds: float = 300.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if capacity < 1 or ttl_seconds <= 0:
            raise ValueError("scene candidate capacity and TTL must be positive")
        self._capacity = capacity
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[str, tuple[ObservedSceneCandidate, float]] = OrderedDict()

    def _expire(self, now: float) -> None:
        while self._entries:
            _, expires_at = next(iter(self._entries.values()))
            if expires_at > now:
                break
            self._entries.popitem(last=False)

    def observe(self, ingress: HostIngressEnvelope) -> ObservedSceneCandidate | None:
        if ingress.visibility not in {"private", "group"}:
            return None
        now = self._clock()
        self._expire(now)
        candidate = ObservedSceneCandidate(
            ingress.namespace, ingress.platform_ref, ingress.conversation_ref,
            ingress.visibility,
            scene_ref_for_conversation(
                ingress.namespace, ingress.platform_ref, ingress.conversation_ref),
        )
        self._entries[candidate.scene_ref] = (candidate, now + self._ttl_seconds)
        self._entries.move_to_end(candidate.scene_ref)
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)
        return candidate

    def for_namespace(self, namespace: NamespaceId) -> tuple[ObservedSceneCandidate, ...]:
        self._expire(self._clock())
        return tuple(candidate for candidate, _ in self._entries.values()
                     if candidate.namespace == namespace)

    def get_exact(self, *, namespace: NamespaceId, platform_ref: str,
                  conversation_ref: str, visibility: str,
                  scene_ref: str) -> ObservedSceneCandidate | None:
        self._expire(self._clock())
        entry = self._entries.get(scene_ref)
        if entry is None:
            return None
        candidate, _ = entry
        if (candidate.namespace, candidate.platform_ref, candidate.conversation_ref,
                candidate.visibility) != (namespace, platform_ref, conversation_ref,
                                          visibility):
            return None
        return candidate

    def clear(self) -> None:
        self._entries.clear()


__all__ = ("ObservedSceneCandidate", "SceneCandidateCatalog")
