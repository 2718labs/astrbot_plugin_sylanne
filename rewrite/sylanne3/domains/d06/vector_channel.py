"""Volatile, permission-partitioned vector candidates for D06 retrieval.

This is a supplemental candidate channel, not evidence or a durable index.
Every hit is re-read through MemoryRetriever before it can enter C03.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...contracts import StaleRead
from ...graph_types import NamespaceEpoch
from ...memory_repository import MemoryRepository
from ...memory_retrieval import MemoryBatch, MemoryQuery, MemoryRetriever
from ...memory_types import access_key, source_key


def _vector(values: tuple[float, ...], dimension: int | None = None) -> tuple[float, ...]:
    if (type(values) is not tuple or not values or len(values) > 4096
            or (dimension is not None and len(values) != dimension)
            or any(type(value) not in (int, float) or isinstance(value, bool)
                   or not math.isfinite(value) for value in values)):
        raise ValueError("vector dimension or coordinates are invalid")
    norm = math.sqrt(sum(float(value) ** 2 for value in values))
    if not math.isfinite(norm) or norm == 0:
        raise ValueError("vector norm must be finite and positive")
    return tuple(float(value) / norm for value in values)


@dataclass(frozen=True, slots=True)
class VectorEntry:
    source_id: str
    source_revision: int
    access_revision: int
    coordinates: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class VolatileVectorGeneration:
    """One immutable embedding space for one audience and purpose."""

    epoch: NamespaceEpoch
    model_id: str
    preprocessing_id: str
    audience: str
    purpose: str
    dimension: int
    entries: tuple[VectorEntry, ...]

    @classmethod
    def build(
        cls, repository: MemoryRepository, *, model_id: str,
        preprocessing_id: str, audience: str, purpose: str,
        vectors: tuple[tuple[str, tuple[float, ...]], ...],
    ) -> VolatileVectorGeneration:
        for value in (model_id, preprocessing_id, audience, purpose):
            if type(value) is not str or not value.strip():
                raise ValueError("vector partition and model identities are required")
        if type(vectors) is not tuple or len(vectors) > 4096:
            raise ValueError("vector generation exceeds its entry bound")
        epoch = repository.store.graph_epoch(repository.bot, repository.persona)
        entries = []
        seen = set()
        dimension = None
        for source_id, values in vectors:
            if type(source_id) is not str or not source_id or source_id in seen:
                raise ValueError("vector source identities must be unique")
            seen.add(source_id)
            coordinates = _vector(values, dimension)
            dimension = len(coordinates)
            source, proof = repository.read_source_evidence(
                source_id, audience=audience, purpose=purpose,
            )
            if proof.epochs != (epoch,):
                raise StaleRead("vector generation changed during build")
            if source is None:
                continue
            versions = {item.key: item.revision for item in proof.versions}
            source_revision = versions.get(source_key(repository.bot, repository.persona, source_id))
            access_revision = versions.get(access_key(repository.bot, repository.persona, source_id))
            if not source_revision or not access_revision:
                raise ValueError("vector source proof lacks current source or access")
            entries.append(VectorEntry(source_id, source_revision,
                                       access_revision, coordinates))
        if repository.store.graph_epoch(repository.bot, repository.persona) != epoch:
            raise StaleRead("vector generation changed during build")
        if dimension is None:
            raise ValueError("vector generation needs a declared dimension")
        return cls(epoch, model_id, preprocessing_id, audience, purpose,
                   dimension, tuple(entries))

    def search(
        self, retriever: MemoryRetriever, *, query: tuple[float, ...],
        model_id: str, preprocessing_id: str, audience: str, purpose: str,
        enabled: bool = True, limit: int = 32,
    ) -> tuple[MemoryBatch | None, str]:
        """Return authorized candidates or a reason to use structural search."""
        if type(enabled) is not bool or type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("vector switch or candidate limit is invalid")
        if not enabled:
            return None, "disabled_structural_fallback"
        if (model_id, preprocessing_id, audience, purpose) != (
            self.model_id, self.preprocessing_id, self.audience, self.purpose,
        ):
            return None, "partition_or_generation_mismatch_structural_fallback"
        if (retriever.repository.bot, retriever.repository.persona) != (
            self.epoch.bot, self.epoch.persona,
        ):
            return None, "namespace_mismatch_structural_fallback"
        current = retriever.repository.store.graph_epoch(self.epoch.bot, self.epoch.persona)
        if current != self.epoch:
            return None, "stale_structural_fallback"
        coordinates = _vector(query, self.dimension)
        ranked = sorted(
            self.entries,
            key=lambda entry: (-sum(a * b for a, b in zip(coordinates, entry.coordinates)),
                               entry.source_id),
        )[:limit]
        if not ranked:
            return None, "empty_structural_fallback"
        try:
            batch = retriever.search(
                MemoryQuery("source", ids=tuple(entry.source_id for entry in ranked)),
                audience=audience, purpose=purpose, max_candidates=limit,
                max_nodes=128, page_size=limit, max_pages=1,
                expected_epoch=self.epoch,
            )
        except StaleRead:
            return None, "stale_structural_fallback"
        revisions = {entry.source_id: entry for entry in ranked}
        for hit in batch.hits:
            expected = revisions[hit.record.source_id]
            proof = {item.key: item.revision for item in hit.proof_versions}
            if (proof.get(source_key(self.epoch.bot, self.epoch.persona,
                                     expected.source_id)) != expected.source_revision
                    or proof.get(access_key(self.epoch.bot, self.epoch.persona,
                                            expected.source_id)) != expected.access_revision):
                return None, "stale_structural_fallback"
        return batch, "vector_candidates_revalidated"


__all__ = ["VectorEntry", "VolatileVectorGeneration"]
