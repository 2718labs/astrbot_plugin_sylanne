"""Bounded, authorized indexed retrieval for persistent memory records."""

from dataclasses import dataclass
import math

from .contracts import CapacityExceeded, StaleRead, nonempty
from .graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from .memory_repository import MemoryRepository
from .memory_types import (
    InterpretationRecord,
    SourceRecord,
    interpretation_key,
    source_key,
)


_KINDS = frozenset({"source", "interpretation"})


def _strings(value: object, label: str, *, maximum: int, item_maximum: int | None = None) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if len(value) > maximum:
        raise ValueError(f"{label} may contain at most {maximum} values")
    for item in value:
        nonempty(item, f"{label} item")
        if item_maximum is not None and len(item) > item_maximum:
            raise ValueError(f"{label} items may contain at most {item_maximum} characters")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must contain unique strings")


def _positive_integer(value: object, label: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be an integer from 1 to {maximum}")


def _optional_time(value: object, label: str) -> None:
    if value is not None and (
        type(value) not in (int, float) or not math.isfinite(value) or value < 0
    ):
        raise ValueError(f"{label} must be a finite nonnegative real number or None")


@dataclass(frozen=True)
class MemoryQuery:
    """An exact predicate specification, not a semantic truth query."""

    kind: str
    ids: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    subject_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"unknown memory query kind: {self.kind!r}")
        _strings(self.ids, "ids", maximum=64)
        _strings(self.terms, "terms", maximum=16, item_maximum=256)
        if self.subject_id is not None:
            nonempty(self.subject_id, "subject_id")
        if not self.ids and not self.terms and self.subject_id is None:
            raise ValueError("memory query requires at least one filter")


@dataclass(frozen=True)
class MemoryHit:
    key: AtomKey
    record: SourceRecord | InterpretationRecord
    proof_versions: tuple[GraphVersion, ...]
    provenance_roots: tuple[str, ...]
    sources: tuple[SourceRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.key, AtomKey):
            raise TypeError("key must be AtomKey")
        if not isinstance(self.record, (SourceRecord, InterpretationRecord)):
            raise TypeError("record must be a memory record")
        if type(self.proof_versions) is not tuple or any(
            not isinstance(version, GraphVersion) for version in self.proof_versions
        ):
            raise TypeError("proof_versions must contain GraphVersion values")
        _strings(self.provenance_roots, "provenance_roots", maximum=4096)
        if type(self.sources) is not tuple or any(
            not isinstance(source, SourceRecord) for source in self.sources
        ):
            raise TypeError("sources must contain SourceRecord values")


@dataclass(frozen=True)
class MemoryBatch:
    hits: tuple[MemoryHit, ...]
    epoch: NamespaceEpoch
    candidate_count: int
    node_count: int
    page_count: int
    complete: bool
    continuation: AtomKey | None

    def __post_init__(self) -> None:
        if type(self.hits) is not tuple or any(not isinstance(hit, MemoryHit) for hit in self.hits):
            raise TypeError("hits must contain MemoryHit values")
        if not isinstance(self.epoch, NamespaceEpoch):
            raise TypeError("epoch must be NamespaceEpoch")
        for label in ("candidate_count", "node_count", "page_count"):
            value = getattr(self, label)
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be a nonnegative exact integer")
        if type(self.complete) is not bool:
            raise TypeError("complete must be bool")
        if self.continuation is not None and not isinstance(self.continuation, AtomKey):
            raise TypeError("continuation must be AtomKey or None")


def _unique_versions(snapshots: tuple[GraphSnapshot, ...]) -> tuple[GraphVersion, ...]:
    result: list[GraphVersion] = []
    seen: set[AtomKey] = set()
    for snapshot in snapshots:
        for version in snapshot.versions:
            if version.key not in seen:
                seen.add(version.key)
                result.append(version)
    return tuple(result)


def _unique_roots(sources: tuple[SourceRecord, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(source.provenance_root for source in sources))


class MemoryRetriever:
    """Synchronous bounded retrieval over one repository namespace."""

    def __init__(self, repository: MemoryRepository):
        if not isinstance(repository, MemoryRepository):
            raise TypeError("repository must be MemoryRepository")
        self.repository = repository

    def _check_snapshot_epoch(self, snapshot: GraphSnapshot, epoch: NamespaceEpoch) -> None:
        if snapshot.epochs != (epoch,):
            raise StaleRead("memory namespace changed during retrieval")

    def _final_batch(
        self,
        *,
        epoch: NamespaceEpoch,
        hits: list[MemoryHit],
        candidate_count: int,
        node_count: int,
        page_count: int,
        complete: bool,
        continuation: AtomKey | None,
    ) -> MemoryBatch:
        current = self.repository.store.graph_epoch(self.repository.bot, self.repository.persona)
        if current != epoch:
            raise StaleRead("memory namespace changed during retrieval")
        return MemoryBatch(
            tuple(hits), epoch, candidate_count, node_count, page_count, complete, continuation
        )

    @staticmethod
    def _predicate(
        record: SourceRecord | InterpretationRecord,
        query: MemoryQuery,
        folded_terms: tuple[str, ...],
    ) -> bool:
        record_id = (
            record.source_id if isinstance(record, SourceRecord) else record.interpretation_id
        )
        subject = record.speaker_id if isinstance(record, SourceRecord) else record.subject_id
        text = record.text if isinstance(record, SourceRecord) else record.claim
        folded_text = text.casefold()
        return (
            (not query.ids or record_id in query.ids)
            and (query.subject_id is None or subject == query.subject_id)
            and all(term in folded_text for term in folded_terms)
        )

    def search(
        self,
        query: MemoryQuery,
        *,
        audience: str,
        purpose: str,
        as_known_at=None,
        valid_at=None,
        max_candidates: int = 64,
        max_nodes: int = 256,
        page_size: int = 32,
        max_pages: int = 4,
        expected_epoch: NamespaceEpoch | None = None,
        after: AtomKey | None = None,
    ) -> MemoryBatch:
        if not isinstance(query, MemoryQuery):
            raise TypeError("query must be MemoryQuery")
        nonempty(audience, "audience")
        nonempty(purpose, "purpose")
        _positive_integer(max_candidates, "max_candidates", 4096)
        _positive_integer(max_nodes, "max_nodes", 4096)
        _positive_integer(page_size, "page_size", 512)
        _positive_integer(max_pages, "max_pages", 64)
        _optional_time(as_known_at, "as_known_at")
        _optional_time(valid_at, "valid_at")

        bot, persona = self.repository.bot, self.repository.persona
        type_name = "memory.source" if query.kind == "source" else "memory.interpretation"
        make_key = source_key if query.kind == "source" else interpretation_key
        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError("expected_epoch must be NamespaceEpoch")
            if (expected_epoch.bot, expected_epoch.persona) != (bot, persona):
                raise ValueError("epoch crosses namespace")
        if after is not None:
            if not isinstance(after, AtomKey):
                raise TypeError("after must be AtomKey or None")
            if (after.owner.bot, after.owner.persona) != (bot, persona):
                raise ValueError("cursor crosses namespace")
            if after != make_key(bot, persona, after.owner.subject):
                raise ValueError("cursor does not match query kind")

        epoch = self.repository.store.graph_epoch(bot, persona)
        if expected_epoch is not None and epoch != expected_epoch:
            raise StaleRead("memory namespace changed between retrieval batches")

        hits: list[MemoryHit] = []
        candidate_count = node_count = page_count = 0
        processed_after = after
        folded_terms = tuple(term.casefold() for term in query.terms)

        def decode(key: AtomKey, value: dict):
            record = (
                SourceRecord.from_dict(value)
                if query.kind == "source"
                else InterpretationRecord.from_dict(value)
            )
            record_id = (
                record.source_id if isinstance(record, SourceRecord)
                else record.interpretation_id
            )
            if key != make_key(bot, persona, record_id):
                raise ValueError("memory record identity does not match its graph key")
            return record

        def finish(complete: bool, continuation: AtomKey | None) -> MemoryBatch:
            return self._final_batch(
                epoch=epoch,
                hits=hits,
                candidate_count=candidate_count,
                node_count=node_count,
                page_count=page_count,
                complete=complete,
                continuation=continuation,
            )

        def inspect(key: AtomKey, raw_record) -> bool:
            """Return False only when the node budget stopped this candidate."""
            nonlocal node_count
            if raw_record is None or not self._predicate(raw_record, query, folded_terms):
                return True
            remaining = max_nodes - node_count
            if remaining < 1:
                node_count = max_nodes
                return False
            try:
                if query.kind == "source":
                    record, proof = self.repository.read_source_evidence(
                        raw_record.source_id,
                        audience=audience,
                        purpose=purpose,
                        as_known_at=as_known_at,
                        max_nodes=remaining,
                    )
                    self._check_snapshot_epoch(proof, epoch)
                    node_count += len(proof.atoms)
                    if record is not None:
                        sources = (record,)
                        hits.append(MemoryHit(
                            key, record, proof.versions, _unique_roots(sources), sources
                        ))
                    return True

                record, interpretation_proof = self.repository.read_interpretation_evidence(
                    raw_record.interpretation_id,
                    audience=audience,
                    purpose=purpose,
                    as_known_at=as_known_at,
                    valid_at=valid_at,
                    max_nodes=remaining,
                )
                self._check_snapshot_epoch(interpretation_proof, epoch)
                node_count += len(interpretation_proof.atoms)
                if record is None:
                    return True
                sources: list[SourceRecord] = []
                proofs = [interpretation_proof]
                for source_id in record.source_ids:
                    remaining = max_nodes - node_count
                    if remaining < 1:
                        node_count = max_nodes
                        return False
                    source, source_proof = self.repository.read_source_evidence(
                        source_id,
                        audience=audience,
                        purpose=purpose,
                        as_known_at=as_known_at,
                        max_nodes=remaining,
                    )
                    self._check_snapshot_epoch(source_proof, epoch)
                    node_count += len(source_proof.atoms)
                    if source is None:
                        raise RuntimeError("authorized interpretation lost supporting source")
                    sources.append(source)
                    proofs.append(source_proof)
                source_tuple = tuple(sources)
                hits.append(MemoryHit(
                    key,
                    record,
                    _unique_versions(tuple(proofs)),
                    _unique_roots(source_tuple),
                    source_tuple,
                ))
                return True
            except CapacityExceeded:
                node_count = max_nodes
                return False

        if query.ids:
            keys = tuple(sorted((make_key(bot, persona, value) for value in query.ids),
                                key=lambda value: value.token))
            if after is not None:
                keys = tuple(key for key in keys if key.token > after.token)
            offset = 0
            while offset < len(keys):
                if candidate_count >= max_candidates or page_count >= max_pages:
                    return finish(False, processed_after)
                count = min(page_size, max_candidates - candidate_count, len(keys) - offset)
                page_keys = keys[offset:offset + count]
                snapshot = self.repository.store.graph_snapshot(page_keys)
                self._check_snapshot_epoch(snapshot, epoch)
                page_count += 1
                for key, atom in zip(page_keys, snapshot.atoms, strict=True):
                    candidate_count += 1
                    raw_record = None
                    if atom.valid and atom.revision > 0:
                        raw_record = decode(key, atom.value)
                    if not inspect(key, raw_record):
                        return finish(False, processed_after)
                    processed_after = key
                offset += count
            return finish(True, None)

        cursor = after
        while True:
            if candidate_count >= max_candidates or page_count >= max_pages:
                return finish(False, processed_after)
            limit = min(page_size, max_candidates - candidate_count)
            page = self.repository.store.graph_query(
                bot,
                persona,
                type_names=(type_name,),
                after=cursor,
                limit=limit,
                expected_epoch=epoch,
            )
            self._check_snapshot_epoch(page.snapshot, epoch)
            page_count += 1
            for atom in page.snapshot.atoms:
                candidate_count += 1
                raw_record = decode(atom.key, atom.value)
                if not inspect(atom.key, raw_record):
                    return finish(False, processed_after)
                processed_after = atom.key
            if page.next_after is None:
                return finish(True, None)
            cursor = page.next_after
