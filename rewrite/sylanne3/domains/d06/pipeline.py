"""Read-only D06 preparation over the shared persistent-memory graph.

This module deliberately stops at candidates.  Source ingestion and every
write still go through the shared coordinator; a successful query or encoding
preparation is never an assertion that a memory episode or recollection took
place.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import GraphVersion, NamespaceEpoch
from ...memory_repository import MemoryRepository
from ...memory_retrieval import MemoryBatch, MemoryQuery, MemoryRetriever
from ...memory_retrieval import MemoryHit
from ...memory_recollection_view import prepare_affective_recollection_view
from ...memory_reconstruction import DetailCue, RecollectionReconstruction, reconstruct_recollection_candidate
from ...memory_types import source_key
from ...memory_types import access_key
from ...runtime_contracts import NamespaceId, SourceQualification
from ...graph_types import AtomKey, GraphSnapshot
from ..d04 import AffectCoupling, AffectScheme
from . import (
    CandidateSet,
    D06DomainAdapter,
    EncodingContext,
    EncodingProposal,
    RecallQualification,
    RetrievalChannel,
    RecollectionContext,
    SelectionTicket,
)


def _epoch(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _unique_versions(batches: tuple[MemoryBatch, ...]) -> tuple[GraphVersion, ...]:
    versions: list[GraphVersion] = []
    seen = set()
    for batch in batches:
        for hit in batch.hits:
            for version in hit.proof_versions:
                if version.key not in seen:
                    seen.add(version.key)
                    versions.append(version)
    return tuple(versions)


@dataclass(frozen=True)
class SearchPlan:
    """One bounded, structural retrieval channel.

    ``query`` remains an exact predicate.  This type intentionally has no
    semantic-model field: vector/model retrieval needs a separately admitted
    provider and must not be silently treated as source evidence.
    """

    name: str
    query: MemoryQuery
    activation: float

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.strip():
            raise ValueError("name must be a nonempty string")
        if not isinstance(self.query, MemoryQuery):
            raise TypeError("query must be MemoryQuery")
        if (type(self.activation) not in (int, float)
                or isinstance(self.activation, bool)
                or not math.isfinite(self.activation)):
            raise ValueError("activation must be a finite number from 0 to 1")
        if not 0.0 <= float(self.activation) <= 1.0:
            raise ValueError("activation must be a finite number from 0 to 1")


@dataclass(frozen=True)
class PreparedEncoding:
    """A source-verified C02 candidate, with the exact proof it read."""

    source_ref: str
    proposal: EncodingProposal
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate"


@dataclass(frozen=True)
class RetrievalOutcome:
    """Candidate material plus the frozen proof set; never a recall receipt."""

    status: str
    candidates: CandidateSet | None
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch | None
    batches: tuple[MemoryBatch, ...]


@dataclass(frozen=True)
class PreparedAssociation:
    source_ref: str
    target_ref: str
    basis_source_refs: tuple[str, ...]
    proof_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate"


class D06MemoryPipeline:
    """Connect committed source evidence to D06-only encoding/query candidates."""

    def __init__(self, adapter: D06DomainAdapter, repository: MemoryRepository):
        if not isinstance(adapter, D06DomainAdapter):
            raise TypeError("adapter must be D06DomainAdapter")
        if not isinstance(repository, MemoryRepository):
            raise TypeError("repository must be MemoryRepository")
        if (repository.bot, repository.persona) != adapter.namespace.as_tuple:
            raise ValueError("repository namespace differs from D06 adapter")
        self.adapter = adapter
        self.repository = repository
        self.retriever = MemoryRetriever(repository)

    def prepare_affective_recollection(
        self,
        outcome: RetrievalOutcome,
        ticket: SelectionTicket,
        context: RecollectionContext,
        *,
        audience: str,
        purpose: str,
        mood_snapshot: GraphSnapshot,
        mood_key: AtomKey,
        scheme: AffectScheme,
        coupling: AffectCoupling,
        source_qualification: SourceQualification,
        base_salience: tuple[float, float],
        base_tone: tuple[float, float],
        detail_cues: tuple[DetailCue, ...],
        then_meaning_refs: tuple[str, ...] = (),
        temporal_focus: bool = False,
    ) -> RecollectionReconstruction:
        """Prepare one selected source as a mood-shaped C04 candidate.

        The source and access are read again after retrieval. A final graph
        snapshot checks the mood and every read version before returning.
        Actual recollection and experience submission belong to C04/D11.
        """
        if outcome.status != "candidate" or outcome.candidates is None or outcome.epoch is None:
            raise ValueError("a qualified D06 retrieval outcome is required")
        if len(ticket.selected_candidate_ids) != 1:
            raise ValueError("one D07 selected candidate is required")
        if (mood_snapshot.epochs != (outcome.epoch,) or
                (outcome.epoch.bot, outcome.epoch.persona) != self.adapter.namespace.as_tuple):
            raise RuntimeError("D06 retrieval and D04 mood epochs differ")
        selected = next((item for item in outcome.candidates.items
                         if item.candidate_id == ticket.selected_candidate_ids[0]), None)
        if selected is None:
            raise ValueError("D07 ticket does not select a D06 candidate")
        hit = next((hit for batch in outcome.batches for hit in batch.hits
                    if isinstance(hit, MemoryHit) and hit.key == source_key(
                        *self.adapter.namespace.as_tuple, selected.content_ref)), None)
        if hit is None:
            raise ValueError("selected source has no retrieval proof")
        current_source, source_proof = self.repository.read_source_evidence(
            selected.content_ref, audience=audience, purpose=purpose,
        )
        if current_source is None:
            raise PermissionError("selected source is no longer accessible")
        if source_proof.epochs != (outcome.epoch,) or current_source != hit.record:
            raise RuntimeError("selected source changed after retrieval")
        proof_by_key = {version.key: version for version in source_proof.versions}
        if any(proof_by_key.get(version.key) != version for version in hit.proof_versions):
            raise RuntimeError("selected source or access proof changed after retrieval")

        view = prepare_affective_recollection_view(
            ticket=ticket, candidates=outcome.candidates, hit=hit,
            mood_snapshot=mood_snapshot, mood_key=mood_key,
            scheme=scheme, coupling=coupling,
            source_qualification=source_qualification,
            base_salience=base_salience, base_tone=base_tone, purpose=purpose,
        )
        proposal = self.adapter.prepare_recollection(ticket, outcome.candidates, context)
        result = reconstruct_recollection_candidate(
            proposal=proposal, view=view, detail_cues=detail_cues,
            then_meaning_refs=then_meaning_refs, temporal_focus=temporal_focus,
        )
        current = self.repository.store.graph_snapshot(
            tuple(dict.fromkeys((*proof_by_key, mood_key)))
        )
        if (current.epochs != (outcome.epoch,) or
                current.get(mood_key) != mood_snapshot.get(mood_key) or any(
            current.get(version.key) is None or
            current.get(version.key).revision != version.revision or
            not current.get(version.key).valid
            for version in (*source_proof.versions, *result.read_versions)
        )):
            raise RuntimeError("recollection source, access, or mood changed during preparation")
        return result

    def prepare_association(
        self,
        source_id: str,
        target_id: str,
        basis_source_ids: tuple[str, ...],
        *,
        audience: str,
        purpose: str,
    ) -> PreparedAssociation:
        """Read all edge sources through current access before graph compilation."""
        if type(basis_source_ids) is not tuple or not basis_source_ids:
            raise ValueError("association needs at least one basis source")
        if source_id == target_id:
            raise ValueError("association endpoints must differ")
        ids = tuple(dict.fromkeys((source_id, target_id, *basis_source_ids)))
        if len(ids) > 10 or any(type(item) is not str or not item for item in ids):
            raise ValueError("association source IDs must be bounded nonempty strings")
        proofs: list[GraphVersion] = []
        epoch = None
        namespace = self.adapter.namespace.as_tuple
        for source_id_to_read in ids:
            source, proof = self.repository.read_source_evidence(
                source_id_to_read, audience=audience, purpose=purpose,
            )
            if source is None:
                raise PermissionError("association source is unavailable")
            current_epoch = proof.epochs[0]
            if epoch is not None and current_epoch != epoch:
                raise RuntimeError("association namespace changed during source reads")
            epoch = current_epoch
            for key in (source_key(*namespace, source_id_to_read),
                        access_key(*namespace, source_id_to_read)):
                if not any(version.key == key and version.revision > 0 for version in proof.versions):
                    raise RuntimeError("association source lacks committed access proof")
            proofs.extend(proof.versions)
        if self.repository.store.graph_epoch(*namespace) != epoch:
            raise RuntimeError("association namespace changed during preparation")
        unique = {version.key: version for version in proofs}
        if len(unique) != len(proofs) and any(
            unique[version.key] != version for version in proofs
        ):
            raise RuntimeError("association source proof changed during preparation")
        return PreparedAssociation(
            source_id, target_id, basis_source_ids, tuple(unique.values()), epoch,
        )

    def prepare_encoding(
        self,
        source_ref: str,
        context: EncodingContext,
        *,
        audience: str,
        purpose: str,
        expected_epoch: NamespaceEpoch | None = None,
    ) -> PreparedEncoding:
        """Prepare C02 only from currently authorized, committed source bytes."""

        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError("expected_epoch must be NamespaceEpoch or None")
            if (expected_epoch.bot, expected_epoch.persona) != self.adapter.namespace.as_tuple:
                raise ValueError("expected_epoch crosses D06 namespace")
        source, proof = self.repository.read_source_evidence(
            source_ref, audience=audience, purpose=purpose
        )
        if source is None:
            raise PermissionError("source is unavailable for encoding")
        epoch = proof.epochs[0]
        if expected_epoch is not None and epoch != expected_epoch:
            raise RuntimeError("source namespace changed before encoding preparation")
        if self.repository.store.graph_epoch(*self.adapter.namespace.as_tuple) != epoch:
            raise RuntimeError("source namespace changed during encoding preparation")
        source_version = next(
            (version for version in proof.versions
             if version.key == source_key(*self.adapter.namespace.as_tuple, source_ref)),
            None,
        )
        if source_version is None:
            raise RuntimeError("source read proof does not contain the requested source")
        if not any(
            (ref, source_version.revision) in context.read_versions
            for ref in (source_ref, source_version.key.token)
        ):
            raise ValueError("encoding context must bind the committed source revision")
        proposal = self.adapter.prepare_encoding(source.source_id, context)
        return PreparedEncoding(source.source_id, proposal, proof.versions, epoch)

    def retrieve_candidates(
        self,
        qualification: RecallQualification,
        candidate_set_id: str,
        plans: tuple[SearchPlan, ...],
        *,
        audience: str,
        purpose: str,
        access_epoch: int,
        delete_epoch: int,
        as_known_at: float | None = None,
        valid_at: float | None = None,
        expected_epoch: NamespaceEpoch | None = None,
    ) -> RetrievalOutcome:
        """Run only qualified bounded searches and return authorization-bound candidates."""

        if not isinstance(qualification, RecallQualification):
            raise TypeError("qualification must be RecallQualification")
        if type(plans) is not tuple or any(not isinstance(plan, SearchPlan) for plan in plans):
            raise TypeError("plans must be a tuple of SearchPlan")
        if len(plans) > 5:
            raise ValueError("at most five structural search plans are allowed")
        _epoch(access_epoch, "access_epoch")
        _epoch(delete_epoch, "delete_epoch")
        if qualification.mode in {"no_history_search", "working_set_only"}:
            return RetrievalOutcome("not_requested", None, (), None, ())
        if qualification.mode not in {"mandatory", "optional_association"}:
            raise ValueError("unknown recall qualification mode")
        if not plans:
            raise ValueError("qualified history retrieval requires at least one search plan")

        batches: list[MemoryBatch] = []
        for plan in plans:
            batch = self.retriever.search(
                plan.query,
                audience=audience,
                purpose=purpose,
                as_known_at=as_known_at,
                valid_at=valid_at,
                max_candidates=32,
                max_nodes=128,
                page_size=32,
                max_pages=1,
                expected_epoch=expected_epoch,
            )
            batches.append(batch)
            expected_epoch = batch.epoch

        batch_tuple = tuple(batches)
        candidates = self.adapter.assemble_candidates(
            candidate_set_id,
            tuple(RetrievalChannel(plan.name, batch, plan.activation)
                  for plan, batch in zip(plans, batch_tuple, strict=True)),
            purpose=purpose,
            max_candidates=64,
            access_epoch=access_epoch,
            delete_epoch=delete_epoch,
        )
        return RetrievalOutcome(
            "candidate",
            candidates,
            _unique_versions(batch_tuple),
            batch_tuple[0].epoch,
            batch_tuple,
        )
