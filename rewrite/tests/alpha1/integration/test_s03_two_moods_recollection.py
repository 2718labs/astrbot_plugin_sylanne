"""S03 candidate slice: one source, two D07 selections, two D04 mood reads.

Source and mood are persisted fixtures. D06 retrieval/reconstruction, D07
selection, and GraphCoordinator snapshot reads use their real implementations.
No C04 activity or expense settlement is claimed by this test.
"""

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import (
    AffectAxis, AffectCoupling, AffectProvider, AffectScheme, MoodField,
)
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, RecallIntent, RecollectionContext,
    TriggerKind,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import (
    SourceRecord, access_key, register_memory_types, source_key,
)
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId, SourceQualification


ROLE = NamespaceId("bot", "persona")
SCOPE = Scope("bot", "persona", "session")
SOURCE = source_key("bot", "persona", "one-evening")
MOOD = AtomKey(Owner("persona", "bot", "persona"), "d04.mood_field.v1", "current")


def test_same_source_two_moods_and_withdrawal_barrier(tmp_path):
    scheme = AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameters-1",
        "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), ())
    coupling = AffectCoupling("recall", "coupling-1", "warmth", "warmth",
                              0.0, 0.5, 0.5)
    affect = AffectProvider(active_scheme=scheme)
    memory = D06DomainProvider()
    attention = D07DomainProvider()
    registry = TypeRegistry()
    register_memory_types(registry)
    for provider in (memory, affect, attention):
        specs = (provider.type_specs() if hasattr(provider, "type_specs")
                 else provider.register_types())
        for spec in specs:
            if spec.name not in {item.name for item in registry.specs}:
                registry.register(spec)
    store = GraphStore(tmp_path / "business.db", registry)
    try:
        repository = MemoryRepository(store, "bot", "persona")
        pipeline = D06MemoryPipeline(D06DomainAdapter(ROLE), repository)
        repository.ingest(
            Event(SCOPE, "one-observed-evening", 1.0, "ingress", {}),
            SourceRecord("one-evening", "We waited together", "alice",
                         "observed", "confirmed", 1.0, 2.0, "family-evening",
                         ("owner",), ("context",)))
        bootstrap = object()
        graph = GraphCoordinator(store, bootstrap)
        for domain, provider, proposal_schema in (
            ("d06", memory, "d06.contract.v1"),
            ("d04", affect, "d04.proposal.v1"),
            ("d07", attention, "d07.proposal.v1"),
        ):
            graph.register_provider(
                bootstrap, domain, provider, proposal_schema,
                provider.descriptor.request_schema_hash)
        lease, ref = graph.grant(
            bootstrap, actor="recollection-worker", issuer_domain="d06",
            namespace=ROLE, domains=("d04", "d06", "d07"),
            activation_generation=1)
        authority = AuthorityContext(
            "recollection-worker", "d06", ref, ROLE,
            ("persona", "event", "activity"), "context", ("owner",),
            "policy", 1)
        qualification = pipeline.adapter.qualify_recall(
            RecallIntent("ask", TriggerKind.EXPLICIT_PAST_REQUEST,
                         "remember that evening"))
        source_qualification = SourceQualification(
            (SOURCE.token,), "observed", 1.0, 2.0,
            "external_observation", "eligible", 0.8, "not_applicable")

        def reconstruct(activity_id, warmth):
            mood = MoodField(
                "mood-1", "scheme-1", (("warmth", warmth),),
                (SOURCE.token,), "parameters-1", "coupling-1", 2.0)
            old = store.graph_snapshot((MOOD,))
            store.graph_commit(GraphCandidate(
                Event(SCOPE, "mood:" + activity_id, 2.0, "mood", {}),
                old.versions,
                (GraphWrite(MOOD, {
                    **mood.__dict__, "coordinates": [["warmth", warmth]],
                    "source_refs": [SOURCE.token],
                }),), old.epochs))
            mood_snapshot = graph.read_snapshot(authority, lease, (MOOD,))
            outcome = pipeline.retrieve_candidates(
                qualification, "set:" + activity_id,
                (SearchPlan("exact", MemoryQuery("source", ids=("one-evening",)), 1),),
                audience="owner", purpose="context", access_epoch=0,
                delete_epoch=0)
            assert len(outcome.candidates.items) == 1
            handoff = attention.select_bounded_recollection(
                activity_id=activity_id, focus_epoch=1,
                candidates=outcome.candidates, purpose="context",
                eligible_candidate_ids=tuple(
                    item.candidate_id for item in outcome.candidates.items))
            result = pipeline.prepare_affective_recollection(
                outcome, handoff.selection_ticket,
                RecollectionContext((), (), ()), audience="owner",
                purpose="context", mood_snapshot=mood_snapshot,
                mood_key=MOOD, scheme=scheme, coupling=coupling,
                source_qualification=source_qualification,
                base_salience=(0.4, 0.6), base_tone=(-0.1, 0.1),
                detail_cues=())
            return handoff, result

        first_ticket, first = reconstruct("recall-warm", 0.8)
        second_ticket, second = reconstruct("recall-guarded", -0.8)
        assert first_ticket.selection_ticket.activity_id != second_ticket.selection_ticket.activity_id
        assert first.status == second.status == "candidate_hold"
        assert first.source_ref == second.source_ref == SOURCE.token
        assert first.source_fields == second.source_fields
        assert first.subjective_tone != second.subjective_tone
        assert first.subjective_weight != second.subjective_weight
        assert {version.revision for version in first.read_versions
                if version.key == MOOD} == {1}
        assert {version.revision for version in second.read_versions
                if version.key == MOOD} == {2}
        assert len(graph.query(
            authority, lease, type_names=("memory.source",),
            owner_kind="event").snapshot.atoms) == 1

        # A later access withdrawal blocks a new authorized reconstruction.
        access = access_key("bot", "persona", "one-evening")
        before = store.graph_snapshot((access,))
        current = before.get(access)
        store.graph_commit(GraphCandidate(
            Event(SCOPE, "withdraw-access", 3.0, "access", {}),
            before.versions,
            (GraphWrite(access, {**current.value, "status": "withdrawn"}),),
            before.epochs))
        source, _ = repository.read_source_evidence(
            "one-evening", audience="owner", purpose="context")
        assert source is None
        assert first.source_ref == second.source_ref  # history is not duplicated
    finally:
        store.close()
