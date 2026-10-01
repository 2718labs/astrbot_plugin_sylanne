"""Optional D06 vectors never replace authorized structural retrieval."""

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainAdapter, RecallIntent, TriggerKind
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.domains.d06.vector_channel import VolatileVectorGeneration
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import SourceRecord, register_memory_types
from sylanne3.runtime_contracts import NamespaceId


def test_vector_generation_switch_disable_and_revocation_fall_back(tmp_path):
    registry = TypeRegistry()
    register_memory_types(registry)
    store = GraphStore(tmp_path / "memory.db", registry)
    try:
        repository = MemoryRepository(store, "bot", "persona")
        scope = Scope("bot", "persona", "session")
        for index, (source_id, text) in enumerate((
            ("lexical", "the blue bridge"), ("semantic", "the old crossing"),
        ), start=1):
            repository.ingest(
                Event(scope, f"ingest-{index}", float(index), "ingest", {}),
                SourceRecord(source_id, text, "alice", "observed", "confirmed",
                             float(index), float(index), source_id,
                             ("owner",), ("context",)),
            )
        index = VolatileVectorGeneration.build(
            repository, model_id="embed-v1", preprocessing_id="prep-v1",
            audience="owner", purpose="context", vectors=(
                ("lexical", (0.0, 1.0)), ("semantic", (1.0, 0.0)),
            ),
        )
        pipeline = D06MemoryPipeline(D06DomainAdapter(NamespaceId("bot", "persona")),
                                     repository)
        qualification = pipeline.adapter.qualify_recall(RecallIntent(
            "ask", TriggerKind.EXPLICIT_PAST_REQUEST, "blue bridge",
        ))
        plans = (SearchPlan("lexical", MemoryQuery("source", terms=("blue",)), 1.0),)

        def search(*, enabled=True, model="embed-v1"):
            return pipeline.retrieve_candidates(
                qualification, "candidate-set", plans, audience="owner",
                purpose="context", access_epoch=0, delete_epoch=0,
                vector_generation=index, vector_query=(1.0, 0.0),
                vector_model_id=model, vector_preprocessing_id="prep-v1",
                vector_enabled=enabled,
            )

        enabled = search()
        assert enabled.vector_coverage == "vector_candidates_revalidated"
        assert {item.content_ref for item in enabled.candidates.items} == {
            "lexical", "semantic",
        }
        disabled = search(enabled=False)
        assert disabled.vector_coverage == "disabled_structural_fallback"
        assert {item.content_ref for item in disabled.candidates.items} == {"lexical"}
        wrong_model = search(model="embed-v2")
        assert wrong_model.vector_coverage == "partition_or_generation_mismatch_structural_fallback"
        assert {item.content_ref for item in wrong_model.candidates.items} == {"lexical"}

        repository.set_access(
            Event(scope, "withdraw", 3.0, "withdraw", {}), "semantic",
            audiences=("owner",), purposes=("context",), status="withdrawn",
            recorded_at=3.0,
        )
        stale = search()
        assert stale.vector_coverage == "stale_structural_fallback"
        assert {item.content_ref for item in stale.candidates.items} == {"lexical"}
    finally:
        store.close()
