"""One persisted source can inform distinct mood-bound C04 candidates."""

import pytest
from dataclasses import asdict, replace

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectAxis, AffectCoupling, AffectProvider, AffectScheme
from sylanne3.domains.d06 import (
    CandidateItem, CandidateSet, D06DomainProvider, RecollectionContext,
    SelectionTicket,
)
from sylanne3.domains.d06.current_memory_evidence import (
    project_current_memory_evidence_page_v1,
)
from sylanne3.domains.d06.current_recollection_bridge import (
    prepare_current_c04_source_candidate_v1,
)
from sylanne3.domains.d06.current_focus_binding import bind_current_c04_focus_v1
from sylanne3.domains.d06.current_association_candidates import (
    CurrentAssociationBudgetV1, prepare_current_association_candidates_v1,
)
from sylanne3.domains.d07 import AttentionTicket, D07DomainProvider, FocusState, attention_ticket_key
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, association_key, source_key
from sylanne3.memory_association import PersistentAssociationReader
from sylanne3.runtime.current_memory_read_v1 import read_current_memory_evidence_page_v1
from sylanne3.runtime_contracts import NamespaceId, SourceQualification


NS = NamespaceId("bot", "persona")
SCOPE = Scope(*NS.as_tuple, "session")
SOURCE = source_key(*NS.as_tuple, "source-1")
MOOD = AtomKey(Owner("persona", *NS.as_tuple), "d04.mood_field.v1", "current")
SCHEME = AffectScheme("d04.affect.scheme.v1", "scheme-1", "operator-1",
                      "parameter-1", "coupling-1",
                      (AffectAxis("warmth", "normalized", "warmth"),), ())
COUPLING = AffectCoupling("recall", "coupling-1", "warmth", "warmth",
                          0.0, 0.25, 0.5)
QUALIFICATION = SourceQualification(
    (SOURCE.token,), "observed", 1.0, 2.0,
    "external_observation", "eligible", 0.8, "not_applicable",
)


def read_evidence(graph):
    epoch = graph.graph_epoch(*NS.as_tuple)
    db = graph._db
    db.execute("BEGIN")
    try:
        page, closure, coverage = read_current_memory_evidence_page_v1(
            db, NS, audience="owner", purpose="context", graph_epoch=epoch,
            access_epoch=0, delete_epoch=0,
        )
        evidence = project_current_memory_evidence_page_v1(
            page, closure, namespace=NS, graph_epoch=epoch,
            access_epoch=0, deletion_epoch=0, audience="owner",
            purpose="context", query_coverage=coverage,
        )
        db.execute("COMMIT")
        return evidence
    except BaseException:
        db.execute("ROLLBACK")
        raise


def commit_mood(graph, *, value, revision):
    snapshot = graph.graph_snapshot((MOOD, SOURCE))
    graph.graph_commit(GraphCandidate(
        Event(SCOPE, "mood-" + str(revision), 2.0 + revision, "mood", {}),
        snapshot.versions,
        (GraphWrite(MOOD, {
            "mood_id": "mood-1", "basis_version": "scheme-1",
            "coordinates": [["warmth", value]], "source_refs": [SOURCE.token],
            "parameter_version": "parameter-1", "coupling_version": "coupling-1",
            "cursor": 2.0 + revision, "revision": revision,
        }, (SOURCE,)),), snapshot.epochs,
    ))


def candidate(graph, activity, evidence=None, qualification=QUALIFICATION):
    evidence = evidence or read_evidence(graph)
    candidates = CandidateSet(
        "set-" + activity,
        (CandidateItem("item-" + activity, "source-1", "family-1", "exact",
                       ("context",), 0.8, "observed"),),
        "complete", access_epoch=0, delete_epoch=0,
    )
    ticket = SelectionTicket("ticket-" + activity, activity,
                             candidates.candidate_set_id,
                             ("item-" + activity,), 1)
    return prepare_current_c04_source_candidate_v1(
        evidence, namespace=NS, ticket=ticket, candidates=candidates,
        context=RecollectionContext((), (), ()),
        mood_snapshot=graph.graph_snapshot((MOOD,)), mood_key=MOOD,
        scheme=SCHEME, coupling=COUPLING,
        source_qualification=qualification,
        base_salience=(0.3, 0.4), base_tone=(-0.1, 0.0),
    )


def test_persisted_source_two_moods_yield_distinct_uncommitted_candidates(tmp_path):
    registry = TypeRegistry()
    for spec in (*D06DomainProvider.type_specs(),
                 *AffectProvider(active_scheme=SCHEME).type_specs()):
        registry.register(spec)
    graph = GraphStore(tmp_path / "graph.db", registry)
    try:
        repository = MemoryRepository(graph, *NS.as_tuple)
        repository.ingest(
            Event(SCOPE, "source-once", 1.0, "ingest", {}),
            SourceRecord("source-1", "A shared evening", "alice", "observed",
                         "confirmed", 1.0, 2.0, "family-1", ("owner",),
                         ("context",)),
        )
        graph._db.execute(
            "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
            "VALUES(?,?,0,0)", NS.as_tuple,
        )
        commit_mood(graph, value=0.6, revision=1)
        warm = candidate(graph, "activity-warm")
        with pytest.raises(ValueError, match="provenance or time"):
            candidate(graph, "activity-forged", qualification=replace(
                QUALIFICATION, occurred_at=9.0))
        stale_evidence = read_evidence(graph)
        commit_mood(graph, value=-0.6, revision=2)
        with pytest.raises(ValueError, match="one graph epoch"):
            candidate(graph, "activity-stale", stale_evidence)
        guarded = candidate(graph, "activity-guarded")
        assert warm.status == guarded.status == "candidate_hold_w01_atomic_c04"
        assert warm.view.source_text == guarded.view.source_text == "A shared evening"
        assert warm.view.subjective_tone != guarded.view.subjective_tone
        assert warm.view.subjective_salience != guarded.view.subjective_salience
        assert warm.proposal.activity_id != guarded.proposal.activity_id
        assert warm.reconstruction.source_ref == guarded.reconstruction.source_ref
        assert next(v.revision for v in warm.read_versions if v.key == MOOD) == 1
        assert next(v.revision for v in guarded.read_versions if v.key == MOOD) == 2
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='memory.source'",
        ).fetchone() == (1,)
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d04.recollection_experience.v1'",
        ).fetchone() == (0,)
        repository.set_access(
            Event(SCOPE, "withdraw", 5.0, "withdraw", {}), "source-1",
            audiences=("owner",), purposes=("context",),
            status="withdrawn", recorded_at=5.0,
        )
        assert read_evidence(graph).candidates == ()
        with pytest.raises(PermissionError, match="not currently qualified"):
            candidate(graph, "activity-after-withdrawal")
    finally:
        graph.close()


def test_current_focus_adds_d07_guard_and_rejects_unrelated_selection(tmp_path):
    registry = TypeRegistry()
    for spec in (*D06DomainProvider.type_specs(),
                 *AffectProvider(active_scheme=SCHEME).type_specs(),
                 *D07DomainProvider.type_specs()):
        registry.register(spec)
    graph = GraphStore(tmp_path / "focus.db", registry)
    try:
        MemoryRepository(graph, *NS.as_tuple).ingest(
            Event(SCOPE, "source-once", 1.0, "ingest", {}),
            SourceRecord("source-1", "A shared evening", "alice", "observed",
                         "confirmed", 1.0, 2.0, "family-1", ("owner",),
                         ("context",)),
        )
        target = source_key(*NS.as_tuple, "source-2")
        repository = MemoryRepository(graph, *NS.as_tuple)
        repository.ingest(
            Event(SCOPE, "target-once", 1.5, "ingest", {}),
            SourceRecord("source-2", "Another shared evening", "alice",
                         "observed", "confirmed", 1.5, 2.5, "family-2",
                         ("owner",), ("context",)),
        )
        graph._db.execute(
            "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
            "VALUES(?,?,0,0)", NS.as_tuple,
        )
        commit_mood(graph, value=0.6, revision=1)
        attention = AttentionTicket(
            "attention-1", "question:one", None, SOURCE.token, "interaction",
            0.8, 0.7, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
            1, 100.0, True, True, (), (SOURCE.token,),
        )
        attention_key = attention_ticket_key(NS, attention.ticket_id)
        focus_key = AtomKey(Owner("persona", *NS.as_tuple), "d07.focus.v1", NS.persona_id)
        focus = FocusState(NS.persona_id, 1, attention_key.token, (), "chosen")
        before = graph.graph_snapshot((attention_key, focus_key))
        graph.graph_commit(GraphCandidate(
            Event(SCOPE, "focus-on-source", 4.0, "focus", {}), before.versions,
            (GraphWrite(attention_key, {
                **asdict(attention), "schema": "d07.attention_ticket.v1",
                "cancel_refs": [], "source_refs": [SOURCE.token],
            }), GraphWrite(focus_key, {
                **asdict(focus), "schema": "d07.focus.v1",
                "auxiliary_ticket_refs": [],
            })), before.epochs,
        ))
        edge = association_key(*NS.as_tuple, "source-1", "related-evening")
        before_edge = graph.graph_snapshot((edge,))
        graph.graph_commit(GraphCandidate(
            Event(SCOPE, "existing-personal-link", 4.5, "association", {}),
            before_edge.versions,
            (GraphWrite(edge, {
                "association_id": "related-evening", "source_ref": SOURCE.token,
                "target_ref": target.token, "kind": "subjective_meaning",
                "weight": 0.8, "context_tags": ["evening"],
                "basis_source_refs": [SOURCE.token],
                "content_reality": "subjective",
            }),), before_edge.epochs,
        ))
        prepared = candidate(graph, "focused")
        selected = SelectionTicket("ticket-focused", "focused", "set-focused",
                                   ("item-focused",), 1)
        focus_snapshot = graph.graph_snapshot((
            attention_key, focus_key, SOURCE,
            access_key(*NS.as_tuple, "source-1"),
            source_correction_head_key(NS, "source-1"),
        ))
        bound = bind_current_c04_focus_v1(
            prepared, ticket=selected, focus_snapshot=focus_snapshot,
            namespace=NS, now=5.0, audience="owner", purpose="context",
        )
        assert bound.status == "candidate_hold_w01_atomic_c04"
        assert {v.key for v in bound.focus_read_versions} >= {focus_key, attention_key}
        assert set(bound.focus_read_versions) <= set(bound.read_versions)
        assert bound.reconstruction.source_ref == prepared.reconstruction.source_ref
        associations = prepare_current_association_candidates_v1(
            prepared, ticket=selected, focus_snapshot=focus_snapshot,
            namespace=NS, reader=PersistentAssociationReader(repository),
            now=5.0, audience="owner", purpose="context",
            budget=CurrentAssociationBudgetV1(max_edges=1),
            context_tags=("evening",),
        )
        assert tuple(item.source_ref for item in associations.candidates) == (target.token,)
        assert associations.candidates[0].evidence_eligibility == "subjective_association_only"
        assert associations.edge_refs == (edge.token,)
        assert associations.visited_edges == 1
        assert associations.status == "candidate_hold_d07_choice_w01_fence"
        stopped = prepare_current_association_candidates_v1(
            prepared, ticket=selected, focus_snapshot=focus_snapshot,
            namespace=NS, reader=PersistentAssociationReader(repository),
            now=5.0, audience="owner", purpose="context",
            budget=CurrentAssociationBudgetV1(max_hops=0),
            context_tags=("evening",),
        )
        assert stopped.candidates == ()
        assert stopped.visited_edges == 0
        assert stopped.stop_reason == "hop_budget_exhausted"
        commit_mood(graph, value=-0.6, revision=2)
        other_mood = candidate(graph, "focused")
        other_focus = graph.graph_snapshot((
            attention_key, focus_key, SOURCE,
            access_key(*NS.as_tuple, "source-1"),
            source_correction_head_key(NS, "source-1"),
        ))
        alternate = prepare_current_association_candidates_v1(
            other_mood, ticket=selected, focus_snapshot=other_focus,
            namespace=NS, reader=PersistentAssociationReader(repository),
            now=5.0, audience="owner", purpose="context",
            budget=CurrentAssociationBudgetV1(max_edges=1),
            context_tags=("evening",),
        )
        assert tuple(item.source_ref for item in alternate.candidates) == (target.token,)
        assert (alternate.candidates[0].mood_weighted_activation
                != associations.candidates[0].mood_weighted_activation)
        assert alternate.candidates[0].activation == associations.candidates[0].activation
        with pytest.raises(ValueError, match="qualified D07 focus"):
            bind_current_c04_focus_v1(
                prepared, ticket=selected,
                focus_snapshot=replace(focus_snapshot, atoms=tuple(
                    atom for atom in focus_snapshot.atoms if atom.key != attention_key)),
                namespace=NS, now=5.0, audience="owner", purpose="context",
            )
        repository.set_access(
            Event(SCOPE, "withdraw-target", 6.0, "withdraw", {}), "source-2",
            audiences=("owner",), purposes=("context",),
            status="withdrawn", recorded_at=6.0,
        )
        current = candidate(graph, "focused")
        current_focus = graph.graph_snapshot((
            attention_key, focus_key, SOURCE,
            access_key(*NS.as_tuple, "source-1"),
            source_correction_head_key(NS, "source-1"),
        ))
        after = prepare_current_association_candidates_v1(
            current, ticket=selected, focus_snapshot=current_focus,
            namespace=NS, reader=PersistentAssociationReader(repository),
            now=7.0, audience="owner", purpose="context",
            budget=CurrentAssociationBudgetV1(max_edges=1),
            context_tags=("evening",),
        )
        assert after.candidates == ()
        assert after.stop_reason == "no_eligible_association"
        with pytest.raises(ValueError, match="qualified D07 focus"):
            bind_current_c04_focus_v1(
                prepared, ticket=selected, focus_snapshot=focus_snapshot,
                namespace=NS, now=101.0, audience="owner", purpose="context",
            )
        with pytest.raises(ValueError, match="qualified D07 focus"):
            bind_current_c04_focus_v1(
                prepared, ticket=replace(selected, focus_epoch=2),
                focus_snapshot=focus_snapshot, namespace=NS, now=5.0,
                audience="owner", purpose="context",
            )
        access = access_key(*NS.as_tuple, "source-1")
        with pytest.raises(ValueError, match="qualified D07 focus"):
            bind_current_c04_focus_v1(
                prepared, ticket=selected,
                focus_snapshot=replace(focus_snapshot, atoms=tuple(
                    replace(atom, value={**atom.value, "status": "withdrawn"})
                    if atom.key == access else atom for atom in focus_snapshot.atoms)),
                namespace=NS, now=5.0, audience="owner", purpose="context",
            )
    finally:
        graph.close()
