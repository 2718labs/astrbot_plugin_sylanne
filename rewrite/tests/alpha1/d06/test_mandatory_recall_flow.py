"""A persisted source can yield two different candidate experiences, not two facts."""

from pathlib import Path

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectAxis, AffectCoupling, AffectProvider, AffectScheme, MoodField
from sylanne3.domains.d03.context import ContextProvider
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, RecallIntent, RecollectionContext,
    TriggerKind, source_correction_head_key,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.domains.d06.recall_flow import prepare_mandatory_recollection_candidate
from sylanne3.domains.d06.recall_flow import assemble_prepared_mandatory_recollection_bundle
from sylanne3.domains.d07 import (
    CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_reconstruction import DetailCue
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import (
    SourceRecord, access_key, episode_key, source_key, subjective_trace_v2_key,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainProposal,
    NamespaceId, OperationIdentity, RUNTIME_SCHEMA, SourceQualification,
    VersionGuard, VersionedRef, canonical_digest, schema_hash,
)


def _fixture(tmp_path: Path, *, private_baseline_source=False):
    namespace = NamespaceId("bot", "persona")
    scheme = AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameters-1",
        "coupling-1", (AffectAxis("warmth", "normalized", "warmth"),), (),
    )
    coupling = AffectCoupling("recall", "coupling-1", "warmth", "warmth", 0, 0.5, 0.5)
    registry = TypeRegistry()
    for provider in (D06DomainProvider(), AffectProvider(active_scheme=scheme),
                     ContextProvider()):
        for spec in provider.type_specs():
            registry.register(spec)
    store = GraphStore(tmp_path / "memory.db", registry)
    repository = MemoryRepository(store, "bot", "persona")
    scope = Scope("bot", "persona", "session")
    source = SourceRecord(
        "source-1", "I waited a long time", "alice", "reported", "reported",
        1.0, 2.0, "family-1", ("owner",), ("context",),
    )
    repository.ingest(Event(scope, "ingest-1", 1, "ingress", {}), source)
    source_ref = source_key("bot", "persona", "source-1")
    source_refs = [source_ref.token]
    if private_baseline_source:
        private = SourceRecord(
            "source-2", "A private detail", "alice", "reported", "reported",
            1.0, 2.0, "family-2", ("private",), ("context",),
        )
        repository.ingest(Event(scope, "ingest-2", 1, "ingress", {}), private)
        source_refs.append(source_key("bot", "persona", "source-2").token)
    mood_key = AtomKey(Owner("persona", "bot", "persona"), "d04.mood_field.v1", "current")
    episode = episode_key("bot", "persona", "episode-1")
    trace = subjective_trace_v2_key("bot", "persona", "trace-1")
    event = AtomKey(Owner("event", "bot", "persona", "world:event-1"),
                    "d03.world_event", "current")
    perspective = AtomKey(Owner("scene", "bot", "persona", "scene:1"),
                          "d03.role_binding", "current")
    baseline = AtomKey(Owner("event", "bot", "persona", "world:event-1"),
                       "d04.encoding_baseline.v1", "record")
    graph = store.graph_snapshot((episode, trace, baseline, mood_key, event, perspective))
    store.graph_commit(GraphCandidate(
        Event(scope, "encoding-1", 2, "encoding", {}), graph.versions,
        (
            GraphWrite(event, {
                "event_id": "world:event-1", "kind": "conversation",
                "participant_roles": [["entity:alice", "speaker"]],
                "occurred_from": 1.0, "occurred_until": 1.0,
                "learned_at": 2.0, "scene_ref": "scene:1",
                "source_refs": [source_ref.token], "reality": "reported",
            }),
            GraphWrite(perspective, {
                "role_binding_id": "binding:1", "subject_persona_ref": "persona:persona",
                "social_role": "friend", "target_entity_ref": "entity:alice",
                "group_ref": None, "scene_ref": "scene:1",
                "scope_selector": "scene", "visibility_scope": "owner", "norm_refs": [],
                "effective_from": 1.0, "effective_until": None,
                "precedence": 0, "source_refs": [source_ref.token],
                "binding_version": 1, "status": "active",
            }),
            GraphWrite(episode, {"episode_id": "episode-1",
                                 "source_refs": [source_ref.token], "event_ref": event.token}),
            GraphWrite(trace, {"trace_id": "trace-1", "episode_ref": episode.token,
                               "perspective_ref": perspective.token,
                               "then_feeling_refs": [], "interpretation_refs": [],
                               "detail_weights": [["waiting", 0.65]],
                               "encoding_baseline_ref": baseline.token}),
            GraphWrite(baseline, {
                "baseline_id": "baseline-1", "source_refs": source_refs,
                "perspective_ref": perspective.token, "then_feeling_versions": [],
                "interpretation_versions": [], "as_known_at": None,
                "projection_policy_ref": "policy-unresolved",
                "projection_policy_version": "policy-v1", "basis_version": "scheme-1",
                "parameter_version": "parameters-1", "salience_interval": None,
                "tone_interval": None,
                "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
            }),
        ), graph.epochs,
    ))
    adapter = D06DomainAdapter(namespace)
    pipeline = D06MemoryPipeline(adapter, repository)
    return store, scope, pipeline, namespace, scheme, coupling, mood_key, trace


def _mood(store, scope, mood_key, warmth, event_id):
    source = source_key("bot", "persona", "source-1")
    mood = MoodField("mood-1", "scheme-1", (("warmth", warmth),),
                     (source.token,), "parameters-1", "coupling-1", 2.0)
    before = store.graph_snapshot((mood_key,))
    store.graph_commit(GraphCandidate(
        Event(scope, event_id, 3, "mood", {}), before.versions,
        (GraphWrite(mood_key, {**mood.__dict__,
                               "coordinates": [["warmth", warmth]],
                               "source_refs": [source.token]}),), before.epochs,
    ))


def _prepare(store, pipeline, namespace, scheme, coupling, mood_key, trace, activity,
             source_qualification=None, context=None):
    source = source_key(*namespace.as_tuple, "source-1")
    access = access_key(*namespace.as_tuple, "source-1")
    correction = source_correction_head_key(namespace, "source-1")
    episode = episode_key(*namespace.as_tuple, "episode-1")
    baseline = AtomKey(Owner("event", *namespace.as_tuple, "world:event-1"),
                       "d04.encoding_baseline.v1", "record")
    event = AtomKey(Owner("event", *namespace.as_tuple, "world:event-1"),
                    "d03.world_event", "current")
    perspective = AtomKey(Owner("scene", *namespace.as_tuple, "scene:1"),
                          "d03.role_binding", "current")
    qualification = pipeline.adapter.qualify_recall(RecallIntent(
        "ask-1", TriggerKind.EXPLICIT_PAST_REQUEST, "What happened before?",
    ))
    outcome = pipeline.retrieve_candidates(
        qualification, f"set-{activity}",
        (SearchPlan("exact", MemoryQuery("source", ids=("source-1",)), 1.0),),
        audience="owner", purpose="context", access_epoch=0, delete_epoch=0,
    )
    snapshot = store.graph_snapshot((source, access, correction, mood_key,
                                     episode, trace, baseline, event, perspective,
                                     source_key(*namespace.as_tuple, "source-2")))
    epoch_before = store.graph_epoch(*namespace.as_tuple)
    candidate = prepare_mandatory_recollection_candidate(
        adapter=pipeline.adapter, cognition=D07DomainProvider(),
        intent=RecallIntent("ask-1", TriggerKind.EXPLICIT_PAST_REQUEST,
                            "What happened before?"),
        outcome=outcome, snapshot=snapshot, activity_id=activity,
        focus_epoch=1, audience="owner", purpose="context",
        mood_key=mood_key, scheme=scheme, coupling=coupling,
        source_qualification=source_qualification or SourceQualification(
            (source.token,), "reported", 1.0, 2.0, "external_report",
            "qualified", 0.6, "not_applicable",
        ),
        base_salience=(0.4, 0.6), base_tone=(-0.1, 0.1),
        detail_cues=(DetailCue("waiting", (0, 8), 0.65),),
        context=context or RecollectionContext((), (), ()), encoding_trace_ref=trace.token,
    )
    assert store.graph_epoch(*namespace.as_tuple) == epoch_before
    return candidate


def test_one_committed_source_two_moods_change_only_candidate_experience(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        _mood(store, scope, mood_key, 0.8, "warm-mood")
        warm = _prepare(store, pipeline, namespace, scheme, coupling,
                        mood_key, trace, "activity-warm")
        _mood(store, scope, mood_key, -0.8, "guarded-mood")
        guarded = _prepare(store, pipeline, namespace, scheme, coupling,
                           mood_key, trace, "activity-guarded")
        assert warm.status == guarded.status == "candidate_hold"
        assert warm.qualification.mode == "mandatory"
        assert warm.handoff.selection_ticket.selected_candidate_ids
        assert warm.reconstruction.encoding_trace_ref == trace.token
        assert warm.event_ref == guarded.event_ref == AtomKey(
            Owner("event", *namespace.as_tuple, "world:event-1"),
            "d03.world_event", "current").token
        assert warm.episode_ref == guarded.episode_ref == episode_key(
            *namespace.as_tuple, "episode-1").token
        assert warm.reconstruction.activity_id != guarded.reconstruction.activity_id
        assert warm.reconstruction.source_ref == guarded.reconstruction.source_ref
        assert warm.reconstruction.source_fields == guarded.reconstruction.source_fields
        assert warm.reconstruction.subjective_tone != guarded.reconstruction.subjective_tone
        assert warm.reconstruction.subjective_weight != guarded.reconstruction.subjective_weight
        assert store.graph_snapshot((source_key(*namespace.as_tuple, "source-1"),)).atoms[0].revision == 1
    finally:
        store.close()


def test_reported_source_cannot_be_promoted_to_observed_or_eligible(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        _mood(store, scope, mood_key, 0.8, "warm-mood")
        source = source_key(*namespace.as_tuple, "source-1")
        for claim in (
            SourceQualification((source.token,), "observed", 1.0, 2.0,
                                "external_observation", "eligible", 0.6,
                                "not_applicable"),
            SourceQualification((source.token,), "reported", 1.0, 2.0,
                                "external_report", "eligible", 0.6,
                                "not_applicable"),
        ):
            with pytest.raises(ValueError, match="qualification differs"):
                _prepare(store, pipeline, namespace, scheme, coupling,
                         mood_key, trace, "activity-false-claim", claim)
    finally:
        store.close()


def _bundle_candidate(store, pipeline, namespace, scheme, coupling, mood_key,
                      prepared, warmth):
    activity = prepared.reconstruction.activity_id
    selected = prepared.reconstruction.source_ref
    snapshot = store.graph_snapshot(tuple(version.key for version in prepared.read_versions))
    ticket = prepared.handoff.selection_ticket
    input_refs = (ticket.ticket_id, ticket.candidate_set_id)
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(activity, None, f"attempt-{activity}",
                          "realize-recollection", f"operation-{activity}",
                          canonical_digest({"input_refs": list(input_refs)})),
        AuthorityContext("host", "d06", "candidate-capability", namespace,
                         ("activity",), "context", ("owner",), "policy-1", 1),
        VersionGuard(
            prepared.read_versions, (), 0, 0, "candidate-catalogue",
            scheme.scheme_version, scheme.operator_version, "policy-1", (),
            (VersionedRef("focus-lease", ticket.focus_epoch),), (),
        ),
        prepared.source_qualification, input_refs, "parent-budget", 100.0,
        100.0, "character-interval", ("ask-1",),
    )
    interpretation = CurrentInterpretationCandidate(
        f"interpretation-{activity}", activity, "question:waiting",
        "The speaker reported waiting", Stance.SUSPEND, 0.5,
        EvidenceStatus.INSUFFICIENT, (selected,), ("family-1",),
        ("The report is not direct observation",),
    )
    affect = AffectProvider(active_scheme=scheme)
    mood = MoodField("mood-1", "scheme-1", (("warmth", warmth),),
                     (selected,), "parameters-1", "coupling-1", 2.0)
    influence = affect.condition_recollection(
        memory_ref=selected, memory_source_refs=(selected,),
        base_salience_interval=(0.4, 0.6), base_tone_interval=(-0.1, 0.1),
        mood=mood, coupling=coupling,
    )
    recollection = prepared.reconstruction
    recollection_key = AtomKey(
        Owner("activity", *namespace.as_tuple, activity),
        "d06.recollection.v1", recollection.recollection_id,
    )
    affect_proposal = affect.propose_recollection_experience(
        envelope, experience_id=f"experience-{activity}",
        recollection_ref=recollection_key.token, influence=influence,
        mood=mood, coupling=coupling,
        source_versions=tuple(version for version in prepared.read_versions
                              if version.key == AtomKey.from_token(selected)),
        dependencies=DependencySet(),
    )
    affect.validate(affect_proposal, snapshot)
    owner = Owner("activity", *namespace.as_tuple, activity)
    settlement = AtomKey(owner, "d02.settlement.v1", f"settlement-{activity}")
    cost = AtomKey(owner, "runtime.cost_settlement", f"cost-{activity}")
    job = AtomKey(owner, "runtime.job", f"job-{activity}")
    outbox = AtomKey(owner, "runtime.outbox", f"outbox-{activity}")

    def external(domain, writes):
        return DomainProposal(domain, f"{domain}.proposal.v1",
                              schema_hash({"domain": domain, "proposal": 1}),
                              envelope, writes, DependencySet(), (), ())

    bundle = assemble_prepared_mandatory_recollection_bundle(
        prepared=prepared, snapshot=snapshot, envelope=envelope,
        adapter=pipeline.adapter, cognition=D07DomainProvider(),
        interpretation=interpretation, affect_proposal=affect_proposal,
        resource_proposal=external("d02", (GraphWrite(settlement, {}),)),
        runtime_proposal=external("d11", (
            GraphWrite(cost, {}), GraphWrite(job, {}), GraphWrite(outbox, {}),
        )),
        d02_settlement_ref=settlement.token,
        d11_cost_settlement_ref=cost.token,
        persistent_job_ref=job.token, outbox_ref=outbox.token,
    )
    return bundle, envelope, interpretation, affect_proposal, snapshot


def test_two_internal_recollection_bundles_keep_one_external_event(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        bundles = []
        for warmth, activity in ((0.8, "activity-warm"), (-0.8, "activity-guarded")):
            _mood(store, scope, mood_key, warmth, f"mood-{activity}")
            interpretation_ref = AtomKey(
                Owner("activity", *namespace.as_tuple, activity),
                "d07.current_interpretation.v1", f"interpretation-{activity}",
            )
            experience_ref = AtomKey(
                Owner("activity", *namespace.as_tuple, activity),
                "d04.recollection_experience.v1", f"experience-{activity}",
            )
            prepared = _prepare(
                store, pipeline, namespace, scheme, coupling, mood_key, trace,
                activity, context=RecollectionContext(
                    (interpretation_ref.token,), (experience_ref.token,), (),
                ),
            )
            bundle, *_ = _bundle_candidate(
                store, pipeline, namespace, scheme, coupling, mood_key,
                prepared, warmth,
            )
            writes = tuple(write for proposal in bundle.proposals
                           for write in proposal.typed_writes)
            assert not any(write.key.type_name == "d03.world_event" for write in writes)
            assert any(write.key.type_name == "d06.recollection_projection.v1"
                       for write in writes)
            bundles.append((prepared, bundle, writes))
        assert bundles[0][0].event_ref == bundles[1][0].event_ref
        assert bundles[0][0].episode_ref == bundles[1][0].episode_ref
        assert bundles[0][0].reconstruction.source_ref == bundles[1][0].reconstruction.source_ref
        assert bundles[0][0].reconstruction.subjective_tone != bundles[1][0].reconstruction.subjective_tone
        assert bundles[0][2][0].key.owner.subject != bundles[1][2][0].key.owner.subject
    finally:
        store.close()


@pytest.mark.parametrize("change", ("correction", "withdrawal"))
def test_prepared_bundle_is_blocked_when_source_head_changes(tmp_path, change):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        activity = "activity-stale"
        _mood(store, scope, mood_key, 0.8, "mood-before-change")
        owner = Owner("activity", *namespace.as_tuple, activity)
        prepared = _prepare(
            store, pipeline, namespace, scheme, coupling, mood_key, trace,
            activity, context=RecollectionContext((
                AtomKey(owner, "d07.current_interpretation.v1",
                        f"interpretation-{activity}").token,
            ), (
                AtomKey(owner, "d04.recollection_experience.v1",
                        f"experience-{activity}").token,
            ), ()),
        )
        if change == "correction":
            key = source_correction_head_key(namespace, "source-1")
            value = {
                "source_ref": source_key(*namespace.as_tuple, "source-1").token,
                "source_revision": 1,
                "correction_source_ref": source_key(*namespace.as_tuple, "correction-1").token,
                "target_refs": [AtomKey(Owner("event", *namespace.as_tuple, "source-1"),
                                        "memory.interpretation", "current").token],
                "operation_id": "correction-1", "state": "pending_reevaluation",
                "access_epoch": 0, "deletion_epoch": 0,
            }
        else:
            key = access_key(*namespace.as_tuple, "source-1")
            value = {**store.graph_snapshot((key,)).get(key).value,
                     "status": "withdrawn"}
        before = store.graph_snapshot((key,))
        store.graph_commit(GraphCandidate(
            Event(scope, f"change-{change}", 4, change, {}), before.versions,
            (GraphWrite(key, value),), before.epochs,
        ))
        with pytest.raises(ValueError, match="snapshot differs"):
            _bundle_candidate(store, pipeline, namespace, scheme, coupling,
                              mood_key, prepared, 0.8)
    finally:
        store.close()


def test_current_correction_head_rejects_old_recall_candidate(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        _mood(store, scope, mood_key, 0.8, "warm-mood")
        _prepare(store, pipeline, namespace, scheme, coupling,
                 mood_key, trace, "activity-before")
        head = source_correction_head_key(namespace, "source-1")
        before = store.graph_snapshot((head,))
        store.graph_commit(GraphCandidate(
            Event(scope, "correction-head", 4, "correction", {}), before.versions,
            (GraphWrite(head, {
                "source_ref": source_key(*namespace.as_tuple, "source-1").token,
                "source_revision": 1,
                "correction_source_ref": source_key(*namespace.as_tuple, "correction-1").token,
                "target_refs": [AtomKey(Owner("event", *namespace.as_tuple, "source-1"),
                                        "memory.interpretation", "current").token],
                "operation_id": "correction-1", "state": "pending_reevaluation",
                "access_epoch": 0, "deletion_epoch": 0,
            }),), before.epochs,
        ))
        with pytest.raises(ValueError, match="source correction requires"):
            _prepare(store, pipeline, namespace, scheme, coupling,
                     mood_key, trace, "activity-after")
    finally:
        store.close()


def test_withdrawn_access_cannot_enter_bounded_selection(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(tmp_path)
    try:
        _mood(store, scope, mood_key, 0.8, "warm-mood")
        _prepare(store, pipeline, namespace, scheme, coupling,
                 mood_key, trace, "activity-before")
        access = access_key(*namespace.as_tuple, "source-1")
        before = store.graph_snapshot((access,))
        store.graph_commit(GraphCandidate(
            Event(scope, "withdraw-access", 4, "withdraw", {}), before.versions,
            (GraphWrite(access, {**before.get(access).value, "status": "withdrawn"}),),
            before.epochs,
        ))
        with pytest.raises(ValueError, match="no qualified source fragment"):
            _prepare(store, pipeline, namespace, scheme, coupling,
                     mood_key, trace, "activity-after")
    finally:
        store.close()


def test_private_baseline_source_cannot_enter_recollection(tmp_path):
    store, scope, pipeline, namespace, scheme, coupling, mood_key, trace = _fixture(
        tmp_path, private_baseline_source=True,
    )
    try:
        _mood(store, scope, mood_key, 0.8, "warm-mood")
        with pytest.raises(PermissionError, match="outside the C03 proof"):
            _prepare(store, pipeline, namespace, scheme, coupling,
                     mood_key, trace, "activity-private")
    finally:
        store.close()
