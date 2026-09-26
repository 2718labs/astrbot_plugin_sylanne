"""A real D06 source read and mood candidate feed the five-domain C04 commit."""

from dataclasses import replace

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectCoupling, MoodField
from sylanne3.domains.d06 import (
    D06DomainAdapter, RecallIntent, RecollectionContext, TriggerKind,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline, SearchPlan
from sylanne3.domains.d07 import CurrentInterpretationCandidate, EvidenceStatus, Stance
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner
from sylanne3.memory_reconstruction import DetailCue
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_retrieval import MemoryQuery
from sylanne3.memory_types import source_key
from sylanne3.runtime.budget import get_budget_lease, predict_budget_settlement
from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.runtime_contracts import canonical_digest

from test_c04_atomic_real_issuers import C04Harness


def _run_mood(tmp_path, warmth):
    tmp_path.mkdir()
    harness = C04Harness(tmp_path)
    try:
        source = source_key("bot", "persona", "source-1")
        mood_key = AtomKey(Owner("persona", "bot", "persona"),
                           "d04.mood_field.v1", "current")
        mood = MoodField("mood-c04", "scheme-1", (("care", warmth),),
                         (source.token,), "parameter-1", "coupling-1", 2.0)
        prior = harness.store.graph_snapshot((mood_key,))
        harness.store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "mood-ingress", 2.0,
                  "mood", {}), prior.versions,
            (GraphWrite(mood_key, {
                **mood.__dict__, "coordinates": [["care", warmth]],
                "source_refs": [source.token],
            }),), prior.epochs,
        ))
        mood_snapshot = harness.store.graph_snapshot((mood_key,))
        original = harness.bundle()
        old_envelope = original.envelope
        pipeline = D06MemoryPipeline(D06DomainAdapter(harness.namespace),
                                     MemoryRepository(harness.store, "bot", "persona"))
        qualification = pipeline.adapter.qualify_recall(RecallIntent(
            "ask", TriggerKind.EXPLICIT_PAST_REQUEST, "remember the evening",
        ))
        outcome = pipeline.retrieve_candidates(
            qualification, "set-c04",
            (SearchPlan("exact", MemoryQuery("source", ids=("source-1",)), 0.8),),
            audience="owner", purpose="context", access_epoch=0, delete_epoch=0,
        )
        selected = outcome.candidates.items[0]
        handoff = harness.providers["d07"].select_recollection(
            activity_id="activity-c04", focus_epoch=4, candidates=outcome.candidates,
            selected_candidate_ids=(selected.candidate_id,),
        )
        ticket = handoff.selection_ticket
        inputs = (ticket.ticket_id, outcome.candidates.candidate_set_id)
        new_recollection = pipeline.adapter.prepare_recollection(
            ticket, outcome.candidates, RecollectionContext((), (), ()),
        )
        owner = Owner("activity", "bot", "persona", ticket.activity_id)
        fresh_writes = harness.store.graph_snapshot((
            AtomKey(owner, "d07.selection_ticket.v1", ticket.ticket_id),
            AtomKey(owner, "d06.recollection.v1", new_recollection.recollection_id),
        )).versions
        mood_version = mood_snapshot.versions[0]
        envelope = replace(
            old_envelope,
            identity=replace(old_envelope.identity, canonical_input_digest=canonical_digest(
                {"input_refs": list(inputs)},
            )),
            input_refs=inputs,
            version_guard=replace(
                old_envelope.version_guard,
                read_versions=(*(
                    version for version in old_envelope.version_guard.read_versions
                    if version.key.type_name not in {
                        "d07.selection_ticket.v1", "d06.recollection.v1",
                    }
                ), *fresh_writes, mood_version),
            ),
        )
        interpretation = CurrentInterpretationCandidate(
            "meaning-c04", ticket.activity_id, "question:memory",
            "perhaps it matters now", Stance.SUSPEND, 0.4,
            EvidenceStatus.INSUFFICIENT, (source.token,), ("family-1",),
            ("present meaning is uncertain",),
        )
        support = {
            "d07": harness.providers["d07"].recollection_support_proposal(
                envelope, handoff, interpretation, source_dependencies=(source,),
            ),
            **{proposal.domain: replace(proposal, envelope=envelope)
               for proposal in original.proposals if proposal.domain in {"d02", "d11"}},
        }
        d11 = support["d11"]
        cost = d11.typed_writes[0]
        outbox = d11.typed_writes[2]
        ceiling = {"cpu_ms": 200, "model_microusd": 300}
        with harness.store._lock:
            durable_lease = get_budget_lease(harness.store._db, "parent")
        digest = budget_operation_digest(envelope, "parent", ceiling)
        prediction = predict_budget_settlement(
            durable_lease, envelope.identity.operation_id, digest,
            ceiling, ceiling, inline_reserve=True,
        )
        support["d11"] = replace(d11, typed_writes=(
            replace(cost, value={**cost.value,
                                 "budget_receipt_digest": prediction.receipt_json_sha256}),
            d11.typed_writes[1],
            replace(outbox, value={**outbox.value,
                                   "payload_ref": new_recollection.recollection_id}),
        ))
        interpretation_ref = next(
            write.key.token for write in support["d07"].typed_writes
            if write.key.type_name == "d07.current_interpretation.v1"
        )
        feeling_ref = AtomKey(
            Owner("activity", "bot", "persona", ticket.activity_id),
            "d04.recollection_experience.v1", "feeling-c04",
        ).token
        context = RecollectionContext((interpretation_ref,), (feeling_ref,), ())
        coupling = AffectCoupling("recall-c04", "coupling-1", "care", "care",
                                  0.0, 0.5, 0.5)
        base_salience = (0.3, 0.4)
        base_tone = (-0.1, 0.0)
        reconstruction = pipeline.prepare_affective_recollection(
            outcome, ticket, context, audience="owner", purpose="context",
            mood_snapshot=mood_snapshot, mood_key=mood_key,
            scheme=harness.providers["d04"]._active_scheme, coupling=coupling,
            source_qualification=envelope.source_qualification,
            base_salience=base_salience, base_tone=base_tone,
            detail_cues=(DetailCue("shared", (0, 6), 0.65),),
        )
        bundle = pipeline.assemble_affective_recollection_bundle(
            envelope, outcome, ticket, reconstruction,
            mood_snapshot=mood_snapshot, mood_key=mood_key,
            scheme=harness.providers["d04"]._active_scheme, coupling=coupling,
            base_salience=base_salience, base_tone=base_tone,
            affect_provider=harness.providers["d04"], experience_id="feeling-c04",
            supporting_proposals=(support["d07"], support["d02"], support["d11"]),
            choice_ref=next(write.key.token for write in support["d07"].typed_writes
                            if write.key.type_name == "d07.selection_ticket.v1"),
            d02_settlement_ref=original.d02_settlement_refs[0],
            d11_cost_settlement_ref=original.d11_cost_settlement_refs[0],
            persistent_job_ref=original.persistent_job_refs[0],
            outbox_ref=original.outbox_refs[0],
        )
        first = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        retry = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        d04_write = next(proposal.typed_writes[0] for proposal in bundle.proposals
                         if proposal.domain == "d04")
        stored = harness.store.graph_snapshot((d04_write.key,)).get(d04_write.key)
        return {
            "source_fields": reconstruction.source_fields,
            "detail": reconstruction.subjective_details[0],
            "source_status": selected.provenance_eligibility,
            "reconstruction": reconstruction,
            "experience": stored.value,
            "domains": {proposal.domain for proposal in bundle.proposals},
            "first": first.status,
            "retry": retry.status,
            "operation_count": harness.store._db.execute(
                "SELECT COUNT(*) FROM graph_bundle_operations"
            ).fetchone()[0],
            "budget_used": get_budget_lease(harness.store._db, "parent").used,
        }
    finally:
        harness.close()


def test_real_selected_source_and_mood_join_commit_without_evidence_inflation(tmp_path):
    warm = _run_mood(tmp_path / "warm", 0.8)
    guarded = _run_mood(tmp_path / "guarded", -0.8)
    assert warm["source_fields"] == guarded["source_fields"]
    assert warm["source_fields"][0].literal_text == "shared"
    assert warm["source_fields"][0].assertion_status == "confirmed"
    assert warm["source_status"] == guarded["source_status"] == "observed"
    assert warm["detail"].state == "retrieved"
    assert guarded["detail"].state == "blurred"
    assert warm["experience"]["tone_interval"] != guarded["experience"]["tone_interval"]
    for result in (warm, guarded):
        assert result["domains"] == {"d02", "d04", "d06", "d07", "d11"}
        assert result["experience"]["memory_source_refs"] == [result["reconstruction"].source_ref]
        assert result["experience"]["evidence_weight_delta"] == 0.0
        assert result["experience"]["salience_interval"] == list(
            result["reconstruction"].subjective_weight
        )
        assert result["first"] == "committed"
        assert result["retry"] == "duplicate"
        assert result["operation_count"] == 1
        assert result["budget_used"] == {"cpu_ms": 200, "model_microusd": 300}
