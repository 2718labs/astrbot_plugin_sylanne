"""A current source page can become a paid C04 commit through W01."""

from dataclasses import replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectCoupling
from sylanne3.domains.d06 import CandidateItem, CandidateSet, RecollectionContext, SelectionTicket
from sylanne3.domains.d06.current_c04_bundle import (
    assemble_current_c04_bundle_v1, current_c04_projection_key_v1,
)
from sylanne3.domains.d06.current_memory_evidence import project_current_memory_evidence_page_v1
from sylanne3.domains.d06.current_recollection_bridge import prepare_current_c04_source_candidate_v1
from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.budget import get_budget_lease, predict_budget_settlement
from sylanne3.runtime.current_memory_read_v1 import read_current_memory_evidence_page_v1

from test_c04_atomic_real_issuers import C04Harness


def _current_candidate(harness, *, suffix="c04", mood_value=0.8, mood_revision=1):
    namespace = harness.namespace
    source = source_key(*namespace.as_tuple, "source-1")
    mood_key = AtomKey(Owner("persona", *namespace.as_tuple), "d04.mood_field.v1", "current")
    prior = harness.store.graph_snapshot((mood_key, source))
    harness.store.graph_commit(GraphCandidate(
        Event(Scope(*namespace.as_tuple, "session"), f"mood-{mood_revision}",
              1.0 + mood_revision, "mood", {}),
        prior.versions,
        (GraphWrite(mood_key, {
            "mood_id": "mood-current", "basis_version": "scheme-1",
            "coordinates": [["care", mood_value]], "source_refs": [source.token],
            "parameter_version": "parameter-1", "coupling_version": "coupling-1",
            "cursor": 1.0 + mood_revision, "revision": mood_revision,
        }, (source,)),), prior.epochs,
    ))
    original = harness.bundle(suffix)
    d07 = next(item for item in original.proposals if item.domain == "d07")
    feeling = next(item for item in original.proposals if item.domain == "d04")
    interpretation_ref = next(write.key.token for write in d07.typed_writes
                              if write.key.type_name == "d07.current_interpretation.v1")
    context = RecollectionContext((interpretation_ref,),
                                  (feeling.typed_writes[0].key.token,), ())
    candidates = CandidateSet(
        f"set-{suffix}", (CandidateItem("candidate-1", "source-1", "family-1",
                                  "association", ("context",), 0.8, "observed"),),
        "complete", access_epoch=0, delete_epoch=0,
    )
    choice = next(write for write in d07.typed_writes
                  if write.key.type_name == "d07.selection_ticket.v1")
    ticket = SelectionTicket(
        choice.value["ticket_id"], choice.value["activity_id"],
        choice.value["candidate_set_id"],
        tuple(choice.value["selected_candidate_ids"]), choice.value["focus_epoch"],
    )
    epoch = harness.store.graph_epoch(*namespace.as_tuple)
    with harness.store._lock:
        harness.store._db.execute(
            "INSERT OR IGNORE INTO graph_authority_epochs"
            "(bot,persona,access_epoch,delete_epoch) VALUES(?,?,0,0)",
            namespace.as_tuple,
        )
        harness.store._db.execute("BEGIN")
        try:
            page, closure, coverage = read_current_memory_evidence_page_v1(
                harness.store._db, namespace, audience="owner", purpose="context",
                graph_epoch=epoch, access_epoch=0, delete_epoch=0,
            )
            evidence = project_current_memory_evidence_page_v1(
                page, closure, namespace=namespace, graph_epoch=epoch,
                access_epoch=0, deletion_epoch=0, audience="owner",
                purpose="context", query_coverage=coverage,
            )
            harness.store._db.execute("COMMIT")
        except BaseException:
            harness.store._db.execute("ROLLBACK")
            raise
    scheme = harness.providers["d04"]._active_scheme
    coupling = AffectCoupling("recall", "coupling-1", "care", "care", 0.0, 0.5, 0.5)
    candidate = prepare_current_c04_source_candidate_v1(
        evidence, namespace=namespace, ticket=ticket, candidates=candidates,
        context=context, mood_snapshot=harness.store.graph_snapshot((mood_key,)),
        mood_key=mood_key, scheme=scheme, coupling=coupling,
        source_qualification=original.envelope.source_qualification,
        base_salience=(0.3, 0.4), base_tone=(-0.1, 0.0),
    )
    old = original.envelope
    projection_key = current_c04_projection_key_v1(
        candidate, experience_id=f"feeling-{suffix}",
    )
    projection_absence = harness.store.graph_snapshot((projection_key,)).versions
    reads = tuple(dict.fromkeys((
        *old.version_guard.read_versions, *candidate.read_versions, *projection_absence,
    )))
    envelope = replace(old, version_guard=replace(
        old.version_guard, read_versions=reads,
        query_epochs=(*old.version_guard.query_epochs, candidate.query_epoch),
    ))
    support = {item.domain: replace(item, envelope=envelope)
               for item in original.proposals if item.domain in {"d07", "d02", "d11"}}
    d11 = support["d11"]
    with harness.store._lock:
        lease = get_budget_lease(harness.store._db, "parent")
    ceiling = {"cpu_ms": 200, "model_microusd": 300}
    digest = budget_operation_digest(envelope, "parent", ceiling)
    prediction = predict_budget_settlement(
        lease, envelope.identity.operation_id, digest, ceiling, ceiling,
        inline_reserve=True,
    )
    cost = d11.typed_writes[0]
    support["d11"] = replace(d11, typed_writes=(
        replace(cost, value={**cost.value,
                             "budget_receipt_digest": prediction.receipt_json_sha256}),
        *d11.typed_writes[1:],
    ))
    return candidate, envelope, ticket, candidates, scheme, coupling, mood_key, support, original


def test_current_source_builds_paid_atomic_c04_candidate(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        (candidate, envelope, ticket, candidates, scheme, coupling,
         mood_key, support, original) = _current_candidate(harness)
        kwargs = dict(
            envelope=envelope, ticket=ticket, candidates=candidates,
            mood_snapshot=harness.store.graph_snapshot((mood_key,)), mood_key=mood_key,
            scheme=scheme, coupling=coupling,
            affect_provider=harness.providers["d04"], experience_id="feeling-c04",
            supporting_proposals=(support["d07"], support["d02"], support["d11"]),
            choice_ref=original.choice_refs[0],
            d02_settlement_ref=original.d02_settlement_refs[0],
            d11_cost_settlement_ref=original.d11_cost_settlement_refs[0],
            persistent_job_ref=original.persistent_job_refs[0],
            outbox_ref=original.outbox_refs[0],
        )
        bundle = assemble_current_c04_bundle_v1(candidate, **kwargs)
        assert {item.domain for item in bundle.proposals} == {"d02", "d04", "d06", "d07", "d11"}
        assert len(next(item for item in bundle.proposals if item.domain == "d06").typed_writes) == 2
        assert harness.store.graph_snapshot((
            next(item for item in bundle.proposals if item.domain == "d06").typed_writes[0].key,
        )).atoms[0].revision == 0
        first = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        retry = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        assert (first.status, retry.status) == ("committed", "duplicate")
        assert get_budget_lease(harness.store._db, "parent").used == {
            "cpu_ms": 200, "model_microusd": 300,
        }
        with pytest.raises(ValueError, match="read closure"):
            assemble_current_c04_bundle_v1(
                candidate, **{**kwargs, "envelope": replace(
                    envelope, version_guard=replace(
                        envelope.version_guard,
                        read_versions=tuple(version for version in envelope.version_guard.read_versions
                                            if version.key != mood_key),
                    ),
                )},
            )
    finally:
        harness.close()


def test_same_persisted_source_two_moods_commit_two_paid_activities_once_each(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        feelings = []
        projections = []
        source_ref = source_key(*harness.namespace.as_tuple, "source-1").token
        for suffix, mood_value, mood_revision in (
            ("warm", 0.8, 1), ("guarded", -0.8, 2),
        ):
            (candidate, envelope, ticket, candidates, scheme, coupling,
             mood_key, support, original) = _current_candidate(
                harness, suffix=suffix, mood_value=mood_value,
                mood_revision=mood_revision,
            )
            bundle = assemble_current_c04_bundle_v1(
                candidate,
                envelope=envelope, ticket=ticket, candidates=candidates,
                mood_snapshot=harness.store.graph_snapshot((mood_key,)),
                mood_key=mood_key, scheme=scheme, coupling=coupling,
                affect_provider=harness.providers["d04"],
                experience_id=f"feeling-{suffix}",
                supporting_proposals=(support["d07"], support["d02"], support["d11"]),
                choice_ref=original.choice_refs[0],
                d02_settlement_ref=original.d02_settlement_refs[0],
                d11_cost_settlement_ref=original.d11_cost_settlement_refs[0],
                persistent_job_ref=original.persistent_job_refs[0],
                outbox_ref=original.outbox_refs[0],
            )
            assert harness.coordinator.commit_domain_bundle(bundle, harness.lease).status == "committed"
            assert harness.coordinator.commit_domain_bundle(bundle, harness.lease).status == "duplicate"
            d04 = next(item for item in bundle.proposals if item.domain == "d04")
            d06 = next(item for item in bundle.proposals if item.domain == "d06")
            feelings.append(d04.typed_writes[0].value)
            projections.append(d06.typed_writes[1].value)
            assert d06.typed_writes[0].value["content_refs"] == ["source-1"]
            assert d04.typed_writes[0].value["memory_source_refs"] == [source_ref]
            assert d04.typed_writes[0].value["evidence_weight_delta"] == 0.0
            assert harness.store._db.execute(
                "SELECT COUNT(*) FROM graph_atoms WHERE type_name='memory.source'"
            ).fetchone()[0] == 1
        assert feelings[0]["tone_interval"] != feelings[1]["tone_interval"]
        assert projections[0]["subjective_tone"] != projections[1]["subjective_tone"]
        assert projections[0]["source_ref"] == projections[1]["source_ref"] == source_ref
        assert harness.store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations"
        ).fetchone()[0] == 2
        assert harness.store._db.execute(
            "SELECT COUNT(*) FROM runtime_resource_outcomes"
        ).fetchone()[0] == 2
        assert harness.store._db.execute(
            "SELECT COUNT(*) FROM runtime_budget_operations WHERE phase='settle'"
        ).fetchone()[0] == 2
        assert get_budget_lease(harness.store._db, "parent").used == {
            "cpu_ms": 400, "model_microusd": 600,
        }
    finally:
        harness.close()
