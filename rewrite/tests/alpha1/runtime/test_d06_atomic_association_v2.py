"""Real GraphStore rows for D06's W01 transaction reader."""

from dataclasses import asdict, replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.current_association_candidates import CurrentAssociationBudgetV1
from sylanne3.domains.d06.current_c04_association_preflight import (
    CurrentC04AssemblyOriginalsV1, preflight_current_c04_association_v1,
)
from sylanne3.domains.d07 import AttentionTicket, FocusState, attention_ticket_key
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphSnapshot, GraphWrite, Owner
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, association_key, source_key
from sylanne3.runtime.d06_atomic_association_v2 import read_atomic_association_v2

from test_c04_atomic_real_issuers import C04Harness
from test_current_c04_bundle_v1 import _current_candidate


def _setup(tmp_path):
    harness = C04Harness(tmp_path)
    namespace = harness.namespace
    scope = Scope(*namespace.as_tuple, "session")
    repository = MemoryRepository(harness.store, *namespace.as_tuple)
    cue = source_key(*namespace.as_tuple, "source-1")
    target = source_key(*namespace.as_tuple, "source-2")
    repository.ingest(
        Event(scope, "second-ingress", 1.5, "ingress", {}),
        SourceRecord("source-2", "another evening", "alice", "observed",
                     "confirmed", 1.5, 2.5, "family-2", ("owner",), ("context",)),
    )
    edge = association_key(*namespace.as_tuple, "source-1", "related")
    attention = AttentionTicket(
        "attention-current", "question:past", None, cue.token,
        "interaction", 0.8, 0.7, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
        1, 100.0, True, True, (), (cue.token,),
    )
    attention_key = attention_ticket_key(namespace, attention.ticket_id)
    focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d07.focus.v1", namespace.persona_id)
    focus = FocusState(namespace.persona_id, 4, attention_key.token, (), "chosen")
    before = harness.store.graph_snapshot((edge, attention_key, focus_key))
    harness.store.graph_commit(GraphCandidate(
        Event(scope, "link-and-focus", 3.0, "association", {}), before.versions,
        (GraphWrite(edge, {
            "association_id": "related", "source_ref": cue.token,
            "target_ref": target.token, "kind": "subjective_meaning",
            "weight": 0.8, "context_tags": ["evening"],
            "basis_source_refs": [cue.token], "content_reality": "subjective",
        }), GraphWrite(attention_key, {
            **asdict(attention), "schema": "d07.attention_ticket.v1",
            "cancel_refs": [], "source_refs": [cue.token],
        }), GraphWrite(focus_key, {
            **asdict(focus), "schema": "d07.focus.v1",
            "auxiliary_ticket_refs": [],
        })), before.epochs,
    ))
    original = _current_candidate(harness, suffix="atomic", mood_value=0.8,
                                  mood_revision=1)
    keys = (attention_key, focus_key, cue,
            access_key(*namespace.as_tuple, "source-1"),
            source_correction_head_key(namespace, "source-1"))
    return harness, repository, scope, original, harness.store.graph_snapshot(keys), target


def test_current_traversal_and_c04_preflight_share_one_write_transaction(tmp_path):
    harness, repository, scope, original, focus_snapshot, target = _setup(tmp_path)
    candidate, envelope, ticket, candidates, scheme, coupling, mood_key, support, bundle = original
    body_snapshot = harness.store.graph_snapshot(tuple(
        version.key for version in envelope.version_guard.read_versions
        if version.key.type_name in {"d02.body_state.v1", "d02.reservation.v1"}))
    try:
        with harness.store._lock:
            db = harness.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                result = read_atomic_association_v2(
                    db, candidate, ticket=ticket, focus_snapshot=focus_snapshot,
                    namespace=harness.namespace, now=5.0, audience="owner",
                    purpose="context", budget=CurrentAssociationBudgetV1(max_edges=1),
                    context_tags=("evening",),
                )
                assert tuple(item.source_ref for item in result.associations.candidates) == (target.token,)
                assert result.associations.candidates[0].evidence_eligibility == "subjective_association_only"
                assert result.current_snapshot.get(
                    source_correction_head_key(harness.namespace, "source-2")
                ).revision == 0
                reads = tuple({v.key: v for v in (
                    *envelope.version_guard.read_versions,
                    *result.current_snapshot.versions,
                )}.values())
                envelope = replace(envelope, version_guard=replace(
                    envelope.version_guard, read_versions=reads))
                originals = CurrentC04AssemblyOriginalsV1(
                    mood_key, scheme, coupling, harness.providers["d04"],
                    "feeling-atomic", tuple(replace(support[domain], envelope=envelope)
                                            for domain in ("d07", "d02", "d11")),
                    bundle.choice_refs[0], bundle.d02_settlement_refs[0],
                    bundle.d11_cost_settlement_refs[0],
                    bundle.persistent_job_refs[0], bundle.outbox_refs[0],
                )
                preflight = preflight_current_c04_association_v1(
                    candidate, ticket=ticket, candidates=candidates,
                    associations=result.associations,
                    current_snapshot=GraphSnapshot(
                        (*result.current_snapshot.atoms, *body_snapshot.atoms),
                        result.current_snapshot.epochs),
                    namespace=harness.namespace, envelope=envelope,
                    originals=originals, now=5.0, audience="owner", purpose="context",
                )
                assert preflight.association_candidates == result.associations
            finally:
                db.execute("ROLLBACK")
    finally:
        harness.close()


def test_revoked_target_is_excluded_and_stale_candidate_is_rejected(tmp_path):
    harness, repository, scope, original, focus_snapshot, target = _setup(tmp_path)
    candidate, _, ticket, *_ = original
    try:
        repository.set_access(
            Event(scope, "withdraw-target", 7.0, "withdraw", {}), "source-2",
            audiences=("owner",), purposes=("context",),
            status="withdrawn", recorded_at=7.0,
        )
        current = _current_candidate(harness, suffix="after-withdrawal",
                                     mood_value=-0.8, mood_revision=2)
        current_candidate, _, current_ticket, *_ = current
        current_focus = harness.store.graph_snapshot(tuple(
            atom.key for atom in focus_snapshot.atoms))
        with harness.store._lock:
            db = harness.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(ValueError, match="barrier changed"):
                    read_atomic_association_v2(
                        db, candidate, ticket=ticket, focus_snapshot=focus_snapshot,
                        namespace=harness.namespace, now=8.0, audience="owner",
                        purpose="context", budget=CurrentAssociationBudgetV1(),
                    )
                result = read_atomic_association_v2(
                    db, current_candidate, ticket=current_ticket,
                    focus_snapshot=current_focus, namespace=harness.namespace,
                    now=8.0, audience="owner", purpose="context",
                    budget=CurrentAssociationBudgetV1(),
                )
                assert result.associations.candidates == ()
                assert result.associations.edge_refs == ()
            finally:
                db.execute("ROLLBACK")
    finally:
        harness.close()
