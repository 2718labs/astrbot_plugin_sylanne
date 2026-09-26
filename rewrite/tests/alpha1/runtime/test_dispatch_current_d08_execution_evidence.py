"""D08 effect and cancellation observations cannot authorize final handoff."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.contracts import canonical_json
from sylanne3.domains.d08.execution import (
    ActionCancellationState, ActionIntent, GoalPredicate, RequiredCheckSpec,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner,
)
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.dispatch_current_commitments import (
    read_current_d08_action_conflict_evidence, read_current_job_cancellation,
)
from sylanne3.runtime.jobs import (
    PersistentJob, acquire_job, cancel_job, create_job, get_job, install_schema,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    OperationIdentity, QueryEpoch, VersionedRef, canonical_digest,
)

from test_dispatch_current_commitments import _case
from test_dispatch_action_job_binding import _case as _bound_case


def _evidence_case():
    db, namespace, snapshot, query = _case()
    install_schema(db)
    identity = OperationIdentity(
        "activity:one", "effect:one", "attempt:one", "prepare",
        "operation:one", canonical_digest("input"),
    )
    check = RequiredCheckSpec(
        "commitment_conflict", "d08.commitment_conflict", "persona:persona",
        "action:one", "expression", "criteria:one",
        (VersionedRef("criteria:one", 1),),
    )
    intent = ActionIntent(
        "action:one", 1, "goal:one", (), "entity:user", "message",
        "expression", "reversible", canonical_digest("params"), identity,
        "schema:one", (check,), GoalPredicate("communicated", "delivery", (), 0.0, None),
        ("message:entity:user",), None, ("source:one",),
    )
    atom = GraphAtom(
        AtomKey(Owner("activity", "bot", "persona", identity.activity_id),
                "d08.action_intent.v1", intent.action_id),
        1, json.loads(json.dumps(asdict(intent))),
    )
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        atom.key.token, "bot", "persona", atom.key.type_name,
        atom.revision, canonical_json(atom.value), 1,
    ))
    snapshot = GraphSnapshot(snapshot.atoms + (atom,), snapshot.epochs)
    anchor = RestoreAnchor(
        "authority:test", "bot/persona", 1, "deletion:test", 0, "genesis",
        "execution:test", 2, "sha256:" + "a" * 64, 0, "proof:test",
    )
    p2 = FencePermitV2(
        "authority:test", "bot/persona", "subject:test", "holder:test", 1,
        "dispatch", identity.operation_id, "A" * 43, 1, 3, anchor,
        identity.effect_id, "sha256:" + "b" * 64, "sha256:" + "c" * 64,
    )
    effect = CurrentEffectReadV2(
        "authority:test", "bot/persona", identity.effect_id, 1,
        "unresolved", 2, anchor.execution_digest, 2, "append:one",
        anchor.execution_digest, "mutation:one",
    )
    return db, namespace, snapshot, query, p2, effect


def _job(namespace):
    return PersistentJob(
        "job:one", "operation:one", "activity:one", "effect:one",
        *namespace.as_tuple, "snapshot:one", "queued", "dispatch", {}, None,
        "2030-01-01T00:00:00Z", "budget:one", "resource:one", {},
        None, None, 0, 0, {}, None,
    )


def _bound_evidence_case():
    db, namespace, intent, admission, _job_row, bind, _load = _bound_case()
    db.execute("CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("INSERT INTO graph_epochs VALUES('bot','persona',5)")
    db.commit()
    action_key = AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                         "d08.action_intent.v1", intent.action_id)
    atom = GraphAtom(action_key, intent.revision,
                     json.loads(json.dumps(asdict(intent))))
    snapshot = GraphSnapshot((atom,), (NamespaceEpoch("bot", "persona", 5),))
    query = QueryEpoch(namespace, "all", 5)
    anchor = RestoreAnchor(
        "authority:test", "bot/persona", 1, "deletion:test", 0, "genesis",
        "execution:test", 2, "sha256:" + "a" * 64, 0, "proof:test")
    p2 = FencePermitV2(
        "authority:test", "bot/persona", "subject:test", "holder:test", 1,
        "dispatch", intent.identity.operation_id, "A" * 43, 1, 3, anchor,
        intent.identity.effect_id, "sha256:" + "b" * 64,
        "sha256:" + "c" * 64)
    effect = CurrentEffectReadV2(
        "authority:test", "bot/persona", intent.identity.effect_id, 1,
        "unresolved", 2, anchor.execution_digest, 2, "append:one",
        anchor.execution_digest, "mutation:one")
    return db, namespace, intent, admission, bind, snapshot, query, p2, effect


def _advance_job_projection(db, namespace, job_id, revision):
    projected = job_graph_write(get_job(db, job_id))
    db.execute(
        "UPDATE graph_atoms SET revision=?,value=? WHERE token=? "
        "AND bot=? AND persona=?",
        (revision, canonical_json(projected.value), projected.key.token,
         *namespace.as_tuple),
    )


def _install_action_cancel_head(db, namespace, snapshot, intent, *, cancelled=False):
    db.executescript("""
        CREATE TABLE graph_events(bot TEXT,persona TEXT,session TEXT,event_id TEXT,
                                  reads TEXT,revisions TEXT,epoch_revision INTEGER);
        CREATE TABLE graph_history(token TEXT,revision INTEGER,value TEXT,valid INTEGER,
                                   event_bot TEXT,event_persona TEXT,event_session TEXT,
                                   event_id TEXT);
    """)
    action_key = snapshot.atoms[0].key
    key = AtomKey(action_key.owner, "d08.action_cancellation.v1", intent.action_id)
    initial = ActionCancellationState.for_action(
        intent, state="active", actor="host:user", source_refs=("source:one",),
        operation_id=intent.identity.operation_id,
    )
    values = [initial]
    if cancelled:
        values.append(replace(initial, state="cancelled", cancel_epoch=1,
                              operation_id="operation:cancel-action"))
    for revision, state in enumerate(values, 1):
        encoded = canonical_json(json.loads(json.dumps(asdict(state))))
        reads = canonical_json([[action_key.token, 0 if revision == 1 else intent.revision],
                                [key.token, revision - 1]])
        revisions = canonical_json(([[action_key.token, intent.revision]]
                                    if revision == 1 else [])
                                   + [[key.token, revision]])
        db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?)", (
            *namespace.as_tuple, intent.identity.activity_id, state.operation_id,
            reads, revisions, 5,
        ))
        db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?)", (
            key.token, revision, encoded, 1, *namespace.as_tuple,
            intent.identity.activity_id, state.operation_id,
        ))
    current = values[-1]
    atom = GraphAtom(key, len(values), json.loads(json.dumps(asdict(current))))
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        key.token, *namespace.as_tuple, key.type_name, atom.revision,
        canonical_json(atom.value), 1,
    ))
    return GraphSnapshot(snapshot.atoms + (atom,), snapshot.epochs)


def test_durable_action_job_binding_proves_local_link_but_keeps_authority_hold():
    db, namespace, intent, admission, bind, snapshot, query, p2, effect = (
        _bound_evidence_case())
    try:
        db.execute("BEGIN IMMEDIATE")
        binding = bind(db, intent, admission)
        current = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert current.action_job_binding_digest == binding.digest
        assert current.job_graph_version.revision == binding.job_graph_revision
        assert (current.job_id, current.job_fence, current.job_cancel_epoch) == (
            binding.job_id, 0, 0)
        assert current.job_cancellation_state == "clear"
        assert current.action_cancellation_state == "unknown"
        assert "action_attempt_to_job_binding" not in current.missing_sources
        assert "current_action_cancellation_read" in current.missing_sources
        assert "trusted_authority_effect_read_provenance" in current.missing_sources
        assert "authority_post_graph_p2_cas" in current.missing_sources

        acquired = acquire_job(
            db, binding.job_id, "worker:one", now_utc="2026-09-26T00:00:00Z",
            lease_seconds=60)
        assert acquired.fence == 1
        stale_projection = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert "current_bound_job_graph_mismatch" in stale_projection.missing_sources
        assert "action_attempt_to_job_binding" in stale_projection.missing_sources
        _advance_job_projection(db, namespace, binding.job_id, 2)
        running = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert running.job_fence == 1
        assert "action_attempt_to_job_binding" not in running.missing_sources
        assert "current_worker_lease_unverified" in running.missing_sources

        cancel_job(db, binding.job_id, "job-cancel:one", "b" * 64)
        _advance_job_projection(db, namespace, binding.job_id, 3)
        cancelled = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert cancelled.job_cancellation_state == "cancelled"
        assert cancelled.job_cancel_epoch == 1
        assert "matching_job_cancelled" in cancelled.missing_sources
        assert "action_attempt_to_job_binding" not in cancelled.missing_sources
    finally:
        db.close()


def test_stale_action_or_forged_binding_never_proves_current_link():
    db, namespace, intent, admission, bind, snapshot, query, p2, effect = (
        _bound_evidence_case())
    try:
        db.execute("BEGIN IMMEDIATE")
        binding = bind(db, intent, admission)
        db.execute("UPDATE graph_dispatch_action_job_bindings_v1 "
                   "SET binding_digest=? WHERE admission_ref=?",
                   ("0" * 64, admission.admission.admission_ref))
        with pytest.raises(ValueError, match="binding digest differs"):
            read_current_d08_action_conflict_evidence(
                db, namespace, snapshot, query, intent.action_id, p2, effect)
        db.execute("UPDATE graph_dispatch_action_job_bindings_v1 "
                   "SET binding_digest=? WHERE admission_ref=?",
                   (binding.digest, admission.admission.admission_ref))
        revised = replace(intent, revision=2)
        revised_atom = GraphAtom(snapshot.atoms[0].key, 2,
                                 json.loads(json.dumps(asdict(revised))))
        db.execute("UPDATE graph_atoms SET revision=2,value=? WHERE token=?",
                   (canonical_json(revised_atom.value), revised_atom.key.token))
        revised_snapshot = GraphSnapshot((revised_atom,), snapshot.epochs)
        stale_action = read_current_d08_action_conflict_evidence(
            db, namespace, revised_snapshot, query, intent.action_id, p2, effect)
        assert "current_action_job_binding_stale" in stale_action.missing_sources
        assert "action_attempt_to_job_binding" in stale_action.missing_sources
    finally:
        db.close()


@pytest.mark.parametrize("cancelled,expected", [
    (False, "clear"), (True, "cancelled"),
])
def test_action_cancellation_requires_current_head_and_admission_origin(cancelled, expected):
    db, namespace, intent, admission, bind, snapshot, query, p2, effect = (
        _bound_evidence_case())
    try:
        snapshot = _install_action_cancel_head(
            db, namespace, snapshot, intent, cancelled=cancelled)
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        bind(db, intent, admission)
        current = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert current.action_cancellation_state == expected
        assert current.action_cancellation_graph_version.revision == (2 if cancelled else 1)
        assert "current_action_cancellation_read" not in current.missing_sources
        assert ("matching_action_cancelled" in current.missing_sources) == cancelled
        assert current.status == "hold"
        assert "authority_post_graph_p2_cas" in current.missing_sources
    finally:
        db.close()


def test_action_cancellation_fails_closed_for_missing_origin_or_wrong_attempt():
    db, namespace, intent, admission, bind, snapshot, query, p2, effect = (
        _bound_evidence_case())
    try:
        snapshot = _install_action_cancel_head(db, namespace, snapshot, intent)
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        bind(db, intent, admission)
        key = snapshot.atoms[-1].key
        db.execute("UPDATE graph_history SET event_id='operation:other' WHERE token=?", (key.token,))
        missing = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, intent.action_id, p2, effect)
        assert missing.action_cancellation_state == "unknown"
        assert "current_action_cancellation_read" in missing.missing_sources
        db.execute("UPDATE graph_history SET event_id=? WHERE token=?",
                   (intent.identity.operation_id, key.token))
        wrong = replace(intent, identity=replace(intent.identity, attempt_id="attempt:later"))
        wrong_value = ActionCancellationState.for_action(
            wrong, state="active", actor="host:user", source_refs=("source:one",),
            operation_id=intent.identity.operation_id,
        )
        encoded = canonical_json(json.loads(json.dumps(asdict(wrong_value))))
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (encoded, key.token))
        db.execute("UPDATE graph_history SET value=? WHERE token=?", (encoded, key.token))
        wrong_atom = GraphAtom(key, 1, json.loads(encoded))
        wrong_snapshot = GraphSnapshot(snapshot.atoms[:-1] + (wrong_atom,), snapshot.epochs)
        mismatch = read_current_d08_action_conflict_evidence(
            db, namespace, wrong_snapshot, query, intent.action_id, p2, effect)
        assert mismatch.action_cancellation_state == "unknown"
        assert "action_cancellation_attempt_mismatch" in mismatch.missing_sources
    finally:
        db.close()


def test_exact_effect_and_job_cancellation_remain_partial():
    db, namespace, snapshot, query, p2, effect = _evidence_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        missing = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2, effect)
        assert (missing.effect_state, missing.job_cancellation_state,
                missing.action_cancellation_state, missing.status) == (
                    "unresolved", "unknown", "unknown", "hold")
        assert "unique_current_action_job_unproven" in missing.missing_sources

        create_job(db, _job(namespace), "job-create:one", "a" * 64)
        current = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2, effect)
        assert current.job_cancellation_state == "clear"
        assert current.job_cancel_epoch == 0
        assert current.action_cancellation_state == "unknown"
        assert "action_attempt_to_job_binding" in current.missing_sources
        assert "trusted_authority_effect_read_provenance" in current.missing_sources

        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id='job:one'")
        uncertain = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2, effect)
        assert uncertain.job_cancellation_state == "unknown"
        assert uncertain.job_cancel_epoch == 1

        cancel_job(db, "job:one", "job-cancel:one", "b" * 64)
        cancelled = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2, effect)
        assert cancelled.job_cancellation_state == "cancelled"
        assert "matching_job_cancelled" in cancelled.missing_sources
    finally:
        db.close()


def test_absent_and_stale_effects_never_clear_claimed_dispatch():
    db, namespace, snapshot, query, p2, effect = _evidence_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        absent = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2,
            replace(effect, state="absent", effect_seq=None, append_id=None,
                    append_digest=None, mutation_id=None))
        assert absent.effect_state == "clear"
        assert absent.status == "hold"
        assert "claimed_effect_absent" in absent.missing_sources

        stale = read_current_d08_action_conflict_evidence(
            db, namespace, snapshot, query, "action:one", p2,
            replace(effect, execution_head_seq=0))
        assert stale.effect_state == "unknown"
        assert "authority_effect_read_not_at_claimed_p2" in stale.missing_sources
        with pytest.raises(ValueError, match="action is absent"):
            read_current_d08_action_conflict_evidence(
                db, namespace, snapshot, query, "action:missing", p2, effect)
    finally:
        db.close()


def test_current_job_cancellation_requires_row_and_exact_command_epochs():
    db, namespace, _, _, _, _ = _evidence_case()
    try:
        with pytest.raises(ValueError, match="graph transaction"):
            read_current_job_cancellation(db, namespace, "job:one")
        db.execute("BEGIN IMMEDIATE")
        missing = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=0,
            expected_cancel_epoch=0)
        assert missing.state == "unknown"
        assert missing.missing_sources == ("current_job_missing",)

        create_job(db, _job(namespace), "job-create:one", "a" * 64)
        clear = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=0,
            expected_cancel_epoch=0)
        assert (clear.state, clear.fence_state, clear.cancel_epoch_state) == (
            "clear", "row_match", "row_match")
        assert (clear.phase, clear.fence, clear.cancel_epoch) == ("queued", 0, 0)

        stale = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=1,
            expected_cancel_epoch=0)
        assert stale.state == "unknown"
        assert stale.fence_state == "mismatch"
        assert "job_worker_fence_mismatch" in stale.missing_sources

        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id='job:one'")
        epoch_only = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=0,
            expected_cancel_epoch=1)
        assert epoch_only.state == "unknown"
        assert epoch_only.cancel_epoch_state == "row_match"

        cancel_job(db, "job:one", "job-cancel:one", "b" * 64)
        cancelled = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=0,
            expected_cancel_epoch=2)
        assert cancelled.state == "cancelled"
        assert cancelled.phase == "cancelled"
        assert cancelled.cancel_epoch == 2
        assert cancelled.latest_cancel_receipt_epoch == 2

        db.execute(
            "UPDATE runtime_jobs SET phase='queued',cancel_epoch=0 "
            "WHERE job_id='job:one'")
        contradicted = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=0,
            expected_cancel_epoch=0)
        assert contradicted.state == "unknown"
        assert "job_cancel_history_mismatch" in contradicted.missing_sources
    finally:
        db.close()


def test_draining_cancellation_advances_worker_fence():
    db, namespace, _, _, _, _ = _evidence_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        create_job(db, _job(namespace), "job-create:one", "a" * 64)
        running = acquire_job(
            db, "job:one", "worker:one", now_utc="2026-09-26T00:00:00Z",
            lease_seconds=60)
        assert running.fence == 1
        cancel_job(db, "job:one", "job-cancel:one", "b" * 64)
        current = read_current_job_cancellation(
            db, namespace, "job:one", expected_fence=1,
            expected_cancel_epoch=0)
        assert (current.state, current.phase, current.fence,
                current.cancel_epoch) == ("cancelled", "draining", 2, 1)
        assert current.fence_state == "mismatch"
        assert current.cancel_epoch_state == "mismatch"
        assert current.latest_cancel_receipt_epoch == 1
    finally:
        db.close()
