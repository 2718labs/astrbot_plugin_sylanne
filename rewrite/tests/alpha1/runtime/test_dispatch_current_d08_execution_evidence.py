"""D08 effect and cancellation observations cannot authorize final handoff."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.contracts import canonical_json
from sylanne3.domains.d08.execution import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from sylanne3.runtime.dispatch_current_commitments import (
    read_current_d08_action_conflict_evidence,
)
from sylanne3.runtime.jobs import PersistentJob, cancel_job, create_job, install_schema
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import OperationIdentity, VersionedRef, canonical_digest

from test_dispatch_current_commitments import _case


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
