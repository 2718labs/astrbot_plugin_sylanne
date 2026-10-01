"""A write fence sees a complete Authority-owned effect set at its pinned head."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, canonical_digest, from_wire, to_wire,
)

from test_execution_binding_v2_claim import (
    AUTH_NS, _binding_v2, _digest, _prepared, _service,
)


def _write_fence(core, fences, *, operation_id="write-a"):
    with core._tx() as db:
        anchor = core._anchor(db, AUTH_NS, core._row(db, AUTH_NS))
    return fences.begin_fence(
        subject="subject-a", holder="holder-a", operation="write",
        current_anchor=anchor, operation_id=operation_id)


def test_empty_current_snapshot_is_bound_to_live_write_permit(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    permit = _write_fence(core, fences)
    snapshot = bridge.read_current_effect_snapshot_for_write_fence(
        credential="ok", subject="subject-a", permit=permit)
    assert type(snapshot) is AuthorityCurrentEffectSnapshotV2
    assert snapshot.coverage == "complete"
    assert snapshot.unresolved_effects == ()
    assert snapshot.anchor == permit.pinned_anchor
    assert snapshot.permit_digest == canonical_digest(permit)
    assert (snapshot.execution_head_seq, snapshot.execution_head_digest) == (
        permit.pinned_anchor.execution_seq, permit.pinned_anchor.execution_digest)
    assert from_wire(to_wire(snapshot)) == snapshot
    with pytest.raises(AuthorityUnavailable):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="bad", subject="subject-a", permit=permit)
    with pytest.raises(AuthorityUnavailable, match="ordinary write"):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="other-subject", permit=permit)
    with pytest.raises(AuthorityUnavailable, match="active v2 fence"):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="subject-a",
            permit=replace(permit, revision=1))
    core.close()
    journal.close()


def test_snapshot_covers_other_unresolved_effect_and_rejects_stale_head(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, _ = _prepared(core, fences, bridge)
    with core._tx() as db:
        dispatch_permit = fences._permit(fences._row(db, "operation-a"))
    fences.finish_fence(
        dispatch_permit, subject="subject-a",
        current_anchor=prepared.after_anchor,
        request_id="finish-dispatch-a", request_digest=_digest("e"))
    permit = _write_fence(core, fences)
    snapshot = bridge.read_current_effect_snapshot_for_write_fence(
        credential="ok", subject="subject-a", permit=permit)
    assert len(snapshot.unresolved_effects) == 1
    effect = snapshot.unresolved_effects[0]
    assert (effect.effect_id, effect.phase, effect.execution_seq) == (
        "effect-a", "prepared", 1)
    assert effect.footprint.effect_id == "effect-a"
    with core._tx() as db:
        db.execute("DELETE FROM authority_effects WHERE namespace=? AND effect_id=?",
                   (AUTH_NS, "effect-a"))
    with pytest.raises(AuthorityUnavailable, match="execution effect is absent"):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="subject-a", permit=permit)
    core.close()
    journal.close()


def test_snapshot_rejects_fence_at_previous_anchor(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    permit = _write_fence(core, fences)
    with core._tx() as db:
        db.execute("UPDATE authority_namespaces SET anchor_nonce=? WHERE namespace=?",
                   ("changed-nonce", AUTH_NS))
    with pytest.raises(AuthorityUnavailable, match="pinned anchor is stale"):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="subject-a", permit=permit)
    core.close()
    journal.close()


def test_snapshot_rejects_effect_append_from_other_authority_incarnation(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, _ = _prepared(core, fences, bridge)
    with core._tx() as db:
        dispatch_permit = fences._permit(fences._row(db, "operation-a"))
    fences.finish_fence(
        dispatch_permit, subject="subject-a",
        current_anchor=prepared.after_anchor,
        request_id="finish-dispatch-a", request_digest=_digest("e"))
    # Simulate an incorrectly paired Authority metadata restore. The
    # independent execution append and its effect index remain internally valid,
    # but their originating Authority identity is no longer current.
    with core._tx() as db:
        db.execute("UPDATE authority_meta SET value=? WHERE key='authority_id'",
                   ("other-authority-incarnation",))
    permit = _write_fence(core, fences)
    with pytest.raises(AuthorityUnavailable, match="Authority identity"):
        bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="subject-a", permit=permit)
    core.close()
    journal.close()


def test_newer_independent_claim_remains_in_complete_snapshot(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, origin = _prepared(core, fences, bridge)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=_binding_v2(origin))
    with core._tx() as db:
        dispatch_permit = fences._permit(fences._row(db, "operation-a"))
    fences.finish_fence(
        dispatch_permit, subject="subject-a",
        current_anchor=claimed.after_anchor,
        request_id="finish-dispatch-a", request_digest=_digest("e"))
    permit = _write_fence(core, fences)
    snapshot = bridge.read_current_effect_snapshot_for_write_fence(
        credential="ok", subject="subject-a", permit=permit)
    assert snapshot.coverage == "complete"
    assert (snapshot.execution_head_seq, snapshot.execution_head_digest) == (
        claimed.after_anchor.execution_seq,
        claimed.after_anchor.execution_digest)
    assert len(snapshot.unresolved_effects) == 1
    effect = snapshot.unresolved_effects[0]
    assert (effect.effect_id, effect.phase, effect.mutation_id) == (
        "effect-a", "claimed", claimed.pending.mutation_id)
    core.close()
    journal.close()
