"""Internal B2.2 prepared path; no RPC or production service qualification."""

from dataclasses import replace
import hashlib
import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_contract import (
    ExecutionBindingV1, canonical_bytes, decode_bytes,
)
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
    ReservationConstraint,
)


def setup_service(tmp_path, *, create=True):
    deletion_journal = DeletionJournal(tmp_path / "deletion.db", create=create)
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    deletion_head = deletion_journal.latest_head()
    deletion_anchor = JournalHead(deletion_head.journal_id, deletion_head.seq,
                                  deletion_head.chain_digest)
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=create)
    calls = []
    refs = {}

    def dispatch_verifier(namespace, effect_id, keys):
        assert not refs["core"]._db.in_transaction
        assert journal._guard_owner is None
        calls.append((namespace, effect_id, keys))
        return True

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=create,
        authorizer=lambda credential, action, namespace, holder: credential == "ok",
        deletion_verifier=lambda ns, previous, current, phase:
            current == deletion_anchor and phase == "clear",
        execution_verifier=lambda ns, previous, current, phase:
            journal.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=dispatch_verifier,
    )
    refs["core"] = core
    if create:
        core.register_namespace("ok", "ns-a", "holder-a",
                                deletion_anchor,
                                JournalHead("execution-a", 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    bridge = AuthorityV2ExecutionBridge(core=core, fences=fences,
                                        journal=journal, namespace="ns-a",
                                        deletion=deletion)
    bridge._test_deletion_journal = deletion_journal
    return core, fences, journal, bridge, calls


def footprint():
    return RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",),
    )


def rich_footprint():
    return RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        external_idempotency_ref="idem-a", external_query_ref="query-a",
        conflict_keys=("resource-a",), communication_action="send",
        contact_id="contact-a", segment_id="segment-a",
        object_gate_keys=("gate-a",),
        quota_occupancies=(QuotaOccupancy("quota-a", "window-a", 2),),
        reservations=(ReservationConstraint("reserve-a", "component-a", "4"),),
        budgets=(BudgetConstraint("budget-a", "2", "1", "5"),),
    )


def begin(core, fences, item):
    anchor = authority_anchor(core)
    digest = "sha256:" + hashlib.sha256(item._json().encode()).hexdigest()
    return fences.begin_fence(
        subject="subject-a", holder="holder-a", operation="dispatch",
        current_anchor=anchor, operation_id="operation-a",
        effect_id="effect-a", command_digest="sha256:" + "a" * 64,
        footprint_digest=digest,
    )


def authority_anchor(core):
    with core._tx() as db:
        return core._anchor(db, "ns-a", core._row(db, "ns-a"))


def execution_binding(permit, item, **changes):
    fields = dict(
        permit=permit, namespace="ns-a", activity_id=item.activity_id,
        effect_id=item.effect_id, attempt_id="attempt-a",
        operation_id=permit.operation_id, dispatch_generation=1,
        activation_generation=permit.generation, admission_ref="admission-a",
        verified_check_refs=("check-a",), payload_digest="sha256:" + "b" * 64,
        platform_capability_ref="capability-a", adapter_ref="adapter-a",
        account_ref="account-a", destination_ref="destination-a",
        worker_fence=1, content_fence="content-a", cancel_epoch=0,
        footprint=item,
    )
    fields.update(changes)
    return ExecutionBindingV1(**fields)


def test_claim_advances_same_operation_and_replays_after_restart(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    prepared, prepared_permit = bridge.execution_prepare(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    binding = execution_binding(permit, item)
    claimed, claimed_permit = bridge.execution_claim(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding)
    assert claimed.pending.phase == "claimed"
    assert claimed.pending.prepared_receipt == prepared
    assert claimed.pending.binding == binding
    assert claimed.pending.permit == prepared_permit
    assert claimed.durable_state == "committed"
    assert claimed_permit.operation_id == permit.operation_id
    assert claimed_permit.revision == 2
    assert claimed_permit.pinned_anchor == authority_anchor(core)
    assert journal.verified_head().seq == 2
    assert core._db.execute(
        "SELECT state,execution_seq FROM authority_effects WHERE namespace=? AND effect_id=?",
        ("ns-a", "effect-a")).fetchone() == ("unresolved", 2)
    core.close()
    journal.close()

    core, fences, journal, bridge, _ = setup_service(tmp_path, create=False)
    assert bridge.execution_claim(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding) == (claimed, claimed_permit)
    with pytest.raises(AuthorityUnavailable):
        bridge.execution_claim(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=execution_binding(permit, item, attempt_id="attempt-b"))
    with pytest.raises(AuthorityUnavailable):
        bridge.execution_claim(
            credential="ok", subject="subject-b", prepared_receipt=prepared,
            binding=binding)
    assert journal.verified_head().seq == 2
    core.close()
    journal.close()


def test_claim_pending_recovers_one_append_without_platform_handoff(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    prepared, _ = bridge.execution_prepare(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    binding = execution_binding(permit, item)
    pending = bridge.prepare_claim_pending(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding)
    assert decode_bytes(canonical_bytes(pending)) == pending
    assert journal.verified_head().seq == 1
    assert fences.get_operation("operation-a", subject="subject-a", namespace="ns-a")[2] == pending
    with pytest.raises(AuthorityUnavailable, match="claimed pending requires"):
        bridge.reconcile_mutation(
            credential="ok", subject="subject-a", pending=pending,
            allow_cancel=True)
    with pytest.raises(AuthorityUnavailable):
        bridge.prepare_claim_pending(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=execution_binding(permit, item, attempt_id="attempt-b"))
    assert journal.verified_head().seq == 1
    bridge.append_pending(pending, credential="ok", subject="subject-a")
    core.close()
    journal.close()

    core, fences, journal, bridge, _ = setup_service(tmp_path, create=False)
    claimed, updated = bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending)
    assert claimed.durable_state == "committed"
    assert updated.revision == 2 and journal.verified_head().seq == 2
    assert bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending) == (claimed, updated)
    core.close()
    journal.close()


def test_prepared_commit_updates_head_effect_fence_and_receipt(tmp_path):
    core, fences, journal, bridge, calls = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    receipt, updated = bridge.execution_prepare(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    assert receipt.durable_state == "committed"
    assert receipt.updated_revision == 1
    assert updated.revision == 1 and updated.pinned_anchor == receipt.after_anchor
    assert journal.verified_head().seq == receipt.after_anchor.execution_seq == 1
    assert authority_anchor(core) == receipt.after_anchor
    assert core._db.execute("SELECT state,execution_seq FROM authority_effects WHERE effect_id='effect-a'").fetchone() == ("unresolved", 1)
    assert fences.get_operation("operation-a", subject="subject-a", namespace="ns-a") == (updated, "active", None)
    with pytest.raises(AuthorityUnavailable):
        fences.validate_fence(permit, subject="subject-a",
                              current_anchor=receipt.after_anchor)
    assert fences.validate_fence(updated, subject="subject-a",
                                  current_anchor=receipt.after_anchor) == updated
    assert len(calls) == 1
    core.close()
    journal.close()


def test_locked_observation_tracks_prepare_without_platform_claim(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    before = bridge.observe_prepared(credential="ok", subject="subject-a",
                                     pending=pending)
    assert before.append is None and before.result is None
    bridge.append_pending(pending, credential="ok", subject="subject-a")
    appended = bridge.observe_prepared(credential="ok", subject="subject-a",
                                       pending=pending)
    assert appended.append is not None and appended.result is None
    assert appended.append.mutation_id == pending.mutation_id
    receipt, updated = bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending)
    committed = bridge.observe_prepared(credential="ok", subject="subject-a",
                                        pending=pending)
    assert committed.append == appended.append
    assert committed.result == (receipt, updated)
    assert bridge.observe_prepared(credential="ok", subject="subject-a",
                                   pending=pending) == committed
    core.close()
    journal.close()


def test_locked_observation_rejects_authority_effect_drift(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    receipt, _ = bridge.execution_prepare(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    core._db.execute("UPDATE authority_effects SET conflict_keys_json='[]' "
                     "WHERE namespace='ns-a' AND effect_id='effect-a'")
    with pytest.raises(AuthorityUnavailable, match="Authority effect"):
        bridge.observe_prepared(credential="ok", subject="subject-a",
                                pending=receipt.pending)
    core.close()
    journal.close()


def test_deletion_head_drift_blocks_append_and_keeps_pending(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    bridge._test_deletion_journal.append_intent(
        namespace="ns-a", operation_id="delete-a", closure_roots=("item-a",),
        epoch=1, policy_ref="policy-a")
    with pytest.raises(AuthorityUnavailable, match="historical deletion closure"):
        bridge.append_pending(pending, credential="ok", subject="subject-a")
    with pytest.raises(AuthorityUnavailable, match="historical deletion closure"):
        bridge.reconcile_mutation(credential="ok", subject="subject-a",
                                  pending=pending, allow_cancel=True)
    with pytest.raises(AuthorityUnavailable, match="historical deletion closure"):
        bridge.observe_prepared(credential="ok", subject="subject-a",
                                pending=pending)
    assert journal.verified_head().seq == 0
    assert fences.get_operation("operation-a", subject="subject-a",
                                namespace="ns-a")[2] == pending
    core.close()
    bridge._test_deletion_journal.close()
    bridge.deletion.close()
    journal.close()


def test_fsync_then_authority_commit_failure_recovers_after_reopen(tmp_path, monkeypatch):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    bridge.append_pending(pending, credential="ok", subject="subject-a")
    original = fences.finish_mutation_locked

    def fail_once(*args, **kwargs):
        monkeypatch.setattr(fences, "finish_mutation_locked", original)
        raise RuntimeError("injected authority commit failure")

    monkeypatch.setattr(fences, "finish_mutation_locked", fail_once)
    with pytest.raises(RuntimeError):
        bridge.reconcile_mutation(credential="ok", subject="subject-a",
                                  pending=pending)
    assert journal.verified_head().seq == 1
    assert core._db.execute("SELECT execution_seq FROM authority_namespaces WHERE namespace='ns-a'").fetchone() == (0,)
    assert fences.get_operation("operation-a", subject="subject-a", namespace="ns-a")[2] == pending
    core.close()
    journal.close()

    core, fences, journal, bridge, _ = setup_service(tmp_path, create=False)
    receipt, updated = bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending)
    assert receipt.durable_state == "committed"
    assert updated.revision == 1
    assert authority_anchor(core) == receipt.after_anchor
    core.close()
    journal.close()


def test_crash_after_authority_pending_before_append_retains_full_limits(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = rich_footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    assert journal.verified_head().seq == 0
    core.close()
    journal.close()

    core, fences, journal, bridge, _ = setup_service(tmp_path, create=False)
    assert fences.get_recovery_footprint(
        "mutation-a", subject="subject-a", namespace="ns-a") == item
    assert bridge.observe_prepared(
        credential="ok", subject="subject-a", pending=pending).append is None
    bridge.append_pending(pending, credential="ok", subject="subject-a")
    receipt, _ = bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending)
    assert receipt.durable_state == "committed"
    assert fences.get_recovery_footprint(
        "mutation-a", subject="subject-a", namespace="ns-a") == item
    core.close()
    journal.close()


def test_tampered_authority_footprint_blocks_append_recovery_and_observe(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = rich_footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=item)
    changed = replace(item, budgets=(BudgetConstraint("budget-a", "3", "1", "5"),))
    core._db.execute(
        "UPDATE authority_v2_mutations SET footprint=? WHERE mutation_id=?",
        (changed._json().encode(), pending.mutation_id))
    with pytest.raises(AuthorityUnavailable, match="footprint|mutation kind"):
        bridge.append_pending(pending, credential="ok", subject="subject-a")
    with pytest.raises(AuthorityUnavailable, match="footprint|mutation kind"):
        bridge.reconcile_mutation(
            credential="ok", subject="subject-a", pending=pending, allow_cancel=True)
    with pytest.raises(AuthorityUnavailable, match="footprint|mutation kind"):
        bridge.observe_prepared(
            credential="ok", subject="subject-a", pending=pending)
    assert journal.verified_head().seq == 0
    core.close()
    journal.close()


def test_zero_append_cancel_and_extra_append_quarantine(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    with pytest.raises(AuthorityUnavailable, match="no durable append"):
        bridge.reconcile_mutation(credential="ok", subject="subject-a",
                                  pending=pending)
    receipt, updated = bridge.reconcile_mutation(
        credential="ok", subject="subject-a", pending=pending,
        allow_cancel=True)
    assert receipt.durable_state == "cancelled_unappended"
    assert updated.revision == 1 and journal.verified_head().seq == 0
    cancelled = bridge.observe_prepared(credential="ok", subject="subject-a",
                                        pending=pending)
    assert cancelled.append is None and cancelled.result == (receipt, updated)
    with pytest.raises(AuthorityUnavailable):
        bridge.append_pending(pending, credential="ok", subject="subject-a")
    core.close()
    journal.close()

    core, fences, journal, bridge, _ = setup_service(tmp_path / "extra")
    item = footprint()
    permit = begin(core, fences, item)
    pending = bridge.prepare_pending(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    first = bridge.append_pending(pending, credential="ok", subject="subject-a")
    # Deliberately bypass Authority to emulate a second service writer fault.
    newer_anchor = replace(permit.pinned_anchor, execution_seq=1,
                           execution_digest=first.chain_digest, proof="proof-next")
    newer_permit = replace(permit, revision=1, pinned_anchor=newer_anchor)
    draft = replace(pending, permit=newer_permit, mutation_id="mutation-b",
                    request_digest="sha256:" + "b" * 64,
                    before_anchor=newer_anchor, expected_append_id="append-b",
                    expected_append_digest="sha256:" + "0" * 64)
    journal.append_once(replace(draft, expected_append_digest=
                                journal.expected_digest(draft)))
    with pytest.raises(AuthorityUnavailable, match="extra"):
        bridge.reconcile_mutation(credential="ok", subject="subject-a",
                                  pending=pending)
    with pytest.raises(AuthorityUnavailable, match="extra execution append"):
        bridge.observe_prepared(credential="ok", subject="subject-a",
                                pending=pending)
    assert fences.get_operation("operation-a", subject="subject-a", namespace="ns-a")[2] == pending
    assert core._db.execute("SELECT execution_seq FROM authority_namespaces WHERE namespace='ns-a'").fetchone() == (0,)
    core.close()
    journal.close()


def test_response_loss_same_id_retry_and_digest_subject_conflicts(tmp_path):
    core, fences, journal, bridge, calls = setup_service(tmp_path)
    item = footprint()
    permit = begin(core, fences, item)
    first = bridge.execution_prepare(credential="ok", subject="subject-a",
                                     permit=permit, mutation_id="mutation-a",
                                     footprint=item)
    assert bridge.execution_prepare(credential="ok", subject="subject-a",
                                    permit=permit, mutation_id="mutation-a",
                                    footprint=item) == first
    assert journal.verified_head().seq == 1
    with pytest.raises(AuthorityUnavailable):
        bridge.execution_prepare(credential="ok", subject="subject-b",
                                 permit=permit, mutation_id="mutation-a",
                                 footprint=item)
    changed = replace(item, conflict_keys=("resource-b",))
    with pytest.raises(AuthorityUnavailable):
        bridge.execution_prepare(credential="ok", subject="subject-a",
                                 permit=permit, mutation_id="mutation-a",
                                 footprint=changed)
    assert len(calls) == 1
    core.close()
    journal.close()


def test_active_read_fence_blocks_prepare_before_append(tmp_path):
    core, fences, journal, bridge, _ = setup_service(tmp_path)
    item = footprint()
    anchor = authority_anchor(core)
    fences.begin_fence(subject="reader", holder="holder-a", operation="read",
                       current_anchor=anchor, operation_id="reader-a")
    with pytest.raises(AuthorityUnavailable):
        begin(core, fences, item)
    assert journal.verified_head().seq == 0
    core.close()
    journal.close()
