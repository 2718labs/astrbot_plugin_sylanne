"""W01/D11 can bind durable identities but must keep final send on HOLD."""

from dataclasses import replace
import hashlib
import time

import pytest

from sylanne3.authority_service.v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PendingMutationV2,
)
from sylanne3.runtime.dispatch_admission import load_request
from sylanne3.runtime.dispatch_current_source_budget import CurrentDispatchHold
from sylanne3.runtime.dispatch_final_claim import read_final_claim_prerequisite
from sylanne3.runtime.restore_anchor import RestoreAnchor

from test_dispatch_current_source_budget import _admitted


def _chain(db, namespace):
    receipt, request = load_request(db, namespace, "admission:one")
    admission = receipt.admission
    anchor = RestoreAnchor(
        "authority:test", request.namespace, request.activation_generation,
        "deletion:test", 0, "genesis", "execution:test", 0, "genesis", 0,
        "proof:test",
    )
    permit = FencePermitV2(
        "authority:test", request.namespace, "subject:test", "holder:test",
        request.activation_generation, "dispatch", request.operation_id,
        "A" * 43, 1, 1, anchor, request.effect_id,
        "sha256:" + request.command_digest,
        "sha256:" + hashlib.sha256(request.footprint._json().encode()).hexdigest(),
    )
    origin = ExecutionBindingV1(
        permit=permit, namespace=request.namespace,
        activity_id=request.activity_id, effect_id=request.effect_id,
        attempt_id=request.attempt_id, operation_id=request.operation_id,
        dispatch_generation=request.dispatch_generation,
        activation_generation=request.activation_generation,
        admission_ref=admission.admission_ref,
        verified_check_refs=request.required_check_refs,
        payload_digest="sha256:" + request.payload_digest,
        platform_capability_ref=request.platform_capability_ref,
        adapter_ref="adapter:test", account_ref=admission.account_ref,
        destination_ref=admission.destination_ref,
        worker_fence=request.worker_fence, content_fence=request.content_fence,
        cancel_epoch=request.cancel_epoch, footprint=request.footprint,
        proactive_contact=request.proactive_contact,
        segment_authorization_ref=request.segment_authorization_ref,
        segment_manifest_digest=(
            "sha256:" + request.segment_manifest_digest
            if request.segment_manifest_digest is not None else None
        ),
        segment_index=request.segment_index,
        segment_count=request.segment_count,
        contact_policy_check_ref=request.contact_policy_check_ref,
    )
    binding = ExecutionBindingV2(
        origin, admission.namespace, admission.graph_incarnation,
        "sha256:" + receipt.receipt_digest,
        receipt.graph_version, receipt.graph_epoch,
        admission.access_epoch, admission.delete_epoch,
        "sha256:" + admission.action_intent_digest,
        admission.action_intent_schema_version,
        "sha256:" + admission.action_schema_digest,
        admission.action_schema_version,
        "sha256:" + admission.required_checks_digest,
        admission.required_checks_schema_version,
        "sha256:" + admission.initial_check_evidence_digest,
        admission.utc_deadline, admission.clock_policy_ref,
        "sha256:" + admission.clock_policy_digest,
    )
    prepared = PendingMutationV2(
        permit, "prepare:test", "sha256:" + "a" * 64, "prepared", anchor,
        "append:prepared", "sha256:" + "b" * 64,
    )
    anchor1 = replace(anchor, execution_seq=1, execution_digest="sha256:" + "b" * 64)
    prepared_receipt = MutationReceiptV2(prepared, anchor1, 2, "committed")
    permit1 = replace(permit, revision=2, pinned_anchor=anchor1)
    claimed = PendingMutationV2(
        permit1, "claim:test", "sha256:" + "c" * 64, "claimed", anchor1,
        "append:claimed", "sha256:" + "d" * 64,
        prepared_receipt=prepared_receipt, binding=binding,
    )
    anchor2 = replace(anchor1, execution_seq=2, execution_digest="sha256:" + "d" * 64)
    return binding, MutationReceiptV2(claimed, anchor2, 3, "committed")


def test_durable_prerequisite_is_explicit_hold_and_stable_on_replay(tmp_path):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                first = read_final_claim_prerequisite(
                    db, namespace, binding, claimed, "handoff:one",
                    now_utc=time.time(),
                )
                second = read_final_claim_prerequisite(
                    db, namespace, binding, claimed, "handoff:one",
                    now_utc=time.time(),
                )
                assert first == second
                assert first.status == "hold"
                assert "current_d08_execution_effect_and_cancellation" in first.missing_guards
                assert first.binding_digest.startswith("sha256:")
                altered_binding = replace(
                    binding, action_intent_digest="sha256:" + "0" * 64,
                )
                altered_claim = replace(
                    claimed, pending=replace(
                        claimed.pending, binding=altered_binding,
                    ),
                )
                with pytest.raises(CurrentDispatchHold, match="binding differs"):
                    read_final_claim_prerequisite(
                        db, namespace, altered_binding, altered_claim,
                        "handoff:one", now_utc=time.time(),
                    )
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()


def test_prerequisite_rejects_missing_transaction_and_moved_access(tmp_path):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
            finally:
                db.execute("ROLLBACK")
            with pytest.raises(CurrentDispatchHold, match="held business transaction"):
                read_final_claim_prerequisite(
                    db, namespace, binding, claimed, "handoff:one",
                    now_utc=time.time(),
                )
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO graph_authority_epochs"
                    "(bot,persona,access_epoch,delete_epoch) VALUES(?,?,1,0) "
                    "ON CONFLICT(bot,persona) DO UPDATE SET access_epoch=1",
                    namespace.as_tuple,
                )
                with pytest.raises(CurrentDispatchHold, match="epoch moved"):
                    read_final_claim_prerequisite(
                        db, namespace, binding, claimed, "handoff:one",
                        now_utc=time.time(),
                    )
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()
