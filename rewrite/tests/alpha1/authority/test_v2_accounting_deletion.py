"""A verified deletion history must not turn accounting into a content permit."""

from dataclasses import asdict, replace

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_accounting_contract import AccountingMaintenanceRequestV1
from sylanne3.authority_service.v2_accounting_service import AuthorityV2AccountingMaintenanceService
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.runtime_contracts import canonical_digest


def _observed_original(service, core):
    """Fixture seeds a trusted, already admitted and finished original call."""
    store = AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock)
    anchor = service.current_anchor(credential="ok", subject="accounting-observer")
    with service._frozen() as (db, deletion_head, execution_head, history):
        assert not history
        permit = service.fences.begin_fence_locked(
            db, subject="worker-a", holder="holder-a", operation="model_egress",
            current_anchor=anchor, operation_id="original-model-op")
        intent = model_intent(
            authority_id=anchor.authority_id, namespace="ns-a",
            subject="worker-a", operation_id=permit.operation_id,
            call_id="original-call", job_id="original-job",
            fence_token=permit.token, fence_epoch=permit.fence_epoch,
            fence_revision=permit.revision,
            anchor_digest=canonical_digest(asdict(anchor)),
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq)
        store.prepare_locked(db, intent)
        store.bind_fence_locked(db, intent)
        store._record_dispatch_started_fenced_locked(
            db, intent, permit, service.fences, anchor)
        admission = ModelAdmissionV2(
            "a" * 64, intent.authority_id, intent.namespace,
            intent.subject, intent.operation_id, intent.call_id,
            intent.request_digest, intent.provider_config_digest,
            "original-install", "b" * 64, "original-profile",
            "c" * 64, "d" * 64)
        store.record_admission_locked(db, intent, admission)
        observation = ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", "{}", (), (), None)
        store._record_observation_locked(db, observation)
        service.fences.finish_terminal_model_egress_locked(
            db, permit, intent=intent, current_anchor=anchor,
            status="completed")
        receipt = ModelTerminalReceiptV2(
            admission.admission_id, intent.call_id, intent.request_digest,
            "e" * 64, observation.digest,
            service.fences.model_terminal_finish_digest(
                intent, permit, "completed", observation.digest),
            admission.installation_id, admission.host_incarnation)
        store.record_terminal_receipt_locked(db, admission, receipt)
    return store, intent


def _sync_authority_to_journal(core, journal):
    """Test-only finalizer stand-in; production v2 deletion CAS is still HOLD."""
    head = journal.latest_head()
    with core._tx() as db:
        db.execute(
            "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
            "deletion_phase='clear',revocation_epoch=revocation_epoch+1,"
            "anchor_nonce=? WHERE namespace='ns-a'",
            (head.seq, head.chain_digest, core._new_nonce()))
        return core._anchor(db, "ns-a", core._row(db, "ns-a"))


def test_pending_history_cannot_issue_accounting_even_with_clear_authority_row(tmp_path):
    service, core, _, journal, guard, execution, _ = installed(tmp_path)
    try:
        store, intent = _observed_original(service, core)
        accounting = AuthorityV2AccountingMaintenanceService(
            store=store, fences=service,
            subject="accounting-observer", holder="holder-a")
        journal.append_intent(
            namespace="ns-a", operation_id="delete-original-source",
            closure_roots=("source-a",), epoch=1, policy_ref="policy-a")
        # Reproduce a dangerous split: Authority's head matches the independent
        # journal, but its phase row is erroneously clear. The journal is pending.
        pending_anchor = _sync_authority_to_journal(core, journal)
        request = AccountingMaintenanceRequestV1(
            "accounting-after-delete", intent, pending_anchor)
        with pytest.raises(AuthorityUnavailable, match="deletion.*pending"):
            accounting.begin(credential="ok", request=request)
        assert service.fences._row(core._db, request.operation_id) is None

        journal.advance("delete-original-source", "accepted",
                        business_barrier=lambda _: True)
        accepted_anchor = _sync_authority_to_journal(core, journal)
        with pytest.raises(AuthorityUnavailable, match="deletion.*accepted"):
            accounting.begin(
                credential="ok",
                request=replace(request, expected_anchor=accepted_anchor))
        assert service.fences._row(core._db, request.operation_id) is None
        journal.advance("delete-original-source", "closed",
                        cleanup_verifier=lambda _: True)
        closed_anchor = _sync_authority_to_journal(core, journal)
        with core._tx() as db:
            erased = store._erase_observation_content_locked(db, intent)
        assert erased.content_erased is True
        closed_request = replace(request, expected_anchor=closed_anchor)
        grant = accounting.begin(credential="ok", request=closed_request)
        assert grant.permit.operation == "accounting"
        accounting.finish(credential="ok", request=closed_request, grant=grant)
        for operation in ("read", "write"):
            with pytest.raises(AuthorityUnavailable, match="historical deletion"):
                service.begin_fence(
                    credential="ok", subject="accounting-observer",
                    holder="holder-a", operation=operation,
                    operation_id="ordinary-" + operation + "-after-delete",
                    expected_anchor=closed_anchor)
    finally:
        core.close()
        journal.close()
        guard.close()
        execution.close()
