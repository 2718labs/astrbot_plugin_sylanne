"""The graph selector rereads one durable pending barrier, not caller evidence.

This is a storage/transport contract fixture; Owner issuance is controlled here.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_deletion_graph_read import (
    AuthorityV2DeletionGraphReadService,
)
from sylanne3.authority_service.v2_deletion_recovery_service import (
    AuthorityV2DeletionPendingRecovery,
)
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore

from test_current_erasure_service import _close_ledger, _open_ledger, _phase


def test_pending_graph_read_uses_live_updated_delete_permit_and_durable_head(
        tmp_path, monkeypatch):
    parts = _open_ledger(tmp_path, create=True)
    try:
        core, fences, _, deletion, execution = parts
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        owner = AuthorityV2OwnerTicketStore(core, create=True)
        monkeypatch.setattr(owner, "current_migration_head_in_tx", lambda *_args, **_kwargs:
            SimpleNamespace(state="active", issue_operation=SimpleNamespace(
                installation_id="installation")))
        reader = AuthorityV2DeletionGraphReadService(
            fence_service=service, owner_tickets=owner)
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        old_permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="fence-a", expected_anchor=anchor)
        pending = _phase(parts, old_permit, "absent", "pending", ordinal=1)
        with core._tx() as db:
            fences.record_deletion_pending_locked(
                db, pending, subject="subject-a", current_anchor=anchor)
        deletion.append_pending(pending, core=core, fences=fences)
        receipt = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a").recover(
                credential="ok", subject="subject-a", mutation_id=pending.mutation_id)
        assert receipt is not None
        live_permit = replace(
            old_permit, revision=receipt.updated_revision,
            pinned_anchor=receipt.after_anchor)
        read = lambda permit=live_permit, installation_id="installation", operation="deletion-a": (
            reader.get_pending_deletion_for_graph_write(
                credential="ok", subject="subject-a", installation_id=installation_id,
                deletion_operation_id=operation, permit=permit))
        assert read() == receipt
        with pytest.raises(AuthorityUnavailable):
            read(permit=old_permit)
        with pytest.raises(AuthorityUnavailable):
            read(operation="another-deletion")
        with pytest.raises(AuthorityUnavailable):
            read(installation_id="another-installation")
        with pytest.raises(AuthorityUnavailable):
            reader.get_pending_deletion_for_graph_write(
                credential="ok", subject="another-subject",
                installation_id="installation",
                deletion_operation_id="deletion-a", permit=live_permit)
        monkeypatch.setattr(owner, "current_migration_head_in_tx", lambda *_args, **_kwargs:
            SimpleNamespace(state="revoked", issue_operation=SimpleNamespace(
                installation_id="installation")))
        with pytest.raises(AuthorityUnavailable):
            read()
    finally:
        _close_ledger(parts)
