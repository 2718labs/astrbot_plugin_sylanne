"""Real correction commits expose durable progress without resolving D06."""

import pytest

from test_source_correction_job_acquire_v2 import _ready
from sylanne3.graph_types import AtomKey
from sylanne3.runtime.source_correction_resolution import (
    SourceCorrectionResolutionHold,
    read_source_correction_durable_state_v1,
)


def test_pending_and_acquired_correction_are_still_hold(tmp_path):
    (store, authority_db, coordinator, namespace, receipt,
     job_id, acquire_id, authority, lease) = _ready(tmp_path)
    source_id = AtomKey.from_token(receipt.source_refs[0]).owner.subject
    try:
        db = store._db
        db.execute("BEGIN")
        state = read_source_correction_durable_state_v1(
            db, namespace, source_id)
        assert state.job_id == job_id
        assert state.job_phase == "queued"
        assert state.outbox_ledger_phase == "pending"
        assert state.outbox_graph_phase == "pending"
        assert state.d11_budget_state == "reserved"
        assert state.d11_actual_usage is None
        assert state.status == "HOLD"
        db.rollback()
        coordinator._acquire_source_correction_job_v1(
            authority, lease, job_id, acquire_id, lease_seconds=10)
        db.execute("BEGIN")
        acquired = read_source_correction_durable_state_v1(
            db, namespace, source_id)
        assert acquired.job_phase == "running"
        assert acquired.outbox_ledger_phase == "pending"
        assert acquired.status == "HOLD"
        db.rollback()
    finally:
        store.close()
        authority_db.close()


def test_stale_job_projection_cannot_be_reported_as_progress(tmp_path):
    (store, authority_db, _, namespace, receipt,
     *_) = _ready(tmp_path)
    source_id = AtomKey.from_token(receipt.source_refs[0]).owner.subject
    try:
        db = store._db
        db.execute("UPDATE graph_atoms SET value='{}' WHERE type_name='runtime.job' "
                   "AND bot=? AND persona=?", namespace.as_tuple)
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(SourceCorrectionResolutionHold, match="job projection"):
            read_source_correction_durable_state_v1(
                db, namespace, source_id)
        db.rollback()
    finally:
        store.close()
        authority_db.close()
