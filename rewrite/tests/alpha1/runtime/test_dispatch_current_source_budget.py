"""A durable D11 admission still needs current source and budget state."""

import time

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime.dispatch_current_source_budget import (
    CurrentDispatchHold, read_current_source_budget,
)

from test_dispatch_admission import _issuer_case


def _admitted(tmp_path):
    store, coordinator, authority, lease, bundle, _issuer = _issuer_case(
        tmp_path, with_projection=True)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    coordinator._commit_domain_bundle_fenced(bundle, lease, dispatch_clock_reading=reading)
    return store, authority.namespace


def test_current_source_and_reservation_can_be_read_under_write_transaction(tmp_path):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            with pytest.raises(CurrentDispatchHold, match="held business transaction"):
                read_current_source_budget(
                    store._db, namespace, "admission:one", now_utc=time.time())
            store._db.execute("BEGIN IMMEDIATE")
            try:
                current = read_current_source_budget(
                    store._db, namespace, "admission:one", now_utc=time.time())
                assert current.admission_ref == "admission:one"
                assert current.source_proof_digest
                assert current.budget_reservation_digest
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()


@pytest.mark.parametrize("change", (
    "revoke_access", "change_access_row", "release_budget", "expire",
))
def test_current_source_budget_gate_holds_on_revocation_reservation_or_expiry(
        tmp_path, change):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                if change == "revoke_access":
                    store._db.execute(
                        "INSERT INTO graph_authority_epochs"
                        "(bot,persona,access_epoch,delete_epoch) VALUES(?,?,1,0) "
                        "ON CONFLICT(bot,persona) DO UPDATE SET access_epoch=1",
                        namespace.as_tuple,
                    )
                elif change == "change_access_row":
                    store._db.execute(
                        "UPDATE graph_atoms SET value=replace(value,'\"active\"',"
                        "'\"withdrawn\"') WHERE type_name='memory.access'",
                    )
                elif change == "release_budget":
                    store._db.execute(
                        "UPDATE runtime_budget_reservations SET state='settled' "
                        "WHERE lease_id='parent'",
                    )
                now = 4102444800.0 if change == "expire" else time.time()
                with pytest.raises(CurrentDispatchHold):
                    read_current_source_budget(
                        store._db, namespace, "admission:one", now_utc=now)
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()
