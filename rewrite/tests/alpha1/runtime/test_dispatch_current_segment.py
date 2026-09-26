"""Current D09 graph segment evidence cannot authorize a live platform route."""

import json
import time

import pytest

from sylanne3.runtime.dispatch_current_segment import read_current_dispatch_segment
from sylanne3.runtime.dispatch_current_source_budget import CurrentDispatchHold
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2

from test_dispatch_admission import _issuer_case


def _admitted(tmp_path):
    store, coordinator, authority, lease, bundle, _issuer = _issuer_case(
        tmp_path, with_projection=True, astrbot_route=True,
    )
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading,
    )
    return store, authority.namespace


def test_current_segment_binds_original_command_batch_and_route_but_holds_host(tmp_path):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            with pytest.raises(CurrentDispatchHold, match="held graph transaction"):
                read_current_dispatch_segment(
                    db, namespace, "admission:one", now_utc=time.time(),
                )
            db.execute("BEGIN IMMEDIATE")
            try:
                result = read_current_dispatch_segment(
                    db, namespace, "admission:one", now_utc=time.time(),
                )
                assert result.status == "hold"
                assert result.missing_sources == ("current_host_route_and_scene",)
                assert result.operation_id == "operation:one"
                assert result.effect_id == "effect:one"
                assert result.batch_ref and result.batch_digest
                assert result.payload_digest and result.route_digest
                assert not hasattr(result, "body")
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()


@pytest.mark.parametrize("change", (
    "current_batch", "batch_revision", "payload", "route", "event", "expired",
))
def test_current_segment_holds_if_current_or_original_identity_moves(tmp_path, change):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if change == "current_batch":
                    db.execute(
                        "UPDATE graph_atoms SET valid=0 WHERE type_name="
                        "'d09.verified_segment_batch.v1' AND bot=? AND persona=?",
                        namespace.as_tuple,
                    )
                elif change == "batch_revision":
                    db.execute(
                        "UPDATE graph_atoms SET revision=revision+1 WHERE type_name="
                        "'d09.verified_segment_batch.v1' AND bot=? AND persona=?",
                        namespace.as_tuple,
                    )
                elif change == "payload":
                    db.execute(
                        "UPDATE graph_atoms SET value=replace(value,'Hello','Hallo') "
                        "WHERE type_name='d09.verified_segment_batch.v1' "
                        "AND bot=? AND persona=?", namespace.as_tuple,
                    )
                elif change == "route":
                    row = db.execute(
                        "SELECT admission_json FROM graph_dispatch_admissions "
                        "WHERE bot=? AND persona=? AND admission_ref='admission:one'",
                        namespace.as_tuple,
                    ).fetchone()
                    data = json.loads(row[0])
                    data["account_ref"] = '["wrong","aiocqhttp","account"]'
                    db.execute(
                        "UPDATE graph_dispatch_admissions SET admission_json=? "
                        "WHERE bot=? AND persona=? AND admission_ref='admission:one'",
                        (json.dumps(data, sort_keys=True, separators=(",", ":")),
                         *namespace.as_tuple),
                    )
                elif change == "event":
                    db.execute(
                        "DELETE FROM graph_events WHERE bot=? AND persona=? "
                        "AND event_id='operation:one'", namespace.as_tuple,
                    )
                now_utc = 4102444800.0 if change == "expired" else time.time()
                with pytest.raises((CurrentDispatchHold, ValueError)):
                    read_current_dispatch_segment(
                        db, namespace, "admission:one", now_utc=now_utc,
                    )
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()
