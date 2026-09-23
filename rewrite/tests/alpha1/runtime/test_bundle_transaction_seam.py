"""The coordinator can join a caller-owned write transaction for v2 ingress."""

from unittest.mock import patch

import pytest

from sylanne3.graph_coordinator import UnavailableGuard

from test_c04_atomic_real_issuers import C04Harness
import test_ingress_issuance as ingress_fixture


def test_bundle_joins_transaction_and_rollback_covers_graph_and_ledgers(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        bundle = harness.bundle()
        store = harness.store
        db = store._db
        store._coordinator_capability = harness.coordinator._GraphCoordinator__graph_capability
        with pytest.raises(RuntimeError, match="store lock and active transaction"):
            harness.coordinator._commit_domain_bundle_fenced(
                bundle, harness.lease, in_transaction=True)
        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            try:
                # Issuer admission must use the supplied trusted UTC throughout.
                with patch("sylanne3.runtime.issuers.time.time",
                           side_effect=AssertionError("host clock was read")):
                    receipt = harness.coordinator._commit_domain_bundle_fenced(
                        bundle, harness.lease, in_transaction=True,
                        now_utc=4_102_444_700.0)
                assert receipt.status == "committed"
                assert db.in_transaction
                assert db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0] == 2
                assert db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone()[0] == 1
                assert db.execute("SELECT COUNT(*) FROM graph_outbox_jobs").fetchone()[0] == 1
                assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone()[0] == 1
            finally:
                db.execute("ROLLBACK")
        assert db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM graph_outbox_jobs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone()[0] == 0
        # The harness installed one source event before the candidate bundle.
        assert db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0] == 1
    finally:
        harness.close()


def test_sealed_ingress_checks_deadline_twice_and_leaves_rollback_to_caller():
    fixture = ingress_fixture.IngressIssuanceTests("test_public_issuance_contract_exists")
    fixture.setUp()
    try:
        authorization = fixture.coordinator.issue_ingress_authorization(
            fixture.bootstrap, fixture.request, fixture.session)
        bundle = fixture.bundle_for(authorization)
        store = fixture.store
        db = store._db
        store._coordinator_capability = fixture.coordinator._GraphCoordinator__graph_capability
        db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + fixture.namespace.as_tuple
            + (fixture.request.operation_id,),
        )
        # The v2 caller supplies its own trusted upper-bound check.
        fixture.coordinator._GraphCoordinator__ingress_clock = None
        checked = []

        def deadline_check(deadline_utc):
            checked.append(deadline_utc)
            if len(checked) == 2:
                raise UnavailableGuard("trusted upper bound passed deadline")

        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(UnavailableGuard, match="trusted upper bound"):
                    fixture.coordinator._commit_domain_bundle_fenced(
                        bundle, authorization.lease, in_transaction=True,
                        now_utc=fixture.clock.wall_now_utc,
                        ingress_deadline_check=deadline_check)
                assert db.in_transaction
                assert checked == [bundle.envelope.deadline_utc] * 2
            finally:
                db.execute("ROLLBACK")
        assert db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0] == 0
    finally:
        fixture.tearDown()


def test_deadline_callback_cannot_bypass_unsealed_four_key_ingress():
    fixture = ingress_fixture.IngressIssuanceTests("test_public_issuance_contract_exists")
    fixture.setUp()
    try:
        authorization = fixture.coordinator.issue_ingress_authorization(
            fixture.bootstrap, fixture.request, fixture.session)
        bundle = fixture.bundle_for(authorization)
        store = fixture.store
        store._coordinator_capability = fixture.coordinator._GraphCoordinator__graph_capability
        checked = []
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(UnavailableGuard, match="query epoch"):
                    fixture.coordinator._commit_domain_bundle_fenced(
                        bundle, authorization.lease, in_transaction=True,
                        ingress_deadline_check=checked.append)
            finally:
                store._db.execute("ROLLBACK")
        assert checked == []
    finally:
        fixture.tearDown()
