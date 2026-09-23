import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import (
    BudgetConflict,
    BudgetLease,
    BudgetUnavailable,
    close_budget_lease,
    create_budget_lease,
    get_budget_lease,
    reserve_budget,
    resolve_unconfirmed,
    settle_budget,
)
from sylanne3.runtime.clock import (
    CharacterClockMapping,
    PersistentDeadline,
    get_deadline,
    get_clock_mapping,
    issue_clock_mapping,
    put_deadline,
    rebuild_deadline,
)
from sylanne3.runtime.jobs import (
    JobConflict,
    JobFenceRejected,
    JobNotRunnable,
    PersistentJob,
    acquire_job,
    cancel_job,
    checkpoint_job,
    create_job,
    get_job,
    transition_job,
    wake_job,
)


UTC = timezone.utc


class RuntimeBudgetJobsClockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "business.db"
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        install_runtime_schema(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def reopen(self):
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row

    @staticmethod
    def lease(lease_id="parent", parent_id=None, *, limits=None):
        return BudgetLease(
            lease_id=lease_id,
            parent_id=parent_id,
            bot_id="bot",
            persona_id="persona",
            currency="USD",
            limits=limits or {"model_microusd": 1_000, "model_tokens": 10_000},
            used={},
            reserved={},
            unconfirmed={},
            version=1,
            state="active",
        )

    def test_budget_duplicate_is_stable_and_digest_conflict_rejected(self):
        create_budget_lease(self.db, self.lease(), "create-parent", "a" * 64)
        first = reserve_budget(
            self.db, "parent", "call-1", "b" * 64,
            {"model_microusd": 200, "model_tokens": 500},
        )
        duplicate = reserve_budget(
            self.db, "parent", "call-1", "b" * 64,
            {"model_microusd": 200, "model_tokens": 500},
        )
        self.assertEqual(duplicate, first)
        with self.assertRaises(BudgetConflict):
            reserve_budget(
                self.db, "parent", "call-1", "c" * 64,
                {"model_microusd": 1},
            )
        current = get_budget_lease(self.db, "parent")
        self.assertEqual(current.reserved["model_microusd"], 200)
        self.assertEqual(current.version, 2)

    def test_child_allocation_encumbers_parent_and_survives_restart(self):
        create_budget_lease(self.db, self.lease(), "create-parent", "a" * 64)
        child = self.lease(
            "child", "parent",
            limits={"model_microusd": 400, "model_tokens": 2_000},
        )
        create_budget_lease(self.db, child, "create-child", "d" * 64)
        self.db.commit()
        self.reopen()
        parent = get_budget_lease(self.db, "parent")
        loaded = get_budget_lease(self.db, "child")
        self.assertEqual(parent.reserved["model_microusd"], 400)
        self.assertEqual(loaded.parent_id, "parent")
        with self.assertRaises(BudgetUnavailable):
            create_budget_lease(
                self.db,
                self.lease("too-large", "parent", limits={"model_microusd": 700}),
                "create-too-large", "e" * 64,
            )

    def test_unknown_cost_holds_ceiling_until_proven_resolution(self):
        create_budget_lease(self.db, self.lease(), "create-parent", "a" * 64)
        reserve_budget(
            self.db, "parent", "call-unknown", "f" * 64,
            {"model_microusd": 300},
        )
        unknown = settle_budget(
            self.db, "parent", "call-unknown", "f" * 64,
            actual=None,
        )
        self.assertEqual(unknown.status, "pending_confirmation")
        self.assertEqual(get_budget_lease(self.db, "parent").unconfirmed["model_microusd"], 300)
        # A retry resolves the original operation. It cannot reserve a fresh ceiling.
        duplicate = settle_budget(
            self.db, "parent", "call-unknown", "f" * 64,
            actual=None,
        )
        self.assertEqual(duplicate, unknown)
        resolved = resolve_unconfirmed(
            self.db, "parent", "call-unknown", "resolve-1", "1" * 64,
            actual={"model_microusd": 125}, execution_revoked=True,
        )
        self.assertEqual(resolved.status, "settled")
        current = get_budget_lease(self.db, "parent")
        self.assertEqual(current.used["model_microusd"], 125)
        self.assertEqual(current.unconfirmed.get("model_microusd", 0), 0)

    def test_child_close_releases_only_after_execution_authority_is_revoked(self):
        create_budget_lease(self.db, self.lease(), "create-parent", "a" * 64)
        create_budget_lease(
            self.db,
            self.lease("child", "parent", limits={"model_microusd": 400}),
            "create-child", "d" * 64,
        )
        reserve_budget(
            self.db, "child", "child-call", "e" * 64,
            {"model_microusd": 200},
        )
        with self.assertRaises(BudgetUnavailable):
            settle_budget(
                self.db, "child", "child-call", "e" * 64,
                actual={"model_microusd": 125}, execution_revoked=False,
            )
        settle_budget(
            self.db, "child", "child-call", "e" * 64,
            actual={"model_microusd": 125}, execution_revoked=True,
        )
        with self.assertRaises(BudgetUnavailable):
            close_budget_lease(
                self.db, "child", "close-child", "f" * 64,
                execution_revoked=False,
            )
        close_budget_lease(
            self.db, "child", "close-child", "f" * 64,
            execution_revoked=True,
        )
        parent = get_budget_lease(self.db, "parent")
        self.assertEqual(parent.used["model_microusd"], 125)
        self.assertEqual(parent.reserved.get("model_microusd", 0), 0)
        self.assertEqual(get_budget_lease(self.db, "child").state, "closed")

    @staticmethod
    def job(job_id="job-1", phase="queued"):
        return PersistentJob(
            job_id=job_id,
            operation_id="operation-1",
            activity_id="activity-1",
            effect_id=None,
            bot_id="bot",
            persona_id="persona",
            snapshot_ref="snapshot:1",
            phase=phase,
            work_kind="native_batch",
            continuation={"offset": 0},
            wake_condition={"kind": "manual"} if phase == "waiting" else None,
            deadline_utc="2026-09-24T00:00:00Z",
            budget_ref="parent",
            resource_ref="resource:1",
            operator_versions={"native": "2"},
            lease_holder=None,
            lease_expires_utc=None,
            fence=0,
            cancel_epoch=0,
            usage={},
            result_ref=None,
        )

    def test_job_fence_rejects_late_worker_after_reacquire_and_restart(self):
        create_job(self.db, self.job(), "create-job", "2" * 64)
        first = acquire_job(
            self.db, "job-1", "worker-a",
            now_utc="2026-09-23T00:00:00Z", lease_seconds=10,
        )
        self.db.commit()
        self.reopen()
        second = acquire_job(
            self.db, "job-1", "worker-b",
            now_utc="2026-09-23T00:00:11Z", lease_seconds=10,
        )
        self.assertGreater(second.fence, first.fence)
        with self.assertRaises(JobFenceRejected):
            checkpoint_job(
                self.db, "job-1", "worker-a", first.fence,
                continuation={"offset": 1}, usage={"cpu_ms": 1},
            )
        checkpointed = checkpoint_job(
            self.db, "job-1", "worker-b", second.fence,
            continuation={"offset": 2}, usage={"cpu_ms": 2},
        )
        self.assertEqual(checkpointed.continuation, {"offset": 2})
        with self.assertRaises(JobConflict):
            checkpoint_job(
                self.db, "job-1", "worker-b", second.fence,
                continuation={"offset": 3}, usage={"cpu_ms": 1},
            )

    def test_waiting_job_holds_no_worker_and_requires_explicit_wake(self):
        create_job(self.db, self.job(phase="waiting"), "create-wait", "3" * 64)
        with self.assertRaises(JobNotRunnable):
            acquire_job(
                self.db, "job-1", "worker-a",
                now_utc="2026-09-23T00:00:00Z", lease_seconds=10,
            )
        wake_job(self.db, "job-1", "wake-1", "4" * 64)
        acquired = acquire_job(
            self.db, "job-1", "worker-a",
            now_utc="2026-09-23T00:00:00Z", lease_seconds=10,
        )
        self.assertEqual(acquired.phase, "running")

    def test_expired_job_never_acquires_a_worker_slot(self):
        create_job(self.db, self.job(), "create-job", "2" * 64)
        with self.assertRaises(JobNotRunnable):
            acquire_job(
                self.db, "job-1", "worker-a",
                now_utc="2026-09-24T00:00:00Z", lease_seconds=10,
            )
        current = get_job(self.db, "job-1")
        self.assertEqual(current.phase, "queued")
        self.assertIsNone(current.lease_holder)

    def test_cancelled_running_job_drains_and_cannot_publish_late_result(self):
        create_job(self.db, self.job(), "create-job", "2" * 64)
        running = acquire_job(
            self.db, "job-1", "worker-a",
            now_utc="2026-09-23T00:00:00Z", lease_seconds=10,
        )
        cancelled = cancel_job(self.db, "job-1", "cancel-1", "5" * 64)
        self.assertEqual(cancelled.phase, "draining")
        self.assertEqual(cancelled.cancel_epoch, 1)
        with self.assertRaises(JobFenceRejected):
            transition_job(
                self.db, "job-1", "worker-a", running.fence,
                target_phase="completed", result_ref="result:late",
            )

    def test_character_clock_mapping_is_versioned_and_bounded(self):
        mapping = CharacterClockMapping(
            mapping_id="life-clock",
            version=1,
            wall_origin_utc="2026-09-23T00:00:00Z",
            character_origin=Decimal("100.0"),
            rate=Decimal("2.0"),
            valid_from_utc="2026-09-23T00:00:00Z",
            valid_until_utc="2026-09-24T00:00:00Z",
            policy_ref="policy:clock-v1",
            issuer_domain="d11",
        )
        issue_clock_mapping(self.db, mapping, "clock-issue-1", "6" * 64)
        loaded = get_clock_mapping(self.db, "life-clock", 1)
        self.assertEqual(
            loaded.character_at("2026-09-23T00:00:10Z"), Decimal("120.0"),
        )
        with self.assertRaises(ValueError):
            issue_clock_mapping(
                self.db,
                CharacterClockMapping(**{**mapping.__dict__, "version": 2,
                                         "rate": Decimal("NaN")}),
                "clock-issue-2", "7" * 64,
            )

    def test_restart_rebuilds_monotonic_deadline_and_untrusted_clock_defers(self):
        deadline = PersistentDeadline(
            deadline_id="deadline-1",
            deadline_utc="2026-09-23T00:01:00Z",
            floating_rule=None,
            timezone_name="UTC",
            policy_ref="policy:deadline-v1",
        )
        put_deadline(self.db, deadline, "deadline-put-1", "8" * 64)
        self.db.commit()
        self.reopen()
        deadline = get_deadline(self.db, "deadline-1")
        armed = rebuild_deadline(
            deadline,
            wall_now_utc="2026-09-23T00:00:20Z",
            monotonic_now=900.0,
            clock_trusted=True,
        )
        self.assertEqual(armed.status, "armed")
        self.assertEqual(armed.monotonic_deadline, 940.0)
        # The persisted object contains no process-local monotonic value.
        restarted = rebuild_deadline(
            deadline,
            wall_now_utc="2026-09-23T00:00:30Z",
            monotonic_now=10.0,
            clock_trusted=True,
        )
        self.assertEqual(restarted.monotonic_deadline, 40.0)
        deferred = rebuild_deadline(
            deadline,
            wall_now_utc="2026-09-23T00:00:30Z",
            monotonic_now=10.0,
            clock_trusted=False,
        )
        self.assertEqual(deferred.status, "deferred")
        self.assertIsNone(deferred.monotonic_deadline)


if __name__ == "__main__":
    unittest.main()
