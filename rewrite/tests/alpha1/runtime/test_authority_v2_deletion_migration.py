"""Same-file v2 deletion migration is restartable and fail closed."""

import sqlite3
import subprocess
import sys

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal


def open_bundle(tmp_path, *, create=False, old_history=False):
    journal = DeletionJournal(tmp_path / "deletion.db", create=create)
    if old_history:
        journal.append_intent(namespace="ns-a", operation_id="old-delete",
                              closure_roots=("old-item",), epoch=1,
                              policy_ref="policy-a")
        journal.advance("old-delete", "accepted",
                        business_barrier=lambda _: True)
        journal.advance("old-delete", "closed",
                        cleanup_verifier=lambda _: True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=create)
    head = journal.latest_head()
    expected = JournalHead(head.journal_id, head.seq, head.chain_digest)
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=create,
        authorizer=lambda credential, action, namespace, holder: credential == "ok",
        deletion_verifier=lambda ns, before, current, phase:
            current == expected and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    if create:
        core.register_namespace("ok", "ns-a", "holder-a", expected,
                                JournalHead("execution-a", 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    migration = AuthorityV2DeletionMigration(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a")
    return core, fences, journal, guard, execution, migration


def close_bundle(bundle):
    core, _, journal, guard, execution, _ = bundle
    core.close(); journal.close(); guard.close(); execution.close()


def service(bundle):
    core, fences, _, guard, execution, _ = bundle
    return AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a")


def test_blocker_survives_second_connection_and_restart(tmp_path):
    first = open_bundle(tmp_path, create=True)
    first[-1].begin_block(credential="ok")
    with first[0]._tx() as db:
        anchor = first[0]._anchor(db, "ns-a", first[0]._row(db, "ns-a"))
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        first[1].begin_fence(subject="subject-a", holder="holder-a",
                             operation="read", operation_id="read-a",
                             current_anchor=anchor)
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        service(first)
    second = open_bundle(tmp_path)
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        service(second)
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        AuthorityV2ExecutionBridge(core=second[0], fences=second[1],
                                   journal=second[4], deletion=second[3],
                                   namespace="ns-a")
    close_bundle(first); close_bundle(second)
    resumed = open_bundle(tmp_path)
    resumed[-1].run(credential="ok")
    assert service(resumed).current_anchor(
        credential="ok", subject="subject-a").deletion_seq == 0
    with resumed[3].freeze_writes():
        assert resumed[3].schema_kind() == "v2"
    close_bundle(resumed)


def test_log_commit_before_authority_completion_recovers_and_old_writer_rejected(tmp_path):
    bundle = open_bundle(tmp_path, create=True, old_history=True)
    migration = bundle[-1]
    migration.begin_block(credential="ok")
    migration.migrate_journal(credential="ok")
    with bundle[3].freeze_writes():
        assert bundle[3].schema_kind() == "v2"
        assert bundle[3].latest_phases() == {("ns-a", "old-delete"): "closed"}
        assert bundle[3].verified_head().seq == 3
    with pytest.raises(sqlite3.DatabaseError):
        bundle[2].append_intent(namespace="ns-a", operation_id="old-writer-late",
                                closure_roots=("late-item",), epoch=2,
                                policy_ref="policy-a")
    script = (
        "import sqlite3,sys\n"
        "db=sqlite3.connect(sys.argv[1],isolation_level=None)\n"
        "try:\n"
        " db.execute(\"INSERT INTO deletion_events(seq,namespace,operation_id,roots_json,epoch,policy_ref,phase,prev_digest,chain_digest) VALUES(4,'ns-a','bypass','[]',2,'p','pending','x','x')\")\n"
        "except sqlite3.DatabaseError: sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    assert subprocess.run([sys.executable, "-c", script,
                           str(bundle[2].path)], check=False).returncode == 0
    other = sqlite3.connect(bundle[2].path, isolation_level=None)
    try:
        for sql in ("UPDATE deletion_events SET phase='pending' WHERE seq=3",
                    "DELETE FROM deletion_events WHERE seq=3",
                    "INSERT INTO authority_deletion_v2_tail(seq) VALUES(4)"):
            with pytest.raises(sqlite3.DatabaseError):
                other.execute(sql)
    finally:
        other.close()
    close_bundle(bundle)
    resumed = open_bundle(tmp_path)
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        service(resumed)
    resumed[-1].run(credential="ok")
    with resumed[3].freeze_writes():
        assert resumed[3].latest_phases() == {("ns-a", "old-delete"): "closed"}
    anchor = service(resumed).current_anchor(
        credential="ok", subject="subject-a")
    with pytest.raises(AuthorityUnavailable, match="historical deletion closure"):
        service(resumed).begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="read", operation_id="read-a", expected_anchor=anchor)
    close_bundle(resumed)


def test_active_fence_refuses_to_start_migration(tmp_path):
    bundle = open_bundle(tmp_path, create=True)
    protected = service(bundle)
    anchor = protected.current_anchor(credential="ok", subject="subject-a")
    protected.begin_fence(credential="ok", subject="subject-a", holder="holder-a",
                          operation="read", operation_id="read-a",
                          expected_anchor=anchor)
    with pytest.raises(AuthorityUnavailable, match="active v2 fence"):
        bundle[-1].begin_block(credential="ok")
    with bundle[0]._tx() as db:
        assert db.execute("SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone() is None
    close_bundle(bundle)


def test_old_writer_between_block_and_migration_quarantines(tmp_path):
    bundle = open_bundle(tmp_path, create=True)
    bundle[-1].begin_block(credential="ok")
    bundle[2].append_intent(namespace="ns-a", operation_id="late-delete",
                            closure_roots=("item-a",), epoch=1,
                            policy_ref="policy-a")
    with pytest.raises(AuthorityUnavailable, match="old deletion head changed"):
        bundle[-1].migrate_journal(credential="ok")
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        service(bundle)
    close_bundle(bundle)


def test_completed_retry_still_verifies_authority_and_log_heads(tmp_path):
    bundle = open_bundle(tmp_path, create=True)
    bundle[-1].run(credential="ok")
    bundle[-1].complete(credential="ok")
    with bundle[0]._tx() as db:
        db.execute("UPDATE authority_namespaces SET deletion_digest=? WHERE namespace='ns-a'",
                   ("sha256:" + "a" * 64,))
    with pytest.raises(AuthorityUnavailable, match="final anchor differs"):
        bundle[-1].run(credential="ok")
    close_bundle(bundle)


def test_reader_preserves_each_historical_operation_phase(tmp_path):
    journal = DeletionJournal(tmp_path / "deletion.db", create=True)
    for operation, epoch in (("pending-a", 1), ("accepted-a", 2),
                             ("closed-a", 3)):
        journal.append_intent(namespace="ns-a", operation_id=operation,
                              closure_roots=(operation,), epoch=epoch,
                              policy_ref="policy-a")
    journal.advance("accepted-a", "accepted", business_barrier=lambda _: True)
    journal.advance("closed-a", "accepted", business_barrier=lambda _: True)
    journal.advance("closed-a", "closed", cleanup_verifier=lambda _: True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    with guard.freeze_writes():
        assert guard.latest_phases() == {
            ("ns-a", "pending-a"): "pending",
            ("ns-a", "accepted-a"): "accepted",
            ("ns-a", "closed-a"): "closed",
        }
        assert guard.has_deletion_history("ns-a")
    guard.close(); journal.close()
