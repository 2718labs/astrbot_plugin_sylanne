"""Schema-2 deletion tail upgrade keeps the Authority blocker durable."""

import json
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal


def bundle(path, *, create=False):
    journal = DeletionJournal(path / "deletion.db", create=create)
    if create:
        journal.append_intent(namespace="ns-a", operation_id="old-delete",
                              closure_roots=("old-item",), epoch=1,
                              policy_ref="policy-a")
    guard = AuthorityV2DeletionGuard(path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(path / "execution.db", namespace="ns-a",
                                             journal_id="execution-a", create=create)
    deletion_head = journal.latest_head()
    head = JournalHead(deletion_head.journal_id, deletion_head.seq,
                       deletion_head.chain_digest)
    core = AuthorityServiceCore(
        path / "authority.db", create=create,
        authorizer=lambda credential, action, namespace, holder: credential == "ok",
        deletion_verifier=lambda ns, before, current, phase: current == head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase: execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True)
    if create:
        core.register_namespace("ok", "ns-a", "holder-a", head,
                                JournalHead("execution-a", 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    old = AuthorityV2DeletionMigration(core=core, fences=fences,
                                        deletion=guard, execution=execution,
                                        namespace="ns-a")
    new = AuthorityV2DeletionTailMigration(core=core, fences=fences,
                                            deletion=guard, execution=execution,
                                            namespace="ns-a")
    return core, fences, journal, guard, execution, old, new


def close(parts):
    core, _, journal, guard, execution, _, _ = parts
    core.close()
    journal.close()
    guard.close()
    execution.close()


def test_blocked_upgrade_survives_restart_and_preserves_prefix(tmp_path):
    first = bundle(tmp_path, create=True)
    first[5].run(credential="ok")
    before = first[3]
    with before.freeze_writes():
        assert before.schema_version() == 1
        old_head = before.verified_head()
    first[6].begin_block(credential="ok")
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        AuthorityV2FenceService(core=first[0], fences=first[1],
                                deletion=first[3], execution=first[4], namespace="ns-a")
    with pytest.raises(AuthorityUnavailable, match="unknown deletion migration marker"):
        first[5].run(credential="ok")
    close(first)

    resumed = bundle(tmp_path)
    resumed[6].migrate_journal(credential="ok")
    with resumed[3].freeze_writes():
        assert resumed[3].schema_version() == 2
        assert resumed[3].verified_head() == old_head
        assert resumed[3].latest_phases() == {("ns-a", "old-delete"): "pending"}
    with pytest.raises(AuthorityUnavailable, match="migration blocks"):
        AuthorityV2FenceService(core=resumed[0], fences=resumed[1],
                                deletion=resumed[3], execution=resumed[4], namespace="ns-a")
    close(resumed)

    completed = bundle(tmp_path)
    completed[6].run(credential="ok")
    completed[6].run(credential="ok")
    with completed[3].freeze_writes():
        assert completed[3].verified_head() == old_head
    other = sqlite3.connect(tmp_path / "deletion.db", isolation_level=None)
    try:
        for sql in (
            "INSERT INTO deletion_events(seq) VALUES(2)",
            "UPDATE deletion_events SET phase='closed' WHERE seq=1",
            "DELETE FROM deletion_events WHERE seq=1",
            "INSERT INTO authority_deletion_v2_tail(seq) VALUES(2)",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                other.execute(sql)
    finally:
        other.close()
    close(completed)


def test_upgrade_rejects_nonempty_old_tail_and_keeps_blocker(tmp_path):
    parts = bundle(tmp_path, create=True)
    parts[5].run(credential="ok")
    parts[6].begin_block(credential="ok")
    with parts[3].freeze_writes():
        db = parts[3]._db
        old_digest = parts[3].verified_head().digest
        db.execute("DROP TRIGGER authority_deletion_v2_no_insert")
        db.execute("INSERT INTO authority_deletion_v2_tail(seq,mutation_id,request_digest,namespace,operation_id,phase,subject,holder,token_digest,fence_epoch,revision,before_seq,before_digest,evidence_digest,roots_json,epoch,policy_ref,prev_digest,chain_digest) VALUES(2,'m','r','ns-a','op','pending','s','h','t',1,0,1,?, 'e','[\"x\"]',2,'p',?,'invalid')",
                   (old_digest, old_digest))
        from sylanne3.authority_service.v2_deletion_guard import _TAIL_TRIGGERS
        db.execute(_TAIL_TRIGGERS["authority_deletion_v2_no_insert"])
    with pytest.raises(AuthorityUnavailable):
        parts[6].migrate_journal(credential="ok")
    with parts[0]._tx() as db:
        marker = json.loads(db.execute("SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone()[0])
        assert marker["stage"] == "tail-blocked"
    close(parts)


def test_upgrade_rejects_changed_prefix_ddl(tmp_path):
    parts = bundle(tmp_path, create=True)
    parts[5].run(credential="ok")
    parts[6].begin_block(credential="ok")
    with parts[3].freeze_writes():
        db = parts[3]._db
        db.execute("DROP INDEX deletion_intent_once")
        db.execute("CREATE UNIQUE INDEX deletion_intent_once ON deletion_events(operation_id) WHERE phase='accepted'")
    with pytest.raises(AuthorityUnavailable, match="prefix DDL differs"):
        parts[6].migrate_journal(credential="ok")
    with parts[3].freeze_writes():
        assert parts[3].schema_version() == 1
    close(parts)
