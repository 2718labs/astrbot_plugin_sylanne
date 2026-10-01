"""Installed Core callbacks read real independent journals and fail closed."""

import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.installed_core_verifiers import (
    installed_core_verifier_factory,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.runtime.deletion import DeletionJournal


NAMESPACE = "bot:persona"


def test_real_current_heads_phase_and_closed_legacy_routes(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=NAMESPACE,
        journal_id="execution-installed", create=True)
    try:
        checks = installed_core_verifier_factory(deletion, {NAMESPACE: execution})
        with deletion.freeze_writes():
            deletion_genesis = deletion.verified_head()
        execution_genesis = execution.verified_head()

        assert checks.deletion(NAMESPACE, None, deletion_genesis, "clear")
        assert checks.deletion(NAMESPACE, deletion_genesis, deletion_genesis, "clear")
        assert checks.execution(NAMESPACE, None, execution_genesis, None)
        assert checks.execution(NAMESPACE, execution_genesis, execution_genesis, None)
        assert not checks.deletion("wrong:persona", None, deletion_genesis, "clear")
        assert not checks.execution("wrong:persona", None, execution_genesis, None)
        assert not checks.deletion(NAMESPACE, None, deletion_genesis, "pending")
        assert not checks.execution(NAMESPACE, None, execution_genesis, "clear")
        assert not checks.deletion(NAMESPACE, None, JournalHead(
            deletion_genesis.journal_id, 1, "sha256:" + "a" * 64), "clear")
        assert not checks.execution(NAMESPACE, None, JournalHead(
            execution_genesis.journal_id, 1, "sha256:" + "b" * 64), None)
        assert not checks.effect(NAMESPACE, "effect", "unresolved", (), execution_genesis)
        assert not checks.dispatch(NAMESPACE, "effect", ())

        deletion_log.append_intent(
            namespace=NAMESPACE, operation_id="deletion-1",
            closure_roots=("root-1",), epoch=1, policy_ref="policy-1")
        with deletion.freeze_writes():
            deletion_pending = deletion.verified_head()
        assert not checks.deletion(NAMESPACE, deletion_genesis, deletion_genesis, "clear")
        assert checks.deletion(NAMESPACE, deletion_pending, deletion_pending, "pending")
        assert not checks.deletion(NAMESPACE, deletion_pending, deletion_pending, "clear")
        # No public prefix proof exists; a purported one-step legacy advance
        # must not be accepted from sequence arithmetic alone.
        assert not checks.deletion(NAMESPACE, deletion_genesis, deletion_pending, "pending")
        assert not checks.execution(NAMESPACE, JournalHead(
            execution_genesis.journal_id, 1, "sha256:" + "c" * 64),
            execution_genesis, None)
    finally:
        execution.close()
        deletion.close()
        deletion_log.close()


def test_rejects_wrong_execution_binding_and_tampered_independent_chain(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.append_intent(
        namespace=NAMESPACE, operation_id="deletion-1",
        closure_roots=("root-1",), epoch=1, policy_ref="policy-1")
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=NAMESPACE,
        journal_id="execution-installed", create=True)
    try:
        with pytest.raises(AuthorityUnavailable, match="namespace binding"):
            installed_core_verifier_factory(deletion, {"wrong:persona": execution})
        checks = installed_core_verifier_factory(deletion, {NAMESPACE: execution})
        with deletion.freeze_writes():
            head = deletion.verified_head()
        assert checks.deletion(NAMESPACE, head, head, "pending")
        # The immutable trigger rejects direct edits from another connection.
        with sqlite3.connect(tmp_path / "deletion.db") as db:
            with pytest.raises(sqlite3.DatabaseError):
                db.execute("UPDATE deletion_events SET chain_digest=? WHERE seq=1",
                           ("sha256:" + "0" * 64,))
        assert checks.deletion(NAMESPACE, head, head, "pending")
        # Even a privileged schema/row rewrite cannot pass the callback's
        # independent schema and chain scan.
        with sqlite3.connect(tmp_path / "deletion.db") as db:
            db.execute("DROP TRIGGER deletion_events_immutable_update")
            db.execute("UPDATE deletion_events SET chain_digest=? WHERE seq=1",
                       ("sha256:" + "0" * 64,))
        with pytest.raises(AuthorityUnavailable, match="schema"):
            checks.deletion(NAMESPACE, head, head, "pending")
    finally:
        execution.close()
        deletion.close()
        deletion_log.close()
