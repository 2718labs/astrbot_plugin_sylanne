"""A C04 append becomes current only after one exact Core head CAS."""

from dataclasses import replace
import hashlib

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, terminal_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.deletion import DeletionJournal


NAMESPACE = "ns:sha256:" + hashlib.sha256(
    canonical_json(["bot", "persona"]).encode("utf-8")
).hexdigest()
RESERVATION = AtomKey(
    Owner("activity", "bot", "persona", "activity-1"),
    "d02.reservation.v1", "reservation",
).token
JOURNAL_ID = "execution-1"


def binding() -> InternalWorkBindingV1:
    return InternalWorkBindingV1(
        NAMESPACE, "activity-1", "operation-1", "execution-1", "a" * 64,
        "resource-quote", 1, "b" * 64, "body-quote", 1, "c" * 64,
        RESERVATION, "component", "budget", 1, "algorithm", "policy")


def opened(tmp_path, *, create: bool):
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=NAMESPACE,
        journal_id=JOURNAL_ID, create=create)
    verifiers = installed_core_verifier_factory(deletion, {NAMESPACE: journal})
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=create,
        authorizer=lambda credential, *_: credential == "ok",
        deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution,
        effect_verifier=verifiers.effect,
        dispatch_verifier=verifiers.dispatch)
    if create:
        with deletion.freeze_writes():
            deletion_head = deletion.verified_head()
        core.register_namespace("ok", NAMESPACE, "host", deletion_head,
                                JournalHead(JOURNAL_ID, 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    bridge = AuthorityV2ExecutionBridge(
        core=core, fences=fences, journal=journal, namespace=NAMESPACE,
        deletion=deletion)
    return core, deletion, journal, bridge


def close(core, deletion, journal):
    core.close()
    journal.close()
    deletion.close()


def test_claim_crash_head_reconcile_restart_unknown_and_terminal_exact_replay(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    work = binding()
    service = AuthorityInternalWorkService(journal)
    claim = service.begin(work)
    try:
        with journal.freeze_writes():
            claim_append = journal.append_internal_work_claim_v1(
                work, claim, JournalHead(JOURNAL_ID, 0, "genesis"))
        assert claim_append.sequence == 1
        assert not bridge.is_current_internal_work_head_v1(
            credential="ok", head=JournalHead(
                JOURNAL_ID, claim_append.sequence, claim_append.chain_digest))
        with core._tx() as db:
            assert core._head(core._row(db, NAMESPACE), "execution").seq == 0
        assert bridge.reconcile_internal_work_head(
            credential="ok", binding=work, phase="claim").execution_seq == 1
        assert bridge.is_current_internal_work_head_v1(
            credential="ok", head=JournalHead(
                JOURNAL_ID, claim_append.sequence, claim_append.chain_digest))
        assert bridge.reconcile_internal_work_head(
            credential="ok", binding=work, phase="claim").execution_seq == 1
    finally:
        close(core, deletion, journal)

    core, deletion, journal, bridge = opened(tmp_path, create=False)
    service = AuthorityInternalWorkService(journal)
    try:
        inspected = service.inspect(work)
        assert inspected.claim == claim and inspected.terminal is None
        assert inspected.verified_head.seq == 1  # Unknown cost, not zero.
        unknown = terminal_internal_work_v1(work, claim, status="unknown")
        with journal.freeze_writes():
            terminal_append = journal.append_internal_work_terminal_v1(
                work, claim, unknown, inspected.verified_head)
        assert terminal_append.sequence == 2
        assert bridge.reconcile_internal_work_head(
            credential="ok", binding=work, phase="terminal").execution_seq == 2
        with journal.freeze_writes():
            assert journal.append_internal_work_terminal_v1(
                work, claim, unknown, inspected.verified_head) == terminal_append
        assert service.inspect(work).terminal.actual_cpu_ms is None
        with pytest.raises(AuthorityUnavailable, match="mutation ID was reused"):
            with journal.freeze_writes():
                journal.append_internal_work_terminal_v1(
                    work, claim, terminal_internal_work_v1(
                        work, claim, status="failed", actual_cpu_ms=0),
                    inspected.verified_head)
    finally:
        close(core, deletion, journal)


def test_wrong_binding_or_unordered_recovery_cannot_advance_core(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    service = AuthorityInternalWorkService(journal)
    work = binding()
    claim = service.begin(work)
    try:
        with journal.freeze_writes():
            journal.append_internal_work_claim_v1(
                work, claim, JournalHead(JOURNAL_ID, 0, "genesis"))
        with pytest.raises(AuthorityUnavailable, match="no durable append"):
            bridge.reconcile_internal_work_head(
                credential="ok", binding=replace(work, activation_generation=2),
                phase="claim")
        terminal = terminal_internal_work_v1(work, claim, status="unknown")
        with journal.freeze_writes():
            journal.append_internal_work_terminal_v1(
                work, claim, terminal, journal.verified_head())
        with pytest.raises(AuthorityUnavailable, match="ordered recovery"):
            bridge.reconcile_internal_work_head(
                credential="ok", binding=work, phase="claim")
        with core._tx() as db:
            assert core._head(core._row(db, NAMESPACE), "execution").seq == 0
    finally:
        close(core, deletion, journal)
