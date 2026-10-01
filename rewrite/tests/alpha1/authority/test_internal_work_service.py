"""C04 does not execute or settle through a dispatch-shaped journal row."""

import hashlib

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
    terminal_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner


NAMESPACE = "ns:sha256:" + hashlib.sha256(
    canonical_json(["bot", "persona"]).encode("utf-8")
).hexdigest()
RESERVATION = AtomKey(
    Owner("activity", "bot", "persona", "activity-1"),
    "d02.reservation.v1", "reservation",
).token


def binding() -> InternalWorkBindingV1:
    return InternalWorkBindingV1(
        NAMESPACE, "activity-1", "operation-1", "execution-1",
        "a" * 64, "resource-quote", 1, "b" * 64,
        "body-quote", 1, "c" * 64, RESERVATION, "component",
        "budget", 1, "algorithm", "policy",
    )


def test_same_chain_claim_only_restart_is_unknown_then_terminal_is_idempotent(tmp_path):
    path = tmp_path / "execution.db"
    journal = AuthorityV2ExecutionJournal(
        path, namespace=NAMESPACE, journal_id="execution-1", create=True)
    before = JournalHead("execution-1", 0, "genesis")
    work = binding()
    try:
        service = AuthorityInternalWorkService(journal)
        claim = service.begin(work)
        assert service.begin(work) == claim
        unknown = terminal_internal_work_v1(work, claim, status="unknown")
        assert unknown.actual_cpu_ms is None
        with pytest.raises(AuthorityUnavailable, match="installed W01 preparation"):
            service.claim(work, before_head=before)
        with journal.freeze_writes():
            claimed = journal.append_internal_work_claim_v1(work, claim, before)
        assert claimed.sequence == 1
        assert claimed.mutation_id == claim.mutation_id
        after_claim = service.current_head_for_restore()
        inspection = service.inspect(work)
        assert inspection.claim == claim and inspection.terminal is None
        assert inspection.verified_head == after_claim
        assert after_claim.seq == 1
        with pytest.raises(AuthorityUnavailable, match="installed terminal measurement"):
            service.terminal(work, claim, unknown, before_head=after_claim)
    finally:
        journal.close()
    reopened = AuthorityV2ExecutionJournal(
        path, namespace=NAMESPACE, journal_id="execution-1", create=False)
    try:
        service = AuthorityInternalWorkService(reopened)
        assert service.current_head_for_restore() == after_claim
        inspection = service.inspect(work)
        assert inspection.claim == claim and inspection.terminal is None
        with reopened.freeze_writes():
            assert reopened.append_internal_work_claim_v1(work, claim, before) == claimed
            terminal_append = reopened.append_internal_work_terminal_v1(
                work, claim, unknown, after_claim)
        assert terminal_append.sequence == 2
        inspected = service.inspect(work)
        assert inspected.terminal == unknown
        proof = InternalWorkTerminalProofV1(
            work, claim, unknown, claimed.receipt_ref, claimed.content_digest,
            terminal_append.receipt_ref, terminal_append.content_digest,
            inspected.verified_head)
        with pytest.raises(AuthorityUnavailable, match="current Core"):
            service.verify_original_internal_work_terminal(proof)
        from dataclasses import replace
        with pytest.raises(AuthorityUnavailable, match="current Core"):
            service.verify_original_internal_work_terminal(replace(
                proof, terminal_receipt_digest="f" * 64))
        with reopened.freeze_writes():
            assert reopened.append_internal_work_terminal_v1(
                work, claim, unknown, after_claim) == terminal_append
            with pytest.raises(AuthorityUnavailable, match="mutation ID was reused"):
                reopened.append_internal_work_terminal_v1(
                    work, claim, terminal_internal_work_v1(
                        work, claim, status="failed", actual_cpu_ms=0),
                    after_claim)
        assert service.current_head_for_restore().seq == 2
    finally:
        reopened.close()


def test_service_refuses_cross_namespace_before_any_port(tmp_path):
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=NAMESPACE,
        journal_id="execution-1", create=True)
    try:
        service = AuthorityInternalWorkService(journal)
        from dataclasses import replace
        with pytest.raises(AuthorityUnavailable, match="namespace differs"):
            other_namespace = "ns:sha256:" + hashlib.sha256(
                canonical_json(["other", "persona"]).encode("utf-8")
            ).hexdigest()
            other_reservation = AtomKey(
                Owner("activity", "other", "persona", "activity-1"),
                "d02.reservation.v1", "reservation",
            ).token
            service.begin(replace(binding(), namespace=other_namespace,
                                  body_reservation_ref=other_reservation))
    finally:
        journal.close()


def test_existing_schema_one_requires_explicit_upgrade_before_internal_work(tmp_path):
    import sqlite3

    path = tmp_path / "execution.db"
    journal = AuthorityV2ExecutionJournal(
        path, namespace=NAMESPACE, journal_id="execution-1", create=True)
    journal.close()
    # Represent a previously installed v1 journal; cold-open never promotes it.
    with sqlite3.connect(path) as db:
        db.execute("UPDATE authority_v2_execution_meta SET value='1' "
                   "WHERE key='schema_version'")
    reopened = AuthorityV2ExecutionJournal(
        path, namespace=NAMESPACE, journal_id="execution-1", create=False)
    try:
        service = AuthorityInternalWorkService(reopened)
        work = binding()
        with reopened.freeze_writes():
            with pytest.raises(AuthorityUnavailable, match="explicit execution schema v2"):
                reopened.append_internal_work_claim_v1(
                    work, service.begin(work), JournalHead("execution-1", 0, "genesis"))
        assert reopened.verified_head() == JournalHead("execution-1", 0, "genesis")
        with sqlite3.connect(path) as db:
            assert db.execute("SELECT value FROM authority_v2_execution_meta "
                              "WHERE key='schema_version'").fetchone() == ("1",)
    finally:
        reopened.close()
