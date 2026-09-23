"""Journal-only invariants; these tests do not grant a fence or commit Authority."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.v2_contract import FencePermitV2, PendingMutationV2
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.runtime.restore_anchor import RestoreAnchor


def digest(char):
    return "sha256:" + char * 64


def anchor(*, seq=0, chain="genesis", namespace="ns-a", proof="proof-a"):
    return RestoreAnchor(
        authority_id="authority-a", namespace=namespace, activation_generation=2,
        deletion_journal_id="delete-a", deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-a", execution_seq=seq,
        execution_digest=chain, revocation_epoch=1, proof=proof,
    )


def pending(*, before=None, revision=0, mutation_id="mutation-a",
            request_digest=None, append_id="append-a", token="A" * 43):
    before = before or anchor()
    permit = FencePermitV2(
        authority_id="authority-a", namespace=before.namespace,
        subject="subject-a", holder="holder-a", generation=2,
        operation="dispatch", operation_id="operation-a", token=token,
        fence_epoch=1, revision=revision, pinned_anchor=before,
        effect_id="effect-a", command_digest=digest("a"),
        footprint_digest=digest("b"),
    )
    draft = PendingMutationV2(
        permit=permit, mutation_id=mutation_id,
        request_digest=request_digest or digest("c"), phase="prepared",
        before_anchor=before, expected_append_id=append_id,
        expected_append_digest=digest("0"),
    )
    return replace(draft, expected_append_digest=
                   AuthorityV2ExecutionJournal.expected_digest(draft))


def open_journal(path, *, namespace="ns-a", journal_id="execution-a", create=False):
    return AuthorityV2ExecutionJournal(
        path, namespace=namespace, journal_id=journal_id, create=create)


def test_append_once_exact_retry_and_reopen(tmp_path):
    path = tmp_path / "execution.db"
    journal = open_journal(path, create=True)
    item = pending()
    assert journal.verified_head() == JournalHead("execution-a", 0, "genesis")
    with pytest.raises(AuthorityUnavailable, match="frozen"):
        journal.inspect_expected(item)
    with journal.freeze_writes():
        assert journal.inspect_expected(item).following_count == 0
    first = journal.append_once(item)
    assert first.chain_digest == item.expected_append_digest
    assert journal.append_once(item) == first
    with journal.freeze_writes():
        inspected = journal.inspect_expected(item)
        assert (inspected.following_count, inspected.first_append) == (1, first)
    journal.close()
    journal = open_journal(path)
    assert journal.verified_head() == JournalHead("execution-a", 1, first.chain_digest)
    assert journal.append_once(item) == first
    journal.close()


def test_wrong_identity_digest_before_head_and_namespace_are_rejected(tmp_path):
    path = tmp_path / "execution.db"
    journal = open_journal(path, create=True)
    item = pending()
    with pytest.raises(AuthorityUnavailable, match="expected digest"):
        journal.append_once(replace(item, expected_append_digest=digest("f")))
    first = journal.append_once(item)
    for altered in (
        pending(request_digest=digest("d")),
        pending(token="B" * 43),
        pending(mutation_id="mutation-a", append_id="append-b"),
    ):
        with pytest.raises(AuthorityUnavailable):
            journal.append_once(altered)
    with pytest.raises(AuthorityUnavailable, match="before-head"):
        journal.append_once(pending(mutation_id="mutation-b", append_id="append-b"))
    with pytest.raises(AuthorityUnavailable, match="namespace"):
        journal.append_once(pending(before=anchor(namespace="ns-b")))
    assert journal.verified_head().digest == first.chain_digest
    journal.close()
    with pytest.raises(AuthorityUnavailable, match="namespace"):
        open_journal(path, namespace="ns-b")


def test_inspection_distinguishes_zero_one_and_multiple_without_repair(tmp_path):
    journal = open_journal(tmp_path / "execution.db", create=True)
    first_pending = pending()
    first = journal.append_once(first_pending)
    next_anchor = anchor(seq=1, chain=first.chain_digest, proof="proof-b")
    second_pending = pending(
        before=next_anchor, revision=1, mutation_id="mutation-b",
        request_digest=digest("d"), append_id="append-b",
    )
    with journal.freeze_writes():
        assert journal.inspect_expected(second_pending).following_count == 0
    second = journal.append_once(second_pending)
    with journal.freeze_writes():
        older = journal.inspect_expected(first_pending)
        newer = journal.inspect_expected(second_pending)
        assert (older.following_count, older.first_append) == (2, first)
        assert (newer.following_count, newer.first_append) == (1, second)
        assert older.verified_head.seq == 2
    with pytest.raises(AuthorityUnavailable):
        journal.append_once(first_pending)  # An old retry cannot hide a later append.
    journal.close()


def test_mixed_unknown_or_partial_schema_fails_closed(tmp_path):
    path = tmp_path / "mixed.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE execution_entries(seq INTEGER)")
    db.close()
    with pytest.raises(AuthorityUnavailable, match="schema"):
        open_journal(path, create=True)
    assert sqlite3.connect(path).execute(
        "SELECT count(*) FROM sqlite_master WHERE name='authority_v2_execution_entries'"
    ).fetchone()[0] == 0

    path = tmp_path / "unknown.db"
    journal = open_journal(path, create=True)
    journal.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE authority_v2_execution_meta SET value='future' WHERE key='schema_version'")
    db.commit()
    db.close()
    with pytest.raises(AuthorityUnavailable, match="version"):
        open_journal(path)


def test_reopen_rejects_old_entry_tampering_and_sequence_gap(tmp_path):
    path = tmp_path / "execution.db"
    journal = open_journal(path, create=True)
    first = journal.append_once(pending())
    journal.append_once(pending(before=anchor(seq=1, chain=first.chain_digest,
                                              proof="proof-b"), revision=1,
                                mutation_id="mutation-b", append_id="append-b"))
    journal.close()

    db = sqlite3.connect(path)
    trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='authority_v2_execution_no_update'").fetchone()[0]
    db.execute("DROP TRIGGER authority_v2_execution_no_update")
    db.execute("UPDATE authority_v2_execution_entries SET request_digest=? WHERE seq=1",
               (digest("e"),))
    db.execute(trigger)
    db.commit()
    db.close()
    with pytest.raises(AuthorityUnavailable, match="chain"):
        open_journal(path)

    path = tmp_path / "gap.db"
    journal = open_journal(path, create=True)
    first = journal.append_once(pending())
    journal.append_once(pending(before=anchor(seq=1, chain=first.chain_digest,
                                              proof="proof-b"), revision=1,
                                mutation_id="mutation-b", append_id="append-b"))
    journal.close()
    db = sqlite3.connect(path)
    trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='authority_v2_execution_no_delete'").fetchone()[0]
    db.execute("DROP TRIGGER authority_v2_execution_no_delete")
    db.execute("DELETE FROM authority_v2_execution_entries WHERE seq=1")
    db.execute(trigger)
    db.commit()
    db.close()
    with pytest.raises(AuthorityUnavailable, match="chain"):
        open_journal(path)


def test_two_service_connections_compete_for_same_before_head(tmp_path):
    path = tmp_path / "execution.db"
    first = open_journal(path, create=True)
    second = open_journal(path)
    barrier = threading.Barrier(2)

    def attempt(journal, item):
        barrier.wait()
        try:
            return journal.append_once(item)
        except AuthorityUnavailable:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(attempt, first, pending())
        b = pool.submit(attempt, second, pending(
            mutation_id="mutation-b", append_id="append-b"))
        assert sum(result is not None for result in (a.result(), b.result())) == 1
    assert first.verified_head().seq == 1
    first.close()
    second.close()
