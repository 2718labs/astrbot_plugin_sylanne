"""B1 storage tests; these do not establish service authentication or journal trust."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3
import threading

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import PendingMutationV2
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.restore_anchor import RestoreAnchor


def digest(char: str) -> str:
    return "sha256:" + char * 64


def anchor(namespace: str = "ns-a") -> RestoreAnchor:
    return RestoreAnchor(
        authority_id="authority-a", namespace=namespace, activation_generation=2,
        deletion_journal_id="delete-a", deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-a", execution_seq=0,
        execution_digest="genesis", revocation_epoch=1, proof="opaque-proof-a",
    )


def open_store(path, *, create=False):
    db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=5)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    try:
        return db, AuthorityV2FenceStore(db, create=create)
    except BaseException:
        db.close()
        raise


def begin(store, *, operation_id="op-a", current_anchor=None, **changes):
    fields = dict(subject="subject-a", holder="holder-a", operation="read",
                  operation_id=operation_id, current_anchor=current_anchor or anchor())
    fields.update(changes)
    return store.begin_fence(**fields)


def finish(store, permit, *, current_anchor=None, **changes):
    fields = dict(subject="subject-a", current_anchor=current_anchor or anchor(),
                  request_id="finish-a", request_digest=digest("f"))
    fields.update(changes)
    return store.finish_fence(permit, **fields)


def test_exclusive_retry_finish_epoch_and_restart(tmp_path):
    path = tmp_path / "service.db"
    db, store = open_store(path, create=True)
    first = begin(store)
    assert len(first.token) >= 32 and first.revision == 0 and first.fence_epoch == 1
    assert begin(store) == first
    assert store.validate_fence(first, subject="subject-a", current_anchor=anchor()) == first
    with pytest.raises(AuthorityUnavailable):
        begin(store, operation_id="op-b")
    db.close()

    db, store = open_store(path)
    assert store.get_operation("op-a", subject="subject-a", namespace="ns-a") == (first, "active", None)
    with pytest.raises(AuthorityUnavailable):
        begin(store, operation_id="op-b")
    finish(store, first)
    db.close()

    db, store = open_store(path)
    finish(store, first)
    # A completed request remains idempotent even after another operation moves the head.
    second = begin(store, operation_id="op-b")
    assert second.fence_epoch == 2 and second.token != first.token
    finish(store, first, current_anchor=replace(anchor(), proof="new-proof"))
    with pytest.raises(AuthorityUnavailable):
        store.validate_fence(first, subject="subject-a", current_anchor=anchor())
    with pytest.raises(AuthorityUnavailable):
        begin(store)
    db.close()


def test_identity_anchor_and_finish_conflicts_fail_closed(tmp_path):
    db, store = open_store(tmp_path / "service.db", create=True)
    permit = begin(store)
    changed = replace(anchor(), proof="different-proof")
    for kwargs in (dict(subject="subject-b"), dict(holder="holder-b"),
                   dict(operation="write"), dict(current_anchor=changed)):
        with pytest.raises(AuthorityUnavailable):
            begin(store, **kwargs)
    for kwargs in (dict(subject="subject-b"), dict(current_anchor=changed),
                   dict(permit=replace(permit, revision=1)),
                   dict(permit=replace(permit, token="B" * 43))):
        with pytest.raises(AuthorityUnavailable):
            fields = dict(permit=permit, subject="subject-a", current_anchor=anchor())
            fields.update(kwargs)
            store.validate_fence(**fields)
    with pytest.raises(AuthorityUnavailable):
        store.get_operation("op-a", subject="subject-b", namespace="ns-a")
    with pytest.raises(AuthorityUnavailable):
        store.get_operation("op-a", subject="subject-a", namespace="ns-b")
    with pytest.raises(AuthorityUnavailable):
        finish(store, permit, current_anchor=changed)
    finish(store, permit)
    with pytest.raises(AuthorityUnavailable):
        finish(store, permit, request_id="finish-b")
    with pytest.raises(AuthorityUnavailable):
        finish(store, permit, request_digest=digest("e"))
    db.close()


def test_pending_survives_restart_and_blocks_all_finishes(tmp_path):
    path = tmp_path / "service.db"
    db, store = open_store(path, create=True)
    permit = begin(store, operation="dispatch", effect_id="effect-a",
                   command_digest=digest("a"), footprint_digest=digest("b"))
    pending = PendingMutationV2(
        permit=permit, mutation_id="mutation-a", request_digest=digest("c"),
        phase="prepared", before_anchor=anchor(), expected_append_id="append-a",
        expected_append_digest=digest("d"),
    )
    assert store.record_pending(pending, subject="subject-a", current_anchor=anchor()) == pending
    assert store.record_pending(pending, subject="subject-a", current_anchor=anchor()) == pending
    with pytest.raises(AuthorityUnavailable):
        store.record_pending(replace(pending, request_digest=digest("e")),
                             subject="subject-a", current_anchor=anchor())
    db.close()
    db, store = open_store(path)
    assert store.get_operation("op-a", subject="subject-a", namespace="ns-a") == (permit, "active", pending)
    with pytest.raises(AuthorityUnavailable):
        store.validate_fence(permit, subject="subject-a", current_anchor=anchor())
    with pytest.raises(AuthorityUnavailable):
        finish(store, permit)
    with pytest.raises(AuthorityUnavailable):
        begin(store, operation_id="op-b")
    db.close()


def test_two_connections_race_for_one_namespace(tmp_path):
    path = tmp_path / "service.db"
    db0, _ = open_store(path, create=True)
    db1, first = open_store(path)
    db2, second = open_store(path)
    barrier = threading.Barrier(2)

    def attempt(store, operation_id):
        barrier.wait()
        try:
            return begin(store, operation_id=operation_id)
        except AuthorityUnavailable:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(attempt, first, "op-a")
        b = pool.submit(attempt, second, "op-b")
        results = [a.result(), b.result()]
    assert sum(item is not None for item in results) == 1
    winner = next(item for item in results if item is not None)
    assert first.get_operation(winner.operation_id, subject="subject-a", namespace="ns-a")[1] == "active"
    db2.close()
    db1.close()
    db0.close()


def test_unknown_or_malformed_schema_never_migrates_implicitly(tmp_path):
    path = tmp_path / "service.db"
    with pytest.raises(AuthorityUnavailable):
        open_store(path)
    db, _ = open_store(path, create=True)
    db.execute("UPDATE authority_v2_meta SET value='future' WHERE key='schema_version'")
    db.close()
    with pytest.raises(AuthorityUnavailable):
        open_store(path, create=True)

    partial = tmp_path / "partial.db"
    db = sqlite3.connect(partial, isolation_level=None)
    db.execute("CREATE TABLE authority_v2_fences(operation_id TEXT)")
    db.close()
    with pytest.raises(AuthorityUnavailable):
        open_store(partial, create=True)


def test_corrupt_persisted_permit_is_not_accepted(tmp_path):
    db, store = open_store(tmp_path / "service.db", create=True)
    permit = begin(store)
    db.execute("UPDATE authority_v2_fences SET permit=? WHERE operation_id='op-a'", (b'{}',))
    with pytest.raises(AuthorityUnavailable):
        store.validate_fence(permit, subject="subject-a", current_anchor=anchor())
    db.close()
