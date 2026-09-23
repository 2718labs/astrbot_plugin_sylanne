"""Explicit 2→3 Authority mutation migration and strict typed reads."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1,
    FencePermitV2, MutationReceiptV2, PendingMutationV2, canonical_bytes,
    deletion_scope_digest,
)
from sylanne3.authority_service.v2_fence_store import (
    AuthorityV2FenceStore, _EPOCH_DDL, _FENCE_DDL, _INDEX_DDL,
    _META_DDL, _MUTATION_DDL_V2,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor


def digest(char):
    return "sha256:" + char * 64


def anchor():
    return RestoreAnchor(
        "authority-a", "ns-a", 2, "delete-a", 0, "genesis",
        "execution-a", 0, "genesis", 1, "proof-a")


def open_db(path):
    db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def legacy_schema(db):
    for ddl in (_META_DDL, _EPOCH_DDL, _FENCE_DDL, _INDEX_DDL, _MUTATION_DDL_V2):
        db.execute(ddl)
    db.execute("INSERT INTO authority_v2_meta VALUES('schema_version','2')")
    db.execute("INSERT INTO authority_v2_epochs VALUES('ns-a',1)")


def execution_objects():
    permit = FencePermitV2(
        authority_id="authority-a", namespace="ns-a", subject="subject-a",
        holder="holder-a", generation=2, operation="dispatch",
        operation_id="execution-fence-a", token="A" * 43,
        fence_epoch=1, revision=0, pinned_anchor=anchor(),
        effect_id="effect-a", command_digest=digest("a"),
        footprint_digest=digest("b"))
    pending = PendingMutationV2(
        permit=permit, mutation_id="execution-mutation-a",
        request_digest=digest("c"), phase="prepared", before_anchor=anchor(),
        expected_append_id="execution-append-a",
        expected_append_digest=digest("d"))
    after = replace(anchor(), execution_seq=1,
                    execution_digest=digest("d"), proof="proof-b")
    receipt = MutationReceiptV2(pending, after, 1, "committed")
    return permit, pending, receipt, replace(permit, revision=1,
                                             pinned_anchor=after)


def add_completed_execution(db):
    permit, pending, receipt, updated = execution_objects()
    db.execute("INSERT INTO authority_v2_fences VALUES(?,?,?,?,?,?,'finished',?,?,?,NULL)", (
        permit.operation_id, permit.namespace, permit.subject, permit.token,
        permit.fence_epoch, updated.revision, canonical_bytes(updated),
        "finish-a", digest("f")))
    db.execute("INSERT INTO authority_v2_mutations VALUES(?,?,?,?,?,'committed',?,?,?,?)", (
        pending.mutation_id, permit.operation_id, permit.namespace,
        permit.subject, pending.request_digest, '["resource-a"]',
        canonical_bytes(pending), canonical_bytes(receipt), canonical_bytes(updated)))
    return pending, receipt, updated


def test_explicit_upgrade_preserves_old_execution_bytes_and_kind(tmp_path):
    path = tmp_path / "authority.db"
    db = open_db(path)
    legacy_schema(db)
    pending, receipt, updated = add_completed_execution(db)
    old = db.execute("SELECT pending,receipt,updated_permit FROM authority_v2_mutations").fetchone()
    with pytest.raises(AuthorityUnavailable):
        AuthorityV2FenceStore(db)
    AuthorityV2FenceStore.upgrade_schema_2_to_3(db)
    assert db.execute("SELECT pending,receipt,updated_permit,mutation_kind,deletion_evidence FROM authority_v2_mutations").fetchone() == (*old, "execution", None)
    with pytest.raises(AuthorityUnavailable, match="version|migration"):
        AuthorityV2FenceStore(db)
    with pytest.raises(AuthorityUnavailable, match="footprint|HOLD"):
        AuthorityV2FenceStore.upgrade_schema_3_to_4(db)
    assert db.execute("SELECT value FROM authority_v2_meta").fetchone() == ("3",)
    db.close()
    reopened = open_db(path)
    with pytest.raises(AuthorityUnavailable, match="version|migration"):
        AuthorityV2FenceStore(reopened)
    assert reopened.execute("SELECT pending,receipt,updated_permit FROM authority_v2_mutations").fetchone() == old
    reopened.close()


def test_half_migration_and_live_fence_fail_closed(tmp_path):
    db = open_db(tmp_path / "half.db")
    legacy_schema(db)
    db.execute("UPDATE authority_v2_meta SET value='3'")
    with pytest.raises(AuthorityUnavailable):
        AuthorityV2FenceStore.upgrade_schema_2_to_3(db)
    with pytest.raises(AuthorityUnavailable):
        AuthorityV2FenceStore(db)
    db.close()

    db = open_db(tmp_path / "active.db")
    legacy_schema(db)
    permit = execution_objects()[0]
    db.execute("INSERT INTO authority_v2_fences(operation_id,namespace,subject,token,fence_epoch,revision,state,permit) VALUES(?,?,?,?,?,0,'active',?)", (
        permit.operation_id, permit.namespace, permit.subject, permit.token,
        permit.fence_epoch, canonical_bytes(permit)))
    with pytest.raises(AuthorityUnavailable, match="live fence"):
        AuthorityV2FenceStore.upgrade_schema_2_to_3(db)
    assert db.execute("SELECT value FROM authority_v2_meta").fetchone() == ("2",)
    db.close()

    db = open_db(tmp_path / "malformed-old-row.db")
    legacy_schema(db)
    add_completed_execution(db)
    db.execute("UPDATE authority_v2_mutations SET receipt=?", (b"{}",))
    with pytest.raises(AuthorityUnavailable, match="old execution mutation"):
        AuthorityV2FenceStore.upgrade_schema_2_to_3(db)
    assert db.execute("SELECT value FROM authority_v2_meta").fetchone() == ("2",)
    assert tuple(row[1] for row in db.execute(
        "PRAGMA table_info(authority_v2_mutations)"))[-1] == "updated_permit"
    db.close()


def deletion_objects(permit):
    evidence = DeletionEvidenceV1(
        authority_id="authority-a", namespace="ns-a",
        deletion_operation_id="deletion-operation-a",
        kind="request_authorized", issuer_id="issuer-a",
        evidence_id="evidence-a", bound_anchor=anchor(),
        request_digest=digest("a"),
        scope_digest=deletion_scope_digest(("root-a",), 1, "policy-a"),
        proof_digest=digest("b"))
    pending = DeletionPendingV1(
        permit=permit, mutation_id="deletion-mutation-a",
        request_digest=digest("a"),
        deletion_operation_id="deletion-operation-a",
        source_phase="absent", target_phase="pending",
        closure_roots=("root-a",), deletion_epoch=1,
        policy_ref="policy-a", before_anchor=anchor(),
        evidence=evidence, expected_append_id="deletion-append-a",
        expected_append_digest=digest("c"))
    after = replace(anchor(), deletion_seq=1,
                    deletion_digest=digest("c"), revocation_epoch=2,
                    proof="proof-b")
    receipt = DeletionMutationReceiptV1(pending, after, 1)
    return evidence, pending, receipt, replace(permit, revision=1,
                                               pinned_anchor=after)


def test_deletion_rows_are_strictly_readable_but_no_dto_write_api(tmp_path):
    db = open_db(tmp_path / "authority.db")
    store = AuthorityV2FenceStore(db, create=True)
    permit = store.begin_fence(
        subject="subject-a", holder="holder-a", operation="delete",
        operation_id="delete-fence-a", current_anchor=anchor())
    evidence, pending, receipt, updated = deletion_objects(permit)
    with pytest.raises(AuthorityUnavailable, match="invalid pending mutation"):
        store.record_pending(pending, subject="subject-a", current_anchor=anchor())
    # Direct SQL is a test fixture only; no service deletion admission exists.
    db.execute("UPDATE authority_v2_fences SET pending=? WHERE operation_id=?",
               (canonical_bytes(pending), permit.operation_id))
    db.execute("INSERT INTO authority_v2_mutations VALUES(?,?,?,?,?,'pending','null',?,NULL,NULL,'deletion',?,NULL)", (
        pending.mutation_id, permit.operation_id, permit.namespace,
        permit.subject, pending.request_digest, canonical_bytes(pending),
        canonical_bytes(evidence)))
    assert store.get_operation(permit.operation_id, subject="subject-a",
                               namespace="ns-a")[2] == pending
    assert store.get_mutation(pending.mutation_id, subject="subject-a",
                              namespace="ns-a") == ("deletion", pending, None, None)
    db.execute("UPDATE authority_v2_mutations SET deletion_evidence=? WHERE mutation_id=?",
               (canonical_bytes(replace(evidence, proof_digest=digest("f"))),
                pending.mutation_id))
    with pytest.raises(AuthorityUnavailable, match="persisted mutation"):
        store.get_operation(permit.operation_id, subject="subject-a", namespace="ns-a")
    db.execute("UPDATE authority_v2_mutations SET deletion_evidence=? WHERE mutation_id=?",
               (canonical_bytes(evidence), pending.mutation_id))
    db.execute("UPDATE authority_v2_fences SET revision=1,permit=?,pending=NULL WHERE operation_id=?",
               (canonical_bytes(updated), permit.operation_id))
    db.execute("UPDATE authority_v2_mutations SET state='committed',receipt=?,updated_permit=? WHERE mutation_id=?",
               (canonical_bytes(receipt), canonical_bytes(updated), pending.mutation_id))
    assert store.get_mutation(pending.mutation_id, subject="subject-a",
                              namespace="ns-a") == ("deletion", pending, receipt, updated)
    db.execute("UPDATE authority_v2_mutations SET receipt=? WHERE mutation_id=?",
               (canonical_bytes(execution_objects()[2]), pending.mutation_id))
    with pytest.raises(AuthorityUnavailable, match="persisted mutation"):
        store.get_mutation(pending.mutation_id, subject="subject-a", namespace="ns-a")
    db.close()


def test_locked_validate_and_finish_preserve_completed_retry_semantics(tmp_path):
    db = open_db(tmp_path / "authority.db")
    store = AuthorityV2FenceStore(db, create=True)
    first = store.begin_fence(subject="subject-a", holder="holder-a",
                              operation="read", operation_id="read-a",
                              current_anchor=anchor())
    with store._tx() as tx:
        assert store.validate_fence_locked(
            tx, first, subject="subject-a", current_anchor=anchor()) == first
        store.finish_fence_locked(
            tx, first, subject="subject-a", current_anchor=anchor(),
            request_id="finish-a", request_digest=digest("f"))
    later_anchor = replace(anchor(), proof="new-proof")
    store.begin_fence(subject="subject-a", holder="holder-a", operation="read",
                      operation_id="read-b", current_anchor=later_anchor)
    with store._tx() as tx:
        store.finish_fence_locked(
            tx, first, subject="subject-a", current_anchor=later_anchor,
            request_id="finish-a", request_digest=digest("f"))
        with pytest.raises(AuthorityUnavailable, match="absent or finished"):
            store.validate_fence_locked(
                tx, first, subject="subject-a", current_anchor=later_anchor)
    db.close()
