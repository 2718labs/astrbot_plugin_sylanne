"""Schema-2 deletion tail upgrade keeps the Authority blocker durable."""

import json
import hashlib
import sqlite3
from dataclasses import replace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_deletion_recovery_service import (
    AuthorityV2DeletionPendingRecovery,
)
from sylanne3.authority_service.v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1, canonical_bytes,
    deletion_scope_digest,
)
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def bundle(path, *, create=False, old_history=True):
    journal = DeletionJournal(path / "deletion.db", create=create)
    if create and old_history:
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
            "INSERT INTO deletion_events(seq,namespace,operation_id,roots_json,epoch,"
            "policy_ref,phase,prev_digest,chain_digest) VALUES"
            "(2,'ns-a','external-old','[\"root\"]',2,'policy-a','pending',"
            "'prior','digest')",
            "UPDATE deletion_events SET phase='closed' WHERE seq=1",
            "DELETE FROM deletion_events WHERE seq=1",
            "INSERT INTO authority_deletion_v2_tail(seq,schema,kind,append_id,"
            "mutation_id,request_digest,namespace,operation_id,phase,subject,holder,"
            "token_digest,fence_epoch,revision,before_seq,before_digest,"
            "evidence_digest,roots_json,epoch,policy_ref,prev_digest,chain_digest) "
            "VALUES(2,'sylanne3.deletion-tail.v2','deletion','external-append',"
            "'external-mutation','request','ns-a','external-delete','pending',"
            "'subject-a','holder-a','token',1,0,1,'prior','evidence',"
            "'[\"root\"]',2,'policy-a','prior','digest')",
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


def _pending(parts, *, direct_fence=False, fence_id="delete-fence-a",
             mutation_id="deletion-mutation-a", append_id="deletion-append-a",
             deletion_operation_id="deletion-operation-a"):
    core, fences, _, guard, execution, _, _ = parts
    if direct_fence:
        with core._tx() as db:
            anchor = core._anchor(db, "ns-a", core._row(db, "ns-a"))
        permit = fences.begin_fence(
            subject="subject-a", holder="holder-a", operation="delete",
            operation_id=fence_id, current_anchor=anchor)
    else:
        service = AuthorityV2FenceService(core=core, fences=fences, deletion=guard,
                                          execution=execution, namespace="ns-a")
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id=fence_id, expected_anchor=anchor)
    request_digest = "sha256:" + "a" * 64
    evidence = DeletionEvidenceV1(
        authority_id=permit.authority_id, namespace="ns-a",
        deletion_operation_id=deletion_operation_id, kind="request_authorized",
        issuer_id="test-trusted-issuer", evidence_id="evidence-a",
        bound_anchor=anchor, request_digest=request_digest,
        scope_digest=deletion_scope_digest(("root-a",), 1, "policy-a"),
        proof_digest="sha256:" + "b" * 64)
    draft = DeletionPendingV1(
        permit=permit, mutation_id=mutation_id,
        request_digest=request_digest, deletion_operation_id=deletion_operation_id,
        source_phase="absent", target_phase="pending",
        closure_roots=("root-a",), deletion_epoch=1, policy_ref="policy-a",
        before_anchor=anchor, evidence=evidence,
        expected_append_id=append_id,
        expected_append_digest="sha256:" + "0" * 64)
    pending = replace(draft, expected_append_digest=guard.expected_digest(draft))
    return pending


def _persist_fixture_pending(parts, pending):
    # Direct SQL is confined to the test fixture; no trusted D12 issuer API exists yet.
    core = parts[0]
    with core._tx() as db:
        db.execute("UPDATE authority_v2_fences SET pending=? WHERE operation_id=?",
                   (canonical_bytes(pending), pending.permit.operation_id))
        db.execute("INSERT INTO authority_v2_mutations(mutation_id,operation_id,namespace,subject,request_digest,state,conflict_keys_json,pending,mutation_kind,deletion_evidence) VALUES(?,?,?,?,?,'pending','null',?,'deletion',?)",
                   (pending.mutation_id, pending.permit.operation_id,
                    pending.permit.namespace, pending.permit.subject,
                    pending.request_digest, canonical_bytes(pending),
                    canonical_bytes(pending.evidence)))


def _recovery(parts):
    return AuthorityV2DeletionPendingRecovery(
        core=parts[0], fences=parts[1], deletion=parts[3],
        execution=parts[4], namespace="ns-a")


def test_original_pending_recovery_holds_without_append_then_commits_once(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=False)
    try:
        parts[5].run(credential="ok")
        parts[6].run(credential="ok")
        pending = _pending(parts)
        _persist_fixture_pending(parts, pending)
        recovery = _recovery(parts)
        assert recovery.recover(credential="ok", subject="subject-a",
                                mutation_id=pending.mutation_id) is None
        assert parts[1].get_mutation(pending.mutation_id, subject="subject-a",
                                     namespace="ns-a")[2] is None
        with parts[0]._tx() as db:
            before = parts[0]._anchor(db, "ns-a", parts[0]._row(db, "ns-a"))
            assert before == pending.before_anchor
        with pytest.raises(AuthorityUnavailable):
            AuthorityV2FenceService(core=parts[0], fences=parts[1],
                                    deletion=parts[3], execution=parts[4],
                                    namespace="ns-a").current_anchor(
                                        credential="ok", subject="subject-a")

        parts[3].append_pending(pending, core=parts[0], fences=parts[1])
        receipt = recovery.recover(credential="ok", subject="subject-a",
                                   mutation_id=pending.mutation_id)
        assert type(receipt) is DeletionMutationReceiptV1
        assert receipt.pending == pending
        assert receipt.after_anchor.deletion_seq == pending.expected_deletion_seq
        assert receipt.after_anchor.deletion_digest == pending.expected_append_digest
        assert receipt.after_anchor.revocation_epoch == before.revocation_epoch + 1
        assert receipt.updated_revision == pending.permit.revision + 1
        with parts[0]._tx() as db:
            row = parts[0]._row(db, "ns-a")
            assert row[9] == "pending"
            assert parts[0]._anchor(db, "ns-a", row) == receipt.after_anchor
        assert recovery.recover(credential="ok", subject="subject-a",
                                mutation_id=pending.mutation_id) == receipt
        with parts[3].freeze_writes():
            assert parts[3].verified_head().seq == pending.expected_deletion_seq
        kind, saved, stored, updated = parts[1].get_mutation(
            pending.mutation_id, subject="subject-a", namespace="ns-a")
        assert kind == "deletion" and saved == pending and stored == receipt
        assert updated.pinned_anchor == receipt.after_anchor
        with pytest.raises(AuthorityUnavailable):
            AuthorityV2FenceService(core=parts[0], fences=parts[1],
                                    deletion=parts[3], execution=parts[4],
                                    namespace="ns-a").current_anchor(
                                        credential="ok", subject="subject-a")
    finally:
        close(parts)


def test_original_pending_recovery_after_restart_and_authority_rollback(
        tmp_path, monkeypatch):
    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    pending = _pending(parts)
    _persist_fixture_pending(parts, pending)
    parts[3].append_pending(pending, core=parts[0], fences=parts[1])
    close(parts)

    resumed = bundle(tmp_path)
    try:
        recovery = _recovery(resumed)
        def fail_after_head_update(*args, **kwargs):
            raise AuthorityUnavailable("injected Authority result write failure")

        with monkeypatch.context() as patcher:
            patcher.setattr(resumed[1], "finish_deletion_mutation_locked",
                            fail_after_head_update)
            with pytest.raises(AuthorityUnavailable, match="injected Authority"):
                recovery.recover(credential="ok", subject="subject-a",
                                 mutation_id=pending.mutation_id)
        with resumed[0]._tx() as db:
            row = resumed[0]._row(db, "ns-a")
            assert row[9] == "clear"
            assert resumed[0]._anchor(db, "ns-a", row) == pending.before_anchor
        assert resumed[1].get_mutation(
            pending.mutation_id, subject="subject-a", namespace="ns-a")[2] is None
        with pytest.raises(AuthorityUnavailable):
            recovery.recover(credential="bad", subject="subject-a",
                             mutation_id=pending.mutation_id)
        with pytest.raises(AuthorityUnavailable):
            recovery.recover(credential="ok", subject="subject-b",
                             mutation_id=pending.mutation_id)
        receipt = recovery.recover(credential="ok", subject="subject-a",
                                   mutation_id=pending.mutation_id)
        assert receipt.after_anchor.deletion_digest == pending.expected_append_digest
    finally:
        close(resumed)

    completed = bundle(tmp_path)
    try:
        assert _recovery(completed).recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id) == receipt
        with completed[3].freeze_writes():
            assert completed[3].verified_head().seq == 1
    finally:
        close(completed)


def test_schema2_append_requires_persisted_exact_pending_and_retries(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    pending = _pending(parts)
    guard = parts[3]
    with pytest.raises(AuthorityUnavailable, match="durably owned"):
        guard.append_pending(pending, core=parts[0], fences=parts[1])
    barrier_evidence = replace(
        pending.evidence, kind="barrier_installed", graph_version="graph-a",
        incarnation="incarnation-a", access_epoch=1, deletion_epoch=1,
        barrier_scope_digest="sha256:" + "c" * 64)
    barrier_pending = replace(
        pending, source_phase="pending", target_phase="accepted",
        evidence=barrier_evidence)
    with pytest.raises(AuthorityUnavailable, match="remain HOLD"):
        guard.append_pending(barrier_pending, core=parts[0], fences=parts[1])
    with guard.freeze_writes():
        assert guard.verified_head().seq == 0
    _persist_fixture_pending(parts, pending)
    assert guard.inspect_pending(pending, core=parts[0], fences=parts[1]) is None
    result = guard.append_pending(pending, core=parts[0], fences=parts[1])
    assert (result.seq, result.append_id, result.mutation_id, result.digest) == (
        1, pending.expected_append_id, pending.mutation_id,
        pending.expected_append_digest)
    assert guard.append_pending(pending, core=parts[0], fences=parts[1]) == result
    assert guard.inspect_pending(pending, core=parts[0], fences=parts[1]) == result
    with pytest.raises(AuthorityUnavailable):
        guard.append_pending(replace(pending, expected_append_id="other-append",
                                     expected_append_digest="sha256:" + "f" * 64),
                             core=parts[0], fences=parts[1])
    with guard.freeze_writes():
        assert guard.verified_head().seq == 1
    close(parts)
    reopened = bundle(tmp_path)
    assert reopened[3].inspect_pending(
        pending, core=reopened[0], fences=reopened[1]) == result
    assert reopened[3].append_pending(
        pending, core=reopened[0], fences=reopened[1]) == result
    close(reopened)


def test_schema1_snapshot_after_upgrade_cannot_reenter_v2_service(tmp_path):
    from sylanne3.authority_service.v2_deletion_guard import (
        _TAIL_TRIGGERS, _TAIL_TRIGGERS_V2, _V2_TAIL_DDL)

    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    service = AuthorityV2FenceService(
        core=parts[0], fences=parts[1], deletion=parts[3],
        execution=parts[4], namespace="ns-a")
    anchor = service.current_anchor(credential="ok", subject="subject-a")
    assert anchor.deletion_seq == 0
    with parts[3].freeze_writes():
        db = parts[3]._db
        for name in _TAIL_TRIGGERS_V2:
            db.execute(f"DROP TRIGGER {name}")
        db.execute("DROP TABLE authority_deletion_v2_tail")
        db.execute(_V2_TAIL_DDL)
        for ddl in _TAIL_TRIGGERS.values():
            db.execute(ddl)
        db.execute("UPDATE authority_deletion_v2_meta SET value='1' WHERE key='schema_version'")
    with pytest.raises(AuthorityUnavailable, match="schema rollback"):
        service.current_anchor(credential="ok", subject="subject-a")
    with pytest.raises(AuthorityUnavailable, match="schema rollback"):
        service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="read", operation_id="read-a",
            expected_anchor=anchor)
    bridge = AuthorityV2ExecutionBridge(
        core=parts[0], fences=parts[1], journal=parts[4],
        deletion=parts[3], namespace="ns-a")
    footprint = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    footprint_digest = "sha256:" + hashlib.sha256(
        footprint._json().encode()).hexdigest()
    permit = parts[1].begin_fence(
        subject="subject-a", holder="holder-a", operation="dispatch",
        current_anchor=anchor, operation_id="dispatch-a", effect_id="effect-a",
        command_digest="sha256:" + "a" * 64,
        footprint_digest=footprint_digest)
    with pytest.raises(AuthorityUnavailable, match="schema rollback"):
        bridge.prepare_pending(
            credential="ok", subject="subject-a", permit=permit,
            mutation_id="execution-mutation-a", footprint=footprint)
    close(parts)


def test_schema2_resume_and_completion_reject_wrong_namespace(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].begin_block(credential="ok")
    with parts[3].freeze_writes():
        parts[3]._db.execute(
            "UPDATE authority_deletion_v2_meta SET value='ns-b' WHERE key='namespace'")
    with pytest.raises(AuthorityUnavailable, match="namespace differs"):
        parts[6].migrate_journal(credential="ok")
    with parts[0]._tx() as db:
        assert json.loads(db.execute(
            "SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone()[0])["stage"] == "tail-blocked"
    close(parts)

    parts = bundle(tmp_path)
    with parts[3].freeze_writes():
        parts[3]._db.execute(
            "UPDATE authority_deletion_v2_meta SET value='ns-a' WHERE key='namespace'")
    parts[6].migrate_journal(credential="ok")
    with parts[3].freeze_writes():
        parts[3]._db.execute(
            "UPDATE authority_deletion_v2_meta SET value='ns-b' WHERE key='namespace'")
    with pytest.raises(AuthorityUnavailable, match="namespace differs"):
        parts[6].complete(credential="ok")
    close(parts)


def test_extra_valid_chain_entry_quarantines_pending_inspection(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    pending = _pending(parts)
    _persist_fixture_pending(parts, pending)
    guard = parts[3]
    guard.append_pending(pending, core=parts[0], fences=parts[1])
    with guard.freeze_writes():
        db = guard._db
        row = db.execute("SELECT * FROM authority_deletion_v2_tail WHERE seq=1").fetchone()
        body = dict(
            seq=2, schema=row[1], kind=row[2], append_id="other-append",
            mutation_id="other-mutation", request_digest=row[5],
            namespace=row[6], operation_id="other-delete", phase=row[8],
            subject=row[9], holder=row[10], token_digest=row[11],
            fence_epoch=row[12], revision=row[13], before_seq=1,
            before_digest=row[21], evidence_digest=row[16],
            roots=json.loads(row[17]), epoch=row[18], policy_ref=row[19],
            previous=row[21])
        digest = "sha256:" + hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        guard._append_allowed = True
        try:
            db.execute("INSERT INTO authority_deletion_v2_tail VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (2, body["schema"], body["kind"], body["append_id"],
                        body["mutation_id"], body["request_digest"], body["namespace"],
                        body["operation_id"], body["phase"], body["subject"],
                        body["holder"], body["token_digest"], body["fence_epoch"],
                        body["revision"], body["before_seq"], body["before_digest"],
                        body["evidence_digest"], row[17], body["epoch"],
                        body["policy_ref"], body["previous"], digest))
        finally:
            guard._append_allowed = False
        assert guard.verified_head().seq == 2
    with pytest.raises(AuthorityUnavailable, match="extra or mismatched"):
        guard.inspect_pending(pending, core=parts[0], fences=parts[1])
    with pytest.raises(AuthorityUnavailable, match="extra or mismatched"):
        _recovery(parts).recover(credential="ok", subject="subject-a",
                                 mutation_id=pending.mutation_id)
    with parts[0]._tx() as db:
        assert parts[0]._anchor(db, "ns-a", parts[0]._row(db, "ns-a")) == pending.before_anchor
    close(parts)


def test_historical_prefix_pending_blocks_duplicate_operation_before_append(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=True)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    pending = _pending(parts, direct_fence=True,
                       deletion_operation_id="old-delete")
    _persist_fixture_pending(parts, pending)
    with pytest.raises(AuthorityUnavailable, match="already has history"):
        parts[3].append_pending(pending, core=parts[0], fences=parts[1])
    with parts[3].freeze_writes():
        assert parts[3].verified_head().seq == pending.before_anchor.deletion_seq
    close(parts)


def test_schema2_tail_pending_blocks_duplicate_operation_before_append(tmp_path):
    parts = bundle(tmp_path, create=True, old_history=False)
    parts[5].run(credential="ok")
    parts[6].run(credential="ok")
    first = _pending(parts)
    _persist_fixture_pending(parts, first)
    parts[3].append_pending(first, core=parts[0], fences=parts[1])
    # Fixture only: simulate an Authority CAS so a second durable fence can be
    # formed for the same deletion operation. The real CAS is not implemented.
    with parts[0]._tx() as db:
        db.execute("UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,revocation_epoch=revocation_epoch+1,anchor_nonce=? WHERE namespace='ns-a'",
                   (first.expected_deletion_seq, first.expected_append_digest,
                    parts[0]._new_nonce()))
        after = parts[0]._anchor(db, "ns-a", parts[0]._row(db, "ns-a"))
        receipt = DeletionMutationReceiptV1(first, after, 1)
        updated = replace(first.permit, revision=1, pinned_anchor=after)
        db.execute("UPDATE authority_v2_fences SET state='finished',revision=1,permit=?,pending=NULL,finish_request_id='fixture-finish',finish_request_digest=? WHERE operation_id=?",
                   (canonical_bytes(updated), "sha256:" + "f" * 64,
                    first.permit.operation_id))
        db.execute("UPDATE authority_v2_mutations SET state='committed',receipt=?,updated_permit=? WHERE mutation_id=?",
                   (canonical_bytes(receipt), canonical_bytes(updated), first.mutation_id))
    duplicate = _pending(parts, direct_fence=True, fence_id="delete-fence-b",
                         mutation_id="deletion-mutation-b", append_id="deletion-append-b")
    _persist_fixture_pending(parts, duplicate)
    with pytest.raises(AuthorityUnavailable, match="already has history"):
        parts[3].append_pending(duplicate, core=parts[0], fences=parts[1])
    with parts[3].freeze_writes():
        assert parts[3].verified_head().seq == first.expected_deletion_seq
    close(parts)
