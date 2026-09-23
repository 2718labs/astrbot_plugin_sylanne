"""Protected B2.3c fence lifecycle; the store alone is not a trust root."""

from dataclasses import replace
import hashlib
import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_contract import PendingMutationV2, to_wire
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def digest(char):
    return "sha256:" + char * 64


def prepare_request_digest(permit, item):
    material = json.dumps({
        "permit": to_wire(permit), "mutation_id": "mutation-a",
        "footprint": json.loads(item._json()), "phase": "prepared",
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()


@pytest.fixture
def installed(tmp_path):
    deletion_journal = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_head = deletion_journal.latest_head()
    deletion_anchor = JournalHead(deletion_head.journal_id, deletion_head.seq,
                                  deletion_head.chain_digest)
    opened = []

    def connect(*, create=False):
        deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
        execution = AuthorityV2ExecutionJournal(
            tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
            create=create)
        core = AuthorityServiceCore(
            tmp_path / "authority.db", create=create,
            authorizer=lambda credential, action, namespace, holder: credential == "ok",
            deletion_verifier=lambda ns, before, current, phase:
                current == deletion_anchor and phase == "clear",
            execution_verifier=lambda ns, before, current, phase:
                execution.verified_head() == current,
            effect_verifier=lambda *args: True,
            dispatch_verifier=lambda *args: True,
        )
        if create:
            core.register_namespace("ok", "ns-a", "holder-a", deletion_anchor,
                                    JournalHead("execution-a", 0, "genesis"))
            core.seal_v2_only("ok")
        fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        opened.append((core, deletion, execution))
        return service, fences, core, execution

    try:
        yield connect, deletion_journal
    finally:
        for core, deletion, execution in reversed(opened):
            core.close()
            deletion.close()
            execution.close()
        deletion_journal.close()


def begin(service, *, operation="read", operation_id="operation-a",
          subject="subject-a"):
    anchor = service.current_anchor(credential="ok", subject=subject)
    fields = {}
    if operation == "dispatch":
        fields = dict(effect_id="effect-a", command_digest=digest("a"),
                      footprint=RecoveryConstraintFootprint(
                          namespace="ns-a", activity_id="activity-a",
                          effect_id="effect-a", conflict_keys=("resource-a",)))
    return service.begin_fence(
        credential="ok", subject=subject, holder="holder-a",
        operation=operation, operation_id=operation_id, expected_anchor=anchor,
        **fields)


def validate(service, permit, *, subject="subject-a", credential="ok"):
    return service.validate_fence(credential=credential, subject=subject,
                                  permit=permit)


def finish(service, permit, *, subject="subject-a", credential="ok",
           request_id="finish-a", request_digest=None):
    return service.finish_fence(
        credential=credential, subject=subject, permit=permit,
        request_id=request_id, request_digest=request_digest or digest("f"))


def test_two_connections_validate_finish_and_lost_response_retry(installed):
    connect, _ = installed
    first, _, _, _ = connect(create=True)
    second, fences, core, _ = connect()
    permit = begin(first)
    assert validate(second, permit) == permit
    assert finish(second, permit) is None
    assert finish(first, permit) is None  # Identical request after lost response.
    assert fences.get_operation("operation-a", subject="subject-a",
                                namespace="ns-a") == (permit, "finished", None)
    with pytest.raises(AuthorityUnavailable):
        validate(first, permit)  # A finish replay never restores read authority.
    # Model a later Authority proof rotation while both independent heads stay verified.
    with core._tx() as db:
        db.execute("UPDATE authority_namespaces SET anchor_nonce=? WHERE namespace=?",
                   (core._new_nonce(), "ns-a"))
    assert second.current_anchor(credential="ok", subject="subject-a") != permit.pinned_anchor
    with pytest.raises(AuthorityUnavailable):
        validate(second, permit)
    assert finish(first, permit) is None  # Historical acknowledgment, not live authority.
    newer = begin(second, operation_id="operation-b")
    assert newer.fence_epoch == permit.fence_epoch + 1
    assert finish(first, permit) is None  # Durable completion survives a new fence.
    with pytest.raises(AuthorityUnavailable):
        finish(first, permit, request_id="finish-conflict")
    with pytest.raises(AuthorityUnavailable):
        finish(first, permit, request_digest=digest("e"))


def test_subject_credential_revision_and_pending_fail_closed(installed):
    connect, _ = installed
    service, fences, _, _ = connect(create=True)
    permit = begin(service, operation="dispatch")
    for action in (validate, finish):
        with pytest.raises(AuthorityUnavailable):
            action(service, permit, subject="subject-b")
        with pytest.raises(AuthorityUnavailable, match="authentication denied"):
            action(service, permit, credential="bad")
        with pytest.raises(AuthorityUnavailable):
            action(service, replace(permit, revision=1))
        with pytest.raises(AuthorityUnavailable):
            action(service, replace(permit, holder="holder-b"))
        with pytest.raises(AuthorityUnavailable):
            action(service, replace(
                permit, pinned_anchor=replace(permit.pinned_anchor, proof="wrong")))
    item = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    pending = PendingMutationV2(
        permit=permit, mutation_id="mutation-a",
        request_digest=prepare_request_digest(permit, item),
        phase="prepared", before_anchor=permit.pinned_anchor,
        expected_append_id="append-a", expected_append_digest=digest("d"))
    assert fences.record_pending(
        pending, subject="subject-a", current_anchor=permit.pinned_anchor,
        footprint=item) == pending
    with pytest.raises(AuthorityUnavailable, match="pending"):
        validate(service, permit)
    with pytest.raises(AuthorityUnavailable, match="pending"):
        finish(service, permit)
    assert fences.get_operation("operation-a", subject="subject-a",
                                namespace="ns-a")[1:] == ("active", pending)


def test_independent_deletion_drift_and_migration_blocker(installed):
    connect, deletion_journal = installed
    service, fences, core, _ = connect(create=True)
    permit = begin(service)
    deletion_journal.append_intent(
        namespace="ns-a", operation_id="delete-a", closure_roots=("item-a",),
        epoch=1, policy_ref="policy-a")
    for action in (validate, finish):
        with pytest.raises(AuthorityUnavailable, match="behind or differs"):
            action(service, permit)
    # The bare store still sees only the caller-supplied, now-stale anchor.
    assert fences.validate_fence(
        permit, subject="subject-a", current_anchor=permit.pinned_anchor) == permit
    assert fences.get_operation("operation-a", subject="subject-a",
                                namespace="ns-a")[1] == "active"
    with core._tx() as db:
        db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)", (
            "deletion_v2_migration", json.dumps({
                "schema": "sylanne3.deletion-migration.v1", "stage": "blocked"})))
    for action in (validate, finish):
        with pytest.raises(AuthorityUnavailable, match="migration"):
            action(service, permit)


def test_execution_journal_drift_rejects_live_permit(installed):
    connect, _ = installed
    service, fences, _, execution = connect(create=True)
    permit = begin(service, operation="dispatch")
    draft = PendingMutationV2(
        permit=permit, mutation_id="mutation-a", request_digest=digest("c"),
        phase="prepared", before_anchor=permit.pinned_anchor,
        expected_append_id="append-a", expected_append_digest=digest("d"))
    execution.append_once(replace(
        draft, expected_append_digest=execution.expected_digest(draft)))
    for action in (validate, finish):
        with pytest.raises(AuthorityUnavailable, match="behind or differs"):
            action(service, permit)
    assert fences.get_operation("operation-a", subject="subject-a",
                                namespace="ns-a")[1] == "active"
