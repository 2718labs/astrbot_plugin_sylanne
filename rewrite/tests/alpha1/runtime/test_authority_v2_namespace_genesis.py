"""An administrator explicitly activates a fresh v2 namespace once."""

import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId, NamespaceRuntimeState


NAMESPACE_ID = NamespaceId("bot-a", "persona-a")


def open_service(path, *, create=False, execution_journal_id="execution-a"):
    seed = DeletionJournal(path / "seed-deletion.db", create=create)
    deletion = DeletionJournal(path / "deletion.db", create=create)
    guard = AuthorityV2DeletionGuard(path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        path / "execution.db", namespace="ns-a", journal_id=execution_journal_id, create=create)
    seed_head = seed.latest_head()
    seed_head = JournalHead(seed_head.journal_id, seed_head.seq, seed_head.chain_digest)
    refs = {}
    actions = []

    def authorize(credential, action, namespace, holder):
        actions.append(action)
        core = refs.get("core")
        assert core is None or not core._db.in_transaction
        assert not guard._db.in_transaction
        assert execution._guard_owner is None
        return credential == "admin"

    core = AuthorityServiceCore(
        path / "authority.db", create=create, authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase: (
            ns == "ns-seed" and current == seed_head and phase == "clear"),
        execution_verifier=lambda ns, before, current, phase: (
            ns == "ns-seed" and current == JournalHead("seed-execution", 0, "genesis")),
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    refs["core"] = core
    if create:
        core.register_namespace("admin", "ns-seed", "seed-holder", seed_head,
                                JournalHead("seed-execution", 0, "genesis"))
        core.seal_v2_only("admin")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution, namespace="ns-a")
    return service, core, seed, deletion, guard, execution, actions


def close_bundle(bundle):
    _, core, seed, deletion, guard, execution, _ = bundle
    core.close()
    seed.close()
    deletion.close()
    guard.close()
    execution.close()


def activate(service, *, credential="admin", subject="admin-subject", holder="holder-a",
             namespace_id=NAMESPACE_ID, request_id="genesis-a"):
    return service.activate_namespace(
        credential=credential, subject=subject, holder=holder,
        namespace_id=namespace_id, request_id=request_id)


def test_explicit_genesis_is_durable_and_returns_full_anchor(tmp_path):
    bundle = open_service(tmp_path, create=True)
    service, core, _, _, _, _, actions = bundle
    before = service.namespace_bootstrap(
        credential="admin", subject="admin-subject", namespace_id=NAMESPACE_ID)
    assert before.state is NamespaceRuntimeState.UNBOUND
    assert core._db.execute(
        "SELECT 1 FROM authority_namespaces WHERE namespace='ns-a'").fetchone() is None

    result = activate(service)
    assert result.state is NamespaceRuntimeState.ACTIVE
    assert result.holder == "holder-a" and result.generation == 1
    assert result.anchor == service.current_anchor(
        credential="admin", subject="admin-subject")
    assert result.anchor.deletion_seq == result.anchor.execution_seq == 0
    assert result.anchor.deletion_digest == result.anchor.execution_digest == "genesis"
    assert result.anchor.proof and result.anchor.authority_id
    assert activate(service) == result
    assert actions.count("namespace_genesis") == 2
    assert core._db.execute(
        "SELECT count(*) FROM authority_events WHERE namespace='ns-a'").fetchone() == (1,)
    close_bundle(bundle)

    reopened = open_service(tmp_path)
    try:
        assert activate(reopened[0]) == result
        assert reopened[1]._db.execute(
            "SELECT count(*) FROM authority_events WHERE namespace='ns-a'").fetchone() == (1,)
        with pytest.raises(AuthorityUnavailable, match="different parameters"):
            activate(reopened[0], holder="other-holder")
        with pytest.raises(AuthorityUnavailable, match="different parameters"):
            activate(reopened[0], namespace_id=NamespaceId("bot-b", "persona-a"))
        with pytest.raises(AuthorityUnavailable, match="different parameters"):
            activate(reopened[0], subject="other-subject")
        with pytest.raises(AuthorityUnavailable, match="Authority history"):
            activate(reopened[0], request_id="new-request")
    finally:
        close_bundle(reopened)


def test_authentication_denial_never_enters_writer_guards(tmp_path):
    bundle = open_service(tmp_path, create=True)
    try:
        with pytest.raises(AuthorityUnavailable, match="authentication denied"):
            activate(bundle[0], credential="denied")
        assert bundle[1]._db.execute(
            "SELECT 1 FROM authority_namespaces WHERE namespace='ns-a'").fetchone() is None
    finally:
        close_bundle(bundle)


def test_genesis_rejects_execution_journal_identity_owned_by_another_namespace(tmp_path):
    bundle = open_service(tmp_path, create=True, execution_journal_id="seed-execution")
    seed_execution = AuthorityV2ExecutionJournal(
        tmp_path / "seed-execution.db", namespace="ns-seed",
        journal_id="seed-execution", create=True)
    try:
        assert seed_execution.path != bundle[5].path
        assert seed_execution.verified_head() == bundle[5].verified_head()
        with pytest.raises(AuthorityUnavailable, match="execution journal already belongs"):
            activate(bundle[0])
        assert bundle[1]._db.execute(
            "SELECT 1 FROM authority_namespaces WHERE namespace='ns-a'").fetchone() is None
    finally:
        seed_execution.close()
        close_bundle(bundle)


@pytest.mark.parametrize("blocker", [
    "deletion_history", "existing_namespace", "old_history",
    "active_fence", "pending_mutation", "migration",
])
def test_genesis_rejects_unsettled_or_used_namespace(tmp_path, blocker):
    bundle = open_service(tmp_path, create=True)
    service, core, _, deletion, _, _, _ = bundle
    try:
        if blocker == "deletion_history":
            deletion.append_intent(
                namespace="ns-a", operation_id="delete-a", closure_roots=("item-a",),
                epoch=1, policy_ref="policy-a")
        elif blocker == "existing_namespace":
            core._db.execute(
                "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("ns-a", "holder-a", 1, "active", None, None, 0,
                 "delete-a", 0, "genesis", "clear", "execution-a", 0,
                 "genesis", "nonce-a"))
        elif blocker == "old_history":
            core._db.execute(
                "INSERT INTO authority_events(namespace,kind,generation,detail_digest) VALUES(?,?,?,?)",
                ("ns-a", "install", 1, "history"))
        elif blocker == "active_fence":
            core._db.execute("INSERT INTO authority_v2_epochs VALUES('ns-a',1)")
            core._db.execute(
                "INSERT INTO authority_v2_fences(operation_id,namespace,subject,token,"
                "fence_epoch,revision,state,permit) VALUES(?,?,?,?,1,0,'active',?)",
                ("operation-a", "ns-a", "subject-a", "token-a", b"invalid"))
        elif blocker == "pending_mutation":
            # Direct SQL fixture tests ledger occupancy; genesis does not decode it.
            core._db.execute(
                "INSERT INTO authority_v2_mutations(mutation_id,operation_id,namespace,subject,"
                "request_digest,state,conflict_keys_json,pending,mutation_kind,footprint) "
                "VALUES(?,?,?,?,?,'pending','[]',?,'execution',?)",
                ("mutation-a", "operation-a", "ns-a", "subject-a", "sha256:" + "a" * 64,
                 b"pending", b"fixture-footprint"))
        else:
            core._db.execute(
                "INSERT INTO authority_meta(key,value) VALUES('deletion_v2_migration',?)",
                (json.dumps({"schema": "sylanne3.deletion-migration.v1", "stage": "blocked"}),))
        with pytest.raises(AuthorityUnavailable):
            activate(service)
        assert core._db.execute(
            "SELECT 1 FROM authority_meta WHERE key='v2_namespace_genesis_request:genesis-a'").fetchone() is None
    finally:
        close_bundle(bundle)
