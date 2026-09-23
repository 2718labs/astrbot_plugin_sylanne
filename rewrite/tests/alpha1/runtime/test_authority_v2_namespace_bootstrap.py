"""Namespace bootstrap observes durable Authority state without activating it."""

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId, NamespaceRuntimeState


_ID = NamespaceId("bot-a", "persona-a")


@pytest.fixture
def installed(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a", create=True)
    raw_head = deletion.latest_head()
    deletion_head = JournalHead(raw_head.journal_id, raw_head.seq, raw_head.chain_digest)
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, *args: credential == "ok",
        deletion_verifier=lambda ns, before, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    core.register_namespace("ok", "ns-a", "holder-a", deletion_head,
                            JournalHead("execution-a", 0, "genesis"))
    core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a")
    try:
        yield service, core, deletion, guard, execution
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def observe(service, *, credential="ok"):
    return service.namespace_bootstrap(
        credential=credential, subject="subject-a", namespace_id=_ID)


def test_active_is_exact_read_only_observation(installed):
    service, core, deletion, guard, execution = installed
    changes = core._db.total_changes
    result = observe(service)
    assert result.namespace == _ID
    assert result.authority_namespace == "ns-a"
    assert result.holder == "holder-a" and result.generation == 1
    assert result.phase == "active" and result.state is NamespaceRuntimeState.ACTIVE
    assert result.anchor == service.current_anchor(credential="ok", subject="subject-a")
    assert result.blocking_reasons == ()
    assert core._db.total_changes == changes
    with pytest.raises(AuthorityUnavailable, match="authentication denied"):
        observe(service, credential="bad")


def test_absent_row_is_unbound_without_activation(installed):
    service, core, deletion, guard, execution = installed
    core._db.execute("DELETE FROM authority_namespaces WHERE namespace='ns-a'")
    changes = core._db.total_changes
    result = observe(service)
    assert result.state is NamespaceRuntimeState.UNBOUND
    assert result.phase == "unbound" and result.generation == 0
    assert result.holder is None and result.anchor is None
    assert core._db.total_changes == changes


def test_ordinary_read_fence_stays_active_but_stale_head_blocks(installed):
    service, core, deletion, guard, execution = installed
    anchor = observe(service).anchor
    service.begin_fence(
        credential="ok", subject="subject-a", holder="holder-a",
        operation="read", operation_id="read-a", expected_anchor=anchor)
    result = observe(service)
    assert result.state is NamespaceRuntimeState.ACTIVE
    assert result.blocking_reasons == ()
    assert result.anchor == anchor
    core._db.execute(
        "UPDATE authority_namespaces SET execution_digest=? WHERE namespace=?",
        ("sha256:" + "0" * 64, "ns-a"))
    result = observe(service)
    assert result.state is NamespaceRuntimeState.RECOVERING
    assert "journal_head_mismatch" in result.blocking_reasons
    assert result.anchor is None


def test_deletion_history_quarantines_even_after_head_catches_up(installed):
    service, core, deletion, guard, execution = installed
    deletion.append_intent(
        namespace="ns-a", operation_id="delete-a", closure_roots=("item-a",),
        epoch=1, policy_ref="policy-a")
    head = deletion.latest_head()
    core._db.execute(
        "UPDATE authority_namespaces SET deletion_seq=?, deletion_digest=? "
        "WHERE namespace=?", (head.seq, head.chain_digest, "ns-a"))
    result = observe(service)
    assert result.state is NamespaceRuntimeState.QUARANTINED
    assert result.blocking_reasons == ("deletion_history",)
    assert result.anchor is not None


def test_pending_mutation_ledger_blocks_activation(installed):
    service, core, deletion, guard, execution = installed
    # Direct SQL fixture tests ledger occupancy; this path does not decode the footprint.
    core._db.execute(
        "INSERT INTO authority_v2_mutations("
        "mutation_id,operation_id,namespace,subject,request_digest,state,"
        "conflict_keys_json,pending,mutation_kind,footprint) "
        "VALUES(?,?,?,?,?,'pending','[]',?,'execution',?)",
        ("mutation-a", "operation-a", "ns-a", "subject-a",
         "sha256:" + "a" * 64, b"pending", b"fixture-footprint"))
    result = observe(service)
    assert result.state is NamespaceRuntimeState.RECOVERING
    assert result.blocking_reasons == ("pending_mutation",)
