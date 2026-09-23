"""Protected v2 service reads/issuance, with no production entry wiring."""

from dataclasses import replace
import subprocess
import sys
import threading
import time

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal


def installed(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=True)
    dh = deletion.latest_head()
    deletion_head = JournalHead(dh.journal_id, dh.seq, dh.chain_digest)
    callbacks = []
    refs = {}

    def authorizer(credential, action, namespace, holder):
        assert refs.get("core") is None or not refs["core"]._db.in_transaction
        assert not guard._db.in_transaction
        assert execution._guard_owner is None
        callbacks.append(action)
        return credential == "ok"

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorizer,
        deletion_verifier=lambda ns, before, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    refs["core"] = core
    core.register_namespace("ok", "ns-a", "holder-a", deletion_head,
                            JournalHead("execution-a", 0, "genesis"))
    core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    service = AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard, execution=execution,
        namespace="ns-a")
    return service, core, fences, deletion, guard, execution, callbacks


def begin(service, anchor, *, operation_id="operation-a"):
    return service.begin_fence(
        credential="ok", subject="subject-a", holder="holder-a",
        operation="read", operation_id=operation_id, expected_anchor=anchor)


def test_protected_read_issue_retry_conflict_and_full_anchor(tmp_path):
    service, core, fences, deletion, guard, execution, callbacks = installed(tmp_path)
    anchor = service.current_anchor(credential="ok", subject="subject-a")
    permit = begin(service, anchor)
    assert begin(service, anchor) == permit
    assert permit.pinned_anchor == anchor and permit.revision == 0
    with pytest.raises(AuthorityUnavailable, match="active"):
        begin(service, anchor, operation_id="operation-b")
    with pytest.raises(AuthorityUnavailable, match="anchor changed"):
        begin(service, replace(anchor, proof="other"))
    with pytest.raises(AuthorityUnavailable, match="authentication denied"):
        service.current_anchor(credential="bad", subject="subject-a")
    assert "current" in callbacks and "read" in callbacks
    core.close(); deletion.close(); guard.close(); execution.close()


def test_deletion_append_after_fence_closes_read_and_issue(tmp_path):
    service, core, fences, deletion, guard, execution, _ = installed(tmp_path)
    anchor = service.current_anchor(credential="ok", subject="subject-a")
    begin(service, anchor)
    deletion.append_intent(namespace="ns-a", operation_id="delete-a",
                           closure_roots=("item-a",), epoch=1, policy_ref="policy-a")
    with pytest.raises(AuthorityUnavailable, match="behind or differs"):
        service.current_anchor(credential="ok", subject="subject-a")
    with pytest.raises(AuthorityUnavailable, match="behind or differs"):
        begin(service, anchor)
    core.close(); deletion.close(); guard.close(); execution.close()


def test_independent_process_deletion_writer_blocks_fence_issuance(tmp_path):
    service, core, fences, deletion, guard, execution, _ = installed(tmp_path)
    anchor = service.current_anchor(credential="ok", subject="subject-a")
    ready, release = tmp_path / "ready", tmp_path / "release"
    script = (
        "import pathlib,sqlite3,time,sys\n"
        "db=sqlite3.connect(sys.argv[1],isolation_level=None)\n"
        "db.execute('BEGIN IMMEDIATE')\n"
        "pathlib.Path(sys.argv[2]).write_text('ready')\n"
        "stop=pathlib.Path(sys.argv[3])\n"
        "while not stop.exists(): time.sleep(.01)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", script, str(deletion.path),
                              str(ready), str(release)])
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert ready.exists() and child.poll() is None
        result = []
        worker = threading.Thread(target=lambda: result.append(begin(service, anchor)))
        worker.start()
        time.sleep(.15)
        assert worker.is_alive() and result == []
        release.write_text("go")
        worker.join(timeout=5)
        assert not worker.is_alive() and len(result) == 1
        assert child.wait(timeout=5) == 0
    finally:
        release.write_text("go")
        if child.poll() is None:
            child.kill(); child.wait()
        core.close(); deletion.close(); guard.close(); execution.close()
