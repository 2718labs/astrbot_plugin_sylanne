"""Persistent v2-only seal gates legacy service entrances before log access."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from sylanne3.authority_service.contract import (
    AuthorityUnavailable, ContentPermit, JournalHead,
)
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.local_bridge import LocalJournalBridge
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.activation import TransferPlan


GENESIS_DELETE = JournalHead("delete-a", 0, "genesis")
GENESIS_EXECUTION = JournalHead("execution-a", 0, "genesis")


def open_core(path, calls, *, create=False, deletion_hook=None):
    def deletion_verifier(*args):
        calls.append("deletion")
        if deletion_hook is not None:
            deletion_hook()
        return args[2] == GENESIS_DELETE

    def execution_verifier(*args):
        calls.append("execution")
        return args[2] == GENESIS_EXECUTION

    return AuthorityServiceCore(
        path, create=create,
        authorizer=lambda credential, action, namespace, holder: credential == "ok",
        deletion_verifier=deletion_verifier,
        execution_verifier=execution_verifier,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )


def installed_core(path, calls):
    core = open_core(path, calls, create=True)
    core.register_namespace("ok", "ns-a", "holder-a", GENESIS_DELETE,
                            GENESIS_EXECUTION)
    return core


def test_core_legacy_entrances_reject_before_verifier_and_after_reopen(tmp_path):
    path = tmp_path / "authority.db"
    calls = []
    core = installed_core(path, calls)
    anchor = core.current_anchor("ok", "ns-a")
    core.seal_v2_only("ok")
    core.seal_v2_only("ok")  # Same installer action is idempotent.
    before = list(calls)
    operations = (
        lambda: core.current("ok", "ns-a"),
        lambda: core.current_anchor("ok", "ns-a"),
        lambda: core.verify_current("ok", anchor),
        lambda: core.check("ok", namespace="ns-a", holder="holder-a",
                           generation=1, operation="read"),
        lambda: core.begin_content_operation("ok", namespace="ns-a",
                                             holder="holder-a", generation=1,
                                             operation="read"),
        lambda: core.end_content_operation("ok", ContentPermit(
            "token-a", "ns-a", "holder-a", 1, "read")),
        lambda: core.register_namespace("ok", "ns-b", "holder-b",
                                        GENESIS_DELETE, GENESIS_EXECUTION),
        lambda: core.observe_deletion_head("ok", "ns-a", GENESIS_DELETE,
                                           GENESIS_DELETE, "clear"),
        lambda: core.observe_execution_head("ok", "ns-a", GENESIS_EXECUTION,
                                            GENESIS_EXECUTION, effect_id="effect-a",
                                            state="unresolved", conflict_keys=()),
        lambda: core.admit_dispatch("ok", namespace="ns-a", holder="holder-a",
                                    generation=1, effect_id="effect-a",
                                    conflict_keys=(), permit=ContentPermit(
                                        "token-a", "ns-a", "holder-a", 1, "dispatch")),
        lambda: core.begin_transfer("ok", TransferPlan(
            "ns-a", "holder-a", "holder-b", "transfer-a"),
            expected_generation=1),
        lambda: core.revoke_source("ok", "transfer-a", expected_generation=1),
        lambda: core.activate_target("ok", "transfer-a",
                                     expected_revoked_generation=2,
                                     deletion=GENESIS_DELETE,
                                     execution=GENESIS_EXECUTION),
        lambda: core.recover_transfer("ok", "transfer-a"),
    )
    for operation in operations:
        with pytest.raises(AuthorityUnavailable, match="v2-only"):
            operation()
    assert calls == before
    core.close()
    second_calls = []
    second = open_core(path, second_calls)
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        second.current_anchor("ok", "ns-a")
    assert second_calls == []
    second.close()


@pytest.mark.parametrize("contamination", ["permit", "transfer", "effect", "deletion"])
def test_seal_rejects_legacy_inflight_state_without_clearing(tmp_path, contamination):
    core = installed_core(tmp_path / "authority.db", [])
    if contamination == "permit":
        core._db.execute("INSERT INTO authority_permits VALUES('token-a','ns-a','holder-a',1,'read')")
        table = "authority_permits"
    elif contamination == "transfer":
        core._db.execute("INSERT INTO authority_transfers VALUES('transfer-a','ns-a','holder-a','holder-b',1,'planned')")
        table = "authority_transfers"
    elif contamination == "effect":
        core._db.execute("INSERT INTO authority_effects VALUES('ns-a','effect-a','unresolved','[]',1)")
        table = "authority_effects"
    else:
        core._db.execute("UPDATE authority_namespaces SET deletion_phase='pending' WHERE namespace='ns-a'")
        table = "authority_namespaces"
    with pytest.raises(AuthorityUnavailable):
        core.seal_v2_only("ok")
    assert core._db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() is None
    assert core._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] >= 1
    core.close()


def test_seal_waits_for_inflight_legacy_verification_across_connections(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    seal_authorized = threading.Event()

    def hook():
        entered.set()
        assert release.wait(3)

    path = tmp_path / "authority.db"
    first = open_core(path, [], create=True, deletion_hook=hook)
    # Registration also verifies the genesis heads; avoid blocking during setup.
    first._deletion_verifier = lambda *args: args[2] == GENESIS_DELETE
    first.register_namespace("ok", "ns-a", "holder-a", GENESIS_DELETE,
                             GENESIS_EXECUTION)
    first._deletion_verifier = lambda *args: (hook() or True)
    second = open_core(path, [])
    second._authorize_callback = lambda cred, action, ns, holder: (
        seal_authorized.set() or True) if action == "seal_v2_only" else cred == "ok"
    with ThreadPoolExecutor(max_workers=2) as pool:
        query = pool.submit(first.current_anchor, "ok", "ns-a")
        assert entered.wait(3)
        seal = pool.submit(second.seal_v2_only, "ok")
        assert seal_authorized.wait(3)
        assert not seal.done()
        release.set()
        query.result(timeout=3)
        seal.result(timeout=3)
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        first.current_anchor("ok", "ns-a")
    first.close()
    second.close()


def test_seal_rejects_journal_head_ahead_of_authority(tmp_path):
    core = installed_core(tmp_path / "authority.db", [])
    core._execution_verifier = lambda *args: False
    with pytest.raises(AuthorityUnavailable, match="behind independent journal"):
        core.seal_v2_only("ok")
    assert core._db.execute(
        "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() is None
    core.close()


def test_local_bridge_write_entrances_and_reopen_reject_before_log_access(tmp_path, monkeypatch):
    path = tmp_path / "authority.db"
    args = dict(
        namespace="ns-a", authority_path=path,
        deletion_path=tmp_path / "deletion.db",
        execution_path=tmp_path / "execution.db",
        authorizer=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    bridge = LocalJournalBridge(**args, create=True)
    bridge.register_namespace("ok", "holder-a")
    bridge.core.seal_v2_only("ok")

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy log was touched after v2 seal")

    monkeypatch.setattr(bridge, "_deletion_head", forbidden)
    monkeypatch.setattr(bridge, "_execution_head", forbidden)
    monkeypatch.setattr(bridge.deletion, "append_intent", forbidden)
    monkeypatch.setattr(bridge.execution, "prepare", forbidden)
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        bridge.register_namespace("ok", "holder-b")
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        bridge.append_deletion_intent("ok", operation_id="delete-a",
                                      closure_roots=("root-a",), epoch=1,
                                      policy_ref="policy-a")
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        bridge.reconcile_one("ok", "execution")
    bridge.close()

    monkeypatch.setattr("sylanne3.authority_service.local_bridge.ExecutionJournal", forbidden)
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        LocalJournalBridge(**args)


def test_v2_bridge_cannot_start_before_persistent_seal(tmp_path):
    path = tmp_path / "authority.db"
    core = installed_core(path, [])
    journal = AuthorityV2ExecutionJournal(tmp_path / "v2-execution.db",
                                          namespace="ns-a", journal_id="execution-a",
                                          create=True)
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    with pytest.raises(AuthorityUnavailable, match="v2-only"):
        AuthorityV2ExecutionBridge(core=core, fences=fences,
                                   journal=journal, namespace="ns-a")
    core.close()
    journal.close()
