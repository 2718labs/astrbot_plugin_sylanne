"""The business graph stores recovery targets in its own SQLite transaction."""

from dataclasses import replace

import pytest

from sylanne3.contracts import StaleRead
from sylanne3.graph_store import GraphRecoveryMetadataV2, GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


NAMESPACE = NamespaceId("bot-a", "persona-a")


def requirements(**changes):
    initial = SnapshotRequirementsV2(
        namespace=NAMESPACE,
        authority_id="authority-a",
        authority_namespace="namespace-a",
        activation_generation=1,
        deletion_journal_id="deletion-a",
        deletion_seq=0,
        deletion_digest="genesis",
        execution_journal_id="execution-a",
        execution_seq=0,
        execution_digest="genesis",
        revocation_epoch=0,
        graph_incarnation="graph-a",
    )
    return replace(initial, **changes)


def open_store(path, capability):
    store = GraphStore(path, TypeRegistry())
    store._coordinator_capability = capability
    return store


def test_empty_namespace_genesis_persists_complete_target_and_revision(tmp_path):
    path = tmp_path / "business.db"
    capability = object()
    store = open_store(path, capability)
    target = requirements()
    try:
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) is None
        with pytest.raises(PermissionError):
            store.graph_recovery_metadata(NAMESPACE)
        installed = store.install_graph_recovery_genesis(target, _capability=capability)
        assert installed == GraphRecoveryMetadataV2(target, 0)
        with pytest.raises(StaleRead):
            store.install_graph_recovery_genesis(target, _capability=capability)
    finally:
        store.close()

    reopened = open_store(path, capability)
    try:
        assert reopened.graph_recovery_metadata(NAMESPACE, _capability=capability) == installed
    finally:
        reopened.close()


@pytest.mark.parametrize("legacy_row", [
    "atom", "bundle", "outbox", "job", "observation", "history",
])
def test_existing_role_content_cannot_be_silently_sealed(tmp_path, legacy_row):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        if legacy_row == "atom":
            store._db.execute(
                "INSERT INTO atoms(bot,persona,session,name,revision,value) "
                "VALUES(?,?,?,?,?,?)", (*NAMESPACE.as_tuple, "session", "x", 1, "{}"))
        elif legacy_row == "bundle":
            store._db.execute(
                "INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?)",
                (*NAMESPACE.as_tuple, 1))
        elif legacy_row == "outbox":
            store._db.execute(
                "INSERT INTO graph_bundle_outbox(bot,persona,outbox_ref,"
                "operation_id,phase) VALUES(?,?,?,?,?)",
                (*NAMESPACE.as_tuple, "outbox-a", "operation-a", "pending"))
        elif legacy_row == "job":
            store._db.execute(
                "INSERT INTO runtime_jobs(job_id,operation_id,activity_id,bot_id,"
                "persona_id,snapshot_ref,phase,work_kind,continuation_json,"
                "deadline_utc,budget_ref,resource_ref,operator_versions_json,"
                "fence,cancel_epoch,usage_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("job-a", "operation-a", "activity-a", *NAMESPACE.as_tuple,
                 "snapshot-a", "queued", "encode", "{}", "2030-01-01T00:00:00Z",
                 "budget-a", "resource-a", "{}", 0, 0, "{}"))
        elif legacy_row == "observation":
            store._db.execute("CREATE TABLE ingress_first_observations ("
                              "bot TEXT, persona TEXT, operation_id TEXT)")
            store._db.execute(
                "INSERT INTO ingress_first_observations VALUES(?,?,?)",
                (*NAMESPACE.as_tuple, "operation-a"))
        else:
            store._db.execute(
                "INSERT INTO graph_history(token,revision,value,valid,dependencies,"
                "event_bot,event_persona,event_session,event_id) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                ("orphan", 1, "{}", 1, "[]", *NAMESPACE.as_tuple, "session", "event"))
        with pytest.raises(RuntimeError, match="unsealed"):
            store.graph_recovery_metadata(NAMESPACE, _capability=capability)
        with pytest.raises(RuntimeError, match="unsealed"):
            store.install_graph_recovery_genesis(requirements(), _capability=capability)
        assert store._db.execute("SELECT COUNT(*) FROM graph_recovery_metadata_v2").fetchone() == (0,)
    finally:
        store.close()


def test_unowned_legacy_clock_row_blocks_empty_namespace_genesis(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        store._db.execute(
            "INSERT INTO runtime_deadlines(deadline_id,deadline_utc,floating_rule,"
            "timezone_name,policy_ref) VALUES(?,?,?,?,?)",
            ("deadline-a", "2030-01-01T00:00:00Z", None, "UTC", "policy-a"))
        with pytest.raises(RuntimeError, match="unsealed"):
            store.graph_recovery_metadata(NAMESPACE, _capability=capability)
        with pytest.raises(RuntimeError, match="unsealed"):
            store.install_graph_recovery_genesis(requirements(), _capability=capability)
        assert store._db.execute("SELECT COUNT(*) FROM graph_recovery_metadata_v2").fetchone() == (0,)
    finally:
        store.close()


def test_locked_genesis_requires_capability_and_existing_transaction(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        with pytest.raises(PermissionError):
            store._install_graph_recovery_genesis_locked(requirements())
        with pytest.raises(RuntimeError, match="active SQL transaction"):
            store._install_graph_recovery_genesis_locked(
                requirements(), _capability=capability)
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) is None
    finally:
        store.close()


@pytest.mark.parametrize("invalid_head", [
    {"activation_generation": 0},
    {"revocation_epoch": 1},
    {"deletion_seq": 1, "deletion_digest": "sha256:" + "a" * 64},
    {"execution_seq": 1, "execution_digest": "sha256:" + "b" * 64},
])
def test_locked_genesis_requires_active_zero_heads(tmp_path, invalid_head):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(ValueError, match="zero-head"):
                    store._install_graph_recovery_genesis_locked(
                        requirements(**invalid_head), _capability=capability)
            finally:
                store._db.execute("ROLLBACK")
        assert store._db.execute("SELECT COUNT(*) FROM graph_recovery_metadata_v2").fetchone() == (0,)
    finally:
        store.close()


def test_locked_genesis_rolls_back_with_guard_and_budget_rows(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        with pytest.raises(RuntimeError, match="simulated provisioning failure"):
            with store._lock:
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    installed = store._install_graph_recovery_genesis_locked(
                        requirements(), _capability=capability)
                    assert installed == GraphRecoveryMetadataV2(requirements(), 0)
                    store._db.execute(
                        "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                        "VALUES(?,?,?,?,?)",
                        (*NAMESPACE.as_tuple, "activation", "current", "1"))
                    lease = BudgetLease(
                        "lease-a", None, *NAMESPACE.as_tuple, "USD",
                        {"cpu_ms": 100}, {}, {}, {}, 1, "active")
                    create_budget_lease(store._db, lease, "budget-create-a", "a" * 64)
                    raise RuntimeError("simulated provisioning failure")
                except BaseException:
                    store._db.execute("ROLLBACK")
                    raise
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) is None
        for table in ("graph_recovery_metadata_v2", "graph_guard_versions",
                      "runtime_budget_leases", "runtime_budget_operations"):
            assert store._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
    finally:
        store.close()


def test_locked_genesis_still_rejects_legacy_history(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        store._db.execute(
            "INSERT INTO atoms(bot,persona,session,name,revision,value) "
            "VALUES(?,?,?,?,?,?)", (*NAMESPACE.as_tuple, "session", "x", 1, "{}"))
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(RuntimeError, match="unsealed"):
                    store._install_graph_recovery_genesis_locked(
                        requirements(), _capability=capability)
            finally:
                store._db.execute("ROLLBACK")
        assert store._db.execute("SELECT COUNT(*) FROM graph_recovery_metadata_v2").fetchone() == (0,)
    finally:
        store.close()


def test_cas_joins_business_transaction_and_rolls_back_together(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        original = store.install_graph_recovery_genesis(requirements(), _capability=capability)
        advanced = requirements(execution_seq=1, execution_digest="sha256:" + "a" * 64)
        with pytest.raises(RuntimeError, match="active SQL transaction"):
            store.cas_graph_recovery_metadata(original, advanced, _capability=capability)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            store._db.execute(
                "INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,?)",
                (*NAMESPACE.as_tuple, 1))
            changed = store.cas_graph_recovery_metadata(
                original, advanced, _capability=capability)
            assert changed == GraphRecoveryMetadataV2(advanced, 1)
            store._db.execute("ROLLBACK")
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == original
        assert store._db.execute("SELECT COUNT(*) FROM graph_epochs").fetchone() == (0,)
    finally:
        store.close()


def test_cas_rejects_other_identity_and_stale_revision(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        original = store.install_graph_recovery_genesis(requirements(), _capability=capability)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                for field, value in (("authority_id", "authority-b"),
                                     ("deletion_journal_id", "deletion-b"),
                                     ("execution_journal_id", "execution-b")):
                    with pytest.raises(StaleRead, match="identity"):
                        store.cas_graph_recovery_metadata(
                            original, requirements(**{field: value}),
                            _capability=capability)
                current = store.cas_graph_recovery_metadata(
                    original, requirements(revocation_epoch=1),
                    _capability=capability)
                assert current.graph_revision == 1
                with pytest.raises(StaleRead, match="changed"):
                    store.cas_graph_recovery_metadata(
                        original, requirements(revocation_epoch=2),
                        _capability=capability)
                store._db.execute("COMMIT")
            except BaseException:
                store._db.execute("ROLLBACK")
                raise
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == current
    finally:
        store.close()


def test_normal_cas_rejects_generation_change_and_watermark_rollback(tmp_path):
    capability = object()
    store = open_store(tmp_path / "business.db", capability)
    try:
        original = store.install_graph_recovery_genesis(requirements(), _capability=capability)
        high_water = requirements(
            deletion_seq=1, deletion_digest="sha256:" + "a" * 64,
            execution_seq=1, execution_digest="sha256:" + "b" * 64,
            revocation_epoch=1)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                current = store.cas_graph_recovery_metadata(
                    original, high_water, _capability=capability)
                with pytest.raises(StaleRead, match="identity"):
                    store.cas_graph_recovery_metadata(
                        current, replace(high_water, activation_generation=2),
                        _capability=capability)
                for lowered in (
                    replace(high_water, deletion_seq=0, deletion_digest="genesis"),
                    replace(high_water, execution_seq=0, execution_digest="genesis"),
                    replace(high_water, revocation_epoch=0),
                ):
                    with pytest.raises(StaleRead, match="regressed"):
                        store.cas_graph_recovery_metadata(
                            current, lowered, _capability=capability)
                store._db.execute("COMMIT")
            except BaseException:
                store._db.execute("ROLLBACK")
                raise
        assert store.graph_recovery_metadata(NAMESPACE, _capability=capability) == current
    finally:
        store.close()
