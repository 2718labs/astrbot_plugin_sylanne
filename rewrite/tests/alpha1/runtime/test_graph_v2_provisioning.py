"""Administrator namespace genesis uses one fenced, atomic business write."""

from dataclasses import replace
import sqlite3
import time

import pytest

from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.graph_coordinator import (
    AuthorityDenied, GraphCoordinator, UnavailableGuard,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease, get_budget_lease
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer, build_runtime_issuers,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    InstallationGrantV2, NamespaceBootstrapV2, NamespaceId,
    NamespaceRuntimeState,
)


class AuthorityPort:
    def __init__(self, store, db):
        self.store = store
        self.fences = AuthorityV2FenceStore(db, create=True)
        self.installation_grant = InstallationGrantV2(
            "authority", "subject", "administrator", "installation",
            "a" * 64, "publisher-trust", "2", "b" * 64)
        self.anchors = {}
        self.genesis_requests = []
        self.validations = []
        self.finishes = []
        self.lose_finish_after_durable = False

    def outside_graph_lock(self):
        assert not self.store._lock._is_owned()

    def provision_namespace(self, *, namespace, request_id):
        self.outside_graph_lock()
        self.genesis_requests.append((namespace, request_id))
        anchor = self.anchors.setdefault(namespace, RestoreAnchor(
            "authority", "opaque:" + namespace.persona_id, 1,
            "deletion:" + namespace.persona_id, 0, "genesis",
            "execution:" + namespace.persona_id, 0, "genesis", 0,
            "authority-proof"))
        return NamespaceBootstrapV2(
            "authority", namespace, anchor.namespace, "administrator", 1,
            "active", NamespaceRuntimeState.ACTIVE, anchor, ())

    def current_anchor(self, *, namespace, authority_namespace):
        self.outside_graph_lock()
        anchor = self.anchors[namespace]
        assert anchor.namespace == authority_namespace
        return anchor

    def get_fence_operation(self, *, namespace, authority_namespace, operation_id):
        self.outside_graph_lock()
        assert self.anchors[namespace].namespace == authority_namespace
        permit, state, pending = self.fences.get_operation(
            operation_id, subject="subject", namespace=authority_namespace)
        assert pending is None
        return permit, state

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self.outside_graph_lock()
        assert expected_anchor == self.anchors[namespace]
        assert expected_anchor.namespace == authority_namespace
        assert generation == 1
        return self.fences.begin_fence(
            subject="subject", holder=holder, operation=operation,
            operation_id=operation_id, current_anchor=expected_anchor)

    def validate_fence(self, scope):
        self.outside_graph_lock()
        self.validations.append(scope.operation)
        return self.fences.validate_fence(
            scope.permit, subject="subject",
            current_anchor=self.anchors[scope.namespace])

    def finish_fence(self, scope, *, request_id, request_digest):
        self.outside_graph_lock()
        self.fences.finish_fence(
            scope.permit, subject="subject",
            current_anchor=self.anchors[scope.namespace],
            request_id=request_id, request_digest=request_digest)
        self.finishes.append((scope.operation, request_id, request_digest))
        if self.lose_finish_after_durable:
            self.lose_finish_after_durable = False
            raise RuntimeError("finish response lost")


def policy_for(store, persona="persona", *, scheme="scheme-1"):
    namespace = NamespaceId("bot", persona)
    lease = BudgetLease(
        "lease-" + persona, None, *namespace.as_tuple, "USD",
        {"cpu_ms": 200}, {}, {}, {}, 1, "active")
    grant = BudgetLeaseGrant(
        "grant-" + persona, 1, *namespace.as_tuple, lease.lease_id,
        "USD", {"cpu_ms": 100}, ("encode",), time.time() + 3600,
        "d11-policy")
    return AdminInstallationPolicy(
        namespace, "opaque:" + persona, "installation", "a" * 64,
        "administrator", "authority", store._registry.catalogue_hash,
        scheme, "operator-1", "policy-1", lease, grant)


@pytest.fixture
def system(tmp_path):
    store = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(
        tmp_path / "authority.db", isolation_level=None)
    port = AuthorityPort(store, authority_db)
    _, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        d11_issuer=d11)
    try:
        yield store, coordinator, bootstrap, port, d11
    finally:
        store.close()
        authority_db.close()


def row_counts(store):
    tables = {row[0] for row in store._db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return {table: (store._db.execute(
        f"SELECT COUNT(*) FROM {table}").fetchone()[0] if table in tables else 0)
        for table in (
            "graph_recovery_metadata_v2", "graph_guard_versions",
            "runtime_budget_leases", "runtime_budget_operations",
            "runtime_budget_grants", "graph_namespace_provisioning_v2")}


def test_genesis_uses_d11_grant_capability_without_d02(tmp_path):
    store = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    try:
        port = AuthorityPort(store, authority_db)
        issuer = D11BudgetGrantIssuer(b"K" * 32)
        bootstrap = object()
        coordinator = GraphCoordinator(
            store, bootstrap, holder="administrator", content_fence_v2=port,
            d11_issuer=issuer)
        policy = policy_for(store)
        receipt = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
        assert issuer.current_budget_grant(store._db, receipt.root_lease_id) == policy.root_grant
        assert coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona") == receipt
    finally:
        store.close()
        authority_db.close()


def test_success_stages_recovery_guards_real_budget_and_reconcilable_receipt(system):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert row_counts(store) == {
        "graph_recovery_metadata_v2": 1, "graph_guard_versions": 4,
        "runtime_budget_leases": 1, "runtime_budget_operations": 1,
        "runtime_budget_grants": 1, "graph_namespace_provisioning_v2": 1}
    metadata = store.graph_recovery_metadata(
        policy.namespace, _capability=store._coordinator_capability)
    assert metadata.requirements.graph_incarnation == receipt.graph_incarnation
    assert metadata.requirements.deletion_seq == metadata.requirements.execution_seq == 0
    assert get_budget_lease(store._db, receipt.root_lease_id).limits == {"cpu_ms": 200}
    assert d11.current_budget_grant(store._db, receipt.root_lease_id) == policy.root_grant
    assert receipt.fence_attempt_id in receipt.finish_request_id
    assert receipt.permit_wire["operation_id"] == receipt.fence_attempt_id
    assert port.validations == ["write", "write"]
    assert len(port.finishes) == 1 and port.finishes[0][0] == "write"

    duplicate = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert duplicate == receipt
    assert row_counts(store)["runtime_budget_leases"] == 1
    assert len(port.genesis_requests) == 1
    assert port.validations == ["write", "write", "read", "read"]


def test_issuer_failure_rolls_back_all_business_rows(system):
    store, coordinator, bootstrap, port, d11 = system
    def unavailable(*_args):
        raise RuntimeError("issuer unavailable")
    d11.issue_budget_grant = unavailable
    with pytest.raises(RuntimeError, match="issuer unavailable"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store), operation_id="install-persona")
    assert all(count == 0 for count in row_counts(store).values())
    assert len(port.finishes) == 1


def test_same_business_id_with_different_policy_digest_is_rejected(system):
    store, coordinator, bootstrap, port, _ = system
    first = policy_for(store)
    coordinator.provision_namespace_v2(bootstrap, first, operation_id="install-persona")
    with pytest.raises(AuthorityDenied, match="identity differs"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store, scheme="scheme-2"),
            operation_id="install-persona")
    assert len(port.genesis_requests) == 1
    assert row_counts(store)["runtime_budget_leases"] == 1


def test_old_unsealed_history_rejects_before_authority_genesis(system):
    store, coordinator, bootstrap, port, _ = system
    store._db.execute(
        "INSERT INTO atoms(bot,persona,session,name,revision,value) "
        "VALUES(?,?,?,?,?,?)", ("bot", "persona", "s", "legacy", 1, "{}"))
    with pytest.raises(UnavailableGuard, match="unsealed"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store), operation_id="install-persona")
    assert not port.genesis_requests
    assert row_counts(store)["graph_recovery_metadata_v2"] == 0


def test_existing_other_persona_grant_does_not_block_second_genesis(system):
    store, coordinator, bootstrap, port, _ = system
    first = coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "one"), operation_id="install-one")
    second = coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "two"), operation_id="install-two")
    assert first.namespace != second.namespace
    assert row_counts(store)["graph_recovery_metadata_v2"] == 2
    assert row_counts(store)["runtime_budget_grants"] == 2


def test_other_sealed_graph_dependency_is_attributed_to_its_owner(system):
    store, coordinator, bootstrap, _, _ = system
    coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "one"), operation_id="install-one")
    key = AtomKey(Owner("persona", "bot", "one"), "legacy-state", "a")
    store._db.execute(
        "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,"
        "name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (key.token, "bot", "one", "persona", None, "legacy-state",
         "a", 1, "{}", 1))
    store._db.execute(
        "INSERT INTO graph_dependencies(dependent_token,dependency_token,"
        "dependency_revision) VALUES(?,?,?)", (key.token, key.token, 1))
    assert coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "two"),
        operation_id="install-two").namespace == NamespaceId("bot", "two")


def test_competing_authority_write_fence_leaves_business_db_empty(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    anchor = port.provision_namespace(
        namespace=policy.namespace, request_id="external-genesis").anchor
    foreign = port.fences.begin_fence(
        subject="subject", holder="administrator", operation="write",
        operation_id="foreign-active", current_anchor=anchor)
    try:
        with pytest.raises(RuntimeError, match="active v2 fence"):
            coordinator.provision_namespace_v2(
                bootstrap, policy, operation_id="install-persona")
        assert all(count == 0 for count in row_counts(store).values())
    finally:
        port.fences.finish_fence(
            foreign, subject="subject", current_anchor=anchor,
            request_id="finish-foreign", request_digest="sha256:" + "a" * 64)


def test_lost_finish_response_keeps_durable_reconciliation_identity(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_finish_after_durable = True
    with pytest.raises(RuntimeError, match="finish response lost"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert row_counts(store)["graph_namespace_provisioning_v2"] == 1
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert receipt.finish_request_id == port.finishes[0][1]
    assert receipt.finish_request_digest == port.finishes[0][2]
    assert len(port.genesis_requests) == 1


def test_cold_restart_finishes_exact_durable_write_fence_then_reads(system, tmp_path):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    anchor = None

    def crash_before_finish(*_args, **_kwargs):
        raise RuntimeError("simulated process crash before Authority finish")

    port.finish_fence = crash_before_finish
    with pytest.raises(RuntimeError, match="simulated process crash"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    row = coordinator._provision_row(store._db, policy.namespace)
    assert row is not None
    anchor = port.anchors[policy.namespace]
    receipt = coordinator._decode_provision_receipt(row)
    _, state = port.get_fence_operation(
        namespace=policy.namespace, authority_namespace=anchor.namespace,
        operation_id=receipt.fence_attempt_id)
    assert state == "active"

    store.close()
    port.fences._db.close()
    reopened = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(
        tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d11_issuer=d11)
    try:
        assert next_coordinator.provision_namespace_v2(
            next_bootstrap, policy, operation_id="install-persona") == receipt
        _, state = next_port.get_fence_operation(
            namespace=policy.namespace, authority_namespace=anchor.namespace,
            operation_id=receipt.fence_attempt_id)
        assert state == "finished"
        assert next_port.finishes[0] == (
            "write", receipt.finish_request_id, receipt.finish_request_digest)
        assert next_port.finishes[1][0] == "read"
        assert not next_port.genesis_requests
        assert row_counts(reopened)["runtime_budget_leases"] == 1
    finally:
        reopened.close()
        authority_db.close()


def test_mismatched_authority_permit_cannot_finish_old_active_fence(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)

    def crash_before_finish(*_args, **_kwargs):
        raise RuntimeError("simulated process crash before Authority finish")

    port.finish_fence = crash_before_finish
    with pytest.raises(RuntimeError, match="simulated process crash"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    port.finish_fence = AuthorityPort.finish_fence.__get__(port)
    original_status = port.get_fence_operation

    def altered_status(**kwargs):
        permit, state = original_status(**kwargs)
        return replace(permit, token="z" * 48), state

    port.get_fence_operation = altered_status
    with pytest.raises(UnavailableGuard, match="status differs"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert not port.finishes
    assert row_counts(store)["runtime_budget_leases"] == 1
