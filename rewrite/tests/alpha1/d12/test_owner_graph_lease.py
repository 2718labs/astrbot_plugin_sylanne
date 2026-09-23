"""D12 production reads require the same live Owner heads as graph content."""

from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.contracts import canonical_json
from sylanne3.graph_coordinator import (
    GraphCoordinator, UnavailableGuard, namespace_ref,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import (
    TypeRegistry, owner_grant_key, owner_grant_spec,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, NamespaceId, SnapshotRequirementsV2, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")
PRINCIPAL = OwnerPrincipalV1("owner-idp", "account", "incarnation")


class OwnerReadPort:
    def __init__(self, graph, anchor):
        self.graph = graph
        self.anchor = anchor
        self.guard = None
        self.active = None
        self.guard_reads = 0
        self.finishes = 0
        self.on_guard_read = None
        self.installation_grant = SimpleNamespace(installation_id="installation")

    def _outside_graph(self):
        assert not self.graph._lock._is_owned()

    def current_anchor(self, *, namespace, authority_namespace):
        self._outside_graph()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        return self.anchor

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self._outside_graph()
        assert self.active is None and namespace == NAMESPACE
        assert authority_namespace == self.anchor.namespace
        assert holder == "holder" and generation == 1 and operation == "read"
        assert expected_anchor == self.anchor
        self.active = FencePermitV2(
            self.anchor.authority_id, authority_namespace, "subject", holder,
            generation, operation, operation_id, "x" * 48, 1, 0, self.anchor)
        return self.active

    def validate_fence(self, scope):
        self._outside_graph()
        assert scope.permit is self.active and scope.pinned_anchor == self.anchor
        return self.active

    def get_current_owner_guard_for_fence(
            self, *, namespace, authority_namespace, permit):
        self._outside_graph()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        assert permit is self.active
        self.guard_reads += 1
        if self.on_guard_read is not None:
            self.on_guard_read(self.guard_reads)
        return self.guard, permit

    def finish_fence(self, scope, *, request_id, request_digest):
        self._outside_graph()
        assert scope.permit is self.active
        assert request_id == "finish:" + scope.operation_id
        assert request_digest.startswith("sha256:")
        self.finishes += 1
        self.active = None


class Provider:
    def validate(self, proposal, snapshot):
        return True


@pytest.fixture
def owner_graph(tmp_path):
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    graph = ProductionGraphStore(tmp_path / "business.db", registry)
    anchor = RestoreAnchor(
        "authority", namespace_ref(NAMESPACE), 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "authority-proof")
    target = SnapshotRequirementsV2(
        NAMESPACE, anchor.authority_id, anchor.namespace, 1,
        anchor.deletion_journal_id, 0, anchor.deletion_digest,
        anchor.execution_journal_id, 0, anchor.execution_digest,
        0, "graph-incarnation")
    port = OwnerReadPort(graph, anchor)
    bootstrap = object()
    pairing = {"principal": PRINCIPAL}
    coordinator = GraphCoordinator(
        graph, bootstrap, holder="holder", content_fence_v2=port,
        owner_principal_resolver=lambda actor, namespace:
            pairing["principal"] if actor == "owner-session"
            and namespace == NAMESPACE else None)
    spec = registry.spec(owner_grant_key(*NAMESPACE.as_tuple).type_name)
    coordinator.register_provider(bootstrap, "d11", Provider(), "owner", spec.schema_hash)
    metadata = graph.install_graph_recovery_genesis(
        target, _capability=graph._coordinator_capability)
    grant = {
        "schema": "sylanne3.graph.owner_grant.v1",
        "authority_id": "authority", "installation_id": "installation",
        "grant_id": "grant-1", "principal": asdict(PRINCIPAL),
        "ticket_id": "ticket-1", "creation_operation_id": "creation-1",
        "creation_digest": "sha256:" + "a" * 64,
        "issue_operation_id": "issue-1", "grant_revision": 1,
        "state": "pending_authority", "scope": "bot/persona",
        "issuer_ref": "authority:installation",
        "capabilities": ["workbench.read"],
        "purposes": ["workbench_view"], "audiences": ["owner"],
        "activation_generation": 1, "graph_incarnation": "graph-incarnation",
    }
    proof = OwnerGraphCommitProofV1(
        NAMESPACE, "issue-1", "sha256:" + "b" * 64,
        grant["grant_id"], "sha256:" + canonical_digest(grant),
        "graph-incarnation", 1, 1, 1, "sha256:" + "c" * 64)
    port.guard = OwnerAuthorizationGuardV1(
        "authority", "installation", NAMESPACE, 1,
        owner_contract_digest(proof), 0, 0)
    key = owner_grant_key(*NAMESPACE.as_tuple)
    with graph._lock:
        graph._db.execute("BEGIN IMMEDIATE")
        try:
            graph._db.execute(
                "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (key.token, *NAMESPACE.as_tuple, "persona", None, key.type_name,
                 key.name, 1, canonical_json(grant), 1))
            graph._db.execute(
                "INSERT INTO graph_owner_issue_operations_v1"
                "(bot,persona,operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,"
                "graph_receipt_digest,proof_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                NAMESPACE.as_tuple + (
                    proof.operation_id, proof.request_digest, proof.grant_id,
                    proof.grant_digest, proof.graph_incarnation,
                    proof.graph_access_epoch, proof.graph_epoch,
                    proof.graph_receipt_digest, canonical_json(asdict(proof))))
            graph._db.execute(
                "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
                "VALUES(?,?,1,0)", NAMESPACE.as_tuple)
            graph._db.execute(
                "INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,1)",
                NAMESPACE.as_tuple)
            graph.cas_graph_recovery_metadata(
                metadata, target, _capability=graph._coordinator_capability)
            graph._db.execute("COMMIT")
        except BaseException:
            graph._db.execute("ROLLBACK")
            raise
    try:
        yield graph, coordinator, bootstrap, port, key, pairing
    finally:
        graph.close()


def test_owner_read_requires_resolved_principal_and_current_heads(owner_graph):
    graph, coordinator, bootstrap, port, key, pairing = owner_graph
    with pytest.raises(UnavailableGuard, match="D12 requires"):
        coordinator.grant(
            bootstrap, actor="owner-session", issuer_domain="d12",
            namespace=NAMESPACE, domains=("d11",), activation_generation=1)
    authority, lease, binding = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d11",), purpose="workbench_view", audience="owner",
        activation_generation=1)
    assert binding.grant_id == "grant-1" and binding.access_epoch == 1
    assert coordinator.read_snapshot(authority, lease, (key,)).get(key).revision == 1
    assert coordinator.query(
        authority, lease, type_names=(key.type_name,), owner_kind="persona")
    assert port.guard_reads == 6 and port.finishes == 3

    pairing["principal"] = None
    with pytest.raises(UnavailableGuard, match="pairing"):
        coordinator.read_snapshot(authority, lease, (key,))
    assert port.finishes == 4
    pairing["principal"] = PRINCIPAL

    port.guard = replace(port.guard, pending_revoke_operation_id="revoke-1")
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.read_snapshot(authority, lease, (key,))
    assert port.finishes == 5

    port.guard = replace(port.guard, pending_revoke_operation_id=None)
    with graph._lock:
        graph._db.execute(
            "UPDATE graph_authority_epochs SET access_epoch=2 WHERE bot=? AND persona=?",
            NAMESPACE.as_tuple)
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.query(
            authority, lease, type_names=(key.type_name,), owner_kind="persona")
    assert port.finishes == 6
    refreshed, refreshed_lease, current = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d11",), purpose="workbench_view", audience="owner",
        activation_generation=1)
    assert current.access_epoch == 2
    assert coordinator.query(
        refreshed, refreshed_lease, type_names=(key.type_name,),
        owner_kind="persona")


def test_current_owner_view_returns_guard_and_binding_without_lease(owner_graph):
    _, coordinator, bootstrap, port, _, _ = owner_graph
    leases_before = len(coordinator._GraphCoordinator__leases)
    view = coordinator.read_current_owner_view(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        purpose="workbench_view", audience="owner",
        expected_principal=PRINCIPAL)

    assert view.authority_guard == port.guard
    assert view.graph_binding.principal == PRINCIPAL
    assert view.graph_binding.capabilities == frozenset({"workbench.read"})
    assert len(coordinator._GraphCoordinator__leases) == leases_before
    assert port.guard_reads == 2 and port.finishes == 1


def test_current_owner_view_holds_on_changed_pairing_or_guard(owner_graph):
    _, coordinator, bootstrap, port, _, pairing = owner_graph
    pairing["principal"] = OwnerPrincipalV1("owner-idp", "other", "incarnation")
    with pytest.raises(UnavailableGuard, match="pairing changed"):
        coordinator.read_current_owner_view(
            bootstrap, actor="owner-session", namespace=NAMESPACE,
            purpose="workbench_view", audience="owner",
            expected_principal=PRINCIPAL)
    pairing["principal"] = PRINCIPAL
    port.guard = replace(port.guard, pending_revoke_operation_id="revoke-1")
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.read_current_owner_view(
            bootstrap, actor="owner-session", namespace=NAMESPACE,
            purpose="workbench_view", audience="owner",
            expected_principal=PRINCIPAL)


def test_current_owner_view_holds_on_guard_or_graph_change_during_read(owner_graph):
    graph, coordinator, bootstrap, port, _, _ = owner_graph
    def change_guard(read_number):
        if read_number == 2:
            port.guard = replace(port.guard, minimum_revocation_revision=1)

    port.on_guard_read = change_guard
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.read_current_owner_view(
            bootstrap, actor="owner-session", namespace=NAMESPACE,
            purpose="workbench_view", audience="owner",
            expected_principal=PRINCIPAL)

    port.guard = replace(port.guard, minimum_revocation_revision=0)
    port.guard_reads = 0

    def change_graph(read_number):
        if read_number == 2:
            with graph._lock:
                graph._db.execute(
                    "UPDATE graph_epochs SET revision=2 WHERE bot=? AND persona=?",
                    NAMESPACE.as_tuple)

    port.on_guard_read = change_graph
    with pytest.raises(UnavailableGuard):
        coordinator.read_current_owner_view(
            bootstrap, actor="owner-session", namespace=NAMESPACE,
            purpose="workbench_view", audience="owner",
            expected_principal=PRINCIPAL)


def test_owner_lease_denies_unpaired_and_changed_purpose(owner_graph):
    _, coordinator, bootstrap, port, key, _ = owner_graph
    with pytest.raises(UnavailableGuard, match="pairing"):
        coordinator.grant_current_owner(
            bootstrap, actor="dashboard-admin", namespace=NAMESPACE,
            domains=("d11",), purpose="workbench_view", audience="owner",
            activation_generation=1)
    assert port.finishes == 0
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d11",), purpose="workbench_view", audience="owner",
        activation_generation=1)
    with pytest.raises(UnavailableGuard, match="current Owner graph read lease"):
        coordinator.query(
            replace(authority, purpose="workbench_user_action"), lease,
            type_names=(key.type_name,), owner_kind="persona")
    assert port.finishes == 1


def test_owner_head_change_during_read_discards_projection(owner_graph):
    _, coordinator, bootstrap, port, key, _ = owner_graph
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d11",), purpose="workbench_view", audience="owner",
        activation_generation=1)

    def revoke_on_second_guard(read_number):
        if read_number == 4:
            port.guard = replace(
                port.guard, pending_revoke_operation_id="revoke-during-read")

    port.on_guard_read = revoke_on_second_guard
    with pytest.raises(UnavailableGuard, match="Owner lease differs"):
        coordinator.query(
            authority, lease, type_names=(key.type_name,), owner_kind="persona")
    assert port.finishes == 2


def test_production_without_v2_cannot_fall_back_to_legacy_d12(tmp_path):
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    graph = ProductionGraphStore(tmp_path / "legacy-business.db", registry)
    bootstrap = object()
    coordinator = GraphCoordinator(
        graph, bootstrap, holder="holder", deletion_journal=object(),
        migration_authority=object(), restore_authority=object(),
        execution_journal_port=SimpleNamespace(verify_current_chain=lambda: True),
        snapshot_requirements=lambda namespace: None,
        content_fence=lambda *args: None,
        d02_issuer=SimpleNamespace(authorize_resources=lambda *args: True),
        d11_issuer=SimpleNamespace(admit_runtime=lambda *args: True),
    )
    spec = registry.spec(owner_grant_key(*NAMESPACE.as_tuple).type_name)
    coordinator.register_provider(bootstrap, "d11", Provider(), "owner", spec.schema_hash)
    try:
        with pytest.raises(UnavailableGuard, match="D12 requires"):
            coordinator.grant(
                bootstrap, actor="owner-session", issuer_domain="d12",
                namespace=NAMESPACE, domains=("d11",), activation_generation=1)
        with pytest.raises(UnavailableGuard, match="resolver is unavailable"):
            coordinator.grant_current_owner(
                bootstrap, actor="owner-session", namespace=NAMESPACE,
                domains=("d11",), purpose="workbench_view", audience="owner",
                activation_generation=1)

        # Exercise the authorization boundary even if an internal caller has
        # retained a process lease from before the port configuration changed.
        lease, ref = coordinator._grant_registered(
            actor="owner-session", issuer_domain="d12", namespace=NAMESPACE,
            domains=("d11",), activation_generation=1)
        authority = AuthorityContext(
            "owner-session", "d12", ref, NAMESPACE, ("persona",),
            "workbench_view", ("owner",), "owner-grant-v1", 1)
        with pytest.raises(UnavailableGuard, match="current Owner graph read lease"):
            coordinator.read_snapshot(
                authority, lease, (owner_grant_key(*NAMESPACE.as_tuple),))
    finally:
        graph.close()
