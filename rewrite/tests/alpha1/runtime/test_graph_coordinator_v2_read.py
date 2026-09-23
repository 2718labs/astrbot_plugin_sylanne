"""Production graph reads admit against durable v2 recovery targets."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry, TypeSpec
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId, SnapshotRequirementsV2


NAMESPACE = NamespaceId("bot", "persona")


class ControlledFencePort:
    """Test Authority boundary: exact scopes, live permits, and no graph lock during RPC."""

    def __init__(self, store, anchor):
        self.store = store
        self.anchor = anchor
        self.active = None
        self.validations = 0
        self.finishes = []
        self.on_validate = None
        self.fences = None

    def _outside_graph_lock(self):
        assert not self.store._lock._is_owned()

    def current_anchor(self, *, namespace, authority_namespace):
        self._outside_graph_lock()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        return self.anchor

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self._outside_graph_lock()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        assert holder == "holder" and generation == 1 and operation == "read"
        assert expected_anchor == self.anchor and self.active is None
        if self.fences is not None:
            self.active = self.fences.begin_fence(
                subject="subject", holder=holder, operation=operation,
                operation_id=operation_id, current_anchor=expected_anchor)
            return self.active
        self.active = FencePermitV2(
            self.anchor.authority_id, authority_namespace, "subject", holder,
            generation, operation, operation_id, "x" * 48, 1, 0, expected_anchor)
        return self.active

    def validate_fence(self, scope):
        self._outside_graph_lock()
        assert scope.permit is self.active and scope.pinned_anchor == self.anchor
        assert scope.namespace == NAMESPACE and scope.graph_epoch.revision == 0
        self.validations += 1
        if self.on_validate is not None:
            self.on_validate(self.validations)
        if self.fences is not None:
            return self.fences.validate_fence(
                scope.permit, subject="subject", current_anchor=self.anchor)
        return self.active

    def finish_fence(self, scope, *, request_id, request_digest):
        self._outside_graph_lock()
        assert scope.permit is self.active
        assert request_id == "finish:" + scope.operation_id
        assert len(request_digest) == 71 and request_digest.startswith("sha256:")
        assert all(char in "0123456789abcdef" for char in request_digest[7:])
        if self.fences is not None:
            self.fences.finish_fence(
                scope.permit, subject="subject", current_anchor=self.anchor,
                request_id=request_id, request_digest=request_digest)
        self.finishes.append((request_id, request_digest))
        self.active = None


class Provider:
    def validate(self, proposal, snapshot):
        return True


@pytest.fixture
def setup(tmp_path):
    registry = TypeRegistry()
    registry.register(TypeSpec(
        "state", ("persona",), "state", lambda value: None,
        writer_domain="d06", schema_hash="a" * 64))
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    anchor = RestoreAnchor(
        "authority", "opaque-namespace", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "authority-proof")
    target = SnapshotRequirementsV2(
        NAMESPACE, anchor.authority_id, anchor.namespace, anchor.activation_generation,
        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest,
        anchor.revocation_epoch, "graph-incarnation")
    port = ControlledFencePort(store, anchor)
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="holder", content_fence_v2=port)
    coordinator.register_provider(bootstrap, "d06", Provider(), "schema", "a" * 64)
    lease, ref = coordinator.grant(
        bootstrap, actor="actor", issuer_domain="d06", namespace=NAMESPACE,
        domains=("d06",), activation_generation=1)
    authority = AuthorityContext(
        "actor", "d06", ref, NAMESPACE, ("persona",), "remember",
        ("internal",), "policy", 1)
    key = AtomKey(Owner("persona", "bot", "persona"), "state", "mood")
    try:
        yield store, coordinator, bootstrap, port, target, authority, lease, key
    finally:
        store.close()


def install(store, target):
    return store.install_graph_recovery_genesis(
        target, _capability=store._coordinator_capability)


def test_v2_reads_use_full_stored_target_and_two_validations(setup):
    store, coordinator, bootstrap, port, target, authority, lease, key = setup
    install(store, target)
    snapshot = coordinator.read_snapshot(authority, lease, (key,))
    assert snapshot.get(key).revision == 0
    assert coordinator.query(
        authority, lease, type_names=("state",), owner_kind="persona") is not None
    assert coordinator.get_operation(authority, lease, "missing") is None
    assert port.validations == 6 and len(port.finishes) == 3
    with pytest.raises(UnavailableGuard, match="v2 graph write"):
        coordinator.set_guard_version(bootstrap, NAMESPACE, "policy", "current", "1")


def test_v2_read_without_persisted_metadata_fails_before_authority_call(setup):
    _, coordinator, _, port, _, authority, lease, key = setup
    with pytest.raises(UnavailableGuard, match="metadata is absent"):
        coordinator.read_snapshot(authority, lease, (key,))
    assert port.validations == 0 and not port.finishes


def test_v2_read_finishes_a_real_durable_fence(setup, tmp_path):
    store, coordinator, _, port, target, authority, lease, key = setup
    install(store, target)
    db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    try:
        port.fences = AuthorityV2FenceStore(db, create=True)
        assert coordinator.read_snapshot(authority, lease, (key,)).get(key).revision == 0
        request_id, request_digest = port.finishes[0]
        permit, state, pending = port.fences.get_operation(
            request_id.removeprefix("finish:"), subject="subject",
            namespace=target.authority_namespace)
        assert state == "finished" and pending is None
        port.fences.finish_fence(
            permit, subject="subject", current_anchor=port.anchor,
            request_id=request_id, request_digest=request_digest)
    finally:
        db.close()


def test_v2_read_rejects_different_full_anchor(setup):
    store, coordinator, _, port, target, authority, lease, key = setup
    install(store, target)
    port.anchor = replace(port.anchor, revocation_epoch=1)
    with pytest.raises(UnavailableGuard, match="anchor differs"):
        coordinator.read_snapshot(authority, lease, (key,))
    assert port.validations == 0 and not port.finishes


def test_v2_read_rejects_recovery_revision_changed_during_read(setup):
    store, coordinator, _, port, target, authority, lease, key = setup
    original = install(store, target)

    def recover(count):
        if count == 2:
            with store._lock:
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    store.cas_graph_recovery_metadata(
                        original, replace(target, revocation_epoch=1),
                        _capability=store._coordinator_capability)
                    store._db.execute("COMMIT")
                except BaseException:
                    store._db.execute("ROLLBACK")
                    raise

    port.on_validate = recover
    with pytest.raises(UnavailableGuard, match="stamp changed"):
        coordinator.read_snapshot(authority, lease, (key,))
    assert port.validations == 2 and len(port.finishes) == 1
