"""S14 slice: an old business graph cannot read past a durable deletion intent.

The source row is a controlled graph fixture. Read admission, Authority Core,
the deletion and execution journals, and recovery metadata are production code.
"""

import shutil
import sqlite3

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry, TypeSpec
from sylanne3.runtime_contracts import (
    AuthorityContext, NamespaceId, SnapshotRequirementsV2,
)


ROLE = NamespaceId("bot", "persona")


class _LocalAuthorityPort:
    """Controlled in-process transport to the durable Authority service."""

    def __init__(self, graph, service):
        self.graph = graph
        self.service = service
        self.validation_count = 0

    def _outside_graph(self):
        assert not self.graph._lock._is_owned()

    def current_anchor(self, *, namespace, authority_namespace):
        self._outside_graph()
        assert (namespace, authority_namespace) == (ROLE, "ns-a")
        return self.service.current_anchor(credential="ok", subject="subject-a")

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self._outside_graph()
        assert (namespace, authority_namespace, holder, generation, operation) == (
            ROLE, "ns-a", "holder-a", 1, "read")
        return self.service.begin_fence(
            credential="ok", subject="subject-a", holder=holder,
            operation=operation, operation_id=operation_id,
            expected_anchor=expected_anchor)

    def validate_fence(self, scope):
        self._outside_graph()
        self.validation_count += 1
        return self.service.validate_fence(
            credential="ok", subject="subject-a", permit=scope.permit)

    def finish_fence(self, scope, *, request_id, request_digest):
        self._outside_graph()
        return self.service.finish_fence(
            credential="ok", subject="subject-a", permit=scope.permit,
            request_id=request_id, request_digest=request_digest)


def _graph(path, service):
    registry = TypeRegistry()
    registry.register(TypeSpec(
        "private_note", ("persona",), "state", lambda _: None,
        writer_domain="d06", schema_hash="a" * 64))
    graph = ProductionGraphStore(path, registry)
    port = _LocalAuthorityPort(graph, service)
    bootstrap = object()
    coordinator = GraphCoordinator(
        graph, bootstrap, holder="holder-a", content_fence_v2=port)
    provider = D06DomainProvider()
    coordinator.register_provider(
        bootstrap, "d06", provider, "d06.contract.v1",
        provider.descriptor.request_schema_hash)
    lease, capability = coordinator.grant(
        bootstrap, actor="owner", issuer_domain="d06", namespace=ROLE,
        domains=("d06",), activation_generation=1)
    authority = AuthorityContext(
        "owner", "d06", capability, ROLE, ("persona",), "remember",
        ("owner",), "policy", 1)
    key = AtomKey(Owner("persona", "bot", "persona"), "private_note", "one")
    return graph, coordinator, lease, authority, key, port


def test_old_business_backup_cannot_read_after_independent_deletion(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    graph_path = tmp_path / "business.db"
    backup_path = tmp_path / "old-business.db"
    graph, coordinator, lease, authority, key, port = _graph(graph_path, service)
    try:
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        target = SnapshotRequirementsV2(
            ROLE, anchor.authority_id, anchor.namespace,
            anchor.activation_generation, anchor.deletion_journal_id,
            anchor.deletion_seq, anchor.deletion_digest,
            anchor.execution_journal_id, anchor.execution_seq,
            anchor.execution_digest, anchor.revocation_epoch,
            "graph-incarnation")
        graph.install_graph_recovery_genesis(
            target, _capability=graph._coordinator_capability)
        # Only the source row is fixture setup; no product ingress is claimed.
        graph._db.execute(
            "INSERT INTO graph_atoms"
            "(token,bot,persona,owner_kind,subject,type_name,name,revision,value,valid) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (key.token, "bot", "persona", "persona", None,
             "private_note", "one", 1, '{"text":"private fixture"}', 1))
        assert coordinator.read_snapshot(authority, lease, (key,)).get(key).value == (
            {"text": "private fixture"})
        assert port.validation_count == 3
        with sqlite3.connect(backup_path) as backup:
            graph._db.backup(backup)
        deletion.append_intent(
            namespace="ns-a", operation_id="delete-private-source",
            closure_roots=(key.token,), epoch=1, policy_ref="policy")
        assert deletion.latest_head().seq == 1
        assert execution.verified_head().seq == 0
        graph.close()
        shutil.copyfile(backup_path, graph_path)
        restored, restored_coordinator, old_lease, old_authority, old_key, restored_port = (
            _graph(graph_path, service))
        try:
            # The restored row is present, but content admission must fail
            # against the newer independent deletion journal.
            assert restored._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (old_key.token,)
            ).fetchone() is not None
            with pytest.raises(UnavailableGuard):
                restored_coordinator.read_snapshot(
                    old_authority, old_lease, (old_key,))
            assert restored_port.validation_count == 0
        finally:
            restored.close()
    finally:
        if graph._db is not None:
            try:
                graph.close()
            except sqlite3.ProgrammingError:
                pass
        core.close()
        deletion.close()
        guard.close()
        execution.close()
