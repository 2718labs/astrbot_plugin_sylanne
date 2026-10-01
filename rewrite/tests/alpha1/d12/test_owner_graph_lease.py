"""D12 production reads require the same live Owner heads as graph content."""

from dataclasses import asdict, replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.contracts import Event, Scope, canonical_json
from sylanne3.graph_coordinator import (
    GraphCoordinator, UnavailableGuard, namespace_ref,
)
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphWrite, Owner, TypeRegistry, owner_grant_key, owner_grant_spec,
)
from sylanne3.domains.d05 import RelationshipProvider
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, NamespaceId, SnapshotRequirementsV2, canonical_digest,
)
from sylanne3.workbench_api.owner_grant import (
    DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort,
)
from sylanne3.workbench_api.service import AuthenticatedSession, WorkbenchService
from sylanne3.workbench_api import (
    AsyncGraphWorkbenchService, CoordinatorGrant, CurrentDomainViewRegistry,
    GraphWorkbenchIssuer, RequestContext,
)


NAMESPACE = NamespaceId("bot", "persona")
PRINCIPAL = OwnerPrincipalV1("owner-idp", "account", "incarnation")
OWNER_TOKEN = "T" * 43
OWNER_REQUEST = OwnerSessionLoginRequestV1(
    "authority", namespace_ref(NAMESPACE), "installation", PRINCIPAL,
    "credential", 1, "owner", "https://dashboard.local")


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
        self.session_current = True
        self.operations = {}

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
        assert holder == "holder" and generation == 1 and operation in {"read", "write"}
        assert expected_anchor == self.anchor
        assert operation_id not in self.operations
        self.active = FencePermitV2(
            self.anchor.authority_id, authority_namespace, "subject", holder,
            generation, operation, operation_id, "x" * 48, 1, 0, self.anchor)
        self.operations[operation_id] = (self.active, "active")
        return self.active

    def get_fence_operation(self, *, namespace, authority_namespace, operation_id):
        self._outside_graph()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        return self.operations.get(operation_id, (None, "absent"))

    def validate_fence(self, scope):
        self._outside_graph()
        assert scope.permit is self.active and scope.pinned_anchor == self.anchor
        return self.active

    def get_current_owner_guard_for_fence(
            self, *, namespace, authority_namespace, permit,
            owner_actor_id=None, owner_session_token=None, owner_session_request=None):
        self._outside_graph()
        assert namespace == NAMESPACE and authority_namespace == self.anchor.namespace
        assert permit is self.active
        if owner_session_token is not None:
            assert (owner_actor_id, owner_session_token, owner_session_request) == (
                "owner-session", OWNER_TOKEN, OWNER_REQUEST)
            if not self.session_current:
                raise RuntimeError("Owner session revoked")
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
        self.operations[scope.operation_id] = (scope.permit, "finished")
        self.active = None

    def read_ingress_clock(self, _policy):
        import time
        self._outside_graph()
        return SimpleNamespace(monotonic_after_seconds=time.monotonic(),
                               utc_upper_bound_seconds=10.0)


class Provider:
    def validate(self, proposal, snapshot):
        return True


@pytest.fixture
def owner_graph(tmp_path):
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in RelationshipProvider().type_specs():
        registry.register(spec)
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
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
    d05 = RelationshipProvider()
    coordinator.register_provider(
        bootstrap, "d05", d05, "d05.proposal.v1", d05.descriptor.request_schema_hash,
    )
    d06 = D06DomainProvider()
    coordinator.register_provider(
        bootstrap, "d06", d06, "d06.contract.v1", d06.descriptor.request_schema_hash,
    )
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
        "purposes": ["context", "workbench_view"], "audiences": ["owner"],
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


def test_d05_relations_read_uses_committed_graph_and_current_owner_fence(owner_graph):
    graph, coordinator, bootstrap, port, _, _ = owner_graph
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d05", "d11"), purpose="workbench_view", audience="owner",
        activation_generation=1, owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST,
    )

    class Resolver:
        def resolve(self, **_kwargs):
            return CoordinatorGrant("bot/persona", authority, lease)

    issuer = GraphWorkbenchIssuer(
        coordinator, Resolver(), CurrentDomainViewRegistry(discover_domain_registry),
    )
    session = AuthenticatedSession(
        "owner-session", "signed-session",
        {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"workbench_view"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )
    payload = {
        "schema_version": "d12.contract.v1", "action": "read_character_view",
        "scope": "bot/persona", "purpose": "workbench_view", "audience": "owner",
        "operation_id": str(uuid4()), "input": {"view_type": "relations"},
    }

    def read():
        return WorkbenchService(issuer).handle(
            payload, session=session, context=RequestContext(True, True, True),
        ).as_dict()

    assert read()["projection"]["data"] == {"relations": [], "coverage": "complete"}
    key = AtomKey(Owner("relation", "bot", "persona", "entity:alice"),
                  "d05.relationship_projection", "trust:work")
    snapshot = GraphStore.graph_snapshot(
        graph, (key,), _capability=graph._coordinator_capability,
    )
    GraphStore.graph_commit(
        graph, GraphCandidate(
            Event(Scope("bot", "persona", "seed"), "relation-projection", 2.0,
                  "test", {}),
            snapshot.versions,
            (GraphWrite(key, {"subject_entity_ref": "entity:alice",
                              "dimension": "trust:work", "status": "available"}),),
            snapshot.epochs,
        ), _capability=graph._coordinator_capability,
    )
    with graph._lock:
        graph._db.execute("BEGIN IMMEDIATE")
        try:
            recovery = graph.graph_recovery_metadata(
                NAMESPACE, _capability=graph._coordinator_capability,
            )
            graph.cas_graph_recovery_metadata(
                recovery, recovery.requirements,
                _capability=graph._coordinator_capability,
            )
            graph._db.execute("COMMIT")
        except BaseException:
            graph._db.execute("ROLLBACK")
            raise

    assert read()["projection"]["data"] == {
        "relations": [{"subject_entity_ref": "entity:alice", "dimensions": [
            {"dimension": "trust:work", "status": "available"},
        ]}], "coverage": "complete",
    }
    denied = replace(session, scope_capabilities={"bot/persona": frozenset()})
    assert WorkbenchService(issuer).handle(
        payload, session=denied, context=RequestContext(True, True, True),
    ).status == "unauthorized"
    limited_authority, limited_lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d11",), purpose="workbench_view", audience="owner",
        activation_generation=1, owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST,
    )

    class LimitedResolver:
        def resolve(self, **_kwargs):
            return CoordinatorGrant("bot/persona", limited_authority, limited_lease)

    limited_issuer = GraphWorkbenchIssuer(
        coordinator, LimitedResolver(), CurrentDomainViewRegistry(discover_domain_registry),
    )
    assert WorkbenchService(limited_issuer).handle(
        payload, session=session, context=RequestContext(True, True, True),
    ).problem["code"] == "view_unsupported"
    coordinator.release_current_owner_lease(bootstrap, limited_lease)
    port.session_current = False
    revoked = read()
    assert revoked["status"] == "unavailable" and "projection" not in revoked
    coordinator.release_current_owner_lease(bootstrap, lease)


def test_d06_workbench_reads_authorized_source_then_hides_withdrawn_access(owner_graph):
    graph, coordinator, bootstrap, port, _, _ = owner_graph
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d06", "d11"), purpose="context", audience="owner",
        activation_generation=1, owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST,
    )

    class Resolver:
        def resolve(self, **_kwargs):
            return CoordinatorGrant("bot/persona", authority, lease)

    issuer = GraphWorkbenchIssuer(
        coordinator, Resolver(), CurrentDomainViewRegistry(discover_domain_registry),
    )
    session = AuthenticatedSession(
        "owner-session", "signed-session",
        {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"context"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )
    source = SourceRecord(
        "visible-source", "private source text", "private speaker", "reported",
        "reported", None, 7.0, "private provenance", ("owner",), ("context",),
    )
    source_ref = source_key("bot", "persona", source.source_id)
    access_ref = access_key("bot", "persona", source.source_id)

    def commit(event_id, writes):
        keys = tuple(dict.fromkeys(
            key for write in writes for key in (write.key, *write.dependencies)
        ))
        snapshot = GraphStore.graph_snapshot(
            graph, keys, _capability=graph._coordinator_capability,
        )
        GraphStore.graph_commit(
            graph, GraphCandidate(
                Event(Scope("bot", "persona", "seed"), event_id, 2.0, "test", {}),
                snapshot.versions, tuple(writes), snapshot.epochs,
            ), _capability=graph._coordinator_capability,
        )
        with graph._lock:
            graph._db.execute("BEGIN IMMEDIATE")
            try:
                recovery = graph.graph_recovery_metadata(
                    NAMESPACE, _capability=graph._coordinator_capability,
                )
                graph.cas_graph_recovery_metadata(
                    recovery, recovery.requirements,
                    _capability=graph._coordinator_capability,
                )
                graph._db.execute("COMMIT")
            except BaseException:
                graph._db.execute("ROLLBACK")
                raise

    def read():
        return issuer.read_projection(
            session=session, scope="bot/persona", view_type="d06.memory_sources.v1",
            purpose="context", audience="owner",
        )

    def access(status):
        return {"source_id": source.source_id, "audiences": ["owner"],
                "purposes": ["context"], "status": status, "recorded_at": 7.0}

    commit("source-visible", (
        GraphWrite(source_ref, source.to_dict()),
        GraphWrite(access_ref, access("active"), (source_ref,)),
    ))
    visible = read()
    assert visible["status"] == "ready"
    assert visible["projection"]["data"] == {"sources": [{
        "source_id": "visible-source", "source_kind": "reported",
        "assertion_status": "reported", "recorded_at": 7.0,
        "qualification": "not_recorded",
    }], "coverage": "complete"}
    assert "private source text" not in repr(visible)
    assert "private speaker" not in repr(visible)

    commit("source-withdrawn", (GraphWrite(
        access_ref, access("withdrawn"), (source_ref,),
    ),))
    withdrawn = read()
    assert withdrawn["status"] == "ready"
    assert withdrawn["projection"]["data"] == {"sources": [], "coverage": "complete"}
    assert source.source_id not in repr(withdrawn)

    port.session_current = False
    stale_owner = read()
    assert stale_owner["status"] == "unavailable" and "projection" not in stale_owner
    coordinator.release_current_owner_lease(bootstrap, lease)


def test_d06_workbench_uses_full_fenced_private_scan_without_count_side_channel(
        owner_graph, monkeypatch):
    graph, coordinator, bootstrap, _, _, _ = owner_graph
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d06", "d11"), purpose="context", audience="owner",
        activation_generation=1,
    )
    views = CurrentDomainViewRegistry(discover_domain_registry)

    class Resolver:
        def resolve(self, **_kwargs):
            return CoordinatorGrant("bot/persona", authority, lease)

    issuer = GraphWorkbenchIssuer(coordinator, Resolver(), views)
    session = AuthenticatedSession(
        "owner-session", "dashboard-session",
        {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"context"})},
    )
    baseline = issuer.read_projection(
        session=session, scope="bot/persona", view_type="d06.memory_sources.v1",
        purpose="context", audience="owner",
    )
    assert baseline["status"] == "ready"
    assert baseline["projection"]["data"]["sources"] == []

    namespace = NAMESPACE.as_tuple
    writes = []
    for index in range(400):
        source_id = f"private-{index:03d}"
        source_audiences = ("other",) if index % 3 == 0 else ("owner",)
        source = SourceRecord(
            source_id, f"private text {index}", "private speaker", "reported",
            "reported", None, 1.0, "private-provenance", source_audiences, ("context",),
        )
        source_ref = source_key(*namespace, source_id)
        access_ref = access_key(*namespace, source_id)
        writes.append(GraphWrite(source_ref, source.to_dict()))
        if index % 3 != 2:
            withdrawn = index % 3 == 1
            writes.append(GraphWrite(access_ref, {
                "source_id": source_id,
                "audiences": ["owner"] if withdrawn else ["other"],
                "purposes": ["context"],
                "status": "withdrawn" if withdrawn else "active",
                "recorded_at": 1.0,
            }, (source_ref,)))
    reads = GraphStore.graph_snapshot(
        graph, tuple(write.key for write in writes),
        _capability=graph._coordinator_capability,
    )
    GraphStore.graph_commit(
        graph,
        GraphCandidate(
            Event(Scope("bot", "persona", "seed"), "private-memory-batch", 2.0,
                  "test", {}),
            reads.versions, tuple(writes), reads.epochs,
        ),
        _capability=graph._coordinator_capability,
    )
    with graph._lock:
        graph._db.execute("BEGIN IMMEDIATE")
        try:
            recovery = graph.graph_recovery_metadata(
                NAMESPACE, _capability=graph._coordinator_capability,
            )
            graph.cas_graph_recovery_metadata(
                recovery, recovery.requirements,
                _capability=graph._coordinator_capability,
            )
            graph._db.execute("COMMIT")
        except BaseException:
            graph._db.execute("ROLLBACK")
            raise

    query_calls = []
    original_query = GraphStore.graph_query

    def count_memory_pages(store, *args, **kwargs):
        if set(kwargs.get("type_names", ())) == {
                "memory.source", "memory.access", "memory.interpretation"}:
            query_calls.append(kwargs)
        return original_query(store, *args, **kwargs)

    monkeypatch.setattr(GraphStore, "graph_query", count_memory_pages)
    after_private_rows = issuer.read_projection(
        session=session, scope="bot/persona", view_type="d06.memory_sources.v1",
        purpose="context", audience="owner",
    )
    assert len(query_calls) == 2
    assert after_private_rows["status"] == baseline["status"] == "ready"
    assert after_private_rows["projection"] == baseline["projection"]
    assert "private text" not in repr(after_private_rows)
    assert "private-" not in repr(after_private_rows)

    coordinator.release_current_owner_lease(bootstrap, lease)


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


def test_workbench_port_issues_real_current_owner_lease(owner_graph):
    _, coordinator, bootstrap, owner_guard, key, _ = owner_graph
    subject = GraphCurrentOwnerGrantPort(
        coordinator, bootstrap, namespace=NAMESPACE,
        activation_generation=1, domains=("d11",))

    assert subject.resolve_current_owner(
        actor_id="owner-session", scope="bot/persona",
        purpose="workbench_view", audience="owner") is None
    assert len(coordinator._GraphCoordinator__leases) == 0
    session = AuthenticatedSession(
        "owner-session", "signed-session",
        {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"workbench_view"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )
    with subject.request_scope():
        assert subject.resolve_current_owner(
            actor_id="owner-session", scope="bot/persona",
            purpose="workbench_view", audience="owner") is None
        assert subject.resolve_current_owner(
            actor_id="owner-session", scope="other/persona",
            purpose="workbench_view", audience="owner") is None
        current = subject.resolve_current_owner(
            actor_id="owner-session", scope="bot/persona",
            purpose="workbench_view", audience="owner",
            owner_session_token=OWNER_TOKEN,
            owner_session_request=OWNER_REQUEST)
        assert current is not None
        assert current.scope == "bot/persona" and current.grant_id == "grant-1"
        assert current.grant.authority.namespace == NAMESPACE
        assert DurableOwnerGrantResolver(subject).resolve(
            session=session, scope="bot/persona", purpose="workbench_view",
            audience="owner") is not None
        assert coordinator.query(
            current.grant.authority, current.grant.lease,
            type_names=(key.type_name,), owner_kind="persona")
        owner_guard.session_current = False
        with pytest.raises(UnavailableGuard, match="content authority"):
            coordinator.query(
                current.grant.authority, current.grant.lease,
                type_names=(key.type_name,), owner_kind="persona")
        owner_guard.session_current = True
        with pytest.raises(PermissionError, match="host bootstrap"):
            coordinator.release_current_owner_lease(object(), current.grant.lease)
    assert len(coordinator._GraphCoordinator__leases) == 0
    assert len(coordinator._GraphCoordinator__owner_leases) == 0
    with pytest.raises(PermissionError, match="unknown process authority"):
        coordinator.query(
            current.grant.authority, current.grant.lease,
            type_names=(key.type_name,), owner_kind="persona")
    ordinary, _ = coordinator.grant(
        bootstrap, actor="owner-session", issuer_domain="d11",
        namespace=NAMESPACE, domains=("d11",), activation_generation=1)
    with pytest.raises(PermissionError, match="current Owner lease required"):
        coordinator.release_current_owner_lease(bootstrap, ordinary)


def test_workbench_port_denies_wrong_actor_pairing_and_revoke(owner_graph):
    _, coordinator, bootstrap, guard_port, _, pairing = owner_graph
    subject = GraphCurrentOwnerGrantPort(
        coordinator, bootstrap, namespace=NAMESPACE,
        activation_generation=1, domains=("d11",))
    request = dict(
        scope="bot/persona", purpose="workbench_view", audience="owner",
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST)
    with subject.request_scope():
        assert subject.resolve_current_owner(actor_id="dashboard-admin", **request) is None
        pairing["principal"] = OwnerPrincipalV1("owner-idp", "other", "incarnation")
        assert subject.resolve_current_owner(actor_id="owner-session", **request) is None
        pairing["principal"] = PRINCIPAL
        guard_port.guard = replace(guard_port.guard, pending_revoke_operation_id="revoke-1")
        assert subject.resolve_current_owner(actor_id="owner-session", **request) is None
    assert len(coordinator._GraphCoordinator__leases) == 0


@pytest.mark.asyncio
async def test_async_workbench_releases_owner_lease_after_each_read_and_exception(owner_graph):
    _, coordinator, bootstrap, owner_guard, key, _ = owner_graph
    port = GraphCurrentOwnerGrantPort(
        coordinator, bootstrap, namespace=NAMESPACE,
        activation_generation=1, domains=("d11",))
    resolver = DurableOwnerGrantResolver(port)
    session = AuthenticatedSession(
        "owner-session", "signed-session",
        {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"workbench_view"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )

    class Views:
        def view_types(self, authority):
            return {"overview": (key.type_name,)}

        def view_owner_kind(self, authority, view_type):
            return "persona"

        def project_workbench(self, authority, view_type, atoms):
            return {"count": len(atoms)}

    class Store:
        def close(self):
            pass

    worker = await GraphWorker.start(Store, lambda store: coordinator)
    try:
        service = AsyncGraphWorkbenchService(worker, resolver, Views())
        payload = {
            "schema_version": "d12.contract.v1", "action": "read_character_view",
            "scope": "bot/persona", "purpose": "workbench_view", "audience": "owner",
            "operation_id": str(uuid4()), "input": {"view_type": "overview"},
        }
        for _ in range(3):
            answer = await service.handle(
                payload, session=session, context=RequestContext(True, True, True))
            assert answer.status == "ready"
            assert len(coordinator._GraphCoordinator__leases) == 0
            assert len(coordinator._GraphCoordinator__owner_leases) == 0

        owner_guard.session_current = False
        revoked = await service.handle(
            payload, session=session, context=RequestContext(True, True, True))
        assert revoked.status == "unavailable"
        assert revoked.problem["code"] == "authority_unavailable"
        assert len(coordinator._GraphCoordinator__leases) == 0
        owner_guard.session_current = True

        class RaisingResolver(DurableOwnerGrantResolver):
            def resolve(self, **kwargs):
                assert super().resolve(**kwargs) is not None
                raise RuntimeError("projection interrupted")

        broken = AsyncGraphWorkbenchService(worker, RaisingResolver(port), Views())
        failed = await broken.handle(
            payload, session=session, context=RequestContext(True, True, True))
        assert failed.status == "unavailable"
        assert failed.problem["code"] == "provider_failed"
        assert len(coordinator._GraphCoordinator__leases) == 0
        assert len(coordinator._GraphCoordinator__owner_leases) == 0
    finally:
        await worker.close()


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
