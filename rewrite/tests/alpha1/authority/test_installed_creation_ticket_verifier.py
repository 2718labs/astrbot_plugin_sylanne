"""A real GraphStore genesis is necessary for an offline first Owner pairing."""

from dataclasses import replace
import json
import sqlite3

import pytest

from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import AuthorityPort, policy_for
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.installed_creation_ticket_verifier import (
    PinnedInstalledCreationTicketVerifier,
)
from sylanne3.authority_service.v2_owner_contract import OwnerClaimTicketV1, OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import GraphCoordinator, namespace_ref
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.runtime_contracts import NamespaceBootstrapV2, NamespaceRuntimeState


class CurrentAuthorityPort(AuthorityPort):
    def provision_namespace(self, *, namespace, request_id):
        self.outside_graph_lock()
        anchor = self.anchors[namespace]
        return NamespaceBootstrapV2(
            "authority", namespace, anchor.namespace, "administrator", 1,
            "active", NamespaceRuntimeState.ACTIVE, anchor, (),
        )


@pytest.fixture
def original(tmp_path):
    graph = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    core = AuthorityServiceCore(
        tmp_path / "authority.db",
        authorizer=lambda *_: True,
        deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True,
        create=True,
    )
    authority_db = sqlite3.connect(tmp_path / "fences.db", isolation_level=None)
    try:
        policy = replace(policy_for(graph), authority_namespace=namespace_ref(policy_for(graph).namespace))
        with core._tx() as db:
            db.execute("UPDATE authority_meta SET value='authority' WHERE key='authority_id'")
        core.register_namespace(
            "admin", policy.authority_namespace, "administrator",
            JournalHead("deletion:persona", 0, "genesis"),
            JournalHead("execution:persona", 0, "genesis"),
        )
        anchor = core.current_anchor("admin", policy.authority_namespace)
        core.seal_v2_only("admin")
        AuthorityV2OwnerTicketStore(core, create=True)
        port = CurrentAuthorityPort(graph, authority_db)
        port.anchors[policy.namespace] = anchor
        _, issuer = build_runtime_issuers(b"issuer-key-" * 4)
        bootstrap = object()
        coordinator = GraphCoordinator(
            graph, bootstrap, holder="administrator", content_fence_v2=port,
            d11_issuer=issuer,
        )
        receipt = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="creation-1")
        ticket = OwnerClaimTicketV1(
            "authority", "installation", policy.namespace,
            OwnerPrincipalV1("idp", "account", "incarnation"),
            "ticket-1", receipt.operation_id, "sha256:" + receipt.input_digest,
            "sha256:" + receipt.input_digest, "a" * 32,
            "2099-01-01T00:00:00Z",
        )
        yield graph, core, ticket, PinnedInstalledCreationTicketVerifier(
            tmp_path / "business.db", core)
    finally:
        graph.close()
        core.close()
        authority_db.close()


def test_real_graph_genesis_and_current_core_anchor(original):
    _, _, ticket, verifier = original
    assert verifier._current_anchor(ticket) is not None
    with sqlite3.connect(verifier._path) as db:
        assert verifier._graph_original(db, ticket, verifier._current_anchor(ticket)) is True
    assert verifier(ticket) is True
    assert verifier(replace(ticket, creation_operation_id="another")) is False
    assert verifier(replace(ticket, creation_digest="sha256:" + "f" * 64)) is False
    assert verifier(replace(ticket, installation_id="other")) is False
    # A principal is an administrator pairing decision, not a graph original.
    assert verifier(replace(ticket, principal=OwnerPrincipalV1("idp", "other", "incarnation"))) is True


def test_tampered_intent_and_missing_creation_hold(original):
    graph, _, ticket, verifier = original
    ns = ticket.namespace.as_tuple
    graph._db.execute("DROP TRIGGER graph_namespace_provision_intent_anchor_once_v2")
    graph._db.execute(
        "UPDATE graph_namespace_provision_intents_v2 SET identity_json=? "
        "WHERE bot=? AND persona=?", (json.dumps({"forged": True}),) + ns,
    )
    assert verifier(ticket) is False
    graph._db.execute("DELETE FROM graph_namespace_provisioning_v2 WHERE bot=? AND persona=?", ns)
    assert verifier(ticket) is False


def test_old_graph_or_registered_ticket_holds(original):
    _, core, ticket, verifier = original
    namespace = namespace_ref(ticket.namespace)
    with core._tx() as db:
        db.execute(
            "INSERT INTO authority_owner_claim_tickets_v1"
            "(authority_namespace,ticket_id,ticket_bytes) VALUES(?,?,?)",
            (namespace, ticket.ticket_id, b"already registered"),
        )
    assert verifier(ticket) is False
    with core._tx() as db:
        db.execute("DELETE FROM authority_owner_claim_tickets_v1 WHERE authority_namespace=?", (namespace,))
        db.execute("UPDATE authority_namespaces SET revocation_epoch=1 WHERE namespace=?", (namespace,))
    assert verifier(ticket) is False


def test_graph_issue_without_new_creation_hold(original):
    graph, _, ticket, verifier = original
    graph._db.execute(
        "INSERT INTO graph_owner_issue_operations_v1"
        "(bot,persona,operation_id,request_digest,grant_id,grant_digest,"
        "graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ticket.namespace.as_tuple + (
            "issued", "digest", "grant", "digest", "graph", 1, 1, "digest", "{}",
        ),
    )
    assert verifier(ticket) is False
