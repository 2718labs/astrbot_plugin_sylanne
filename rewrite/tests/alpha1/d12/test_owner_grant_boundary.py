"""The D12 consumer must never infer owner access from a dashboard login."""

from __future__ import annotations

from uuid import uuid4

from sylanne3.graph_types import GraphPage, GraphSnapshot, NamespaceEpoch
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api import (
    AuthenticatedSession, CoordinatorGrant, CurrentOwnerGrant,
    DurableOwnerGrantResolver, GraphWorkbenchIssuer, RequestContext,
    WorkbenchService,
)


SCOPE = "bot/persona"
SESSION = AuthenticatedSession(
    "dashboard-admin", "authenticated-session",
    {SCOPE: frozenset({"workbench.read"})},
    {SCOPE: frozenset({"owner"})},
    {SCOPE: frozenset({"workbench_view"})},
)


class W01Port:
    def __init__(self, current):
        self.current = current
        self.calls = []

    def resolve_current_owner(self, **kwargs):
        self.calls.append(kwargs)
        return self.current


class Graph:
    def __init__(self):
        self.queries = 0

    def query(self, *args, **kwargs):
        self.queries += 1
        return GraphPage(GraphSnapshot((), (NamespaceEpoch("bot", "persona", 1),)), None)


class Views:
    def view_types(self, authority):
        return {"overview": ("d01.persona_plan.v1",)}

    def view_owner_kind(self, authority, view_type):
        return "persona"

    def project_workbench(self, authority, view_type, atoms):
        return {"items": []}


def request():
    return {
        "schema_version": "d12.contract.v1", "action": "read_character_view",
        "scope": SCOPE, "purpose": "workbench_view", "audience": "owner",
        "operation_id": str(uuid4()), "input": {"view_type": "overview"},
    }


def current(*, actor="dashboard-admin", issuer="authority:paired-installation"):
    namespace = NamespaceId("bot", "persona")
    authority = AuthorityContext(
        actor, "d12", "w01:grant-ref", namespace, ("persona",),
        "workbench_view", ("owner",), "installed-policy", 4,
    )
    return CurrentOwnerGrant(
        "durable-grant-id", issuer, actor, SCOPE, namespace,
        frozenset({"workbench.read"}), frozenset({"workbench_view"}),
        frozenset({"owner"}), 2, 1,
        CoordinatorGrant(SCOPE, authority, object()),
    )


def service(port):
    graph = Graph()
    issuer = GraphWorkbenchIssuer(graph, DurableOwnerGrantResolver(port), Views())
    return WorkbenchService(issuer), graph


def test_admin_session_without_w01_owner_grant_cannot_read():
    subject, graph = service(None)
    answer = subject.handle(request(), session=SESSION,
                            context=RequestContext(True, True, True))
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "authority_unavailable"
    assert graph.queries == 0


def test_w01_resolution_is_checked_on_every_read_and_revoke_blocks_next_read():
    port = W01Port(current())
    subject, graph = service(port)
    first = subject.handle(request(), session=SESSION,
                           context=RequestContext(True, True, True))
    assert first.status == "ready"
    assert graph.queries == 1
    assert port.calls == [{"actor_id": "dashboard-admin", "scope": SCOPE,
                           "purpose": "workbench_view", "audience": "owner"}]

    port.current = None  # W01 has revoked the durable grant.
    second = subject.handle(request(), session=SESSION,
                            context=RequestContext(True, True, True))
    assert second.status == "unavailable"
    assert second.projection is None
    assert graph.queries == 1
    assert len(port.calls) == 2


def test_wrong_actor_or_untrusted_scope_is_not_promoted_to_owner():
    port = W01Port(current(actor="another-user"))
    subject, graph = service(port)
    answer = subject.handle(request(), session=SESSION,
                            context=RequestContext(True, True, True))
    assert answer.status == "unavailable" and graph.queries == 0

    port.current = "browser-supplied-owner-claim"
    answer = subject.handle(request(), session=SESSION,
                            context=RequestContext(True, True, True))
    assert answer.status == "unavailable" and graph.queries == 0

    granted = current()
    port.current = CurrentOwnerGrant(
        granted.grant_id, granted.issuer_ref, granted.actor_id, granted.scope,
        granted.namespace, frozenset(), granted.purposes, granted.audiences,
        granted.grant_revision, granted.revocation_epoch, granted.grant,
    )
    answer = subject.handle(request(), session=SESSION,
                            context=RequestContext(True, True, True))
    assert answer.status == "unavailable" and graph.queries == 0
