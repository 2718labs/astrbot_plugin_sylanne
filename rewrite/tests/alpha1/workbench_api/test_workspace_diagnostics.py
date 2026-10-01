from uuid import uuid4

from sylanne3.graph_types import AtomKey, GraphAtom, GraphPage, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer
from sylanne3.workbench_api.service import (
    AuthenticatedSession, RequestContext, WorkbenchService,
)


SCOPE = "bot/persona"
CONTEXT = RequestContext(True, True, True)


class Resolver:
    def __init__(self):
        self.calls = 0

    def resolve(self, **kwargs):
        self.calls += 1
        return CoordinatorGrant(SCOPE, AuthorityContext(
            "actor", "d12", "capability", NamespaceId("bot", "persona"),
            ("persona",), "workbench_view", ("owner",), "policy", 4,
        ), object())


class Registry:
    def view_types(self, authority):
        return {"overview": ("d01.public.v1",)}

    def view_owner_kind(self, authority, view_type):
        return "persona"

    def project_workbench(self, authority, view_type, atoms):
        return {"private_content": "do not copy into diagnostics"}


class Coordinator:
    def __init__(self):
        self.calls = 0
        atom = GraphAtom(AtomKey(Owner("persona", "bot", "persona"),
                                 "d01.public.v1", "current"), 1, {"private": "secret"})
        self.page = GraphPage(GraphSnapshot((atom,),
                           (NamespaceEpoch("bot", "persona", 9),)), atom.key)

    def query(self, authority, lease, **kwargs):
        self.calls += 1
        return self.page


def session(allowed=True):
    return AuthenticatedSession(
        "actor", "session",
        {SCOPE: frozenset({"workbench.read"}) if allowed else frozenset()},
        {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"workbench_view"})},
    )


def request():
    return {"schema_version": "d12.contract.v1", "action": "open_workspace",
            "scope": SCOPE, "purpose": "workbench_view", "audience": "owner",
            "operation_id": str(uuid4()),
            "input": {"client_protocol": "d12.contract.v1"}}


def test_authorized_workspace_reports_real_partial_read_without_content():
    coordinator, resolver = Coordinator(), Resolver()
    service = WorkbenchService(GraphWorkbenchIssuer(coordinator, resolver, Registry()))
    result = service.handle(request(), session=session(), context=CONTEXT)
    assert result.status == "ready"
    assert result.projection["view_diagnostics"] == ({
        "view_type": "overview", "read_status": "ready",
        "coverage": "partial", "snapshot_epoch": 9,
    },)
    assert "private_content" not in str(result.projection["view_diagnostics"])
    assert "secret" not in str(result.projection["view_diagnostics"])
    assert coordinator.calls == 1


def test_unauthorized_workspace_does_not_resolve_or_query():
    coordinator, resolver = Coordinator(), Resolver()
    service = WorkbenchService(GraphWorkbenchIssuer(coordinator, resolver, Registry()))
    result = service.handle(request(), session=session(False), context=CONTEXT)
    assert result.status == "unauthorized"
    assert result.projection is None
    assert coordinator.calls == resolver.calls == 0


def test_failed_graph_read_reports_reason_without_advertising_view():
    coordinator, resolver = Coordinator(), Resolver()
    coordinator.page = object()
    service = WorkbenchService(GraphWorkbenchIssuer(coordinator, resolver, Registry()))
    result = service.handle(request(), session=session(), context=CONTEXT)
    assert result.status == "ready"
    assert result.projection["views"] == ({"view_type": "overview", "status": "unavailable"},)
    assert result.projection["view_diagnostics"] == ({
        "view_type": "overview", "read_status": "unavailable",
        "problem_code": "invalid_graph_snapshot",
    },)
