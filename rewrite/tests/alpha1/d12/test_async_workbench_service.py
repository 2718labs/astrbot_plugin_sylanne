from __future__ import annotations

from threading import get_ident
from uuid import uuid4

import pytest

from sylanne3.graph_types import AtomKey, GraphAtom, GraphPage, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.graph_worker import GraphWorker
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api import (
    AsyncGraphWorkbenchService, AuthenticatedSession, CoordinatorGrant, RequestContext,
)


SCOPE = "bot/persona"
SESSION = AuthenticatedSession(
    "actor", "session", {SCOPE: frozenset({"workbench.read"})},
    {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"workbench_view"})},
)
CONTEXT = RequestContext(True, True, True)


def request():
    return {"schema_version": "d12.contract.v1", "action": "read_character_view",
            "scope": SCOPE, "purpose": "workbench_view", "audience": "owner",
            "operation_id": str(uuid4()), "input": {"view_type": "overview"}}


class Store:
    def close(self):
        pass


class Coordinator:
    def __init__(self, calls):
        self.calls = calls

    def query(self, authority, lease, **kwargs):
        self.calls.append(("query", get_ident()))
        atom = GraphAtom(
            AtomKey(Owner("persona", "bot", "persona"), "d01.persona_plan.v1", "current"),
            1, {"identity": "candidate"},
        )
        return GraphPage(GraphSnapshot((atom,), (NamespaceEpoch("bot", "persona", 1),)), None)


class Grants:
    def __init__(self, calls, grant):
        self.calls, self.grant = calls, grant

    def resolve(self, **kwargs):
        self.calls.append(("grant", get_ident()))
        return self.grant


class Views:
    def __init__(self, calls):
        self.calls = calls

    def view_types(self, authority):
        return {"overview": ("d01.persona_plan.v1",)}

    def view_owner_kind(self, authority, view_type):
        return "persona"

    def project_workbench(self, authority, view_type, atoms):
        self.calls.append(("project", get_ident()))
        return {"identity": atoms[0]["value"]["identity"]}


@pytest.mark.asyncio
async def test_async_workbench_command_runs_grant_query_and_projection_on_graph_worker():
    calls = []
    worker = await GraphWorker.start(Store, lambda store: Coordinator(calls))
    try:
        authority = AuthorityContext(
            "actor", "d12", "capability", NamespaceId("bot", "persona"),
            ("persona",), "workbench_view", ("owner",), "policy", 4,
        )
        service = AsyncGraphWorkbenchService(
            worker, Grants(calls, CoordinatorGrant(SCOPE, authority, object())), Views(calls),
        )
        answer = await service.handle(request(), session=SESSION, context=CONTEXT)
        assert answer.status == "ready"
        assert answer.projection["data"] == {"identity": "candidate"}
        assert [name for name, _ in calls] == ["grant", "query", "project"]
        assert len({thread for _, thread in calls}) == 1
        assert calls[0][1] != get_ident()
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_async_workbench_without_w01_grant_holds_without_graph_query():
    calls = []
    worker = await GraphWorker.start(Store, lambda store: Coordinator(calls))
    try:
        service = AsyncGraphWorkbenchService(worker, Grants(calls, None), Views(calls))
        answer = await service.handle(request(), session=SESSION, context=CONTEXT)
        assert answer.status == "unavailable"
        assert answer.problem["code"] == "authority_unavailable"
        assert answer.projection is None
        assert [name for name, _ in calls] == ["grant"]
    finally:
        await worker.close()
