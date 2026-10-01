from __future__ import annotations

import json
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.graph_coordinator import SourceAccessRevocationReceiptV1
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.workbench_api import (
    AuthenticatedSession, CoordinatorGrant, GraphWorkbenchIssuer,
    RequestContext, WorkbenchService,
)
from sylanne3.workbench_api.http_transport import (
    SYLANNE_OWNER_SESSION_COOKIE, TransportConfig, WorkbenchHttpTransport,
)
from tests.alpha1.d12.test_owner_graph_lease import (
    OWNER_REQUEST, OWNER_TOKEN, owner_graph as owner_graph_fixture,
)
from tests.alpha1.runtime.test_source_access_revocation_owner_v1 import _case
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case


SCOPE = "bot/persona"
CONTEXT = RequestContext(True, True, True)
LOGIN = OwnerSessionLoginRequestV1(
    "authority", SCOPE, "installation",
    OwnerPrincipalV1("host", "owner", "incarnation"),
    "credential", 1, "owner", "https://localhost:8080",
)
SESSION = AuthenticatedSession(
    "actor", "session", {SCOPE: frozenset({"workbench.read", "workbench.correct"})},
    {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"audit"})},
    owner_session_token="signed-owner-token", owner_session_request=LOGIN,
)
AUTHORITY = AuthorityContext(
    "actor", "d12", "capability", NamespaceId("bot", "persona"),
    ("persona",), "audit", ("owner",), "policy", 4,
)


def command(*, operation_id: str | None = None, input_data: dict | None = None):
    return {
        "schema_version": "d12.contract.v1", "action": "correct_or_edit",
        "scope": SCOPE, "purpose": "audit", "audience": "owner",
        "operation_id": operation_id or str(uuid4()),
        "input": input_data or {
            "schema": "d12.source_access_revocation.v1",
            "correction_kind": "source_access_revocation",
            "source_id": "src-1", "recorded_at": 10.0,
        },
    }


class Resolver:
    def resolve(self, **_):
        return CoordinatorGrant(
            SCOPE, AUTHORITY, object(), frozenset({"workbench.correct"}),
        )

    def resolve_for_domains(self, *, domains, **kwargs):
        assert domains == ("d06", "d11")
        return self.resolve(**kwargs)


class Registry:
    def view_types(self, *_):
        return {}


class Coordinator:
    def __init__(self):
        self.calls = []

    def query(self, *_args, **_kwargs):
        raise AssertionError("revocation must not use a graph read/write shortcut")

    def revoke_source_access_v1(self, authority, lease, request):
        self.calls.append((authority, lease, request))
        return SourceAccessRevocationReceiptV1(
            authority.namespace, request.source_id, "d06.operation:abc",
            "sha256:" + "a" * 64, 3, 4, 11, 8, 5, 2,
        )


def test_owner_audit_request_reaches_only_coordinator_revocation_port():
    coordinator = Coordinator()
    issuer = GraphWorkbenchIssuer(coordinator, Resolver(), Registry())
    payload = command()
    answer = WorkbenchService(issuer).handle(payload, session=SESSION, context=CONTEXT)
    replay = WorkbenchService(issuer).handle(payload, session=SESSION, context=CONTEXT)

    assert answer.status == "ready"
    assert replay.receipt == answer.receipt
    assert answer.receipt["operation_id"] == payload["operation_id"]
    assert answer.receipt["coordinator_operation_id"] == "d06.operation:abc"
    assert len(coordinator.calls) == 2
    authority, lease, request = coordinator.calls[0]
    assert coordinator.calls[1][2] == request
    assert authority is AUTHORITY and request.request_id == payload["operation_id"]
    assert request.owner_actor == SESSION.actor_id
    assert request.source_id == "src-1" and request.recorded_at == 10.0


@pytest.mark.parametrize("payload", [
    command(operation_id="00000000-0000-0000-0000-000000000001"),
    command(input_data={
        "schema": "d12.source_access_revocation.v1",
        "correction_kind": "source_access_revocation",
        "source_id": "src-1", "recorded_at": True,
    }),
    command(input_data={
        "schema": "d12.source_access_revocation.v1",
        "correction_kind": "source_access_revocation",
        "source_id": "src-1", "recorded_at": 10.0,
        "owner_actor": "attacker",
    }),
])
def test_malformed_revocation_is_rejected_before_coordinator(payload):
    coordinator = Coordinator()
    issuer = GraphWorkbenchIssuer(coordinator, Resolver(), Registry())
    answer = WorkbenchService(issuer).handle(payload, session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable" and answer.problem["code"] == "invalid_request"
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_http_transport_workbench_service_commits_through_real_coordinator(
        owner_graph_fixture, tmp_path):
    graph, coordinator, port, authority, lease, source, access = _case(owner_graph_fixture)
    assert type(graph) is ProductionGraphStore

    class CurrentOwnerResolver:
        def resolve(self, **_):
            raise AssertionError("revocation must request a D06/D11 scoped lease")

        def resolve_for_domains(self, *, session, scope, purpose, audience, domains):
            assert domains == ("d06", "d11")
            assert session.owner_session_token == OWNER_TOKEN
            assert session.owner_session_request == OWNER_REQUEST
            return CoordinatorGrant(
                scope, authority, lease,
                frozenset({"workbench.read", "workbench.correct"}),
            )

    session = AuthenticatedSession(
        "owner-session", "signed-owner-session",
        {SCOPE: frozenset({"workbench.read", "workbench.correct"})},
        {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"audit"})},
        host_username="dashboard-user", owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST,
    )
    payload = command(input_data={
        "schema": "d12.source_access_revocation.v1",
        "correction_kind": "source_access_revocation",
        "source_id": "source-1", "recorded_at": 3.0,
    })
    service = WorkbenchService(
        GraphWorkbenchIssuer(coordinator, CurrentOwnerResolver(), Registry()),
    )
    class Sessions:
        def resolve(self, *, username, session_hint):
            return session if username == "dashboard-user" and session_hint == OWNER_TOKEN else None

    class Csrf:
        def validate(self, *, session, token):
            return session.session_id == "signed-owner-session" and token == "csrf-token"

    class Request:
        username = "dashboard-user"
        content_type = "application/json"
        headers = {"origin": "https://dashboard.local", "x-csrf-token": "csrf-token"}
        cookies = {SYLANNE_OWNER_SESSION_COOKIE: OWNER_TOKEN}

        def __init__(self, body):
            self._body = body

        async def body(self):
            return self._body

    transport = WorkbenchHttpTransport(
        service, Sessions(), Csrf(),
        TransportConfig("https://dashboard.local", tmp_path),
    )
    encoded = json.dumps(payload).encode("utf-8")
    response = await transport.command(Request(encoded))
    replay = await transport.command(Request(encoded))

    assert response["status"] == "ready", response
    assert replay["receipt"] == response["receipt"]
    assert response["receipt"]["operation_id"] == payload["operation_id"]
    assert response["receipt"]["access_revision"] == 2
    assert response["receipt"]["access_epoch"] == 2
    assert response["receipt"]["coordinator_operation_id"] != payload["operation_id"]
    source_row = graph._db.execute(
        "SELECT valid FROM graph_atoms WHERE token=?", (source.token,),
    ).fetchone()
    access_row = graph._db.execute(
        "SELECT revision,value FROM graph_atoms WHERE token=?", (access.token,),
    ).fetchone()
    assert source_row == (1,)
    assert access_row[0] == 2 and json.loads(access_row[1])["status"] == "withdrawn"


def test_workbench_service_reads_draft_through_nonempty_coordinator_scheme_port(
        owner_graph_fixture):
    _, coordinator, _, authority, lease = _creator_case(owner_graph_fixture)

    class CurrentCreatorResolver:
        def resolve(self, *, session, scope, purpose, audience):
            assert session.actor_id == "owner-session"
            assert purpose == "workbench_user_action" and audience == "owner"
            return CoordinatorGrant(
                scope, authority, lease,
                frozenset({"workbench.read", "workbench.create"}),
            )

    session = AuthenticatedSession(
        "owner-session", "signed-owner-session",
        {SCOPE: frozenset({"workbench.read", "workbench.create"})},
        {SCOPE: frozenset({"owner"})},
        {SCOPE: frozenset({"workbench_user_action"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )
    service = WorkbenchService(GraphWorkbenchIssuer(
        coordinator, CurrentCreatorResolver(), Registry(), scheme_port=coordinator,
    ))
    payload = {
        "schema_version": "d12.contract.v1", "action": "read_creator_draft",
        "scope": SCOPE, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": str(uuid4()), "input": {
            "draft_ref": character_draft_key(NamespaceId("bot", "persona")).token,
            "expected_graph_revision": 1,
        },
    }

    response = service.handle(payload, session=session, context=CONTEXT)

    assert response.status == "ready"
    assert response.projection["schema"] == "d12.creator_draft_view.v1"
    assert response.projection["fields"] == {"d01.voice": "clear"}
    assert response.projection["draft_revision"] == 1
    assert response.projection["active_head_revision"] == 1
