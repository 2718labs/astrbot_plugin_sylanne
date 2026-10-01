"""AstrBot 4.28.1 POST route reaches the current D12 creator draft."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from astrbot.dashboard.api.plugins import _match_registered_web_api

from sylanne3.domains.d12.types import character_draft_key
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api import (
    AuthenticatedSession, CoordinatorGrant, GraphWorkbenchIssuer,
    WorkbenchService,
)
from sylanne3.workbench_api.http_transport import (
    COMMAND_ROUTE, SYLANNE_OWNER_SESSION_COOKIE, TransportConfig,
    WorkbenchHttpTransport,
)
from tests.alpha1.d12.test_owner_graph_lease import (
    OWNER_REQUEST, OWNER_TOKEN, owner_graph as owner_graph_fixture,
)
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import (
    _creator_case,
)


@pytest.mark.asyncio
async def test_registered_astrbot_command_reads_current_creator_draft(
        owner_graph_fixture, tmp_path):
    _, coordinator, _, authority, lease = _creator_case(owner_graph_fixture)
    scope = "bot/persona"
    session = AuthenticatedSession(
        "owner-session", "signed-owner-session",
        {scope: frozenset({"workbench.read", "workbench.create"})},
        {scope: frozenset({"owner"})},
        {scope: frozenset({"workbench_user_action"})},
        host_username="dashboard-user", owner_session_token=OWNER_TOKEN,
        owner_session_request=OWNER_REQUEST)

    class GrantResolver:
        def resolve(self, *, session, scope, purpose, audience):
            assert session.owner_session_token == OWNER_TOKEN
            assert purpose == "workbench_user_action" and audience == "owner"
            return CoordinatorGrant(
                scope, authority, lease,
                frozenset({"workbench.read", "workbench.create"}))

    class SessionResolver:
        def resolve(self, *, username, session_hint):
            return (session if username == "dashboard-user"
                    and session_hint == OWNER_TOKEN else None)

    class Csrf:
        def validate(self, *, session, token):
            return session.session_id == "signed-owner-session" and token == "csrf-token"

    class Registry:
        def view_types(self, *_):
            return {}

    payload = {
        "schema_version": "d12.contract.v1", "action": "read_creator_draft",
        "scope": scope, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": str(uuid4()), "input": {
            "draft_ref": character_draft_key(NamespaceId("bot", "persona")).token,
            "expected_graph_revision": 1,
        },
    }

    class Request:
        username = "dashboard-user"
        content_type = "application/json"
        headers = {"origin": "https://dashboard.local", "x-csrf-token": "csrf-token"}
        cookies = {SYLANNE_OWNER_SESSION_COOKIE: OWNER_TOKEN}

        async def body(self):
            return json.dumps(payload).encode("utf-8")

    service = WorkbenchService(GraphWorkbenchIssuer(
        coordinator, GrantResolver(), Registry(), scheme_port=coordinator))
    transport = WorkbenchHttpTransport(
        service, SessionResolver(), Csrf(),
        TransportConfig("https://dashboard.local", Path(tmp_path)))
    context = SimpleNamespace(registered_web_apis=[])
    context.register_web_api = lambda route, handler, methods, description: (
        context.registered_web_apis.append((route, handler, methods, description)))
    mount = WorkbenchHostMount()
    mount.attach_transport(transport)
    with patch("astrbot.api.web.request", Request()):
        mount.register(context)
        handler, _ = _match_registered_web_api(
            context.registered_web_apis, COMMAND_ROUTE, "POST")
        response = await handler()
    body = json.loads(response.body)
    assert response.status_code == 200, body
    assert body["status"] == "ready"
    assert body["projection"]["schema"] == "d12.creator_draft_view.v1"
    assert body["projection"]["fields"] == {"d01.voice": "clear"}
