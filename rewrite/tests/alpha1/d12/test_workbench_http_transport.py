from __future__ import annotations

from pathlib import Path
import json
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import pytest

from sylanne3.workbench_api.http_transport import (
    SYLANNE_OWNER_SESSION_COOKIE, BoundCsrfTokens,
    ASSET_ROUTE, COMMAND_ROUTE, CurrentOwnerDashboardSessions, TransportConfig,
    VerifiedOwnerPairing, WorkbenchHttpTransport,
)
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerPrincipalV1,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.service import AuthenticatedSession, WorkbenchService


SCOPE = "bot/persona"


class Request:
    def __init__(self, body: bytes, *, username="dashboard-user", origin="https://dashboard.local", csrf="token", content_type="application/json", length=None, owner_token="owner-token", dashboard_jwt="host-jwt", referer=None, fetch_site=None):
        self._body = body; self.username = username; self.content_type = content_type
        self.headers = {"x-csrf-token": csrf}
        if origin is not None: self.headers["origin"] = origin
        if referer is not None: self.headers["referer"] = referer
        if fetch_site is not None: self.headers["sec-fetch-site"] = fetch_site
        self.cookies = {"astrbot_dashboard_jwt": dashboard_jwt} if dashboard_jwt else {}
        if owner_token: self.cookies[SYLANNE_OWNER_SESSION_COOKIE] = owner_token
        if length is not None: self.headers["content-length"] = length
    async def body(self): return self._body


class Sessions:
    def resolve(self, *, username, session_hint):
        if username != "dashboard-user" or session_hint != "owner-token": return None
        return AuthenticatedSession("owner:independent-account", "server-session", {SCOPE: frozenset({"workbench.read"})}, {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"workbench_view"})}, host_username="dashboard-user")


class Csrf:
    def validate(self, *, session, token): return token == "token" and session.actor_id == "owner:independent-account"


def payload():
    return ('{"schema_version":"d12.contract.v1","action":"read_character_view",'
            f'"scope":"{SCOPE}","purpose":"workbench_view","audience":"owner",'
            f'"operation_id":"{uuid4()}","input":{{"view_type":"overview"}}}}').encode()


def transport(tmp_path):
    return WorkbenchHttpTransport(WorkbenchService(), Sessions(), Csrf(), TransportConfig("https://dashboard.local", tmp_path))


@pytest.mark.asyncio
async def test_transport_derives_identity_from_host_and_rejects_bad_origin_or_csrf(tmp_path):
    subject = transport(tmp_path)
    ok = await subject.command(Request(payload()))
    assert ok["status"] == "unavailable" and ok["problem"]["code"] == "provider_unavailable"
    assert (await subject.command(Request(payload(), username=None)))["problem"]["code"] == "host_session_missing"
    assert (await subject.command(Request(payload(), origin="https://evil.invalid")))["problem"]["code"] == "origin_denied"
    assert (await subject.command(Request(payload(), csrf="wrong")))["problem"]["code"] == "csrf_denied"


@pytest.mark.asyncio
async def test_transport_awaits_async_service_after_host_checks(tmp_path):
    calls = []

    class AsyncService:
        async def handle(self, body, *, session, context):
            calls.append((body, session, context))
            return WorkbenchService().handle(body, session=session, context=context)

    subject = WorkbenchHttpTransport(
        AsyncService(), Sessions(), Csrf(), TransportConfig("https://dashboard.local", tmp_path),
    )
    assert (await subject.command(Request(payload())))["problem"]["code"] == "provider_unavailable"
    assert len(calls) == 1
    assert (await subject.command(Request(payload(), csrf="wrong")))["problem"]["code"] == "csrf_denied"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_transport_bounds_and_parses_json_before_service(tmp_path):
    subject = transport(tmp_path)
    assert (await subject.command(Request(b"not-json")))["problem"]["code"] == "invalid_json"
    assert (await subject.command(Request(payload(), content_type="text/plain")))["http_status"] == 415
    assert (await subject.command(Request(b"x" * 100, length="99999")))["problem"]["code"] == "body_too_large"
    assert (await subject.command(Request(payload(), length="-1")))["problem"]["code"] == "invalid_content_length"


def test_asset_path_is_confined_to_workbench_root(tmp_path):
    root = tmp_path / "assets"; root.mkdir(); (root / "index.html").write_text("ok")
    subject = WorkbenchHttpTransport(WorkbenchService(), Sessions(), Csrf(), TransportConfig("https://dashboard.local", root))
    assert subject.asset_path("index.html") == (root / "index.html").resolve()
    assert subject.asset_path("../outside.txt") is None
    assert subject.asset_path("..\\outside.txt") is None


def test_mount_uses_only_astrbot_context_registration_seam(tmp_path, monkeypatch):
    web = ModuleType("astrbot.api.web")
    web.request = SimpleNamespace()
    web.json_response = lambda data, **kwargs: (data, kwargs)
    web.file_response = lambda path, **kwargs: (path, kwargs)
    monkeypatch.setitem(sys.modules, "astrbot.api.web", web)
    registered = []
    class Context:
        def register_web_api(self, *args): registered.append(args)
    transport(tmp_path).mount_astrbot(Context())
    assert [(route, methods) for route, _, methods, _ in registered] == [
        ("/astrbot_plugin_sylanne/workbench/v1/commands", ["POST"]),
        ("/astrbot_plugin_sylanne/workbench/<path:asset>", ["GET"]),
    ]
    assert registered[0][1].__name__ == "serve_command"


@pytest.mark.asyncio
async def test_mounted_handlers_use_bound_sdk_request_and_http_status(tmp_path):
    web = pytest.importorskip("astrbot.api.web")
    from starlette.requests import Request as StarletteRequest

    root = tmp_path / "assets"; root.mkdir(); (root / "index.html").write_text("ok")
    subject = WorkbenchHttpTransport(WorkbenchService(), Sessions(), Csrf(), TransportConfig("https://dashboard.local", root))
    registered = []
    class Context:
        def register_web_api(self, *args): registered.append(args)
    subject.mount_astrbot(Context())
    command = registered[0][1]
    asset = registered[1][1]

    def bound(*, body=payload(), origin="https://dashboard.local", csrf="token", owner_token="owner-token", username="dashboard-user"):
        headers = [(b"content-type", b"application/json"), (b"origin", origin.encode()),
                   (b"x-csrf-token", csrf.encode())]
        if owner_token:
            headers.append((b"cookie", f"{SYLANNE_OWNER_SESSION_COOKIE}={owner_token}".encode()))
        sent = False
        async def receive():
            nonlocal sent
            if sent: return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        scope = {"type": "http", "method": "POST", "path": "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/commands",
                 "query_string": b"", "headers": headers, "client": ("127.0.0.1", 12345), "server": ("dashboard.local", 443), "scheme": "https"}
        request = StarletteRequest(scope, receive)
        return web.PluginRequest(request, username=username)

    with web.bind_request_context(bound(body=b"bad")):
        response = await command()
    assert response.status_code == 400
    assert json.loads(response.body)["problem"]["code"] == "invalid_json"
    assert "http_status" not in json.loads(response.body)
    with web.bind_request_context(bound(csrf="wrong")):
        response = await command()
    assert response.status_code == 403
    with web.bind_request_context(bound(owner_token=None)):
        response = await asset("index.html")
    assert response.status_code == 200
    with web.bind_request_context(bound(owner_token=None)):
        response = await command()
    assert response.status_code == 401
    assert json.loads(response.body)["problem"]["code"] == "owner_session_locked"
    with web.bind_request_context(bound()):
        response = await asset("../outside.txt")
    assert response.status_code == 404
    with web.bind_request_context(bound()):
        response = await asset("index.html")
    assert response.status_code == 200

    # Exercise AstrBot's installed dispatcher, which invokes the registered
    # handler without passing a request argument.
    from astrbot.dashboard.api.plugins import _call_plugin_extension, router as plugins_router
    from astrbot.dashboard.api.router import API_V1_PREFIX
    assert API_V1_PREFIX == "/api/v1"
    assert any(route.path == "/plugins/extensions/{plugin_path:path}" and "POST" in route.methods
               for route in plugins_router.routes)
    host_request = bound()._request
    host_request.scope["app"] = SimpleNamespace(state=SimpleNamespace(
        core_lifecycle=SimpleNamespace(star_context=SimpleNamespace(registered_web_apis=registered))))
    from astrbot.dashboard.api.plugins import _match_registered_web_api
    assert _match_registered_web_api(registered, "astrbot_plugin_sylanne/workbench/v1/commands", "POST")[0] is command
    assert _match_registered_web_api(registered, "astrbot_plugin_sylanne/workbench/index.html", "GET")[0] is asset
    assert _match_registered_web_api(registered, "workbench/v1/commands", "POST") is None
    assert COMMAND_ROUTE == registered[0][0] and ASSET_ROUTE == registered[1][0]
    response = await _call_plugin_extension("astrbot_plugin_sylanne/workbench/v1/commands", host_request, "dashboard-user")
    assert response.status_code == 503
    assert json.loads(response.body)["problem"]["code"] == "provider_unavailable"


@pytest.mark.asyncio
async def test_dashboard_cookie_alone_cannot_unlock_owner_commands(tmp_path):
    subject = transport(tmp_path)
    assert (await subject.open_session(Request(b"", owner_token=None)))["problem"]["code"] == "owner_session_locked"
    assert (await subject.command(Request(payload(), owner_token=None)))["problem"]["code"] == "owner_session_locked"
    assert (await subject.command(Request(payload(), owner_token="revoked")))["problem"]["code"] == "owner_session_locked"
    assert (await subject.command(Request(payload(), dashboard_jwt=None)))["problem"]["code"] == "provider_unavailable"


@pytest.mark.asyncio
async def test_current_owner_pairing_keeps_dashboard_and_owner_identities_separate(tmp_path):
    owner = AuthenticatedSession(
        "owner:independent-account", "owner-session",
        {SCOPE: frozenset({"workbench.read"})},
        {SCOPE: frozenset({"owner"})},
        {SCOPE: frozenset({"workbench_view"})},
        host_username="dashboard-user")
    guard = OwnerAuthorizationGuardV1(
        "authority", "installation", NamespaceId("bot", "persona"),
        1, "sha256:" + "a" * 64, 0, 0)

    class Pairing:
        current = True

        def resolve_current_owner_session(self, *, username, owner_session_token):
            if (self.current and username == "dashboard-user"
                    and owner_session_token == "owner-token"):
                return VerifiedOwnerPairing(
                    owner, OwnerPrincipalV1("paired-idp", "account", "incarnation"),
                    guard)
            return None

    pairing, csrf = Pairing(), BoundCsrfTokens()
    subject = WorkbenchHttpTransport(
        WorkbenchService(), CurrentOwnerDashboardSessions(pairing), csrf,
        TransportConfig("https://dashboard.local", tmp_path))
    assert (await subject.open_session(Request(b"", origin=None)))["problem"]["code"] == "origin_denied"
    assert (await subject.open_session(Request(
        b"", origin=None, referer="https://evil.invalid/page")))["problem"]["code"] == "origin_denied"
    opened = await subject.open_session(Request(
        b"", origin=None, referer="https://dashboard.local/workbench"))
    assert opened["status"] == "ready"
    assert opened["dashboard_session"] == "authenticated"
    assert opened["owner_session"] == "unlocked"
    first_tab_token = opened["csrf_token"]
    opened_again = await subject.open_session(Request(
        b"", origin=None, fetch_site="same-origin"))
    assert opened_again["status"] == "ready"
    token = opened_again["csrf_token"]
    assert token != first_tab_token
    assert (await subject.command(Request(payload(), csrf=first_tab_token)))["problem"]["code"] == "provider_unavailable"
    assert (await subject.command(Request(payload(), origin=None, csrf=token)))["problem"]["code"] == "origin_denied"
    assert (await subject.command(Request(payload(), csrf=token)))["problem"]["code"] == "provider_unavailable"
    pairing.current = False
    assert (await subject.command(Request(payload(), csrf=token)))["problem"]["code"] == "owner_session_locked"
    assert (await subject.open_session(Request(b"")))["problem"]["code"] == "owner_session_locked"


@pytest.mark.asyncio
async def test_legacy_dashboard_pairing_port_starts_but_never_unlocks(tmp_path):
    class OldPairing:
        def resolve_current_pairing(self, *, username, dashboard_jwt_digest):
            raise AssertionError("Dashboard JWT pairing must never be used")

    subject = WorkbenchHttpTransport(
        WorkbenchService(), CurrentOwnerDashboardSessions(OldPairing()), BoundCsrfTokens(),
        TransportConfig("https://dashboard.local", tmp_path))
    assert (await subject.open_session(Request(b"")))["problem"]["code"] == "owner_session_locked"
