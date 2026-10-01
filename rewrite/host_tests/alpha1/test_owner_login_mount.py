"""Owner login routes never grant a session without the independent signer."""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import patch

from astrbot.dashboard.api.plugins import _match_registered_web_api

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1, to_wire,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.workbench_mount import (
    OWNER_CHALLENGE_ROUTE, OWNER_COMPLETE_ROUTE, OWNER_LOGOUT_ROUTE,
    WorkbenchHostMount,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.owner_session_resolver import BoundOwnerSessions


ORIGIN = "https://dashboard.local"
LOGIN_REQUEST = OwnerSessionLoginRequestV1(
    "authority", namespace_ref(NamespaceId("bot", "persona")), "installation",
    OwnerPrincipalV1("idp", "account", "incarnation"), "credential", 1,
    "owner", ORIGIN)
CHALLENGE = OwnerSessionLoginChallengeV1(
    LOGIN_REQUEST, "N" * 43, 0, "B" * 43,
    "2026-09-24T00:00:00Z", "2026-09-24T00:05:00Z")
TOKEN = "T" * 43


class Context:
    def __init__(self):
        self.registered_web_apis = []

    def register_web_api(self, route, handler, methods, description):
        self.registered_web_apis.append((route, handler, methods, description))


class Request:
    def __init__(self, payload, *, username="dashboard-a", origin=ORIGIN,
                 cookies=None, content_type="application/json"):
        self.username = username
        self.headers = {"origin": origin}
        self.cookies = cookies or {}
        self.content_type = content_type
        self.payload = payload

    async def body(self):
        return json.dumps(self.payload).encode("utf-8")


class Sessions(BoundOwnerSessions):
    def __init__(self, origin=ORIGIN):
        self._origin = origin
        self.begun = 0
        self.completed = 0
        self.revoked = 0

    @property
    def origin(self):
        return self._origin

    async def begin_signed_login(self, *, request, login_request):
        assert request.username == "dashboard-a" and login_request == LOGIN_REQUEST
        self.begun += 1
        return CHALLENGE

    async def complete_signed_login(self, *, request, challenge, signature):
        assert request.username == "dashboard-a" and challenge == CHALLENGE
        assert signature == b"s" * 64
        self.completed += 1
        return TOKEN

    async def revoke_bound_session(self, *, username, owner_session_token):
        assert username == "dashboard-a" and owner_session_token == TOKEN
        self.revoked += 1
        return True


def route(context, path):
    matched = _match_registered_web_api(context.registered_web_apis, path, "POST")
    assert matched is not None
    return matched[0]


def test_signed_owner_login_routes_produce_exact_payload_and_httponly_cookie():
    context, sessions = Context(), Sessions()
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    request = Request({"request": to_wire(LOGIN_REQUEST)})
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        challenge = asyncio.run(route(context, OWNER_CHALLENGE_ROUTE)())
        payload = json.loads(challenge.body)
        assert challenge.status_code == 200 and payload["challenge"] == to_wire(CHALLENGE)
        assert base64.b64decode(payload["signing_payload_base64"]) == CHALLENGE.signed_bytes()
        assert sessions.begun == 1
        request.payload = {
            "challenge": to_wire(CHALLENGE),
            "signature_base64": base64.b64encode(b"s" * 64).decode("ascii")}
        completed = asyncio.run(route(context, OWNER_COMPLETE_ROUTE)())
        assert json.loads(completed.body) == {
            "status": "authenticated", "owner_session": "unlocked"}
        assert sessions.completed == 1 and TOKEN not in completed.body.decode("utf-8")
        cookie = completed.headers["set-cookie"]
        assert "sylanne_owner_session=" + TOKEN in cookie
        assert "httponly" in cookie.lower() and "secure" in cookie.lower()
        assert "samesite=strict" in cookie.lower()
        assert "path=/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1" in cookie.lower()
        request.payload = {}
        request.cookies = {"sylanne_owner_session": TOKEN}
        logged_out = asyncio.run(route(context, OWNER_LOGOUT_ROUTE)())
        assert json.loads(logged_out.body)["owner_session"] == "locked"
        assert sessions.revoked == 1 and "max-age=0" in logged_out.headers["set-cookie"].lower()


def test_owner_login_rejects_unauthenticated_foreign_origin_and_invalid_signature():
    context, sessions = Context(), Sessions()
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    request = Request({"request": to_wire(LOGIN_REQUEST)})
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        start = route(context, OWNER_CHALLENGE_ROUTE)
        complete = route(context, OWNER_COMPLETE_ROUTE)
        request.username = None
        assert asyncio.run(start()).status_code == 401
        request.username = "dashboard-a"
        request.headers["origin"] = "https://evil.invalid"
        assert asyncio.run(start()).status_code == 403
        request.headers["origin"] = ORIGIN
        request.content_type = "text/plain"
        assert asyncio.run(start()).status_code == 400
        request.content_type = "application/json"
        request.payload = {"challenge": to_wire(CHALLENGE), "signature_base64": "bad"}
        assert asyncio.run(complete()).status_code == 400
    assert sessions.begun == 0 and sessions.completed == 0


def test_owner_login_refuses_http_before_issuing_a_challenge_or_cookie():
    context, sessions = Context(), Sessions("http://127.0.0.1:6185")
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    with patch("astrbot.api.web.request", Request(
            {"request": to_wire(LOGIN_REQUEST)}, origin="http://127.0.0.1:6185")):
        mount.register(context)
        response = asyncio.run(route(context, OWNER_CHALLENGE_ROUTE)())
    assert response.status_code == 503
    assert json.loads(response.body)["problem"]["code"] == "owner_login_https_required"
    assert sessions.begun == 0 and "set-cookie" not in response.headers
