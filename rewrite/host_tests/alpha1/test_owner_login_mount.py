"""Owner login routes never grant a session without the independent signer."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from starlette.requests import Request as StarletteRequest

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
                 cookies=None, content_type="application/json", url=None):
        self._request = StarletteRequest({"type": "http", "scheme": (url or origin).split("://", 1)[0],
            "path": "/", "query_string": b"", "headers": [
                (b"host", (url or origin).split("://", 1)[1].encode("ascii"))]})
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
        self.login_request = replace(LOGIN_REQUEST, dashboard_origin=origin)
        self.challenge = replace(CHALLENGE, request=self.login_request)
        self.begun = 0
        self.completed = 0
        self.revoked = 0

    @property
    def origin(self):
        return self._origin

    async def begin_signed_login(self, *, request, login_request):
        assert request.username == "dashboard-a" and login_request == self.login_request
        self.begun += 1
        return self.challenge

    async def complete_signed_login(self, *, request, challenge, signature):
        assert request.username == "dashboard-a" and challenge == self.challenge
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


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_signed_owner_login_routes_produce_exact_payload_and_httponly_cookie(scheme):
    origin = scheme + "://dashboard.local"
    context, sessions = Context(), Sessions(origin)
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    request = Request({"request": to_wire(sessions.login_request)}, origin=origin)
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        challenge = asyncio.run(route(context, OWNER_CHALLENGE_ROUTE)())
        payload = json.loads(challenge.body)
        assert challenge.status_code == 200 and payload["challenge"] == to_wire(sessions.challenge)
        assert base64.b64decode(payload["signing_payload_base64"]) == sessions.challenge.signed_bytes()
        assert sessions.begun == 1
        request.payload = {
            "challenge": to_wire(sessions.challenge),
            "signature_base64": base64.b64encode(b"s" * 64).decode("ascii")}
        completed = asyncio.run(route(context, OWNER_COMPLETE_ROUTE)())
        assert json.loads(completed.body) == {
            "status": "authenticated", "owner_session": "unlocked"}
        assert sessions.completed == 1 and TOKEN not in completed.body.decode("utf-8")
        cookie = completed.headers["set-cookie"]
        assert "sylanne_owner_session=" + TOKEN in cookie
        assert "httponly" in cookie.lower()
        assert ("; secure" in cookie.lower()) is (scheme == "https")
        assert "samesite=strict" in cookie.lower()
        assert "path=/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1" in cookie.lower()
        request.payload = {}
        request.cookies = {"sylanne_owner_session": TOKEN}
        logged_out = asyncio.run(route(context, OWNER_LOGOUT_ROUTE)())
        assert json.loads(logged_out.body)["owner_session"] == "locked"
        assert sessions.revoked == 1 and "max-age=0" in logged_out.headers["set-cookie"].lower()
        logout_cookie = logged_out.headers["set-cookie"].lower()
        assert ("; secure" in logout_cookie) is (scheme == "https")
        assert "httponly" in logout_cookie and "samesite=strict" in logout_cookie
        assert "path=/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1" in logout_cookie


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_owner_login_rejects_unauthenticated_foreign_origin_and_invalid_signature(scheme):
    origin = scheme + "://dashboard.local"
    context, sessions = Context(), Sessions(origin)
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    request = Request({"request": to_wire(sessions.login_request)}, origin=origin)
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        start = route(context, OWNER_CHALLENGE_ROUTE)
        complete = route(context, OWNER_COMPLETE_ROUTE)
        request.username = None
        assert asyncio.run(start()).status_code == 401
        request.username = "dashboard-a"
        request.headers["origin"] = "https://evil.invalid"
        assert asyncio.run(start()).status_code == 403
        request.headers["origin"] = origin
        request.content_type = "text/plain"
        assert asyncio.run(start()).status_code == 400
        request.content_type = "application/json"
        request.payload = {"challenge": to_wire(sessions.challenge), "signature_base64": "bad"}
        assert asyncio.run(complete()).status_code == 400
    assert sessions.begun == 0 and sessions.completed == 0


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_owner_login_rejects_scheme_host_mismatch_and_forwarded_before_issuing_a_challenge_or_cookie(scheme):
    origin = scheme + "://dashboard.local"
    context, sessions = Context(), Sessions(origin)
    mount = WorkbenchHostMount()
    mount.attach_owner_sessions(sessions)
    other_scheme = "https" if scheme == "http" else "http"
    requests = [
        Request({"request": to_wire(sessions.login_request)}, origin=origin,
                url=other_scheme + "://dashboard.local"),
        Request({"request": to_wire(sessions.login_request)}, origin=origin,
                url=scheme + "://foreign.invalid"),
    ]
    for header in ("Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-For", "X-Real-IP"):
        request = Request({"request": to_wire(sessions.login_request)}, origin=origin)
        request.headers[header] = "https"
        requests.append(request)
    request = Request({"request": to_wire(sessions.login_request)}, origin=origin)
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        for rejected_request in requests:
            request._request = rejected_request._request
            request.headers = rejected_request.headers
            for path in (OWNER_CHALLENGE_ROUTE, OWNER_COMPLETE_ROUTE, OWNER_LOGOUT_ROUTE):
                response = asyncio.run(route(context, path)())
                assert response.status_code == 403
                assert json.loads(response.body)["problem"]["code"] == "origin_denied"
                assert "set-cookie" not in response.headers
    assert sessions.begun == sessions.completed == sessions.revoked == 0
