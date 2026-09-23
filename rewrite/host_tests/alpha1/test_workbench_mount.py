"""AstrBot exposes packaged static assets and protects the D12 command seam."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from astrbot.dashboard.api.plugins import _match_registered_web_api

from rewrite.sylanne3.host.workbench_mount import STATUS_ROUTE, WorkbenchHostMount
from rewrite.sylanne3.host.scene_candidates import ObservedSceneCandidate
from rewrite.sylanne3.runtime_contracts import NamespaceId
from rewrite.sylanne3.workbench_api.http_transport import (
    ASSET_ROUTE, COMMAND_ROUTE, PLUGIN_ROUTE_PREFIX, SCENE_CANDIDATES_ROUTE,
    SESSION_ROUTE, TransportConfig, WorkbenchHttpTransport,
)
from rewrite.sylanne3.workbench_api.owner_session_resolver import BoundOwnerSessions
from rewrite.sylanne3.workbench_api.service import AuthenticatedSession


class _Context:
    def __init__(self) -> None:
        self.registered_web_apis = []

    def register_web_api(self, route, handler, methods, description):
        self.registered_web_apis.append((route, handler, methods, description))


def test_host_mount_serves_packaged_assets_without_promoting_dashboard_admin_to_owner():
    context = _Context()
    mount = WorkbenchHostMount()
    with patch("astrbot.api.web.request", SimpleNamespace(username="dashboard-admin")):
        mount.register(context)
        assert len(context.registered_web_apis) == 9
        assert context.registered_web_apis[0][0] == COMMAND_ROUTE
        matched = _match_registered_web_api(
            context.registered_web_apis, COMMAND_ROUTE, "POST",
        )
        assert matched is not None
        handler, _ = matched
        response = asyncio.run(handler())
        assert response.status_code == 503
        assert json.loads(response.body)["problem"]["code"] == "authority_unavailable"
        assert response.headers["cache-control"] == "no-store"
        page, _ = _match_registered_web_api(context.registered_web_apis, PLUGIN_ROUTE_PREFIX, "GET")
        index = asyncio.run(page())
        assert index.status_code == 200
        assert index.media_type == "text/html; charset=utf-8"
        assert Path(index.path).read_bytes().startswith(b"<!doctype html>")
        assert index.headers["cache-control"] == "no-store"
        asset, params = _match_registered_web_api(
            context.registered_web_apis, "/astrbot_plugin_sylanne/workbench/src/app.js", "GET",
        )
        assert params == {"asset": "src/app.js"}
        script = asyncio.run(asset(**params))
        assert script.status_code == 200
        assert script.media_type == "text/javascript; charset=utf-8"
        assert Path(script.path).read_bytes().startswith(b"import ")
        assert _match_registered_web_api(context.registered_web_apis, COMMAND_ROUTE, "GET") is not None
        session, _ = _match_registered_web_api(
            context.registered_web_apis, SESSION_ROUTE, "GET")
        assert json.loads(asyncio.run(session()).body)["problem"]["code"] == "authority_unavailable"
        install, _ = _match_registered_web_api(context.registered_web_apis, STATUS_ROUTE, "GET")
        assert json.loads(asyncio.run(install()).body)["problem"]["code"] == "runtime_unavailable"
        assert asyncio.run(asset(asset="v1/commands")).status_code == 404
        assert asyncio.run(asset(asset="workbench-manifest.json")).status_code == 404
        assert asyncio.run(asset(asset="../metadata.yaml")).status_code == 404
        mount.close()
        assert json.loads(asyncio.run(handler()).body)["problem"]["code"] == "host_stopped"
        assert asyncio.run(page()).status_code == 503


def test_installation_stage_is_readable_without_owner_but_only_exposes_safe_codes():
    health = ["enrollment_required", "authority_profile"]
    context = _Context()
    mount = WorkbenchHostMount(lambda: tuple(health))
    request = SimpleNamespace(username="dashboard-admin")
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        handler, _ = _match_registered_web_api(context.registered_web_apis, STATUS_ROUTE, "GET")
        response = asyncio.run(handler())
        assert response.status_code == 200
        assert json.loads(response.body) == {
            "schema_version": "sylanne.install-status.v1",
            "runtime_stage": "enrollment_required", "reason_code": "authority_profile",
        }
        assert response.headers["cache-control"] == "no-store"
        for reason in ("owner_guard", "active_role", "scene_binding", "dispatch",
                       "product_ingress", "installed_package", "graph_worker",
                       "domain_registry", "v2_fence_recovery"):
            health[:] = ["limited", reason]
            assert json.loads(asyncio.run(handler()).body)["reason_code"] == reason
        health[:] = ["limited", "private-path-or-secret"]
        assert json.loads(asyncio.run(handler()).body)["reason_code"] == "runtime_unavailable"
        health[:] = ["ready", "none"]
        assert json.loads(asyncio.run(handler()).body)["runtime_stage"] == "ready"
        request.username = None
        assert asyncio.run(handler()).status_code == 401


def test_direct_call_without_host_authenticated_user_is_denied():
    context = _Context()
    mount = WorkbenchHostMount()
    with patch("astrbot.api.web.request", SimpleNamespace(username=None)):
        mount.register(context)
        handler = context.registered_web_apis[0][1]
        response = asyncio.run(handler())
        assert response.status_code == 401
        assert json.loads(response.body)["problem"]["code"] == "host_session_missing"
        page = context.registered_web_apis[1][1]
        assert asyncio.run(page()).status_code == 401


def test_scene_candidates_require_dashboard_and_owner_and_only_return_installed_namespace():
    namespace = NamespaceId("bot", "persona")
    other = NamespaceId("other", "persona")
    scope = "bot/persona"
    session = AuthenticatedSession(
        "owner", "session", {scope: frozenset({"workbench.read"})},
        {scope: frozenset({"owner"})}, {scope: frozenset({"workbench_view"})},
        host_username="dashboard-admin")

    class Sessions(BoundOwnerSessions):
        def __init__(self):
            pass

        @property
        def namespace(self):
            return namespace

    class Resolver:
        async def resolve(self, *, username, session_hint):
            return session if username == "dashboard-admin" and session_hint == "current" else None

    class Csrf:
        pass

    seen = []
    available = [True]

    def candidates(requested):
        seen.append(requested)
        if not available[0]:
            return ()
        return (
            ObservedSceneCandidate(namespace, "onebot", "group-7", "group", "scene:conversation-v1:" + "a" * 64),
            ObservedSceneCandidate(other, "private", "hidden", "private", "scene:conversation-v1:" + "b" * 64),
        )

    context = _Context()
    mount = WorkbenchHostMount(scene_candidates=candidates)
    mount.attach_owner_sessions(Sessions())
    mount.attach_transport(WorkbenchHttpTransport(
        None, Resolver(), Csrf(), TransportConfig("https://dashboard.local", Path("."))))
    request = SimpleNamespace(
        username="dashboard-admin", cookies={"sylanne_owner_session": "current"},
        headers={"origin": "https://dashboard.local"})
    with patch("astrbot.api.web.request", request):
        mount.register(context)
        handler, _ = _match_registered_web_api(context.registered_web_apis, SCENE_CANDIDATES_ROUTE, "GET")
        result = asyncio.run(handler())
        assert result.status_code == 200
        assert json.loads(result.body) == {
            "schema_version": "sylanne.scene-candidates.v1", "status": "ready",
            "candidates": [{"platform_ref": "onebot", "conversation_ref": "group-7",
                            "visibility": "group", "scene_ref": "scene:conversation-v1:" + "a" * 64}],
        }
        assert seen == [namespace]
        available[0] = False
        assert json.loads(asyncio.run(handler()).body) == {
            "schema_version": "sylanne.scene-candidates.v1", "status": "empty",
            "candidates": [],
        }
        request.cookies = {}
        assert json.loads(asyncio.run(handler()).body)["problem"]["code"] == "owner_session_locked"
        request.username = None
        assert json.loads(asyncio.run(handler()).body)["problem"]["code"] == "host_session_missing"
