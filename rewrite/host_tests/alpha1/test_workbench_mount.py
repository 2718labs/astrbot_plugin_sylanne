"""AstrBot exposes packaged static assets and protects the D12 command seam."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from astrbot.dashboard.api.plugins import _match_registered_web_api

from rewrite.sylanne3.host.workbench_mount import WorkbenchHostMount
from rewrite.sylanne3.workbench_api.http_transport import (
    ASSET_ROUTE, COMMAND_ROUTE, PLUGIN_ROUTE_PREFIX, SESSION_ROUTE,
)


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
        assert len(context.registered_web_apis) == 4
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
        assert asyncio.run(asset(asset="v1/commands")).status_code == 404
        assert asyncio.run(asset(asset="workbench-manifest.json")).status_code == 404
        assert asyncio.run(asset(asset="../metadata.yaml")).status_code == 404
        mount.close()
        assert json.loads(asyncio.run(handler()).body)["problem"]["code"] == "host_stopped"
        assert asyncio.run(page()).status_code == 503


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
