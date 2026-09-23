"""The host must expose only a protected, unavailable D12 command seam."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

from astrbot.dashboard.api.plugins import _match_registered_web_api

from rewrite.sylanne3.host.workbench_mount import WorkbenchHostMount
from rewrite.sylanne3.workbench_api.http_transport import COMMAND_ROUTE


class _Context:
    def __init__(self) -> None:
        self.registered_web_apis = []

    def register_web_api(self, route, handler, methods, description):
        self.registered_web_apis.append((route, handler, methods, description))


def test_host_mount_registers_only_command_and_fails_closed_without_grant():
    context = _Context()
    mount = WorkbenchHostMount()
    with patch("astrbot.api.web.request", SimpleNamespace(username="dashboard-admin")):
        mount.register(context)
        assert len(context.registered_web_apis) == 1
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
        assert _match_registered_web_api(
            context.registered_web_apis, COMMAND_ROUTE, "GET",
        ) is None
        mount.close()
        assert json.loads(asyncio.run(handler()).body)["problem"]["code"] == "host_stopped"


def test_direct_call_without_host_authenticated_user_is_denied():
    context = _Context()
    mount = WorkbenchHostMount()
    with patch("astrbot.api.web.request", SimpleNamespace(username=None)):
        mount.register(context)
        handler = context.registered_web_apis[0][1]
        response = asyncio.run(handler())
        assert response.status_code == 401
        assert json.loads(response.body)["problem"]["code"] == "host_session_missing"
