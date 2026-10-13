"""One maintenance-shell contract node; real Manager upgrades are separate."""
from __future__ import annotations

import asyncio
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys

from astrbot.api.star import Context, Star
from astrbot.api.web import PluginRequest, bind_request_context
from astrbot.core.star.star import star_map, star_registry
from starlette.requests import Request


ROOT = Path(__file__).resolve().parents[3]


def test_restart_shell_fixed_routes_auth_close_and_no_runtime_imports():
    class RuntimeImportForbidden(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if (fullname == "sylanne3" or fullname.startswith("sylanne3.")
                    or fullname.endswith(".sylanne3") or ".sylanne3." in fullname):
                raise AssertionError("maintenance shell must not import runtime")
            return None

    async def exercise():
        name = "data.plugins.sylanne_restart_shell_test.main"
        context = Context(asyncio.Queue(), {}, None, None, None, None,
                          None, None, None, None, None)
        route_list = context.registered_web_apis
        original_routes = list(context.registered_web_apis)
        before = {key for key in sys.modules if key == "sylanne3" or key.startswith("sylanne3.")}
        guard = RuntimeImportForbidden()
        sys.meta_path.insert(0, guard)
        metadata = None
        try:
            spec = importlib.util.spec_from_file_location(
                "sylanne_restart_shell_contract", ROOT / "_restart_required.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin_type = module.restart_required_plugin_type_v1(name)
            metadata = star_map[name]
            assert issubclass(plugin_type, Star)
            assert plugin_type.__name__ == "Sylanne3Plugin"
            assert plugin_type.__module__ == metadata.module_path == name
            assert metadata.star_cls_type is plugin_type

            async def foreign_handler():
                raise AssertionError("foreign handler must not be invoked")

            prefix = "/astrbot_plugin_sylanne"
            foreign = [
                ("/another_plugin/workbench", foreign_handler, ["GET"], "foreign"),
                ("/astrbot_plugin_sylanne_extra/workbench", foreign_handler, ["GET"], "near"),
                ("/astrbot_plugin_sylanne-other", foreign_handler, ["POST"], "near"),
            ]
            retained = [row for row in original_routes
                        if row[0] != prefix and not row[0].startswith(prefix + "/")] + foreign
            retired = [
                (prefix, object(), ["GET"], "old root"),
                (prefix + "/workbench/v1/commands", object(), ["POST"], "old command"),
                (prefix + "/workbench/v1/owner/challenge", object(), ["POST"], "old owner"),
                (prefix + "/workbench/v1/status", object(), ["GET"], "old status"),
            ]
            route_list.extend(foreign + retired)
            plugin = plugin_type(context, {"provider_key": "PRIVATE_CONFIG_CANARY"})
            assert context.registered_web_apis is route_list
            assert route_list[:len(retained)] == retained
            assert all(row not in route_list for row in retired)
            routes = [row for row in context.registered_web_apis
                      if row[0].startswith(prefix + "/")]
            assert [(row[0], row[2]) for row in routes] == [
                ("/astrbot_plugin_sylanne/workbench", ["GET"]),
                ("/astrbot_plugin_sylanne/workbench/v1/status", ["GET"])]
            assert all(row[1].__module__ == name for row in routes)

            async def invoke(handler, username):
                raw = Request({"type": "http", "method": "GET", "scheme": "https",
                               "server": ("localhost", 6238), "path": "/workbench",
                               "query_string": b"", "headers": []})
                with bind_request_context(PluginRequest(raw, username=username)):
                    return await handler()

            for _, handler, _, _ in routes:
                denied = await invoke(handler, None)
                assert denied.status_code == 401
                assert json.loads(denied.body) == {
                    "stage": "blocked", "reason_code": "host_session_missing"}
            page = await invoke(plugin.page, "sdk-dashboard-contract-user")
            body = b"".join([chunk async for chunk in page.body_iterator])
            assert page.status_code == 200
            text = body.decode("utf-8")
            for notice in ["新版本文件已安装", "本进程缓存旧 runtime", "新版本业务未启动",
                           "必须停止并重新启动整个 AstrBot 进程", "插件 reload 不够",
                           "旧进程任务是否完全终止未作保证"]:
                assert notice in text
            assert "<script" not in text and "href=" not in text
            assert b"PRIVATE_CONFIG_CANARY" not in body
            assert page.headers["cache-control"] == "no-store"
            assert page.headers["content-security-policy"] == (
                "default-src 'none'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'; sandbox")
            status = await invoke(plugin.status, "sdk-dashboard-contract-user")
            assert json.loads(status.body) == {
                "schema_version": "sylanne.install-status.v1", "runtime_stage": "blocked",
                "reason_code": "runtime_restart_required"}
            assert status.headers["cache-control"] == "no-store"
            await plugin.terminate()
            assert context.registered_web_apis is route_list
            assert route_list == retained
            for _, handler, _, _ in routes:
                closed = await invoke(handler, "sdk-dashboard-contract-user")
                assert closed.status_code == 503
                assert json.loads(closed.body) == {
                    "stage": "blocked", "reason_code": "host_stopped"}
            old_shell = plugin_type(context)
            new_shell = plugin_type(context)
            current = tuple(route_list)
            await old_shell.terminate()
            assert context.registered_web_apis is route_list
            assert tuple(route_list) == current
            assert all(any(row[1] is saved[1] for row in route_list)
                       for saved in new_shell._registered_routes)
            await new_shell.terminate()
            assert route_list == retained
            assert {key for key in sys.modules
                    if key == "sylanne3" or key.startswith("sylanne3.")} == before
        finally:
            sys.meta_path.remove(guard)
            context.registered_web_apis[:] = original_routes
            star_map.pop(name, None)
            if metadata in star_registry:
                star_registry.remove(metadata)

    asyncio.run(exercise())
