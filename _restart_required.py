"""Authenticated maintenance notice without importing the installed runtime."""
from __future__ import annotations

from astrbot.api import logger
from astrbot.api.star import Context, Star
from astrbot.api.web import json_response, request, stream_response


_PLUGIN_PREFIX = "/astrbot_plugin_sylanne"
_WORKBENCH = f"{_PLUGIN_PREFIX}/workbench"
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'; sandbox"
    ),
}
_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sylanne 需要重启 AstrBot</title></head><body>
<main><h1>需要重启整个 AstrBot 进程</h1>
<p>新版本文件已安装；本进程缓存旧 runtime；新版本业务未启动。</p>
<p>必须停止并重新启动整个 AstrBot 进程，插件 reload 不够。</p>
<p>旧进程任务是否完全终止未作保证。</p>
</main></body></html>""".encode("utf-8")


def restart_required_plugin_type_v1(module_name: str):
    """Create the maintenance Star with the actual entry module's ownership."""
    def __init__(self, context: Context, config=None):
        Star.__init__(self, context)
        self._closed = False
        context.registered_web_apis[:] = [
            row for row in context.registered_web_apis
            if row[0] != _PLUGIN_PREFIX and not row[0].startswith(f"{_PLUGIN_PREFIX}/")]
        self._registered_routes = (
            (_WORKBENCH, self.page, ["GET"], "Sylanne 重启提示"),
            (f"{_WORKBENCH}/v1/status", self.status, ["GET"], "Sylanne 重启状态"),
        )
        for route in self._registered_routes:
            context.register_web_api(*route)
        logger.warning("Sylanne runtime restart required; new runtime has not started")

    def unavailable(self):
        if not isinstance(request.username, str) or not request.username:
            return json_response(
                {"stage": "blocked", "reason_code": "host_session_missing"},
                status_code=401, headers=_HEADERS)
        if self._closed:
            return json_response(
                {"stage": "blocked", "reason_code": "host_stopped"},
                status_code=503, headers=_HEADERS)
        return None

    async def page(self):
        problem = unavailable(self)
        if problem is not None:
            return problem
        return stream_response(iter((_PAGE,)), content_type="text/html; charset=utf-8",
                               headers=_HEADERS)

    async def status(self):
        problem = unavailable(self)
        if problem is not None:
            return problem
        return json_response(
            {"schema_version": "sylanne.install-status.v1", "runtime_stage": "blocked",
             "reason_code": "runtime_restart_required"},
            headers=_HEADERS)

    async def terminate(self):
        self._closed = True
        self.context.registered_web_apis[:] = [
            row for row in self.context.registered_web_apis
            if not any(row[0] == saved[0] and row[2] == saved[2] and row[1] is saved[1]
                       for saved in self._registered_routes)]

    methods = {"__init__": __init__, "page": page, "status": status,
               "terminate": terminate}
    for method in methods.values():
        method.__module__ = module_name
    return type("Sylanne3Plugin", (Star,), {"__module__": module_name, **methods})
