"""Owned WebUI socket and a narrow gateway to the existing SDK Dashboard."""
from __future__ import annotations

import asyncio
import os
import ssl

from astrbot.api import logger
from astrbot.api.star import Context
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.utils import wrap_app
from starlette.responses import FileResponse, JSONResponse
from astrbot.dashboard.services.auth_service import DASHBOARD_JWT_COOKIE_NAME

from .workbench_mount import _asset_file, _packaged_assets


_PLUGIN_API = "/api/v1/plugins/extensions/astrbot_plugin_sylanne"
_AUTH_POST = frozenset({"/api/v1/auth/login", "/api/v1/auth/logout"})
_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"}


class WebuiListenerV1:
    def __init__(self, context, *, enabled, bind="0.0.0.0", port=2718):
        if not isinstance(context, Context):
            raise TypeError("actual SDK Context required")
        if (type(enabled) is not bool or type(bind) is not str or not bind
                or type(port) is not int or not 0 <= port <= 65535):
            raise ValueError("listener requires exact startup settings")
        self._context = context
        self._startup = {"enabled": enabled, "bind": bind, "port": port}
        self._scheme = "http"
        self._state = "disabled" if not enabled else "stopped"
        self._reason = "webui_disabled" if not enabled else "webui_stopped"
        self._task = None
        self._shutdown = asyncio.Event()
        self._servers = ()
        self._connections = set()

    def status_v1(self):
        return {"schema_version": "sylanne.webui-listener-status.v1",
                "startup_values": dict(self._startup), "scheme": self._scheme,
                "state": self._state, "reason_code": self._reason,
                "bound_addresses": [{"host": sock.getsockname()[0], "port": sock.getsockname()[1]}
                    for server in self._servers for sock in server.sockets],
                "access_hint": ("使用 https://<服务器域名或IP>:<实际端口>/；HTTP 无法访问此 TLS 端口。"
                    if self._scheme == "https" else "使用 http://<服务器域名或IP>:<实际端口>/。")}

    def _config(self):
        from astrbot.dashboard.server import AstrBotDashboard, _parse_env_bool
        dashboard = self._context.get_config().get("dashboard", {})
        setting = dashboard.get("ssl", {})
        enabled = _parse_env_bool(
            os.environ.get("DASHBOARD_SSL_ENABLE") or os.environ.get("ASTRBOT_DASHBOARD_SSL_ENABLE"),
            bool(setting.get("enable", False)))
        self._scheme = "https" if enabled else "http"
        config = Config()
        config.bind = [f"{self._startup['bind']}:{self._startup['port']}"]
        config.accesslog = None
        if enabled:
            valid, resolved = AstrBotDashboard._resolve_dashboard_ssl_config(setting)
            if not valid:
                raise ValueError("global dashboard TLS is unavailable")
            config.certfile, config.keyfile = resolved["certfile"], resolved["keyfile"]
            if "ca_certs" in resolved:
                config.ca_certs = resolved["ca_certs"]
            config.create_ssl_context()
        return config

    async def start(self):
        if not self._startup["enabled"] or self._task is not None:
            return self.status_v1()
        self._state, self._reason = "starting", "webui_starting"
        try:
            config = self._config()
            tls = config.create_ssl_context() if config.ssl_enabled else None
        except (ValueError, OSError, ssl.SSLError):
            self._state, self._reason = "blocked", "tls_unavailable"
            return self.status_v1()
        self._shutdown = asyncio.Event()
        app = wrap_app(self, config.wsgi_max_body_size, "asgi")
        context = WorkerContext(None)
        loop = asyncio.get_running_loop()

        async def connection(reader, writer):
            task = asyncio.current_task()
            self._connections.add(task)
            try:
                await TCPServer(app, loop, config, context, {}, reader, writer)
            finally:
                self._connections.discard(task)

        try:
            server = await asyncio.start_server(
                connection, host=self._startup["bind"], port=self._startup["port"],
                ssl=tls, backlog=config.backlog, reuse_address=False,
                ssl_handshake_timeout=config.ssl_handshake_timeout if tls is not None else None)
        except OSError:
            self._state, self._reason = "blocked", "bind_failed"
            return self.status_v1()
        except BaseException:
            self._state, self._reason = "blocked", "startup_failed"
            raise
        self._servers = (server,)
        self._state, self._reason = "listening", "none"
        self._task = asyncio.create_task(self._serve(config, context))
        self._task.add_done_callback(self._finished)
        return self.status_v1()

    async def _serve(self, config, context):
        serving = tuple(asyncio.create_task(server.serve_forever()) for server in self._servers)
        stopped = asyncio.create_task(self._shutdown.wait())
        try:
            done, _ = await asyncio.wait((*serving, stopped), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task is not stopped:
                    task.result()
                    raise RuntimeError("WebUI server stopped without shutdown")
        finally:
            for server in self._servers:
                server.close()
            for server in self._servers:
                await server.wait_closed()
            self._servers = ()
            await context.terminated.set()
            pending = tuple(self._connections)
            if pending:
                _, unfinished = await asyncio.wait(pending, timeout=config.graceful_timeout)
                for task in unfinished:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            for task in (*serving, stopped):
                task.cancel()
            await asyncio.gather(*serving, stopped, return_exceptions=True)

    def _finished(self, task):
        if task.cancelled():
            self._state, self._reason = "blocked", "listener_cancelled"
        elif task.exception() is not None:
            self._state, self._reason = "blocked", "listener_failed"
            logger.error("Sylanne WebUI listener failed: %s", type(task.exception()).__name__)
        else:
            self._state, self._reason = "stopped", "webui_stopped"

    async def close(self):
        if self._task is not None:
            self._shutdown.set()
            try:
                await asyncio.gather(self._task, return_exceptions=True)
            finally:
                self._task = None
        self._state, self._reason = "stopped", "webui_stopped"

    @staticmethod
    def _dashboard():
        from astrbot.dashboard import server
        if server.APP is None:
            return None
        dashboard = server.APP._dashboard_server
        if type(dashboard) is not server.AstrBotDashboard:
            return None
        return dashboard.asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # The existing Dashboard owns its lifespan; this socket owns only itself.
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        else:
            path, method = scope["path"], scope["method"]
            response = None
            if path == "/webui/status" and method == "GET":
                response = JSONResponse(self.status_v1(), headers=_HEADERS)
            elif method == "GET" and (path in {"/", "/workbench", "/index.html"}
                                      or path.startswith("/assets/")):
                try:
                    relative = "index.html" if path in {"/", "/workbench", "/index.html"} else path[1:]
                    file = _asset_file(relative, _packaged_assets())
                except (ValueError, OSError, KeyError):
                    file = None
                response = (FileResponse(file, headers=_HEADERS) if file is not None else
                            JSONResponse({"reason_code": "asset_unavailable"}, status_code=404, headers=_HEADERS))
            elif scope["scheme"] not in {"http", "https"}:
                response = JSONResponse({"reason_code": "scheme_denied"}, status_code=403, headers=_HEADERS)
            elif ((path in _AUTH_POST and method == "POST")
                  or (path == _PLUGIN_API or path.startswith(_PLUGIN_API + "/"))):
                headers = {name.lower(): value for name, value in scope["headers"]}
                if any(name in {b"forwarded", b"x-real-ip"} or name.startswith(b"x-forwarded-")
                       for name in headers):
                    await JSONResponse({"reason_code": "forwarded_headers_denied"},
                                       status_code=403, headers=_HEADERS)(scope, receive, send)
                    return
                if path in _AUTH_POST and headers.get(b"origin") != scope["scheme"].encode("ascii") + b"://" + headers.get(b"host", b""):
                    await JSONResponse({"reason_code": "origin_denied"},
                                       status_code=403, headers=_HEADERS)(scope, receive, send)
                    return
                app = self._dashboard()
                if app is not None:
                    if scope["scheme"] == "http" and method == "POST" and path in _AUTH_POST:
                        async def send_http_auth(message):
                            if message["type"] == "http.response.start":
                                cookie_name = DASHBOARD_JWT_COOKIE_NAME.encode("ascii")
                                response_headers = []
                                for name, value in message["headers"]:
                                    if name.lower() == b"set-cookie":
                                        segments = value.split(b";")
                                        if segments[0].split(b"=", 1)[0] == cookie_name:
                                            value = b";".join(segment for index, segment in enumerate(segments)
                                                if index == 0 or segment.strip().lower() != b"secure")
                                    response_headers.append((name, value))
                                message = {**message, "headers": response_headers}
                            await send(message)
                        await app(scope, receive, send_http_auth)
                    else:
                        await app(scope, receive, send)
                    return
                response = JSONResponse({"reason_code": "dashboard_not_ready"}, status_code=503, headers=_HEADERS)
            else:
                response = JSONResponse({"reason_code": "route_unavailable"}, status_code=404, headers=_HEADERS)
            await response(scope, receive, send)
