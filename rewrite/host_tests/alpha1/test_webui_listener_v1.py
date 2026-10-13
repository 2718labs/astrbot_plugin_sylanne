"""Owned loopback socket and real SDK Dashboard delegation; no model work."""
import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import hashlib
import secrets
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx
import pytest

from astrbot import core
from astrbot.api.star import Context
from astrbot.api.web import json_response, request
from astrbot.core.astrbot_config_mgr import AstrBotConfigManager
from astrbot.core.conversation_mgr import ConversationManager
from astrbot.core.core_lifecycle import AstrBotCoreLifecycle
from astrbot.core.db.sqlite import SQLiteDatabase
from astrbot.core.log import LogBroker
from astrbot.core.persona_mgr import PersonaManager
from astrbot.core.platform_message_history_mgr import PlatformMessageHistoryManager
from astrbot.core.provider.manager import ProviderManager
from astrbot.core.star.star_manager import PluginManager
from astrbot.core.umop_config_router import UmopConfigRouter
from astrbot.dashboard import server as dashboard_server
from astrbot.dashboard.password_state import set_dashboard_password_hashes
from astrbot.dashboard.api.auth import _set_dashboard_jwt_cookie, _clear_dashboard_jwt_cookie
from astrbot.dashboard.asgi_runtime import FastAPIAppAdapter
from astrbot.dashboard.services.auth_service import DASHBOARD_JWT_COOKIE_NAME
from fastapi import FastAPI
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse

from sylanne3.host.webui_listener_v1 import WebuiListenerV1


def context_for(config):
    return Context(asyncio.Queue(), config, None, None, None, None,
                   None, None, None, None, None)


def test_http_owned_listener_static_status_conflict_and_close(monkeypatch):
    async def exercise():
        monkeypatch.setattr(dashboard_server, "APP", None)
        config = {"dashboard": {"ssl": {"enable": False}}}
        context = context_for(config)
        listener = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=0)
        status = await listener.start()
        assert status["state"] == "listening" and status["scheme"] == "http"
        port = listener.status_v1()["bound_addresses"][0]["port"]
        assert status["bound_addresses"] == [{"host": "127.0.0.1", "port": port}]
        conflict = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=port)
        try:
            assert (await conflict.start())["reason_code"] == "bind_failed"
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
                public = await client.get("/webui/status")
                assert public.status_code == 200 and public.json() == status
                page = await client.get("/")
                assert page.status_code == 200 and b"<!doctype html" in page.content.lower()
                assert page.headers["cache-control"] == "no-store"
                for method, path, code, reason in [
                    ("POST", "/api/v1/auth/login", 403, "origin_denied"),
                    ("POST", "/api/v1/auth/logout", 403, "origin_denied"),
                    ("GET", "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/session", 503, "dashboard_not_ready"),
                    ("POST", "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/owner/challenge", 503, "dashboard_not_ready"),
                    ("GET", "/api/v1/config", 404, "route_unavailable")]:
                    denied = await client.request(method, path)
                    assert denied.status_code == code and denied.json()["reason_code"] == reason
                assert (await client.get("/assets/../private.key")).status_code in {403, 404}
        finally:
            await listener.close()
            await conflict.close()
        assert listener.status_v1()["state"] == "stopped"
        reused = socket.socket()
        try:
            reused.bind(("127.0.0.1", port))
        finally:
            reused.close()
        disabled = WebuiListenerV1(context, enabled=False)
        assert (await disabled.start())["state"] == "disabled"
        config["dashboard"]["ssl"] = {"enable": True, "cert_file": "missing-fixture-cert", "key_file": "missing-fixture-key"}
        invalid_tls = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=0)
        assert (await invalid_tls.start())["reason_code"] == "tls_unavailable"
        assert invalid_tls.status_v1()["scheme"] == "https" and invalid_tls._servers == ()

    asyncio.run(exercise())


def test_listener_start_failure_and_cancel_release_actual_port(monkeypatch):
    async def exercise():
        context = context_for({"dashboard": {"ssl": {"enable": False}}})
        listener = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=0)
        async def rejected(*args, **kwargs):
            raise OSError("fixture server start failure")
        with monkeypatch.context() as patch:
            patch.setattr(asyncio, "start_server", rejected)
            status = await listener.start()
        assert status["state"] == "blocked" and status["reason_code"] == "bind_failed"
        assert status["bound_addresses"] == [] and listener._servers == ()
        assert (await listener.start())["state"] == "listening"
        port = listener.status_v1()["bound_addresses"][0]["port"]
        # Cancel the actual serving owner after it has acquired its server tasks.
        await asyncio.sleep(0)
        listener._task.cancel()
        await asyncio.gather(listener._task, return_exceptions=True)
        assert listener.status_v1()["state"] == "blocked"
        assert listener.status_v1()["reason_code"] == "listener_cancelled"
        assert listener._servers == () and listener.status_v1()["bound_addresses"] == []
        await listener.close()
        reused = socket.socket()
        try:
            reused.bind(("127.0.0.1", port))
        finally:
            reused.close()
    asyncio.run(exercise())


def fixture_tls(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                           x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    public, private = tmp_path / "fixture-cert.pem", tmp_path / "fixture-key.pem"
    public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return public, private


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_owned_listener_late_real_dashboard_auth_and_original_scope(tmp_path, monkeypatch, scheme):
    async def exercise():
        tls_settings = {"enable": scheme == "https"}
        if scheme == "https":
            public, private = fixture_tls(tmp_path)
            tls_settings.update(cert_file=str(public), key_file=str(private))
        password = "Listener9!" + secrets.token_hex(16)
        config = core.astrbot_config
        config["dashboard"] = {"username": "listener-test-admin", "jwt_secret": secrets.token_hex(32),
                               "password_change_required": False, "disable_access_log": True,
                               "trust_proxy_headers": True,
                               "ssl": tls_settings}
        set_dashboard_password_hashes(config, password)
        context = context_for(config)
        before = list(context.registered_web_apis)
        observed = []
        async def probe():
            observed.append((request._request.url.scheme, request.headers.get("host"),
                             request.headers.get("origin"), request.headers.get("cookie")))
            return json_response({"authenticated": bool(request.username)})
        context.register_web_api("/astrbot_plugin_sylanne/workbench/v1/listener-test", probe, ["GET"], "fixture")
        monkeypatch.setattr(dashboard_server, "APP", None)
        listener = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=0)
        assert (await listener.start())["state"] == "listening"
        port = listener.status_v1()["bound_addresses"][0]["port"]
        assert listener.status_v1()["bound_addresses"] == [{"host": "127.0.0.1", "port": port}]
        assert scheme + "://" in listener.status_v1()["access_hint"]
        if scheme == "https":
            # HTTP on a real TLS listener closes before ASGI; it cannot be fixed by an API route.
            plain_reader, plain_writer = await asyncio.open_connection("127.0.0.1", port)
            plain_writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await plain_writer.drain()
            try:
                assert await asyncio.wait_for(plain_reader.read(1), timeout=3) == b""
            except ConnectionResetError:
                pass
            finally:
                plain_writer.close()
                try:
                    await plain_writer.wait_closed()
                except ConnectionResetError:
                    pass
        origin = f"{scheme}://localhost:{port}"
        verified_tls = ssl.create_default_context(cafile=str(public)) if scheme == "https" else True
        db = SQLiteDatabase(str(tmp_path / "dashboard.db"))
        lifecycle = AstrBotCoreLifecycle(LogBroker(), db)
        lifecycle.umop_config_router = UmopConfigRouter(sp=core.sp)
        lifecycle.astrbot_config_mgr = AstrBotConfigManager(config, lifecycle.umop_config_router, core.sp)
        lifecycle.persona_mgr = PersonaManager(db, lifecycle.astrbot_config_mgr)
        lifecycle.provider_manager = ProviderManager(lifecycle.astrbot_config_mgr, db, lifecycle.persona_mgr)
        lifecycle.conversation_manager = ConversationManager(db)
        lifecycle.platform_message_history_manager = PlatformMessageHistoryManager(db)
        lifecycle.platform_manager = None
        lifecycle.star_context = context
        lifecycle.plugin_manager = PluginManager(context, config)
        lifecycle.astrbot_updater = None
        path = "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/listener-test"
        try:
            async with httpx.AsyncClient(base_url=origin, verify=verified_tls, trust_env=False) as client:
                unavailable = await client.get(path)
                assert unavailable.status_code == 503 and unavailable.json()["reason_code"] == "dashboard_not_ready"
                dashboard = dashboard_server.AstrBotDashboard(lifecycle, db, asyncio.Event())
                assert dashboard_server.APP._dashboard_server is dashboard
                assert listener._dashboard() is dashboard.asgi_app
                assert dashboard.app.debug is False and dashboard.app.testing is False
                assert dashboard.app.config.get("DASHBOARD_JWT_COOKIE_SECURE", True) is True
                assert (await client.get(path)).status_code == 401
                assert lifecycle.provider_manager.provider_insts == []
                credentials = {"username": "listener-test-admin", "password": password}
                assert (await client.post("/api/v1/auth/login", json=credentials)).status_code == 403
                assert (await client.post("/api/v1/auth/login", json=credentials,
                                          headers={"Origin": "https://foreign.invalid"})).status_code == 403
                login = await client.post("/api/v1/auth/login", json=credentials, headers={"Origin": origin})
                assert login.status_code == 200 and login.json()["status"] == "ok"
                jwt_cookie = next(cookie for cookie in login.headers.get_list("set-cookie")
                                  if cookie.startswith(DASHBOARD_JWT_COOKIE_NAME + "="))
                assert ("; Secure" in jwt_cookie) is (scheme == "https")
                assert "; HttpOnly" in jwt_cookie and "; SameSite=strict" in jwt_cookie
                result = await client.get(path, headers={"Origin": origin})
                assert result.status_code == 200 and result.json() == {"authenticated": True}
                assert observed[-1][0:3] == (scheme, f"localhost:{port}", origin)
                actual_cookie = hashlib.sha256(observed[-1][3].encode()).digest()
                sent_cookie = hashlib.sha256(
                    "; ".join(f"{key}={value}" for key, value in client.cookies.items()).encode()).digest()
                assert actual_cookie == sent_cookie
                for header in ["Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-For", "X-Real-IP"]:
                    denied = await client.get(path, headers={"Origin": origin, header: "https"})
                    assert denied.status_code == 403 and denied.json()["reason_code"] == "forwarded_headers_denied"
                for blocked in ["/api/v1/config", "/api/v1/plugins", "/api/v1/auth/desktop-session",
                                "/api/v1/plugins/extensions/astrbot_plugin_sylanne_extra/workbench"]:
                    assert (await client.get(blocked)).status_code == 404
                assert (await client.post("/api/v1/auth/logout", headers={"Origin": "https://foreign.invalid"})).status_code == 403
                assert (await client.post("/api/v1/auth/logout", headers={"Origin": origin})).status_code == 200
                assert (await client.get(path)).status_code == 401
        finally:
            await listener.close()
            context.registered_web_apis[:] = before
            await db.engine.dispose()

    asyncio.run(exercise())


@pytest.mark.parametrize("scheme", ("http", "https"))
@pytest.mark.parametrize("path", ("/api/v1/auth/login", "/api/v1/auth/logout"))
def test_listener_changes_only_sdk_jwt_secure_flag(scheme, path, monkeypatch):
    async def exercise():
        app = FastAPI()
        adapter = FastAPIAppAdapter(app)
        assert adapter.debug is False and adapter.testing is False and adapter.config == {}
        origin = scheme + "://dashboard.local"
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "scheme": scheme, "method": "POST", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "server": ("dashboard.local", 443 if scheme == "https" else 80),
                 "client": ("127.0.0.1", 1), "headers": [(b"host", b"dashboard.local"),
                     (b"origin", origin.encode())], "app": app}
        sdk_request = StarletteRequest(scope)
        response = JSONResponse({"status": "ok"}, status_code=200 if path.endswith("login") else 403)
        if path.endswith("login"):
            _set_dashboard_jwt_cookie(sdk_request, response, "original.header.payload.signature")
        else:
            _clear_dashboard_jwt_cookie(sdk_request, response)
        response.set_cookie("independent_cookie", "original-value", secure=True, httponly=True,
                            samesite="strict", path="/other", expires="Wed, 21 Oct 2037 07:28:00 GMT")
        response.raw_headers.append((b"set-cookie", b"" + DASHBOARD_JWT_COOKIE_NAME.encode() +
            b"_shadow=untouched; Secure; Path=/; SameSite=Strict"))
        response.raw_headers.append((b"set-cookie", DASHBOARD_JWT_COOKIE_NAME.encode().upper() +
            b"=case-sensitive; Secure; Path=/"))
        response.raw_headers.append((b"set-cookie", b"custom=not-a-jwt; Secure=1; Path=/"))
        before = tuple(response.raw_headers)
        jwt_before = next(value for name, value in before
                          if name == b"set-cookie" and value.split(b"=", 1)[0] == DASHBOARD_JWT_COOKIE_NAME.encode())
        assert b"; Secure" in jwt_before
        listener = WebuiListenerV1(context_for({}), enabled=False)
        monkeypatch.setattr(listener, "_dashboard", lambda: response)
        received = []
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            received.append(message)
        await listener(scope, receive, send)
        after = tuple(received[0]["headers"])
        expected = tuple((name, value.replace(b"; Secure", b"", 1)
                    if scheme == "http" and name == b"set-cookie"
                    and value.split(b"=", 1)[0] == DASHBOARD_JWT_COOKIE_NAME.encode()
                    else value) for name, value in before)
        assert after == expected
        assert received[0]["status"] == response.status_code
        assert received[1]["body"] == response.body
        assert adapter.config == {} and adapter.debug is False and adapter.testing is False
    asyncio.run(exercise())
