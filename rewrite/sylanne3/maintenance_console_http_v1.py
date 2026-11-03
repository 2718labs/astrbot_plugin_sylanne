"""Independent fixed-route maintenance HTTP server; construction does not listen."""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import ssl
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from .authority_service.v2_owner_session import OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1, from_wire
from .maintenance_console_client_v1 import MaintenanceConsoleUnavailableV1
from .maintenance_console_issuer_v1 import InstalledMaintenanceConsoleOwnerSessionsV1

COOKIE = "SylanneMaintenanceConsoleV1"
_READ_ACTIONS = {"workflow": "inspection_workflow_status", "recovery": "inspection_recovery_status",
    "reconciliation": "inspection_reconciliation_status"}
_MUTATIONS = {"/api/inspection/accept": ("workflow", "inspection_workflow_accept"),
    "/api/inspection/resume-completed": ("recovery", "resume_completed_inspection_v1"),
    "/api/inspection/reconcile-held": ("reconciliation", "reconcile_held_inspection_v1")}


def _uuid(value):
    if type(value) is not str or str(UUID(value)) != value or UUID(value).version != 4:
        raise ValueError("canonical operation UUID4 required")
    return value


class MaintenanceConsoleHttpServerV1(HTTPServer):
    def __init__(self, *, issuer, bind_host, bind_port, asset_root, assets, tls_context=None):
        if (type(issuer) is not InstalledMaintenanceConsoleOwnerSessionsV1
                or type(bind_host) is not str or not bind_host or type(bind_port) is not int
                or not 1 <= bind_port <= 65535 or type(assets) is not dict
                or set(assets) != {"maintenance-console.html", "assets/console.js", "assets/maintenance-console.css"}):
            raise ValueError("protected console listener and fixed packaged assets required")
        if ((issuer.transport_profile == "https") != (tls_context is not None)
                or tls_context is not None and type(tls_context) is not ssl.SSLContext):
            raise ValueError("explicit console transport profile and TLS listener differ")
        self.issuer, self.asset_root, self.assets = issuer, Path(asset_root), dict(assets)
        if not self.asset_root.is_absolute():
            raise ValueError("packaged maintenance console asset root must be absolute")
        self.tls_context = tls_context
        self.runner = None
        super().__init__((bind_host, bind_port), _ConsoleHandlerV1, bind_and_activate=False)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.issuer.client.profile.timeout_seconds)
        return connection, address

    def run_v1(self):
        self.server_bind()
        if self.tls_context is not None:
            self.socket = self.tls_context.wrap_socket(self.socket, server_side=True)
        self.server_activate()
        try:
            with asyncio.Runner() as runner:
                self.runner = runner
                self.serve_forever()
        finally:
            self.runner = None
            self.issuer.close()
            self.server_close()


class _ConsoleHandlerV1(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, value, *, content_type="application/json; charset=utf-8", cookie=None):
        payload = value if type(value) is bytes else json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        if cookie is not None:
            secure = "; Secure" if self.server.issuer.transport_profile == "https" else ""
            self.send_header("Set-Cookie", COOKIE + "=" + cookie + "; Path=/; HttpOnly; SameSite=Strict" + secure)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(payload)

    def _browser(self):
        cookies = SimpleCookie()
        cookies.load(self.headers.get("Cookie", ""))
        value = cookies.get(COOKIE)
        return None if value is None else value.value

    def _request_origin(self, *, mutation=False):
        expected = self.server.issuer.origin
        if self.headers.get_all("Host", []) != [urlsplit(expected).netloc]:
            raise PermissionError("origin_denied")
        origins = self.headers.get_all("Origin", [])
        if (mutation and origins != [expected]) or (origins and origins != [expected]):
            raise PermissionError("origin_denied")
        if self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "none"}:
            raise PermissionError("origin_denied")
        return expected

    def _json(self):
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("JSON request required")
        if self.headers.get("Transfer-Encoding") is not None or len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("finite JSON request length required")
        size = int(self.headers["Content-Length"])
        if not 0 < size <= self.server.issuer.client.profile.max_message_bytes:
            raise ValueError("JSON request exceeds installed transport bound")
        data = json.loads(self.rfile.read(size).decode("utf-8"))
        if type(data) is not dict:
            raise ValueError("exact JSON object required")
        return data

    def _run(self, awaitable):
        return self.server.runner.run(awaitable)

    def do_GET(self):
        try:
            self._request_origin()
            path = urlsplit(self.path)
            if path.path == "/maintenance" and not path.query:
                return self._asset("maintenance-console.html")
            if path.path.startswith("/assets/") and not path.query:
                return self._asset(path.path[1:])
            if path.path == "/api/session/status" and not path.query:
                return self._reply(200, self._run(self.server.issuer.status(self._browser())))
            match = re.fullmatch(r"/api/inspection/([0-9a-f-]+)(/recovery-options)?", path.path)
            if match is None:
                return self._reply(404, {"error": "route_unavailable"})
            operation = _uuid(match[1])
            if match[2]:
                if path.query:
                    raise ValueError("recovery options have no query fields")
                action, fields = "read_inspection_recovery_options_v1", {"parent_workflow_operation_id": operation}
            else:
                query = parse_qs(path.query, keep_blank_values=True)
                if set(query) != {"kind"} or len(query["kind"]) != 1 or query["kind"][0] not in _READ_ACTIONS:
                    raise ValueError("exact inspection read kind required")
                action, fields = _READ_ACTIONS[query["kind"][0]], {"operation_id": operation}
            result = self._run(self.server.issuer.inspect(browser=self._browser(), action=action, fields=fields))
            return self._reply(200, result)
        except PermissionError as exc:
            self._reply(403, {"error": str(exc)})
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            self._reply(400, {"error": "request_invalid"})
        except MaintenanceConsoleUnavailableV1 as exc:
            self._reply(503, {"error": exc.code})

    def _asset(self, name):
        if name not in self.server.assets:
            return self._reply(404, {"error": "route_unavailable"})
        path = self.server.asset_root / name
        if self.server.asset_root.is_symlink() or any(p.is_symlink() for p in (path, path.parent)):
            raise ValueError("packaged asset path differs")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != self.server.assets[name]:
            raise ValueError("packaged asset digest differs")
        content_type = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8"}[path.suffix]
        self._reply(200, payload, content_type=content_type)

    def do_POST(self):
        mutation = None
        operation = None
        try:
            origin = self._request_origin(mutation=True)
            path = urlsplit(self.path)
            if path.query:
                raise ValueError("mutation query not permitted")
            data = self._json()
            issuer = self.server.issuer
            browser = self._browser()
            if path.path == "/api/session/challenge":
                if set(data) != {"request"}:
                    raise ValueError("exact Owner request required")
                request = from_wire(data["request"])
                if type(request) is not OwnerSessionLoginRequestV1:
                    raise ValueError("Owner request kind differs")
                cookie, value = self._run(issuer.begin(browser=browser, origin=origin, request=request))
                return self._reply(200, value, cookie=cookie)
            if path.path == "/api/session/complete":
                if set(data) != {"challenge", "signature_base64"} or type(data["signature_base64"]) is not str:
                    raise ValueError("exact signed Owner challenge required")
                challenge = from_wire(data["challenge"])
                if type(challenge) is not OwnerSessionLoginChallengeV1:
                    raise ValueError("Owner challenge kind differs")
                signature = base64.b64decode(data["signature_base64"], validate=True)
                cookie, value = self._run(issuer.complete(browser=browser, origin=origin, challenge=challenge, signature=signature))
                return self._reply(200, value, cookie=cookie)
            if path.path == "/api/session/logout":
                if data:
                    raise ValueError("logout has no input fields")
                value = self._run(issuer.logout(browser=browser, origin=origin, csrf=self.headers.get("X-CSRF-Token")))
                return self._reply(200, value, cookie="")
            mutation = _MUTATIONS.get(path.path)
            if mutation is None:
                return self._reply(404, {"error": "route_unavailable"})
            if set(data) != {"operation_id", "input"}:
                raise ValueError("exact maintenance operation and input required")
            operation = _uuid(data["operation_id"])
            if mutation[0] == "workflow":
                from .workbench_api.source_inspection_migration_v1 import _workflow_input
                locator = issuer.client.request["namespace"]
                _workflow_input(data["input"], scope=locator["bot_id"] + "/" + locator["persona_id"], operation_id=operation)
            elif mutation[0] == "recovery":
                from .authority_service.source_inspection_recovery_v1 import validate_recovery_input_v1
                validate_recovery_input_v1(operation, data["input"])
            else:
                from .authority_service.source_inspection_held_reconciliation_v1 import validate_held_input_v1
                validate_held_input_v1(operation, data["input"])
            value = self._run(issuer.inspect(browser=browser, origin=origin, csrf=self.headers.get("X-CSRF-Token"),
                action=mutation[1], fields=dict(operation_id=operation, input_data=data["input"])))
            return self._reply(200, value)
        except PermissionError as exc:
            self._reply(403, {"error": str(exc)})
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, binascii.Error):
            self._reply(400, {"error": "request_invalid"})
        except MaintenanceConsoleUnavailableV1 as exc:
            if mutation is not None and operation is not None:
                return self._reply(202, dict(status="pending_confirmation", operation_id=operation, kind=mutation[0]))
            self._reply(503, {"error": exc.code}, cookie="" if self.path == "/api/session/logout" else None)
