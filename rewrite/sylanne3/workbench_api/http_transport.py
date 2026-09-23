"""AstrBot Web API adapter for the D12 command service.

The adapter deliberately receives its authority only from the authenticated
AstrBot request context and a W09 session resolver.  JSON fields never create
an actor, role, capability, or CSRF exemption.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import inspect
import json
from pathlib import Path
import secrets
from typing import Any, Awaitable, Mapping, Protocol

from .service import ApiResponse, AuthenticatedSession, RequestContext


MAX_JSON_BYTES = 64 * 1024
PLUGIN_ROUTE_PREFIX = "/astrbot_plugin_sylanne/workbench"
COMMAND_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/commands"
ASSET_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/<path:asset>"
ASTRBOT_DASHBOARD_JWT_COOKIE = "astrbot_dashboard_jwt"


class SessionResolver(Protocol):
    """Resolve a W09-issued session from the host-authenticated username."""

    def resolve(self, *, username: str, session_hint: str | None) -> AuthenticatedSession | None: ...


class CsrfValidator(Protocol):
    """Validate a CSRF token bound to the same server-side session."""

    def validate(self, *, session: AuthenticatedSession, token: str) -> bool: ...


class PluginRequest(Protocol):
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    username: str | None
    content_type: str | None

    async def body(self) -> bytes: ...


class WorkbenchHandler(Protocol):
    def handle(self, payload: object, *, session: AuthenticatedSession | None,
               context: RequestContext) -> ApiResponse | Awaitable[ApiResponse]: ...


class BoundDashboardSessions:
    """W09-owned store binding a validated AstrBot dashboard JWT to a session.

    ``bind_authenticated_dashboard_session`` may only be called by code that
    has already passed AstrBot's dashboard authentication. The raw JWT is never
    retained: lookup uses a domain-separated digest and requires the same host
    cookie on every command. No entry means fail closed.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], AuthenticatedSession] = {}

    def bind_authenticated_dashboard_session(self, *, username: str, dashboard_jwt: str,
                                             session: AuthenticatedSession) -> None:
        if not isinstance(username, str) or not username or not isinstance(dashboard_jwt, str) or not dashboard_jwt:
            raise ValueError("trusted dashboard identity and JWT are required")
        if session.actor_id != username:
            raise ValueError("session actor must match the host-authenticated username")
        self._entries[(username, _credential_digest(dashboard_jwt))] = session

    def revoke(self, *, username: str, dashboard_jwt: str) -> None:
        self._entries.pop((username, _credential_digest(dashboard_jwt)), None)

    def resolve(self, *, username: str, session_hint: str | None) -> AuthenticatedSession | None:
        if not isinstance(session_hint, str) or not session_hint:
            return None
        return self._entries.get((username, session_hint))


class BoundCsrfTokens:
    """Server-issued per-session CSRF tokens; raw values are never persisted."""

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}

    def issue(self, *, session: AuthenticatedSession) -> str:
        token = secrets.token_urlsafe(32)
        self._tokens[session.session_id] = _credential_digest(token)
        return token

    def revoke(self, *, session: AuthenticatedSession) -> None:
        self._tokens.pop(session.session_id, None)

    def validate(self, *, session: AuthenticatedSession, token: str) -> bool:
        expected = self._tokens.get(session.session_id)
        return isinstance(token, str) and expected is not None and hmac.compare_digest(expected, _credential_digest(token))


def _credential_digest(value: str) -> str:
    import hashlib
    return hashlib.sha256(b"sylanne.workbench.host-binding.v1\\0" + value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TransportConfig:
    origin: str
    asset_root: Path
    max_json_bytes: int = MAX_JSON_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.origin, str) or not self.origin.startswith(("http://", "https://")):
            raise ValueError("origin must be an absolute http(s) origin")
        if self.origin.rstrip("/") != self.origin:
            raise ValueError("origin must not end with a slash")
        if type(self.max_json_bytes) is not int or not 1 <= self.max_json_bytes <= MAX_JSON_BYTES:
            raise ValueError("max_json_bytes must be bounded")


class WorkbenchHttpTransport:
    def __init__(self, service: WorkbenchHandler, sessions: SessionResolver,
                 csrf: CsrfValidator, config: TransportConfig) -> None:
        self._service, self._sessions, self._csrf, self._config = service, sessions, csrf, config

    async def command(self, request: PluginRequest) -> dict[str, Any]:
        """Handle a mounted POST only after host session, Origin and CSRF checks."""
        session = self._bound_session(request)
        if not isinstance(request.username, str) or not request.username:
            return self._error("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
        if session is None:
            return self._error("unauthorized", "session_unbound", "工作台会话未建立。", 401)
        if not self._origin_allowed(request):
            return self._error("unauthorized", "origin_denied", "请求来源未获允许。", 403)
        token = request.headers.get("x-csrf-token")
        if not isinstance(token, str) or not token or not self._csrf.validate(session=session, token=token):
            return self._error("unauthorized", "csrf_denied", "防跨站校验未通过。", 403)
        if request.content_type is None or request.content_type.split(";", 1)[0].strip().lower() != "application/json":
            return self._error("unavailable", "unsupported_content_type", "请求必须使用 application/json。", 415)
        length = request.headers.get("content-length")
        try:
            declared_length = int(length) if length is not None else None
            if declared_length is not None and declared_length < 0:
                return self._error("unavailable", "invalid_content_length", "请求长度无效。", 400)
            if declared_length is not None and declared_length > self._config.max_json_bytes:
                return self._error("unavailable", "body_too_large", "请求体超过限制。", 413)
        except ValueError:
            return self._error("unavailable", "invalid_content_length", "请求长度无效。", 400)
        raw = await request.body()
        if len(raw) > self._config.max_json_bytes:
            return self._error("unavailable", "body_too_large", "请求体超过限制。", 413)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._error("unavailable", "invalid_json", "请求 JSON 无效。", 400)
        response = self._service.handle(payload, session=session,
                                        context=RequestContext(True, True, True))
        if inspect.isawaitable(response):
            response = await response
        return response.as_dict()

    def _bound_session(self, request: PluginRequest) -> AuthenticatedSession | None:
        # Only the dashboard's authenticated username plus its own cookie can
        # select a W09-issued session. Neither JSON nor a request header can.
        username = request.username
        if not isinstance(username, str) or not username:
            return None
        host_cookie = request.cookies.get(ASTRBOT_DASHBOARD_JWT_COOKIE)
        if not isinstance(host_cookie, str) or not host_cookie:
            return None
        session = self._sessions.resolve(username=username, session_hint=_credential_digest(host_cookie))
        return session if session is not None and session.actor_id == username else None

    def _origin_allowed(self, request: PluginRequest) -> bool:
        origin = request.headers.get("origin")
        return isinstance(origin, str) and hmac.compare_digest(origin, self._config.origin)

    def asset_path(self, asset: str) -> Path | None:
        """Resolve a static asset beneath the immutable workbench asset root."""
        if not isinstance(asset, str) or not asset or "\\" in asset:
            return None
        root = self._config.asset_root.resolve()
        candidate = (root / asset).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    def mount_astrbot(self, context: Any) -> None:
        """Mount through AstrBot 4.28.1's ``Context.register_web_api`` seam."""
        from astrbot.api.web import file_response, json_response, request

        response_headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

        def error_response(status: str, code: str, message: str, status_code: int):
            result = self._error(status, code, message, status_code)
            result.pop("http_status")
            return json_response(result, status_code=status_code, headers=response_headers)

        async def serve_command():
            result = await self.command(request)
            status_code = result.pop("http_status", None)
            if status_code is None:
                code = (result.get("problem") or {}).get("code")
                status_code = {"session_unbound": 401, "invalid_request": 400,
                               "invalid_provider_response": 502}.get(code)
                if status_code is None:
                    status_code = {"unauthorized": 403, "unavailable": 503}.get(result.get("status"), 200)
            return json_response(result, status_code=status_code, headers=response_headers)

        async def serve_asset(asset: str):
            if not isinstance(request.username, str) or not request.username:
                return error_response("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
            if self._bound_session(request) is None:
                return error_response("unauthorized", "session_unbound", "工作台会话未建立。", 401)
            # Fetching images/scripts cannot supply a CSRF header. The host
            # session is required; any supplied Origin must match our origin.
            if request.headers.get("origin") is not None and not self._origin_allowed(request):
                return error_response("unauthorized", "origin_denied", "请求来源未获允许。", 403)
            path = self.asset_path(asset)
            if path is None:
                return error_response("unavailable", "asset_not_found", "资源不存在。", 404)
            return file_response(path, headers=response_headers)

        context.register_web_api(COMMAND_ROUTE, serve_command, ["POST"], "Sylanne D12 workbench command")
        context.register_web_api(ASSET_ROUTE, serve_asset, ["GET"], "Sylanne workbench static asset")

    @staticmethod
    def _error(status: str, code: str, message: str, http_status: int) -> dict[str, Any]:
        return {"status": status, "problem": {"code": code, "message": message, "retryable": False}, "http_status": http_status}
