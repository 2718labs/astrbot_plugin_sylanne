"""Mount packaged W11 assets and D12 commands on AstrBot's authenticated API."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from ..authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
    from_wire as owner_session_from_wire, to_wire as owner_session_to_wire,
)
from ..workbench_api.http_transport import (
    ASSET_ROUTE, COMMAND_ROUTE, PLUGIN_ROUTE_PREFIX, SCENE_CANDIDATES_ROUTE, SESSION_ROUTE,
    SYLANNE_OWNER_SESSION_COOKIE, WorkbenchHttpTransport,
)
from ..workbench_api.owner_session_resolver import BoundOwnerSessions


_WORKBENCH_ROOT = Path(__file__).resolve().parents[3] / "resources" / "workbench"
_CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                  ".css": "text/css; charset=utf-8"}
_STATIC_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
STATUS_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/status"
OWNER_CHALLENGE_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/owner/challenge"
OWNER_COMPLETE_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/owner/complete"
OWNER_LOGOUT_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/owner/logout"
_OWNER_COOKIE_PATH = f"/api/v1/plugins/extensions{PLUGIN_ROUTE_PREFIX}/v1"
_OWNER_LOGIN_SCHEMA = "sylanne.owner-login.v1"
_MAX_LOGIN_JSON_BYTES = 16 * 1024
_OWNER_ERRORS = {
    "host_stopped": "工作台宿主已停止。",
    "host_session_missing": "AstrBot 控制台登录已失效。",
    "owner_login_unavailable": "Owner 登录服务暂不可用。",
    "owner_login_https_required": "Owner 登录需要 HTTPS 工作台地址。",
    "origin_denied": "请求来源未获允许。",
    "owner_login_invalid_request": "Owner 登录请求格式无效。",
    "owner_login_rejected": "Owner 签名或当前授权核验未通过。",
    "owner_logout_invalid_request": "Owner 退出请求格式无效。",
    "owner_logout_authority_unavailable": "本地会话已锁定，Authority 退出暂未确认。",
}
_RUNTIME_STAGES = {"limited", "blocked", "enrollment_required", "ready", "stopped"}
_REASON_CODES = {
    "none", "not_started", "disabled", "configuration", "data_dir", "authority_profile",
    "authority_profile_verification", "authority_profile_integrity",
    "installation_verification", "affect_scheme_verification", "runtime_bootstrap",
    "namespace_activation", "installed_package", "graph_worker", "domain_registry",
    "v2_fence_recovery", "product_ingress", "owner_guard", "active_role",
    "scene_binding", "dispatch", "runtime_unavailable",
}


def _packaged_assets() -> dict[str, str]:
    manifest = json.loads((_WORKBENCH_ROOT / "workbench-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "sylanne.workbench-assets.v1":
        raise ValueError("packaged workbench manifest is invalid")
    result = {}
    for entry in manifest["files"]:
        path = entry["path"]
        if path in result or Path(path).suffix not in _CONTENT_TYPES:
            raise ValueError("packaged workbench asset is invalid")
        result[path] = entry["sha256"]
    if "index.html" not in result:
        raise ValueError("packaged workbench has no index")
    return result


def _asset_file(relative: str, assets: dict[str, str]) -> Path | None:
    if relative not in assets or "\\" in relative or relative.startswith("/"):
        return None
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    path = _WORKBENCH_ROOT
    for part in parts:
        path = path / part
        if path.is_symlink():
            return None
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != assets[relative]:
        return None
    return path


async def _login_json(request: Any) -> dict[str, object]:
    if (not isinstance(request.content_type, str)
            or request.content_type.split(";", 1)[0].strip().lower() != "application/json"):
        raise ValueError("Owner login requires application/json")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) < 0 or int(length) > _MAX_LOGIN_JSON_BYTES:
                raise ValueError("Owner login body exceeds its limit")
        except (TypeError, ValueError) as exc:
            raise ValueError("Owner login content length is invalid") from exc
    raw = await request.body()
    if len(raw) > _MAX_LOGIN_JSON_BYTES:
        raise ValueError("Owner login body exceeds its limit")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Owner login JSON is invalid") from exc
    if type(result) is not dict:
        raise ValueError("Owner login JSON object is required")
    return result


def _owner_cookie(response: Any, token: str | None) -> None:
    response.set_cookie(
        SYLANNE_OWNER_SESSION_COOKIE, token or "", max_age=3600 if token else 0,
        expires=None if token else 0, path=_OWNER_COOKIE_PATH,
        httponly=True, secure=True, samesite="strict",
    )


class WorkbenchHostMount:
    """One host route whose handler fails closed across plugin reloads."""

    def __init__(self, status_provider: Callable[[], tuple[str, str]] | None = None,
                 scene_candidates: Callable[[Any], tuple[object, ...]] | None = None) -> None:
        self._transport: WorkbenchHttpTransport | None = None
        self._owner_sessions: BoundOwnerSessions | None = None
        self._status_provider = status_provider
        self._scene_candidates = scene_candidates
        self._closed = False

    def attach_transport(self, transport: WorkbenchHttpTransport) -> None:
        if self._closed or self._transport is not None:
            raise RuntimeError("workbench mount is closed or already attached")
        if not isinstance(transport, WorkbenchHttpTransport):
            raise TypeError("trusted D12 transport is required")
        self._transport = transport

    def attach_owner_sessions(self, sessions: BoundOwnerSessions) -> None:
        if self._closed or self._owner_sessions is not None:
            raise RuntimeError("workbench mount is closed or Owner sessions already attached")
        if not isinstance(sessions, BoundOwnerSessions):
            raise TypeError("trusted Owner session resolver is required")
        self._owner_sessions = sessions

    def register(self, context: Any) -> None:
        """Register authenticated, read-only assets and the POST command seam."""
        from astrbot.api.web import file_response, json_response, request

        async def static(asset: str = ""):
            if self._closed:
                return json_response(_unavailable("host_stopped"), status_code=503, headers=_STATIC_HEADERS)
            if not isinstance(request.username, str) or not request.username:
                return json_response(
                    {"status": "unauthorized", "problem": {"code": "host_session_missing",
                     "retryable": False}}, status_code=401, headers=_STATIC_HEADERS,
                )
            try:
                assets = _packaged_assets()
                relative = asset or "index.html"
                path = _asset_file(relative, assets)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                path = None
            if path is None:
                return json_response(
                    {"status": "unavailable", "problem": {"code": "asset_unavailable",
                     "retryable": False}}, status_code=404, headers=_STATIC_HEADERS,
                )
            return file_response(path, content_type=_CONTENT_TYPES[path.suffix], headers=_STATIC_HEADERS)

        async def command():
            headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
            if self._closed:
                return json_response(
                    _unavailable("host_stopped"), status_code=503, headers=headers,
                )
            # AstrBot's plugin extension dependency authenticates this username.
            # A direct call or a changed host API must not become an anonymous
            # command path, even while the Authority bridge is unavailable.
            if not isinstance(request.username, str) or not request.username:
                return json_response(
                    {"status": "unauthorized", "problem": {"code": "host_session_missing",
                     "retryable": False}}, status_code=401, headers=headers,
                )
            transport = self._transport
            if transport is None:
                return json_response(
                    _unavailable("authority_unavailable"), status_code=503, headers=headers,
                )
            # The transport rechecks the independent Sylanne Owner session,
            # exact Origin, CSRF and server-issued scope grants before D12 runs.
            result = await transport.command(request)
            status_code = result.pop("http_status", None)
            if status_code is None:
                code = (result.get("problem") or {}).get("code")
                status_code = {"owner_session_locked": 401, "invalid_request": 400,
                               "invalid_provider_response": 502}.get(code)
                if status_code is None:
                    status_code = {"unauthorized": 403, "unavailable": 503}.get(
                        result.get("status"), 200,
                    )
            return json_response(result, status_code=status_code, headers=headers)

        async def session():
            if self._closed:
                return json_response(_unavailable("host_stopped"), status_code=503,
                                     headers=_STATIC_HEADERS)
            if not isinstance(request.username, str) or not request.username:
                return json_response(
                    {"status": "unauthorized", "problem": {"code": "host_session_missing",
                     "retryable": False}}, status_code=401, headers=_STATIC_HEADERS)
            transport = self._transport
            if transport is None:
                return json_response(_unavailable("authority_unavailable"), status_code=503,
                                     headers=_STATIC_HEADERS)
            result = await transport.open_session(request)
            status_code = result.pop("http_status", 200)
            return json_response(result, status_code=status_code, headers=_STATIC_HEADERS)

        async def scene_candidates():
            if self._closed:
                return json_response(_unavailable("host_stopped"), status_code=503,
                                     headers=_STATIC_HEADERS)
            if not isinstance(request.username, str) or not request.username:
                return json_response(
                    {"status": "unauthorized", "problem": {"code": "host_session_missing",
                     "retryable": False}}, status_code=401, headers=_STATIC_HEADERS)
            transport, sessions, provider = (self._transport, self._owner_sessions,
                                             self._scene_candidates)
            if transport is None or sessions is None or provider is None:
                return json_response(_unavailable("scene_candidates_unavailable"),
                                     status_code=503, headers=_STATIC_HEADERS)
            result = await transport.scene_candidates(
                request, namespace=sessions.namespace, provider=provider)
            status_code = result.pop("http_status", 200)
            return json_response(result, status_code=status_code, headers=_STATIC_HEADERS)

        async def status():
            if self._closed:
                return json_response(_unavailable("host_stopped"), status_code=503,
                                     headers=_STATIC_HEADERS)
            if not isinstance(request.username, str) or not request.username:
                return json_response(
                    {"status": "unauthorized", "problem": {"code": "host_session_missing",
                     "retryable": False}}, status_code=401, headers=_STATIC_HEADERS)
            if self._status_provider is None:
                return json_response(_unavailable("runtime_unavailable"), status_code=503,
                                     headers=_STATIC_HEADERS)
            try:
                stage, reason = self._status_provider()
            except Exception:
                return json_response(_unavailable("runtime_unavailable"), status_code=503,
                                     headers=_STATIC_HEADERS)
            if stage not in _RUNTIME_STAGES:
                stage = "blocked"
                reason = "runtime_unavailable"
            if reason not in _REASON_CODES:
                reason = "runtime_unavailable"
            return json_response(
                {"schema_version": "sylanne.install-status.v1", "runtime_stage": stage,
                 "reason_code": reason}, headers=_STATIC_HEADERS)

        def owner_error(code: str, status_code: int):
            return json_response(
                {"status": "unauthorized" if status_code < 500 else "unavailable",
                 "problem": {"code": code, "message": _OWNER_ERRORS[code],
                             "retryable": False}},
                status_code=status_code, headers=_STATIC_HEADERS)

        def owner_preflight():
            if self._closed:
                return None, owner_error("host_stopped", 503)
            if not isinstance(request.username, str) or not request.username:
                return None, owner_error("host_session_missing", 401)
            sessions = self._owner_sessions
            if sessions is None:
                return None, owner_error("owner_login_unavailable", 503)
            if not sessions.origin.startswith("https://"):
                return None, owner_error("owner_login_https_required", 503)
            if request.headers.get("origin") != sessions.origin:
                return None, owner_error("origin_denied", 403)
            return sessions, None

        async def owner_challenge():
            sessions, error = owner_preflight()
            if error is not None:
                return error
            try:
                payload = await _login_json(request)
                if set(payload) != {"request"}:
                    raise ValueError("Owner login request fields differ")
                login_request = owner_session_from_wire(payload["request"])
                if type(login_request) is not OwnerSessionLoginRequestV1:
                    raise ValueError("Owner login request is required")
                challenge = await sessions.begin_signed_login(
                    request=request, login_request=login_request)
            except (TypeError, ValueError):
                return owner_error("owner_login_invalid_request", 400)
            except RuntimeError:
                return owner_error("owner_login_unavailable", 503)
            return json_response(
                {"schema_version": _OWNER_LOGIN_SCHEMA,
                 "challenge": owner_session_to_wire(challenge),
                 "signing_payload_base64": base64.b64encode(
                     challenge.signed_bytes()).decode("ascii")},
                headers=_STATIC_HEADERS)

        async def owner_complete():
            sessions, error = owner_preflight()
            if error is not None:
                return error
            try:
                payload = await _login_json(request)
                if set(payload) != {"challenge", "signature_base64"}:
                    raise ValueError("Owner signature fields differ")
                challenge = owner_session_from_wire(payload["challenge"])
                encoded = payload["signature_base64"]
                if (type(challenge) is not OwnerSessionLoginChallengeV1
                        or type(encoded) is not str or len(encoded) > 128):
                    raise ValueError("Owner signature is invalid")
                signature = base64.b64decode(encoded, validate=True)
                if len(signature) != 64:
                    raise ValueError("Owner signature is invalid")
                token = await sessions.complete_signed_login(
                    request=request, challenge=challenge, signature=signature)
            except (TypeError, ValueError, binascii.Error):
                return owner_error("owner_login_invalid_request", 400)
            except RuntimeError:
                return owner_error("owner_login_rejected", 403)
            response = json_response(
                {"status": "authenticated", "owner_session": "unlocked"},
                headers=_STATIC_HEADERS)
            _owner_cookie(response, token)
            return response

        async def owner_logout():
            sessions, error = owner_preflight()
            if error is not None:
                return error
            try:
                if await _login_json(request) != {}:
                    raise ValueError("Owner logout body must be empty")
            except (TypeError, ValueError):
                return owner_error("owner_logout_invalid_request", 400)
            token = request.cookies.get(SYLANNE_OWNER_SESSION_COOKIE)
            response = json_response(
                {"status": "ok", "owner_session": "locked"}, headers=_STATIC_HEADERS)
            if isinstance(token, str) and token:
                try:
                    await sessions.revoke_bound_session(
                        username=request.username, owner_session_token=token)
                except RuntimeError:
                    response = owner_error("owner_logout_authority_unavailable", 503)
            _owner_cookie(response, None)
            return response

        context.register_web_api(
            COMMAND_ROUTE, command, ["POST"], "Sylanne D12 authenticated command",
        )
        context.register_web_api(
            PLUGIN_ROUTE_PREFIX, static, ["GET"], "Sylanne W11 authenticated workbench",
        )
        context.register_web_api(
            SESSION_ROUTE, session, ["GET"], "Sylanne current Owner session",
        )
        context.register_web_api(
            SCENE_CANDIDATES_ROUTE, scene_candidates, ["GET"],
            "Sylanne current Owner scene observations",
        )
        context.register_web_api(
            STATUS_ROUTE, status, ["GET"], "Sylanne installation stage",
        )
        context.register_web_api(
            OWNER_CHALLENGE_ROUTE, owner_challenge, ["POST"], "Sylanne Owner signed login challenge",
        )
        context.register_web_api(
            OWNER_COMPLETE_ROUTE, owner_complete, ["POST"], "Sylanne Owner signed login completion",
        )
        context.register_web_api(
            OWNER_LOGOUT_ROUTE, owner_logout, ["POST"], "Sylanne Owner logout",
        )
        context.register_web_api(
            ASSET_ROUTE, static, ["GET"], "Sylanne W11 authenticated static assets",
        )

    def close(self) -> None:
        self._closed = True
        self._transport = None
        self._owner_sessions = None
        self._status_provider = None
        self._scene_candidates = None


def _unavailable(code: str) -> dict[str, object]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("WorkbenchHostMount",)
