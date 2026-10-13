"""AstrBot Web API adapter for the D12 command service.

The Dashboard login opens the page. Owner commands additionally require a
current Sylanne Owner session, checked by a trusted resolver on every request.
JSON fields never create an actor, role, capability, or CSRF exemption.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import inspect
import json
import math
import sys
from pathlib import Path
from threading import Lock
import secrets
from typing import Any, Awaitable, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerPrincipalV1,
)
from ..runtime_contracts import NamespaceId
from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import OwnedGraphStorageResultV3
from .service import ApiResponse, AuthenticatedSession, RequestContext


MAX_JSON_BYTES = 64 * 1024
PLUGIN_ROUTE_PREFIX = "/astrbot_plugin_sylanne/workbench"
COMMAND_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/commands"
SESSION_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/session"
REPLY_CONTROL_SESSION_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/reply-control-session"
SCENE_CANDIDATES_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/scene-candidates"
ASSET_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/<path:asset>"
SYLANNE_OWNER_SESSION_COOKIE = "sylanne_owner_session"


class SessionResolver(Protocol):
    """Recheck an independent Owner bearer session for this Dashboard user."""

    def resolve(self, *, username: str, session_hint: str | None
                ) -> AuthenticatedSession | None | Awaitable[AuthenticatedSession | None]: ...


@dataclass(frozen=True)
class VerifiedOwnerPairing:
    """One current Owner session with its independently verified guard."""

    session: AuthenticatedSession
    principal: OwnerPrincipalV1
    guard: OwnerAuthorizationGuardV1


class CurrentOwnerPairingPort(Protocol):
    """Trusted installation port; recheck the revocable Authority session."""

    def resolve_current_owner_session(self, *, username: str, owner_session_token: str
                                ) -> VerifiedOwnerPairing | None | Awaitable[VerifiedOwnerPairing | None]: ...


class CurrentOwnerDashboardSessions:
    """Keep the historic constructor name while requiring an Owner session.

    Older Dashboard-JWT pairing ports stay locked. This allows an existing
    runtime composition to start safely until its Authority session port is
    installed.
    """

    def __init__(self, pairing: CurrentOwnerPairingPort) -> None:
        self._pairing = pairing if callable(
            getattr(pairing, "resolve_current_owner_session", None)) else None

    async def resolve(self, *, username: str,
                      session_hint: str | None) -> AuthenticatedSession | None:
        if (not isinstance(username, str) or not username
                or not isinstance(session_hint, str) or not session_hint
                or self._pairing is None):
            return None
        paired = self._pairing.resolve_current_owner_session(
            username=username, owner_session_token=session_hint)
        if inspect.isawaitable(paired):
            paired = await paired
        if not isinstance(paired, VerifiedOwnerPairing):
            return None
        session, principal, guard = paired.session, paired.principal, paired.guard
        if (not isinstance(session, AuthenticatedSession)
                or type(principal) is not OwnerPrincipalV1
                or type(guard) is not OwnerAuthorizationGuardV1
                or guard.authorization_revision < 1
                or guard.pending_revoke_operation_id is not None
                or session.host_username != username
                or not session.actor_id or not session.session_id):
            return None
        scope = f"{guard.namespace.bot_id}/{guard.namespace.persona_id}"
        if (set(session.scope_capabilities) != {scope}
                or set(session.scope_audiences) != {scope}
                or set(session.scope_purposes) != {scope}):
            return None
        return session

    async def resolve_operation_status(self, *, username, session_hint, original_ref, purpose):
        reader = getattr(self._pairing, "resolve_current_operation_status_session", None)
        if (not callable(reader) or type(username) is not str or not username
                or type(session_hint) is not str or not session_hint):
            return None
        session = reader(username=username, owner_session_token=session_hint,
                         original_ref=original_ref, purpose=purpose)
        if inspect.isawaitable(session):
            session = await session
        if (type(session) is not AuthenticatedSession or session.host_username != username
                or session.backend_operation_ref != original_ref
                or any(value != frozenset({"workbench.operation_status"})
                       for value in session.scope_capabilities.values())):
            return None
        return session

    async def resolve_reply_controls(self, *, username, session_hint):
        reader = getattr(self._pairing, "resolve_current_reply_control_session", None)
        if (not callable(reader) or type(username) is not str or not username
                or type(session_hint) is not str or not session_hint):
            return None
        session = reader(username=username, owner_session_token=session_hint)
        if inspect.isawaitable(session):
            session = await session
        if (type(session) is not AuthenticatedSession or session.host_username != username
                or any(value != frozenset({"workbench.control"})
                       for value in session.scope_capabilities.values())):
            return None
        return session

    async def resolve_package_status(self,*,username,session_hint,operation_id,purpose):
        reader=getattr(self._pairing,"resolve_current_package_status_session",None)
        if not callable(reader) or type(username) is not str or not username or type(session_hint) is not str or not session_hint:return None
        session=reader(username=username,owner_session_token=session_hint,operation_id=operation_id,purpose=purpose)
        if inspect.isawaitable(session):session=await session
        if (type(session) is not AuthenticatedSession or session.host_username!=username or session.package_operation_id!=operation_id
                or any(v!=frozenset({"workbench.package_status"}) for v in session.scope_capabilities.values())):return None
        return session


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


class BoundCsrfTokens:
    """Server-issued per-session CSRF tokens; raw values are never persisted."""

    def __init__(self) -> None:
        self._tokens: dict[str, list[str]] = {}

    def issue(self, *, session: AuthenticatedSession) -> str:
        return self.issue_for_session_id(session.session_id)

    def issue_for_session_id(self, session_id: str) -> str:
        token = secrets.token_urlsafe(32)
        # Each open workbench tab gets its own token. Keep recent tabs usable
        # without retaining an unlimited number of tokens for one session.
        tokens = self._tokens.setdefault(session_id, [])
        tokens.append(_credential_digest(token))
        del tokens[:-32]
        return token

    def revoke(self, *, session: AuthenticatedSession) -> None:
        self.revoke_session_id(session.session_id)

    def revoke_session_id(self, session_id: str) -> None:
        self._tokens.pop(session_id, None)

    def validate(self, *, session: AuthenticatedSession, token: str) -> bool:
        return self.validate_session_id(session.session_id, token)

    def validate_session_id(self, session_id: str, token: str) -> bool:
        if not isinstance(token, str):
            return False
        received = _credential_digest(token)
        return any(hmac.compare_digest(expected, received)
                   for expected in self._tokens.get(session_id, ()))

    def close(self) -> None:
        self._tokens.clear()


def _credential_digest(value: str) -> str:
    import hashlib
    return hashlib.sha256(b"sylanne.workbench.host-binding.v1\\0" + value.encode("utf-8")).hexdigest()



_OWNED_JSON_ISSUER_V3 = object()


class OwnedWorkbenchJSONV3:
    """Private response payload and its actual transferred retention lease."""
    __slots__ = ("_payload", "_lease", "_lock")

    def __init__(self, issuer, payload, lease):
        if issuer is not _OWNED_JSON_ISSUER_V3:
            raise TypeError("actual workbench transport ownership required")
        self._payload, self._lease, self._lock = payload, lease, Lock()

    @property
    def payload(self):
        return self._payload

    def release_v3(self):
        with self._lock:
            lease = self._lease
            self._payload = self._lease = None
        if lease is not None:
            lease.release()


def _metadata_render_size_v3(value, limit):
    """Count closed JSON with the installed SDK's compact UTF-8 parameters.

    AstrBot4.28.2 uses FastAPI jsonable_encoder then Starlette JSONResponse:
    ensure_ascii=False, allow_nan=False, indent=None, separators=(',', ':').
    This registered metadata tree needs no custom object conversion. Count
    characters before creating encoded strings or the encoder's container copy.
    """
    size = chars = copies = 0

    def add(bytes_count, char_count=None):
        nonlocal size, chars
        size += bytes_count
        chars += bytes_count if char_count is None else char_count
        if size > limit:
            raise OverflowError("metadata response exceeds the existing output limit")

    def string(text):
        add(2)
        for index, character in enumerate(text):
            code = ord(character)
            if character in '\\"\b\f\n\r\t':
                add(2)
            elif code < 32:
                add(6)
            elif code < 128:
                add(1)
            elif code < 2048:
                add(2, 1)
            elif 0xD800 <= code <= 0xDFFF:
                raise UnicodeEncodeError("utf-8", text, index, index + 1, "surrogates not allowed")
            elif code < 65536:
                add(3, 1)
            else:
                add(4, 1)

    def walk(node):
        nonlocal copies
        # Account for the SDK's duplicate container, allowed-keys set, list
        # growth, and encoder chunk metadata using the actual source sizes.
        copies += 4 * sys.getsizeof(node) if type(node) in {dict, list, tuple} else 64
        if node is None:
            add(4)
        elif type(node) is bool:
            add(4 if node else 5)
        elif type(node) is str:
            string(node)
        elif type(node) is int:
            add(len(str(node)))
        elif type(node) is float:
            if not math.isfinite(node):
                raise ValueError("non-finite JSON metadata value")
            add(len(repr(node)))
        elif type(node) is dict:
            add(2)
            first = True
            for key, child in node.items():
                if type(key) is not str:
                    raise TypeError("registered JSON metadata keys must be strings")
                if key.startswith("_sa"):
                    continue  # FastAPI's actual default sqlalchemy_safe filter.
                if not first:
                    add(1)
                first = False
                string(key)
                add(1)
                walk(child)
        elif type(node) in {list, tuple}:
            add(2)
            for index, child in enumerate(node):
                if index:
                    add(1)
                walk(child)
        else:
            raise TypeError("registered JSON metadata must contain only actual JSON values")

    walk(value)
    # Both encoder chunks/joined Unicode text and final UTF-8 bytes can be
    # alive together. Reserve a conservative bound within the same actual pool.
    return size, copies + 8 * chars + size


def command_json_response_v1(result, *, action, status_code, headers):
    """Encode the actual SDK response before releasing a private result lease."""
    from astrbot.api.web import json_response
    from ..runtime.d12_owner_artifact_read_v1 import (
        BODY_RESPONSE_MAX_BYTES, METADATA_RESPONSE_MAX_BYTES,
    )
    owned = result if type(result) is OwnedWorkbenchJSONV3 else None
    if owned is not None:
        result = owned.payload
    try:
        if owned is not None:
            try:
                exact_size, reservation = _metadata_render_size_v3(result, METADATA_RESPONSE_MAX_BYTES)
            except OverflowError:
                return json_response({"status": "unavailable", "problem": {
                    "code": "response_too_large", "retryable": False}},
                    status_code=502, headers=headers)
            try:
                owned._lease.retain(reservation)
            except AuthorityUnavailable:
                return json_response({"status": "unavailable", "problem": {
                    "code": "response_retention_unavailable", "retryable": False}},
                    status_code=503, headers=headers)
            response = json_response(result, status_code=status_code, headers=headers)
            if len(response.body) != exact_size or len(response.body) > METADATA_RESPONSE_MAX_BYTES:
                return json_response({"status": "unavailable", "problem": {
                    "code": "response_too_large", "retryable": False}},
                    status_code=502, headers=headers)
            return response
        projection = result.get("projection")
        body_fields = {"schema", "namespace", "installation_id", "project_ref",
                       "progress_ref", "artifact_ref", "artifact_version", "content_digest",
                       "content_length_bytes", "content_type", "body_encoding", "body_base64"}
        body_result = (action == "read_owner_project_artifact_v1"
                       and result.get("status") == "ready" and set(result) == {"status", "projection"}
                       and type(projection) is dict and set(projection) == body_fields
                       and projection["schema"] == "d12.owner-artifact-read-result.v2"
                       and projection["body_encoding"] == "base64")
        if body_result:
            metadata = dict(result)
            metadata["projection"] = dict(projection)
            metadata["projection"].pop("body_base64")
            if len(json_response(metadata, status_code=status_code, headers=headers).body) > METADATA_RESPONSE_MAX_BYTES:
                return json_response({"status": "unavailable", "problem": {
                    "code": "artifact_response_metadata_too_large", "retryable": False}},
                    status_code=502, headers=headers)
        response = json_response(result, status_code=status_code, headers=headers)
        limit = BODY_RESPONSE_MAX_BYTES if body_result else METADATA_RESPONSE_MAX_BYTES
        if len(response.body) > limit:
            return json_response({"status": "unavailable", "problem": {
                "code": "response_too_large", "retryable": False}},
                status_code=502, headers=headers)
        return response
    finally:
        if owned is not None:
            result = None
            owned.release_v3()


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
                 csrf: CsrfValidator, config: TransportConfig, *, reply_controls=None) -> None:
        if reply_controls is not None:
            from .owner_stop_reply_transport_v1 import InstalledOwnerReplyControlTransportV1
            if type(reply_controls) is not InstalledOwnerReplyControlTransportV1:
                raise TypeError("actual installed Owner reply control transport required")
        self._reply_controls = reply_controls
        self._service, self._sessions, self._csrf, self._config = service, sessions, csrf, config

    async def command(self, request: PluginRequest) -> dict[str, Any]:
        """Bounded parsing selects ordinary content or exact status admission."""
        if not isinstance(request.username, str) or not request.username:
            return self._error("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
        if not self._origin_allowed(request):
            return self._error("unauthorized", "origin_denied", "请求来源未获允许。", 403)
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
        from .owner_stop_reply_transport_v1 import ACTIONS as REPLY_CONTROL_ACTIONS, parse_owner_reply_control_command_v1
        reply_control = type(payload) is dict and payload.get("action") in REPLY_CONTROL_ACTIONS
        if reply_control:
            if self._reply_controls is None:
                return self._error("unavailable", "reply_control_unavailable", "当前安装没有回复停止入口。", 503)
            try:
                parse_owner_reply_control_command_v1(payload)
            except (ValueError, TypeError, KeyError):
                return self._error("unavailable", "invalid_request", "回复控制请求无效。", 400)
            session = await self._bound_reply_control_session(request)
        elif type(payload) is dict and payload.get("action") in {"read_backend_operation","read_package_operation"}:
            # Validate its exact request shape before selecting the separate
            # operation-only resolver. A normal content failure never comes here.
            from .service import WorkbenchService
            try:
                command = WorkbenchService._parse(payload)
            except (ValueError, TypeError, KeyError):
                return self._error("unavailable", "invalid_request", "操作状态请求无效。", 400)
            package_status=command["action"]=="read_package_operation"
            resolver = getattr(self._sessions, "resolve_package_status" if package_status else "resolve_operation_status", None)
            session = None
            if callable(resolver):
                selector={"operation_id":command["input"]["operation_id"]} if package_status else {"original_ref":command["input"]["original_ref"]}
                session = resolver(username=request.username,
                    session_hint=request.cookies.get(SYLANNE_OWNER_SESSION_COOKIE),
                    **selector, purpose=command["purpose"])
                if inspect.isawaitable(session):
                    session = await session
        else:
            session = await self._bound_session(request)
        if (not isinstance(session, AuthenticatedSession)
                or session.host_username != request.username):
            return self._error("unauthorized", "owner_session_locked", "Sylanne Owner 会话未解锁或已失效。", 401)
        token = request.headers.get("x-csrf-token")
        if not isinstance(token, str) or not token or not self._csrf.validate(session=session, token=token):
            return self._error("unauthorized", "csrf_denied", "防跨站校验未通过。", 403)
        if reply_control:
            try:
                return await self._reply_controls.handle(payload, session=session)
            except PermissionError:
                return self._error("unauthorized", "reply_control_denied", "当前 Owner 无此范围的控制资格。", 403)
            except (ValueError, TypeError, KeyError):
                return self._error("unavailable", "invalid_request", "回复控制请求无效。", 400)
            except (RuntimeError, OSError):
                return {"status": "unavailable", "problem": {
                    "code": "reply_control_outcome_unknown", "retryable": True,
                    "message": "控制结果尚未确认，请用原操作标识重新核验。"}, "http_status": 503}
        response = self._service.handle(payload, session=session,
                                        context=RequestContext(True, True, True))
        if inspect.isawaitable(response):
            response = await response
        if type(response) is OwnedGraphStorageResultV3:
            value, lease = response.take_value_v3()
            try:
                # ApiResponse.as_dict creates the envelope and shallow copies
                # its three optional mappings. Charge before those allocations.
                copy_reservation = 256 + sys.getsizeof(value)
                for mapping in (value.projection, value.receipt, value.problem):
                    if mapping is not None:
                        if type(mapping) is not dict:
                            raise TypeError("registered owned response mappings must be actual JSON dicts")
                        copy_reservation += 2 * sys.getsizeof(mapping) + 64
                lease.retain(copy_reservation)
                payload = value.as_dict()
                return OwnedWorkbenchJSONV3(_OWNED_JSON_ISSUER_V3, payload, lease)
            except AuthorityUnavailable:
                value = None
                lease.release()
                return self._error("unavailable", "response_retention_unavailable", "实际响应保留池额度不足。", 503)
            except BaseException:
                value = None
                lease.release()
                raise
        return response.as_dict()

    async def open_session(self, request: PluginRequest) -> dict[str, Any]:
        """Issue a CSRF token only after a current trusted Owner pairing."""
        session = await self._bound_session(request)
        if not isinstance(request.username, str) or not request.username:
            return self._error("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
        if session is None:
            return self._error("unauthorized", "owner_session_locked", "Sylanne Owner 会话未解锁或已失效。", 401)
        if not self._session_origin_allowed(request):
            return self._error("unauthorized", "origin_denied", "请求来源未获允许。", 403)
        issue = getattr(self._csrf, "issue", None)
        if not callable(issue):
            return self._error("unavailable", "csrf_unavailable", "防跨站令牌不可用。", 503)
        return {"status": "ready", "dashboard_session": "authenticated",
                "owner_session": "unlocked", "csrf_token": issue(session=session)}

    async def _bound_reply_control_session(self, request):
        resolver = getattr(self._sessions, "resolve_reply_controls", None)
        if not callable(resolver):
            return None
        session = resolver(username=request.username,
            session_hint=request.cookies.get(SYLANNE_OWNER_SESSION_COOKIE))
        if inspect.isawaitable(session):
            session = await session
        return session if (type(session) is AuthenticatedSession
                           and session.host_username == request.username) else None

    async def open_reply_control_session(self, request: PluginRequest):
        """Explicit metadata session; ordinary content resolution is never a fallback."""
        if self._reply_controls is None:
            return self._error("unavailable", "reply_control_unavailable", "当前安装没有回复停止入口。", 503)
        if not isinstance(request.username, str) or not request.username:
            return self._error("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
        if not self._session_origin_allowed(request):
            return self._error("unauthorized", "origin_denied", "请求来源未获允许。", 403)
        session = await self._bound_reply_control_session(request)
        if session is None:
            return self._error("unauthorized", "owner_session_locked", "Owner 控制会话未解锁或已失效。", 401)
        issue = getattr(self._csrf, "issue", None)
        if not callable(issue):
            return self._error("unavailable", "csrf_unavailable", "防跨站令牌不可用。", 503)
        return {"status": "ready", "dashboard_session": "authenticated",
                "owner_session": "unlocked", "csrf_token": issue(session)}

    async def scene_candidates(self, request: PluginRequest, *, namespace: NamespaceId,
                               provider: Callable[[NamespaceId], tuple[object, ...]]) -> dict[str, Any]:
        """Read recent host observations under the current signed Owner session."""
        if not isinstance(request.username, str) or not request.username:
            return self._error("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
        session = await self._bound_session(request)
        if session is None:
            return self._error("unauthorized", "owner_session_locked", "Sylanne Owner 会话未解锁或已失效。", 401)
        if not self._session_origin_allowed(request):
            return self._error("unauthorized", "origin_denied", "请求来源未获允许。", 403)
        scope = f"{namespace.bot_id}/{namespace.persona_id}"
        if not session.allows(scope, "workbench.read", "workbench_view", "owner"):
            return self._error("unauthorized", "owner_scope_denied", "当前 Owner 无权读取场景候选。", 403)
        candidates = tuple(item for item in provider(namespace) if item.namespace == namespace)
        return {"schema_version": "sylanne.scene-candidates.v1",
                "status": "ready" if candidates else "empty",
                "candidates": [{"platform_ref": item.platform_ref,
                                "conversation_ref": item.conversation_ref,
                                "visibility": item.visibility, "scene_ref": item.scene_ref}
                               for item in candidates]}

    async def _bound_session(self, request: PluginRequest) -> AuthenticatedSession | None:
        # AstrBot authenticates username, while Sylanne's own bearer cookie
        # identifies the revocable Owner session. JSON/headers cannot supply it.
        username = request.username
        if not isinstance(username, str) or not username:
            return None
        owner_cookie = request.cookies.get(SYLANNE_OWNER_SESSION_COOKIE)
        if not isinstance(owner_cookie, str) or not owner_cookie:
            return None
        session = self._sessions.resolve(
            username=username, session_hint=owner_cookie)
        if inspect.isawaitable(session):
            session = await session
        return session if isinstance(session, AuthenticatedSession) and (
            session.host_username == username and session.actor_id and session.session_id) else None

    def _origin_allowed(self, request: PluginRequest) -> bool:
        origin = request.headers.get("origin")
        return isinstance(origin, str) and hmac.compare_digest(origin, self._config.origin)

    def _session_origin_allowed(self, request: PluginRequest) -> bool:
        # Same-origin GET fetches commonly omit Origin. A present Origin must
        # match; otherwise use the browser's Referrer or Fetch Metadata.
        if request.headers.get("origin") is not None:
            return self._origin_allowed(request)
        referer = request.headers.get("referer")
        if isinstance(referer, str) and referer:
            parsed = urlsplit(referer)
            return hmac.compare_digest(
                f"{parsed.scheme}://{parsed.netloc}", self._config.origin)
        return request.headers.get("sec-fetch-site") == "same-origin"

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
            payload = result.payload if type(result) is OwnedWorkbenchJSONV3 else result
            try:
                status_code = payload.pop("http_status", None)
                if status_code is None:
                    code = (payload.get("problem") or {}).get("code")
                    status_code = {"owner_session_locked": 401, "invalid_request": 400,
                                   "invalid_provider_response": 502}.get(code)
                    if status_code is None:
                        status_code = {"unauthorized": 403, "unavailable": 503}.get(payload.get("status"), 200)
                action = None
                projection = payload.get("projection")
                if (payload.get("status") == "ready" and type(projection) is dict
                        and projection.get("schema") == "d12.owner-artifact-read-result.v2"):
                    # command() already bounded/parsed this successful request; SDK body() returns its cache.
                    action = json.loads((await request.body()).decode("utf-8"))["action"]
                return command_json_response_v1(result, action=action, status_code=status_code, headers=response_headers)
            finally:
                payload = None
                if type(result) is OwnedWorkbenchJSONV3:
                    result.release_v3()

        async def serve_asset(asset: str):
            if not isinstance(request.username, str) or not request.username:
                return error_response("unauthorized", "host_session_missing", "AstrBot 未提供已认证会话。", 401)
            # Static assets contain no Owner projection. A Dashboard login can
            # load the page while its independent Owner session is locked.
            # Any supplied Origin must still match our origin.
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
