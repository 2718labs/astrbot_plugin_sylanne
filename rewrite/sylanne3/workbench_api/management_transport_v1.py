"""Same-origin management adapter; permissions remain in installed Authority."""
from __future__ import annotations

import asyncio
import hmac
import json
from urllib.parse import urlsplit

from ..authority_service.installation_management_v1 import (
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ManagementProblem,
)
from ..host.v2_fence_port import V2FencePort
from .http_transport import BoundCsrfTokens, SYLANNE_OWNER_SESSION_COOKIE, TransportConfig
from .installation_owner_sessions_v1 import InstallationOwnerSessionsV1


class InstallationManagementTransportV1:
    def __init__(self, *, identity, csrf, port, config):
        if (type(identity) is not InstallationOwnerSessionsV1
                or type(csrf) is not BoundCsrfTokens or type(port) is not V2FencePort
                or type(config) is not TransportConfig or identity.origin != config.origin
                or port._installation_grant.installation_id != identity._installation_id
                or port._installation_grant.authority_id != identity._authority_id):
            raise TypeError("actual installed management transport is required")
        self.identity, self.csrf, self.port, self.config = identity, csrf, port, config

    def _origin(self, request, *, read=False):
        site = request.headers.get("sec-fetch-site")
        if site is not None and site != "same-origin":
            return False
        origin = request.headers.get("origin")
        if origin is not None:
            return type(origin) is str and hmac.compare_digest(origin, self.config.origin)
        if not read:
            return False
        referer = request.headers.get("referer")
        if type(referer) is str and referer:
            parsed = urlsplit(referer)
            return hmac.compare_digest(f"{parsed.scheme}://{parsed.netloc}", self.config.origin)
        return site == "same-origin"

    async def _identity(self, request):
        if type(request.username) is not str or not request.username:
            return None
        token = request.cookies.get(SYLANNE_OWNER_SESSION_COOKIE)
        return await self.identity.resolve_current_identity(
            username=request.username, owner_session_token=token)

    async def open_session(self, request):
        # This proves the two identities only; it grants no D12 or management
        # capability. Both services still authorize every protected operation.
        if not self._origin(request, read=True):
            return {"status": "unauthorized", "problem": {"code": "origin_denied", "retryable": False},
                    "http_status": 403}
        identity = await self._identity(request)
        if identity is None:
            return {"status": "unauthorized", "problem": {"code": "owner_session_locked", "retryable": False},
                    "http_status": 401}
        return {"status": "ready", "dashboard_session": "authenticated", "owner_session": "unlocked",
                "csrf_token": self.csrf.issue_for_session_id(identity.session_id)}

    async def command(self, operation, request):
        try:
            if type(request.username) is not str or not request.username:
                raise ManagementProblem("host_session_missing", 401)
            if not self._origin(request):
                raise ManagementProblem("origin_denied", 403)
            identity = await self._identity(request)
            if identity is None:
                raise ManagementProblem("owner_session_invalid", 401)
            if not self.csrf.validate_session_id(identity.session_id, request.headers.get("x-csrf-token")):
                raise ManagementProblem("csrf_denied", 403)
            if (type(request.content_type) is not str
                    or request.content_type.split(";", 1)[0].strip().lower() != "application/json"):
                raise ManagementProblem("unsupported_content_type", 415)
            length = request.headers.get("content-length")
            if length is not None:
                try:
                    size = int(length)
                except (TypeError, ValueError):
                    raise ManagementProblem("invalid_request", 400) from None
                if size < 0:
                    raise ManagementProblem("invalid_request", 400)
                if size > MAX_REQUEST_BYTES:
                    raise ManagementProblem("body_too_large", 413)
            raw = await request.body()
            if len(raw) > MAX_REQUEST_BYTES:
                raise ManagementProblem("body_too_large", 413)
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ManagementProblem("invalid_request", 400) from None
            try:
                result = await asyncio.to_thread(self.port.installation_management_v1,
                    namespace=self.identity.namespace, authority_namespace=self.identity._authority_namespace,
                    operation=operation, owner_token=request.cookies[SYLANNE_OWNER_SESSION_COOKIE], payload=payload)
            except (RuntimeError, ValueError, TypeError, OSError):
                # The service may have committed a write. Return uncertainty;
                # neither this adapter nor the client retries it automatically.
                raise ManagementProblem("management_unavailable", 503) from None
            if await self._identity(request) != identity:
                raise ManagementProblem("owner_session_invalid", 401)
            if (type(result) is not dict or set(result) != {"http_status", "json"}
                    or type(result["http_status"]) is not int or type(result["json"]) is not dict
                    or len(json.dumps(result["json"], ensure_ascii=False, allow_nan=False).encode()) > MAX_RESPONSE_BYTES):
                raise ManagementProblem("management_response_invalid", 502)
            return result
        except ManagementProblem as error:
            return {"http_status": error.status, "json": error.json()}
