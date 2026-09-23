"""Mount packaged W11 assets and D12 commands on AstrBot's authenticated API."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from ..workbench_api.http_transport import (
    ASSET_ROUTE, COMMAND_ROUTE, PLUGIN_ROUTE_PREFIX, SESSION_ROUTE,
    WorkbenchHttpTransport,
)


_WORKBENCH_ROOT = Path(__file__).resolve().parents[3] / "resources" / "workbench"
_CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                  ".css": "text/css; charset=utf-8"}
_STATIC_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
STATUS_ROUTE = f"{PLUGIN_ROUTE_PREFIX}/v1/status"
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


class WorkbenchHostMount:
    """One host route whose handler fails closed across plugin reloads."""

    def __init__(self, status_provider: Callable[[], tuple[str, str]] | None = None) -> None:
        self._transport: WorkbenchHttpTransport | None = None
        self._status_provider = status_provider
        self._closed = False

    def attach_transport(self, transport: WorkbenchHttpTransport) -> None:
        if self._closed or self._transport is not None:
            raise RuntimeError("workbench mount is closed or already attached")
        if not isinstance(transport, WorkbenchHttpTransport):
            raise TypeError("trusted D12 transport is required")
        self._transport = transport

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
            STATUS_ROUTE, status, ["GET"], "Sylanne installation stage",
        )
        context.register_web_api(
            ASSET_ROUTE, static, ["GET"], "Sylanne W11 authenticated static assets",
        )

    def close(self) -> None:
        self._closed = True
        self._transport = None
        self._status_provider = None


def _unavailable(code: str) -> dict[str, object]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("WorkbenchHostMount",)
