"""Mount packaged W11 assets and D12 commands on AstrBot's authenticated API."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..workbench_api.http_transport import ASSET_ROUTE, COMMAND_ROUTE, PLUGIN_ROUTE_PREFIX, WorkbenchHttpTransport


_WORKBENCH_ROOT = Path(__file__).resolve().parents[3] / "resources" / "workbench"
_CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                  ".css": "text/css; charset=utf-8"}
_STATIC_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


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

    def __init__(self) -> None:
        self._transport: WorkbenchHttpTransport | None = None
        self._closed = False

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
            # The transport verifies a bound dashboard cookie, exact Origin,
            # per-session CSRF and server-issued scope grants before D12 runs.
            result = await transport.command(request)
            status_code = result.pop("http_status", None)
            if status_code is None:
                code = (result.get("problem") or {}).get("code")
                status_code = {"session_unbound": 401, "invalid_request": 400,
                               "invalid_provider_response": 502}.get(code)
                if status_code is None:
                    status_code = {"unauthorized": 403, "unavailable": 503}.get(
                        result.get("status"), 200,
                    )
            return json_response(result, status_code=status_code, headers=headers)

        context.register_web_api(
            COMMAND_ROUTE, command, ["POST"], "Sylanne D12 authenticated command",
        )
        context.register_web_api(
            PLUGIN_ROUTE_PREFIX, static, ["GET"], "Sylanne W11 authenticated workbench",
        )
        context.register_web_api(
            ASSET_ROUTE, static, ["GET"], "Sylanne W11 authenticated static assets",
        )

    def close(self) -> None:
        self._closed = True
        self._transport = None


def _unavailable(code: str) -> dict[str, object]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("WorkbenchHostMount",)
