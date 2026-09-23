"""Mount the D12 command boundary on AstrBot's authenticated plugin API.

An installation grant is not a browser user's graph grant.  The route stays
unavailable until a separately authenticated W09 session and W01 grant bridge
can supply a WorkbenchHttpTransport.  No static asset is served here.
"""

from __future__ import annotations

from typing import Any

from ..workbench_api.http_transport import COMMAND_ROUTE, WorkbenchHttpTransport


class WorkbenchHostMount:
    """One host route whose handler fails closed across plugin reloads."""

    def __init__(self) -> None:
        self._transport: WorkbenchHttpTransport | None = None
        self._closed = False

    def register(self, context: Any) -> None:
        """Register only the AstrBot-authenticated POST extension route."""
        from astrbot.api.web import json_response, request

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

    def close(self) -> None:
        self._closed = True
        self._transport = None


def _unavailable(code: str) -> dict[str, object]:
    return {"status": "unavailable", "problem": {"code": code, "retryable": True}}


__all__ = ("WorkbenchHostMount",)
