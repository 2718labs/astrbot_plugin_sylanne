"""W09 routing boundary only; Authority cryptographic admission is tested separately."""
from uuid import uuid4
import json

import pytest

from sylanne3.workbench_api.http_transport import (
    BoundCsrfTokens, WorkbenchHttpTransport, TransportConfig, SYLANNE_OWNER_SESSION_COOKIE,
)
from sylanne3.workbench_api.service import AuthenticatedSession, ApiResponse


@pytest.mark.asyncio
async def test_explicit_status_uses_only_status_session_and_preserves_csrf(tmp_path):
    ref = "d12authority:" + "a" * 64
    session = AuthenticatedSession("owner", "same-login-id",
        {"bot/persona": frozenset({"workbench.operation_status"})},
        {"bot/persona": frozenset({"owner"})}, {"bot/persona": frozenset({"audit"})},
        host_username="dashboard", backend_operation_ref=ref)
    calls = []
    class Sessions:
        def resolve(self, **kwargs):
            calls.append("content")
            return None
        def resolve_operation_status(self, **kwargs):
            calls.append("status")
            assert kwargs["original_ref"] == ref and kwargs["session_hint"] == "signed-cookie"
            return session
    class Handler:
        def handle(self, payload, *, session, context):
            calls.append("handler")
            assert session.backend_operation_ref == ref
            assert session.scope_capabilities["bot/persona"] == frozenset({"workbench.operation_status"})
            assert context.origin_verified and context.csrf_verified and context.session_bound
            return ApiResponse("running")
    csrf = BoundCsrfTokens()
    token = csrf.issue(session=session)
    transport = WorkbenchHttpTransport(Handler(), Sessions(), csrf, TransportConfig("https://dashboard.local", tmp_path))
    class Request:
        username = "dashboard"
        content_type = "application/json"
        cookies = {SYLANNE_OWNER_SESSION_COOKIE: "signed-cookie"}
        headers = {"origin": "https://dashboard.local", "x-csrf-token": token}
        action = "read_backend_operation"
        async def body(self):
            return json.dumps({"schema_version": "d12.contract.v1", "action": self.action,
                "scope": "bot/persona", "purpose": "audit", "audience": "owner",
                "operation_id": str(uuid4()), "input": {"original_ref": ref}}).encode()
    request = Request()
    assert (await transport.command(request))["status"] == "running"
    assert calls == ["status", "handler"]
    calls.clear()
    request.action = "open_workspace"
    assert (await transport.command(request))["status"] == "unauthorized"
    assert calls == ["content"]
    calls.clear()
    request.action = "read_backend_operation"
    request.headers = {"origin": "https://dashboard.local", "x-csrf-token": "wrong"}
    assert (await transport.command(request))["problem"]["code"] == "csrf_denied"
    assert calls == ["status"]
    calls.clear()
    request.headers = {"origin": "https://attacker.invalid", "x-csrf-token": token}
    assert (await transport.command(request))["problem"]["code"] == "origin_denied"
    assert calls == []
