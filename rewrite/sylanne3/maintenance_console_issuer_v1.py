"""Fresh paired Owner sessions for the independent maintenance browser."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import secrets
import time

from .authority_service.v2_owner_proof import _time
from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1, to_wire
from .maintenance_console_client_v1 import MaintenanceConsoleClientV1, MaintenanceConsoleUnavailableV1


@dataclass(frozen=True, slots=True)
class MaintenanceConsoleOwnerIdentityV1:
    request: OwnerSessionLoginRequestV1
    actor_id: str
    session_id: str


@dataclass(frozen=True, slots=True)
class _BrowserOwnerV1:
    identity: MaintenanceConsoleOwnerIdentityV1
    token: str = field(repr=False)


class InstalledMaintenanceConsoleOwnerSessionsV1:
    def __init__(self, *, client, transport_profile):
        if type(client) is not MaintenanceConsoleClientV1 or transport_profile not in {"full_http", "https"}:
            raise TypeError("independent installed maintenance client/transport profile required")
        self.client, self.transport_profile = client, transport_profile
        self.origin = client.request["origin"]
        if self.origin.split(":", 1)[0] != ("https" if transport_profile == "https" else "http"):
            raise ValueError("protected console Origin and explicit transport profile differ")
        self._secret = secrets.token_bytes(32)
        self._pending = {}
        self._browsers = {}
        self._closed = False

    def _open(self):
        if self._closed:
            raise PermissionError("console_closed")

    def _origin(self, origin):
        self._open()
        if origin != self.origin:
            raise PermissionError("origin_denied")

    def _matches(self, request):
        locator = self.client.request
        return (type(request) is OwnerSessionLoginRequestV1 and request.authority_id == locator["authority_id"]
            and request.authority_namespace == locator["authority_namespace"]
            and request.installation_id == locator["installation_id"]
            and request.dashboard_origin == self.origin and request.audience == "owner")

    def _csrf(self, browser, identity):
        value = json.dumps(dict(browser=browser, request=to_wire(identity.request), origin=self.origin),
            sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hmac.new(self._secret, value, hashlib.sha256).hexdigest()

    def _public(self, status, browser=None, binding=None):
        locator = self.client.request
        namespace = locator["namespace"]
        return dict(schema="sylanne.maintenance-console-session.v1", status=status,
            transport_profile=self.transport_profile, origin=self.origin,
            locator=dict(authority_id=locator["authority_id"], authority_namespace=locator["authority_namespace"],
                installation_id=locator["installation_id"], console_profile_id=locator["console_profile_id"],
                scope=namespace["bot_id"] + "/" + namespace["persona_id"]),
            owner=to_wire(binding.identity.request) if status == "authenticated" else None,
            csrf_token=None if binding is None else self._csrf(browser, binding.identity))

    async def status(self, browser):
        self._open()
        binding = self._browsers.get(browser)
        try:
            await self.client.describe()
            if binding is None:
                return self._public("locked")
            actor = await self.client.current(binding.identity.request, binding.token)
            if actor != binding.identity.actor_id:
                raise MaintenanceConsoleUnavailableV1("owner_session_changed")
        except MaintenanceConsoleUnavailableV1:
            return self._public("unavailable", browser, binding)
        return self._public("authenticated", browser, binding)

    async def begin(self, *, browser, origin, request):
        self._origin(origin)
        if not self._matches(request):
            raise ValueError("owner_login_invalid_request")
        if browser in self._browsers:
            raise PermissionError("owner_logout_required")
        now = time.time()
        for key, pending in tuple(self._pending.items()):
            if _time(pending.expires_at_utc).timestamp() <= now:
                del self._pending[key]
        if browser in self._pending:
            del self._pending[browser]
        if len(self._pending) >= 128 or len(self._browsers) >= 128:
            raise PermissionError("console_session_capacity")
        await self.client.describe()
        challenge = await self.client.begin(request)
        cookie = secrets.token_urlsafe(32)
        self._pending[cookie] = challenge
        return cookie, dict(schema_version="sylanne.owner-login.v1", challenge=to_wire(challenge),
            signing_payload_base64=base64.b64encode(challenge.signed_bytes()).decode("ascii"))

    async def complete(self, *, browser, origin, challenge, signature):
        self._origin(origin)
        pending = self._pending.pop(browser, None)
        if (pending is None or pending != challenge or not self._matches(challenge.request)
                or _time(challenge.expires_at_utc).timestamp() <= time.time()
                or type(signature) is not bytes or len(signature) != 64):
            raise PermissionError("owner_login_rejected")
        if len(self._browsers) >= 128:
            raise PermissionError("console_session_capacity")
        token = await self.client.accept(challenge, signature)
        try:
            actor = await self.client.current(challenge.request, token)
        except MaintenanceConsoleUnavailableV1:
            try:
                await self.client.logout(challenge.request, token)
            except MaintenanceConsoleUnavailableV1:
                pass
            raise
        cookie = secrets.token_urlsafe(32)
        identity = MaintenanceConsoleOwnerIdentityV1(challenge.request, actor, "maintenance-console:" + secrets.token_hex(32))
        self._browsers[cookie] = _BrowserOwnerV1(identity, token)
        return cookie, {"status": "authenticated"}

    def _browser(self, browser, *, csrf=None, origin=None, mutation=False):
        self._open()
        binding = self._browsers.get(browser)
        if binding is None:
            raise PermissionError("owner_session_locked")
        if mutation or csrf is not None or origin is not None:
            self._origin(origin)
            if type(csrf) is not str or not hmac.compare_digest(csrf, self._csrf(browser, binding.identity)):
                raise PermissionError("csrf_denied")
        return binding

    async def inspect(self, *, browser, action, fields, csrf=None, origin=None):
        binding = self._browser(browser, csrf=csrf, origin=origin, mutation=action in {
            "inspection_workflow_accept", "resume_completed_inspection_v1", "reconcile_held_inspection_v1"})
        actor = await self.client.current(binding.identity.request, binding.token)
        if actor != binding.identity.actor_id:
            raise PermissionError("owner_session_changed")
        return await self.client.inspect(action=action, fields=fields, identity=binding.identity, token=binding.token)

    async def logout(self, *, browser, origin, csrf):
        self._origin(origin)
        if browser in self._pending:
            del self._pending[browser]
            return {"status": "locked"}
        binding = self._browser(browser, csrf=csrf, origin=origin)
        del self._browsers[browser]
        await self.client.logout(binding.identity.request, binding.token)
        return {"status": "locked"}

    def close(self):
        self._closed = True
        self._pending.clear()
        self._browsers.clear()
