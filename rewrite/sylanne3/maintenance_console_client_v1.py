"""Locator-only mTLS client for the independent Owner maintenance console."""
from __future__ import annotations

import asyncio
import hashlib
import json
from uuid import uuid4

from .authority_service.maintenance_console_rpc_v1 import MaintenanceConsoleBindingV1
from .authority_service.v2_owner_session import (OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1, from_wire, to_wire)
from .host.authority_transport_contract import AuthorityTlsProfile

PROTOCOL = "sylanne3.maintenance-console.v1"
_ACTION_FIELDS = {
    "describe": frozenset(),
    "begin_owner_session_v1": frozenset({"request"}),
    "accept_owner_session_v1": frozenset({"challenge", "signature"}),
    "describe_owner_session_v1": frozenset({"token"}),
    "current_owner_session_v1": frozenset({"request", "token"}),
    "logout_owner_session_v1": frozenset({"request", "token"}),
    "inspection_workflow_accept": frozenset({"operation_id", "input_data"}),
    "inspection_workflow_status": frozenset({"operation_id"}),
    "resume_completed_inspection_v1": frozenset({"operation_id", "input_data"}),
    "inspection_recovery_status": frozenset({"operation_id"}),
    "reconcile_held_inspection_v1": frozenset({"operation_id", "input_data"}),
    "inspection_reconciliation_status": frozenset({"operation_id"}),
    "read_inspection_recovery_options_v1": frozenset({"parent_workflow_operation_id"}),
}
_OWNER_FIELDS = frozenset({"owner_actor_id", "owner_session_token", "owner_session_request"})
_BUSINESS = frozenset(action for action in _ACTION_FIELDS if action not in {
    "describe", "begin_owner_session_v1", "accept_owner_session_v1",
    "describe_owner_session_v1", "current_owner_session_v1", "logout_owner_session_v1"})


class MaintenanceConsoleUnavailableV1(RuntimeError):
    def __init__(self, code="authority_unavailable", *, uncertain=False):
        super().__init__(code)
        self.code, self.uncertain = code, uncertain


class MaintenanceConsoleClientV1:
    def __init__(self, *, profile, binding):
        if (type(profile) is not AuthorityTlsProfile or type(binding) is not MaintenanceConsoleBindingV1
                or profile.prepared_ssl_context is None):
            raise TypeError("protected console binding and prepared independent TLS profile required")
        request = binding.request_v1()
        if (request["protocol"] != PROTOCOL or request["console_profile_id"] != profile.profile_id
                or request["authority_id"] != profile.expected_authority_id):
            raise ValueError("maintenance console TLS/locator binding differs")
        self.profile, self.binding, self.request = profile, binding, request

    async def _rpc(self, action, fields):
        allowed = _ACTION_FIELDS.get(action)
        required = allowed | _OWNER_FIELDS if action in _BUSINESS else allowed
        if allowed is None or type(fields) is not dict or set(fields) != required:
            raise ValueError("maintenance console fixed command fields differ")
        profile = self.profile
        request_id = str(uuid4())
        message = dict(protocol=PROTOCOL, request_id=request_id, method="maintenance_console_v1",
            request=self.request, command=dict(action=action, **fields))
        encoded = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode() + b"\n"
        if len(encoded) > profile.max_message_bytes:
            raise ValueError("maintenance console command exceeds installed transport bound")
        writer = None
        dispatched = False
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                profile.host, profile.port, ssl=profile.prepared_ssl_context,
                server_hostname=profile.server_name, limit=profile.max_message_bytes), profile.timeout_seconds)
            ssl_object = writer.get_extra_info("ssl_object")
            channel = None if ssl_object is None else ssl_object.get_channel_binding("tls-unique")
            if not channel:
                raise MaintenanceConsoleUnavailableV1("channel_binding_unavailable")
            binding_digest = hashlib.sha256(channel).hexdigest()
            dispatched = True
            writer.write(encoded)
            await asyncio.wait_for(writer.drain(), profile.timeout_seconds)
            line = await asyncio.wait_for(reader.readuntil(b"\n"), profile.timeout_seconds)
            if len(line) > profile.max_message_bytes:
                raise MaintenanceConsoleUnavailableV1("response_invalid", uncertain=True)
            response = json.loads(line)
            if type(response) is not dict or response.get("request_id") != request_id:
                raise MaintenanceConsoleUnavailableV1("response_invalid", uncertain=True)
            if response.get("ok") is not True:
                if set(response) != {"request_id", "ok", "error"} or type(response["error"]) is not str:
                    raise MaintenanceConsoleUnavailableV1("response_invalid", uncertain=True)
                raise MaintenanceConsoleUnavailableV1(response["error"])
            if set(response) != {"request_id", "ok", "result"} or type(response["result"]) is not dict:
                raise MaintenanceConsoleUnavailableV1("response_invalid", uncertain=True)
            result = response["result"]
            if result.get("channel_binding_sha256") != binding_digest:
                raise MaintenanceConsoleUnavailableV1("channel_binding_invalid", uncertain=True)
            return {key: value for key, value in result.items() if key != "channel_binding_sha256"}
        except MaintenanceConsoleUnavailableV1:
            raise
        except (OSError, TimeoutError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise MaintenanceConsoleUnavailableV1(uncertain=dispatched) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), profile.timeout_seconds)
                except (OSError, TimeoutError):
                    pass

    async def describe(self):
        result = await self._rpc("describe", {})
        if result != {"binding": self.request}:
            raise MaintenanceConsoleUnavailableV1("console_binding_changed")
        return result["binding"]

    async def begin(self, request):
        if type(request) is not OwnerSessionLoginRequestV1:
            raise TypeError("actual Owner login request required")
        result = await self._rpc("begin_owner_session_v1", {"request": to_wire(request)})
        if set(result) != {"challenge"}:
            raise MaintenanceConsoleUnavailableV1("response_invalid")
        challenge = from_wire(result["challenge"])
        if type(challenge) is not OwnerSessionLoginChallengeV1 or challenge.request != request:
            raise MaintenanceConsoleUnavailableV1("response_invalid")
        return challenge

    async def accept(self, challenge, signature):
        if type(challenge) is not OwnerSessionLoginChallengeV1 or type(signature) is not bytes or len(signature) != 64:
            raise ValueError("actual Owner challenge and signature required")
        result = await self._rpc("accept_owner_session_v1", {"challenge": to_wire(challenge), "signature": signature.hex()})
        if set(result) != {"token"} or type(result["token"]) is not str:
            raise MaintenanceConsoleUnavailableV1("response_invalid", uncertain=True)
        return result["token"]

    async def current(self, request, token):
        described = await self._rpc("describe_owner_session_v1", {"token": token})
        if set(described) != {"request", "actualactor_id"} or from_wire(described["request"]) != request:
            raise MaintenanceConsoleUnavailableV1("owner_session_changed")
        current = await self._rpc("current_owner_session_v1", {"request": to_wire(request), "token": token})
        actor = described["actualactor_id"]
        if (current != {"current": True, "actualactor_id": actor} or type(actor) is not str or not actor):
            raise MaintenanceConsoleUnavailableV1("owner_session_changed")
        return actor

    async def logout(self, request, token):
        result = await self._rpc("logout_owner_session_v1", {"request": to_wire(request), "token": token})
        if result != {"revoked": True}:
            raise MaintenanceConsoleUnavailableV1("owner_logout_unconfirmed", uncertain=True)

    async def inspect(self, *, action, fields, identity, token):
        if action not in _BUSINESS:
            raise ValueError("unregistered maintenance console action")
        return await self._rpc(action, dict(fields, owner_actor_id=identity.actor_id,
            owner_session_token=token, owner_session_request=to_wire(identity.request)))
