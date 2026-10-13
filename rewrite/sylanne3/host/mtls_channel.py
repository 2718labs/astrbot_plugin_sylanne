"""The single mutual-TLS channel shared by host runtime and Owner console.

Pairing, renewal, business dispatch and two-stage C02 recovery use this same
implementation. Domain RPC adapters extend it in mtls_transport.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import hashlib
import json
import secrets
import time
from typing import Mapping

from ..authority_service.v2_model_egress_contract import ModelEgressObservationV1
from ..runtime_contracts import InstallationGrantV2, canonical_digest as runtime_canonical_digest
from .authority_transport_contract import (
    AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL, AuthorityTlsProfile,
    AuthorityCapabilityGrant, AuthorityEnrollmentGrant, AuthorityHandshake,
    AuthorityProvisioningRequest, _SHA256,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _terminal_c02_observation(raw: object) -> ModelEgressObservationV1:
    from ..authority_service.v2_model_egress_contract import model_observation_from_wire_v1
    try:
        return model_observation_from_wire_v1(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("terminal C02 observation is invalid") from exc


def _request_payload(request: AuthorityProvisioningRequest) -> dict[str, str]:
    """Return the content-free subset allowed onto the authority wire."""
    return {
        "protocol": request.protocol,
        "profile_id": request.profile_id,
        "plugin_name": request.plugin_name,
        "host_api_version": request.host_api_version,
        "manifest_sha256": request.publisher_package.manifest_sha256,
    }


class AuthorityChannelUnavailable(RuntimeError):
    """Transport lost before a trustworthy response; original outcome is unknown."""


class V2OwnerAuthorizationBarrier(RuntimeError):
    """The paired Authority confirmed a current Owner revoke barrier."""


class V2PlatformObservationVerifierUnavailable(RuntimeError):
    """The paired Authority cannot persist a V2 platform observation."""


@dataclass
class _Session:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    binding: str
    request_digest: str
    handshake_started_at: float = 0.0


class MtlsAuthorityChannel:
    """A single live mTLS channel binds handshake and capability grant."""

    def __init__(self, profiles: Mapping[str, AuthorityTlsProfile]) -> None:
        copied = dict(profiles)
        if not copied or any(key != value.profile_id for key, value in copied.items()):
            raise ValueError("administrator authority profiles are invalid")
        if any(not isinstance(value, AuthorityTlsProfile) for value in copied.values()):
            raise TypeError("authority profiles must be AuthorityTlsProfile")
        self._profiles = copied
        self._sessions: dict[str, _Session] = {}
        self._owner_loop: asyncio.AbstractEventLoop | None = None
        self._operation_lock = asyncio.Lock()

    def _require_owner_loop(self) -> None:
        loop = asyncio.get_running_loop()
        if self._owner_loop is None:
            self._owner_loop = loop
        elif self._owner_loop is not loop:
            raise RuntimeError("authority transport belongs to another event loop")

    async def _discard(self, session: _Session, timeout_seconds: float) -> None:
        for profile_id, current in tuple(self._sessions.items()):
            if current is session:
                del self._sessions[profile_id]
        session.writer.close()
        try:
            await asyncio.wait_for(session.writer.wait_closed(), timeout_seconds)
        except (OSError, RuntimeError, TimeoutError):
            pass

    async def close(self) -> None:
        """Close every session on the event loop that owns its streams."""
        self._require_owner_loop()
        async with self._operation_lock:
            sessions = tuple(self._sessions.items())
            self._sessions.clear()
            for profile_id, session in sessions:
                await self._discard(session, self._profiles[profile_id].timeout_seconds)

    def profile_for(self, profile_id: str) -> AuthorityTlsProfile:
        if not isinstance(profile_id, str) or profile_id not in self._profiles:
            raise ValueError("authority profile is not installed by an administrator")
        return self._profiles[profile_id]

    @staticmethod
    def _channel_binding(writer: asyncio.StreamWriter) -> bytes:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            raise RuntimeError("authority TLS channel is absent")
        binding = ssl_object.get_channel_binding("tls-unique")
        if not binding:
            raise RuntimeError("authority TLS channel binding is unavailable")
        return binding

    async def _rpc(
        self,
        session: _Session,
        profile: AuthorityTlsProfile,
        method: str,
        request: dict[str, str],
        handshake_binding: str | None = None,
        command: dict[str, object] | None = None,
        _on_dispatch=None,
    ) -> dict[str, object]:
        # Authority expires its paired-channel registration after 30 seconds.
        # Renew on this same TLS channel before sending a business command;
        # an uncertain business response is never retried here.
        if method != "handshake" and time.monotonic() - session.handshake_started_at >= 20.0:
            renewed = await self._rpc(session, profile, "handshake", request)
            if (renewed.get("state") != "paired"
                    or renewed.get("publisher_trusted") is not True
                    or renewed.get("installation_authority_id") != profile.expected_authority_id
                    or renewed.get("channel_binding_sha256") != session.binding):
                await self._discard(session, profile.timeout_seconds)
                raise AuthorityChannelUnavailable("authority channel renewal differs")
        handshake_started_at = time.monotonic() if method == "handshake" else None
        message: dict[str, object] = {
            "protocol": request["protocol"],
            "request_id": secrets.token_hex(16),
            "method": method,
            "request": request,
        }
        if handshake_binding is not None:
            message["handshake_binding_sha256"] = handshake_binding
        if command is not None:
            message["command"] = command
        encoded = _canonical(message)
        if len(encoded) + 1 > profile.max_message_bytes:
            raise RuntimeError("authority request exceeds configured limit")
        frame = encoded + b"\n"
        try:
            # The hook belongs only to this business RPC. Recursive handshake
            # renewal above never receives it. No await separates mark and write;
            # a write exception is uncertain and must retain the reservation.
            if _on_dispatch is not None:
                _on_dispatch()
            session.writer.write(frame)
            await asyncio.wait_for(session.writer.drain(), profile.timeout_seconds)
            if method == "owner_artifact_read_for_fence_v1" and request["protocol"] == AUTHORITY_V2_PROTOCOL:
                from .d12_owner_artifact_read_port_v1 import read_owner_artifact_response_line_v2
                line = await read_owner_artifact_response_line_v2(session.reader, timeout_seconds=profile.timeout_seconds)
            else:
                line = await asyncio.wait_for(
                    session.reader.readuntil(b"\n"), profile.timeout_seconds
                )
        except BaseException as exc:
            await self._discard(session, profile.timeout_seconds)
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise AuthorityChannelUnavailable("authority transport unavailable") from exc
        response_limit = 1_048_576 if method == "owner_artifact_read_for_fence_v1" and request["protocol"] == AUTHORITY_V2_PROTOCOL else profile.max_message_bytes
        if not line or len(line) > response_limit:
            await self._discard(session, profile.timeout_seconds)
            raise RuntimeError("authority response is invalid")
        try:
            response = json.loads(line)
        except (TypeError, ValueError) as exc:
            await self._discard(session, profile.timeout_seconds)
            raise RuntimeError("authority response is invalid") from exc
        if not isinstance(response, dict) or response.get("request_id") != message["request_id"]:
            await self._discard(session, profile.timeout_seconds)
            raise RuntimeError("authority response is invalid")
        if (method == "execution_begin_handoff_v2"
                and response == {"request_id": message["request_id"], "ok": False,
                                 "error": "owner_authorization_barrier"}):
            raise V2OwnerAuthorizationBarrier("current Owner authorization bars handoff")
        if (method == "execution_begin_handoff_v2"
                and response == {"request_id": message["request_id"], "ok": False,
                                 "error": "platform_observation_verifier_unavailable"}):
            raise V2PlatformObservationVerifierUnavailable(
                "installed platform observation verifier is unavailable")
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise RuntimeError("authority service unavailable")
        if handshake_started_at is not None:
            session.handshake_started_at = handshake_started_at
        if method == "terminal_c02_recovery_read_v1":
            try:
                from ..authority_service.v2_terminal_c02_recovery_contract import (
                    TerminalRecoveryReadRequestV1, TerminalRecoveryReadFactV1,
                    from_wire as terminal_c02_from_wire, to_wire as terminal_c02_to_wire,
                )
                if command is None or set(command) != {"namespace", "read_request"}:
                    raise RuntimeError("terminal C02 read command differs")
                read_request = terminal_c02_from_wire(
                    command["read_request"], TerminalRecoveryReadRequestV1)
                result = response["result"]
                if (set(result) != {"result", "channel_binding_sha256"}
                        or result["channel_binding_sha256"] != session.binding
                        or type(result["result"]) is not dict
                        or set(result["result"]) != {"request", "observation"}):
                    raise RuntimeError("terminal C02 response fields differ")
                delivered = terminal_c02_from_wire(
                    result["result"]["request"], TerminalRecoveryReadRequestV1)
                observation = _terminal_c02_observation(result["result"]["observation"])
                key = read_request.original_key
                if (delivered != read_request or observation.status != "completed"
                        or (observation.authority_id, observation.namespace,
                            observation.operation_id, observation.call_id,
                            observation.request_digest, observation.digest) !=
                           (key.authority_id, key.authority_namespace,
                            key.original_model_operation_id, key.call_id,
                            key.model_request_digest, key.observation_digest)):
                    raise RuntimeError("terminal C02 original result differs")
                ack = {
                    "kind": "terminal_c02_recovery_drain_ack_v1",
                    "request_id": message["request_id"],
                    "channel_binding_sha256": session.binding,
                    "response_digest": hashlib.sha256(line[:-1]).hexdigest(),
                    "original_key_digest": key.digest,
                    "read_request_digest": read_request.digest,
                }
                session.writer.write(_canonical(ack) + b"\n")
                await asyncio.wait_for(session.writer.drain(), profile.timeout_seconds)
                final_line = await asyncio.wait_for(
                    session.reader.readuntil(b"\n"), profile.timeout_seconds)
                if not final_line or len(final_line) > profile.max_message_bytes:
                    raise RuntimeError("terminal C02 fact response is invalid")
                final = json.loads(final_line)
                if (type(final) is not dict or final.get("request_id") != message["request_id"]
                        or final.get("ok") is not True or type(final.get("result")) is not dict
                        or set(final["result"]) != {"read_fact", "channel_binding_sha256"}
                        or final["result"]["channel_binding_sha256"] != session.binding):
                    raise RuntimeError("terminal C02 fact response differs")
                fact = terminal_c02_from_wire(
                    final["result"]["read_fact"], TerminalRecoveryReadFactV1)
                from ..authority_service.v2_model_egress_contract import model_observation_to_wire_v1
                if (fact.request != read_request
                        or fact.handoff_digest != runtime_canonical_digest({
                            "request": asdict(read_request),
                            "observation": model_observation_to_wire_v1(observation)})):
                    raise RuntimeError("terminal C02 handoff fact differs")
                return {"observation": model_observation_to_wire_v1(observation),
                        "read_fact": terminal_c02_to_wire(fact),
                        "channel_binding_sha256": session.binding}
            except BaseException:
                await self._discard(session, profile.timeout_seconds)
                raise
        return response["result"]

    @staticmethod
    def _require_string(value: object, field: str, *, nullable: bool = False) -> str | None:
        if nullable and value is None:
            return None
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"authority {field} is invalid")
        return value

    @staticmethod
    def _require_nonnegative_int(value: object, field: str) -> int:
        if type(value) is not int or value < 0:
            raise RuntimeError(f"authority {field} is invalid")
        return value

    async def _content_rpc(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        method: str, command: dict[str, object], *, protocol: str = AUTHORITY_PROTOCOL,
        _on_dispatch=None,
    ) -> dict[str, object]:
        self._require_owner_loop()
        profile = self.profile_for(request.profile_id)
        wire_request = _request_payload(request)
        wire_request["protocol"] = protocol
        digest = hashlib.sha256(_canonical(wire_request)).hexdigest()
        async with self._operation_lock:
            session = self._sessions.get(request.profile_id)
            if session is not None and session.writer.is_closing():
                await self._discard(session, profile.timeout_seconds)
                session = None
            if (session is None or session.binding != handshake.channel_binding_sha256
                    or session.request_digest != digest):
                raise AuthorityChannelUnavailable("authority handshake channel is unavailable")
            response = await self._rpc(
                session, profile, method, wire_request,
                handshake_binding=session.binding, command=command, _on_dispatch=_on_dispatch,
            )
            if response.get("channel_binding_sha256") != session.binding:
                await self._discard(session, profile.timeout_seconds)
                raise RuntimeError("authority response binding mismatch")
            return response

    async def handshake(self, request: AuthorityProvisioningRequest, *,
                        protocol: str = AUTHORITY_PROTOCOL) -> AuthorityHandshake:
        if protocol not in (AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL):
            raise ValueError("unknown authority protocol")
        self._require_owner_loop()
        profile = self.profile_for(request.profile_id)
        async with self._operation_lock:
            context = profile.ssl_context()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        profile.host, profile.port, ssl=context,
                        server_hostname=profile.server_name, limit=profile.max_message_bytes,
                    ),
                    profile.timeout_seconds,
                )
            except Exception as exc:
                raise AuthorityChannelUnavailable("authority transport unavailable") from exc
            wire_request = _request_payload(request)
            wire_request["protocol"] = protocol
            session = _Session(
                reader, writer, "", hashlib.sha256(_canonical(wire_request)).hexdigest()
            )
            try:
                response = await self._rpc(session, profile, "handshake", wire_request)
                expected = hashlib.sha256(
                    self._channel_binding(writer) + bytes.fromhex(session.request_digest)
                ).hexdigest()
                binding = response.get("channel_binding_sha256")
                if not isinstance(binding, str) or not _SHA256.fullmatch(binding) or binding != expected:
                    raise RuntimeError("authority channel binding mismatch")
                handshake = AuthorityHandshake(
                    state=response.get("state", ""),
                    installation_authority_id=response.get("installation_authority_id", ""),
                    installation_identity_ref=response.get("installation_identity_ref", ""),
                    channel_binding_sha256=binding,
                    publisher_trusted=response.get("publisher_trusted") is True,
                )
                if not handshake.valid_pairing():
                    raise RuntimeError("authority pairing unavailable")
                if handshake.installation_authority_id != profile.expected_authority_id:
                    raise RuntimeError("authority identity does not match administrator pin")
            except BaseException:
                await self._discard(session, profile.timeout_seconds)
                raise
            session.binding = binding
            prior = self._sessions.pop(request.profile_id, None)
            if prior is not None:
                await self._discard(prior, profile.timeout_seconds)
            self._sessions[request.profile_id] = session
            return handshake

    async def capability_grant(
        self,
        request: AuthorityProvisioningRequest,
        handshake: AuthorityHandshake,
    ) -> AuthorityEnrollmentGrant | AuthorityCapabilityGrant:
        self._require_owner_loop()
        profile = self.profile_for(request.profile_id)
        wire_request = _request_payload(request)
        digest = hashlib.sha256(_canonical(wire_request)).hexdigest()
        async with self._operation_lock:
            session = self._sessions.get(request.profile_id)
            if session is not None and session.writer.is_closing():
                await self._discard(session, profile.timeout_seconds)
                session = None
            if (session is None or session.binding != handshake.channel_binding_sha256
                    or session.request_digest != digest):
                raise AuthorityChannelUnavailable("authority handshake channel is unavailable")
            response = await self._rpc(
                session, profile, "capability_grant", wire_request, session.binding
            )
            if response.get("channel_binding_sha256") != session.binding:
                await self._discard(session, profile.timeout_seconds)
                raise RuntimeError("authority grant binding mismatch")
        capabilities = response.get("capabilities")
        if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
            raise RuntimeError("authority grant is invalid")
        if tuple(capabilities) == ("enrollment",):
            return AuthorityEnrollmentGrant(
                grant_id=response.get("grant_id", ""),
                authority_id=response.get("authority_id", ""),
                installation_identity_ref=response.get("installation_identity_ref", ""),
                capabilities=("enrollment",),
            )
        return AuthorityCapabilityGrant(
            grant_id=response.get("grant_id", ""),
            authority_id=response.get("authority_id", ""),
            installation_identity_ref=response.get("installation_identity_ref", ""),
            activation_generation=response.get("activation_generation", -1),
            revocation_epoch=response.get("revocation_epoch", -1),
            capabilities=tuple(capabilities),
        )

    async def installation_grant_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
    ) -> InstallationGrantV2:
        """Read installation facts only from the paired v2 TLS session."""
        if not handshake.valid_pairing():
            raise RuntimeError("authority v2 pairing is invalid")
        response = await self._content_rpc(
            request, handshake, "installation_grant_v2", {},
            protocol=AUTHORITY_V2_PROTOCOL,
        )
        if set(response) != set(InstallationGrantV2.__dataclass_fields__):
            raise RuntimeError("authority v2 installation grant is invalid")
        try:
            grant = InstallationGrantV2(**response)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 installation grant is invalid") from exc
        profile = self.profile_for(request.profile_id)
        if (grant.authority_id != profile.expected_authority_id
                or grant.authority_id != handshake.installation_authority_id
                or grant.subject != handshake.installation_identity_ref
                or grant.manifest_digest != request.publisher_package.manifest_sha256
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256):
            raise RuntimeError("authority v2 installation grant binding is invalid")
        return grant


__all__ = (
    "MtlsAuthorityChannel", "AuthorityChannelUnavailable",
    "V2OwnerAuthorizationBarrier", "V2PlatformObservationVerifierUnavailable",
)
