"""Administrator-configured mutual-TLS transport for Sylanne Authority.

The plugin receives only a selected profile identifier.  Endpoints, trust
roots, and the client certificate are read from an installation-owned mapping;
they are never copied from an AstrBot setting or an Authority request.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import secrets
import ssl
from typing import Mapping

from ..authority_service.contract import CONTENT_OPERATIONS, ContentPermit
from ..authority_service.v2_contract import (
    FencePermitV2, SCHEMA as AUTHORITY_V2_PROTOCOL, from_wire, to_wire,
)
from ..runtime.activation import ActivationProof
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
)
from .authority_client import (
    AUTHORITY_PROTOCOL,
    AuthorityCapabilityGrant,
    AuthorityEnrollmentGrant,
    AuthorityHandshake,
    AuthorityProvisioningRequest,
)


_PROFILE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_AUTHORITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_V2_CONTENT_OPERATIONS = CONTENT_OPERATIONS - {"dispatch"}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _request_payload(request: AuthorityProvisioningRequest) -> dict[str, str]:
    """Return the content-free subset allowed onto the authority wire."""
    return {
        "protocol": request.protocol,
        "profile_id": request.profile_id,
        "plugin_name": request.plugin_name,
        "host_api_version": request.host_api_version,
        "manifest_sha256": request.publisher_package.manifest_sha256,
    }


@dataclass(frozen=True)
class AuthorityTlsProfile:
    """Installation-owned connection material; no key bytes are retained here."""

    profile_id: str
    host: str
    port: int
    server_name: str
    expected_authority_id: str
    trust_root: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536
    prepared_ssl_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _PROFILE.fullmatch(self.profile_id):
            raise ValueError("invalid authority profile")
        if (not isinstance(self.host, str) or not self.host or len(self.host) > 255
                or not isinstance(self.server_name, str) or not self.server_name):
            raise ValueError("authority endpoint is invalid")
        if not isinstance(self.expected_authority_id, str) or not _AUTHORITY_ID.fullmatch(
            self.expected_authority_id
        ):
            raise ValueError("authority identity is invalid")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("authority port is invalid")
        if (not isinstance(self.timeout_seconds, (int, float))
                or not 0 < self.timeout_seconds <= 30):
            raise ValueError("authority timeout is invalid")
        if type(self.max_message_bytes) is not int or not 512 <= self.max_message_bytes <= 1_048_576:
            raise ValueError("authority message limit is invalid")
        for name in ("trust_root", "client_certificate", "client_private_key"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise ValueError(f"{name} must be an absolute administrator path")
            object.__setattr__(self, name, value)

    def ssl_context(self) -> ssl.SSLContext:
        """Use the verified context; direct profiles retain a test-only path seam.

        build_admin_authority_transport prepares the context from pinned file
        descriptors before creating this profile. Its production path cannot
        reach the pathname fallback below.
        """
        if self.prepared_ssl_context is not None:
            return self.prepared_ssl_context
        for path in (self.trust_root, self.client_certificate, self.client_private_key):
            if not path.is_file() or path.is_symlink():
                raise FileNotFoundError("administrator TLS material is unavailable or unsafe")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.trust_root))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(self.client_certificate), str(self.client_private_key))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


@dataclass
class _Session:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    binding: str
    request_digest: str


class MtlsAuthorityTransport:
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
    ) -> dict[str, object]:
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
        try:
            session.writer.write(encoded + b"\n")
            await asyncio.wait_for(session.writer.drain(), profile.timeout_seconds)
            line = await asyncio.wait_for(
                session.reader.readuntil(b"\n"), profile.timeout_seconds
            )
        except BaseException as exc:
            await self._discard(session, profile.timeout_seconds)
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("authority transport unavailable") from exc
        if not line or len(line) > profile.max_message_bytes:
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
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise RuntimeError("authority service unavailable")
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
                raise RuntimeError("authority handshake channel is unavailable")
            response = await self._rpc(
                session, profile, method, wire_request,
                handshake_binding=session.binding, command=command,
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
                raise RuntimeError("authority transport unavailable") from exc
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
                raise RuntimeError("authority handshake channel is unavailable")
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

    async def v2_namespace_bootstrap(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: NamespaceId,
    ) -> NamespaceBootstrapV2:
        """Observe one mapped namespace; the result grants no content access."""
        if not handshake.valid_pairing() or type(namespace) is not NamespaceId:
            raise RuntimeError("authority v2 namespace request is invalid")
        response = await self._content_rpc(
            request, handshake, "namespace_bootstrap",
            {"namespace": asdict(namespace)}, protocol=AUTHORITY_V2_PROTOCOL,
        )
        return self._v2_namespace_response(request, handshake, namespace, response)

    async def v2_namespace_genesis(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: NamespaceId, request_id: str,
    ) -> NamespaceBootstrapV2:
        """Explicit administrator-authorized genesis for one mapped namespace."""
        if (not handshake.valid_pairing() or type(namespace) is not NamespaceId
                or not isinstance(request_id, str) or not request_id):
            raise RuntimeError("authority v2 namespace genesis request is invalid")
        response = await self._content_rpc(
            request, handshake, "namespace_genesis",
            {"namespace": asdict(namespace), "request_id": request_id},
            protocol=AUTHORITY_V2_PROTOCOL,
        )
        return self._v2_namespace_response(request, handshake, namespace, response)

    def _v2_namespace_response(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: NamespaceId, response: dict[str, object],
    ) -> NamespaceBootstrapV2:
        if set(response) != set(NamespaceBootstrapV2.__dataclass_fields__) | {
            "channel_binding_sha256"
        } or response["channel_binding_sha256"] != handshake.channel_binding_sha256:
            raise RuntimeError("authority v2 namespace response is invalid")
        namespace_wire = response["namespace"]
        anchor_wire = response["anchor"]
        if (type(namespace_wire) is not dict
                or set(namespace_wire) != set(NamespaceId.__dataclass_fields__)
                or (anchor_wire is not None and type(anchor_wire) is not dict)
                or type(response["state"]) is not str
                or type(response["blocking_reasons"]) is not list):
            raise RuntimeError("authority v2 namespace response is invalid")
        try:
            observed = NamespaceBootstrapV2(
                authority_id=response["authority_id"],
                namespace=NamespaceId(**namespace_wire),
                authority_namespace=response["authority_namespace"],
                holder=response["holder"], generation=response["generation"],
                phase=response["phase"],
                state=NamespaceRuntimeState(response["state"]),
                anchor=(None if anchor_wire is None else self._restore_anchor_response(
                    {**anchor_wire, "channel_binding_sha256":
                     response["channel_binding_sha256"]}, "v2 namespace anchor")),
                blocking_reasons=tuple(response["blocking_reasons"]),
                schema=response["schema"],
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise RuntimeError("authority v2 namespace response is invalid") from exc
        profile = self.profile_for(request.profile_id)
        if (observed.namespace != namespace
                or observed.authority_id != handshake.installation_authority_id
                or observed.authority_id != profile.expected_authority_id):
            raise RuntimeError("authority v2 namespace binding is invalid")
        return observed

    async def current(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: str,
    ) -> ActivationProof:
        response = await self._content_rpc(
            request, handshake, "current", {"namespace": namespace}
        )
        return self._activation_proof_response(response, "current")

    def _activation_proof_response(
        self, response: dict[str, object], name: str,
    ) -> ActivationProof:
        if set(response) != {
            "authority_id", "namespace", "holder", "generation", "phase",
            "operation_id", "channel_binding_sha256",
        }:
            raise RuntimeError(f"authority {name} response is invalid")
        return ActivationProof(
            self._require_string(response["authority_id"], "authority_id"),
            self._require_string(response["namespace"], "namespace"),
            self._require_string(response["holder"], "holder", nullable=True),
            self._require_nonnegative_int(response["generation"], "generation"),
            self._require_string(response["phase"], "phase"),
            self._require_string(response["operation_id"], "operation_id", nullable=True),
        )

    async def check(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, holder: str, generation: int, operation: str,
    ) -> ActivationProof:
        response = await self._content_rpc(
            request, handshake, "check",
            {"namespace": namespace, "holder": holder, "generation": generation,
             "operation": operation},
        )
        return self._activation_proof_response(response, "check")

    async def current_anchor(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: str,
    ) -> RestoreAnchor:
        response = await self._content_rpc(
            request, handshake, "current_anchor", {"namespace": namespace}
        )
        return self._restore_anchor_response(response, "anchor")

    def _restore_anchor_response(
        self, response: dict[str, object], name: str,
    ) -> RestoreAnchor:
        if set(response) != {
            "authority_id", "namespace", "activation_generation",
            "deletion_journal_id", "deletion_seq", "deletion_digest",
            "execution_journal_id", "execution_seq", "execution_digest",
            "revocation_epoch", "proof", "channel_binding_sha256",
        }:
            raise RuntimeError(f"authority {name} response is invalid")
        return RestoreAnchor(
            self._require_string(response["authority_id"], "authority_id"),
            self._require_string(response["namespace"], "namespace"),
            self._require_nonnegative_int(response["activation_generation"], "activation_generation"),
            self._require_string(response["deletion_journal_id"], "deletion_journal_id"),
            self._require_nonnegative_int(response["deletion_seq"], "deletion_seq"),
            self._require_string(response["deletion_digest"], "deletion_digest"),
            self._require_string(response["execution_journal_id"], "execution_journal_id"),
            self._require_nonnegative_int(response["execution_seq"], "execution_seq"),
            self._require_string(response["execution_digest"], "execution_digest"),
            self._require_nonnegative_int(response["revocation_epoch"], "revocation_epoch"),
            self._require_string(response["proof"], "proof"),
        )

    async def verify_execution_chain(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: str,
    ) -> RestoreAnchor:
        response = await self._content_rpc(
            request, handshake, "verify_execution_chain", {"namespace": namespace}
        )
        if response.get("verified") is not True:
            raise RuntimeError("authority execution chain is unavailable")
        response = {key: value for key, value in response.items() if key != "verified"}
        return self._restore_anchor_response(response, "execution chain")

    async def begin_content_operation(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, holder: str, generation: int, operation: str,
    ) -> ContentPermit:
        response = await self._content_rpc(
            request, handshake, "begin_content_operation",
            {"namespace": namespace, "holder": holder, "generation": generation,
             "operation": operation},
        )
        if set(response) != {
            "token", "namespace", "holder", "generation", "operation",
            "channel_binding_sha256",
        }:
            raise RuntimeError("authority permit response is invalid")
        return ContentPermit(
            self._require_string(response["token"], "token"),
            self._require_string(response["namespace"], "namespace"),
            self._require_string(response["holder"], "holder"),
            self._require_nonnegative_int(response["generation"], "generation"),
            self._require_string(response["operation"], "operation"),
        )

    async def end_content_operation(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        permit: ContentPermit,
    ) -> None:
        if not isinstance(permit, ContentPermit):
            raise TypeError("ContentPermit is required")
        response = await self._content_rpc(
            request, handshake, "end_content_operation",
            {"permit": {
                "token": permit.token, "namespace": permit.namespace,
                "holder": permit.holder, "generation": permit.generation,
                "operation": permit.operation,
            }},
        )
        if set(response) != {"ended", "channel_binding_sha256"} or response["ended"] is not True:
            raise RuntimeError("authority release response is invalid")

    async def verify_current(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        anchor: RestoreAnchor,
    ) -> bool:
        if not isinstance(anchor, RestoreAnchor):
            raise TypeError("RestoreAnchor is required")
        response = await self._content_rpc(
            request, handshake, "verify_current",
            {"anchor": {
                "authority_id": anchor.authority_id, "namespace": anchor.namespace,
                "activation_generation": anchor.activation_generation,
                "deletion_journal_id": anchor.deletion_journal_id,
                "deletion_seq": anchor.deletion_seq,
                "deletion_digest": anchor.deletion_digest,
                "execution_journal_id": anchor.execution_journal_id,
                "execution_seq": anchor.execution_seq,
                "execution_digest": anchor.execution_digest,
                "revocation_epoch": anchor.revocation_epoch, "proof": anchor.proof,
            }},
        )
        if set(response) != {"verified", "channel_binding_sha256"} or type(response["verified"]) is not bool:
            raise RuntimeError("authority verification response is invalid")
        return response["verified"]

    async def v2_current_anchor(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        namespace: str,
    ) -> RestoreAnchor:
        response = await self._content_rpc(
            request, handshake, "current_anchor", {"namespace": namespace},
            protocol=AUTHORITY_V2_PROTOCOL)
        return self._restore_anchor_response(response, "v2 anchor")

    @staticmethod
    def _v2_permit_response(response: dict[str, object]) -> FencePermitV2:
        if set(response) != {"permit", "channel_binding_sha256"}:
            raise RuntimeError("authority v2 permit response is invalid")
        try:
            permit = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 permit response is invalid") from exc
        if type(permit) is not FencePermitV2 or permit.operation not in _V2_CONTENT_OPERATIONS:
            raise RuntimeError("authority v2 content permit is invalid")
        return permit

    async def v2_begin_content_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, holder: str, operation: str, operation_id: str,
        expected_anchor: RestoreAnchor,
    ) -> FencePermitV2:
        if type(expected_anchor) is not RestoreAnchor:
            raise TypeError("RestoreAnchor is required")
        if type(operation) is not str or operation not in _V2_CONTENT_OPERATIONS:
            raise ValueError("unsupported authority v2 content operation")
        response = await self._content_rpc(
            request, handshake, "begin_fence",
            {"namespace": namespace, "holder": holder, "operation": operation,
             "operation_id": operation_id, "expected_anchor": asdict(expected_anchor)},
            protocol=AUTHORITY_V2_PROTOCOL)
        permit = self._v2_permit_response(response)
        if (permit.namespace != namespace or permit.holder != holder
                or permit.operation != operation
                or permit.operation_id != operation_id
                or permit.pinned_anchor != expected_anchor
                or permit.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority v2 permit binding is invalid")
        return permit

    async def v2_begin_read_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, holder: str, operation_id: str,
        expected_anchor: RestoreAnchor,
    ) -> FencePermitV2:
        return await self.v2_begin_content_fence(
            request, handshake, namespace=namespace, holder=holder,
            operation="read", operation_id=operation_id,
            expected_anchor=expected_anchor,
        )

    async def v2_validate_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        permit: FencePermitV2,
    ) -> FencePermitV2:
        if type(permit) is not FencePermitV2 or permit.operation not in _V2_CONTENT_OPERATIONS:
            raise TypeError("content FencePermitV2 is required")
        if permit.authority_id != handshake.installation_authority_id:
            raise RuntimeError("authority v2 permit binding is invalid")
        response = await self._content_rpc(
            request, handshake, "validate_fence", {"permit": to_wire(permit)},
            protocol=AUTHORITY_V2_PROTOCOL)
        validated = self._v2_permit_response(response)
        if validated != permit:
            raise RuntimeError("authority v2 permit changed on validation")
        return validated

    async def v2_finish_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        permit: FencePermitV2, *, request_id: str, request_digest: str,
    ) -> None:
        if type(permit) is not FencePermitV2 or permit.operation not in _V2_CONTENT_OPERATIONS:
            raise TypeError("content FencePermitV2 is required")
        if permit.authority_id != handshake.installation_authority_id:
            raise RuntimeError("authority v2 permit binding is invalid")
        response = await self._content_rpc(
            request, handshake, "finish_fence",
            {"permit": to_wire(permit), "request_id": request_id,
             "request_digest": request_digest}, protocol=AUTHORITY_V2_PROTOCOL)
        if response != {"finished": True,
                        "channel_binding_sha256": handshake.channel_binding_sha256}:
            raise RuntimeError("authority v2 finish response is invalid")


__all__ = ("AuthorityTlsProfile", "MtlsAuthorityTransport")
