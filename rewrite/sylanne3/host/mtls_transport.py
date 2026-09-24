"""Administrator-configured mutual-TLS transport for Sylanne Authority.

The plugin receives only a selected profile identifier.  Endpoints, trust
roots, and the client certificate are read from an installation-owned mapping;
they are never copied from an AstrBot setting or an Authority request.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
from pathlib import Path
import re
import secrets
import ssl
from typing import Mapping

from ..authority_service.contract import CONTENT_OPERATIONS, ContentPermit, identifier
from ..authority_service.v2_clock import IngressClockSampleV2
from ..authority_service.v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    SCHEMA as AUTHORITY_V2_PROTOCOL,
    canonical_digest, from_wire, to_wire,
)
from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerGraphCommitProofV1,
    OwnerActorBindingV1, OwnerPrincipalV1,
    from_wire as owner_from_wire, to_wire as owner_to_wire,
)
from ..authority_service.v2_owner_proof import (
    OwnerCredentialRegistrationV1, OwnerProofAcceptanceV1,
    OwnerProofChallengeV1, OwnerProofRequestV1,
    from_wire as proof_from_wire, to_wire as proof_to_wire,
)
from ..authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
    from_wire as session_from_wire, to_wire as session_to_wire,
)
from ..authority_service.v2_execution_bridge import HandoffStartV2
from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelAdmissionV2, HostObservedModelCompletionV2, ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_egress_wire import (
    from_wire as model_from_wire, to_wire as model_to_wire,
)
from ..authority_service.v2_model_result_read_contract import (
    ModelResultReadRequestV1, ModelResultReadV1,
)
from ..authority_service.v2_model_result_read_wire import (
    from_wire as result_from_wire, to_wire as result_to_wire,
)
from ..authority_service.v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from ..authority_service.v2_accounting_wire import (
    from_wire as accounting_from_wire, to_wire as accounting_to_wire,
)
from ..model_broker.broker import ModelCallRequest
from ..runtime_journal import RecoveryConstraintFootprint
from ..runtime.activation import ActivationProof
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
    canonical_digest as runtime_canonical_digest,
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

    @staticmethod
    def _model_identity(
        request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, namespace: str, holder: str,
        candidate: ModelEgressDraftV1 | ModelEgressIntentV1,
    ) -> None:
        if (type(grant) is not InstallationGrantV2 or not handshake.valid_pairing()
                or grant.authority_id != handshake.installation_authority_id
                or grant.subject != handshake.installation_identity_ref
                or grant.manifest_digest != request.publisher_package.manifest_sha256
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256
                or grant.administrator_holder != holder
                or type(candidate) not in {ModelEgressDraftV1, ModelEgressIntentV1}
                or (candidate.authority_id, candidate.namespace, candidate.subject)
                != (grant.authority_id, namespace, grant.subject)):
            raise RuntimeError("authority model installation binding is invalid")

    @staticmethod
    def _model_response(
        response: dict[str, object], grant: InstallationGrantV2,
        candidate: ModelEgressDraftV1 | ModelEgressIntentV1,
        expected_state: str | None,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        if set(response) != {"record", "permit", "channel_binding_sha256"}:
            raise RuntimeError("authority model response is invalid")
        try:
            record = model_from_wire(response["record"], ModelEgressRecoveryV1)
            permit = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority model response is invalid") from exc
        intent = record.intent
        if (type(permit) is not FencePermitV2
                or permit.operation != "model_egress"
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject
                or permit.namespace != intent.namespace
                or permit.holder != grant.administrator_holder
                or permit.operation_id != intent.operation_id
                or (intent.fence_token, intent.fence_epoch, intent.fence_revision,
                    intent.anchor_digest) !=
                   (permit.token, permit.fence_epoch, permit.revision,
                    runtime_canonical_digest(asdict(permit.pinned_anchor)))
                or (ModelEgressDraftV1.from_intent(intent) != candidate
                    if type(candidate) is ModelEgressDraftV1 else intent != candidate)
                or (expected_state is not None and record.state != expected_state)):
            raise RuntimeError("authority model response binding is invalid")
        return record, permit

    async def model_prepare_fenced_v1(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        draft: ModelEgressDraftV1, expected_anchor: RestoreAnchor,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        self._model_identity(request, handshake, grant, namespace, holder, draft)
        if (type(expected_anchor) is not RestoreAnchor
                or (expected_anchor.authority_id, expected_anchor.namespace)
                != (grant.authority_id, namespace)):
            raise RuntimeError("authority model anchor binding is invalid")
        response = await self._content_rpc(
            request, handshake, "model_prepare_fenced_v1",
            {"namespace": namespace, "holder": holder, "draft": model_to_wire(draft),
             "expected_anchor": asdict(expected_anchor)},
            protocol=AUTHORITY_V2_PROTOCOL)
        record, permit = self._model_response(response, grant, draft, "prepared")
        if permit.pinned_anchor != expected_anchor:
            raise RuntimeError("authority model anchor binding is invalid")
        return record, permit

    async def model_admit_dispatch_once_v1(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        model_request: ModelCallRequest,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        self._model_identity(request, handshake, grant, namespace, holder, intent)
        if (type(model_request) is not ModelCallRequest
                or model_request.digest != intent.request_digest
                or model_request.call_id != intent.call_id
                or model_request.identity.operation_id != intent.operation_id
                or (model_request.provider_id, model_request.model_id,
                    model_request.max_output_tokens) !=
                   (intent.provider_id, intent.model_id, intent.max_output_tokens)
                or type(expected_anchor) is not RestoreAnchor
                or (expected_anchor.authority_id, expected_anchor.namespace)
                != (grant.authority_id, namespace)
                or runtime_canonical_digest(asdict(expected_anchor)) != intent.anchor_digest):
            raise RuntimeError("authority model request binding is invalid")
        response = await self._content_rpc(
            request, handshake, "model_admit_dispatch_once_v1",
            {"namespace": namespace, "holder": holder, "intent": model_to_wire(intent),
             "expected_anchor": asdict(expected_anchor),
             "request": model_to_wire(model_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        return self._model_response(response, grant, intent, "dispatch_started")

    async def model_recover_fenced_v1(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        intent: ModelEgressIntentV1,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        self._model_identity(request, handshake, grant, namespace, holder, intent)
        response = await self._content_rpc(
            request, handshake, "model_recover_fenced_v1",
            {"namespace": namespace, "holder": holder, "intent": model_to_wire(intent)},
            protocol=AUTHORITY_V2_PROTOCOL)
        return self._model_response(response, grant, intent, None)

    @staticmethod
    def _model_admission_binding(
        admission: ModelAdmissionV2, grant: InstallationGrantV2,
        request: AuthorityProvisioningRequest, intent: ModelEgressIntentV1,
        host_incarnation: str,
    ) -> None:
        if (type(admission) is not ModelAdmissionV2
                or not grant.subject.startswith("mtls:sha256:")
                or _SHA256.fullmatch(grant.subject.removeprefix("mtls:sha256:")) is None
                or (admission.authority_id, admission.namespace, admission.subject,
                    admission.operation_id, admission.call_id,
                    admission.request_digest, admission.provider_config_digest,
                    admission.installation_id, admission.observer_peer_sha256,
                    admission.observer_profile_id, admission.manifest_digest,
                    admission.host_incarnation) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id,
                    intent.request_digest, intent.provider_config_digest,
                    grant.installation_id, grant.subject.removeprefix("mtls:sha256:"),
                    request.profile_id, grant.manifest_digest, host_incarnation)):
            raise RuntimeError("authority model admission binding is invalid")

    async def model_admit_dispatch_once_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        model_request: ModelCallRequest, host_incarnation: str,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelAdmissionV2]:
        self._model_identity(request, handshake, grant, namespace, holder, intent)
        if (type(model_request) is not ModelCallRequest
                or model_request.digest != intent.request_digest
                or model_request.call_id != intent.call_id
                or model_request.identity.operation_id != intent.operation_id
                or (model_request.provider_id, model_request.model_id,
                    model_request.max_output_tokens) !=
                   (intent.provider_id, intent.model_id, intent.max_output_tokens)
                or type(expected_anchor) is not RestoreAnchor
                or (expected_anchor.authority_id, expected_anchor.namespace)
                != (grant.authority_id, namespace)
                or runtime_canonical_digest(asdict(expected_anchor)) != intent.anchor_digest
                or type(host_incarnation) is not str
                or not _SHA256.fullmatch(host_incarnation)):
            raise RuntimeError("authority model request binding is invalid")
        response = await self._content_rpc(
            request, handshake, "model_admit_dispatch_once_v2",
            {"namespace": namespace, "holder": holder, "intent": model_to_wire(intent),
             "expected_anchor": asdict(expected_anchor),
             "request": model_to_wire(model_request),
             "host_incarnation": host_incarnation},
            protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"record", "permit", "admission", "channel_binding_sha256"}:
            raise RuntimeError("authority model admission response is invalid")
        record, permit = self._model_response(
            {key: response[key] for key in ("record", "permit", "channel_binding_sha256")},
            grant, intent, "dispatch_started")
        if permit.pinned_anchor != expected_anchor:
            raise RuntimeError("authority model admission anchor is invalid")
        try:
            admission = model_from_wire(response["admission"], ModelAdmissionV2)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority model admission response is invalid") from exc
        self._model_admission_binding(admission, grant, request, intent, host_incarnation)
        return record, permit, admission

    async def model_complete_observed_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        admission: ModelAdmissionV2, report: HostObservedModelCompletionV2,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelTerminalReceiptV2]:
        self._model_identity(request, handshake, grant, namespace, holder, intent)
        if (type(expected_anchor) is not RestoreAnchor
                or (expected_anchor.authority_id, expected_anchor.namespace)
                != (grant.authority_id, namespace)
                or runtime_canonical_digest(asdict(expected_anchor)) != intent.anchor_digest
                or type(report) is not HostObservedModelCompletionV2):
            raise RuntimeError("authority model completion binding is invalid")
        self._model_admission_binding(
            admission, grant, request, intent, report.host_incarnation)
        if ((report.admission_id, report.call_id, report.request_digest,
             report.provider_id, report.model_id, report.provider_config_digest) !=
            (admission.admission_id, intent.call_id, intent.request_digest,
             intent.provider_id, intent.model_id, intent.provider_config_digest)):
            raise RuntimeError("authority model completion binding is invalid")
        response = await self._content_rpc(
            request, handshake, "model_complete_observed_v2",
            {"namespace": namespace, "holder": holder, "intent": model_to_wire(intent),
             "expected_anchor": asdict(expected_anchor),
             "admission": model_to_wire(admission), "report": model_to_wire(report)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"record", "permit", "receipt", "channel_binding_sha256"}:
            raise RuntimeError("authority model completion response is invalid")
        record, permit = self._model_response(
            {key: response[key] for key in ("record", "permit", "channel_binding_sha256")},
            grant, intent, "observed")
        try:
            receipt = model_from_wire(response["receipt"], ModelTerminalReceiptV2)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority model completion response is invalid") from exc
        if (permit.pinned_anchor != expected_anchor
                or (receipt.admission_id, receipt.call_id, receipt.request_digest,
                    receipt.report_digest, receipt.observation_digest,
                    receipt.installation_id, receipt.host_incarnation) !=
                   (admission.admission_id, intent.call_id, intent.request_digest,
                    report.digest, report.observation_for(intent).digest,
                    grant.installation_id, admission.host_incarnation)
                or receipt.observation_digest != record.observation_digest):
            raise RuntimeError("authority model terminal receipt binding is invalid")
        return record, permit, receipt

    async def model_terminal_fact_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        intent: ModelEgressIntentV1,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2, ModelAdmissionV2,
               ModelTerminalReceiptV2 | None]:
        """Query the original content-free terminal; never reissue admission."""
        self._model_identity(request, handshake, grant, namespace, holder, intent)
        response = await self._content_rpc(
            request, handshake, "model_terminal_fact_v2",
            {"namespace": namespace, "holder": holder,
             "intent": model_to_wire(intent)}, protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"record", "permit", "admission", "receipt",
                             "channel_binding_sha256"}:
            raise RuntimeError("authority model terminal facts are invalid")
        record, permit = self._model_response(
            {key: response[key] for key in
             ("record", "permit", "channel_binding_sha256")},
            grant, intent, None)
        try:
            admission = model_from_wire(response["admission"], ModelAdmissionV2)
            receipt = (None if response["receipt"] is None else
                       model_from_wire(response["receipt"], ModelTerminalReceiptV2))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority model terminal facts are invalid") from exc
        self._model_admission_binding(
            admission, grant, request, intent, admission.host_incarnation)
        if ((record.state == "observed") != (receipt is not None)
                or receipt is not None and (
                    receipt.admission_id != admission.admission_id
                    or receipt.call_id != intent.call_id
                    or receipt.request_digest != intent.request_digest
                    or receipt.observation_digest != record.observation_digest
                    or receipt.installation_id != grant.installation_id
                    or receipt.host_incarnation != admission.host_incarnation)):
            raise RuntimeError("authority model terminal identity differs")
        return record, permit, admission, receipt

    async def model_result_read_v1(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str,
        read_request: ModelResultReadRequestV1, owner_session_token: str,
    ) -> ModelResultReadV1:
        if (type(read_request) is not ModelResultReadRequestV1
                or (read_request.authority_id, read_request.authority_namespace,
                    read_request.installation_id)
                != (grant.authority_id, namespace, grant.installation_id)
                or type(owner_session_token) is not str
                or not owner_session_token):
            raise RuntimeError("installed Owner result read identity is invalid")
        response = await self._content_rpc(
            request, handshake, "model_result_read_v1",
            {"namespace": namespace, "read_request": result_to_wire(read_request),
             "owner_session_token": owner_session_token},
            protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"result", "channel_binding_sha256"}:
            raise RuntimeError("authority Owner result response is invalid")
        try:
            result = result_from_wire(response["result"], ModelResultReadV1)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority Owner result response is invalid") from exc
        if result.call_id != read_request.call_id:
            raise RuntimeError("authority Owner result call identity differs")
        return result

    async def model_result_read_recover_finish_v1(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str,
        read_request: ModelResultReadRequestV1,
    ) -> bool:
        if (type(read_request) is not ModelResultReadRequestV1
                or (read_request.authority_id, read_request.authority_namespace,
                    read_request.installation_id)
                != (grant.authority_id, namespace, grant.installation_id)):
            raise RuntimeError("installed Owner result read identity is invalid")
        response = await self._content_rpc(
            request, handshake, "model_result_read_recover_finish_v1",
            {"namespace": namespace, "read_request": result_to_wire(read_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"finished", "channel_binding_sha256"}
                or response["finished"] is not True):
            raise RuntimeError("authority Owner read finish is unresolved")
        return True

    async def _accounting_rpc(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        grant: InstallationGrantV2, *, namespace: str, holder: str,
        method: str, accounting_request: AccountingMaintenanceRequestV1,
        accounting_grant: AccountingMaintenanceGrantV1 | None = None,
    ):
        if type(accounting_request) is not AccountingMaintenanceRequestV1:
            raise TypeError("original accounting maintenance request required")
        self._model_identity(
            request, handshake, grant, namespace, holder,
            accounting_request.intent)
        if (accounting_request.expected_anchor.authority_id != grant.authority_id
                or accounting_request.expected_anchor.namespace != namespace):
            raise RuntimeError("accounting anchor differs from installation")
        command = {"namespace": namespace,
                   "request": accounting_to_wire(accounting_request)}
        if method in {"accounting_validate_v1", "accounting_finish_v1"}:
            if type(accounting_grant) is not AccountingMaintenanceGrantV1:
                raise TypeError("accounting grant required")
            command["grant"] = accounting_to_wire(accounting_grant)
        response = await self._content_rpc(
            request, handshake, method, command,
            protocol=AUTHORITY_V2_PROTOCOL)
        expected = ({"grant", "channel_binding_sha256"}
                    if method == "accounting_begin_v1" else
                    {"valid", "channel_binding_sha256"}
                    if method == "accounting_validate_v1" else
                    {"finished", "channel_binding_sha256"})
        if set(response) != expected:
            raise RuntimeError("authority accounting response is invalid")
        if method == "accounting_begin_v1":
            observed = accounting_from_wire(
                response["grant"], AccountingMaintenanceGrantV1)
            if (observed.call_id != accounting_request.intent.call_id
                    or observed.permit.operation_id != accounting_request.operation_id
                    or observed.permit.pinned_anchor !=
                       accounting_request.expected_anchor):
                raise RuntimeError("authority accounting grant identity differs")
            return observed
        field = "valid" if method == "accounting_validate_v1" else "finished"
        if response[field] is not True:
            raise RuntimeError("authority accounting fence is unresolved")
        return True

    async def accounting_begin_v1(self, request, handshake, grant, *,
                                  namespace, holder, accounting_request):
        return await self._accounting_rpc(
            request, handshake, grant, namespace=namespace, holder=holder,
            method="accounting_begin_v1", accounting_request=accounting_request)

    async def accounting_validate_v1(self, request, handshake, grant, *,
                                     namespace, holder, accounting_request,
                                     accounting_grant):
        return await self._accounting_rpc(
            request, handshake, grant, namespace=namespace, holder=holder,
            method="accounting_validate_v1", accounting_request=accounting_request,
            accounting_grant=accounting_grant)

    async def accounting_finish_v1(self, request, handshake, grant, *,
                                   namespace, holder, accounting_request,
                                   accounting_grant):
        return await self._accounting_rpc(
            request, handshake, grant, namespace=namespace, holder=holder,
            method="accounting_finish_v1", accounting_request=accounting_request,
            accounting_grant=accounting_grant)

    async def accounting_recover_finish_v1(self, request, handshake, grant, *,
                                           namespace, holder, accounting_request):
        return await self._accounting_rpc(
            request, handshake, grant, namespace=namespace, holder=holder,
            method="accounting_recover_finish_v1",
            accounting_request=accounting_request)

    async def ingress_clock_sample_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        installation_id: str,
    ) -> IngressClockSampleV2:
        """Read one server clock sample from the paired v2 TLS session."""
        if not handshake.valid_pairing() or not isinstance(installation_id, str) or not installation_id:
            raise RuntimeError("authority v2 clock request is invalid")
        response = await self._content_rpc(
            request, handshake, "ingress_clock_sample_v2", {},
            protocol=AUTHORITY_V2_PROTOCOL,
        )
        if (type(response) is not dict
                or set(response) != set(IngressClockSampleV2.__dataclass_fields__) | {
                    "channel_binding_sha256"
                }
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority v2 clock response is invalid")
        try:
            sample = IngressClockSampleV2(**{
                key: value for key, value in response.items()
                if key != "channel_binding_sha256"
            })
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 clock response is invalid") from exc
        profile = self.profile_for(request.profile_id)
        if (sample.authority_id != profile.expected_authority_id
                or sample.authority_id != handshake.installation_authority_id
                or sample.installation_id != installation_id):
            raise RuntimeError("authority v2 clock response is invalid")
        return sample

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

    async def v2_begin_dispatch_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, holder: str, operation_id: str,
        expected_anchor: RestoreAnchor, effect_id: str, command_digest: str,
        footprint: RecoveryConstraintFootprint,
    ) -> FencePermitV2:
        if type(footprint) is not RecoveryConstraintFootprint or type(expected_anchor) is not RestoreAnchor:
            raise TypeError("dispatch footprint and anchor are required")
        response = await self._content_rpc(
            request, handshake, "begin_dispatch_fence", {
                "namespace": namespace, "holder": holder, "operation_id": operation_id,
                "expected_anchor": asdict(expected_anchor), "effect_id": effect_id,
                "command_digest": command_digest, "footprint": json.loads(footprint._json()),
            }, protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"permit", "channel_binding_sha256"} or response[
                "channel_binding_sha256"] != handshake.channel_binding_sha256:
            raise RuntimeError("authority v2 dispatch permit response is invalid")
        try:
            permit = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 dispatch permit response is invalid") from exc
        expected_footprint_digest = "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest()
        if (type(permit) is not FencePermitV2 or permit.operation != "dispatch"
                or permit.namespace != namespace or permit.holder != holder
                or permit.operation_id != operation_id or permit.effect_id != effect_id
                or permit.command_digest != command_digest
                or permit.footprint_digest != expected_footprint_digest
                or permit.pinned_anchor != expected_anchor
                or permit.authority_id != handshake.installation_authority_id
                or permit.subject != handshake.installation_identity_ref):
            raise RuntimeError("authority v2 dispatch permit binding is invalid")
        return permit

    async def v2_execution_prepare(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, permit: FencePermitV2, mutation_id: str,
        footprint: RecoveryConstraintFootprint,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        if (type(permit) is not FencePermitV2 or permit.operation != "dispatch"
                or type(footprint) is not RecoveryConstraintFootprint):
            raise TypeError("dispatch permit and footprint are required")
        response = await self._content_rpc(
            request, handshake, "execution_prepare", {
                "permit": to_wire(permit), "mutation_id": mutation_id,
                "footprint": json.loads(footprint._json()),
            }, protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"receipt", "permit", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority v2 prepared receipt response is invalid")
        try:
            receipt = from_wire(response["receipt"])
            updated = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 prepared receipt response is invalid") from exc
        if (type(receipt) is not MutationReceiptV2 or type(updated) is not FencePermitV2
                or receipt.durable_state != "committed"
                or receipt.pending.phase != "prepared"
                or receipt.pending.permit != permit
                or receipt.pending.mutation_id != mutation_id
                or updated.pinned_anchor != receipt.after_anchor
                or updated.revision != receipt.updated_revision
                or updated.operation_id != permit.operation_id
                or updated.subject != handshake.installation_identity_ref
                or updated.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority v2 prepared receipt binding is invalid")
        return receipt, updated

    async def v2_execution_claim(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, prepared_receipt: MutationReceiptV2, binding: ExecutionBindingV1,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        return await self._v2_execution_claim(
            request, handshake, prepared_receipt=prepared_receipt,
            binding=binding, method="execution_claim")

    async def v2_execution_claim_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, prepared_receipt: MutationReceiptV2, binding: ExecutionBindingV2,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        return await self._v2_execution_claim(
            request, handshake, prepared_receipt=prepared_receipt,
            binding=binding, method="execution_claim_v2")

    async def _v2_execution_claim(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, prepared_receipt: MutationReceiptV2,
        binding: ExecutionBindingV1 | ExecutionBindingV2, method: str,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        """Persist the exact claimed phase; this response is not a send permit."""
        if (type(prepared_receipt) is not MutationReceiptV2
                or prepared_receipt.pending.phase != "prepared"
                or prepared_receipt.durable_state != "committed"
                or type(binding) is not (
                    ExecutionBindingV2 if method == "execution_claim_v2"
                    else ExecutionBindingV1)
                or binding.permit != prepared_receipt.pending.permit):
            raise TypeError("original prepared receipt and execution binding are required")
        response = await self._content_rpc(
            request, handshake, method, {
                "prepared_receipt": to_wire(prepared_receipt),
                "binding": to_wire(binding),
            }, protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"receipt", "permit", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority v2 claim response is invalid")
        try:
            receipt = from_wire(response["receipt"])
            updated = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 claim response is invalid") from exc
        if (type(receipt) is not MutationReceiptV2 or type(updated) is not FencePermitV2
                or receipt.durable_state != "committed"
                or receipt.pending.phase != "claimed"
                or receipt.pending.prepared_receipt != prepared_receipt
                or receipt.pending.binding != binding
                or updated.pinned_anchor != receipt.after_anchor
                or updated.revision != receipt.updated_revision
                or updated.operation_id != binding.operation_id
                or updated.subject != handshake.installation_identity_ref
                or updated.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority v2 claim binding is invalid")
        return receipt, updated

    async def v2_execution_begin_handoff(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, claimed_receipt: MutationReceiptV2, handoff_id: str,
    ) -> HandoffStartV2:
        return await self._v2_execution_begin_handoff(
            request, handshake, claimed_receipt=claimed_receipt,
            handoff_id=handoff_id, method="execution_begin_handoff")

    async def v2_execution_begin_handoff_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, claimed_receipt: MutationReceiptV2, handoff_id: str,
    ) -> HandoffStartV2:
        return await self._v2_execution_begin_handoff(
            request, handshake, claimed_receipt=claimed_receipt,
            handoff_id=handoff_id, method="execution_begin_handoff_v2")

    async def _v2_execution_begin_handoff(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, claimed_receipt: MutationReceiptV2, handoff_id: str, method: str,
    ) -> HandoffStartV2:
        """Durably begin one handoff; the RPC itself never sends content."""
        if (type(claimed_receipt) is not MutationReceiptV2
                or claimed_receipt.pending.phase != "claimed"
                or claimed_receipt.durable_state != "committed"
                or type(claimed_receipt.pending.binding) is not (
                    ExecutionBindingV2 if method == "execution_begin_handoff_v2"
                    else ExecutionBindingV1)):
            raise TypeError("committed execution claim is required")
        response = await self._content_rpc(
            request, handshake, method, {
                "claimed_receipt": to_wire(claimed_receipt),
                "handoff_id": handoff_id,
            }, protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict
                or set(response) != {"start", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority v2 handoff start response is invalid")
        try:
            start = HandoffStartV2.from_wire(response["start"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 handoff start response is invalid") from exc
        claimed_permit = claimed_receipt.pending.permit
        if (start.handoff_id != handoff_id
                or start.operation_id != claimed_permit.operation_id
                or start.effect_id != claimed_permit.effect_id
                or start.namespace != claimed_permit.namespace
                or start.claim_digest != canonical_digest(claimed_receipt)
                or start.binding_digest != canonical_digest(claimed_receipt.pending.binding)
                or start.permit != replace(
                    claimed_permit, revision=claimed_receipt.updated_revision,
                    pinned_anchor=claimed_receipt.after_anchor)
                or start.permit.authority_id != handshake.installation_authority_id
                or start.permit.subject != handshake.installation_identity_ref):
            raise RuntimeError("authority v2 handoff start binding is invalid")
        return start

    @staticmethod
    def _owner_result(response: dict[str, object], handshake: AuthorityHandshake,
                      field: str, expected_type: type):
        if (type(response) is not dict
                or set(response) != {field, "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority owner response is invalid")
        try:
            result = owner_from_wire(response[field])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority owner response is invalid") from exc
        if (type(result) is not expected_type
                or owner_to_wire(result) != response[field]):
            raise RuntimeError("authority owner response is invalid")
        return result

    async def v2_current_owner_actor_binding(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, actor_id: str,
    ) -> OwnerActorBindingV1 | None:
        identifier(actor_id, "actor_id")
        response = await self._content_rpc(
            request, handshake, "current_owner_actor_binding_v1",
            {"namespace": namespace, "actor_id": actor_id},
            protocol=AUTHORITY_V2_PROTOCOL)
        return self._owner_binding_result(response, handshake)

    async def v2_current_owner_principal_binding(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, principal: OwnerPrincipalV1,
    ) -> OwnerActorBindingV1 | None:
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("stable Owner principal is required")
        response = await self._content_rpc(
            request, handshake, "current_owner_principal_binding_v1",
            {"namespace": namespace, "principal": owner_to_wire(principal)},
            protocol=AUTHORITY_V2_PROTOCOL)
        binding = self._owner_binding_result(response, handshake)
        if binding is not None and binding.principal != principal:
            raise RuntimeError("Authority Owner principal binding differs")
        return binding

    @staticmethod
    def _owner_binding_result(response: dict[str, object],
                              handshake: AuthorityHandshake) -> OwnerActorBindingV1 | None:
        if (type(response) is not dict
                or set(response) != {"binding", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("Authority Owner binding response is invalid")
        raw = response["binding"]
        if raw is None:
            return None
        try:
            binding = owner_from_wire(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Authority Owner binding response is invalid") from exc
        if type(binding) is not OwnerActorBindingV1 or owner_to_wire(binding) != raw:
            raise RuntimeError("Authority Owner binding response is invalid")
        return binding

    @staticmethod
    def _owner_proof_result(response: dict[str, object], handshake: AuthorityHandshake,
                            field: str, expected_type: type):
        if (type(response) is not dict
                or set(response) != {field, "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("Authority Owner proof response is invalid")
        try:
            value = proof_from_wire(response[field])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Authority Owner proof response is invalid") from exc
        if type(value) is not expected_type or proof_to_wire(value) != response[field]:
            raise RuntimeError("Authority Owner proof response is invalid")
        return value

    async def v2_register_owner_credential(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, registration: OwnerCredentialRegistrationV1,
        rotation_signature: bytes | None = None,
    ) -> OwnerCredentialRegistrationV1:
        if type(registration) is not OwnerCredentialRegistrationV1:
            raise TypeError("Owner credential registration is required")
        if (rotation_signature is not None
                and (type(rotation_signature) is not bytes or len(rotation_signature) != 64)):
            raise ValueError("Owner rotation signature must contain 64 bytes")
        response = await self._content_rpc(
            request, handshake, "register_owner_credential_v1",
            {"namespace": namespace, "registration": proof_to_wire(registration),
             "rotation_signature": (None if rotation_signature is None
                                    else rotation_signature.hex())},
            protocol=AUTHORITY_V2_PROTOCOL)
        result = self._owner_proof_result(
            response, handshake, "registration", OwnerCredentialRegistrationV1)
        if (result != registration
                or result.authority_id != handshake.installation_authority_id
                or result.authority_namespace != namespace):
            raise RuntimeError("Authority Owner credential binding differs")
        return result

    async def v2_begin_owner_proof(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, proof_request: OwnerProofRequestV1,
        operation: OwnerAuthorizationOperationV1,
    ) -> OwnerProofChallengeV1:
        if (type(proof_request) is not OwnerProofRequestV1
                or type(operation) is not OwnerAuthorizationOperationV1):
            raise TypeError("Owner proof request and operation are required")
        proof_request.assert_matches_operation(operation)
        response = await self._content_rpc(
            request, handshake, "begin_owner_proof_v1",
            {"namespace": namespace, "request": proof_to_wire(proof_request),
             "operation": owner_to_wire(operation)}, protocol=AUTHORITY_V2_PROTOCOL)
        challenge = self._owner_proof_result(
            response, handshake, "challenge", OwnerProofChallengeV1)
        if (challenge.request != proof_request or challenge.request.authority_id
                != handshake.installation_authority_id
                or challenge.request.authority_namespace != namespace):
            raise RuntimeError("Authority Owner challenge binding differs")
        return challenge

    async def v2_accept_owner_proof(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, challenge: OwnerProofChallengeV1, signature: bytes,
    ) -> OwnerProofAcceptanceV1:
        if (type(challenge) is not OwnerProofChallengeV1
                or type(signature) is not bytes or len(signature) != 64):
            raise TypeError("Owner challenge and Ed25519 signature are required")
        response = await self._content_rpc(
            request, handshake, "accept_owner_proof_v1",
            {"namespace": namespace, "challenge": proof_to_wire(challenge),
             "signature": signature.hex()}, protocol=AUTHORITY_V2_PROTOCOL)
        acceptance = self._owner_proof_result(
            response, handshake, "acceptance", OwnerProofAcceptanceV1)
        if (acceptance.challenge != challenge
                or acceptance.signature_digest != "sha256:"
                + hashlib.sha256(signature).hexdigest()
                or challenge.request.authority_id != handshake.installation_authority_id
                or challenge.request.authority_namespace != namespace):
            raise RuntimeError("Authority Owner acceptance binding differs")
        return acceptance

    async def v2_get_owner_proof(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation: OwnerAuthorizationOperationV1,
    ) -> OwnerProofAcceptanceV1 | None:
        if type(operation) is not OwnerAuthorizationOperationV1:
            raise TypeError("Owner operation is required")
        response = await self._content_rpc(
            request, handshake, "get_owner_proof_v1",
            {"namespace": namespace, "operation": owner_to_wire(operation)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"acceptance", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("Authority Owner proof response is invalid")
        if response["acceptance"] is None:
            return None
        acceptance = self._owner_proof_result(
            response, handshake, "acceptance", OwnerProofAcceptanceV1)
        acceptance.challenge.request.assert_matches_operation(operation)
        if (operation.authority_id != handshake.installation_authority_id
                or acceptance.challenge.request.authority_namespace != namespace):
            raise RuntimeError("Authority Owner proof binding differs")
        return acceptance

    @staticmethod
    def _owner_session_response(response: dict[str, object],
                                handshake: AuthorityHandshake, field: str) -> object:
        if (type(response) is not dict
                or set(response) != {field, "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("Authority Owner session response is invalid")
        return response[field]

    async def v2_begin_owner_session(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, login_request: OwnerSessionLoginRequestV1,
    ) -> OwnerSessionLoginChallengeV1:
        if type(login_request) is not OwnerSessionLoginRequestV1:
            raise TypeError("Owner session login request is required")
        response = await self._content_rpc(
            request, handshake, "begin_owner_session_v1",
            {"namespace": namespace, "request": session_to_wire(login_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        raw = self._owner_session_response(response, handshake, "challenge")
        try:
            challenge = session_from_wire(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Authority Owner session challenge is invalid") from exc
        if (type(challenge) is not OwnerSessionLoginChallengeV1
                or session_to_wire(challenge) != raw
                or challenge.request != login_request
                or login_request.authority_id != handshake.installation_authority_id
                or login_request.authority_namespace != namespace):
            raise RuntimeError("Authority Owner session challenge binding differs")
        return challenge

    async def v2_accept_owner_session(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, challenge: OwnerSessionLoginChallengeV1, signature: bytes,
    ) -> str:
        if (type(challenge) is not OwnerSessionLoginChallengeV1
                or type(signature) is not bytes or len(signature) != 64):
            raise TypeError("Owner login challenge and Ed25519 signature are required")
        response = await self._content_rpc(
            request, handshake, "accept_owner_session_v1",
            {"namespace": namespace, "challenge": session_to_wire(challenge),
             "signature": signature.hex()}, protocol=AUTHORITY_V2_PROTOCOL)
        token = self._owner_session_response(response, handshake, "token")
        if (type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None
                or challenge.request.authority_id != handshake.installation_authority_id
                or challenge.request.authority_namespace != namespace):
            raise RuntimeError("Authority Owner session token binding differs")
        return token

    async def _v2_owner_session_action(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        method: str, *, namespace: str, login_request: OwnerSessionLoginRequestV1,
        token: str,
    ) -> bool:
        if type(login_request) is not OwnerSessionLoginRequestV1:
            raise TypeError("Owner session login request is required")
        if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise ValueError("Owner session token is invalid")
        if (login_request.authority_id != handshake.installation_authority_id
                or login_request.authority_namespace != namespace):
            raise RuntimeError("Owner session request binding differs")
        response = await self._content_rpc(
            request, handshake, method,
            {"namespace": namespace, "request": session_to_wire(login_request),
             "token": token}, protocol=AUTHORITY_V2_PROTOCOL)
        field = "current" if method == "current_owner_session_v1" else "revoked"
        if self._owner_session_response(response, handshake, field) is not True:
            raise RuntimeError("Authority Owner session response is invalid")
        return True

    async def v2_current_owner_session(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, login_request: OwnerSessionLoginRequestV1, token: str,
    ) -> bool:
        return await self._v2_owner_session_action(
            request, handshake, "current_owner_session_v1",
            namespace=namespace, login_request=login_request, token=token)

    async def v2_describe_owner_session(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, token: str,
    ) -> OwnerSessionLoginRequestV1:
        if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise ValueError("Owner session token is invalid")
        response = await self._content_rpc(
            request, handshake, "describe_owner_session_v1",
            {"namespace": namespace, "token": token}, protocol=AUTHORITY_V2_PROTOCOL)
        raw = self._owner_session_response(response, handshake, "request")
        try:
            described = session_from_wire(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Authority Owner session description is invalid") from exc
        if (type(described) is not OwnerSessionLoginRequestV1
                or session_to_wire(described) != raw
                or described.authority_id != handshake.installation_authority_id
                or described.authority_namespace != namespace):
            raise RuntimeError("Authority Owner session description binding differs")
        return described

    async def v2_logout_owner_session(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, login_request: OwnerSessionLoginRequestV1, token: str,
    ) -> None:
        await self._v2_owner_session_action(
            request, handshake, "logout_owner_session_v1",
            namespace=namespace, login_request=login_request, token=token)

    async def v2_revoke_all_owner_sessions(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, login_request: OwnerSessionLoginRequestV1, token: str,
    ) -> None:
        await self._v2_owner_session_action(
            request, handshake, "revoke_all_owner_sessions_v1",
            namespace=namespace, login_request=login_request, token=token)

    async def v2_revoke_owner_session_key(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, login_request: OwnerSessionLoginRequestV1, token: str,
    ) -> None:
        await self._v2_owner_session_action(
            request, handshake, "revoke_owner_session_key_v1",
            namespace=namespace, login_request=login_request, token=token)

    async def v2_register_owner_ticket(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, ticket: OwnerClaimTicketV1,
    ) -> OwnerClaimTicketV1:
        if type(ticket) is not OwnerClaimTicketV1:
            raise TypeError("owner claim ticket is required")
        response = await self._content_rpc(
            request, handshake, "register_owner_ticket",
            {"namespace": namespace, "ticket": owner_to_wire(ticket)},
            protocol=AUTHORITY_V2_PROTOCOL)
        result = self._owner_result(response, handshake, "ticket", OwnerClaimTicketV1)
        if (result != ticket or result.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority owner ticket response is invalid")
        return result

    @staticmethod
    def _owner_issue_session_fields(
        handshake: AuthorityHandshake, namespace: str,
        owner_session_token: str | None,
        owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> dict[str, object]:
        if owner_session_token is None and owner_session_request is None:
            return {}
        if (type(owner_session_token) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{43}", owner_session_token) is None
                or type(owner_session_request) is not OwnerSessionLoginRequestV1
                or owner_session_request.authority_id != handshake.installation_authority_id
                or owner_session_request.authority_namespace != namespace):
            raise RuntimeError("Owner issue session binding differs")
        return {"owner_session_token": owner_session_token,
                "owner_session_request": session_to_wire(owner_session_request)}

    async def v2_reserve_owner_issue(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation: OwnerAuthorizationOperationV1,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        if type(operation) is not OwnerAuthorizationOperationV1:
            raise TypeError("owner issue operation is required")
        response = await self._content_rpc(
            request, handshake, "reserve_owner_issue",
            {"namespace": namespace, "operation": owner_to_wire(operation),
             **self._owner_issue_session_fields(
                 handshake, namespace, owner_session_token, owner_session_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        result = self._owner_result(
            response, handshake, "receipt", OwnerAuthorizationReceiptV1)
        if (result.operation != operation or result.phase != "pending"
                or result.operation.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority owner issue response is invalid")
        return result

    async def v2_finalize_owner_issue(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation: OwnerAuthorizationOperationV1,
        proof: OwnerGraphCommitProofV1,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(proof) is not OwnerGraphCommitProofV1):
            raise TypeError("owner issue operation and graph proof are required")
        response = await self._content_rpc(
            request, handshake, "finalize_owner_issue",
            {"namespace": namespace, "operation": owner_to_wire(operation),
             "proof": owner_to_wire(proof),
             **self._owner_issue_session_fields(
                 handshake, namespace, owner_session_token, owner_session_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        result = self._owner_result(
            response, handshake, "receipt", OwnerAuthorizationReceiptV1)
        if (result.operation != operation or result.phase != "committed"
                or result.operation.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority owner commit response is invalid")
        return result

    async def v2_get_current_owner_guard_for_fence(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, permit: FencePermitV2,
        owner_actor_id: str | None = None,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> tuple[OwnerAuthorizationGuardV1 | None, FencePermitV2]:
        if (type(permit) is not FencePermitV2
                or permit.operation not in {"read", "write"}
                or permit.namespace != namespace
                or permit.subject != handshake.installation_identity_ref
                or permit.authority_id != handshake.installation_authority_id):
            raise RuntimeError("owner guard read requires this installation's content fence")
        owner_fields = {}
        if any(value is not None for value in (
                owner_actor_id, owner_session_token, owner_session_request)):
            if (type(owner_actor_id) is not str or not owner_actor_id
                    or owner_session_token is None or owner_session_request is None):
                raise RuntimeError("Owner guard actor and session fields must be paired")
            owner_fields = {
                "owner_actor_id": identifier(owner_actor_id, "owner_actor_id"),
                **self._owner_issue_session_fields(
                    handshake, namespace, owner_session_token,
                    owner_session_request),
            }
        response = await self._content_rpc(
            request, handshake, "get_current_owner_guard_for_fence",
            {"namespace": namespace, "permit": to_wire(permit), **owner_fields},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict
                or set(response) != {"guard", "permit", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority owner guard response is invalid")
        try:
            current = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority owner guard response is invalid") from exc
        if type(current) is not FencePermitV2 or current != permit:
            raise RuntimeError("authority owner guard permit changed")
        if response["guard"] is None:
            return None, current
        guard = self._owner_result(
            {"guard": response["guard"],
             "channel_binding_sha256": response["channel_binding_sha256"]},
            handshake, "guard", OwnerAuthorizationGuardV1)
        if guard.authority_id != handshake.installation_authority_id:
            raise RuntimeError("authority owner guard response is invalid")
        return guard, current

    async def v2_get_pending_owner_issue(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation_id: str,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1 | None:
        response = await self._content_rpc(
            request, handshake, "get_pending_owner_issue",
            {"namespace": namespace, "operation_id": operation_id,
             **self._owner_issue_session_fields(
                 handshake, namespace, owner_session_token, owner_session_request)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"receipt", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority owner issue response is invalid")
        if response["receipt"] is None:
            return None
        try:
            receipt = owner_from_wire(response["receipt"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority owner issue response is invalid") from exc
        if (type(receipt) is not OwnerAuthorizationReceiptV1
                or receipt.phase != "pending"
                or receipt.operation.operation_id != operation_id
                or receipt.operation.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority owner issue response is invalid")
        return receipt

    async def v2_get_pending_owner_issue_for_graph_write(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation_id: str, permit: FencePermitV2,
    ) -> OwnerAuthorizationReceiptV1 | None:
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.namespace != namespace
                or permit.subject != handshake.installation_identity_ref):
            raise RuntimeError("owner graph read requires this installation's write fence")
        response = await self._content_rpc(
            request, handshake, "get_pending_owner_issue_for_graph_write",
            {"namespace": namespace, "operation_id": operation_id,
             "permit": to_wire(permit)}, protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"receipt", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise RuntimeError("authority owner graph read response is invalid")
        if response["receipt"] is None:
            return None
        try:
            receipt = owner_from_wire(response["receipt"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority owner graph read response is invalid") from exc
        if (type(receipt) is not OwnerAuthorizationReceiptV1
                or receipt.phase != "pending"
                or receipt.operation.operation_id != operation_id
                or receipt.operation.authority_id != handshake.installation_authority_id):
            raise RuntimeError("authority owner graph read response is invalid")
        return receipt

    async def v2_get_content_fence_operation(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
        *, namespace: str, operation_id: str,
    ) -> tuple[FencePermitV2, str]:
        response = await self._content_rpc(
            request, handshake, "get_fence_operation",
            {"namespace": namespace, "operation_id": operation_id},
            protocol=AUTHORITY_V2_PROTOCOL)
        if (set(response) != {"permit", "state", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256
                or type(response["state"]) is not str
                or response["state"] not in ("active", "finished")):
            raise RuntimeError("authority v2 status response is invalid")
        try:
            permit = from_wire(response["permit"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("authority v2 status response is invalid") from exc
        if (type(permit) is not FencePermitV2
                or permit.operation not in _V2_CONTENT_OPERATIONS
                or permit.authority_id != handshake.installation_authority_id
                or permit.subject != handshake.installation_identity_ref
                or permit.namespace != namespace or permit.operation_id != operation_id):
            raise RuntimeError("authority v2 status response is invalid")
        return permit, response["state"]

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
