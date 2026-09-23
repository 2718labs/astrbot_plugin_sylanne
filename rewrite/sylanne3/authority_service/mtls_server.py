"""Content-free stdlib mTLS JSON-RPC adapter for a separately installed Authority."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import secrets
import ssl
import threading
import time
from typing import TYPE_CHECKING, Callable

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
    ReservationConstraint,
)
from ..runtime_contracts import InstallationGrantV2, NamespaceBootstrapV2, NamespaceId
from .core import AuthorityServiceCore
from .contract import AuthorityUnavailable, CONTENT_OPERATIONS, ContentPermit, identifier
from .v2_clock import AuthorityClockReadingV2, IngressClockSampleV2
from .v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    SCHEMA as AUTHORITY_V2_PROTOCOL, from_wire, to_wire,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_execution_bridge import AuthorityV2ExecutionBridge
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerGraphCommitProofV1,
    OwnerPrincipalV1,
    from_wire as owner_from_wire, to_wire as owner_to_wire,
)
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    OwnerProofChallengeV1, OwnerProofRequestV1,
    from_wire as proof_from_wire, to_wire as proof_to_wire,
)
from .v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginChallengeV1,
    OwnerSessionLoginRequestV1, from_wire as session_from_wire,
    to_wire as session_to_wire,
)
from ..graph_coordinator import namespace_ref

if TYPE_CHECKING:
    from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource


_MAX_SESSIONS = 256
_MAX_INFLIGHT_DISPATCHES = 32
_SESSION_TTL_SECONDS = 30.0
AUTHORITY_PROTOCOL = "sylanne3.authority.v1"
_ENROLLMENT_CAPABILITIES = ("enrollment",)
_V2_REMOTE_CONTENT_OPERATIONS = CONTENT_OPERATIONS - {"dispatch"}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


@dataclass(frozen=True)
class MtlsPeerCredential:
    """Opaque server credential derived from a verified client certificate."""

    certificate_sha256: str

    def __post_init__(self) -> None:
        if (not isinstance(self.certificate_sha256, str)
                or len(self.certificate_sha256) != 64
                or any(item not in "0123456789abcdef" for item in self.certificate_sha256)):
            raise ValueError("invalid mTLS peer credential")


@dataclass(frozen=True)
class AdministratorInstallationV2:
    """Administrator-installed identity and trusted package for one mTLS profile."""

    installation_id: str
    administrator_holder: str
    publisher_policy_ref: str
    service_capability_version: str
    manifest_digest: str
    source_id: str | None = None
    max_utc_error_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.source_id is None and self.max_utc_error_seconds is None:
            return
        if (type(self.source_id) is not str or not self.source_id.strip()
                or type(self.max_utc_error_seconds) not in {int, float}
                or not math.isfinite(self.max_utc_error_seconds)
                or self.max_utc_error_seconds <= 0):
            raise ValueError("administrator clock registration is invalid")


@dataclass(frozen=True)
class AuthorityServerTlsConfig:
    certificate: str
    private_key: str
    client_trust_root: str
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536

    def ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certificate, self.private_key)
        context.load_verify_locations(self.client_trust_root)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


@dataclass(frozen=True)
class _WireRequest:
    profile_id: str
    plugin_name: str
    host_api_version: str
    manifest_sha256: str
    protocol: str = AUTHORITY_PROTOCOL

    @classmethod
    def from_value(cls, value: object) -> "_WireRequest":
        if not isinstance(value, dict) or set(value) != {
            "protocol", "profile_id", "plugin_name", "host_api_version", "manifest_sha256"
        }:
            raise RuntimeError("authority request unavailable")
        if (value["protocol"] not in (AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL)
                or value["plugin_name"] != "astrbot_plugin_sylanne"
                or value["host_api_version"] != "4.28.1"):
            raise RuntimeError("authority request unavailable")
        profile_id = value["profile_id"]
        manifest = value["manifest_sha256"]
        if (not isinstance(profile_id, str) or not profile_id
                or not isinstance(manifest, str) or len(manifest) != 64
                or any(char not in "0123456789abcdef" for char in manifest)):
            raise RuntimeError("authority request unavailable")
        return cls(profile_id, value["plugin_name"], value["host_api_version"],
                   manifest, value["protocol"])

    def payload(self) -> dict[str, str]:
        return {
            "protocol": self.protocol,
            "profile_id": self.profile_id,
            "plugin_name": self.plugin_name,
            "host_api_version": self.host_api_version,
            "manifest_sha256": self.manifest_sha256,
        }


class AuthorityRpcServer:
    """RPC handler; deployment owns server TLS material and authorization policy."""

    def __init__(
        self,
        core: AuthorityServiceCore,
        *,
        administrator_authorizer: Callable[[object, str, str, str | None], bool],
        publisher_manifest_verifier: Callable[[str, str, str, str], bool],
        v2_fences: AuthorityV2FenceService | Mapping[str, AuthorityV2FenceService] | None = None,
        v2_owner_tickets: AuthorityV2OwnerTicketStore | None = None,
        v2_owner_proofs: AuthorityV2OwnerProofStore | None = None,
        v2_owner_sessions: AuthorityV2OwnerSessionStore | None = None,
        v2_owner_pairings: AuthorityOwnerPairingSource | None = None,
        v2_final_handoff_authorizers: Mapping[str, Callable] | None = None,
        installations_v2: Mapping[tuple[str, str], AdministratorInstallationV2] | None = None,
        namespace_bindings_v2: Mapping[tuple[str, str, NamespaceId], str] | None = None,
        clock_provider: Callable[[], AuthorityClockReadingV2] | None = None,
        max_inflight_dispatches: int = _MAX_INFLIGHT_DISPATCHES,
    ) -> None:
        if not isinstance(core, AuthorityServiceCore):
            raise TypeError("AuthorityServiceCore is required")
        if not callable(administrator_authorizer) or not callable(publisher_manifest_verifier):
            raise TypeError("server-side authorizer and publisher verifier are required")
        if type(max_inflight_dispatches) is not int or max_inflight_dispatches < 1:
            raise ValueError("authority dispatch capacity is invalid")
        if v2_fences is None:
            services = {}
        elif type(v2_fences) is AuthorityV2FenceService:
            services = {v2_fences.namespace: v2_fences}
        elif isinstance(v2_fences, Mapping):
            services = dict(v2_fences)
        else:
            raise TypeError("AuthorityV2FenceService mapping is required")
        if any(type(namespace) is not str
               or type(service) is not AuthorityV2FenceService
               or service.namespace != namespace or service.core is not core
               for namespace, service in services.items()):
            raise TypeError("v2 fence services must match their namespace and Authority core")
        self._core = core
        self._administrator_authorizer = administrator_authorizer
        self._publisher_manifest_verifier = publisher_manifest_verifier
        self._v2_fences = services
        if (v2_owner_tickets is not None
                and (type(v2_owner_tickets) is not AuthorityV2OwnerTicketStore
                     or v2_owner_tickets._core is not core)):
            raise TypeError("v2 owner tickets must use the same Authority core")
        self._v2_owner_tickets = v2_owner_tickets
        if (v2_owner_proofs is not None
                and (type(v2_owner_proofs) is not AuthorityV2OwnerProofStore
                     or v2_owner_proofs._core is not core)):
            raise TypeError("v2 Owner proofs must use the same Authority core")
        self._v2_owner_proofs = v2_owner_proofs
        if (v2_owner_sessions is not None
                and (type(v2_owner_sessions) is not AuthorityV2OwnerSessionStore
                     or v2_owner_sessions._core is not core)):
            raise TypeError("v2 Owner sessions must use the same Authority core")
        self._v2_owner_sessions = v2_owner_sessions
        from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
        if (v2_owner_pairings is not None
                and (type(v2_owner_pairings) is not AuthorityOwnerPairingSource
                     or v2_owner_pairings._core is not core)):
            raise TypeError("v2 Owner pairings must use the same Authority core")
        self._v2_owner_pairings = v2_owner_pairings
        handoff_authorizers = dict(v2_final_handoff_authorizers or {})
        if any(namespace not in services or not callable(callback)
               for namespace, callback in handoff_authorizers.items()):
            raise TypeError("v2 final handoff authorizers must be installed per namespace")
        self._v2_execution = {
            namespace: AuthorityV2ExecutionBridge(
                core=core, fences=service.fences, journal=service.execution,
                namespace=namespace, deletion=service.deletion,
                final_handoff_authorizer=handoff_authorizers.get(namespace),
            ) for namespace, service in services.items()
        }
        installed = dict(installations_v2 or {})
        if any(type(key) is not tuple or len(key) != 2
               or type(key[0]) is not str or len(key[0]) != 64
               or any(ch not in "0123456789abcdef" for ch in key[0])
               or type(key[1]) is not str or not key[1]
               or type(value) is not AdministratorInstallationV2
               for key, value in installed.items()):
            raise TypeError("administrator v2 installations are invalid")
        self._installations_v2 = installed
        if clock_provider is not None and not callable(clock_provider):
            raise TypeError("administrator clock provider must be callable")
        self._clock_provider = clock_provider
        bindings = dict(namespace_bindings_v2 or {})
        if any(type(key) is not tuple or len(key) != 3
               or (key[0], key[1]) not in installed
               or type(key[2]) is not NamespaceId
               or type(namespace) is not str or namespace not in services
               for key, namespace in bindings.items()):
            raise TypeError("administrator v2 namespace bindings are invalid")
        namespace_to_role = {}
        role_to_namespace = {}
        for (_, _, role), namespace in bindings.items():
            if (namespace_to_role.get(namespace, role) != role
                    or role_to_namespace.get(role, namespace) != namespace):
                raise ValueError("administrator v2 namespace bindings must be one-to-one")
            namespace_to_role[namespace] = role
            role_to_namespace[role] = namespace
        self._namespace_bindings_v2 = bindings
        self._sessions: dict[str, tuple[float, str, str]] = {}
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="authority-rpc")
        self._worker_slots = threading.BoundedSemaphore(max_inflight_dispatches)
        self._worker_lock = threading.Lock()
        self._worker_close_lock = asyncio.Lock()
        self._worker_closed = False
        self._worker_shutdown_task: asyncio.Task[None] | None = None

    @staticmethod
    def error_payload(exc: BaseException) -> dict[str, object]:
        """Wire failures deliberately reveal no content, paths, or authorization detail."""
        return {"ok": False, "error": "authority_unavailable"}

    @staticmethod
    def _binding(channel_binding: bytes, request: _WireRequest) -> str:
        if not isinstance(channel_binding, bytes) or not channel_binding:
            raise RuntimeError("authority channel binding unavailable")
        digest = hashlib.sha256(_canonical(request.payload())).digest()
        return hashlib.sha256(channel_binding + digest).hexdigest()

    def _authorize(self, credential: object, request: _WireRequest) -> None:
        try:
            allowed = self._administrator_authorizer(
                credential, "pair", "authority:enrollment", request.profile_id
            )
            trusted = self._publisher_manifest_verifier(
                request.profile_id, request.plugin_name, request.host_api_version,
                request.manifest_sha256,
            )
        except Exception as exc:
            raise RuntimeError("authority unavailable") from exc
        if allowed is not True or trusted is not True:
            raise RuntimeError("authority unavailable")

    def _authority_id(self) -> str:
        with self._core._lock:
            if self._core._db is None:
                raise RuntimeError("authority unavailable")
            return self._core._id(self._core._db)

    def _prune_sessions(self) -> None:
        cutoff = time.monotonic() - _SESSION_TTL_SECONDS
        for binding, (created, _, _) in tuple(self._sessions.items()):
            if created < cutoff:
                self._sessions.pop(binding, None)
        while len(self._sessions) > _MAX_SESSIONS:
            self._sessions.pop(next(iter(self._sessions)))

    def _paired_session(self, binding: str, peer: str, request: _WireRequest) -> None:
        self._prune_sessions()
        session = self._sessions.get(binding)
        expected_digest = hashlib.sha256(_canonical(request.payload())).hexdigest()
        if session is None or session[1] != peer or session[2] != expected_digest:
            raise RuntimeError("authority binding unavailable")

    @staticmethod
    def _proof_payload(proof) -> dict[str, object]:
        return {
            "authority_id": proof.authority_id,
            "namespace": proof.namespace,
            "holder": proof.holder,
            "generation": proof.generation,
            "phase": proof.phase,
            "operation_id": proof.operation_id,
        }

    @staticmethod
    def _anchor_payload(anchor) -> dict[str, object]:
        return {
            "authority_id": anchor.authority_id,
            "namespace": anchor.namespace,
            "activation_generation": anchor.activation_generation,
            "deletion_journal_id": anchor.deletion_journal_id,
            "deletion_seq": anchor.deletion_seq,
            "deletion_digest": anchor.deletion_digest,
            "execution_journal_id": anchor.execution_journal_id,
            "execution_seq": anchor.execution_seq,
            "execution_digest": anchor.execution_digest,
            "revocation_epoch": anchor.revocation_epoch,
            "proof": anchor.proof,
        }

    @staticmethod
    def _permit_payload(permit: ContentPermit) -> dict[str, object]:
        return {
            "token": permit.token,
            "namespace": permit.namespace,
            "holder": permit.holder,
            "generation": permit.generation,
            "operation": permit.operation,
        }

    @staticmethod
    def _namespace_command(command: object) -> str:
        if not isinstance(command, dict) or set(command) != {"namespace"}:
            raise RuntimeError("authority unavailable")
        return identifier(command["namespace"], "namespace")

    @staticmethod
    def _content_check_command(command: object) -> tuple[str, str, int, str]:
        if not isinstance(command, dict) or set(command) != {
            "namespace", "holder", "generation", "operation"
        }:
            raise RuntimeError("authority unavailable")
        namespace = identifier(command["namespace"], "namespace")
        holder = identifier(command["holder"], "holder")
        generation = command["generation"]
        operation = command["operation"]
        if type(generation) is not int or generation < 0 or not isinstance(operation, str):
            raise RuntimeError("authority unavailable")
        return namespace, holder, generation, operation

    @staticmethod
    def _anchor_from_command(command: object) -> RestoreAnchor:
        if not isinstance(command, dict) or set(command) != {"anchor"}:
            raise RuntimeError("authority unavailable")
        payload = command["anchor"]
        if not isinstance(payload, dict) or set(payload) != {
            "authority_id", "namespace", "activation_generation",
            "deletion_journal_id", "deletion_seq", "deletion_digest",
            "execution_journal_id", "execution_seq", "execution_digest",
            "revocation_epoch", "proof",
        }:
            raise RuntimeError("authority unavailable")
        return RestoreAnchor(
            payload["authority_id"], payload["namespace"],
            payload["activation_generation"], payload["deletion_journal_id"],
            payload["deletion_seq"], payload["deletion_digest"],
            payload["execution_journal_id"], payload["execution_seq"],
            payload["execution_digest"], payload["revocation_epoch"], payload["proof"],
        )

    def _content_command(self, method: str, credential: MtlsPeerCredential,
                         command: object) -> dict[str, object]:
        try:
            if method == "check":
                namespace, holder, generation, operation = self._content_check_command(command)
                return self._proof_payload(self._core.check(
                    credential, namespace=namespace, holder=holder,
                    generation=generation, operation=operation,
                ))
            if method == "current":
                return self._proof_payload(self._core.current(
                    credential, self._namespace_command(command)))
            if method == "current_anchor":
                return self._anchor_payload(self._core.current_anchor(
                    credential, self._namespace_command(command)))
            if method == "verify_execution_chain":
                # No caller-supplied head is accepted. Core re-runs its injected,
                # service-owned execution verifier against the currently stored head.
                return {"verified": True, **self._anchor_payload(self._core.current_anchor(
                    credential, self._namespace_command(command)))}
            if method == "begin_content_operation":
                namespace, holder, generation, operation = self._content_check_command(command)
                permit = self._core.begin_content_operation(
                    credential, namespace=namespace, holder=holder,
                    generation=generation, operation=operation,
                )
                return self._permit_payload(permit)
            if method == "end_content_operation":
                if not isinstance(command, dict) or set(command) != {"permit"}:
                    raise RuntimeError("authority unavailable")
                payload = command["permit"]
                if not isinstance(payload, dict) or set(payload) != {
                    "token", "namespace", "holder", "generation", "operation"
                }:
                    raise RuntimeError("authority unavailable")
                token = identifier(payload["token"], "token")
                namespace = identifier(payload["namespace"], "namespace")
                holder = identifier(payload["holder"], "holder")
                generation = payload["generation"]
                operation = payload["operation"]
                if type(generation) is not int or generation < 0 or not isinstance(operation, str):
                    raise RuntimeError("authority unavailable")
                self._core.end_content_operation(
                    credential, ContentPermit(token, namespace, holder, generation, operation)
                )
                return {"ended": True}
            if method == "verify_current":
                return {"verified": self._core.verify_current(
                    credential, self._anchor_from_command(command)
                )}
        except (AuthorityUnavailable, TypeError, ValueError) as exc:
            raise RuntimeError("authority unavailable") from exc
        raise RuntimeError("authority unavailable")

    def _v2_service(self, namespace: object) -> AuthorityV2FenceService:
        if type(namespace) is not str:
            raise AuthorityUnavailable("namespace unavailable")
        service = self._v2_fences.get(namespace)
        if service is None:
            raise AuthorityUnavailable("namespace unavailable")
        return service

    def _bound_v2_service(self, credential: MtlsPeerCredential, profile_id: str,
                          manifest_digest: str, namespace: object) -> AuthorityV2FenceService:
        installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
        if (installed is None or installed.manifest_digest != manifest_digest
                or not any(peer == credential.certificate_sha256
                           and profile == profile_id and mapped == namespace
                           for (peer, profile, _), mapped in self._namespace_bindings_v2.items())):
            raise AuthorityUnavailable("namespace unavailable")
        return self._v2_service(namespace)

    def _owner_session_kwargs(self, command: dict[str, object], namespace: str,
                              installation_id: str) -> dict[str, object]:
        fields = {"owner_session_token", "owner_session_request"}
        present = set(command) & fields
        if not present:
            return {}
        if present != fields:
            raise AuthorityUnavailable("Owner session fields must be paired")
        token = command["owner_session_token"]
        if (type(token) is not str or len(token) != 43
                or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                       for ch in token)):
            raise AuthorityUnavailable("Owner session token encoding differs")
        raw = command["owner_session_request"]
        request = session_from_wire(raw)
        if (type(request) is not OwnerSessionLoginRequestV1
                or session_to_wire(request) != raw
                or request.authority_id != self._authority_id()
                or request.authority_namespace != namespace
                or request.installation_id != installation_id):
            raise AuthorityUnavailable("Owner session request identity differs")
        return {"session_token": token, "session_request": request}

    @staticmethod
    def _dispatch_footprint(value: object) -> RecoveryConstraintFootprint:
        if type(value) is not dict:
            raise ValueError("invalid dispatch footprint")
        fields = RecoveryConstraintFootprint.__dataclass_fields__
        if set(value) != set(fields):
            raise ValueError("invalid dispatch footprint fields")
        shaped = dict(value)
        for name in ("conflict_keys", "object_gate_keys"):
            if type(shaped[name]) is not list:
                raise ValueError("invalid dispatch footprint identifiers")
            shaped[name] = tuple(shaped[name])
        for name, kind in (("quota_occupancies", QuotaOccupancy),
                           ("reservations", ReservationConstraint),
                           ("budgets", BudgetConstraint)):
            if type(shaped[name]) is not list or any(type(item) is not list for item in shaped[name]):
                raise ValueError("invalid dispatch footprint constraints")
            shaped[name] = tuple(kind(*item) for item in shaped[name])
        result = RecoveryConstraintFootprint(**shaped)
        if json.loads(result._json()) != value:
            raise ValueError("noncanonical dispatch footprint")
        return result

    def _v2_command(self, method: str, credential: MtlsPeerCredential,
                    profile_id: str, manifest_digest: str,
                    command: object) -> dict[str, object]:
        if type(command) is not dict:
            raise RuntimeError("authority unavailable")
        subject = "mtls:sha256:" + credential.certificate_sha256
        try:
            if method in {"current_owner_actor_binding_v1",
                          "current_owner_principal_binding_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                pairings = self._v2_owner_pairings
                if installed is None or pairings is None:
                    raise AuthorityUnavailable("Owner actor binding service is unavailable")
                if method == "current_owner_actor_binding_v1":
                    if set(command) != {"namespace", "actor_id"}:
                        raise AuthorityUnavailable("Owner actor query fields differ")
                    binding = pairings.current_actor_binding(
                        authority_namespace=namespace,
                        installation_id=installed.installation_id,
                        actor_id=identifier(command["actor_id"], "actor_id"))
                else:
                    if set(command) != {"namespace", "principal"}:
                        raise AuthorityUnavailable("Owner principal query fields differ")
                    raw = command["principal"]
                    principal = owner_from_wire(raw)
                    if type(principal) is not OwnerPrincipalV1 or owner_to_wire(principal) != raw:
                        raise AuthorityUnavailable("Owner principal query differs")
                    binding = pairings.current_principal_binding(
                        authority_namespace=namespace,
                        installation_id=installed.installation_id,
                        principal=principal)
                if (binding is not None
                        and (binding.authority_id != self._authority_id()
                             or binding.installation_id != installed.installation_id
                             or namespace_ref(binding.namespace) != namespace)):
                    raise AuthorityUnavailable("Owner actor binding identity differs")
                return {"binding": None if binding is None else owner_to_wire(binding)}
            if method == "describe_owner_session_v1":
                if set(command) != {"namespace", "token"}:
                    raise AuthorityUnavailable("Owner session description fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                sessions = self._v2_owner_sessions
                if installed is None or sessions is None:
                    raise AuthorityUnavailable("Owner session service is unavailable")
                request = sessions.describe_current(
                    transport_credential=credential, token=command["token"],
                    namespace=namespace, installation_id=installed.installation_id)
                return {"request": session_to_wire(request)}
            if method in {"begin_owner_session_v1", "accept_owner_session_v1",
                          "current_owner_session_v1", "logout_owner_session_v1",
                          "revoke_all_owner_sessions_v1", "revoke_owner_session_key_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                sessions = self._v2_owner_sessions
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if sessions is None or installed is None:
                    raise AuthorityUnavailable("Owner session service is unavailable")
                required = ({"namespace", "request"} if method == "begin_owner_session_v1"
                            else {"namespace", "challenge", "signature"}
                            if method == "accept_owner_session_v1"
                            else {"namespace", "request", "token"})
                if set(command) != required:
                    raise AuthorityUnavailable("Owner session command fields differ")
                field = "challenge" if method == "accept_owner_session_v1" else "request"
                raw = command[field]
                decoded = session_from_wire(raw)
                expected = (OwnerSessionLoginChallengeV1 if field == "challenge"
                            else OwnerSessionLoginRequestV1)
                if type(decoded) is not expected or session_to_wire(decoded) != raw:
                    raise AuthorityUnavailable("Owner session command is not canonical")
                request = decoded.request if type(decoded) is OwnerSessionLoginChallengeV1 else decoded
                if (request.authority_id != self._authority_id()
                        or request.authority_namespace != namespace
                        or request.installation_id != installed.installation_id):
                    raise AuthorityUnavailable("Owner session installation identity differs")
                if method == "begin_owner_session_v1":
                    challenge = sessions.begin_login(
                        transport_credential=credential, request=request)
                    return {"challenge": session_to_wire(challenge)}
                if method == "accept_owner_session_v1":
                    signature = self._owner_proof_signature(command["signature"])
                    token = sessions.accept_login(
                        transport_credential=credential, challenge=decoded,
                        signature=signature)
                    return {"token": token}
                token = command["token"]
                if method == "current_owner_session_v1":
                    sessions.require_current(
                        transport_credential=credential, token=token, request=request)
                    return {"current": True}
                if method == "logout_owner_session_v1":
                    sessions.logout(
                        transport_credential=credential, token=token, request=request)
                elif method == "revoke_all_owner_sessions_v1":
                    sessions.revoke_all(
                        transport_credential=credential, token=token, request=request)
                else:
                    sessions.revoke_credential(
                        transport_credential=credential, token=token, request=request)
                return {"revoked": True}
            if method in {"register_owner_credential_v1", "begin_owner_proof_v1",
                          "accept_owner_proof_v1", "get_owner_proof_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                proofs = self._v2_owner_proofs
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if proofs is None or installed is None:
                    raise AuthorityUnavailable("Owner proof service is unavailable")
                required = {
                    "register_owner_credential_v1": {"namespace", "registration", "rotation_signature"},
                    "begin_owner_proof_v1": {"namespace", "request", "operation"},
                    "accept_owner_proof_v1": {"namespace", "challenge", "signature"},
                    "get_owner_proof_v1": {"namespace", "operation"},
                }[method]
                if set(command) != required:
                    raise AuthorityUnavailable("Owner proof command fields differ")

                def proof_value(field: str, expected: type):
                    raw = command[field]
                    decoded = proof_from_wire(raw)
                    if type(decoded) is not expected or proof_to_wire(decoded) != raw:
                        raise AuthorityUnavailable("Owner proof command is not canonical")
                    return decoded

                def owner_operation() -> OwnerAuthorizationOperationV1:
                    raw = command["operation"]
                    decoded = owner_from_wire(raw)
                    if (type(decoded) is not OwnerAuthorizationOperationV1
                            or owner_to_wire(decoded) != raw
                            or decoded.authority_id != self._authority_id()
                            or decoded.installation_id != installed.installation_id
                            or namespace_ref(decoded.namespace) != namespace
                            or self._namespace_bindings_v2.get((
                                credential.certificate_sha256, profile_id,
                                decoded.namespace)) != namespace):
                        raise AuthorityUnavailable("Owner proof operation identity differs")
                    return decoded

                if method == "register_owner_credential_v1":
                    registration = proof_value("registration", OwnerCredentialRegistrationV1)
                    if (registration.authority_id != self._authority_id()
                            or registration.authority_namespace != namespace
                            or registration.installation_id != installed.installation_id):
                        raise AuthorityUnavailable("Owner credential identity differs")
                    signature_hex = command["rotation_signature"]
                    if signature_hex is not None:
                        signature = self._owner_proof_signature(signature_hex)
                    else:
                        signature = None
                    registered = proofs.register_credential(
                        transport_credential=credential, registration=registration,
                        rotation_signature=signature)
                    return {"registration": proof_to_wire(registered)}
                if method == "begin_owner_proof_v1":
                    operation = owner_operation()
                    request = proof_value("request", OwnerProofRequestV1)
                    if request.installation_id != installed.installation_id:
                        raise AuthorityUnavailable("Owner proof installation differs")
                    challenge = proofs.begin_challenge(
                        transport_credential=credential, request=request,
                        operation=operation)
                    return {"challenge": proof_to_wire(challenge)}
                if method == "accept_owner_proof_v1":
                    challenge = proof_value("challenge", OwnerProofChallengeV1)
                    request = challenge.request
                    if (request.authority_id != self._authority_id()
                            or request.authority_namespace != namespace
                            or request.installation_id != installed.installation_id):
                        raise AuthorityUnavailable("Owner challenge identity differs")
                    signature = self._owner_proof_signature(command["signature"])
                    acceptance = proofs.accept_proof(
                        transport_credential=credential,
                        challenge=challenge, signature=signature)
                    return {"acceptance": proof_to_wire(acceptance)}
                operation = owner_operation()
                acceptance = proofs.get_accepted_for_operation(
                    transport_credential=credential, operation=operation)
                return {"acceptance": None if acceptance is None else proof_to_wire(acceptance)}
            if method == "get_current_owner_guard_for_fence" and set(command) == {
                    "namespace", "permit"}:
                namespace = identifier(command["namespace"], "namespace")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                tickets = self._v2_owner_tickets
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if tickets is None or installed is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in {"read", "write"}
                        or permit.namespace != namespace or permit.subject != subject):
                    raise AuthorityUnavailable("owner guard read requires a content fence")
                current = service.validate_fence(
                    credential=credential, subject=subject, permit=permit)
                guard = tickets.get_current_guard(
                    credential=credential, authority_namespace=namespace,
                    installation_id=installed.installation_id,
                    subject=subject, permit=current)
                if guard is not None and (
                    type(guard) is not OwnerAuthorizationGuardV1
                    or guard.authority_id != self._authority_id()
                    or guard.installation_id != installed.installation_id
                    or namespace_ref(guard.namespace) != namespace
                    or self._namespace_bindings_v2.get((
                        credential.certificate_sha256, profile_id,
                        guard.namespace)) != namespace
                ):
                    raise AuthorityUnavailable("owner guard identity mismatch")
                return {"guard": None if guard is None else owner_to_wire(guard),
                        "permit": to_wire(current)}
            if method in {"register_owner_ticket", "reserve_owner_issue",
                          "finalize_owner_issue"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                tickets = self._v2_owner_tickets
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if tickets is None or installed is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                expected = ({"namespace", "ticket"} if method == "register_owner_ticket"
                            else {"namespace", "operation", "proof"}
                            if method == "finalize_owner_issue"
                            else {"namespace", "operation"})
                session_fields = {"owner_session_token", "owner_session_request"}
                if set(command) != expected and not (
                        method != "register_owner_ticket"
                        and set(command) == expected | session_fields):
                    raise AuthorityUnavailable("owner command is invalid")
                field = "ticket" if method == "register_owner_ticket" else "operation"
                raw = command[field]
                value = owner_from_wire(raw)
                if owner_to_wire(value) != raw:
                    raise AuthorityUnavailable("owner command is not canonical")
                required_type = (OwnerClaimTicketV1 if field == "ticket"
                                 else OwnerAuthorizationOperationV1)
                if (type(value) is not required_type
                        or value.authority_id != self._authority_id()
                        or (method != "register_owner_ticket"
                            and value.installation_id != installed.installation_id)
                        or namespace_ref(value.namespace) != namespace
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            value.namespace)) != namespace):
                    raise AuthorityUnavailable("owner command identity mismatch")
                if method == "register_owner_ticket":
                    ticket = tickets.register_ticket(
                        credential=credential, authority_namespace=namespace,
                        ticket=value)
                    return {"ticket": owner_to_wire(ticket)}
                if method == "reserve_owner_issue":
                    session_kwargs = self._owner_session_kwargs(
                        command, namespace, installed.installation_id)
                    receipt = tickets.reserve_issue(
                        credential=credential, authority_namespace=namespace,
                        operation=value, **session_kwargs)
                    return {"receipt": owner_to_wire(receipt)}
                raw_proof = command["proof"]
                proof = owner_from_wire(raw_proof)
                if (type(proof) is not OwnerGraphCommitProofV1
                        or owner_to_wire(proof) != raw_proof):
                    raise AuthorityUnavailable("owner graph proof is invalid")
                # This is only a candidate. Store invokes its trusted, independent
                # graph verifier and rechecks the Authority snapshot before CAS.
                receipt = tickets.finalize_issue(
                    credential=credential, authority_namespace=namespace,
                    operation=value, proof=proof,
                    **self._owner_session_kwargs(
                        command, namespace, installed.installation_id))
                return {"receipt": owner_to_wire(receipt)}
            if method == "get_pending_owner_issue_for_graph_write" and set(command) == {
                    "namespace", "operation_id", "permit"}:
                namespace = identifier(command["namespace"], "namespace")
                operation_id = identifier(command["operation_id"], "operation_id")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                if self._v2_owner_tickets is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2 or permit.operation != "write"
                        or permit.namespace != namespace or permit.subject != subject):
                    raise AuthorityUnavailable("owner graph read requires a write fence")
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if installed is None:
                    raise AuthorityUnavailable("installation is unavailable")
                service.validate_fence(
                    credential=credential, subject=subject, permit=permit)
                receipt = self._v2_owner_tickets.get_pending_for_graph_write(
                    credential=credential, authority_namespace=namespace,
                    operation_id=operation_id, installation_id=installed.installation_id,
                    subject=subject, permit=permit)
                return {"receipt": None if receipt is None else owner_to_wire(receipt)}
            if method == "get_pending_owner_issue" and (
                    set(command) == {"namespace", "operation_id"}
                    or set(command) == {"namespace", "operation_id",
                                        "owner_session_token", "owner_session_request"}):
                namespace = identifier(command["namespace"], "namespace")
                operation_id = identifier(command["operation_id"], "operation_id")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                if self._v2_owner_tickets is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if installed is None:
                    raise AuthorityUnavailable("installation is unavailable")
                receipt = self._v2_owner_tickets.get_pending(
                    credential=credential, authority_namespace=namespace,
                    operation_id=operation_id,
                    **self._owner_session_kwargs(
                        command, namespace, installed.installation_id))
                if receipt is not None and (
                    type(receipt) is not OwnerAuthorizationReceiptV1
                    or receipt.phase != "pending"
                    or receipt.operation.operation_id != operation_id
                    or receipt.operation.authority_id != self._authority_id()
                ):
                    raise AuthorityUnavailable("owner receipt identity mismatch")
                return {"receipt": None if receipt is None else owner_to_wire(receipt)}
            if method == "begin_dispatch_fence" and set(command) == {
                    "namespace", "holder", "operation_id", "expected_anchor",
                    "effect_id", "command_digest", "footprint"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                footprint = self._dispatch_footprint(command["footprint"])
                permit = service.begin_fence(
                    credential=credential, subject=subject, holder=command["holder"],
                    operation="dispatch", operation_id=command["operation_id"],
                    expected_anchor=anchor, effect_id=command["effect_id"],
                    command_digest=command["command_digest"], footprint=footprint)
                return {"permit": to_wire(permit)}
            if method == "execution_prepare" and set(command) == {
                    "permit", "mutation_id", "footprint"}:
                permit = from_wire(command["permit"])
                if type(permit) is not FencePermitV2 or permit.operation != "dispatch":
                    raise AuthorityUnavailable("dispatch permit required")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                footprint = self._dispatch_footprint(command["footprint"])
                receipt, updated = self._v2_execution[permit.namespace].execution_prepare(
                    credential=credential, subject=subject, permit=permit,
                    mutation_id=command["mutation_id"], footprint=footprint)
                return {"receipt": to_wire(receipt), "permit": to_wire(updated)}
            if method in ("execution_claim", "execution_claim_v2") and set(command) == {
                    "prepared_receipt", "binding"}:
                prepared = from_wire(command["prepared_receipt"])
                binding = from_wire(command["binding"])
                if (type(prepared) is not MutationReceiptV2
                        or prepared.pending.phase != "prepared"
                        or type(binding) is not (
                            ExecutionBindingV2 if method == "execution_claim_v2"
                            else ExecutionBindingV1)
                        or to_wire(prepared) != command["prepared_receipt"]
                        or to_wire(binding) != command["binding"]
                        or binding.permit != prepared.pending.permit
                        or binding.permit.subject != subject):
                    raise AuthorityUnavailable("prepared execution claim identity is invalid")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, binding.namespace)
                claim = (self._v2_execution[binding.namespace].execution_claim_v2
                         if method == "execution_claim_v2"
                         else self._v2_execution[binding.namespace].execution_claim)
                receipt, updated = claim(
                    credential=credential, subject=subject,
                    prepared_receipt=prepared, binding=binding)
                return {"receipt": to_wire(receipt), "permit": to_wire(updated)}
            if method in ("execution_begin_handoff", "execution_begin_handoff_v2") and set(command) == {
                    "claimed_receipt", "handoff_id"}:
                claimed = from_wire(command["claimed_receipt"])
                handoff_id = identifier(command["handoff_id"], "handoff_id")
                if (type(claimed) is not MutationReceiptV2
                        or claimed.pending.phase != "claimed"
                        or claimed.durable_state != "committed"
                        or type(claimed.pending.binding) is not (
                            ExecutionBindingV2 if method == "execution_begin_handoff_v2"
                            else ExecutionBindingV1)
                        or claimed.pending.permit.subject != subject):
                    raise AuthorityUnavailable("committed claim required")
                namespace = claimed.pending.permit.namespace
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                begin = (self._v2_execution[namespace].begin_handoff_v2
                         if method == "execution_begin_handoff_v2"
                         else self._v2_execution[namespace].begin_handoff)
                start = begin(
                    credential=credential, subject=subject,
                    claimed_receipt=claimed, handoff_id=handoff_id)
                return {"start": start.to_wire()}
            if method == "current_anchor" and set(command) == {"namespace"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                return self._anchor_payload(service.current_anchor(
                    credential=credential, subject=subject))
            if method == "begin_fence" and set(command) == {
                    "namespace", "holder", "operation", "operation_id", "expected_anchor"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                operation = command["operation"]
                if (type(operation) is not str
                        or operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence unavailable")
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                permit = service.begin_fence(
                    credential=credential, subject=subject, holder=command["holder"],
                    operation=operation, operation_id=command["operation_id"],
                    expected_anchor=anchor)
                return {"permit": to_wire(permit)}
            if method == "get_fence_operation" and set(command) == {
                    "namespace", "operation_id"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                permit, state = service.get_fence_operation(
                    credential=credential, subject=subject,
                    operation_id=command["operation_id"])
                return {"permit": to_wire(permit), "state": state}
            if method == "validate_fence" and set(command) == {"permit"}:
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence required")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                return {"permit": to_wire(service.validate_fence(
                    credential=credential, subject=subject, permit=permit))}
            if method == "finish_fence" and set(command) == {
                    "permit", "request_id", "request_digest"}:
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence required")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                service.finish_fence(
                    credential=credential, subject=subject, permit=permit,
                    request_id=command["request_id"],
                    request_digest=command["request_digest"])
                return {"finished": True}
        except (AuthorityUnavailable, TypeError, ValueError) as exc:
            raise RuntimeError("authority unavailable") from exc
        raise RuntimeError("authority unavailable")

    @staticmethod
    def _owner_proof_signature(value: object) -> bytes:
        if (type(value) is not str or len(value) != 128
                or any(char not in "0123456789abcdef" for char in value)):
            raise AuthorityUnavailable("Owner signature encoding differs")
        return bytes.fromhex(value)

    def _dispatch(self, method, request, credential, channel_binding: bytes, *,
                  handshake_binding: str | None = None,
                  command: object = None) -> dict[str, object]:
        """Internal RPC core; public dispatch supplies only verified mTLS peers."""
        if hasattr(request, "publisher_package"):
            wire = _WireRequest(
                request.profile_id, request.plugin_name, request.host_api_version,
                request.publisher_package.manifest_sha256,
            )
        else:
            wire = _WireRequest.from_value(request)
        binding = self._binding(channel_binding, wire)
        self._authorize(credential, wire)
        peer = credential.certificate_sha256
        if method == "handshake":
            self._prune_sessions()
            self._sessions[binding] = (
                time.monotonic(), peer, hashlib.sha256(_canonical(wire.payload())).hexdigest()
            )
            return {
                "state": "paired",
                "installation_authority_id": self._authority_id(),
                "installation_identity_ref": "mtls:sha256:" + peer,
                "channel_binding_sha256": binding,
                "publisher_trusted": True,
            }
        if handshake_binding != binding:
            raise RuntimeError("authority unavailable")
        self._paired_session(binding, peer, wire)
        if method == "installation_grant_v2":
            if wire.protocol != AUTHORITY_V2_PROTOCOL or command != {}:
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if installed is None or installed.manifest_digest != wire.manifest_sha256:
                raise RuntimeError("authority unavailable")
            return asdict(InstallationGrantV2(
                authority_id=self._authority_id(),
                subject="mtls:sha256:" + peer,
                administrator_holder=installed.administrator_holder,
                installation_id=installed.installation_id,
                manifest_digest=wire.manifest_sha256,
                publisher_policy_ref=installed.publisher_policy_ref,
                service_capability_version=installed.service_capability_version,
                channel_binding_sha256=binding,
            ))
        if method == "ingress_clock_sample_v2":
            if wire.protocol != AUTHORITY_V2_PROTOCOL or type(command) is not dict or command:
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if (installed is None or installed.manifest_digest != wire.manifest_sha256
                    or installed.source_id is None or self._clock_provider is None):
                raise RuntimeError("authority unavailable")
            try:
                reading = self._clock_provider()
                if (type(reading) is not AuthorityClockReadingV2
                        or reading.source_id != installed.source_id
                        or reading.healthy is not True
                        or reading.utc_error_seconds > installed.max_utc_error_seconds):
                    raise RuntimeError("authority unavailable")
                sample = IngressClockSampleV2(
                    authority_id=self._authority_id(),
                    installation_id=installed.installation_id,
                    source_id=reading.source_id,
                    utc_seconds=reading.utc_seconds,
                    monotonic_seconds=reading.monotonic_seconds,
                    epoch=reading.epoch,
                    utc_error_seconds=reading.utc_error_seconds,
                )
            except Exception as exc:
                raise RuntimeError("authority unavailable") from exc
            return {**asdict(sample), "channel_binding_sha256": binding}
        if method in {"namespace_bootstrap", "namespace_genesis"}:
            if (wire.protocol != AUTHORITY_V2_PROTOCOL or type(command) is not dict
                    or set(command) != ({"namespace"} if method == "namespace_bootstrap"
                                        else {"namespace", "request_id"})
                    or type(command["namespace"]) is not dict
                    or set(command["namespace"]) != {"bot_id", "persona_id"}):
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if installed is None or installed.manifest_digest != wire.manifest_sha256:
                raise RuntimeError("authority unavailable")
            try:
                namespace_id = NamespaceId(**command["namespace"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("authority unavailable") from exc
            namespace = self._namespace_bindings_v2.get((peer, wire.profile_id, namespace_id))
            if namespace is None:
                raise RuntimeError("authority unavailable")
            service = self._v2_service(namespace)
            if method == "namespace_genesis":
                result = service.activate_namespace(
                    credential=credential, subject="mtls:sha256:" + peer,
                    holder=installed.administrator_holder,
                    namespace_id=namespace_id, request_id=command["request_id"],
                )
            else:
                result = service.namespace_bootstrap(
                    credential=credential, subject="mtls:sha256:" + peer,
                    namespace_id=namespace_id,
                )
            if (type(result) is not NamespaceBootstrapV2
                    or result.authority_id != self._authority_id()
                    or result.namespace != namespace_id
                    or result.authority_namespace != namespace):
                raise RuntimeError("authority unavailable")
            return {**asdict(result), "channel_binding_sha256": binding}
        if method == "capability_grant":
            if command is not None:
                raise RuntimeError("authority unavailable")
            return {
                "grant_id": secrets.token_hex(16),
                "authority_id": self._authority_id(),
                "installation_identity_ref": "mtls:sha256:" + peer,
                "capabilities": list(_ENROLLMENT_CAPABILITIES),
                "channel_binding_sha256": binding,
            }
        result = (self._v2_command(
            method, credential, wire.profile_id, wire.manifest_sha256, command)
                  if wire.protocol == AUTHORITY_V2_PROTOCOL else
                  self._content_command(method, credential, command))
        result["channel_binding_sha256"] = binding
        return result

    def dispatch(self, method, request, credential, channel_binding: bytes, *,
                 handshake_binding: str | None = None,
                 command: object = None) -> dict[str, object]:
        """Production RPC entrypoint; only an mTLS peer reaches authorization."""
        if not isinstance(credential, MtlsPeerCredential):
            raise RuntimeError("mTLS peer credential required")
        return self._dispatch(
            method, request, credential, channel_binding,
            handshake_binding=handshake_binding,
            command=command,
        )

    def _dispatch_for_test(self, method, request, credential: MtlsPeerCredential,
                           channel_binding: bytes, *,
                           handshake_binding: str | None = None,
                           command: object = None) -> dict[str, object]:
        """Private deterministic seam; tests still provide an mTLS-shaped peer."""
        if not isinstance(credential, MtlsPeerCredential):
            raise TypeError("MtlsPeerCredential is required for test dispatch")
        return self._dispatch(
            method, request, credential, channel_binding,
            handshake_binding=handshake_binding,
            command=command,
        )

    async def _dispatch_on_worker(self, method, request, credential, binding,
                                  handshake_binding, command) -> dict[str, object]:
        # Release only when the concurrent future actually completes. Cancelling
        # the awaiting connection does not release a still-running service call.
        with self._worker_lock:
            if self._worker_closed or not self._worker_slots.acquire(blocking=False):
                raise RuntimeError("authority unavailable")
            try:
                future = self._worker.submit(
                    self.dispatch, method, request, credential, binding,
                    handshake_binding=handshake_binding, command=command,
                )
            except Exception:
                self._worker_slots.release()
                raise
            future.add_done_callback(lambda _: self._worker_slots.release())
        return await asyncio.wrap_future(future)

    async def aclose(self) -> None:
        """Stop accepting dispatches and wait for submitted service work to finish.

        Deployment closes its asyncio listener first, then awaits this method.
        Closing the listener alone does not own the RPC worker's lifecycle.
        """
        async with self._worker_close_lock:
            if self._worker_shutdown_task is None:
                with self._worker_lock:
                    self._worker_closed = True
                self._worker_shutdown_task = asyncio.create_task(
                    asyncio.to_thread(self._worker.shutdown, wait=True)
                )
            shutdown = self._worker_shutdown_task
        await asyncio.shield(shutdown)

    async def serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        *, timeout_seconds: float, max_message_bytes: int,
    ) -> None:
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        binding = ssl_object.get_channel_binding("tls-unique") if ssl_object else None
        if not certificate or not binding:
            writer.close()
            await writer.wait_closed()
            return
        credential = MtlsPeerCredential(hashlib.sha256(certificate).hexdigest())
        try:
            while True:
                line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout_seconds)
                if len(line) > max_message_bytes:
                    raise RuntimeError("authority unavailable")
                payload = json.loads(line)
                if not isinstance(payload, dict) or set(payload) - {
                    "protocol", "request_id", "method", "request", "handshake_binding_sha256",
                    "command"
                }:
                    raise RuntimeError("authority unavailable")
                if (payload.get("protocol") not in (AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL)
                        or not isinstance(payload.get("request_id"), str)
                        or not isinstance(payload.get("method"), str)):
                    raise RuntimeError("authority unavailable")
                try:
                    if (type(payload.get("request")) is not dict
                            or payload["request"].get("protocol") != payload["protocol"]):
                        raise RuntimeError("authority unavailable")
                    result = await self._dispatch_on_worker(
                        payload["method"], payload.get("request"), credential, binding,
                        payload.get("handshake_binding_sha256"), payload.get("command"),
                    )
                    response = {"request_id": payload["request_id"], "ok": True, "result": result}
                except Exception as exc:
                    response = {"request_id": payload["request_id"], **self.error_payload(exc)}
                encoded = _canonical(response)
                if len(encoded) + 1 > max_message_bytes:
                    raise RuntimeError("authority unavailable")
                writer.write(encoded + b"\n")
                await asyncio.wait_for(writer.drain(), timeout_seconds)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, RuntimeError,
                TimeoutError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(
        self, host: str, port: int, config: AuthorityServerTlsConfig,
    ) -> asyncio.AbstractServer:
        if type(config.max_message_bytes) is not int or not 512 <= config.max_message_bytes <= 1_048_576:
            raise ValueError("authority message limit is invalid")
        if not isinstance(config.timeout_seconds, (int, float)) or not 0 < config.timeout_seconds <= 30:
            raise ValueError("authority timeout is invalid")
        return await asyncio.start_server(
            lambda reader, writer: self.serve_connection(
                reader, writer, timeout_seconds=float(config.timeout_seconds),
                max_message_bytes=config.max_message_bytes,
            ),
            host, port, ssl=config.ssl_context(), ssl_handshake_timeout=config.timeout_seconds,
            limit=config.max_message_bytes,
        )


__all__ = ("AdministratorInstallationV2", "AuthorityRpcServer",
           "AuthorityServerTlsConfig", "MtlsPeerCredential")
