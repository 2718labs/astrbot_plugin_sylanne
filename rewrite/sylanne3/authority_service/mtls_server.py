"""Content-free stdlib mTLS JSON-RPC adapter for a separately installed Authority."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import secrets
import ssl
import time
from typing import Callable

from ..runtime.restore_anchor import RestoreAnchor
from .core import AuthorityServiceCore
from .contract import AuthorityUnavailable, ContentPermit, identifier
from .v2_contract import FencePermitV2, SCHEMA as AUTHORITY_V2_PROTOCOL, from_wire, to_wire
from .v2_fence_service import AuthorityV2FenceService


_MAX_SESSIONS = 256
_SESSION_TTL_SECONDS = 30.0
AUTHORITY_PROTOCOL = "sylanne3.authority.v1"
_ENROLLMENT_CAPABILITIES = ("enrollment",)


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
        v2_fences: AuthorityV2FenceService | None = None,
    ) -> None:
        if not isinstance(core, AuthorityServiceCore):
            raise TypeError("AuthorityServiceCore is required")
        if not callable(administrator_authorizer) or not callable(publisher_manifest_verifier):
            raise TypeError("server-side authorizer and publisher verifier are required")
        if v2_fences is not None and type(v2_fences) is not AuthorityV2FenceService:
            raise TypeError("AuthorityV2FenceService is required")
        self._core = core
        self._administrator_authorizer = administrator_authorizer
        self._publisher_manifest_verifier = publisher_manifest_verifier
        self._v2_fences = v2_fences
        self._sessions: dict[str, tuple[float, str, str]] = {}

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

    def _v2_command(self, method: str, credential: MtlsPeerCredential,
                    command: object) -> dict[str, object]:
        service = self._v2_fences
        if service is None or type(command) is not dict:
            raise RuntimeError("authority unavailable")
        subject = "mtls:sha256:" + credential.certificate_sha256
        try:
            if method == "current_anchor" and set(command) == {"namespace"}:
                if command["namespace"] != service.namespace:
                    raise AuthorityUnavailable("namespace unavailable")
                return self._anchor_payload(service.current_anchor(
                    credential=credential, subject=subject))
            if method == "begin_fence" and set(command) == {
                    "namespace", "holder", "operation", "operation_id", "expected_anchor"}:
                if command["namespace"] != service.namespace or command["operation"] != "read":
                    raise AuthorityUnavailable("read fence unavailable")
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                permit = service.begin_fence(
                    credential=credential, subject=subject, holder=command["holder"],
                    operation="read", operation_id=command["operation_id"],
                    expected_anchor=anchor)
                return {"permit": to_wire(permit)}
            if method == "validate_fence" and set(command) == {"permit"}:
                permit = from_wire(command["permit"])
                if type(permit) is not FencePermitV2 or permit.operation != "read":
                    raise AuthorityUnavailable("read fence required")
                return {"permit": to_wire(service.validate_fence(
                    credential=credential, subject=subject, permit=permit))}
            if method == "finish_fence" and set(command) == {
                    "permit", "request_id", "request_digest"}:
                permit = from_wire(command["permit"])
                if type(permit) is not FencePermitV2 or permit.operation != "read":
                    raise AuthorityUnavailable("read fence required")
                service.finish_fence(
                    credential=credential, subject=subject, permit=permit,
                    request_id=command["request_id"],
                    request_digest=command["request_digest"])
                return {"finished": True}
        except (AuthorityUnavailable, TypeError, ValueError) as exc:
            raise RuntimeError("authority unavailable") from exc
        raise RuntimeError("authority unavailable")

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
        result = (self._v2_command(method, credential, command)
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
                    result = self.dispatch(
                        payload["method"], payload.get("request"), credential, binding,
                        handshake_binding=payload.get("handshake_binding_sha256"),
                        command=payload.get("command"),
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


__all__ = ("AuthorityRpcServer", "AuthorityServerTlsConfig", "MtlsPeerCredential")
