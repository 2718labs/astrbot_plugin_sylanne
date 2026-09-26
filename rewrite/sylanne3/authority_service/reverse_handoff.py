"""Administrator-pinned reverse mTLS call to the host's graph claim port.

This port is only an Authority callback. It cannot receive an endpoint from an
RPC request and does not authorize a platform send.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import socket
import ssl

from .v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    ExecutionBindingV2, MutationReceiptV2, canonical_digest, from_wire, to_wire,
)


def require_exact_reverse_handoff_identity(
    namespace: str, context: DispatchHandoffContextV1,
    binding: ExecutionBindingV2, claimed: MutationReceiptV2,
) -> None:
    """Reject a callback that is not the exact prepared-to-claimed P2 chain.

    The bridge still supplies Authority provenance and the live CAS. This
    transport check binds the registered P0/P1/P2 identities.
    """
    if (type(namespace) is not str or not namespace
            or type(context) is not DispatchHandoffContextV1
            or type(binding) is not ExecutionBindingV2
            or type(claimed) is not MutationReceiptV2):
        raise RuntimeError("reverse graph claim requires typed P2 identity")
    pending = claimed.pending
    prepared = pending.prepared_receipt
    p0 = binding.permit
    p1 = pending.permit
    p2 = context.permit
    if (claimed.durable_state != "committed" or pending.phase != "claimed"
            or pending.binding != binding or prepared is None
            or prepared.durable_state != "committed"
            or prepared.pending.phase != "prepared"
            or prepared.pending.permit != p0
            or binding.namespace != namespace or p0.namespace != namespace
            or p0.operation != "dispatch" or p1.operation != "dispatch"
            or p2.operation != "dispatch"
            or p1.revision != p0.revision + 1
            or claimed.updated_revision != p1.revision + 1
            or p1.pinned_anchor != prepared.after_anchor
            or pending.before_anchor != prepared.after_anchor
            or p2 != replace(p1, revision=claimed.updated_revision,
                             pinned_anchor=claimed.after_anchor)
            or context.claimed_receipt_digest != canonical_digest(claimed)
            or context.binding_digest != canonical_digest(binding)):
        raise RuntimeError("reverse graph claim P2 chain differs")
    exact_fields = (
        "authority_id", "namespace", "subject", "holder", "generation",
        "operation_id", "effect_id", "token", "fence_epoch",
        "command_digest", "footprint_digest",
    )
    if any(getattr(p0, field) != getattr(p1, field)
           or getattr(p0, field) != getattr(p2, field)
           for field in exact_fields):
        raise RuntimeError("reverse graph claim subject, holder or fence differs")


@dataclass(frozen=True, slots=True)
class AdministratorReverseHandoffProfile:
    namespace: str
    profile_id: str
    installation_id: str
    host: str
    port: int
    server_name: str
    expected_host_certificate_sha256: str
    trust_root: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536

    def __post_init__(self) -> None:
        for value in (self.namespace, self.profile_id, self.installation_id,
                      self.host, self.server_name):
            if type(value) is not str or not value or len(value) > 255:
                raise ValueError("reverse handoff administrator identity is invalid")
        if (type(self.port) is not int or not 1 <= self.port <= 65535
                or type(self.timeout_seconds) not in (int, float)
                or not 0 < self.timeout_seconds <= 30
                or type(self.max_message_bytes) is not int
                or not 512 <= self.max_message_bytes <= 1_048_576):
            raise ValueError("reverse handoff administrator endpoint is invalid")
        digest = self.expected_host_certificate_sha256
        if type(digest) is not str or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest):
            raise ValueError("reverse handoff host certificate pin is invalid")
        for name in ("trust_root", "client_certificate", "client_private_key"):
            path = Path(getattr(self, name))
            if not path.is_absolute() or not path.is_file() or path.is_symlink():
                raise ValueError("reverse handoff TLS material is unavailable or unsafe")
            object.__setattr__(self, name, path)


class ReverseGraphClaimClient:
    """Synchronous callback used by the Authority's existing RPC worker."""

    def __init__(self, profile: AdministratorReverseHandoffProfile) -> None:
        if type(profile) is not AdministratorReverseHandoffProfile:
            raise TypeError("administrator reverse handoff profile required")
        self.profile = profile
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=str(profile.trust_root))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(profile.client_certificate),
                                str(profile.client_private_key))
        self._ssl = context

    def claim(self, context: DispatchHandoffContextV1,
              binding: ExecutionBindingV2,
              claimed: MutationReceiptV2) -> DispatchGraphClaimReceiptV1:
        profile = self.profile
        require_exact_reverse_handoff_identity(
            profile.namespace, context, binding, claimed,
        )
        message = {
            "profile_id": profile.profile_id,
            "installation_id": profile.installation_id,
            "namespace": profile.namespace,
            "context": to_wire(context), "binding": to_wire(binding),
            "claimed_receipt": to_wire(claimed),
        }
        data = json.dumps(message, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8") + b"\n"
        if len(data) > profile.max_message_bytes:
            raise RuntimeError("reverse graph claim request exceeds configured limit")
        try:
            with socket.create_connection((profile.host, profile.port),
                                          timeout=profile.timeout_seconds) as raw:
                with self._ssl.wrap_socket(raw, server_hostname=profile.server_name) as tls:
                    tls.settimeout(profile.timeout_seconds)
                    certificate = tls.getpeercert(binary_form=True)
                    if (certificate is None or hashlib.sha256(certificate).hexdigest()
                            != profile.expected_host_certificate_sha256):
                        raise RuntimeError("reverse graph claim host identity differs")
                    tls.sendall(data)
                    response = bytearray()
                    while len(response) <= profile.max_message_bytes:
                        part = tls.recv(1)
                        if not part:
                            raise RuntimeError("reverse graph claim response ended")
                        response.extend(part)
                        if part == b"\n":
                            break
                    if len(response) > profile.max_message_bytes or response[-1:] != b"\n":
                        raise RuntimeError("reverse graph claim response exceeds limit")
        except (OSError, ssl.SSLError) as exc:
            raise RuntimeError("reverse graph claim transport unavailable") from exc
        try:
            value = json.loads(response)
            if type(value) is not dict or set(value) != {"receipt"}:
                raise ValueError("reverse graph claim response fields differ")
            receipt = from_wire(value["receipt"])
            if (type(receipt) is not DispatchGraphClaimReceiptV1
                    or to_wire(receipt) != value["receipt"]
                    or receipt.context_digest != canonical_digest(context)
                    or receipt.graph_namespace != binding.graph_namespace
                    or receipt.graph_incarnation != binding.graph_incarnation):
                raise ValueError("reverse graph claim receipt identity differs")
            return receipt
        except (TypeError, ValueError) as exc:
            raise RuntimeError("reverse graph claim response is invalid") from exc


__all__ = (
    "AdministratorReverseHandoffProfile", "ReverseGraphClaimClient",
    "require_exact_reverse_handoff_identity",
)
