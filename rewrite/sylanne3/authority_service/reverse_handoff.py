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

from .contract import AuthorityUnavailable
from .v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    ExecutionBindingV2, MutationReceiptV2, OwnerDispatchWitnessV1,
    AuthorityDispatchSnapshotV1,
    canonical_digest, from_wire, to_wire,
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


def require_exact_owner_witness(
        profile: AdministratorReverseHandoffProfile,
        context: DispatchHandoffContextV1,
        binding: ExecutionBindingV2,
        witness: OwnerDispatchWitnessV1) -> None:
    """Bind Authority's current grant snapshot to this pinned callback."""
    if (type(witness) is not OwnerDispatchWitnessV1
            or witness.context_digest != canonical_digest(context)
            or witness.authority_namespace != profile.namespace
            or witness.graph_namespace != binding.graph_namespace
            or witness.guard.authority_id != context.permit.authority_id
            or witness.guard.installation_id != profile.installation_id):
        raise RuntimeError("reverse graph claim Owner witness differs")


def require_exact_authority_snapshot(
        context: DispatchHandoffContextV1,
        witness: OwnerDispatchWitnessV1,
        snapshot: AuthorityDispatchSnapshotV1) -> None:
    """Bind the versioned full Authority admission set to this P2 callback."""
    permit = context.permit
    if (type(snapshot) is not AuthorityDispatchSnapshotV1
            or snapshot.context_digest != canonical_digest(context)
            or snapshot.owner_witness_digest != canonical_digest(witness)
            or (snapshot.authority_id, snapshot.namespace,
                snapshot.active_dispatch_operation_id, snapshot.anchor) !=
               (permit.authority_id, permit.namespace,
                permit.operation_id, permit.pinned_anchor)
            or not any(effect.effect_id == permit.effect_id
                       and effect.operation_id == permit.operation_id
                       and "sha256:" + hashlib.sha256(
                           effect.footprint._json().encode("utf-8")).hexdigest()
                           == permit.footprint_digest
                       for effect in snapshot.unresolved_effects)):
        raise RuntimeError("reverse graph claim Authority snapshot differs")


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
        self.client_certificate_sha256 = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(
                profile.client_certificate.read_text(encoding="ascii"))).hexdigest()

    def claim(self, context, binding, claimed, witness, snapshot):
        return self._claim_current_channel_v1(context,binding,claimed,witness,snapshot)

    def claim_contact_v1(self, context, binding, claimed, witness, snapshot, contact_policy_capsule):
        return self._claim_current_channel_v1(context,binding,claimed,witness,snapshot,
            contact_policy_capsule=contact_policy_capsule)

    def _claim_current_channel_v1(self, context: DispatchHandoffContextV1,
              binding: ExecutionBindingV2,
              claimed: MutationReceiptV2,
              witness: OwnerDispatchWitnessV1,
              snapshot: AuthorityDispatchSnapshotV1, *, contact_policy_capsule=None) -> DispatchGraphClaimReceiptV1:
        profile = self.profile
        require_exact_reverse_handoff_identity(
            profile.namespace, context, binding, claimed,
        )
        require_exact_owner_witness(profile, context, binding, witness)
        require_exact_authority_snapshot(context, witness, snapshot)
        message = {
            "profile_id": profile.profile_id,
            "installation_id": profile.installation_id,
            "namespace": profile.namespace,
            "context": to_wire(context), "binding": to_wire(binding),
            "claimed_receipt": to_wire(claimed),
            "owner_witness": to_wire(witness),
            "authority_snapshot": to_wire(snapshot),
        }
        if contact_policy_capsule is not None:
            from .contact_p2_contract_v1 import (
                require_exact_contact_p2_policy_capsule_v1, contact_p2_policy_capsule_to_wire_v1,
            )
            require_exact_contact_p2_policy_capsule_v1(context,binding,claimed,witness,snapshot,contact_policy_capsule)
            message["contact_policy_capsule"] = contact_p2_policy_capsule_to_wire_v1(contact_policy_capsule)
        elif binding.origin.proactive_contact is True:
            raise AuthorityUnavailable("Contact reverse requires its actual current policy capsule")
        response = self._exchange(message)
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

    def _exchange(self, message):
        profile = self.profile
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
        return response

    def commit_first_owner_v1(self, message):
        from .first_owner_reverse_v1 import SCHEMA
        from .v2_owner_contract import from_wire as owner_from_wire, to_wire as owner_to_wire, OwnerGraphCommitProofV1
        if (type(message) is not dict or message.get('schema') != SCHEMA
                or message.get('namespace') != self.profile.namespace
                or message.get('profile_id') != self.profile.profile_id
                or message.get('installation_id') != self.profile.installation_id):
            raise RuntimeError('first Owner fixed reverse scope differs')
        value = json.loads(self._exchange(message))
        if type(value) is not dict or set(value) != {'proof'}:
            raise RuntimeError('first Owner reverse response fields differ')
        proof = owner_from_wire(value['proof'])
        if type(proof) is not OwnerGraphCommitProofV1 or owner_to_wire(proof) != value['proof']:
            raise RuntimeError('first Owner reverse proof is not canonical')
        return proof


__all__ = (
    "AdministratorReverseHandoffProfile", "ReverseGraphClaimClient",
    "require_exact_reverse_handoff_identity", "require_exact_owner_witness",
    "require_exact_authority_snapshot",
)
