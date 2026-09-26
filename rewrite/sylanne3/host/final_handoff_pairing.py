"""Match an authenticated Authority P2 pairing read to local reverse TLS trust."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import ssl

from ..authority_service.final_handoff_pairing import FinalHandoffPairingV1, SCHEMA
from .reverse_handoff import AdministratorHostReverseProfile
from .v2_installation import V2InstallationAssembly


_PUBLIC_FIELDS = frozenset({
    "authority_id", "namespace", "installation_id", "issuer_id",
    "reverse_profile_id", "reverse_host", "reverse_port",
    "reverse_server_name", "reverse_expected_host_certificate_sha256",
    "reverse_client_certificate_sha256", "installation_manifest_digest",
})
_FIELDS = _PUBLIC_FIELDS | {"configuration_digest", "schema"}


@dataclass(frozen=True, slots=True)
class TrustedFinalHandoffBindingV1:
    """Local administrator-approved endpoint and reverse server credentials."""

    profile: AdministratorHostReverseProfile
    listen_host: str
    endpoint_host: str
    port: int
    server_name: str

    def __post_init__(self) -> None:
        if type(self.profile) is not AdministratorHostReverseProfile:
            raise TypeError("local reverse profile required")
        if any(type(value) is not str or not value or len(value) > 255
               for value in (self.listen_host, self.endpoint_host, self.server_name)):
            raise ValueError("local reverse endpoint is invalid")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("local reverse port is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedFinalHandoffPairingV1:
    issuer_id: str
    binding: TrustedFinalHandoffBindingV1
    configuration_digest: str


def _certificate_sha256(path: Path) -> str:
    """Hash the first PEM certificate's full DER bytes, as Authority does."""
    pem = path.read_text(encoding="ascii")
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start = pem.find(begin)
    stop = pem.find(end, start + len(begin))
    if start < 0 or stop < 0:
        raise ValueError("local reverse certificate is not PEM")
    der = ssl.PEM_cert_to_DER_cert(pem[start:stop + len(end)])
    return hashlib.sha256(der).hexdigest()


def verify_final_handoff_pairing_v1(
    authenticated_read: object,
    installation: V2InstallationAssembly,
    binding: TrustedFinalHandoffBindingV1,
) -> VerifiedFinalHandoffPairingV1:
    """Reject either a different Authority configuration or local endpoint.

    The caller must obtain ``authenticated_read`` through the installed,
    paired mTLS transport. A caller-supplied dictionary is never an Authority
    credential by itself; this function checks only its content binding.
    """
    if type(authenticated_read) is FinalHandoffPairingV1:
        authenticated_read = authenticated_read.to_wire()
    if (type(installation) is not V2InstallationAssembly
            or type(binding) is not TrustedFinalHandoffBindingV1
            or type(authenticated_read) is not dict
            or set(authenticated_read) != _FIELDS):
        raise ValueError("complete authenticated P2 pairing read required")
    value = authenticated_read
    if (value["schema"] != SCHEMA
            or any(type(value[key]) is not str or not value[key]
                   for key in _PUBLIC_FIELDS - {"reverse_port"})
            or type(value["reverse_port"]) is not int
            or not 1 <= value["reverse_port"] <= 65535
            or type(value["configuration_digest"]) is not str):
        raise ValueError("P2 pairing fields are invalid")
    public = {key: value[key] for key in _PUBLIC_FIELDS}
    digest = hashlib.sha256(json.dumps(
        public, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()
    if value["configuration_digest"] != digest:
        raise ValueError("Authority P2 configuration digest differs")
    policy = installation.installation_policy
    grant = installation.installation_grant
    profile = binding.profile
    if ((value["authority_id"], value["namespace"], value["installation_id"],
         value["installation_manifest_digest"]) !=
        (grant.authority_id, policy.authority_namespace, grant.installation_id,
         grant.manifest_digest)
            or (profile.namespace, profile.installation_id)
            != (policy.authority_namespace, grant.installation_id)
            or (value["reverse_profile_id"], value["reverse_host"],
                value["reverse_port"], value["reverse_server_name"])
            != (profile.profile_id, binding.endpoint_host,
                binding.port, binding.server_name)
            or value["reverse_expected_host_certificate_sha256"]
            != _certificate_sha256(profile.certificate)
            or value["reverse_client_certificate_sha256"]
            != profile.expected_authority_certificate_sha256):
        raise ValueError("Authority P2 pairing differs from local reverse trust")
    return VerifiedFinalHandoffPairingV1(
        value["issuer_id"], binding, value["configuration_digest"])


__all__ = (
    "TrustedFinalHandoffBindingV1", "VerifiedFinalHandoffPairingV1",
    "verify_final_handoff_pairing_v1",
)
