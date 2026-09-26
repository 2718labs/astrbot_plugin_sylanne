"""The authenticated Authority pairing must match independent host TLS trust."""

from dataclasses import replace
import hashlib
import ssl
from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as certificate_support
from sylanne3.authority_service.final_handoff_pairing import FinalHandoffPairingV1
from sylanne3.host.final_handoff_pairing import (
    TrustedFinalHandoffBindingV1, verify_final_handoff_pairing_v1,
)
from sylanne3.host.reverse_handoff import AdministratorHostReverseProfile
from sylanne3.host.v2_installation import V2InstallationAssembly


def _sha256(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        path.read_text(encoding="ascii"))).hexdigest()


def _pairing(tmp_path):
    files = certificate_support.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    profile = AdministratorHostReverseProfile(
        profile_id="profile-a", installation_id="installation-a",
        namespace="ns-a", expected_authority_certificate_sha256=_sha256(files["client.pem"]),
        certificate=files["server.pem"], private_key=files["server.key"],
        authority_trust_root=files["ca.pem"],
    )
    binding = TrustedFinalHandoffBindingV1(
        profile, "127.0.0.1", "127.0.0.1", 41234, "localhost")
    installation = V2InstallationAssembly(
        SimpleNamespace(authority_namespace="ns-a"),
        SimpleNamespace(authority_id="authority-a", installation_id="installation-a",
                        manifest_digest="a" * 64),
        b"d" * 32, b"e" * 32, object, tmp_path, tmp_path,
    )
    public = dict(
        authority_id="authority-a", namespace="ns-a",
        installation_id="installation-a", issuer_id="issuer-a",
        reverse_profile_id="profile-a", reverse_host="127.0.0.1",
        reverse_port=41234, reverse_server_name="localhost",
        reverse_expected_host_certificate_sha256=_sha256(files["server.pem"]),
        reverse_client_certificate_sha256=_sha256(files["client.pem"]),
        installation_manifest_digest="a" * 64,
    )
    pairing = FinalHandoffPairingV1(
        **public,
        configuration_digest=FinalHandoffPairingV1.digest_public_fields(public))
    return installation, binding, pairing, files


def test_pairing_matches_both_real_certificates_and_installed_endpoint(tmp_path):
    installation, binding, pairing, _ = _pairing(tmp_path)
    result = verify_final_handoff_pairing_v1(pairing, installation, binding)
    assert result.issuer_id == "issuer-a"
    assert result.binding is binding
    assert result.configuration_digest == pairing.configuration_digest


def test_pairing_rejects_endpoint_and_certificate_drift(tmp_path):
    installation, binding, pairing, files = _pairing(tmp_path)
    with pytest.raises(ValueError, match="local reverse trust"):
        verify_final_handoff_pairing_v1(
            pairing, installation,
            replace(binding, port=binding.port + 1))
    other = replace(binding.profile, certificate=files["second.pem"])
    with pytest.raises(ValueError, match="local reverse trust"):
        verify_final_handoff_pairing_v1(pairing, installation, replace(binding, profile=other))
    with pytest.raises(ValueError, match="configuration digest"):
        verify_final_handoff_pairing_v1(
            {**pairing.to_wire(), "issuer_id": "attacker"}, installation, binding)
