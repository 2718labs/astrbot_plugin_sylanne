"""Administrator clock policy stays local to installation assembly."""

import json
import math
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sylanne3.host.authority_client import AuthorityClientStatus
from sylanne3.host.authority_profile import (
    AdminIngressClockPolicy, AdminInstallationBundle, _ingress_clock_from_payload,
    _policy_from_payload, _read_profile_json,
)
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_installation import assemble_v2_installation
from sylanne3.runtime_contracts import InstallationGrantV2

from test_authority_profile import _schema2_payload


def test_schema2_clock_policy_is_optional_and_does_not_change_policy_digest(tmp_path):
    old = _schema2_payload()
    new = _schema2_payload()
    new["ingress_clock"] = {
        "source_id": "admin:ntp-a", "max_utc_error_seconds": 0.5,
        "max_round_trip_seconds": 2,
    }
    profile_file = tmp_path / "profile.json"
    profile_file.write_text(json.dumps(new), encoding="utf-8")
    loaded = _read_profile_json(profile_file)
    clock = _ingress_clock_from_payload(loaded)
    assert clock == AdminIngressClockPolicy("admin:ntp-a", 0.5, 2)
    assert _ingress_clock_from_payload(old) is None
    assert _policy_from_payload(loaded).digest_payload() == _policy_from_payload(old).digest_payload()
    with pytest.raises(FrozenInstanceError):
        clock.source_id = "changed"


@pytest.mark.parametrize("clock", [
    None, {}, {"source_id": "x", "max_utc_error_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": 1, "max_round_trip_seconds": 1,
     "extra": 1},
    {"source_id": " ", "max_utc_error_seconds": 1, "max_round_trip_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": 0, "max_round_trip_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": -1, "max_round_trip_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": True, "max_round_trip_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": math.inf, "max_round_trip_seconds": 1},
    {"source_id": "x", "max_utc_error_seconds": 1, "max_round_trip_seconds": math.nan},
])
def test_invalid_clock_policy_fails_profile_policy_load(clock):
    payload = _schema2_payload()
    payload["ingress_clock"] = clock
    with pytest.raises((TypeError, ValueError)):
        _policy_from_payload(payload)


def test_schema1_cannot_carry_clock(tmp_path):
    payload = {
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org", "expected_authority_id": "authority",
        "ingress_clock": {"source_id": "x", "max_utc_error_seconds": 1,
                          "max_round_trip_seconds": 1},
    }
    profile_file = tmp_path / "profile.json"
    profile_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        _read_profile_json(profile_file)


@pytest.mark.asyncio
async def test_clock_policy_reaches_v2_assembly_without_entering_grant(tmp_path):
    digest = "a" * 64
    policy = _policy_from_payload(_schema2_payload())
    profile = SimpleNamespace(
        profile_id="installed", expected_authority_id=policy.expected_authority_id,
        prepared_ssl_context=object(),
    )
    clock = AdminIngressClockPolicy("admin:ntp-a", 0.5, 2)
    bundle = AdminInstallationBundle(profile, policy, b"k" * 32, b"d" * 32, clock)
    grant = InstallationGrantV2(
        authority_id=policy.expected_authority_id, subject="mtls:sha256:peer",
        administrator_holder=policy.administrator_holder,
        installation_id=policy.installation_id, manifest_digest=digest,
        publisher_policy_ref="publisher-policy", service_capability_version="v2",
        channel_binding_sha256="b" * 64,
    )
    transport = MagicMock(close=AsyncMock())
    client = MagicMock(
        status_v2=AsyncMock(return_value=AuthorityClientStatus("paired", policy.expected_authority_id)),
        installation_grant_v2=AsyncMock(return_value=grant),
    )
    package = InstalledPackageVerification(True, "verified", digest, "3.0.0-alpha1", "formal-alpha1")
    with (patch("sylanne3.host.v2_installation.load_admin_installation_bundle", return_value=bundle),
          patch("sylanne3.host.v2_installation.verify_installed_package", return_value=package),
          patch("sylanne3.host.v2_installation.MtlsAuthorityTransport", return_value=transport),
          patch("sylanne3.host.v2_installation.AuthorityClient", return_value=client)):
        assembly = await assemble_v2_installation(
            "installed", package_root=tmp_path / "package", data_dir=tmp_path / "data",
        )
    assert assembly.ingress_clock is clock
    assert assembly.installation_policy.digest_payload() == policy.digest_payload()
    assert "ingress_clock" not in grant.__dataclass_fields__
    transport.close.assert_awaited_once()
