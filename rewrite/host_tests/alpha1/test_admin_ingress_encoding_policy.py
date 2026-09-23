"""The administrator's optional encoding bounds stay outside the signed policy."""

import json
import math
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sylanne3.host.authority_client import AuthorityClientStatus
from sylanne3.host.authority_profile import (
    AdminIngressEncodingPolicy, AdminInstallationBundle, _ingress_encoding_from_payload,
    _policy_from_payload, _read_profile_json,
)
from sylanne3.host.installed_package import InstalledPackageVerification
from sylanne3.host.v2_installation import assemble_v2_installation
from sylanne3.runtime_contracts import InstallationGrantV2

from test_authority_profile import _schema2_payload


def _encoding():
    return {
        "deadline_after_seconds": 4.5,
        "quote_ceiling": {"tokens": 25},
        "snapshot_ref": "snapshot:1",
        "resource_ref": "resource:1",
        "character_interval_ref": "interval:1",
    }


@pytest.mark.parametrize("clock,encoding", [
    (False, False), (True, False), (False, True), (True, True),
])
def test_schema2_optional_combinations_parse_and_keep_policy_digest(tmp_path, clock, encoding):
    payload = _schema2_payload()
    if clock:
        payload["ingress_clock"] = {
            "source_id": "clock:1", "max_utc_error_seconds": 0.5,
            "max_round_trip_seconds": 2,
        }
    if encoding:
        payload["ingress_encoding"] = _encoding()
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = _read_profile_json(path)
    assert _policy_from_payload(loaded).digest_payload() == (
        _policy_from_payload(_schema2_payload()).digest_payload()
    )
    observed = _ingress_encoding_from_payload(loaded)
    assert (observed is not None) is encoding
    if observed is not None:
        assert observed.quote_ceiling == {"tokens": 25}


def test_encoding_is_immutable_and_snapshots_ceiling():
    source = _encoding()
    encoding = AdminIngressEncodingPolicy(**source)
    source["quote_ceiling"]["tokens"] = 99
    assert encoding.quote_ceiling["tokens"] == 25
    with pytest.raises(TypeError):
        encoding.quote_ceiling["tokens"] = 99
    with pytest.raises(FrozenInstanceError):
        encoding.snapshot_ref = "changed"


@pytest.mark.parametrize("change", [
    {"deadline_after_seconds": 0},
    {"deadline_after_seconds": -1},
    {"deadline_after_seconds": math.inf},
    {"deadline_after_seconds": math.nan},
    {"deadline_after_seconds": True},
    {"deadline_after_seconds": 10 ** 1000},
    {"quote_ceiling": {}},
    {"quote_ceiling": {"tokens": 0}},
    {"quote_ceiling": {"tokens": -1}},
    {"quote_ceiling": {"tokens": True}},
    {"quote_ceiling": {"tokens": 9_000_000_000_000_001}},
    {"quote_ceiling": {"": 1}},
    {"quote_ceiling": {str(n): 1 for n in range(33)}},
    {"snapshot_ref": " "},
    {"resource_ref": ""},
    {"character_interval_ref": None},
    {"extra": "unexpected"},
])
def test_invalid_encoding_rejected_by_real_parse(tmp_path, change):
    payload = _schema2_payload()
    payload["ingress_encoding"] = _encoding() | change
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises((TypeError, ValueError)):
        _policy_from_payload(_read_profile_json(path))


def test_schema1_rejects_encoding(tmp_path):
    payload = {
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
        "ingress_encoding": _encoding(),
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        _read_profile_json(path)


def test_encoding_requires_exact_object_and_ceiling_object():
    for encoding in (None, {}, {"quote_ceiling": {}},
                     _encoding() | {"quote_ceiling": [["tokens", 25]]}):
        payload = _schema2_payload()
        payload["ingress_encoding"] = encoding
        with pytest.raises((TypeError, ValueError)):
            _policy_from_payload(payload)


@pytest.mark.asyncio
async def test_encoding_passes_through_assembly_without_entering_grant(tmp_path):
    policy = _policy_from_payload(_schema2_payload())
    encoding = AdminIngressEncodingPolicy(**_encoding())
    profile = SimpleNamespace(
        profile_id="installed", expected_authority_id=policy.expected_authority_id,
        prepared_ssl_context=object(),
    )
    bundle = AdminInstallationBundle(profile, policy, b"k" * 32, b"d" * 32,
                                     ingress_encoding=encoding)
    grant = InstallationGrantV2(
        authority_id=policy.expected_authority_id, subject="mtls:sha256:peer",
        administrator_holder=policy.administrator_holder,
        installation_id=policy.installation_id, manifest_digest=policy.manifest_digest,
        publisher_policy_ref="publisher-policy", service_capability_version="v2",
        channel_binding_sha256="b" * 64,
    )
    transport = MagicMock(close=AsyncMock())
    client = MagicMock(
        status_v2=AsyncMock(return_value=AuthorityClientStatus("paired", policy.expected_authority_id)),
        installation_grant_v2=AsyncMock(return_value=grant),
    )
    package = InstalledPackageVerification(True, "verified", policy.manifest_digest,
                                           "3.0.0-alpha1", "formal-alpha1")
    with (patch("sylanne3.host.v2_installation.load_admin_installation_bundle", return_value=bundle),
          patch("sylanne3.host.v2_installation.verify_installed_package", return_value=package),
          patch("sylanne3.host.v2_installation.MtlsAuthorityTransport", return_value=transport),
          patch("sylanne3.host.v2_installation.AuthorityClient", return_value=client)):
        assembly = await assemble_v2_installation(
            "installed", package_root=tmp_path / "package", data_dir=tmp_path / "data",
        )
    assert assembly.ingress_encoding is encoding
    assert assembly.ingress_clock is None
    assert "ingress_encoding" not in grant.__dataclass_fields__
    transport.close.assert_awaited_once()
