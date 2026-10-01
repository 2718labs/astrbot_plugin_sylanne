"""Schema-2 D04 semantic-drive policy is installed and root-grant bound."""

from copy import deepcopy

import pytest

from sylanne3.domains.d04.numeric_coupling import SCHEME_VERSION
from sylanne3.host.authority_profile import _policy_from_payload
from sylanne3.native_runtime.d04_semantic_drive_candidate import MAPPING_VERSION, MECHANISMS
from sylanne3.runtime.d04_semantic_policy import WORK_KIND


def _profile(*, allowed=True):
    work_kinds = [WORK_KIND] if allowed else ["d06.encode_source"]
    return {
        "schema": 2, "host": "authority.example", "port": 443,
        "server_name": "authority.example", "expected_authority_id": "authority",
        "installation_policy": {
            "namespace": {"bot_id": "bot", "persona_id": "persona"},
            "authority_namespace": "opaque", "installation_id": "install",
            "manifest_digest": "a" * 64, "administrator_holder": "admin",
            "expected_authority_id": "authority", "catalogue_hash": "b" * 64,
            "scheme_version": "scheme", "operator_version": "operator",
            "policy_version": "policy",
            "root_lease": {
                "lease_id": "lease", "parent_id": None, "bot_id": "bot",
                "persona_id": "persona", "currency": "USD",
                "limits": {"cpu_ms": 100}, "used": {}, "reserved": {},
                "unconfirmed": {}, "version": 1, "state": "active",
            },
            "root_grant": {
                "grant_id": "grant", "version": 1, "bot_id": "bot",
                "persona_id": "persona", "lease_id": "lease", "currency": "USD",
                "max_ceiling": {"cpu_ms": 100}, "allowed_work_kinds": work_kinds,
                "valid_until_utc": 2000.0, "policy_ref": "admin-policy",
            },
        },
        "d04_semantic_drive": {
            "version": 1, "mapping_version": MAPPING_VERSION,
            "basis_version": SCHEME_VERSION,
            "mechanism_max_abs_doses": {name: [0.6, 0.3, 0.2]
                                         for name in MECHANISMS},
            "mechanism_max_family_share": {name: 0.75 for name in MECHANISMS},
        },
    }


def test_schema2_policy_binds_installed_namespace_installation_and_grant():
    installation = _policy_from_payload(_profile())
    from sylanne3.host.authority_profile import _d04_semantic_drive_from_payload

    d04 = _d04_semantic_drive_from_payload(_profile(), installation)
    assert d04 is not None
    assert d04.namespace == installation.namespace
    assert d04.installation_id == installation.installation_id
    assert (d04.grant_id, d04.grant_version, d04.lease_id) == (
        installation.root_grant.grant_id, installation.root_grant.version,
        installation.root_lease.lease_id,
    )
    assert len(d04.axes) == 24
    d04.validate_share("gain_engagement", (-0.6, 0.3, 0.0), 0.75)
    with pytest.raises(ValueError, match="layer dose"):
        d04.validate_share("gain_engagement", (-0.61, 0.0, 0.0), 0.2)
    with pytest.raises(ValueError, match="family share"):
        d04.validate_share("gain_engagement", (0.1, 0.0, 0.0), 0.76)


@pytest.mark.parametrize("mutate", [
    lambda p: p["d04_semantic_drive"].update(extra=True),
    lambda p: p["d04_semantic_drive"]["mechanism_max_abs_doses"]["gain_engagement"].append(0.1),
    lambda p: p["d04_semantic_drive"]["mechanism_max_family_share"].pop("gain_engagement"),
    lambda p: p["d04_semantic_drive"].update(mapping_version="unregistered"),
    lambda p: p["d04_semantic_drive"]["mechanism_max_abs_doses"].update(
        gain_engagement=[1.01, 0.0, 0.0]),
])
def test_policy_rejects_unknown_or_out_of_range_fields(mutate):
    profile = deepcopy(_profile())
    mutate(profile)
    with pytest.raises((TypeError, ValueError)):
        _policy_from_payload(profile)


def test_policy_rejects_non_numeric_dose_values_and_remains_optional():
    profile = _profile()
    profile["d04_semantic_drive"]["mechanism_max_abs_doses"][
        "gain_engagement"] = ["0.5", 0.3, 0.2]
    with pytest.raises(ValueError, match="three dose limits"):
        _policy_from_payload(profile)

    profile = _profile()
    profile.pop("d04_semantic_drive")
    installation = _policy_from_payload(profile)
    from sylanne3.host.authority_profile import _d04_semantic_drive_from_payload

    assert _d04_semantic_drive_from_payload(profile, installation) is None


def test_policy_requires_explicit_root_grant_work_kind():
    with pytest.raises(ValueError, match="explicit root grant work kind"):
        _policy_from_payload(_profile(allowed=False))
