"""D13 technical work is opt-in and priced by the installed D11 budget."""

from __future__ import annotations

from copy import deepcopy

import pytest

from test_authority_profile import _schema2_payload, authority_profile


def _d13_payload() -> dict[str, object]:
    payload = _schema2_payload()
    root = payload["installation_policy"]
    root["root_grant"]["allowed_work_kinds"].append("d13.precompress")
    root["root_grant"]["max_ceiling"]["d13_compute_units"] = 1
    root["root_lease"]["limits"]["d13_compute_units"] = 8
    payload["d13_precompression"] = {
        "history_token_budget": 8192,
        "quote_ceiling": {"d13_compute_units": 1},
        "deadline_after_seconds": 30,
        "max_slots": 32,
        "resource_ref": "d13-deterministic-v1",
    }
    return payload


def test_d13_precompression_profile_is_bound_to_installed_root_budget() -> None:
    assert authority_profile._d13_precompression_from_payload(
        _schema2_payload(), authority_profile._policy_from_payload(
            _schema2_payload())) is None

    payload = _d13_payload()
    root = authority_profile._policy_from_payload(payload)
    policy = authority_profile._d13_precompression_from_payload(payload, root)
    assert policy.namespace == root.namespace
    assert policy.installation_id == root.installation_id
    assert policy.grant_id == root.root_grant.grant_id
    assert policy.grant_version == root.root_grant.version
    assert policy.lease_id == root.root_lease.lease_id
    assert policy.quote_ceiling == {"d13_compute_units": 1}

    no_kind = deepcopy(payload)
    no_kind["installation_policy"]["root_grant"]["allowed_work_kinds"].remove(
        "d13.precompress")
    with pytest.raises(ValueError, match="root grant work kind"):
        authority_profile._policy_from_payload(no_kind)

    over_budget = deepcopy(payload)
    over_budget["installation_policy"]["root_grant"]["max_ceiling"].pop(
        "d13_compute_units")
    with pytest.raises(ValueError, match="signed root budget"):
        authority_profile._policy_from_payload(over_budget)

    inflated_quote = deepcopy(payload)
    inflated_quote["d13_precompression"]["quote_ceiling"]["d13_compute_units"] = 2
    with pytest.raises(ValueError, match="one technical compute unit"):
        authority_profile._policy_from_payload(inflated_quote)


def test_d13_precompression_profile_rejects_uninstalled_fields() -> None:
    payload = _d13_payload()
    payload["d13_precompression"]["model_assist"] = True
    with pytest.raises(ValueError):
        authority_profile._policy_from_payload(payload)
