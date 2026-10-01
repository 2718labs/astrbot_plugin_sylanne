from dataclasses import replace

import pytest

from sylanne3.domains.d03.group_audience import GroupAudienceHostReadV1
from sylanne3.runtime_contracts import NamespaceId


def _read():
    return GroupAudienceHostReadV1(
        NamespaceId("bot", "persona"), "platform", "group:one",
        "scene:group", "group:one", ("account:a", "account:b"), 2,
        "platform-generation:42", 1.0, 2.0, "atomic_complete",
    )


def test_group_host_contract_requires_complete_versioned_set():
    read = _read()
    assert read.platform_member_count == len(read.member_account_refs)
    for change in (
        {"platform_membership_version": ""},
        {"platform_member_count": 1},
        {"member_account_refs": ("account:a", "account:a")},
        {"completeness": "cached_or_partial"},
        {"valid_until_utc": 1.0},
    ):
        with pytest.raises(ValueError):
            replace(read, **change)
