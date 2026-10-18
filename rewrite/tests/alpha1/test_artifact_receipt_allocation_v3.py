"""Permanent pure contracts for the independent Artifact message allocation.

No fixture database, provider, Sender, filesystem asset or Authority is invoked.
"""
from dataclasses import replace
import pytest

from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.foreground_call_plan_v1 import foreground_reply_budget_ids_v1
from sylanne3.runtime.artifact_receipt_allocation_v3 import (
    ForegroundArtifactReceiptAllocationV3, foreground_artifact_receipt_budget_ids_v3,
)


def _allocation():
    namespace = NamespaceId("receipt-bot", "receipt-persona")
    quote = (("message_bytes", 2048), ("message_microusd", 17))
    ids = foreground_artifact_receipt_budget_ids_v3(namespace, "c02-receipt")
    return ForegroundArtifactReceiptAllocationV3(
        namespace=namespace, c02_operation_id="c02-receipt",
        source_ref=source_key(*namespace.as_tuple, "receipt-source").token,
        responsibility_digest="1" * 64, installation_id="receipt-installation", manifest_digest="2" * 64,
        observer_policy_ref="/protected/observer.json", observer_policy_digest="3" * 64,
        parent_lease_ref="installed-root", parent_version=7, parent_state_digest="4" * 64,
        parent_grant_digest="5" * 64, message_policy_digest="6" * 64,
        child_lease_id=ids[0], child_grant_id=ids[1], allocation_operation_id=ids[2],
        currency="USD", valid_until_utc=1900000000.0,
        message_ceiling=quote, child_limits=quote, child_max_ceiling=quote)


def test_artifact_receipt_preserves_one_complete_message_quote():
    allocation = _allocation()
    assert allocation.child_lease().limits == dict(allocation.message_ceiling)
    grant = allocation.child_grant()
    assert grant.max_ceiling == dict(allocation.message_ceiling)
    assert grant.allowed_work_kinds == ("message",)
    assert grant.valid_until_utc == allocation.valid_until_utc


def test_artifact_receipt_has_separate_c02_and_natural_identities():
    allocation = _allocation()
    actual = (allocation.child_lease_id, allocation.child_grant_id, allocation.allocation_operation_id)
    assert actual != foreground_reply_budget_ids_v1(allocation.namespace, allocation.c02_operation_id)
    assert actual != foreground_artifact_receipt_budget_ids_v3(allocation.namespace, "c02-other")
    assert actual != foreground_artifact_receipt_budget_ids_v3(NamespaceId("other-bot", "receipt-persona"), allocation.c02_operation_id)


@pytest.mark.parametrize("change", [
    {"allowed_work_kinds": ("message", "natural_generation")},
    {"allowed_work_kinds": ("message", "natural_review")},
    {"message_slots": 4},
    {"child_lease_id": "borrowed-natural-child"},
    {"schema": "d11.foreground-reply-allocation.v1"},
    {"child_limits": (("message_bytes", 2048),)},
    {"child_max_ceiling": (("message_bytes", 2048),)},
    {"message_ceiling": (("message_bytes", 2048), ("message_microusd", 0))},
])
def test_artifact_receipt_rejects_natural_upgrade_and_incomplete_quote(change):
    with pytest.raises(ValueError):
        replace(_allocation(), **change)
