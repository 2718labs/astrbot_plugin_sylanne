"""A message reservation selects one dimension of a shared parent lease."""

from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    _message_reservation_dimension_limit,
)


def test_message_reservation_uses_only_its_signed_dimension_from_parent():
    parent = BudgetLease(
        "lease:shared", None, "bot", "persona", "USD",
        {"cpu_ms": 200, "output_tokens": 512}, {}, {}, {}, 1, "active")

    assert _message_reservation_dimension_limit(
        parent, {"cpu_ms": 1}) == ("cpu_ms", 200)
    assert _message_reservation_dimension_limit(
        parent, {"gpu_ms": 1}) is None
    assert _message_reservation_dimension_limit(
        parent, {"cpu_ms": 201}) is None
    assert _message_reservation_dimension_limit(
        parent, {"cpu_ms": 1, "output_tokens": 1}) is None
