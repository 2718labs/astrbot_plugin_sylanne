"""Dispatch business namespace must have one unambiguous slash boundary."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.runtime.dispatch_admission import (
    insert_admission, load_request, namespace_of,
)
from sylanne3.runtime_contracts import NamespaceId

from test_dispatch_binding_v2 import _fixture


@pytest.mark.parametrize("ambiguous", (
    "bot", "/persona", "bot/", "bot//persona", "bot/persona/extra",
))
def test_admission_rejects_ambiguous_business_namespace(ambiguous):
    receipt, _request, _permit = _fixture()
    with pytest.raises(ValueError, match="dispatch namespace"):
        replace(receipt.admission, namespace=ambiguous)
    assert namespace_of(receipt.admission) == NamespaceId("bot", "persona")


def test_valid_business_namespace_insert_and_load_is_exact():
    receipt, request, _permit = _fixture()
    db = sqlite3.connect(":memory:")
    try:
        insert_admission(db, receipt, request)
        assert load_request(db, NamespaceId("bot", "persona"),
                            receipt.admission.admission_ref) == (receipt, request)
    finally:
        db.close()
