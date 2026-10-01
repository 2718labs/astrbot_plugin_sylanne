"""The global graph catalogue includes D09's qualified natural batch type."""

import pytest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d09.natural_batch import NATURAL_BATCH_SCHEMA_V2


def test_natural_verified_batch_is_discovered_with_its_validator():
    registry = discover_domain_registry()
    spec = registry.type_registry.spec(NATURAL_BATCH_SCHEMA_V2)
    assert spec.writer_domain == "d09"
    assert spec.owner_kinds == ("activity",)
    assert spec.immutable is True
    assert spec.schema_version == 2
    with pytest.raises((TypeError, ValueError)):
        spec.validator({"schema": NATURAL_BATCH_SCHEMA_V2})
