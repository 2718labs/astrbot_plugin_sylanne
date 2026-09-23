"""The delivery check accepts only the quarantined legacy preview declaration."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.alpha1.verify_delivery_assets import verify_migration_preview


RESOURCE = Path(__file__).resolve().parents[4] / "resources" / "migrations" / "v1.json"


def test_registered_preview_resource_passes_delivery_check() -> None:
    verify_migration_preview(json.loads(RESOURCE.read_text(encoding="utf-8")))


@pytest.mark.parametrize("change", [
    ("release_eligibility", "READY"),
    ("legacy_data_policy", "adopt_all_legacy_data"),
    ("activation", "validated"),
    ("source_revision", "unverified-revision"),
    ("mapping", {"legacy_affinity": "trust"}),
])
def test_delivery_check_rejects_preview_promotion_or_source_drift(change: tuple[str, object]) -> None:
    declaration = json.loads(RESOURCE.read_text(encoding="utf-8"))
    field, value = change
    target = declaration["migrations"][0] if field in declaration["migrations"][0] else declaration
    target[field] = value
    with pytest.raises(ValueError, match="activation-prohibited"):
        verify_migration_preview(declaration)


def test_delivery_check_rejects_a_second_unreviewed_migrator() -> None:
    declaration = json.loads(RESOURCE.read_text(encoding="utf-8"))
    declaration["migrations"].append(deepcopy(declaration["migrations"][0]))
    with pytest.raises(ValueError, match="activation-prohibited"):
        verify_migration_preview(declaration)
