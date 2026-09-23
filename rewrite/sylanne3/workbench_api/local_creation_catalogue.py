"""Manifest-bound local D01 presets and host-verified runtime selections."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Protocol

from ..domains.d01 import PersonaBlock, ValueRule
from ..runtime_contracts import NamespaceId
from .d01_onboarding import (
    VerifiedBudgetLease, VerifiedCreationResources, VerifiedModelCapability,
)


_PRESET_PATH = "resources/catalogue/d01-onboarding-presets.json"
_PRESET_SCHEMA = "sylanne.d01.onboarding-presets.v1"


class HostModelCapabilityChecker(Protocol):
    def resolve_current_model_capability(
        self, *, namespace: NamespaceId, capability_ref: str,
    ) -> VerifiedModelCapability | None: ...


class HostBudgetChecker(Protocol):
    def resolve_current_budget_lease(
        self, *, namespace: NamespaceId, budget_ref: str,
    ) -> VerifiedBudgetLease | None: ...


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON number")))


class LocalCreationCatalogue:
    """Resolve only shipped, manifest-bound presets and currently available host choices."""

    def __init__(
        self,
        *,
        package_root: Path | str | None = None,
        model_checker: HostModelCapabilityChecker,
        budget_checker: HostBudgetChecker,
    ) -> None:
        self._root = Path(package_root) if package_root is not None else Path(__file__).resolve().parents[3]
        self._models = model_checker
        self._budgets = budget_checker

    def resolve_current_resources(
        self,
        *,
        namespace: NamespaceId,
        blueprint_ref: str,
        model_capability_ref: str,
        budget_ref: str,
    ) -> VerifiedCreationResources | None:
        try:
            asset = (self._root / Path(*_PRESET_PATH.split("/"))).read_bytes()
            manifest = _read_json(self._root / "release-manifest.json")
            if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
                return None
            entries = [entry for entry in manifest["files"]
                       if isinstance(entry, dict) and entry.get("path") == _PRESET_PATH]
            if len(entries) != 1 or entries[0].get("sha256") != sha256(asset).hexdigest():
                return None
            data = json.loads(asset.decode("utf-8"), object_pairs_hook=_unique_object)
            if (not isinstance(data, dict) or set(data) != {"schema", "blueprints"}
                    or data["schema"] != _PRESET_SCHEMA
                    or not isinstance(data["blueprints"], list)):
                return None
            selected = [item for item in data["blueprints"]
                        if isinstance(item, dict) and item.get("blueprint_ref") == blueprint_ref]
            if len(selected) != 1:
                return None
            model = self._models.resolve_current_model_capability(
                namespace=namespace, capability_ref=model_capability_ref)
            budget = self._budgets.resolve_current_budget_lease(
                namespace=namespace, budget_ref=budget_ref)
            if (not isinstance(model, VerifiedModelCapability)
                    or model.namespace != namespace
                    or model.capability_ref != model_capability_ref
                    or not isinstance(budget, VerifiedBudgetLease)
                    or budget.namespace != namespace
                    or budget.budget_ref != budget_ref):
                return None
            preset = selected[0]
            if set(preset) != {"blueprint_ref", "version", "label", "description", "blocks", "values"}:
                return None
            if (type(preset["version"]) is not int or preset["version"] < 1
                    or not isinstance(preset["blocks"], list)
                    or not isinstance(preset["values"], list)):
                return None
            blocks = tuple(PersonaBlock(**item) for item in preset["blocks"])
            values = tuple(ValueRule(
                **{**item, "applies_to": tuple(item["applies_to"]),
                   "supports_candidates": tuple(item["supports_candidates"]),
                   "rejects_candidates": tuple(item["rejects_candidates"])}
            ) for item in preset["values"])
            return VerifiedCreationResources(
                namespace, blueprint_ref, model_capability_ref, budget_ref,
                preset["version"], "sha256:" + sha256(asset).hexdigest(),
                blocks, values, model, budget,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError,
                TypeError, KeyError, AttributeError):
            return None


__all__ = ("LocalCreationCatalogue", "HostModelCapabilityChecker", "HostBudgetChecker")
