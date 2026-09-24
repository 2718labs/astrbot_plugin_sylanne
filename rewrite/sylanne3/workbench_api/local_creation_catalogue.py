"""Manifest-bound local D01 presets and host-verified runtime selections."""

from __future__ import annotations

from hashlib import sha256
import hmac
import json
from pathlib import Path
import re
from typing import Protocol

from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..domains.d01 import PersonaBlock, ValueRule
from ..runtime_contracts import NamespaceId
from .d01_onboarding import (
    VerifiedBudgetLease, VerifiedCreationResources, VerifiedModelCapability,
)
from .service import AuthenticatedSession


_PRESET_PATH = "resources/catalogue/d01-onboarding-presets.json"
_PRESET_SCHEMA = "sylanne.d01.onboarding-presets.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class HostModelCapabilityChecker(Protocol):
    def resolve_current_model_capability(
        self, *, namespace: NamespaceId, capability_ref: str,
    ) -> VerifiedModelCapability | None: ...


class HostBudgetChecker(Protocol):
    def resolve_current_budget_lease(
        self, *, namespace: NamespaceId, budget_ref: str,
        session: AuthenticatedSession, principal: OwnerPrincipalV1,
    ) -> VerifiedBudgetLease | None: ...


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _read_json(content: bytes) -> object:
    return json.loads(content, object_pairs_hook=_unique_object,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON number")))


class LocalCreationCatalogue:
    """Resolve only shipped, manifest-bound presets and currently available host choices."""

    def __init__(
        self,
        *,
        package_root: Path | str | None = None,
        expected_manifest_digest: str,
        model_checker: HostModelCapabilityChecker,
        budget_checker: HostBudgetChecker,
    ) -> None:
        if type(expected_manifest_digest) is not str or not _DIGEST.fullmatch(expected_manifest_digest):
            raise ValueError("pinned release manifest digest is required")
        self._root = Path(package_root) if package_root is not None else Path(__file__).resolve().parents[3]
        self._expected_manifest_digest = expected_manifest_digest
        self._models = model_checker
        self._budgets = budget_checker

    def resolve_current_resources(
        self,
        *,
        namespace: NamespaceId,
        blueprint_ref: str,
        model_capability_ref: str,
        budget_ref: str,
        session: AuthenticatedSession,
        principal: OwnerPrincipalV1,
    ) -> VerifiedCreationResources | None:
        try:
            asset = (self._root / Path(*_PRESET_PATH.split("/"))).read_bytes()
            manifest_bytes = (self._root / "release-manifest.json").read_bytes()
            if not hmac.compare_digest(sha256(manifest_bytes).hexdigest(), self._expected_manifest_digest):
                return None
            manifest = _read_json(manifest_bytes)
            if (type(manifest) is not dict or manifest.get("schema_version") != 1
                    or manifest.get("build_mode") != "formal-alpha1"
                    or type(manifest.get("files")) is not list):
                return None
            entries = [entry for entry in manifest["files"]
                       if type(entry) is dict and entry.get("path") == _PRESET_PATH]
            if (len(entries) != 1 or type(entries[0].get("bytes")) is not int
                    or entries[0]["bytes"] != len(asset)
                    or type(entries[0].get("sha256")) is not str
                    or not hmac.compare_digest(entries[0]["sha256"], sha256(asset).hexdigest())):
                return None
            data = _read_json(asset)
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
                namespace=namespace, budget_ref=budget_ref,
                session=session, principal=principal)
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
