"""Derive D12 public views from the live domain registry.

Providers opt in by exposing ``workbench_view_contract`` as either a mapping
or a zero-argument callable. A view with ``projection_context`` set to
``d12.projection_context.v1`` receives the server-resolved authority, audience,
and purpose as a keyword-only ``context`` argument to ``project_workbench``.
Absent metadata is intentionally not inferred from graph AtomTypes: a state,
cache, or source type is not automatically safe to put in the workbench.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping

from ..domain_registry import DomainRegistry, discover_domain_registry
from ..runtime_contracts import AuthorityContext


PROJECTION_CONTEXT_V1 = "d12.projection_context.v1"


@dataclass(frozen=True)
class ProjectionContextV1:
    authority: AuthorityContext
    audience: str
    purpose: str
    schema_version: str = PROJECTION_CONTEXT_V1


@dataclass(frozen=True)
class ViewCatalogue:
    available: Mapping[str, tuple[str, ...]]
    unavailable_domains: Mapping[str, str]


@dataclass(frozen=True)
class _ViewDefinition:
    domain: str
    types: tuple[str, ...]
    owner_kind: str
    fields: frozenset[str]
    projector: Callable[..., object]
    context_version: str | None


class CurrentDomainViewRegistry:
    """A fail-closed adapter over ``discover_domain_registry()``.

    It does not add metadata to existing providers.  Until a provider declares
    its public projection contract, that domain remains unavailable to D12.
    """

    def __init__(self, discover: Callable[[], DomainRegistry] = discover_domain_registry) -> None:
        if not callable(discover):
            raise TypeError("discover must be callable")
        self._discover = discover

    def _definitions(self, authority: AuthorityContext) -> tuple[dict[str, _ViewDefinition], dict[str, str]]:
        if not isinstance(authority, AuthorityContext):
            raise TypeError("authority required")
        registry = self._discover()
        if not isinstance(registry, DomainRegistry):
            raise TypeError("discover did not return DomainRegistry")
        definitions: dict[str, _ViewDefinition] = {}
        unavailable = dict(registry.unavailable)
        for domain, registration in registry.registrations.items():
            contract = getattr(registration.provider, "workbench_view_contract", None)
            if callable(contract):
                try:
                    contract = contract()
                except Exception:
                    unavailable[domain] = "public_projection_contract_failed"
                    continue
            if contract is None:
                unavailable[domain] = "no_public_projection_contract"
                continue
            projector = getattr(registration.provider, "project_workbench", None)
            if not callable(projector):
                unavailable[domain] = "no_field_projection_contract"
                continue
            specs_by_name = {spec.name: spec for spec in registration.type_specs}
            if not isinstance(contract, Mapping):
                unavailable[domain] = "invalid_public_projection_contract"
                continue
            validated: dict[str, _ViewDefinition] = {}
            scope_denied = False
            try:
                for view_name, definition in contract.items():
                    if not isinstance(definition, Mapping):
                        raise ValueError
                    names = tuple(definition.get("types", ()))
                    fields = frozenset(definition.get("fields", ()))
                    context_version = definition.get("projection_context")
                    if (not isinstance(view_name, str) or not view_name or not names or not fields
                            or context_version not in (None, PROJECTION_CONTEXT_V1)
                            or len(set(names)) != len(names)
                            or any(not isinstance(name, str) or name not in specs_by_name
                                   for name in names)
                            or any(not isinstance(field, str) or not field or field == "atoms"
                                   for field in fields)
                            or view_name in definitions or view_name in validated):
                        raise ValueError
                    owner_kinds = {kind for name in names
                                   for kind in specs_by_name[name].owner_kinds}
                    if len(owner_kinds) != 1:
                        raise ValueError
                    owner_kind = owner_kinds.pop()
                    if owner_kind not in authority.owner_scope:
                        scope_denied = True
                        continue
                    validated[view_name] = _ViewDefinition(
                        domain, names, owner_kind, fields, projector, context_version)
            except (TypeError, ValueError):
                unavailable[domain] = "invalid_public_projection_contract"
                continue
            if not validated:
                unavailable[domain] = ("owner_scope_denied" if scope_denied
                                       else "empty_public_projection_contract")
                continue
            definitions.update(validated)
        return definitions, unavailable

    def catalogue(self, authority: AuthorityContext) -> ViewCatalogue:
        definitions, unavailable = self._definitions(authority)
        return ViewCatalogue({name: definition.types for name, definition in sorted(definitions.items())},
                             dict(sorted(unavailable.items())))

    def view_types(self, authority: AuthorityContext) -> Mapping[str, tuple[str, ...]]:
        return self.catalogue(authority).available

    def view_owner_kind(self, authority: AuthorityContext, view_type: str) -> str | None:
        definitions, _ = self._definitions(authority)
        definition = definitions.get(view_type)
        return definition.owner_kind if definition is not None else None

    def projection_context_version(self, authority: AuthorityContext,
                                   view_type: str) -> str | None:
        definitions, _ = self._definitions(authority)
        definition = definitions.get(view_type)
        if definition is None:
            raise LookupError("view is not publicly projected")
        return definition.context_version

    def project_workbench(self, authority: AuthorityContext, view_type: str,
                          atoms: tuple[Mapping[str, Any], ...], *,
                          audience: str | None = None,
                          purpose: str | None = None) -> Mapping[str, Any]:
        definitions, _ = self._definitions(authority)
        definition = definitions.get(view_type)
        if definition is None:
            raise LookupError("view is not publicly projected")
        if any(atom.get("type") not in definition.types for atom in atoms):
            raise ValueError("projection input crosses its declared types")
        if definition.context_version == PROJECTION_CONTEXT_V1:
            if (not isinstance(audience, str) or audience not in authority.audience
                    or purpose != authority.purpose):
                raise PermissionError("projection context does not match authority")
            result = definition.projector(
                view_type, atoms,
                context=ProjectionContextV1(authority, audience, purpose))
        else:
            result = definition.projector(view_type, atoms)
        if not isinstance(result, Mapping) or set(result) - definition.fields:
            raise ValueError("projection output exceeds declared fields")
        try:
            json.dumps(result, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("projection output is not JSON-safe") from exc
        return dict(result)


__all__ = ("CurrentDomainViewRegistry", "ViewCatalogue", "ProjectionContextV1",
           "PROJECTION_CONTEXT_V1")
