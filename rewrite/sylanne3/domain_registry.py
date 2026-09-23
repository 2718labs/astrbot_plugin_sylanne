from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import MappingProxyType

from .graph_types import TypeRegistry, TypeSpec


REQUIRED_DOMAINS = tuple(f"d{number:02d}" for number in range(1, 13))

_PROVIDERS = {
    "d01": (".domains.d01", "PersonaDomain", "d01.proposal.v1"),
    "d02": (".domains.d02", "BodyDomain", "d02.proposal.v1"),
    "d03": (".domains.d03", "ContextProvider", "d03.proposal.v1"),
    "d04": (".domains.d04", "AffectProvider", "d04.proposal.v1"),
    "d05": (".domains.d05", "RelationshipProvider", "d05.proposal.v1"),
    "d06": (".domains.d06", "D06DomainProvider", "d06.contract.v1"),
    "d07": (".domains.d07", "D07DomainProvider", "d07.proposal.v1"),
    "d08": (".domains.d08", "GoalExecutionProvider", "d08.proposal.v1"),
    "d09": (".domains.d09", "D09ExpressionProvider", "d09.proposal.v1"),
    "d10": (".domains.d10", "LifeDomain", "d10.proposal.v1"),
    "d11": (".runtime.d11_types", "D11RuntimeProvider", "d11.runtime.proposal.v1"),
    "d12": (".domains.d12", "D12DomainProvider", "d12.proposal.v1"),
}


@dataclass(frozen=True)
class DomainRegistration:
    domain: str
    provider: object
    proposal_schema: str
    proposal_schema_hash: str
    type_specs: tuple[TypeSpec, ...]


@dataclass(frozen=True)
class DomainRegistry:
    registrations: object
    unavailable: object
    type_registry: TypeRegistry
    required_domains: tuple[str, ...] = REQUIRED_DOMAINS

    @property
    def complete(self) -> bool:
        return not self.unavailable and tuple(sorted(self.registrations)) == self.required_domains


def _concrete_specs(provider: object) -> tuple[TypeSpec, ...]:
    method = getattr(provider, "type_specs", None)
    if not callable(method):
        method = getattr(provider, "register_types", None)
    if not callable(method):
        raise TypeError("provider exports no type specification function")
    raw = tuple(method())
    converted = []
    for item in raw:
        if isinstance(item, TypeSpec):
            converted.append(item)
        elif callable(getattr(item, "to_graph_spec", None)):
            converted.append(item.to_graph_spec())
        else:
            raise TypeError("provider returned names instead of concrete TypeSpec values")
    if not converted:
        raise ValueError("provider exports no graph types")
    return tuple(converted)


def discover_domain_registry() -> DomainRegistry:
    """Build the current real catalogue and retain explicit gaps as a startup gate."""
    catalogue = TypeRegistry()
    registrations: dict[str, DomainRegistration] = {}
    unavailable: dict[str, str] = {}
    for domain, (module_name, class_name, proposal_schema) in _PROVIDERS.items():
        try:
            provider = getattr(import_module(module_name, __package__), class_name)()
            descriptor = provider.descriptor
            if not callable(getattr(provider, "validate", None)):
                raise TypeError("provider has no proposal validator")
            proposal_hash = descriptor.request_schema_hash
            specs = _concrete_specs(provider)
            if any(spec.writer_domain != domain for spec in specs):
                raise ValueError("provider TypeSpec writer_domain does not match its domain")
            for spec in specs:
                catalogue.register(spec)
            registrations[domain] = DomainRegistration(
                domain, provider, proposal_schema, proposal_hash, specs
            )
        except Exception as exc:
            unavailable[domain] = f"{type(exc).__name__}: {exc}"
    return DomainRegistry(
        MappingProxyType(registrations),
        MappingProxyType(unavailable),
        catalogue.freeze(),
    )


__all__ = [
    "DomainRegistration",
    "DomainRegistry",
    "REQUIRED_DOMAINS",
    "discover_domain_registry",
]
