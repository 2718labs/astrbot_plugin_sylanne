"""One explicit adapter for the twelve real D01-D12 TypeSpec exports.

This is an export-time registry only. Registering candidates here has no
runtime effect and must never be interpreted as character-scheme activation.
"""
from __future__ import annotations

import importlib.util

from sylanne3.graph_types import TypeRegistry


def _register(registry: TypeRegistry, specs: object) -> None:
    if not isinstance(specs, tuple) or not specs:
        raise RuntimeError("domain type exporter returned no TypeSpecs")
    for spec in specs:
        registry.register(spec)


def register_all(registry: TypeRegistry) -> None:
    from sylanne3.domains.d01 import PersonaDomain
    from sylanne3.domains.d02 import BodyDomain
    from sylanne3.domains.d03.context import ContextProvider
    from sylanne3.domains.d04.affect import AffectProvider
    from sylanne3.domains.d05.relationship import RelationshipProvider
    from sylanne3.domains.d06 import D06DomainProvider
    from sylanne3.domains.d07 import D07DomainProvider
    from sylanne3.domains.d08.execution import GoalExecutionProvider
    from sylanne3.domains.d09 import D09ExpressionProvider
    from sylanne3.domains.d10 import LifeDomain
    from sylanne3.domains.d12.types import graph_type_specs

    _register(registry, PersonaDomain().type_specs())
    _register(registry, BodyDomain().type_specs())
    _register(registry, ContextProvider().type_specs())
    _register(registry, AffectProvider().type_specs())
    _register(registry, RelationshipProvider().type_specs())
    _register(registry, D06DomainProvider().type_specs())
    _register(registry, D07DomainProvider.type_specs())
    _register(registry, GoalExecutionProvider().register_types())
    _register(registry, D09ExpressionProvider.register_types())
    _register(registry, tuple(spec.to_graph_spec() for spec in LifeDomain.type_specs()))
    _register(registry, graph_type_specs())
    # D11 is owned by the runtime workstream. Once its real export arrives,
    # include it automatically; absence remains visible in current.json.
    if importlib.util.find_spec("sylanne3.runtime.d11_types") is not None:
        from sylanne3.runtime.d11_types import graph_type_specs as d11_graph_type_specs
        _register(registry, d11_graph_type_specs())
