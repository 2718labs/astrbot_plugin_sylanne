"""D04 coupling rows are strict topology, never fixed-block certificates."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04 import (
    AffectAxis, AffectProvider, AffectScheme,
    build_numeric_coupling_write, coupling_id, requires_joint_numeric_compiler,
    validate_numeric_coupling,
)
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.native_runtime.d04_engineering_scheme import LAYERS, MECHANISMS


AXES = tuple(f"{mechanism}:{layer}" for mechanism in MECHANISMS for layer in LAYERS)


def _scheme():
    return AffectScheme(
        "d04.affect.scheme.v1", "candidate:d04-24d-chain:scheme:1",
        "candidate:d04-24d-chain:operator:1", "candidate:d04-24d-chain:parameters:1",
        "candidate:d04-24d-chain:coupling:1",
        tuple(AffectAxis(axis, "normalized", axis) for axis in AXES), (),
    )


def _ref(name, persona="alice"):
    return AtomKey(Owner("persona", "bot", persona), "d04.numeric_checkpoint.v1", name).token


def _write(**overrides):
    args = dict(
        scheme=_scheme(), edge_version=1, left_ref=_ref("feeling"),
        left_axis="loss_response:fast", right_ref=_ref("mood"),
        right_axis="loss_response:fast", coefficient=0.0625,
        source_ref=AtomKey(Owner("event", "bot", "alice", "event:1"),
                           "d03.world_event", "source").token,
        effective_from=1.0, effective_until=3.0,
    )
    return build_numeric_coupling_write(**(args | overrides))


def test_canonical_edge_round_trip_and_fixed_operator_hold_boundary():
    forward = _write()
    reverse = _write(left_ref=_ref("mood"), right_ref=_ref("feeling"))
    assert forward.key == reverse.key
    assert forward.value == reverse.value
    assert forward.dependencies == ()
    edge = validate_numeric_coupling(forward.value, _scheme())
    assert edge.edge_id == forward.key.name == coupling_id(
        edge.left_ref, edge.left_axis, edge.right_ref, edge.right_axis)
    registry = TypeRegistry()
    spec = next(spec for spec in AffectProvider().type_specs()
                if spec.name == "d04.numeric_coupling.v1")
    registry.register(spec)
    assert registry.validate(forward.key, forward.value) == forward.value
    assert requires_joint_numeric_compiler(forward.value, role_time=2.0, scheme=_scheme())
    assert not requires_joint_numeric_compiler(forward.value, role_time=3.0, scheme=_scheme())


@pytest.mark.parametrize("change", [
    {"right_ref": _ref("mood", "bob")},
    {"right_ref": _ref("feeling")},
    {"right_axis": "unregistered:fast"},
    {"right_axis": "gain_engagement:fast"},
    {"coefficient": 0.126},
    {"coefficient": float("nan")},
    {"effective_until": 1.0},
])
def test_constructor_rejects_invalid_topology(change):
    with pytest.raises((ValueError, TypeError)):
        _write(**change)


def test_validator_rejects_free_matrix_unknown_factor_and_noncanonical_identity():
    valid = _write().value
    for change in (
        {"factor_kind": "j_skew"},
        {"template_id": "arbitrary_matrix"},
        {"scheme_version": "unknown-scheme"},
        {"matrix": [[1.0]]},
        {"edge_id": "free-form"},
        {"edge_version": True},
        {"left_axis": "unknown:slow"},
        {"coefficient": float("inf")},
    ):
        with pytest.raises((ValueError, TypeError)):
            validate_numeric_coupling(valid | change, _scheme())
    edge = validate_numeric_coupling(valid)
    with pytest.raises(ValueError, match="canonical"):
        validate_numeric_coupling({**valid, "left_ref": edge.right_ref,
                                   "right_ref": edge.left_ref})


def test_scheme_axis_order_must_match_fixed_24d_template():
    scheme = _scheme()
    changed = replace(scheme, axes=scheme.axes[::-1])
    with pytest.raises(ValueError, match="registered 24D"):
        _write(scheme=changed)


def test_provider_registers_exact_graph_type():
    provider = AffectProvider(active_scheme=_scheme())
    assert "d04.numeric_coupling.v1" in provider.register_types()
    specs = [spec for spec in provider.type_specs()
             if spec.name == "d04.numeric_coupling.v1"]
    assert len(specs) == 1
    assert specs[0].owner_kinds == ("persona",)
    assert specs[0].writer_domain == "d04"
