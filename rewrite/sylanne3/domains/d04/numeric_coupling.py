"""Strict graph topology for proposed D04 cross-block numeric coupling.

The fixed 24D operator asset contains only within-block chain links. A row
here is never an ABI2 operator or a numeric certificate. An active row makes
the fixed-block-only admission path inapplicable until a joint compiler and
full-graph verifier explicitly support its template.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import TYPE_CHECKING

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import canonical_digest, schema_hash

if TYPE_CHECKING:
    from .affect import AffectScheme


TYPE_NAME = "d04.numeric_coupling.v1"
SCHEMA = "d04.numeric_coupling.v1"
TEMPLATE = "d04.cross_block_same_axis_k_laplacian.candidate.v1"
FACTOR_KIND = "k_psd_difference"
MAX_COEFFICIENT = 0.125
SCHEME_VERSION = "candidate:d04-24d-chain:scheme:1"
_MECHANISMS = (
    "gain_engagement", "loss_response", "affiliative_approach",
    "boundary_protection", "agency_mobilization", "low_control_response",
    "self_congruence", "self_discrepancy",
)
REGISTERED_AXIS_IDS = tuple(
    f"{mechanism}:{layer}"
    for mechanism in _MECHANISMS for layer in ("fast", "residual", "slow")
)


def _endpoint(ref: object, axis: object) -> tuple[str, str, AtomKey]:
    if type(ref) is not str or type(axis) is not str or not axis:
        raise ValueError("coupling endpoint needs a checkpoint ref and axis")
    key = AtomKey.from_token(ref)
    if key.owner.kind != "persona" or key.type_name not in {
            "d04.numeric_checkpoint.v1", "d04.numeric_checkpoint.v2"}:
        raise ValueError("coupling endpoint must be a D04 numeric checkpoint")
    if axis not in REGISTERED_AXIS_IDS:
        raise ValueError("coupling axis is absent from the registered 24D template")
    return ref, axis, key


def coupling_id(left_ref: str, left_axis: str, right_ref: str,
                right_axis: str) -> str:
    """Stable undirected identity; weight, provenance and interval are revisions."""
    left = _endpoint(left_ref, left_axis)
    right = _endpoint(right_ref, right_axis)
    if left[2].owner != right[2].owner:
        raise ValueError("coupling endpoints cross a namespace")
    if left[0] == right[0]:
        raise ValueError("coupling endpoints must be different blocks")
    endpoints = sorted(((left_ref, left_axis), (right_ref, right_axis)))
    return "coupling:" + canonical_digest({"template": TEMPLATE, "endpoints": endpoints})


@dataclass(frozen=True, slots=True)
class NumericCoupling:
    edge_id: str
    edge_version: int
    scheme_version: str
    left_ref: str
    left_axis: str
    right_ref: str
    right_axis: str
    template_id: str
    factor_kind: str
    coefficient: float
    source_ref: str
    effective_from: float
    effective_until: float
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or self.scheme_version != SCHEME_VERSION
                or self.template_id != TEMPLATE or self.factor_kind != FACTOR_KIND):
            raise ValueError("unregistered numeric coupling template or factor")
        left = _endpoint(self.left_ref, self.left_axis)
        right = _endpoint(self.right_ref, self.right_axis)
        if left[2].owner != right[2].owner:
            raise ValueError("coupling endpoints cross a namespace")
        if self.left_ref == self.right_ref or (self.left_ref, self.left_axis) >= (self.right_ref, self.right_axis):
            raise ValueError("coupling endpoints must be distinct and canonical")
        if self.left_axis != self.right_axis:
            raise ValueError("registered coupling template requires the same axis")
        if type(self.edge_version) is not int or self.edge_version < 1:
            raise ValueError("coupling edge_version must be a positive integer")
        if self.edge_id != coupling_id(self.left_ref, self.left_axis, self.right_ref, self.right_axis):
            raise ValueError("coupling edge_id differs from canonical endpoints")
        if type(self.coefficient) not in (int, float) or not math.isfinite(self.coefficient) or not 0 < self.coefficient <= MAX_COEFFICIENT:
            raise ValueError("coupling coefficient exceeds registered bound")
        for name in ("effective_from", "effective_until"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("coupling effective interval must be finite")
        if self.effective_until <= self.effective_from:
            raise ValueError("coupling effective interval must be positive")
        if type(self.source_ref) is not str:
            raise ValueError("coupling source_ref must be a graph ref")
        source = AtomKey.from_token(self.source_ref)
        if source.owner.bot != left[2].owner.bot or source.owner.persona != left[2].owner.persona:
            raise ValueError("coupling source crosses a namespace")


def validate_numeric_coupling(value: dict, scheme: AffectScheme | None = None) -> NumericCoupling:
    if type(value) is not dict or set(value) != set(NumericCoupling.__dataclass_fields__):
        raise ValueError("numeric coupling fields differ from v1 schema")
    edge = NumericCoupling(**value)
    if scheme is not None:
        from .affect import AffectScheme

        if type(scheme) is not AffectScheme:
            raise TypeError("scheme must be AffectScheme")
        axes = tuple(axis.axis_id for axis in scheme.axes)
        if axes != REGISTERED_AXIS_IDS:
            raise ValueError("coupling scheme differs from the registered 24D template")
        if scheme.scheme_version != edge.scheme_version:
            raise ValueError("coupling scheme version differs from the registered template")
    return edge


def numeric_coupling_type_spec() -> TypeSpec:
    return TypeSpec(
        TYPE_NAME, ("persona",), "state", validate_numeric_coupling,
        writer_domain="d04", schema_hash=schema_hash({
            "type": TYPE_NAME, "fields": tuple(NumericCoupling.__dataclass_fields__),
            "template": TEMPLATE, "factor": FACTOR_KIND, "max_coefficient": MAX_COEFFICIENT,
            "scheme_version": SCHEME_VERSION,
            "status": "topology_candidate_only",
        }),
    )


def build_numeric_coupling_write(*, scheme: AffectScheme, edge_version: int,
                                 left_ref: str, left_axis: str, right_ref: str,
                                 right_axis: str, coefficient: float,
                                 source_ref: str, effective_from: float,
                                 effective_until: float) -> GraphWrite:
    endpoints = sorted(((left_ref, left_axis), (right_ref, right_axis)))
    edge = NumericCoupling(
        coupling_id(*endpoints[0], *endpoints[1]), edge_version, scheme.scheme_version,
        *endpoints[0], *endpoints[1], TEMPLATE, FACTOR_KIND, coefficient,
        source_ref, effective_from, effective_until,
    )
    validate_numeric_coupling(asdict(edge), scheme)
    owner = AtomKey.from_token(edge.left_ref).owner
    return GraphWrite(AtomKey(Owner("persona", owner.bot, owner.persona),
                              TYPE_NAME, edge.edge_id), asdict(edge))


def requires_joint_numeric_compiler(value: dict, *, role_time: float,
                                    scheme: AffectScheme) -> bool:
    """Fail-closed gate for callers of the unchanged fixed 24D operator."""
    edge = validate_numeric_coupling(value, scheme)
    if type(role_time) not in (int, float) or not math.isfinite(role_time):
        raise ValueError("role_time must be finite")
    return edge.effective_from <= role_time < edge.effective_until
