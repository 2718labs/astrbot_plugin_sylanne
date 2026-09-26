"""Pure, candidate-only compiler for the committed 24-axis D04 fixed chain.

The topology rows are an untrusted proposed snapshot. Requiring every row and
rejecting every added numeric edge prevents this compiler from silently
dropping supplied coupling, but only D11 can attest that the rows are complete
for the live graph and authorize their use. No boundary eta or product flag is
issued here.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import struct

from .d04_engineering_scheme import DIMENSION, build_d04_engineering_candidate
from .fixed_block_transcript import FixedBlockCSR, _same_csr_bits, _same_float_bits


SCHEMA = "d04.fixed-chain-snapshot-candidate.v1"
TOPOLOGY_SCHEMA = "d04.numeric-topology-rows.v1"
AFFECT_SHA256 = "da94af68236cfd509a7330407c094acaf47a3db5633c271bd5a0abafb1409fa3"
OPERATOR_SHA256 = "37af57ea3d6fa1e5623bf0db51d38c1189123d6569bc982e28ef431137175a8b"
PARAMETER_BOUNDS = (
    ("coupling_beta", 0.125, 0.125),
    ("nonlinear_alpha", 0.25, 0.25),
    ("recovery_fast", 1.0, 1.0),
    ("recovery_residual", 0.125, 0.125),
    ("recovery_slow", 0.015625, 0.015625),
)


class D04SnapshotHold(ValueError):
    """The proposed snapshot cannot be compiled as the fixed-chain candidate."""


@dataclass(frozen=True, slots=True)
class D04NumericTopologyRow:
    axis_id: str
    additional_targets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class D04FixedChainSnapshotCandidate:
    graph_version: str
    axis_ids: tuple[str, ...]
    k: FixedBlockCSR
    r: FixedBlockCSR
    j: FixedBlockCSR
    a: FixedBlockCSR
    alpha: tuple[float, ...]
    initial_state: tuple[float, ...]
    drive: tuple[float, ...]
    readout: tuple[float, ...]
    field_sha256: tuple[tuple[str, str], ...]
    snapshot_sha256: str
    schema: str = SCHEMA


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise D04SnapshotHold(f"duplicate template field: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise D04SnapshotHold(f"non-finite template number: {value}")


def _asset(raw: bytes, expected_sha256: str) -> dict[str, object]:
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise D04SnapshotHold("fixed template digest mismatch")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D04SnapshotHold("fixed template is not valid JSON") from exc
    if type(data) is not dict:
        raise D04SnapshotHold("fixed template must be an object")
    return data


def _vector(values: tuple[float, ...], name: str, *, latent: bool = False) -> tuple[float, ...]:
    if type(values) is not tuple or len(values) != DIMENSION:
        raise D04SnapshotHold(f"{name} must contain all 24 axes")
    if any(type(value) not in (int, float) or not math.isfinite(value)
           or abs(value) > 1.0e6 or (latent and not 0.0 <= value <= 4.0)
           for value in values):
        raise D04SnapshotHold(f"{name} is outside the fixed-chain domain")
    return tuple(float(value) for value in values)


def _matrix(raw: object) -> FixedBlockCSR:
    if type(raw) is not dict or set(raw) != {"rows", "cols", "offsets", "indices", "values"}:
        raise D04SnapshotHold("fixed template matrix is incomplete")
    try:
        return FixedBlockCSR(raw["rows"], raw["cols"], tuple(raw["offsets"]),
                             tuple(raw["indices"]), tuple(raw["values"]))
    except (TypeError, ValueError, KeyError) as exc:
        raise D04SnapshotHold("fixed template matrix is invalid") from exc


def _pack_strings(values: tuple[str, ...]) -> bytes:
    payload = bytearray(struct.pack("<Q", len(values)))
    for value in values:
        encoded = value.encode("utf-8")
        payload.extend(struct.pack("<Q", len(encoded)))
        payload.extend(encoded)
    return bytes(payload)


def _pack_floats(values: tuple[float, ...]) -> bytes:
    return struct.pack("<Q", len(values)) + b"".join(struct.pack("<d", value) for value in values)


def _pack_csr(matrix: FixedBlockCSR) -> bytes:
    return (struct.pack("<QQQ", matrix.rows, matrix.cols, len(matrix.values))
            + struct.pack(f"<{len(matrix.offsets)}I", *matrix.offsets)
            + struct.pack(f"<{len(matrix.indices)}I", *matrix.indices)
            + _pack_floats(matrix.values))


def _field_digest(name: str, payload: bytes) -> str:
    return hashlib.sha256(
        b"sylanne3-d04-snapshot-field-v1\0" + _pack_strings((name,)) + payload
    ).hexdigest()


def compile_d04_fixed_chain_snapshot_candidate(
    *,
    affect_template: bytes,
    operator_template: bytes,
    graph_version: str,
    topology_rows: tuple[D04NumericTopologyRow, ...],
    external_numeric_nodes: tuple[str, ...],
    initial_state: tuple[float, ...],
    drive: tuple[float, ...],
    readout: tuple[float, ...],
) -> D04FixedChainSnapshotCandidate:
    """Compile exact fixed-chain bytes when every proposed topology row is empty.

    This checks the supplied snapshot only. It cannot establish that D11 sent
    every live graph edge, that the initial state has a trusted source, or that
    the compiled candidate is eligible for a product readout.
    """
    affect = _asset(affect_template, AFFECT_SHA256)
    operator = _asset(operator_template, OPERATOR_SHA256)
    model = build_d04_engineering_candidate()
    axes = model.axis_ids
    if (affect.get("schema") != "d04.affect.scheme.v1"
            or operator.get("schema") != "d04.fixed-block-operator.v1"
            or operator.get("affect_schema") != affect.get("schema")
            or type(affect.get("axes")) is not list
            or len(affect["axes"]) != DIMENSION
            or any(type(item) is not dict for item in affect["axes"])
            or tuple(item.get("axis_id") for item in affect["axes"]) != axes
            or operator.get("axis_ids") != list(axes)):
        raise D04SnapshotHold("fixed template axis order or schema mismatch")
    bounds = [list(row) for row in PARAMETER_BOUNDS]
    if affect.get("parameter_bounds") != bounds or operator.get("parameter_bounds") != bounds:
        raise D04SnapshotHold("fixed template parameter bounds mismatch")
    for field in ("scheme_version", "operator_version", "parameter_version", "coupling_version"):
        if affect.get(field) != operator.get(field) or not affect.get(field):
            raise D04SnapshotHold(f"fixed template {field} mismatch")
    if type(graph_version) is not str or not graph_version:
        raise D04SnapshotHold("graph version is required")
    if type(topology_rows) is not tuple or len(topology_rows) != DIMENSION:
        raise D04SnapshotHold("numeric topology must contain every axis row")
    if any(type(row) is not D04NumericTopologyRow or row.axis_id != axis
           or type(row.additional_targets) is not tuple
           for row, axis in zip(topology_rows, axes)):
        raise D04SnapshotHold("numeric topology has missing, duplicate or reordered rows")
    if type(external_numeric_nodes) is not tuple:
        raise D04SnapshotHold("external numeric nodes must be enumerated")
    if any(row.additional_targets for row in topology_rows) or external_numeric_nodes:
        raise D04SnapshotHold("additional numeric coupling or external node requires joint solve")
    raw_operator = operator.get("operator")
    if type(raw_operator) is not dict or set(raw_operator) != {"k", "r", "j", "a", "alpha"}:
        raise D04SnapshotHold("fixed template operator is incomplete")
    if type(raw_operator["alpha"]) is not list:
        raise D04SnapshotHold("fixed template alpha is invalid")
    matrices = tuple(_matrix(raw_operator[name]) for name in ("k", "r", "j", "a"))
    alpha = _vector(tuple(raw_operator["alpha"]), "alpha")
    if not all(_same_csr_bits(expected, actual) for expected, actual in zip(
        (model.k, model.r, model.j, model.a), matrices,
    )) or not _same_float_bits(model.alpha, alpha):
        raise D04SnapshotHold("fixed template differs from exact 24-axis chain")
    initial = _vector(initial_state, "initial_state", latent=True)
    drive_values = _vector(drive, "drive")
    readout_values = _vector(readout, "readout")

    payloads = (
        ("affect_template", affect_template),
        ("operator_template", operator_template),
        ("axis_ids", _pack_strings(axes)),
        ("parameter_bounds", _pack_strings(tuple(name for name, _, _ in PARAMETER_BOUNDS))
         + _pack_floats(tuple(value for _, low, high in PARAMETER_BOUNDS
                              for value in (low, high)))),
        ("topology", _pack_strings((TOPOLOGY_SCHEMA, graph_version))
         + b"".join(_pack_strings((row.axis_id,) + row.additional_targets)
                    for row in topology_rows)
         + _pack_strings(external_numeric_nodes)),
        ("k", _pack_csr(matrices[0])),
        ("r", _pack_csr(matrices[1])),
        ("j", _pack_csr(matrices[2])),
        ("a", _pack_csr(matrices[3])),
        ("alpha", _pack_floats(alpha)),
        ("initial_state", _pack_floats(initial)),
        ("drive", _pack_floats(drive_values)),
        ("readout", _pack_floats(readout_values)),
    )
    field_sha256 = tuple((name, _field_digest(name, payload)) for name, payload in payloads)
    whole = hashlib.sha256(b"sylanne3-d04-fixed-chain-snapshot-candidate-v1\0")
    for name, digest in field_sha256:
        whole.update(_pack_strings((name,)))
        whole.update(bytes.fromhex(digest))
    return D04FixedChainSnapshotCandidate(
        graph_version, axes, *matrices, alpha, initial, drive_values, readout_values,
        field_sha256, whole.hexdigest(),
    )
