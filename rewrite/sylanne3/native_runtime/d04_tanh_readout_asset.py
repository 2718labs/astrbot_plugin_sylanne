"""Load a SHA-pinned 24-output D04 tanh readout *candidate*.

The asset declares p = C tanh(z). Loading it does not certify interval math,
psychological calibration, product readout, or graph adoption. RootAssetBindings
bind bytes and versions, but do not prove an installation directory: the caller
must supply a trusted installed root and authenticate its checkpoint separately.
The legacy linear c·z certificate cannot certify this transform.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from ..domains.d04.root import RootAssetBindings


ASSET_NAME = "d04-tanh-readout.v1.json"
SCHEMA = "d04.tanh-readout-asset.v1"
TRANSFORM = "p=C*tanh(z)"
MAX_ASSET_BYTES = 64 * 1024


class D04TanhReadoutAssetUnavailable(ValueError):
    """Missing, unbound, or malformed installed candidate asset."""


@dataclass(frozen=True, slots=True)
class D04TanhReadoutRow:
    output_id: str
    axis_id: str
    unit: str
    output_version: str
    transform: str
    coefficients: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class D04LoadedTanhReadoutAsset:
    readout_id: str
    readout_version: str
    scheme_version: str
    axis_ids: tuple[str, ...]
    axis_units: tuple[str, ...]
    rows: tuple[D04TanhReadoutRow, ...]
    asset_sha256: str
    status: str = "asset_loaded_candidate"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise D04TanhReadoutAssetUnavailable("D04 tanh asset repeats a field")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise D04TanhReadoutAssetUnavailable(f"D04 tanh asset has nonfinite number: {value}")


def load_d04_tanh_readout_asset(
    installation_root: Path, bindings: RootAssetBindings, *, expected_readout_id: str,
) -> D04LoadedTanhReadoutAsset:
    """Load exact checkpoint-pinned bytes from a caller-authenticated install root."""
    if not isinstance(installation_root, Path) or not installation_root.is_absolute():
        raise D04TanhReadoutAssetUnavailable("trusted installation root must be absolute")
    if type(bindings) is not RootAssetBindings:
        raise TypeError("D04 tanh loader requires checkpoint RootAssetBindings")
    if type(expected_readout_id) is not str or not expected_readout_id:
        raise D04TanhReadoutAssetUnavailable("expected readout identity is required")
    path = installation_root / ASSET_NAME
    if path.is_symlink() or not path.is_file():
        raise D04TanhReadoutAssetUnavailable("installed D04 tanh readout asset is absent")
    try:
        if path.stat().st_size > MAX_ASSET_BYTES:
            raise D04TanhReadoutAssetUnavailable("D04 tanh asset exceeds size bound")
        raw = path.read_bytes()
    except OSError as exc:
        raise D04TanhReadoutAssetUnavailable("D04 tanh asset cannot be read") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if not raw or len(raw) > MAX_ASSET_BYTES or digest != bindings.readout_sha256:
        raise D04TanhReadoutAssetUnavailable("D04 tanh SHA-256 differs from checkpoint")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D04TanhReadoutAssetUnavailable("D04 tanh asset is not strict JSON") from exc
    expected = {"schema", "readout_id", "readout_version", "scheme_version",
                "axis_ids", "axis_units", "outputs"}
    if type(value) is not dict or set(value) != expected or value["schema"] != SCHEMA:
        raise D04TanhReadoutAssetUnavailable("D04 tanh asset schema differs")
    if (value["readout_id"] != expected_readout_id
            or type(value["readout_id"]) is not str
            or value["readout_version"] != bindings.readout_version
            or type(value["readout_version"]) is not str
            or value["scheme_version"] != bindings.scheme_version
            or value["scheme_version"] != SCHEME_VERSION):
        raise D04TanhReadoutAssetUnavailable("D04 tanh identity or version differs")
    axes = REGISTERED_AXIS_IDS
    if (type(value["axis_ids"]) is not list or tuple(value["axis_ids"]) != axes
            or type(value["axis_units"]) is not list
            or tuple(value["axis_units"]) != ("normalized",) * len(axes)):
        raise D04TanhReadoutAssetUnavailable("D04 tanh axes differ from ordered scheme")
    outputs = value["outputs"]
    if type(outputs) is not list or len(outputs) != len(axes):
        raise D04TanhReadoutAssetUnavailable("D04 tanh requires all 24 output rows")
    rows: list[D04TanhReadoutRow] = []
    for index, item in enumerate(outputs):
        if type(item) is not dict or set(item) != {
            "output_id", "axis_id", "unit", "output_version", "transform", "coefficients"
        }:
            raise D04TanhReadoutAssetUnavailable("D04 tanh output row schema differs")
        coefficients = item["coefficients"]
        if (type(item["output_id"]) is not str or not item["output_id"]
                or item["axis_id"] != axes[index]
                or item["unit"] != "normalized"
                or item["output_version"] != value["readout_version"]
                or item["transform"] != TRANSFORM
                or type(coefficients) is not list or len(coefficients) != len(axes)
                or any(type(weight) not in (int, float) or not math.isfinite(weight)
                       or not 0 <= weight <= 1.0e6 for weight in coefficients)):
            raise D04TanhReadoutAssetUnavailable("D04 tanh output mapping or monotone coefficients differ")
        rows.append(D04TanhReadoutRow(
            item["output_id"], item["axis_id"], item["unit"],
            item["output_version"], item["transform"],
            tuple(float(weight) for weight in coefficients),
        ))
    if len({row.output_id for row in rows}) != len(axes):
        raise D04TanhReadoutAssetUnavailable("D04 tanh output IDs must be unique")
    return D04LoadedTanhReadoutAsset(
        value["readout_id"], value["readout_version"], value["scheme_version"],
        axes, ("normalized",) * len(axes), tuple(rows), digest,
    )
