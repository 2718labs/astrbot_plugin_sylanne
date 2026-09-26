"""Load D04 linear readout coefficients from an installed, hash-pinned asset.

The caller must obtain RootAssetBindings from a verified current checkpoint
and supply the installation's trusted asset directory. Loading bytes does not
certify ABI2 math, source meaning, or a product readout.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.root import RootAssetBindings


ASSET_NAME = "d04-linear-readout.v1.json"
SCHEMA = "d04.linear-readout-asset.v1"
MAX_ASSET_BYTES = 64 * 1024


class D04ReadoutAssetUnavailable(ValueError):
    """Missing, unbound, or malformed installed D04 readout coefficients."""


@dataclass(frozen=True, slots=True)
class D04LoadedReadoutAsset:
    readout_id: str
    readout_version: str
    scheme_version: str
    output_id: str
    output_unit: str
    axis_ids: tuple[str, ...]
    axis_units: tuple[str, ...]
    coefficients: tuple[float, ...]
    asset_sha256: str
    status: str = "asset_loaded_candidate"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise D04ReadoutAssetUnavailable("readout asset repeats a field")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise D04ReadoutAssetUnavailable(f"readout asset has nonfinite number: {value}")


def load_d04_readout_asset(
    installation_root: Path, bindings: RootAssetBindings, *,
    expected_readout_id: str, expected_output_id: str,
) -> D04LoadedReadoutAsset:
    """Read one fixed-name file whose exact bytes match checkpoint bindings.

    A caller-chosen directory is not an installation authority proof. W01 must
    pin this directory to its installed package and recheck the checkpoint in
    the same adoption path before using the returned coefficients.
    """
    if not isinstance(installation_root, Path) or not installation_root.is_absolute():
        raise D04ReadoutAssetUnavailable("readout installation root must be absolute")
    if type(bindings) is not RootAssetBindings:
        raise TypeError("readout loader requires checkpoint asset bindings")
    if (type(expected_readout_id) is not str or not expected_readout_id
            or type(expected_output_id) is not str or not expected_output_id):
        raise D04ReadoutAssetUnavailable("readout target mapping is required")
    path = installation_root / ASSET_NAME
    if path.is_symlink() or not path.is_file():
        raise D04ReadoutAssetUnavailable("installed D04 readout asset is absent")
    try:
        if path.stat().st_size > MAX_ASSET_BYTES:
            raise D04ReadoutAssetUnavailable("installed D04 readout asset exceeds bound")
        raw = path.read_bytes()
    except OSError as exc:
        raise D04ReadoutAssetUnavailable("installed D04 readout asset cannot be read") from exc
    if (not raw or len(raw) > MAX_ASSET_BYTES
            or hashlib.sha256(raw).hexdigest() != bindings.readout_sha256):
        raise D04ReadoutAssetUnavailable("D04 readout asset SHA-256 differs from checkpoint")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D04ReadoutAssetUnavailable("D04 readout asset is not strict JSON") from exc
    expected = {"schema", "readout_id", "readout_version", "scheme_version",
                "output_id", "output_unit", "axis_ids", "axis_units", "coefficients"}
    if type(value) is not dict or set(value) != expected or value["schema"] != SCHEMA:
        raise D04ReadoutAssetUnavailable("D04 readout asset schema differs")
    for field in ("readout_id", "output_id"):
        if type(value[field]) is not str or not value[field]:
            raise D04ReadoutAssetUnavailable(f"D04 readout {field} is absent")
    if (value["readout_version"] != bindings.readout_version
            or value["scheme_version"] != bindings.scheme_version
            or value["output_unit"] != "normalized"
            or value["readout_id"] != expected_readout_id
            or value["output_id"] != expected_output_id):
        raise D04ReadoutAssetUnavailable("D04 readout version or output mapping differs")
    if (type(value["axis_ids"]) is not list
            or tuple(value["axis_ids"]) != REGISTERED_AXIS_IDS
            or type(value["axis_units"]) is not list
            or tuple(value["axis_units"]) != ("normalized",) * 24):
        raise D04ReadoutAssetUnavailable("D04 readout axes or units differ from 24D scheme")
    weights = value["coefficients"]
    if (type(weights) is not list or len(weights) != 24
            or any(type(item) not in (int, float) or not math.isfinite(item)
                   or abs(item) > 1.0e6 for item in weights)):
        raise D04ReadoutAssetUnavailable("D04 readout coefficients exceed 24D bound")
    return D04LoadedReadoutAsset(
        value["readout_id"], value["readout_version"], value["scheme_version"],
        value["output_id"], value["output_unit"], tuple(value["axis_ids"]),
        tuple(value["axis_units"]), tuple(float(item) for item in weights),
        bindings.readout_sha256,
    )
