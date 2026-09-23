"""Generate deterministic D04 engineering-candidate JSON outside release resources.

These bytes exercise the current fixed-block asset shape. They do not define
an activated affect scheme, calibrated semantics, or a production readout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "rewrite"))
sys.path.insert(0, str(ROOT))

from rewrite.tools import build_plugin_package as package_builder  # noqa: E402
from sylanne3.native_runtime.d04_engineering_scheme import (  # noqa: E402
    COUPLING_BETA,
    MECHANISMS,
    NONLINEAR_ALPHA,
    RECOVERY_RATES,
    build_d04_engineering_candidate,
)
from sylanne3.native_runtime.fixed_block_transcript import FixedBlockCSR  # noqa: E402


AFFECT_FILENAME = "d04-affect-scheme.candidate.json"
OPERATOR_FILENAME = "d04-fixed-block-operator.candidate.json"
VERSIONS = {
    "scheme_version": "candidate:d04-24d-chain:scheme:1",
    "operator_version": "candidate:d04-24d-chain:operator:1",
    "parameter_version": "candidate:d04-24d-chain:parameters:1",
    "coupling_version": "candidate:d04-24d-chain:coupling:1",
}


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _matrix(value: FixedBlockCSR) -> dict[str, object]:
    return {
        "rows": value.rows,
        "cols": value.cols,
        "offsets": list(value.offsets),
        "indices": list(value.indices),
        "values": list(value.values),
    }


def candidate_asset_bytes() -> tuple[bytes, bytes]:
    """Build and structurally validate candidate bytes without writing files."""
    candidate = build_d04_engineering_candidate()
    mechanism_meanings = {
        "gain_engagement": "engagement with gains or attained goals",
        "loss_response": "response to loss or obstruction",
        "affiliative_approach": "tendency toward affiliation",
        "boundary_protection": "protection of a boundary",
        "agency_mobilization": "mobilization to act",
        "low_control_response": "response to limited control",
        "self_congruence": "response to self-congruence",
        "self_discrepancy": "response to self-discrepancy",
    }
    assert set(mechanism_meanings) == set(MECHANISMS)
    axes = [
        {
            "axis_id": axis_id,
            "unit": "normalized",
            "meaning": (f"Engineering candidate {mechanism_meanings[mechanism]} "
                        f"{layer} tanh readout; latent z is separately bounded in [0,4]"),
        }
        for axis_id in candidate.axis_ids
        for mechanism, layer in (axis_id.split(":", 1),)
    ]
    bounds = [
        ["coupling_beta", COUPLING_BETA, COUPLING_BETA],
        ["nonlinear_alpha", NONLINEAR_ALPHA, NONLINEAR_ALPHA],
        *[
            [f"recovery_{layer}", rate, rate]
            for layer, rate in zip(("fast", "residual", "slow"), RECOVERY_RATES)
        ],
    ]
    scheme = {
        "schema": "d04.affect.scheme.v1",
        **VERSIONS,
        "axes": axes,
        "parameter_bounds": bounds,
    }
    operator = {
        "schema": "d04.fixed-block-operator.v1",
        "affect_schema": scheme["schema"],
        **VERSIONS,
        "axis_ids": list(candidate.axis_ids),
        "parameter_bounds": bounds,
        "operator": {
            "k": _matrix(candidate.k),
            "r": _matrix(candidate.r),
            "j": _matrix(candidate.j),
            "a": _matrix(candidate.a),
            "alpha": list(candidate.alpha),
        },
    }
    scheme_bytes, operator_bytes = _json_bytes(scheme), _json_bytes(operator)
    # The catalogue exists only in memory to exercise the packager's existing
    # shape and compatibility checks. No runtime capability is activated.
    payload = {
        "resources/catalogue/current.json": _json_bytes({
            "activation_status": "candidate_only",
            "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        }),
        "resources/catalogue/d04-affect-scheme.json": scheme_bytes,
        "resources/catalogue/d04-fixed-block-operator.json": operator_bytes,
    }
    package_builder._d04_binding(payload)
    package_builder._d04_operator_binding(payload)
    return scheme_bytes, operator_bytes


def write_candidate_assets(output_dir: Path | str) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    if destination.is_relative_to((ROOT / "resources").resolve()):
        raise ValueError("D04 candidate assets cannot be written under release resources")
    scheme_bytes, operator_bytes = candidate_asset_bytes()
    destination.mkdir(parents=True, exist_ok=True)
    targets = ((destination / AFFECT_FILENAME, scheme_bytes),
               (destination / OPERATOR_FILENAME, operator_bytes))
    for path, content in targets:
        if path.exists() and path.read_bytes() != content:
            raise FileExistsError(f"D04 candidate output already differs: {path}")
    for path, content in targets:
        if not path.exists():
            path.write_bytes(content)
    return targets[0][0], targets[1][0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    for path in write_candidate_assets(args.output_dir):
        print(f"candidate {path} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
