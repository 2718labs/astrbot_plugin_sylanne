"""Package-bound D04 fixed-block candidate bridge.

The native interval flag proves a conditional mathematical statement about the
received block. This bridge binds that block to a package scheme, but neither
the flag nor the bridge proves graph closure, inherited error provenance, or
authority to adopt a D04 state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from ..domains.d04 import AffectScheme

from .fixed_block_transcript import (
    FixedBlockCSR,
    FixedBlockContinuation,
    FixedBlockMathTranscript,
    FixedBlockStep,
    _same_csr_bits,
    _same_float_bits,
    run_fixed_block_math,
)
from .initial_box_trajectory import (
    FixedBlockBoxTrajectoryMathTranscript,
    run_fixed_block_box_trajectory_math,
)
from .loader import ABI2NativeLibrary, NativeIntegrityError


D04_AFFECT_SCHEME_PATH = "resources/catalogue/d04-affect-scheme.json"
D04_OPERATOR_PATH = "resources/catalogue/d04-fixed-block-operator.json"
D04_CATALOGUE_PATH = "resources/catalogue/current.json"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise D04CandidateError(f"duplicate D04 asset field: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise D04CandidateError(f"non-finite D04 asset number: {value}")


class D04CandidateError(ValueError):
    """A package scheme does not qualify the proposed fixed block."""


class D04ProductionReadoutUnavailable(RuntimeError):
    """The current bridge cannot issue a D04 production readout."""


@dataclass(frozen=True, slots=True)
class D04FixedBlockCandidate:
    affect_scheme_sha256: str
    operator_sha256: str
    scheme_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    math: FixedBlockMathTranscript


@dataclass(frozen=True, slots=True)
class D04FixedBlockBoxTrajectoryCandidate:
    """Asset-bound nonlinear math candidate, never an adopted D04 state."""

    affect_scheme_sha256: str
    operator_sha256: str
    scheme_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    math: FixedBlockBoxTrajectoryMathTranscript


def _assets(root: Path, handle: ABI2NativeLibrary) -> tuple[dict[str, object], str, dict[str, object], str]:
    binding = handle.production_binding
    if binding is None:
        raise D04CandidateError("D04 candidate requires a package-bound ABI2 handle")
    root = root.resolve()
    if handle.path.resolve() != root / "rewrite" / "sylanne3" / "_native" / f"{binding.os}-{binding.arch}" / handle.path.name:
        raise D04CandidateError("native handle is not bound to this package root")
    manifest_path = root / "release-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise NativeIntegrityError("trusted release manifest is unavailable")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != binding.manifest_sha256:
        raise NativeIntegrityError("release manifest changed after native loading")
    manifest = json.loads(manifest_bytes)
    def load(path: str) -> tuple[dict[str, object], str]:
        entries = [item for item in manifest["files"] if item.get("path") == path]
        if len(entries) != 1:
            raise D04CandidateError(f"trusted D04 scheme asset is absent: {path}")
        entry = entries[0]
        asset_path = root / path
        if any(part.is_symlink() or getattr(part, "is_junction", lambda: False)()
               for part in (asset_path, *asset_path.parents[:-1])):
            raise NativeIntegrityError("D04 scheme asset path contains a link")
        if not asset_path.is_file():
            raise D04CandidateError(f"trusted D04 scheme asset is absent: {path}")
        raw = asset_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if entry.get("bytes") != len(raw) or entry.get("sha256") != digest:
            raise NativeIntegrityError("D04 scheme asset does not match trusted release manifest")
        try:
            data = json.loads(raw, object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise D04CandidateError("D04 scheme asset is invalid JSON") from exc
        if not isinstance(data, dict):
            raise D04CandidateError("D04 scheme asset must be an object")
        return data, digest

    affect, affect_digest = load(D04_AFFECT_SCHEME_PATH)
    binding_claim = manifest.get("affect_scheme")
    if (not isinstance(binding_claim, dict)
            or binding_claim.get("path") != D04_AFFECT_SCHEME_PATH
            or binding_claim.get("sha256") != affect_digest
            or binding_claim.get("bytes") != (root / D04_AFFECT_SCHEME_PATH).stat().st_size
            or binding_claim.get("catalogue_capability") != "d04.affect.scheme.v1"
            or any(binding_claim.get(name) != affect.get(name) for name in (
                "scheme_version", "operator_version", "parameter_version", "coupling_version",
            ))):
        raise D04CandidateError("D04 affect scheme lacks a matching manifest binding")
    catalogue, _ = load(D04_CATALOGUE_PATH)
    capabilities = catalogue.get("domain_capabilities")
    if (not isinstance(capabilities, dict)
            or not isinstance(capabilities.get("d04"), list)
            or "d04.affect.scheme.v1" not in capabilities["d04"]):
        raise D04CandidateError("trusted catalogue lacks D04 affect scheme capability")
    operator, operator_digest = load(D04_OPERATOR_PATH)
    return affect, affect_digest, operator, operator_digest


def _matrix(value: object) -> FixedBlockCSR:
    if not isinstance(value, dict) or set(value) != {"rows", "cols", "offsets", "indices", "values"}:
        raise D04CandidateError("D04 scheme matrix is incomplete")
    if (not isinstance(value["values"], list)
            or any(type(number) not in (int, float) for number in value["values"])):
        raise D04CandidateError("D04 scheme matrix values must be numbers")
    return FixedBlockCSR(value["rows"], value["cols"], value["offsets"], value["indices"], value["values"])


def _verified_fixed_block_binding(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    scheme: AffectScheme,
    block: FixedBlockStep,
) -> tuple[str, str, tuple[str, str, str, str]]:
    if not isinstance(handle, ABI2NativeLibrary) or not isinstance(scheme, AffectScheme):
        raise TypeError("D04 candidate needs an ABI2 handle and AffectScheme")
    if not isinstance(block, FixedBlockStep):
        raise TypeError("D04 candidate needs a FixedBlockStep")
    affect, affect_digest, asset, operator_digest = _assets(Path(package_root), handle)
    versions = ("scheme_version", "operator_version", "parameter_version", "coupling_version")
    if affect.get("schema") != scheme.schema:
        raise D04CandidateError("D04 affect scheme schema does not match")
    if any(affect.get(name) != getattr(scheme, name) for name in versions):
        raise D04CandidateError("D04 affect scheme version does not match current scheme")
    if affect.get("axes") != [
        {"axis_id": axis.axis_id, "unit": axis.unit, "meaning": axis.meaning}
        for axis in scheme.axes
    ] or affect.get("parameter_bounds") != [list(bounds) for bounds in scheme.parameter_bounds]:
        raise D04CandidateError("D04 affect scheme differs from trusted asset")
    if asset.get("schema") != "d04.fixed-block-operator.v1" or asset.get("affect_schema") != scheme.schema:
        raise D04CandidateError("D04 fixed-block scheme schema does not match")
    if any(asset.get(name) != getattr(scheme, name) for name in versions):
        raise D04CandidateError("D04 fixed-block scheme version does not match current affect scheme")
    if asset.get("axis_ids") != [axis.axis_id for axis in scheme.axes]:
        raise D04CandidateError("D04 fixed-block axes do not match current affect scheme")
    if asset.get("parameter_bounds") != [list(bounds) for bounds in scheme.parameter_bounds]:
        raise D04CandidateError("D04 fixed-block parameter bounds do not match current affect scheme")
    operator = asset.get("operator")
    if not isinstance(operator, dict) or set(operator) != {"k", "r", "j", "a", "alpha"}:
        raise D04CandidateError("D04 fixed-block operator is incomplete")
    if (not isinstance(operator["alpha"], list)
            or any(type(number) not in (int, float) for number in operator["alpha"])):
        raise D04CandidateError("D04 fixed-block alpha must contain numbers")
    try:
        matrices = tuple(_matrix(operator[name]) for name in ("k", "r", "j", "a"))
        alpha = tuple(float(value) for value in operator["alpha"])
    except (KeyError, TypeError, ValueError) as exc:
        raise D04CandidateError("D04 fixed-block operator is invalid") from exc
    if (not all(_same_csr_bits(expected, actual)
                for expected, actual in zip(matrices, (block.k, block.r, block.j, block.a)))
            or not _same_float_bits(alpha, block.alpha)):
        raise D04CandidateError("D04 fixed-block input differs from trusted complete operator")
    if len(block.previous) != len(scheme.axes):
        raise D04CandidateError("D04 fixed-block dimension differs from affect axes")
    return affect_digest, operator_digest, tuple(getattr(scheme, name) for name in versions)


def run_d04_fixed_block_candidate(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    scheme: AffectScheme,
    block: FixedBlockStep,
) -> D04FixedBlockCandidate:
    """Bind one native math call to a trusted asset; never product admission."""
    affect_digest, operator_digest, versions = _verified_fixed_block_binding(
        handle, package_root, scheme, block,
    )
    transcript = run_fixed_block_math(handle, block)
    return D04FixedBlockCandidate(
        affect_digest, operator_digest, *versions, transcript,
    )


def run_d04_fixed_block_box_trajectory_candidate(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    scheme: AffectScheme,
    first: FixedBlockStep,
    continuations: tuple[FixedBlockContinuation, ...],
    *,
    lower: tuple[float, ...],
    upper: tuple[float, ...],
) -> D04FixedBlockBoxTrajectoryCandidate:
    """Bind a native box/trajectory chain to exact trusted D04 operator bytes.

    The box's source, graph closure, and D04 adoption remain external premises.
    """
    affect_digest, operator_digest, versions = _verified_fixed_block_binding(
        handle, package_root, scheme, first,
    )
    math = run_fixed_block_box_trajectory_math(
        handle, first, continuations, lower=lower, upper=upper,
    )
    return D04FixedBlockBoxTrajectoryCandidate(
        affect_digest, operator_digest, *versions, math,
    )


def require_d04_production_readout(
    candidate: D04FixedBlockCandidate | D04FixedBlockBoxTrajectoryCandidate,
) -> None:
    """Fail closed until a product issuer proves all D04 admission conditions."""
    if not isinstance(candidate, (D04FixedBlockCandidate, D04FixedBlockBoxTrajectoryCandidate)):
        raise TypeError("D04 production readout requires a bound candidate")
    raise D04ProductionReadoutUnavailable(
        "ABI2 fixed-block interval math is conditional; D04 source, full graph "
        "closure, inherited error, and product certification remain unproven"
    )
