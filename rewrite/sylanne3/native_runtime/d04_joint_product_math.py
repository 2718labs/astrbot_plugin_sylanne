"""Conditional multi-block D04 ABI2 and C*tanh(z) math.

The frozen component, source families, checkpoint originals and installation
root are caller premises. This module never signs a graph read or adopts state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
import math
from pathlib import Path
from typing import TYPE_CHECKING

from ..domains.d04.affect import AffectScheme
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, NumericCoupling
from ..domains.d04.numeric_drive import SourcedNumericDrive, sourced_numeric_drive_write
from ..domains.d04.root import NumericCheckpoint
from ..runtime.joint_numeric_component import JointNumericComponentCandidate
from .abi2 import ABI2ResultError
from .d04_candidate import _assets, _matrix
from .d04_tanh_readout_asset import D04LoadedTanhReadoutAsset, load_d04_tanh_readout_asset
from .fixed_block_transcript import (
    FixedBlockCSR, FixedBlockMathTranscript, FixedBlockTrajectoryMathTranscript, FixedBlockStep, _digest,
    _same_float_bits, run_fixed_block_math,
)
from .initial_box_trajectory import _native_initial_radius
from .loader import ABI2NativeLibrary
from .tanh_asset_readout import D04ConditionalTanhReadoutMath, run_d04_conditional_tanh_readout_math
from .tanh_interval import _outward_binary64
from .d04_fixed_trajectory_v2 import D04ExactSeriesStepPlanV1

if TYPE_CHECKING:
    from ..domains.d04.authored_lineage_v3 import AuthoredNumericCheckpointV2


class D04JointProductMathHold(ValueError):
    """The supplied frozen component cannot yield sound conditional math."""


@dataclass(frozen=True, slots=True)
class D04FamilyAssignment:
    source_ref: str
    family_id: str


@dataclass(frozen=True, slots=True)
class D04DriveQuantization:
    coordinates: tuple[float, ...]
    residuals: tuple[Fraction, ...]  # exact source sum minus binary64 coordinate


@dataclass(frozen=True, slots=True)
class D04JointMemberReadout:
    checkpoint_ref: str
    full: D04ConditionalTanhReadoutMath
    without_family: tuple[tuple[str, D04ConditionalTanhReadoutMath], ...]
    effects: tuple[tuple[str, tuple[tuple[float, float], ...]], ...]


@dataclass(frozen=True, slots=True)
class D04JointProductMathCandidate:
    component_digest: str
    member_refs: tuple[str, ...]
    full_step: FixedBlockStep
    initial_error: float
    full_transcript_sha256: str
    family_transcripts: tuple[tuple[str, str], ...]
    members: tuple[D04JointMemberReadout, ...]
    transcript_sha256: str
    status: str = "conditional_math_hold_for_fenced_graph_and_joint_adoption"
    full_transcript: FixedBlockMathTranscript | FixedBlockTrajectoryMathTranscript | None = None
    family_transcript_originals: tuple[tuple[str, FixedBlockMathTranscript | FixedBlockTrajectoryMathTranscript], ...] = ()
    trajectory_schema: str = "d04.joint-product-fixed-trajectory.v2"


@dataclass(frozen=True, slots=True)
class D04JointCompiledInputsV1:
    component_digest: str
    member_refs: tuple[str, ...]
    asset_digest: str
    full_step: FixedBlockStep
    family_drives: tuple[tuple[str, tuple[float, ...]], ...]
    initial_lower: tuple[float, ...]
    initial_upper: tuple[float, ...]
    inherited_error: float
    readout: D04LoadedTanhReadoutAsset
    plan: D04ExactSeriesStepPlanV1


def _up_sqrt(value: Fraction) -> float:
    result = math.sqrt(float(value))
    if not math.isfinite(result):
        raise D04JointProductMathHold("initial error overflows binary64")
    while Fraction.from_float(result) ** 2 < value:
        result = math.nextafter(result, math.inf)
    return result


def _csr_exact(rows: list[dict[int, Fraction]], n: int) -> FixedBlockCSR:
    offsets = [0]
    indices: list[int] = []
    values: list[float] = []
    for row in rows:
        for column, exact in sorted(row.items()):
            if exact:
                rounded = float(exact)
                if not math.isfinite(rounded) or Fraction.from_float(rounded) != exact:
                    raise D04JointProductMathHold("joint operator needs an unsupported matrix rounding bound")
                indices.append(column)
                values.append(rounded)
        offsets.append(len(indices))
    return FixedBlockCSR(n, n, tuple(offsets), tuple(indices), tuple(values))


def _matrix_rows(matrix: FixedBlockCSR, count: int) -> list[dict[int, Fraction]]:
    n = count * 24
    rows: list[dict[int, Fraction]] = [{} for _ in range(n)]
    if (matrix.rows, matrix.cols) != (24, 24):
        raise D04JointProductMathHold("installed operator is not 24D")
    for block in range(count):
        shift = block * 24
        for row in range(24):
            for pos in range(matrix.offsets[row], matrix.offsets[row + 1]):
                column = shift + matrix.indices[pos]
                rows[shift + row][column] = rows[shift + row].get(column, Fraction()) + Fraction.from_float(matrix.values[pos])
    return rows


def compile_joint_matrices(
    matrices: tuple[FixedBlockCSR, FixedBlockCSR, FixedBlockCSR, FixedBlockCSR],
    refs: tuple[str, ...], edges: tuple[NumericCoupling, ...],
    role_start: float, role_end: float,
) -> tuple[FixedBlockCSR, FixedBlockCSR, FixedBlockCSR, FixedBlockCSR]:
    """Exact block diagonal assembly plus PSD beta(e_i-e_j) edge factors."""
    if (len(refs) < 2 or refs != tuple(sorted(set(refs))) or len(matrices) != 4
            or type(edges) is not tuple):
        raise D04JointProductMathHold("joint members or installed matrices differ")
    n = len(refs) * 24
    k_rows, r_rows, j_rows, a_rows = (_matrix_rows(matrix, len(refs)) for matrix in matrices)
    index = {ref: offset * 24 for offset, ref in enumerate(refs)}
    adjacency = {ref: set() for ref in refs}
    seen_edges = set()
    for edge in edges:
        if (type(edge) is not NumericCoupling or edge.edge_id in seen_edges
                or edge.left_ref not in index or edge.right_ref not in index
                or not edge.effective_from <= role_start
                or not edge.effective_until >= role_end):
            raise D04JointProductMathHold("joint edge differs from complete interval")
        seen_edges.add(edge.edge_id)
        adjacency[edge.left_ref].add(edge.right_ref)
        adjacency[edge.right_ref].add(edge.left_ref)
        i = index[edge.left_ref] + REGISTERED_AXIS_IDS.index(edge.left_axis)
        j = index[edge.right_ref] + REGISTERED_AXIS_IDS.index(edge.right_axis)
        beta = Fraction.from_float(float(edge.coefficient))
        for row, col, term in ((i, i, beta), (j, j, beta), (i, j, -beta), (j, i, -beta)):
            k_rows[row][col] = k_rows[row].get(col, Fraction()) + term
    reachable = {refs[0]}
    pending = [refs[0]]
    while pending:
        for neighbor in adjacency[pending.pop()] - reachable:
            reachable.add(neighbor)
            pending.append(neighbor)
    if reachable != set(refs):
        raise D04JointProductMathHold("coupling graph omits a joint member or edge")
    return tuple(_csr_exact(rows, n) for rows in (k_rows, r_rows, j_rows, a_rows))


def quantize_joint_drive(rows: tuple[tuple[float, ...], ...], n: int) -> D04DriveQuantization:
    """Sum exact binary64 input rationals, then round once per coordinate."""
    if type(rows) is not tuple or any(type(row) is not tuple or len(row) != n for row in rows):
        raise D04JointProductMathHold("drive row dimension differs")
    values = []
    residuals = []
    for index in range(n):
        if any(type(row[index]) is not float or not math.isfinite(row[index]) for row in rows):
            raise D04JointProductMathHold("drive input is not finite binary64")
        exact = sum((Fraction.from_float(row[index]) for row in rows), Fraction())
        try:
            rounded = float(exact)
        except OverflowError as exc:
            raise D04JointProductMathHold("drive sum overflows binary64") from exc
        if not math.isfinite(rounded):
            raise D04JointProductMathHold("drive sum overflows binary64")
        values.append(rounded)
        residuals.append(exact - Fraction.from_float(rounded))
    return D04DriveQuantization(tuple(values), tuple(residuals))


def _assets_and_operator(handle: ABI2NativeLibrary, root: Path, scheme: AffectScheme,
                         checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...],
                         readout_id: str) -> tuple[tuple[FixedBlockCSR, ...], tuple[float, ...], D04LoadedTanhReadoutAsset]:
    affect, affect_sha, operator, operator_sha = _assets(root, handle)
    bindings = checkpoints[0].assets
    fields = ("scheme_version", "operator_version", "parameter_version", "coupling_version")
    if (type(scheme) is not AffectScheme or tuple(axis.axis_id for axis in scheme.axes) != REGISTERED_AXIS_IDS
            or any(getattr(scheme, name) != affect.get(name) or getattr(scheme, name) != operator.get(name)
                   or getattr(bindings, name) != getattr(scheme, name) for name in fields)
            or bindings.scheme_sha256 != affect_sha or bindings.operator_sha256 != operator_sha
            or affect.get("axes") != [{"axis_id": x.axis_id, "unit": x.unit, "meaning": x.meaning} for x in scheme.axes]
            or operator.get("axis_ids") != list(REGISTERED_AXIS_IDS)
            or operator.get("parameter_bounds") != [list(x) for x in scheme.parameter_bounds]):
        raise D04JointProductMathHold("installed operator, scheme or checkpoint binding differs")
    raw = operator.get("operator")
    if type(raw) is not dict or set(raw) != {"k", "r", "j", "a", "alpha"}:
        raise D04JointProductMathHold("installed operator is incomplete")
    matrices = tuple(_matrix(raw[name]) for name in ("k", "r", "j", "a"))
    alpha = tuple(float(x) for x in raw["alpha"])
    if len(alpha) != 24 or any(not math.isfinite(x) or x < 0 for x in alpha):
        raise D04JointProductMathHold("installed nonlinear coefficients differ")
    return matrices, alpha, load_d04_tanh_readout_asset(
        root / "resources" / "catalogue", bindings, expected_readout_id=readout_id,
    )


def compile_d04_joint_product_inputs_v1(
    handle: ABI2NativeLibrary, package_root: Path, scheme: AffectScheme,
    component: JointNumericComponentCandidate, *,
    checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...],
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...],
    readout_id: str, max_iterations: int, tolerance: float,
) -> D04JointCompiledInputsV1:
    """Freeze the full original model without calling the numerical solver.

    A nonexact binary64 drive sum remains HOLD: ABI2 has no drive-input error
    term, so its certificate would enclose the rounded system only.
    """
    from ..domains.d04.authored_lineage_v3 import AuthoredNumericCheckpointV2

    if (type(component) is not JointNumericComponentCandidate or component.status != "hold"
            or type(checkpoints) is not tuple or type(drives) is not tuple
            or type(families) is not tuple or len(component.checkpoint_refs) < 2
            or not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None):
        raise D04JointProductMathHold("typed frozen multi-member input and package ABI2 are required")
    refs = component.checkpoint_refs
    if refs != tuple(sorted(set(refs))) or len(refs) * 24 > handle.capabilities.max_dimension:
        raise D04JointProductMathHold("member order or native dimension differs")
    if (len(checkpoints) != len(refs)
            or any(type(cp) not in (NumericCheckpoint, AuthoredNumericCheckpointV2)
                   for cp in checkpoints)
            or len({type(cp) for cp in checkpoints}) != 1
            or (type(checkpoints[0]) is AuthoredNumericCheckpointV2)
               != (component.root_original_digest is not None)
            or len({cp.checkpoint_id for cp in checkpoints}) != len(refs)
            or len({cp.assets for cp in checkpoints}) != 1
            or len({cp.asset_digest for cp in checkpoints}) != 1
            or tuple(block.checkpoint_ref for block in component.block_drives) != refs):
        raise D04JointProductMathHold("checkpoint list or assets differ")
    for ref, block, cp in zip(refs, component.block_drives, checkpoints):
        if (block.checkpoint_ref != ref or cp.namespace != component.namespace.as_tuple
                or cp.cursor != component.role_start
                or cp.axes != REGISTERED_AXIS_IDS or not _same_float_bits(cp.latent_state, block.initial_state)
                or cp.numeric_error_bound < 0):
            raise D04JointProductMathHold("member checkpoint differs from frozen component")
    # Explicitly match every numeric drive row and its complete 24D values.
    expected = {(version.key.token, version.revision): row
                for block in component.block_drives
                for version, row in zip(block.drive_versions, block.drives)}
    if (len(expected) != sum(len(block.drive_versions) for block in component.block_drives)
            or any(len(block.drive_versions) != len(block.drives) for block in component.block_drives)):
        raise D04JointProductMathHold("frozen drive inventory is ambiguous")
    observed = {}
    for drive in drives:
        if type(drive) is not SourcedNumericDrive:
            raise D04JointProductMathHold("drive is not typed")
        key = (sourced_numeric_drive_write(drive).key.token, drive.drive_version)
        if (key not in expected or key in observed
                or drive.checkpoint_ref not in refs
                or drive.checkpoint_revision != next(block.checkpoint_version.revision for block in component.block_drives if block.checkpoint_ref == drive.checkpoint_ref)
                or (drive.role_start, drive.role_end) != (component.role_start, component.role_end)
                or not _same_float_bits(drive.drive, expected[key])):
            raise D04JointProductMathHold("drive row differs from complete component")
        observed[key] = drive
    if len(observed) != len(expected) or not observed:
        raise D04JointProductMathHold("frozen drive inventory is incomplete")
    family_map = {item.source_ref: item.family_id for item in families if type(item) is D04FamilyAssignment}
    if (len(family_map) != len(families) or set(family_map) != {d.source_ref for d in drives}
            or any(type(x.family_id) is not str or not x.family_id for x in families)):
        raise D04JointProductMathHold("every source needs one explicit contribution family")
    family_ids = tuple(sorted(set(family_map.values())))
    if not family_ids:
        raise D04JointProductMathHold("no contribution families")
    matrices, alpha, readout = _assets_and_operator(handle, package_root, scheme, checkpoints, readout_id)
    n = len(refs) * 24
    matrices_joint = compile_joint_matrices(
        matrices, refs, component.edges, component.role_start, component.role_end,
    )
    index = {ref: offset * 24 for offset, ref in enumerate(refs)}
    previous = tuple(value for cp in checkpoints for value in cp.latent_state)
    lower = tuple(pair[0] for cp in checkpoints for pair in cp.certified_box)
    upper = tuple(pair[1] for cp in checkpoints for pair in cp.certified_box)
    inherited = _up_sqrt(sum((Fraction.from_float(cp.numeric_error_bound) ** 2 for cp in checkpoints), Fraction()))
    source_rows = []
    for drive in drives:
        row = [0.0] * n
        row[index[drive.checkpoint_ref]:index[drive.checkpoint_ref] + 24] = tuple(float(x) for x in drive.drive)
        source_rows.append((family_map[drive.source_ref], tuple(row)))
    def aggregate(omit: str | None) -> tuple[float, ...]:
        quantized = quantize_joint_drive(tuple(row for family, row in source_rows if family != omit), n)
        if any(quantized.residuals):
            raise D04JointProductMathHold("drive rounding lacks an ABI2 input-error certificate")
        return quantized.coordinates
    from .d04_fixed_trajectory_v2 import exact_d04_series_step_plan_v1
    plan = exact_d04_series_step_plan_v1(component.role_start, component.role_end, family_count=len(family_ids))
    first_h = plan.chunk(0)[0]
    step = FixedBlockStep(*matrices_joint, alpha * len(refs), previous, aggregate(None), previous,
                          first_h, inherited, max_iterations, tolerance)
    return D04JointCompiledInputsV1(component.candidate_digest, refs, checkpoints[0].asset_digest,
        step, tuple((family, aggregate(family)) for family in family_ids), lower, upper, inherited, readout, plan)


def run_d04_joint_product_math(handle, package_root, scheme, component, *, checkpoints, drives,
        families, readout_id, max_iterations, tolerance):
    frozen = compile_d04_joint_product_inputs_v1(handle, package_root, scheme, component,
        checkpoints=checkpoints, drives=drives, families=families, readout_id=readout_id,
        max_iterations=max_iterations, tolerance=tolerance)
    from .d04_fixed_trajectory_v2 import fixed_d04_step_plan_v2, run_d04_fixed_trajectory_v2, MAX_NATIVE_CALLS
    plan = fixed_d04_step_plan_v2(component.role_start, component.role_end)
    if len(plan) * (1 + len(frozen.family_drives)) > MAX_NATIVE_CALLS:
        raise D04JointProductMathHold("complete full/LOO trajectories exceed the pinned native-call budget")
    initial_error = max(_native_initial_radius(handle, frozen.full_step.previous, frozen.initial_lower,
        frozen.initial_upper), frozen.inherited_error)
    step = replace(frozen.full_step, previous_error=initial_error)
    full = run_d04_fixed_trajectory_v2(handle, step, plan)
    branches = tuple((family, run_d04_fixed_trajectory_v2(handle, replace(step, drive=drive), plan))
        for family, drive in frozen.family_drives)
    refs, readout = frozen.member_refs, frozen.readout
    members = []
    for position, ref in enumerate(refs):
        section = slice(position * 24, (position + 1) * 24)
        try:
            full_read = run_d04_conditional_tanh_readout_math(readout, full.output[section], full.final_error)
            without = tuple((family, run_d04_conditional_tanh_readout_math(
                readout, branch.output[section], branch.final_error))
                for family, branch in branches)
        except ValueError as exc:
            raise D04JointProductMathHold("ABI2 state interval leaves installed tanh domain") from exc
        effects = []
        for family, branch_read in without:
            intervals = []
            for lhs, rhs in zip(full_read.outputs, branch_read.outputs):
                low = Fraction.from_float(lhs.lower) - Fraction.from_float(rhs.upper)
                high = Fraction.from_float(lhs.upper) - Fraction.from_float(rhs.lower)
                intervals.append((_outward_binary64(low, lower=True), _outward_binary64(high, lower=False)))
            effects.append((family, tuple(intervals)))
        members.append(D04JointMemberReadout(ref, full_read, without, tuple(effects)))
    digest = _digest({"schema": "d04.joint-product-conditional-math.v2",
                      "component": component.candidate_digest, "members": refs,
                      "assets": checkpoints[0].asset_digest, "readout": readout.asset_sha256,
                      "step": step.digest(), "initial_error": initial_error,
                      "full": full.transcript_sha256,
                      "without": tuple((family, branch.transcript_sha256) for family, branch in branches),
                      "effects": tuple((member.checkpoint_ref, member.effects) for member in members)})
    return D04JointProductMathCandidate(component.candidate_digest, refs, step, initial_error,
        full.transcript_sha256, tuple((family, branch.transcript_sha256) for family, branch in branches),
        tuple(members), digest, full_transcript=full,
        family_transcript_originals=branches)


__all__ = ["D04JointProductMathHold", "D04FamilyAssignment", "D04DriveQuantization",
           "D04JointMemberReadout", "D04JointProductMathCandidate", "quantize_joint_drive",
           "compile_joint_matrices", "run_d04_joint_product_math"]
