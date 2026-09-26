"""Fail-closed D04 numeric product preflight.

This checks that the proposed graph values, fixed template, native trajectory,
and linear readout describe the *same* calculation. The graph DTOs are unsigned
and can be made by a caller. Only a coordinator-owned, fenced graph issuer can
turn a successful preflight into product admission.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from ..runtime.current_numeric_sources import CurrentD04NumericSourcesV2
from ..runtime_contracts import canonical_digest
from .d04_candidate import (
    D04FixedBlockBoxTrajectoryCandidate,
    _assets,
)
from .d04_snapshot_compiler import (
    D04FixedChainSnapshotCandidate, D04NumericTopologyRow,
    compile_d04_fixed_chain_snapshot_candidate,
)
from .fixed_block_transcript import _same_csr_bits, _same_float_bits
from .initial_box_trajectory import run_fixed_block_box_linear_readout_math
from .loader import ABI2NativeLibrary


class D04ProductPreflightHold(ValueError):
    """The proposed calculation is inconsistent or lacks a required premise."""


@dataclass(frozen=True, slots=True)
class D04ProductNumericPreflight:
    """Internally consistent conditional math; never an adoption credential."""

    graph_binding_digest: str
    snapshot_sha256: str
    source_values_digest: str
    native_transcript_sha256: str
    readout_transcript_sha256: str
    readout_lower: float
    readout_upper: float
    inherited_error: float
    status: str = "candidate_hold"
    missing_authorities: tuple[str, ...] = (
        "fenced_current_graph_issuer",
        "semantic_drive_mapping_and_contribution_deduplication",
        "authenticated_initial_box_and_inherited_error",
        "installed_readout_and_product_adoption_issuer",
    )


def d04_numeric_graph_binding_digest(
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
) -> str:
    """Bind exact unsigned graph and source values for a fixed-chain proposal."""
    if (type(graph) is not D04UnsignedCouplingSnapshotCandidateV1
            or type(sources) is not CurrentD04NumericSourcesV2):
        raise TypeError("D04 preflight needs typed graph and source candidates")
    if (sources.coupling_snapshot_digest != graph.snapshot_digest
            or sources.status != "hold"
            or sources.query_epoch != graph.query_epoch
            or sources.checkpoint_version.key.token != graph.checkpoint_ref
            or sources.checkpoint_version.revision != graph.checkpoint_revision
            or not set(graph.read_versions).issubset(sources.read_versions)):
        raise D04ProductPreflightHold("D04 graph and numeric sources do not bind")
    return canonical_digest({
        "schema": "d04.unsigned-numeric-graph-binding.v1",
        "graph_snapshot": graph.snapshot_digest,
        "source_values": sources.read_values_digest,
        "graph_incarnation": graph.graph_incarnation,
        "graph_revision": graph.graph_revision,
        "query_epoch": graph.query_epoch.revision,
        "access_epoch": graph.access_epoch,
        "delete_epoch": graph.delete_epoch,
    })


def preflight_d04_product_numeric_readout(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
    snapshot: D04FixedChainSnapshotCandidate,
    candidate: D04FixedBlockBoxTrajectoryCandidate,
) -> D04ProductNumericPreflight:
    """Replay ABI2 and reject omissions while retaining the unsigned HOLD.

    A graph coordinator must re-read the graph under its write fence. This
    function cannot authenticate its caller-supplied graph or initial box.
    """
    if (type(snapshot) is not D04FixedChainSnapshotCandidate
            or type(candidate) is not D04FixedBlockBoxTrajectoryCandidate):
        raise TypeError("D04 preflight needs a compiled snapshot and boxed candidate")
    binding_digest = d04_numeric_graph_binding_digest(graph, sources)
    if snapshot.graph_version != binding_digest:
        raise D04ProductPreflightHold("compiled snapshot is for a different graph version")
    if snapshot.axis_ids != graph.axis_ids:
        raise D04ProductPreflightHold("compiled axes differ from current graph")
    if (not _same_float_bits(snapshot.initial_state, sources.initial_state)
            or not _same_float_bits(snapshot.drive, sources.drive)):
        raise D04ProductPreflightHold("compiled state or drive differs from current sources")
    affect, affect_digest, operator, operator_digest = _assets(Path(package_root), handle)
    if (candidate.affect_scheme_sha256 != affect_digest
            or candidate.operator_sha256 != operator_digest):
        raise D04ProductPreflightHold("candidate assets differ from installed package")
    versions = ("scheme_version", "operator_version", "parameter_version", "coupling_version")
    if any(getattr(candidate, name) != getattr(graph, name)
           or getattr(candidate, name) != affect.get(name)
           or getattr(candidate, name) != operator.get(name)
           for name in versions):
        raise D04ProductPreflightHold("candidate versions differ from current graph")
    # Recompile, since a snapshot dataclass (or its digest) is caller-creatable.
    # The compiler itself still cannot certify the graph rows were complete.
    from .d04_candidate import D04_AFFECT_SCHEME_PATH, D04_OPERATOR_PATH
    root = Path(package_root)
    rebuilt = compile_d04_fixed_chain_snapshot_candidate(
        affect_template=(root / D04_AFFECT_SCHEME_PATH).read_bytes(),
        operator_template=(root / D04_OPERATOR_PATH).read_bytes(),
        graph_version=binding_digest,
        topology_rows=tuple(D04NumericTopologyRow(axis, ()) for axis in graph.axis_ids),
        external_numeric_nodes=(),
        initial_state=sources.initial_state,
        drive=sources.drive,
        readout=snapshot.readout,
    )
    if snapshot != rebuilt:
        raise D04ProductPreflightHold("compiled snapshot fields or digest differ")
    trajectory = candidate.math.trajectory
    if not trajectory.steps:
        raise D04ProductPreflightHold("native trajectory is empty")
    first = trajectory.steps[0].input
    if (not all(_same_csr_bits(getattr(first, name), getattr(snapshot, name))
                for name in ("k", "r", "j", "a"))
            or not _same_float_bits(first.alpha, snapshot.alpha)
            or not _same_float_bits(first.previous, snapshot.initial_state)
            or not _same_float_bits(first.drive, snapshot.drive)
            or not _same_float_bits(candidate.math.trajectory.steps[0].input.previous,
                                    sources.initial_state)):
        raise D04ProductPreflightHold("native fixed block differs from compiled snapshot")
    if candidate.math.production_binding != handle.production_binding:
        raise D04ProductPreflightHold("native trajectory belongs to another package")
    # This replays every native step and the initial-box radius before enclosing
    # the readout. Its interval remains conditional on the unauthenticated box.
    try:
        readout = run_fixed_block_box_linear_readout_math(
            handle, candidate.math, snapshot.readout,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise D04ProductPreflightHold("native trajectory or initial error failed replay") from exc
    return D04ProductNumericPreflight(
        binding_digest, snapshot.snapshot_sha256, sources.read_values_digest,
        candidate.math.transcript_sha256, readout.transcript_sha256,
        readout.readout.lower, readout.readout.upper,
        candidate.math.trajectory.final_error,
    )
