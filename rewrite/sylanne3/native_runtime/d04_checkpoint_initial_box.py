"""Replay a graph checkpoint's initial box against the installed ABI2 package.

This is conditional evidence. The graph snapshot and checkpoint are caller
supplied; only a fenced W01/D11 issuer can authenticate their current origin.
The checkpoint's certificate_source and certificate_digest are never treated
as proof of that origin or of the native calculation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import struct

from ..domains.d04.root import NumericCheckpoint, encode_numeric_checkpoint
from ..runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from ..runtime.current_numeric_sources import CurrentD04NumericSourcesV2
from ..runtime_contracts import canonical_digest
from .abi2 import ABI2ResultError
from .d04_candidate import _assets
from .d04_product_admission import D04ProductPreflightHold, d04_numeric_graph_binding_digest
from .fixed_block_transcript import _same_float_bits
from .initial_box_trajectory import _box_digest, _native_initial_radius
from .loader import ABI2NativeLibrary, NativeLoadBinding


@dataclass(frozen=True, slots=True)
class D04CheckpointInitialBoxPreflight:
    """Replayed box radius, tied to exact unsigned graph and package bytes."""

    graph_binding_digest: str
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint_value_digest: str
    manifest_sha256: str
    native_sha256: str
    initial_box_sha256: str
    verified_initial_error: float
    inherited_error: float
    transcript_sha256: str
    status: str = "candidate_hold"
    missing_authorities: tuple[str, ...] = (
        "fenced_current_graph_and_checkpoint_issuer",
        "checkpoint_adoption_and_certificate_issuer_proof",
        "semantic_drive_mapping_and_contribution_deduplication",
        "product_numeric_adoption_issuer",
    )


def _bits(value: float) -> bytes:
    return struct.pack("!d", value)


def preflight_d04_checkpoint_initial_box(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
    checkpoint: NumericCheckpoint,
) -> D04CheckpointInitialBoxPreflight:
    """Recompute the box error from exact graph-value and release-manifest inputs.

    The returned transcript can be replayed by the graph issuer under its
    write fence. It is never a product readout or a credential by itself.
    """
    if type(checkpoint) is not NumericCheckpoint:
        raise TypeError("D04 initial box needs an exact NumericCheckpoint")
    if not isinstance(handle, ABI2NativeLibrary):
        raise TypeError("D04 initial box needs a package-bound ABI2 handle")
    binding_digest = d04_numeric_graph_binding_digest(graph, sources)
    checkpoint_digest = canonical_digest(encode_numeric_checkpoint(checkpoint))
    if (checkpoint_digest != graph.checkpoint_value_digest
            or checkpoint.namespace != graph.namespace.as_tuple
            or checkpoint.graph_state.ref != graph.graph_state_version.key.token
            or checkpoint.graph_state.revision != graph.graph_state_version.revision
            or checkpoint.axes != graph.axis_ids
            or checkpoint.asset_digest != graph.fixed_template_asset_digest
            or not _same_float_bits(checkpoint.latent_state, sources.initial_state)):
        raise D04ProductPreflightHold("initial box checkpoint differs from graph source value")
    if checkpoint.predecessor_kind != "none" or checkpoint.certificate_source != "trusted_initial_box":
        raise D04ProductPreflightHold("initial box needs a root checkpoint; successor proof is unavailable")
    if (checkpoint.assets.scheme_version != graph.scheme_version
            or checkpoint.assets.operator_version != graph.operator_version
            or checkpoint.assets.parameter_version != graph.parameter_version
            or checkpoint.assets.coupling_version != graph.coupling_version):
        raise D04ProductPreflightHold("initial box checkpoint versions differ from graph")
    affect, affect_sha256, operator, operator_sha256 = _assets(Path(package_root), handle)
    if (checkpoint.assets.scheme_sha256 != affect_sha256
            or checkpoint.assets.operator_sha256 != operator_sha256
            or any(getattr(checkpoint.assets, field) != affect.get(field)
                   or getattr(checkpoint.assets, field) != operator.get(field)
                   for field in ("scheme_version", "operator_version", "parameter_version",
                                 "coupling_version"))):
        raise D04ProductPreflightHold("initial box assets differ from trusted release manifest")
    binding: NativeLoadBinding | None = handle.production_binding
    if binding is None:
        raise D04ProductPreflightHold("initial box lacks installed native binding")
    lower = tuple(pair[0] for pair in checkpoint.certified_box)
    upper = tuple(pair[1] for pair in checkpoint.certified_box)
    try:
        radius = _native_initial_radius(handle, checkpoint.latent_state, lower, upper)
    except (ABI2ResultError, TypeError, ValueError) as exc:
        raise D04ProductPreflightHold("native initial box failed replay") from exc
    # NumericCheckpoint only checks a per-coordinate bound. ABI2 computes the
    # Euclidean radius required by the trajectory, which can be much larger.
    if radius > checkpoint.numeric_error_bound:
        raise D04ProductPreflightHold("checkpoint error bound does not enclose native box radius")
    box_sha256 = _box_digest(checkpoint.latent_state, lower, upper, radius, binding)
    transcript_sha256 = canonical_digest({
        "schema": "d04.checkpoint-initial-box-preflight.v1",
        "graph_binding_digest": binding_digest,
        "checkpoint_ref": graph.checkpoint_ref,
        "checkpoint_revision": graph.checkpoint_revision,
        "checkpoint_value_digest": checkpoint_digest,
        "production_binding": asdict(binding),
        "initial_box_sha256": box_sha256,
        "verified_initial_error_bits": _bits(radius).hex(),
        "inherited_error_bits": _bits(checkpoint.numeric_error_bound).hex(),
        "status": "candidate_hold",
    })
    return D04CheckpointInitialBoxPreflight(
        binding_digest, graph.checkpoint_ref, graph.checkpoint_revision,
        checkpoint_digest, binding.manifest_sha256, binding.native_sha256,
        box_sha256, radius, checkpoint.numeric_error_bound, transcript_sha256,
    )


def verify_d04_checkpoint_initial_box(
    handle: ABI2NativeLibrary,
    package_root: Path | str,
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
    checkpoint: NumericCheckpoint,
    transcript: D04CheckpointInitialBoxPreflight,
) -> None:
    """Replay the current source and native math; reject a modified transcript."""
    if type(transcript) is not D04CheckpointInitialBoxPreflight:
        raise TypeError("D04 initial box needs an exact preflight transcript")
    if transcript != preflight_d04_checkpoint_initial_box(
        handle, package_root, graph, sources, checkpoint,
    ):
        raise D04ProductPreflightHold("initial box transcript differs from native replay")
