"""One replayable D04 semantic, initial-box and numeric product candidate.

All graph inputs are caller supplied. W01 must re-read and adopt the returned
union of graph versions inside its current Authority transaction; this module
never issues a product credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

from ..domains.d04.root import NumericCheckpoint
from ..domains.d04.numeric_drive import SourcedNumericDrive, sourced_numeric_drive_write
from ..domains.d06 import source_correction_head_key
from ..domains.d04.semantic_graph_preflight import (
    D04SemanticGraphPreflight, preflight_d04_semantic_drive_graph,
)
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ..memory_types import access_key
from ..runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from ..runtime.current_numeric_sources import CurrentD04NumericSourcesV2
from ..runtime_contracts import canonical_digest
from .d04_candidate import D04FixedBlockBoxTrajectoryCandidate
from .d04_checkpoint_initial_box import (
    D04CheckpointInitialBoxPreflight, preflight_d04_checkpoint_initial_box,
)
from .d04_product_admission import (
    D04ProductNumericPreflight, D04ProductPreflightHold,
    preflight_d04_product_numeric_readout,
)
from .d04_semantic_drive_candidate import D04SemanticMechanismShare
from .d04_snapshot_compiler import D04FixedChainSnapshotCandidate
from .fixed_block_transcript import _same_float_bits
from .loader import ABI2NativeLibrary


@dataclass(frozen=True, slots=True)
class D04ProductChainPreflight:
    semantic: D04SemanticGraphPreflight
    initial_box: D04CheckpointInitialBoxPreflight
    numeric: D04ProductNumericPreflight
    read_versions: tuple[GraphVersion, ...]
    transcript_sha256: str
    status: str = "candidate_hold_for_w01_current_graph_adoption"


def _replay_source_values_digest(
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
    snapshot: GraphSnapshot,
    drives: tuple[SourcedNumericDrive, ...],
) -> str:
    """Bind the numeric sum to every individual current source row.

    This mirrors the fenced source reader's value transcript. It verifies a
    caller-supplied candidate, but cannot establish that the read was current.
    """
    if (snapshot.epochs != (NamespaceEpoch(*graph.namespace.as_tuple,
                                           graph.query_epoch.revision),)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or len(drives) != len(sources.drive_versions)):
        raise D04ProductPreflightHold("semantic and numeric source epochs or rows differ")
    rows = []
    observed_drives = set()
    observed_sources = set()
    observed_access = set()
    for drive in drives:
        source_key = AtomKey.from_token(drive.source_ref)
        expected = (
            GraphVersion(source_key, drive.source_revision),
            GraphVersion(access_key(*graph.namespace.as_tuple,
                                    source_key.owner.subject), drive.access_revision),
        )
        observed_sources.add(expected[0])
        observed_access.add(expected[1])
        observed_drives.add(GraphVersion(sourced_numeric_drive_write(drive).key,
                                         drive.drive_version))
        for key in (sourced_numeric_drive_write(drive).key,
                    expected[0].key, expected[1].key,
                    source_correction_head_key(graph.namespace,
                                               source_key.owner.subject)):
            atom = snapshot.get(key)
            if atom is None:
                raise D04ProductPreflightHold("per-source numeric graph row is absent")
            rows.append((atom.key.token, atom.revision,
                         canonical_digest(atom.value), atom.valid))
    if (observed_drives != set(sources.drive_versions)
            or observed_sources != set(sources.source_versions)
            or observed_access != set(sources.access_versions)
            or len(rows) != 4 * len(drives)):
        raise D04ProductPreflightHold("per-source numeric inventory differs")
    return canonical_digest((graph.read_values_digest, graph.query_epoch.revision,
                             tuple(sorted(rows)), sources.drive))


def preflight_d04_product_chain(
    *, handle: ABI2NativeLibrary, package_root: Path | str,
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    sources: CurrentD04NumericSourcesV2,
    checkpoint: NumericCheckpoint,
    semantic_snapshot: GraphSnapshot,
    shares: tuple[D04SemanticMechanismShare, ...],
    drives: tuple[SourcedNumericDrive, ...],
    audience: tuple[str, ...], purpose: str,
    fixed_snapshot: D04FixedChainSnapshotCandidate,
    trajectory: D04FixedBlockBoxTrajectoryCandidate,
) -> D04ProductChainPreflight:
    """Replay and bind all three preflights to one 24D graph calculation."""
    if (type(graph) is not D04UnsignedCouplingSnapshotCandidateV1
            or type(sources) is not CurrentD04NumericSourcesV2
            or type(checkpoint) is not NumericCheckpoint):
        raise TypeError("product chain needs typed graph, numeric sources and checkpoint")
    if (type(semantic_snapshot) is not GraphSnapshot or not semantic_snapshot.epochs
            or type(drives) is not tuple or not drives):
        raise D04ProductPreflightHold("semantic graph snapshot or drives are absent")
    checkpoint_atom = semantic_snapshot.get(sources.checkpoint_version.key)
    if (graph.checkpoint_ref != sources.checkpoint_version.key.token
            or checkpoint_atom is None
            or graph.checkpoint_revision != sources.checkpoint_version.revision
            or graph.query_epoch != sources.query_epoch
            or graph.query_epoch.revision != semantic_snapshot.epochs[0].revision
            or checkpoint.namespace != graph.namespace.as_tuple):
        raise D04ProductPreflightHold("semantic and numeric graph snapshots differ")
    semantic = preflight_d04_semantic_drive_graph(
        snapshot=semantic_snapshot, namespace=graph.namespace,
        checkpoint_ref=graph.checkpoint_ref,
        checkpoint_revision=graph.checkpoint_revision,
        role_start=drives[0].role_start, role_end=drives[0].role_end,
        shares=shares, drives=drives, audience=audience, purpose=purpose,
    )
    if (not _same_float_bits(semantic.candidate.drive, sources.drive)
            or {version.key.token for version in sources.drive_versions}
            != {version.key.token for version in semantic.read_versions
                if version.key.type_name == "d04.sourced_numeric_drive.v1"}
            or any(version not in semantic.read_versions
                   for version in (*sources.drive_versions,
                                   *sources.source_versions,
                                   *sources.access_versions))):
        raise D04ProductPreflightHold("semantic drive and numeric source inventory differ")
    if _replay_source_values_digest(graph, sources, semantic_snapshot, drives) != sources.read_values_digest:
        raise D04ProductPreflightHold("per-source numeric value transcript differs")
    initial_box = preflight_d04_checkpoint_initial_box(
        handle, package_root, graph, sources, checkpoint,
    )
    numeric = preflight_d04_product_numeric_readout(
        handle, package_root, graph, sources, fixed_snapshot, trajectory,
    )
    if (numeric.graph_binding_digest != initial_box.graph_binding_digest
            or numeric.source_values_digest != sources.read_values_digest
            or initial_box.checkpoint_ref != graph.checkpoint_ref
            or initial_box.checkpoint_revision != graph.checkpoint_revision
            or initial_box.verified_initial_error > checkpoint.numeric_error_bound):
        raise D04ProductPreflightHold("initial box and numeric product readout differ")
    read_versions = tuple(dict.fromkeys((
        *graph.read_versions, *sources.read_versions, *semantic.read_versions,
    )))
    transcript = canonical_digest({
        "schema": "d04.product-chain-preflight.v1",
        "graph": numeric.graph_binding_digest,
        "semantic": semantic.candidate.transcript_sha256,
        "source_closure": semantic.source_closure_digest,
        "initial_box": initial_box.transcript_sha256,
        "numeric": numeric.native_transcript_sha256,
        "readout": numeric.readout_transcript_sha256,
        "inherited_error_bits": struct.pack("!d", numeric.inherited_error).hex(),
        "read_versions": tuple((item.key.token, item.revision) for item in read_versions),
    })
    return D04ProductChainPreflight(
        semantic, initial_box, numeric, read_versions, transcript,
    )


__all__ = ["D04ProductChainPreflight", "preflight_d04_product_chain"]
