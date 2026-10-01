"""Unsigned bridge from a current D04 graph inventory to mixed readout rows.

The caller supplies both graph reads. Only W01 can prove its numeric query was
exhaustive under the Authority fence and that the adoption/certificate is real.
This helper checks consistency and replays D04's 24-axis projection; it never
issues a product credential or makes a psychological-quality claim.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domains.d04.affect import AffectScheme
from ..domains.d04.numeric_coupling import TYPE_NAME as COUPLING_TYPE, validate_numeric_coupling
from ..domains.d04.product_issuer import (
    D04CurrentProductReadFrameV1, D04VerifiedNumericAdoptionV1,
)
from ..domains.d04.product_readout import (
    AffectiveReadoutCandidate, D04ReadoutHold, project_conditional_affect_behaviour,
)
from ..domains.d04.root import NumericCheckpoint, encode_numeric_checkpoint
from ..domains.d04.source_head import D04SourceHeadRead
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from ..runtime_contracts import canonical_digest
from .d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from .tanh_asset_readout import D04ConditionalTanhReadoutMath


CHECKPOINT_TYPE = "d04.numeric_checkpoint.v1"
SOURCE_TYPES = frozenset({"memory.source", "memory.access", "d06.source_correction_head.v1"})


class D04MixedReadoutHold(ValueError):
    """A proposed current numeric/semantic readout has an inconsistent premise."""


@dataclass(frozen=True, slots=True)
class D04MixedReadoutPreflight:
    graph_version_digest: str
    numeric_inventory_digest: str
    source_closure_digest: str
    readout_proof_digest: str
    read_versions: tuple[GraphVersion, ...]
    status: str = "unsigned_hold_for_w01_fenced_scc_and_adoption"


def _numeric_inventory(
    graph: D04UnsignedCouplingSnapshotCandidateV1,
    snapshot: GraphSnapshot,
    root_ref: str,
    scheme,
) -> str:
    epoch = snapshot.epochs
    if (len(epoch) != 1 or epoch[0].revision != graph.query_epoch.revision
            or (epoch[0].bot, epoch[0].persona) != graph.namespace.as_tuple):
        raise D04MixedReadoutHold("numeric inventory graph epoch differs")
    if len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms):
        raise D04MixedReadoutHold("numeric inventory repeats graph rows")
    expected = {version for version in graph.read_versions
                if version.key.type_name in {CHECKPOINT_TYPE, COUPLING_TYPE}}
    actual = {GraphVersion(atom.key, atom.revision) for atom in snapshot.atoms}
    if (actual != expected or GraphVersion(AtomKey.from_token(root_ref),
                                          graph.checkpoint_revision) not in actual
            or any(atom.key.type_name not in {CHECKPOINT_TYPE, COUPLING_TYPE}
                   or (atom.key.owner.bot, atom.key.owner.persona)
                      != graph.namespace.as_tuple for atom in snapshot.atoms)):
        raise D04MixedReadoutHold("numeric inventory omits or changes an SCC row")
    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    rows = tuple(sorted((atom.key.token, atom.revision,
                         canonical_digest(atom.value), atom.valid)
                        for atom in snapshot.atoms
                        if atom.key.type_name == COUPLING_TYPE))
    if canonical_digest(rows) != graph.numeric_coupling_rows_digest:
        raise D04MixedReadoutHold("numeric coupling row digest differs")
    couplings = {GraphVersion(atom.key, atom.revision)
                 for atom in snapshot.atoms if atom.key.type_name == COUPLING_TYPE}
    if couplings != set(graph.numeric_coupling_versions):
        raise D04MixedReadoutHold("numeric coupling versions differ")
    adjacency: dict[str, set[str]] = {ref: set() for ref, atom in atoms.items()
                                      if atom.key.type_name == CHECKPOINT_TYPE and atom.valid}
    if root_ref not in adjacency:
        raise D04MixedReadoutHold("root checkpoint is absent from numeric SCC")
    if canonical_digest(atoms[root_ref].value) != graph.checkpoint_value_digest:
        raise D04MixedReadoutHold("numeric SCC checkpoint value differs from source graph")
    for atom in snapshot.atoms:
        if atom.key.type_name != COUPLING_TYPE or not atom.valid:
            continue
        try:
            edge = validate_numeric_coupling(atom.value, scheme)
        except (TypeError, ValueError) as exc:
            raise D04MixedReadoutHold("numeric SCC edge has invalid Scheme or factor") from exc
        if (edge.edge_id != atom.key.name or edge.edge_version != atom.revision
                or edge.left_ref not in adjacency or edge.right_ref not in adjacency):
            raise D04MixedReadoutHold("numeric SCC edge endpoint is absent or stale")
        adjacency[edge.left_ref].add(edge.right_ref)
        adjacency[edge.right_ref].add(edge.left_ref)
    reachable = {root_ref}
    pending = [root_ref]
    while pending:
        current = pending.pop()
        for neighbor in adjacency[current] - reachable:
            reachable.add(neighbor)
            pending.append(neighbor)
    if reachable != {root_ref}:
        raise D04MixedReadoutHold("fixed-chain ABI2 certificate omits a coupled SCC member")
    return canonical_digest({
        "schema": "d04.unsigned-numeric-inventory.v1",
        "graph_snapshot": graph.snapshot_digest,
        "query_epoch": graph.query_epoch.revision,
        "numeric_rows": tuple(sorted((atom.key.token, atom.revision,
                                      canonical_digest(atom.value), atom.valid)
                                     for atom in snapshot.atoms)),
    })


def preflight_d04_mixed_readout(
    *, graph: D04UnsignedCouplingSnapshotCandidateV1,
    numeric_snapshot: GraphSnapshot,
    frame: D04CurrentProductReadFrameV1,
    asset: D04LoadedTanhReadoutAsset,
    math_readout: D04ConditionalTanhReadoutMath,
    candidate: AffectiveReadoutCandidate,
) -> D04MixedReadoutPreflight:
    """Bind unsigned SCC/source versions and replay every distinct tendency."""
    if (type(graph) is not D04UnsignedCouplingSnapshotCandidateV1
            or type(numeric_snapshot) is not GraphSnapshot
            or type(frame) is not D04CurrentProductReadFrameV1
            or type(frame.checkpoint) is not NumericCheckpoint
            or type(frame.source_read) is not D04SourceHeadRead
            or type(frame.active_scheme) is not AffectScheme
            or type(frame.adoption) is not D04VerifiedNumericAdoptionV1
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(math_readout) is not D04ConditionalTanhReadoutMath
            or type(candidate) is not AffectiveReadoutCandidate):
        raise TypeError("D04 mixed readout needs typed graph, adoption and projection")
    checkpoint = frame.checkpoint
    read = frame.source_read
    checkpoint_atom = read.snapshot.get(AtomKey.from_token(frame.checkpoint_ref))
    state_atom = read.snapshot.get(graph.graph_state_version.key)
    if (frame.checkpoint_ref != graph.checkpoint_ref
            or frame.checkpoint_revision != graph.checkpoint_revision
            or frame.graph_incarnation != graph.graph_incarnation
            or frame.graph_revision != graph.graph_revision
            or frame.access_epoch != graph.access_epoch
            or frame.delete_epoch != graph.delete_epoch
            or read.namespace != graph.namespace
            or len(read.snapshot.epochs) != 1
            or read.snapshot.epochs[0].revision != graph.query_epoch.revision
            or (read.snapshot.epochs[0].bot, read.snapshot.epochs[0].persona)
               != graph.namespace.as_tuple
            or checkpoint.namespace != graph.namespace.as_tuple
            or checkpoint.graph_state.ref != graph.graph_state_version.key.token
            or checkpoint.graph_state.revision != graph.graph_state_version.revision
            or checkpoint.asset_digest != graph.fixed_template_asset_digest
            or checkpoint.axes != graph.axis_ids
            or checkpoint_atom is None or not checkpoint_atom.valid
            or checkpoint_atom.revision != graph.checkpoint_revision
            or canonical_digest(checkpoint_atom.value) != graph.checkpoint_value_digest
            or canonical_digest(encode_numeric_checkpoint(checkpoint))
               != graph.checkpoint_value_digest
            or state_atom is None or not state_atom.valid
            or state_atom.revision != graph.graph_state_version.revision
            or canonical_digest(state_atom.value) != graph.graph_state_value_digest):
        raise D04MixedReadoutHold("readout source graph version differs from numeric graph")
    versions = ("scheme_version", "operator_version", "parameter_version", "coupling_version")
    if any(getattr(frame.active_scheme, name) != getattr(graph, name)
           or getattr(checkpoint.assets, name) != getattr(graph, name)
           for name in versions):
        raise D04MixedReadoutHold("readout Scheme version differs from numeric graph")
    inventory_digest = _numeric_inventory(
        graph, numeric_snapshot, frame.checkpoint_ref, frame.active_scheme,
    )
    source_versions = {version for version in graph.read_versions
                       if version.key.type_name in SOURCE_TYPES}
    available_sources = {atom.key.token for atom in read.snapshot.atoms
                         if atom.key.type_name == "memory.source"}
    if (not source_versions.issubset(set(read.snapshot.versions))
            or frame.source_ref not in graph.source_refs
            or not set(graph.source_refs).issubset(available_sources)):
        raise D04MixedReadoutHold("readout source graph versions differ")
    closure_digest = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in read.snapshot.atoms
    )))
    adoption = frame.adoption
    if (adoption.status != "coordinator_verified_adoption"
            or adoption.checkpoint_ref != frame.checkpoint_ref
            or adoption.checkpoint_revision != frame.checkpoint_revision
            or adoption.commit_operation_id != checkpoint.commit_operation_id
            or adoption.certificate_source != checkpoint.certificate_source
            or adoption.certificate_digest != checkpoint.certificate_digest
            or adoption.asset_digest != checkpoint.asset_digest
            or adoption.numeric_error_bound != checkpoint.numeric_error_bound
            or adoption.graph_closure_digest != closure_digest):
        raise D04MixedReadoutHold("numeric adoption and source closure differ")
    try:
        replay = project_conditional_affect_behaviour(
            checkpoint=checkpoint, checkpoint_ref=frame.checkpoint_ref,
            checkpoint_revision=frame.checkpoint_revision,
            source_ref=frame.source_ref, scheme=frame.active_scheme,
            source_read=read, asset=asset, math_readout=math_readout,
        )
    except D04ReadoutHold as exc:
        raise D04MixedReadoutHold("mixed semantic readout failed checkpoint/error replay") from exc
    if replay != candidate or len(candidate.tendencies) != len(graph.axis_ids):
        raise D04MixedReadoutHold("mixed semantic tendency projection differs from replay")
    graph_version_digest = canonical_digest({
        "schema": "d04.mixed-readout-graph-version.v1",
        "incarnation": graph.graph_incarnation, "revision": graph.graph_revision,
        "query_epoch": graph.query_epoch.revision,
        "access_epoch": graph.access_epoch, "delete_epoch": graph.delete_epoch,
        "catalogue": graph.catalogue_hash, "snapshot": graph.snapshot_digest,
        "scheme_versions": tuple(getattr(graph, name) for name in versions),
    })
    return D04MixedReadoutPreflight(
        graph_version_digest, inventory_digest, closure_digest,
        candidate.proof_digest,
        tuple(dict.fromkeys((*graph.read_versions, *read.snapshot.versions))),
    )


__all__ = ["D04MixedReadoutHold", "D04MixedReadoutPreflight",
           "preflight_d04_mixed_readout"]
