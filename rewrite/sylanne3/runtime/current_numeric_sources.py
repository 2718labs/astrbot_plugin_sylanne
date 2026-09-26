"""Graph-backed D04 checkpoint and sourced drive read; readout asset stays HOLD."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.numeric_drive import TYPE_NAME, decode_sourced_numeric_drive
from ..domains.d04.root import decode_numeric_checkpoint
from ..domains.d04.source_head import D04SourceHeadRead, _qualified_head
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, TypeRegistry
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .authoritative_coupling_snapshot import (
    CouplingSnapshotHold, D04UnsignedCouplingSnapshotCandidateV1,
    read_unsigned_d04_coupling_snapshot_candidate,
)
from ..domains.d04.affect import AffectScheme


@dataclass(frozen=True, slots=True)
class CurrentD04NumericSourcesV1:
    """Current initial/drive graph values; no coefficient vector or signed solve."""

    coupling_snapshot_digest: str
    checkpoint_version: GraphVersion
    drive_version: GraphVersion
    initial_state: tuple[float, ...]
    drive: tuple[float, ...]
    read_versions: tuple[GraphVersion, ...]
    read_values_digest: str
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "installed_readout_coefficients_asset_and_sha256_loader",
        "semantic_drive_mapping_issuer_verification",
        "w01_atomic_numeric_source_adoption",
    )


@dataclass(frozen=True, slots=True)
class CurrentD04NumericSourcesV2:
    """Unsigned complete multi-source inventory for one checkpoint interval."""

    coupling_snapshot_digest: str
    query_epoch: QueryEpoch
    checkpoint_version: GraphVersion
    drive_versions: tuple[GraphVersion, ...]
    source_versions: tuple[GraphVersion, ...]
    access_versions: tuple[GraphVersion, ...]
    initial_state: tuple[float, ...]
    drive: tuple[float, ...]
    read_versions: tuple[GraphVersion, ...]
    read_values_digest: str
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "installed_readout_coefficients_asset_and_sha256_loader",
        "semantic_drive_mapping_issuer_verification",
        "semantic_contribution_deduplication_proof",
        "w01_atomic_numeric_source_adoption",
    )


def read_current_d04_numeric_sources_v2(
    db: sqlite3.Connection, *, candidate: D04UnsignedCouplingSnapshotCandidateV1,
    registry: TypeRegistry, scheme: AffectScheme, drive_refs: tuple[str, ...],
    audience: tuple[str, ...], purpose: str, max_drive_rows: int = 512,
) -> CurrentD04NumericSourcesV2:
    """Enumerate and re-read every contributing root drive under the caller's write fence.

    Distinct provenance roots are a structural duplicate check, not proof that
    independently worded sources describe distinct semantic contributions.
    """
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(candidate) is not D04UnsignedCouplingSnapshotCandidateV1
            or type(registry) is not TypeRegistry or type(scheme) is not AffectScheme
            or type(drive_refs) is not tuple or not drive_refs
            or type(max_drive_rows) is not int or not 1 <= max_drive_rows <= 512):
        raise CouplingSnapshotHold("multi-source numeric read needs fenced typed inputs")
    try:
        expected = set(drive_refs)
        if len(expected) != len(drive_refs):
            raise ValueError("repeated expected drive")
        expected_keys = {AtomKey.from_token(ref) for ref in expected}
        if (len(expected_keys) != len(expected) or any(
                key.type_name != TYPE_NAME or key.owner.kind != "persona"
                or NamespaceId.from_key(key) != candidate.namespace
                for key in expected_keys)):
            raise ValueError("expected drive crosses namespace or type")
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("multi-source expected drive refs are invalid") from exc
    try:
        spec = registry.spec(TYPE_NAME)
    except KeyError as exc:
        raise CouplingSnapshotHold("sourced numeric drive type is unregistered") from exc
    if spec.writer_domain != "d04" or spec.owner_kinds != ("persona",):
        raise CouplingSnapshotHold("sourced numeric drive catalogue differs")
    observed = read_unsigned_d04_coupling_snapshot_candidate(
        db, namespace=candidate.namespace, registry=registry, scheme=scheme,
        checkpoint_ref=candidate.checkpoint_ref,
        expected_query_epoch=candidate.query_epoch,
        expected_graph_incarnation=candidate.graph_incarnation,
        expected_graph_revision=candidate.graph_revision,
        expected_access_epoch=candidate.access_epoch,
        expected_delete_epoch=candidate.delete_epoch,
        expected_asset_digest=candidate.fixed_template_asset_digest,
        audience=audience, purpose=purpose,
    )
    if observed != candidate:
        raise CouplingSnapshotHold("numeric source coupling snapshot changed")
    namespace = candidate.namespace
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT ?",
        namespace.as_tuple + (TYPE_NAME, max_drive_rows + 1),
    ).fetchall()
    if len(rows) > max_drive_rows:
        raise CouplingSnapshotHold("numeric drive enumeration exceeds complete page")
    drives = {}
    for token, revision, encoded, valid in rows:
        try:
            key = AtomKey.from_token(token)
            value = json.loads(encoded)
            if (NamespaceId.from_key(key) != namespace or key.type_name != TYPE_NAME
                    or canonical_json(value) != encoded or type(valid) is not int
                    or valid not in (0, 1)):
                raise ValueError("numeric drive row differs")
            drive = decode_sourced_numeric_drive(value)
            if key.name != drive.drive_id or revision != drive.drive_version:
                raise ValueError("numeric drive identity or revision differs")
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric drive graph row is invalid") from exc
        drives[key] = (GraphAtom(key, revision, value, bool(valid)), drive)
    if any(key not in drives or not drives[key][0].valid for key in expected_keys):
        raise CouplingSnapshotHold("expected numeric drive is absent or stale")
    selected = [drives[key] for key in sorted(expected_keys, key=lambda key: key.token)]
    anchor = selected[0][1]
    if anchor.checkpoint_ref != candidate.checkpoint_ref:
        raise CouplingSnapshotHold("drive belongs to a different checkpoint")
    interval = (anchor.role_start, anchor.role_end)
    for atom, drive in drives.values():
        if not atom.valid or drive.checkpoint_ref != candidate.checkpoint_ref:
            continue
        overlaps = drive.role_start < interval[1] and interval[0] < drive.role_end
        if overlaps and (drive.role_start, drive.role_end) != interval:
            raise CouplingSnapshotHold("numeric drive interval partially overlaps")
        if overlaps and atom.key not in expected_keys:
            raise CouplingSnapshotHold("multi-source numeric drive inventory omits a contributor")
    if any((drive.checkpoint_ref != candidate.checkpoint_ref
            or (drive.role_start, drive.role_end) != interval
            or drive.checkpoint_revision != candidate.checkpoint_revision
            or drive.axis_ids != candidate.axis_ids
            or drive.scheme_version != candidate.scheme_version
            or drive.mapping_version != anchor.mapping_version
            or drive.mapping_compiler_ref != anchor.mapping_compiler_ref)
           for _, drive in selected):
        raise CouplingSnapshotHold("multi-source drive checkpoint, axis or mapping differs")

    def current(ref: str, revision: int) -> GraphAtom:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise CouplingSnapshotHold("numeric input dependency crosses namespace")
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                         (ref,)).fetchone()
        if row is None or row[0] != revision or row[2] != 1:
            raise CouplingSnapshotHold("numeric input dependency is absent or stale")
        value = json.loads(row[1])
        if canonical_json(value) != row[1]:
            raise CouplingSnapshotHold("numeric input dependency is noncanonical")
        return GraphAtom(key, revision, value)

    checkpoint_atom = current(candidate.checkpoint_ref, candidate.checkpoint_revision)
    if candidate.checkpoint_value_digest != canonical_digest(checkpoint_atom.value):
        raise CouplingSnapshotHold("drive checkpoint differs from coupling snapshot")
    checkpoint = decode_numeric_checkpoint(checkpoint_atom.value)
    if checkpoint.cursor != interval[0] or checkpoint.axes != anchor.axis_ids:
        raise CouplingSnapshotHold("drive time or axes differ from checkpoint")
    source_atoms = []
    access_atoms = []
    provenance_roots = set()
    evidence = []
    for drive_atom, drive in selected:
        source_atom = current(drive.source_ref, drive.source_revision)
        access_atom = current(drive.access_ref, drive.access_revision)
        try:
            source = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric drive source or access is invalid") from exc
        if (source.source_id != source_atom.key.owner.subject
                or access_atom.key != access_key(*namespace.as_tuple, source.source_id)
                or access_atom.value["source_id"] != source.source_id
                or source.parent_source_ids):
            raise CouplingSnapshotHold("numeric drive source requires an independent root")
        if source.provenance_root in provenance_roots:
            raise CouplingSnapshotHold("numeric drive contribution key repeats")
        provenance_roots.add(source.provenance_root)
        head_key = source_correction_head_key(namespace, source.source_id)
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (head_key.token,)).fetchone():
            raise CouplingSnapshotHold("numeric drive source has a correction head")
        snapshot = GraphSnapshot((source_atom, access_atom, GraphAtom(head_key, 0, {}, False)),
                                 (NamespaceEpoch(*namespace.as_tuple, candidate.query_epoch.revision),))
        qualified, reason = _qualified_head(
            drive.source_ref, {atom.key: atom for atom in snapshot.atoms},
            D04SourceHeadRead(snapshot, namespace, audience, purpose, None,
                              False, False, False),
        )
        if qualified is None:
            raise CouplingSnapshotHold(f"numeric drive source is unavailable: {reason}")
        source_atoms.append(source_atom)
        access_atoms.append(access_atom)
        evidence.extend((drive_atom, source_atom, access_atom, GraphAtom(head_key, 0, {}, False)))
    totals = [sum((Fraction(drive.drive[index]) for _, drive in selected), Fraction(0))
              for index in range(len(anchor.axis_ids))]
    try:
        combined = tuple(float(value) for value in totals)
    except OverflowError as exc:
        raise CouplingSnapshotHold("multi-source drive sum is not finite binary64") from exc
    if any(not math.isfinite(value) for value in combined):
        raise CouplingSnapshotHold("multi-source drive sum is not finite binary64")
    versions = tuple(sorted(set(candidate.read_versions) | {
        GraphVersion(atom.key, atom.revision) for atom in evidence
    }, key=lambda item: item.key.token))
    digest = canonical_digest((candidate.read_values_digest,
                               candidate.query_epoch.revision,
                               tuple(sorted((atom.key.token, atom.revision,
                                             canonical_digest(atom.value), atom.valid)
                                            for atom in evidence)), combined))
    return CurrentD04NumericSourcesV2(
        candidate.snapshot_digest, candidate.query_epoch,
        GraphVersion(checkpoint_atom.key, checkpoint_atom.revision),
        tuple(GraphVersion(atom.key, atom.revision) for atom, _ in selected),
        tuple(GraphVersion(atom.key, atom.revision) for atom in source_atoms),
        tuple(GraphVersion(atom.key, atom.revision) for atom in access_atoms),
        checkpoint.latent_state, combined, versions, digest,
    )


def read_current_d04_numeric_sources(
    db: sqlite3.Connection, *, candidate: D04UnsignedCouplingSnapshotCandidateV1,
    registry: TypeRegistry, scheme: AffectScheme, drive_ref: str,
    audience: tuple[str, ...], purpose: str,
    max_drive_rows: int = 512,
) -> CurrentD04NumericSourcesV1:
    """Re-read fixed topology and all drive rows under the caller's write fence.

    The caller retains GraphStore's lock and BEGIN IMMEDIATE. This function
    cannot verify that the reported mapping issuer actually compiled the drive.
    """
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(candidate) is not D04UnsignedCouplingSnapshotCandidateV1
            or type(registry) is not TypeRegistry or type(scheme) is not AffectScheme):
        raise CouplingSnapshotHold("numeric sources need a fenced typed graph read")
    if type(max_drive_rows) is not int or not 1 <= max_drive_rows <= 512:
        raise CouplingSnapshotHold("numeric drive scan bound differs")
    try:
        spec = registry.spec(TYPE_NAME)
    except KeyError as exc:
        raise CouplingSnapshotHold("sourced numeric drive type is unregistered") from exc
    if spec.writer_domain != "d04" or spec.owner_kinds != ("persona",):
        raise CouplingSnapshotHold("sourced numeric drive catalogue differs")
    observed = read_unsigned_d04_coupling_snapshot_candidate(
        db, namespace=candidate.namespace, registry=registry, scheme=scheme,
        checkpoint_ref=candidate.checkpoint_ref,
        expected_query_epoch=candidate.query_epoch,
        expected_graph_incarnation=candidate.graph_incarnation,
        expected_graph_revision=candidate.graph_revision,
        expected_access_epoch=candidate.access_epoch,
        expected_delete_epoch=candidate.delete_epoch,
        expected_asset_digest=candidate.fixed_template_asset_digest,
        audience=audience, purpose=purpose,
    )
    if observed != candidate:
        raise CouplingSnapshotHold("numeric source coupling snapshot changed")
    namespace = candidate.namespace
    try:
        requested = AtomKey.from_token(drive_ref)
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("numeric drive ref is invalid") from exc
    if (requested.type_name != TYPE_NAME or requested.owner.kind != "persona"
            or NamespaceId.from_key(requested) != namespace):
        raise CouplingSnapshotHold("numeric drive ref crosses namespace or type")
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT ?",
        namespace.as_tuple + (TYPE_NAME, max_drive_rows + 1),
    ).fetchall()
    if len(rows) > max_drive_rows:
        raise CouplingSnapshotHold("numeric drive enumeration exceeds complete page")
    drives = {}
    for token, revision, encoded, valid in rows:
        try:
            key = AtomKey.from_token(token)
            value = json.loads(encoded)
            if (NamespaceId.from_key(key) != namespace or key.type_name != TYPE_NAME
                    or canonical_json(value) != encoded or type(valid) is not int
                    or valid not in (0, 1)):
                raise ValueError("numeric drive row differs")
            drive = decode_sourced_numeric_drive(value)
            if key.name != drive.drive_id or revision != drive.drive_version:
                raise ValueError("numeric drive identity or revision differs")
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric drive graph row is invalid") from exc
        drives[key] = (GraphAtom(key, revision, value, bool(valid)), drive)
    if requested not in drives or not drives[requested][0].valid:
        raise CouplingSnapshotHold("selected numeric drive is not current")
    drive_atom, drive = drives[requested]
    if drive.checkpoint_ref != candidate.checkpoint_ref:
        raise CouplingSnapshotHold("drive belongs to a different checkpoint")
    active = tuple(value for atom, value in drives.values()
                   if atom.valid and value.checkpoint_ref == candidate.checkpoint_ref
                   and value.role_start == drive.role_start
                   and value.role_end == drive.role_end)
    if len(active) != 1:
        raise CouplingSnapshotHold("checkpoint interval has ambiguous current drive")

    def current(ref: str, revision: int) -> GraphAtom:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise CouplingSnapshotHold("numeric input dependency crosses namespace")
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                         (ref,)).fetchone()
        if row is None or row[0] != revision or row[2] != 1:
            raise CouplingSnapshotHold("numeric input dependency is absent or stale")
        value = json.loads(row[1])
        if canonical_json(value) != row[1]:
            raise CouplingSnapshotHold("numeric input dependency is noncanonical")
        return GraphAtom(key, revision, value)

    checkpoint_atom = current(drive.checkpoint_ref, drive.checkpoint_revision)
    if (candidate.checkpoint_revision != checkpoint_atom.revision
            or candidate.checkpoint_value_digest != canonical_digest(checkpoint_atom.value)):
        raise CouplingSnapshotHold("drive checkpoint differs from coupling snapshot")
    checkpoint = decode_numeric_checkpoint(checkpoint_atom.value)
    if checkpoint.cursor != drive.role_start or checkpoint.axes != drive.axis_ids:
        raise CouplingSnapshotHold("drive time or axes differ from checkpoint")
    source_atom = current(drive.source_ref, drive.source_revision)
    access_atom = current(drive.access_ref, drive.access_revision)
    source = SourceRecord.from_dict(source_atom.value)
    validate_access(access_atom.value)
    if (source.source_id != source_atom.key.owner.subject
            or access_atom.key != access_key(*namespace.as_tuple, source.source_id)
            or access_atom.value["source_id"] != source.source_id
            or source.parent_source_ids):
        raise CouplingSnapshotHold("numeric drive source requires complete ancestry")
    head_key = source_correction_head_key(namespace, source.source_id)
    head_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                          (head_key.token,)).fetchone()
    if head_row is not None:
        raise CouplingSnapshotHold("numeric drive source has a correction head")
    snapshot = GraphSnapshot((source_atom, access_atom, GraphAtom(head_key, 0, {}, False)),
                             (NamespaceEpoch(*namespace.as_tuple, candidate.query_epoch.revision),))
    qualified, reason = _qualified_head(
        drive.source_ref, {atom.key: atom for atom in snapshot.atoms},
        D04SourceHeadRead(snapshot, namespace, audience, purpose, None,
                          False, False, False),
    )
    if qualified is None:
        raise CouplingSnapshotHold(f"numeric drive source is unavailable: {reason}")
    refs = tuple(sorted((GraphVersion(drive_atom.key, drive_atom.revision),
                         GraphVersion(source_atom.key, source_atom.revision),
                         GraphVersion(access_atom.key, access_atom.revision)),
                        key=lambda item: item.key.token))
    return CurrentD04NumericSourcesV1(
        candidate.snapshot_digest, GraphVersion(checkpoint_atom.key, checkpoint_atom.revision),
        GraphVersion(drive_atom.key, drive_atom.revision), checkpoint.latent_state,
        drive.drive, tuple(sorted(set(candidate.read_versions) | set(refs),
                                  key=lambda item: item.key.token)),
        canonical_digest((candidate.read_values_digest, tuple(
            (item.key.token, item.revision) for item in refs),
                          canonical_digest(drive_atom.value))),
    )
