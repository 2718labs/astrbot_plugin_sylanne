"""Unsigned D04 joint-component inventory inside W01's fenced SQLite transaction.

The current coupling type is an undirected candidate edge, so its connected
component is the prospective joint solve block. This reader never claims an
SCC certificate, semantic independence, live Authority permission, or numeric
adoption. W01 owns the lock, live permit, transaction and subsequent replay.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.numeric_coupling import (
    TYPE_NAME as COUPLING_TYPE, validate_numeric_coupling,
)
from ..domains.d04.numeric_drive import (
    TYPE_NAME as DRIVE_TYPE, decode_sourced_numeric_drive,
)
from ..domains.d04.root import NumericCheckpoint, decode_numeric_checkpoint
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest


CHECKPOINT_TYPE = "d04.numeric_checkpoint.v1"
MAX_NUMERIC_ROWS = 512
MAX_SOURCE_ROWS = 256


class D04JointSccClosureHold(ValueError):
    """Even the unsigned inventory cannot prove its bounded graph read."""


@dataclass(frozen=True, slots=True)
class D04JointGraphRowV1:
    ref: str
    revision: int
    value_digest: str
    valid: bool


@dataclass(frozen=True, slots=True)
class D04JointMemberInventoryV1:
    ref: str
    revision: int
    checkpoint: NumericCheckpoint
    inherited_box: tuple[tuple[float, float], ...]
    asset_digest: str
    drive_rows: tuple[D04JointGraphRowV1, ...]


@dataclass(frozen=True, slots=True)
class D04JointSccInventoryV1:
    namespace: NamespaceId
    root_ref: str
    graph_incarnation: str
    graph_revision: int
    query_epoch: int
    access_epoch: int
    delete_epoch: int
    schema_versions: tuple[tuple[str, int], ...]
    members: tuple[D04JointMemberInventoryV1, ...]
    edges: tuple[D04JointGraphRowV1, ...]
    sources: tuple[D04JointGraphRowV1, ...]
    accesses: tuple[D04JointGraphRowV1, ...]
    corrections: tuple[D04JointGraphRowV1, ...]
    read_versions: tuple[GraphVersion, ...]
    negative_reads: tuple[str, ...]
    full_numeric_scan_digest: str
    inventory_digest: str
    hold_reasons: tuple[str, ...]
    status: str = "hold"


def _row(token: str, revision: int, encoded: str, valid: int,
         namespace: NamespaceId) -> tuple[D04JointGraphRowV1, dict]:
    try:
        key = AtomKey.from_token(token)
        value = json.loads(encoded)
        if (NamespaceId.from_key(key) != namespace or type(value) is not dict
                or canonical_json(value) != encoded
                or type(revision) is not int or revision < 1
                or type(valid) is not int or valid not in (0, 1)):
            raise ValueError("row metadata differs")
    except (TypeError, ValueError) as exc:
        raise D04JointSccClosureHold("numeric graph row is malformed") from exc
    return D04JointGraphRowV1(token, revision, canonical_digest(value), bool(valid)), value


def read_d04_joint_scc_inventory_in_transaction(
    db: sqlite3.Connection, *, namespace: NamespaceId, checkpoint_ref: str,
    expected_graph_epoch: int, expected_graph_revision: int,
    expected_graph_incarnation: str, expected_access_epoch: int,
    expected_delete_epoch: int, max_numeric_rows: int = MAX_NUMERIC_ROWS,
) -> D04JointSccInventoryV1:
    """Enumerate the root's effective undirected component and its graph evidence.

    Expected stamps must come from W01's independently verified Authority fence.
    A SQLite transaction alone does not prove its BEGIN mode or Authority liveness.
    The complete namespace scans bind absence of other numeric rows/drives to the
    graph epoch. An overflow, malformed row, changed stamp or missing root raises
    HOLD; incomplete source/drive/adoption evidence is returned as HOLD reasons.
    """
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise D04JointSccClosureHold("W01 graph transaction is required")
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace must be NamespaceId")
    if (type(max_numeric_rows) is not int or not 1 <= max_numeric_rows <= 512
            or any(type(x) is not int or x < 0 for x in (
                expected_graph_epoch, expected_graph_revision, expected_access_epoch,
                expected_delete_epoch,
            )) or type(expected_graph_incarnation) is not str
            or not expected_graph_incarnation):
        raise D04JointSccClosureHold("expected graph stamp or scan bound is invalid")
    try:
        root_key = AtomKey.from_token(checkpoint_ref)
    except (TypeError, ValueError) as exc:
        raise D04JointSccClosureHold("root checkpoint ref is invalid") from exc
    if (root_key.type_name != CHECKPOINT_TYPE or root_key.owner.kind != "persona"
            or NamespaceId.from_key(root_key) != namespace):
        raise D04JointSccClosureHold("root checkpoint crosses namespace or type")

    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       namespace.as_tuple).fetchone()
    authority_epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    recovery = db.execute(
        "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if (epoch != (expected_graph_epoch,)
            or authority_epochs != (expected_access_epoch, expected_delete_epoch)
            or recovery is None or recovery[1] != expected_graph_revision):
        raise D04JointSccClosureHold("graph or Authority epoch/revision changed")
    try:
        metadata = json.loads(recovery[0])
        if (canonical_json(metadata) != recovery[0]
                or metadata["graph_incarnation"] != expected_graph_incarnation):
            raise ValueError("incarnation changed")
    except (TypeError, ValueError, KeyError) as exc:
        raise D04JointSccClosureHold("graph incarnation changed or malformed") from exc

    numeric_types = (CHECKPOINT_TYPE, COUPLING_TYPE, DRIVE_TYPE)
    catalogue = db.execute(
        "SELECT name,schema_version FROM graph_type_catalog WHERE name IN (?,?,?) "
        "ORDER BY name", numeric_types,
    ).fetchall()
    if (len(catalogue) != len(numeric_types)
            or any(type(version) is not int or version < 1
                   for _, version in catalogue)):
        raise D04JointSccClosureHold("D04 numeric schema catalogue is incomplete")
    schema_versions = tuple(catalogue)
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN (?,?,?) ORDER BY token LIMIT ?",
        namespace.as_tuple + numeric_types + (max_numeric_rows + 1,),
    ).fetchall()
    if len(rows) > max_numeric_rows:
        raise D04JointSccClosureHold("numeric topology scan exceeds bound")
    numeric: dict[str, tuple[D04JointGraphRowV1, object]] = {}
    for raw in rows:
        row, value = _row(*raw, namespace)
        key = AtomKey.from_token(row.ref)
        try:
            if key.type_name == CHECKPOINT_TYPE:
                decoded = decode_numeric_checkpoint(value)
                if (key.name != decoded.block.block_id
                        or decoded.namespace != namespace.as_tuple):
                    raise ValueError("checkpoint address differs")
            elif key.type_name == COUPLING_TYPE:
                decoded = validate_numeric_coupling(value)
                if key.name != decoded.edge_id or row.revision != decoded.edge_version:
                    raise ValueError("coupling address differs")
            else:
                decoded = decode_sourced_numeric_drive(value)
                if key.name != decoded.drive_id or row.revision != decoded.drive_version:
                    raise ValueError("drive address differs")
        except (TypeError, ValueError) as exc:
            raise D04JointSccClosureHold("numeric graph value or address is invalid") from exc
        numeric[row.ref] = (row, decoded)
    if checkpoint_ref not in numeric or not numeric[checkpoint_ref][0].valid:
        raise D04JointSccClosureHold("root checkpoint is absent or invalid")
    root = numeric[checkpoint_ref][1]
    assert isinstance(root, NumericCheckpoint)
    instant = root.cursor
    active_edges = {}
    adjacency: dict[str, set[str]] = {}
    for ref, (row, edge) in numeric.items():
        if AtomKey.from_token(ref).type_name != COUPLING_TYPE or not row.valid:
            continue
        if not edge.effective_from <= instant < edge.effective_until:
            continue
        for endpoint in (edge.left_ref, edge.right_ref):
            if (endpoint not in numeric or not numeric[endpoint][0].valid
                    or AtomKey.from_token(endpoint).type_name != CHECKPOINT_TYPE):
                raise D04JointSccClosureHold("effective coupling endpoint is absent")
        active_edges[ref] = (row, edge)
        adjacency.setdefault(edge.left_ref, set()).add(edge.right_ref)
        adjacency.setdefault(edge.right_ref, set()).add(edge.left_ref)
    members = {checkpoint_ref}
    pending = [checkpoint_ref]
    while pending:
        for neighbor in adjacency.get(pending.pop(), ()):
            if neighbor not in members:
                members.add(neighbor)
                pending.append(neighbor)
    selected_edges = tuple(sorted((row for row, edge in active_edges.values()
                                  if edge.left_ref in members), key=lambda item: item.ref))
    reasons = {"joint_numeric_compiler_and_adoption_missing",
               "semantic_mapping_and_contribution_independence_unverified",
               "installed_joint_asset_attestation_missing",
               "w01_live_authority_and_numeric_replay_required"}
    selected_drives: dict[str, list[D04JointGraphRowV1]] = {ref: [] for ref in members}
    source_refs: set[str] = set()
    state_refs: dict[str, int] = {}
    for ref in members:
        checkpoint = numeric[ref][1]
        assert isinstance(checkpoint, NumericCheckpoint)
        if checkpoint.cursor != instant or checkpoint.asset_digest != root.asset_digest:
            reasons.add("member_cursor_or_asset_version_differs")
        state_refs[checkpoint.graph_state.ref] = checkpoint.graph_state.revision
        source_refs.add(source_key(*namespace.as_tuple,
                                   checkpoint.block.authored_source_id).token)
    for row, edge in active_edges.values():
        if row in selected_edges:
            source_refs.add(edge.source_ref)
    for ref, (row, drive) in numeric.items():
        if AtomKey.from_token(ref).type_name != DRIVE_TYPE or not row.valid:
            continue
        if drive.checkpoint_ref not in members:
            continue
        if drive.role_start <= instant < drive.role_end:
            selected_drives[drive.checkpoint_ref].append(row)
            source_refs.add(drive.source_ref)
            if (drive.checkpoint_revision != numeric[drive.checkpoint_ref][0].revision
                    or drive.scheme_version != root.assets.scheme_version):
                reasons.add("drive_checkpoint_or_scheme_version_differs")
            for dependency_ref, revision in ((drive.source_ref, drive.source_revision),
                                             (drive.access_ref, drive.access_revision)):
                dependency = db.execute(
                    "SELECT revision,valid FROM graph_atoms WHERE token=?",
                    (dependency_ref,),
                ).fetchone()
                if dependency != (revision, 1):
                    reasons.add("drive_source_or_access_revision_stale")
    if any(not selected_drives[ref] for ref in members):
        reasons.add("member_drive_missing")

    positive: dict[str, D04JointGraphRowV1] = {}
    negative: set[str] = set()
    source_rows: dict[str, D04JointGraphRowV1] = {}
    access_rows: dict[str, D04JointGraphRowV1] = {}
    correction_rows: dict[str, D04JointGraphRowV1] = {}
    for state_ref, revision in state_refs.items():
        try:
            state_key = AtomKey.from_token(state_ref)
            if NamespaceId.from_key(state_key) != namespace:
                raise ValueError("state crosses namespace")
        except (TypeError, ValueError) as exc:
            raise D04JointSccClosureHold("member graph_state ref is invalid") from exc
        raw = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                         (state_ref,)).fetchone()
        if raw is None:
            negative.add(state_ref)
            reasons.add("member_graph_state_missing")
            continue
        state_row, value = _row(state_ref, *raw, namespace)
        positive[state_ref] = state_row
        if state_row.revision != revision or not state_row.valid:
            reasons.add("member_graph_state_stale")
        historical = value.get("historical_source_refs", value.get("source_refs"))
        if type(historical) is list:
            source_refs.update(historical)
        else:
            reasons.add("member_state_source_inventory_missing")
    visited: set[str] = set()
    pending_sources = sorted(source_refs)
    while pending_sources:
        source_ref = pending_sources.pop()
        try:
            source_key_parsed = AtomKey.from_token(source_ref)
            source_id = source_key_parsed.owner.subject
            if source_ref != source_key(*namespace.as_tuple, source_id or "").token:
                raise ValueError("source address differs")
        except (TypeError, ValueError) as exc:
            raise D04JointSccClosureHold("component source ref is invalid") from exc
        if source_ref in visited:
            continue
        visited.add(source_ref)
        if len(visited) > MAX_SOURCE_ROWS:
            raise D04JointSccClosureHold("source ancestry scan exceeds bound")
        for key, destination in ((source_key_parsed, source_rows),
                                 (access_key(*namespace.as_tuple, source_id), access_rows),
                                 (source_correction_head_key(namespace, source_id), correction_rows)):
            raw = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                             (key.token,)).fetchone()
            if raw is None:
                negative.add(key.token)
                if destination is not correction_rows:
                    reasons.add("source_or_access_missing")
                continue
            observed, value = _row(key.token, *raw, namespace)
            destination[key.token] = observed
            positive[key.token] = observed
            if destination is correction_rows:
                reasons.add("source_correction_head_present")
            elif not observed.valid:
                reasons.add("source_or_access_invalid")
            elif destination is source_rows:
                try:
                    record = SourceRecord.from_dict(value)
                    if record.source_id != source_id:
                        raise ValueError("source ID differs")
                    pending_sources.extend(source_key(*namespace.as_tuple, parent).token
                                           for parent in record.parent_source_ids)
                except (TypeError, ValueError) as exc:
                    raise D04JointSccClosureHold("source record is malformed") from exc
            else:
                try:
                    validate_access(value)
                    if value["source_id"] != source_id or value["status"] != "active":
                        reasons.add("source_access_not_active")
                    # No audience/purpose is accepted as a caller claim here.
                    # W01 must qualify the access head under its live context.
                    reasons.add("w01_source_audience_and_purpose_qualification_required")
                except (TypeError, ValueError, KeyError) as exc:
                    raise D04JointSccClosureHold("source access is malformed") from exc

    member_rows = tuple(D04JointMemberInventoryV1(
        ref, numeric[ref][0].revision, numeric[ref][1],
        numeric[ref][1].certified_box, numeric[ref][1].asset_digest,
        tuple(sorted(selected_drives[ref], key=lambda row: row.ref)),
    ) for ref in sorted(members))
    selected_numeric = {row.ref: row for row in selected_edges}
    selected_numeric.update((ref, numeric[ref][0]) for ref in members)
    selected_numeric.update((row.ref, row) for drives in selected_drives.values()
                            for row in drives)
    evidence = {**selected_numeric, **positive}
    versions = tuple(sorted((GraphVersion(AtomKey.from_token(row.ref), row.revision)
                             for row in evidence.values()), key=lambda item: item.key.token))
    scan_digest = canonical_digest(tuple((row.ref, row.revision, row.value_digest, row.valid)
                                   for row, _ in numeric.values()))
    digest = canonical_digest({
        "schema": "d04.joint-scc-inventory.v1", "root": checkpoint_ref,
        "incarnation": expected_graph_incarnation,
        "graph_revision": expected_graph_revision, "query_epoch": expected_graph_epoch,
        "access_epoch": expected_access_epoch, "delete_epoch": expected_delete_epoch,
        "schema_versions": schema_versions,
        "numeric_scan": scan_digest,
        "reads": tuple(sorted((row.ref, row.revision, row.value_digest, row.valid)
                              for row in evidence.values())),
        "negative_reads": tuple(sorted(negative)),
    })
    return D04JointSccInventoryV1(
        namespace, checkpoint_ref, expected_graph_incarnation, expected_graph_revision,
        expected_graph_epoch, expected_access_epoch, expected_delete_epoch,
        schema_versions,
        member_rows, selected_edges, tuple(sorted(source_rows.values(), key=lambda x: x.ref)),
        tuple(sorted(access_rows.values(), key=lambda x: x.ref)),
        tuple(sorted(correction_rows.values(), key=lambda x: x.ref)), versions,
        tuple(sorted(negative)), scan_digest, digest, tuple(sorted(reasons)),
    )


__all__ = ["D04JointSccClosureHold", "D04JointGraphRowV1",
           "D04JointMemberInventoryV1", "D04JointSccInventoryV1",
           "read_d04_joint_scc_inventory_in_transaction"]
