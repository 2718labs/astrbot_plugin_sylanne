"""Private, unsigned D04 fixed-chain graph preflight for a D11 signer.

The caller owns the GraphStore lock, a V2 write permit, and an already-open
SQLite BEGIN IMMEDIATE transaction. This module performs no Authority RPC,
signing, persistence, numeric solve, or product admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.affect import AffectScheme
from ..domains.d04.numeric_coupling import (
    REGISTERED_AXIS_IDS, SCHEME_VERSION, TYPE_NAME as COUPLING_TYPE,
    validate_numeric_coupling,
)
from ..domains.d04.root import decode_numeric_checkpoint
from ..domains.d04.source_head import D04SourceHeadRead, _qualified_head
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, TypeRegistry
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..native_runtime.d04_snapshot_compiler import (
    AFFECT_SHA256, OPERATOR_SHA256, PARAMETER_BOUNDS,
)
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest


SCHEMA = "d04.authoritative-coupling-snapshot-candidate.v1"
CHECKPOINT_TYPE = "d04.numeric_checkpoint.v1"
MAX_NUMERIC_ROWS = 512
MAX_SOURCE_ROWS = 256
FIXED_OPERATOR_VERSION = "candidate:d04-24d-chain:operator:1"
FIXED_PARAMETER_VERSION = "candidate:d04-24d-chain:parameters:1"
FIXED_COUPLING_VERSION = "candidate:d04-24d-chain:coupling:1"


class CouplingSnapshotHold(ValueError):
    """The graph cannot support an unsigned fixed-chain snapshot candidate."""


@dataclass(frozen=True, slots=True)
class D04UnsignedCouplingSnapshotCandidateV1:
    """Exact graph evidence for one 24-axis root, never a signed credential."""

    namespace: NamespaceId
    graph_incarnation: str
    graph_revision: int
    query_epoch: QueryEpoch
    catalogue_hash: str
    access_epoch: int
    delete_epoch: int
    scheme_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    axis_ids: tuple[str, ...]
    axis_units: tuple[str, ...]
    fixed_template_asset_digest: str
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint_value_digest: str
    graph_state_version: GraphVersion
    graph_state_value_digest: str
    source_refs: tuple[str, ...]
    numeric_coupling_rows_digest: str
    numeric_coupling_versions: tuple[GraphVersion, ...]
    read_versions: tuple[GraphVersion, ...]
    read_values_digest: str
    snapshot_digest: str
    schema: str = SCHEMA
    status: str = "unsigned_candidate_hold"

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.status != "unsigned_candidate_hold":
            raise ValueError("coupling candidate cannot claim signed admission")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("coupling candidate needs a namespace")
        if type(self.query_epoch) is not QueryEpoch or self.query_epoch != QueryEpoch(
                self.namespace, "all", self.query_epoch.revision):
            raise ValueError("coupling candidate needs a full graph query epoch")
        if self.axis_ids != REGISTERED_AXIS_IDS or self.axis_units != ("normalized",) * 24:
            raise ValueError("coupling candidate axes differ from fixed 24D template")
        if (type(self.graph_revision) is not int or self.graph_revision < 0
                or type(self.checkpoint_revision) is not int or self.checkpoint_revision < 1
                or type(self.access_epoch) is not int or self.access_epoch < 0
                or type(self.delete_epoch) is not int or self.delete_epoch < 0):
            raise ValueError("coupling candidate graph versions are invalid")
        key = AtomKey.from_token(self.checkpoint_ref)
        if (key.type_name != CHECKPOINT_TYPE or key.owner.kind != "persona"
                or NamespaceId.from_key(key) != self.namespace):
            raise ValueError("coupling candidate checkpoint ref differs")
        if (GraphVersion(key, self.checkpoint_revision) not in self.read_versions
                or self.graph_state_version not in self.read_versions
                or any(ref not in self.read_versions
                       for ref in self.numeric_coupling_versions)):
            raise ValueError("coupling candidate lacks graph read versions")
        if len(set(self.read_versions)) != len(self.read_versions):
            raise ValueError("coupling candidate read versions repeat")
        for name in ("graph_incarnation", "catalogue_hash", "scheme_version",
                     "operator_version", "parameter_version", "coupling_version",
                     "fixed_template_asset_digest", "checkpoint_value_digest",
                     "graph_state_value_digest", "numeric_coupling_rows_digest",
                     "read_values_digest", "snapshot_digest"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"coupling candidate {name} is absent")


def read_unsigned_d04_coupling_snapshot_candidate(
    db: sqlite3.Connection, *, namespace: NamespaceId, registry: TypeRegistry,
    scheme: AffectScheme, checkpoint_ref: str, expected_query_epoch: QueryEpoch,
    expected_graph_incarnation: str, expected_graph_revision: int,
    expected_access_epoch: int, expected_delete_epoch: int,
    expected_asset_digest: str, audience: tuple[str, ...], purpose: str,
    max_numeric_rows: int = MAX_NUMERIC_ROWS,
) -> D04UnsignedCouplingSnapshotCandidateV1:
    """Read the entire current numeric topology inside the caller's write tx.

    ``db.in_transaction`` proves a transaction exists; SQLite does not expose
    its BEGIN mode. The coordinator must enter with BEGIN IMMEDIATE, retain its
    graph lock, and separately maintain the V2 Authority write permit.
    """
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise CouplingSnapshotHold("coupling snapshot needs an active write transaction")
    if (type(namespace) is not NamespaceId or type(registry) is not TypeRegistry
            or type(scheme) is not AffectScheme):
        raise TypeError("coupling snapshot needs typed installed graph inputs")
    if (type(expected_query_epoch) is not QueryEpoch
            or expected_query_epoch.namespace != namespace
            or expected_query_epoch.scope_ref != "all"
            or type(max_numeric_rows) is not int or not 1 <= max_numeric_rows <= 512):
        raise CouplingSnapshotHold("coupling full query or scan bound differs")
    axes = tuple(axis.axis_id for axis in scheme.axes)
    units = tuple(axis.unit for axis in scheme.axes)
    if (axes != REGISTERED_AXIS_IDS or units != ("normalized",) * 24
            or scheme.scheme_version != SCHEME_VERSION
            or scheme.operator_version != FIXED_OPERATOR_VERSION
            or scheme.parameter_version != FIXED_PARAMETER_VERSION
            or scheme.coupling_version != FIXED_COUPLING_VERSION
            or scheme.parameter_bounds != PARAMETER_BOUNDS):
        raise CouplingSnapshotHold("installed D04 scheme differs from fixed 24 axes")
    for type_name in (CHECKPOINT_TYPE, COUPLING_TYPE):
        try:
            spec = registry.spec(type_name)
        except KeyError as exc:
            raise CouplingSnapshotHold("D04 numeric type is not registered") from exc
        if (spec.writer_domain != "d04" or spec.owner_kinds != ("persona",)
                or spec.schema_hash is None):
            raise CouplingSnapshotHold("D04 numeric type is not registered")
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple).fetchone()
    authority_epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    recovery = db.execute(
        "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if (epoch_row is None or epoch_row[0] != expected_query_epoch.revision
            or authority_epochs != (expected_access_epoch, expected_delete_epoch)
            or recovery is None or recovery[1] != expected_graph_revision):
        raise CouplingSnapshotHold("coupling graph or authority epoch changed")
    try:
        requirements = json.loads(recovery[0])
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("coupling graph incarnation is invalid") from exc
    if (type(expected_graph_incarnation) is not str or not expected_graph_incarnation
            or type(requirements) is not dict
            or requirements.get("graph_incarnation") != expected_graph_incarnation):
        raise CouplingSnapshotHold("coupling graph incarnation changed")
    for kind, expected in (("scheme", scheme.scheme_version),
                           ("operator", scheme.operator_version)):
        row = db.execute(
            "SELECT version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND kind=? AND ref='current'", namespace.as_tuple + (kind,),
        ).fetchone()
        if row != (expected,):
            raise CouplingSnapshotHold("coupling installed D04 guard changed")

    try:
        root_key = AtomKey.from_token(checkpoint_ref)
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("root checkpoint ref is invalid") from exc
    if (root_key.type_name != CHECKPOINT_TYPE or root_key.owner.kind != "persona"
            or NamespaceId.from_key(root_key) != namespace):
        raise CouplingSnapshotHold("root checkpoint crosses the registered graph")
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN (?,?) ORDER BY token LIMIT ?",
        namespace.as_tuple + (CHECKPOINT_TYPE, COUPLING_TYPE, max_numeric_rows + 1),
    ).fetchall()
    if len(rows) > max_numeric_rows:
        raise CouplingSnapshotHold("numeric atom enumeration exceeds one complete page")
    numeric: dict[AtomKey, GraphAtom] = {}
    row_digests = []
    for token, revision, encoded, valid in rows:
        try:
            key = AtomKey.from_token(token)
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric atom address is invalid") from exc
        if (NamespaceId.from_key(key) != namespace
                or key.type_name not in (CHECKPOINT_TYPE, COUPLING_TYPE)):
            raise CouplingSnapshotHold("numeric atom row crosses registered namespace")
        try:
            value = json.loads(encoded)
            if canonical_json(value) != encoded:
                raise ValueError("noncanonical graph value")
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric atom value is invalid") from exc
        numeric[key] = GraphAtom(key, revision, value, bool(valid))
        row_digests.append((token, revision, canonical_digest(value), bool(valid)))
        if valid and key.type_name == CHECKPOINT_TYPE:
            try:
                node = decode_numeric_checkpoint(value)
            except (TypeError, ValueError) as exc:
                raise CouplingSnapshotHold("numeric checkpoint value is invalid") from exc
            if (node.namespace != namespace.as_tuple
                    or node.block.block_id != key.name
                    or node.axes != axes):
                raise CouplingSnapshotHold("numeric checkpoint axis or address differs")
    root_atom = numeric.get(root_key)
    if root_atom is None or not root_atom.valid:
        raise CouplingSnapshotHold("root checkpoint is not current")
    try:
        checkpoint = decode_numeric_checkpoint(root_atom.value)
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("root checkpoint value is invalid") from exc
    if (checkpoint.namespace != namespace.as_tuple
            or root_key.name != checkpoint.block.block_id
            or checkpoint.axes != axes
            or checkpoint.assets.scheme_version != scheme.scheme_version
            or checkpoint.assets.operator_version != scheme.operator_version
            or checkpoint.assets.parameter_version != scheme.parameter_version
            or checkpoint.assets.coupling_version != scheme.coupling_version
            or checkpoint.assets.scheme_sha256 != AFFECT_SHA256
            or checkpoint.assets.operator_sha256 != OPERATOR_SHA256
            or checkpoint.asset_digest != expected_asset_digest):
        raise CouplingSnapshotHold("root checkpoint differs from fixed installed assets")

    atoms: dict[AtomKey, GraphAtom] = dict(numeric)

    def load(key: AtomKey) -> GraphAtom:
        if NamespaceId.from_key(key) != namespace:
            raise CouplingSnapshotHold("coupling graph ref crosses namespace")
        if key not in atoms:
            try:
                registry.spec(key.type_name)
            except KeyError as exc:
                raise CouplingSnapshotHold("coupling graph ref type is unregistered") from exc
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (key.token,),).fetchone()
            if row is None:
                atoms[key] = GraphAtom(key, 0, {}, False)
            else:
                try:
                    value = json.loads(row[1])
                    if canonical_json(value) != row[1]:
                        raise ValueError("noncanonical graph value")
                except (TypeError, ValueError) as exc:
                    raise CouplingSnapshotHold("coupling graph ref value is invalid") from exc
                atoms[key] = GraphAtom(key, row[0], value, bool(row[2]))
        return atoms[key]

    try:
        state_key = AtomKey.from_token(checkpoint.graph_state.ref)
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("root graph_state ref is invalid") from exc
    state = load(state_key)
    if (not state.valid or state.revision != checkpoint.graph_state.revision
            or state.key.owner != root_key.owner):
        raise CouplingSnapshotHold("root checkpoint graph_state is no longer current")
    try:
        registry.validate(state.key, state.value)
    except (TypeError, ValueError) as exc:
        raise CouplingSnapshotHold("root checkpoint graph_state value is invalid") from exc
    state_sources = state.value.get(
        "source_refs" if checkpoint.block.kind == "mood"
        else "historical_source_refs")
    if (state.value.get("revision") != state.revision
            or state.value.get("basis_version") != scheme.scheme_version
            or state.value.get("parameter_version") != scheme.parameter_version
            or state.value.get("coupling_version") != scheme.coupling_version
            or (checkpoint.block.kind == "feeling"
                and state.value.get("operator_version") != scheme.operator_version)
            or type(state_sources) is not list):
        raise CouplingSnapshotHold("root graph_state versions or sources differ")
    source_ids: set[str] = set()

    def load_source_closure(ref: str) -> None:
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("numeric source ref is invalid") from exc
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise CouplingSnapshotHold("numeric source ref is not canonical")
        pending = [key.owner.subject]
        while pending:
            source_id = pending.pop()
            if source_id in source_ids:
                continue
            source_ids.add(source_id)
            if len(source_ids) > MAX_SOURCE_ROWS:
                raise CouplingSnapshotHold("numeric source ancestry exceeds bound")
            source_atom = load(source_key(*namespace.as_tuple, source_id))
            access_atom = load(access_key(*namespace.as_tuple, source_id))
            head_atom = load(source_correction_head_key(namespace, source_id))
            if (not source_atom.valid or not access_atom.valid
                    or head_atom.revision != 0):
                raise CouplingSnapshotHold("numeric source has lost current access")
            try:
                source = SourceRecord.from_dict(source_atom.value)
                validate_access(access_atom.value)
            except (TypeError, ValueError) as exc:
                raise CouplingSnapshotHold("numeric source or access is invalid") from exc
            pending.extend(source.parent_source_ids)

    root_source = source_key(*namespace.as_tuple, checkpoint.block.authored_source_id)
    if root_source.token not in state_sources:
        raise CouplingSnapshotHold("root authored source differs from graph_state")
    load_source_closure(root_source.token)
    for ref in state_sources:
        load_source_closure(ref)
    for atom in numeric.values():
        if not atom.valid or atom.key.type_name != COUPLING_TYPE:
            continue
        try:
            edge = validate_numeric_coupling(atom.value, scheme)
        except (TypeError, ValueError) as exc:
            raise CouplingSnapshotHold("unknown numeric coupling factor or template") from exc
        if atom.key.name != edge.edge_id or atom.revision != edge.edge_version:
            raise CouplingSnapshotHold("numeric coupling address differs")
        for ref in (edge.left_ref, edge.right_ref):
            try:
                endpoint = AtomKey.from_token(ref)
            except (TypeError, ValueError) as exc:
                raise CouplingSnapshotHold("numeric coupling endpoint is invalid") from exc
            node = numeric.get(endpoint)
            if (node is None or not node.valid
                    or endpoint.type_name != CHECKPOINT_TYPE
                    or NamespaceId.from_key(endpoint) != namespace):
                raise CouplingSnapshotHold("numeric coupling endpoint closure is incomplete")
        load_source_closure(edge.source_ref)
        if checkpoint_ref in (edge.left_ref, edge.right_ref):
            raise CouplingSnapshotHold("root has a numeric coupling requiring joint solve")
    snapshot = GraphSnapshot(tuple(atoms.values()),
                             (NamespaceEpoch(*namespace.as_tuple, epoch_row[0]),))
    read = D04SourceHeadRead(snapshot, namespace, audience, purpose,
                             None, False, False, False)
    for source_id in source_ids:
        qualified, reason = _qualified_head(
            source_key(*namespace.as_tuple, source_id).token, atoms, read)
        if qualified is None:
            raise CouplingSnapshotHold(
                f"numeric source ancestry is unavailable: {reason}")
    coupling_versions = tuple(sorted((GraphVersion(atom.key, atom.revision)
                                      for atom in numeric.values()
                                      if atom.key.type_name == COUPLING_TYPE),
                                     key=lambda item: item.key.token))
    read_versions = tuple(sorted(snapshot.versions, key=lambda item: item.key.token))
    read_values_digest = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in snapshot.atoms)))
    source_refs = tuple(sorted(source_key(*namespace.as_tuple, source_id).token
                               for source_id in source_ids))
    numeric_digest = canonical_digest(tuple(row for row in row_digests
                                            if AtomKey.from_token(row[0]).type_name
                                            == COUPLING_TYPE))
    binding = {
        "schema": SCHEMA, "namespace": namespace.as_tuple,
        "graph_incarnation": expected_graph_incarnation,
        "graph_revision": expected_graph_revision,
        "query_epoch": expected_query_epoch.revision,
        "catalogue_hash": registry.catalogue_hash,
        "access_epoch": expected_access_epoch,
        "delete_epoch": expected_delete_epoch,
        "checkpoint": (checkpoint_ref, root_atom.revision,
                       canonical_digest(root_atom.value)),
        "graph_state": (state.key.token, state.revision),
        "graph_state_value_digest": canonical_digest(state.value),
        "source_refs": source_refs,
        "scheme_version": scheme.scheme_version,
        "operator_version": scheme.operator_version,
        "parameter_version": scheme.parameter_version,
        "coupling_version": scheme.coupling_version,
        "fixed_template_asset_digest": expected_asset_digest,
        "axis_ids": axes, "axis_units": units,
        "numeric_coupling_rows_digest": numeric_digest,
        "read_versions": tuple((item.key.token, item.revision)
                               for item in read_versions),
        "read_values_digest": read_values_digest,
    }
    return D04UnsignedCouplingSnapshotCandidateV1(
        namespace, expected_graph_incarnation, expected_graph_revision,
        expected_query_epoch, registry.catalogue_hash,
        expected_access_epoch, expected_delete_epoch,
        scheme.scheme_version, scheme.operator_version,
        scheme.parameter_version, scheme.coupling_version,
        axes, units, expected_asset_digest, checkpoint_ref,
        root_atom.revision, canonical_digest(root_atom.value),
        GraphVersion(state.key, state.revision), canonical_digest(state.value),
        source_refs, numeric_digest, coupling_versions, read_versions,
        read_values_digest,
        canonical_digest(binding),
    )
