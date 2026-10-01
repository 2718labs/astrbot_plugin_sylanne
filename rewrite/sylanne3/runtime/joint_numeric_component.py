"""Complete, unsigned graph inventory for a connected D04 numeric component.

This is a structural HOLD. The installed 24D asset and snapshot signer cannot
compile a multi-block operator, and this reader does not round summed drives
into solver inputs or issue an ABI2/product certificate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.affect import AffectScheme
from ..domains.d04.numeric_coupling import (
    REGISTERED_AXIS_IDS, TYPE_NAME as EDGE_TYPE, NumericCoupling,
    validate_numeric_coupling,
)
from ..domains.d04.numeric_drive import TYPE_NAME as DRIVE_TYPE, decode_sourced_numeric_drive
from ..domains.d04.root import decode_numeric_checkpoint
from ..domains.d04.source_head import D04SourceHeadRead, _qualified_head
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, TypeRegistry
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest


CHECKPOINT_TYPE = "d04.numeric_checkpoint.v1"
AUTHORED_CHECKPOINT_TYPE = "d04.numeric_checkpoint.v2"
MAX_ROWS = 512


class JointNumericHold(ValueError):
    """The current graph cannot support a complete unsigned joint component."""


@dataclass(frozen=True, slots=True)
class JointBlockDrives:
    checkpoint_ref: str
    checkpoint_version: GraphVersion
    graph_state_version: GraphVersion
    initial_state: tuple[float, ...]
    drive_versions: tuple[GraphVersion, ...]
    drives: tuple[tuple[float, ...], ...]
    predecessor_receipt_digest: str | None = None


@dataclass(frozen=True, slots=True)
class JointNumericComponentCandidate:
    namespace: NamespaceId
    catalogue_hash: str
    query_epoch: QueryEpoch
    graph_incarnation: str
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    checkpoint_refs: tuple[str, ...]
    edges: tuple[NumericCoupling, ...]
    block_drives: tuple[JointBlockDrives, ...]
    read_versions: tuple[GraphVersion, ...]
    read_values_digest: str
    candidate_digest: str
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "joint_operator_asset_and_abi2_binding",
        "per_block_drive_exact_sum_rounding_error_bound",
        "semantic_drive_mapping_issuer_verification",
        "joint_readout_and_initial_box_certificate",
        "w01_atomic_joint_adoption",
    )
    root_original_digest: str | None = None


def _authored_predecessor_original(
    db: sqlite3.Connection, namespace: NamespaceId, checkpoint_ref: str,
    checkpoint_revision: int, checkpoint, state,
) -> tuple[str, str]:
    """Replay committed root/advance/output history down to the authored root."""
    from ..domains.d04.authored_lineage_v3 import (
        decode_authored_numeric_checkpoint_v2, decode_authored_feeling_state_v1,
        decode_authored_mood_state_v1, decode_authored_root_candidate_v3,
        validate_authored_joint_predecessor_v3,
    )
    from ..domains.d04.joint_state_output_v1 import (
        AUTHORED_SCHEMA, _write_set, joint_checkpoint_payload_v1, joint_state_payload_v1,
    )
    from .d04_joint_advance_v2 import read_joint_advance_v2, _numeric_history
    from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
    from .d04_root_original_store_v1 import _receipt
    from .d04_root_original_store_v3 import read_d04_root_original_v3

    def history(ref: str, revision: int, operation_id: str) -> dict:
        activity_id = ("d04.authored_root.v3" if operation_id == root.operation_id
                       else _receipt(db, namespace, operation_id).activity_id)
        rows = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (ref, revision, *namespace.as_tuple, activity_id, operation_id),
        ).fetchall()
        if len(rows) != 1 or rows[0][1] != 1:
            raise ValueError("authored predecessor history is absent or ambiguous")
        value = json.loads(rows[0][0])
        if canonical_json(value) != rows[0][0]:
            raise ValueError("authored predecessor history is noncanonical")
        return value

    root = read_d04_root_original_v3(
        db, namespace=namespace, operation_id=state.root_operation_id)
    root_candidate = decode_authored_root_candidate_v3(json.loads(root.candidate_json))
    root_rows = {ref: (revision, value) for ref, revision, value in
                 json.loads(root.output_json)["rows"]}
    def receipt_digest(operation_id: str) -> str:
        # Authored initialization owns a GraphReceipt, later W01 bundles own CommitReceipts.
        return (root.graph_receipt_digest if operation_id == root.operation_id
                else canonical_digest(asdict(_receipt(db, namespace, operation_id))))

    current_receipt_digest = receipt_digest(checkpoint.commit_operation_id)
    while checkpoint_revision > 1:
        validate_authored_joint_predecessor_v3(checkpoint, state, checkpoint_revision)
        operation_id = checkpoint.commit_operation_id
        from .d04_series_original_v1 import require_series_adopted_original_v1
        require_series_adopted_original_v1(db, namespace, operation_id)
        evidence = read_joint_advance_v2(db, namespace, operation_id)
        output = read_d04_joint_output_original_v1(db, namespace, operation_id)
        if evidence is None or output is None:
            raise ValueError("authored continuation originals are absent")
        _numeric_history(db, evidence)
        members = [item for item in evidence.members if item.checkpoint_ref == checkpoint_ref]
        outputs = [item for item in output.members if item.checkpoint_ref == checkpoint_ref]
        if len(members) != 1 or len(outputs) != 1:
            raise ValueError("authored continuation member original is incomplete")
        member, emitted = members[0], outputs[0]
        receipt = _receipt(db, namespace, operation_id)
        if (evidence.schema != "d11.product_advance_evidence.v3"
                or output.schema != AUTHORED_SCHEMA
                or receipt.operation_digest != evidence.bundle_digest
                or output.member_refs != tuple(item.checkpoint_ref for item in evidence.members)
                or output.write_set_digest != evidence.output_write_set_digest
                or canonical_digest(_write_set(output.members)) != output.write_set_digest
                or output.role_start != evidence.role_start or output.role_end != evidence.role_end
                or evidence.role_end != checkpoint.cursor
                or member.next_revision != checkpoint_revision
                or member.output_state_ref != checkpoint.graph_state.ref
                or member.output_state_revision != state.revision
                or member.next_value_digest != canonical_digest(joint_checkpoint_payload_v1(checkpoint))
                or member.output_state_digest != canonical_digest(joint_state_payload_v1(state))
                or member.next_error_bound != checkpoint.numeric_error_bound
                or emitted.next_checkpoint != checkpoint or emitted.next_state != state
                or emitted.predecessor_checkpoint_revision != member.predecessor_revision
                or emitted.predecessor_checkpoint_digest != member.predecessor_value_digest
                or emitted.predecessor_state_ref != member.predecessor_state_ref
                or emitted.predecessor_state_revision != member.predecessor_state_revision
                or emitted.predecessor_state_digest != member.predecessor_state_value_digest
                or canonical_digest(emitted.axes) != checkpoint.readout_proof_digest
                or tuple((axis.axis_id, axis.representative) for axis in emitted.axes) != state.coordinates):
            raise ValueError("authored continuation values or output proof differ")
        prior_value = history(checkpoint_ref, member.predecessor_revision,
                              member.predecessor_operation_id)
        prior = decode_authored_numeric_checkpoint_v2(prior_value)
        prior_state_value = history(member.predecessor_state_ref,
                                    member.predecessor_state_revision,
                                    member.predecessor_operation_id)
        prior_state = (decode_authored_feeling_state_v1(prior_state_value)
                       if prior.block.kind == "feeling"
                       else decode_authored_mood_state_v1(prior_state_value))
        prior_receipt_digest = receipt_digest(member.predecessor_operation_id)
        reads, writes = set(receipt.read_versions), set(receipt.write_versions)
        prior_versions = (
            GraphVersion(AtomKey.from_token(checkpoint_ref), member.predecessor_revision),
            GraphVersion(AtomKey.from_token(member.predecessor_state_ref), member.predecessor_state_revision),
        )
        next_versions = (
            GraphVersion(AtomKey.from_token(checkpoint_ref), member.next_revision),
            GraphVersion(AtomKey.from_token(member.output_state_ref), member.output_state_revision),
        )
        if (not set(prior_versions) <= reads or not set(next_versions) <= writes
                or member.predecessor_revision != checkpoint_revision - 1
                or member.predecessor_state_revision != state.revision - 1
                or member.predecessor_value_digest != canonical_digest(prior_value)
                or member.predecessor_state_value_digest != canonical_digest(prior_state_value)
                or member.predecessor_operation_id != prior.commit_operation_id
                or member.initial_box_digest != prior.certificate_digest
                or member.inherited_error_bound != prior.numeric_error_bound
                or evidence.role_start != prior.cursor
                or checkpoint.predecessor_receipt_digest != prior_receipt_digest
                or checkpoint.block != prior.block or checkpoint.assets != prior.assets
                or checkpoint.root_candidate_digest != prior.root_candidate_digest):
            raise ValueError("authored continuation CAS, interval or inherited error differs")
        fixed_state_fields = set(asdict(state)) - {
            "coordinates", "readout_proof_digest", "cursor", "revision", "status",
            "active_driver_refs", "historical_source_refs", "source_refs",
        }
        if any(getattr(state, name) != getattr(prior_state, name) for name in fixed_state_fields):
            raise ValueError("authored root identity changed during continuation")
        old_sources = (prior_state.historical_source_refs if prior.block.kind == "feeling"
                       else prior_state.source_refs)
        sources = state.historical_source_refs if prior.block.kind == "feeling" else state.source_refs
        if not set(old_sources) <= set(sources):
            raise ValueError("authored continuation drops inherited source provenance")
        checkpoint_revision, checkpoint, state = member.predecessor_revision, prior, prior_state
    validate_authored_joint_predecessor_v3(checkpoint, state, checkpoint_revision)
    if (checkpoint.commit_operation_id != root.operation_id
            or checkpoint.root_candidate_digest != root_candidate.digest
            or state.owner_draft_id != root_candidate.draft_id
            or state.preset_digest != root_candidate.preset.digest
            or root_rows.get(checkpoint_ref) != (1, joint_checkpoint_payload_v1(checkpoint))
            or root_rows.get(checkpoint.graph_state.ref) != (1, joint_state_payload_v1(state))):
        raise ValueError("authored lineage differs from committed root original")
    return root.original_digest, current_receipt_digest


def read_joint_numeric_component(
    db: sqlite3.Connection, *, namespace: NamespaceId, registry: TypeRegistry,
    scheme: AffectScheme, root_ref: str, role_start: float, role_end: float,
    expected_query_epoch: QueryEpoch, expected_graph_incarnation: str,
    expected_graph_revision: int, expected_access_epoch: int,
    expected_delete_epoch: int, audience: tuple[str, ...], purpose: str,
    max_rows: int = MAX_ROWS, authored_topology_verifier=None,
) -> JointNumericComponentCandidate:
    """Read all numeric rows and the root's entire active connected component."""
    from ..domains.d04.authored_lineage_v3 import (
        decode_authored_numeric_checkpoint_v2, decode_authored_feeling_state_v1,
        decode_authored_mood_state_v1,
    )
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(namespace) is not NamespaceId or type(registry) is not TypeRegistry
            or type(scheme) is not AffectScheme
            or type(expected_query_epoch) is not QueryEpoch
            or expected_query_epoch.namespace != namespace
            or expected_query_epoch.scope_ref != "all"
            or type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS
            or type(role_start) not in (int, float)
            or type(role_end) not in (int, float)
            or not math.isfinite(role_start) or not math.isfinite(role_end)
            or role_end <= role_start):
        raise JointNumericHold("joint inventory needs a fenced complete graph query")
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    with d04_series_original_read_scope_v1(db):
        if tuple(axis.axis_id for axis in scheme.axes) != REGISTERED_AXIS_IDS:
            raise JointNumericHold("joint inventory axes differ from registered scheme")
        try:
            root_key = AtomKey.from_token(root_ref)
        except (TypeError, ValueError) as exc:
            raise JointNumericHold("joint root ref is invalid") from exc
        checkpoint_type = root_key.type_name
        if (checkpoint_type not in (CHECKPOINT_TYPE, AUTHORED_CHECKPOINT_TYPE)
                or root_key.owner.kind != "persona"
                or NamespaceId.from_key(root_key) != namespace):
            raise JointNumericHold("joint root crosses namespace or type")
        authored = checkpoint_type == AUTHORED_CHECKPOINT_TYPE
        for type_name in (checkpoint_type, EDGE_TYPE, DRIVE_TYPE):
            try:
                spec = registry.spec(type_name)
            except KeyError as exc:
                raise JointNumericHold("joint numeric type is unregistered") from exc
            if spec.writer_domain != "d04" or spec.owner_kinds != ("persona",):
                raise JointNumericHold("joint numeric type catalogue differs")
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                           namespace.as_tuple).fetchone()
        authority = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone()
        recovery = db.execute(
            "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
        try:
            incarnation = json.loads(recovery[0])["graph_incarnation"] if recovery else None
        except (TypeError, ValueError, KeyError) as exc:
            raise JointNumericHold("joint graph recovery identity is invalid") from exc
        if (epoch != (expected_query_epoch.revision,)
                or authority != (expected_access_epoch, expected_delete_epoch)
                or recovery is None or recovery[1] != expected_graph_revision
                or incarnation != expected_graph_incarnation):
            raise JointNumericHold("joint graph or authority epoch changed")
        rows = db.execute(
            "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN (?,?,?) ORDER BY token LIMIT ?",
            namespace.as_tuple + (checkpoint_type, EDGE_TYPE, DRIVE_TYPE, max_rows + 1),
        ).fetchall()
        if len(rows) > max_rows:
            raise JointNumericHold("joint numeric enumeration exceeds complete page")
        numeric: dict[AtomKey, GraphAtom] = {}
        checkpoints = {}
        edges = {}
        drives = {}
        for token, revision, encoded, valid in rows:
            try:
                key = AtomKey.from_token(token)
                value = json.loads(encoded)
                if (NamespaceId.from_key(key) != namespace or key.owner.kind != "persona"
                        or canonical_json(value) != encoded or type(valid) is not int
                        or valid not in (0, 1)):
                    raise ValueError("numeric row differs")
                atom = GraphAtom(key, revision, value, bool(valid))
                numeric[key] = atom
                if not atom.valid:
                    continue
                if key.type_name == checkpoint_type:
                    node = (decode_authored_numeric_checkpoint_v2(value) if authored
                            else decode_numeric_checkpoint(value))
                    if (node.block.block_id != key.name or node.namespace != namespace.as_tuple
                            or node.axes != REGISTERED_AXIS_IDS):
                        raise ValueError("checkpoint address or axes differ")
                    checkpoints[token] = (atom, node)
                elif key.type_name == EDGE_TYPE:
                    edge = validate_numeric_coupling(value, scheme)
                    if edge.edge_id != key.name or edge.edge_version != revision:
                        raise ValueError("coupling address differs")
                    edges[token] = (atom, edge)
                else:
                    drive = decode_sourced_numeric_drive(value)
                    if drive.drive_id != key.name or drive.drive_version != revision:
                        raise ValueError("drive address differs")
                    drives[token] = (atom, drive)
            except (TypeError, ValueError) as exc:
                raise JointNumericHold("joint numeric graph row is invalid") from exc
        if root_ref not in checkpoints:
            raise JointNumericHold("joint root checkpoint is absent")
        active_edges = {}
        adjacency = {ref: set() for ref in checkpoints}
        for ref, (atom, edge) in edges.items():
            if edge.left_ref not in checkpoints or edge.right_ref not in checkpoints:
                raise JointNumericHold("joint coupling endpoint closure is incomplete")
            overlaps = edge.effective_from < role_end and role_start < edge.effective_until
            if not overlaps:
                continue
            if edge.effective_from > role_start or edge.effective_until < role_end:
                raise JointNumericHold("joint coupling covers only part of drive interval")
            active_edges[ref] = (atom, edge)
            adjacency[edge.left_ref].add(edge.right_ref)
            adjacency[edge.right_ref].add(edge.left_ref)
        component = {root_ref}
        pending = [root_ref]
        while pending:
            for ref in adjacency[pending.pop()] - component:
                component.add(ref)
                pending.append(ref)
        if len(component) < 2:
            raise JointNumericHold("root has no supported joint numeric component")
        component_edges = tuple(sorted(
            ((atom, edge) for atom, edge in active_edges.values()
             if edge.left_ref in component and edge.right_ref in component),
            key=lambda item: item[0].key.token))
        root_original_digest = None
        atoms: dict[AtomKey, GraphAtom] = dict(numeric)

        def load(ref: str) -> GraphAtom:
            try:
                key = AtomKey.from_token(ref)
                if NamespaceId.from_key(key) != namespace:
                    raise ValueError("cross namespace")
            except (TypeError, ValueError) as exc:
                raise JointNumericHold("joint dependency ref is invalid") from exc
            if key not in atoms:
                row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                                 (ref,)).fetchone()
                if row is None:
                    atoms[key] = GraphAtom(key, 0, {}, False)
                else:
                    try:
                        value = json.loads(row[1])
                        if canonical_json(value) != row[1]:
                            raise ValueError("noncanonical")
                    except (TypeError, ValueError) as exc:
                        raise JointNumericHold("joint dependency value is invalid") from exc
                    atoms[key] = GraphAtom(key, row[0], value, bool(row[2]))
            return atoms[key]

        def qualify_source(ref: str) -> None:
            try:
                key = AtomKey.from_token(ref)
            except (TypeError, ValueError) as exc:
                raise JointNumericHold("joint source ref is invalid") from exc
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise JointNumericHold("joint source ref is not canonical")
            source_atom = load(ref)
            access_atom = load(access_key(*namespace.as_tuple, key.owner.subject).token)
            head_atom = load(source_correction_head_key(namespace, key.owner.subject).token)
            if not source_atom.valid or not access_atom.valid or head_atom.revision != 0:
                raise JointNumericHold("joint source is unavailable or corrected")
            try:
                source = SourceRecord.from_dict(source_atom.value)
                validate_access(access_atom.value)
            except (TypeError, ValueError) as exc:
                raise JointNumericHold("joint source or access is invalid") from exc
            if source.parent_source_ids:
                raise JointNumericHold("joint candidate requires an independent root source")
            snapshot = GraphSnapshot((source_atom, access_atom, head_atom),
                                     (NamespaceEpoch(*namespace.as_tuple,
                                                     expected_query_epoch.revision),))
            qualified, reason = _qualified_head(ref, {atom.key: atom for atom in snapshot.atoms},
                D04SourceHeadRead(snapshot, namespace, audience, purpose, None,
                                  False, False, False))
            if qualified is None:
                raise JointNumericHold(f"joint source is unavailable: {reason}")

        authored_topologies = {}
        for edge_atom, edge in component_edges:
            marker = AtomKey.from_token(edge.source_ref)
            if marker.type_name == "d04.authored_root_topology.v3":
                from .d04_owner_initialization_v3 import InstalledD04AuthoredTopologyVerifierV3
                if not authored or type(authored_topology_verifier) is not InstalledD04AuthoredTopologyVerifierV3:
                    raise JointNumericHold("authored topology needs its independent installed verifier")
                if edge.source_ref not in authored_topologies:
                    verified_rows = authored_topology_verifier.verify_in_transaction(db, namespace, edge)
                    verified = {}
                    for ref, revision, value, valid in verified_rows:
                        actual = load(ref)
                        if (actual.revision, actual.value, actual.valid) != (revision, value, valid):
                            raise JointNumericHold("authored topology closure changed")
                        if ref in verified:
                            raise JointNumericHold("authored topology closure duplicated a ref")
                        verified[ref] = actual
                    authored_topologies[edge.source_ref] = verified
                if authored_topologies[edge.source_ref].get(edge_atom.key.token) != edge_atom:
                    raise JointNumericHold("numeric edge is outside the exact adopted authored topology")
            else:
                qualify_source(edge.source_ref)
        blocks = []
        mapping = None
        asset_digest = None
        for ref in sorted(component):
            atom, checkpoint = checkpoints[ref]
            if asset_digest is None:
                asset_digest = checkpoint.asset_digest
            if (checkpoint.cursor != role_start
                    or checkpoint.asset_digest != asset_digest
                    or checkpoint.assets.scheme_version != scheme.scheme_version
                    or checkpoint.assets.operator_version != scheme.operator_version
                    or checkpoint.assets.parameter_version != scheme.parameter_version
                    or checkpoint.assets.coupling_version != scheme.coupling_version):
                raise JointNumericHold("joint checkpoint time or installed versions differ")
            graph_state = load(checkpoint.graph_state.ref)
            if (not graph_state.valid or graph_state.revision != checkpoint.graph_state.revision
                    or graph_state.key.owner != atom.key.owner):
                raise JointNumericHold("joint checkpoint graph state is incomplete")
            try:
                registry.validate(graph_state.key, graph_state.value)
            except (TypeError, ValueError) as exc:
                raise JointNumericHold("joint checkpoint graph state is invalid") from exc
            state_sources = graph_state.value.get(
                "source_refs" if checkpoint.block.kind == "mood"
                else "historical_source_refs")
            if (graph_state.value.get("revision") != graph_state.revision
                    or graph_state.value.get("basis_version") != scheme.scheme_version
                    or graph_state.value.get("parameter_version") != scheme.parameter_version
                    or graph_state.value.get("coupling_version") != scheme.coupling_version
                    or (checkpoint.block.kind == "feeling"
                        and graph_state.value.get("operator_version") != scheme.operator_version)
                    or type(state_sources) is not list):
                raise JointNumericHold("joint checkpoint graph state versions differ")
            for source_ref in state_sources:
                qualify_source(source_ref)
            predecessor_receipt_digest = None
            if authored:
                try:
                    state = (decode_authored_feeling_state_v1(graph_state.value)
                             if checkpoint.block.kind == "feeling"
                             else decode_authored_mood_state_v1(graph_state.value))
                    original_digest, predecessor_receipt_digest = _authored_predecessor_original(
                        db, namespace, ref, atom.revision, checkpoint, state)
                    if root_original_digest is not None and original_digest != root_original_digest:
                        raise ValueError("authored component crosses root originals")
                    root_original_digest = original_digest
                    for driver_ref in state.active_driver_refs:
                        driver = load(driver_ref)
                        if not driver.valid or driver.key.type_name != DRIVE_TYPE:
                            raise ValueError("authored predecessor driver is unavailable")
                        prior_drive = decode_sourced_numeric_drive(driver.value)
                        if (prior_drive.checkpoint_ref != ref
                                or prior_drive.checkpoint_revision != atom.revision - 1
                                or prior_drive.role_end != checkpoint.cursor
                                or prior_drive.source_ref not in state_sources):
                            raise ValueError("authored predecessor driver closure differs")
                        qualify_source(prior_drive.source_ref)
                except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
                    raise JointNumericHold("authored predecessor originals do not bind current values") from exc
            elif checkpoint.block.kind == "feeling":
                # A facet ID is not a graph key. Only the actual D07 interpretation
                # heads can enter the versioned read set; the authored facet and
                # perspective remain the encoding issuer's separate originals.
                interpretation_refs = graph_state.value.get("interpretation_refs")
                if type(interpretation_refs) is not list or not interpretation_refs:
                    raise JointNumericHold("joint Feeling interpretation set is incomplete")
                for interpretation_ref in interpretation_refs:
                    try:
                        interpretation_key = AtomKey.from_token(interpretation_ref)
                        if (NamespaceId.from_key(interpretation_key) != namespace
                                or interpretation_key.type_name not in {
                                    "d07.current_interpretation.v1",
                                    "d07.belief_revision.v1",
                                }):
                            raise ValueError("interpretation scope or type differs")
                        interpretation = load(interpretation_ref)
                        if (not interpretation.valid or interpretation.revision < 1
                                or interpretation.value.get("current") is not True
                                or (interpretation_key.type_name == "d07.belief_revision.v1"
                                    and interpretation.value.get("replaced_by") is not None)):
                            raise ValueError("interpretation is not current")
                        registry.validate(interpretation.key, interpretation.value)
                        interpretation_sources = interpretation.value.get("source_refs")
                        if (type(interpretation_sources) is not list
                                or not interpretation_sources):
                            raise ValueError("interpretation has no source closure")
                        for interpretation_source in interpretation_sources:
                            qualify_source(interpretation_source)
                    except (TypeError, ValueError, KeyError) as exc:
                        raise JointNumericHold(
                            "joint Feeling interpretation original is unavailable") from exc
            if not authored:
                qualify_source(source_key(*namespace.as_tuple,
                                          checkpoint.block.authored_source_id).token)
                if source_key(*namespace.as_tuple,
                              checkpoint.block.authored_source_id).token not in state_sources:
                    raise JointNumericHold("joint authored source is absent from graph state")
            selected = []
            roots = set()
            for drive_atom, drive in drives.values():
                if drive.checkpoint_ref != ref:
                    continue
                overlaps = drive.role_start < role_end and role_start < drive.role_end
                if overlaps and (drive.role_start, drive.role_end) != (role_start, role_end):
                    raise JointNumericHold("joint drive interval partially overlaps")
                if not overlaps:
                    continue
                if (drive.checkpoint_revision != atom.revision
                        or drive.scheme_version != scheme.scheme_version
                        or drive.axis_ids != REGISTERED_AXIS_IDS):
                    raise JointNumericHold("joint drive checkpoint or axes differ")
                current_mapping = (drive.mapping_version, drive.mapping_compiler_ref)
                if mapping is None:
                    mapping = current_mapping
                elif mapping != current_mapping:
                    raise JointNumericHold("joint drive mapping versions differ")
                source_atom = load(drive.source_ref)
                access_atom = load(drive.access_ref)
                if (not source_atom.valid or source_atom.revision != drive.source_revision
                        or not access_atom.valid or access_atom.revision != drive.access_revision):
                    raise JointNumericHold("joint drive source or access is stale")
                qualify_source(drive.source_ref)
                source = SourceRecord.from_dict(source_atom.value)
                if source.provenance_root in roots:
                    raise JointNumericHold("joint drive contribution key repeats")
                roots.add(source.provenance_root)
                selected.append((drive_atom, drive))
            if not selected:
                raise JointNumericHold("joint block has no complete interval drive")
            selected.sort(key=lambda item: item[0].key.token)
            blocks.append(JointBlockDrives(
                ref, GraphVersion(atom.key, atom.revision),
                GraphVersion(graph_state.key, graph_state.revision), checkpoint.latent_state,
                tuple(GraphVersion(item.key, item.revision) for item, _ in selected),
                tuple(drive.drive for _, drive in selected),
                predecessor_receipt_digest,
            ))
        versions = tuple(sorted((GraphVersion(atom.key, atom.revision)
                                 for atom in atoms.values()), key=lambda item: item.key.token))
        values_digest = canonical_digest(tuple(sorted(
            (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
            for atom in atoms.values())))
        edge_values = tuple(edge for _, edge in component_edges)
        binding = (namespace.as_tuple, registry.catalogue_hash, expected_query_epoch.revision,
                   expected_graph_incarnation, expected_graph_revision,
                   expected_access_epoch, expected_delete_epoch,
                   role_start, role_end, tuple(sorted(component)),
                   tuple(edge.edge_id for edge in edge_values), values_digest,
                   root_original_digest)
        if authored:
            binding += (tuple((block.checkpoint_ref, block.predecessor_receipt_digest)
                              for block in blocks),)
        return JointNumericComponentCandidate(
            namespace, registry.catalogue_hash, expected_query_epoch, expected_graph_incarnation,
            expected_graph_revision, expected_access_epoch, expected_delete_epoch,
            role_start, role_end, tuple(sorted(component)), edge_values,
            tuple(blocks), versions, values_digest, canonical_digest(binding),
            root_original_digest=root_original_digest,
        )
