"""Exact cold PREPARED pointer switch before ordinary store constructors.

The protected control journal and actual installation OS lease are the only
writers here. Frozen source and target SQLite files remain immutable reads.
"""
from contextlib import closing
from pathlib import Path
import json
import sqlite3

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1, ROLES, digest, file_observation_v1


def _frozen_read(path, expected, reader):
    path = Path(path)
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AuthorityUnavailable("C09 preopen frozen file has a sidecar")
    if file_observation_v1(path, exclusive=True) != expected:
        raise AuthorityUnavailable("C09 preopen frozen fingerprint differs")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AuthorityUnavailable("C09 preopen frozen integrity differs")
        reader(db)
    if file_observation_v1(path, exclusive=True) != expected:
        raise AuthorityUnavailable("C09 preopen frozen file changed during validation")


def _source_reader(role, prepared, control):
    namespace = prepared["namespace"]
    anchor = prepared["old_core_anchor_original"]
    def read(db):
        if role == "core":
            if db.execute("SELECT value FROM authority_meta WHERE key='authority_id'").fetchone() != (control.authority_id,):
                raise AuthorityUnavailable("C09 preopen source Authority identity differs")
            names = ("generation", "deletion_journal_id", "deletion_seq", "deletion_digest", "execution_journal_id",
                     "execution_seq", "execution_digest", "revocation_epoch", "anchor_nonce")
            expected = tuple(anchor[name] for name in ("activation_generation", "deletion_journal_id", "deletion_seq",
                "deletion_digest", "execution_journal_id", "execution_seq", "execution_digest", "revocation_epoch", "proof"))
            if db.execute("SELECT " + ",".join(names) + " FROM authority_namespaces WHERE namespace=?", (namespace,)).fetchone() != expected:
                raise AuthorityUnavailable("C09 preopen source Core anchor differs")
        elif role == "deletion":
            expected = prepared["old_deletion_head_original"]
            meta = dict(db.execute("SELECT key,value FROM deletion_meta"))
            row = db.execute("SELECT seq,chain_digest FROM authority_deletion_v2_tail ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None:
                row = db.execute("SELECT seq,chain_digest FROM deletion_events ORDER BY seq DESC LIMIT 1").fetchone()
            actual = (0, "genesis") if row is None else row
            if (meta.get("journal_id"), *actual) != (expected["journal_id"], expected["seq"], expected["digest"]):
                raise AuthorityUnavailable("C09 preopen independent deletion head differs")
        elif role == "execution":
            expected = prepared["old_execution_head_original"]
            meta = dict(db.execute("SELECT key,value FROM authority_v2_execution_meta"))
            row = db.execute("SELECT seq,chain_digest FROM authority_v2_execution_entries ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None and meta.get("schema_version") == "4":
                row = db.execute("SELECT old_seq,old_digest FROM authority_v2_execution_redacted_prefix_v4 WHERE singleton=1").fetchone()
            actual = (0, "genesis") if row is None else row
            if (meta.get("namespace"), meta.get("journal_id"), *actual) != (namespace, expected["journal_id"], expected["seq"], expected["digest"]):
                raise AuthorityUnavailable("C09 preopen independent execution head differs")
        else:
            certificate = prepared["graph_certificate_original"]
            if (certificate["namespace"], certificate["authority_id"]) != (namespace, control.authority_id):
                raise AuthorityUnavailable("C09 preopen source certificate identity differs")
            rows = [(json.loads(payload), revision) for payload, revision in db.execute(
                "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2")]
            scoped = [(raw, revision) for raw, revision in rows if raw.get("authority_namespace") == namespace]
            if len(scoped) != 1:
                raise AuthorityUnavailable("C09 preopen source Graph cohort differs")
            raw, revision = scoped[0]
            if (raw is None or raw.get("authority_id") != control.authority_id
                    or raw.get("authority_namespace") != namespace
                    or (raw.get("graph_incarnation"), revision) !=
                       (prepared["old_graph_head_original"]["incarnation"], prepared["old_graph_head_original"]["revision"])):
                raise AuthorityUnavailable("C09 preopen source Graph head differs")
    return read


def switch_cold_prepared_storage_before_open_v1(*, control, registry=None):
    """Consume actual PREPARED exactly; call before any running-store open."""
    from .c09_process_identity_v1 import require_process_retired_v1
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from .c09_authority_storage_rebase import _root, _objects
    from .c09_build_originals_v1 import decode_installed_build_original_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, _cold_graph_data_root
    if type(control) is not C09StorageControlV1:
        raise AuthorityUnavailable("C09 installed preopen control required")
    control.lease.require_held()
    context = control.read_verified_current_storage_v1()
    if context.stage != "PREPARED":
        if context.stage not in {"READY", "SWITCHED", "CLEANED", "RELEASED"}:
            raise AuthorityUnavailable("C09 preopen stage requires repair")
        return context
    # PREPARED deliberately still selects the old manifest, whose previously
    # applied original (if any) is not this in-progress transition.
    from .c09_storage_control_v1 import _PREPARED_FIELDS
    with control._db() as db:
        pointer = control._current(db)
        row = db.execute("SELECT prepared_original_json,prepared_digest,signature FROM c09_storage_operations_v1 WHERE operation_id=?",
                         (pointer["active_operation_id"],)).fetchone()
    if row is None:
        raise AuthorityUnavailable("C09 preopen actual PREPARED row absent")
    prepared = json.loads(row[0])
    if (set(prepared) != _PREPARED_FIELDS or prepared["prepared_digest"] != row[1]
            or prepared["signature"] != row[2] or prepared["old_manifest_digest"] != context.manifest_digest
            or prepared["expected_pointer_version"] != context.pointer_version
            or prepared["operation_id"] != pointer["active_operation_id"]):
        raise AuthorityUnavailable("C09 preopen PREPARED row/pointer differs")
    operation = prepared["operation_id"]
    control.verify_original_v1(prepared, "prepared_digest")
    quiescence = prepared["writer_quiescence_original"]
    control.verify_original_v1(quiescence, "quiescence_digest")
    if (quiescence.get("operation_id"), quiescence.get("pointer_version"), quiescence.get("active_writers")) != (operation, context.pointer_version, 0):
        raise AuthorityUnavailable("C09 preopen original writer scope differs")
    retired = require_process_retired_v1(quiescence["authority_process_original"])
    for original in quiescence["retired_worker_originals"] + quiescence["retired_peer_originals"]:
        if original.get("state") != "retired" or require_process_retired_v1(original["original_process"]) != original:
            raise AuthorityUnavailable("C09 preopen old cache-holder retirement differs")
    sources = {item["resolved_path"]: item for item in prepared["source_final_fingerprints"]}
    if len(sources) != len(ROLES):
        raise AuthorityUnavailable("C09 preopen source must be four sidecar-free files")
    for member in context.manifest["members"]:
        expected = sources.get(member["resolved_path"])
        if expected is None:
            raise AuthorityUnavailable("C09 preopen source fingerprint absent")
        _frozen_read(member["resolved_path"], expected, _source_reader(member["role"], prepared, control))
    with control._db() as db:
        target = control._read_manifest(db, prepared["new_manifest_digest"])
    original = control.read_build_original_v1(operation_id=operation, kind="graph_candidate")
    if original is None:
        raise AuthorityUnavailable("C09 preopen actual Graph candidate original absent")
    graph = decode_installed_build_original_v1(original["details"]["candidate"], GraphRebaseCandidateV1)
    from .c09_retired_prepared_marker_v1 import verify_retired_prepared_marker_v1
    target_members = {item["role"]: item for item in target["members"]}
    verify_retired_prepared_marker_v1(core_path=Path(target_members["core"]["resolved_path"]),
        source_core_path=Path(next(item["resolved_path"] for item in context.manifest["members"] if item["role"] == "core")),
        execution_path=Path(target_members["execution"]["resolved_path"]), namespace=prepared["namespace"], operation_id=operation,
        expected_pin_digest=prepared["facts_pin_original"]["pin_digest"], expected_issue_digest=prepared["graph_issue_original"]["issue_digest"],
        expected_new_journal_id=target_members["execution"]["incarnation_or_journal_id"], maintenance_generation=target["generation"])
    for member in target["members"]:
        expected = {name: member[name] for name in sources[next(iter(sources))]}
        def target_read(db, member=member):
            if digest(_objects(db)) != member["schema_objects_digest"]:
                raise AuthorityUnavailable("C09 preopen target schema differs")
            if member["role"] == "graph":
                root, cold = _cold_graph_data_root(Path(member["resolved_path"]), graph.namespace,
                    set(graph.affected_atom_refs), graph.new_incarnation, graph.cumulative_erased_key_digests, candidate_connection=db, registry=registry)
                if cold != member["cold_read_digest"]:
                    raise AuthorityUnavailable("C09 preopen target Graph cold proof differs")
            else:
                root = _root(db)
            if root != member["logical_data_root"]:
                raise AuthorityUnavailable("C09 preopen target logical root differs")
        _frozen_read(member["resolved_path"], expected, target_read)
    gate = InstalledC09WriterGateV1(control=control)
    new_quiescence = gate.revoke_and_drain_v1(operation_id=operation)
    from ..runtime_contracts import canonical_digest
    kind = "preopen_switch_quiescence:" + canonical_digest(new_quiescence["authority_process_original"])
    control.record_build_original_v1(operation_id=operation, kind=kind,
        details={"prepared_digest": prepared["prepared_digest"], "retired_authority_original": retired,
                 "quiescence_original": new_quiescence})
    control.switch_prepared_storage_v1(operation_id=operation, quiescence_original=new_quiescence)
    return control.read_verified_current_storage_v1()
