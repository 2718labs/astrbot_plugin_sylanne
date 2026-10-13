"""Compact, independently authenticated C09 V2 PREPARED originals.

V1 originals keep their existing table and signature domain. A selected
manifest must resolve to exactly one registered operation version.
"""
from __future__ import annotations

import json
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import MAX_DESCRIPTOR_BYTES_V2

SCHEMA_V2 = "sylanne3.c09.storage_prepared_original.v2"
TABLE_V2 = "c09_storage_operations_v2"
DDL_V2 = """CREATE TABLE c09_storage_operations_v2(
 operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0), expected_pointer_version INTEGER NOT NULL CHECK(expected_pointer_version>=0),
 old_manifest_digest TEXT NOT NULL REFERENCES c09_storage_manifests_v1(manifest_digest),
 new_manifest_digest TEXT NOT NULL UNIQUE REFERENCES c09_storage_manifests_v1(manifest_digest),
 prepared_original_json TEXT NOT NULL, prepared_digest TEXT NOT NULL UNIQUE, key_id TEXT NOT NULL, signature TEXT NOT NULL) STRICT"""
PREPARED_FIELDS_V2 = frozenset("schema authority_id installation_id namespace operation_id maintenance_generation expected_pointer_version old_manifest_digest new_manifest_digest prior_prepared_digest capture_scope_digest accepted_receipt_digest barrier_receipt_digest writer_freeze_digest facts_complete_original_digest facts_pin_digest graph_issue_original_digest graph_mirror_original_digest four_role_complete_original_digests anchor_transition_original frozen_inventory_digest frozen_scan_digest cumulative_tombstone_root deletion_watermark source_final_fingerprints prepared_digest key_id signature".split())


def install_prepared_schema_v2(control, db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V2,)).fetchone()
    if row is None:
        db.execute(DDL_V2)
        for action in ("UPDATE", "DELETE"):
            db.execute(control._immutable_ddl(TABLE_V2, action))
    validate_prepared_schema_v2(control, db)


def validate_prepared_schema_v2(control, db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V2,)).fetchone()
    if row is None or row[0] != DDL_V2:
        raise AuthorityUnavailable("C09 V2 operation schema differs")
    for action in ("UPDATE", "DELETE"):
        name = TABLE_V2 + "_no_" + action.lower()
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None or row[0] != control._immutable_ddl(TABLE_V2, action):
            raise AuthorityUnavailable("C09 V2 operation immutable trigger differs")


def _build_original(control, db, operation_id, kind, expected_digest=None):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_storage_build_originals_v1'").fetchone() is None:
        raise AuthorityUnavailable("C09 V2 PREPARED actual build-original table absent")
    row = db.execute("SELECT length(CAST(original_json AS BLOB)) FROM c09_storage_build_originals_v1 WHERE installation_id=? AND operation_id=? AND original_kind=?", (control.installation_id, operation_id, kind)).fetchone()
    if row is None or row[0] > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("C09 V2 PREPARED build reference absent or exceeds descriptor bound")
    from .c09_storage_control_v1 import canonical
    stored = db.execute("SELECT original_json,original_digest FROM c09_storage_build_originals_v1 WHERE installation_id=? AND operation_id=? AND original_kind=?", (control.installation_id, operation_id, kind)).fetchone()
    raw = stored[0]
    original = json.loads(raw)
    control.verify_original_v1(original, "original_digest")
    if (original["installation_id"] != control.installation_id or original["operation_id"] != operation_id
            or original["original_kind"] != kind or original["original_digest"] != stored[1]
            or canonical(original) != raw):
        raise AuthorityUnavailable("C09 V2 PREPARED signed build identity differs")
    if expected_digest is not None and original["original_digest"] != expected_digest:
        raise AuthorityUnavailable("C09 V2 PREPARED lost its actual signed " + kind)
    return original["details"]


def verify_prepared_original_v2(control, db, original, manifest):
    from ..segmented_sql_cell_v1 import require_legacy_storage_file_v3
    for member in manifest['members']:
        require_legacy_storage_file_v3(member['resolved_path'])
    if manifest['schema'] == 'sylanne3.c09.storage_manifest.v3':
        raise AuthorityUnavailable('V2 PREPARED cannot qualify segmented V3 storage')
    return _verify_paged_prepared_original_v2(control, db, original, manifest,
        expected_schema=SCHEMA_V2, expected_fields=PREPARED_FIELDS_V2)


def _verify_paged_prepared_original_v2(control, db, original, manifest, *, expected_schema, expected_fields):
    """Common actual paged facts; each version owns its exact signed field domain."""
    from .c09_storage_control_v1 import ROLES
    if (type(original) is not dict or set(original) != expected_fields
            or original["schema"] != expected_schema
            or len(canonical_serialize(original).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2):
        raise AuthorityUnavailable("C09 V2 compact PREPARED fields or bound differ")
    control.verify_original_v1(original, "prepared_digest")
    if ((original["authority_id"], original["installation_id"]) != (control.authority_id, control.installation_id)
            or original["new_manifest_digest"] != manifest["manifest_digest"]
            or original["maintenance_generation"] != manifest["generation"]
            or original["namespace"] != manifest["cohort_namespaces"][0]
            or original["old_manifest_digest"] != manifest["prior_manifest_digest"]):
        raise AuthorityUnavailable("C09 V2 PREPARED installation or manifest lineage differs")
    op = original["operation_id"]
    scope_details = _build_original(control, db, op, "capture_scope_v2")
    from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
    scope = C09CaptureScopeV2(**scope_details)
    if (scope.scope_digest != original["capture_scope_digest"]
            or scope.operation_id != op or scope.authority_namespace != original["namespace"]
            or scope.expected_pointer_version != original["expected_pointer_version"]
            or scope.old_manifest_digest != original["old_manifest_digest"]
            or scope.maintenance_generation != original["maintenance_generation"]
            or scope.accepted_receipt_digest != original["accepted_receipt_digest"]
            or scope.barrier_digest != original["barrier_receipt_digest"]
            or scope.writer_freeze_digest != original["writer_freeze_digest"]):
        raise AuthorityUnavailable("C09 V2 PREPARED differs from actual capture scope")
    facts_raw = _build_original(control, db, op, "capture_facts_complete_v2", original["facts_complete_original_digest"])
    from .c09_paged_recovery_facts_v2 import _decode_completion
    facts = _decode_completion(facts_raw)
    if (facts.scope_digest != scope.scope_digest or facts.facts_intent_digest != scope.facts_pin_intent_digest
            or facts.pin_digest != original["facts_pin_digest"] or facts.pin_digest != manifest["recovery_pin_digest"]):
        raise AuthorityUnavailable("C09 V2 PREPARED complete facts pin differs")
    issue = _build_original(control, db, op, "graph_issued_v2", original["graph_issue_original_digest"])
    mirror = _build_original(control, db, op, "graph_mirror_v2", original["graph_mirror_original_digest"])
    if (issue["issue_digest"] != manifest["graph_issue_digest"]
            or mirror["graph_issue_digest"] != issue["issue_digest"]
            or mirror["certificate_digest"] != manifest["certificate_digest"]
            or mirror["scope_digest"] != scope.scope_digest):
        raise AuthorityUnavailable("C09 V2 PREPARED issued Graph mirror differs")
    refs = original["four_role_complete_original_digests"]
    if type(refs) is not dict or tuple(sorted(refs)) != ROLES:
        raise AuthorityUnavailable("C09 V2 PREPARED requires exactly four completed roles")
    for member in manifest["members"]:
        role = member["role"]
        details = _build_original(control, db, op, "capture_role_complete_v2_" + role, refs[role])
        if (details["scope_digest"] != scope.scope_digest or details["role"] != role
                or details["target_path"] != member["resolved_path"]
                or details["target_sha256"] != member["prepared_sha256"]
                or tuple(details["target_identity"])[:2] != (member["device"], member["file_id"])
                or details["target_schema_digest"] != member["schema_objects_digest"]
                or details["cold_digest"] != member["cold_read_digest"]):
            raise AuthorityUnavailable("C09 V2 PREPARED completed role differs: " + role)
    if (original["frozen_inventory_digest"] != manifest["inventory_manifest_digest"]
            or original["cumulative_tombstone_root"] != manifest["cumulative_tombstone_root"]
            or original["deletion_watermark"] != manifest["deletion_watermark"]):
        raise AuthorityUnavailable("C09 V2 PREPARED inventory or deletion head differs")
    from .c09_storage_manifest_v2 import SCHEMA_V2 as MANIFEST_SCHEMA_V2, require_manifest_actual_provenance_v2
    if manifest["schema"] == MANIFEST_SCHEMA_V2:
        require_manifest_actual_provenance_v2(control, db, manifest, original)
    return original


def read_selected_prepared_v2(control, db, manifest):
    """Return V2 only when V1 absence and exact V2 schema/row are proven."""
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V2,)).fetchone()
    if row is None:
        return None
    validate_prepared_schema_v2(control, db)
    metadata = db.execute("SELECT operation_id,length(CAST(prepared_original_json AS BLOB)) FROM c09_storage_operations_v2 WHERE new_manifest_digest=?", (manifest["manifest_digest"],)).fetchone()
    if metadata is None:
        return None
    if metadata[1] > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("C09 V2 selected PREPARED exceeds its descriptor bound")
    if db.execute("SELECT 1 FROM c09_storage_operations_v1 WHERE new_manifest_digest=?", (manifest["manifest_digest"],)).fetchone() is not None:
        raise AuthorityUnavailable("C09 selected manifest has conflicting operation versions")
    row = db.execute("SELECT * FROM c09_storage_operations_v2 WHERE operation_id=?", (metadata[0],)).fetchone()
    raw = row["prepared_original_json"]
    value = json.loads(raw)
    from .c09_storage_control_v1 import canonical
    if canonical(value) != raw:
        raise AuthorityUnavailable("C09 V2 selected PREPARED canonical bytes differ")
    verify_prepared_original_v2(control, db, value, manifest)
    columns = (("operation_id", "operation_id"), ("installation_id", "installation_id"),
               ("namespace", "namespace"), ("generation", "maintenance_generation"),
               ("expected_pointer_version", "expected_pointer_version"),
               ("old_manifest_digest", "old_manifest_digest"), ("new_manifest_digest", "new_manifest_digest"),
               ("prepared_digest", "prepared_digest"), ("key_id", "key_id"), ("signature", "signature"))
    if any(row[column] != value[field] for column, field in columns):
        raise AuthorityUnavailable("C09 V2 selected PREPARED row differs")
    return value


def retain_verified_authority_role_v2(session, verified):
    """Persist only a complete private role result from this actual session."""
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_authority_storage_rebase_v2 import VerifiedAuthorityRoleRebaseV2
    if type(session) is not C09PagedCaptureSessionV2 or type(verified) is not VerifiedAuthorityRoleRebaseV2:
        raise AuthorityUnavailable("actual installed private authority role result required")
    session.require_current()
    verified.require_current()
    if verified.builder.session is not session or verified.scope != session.scope:
        raise AuthorityUnavailable("completed authority role belongs to another actual operation")
    details = verified.compact_header()
    if len(canonical_serialize(details).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("completed authority role exceeds descriptor bound")
    original = session._control.maintenance.control.record_build_original_v1(
        operation_id=session.scope.operation_id,
        kind="capture_role_complete_v2_" + verified.role, details=details)
    verified.require_current()
    session.require_current()
    return original


def retain_verified_graph_role_v2(session, verified, issued):
    """The Graph role must come from the fresh post-mirror cold sweep."""
    from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
    from .c09_graph_rebase_issue_v2 import record_current_graph_rebase_mirror_v2
    if type(verified) is not VerifiedGraphRebaseColdV2 or verified.session is not session:
        raise AuthorityUnavailable("actual installed private Graph cold result required")
    mirror = record_current_graph_rebase_mirror_v2(session, verified, issued)
    candidate = verified.require_current()
    details = dict(schema="sylanne3.c09.verified-graph-role-rebase.v2",
        scope_digest=session.scope.scope_digest, role="graph",
        source_original=__import__("dataclasses").asdict(candidate.source),
        target_path=verified.pair.target_path, target_identity=verified.target_identity,
        target_sha256=verified.target_file_sha256, cold_digest=verified.cold_read_digest,
        target_schema_digest=verified.target_schema_digest,
        graph_mirror_original_digest=mirror["original_digest"],
        schema_directory=__import__("dataclasses").asdict(candidate.schema_catalogue),
        stream_directory=__import__("dataclasses").asdict(candidate.target_directory))
    if len(canonical_serialize(details).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("completed Graph role exceeds descriptor bound")
    original = session._control.maintenance.control.record_build_original_v1(
        operation_id=session.scope.operation_id, kind="capture_role_complete_v2_graph", details=details)
    verified.require_current()
    return original


def record_prepared_storage_v2(control, *, manifest, prepared_original, closing_continuation):
    """Register the compact transition under the actual continuous final gate."""
    if manifest['schema']=='sylanne3.c09.storage_manifest.v3':
        raise AuthorityUnavailable('V2 PREPARED cannot qualify segmented V3 storage')
    from .c09_storage_control_v1 import canonical, ROLES
    control._manifest(manifest)
    op = prepared_original["operation_id"]
    intent = control.read_operation_event_v1(op, "INTENT")
    for member in manifest["members"]:
        if member["resolved_path"] != intent["details"]["targets"][member["role"]]:
            raise AuthorityUnavailable("C09 V2 candidate differs from actual registered INTENT")
        control.verify_member_v1(member, prepared=True)
    with control._db(write=True) as db:
        current = control._current(db)
        install_prepared_schema_v2(control, db)
        verify_prepared_original_v2(control, db, prepared_original, manifest)
        prior = db.execute("SELECT prepared_original_json FROM c09_storage_operations_v2 WHERE operation_id=?", (op,)).fetchone()
        if db.execute("SELECT 1 FROM c09_storage_operations_v1 WHERE operation_id=? OR new_manifest_digest=?", (op, manifest["manifest_digest"])).fetchone() is not None:
            raise AuthorityUnavailable("C09 V2 operation conflicts with a V1 original")
        if prior is not None:
            if prior[0] != canonical(prepared_original):
                raise AuthorityUnavailable("C09 V2 PREPARED replay differs")
            return control._event(db, current, operation_id=op, stage="PREPARED", details={
                "prepared_digest": prepared_original["prepared_digest"], "new_manifest_digest": manifest["manifest_digest"]})
        if (current["stage"] != "INTENT" or current["active_operation_id"] != op
                or current["pointer_version"] != prepared_original["expected_pointer_version"]
                or current["current_manifest_digest"] != prepared_original["old_manifest_digest"]):
            raise AuthorityUnavailable("C09 V2 PREPARED exact current predecessor changed")
        if (intent["details"]["accepted_receipt_digest"] != prepared_original["accepted_receipt_digest"]
                or intent["details"]["quiescence_original"]["quiescence_digest"] != prepared_original["writer_freeze_digest"]):
            raise AuthorityUnavailable("C09 V2 PREPARED actual acceptance or writer freeze differs")
        gate = control._final_gate_v3
        gate.require_final_continuation_v3(closing_continuation, operation_id=op, observe=False)
        # The actual closed inventory scan is referenced and independently
        # checked; a caller digest or completed-row flag cannot replace it.
        from .c09_prepared_inventory_v2 import require_prepared_inventory_v2
        require_prepared_inventory_v2(control, db, prepared_original, gate)
        old = control._read_manifest(db, prepared_original["old_manifest_digest"])
        if manifest["generation"] != old["generation"] + 1:
            raise AuthorityUnavailable("C09 V2 PREPARED generation does not follow its actual predecessor")
        control._store_manifest(db, manifest)
        db.execute("INSERT INTO c09_storage_operations_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
            op, control.installation_id, prepared_original["namespace"], manifest["generation"],
            prepared_original["expected_pointer_version"], old["manifest_digest"], manifest["manifest_digest"],
            canonical(prepared_original), prepared_original["prepared_digest"], control.key_id, prepared_original["signature"]))
        return control._event(db, current, operation_id=op, stage="PREPARED", details={
            "prepared_digest": prepared_original["prepared_digest"], "new_manifest_digest": manifest["manifest_digest"]})


def switch_prepared_storage_v2(control, *, operation_id, quiescence_original):
    """Perform the same four-file pointer CAS using the actual V2 original."""
    from .c09_storage_control_v1 import canonical, file_observation_v1
    control.verify_original_v1(quiescence_original, "quiescence_digest")
    with control._db(write=True) as db:
        current = control._current(db)
        validate_prepared_schema_v2(control, db)
        row = db.execute("SELECT new_manifest_digest FROM c09_storage_operations_v2 WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise AuthorityUnavailable("C09 V2 switch PREPARED absent")
        new = control._read_manifest(db, row[0])
        prepared = read_selected_prepared_v2(control, db, new)
        old = control._read_manifest(db, prepared["old_manifest_digest"])
        details = {"prepared_digest": prepared["prepared_digest"],
                   "quiescence_digest": quiescence_original["quiescence_digest"],
                   "quiescence_original": quiescence_original}
        existing = db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='SWITCHED'", (operation_id,)).fetchone()
        if existing is not None:
            event = json.loads(existing[0])
            control.verify_original_v1(event, "event_digest")
            if event["details"]["prepared_digest"] != prepared["prepared_digest"]:
                raise AuthorityUnavailable("C09 V2 SWITCHED replay conflicts")
            return event
        if (current["stage"] != "PREPARED" or current["active_operation_id"] != operation_id
                or (current["pointer_version"], current["current_manifest_digest"]) !=
                   (prepared["expected_pointer_version"], old["manifest_digest"])):
            raise AuthorityUnavailable("C09 V2 four-file switch CAS differs")
        if (quiescence_original["operation_id"] != operation_id
                or quiescence_original["pointer_version"] != current["pointer_version"]
                or quiescence_original["active_writers"] != 0):
            raise AuthorityUnavailable("C09 V2 current switch quiescence differs")
        for member in new["members"]:
            control.verify_member_v1(member, prepared=True)
        for source in prepared["source_final_fingerprints"]:
            if file_observation_v1(source["resolved_path"], exclusive=True) != source:
                raise AuthorityUnavailable("C09 V2 final source fingerprint changed")
        event = control._event(db, current, operation_id=operation_id, stage="SWITCHED", details=details, manifest=new)
        for member in old["members"]:
            source = next((value for value in prepared["source_final_fingerprints"]
                           if value["resolved_path"] == member["resolved_path"]), None)
            if source is None:
                raise AuthorityUnavailable("C09 V2 old-file retirement observation absent")
            db.execute("INSERT INTO c09_storage_retired_files_v1 VALUES(?,?,?,?,?,?,?)", (
                control.installation_id, member["role"], old["generation"], member["resolved_path"],
                canonical(source), source["prepared_sha256"], event["event_digest"]))
        return event
