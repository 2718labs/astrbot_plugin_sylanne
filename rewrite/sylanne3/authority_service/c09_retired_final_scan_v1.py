"""Continue an exact closed INTENT checkpoint before any running store opens.

Earlier incomplete builds remain retained for repair. This path consumes actual
old close evidence after OS retirement; it never attributes old handles to the
new process or replaces an already committed candidate.
"""
from contextlib import closing
from dataclasses import asdict
import os
from pathlib import Path
import sqlite3

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import file_observation_v1
from ..runtime_contracts import canonical_digest, canonical_serialize

QUALIFICATION_SCHEMA = "sylanne3.c09.retired_final_scan_qualification.v1"
QUALIFICATION_PREFIX = "retired_final_scan_qualification_v1:"


def _retirement(control, quiescence):
    from .c09_process_identity_v1 import require_process_retired_v1
    control.verify_original_v1(quiescence, "quiescence_digest")
    retired = require_process_retired_v1(quiescence["authority_process_original"])
    for original in quiescence["retired_worker_originals"] + quiescence["retired_peer_originals"]:
        if original != require_process_retired_v1(original["original_process"]):
            raise AuthorityUnavailable("C09 retired source cache-holder original differs")
    return retired


def require_retired_qualification_in_tx_v1(control, db, prepared, gate):
    """Enforce the new process qualification in the PREPARED write transaction."""
    from .c09_process_identity_v1 import read_process_identity_v1
    identity = read_process_identity_v1(os.getpid())
    old = prepared["writer_quiescence_original"]
    if old["authority_process_original"] == identity:
        return
    operation = prepared["operation_id"]
    kind = QUALIFICATION_PREFIX + canonical_digest(identity)
    original = control._build_original_locked(db, operation, kind)
    checkpoint = control._build_original_locked(db, operation, "prepared_checkpoint_inputs_v1")
    scan = control._build_original_locked(db, operation, "current_inventory_scan_v3")
    intent = db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='INTENT'",
        (operation,)).fetchone()
    if original is None or checkpoint is None or scan is None or intent is None:
        raise AuthorityUnavailable("C09 retired final continuation qualification absent")
    import json
    intent = json.loads(intent[0]); control.verify_original_v1(intent, "event_digest")
    value = original["details"]
    expected_fields = {"schema", "operation_id", "intent_digest", "old_manifest_digest", "pointer_version",
        "checkpoint_original_digest", "scan_original_digest", "scan_digest", "old_quiescence_digest",
        "retired_authority_original", "quiescence_original"}
    if set(value) != expected_fields:
        raise AuthorityUnavailable("C09 retired qualification fields differ")
    new = value["quiescence_original"]
    control.verify_original_v1(new, "quiescence_digest")
    if (value["schema"] != QUALIFICATION_SCHEMA or value["operation_id"] != operation
            or value["intent_digest"] != intent["event_digest"]
            or value["old_manifest_digest"] != prepared["old_manifest_digest"]
            or value["pointer_version"] != prepared["expected_pointer_version"]
            or value["checkpoint_original_digest"] != checkpoint["original_digest"]
            or value["scan_original_digest"] != scan["original_digest"]
            or value["scan_digest"] != prepared["frozen_scan_digest"]
            or value["old_quiescence_digest"] != old["quiescence_digest"]
            or value["retired_authority_original"] != _retirement(control, old)
            or new["authority_process_original"] != identity or new["lock_process_id"] != os.getpid()
            or new["operation_id"] != operation or new["pointer_version"] != value["pointer_version"]
            or new["storage_generation"] + 1 != prepared["maintenance_generation"]
            or new["lock_path"] != str(control.lease.path) or new["active_writers"] != 0
            or new["revoked_admission_epoch"] != gate._epoch):
        raise AuthorityUnavailable("C09 retired qualification differs from this continuous gate and predecessor")


def resume_retired_final_scan_before_open_v1(*, control, registry):
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from .c09_build_originals_v1 import decode_installed_build_original_v1, verify_rebased_file_original_v1
    from .c09_authority_storage_rebase import AuthorityStorageRebaseCandidateV1, _identity
    from .c09_graph_rebase_issue_v1 import (
        read_graph_rebase_issue_original_v1, verify_graph_rebase_issue_signature_v1,
    )
    from .current_filesystem_inventory_v3 import verify_current_inventory_evidence_v3, reread_closed_inventory_v3
    from .c09_final_inventory_v3 import read_source_roots_v3
    from .c09_prepared_assembly_v1 import assemble_prepared_storage_v1
    from .c09_retired_prepared_marker_v1 import verify_retired_prepared_marker_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, GraphRebaseMirrorV1, _cold_graph_data_root
    from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
    current = control.read_verified_current_storage_v1()
    if current.stage != "INTENT":
        return current
    if registry is None:
        raise AuthorityUnavailable("C09 cold final scan requires the installed Graph registry")
    with control._db() as db:
        pointer = control._current(db)
    operation = pointer["active_operation_id"]
    intent = control.read_operation_event_v1(operation, "INTENT")
    originals = {kind: control.read_build_original_v1(operation_id=operation, kind=kind)
        for kind in ("graph_candidate", "storage_candidate", "prepared_checkpoint_inputs_v1", "current_inventory_scan_v3")}
    if any(value is None for value in originals.values()):
        raise AuthorityUnavailable("C09 INTENT has no complete closed final checkpoint; earlier build retained for repair")
    checkpoint = originals["prepared_checkpoint_inputs_v1"]["details"]
    scan = verify_current_inventory_evidence_v3(originals["current_inventory_scan_v3"]["details"])
    closed = scan["closed_predecessor"]
    if closed is None:
        raise AuthorityUnavailable("C09 cold continuation requires actual completed old handle closure")
    old_quiescence = closed["quiescence_original"]
    retired = _retirement(control, old_quiescence)
    graph = decode_installed_build_original_v1(originals["graph_candidate"]["details"]["candidate"], GraphRebaseCandidateV1)
    candidate = decode_installed_build_original_v1(originals["storage_candidate"]["details"]["candidate"], AuthorityStorageRebaseCandidateV1)
    mirror = decode_installed_build_original_v1(checkpoint["graph_mirror"], GraphRebaseMirrorV1)
    if (checkpoint["schema"] != "sylanne3.c09.prepared_checkpoint_inputs.v1"
            or checkpoint["operation_id"] != operation or checkpoint["namespace"] != candidate.namespace
            or checkpoint["candidate_digest"] != candidate.candidate_digest
            or checkpoint["graph_candidate_digest"] != graph.candidate_digest
            or closed["candidate_digest"] != candidate.candidate_digest
            or closed["graph_candidate_digest"] != graph.candidate_digest
            or closed["pointer_version"] != current.pointer_version or closed["manifest_digest"] != current.manifest_digest
            or checkpoint["accepted_receipt_digest"] != intent["details"]["accepted_receipt_digest"]):
        raise AuthorityUnavailable("C09 cold checkpoint candidate or INTENT scope differs")
    gate = InstalledC09WriterGateV1(control=control)
    control._final_gate_v3 = gate
    gate.revoke_and_drain_v1(operation_id=operation)
    with gate.hold_final_continuation_v3(operation_id=operation) as continuation:
        new_quiescence = gate.require_final_continuation_v3(continuation, operation_id=operation)
        reread_closed_inventory_v3(scan)
        roots = read_source_roots_v3(current.manifest["members"], installation_id=control.installation_id,
            lease=control.lease, closed=True)
        if roots != closed["logical_roots"]:
            raise AuthorityUnavailable("C09 retired source rows, schemas or persistent metadata changed")
        members = {member["role"]: member for member in current.manifest["members"]}
        for role in ("core", "execution", "deletion", "graph"):
            source = Path(members[role]["resolved_path"])
            if [file_observation_v1(source, exclusive=True)] != closed["after_physical"][role]:
                raise AuthorityUnavailable("C09 retired closed source fingerprint changed")
            target = Path(graph.target_path if role == "graph" else getattr(candidate, role).target_path)
            allocation = control.read_build_original_v1(operation_id=operation, kind="allocation_" + role)
            if allocation is None or allocation["details"]["target_path"] != str(target):
                raise AuthorityUnavailable("C09 cold target allocation absent")
            info = target.stat()
            if (info.st_dev, info.st_ino) != (allocation["details"]["device"], allocation["details"]["file_id"]):
                raise AuthorityUnavailable("C09 cold target allocated inode changed")
            if role != "graph":
                original = getattr(candidate, role)
                saved = control.read_build_original_v1(operation_id=operation, kind="file_" + role)
                if saved is None or canonical_serialize(saved["details"]["file"]) != canonical_serialize(asdict(original)):
                    raise AuthorityUnavailable("C09 cold role file differs from actual build original")
                verify_rebased_file_original_v1(original)
            elif (_identity(target) != mirror.final_file_identity
                    or file_observation_v1(target, exclusive=True)["prepared_sha256"] != mirror.final_file_sha256):
                raise AuthorityUnavailable("C09 cold mirrored Graph bytes changed")
        with closing(sqlite3.connect(Path(candidate.core.source_path).as_uri()+"?mode=ro&immutable=1", uri=True)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
            issue = read_graph_rebase_issue_original_v1(db, candidate.namespace, operation)
            if issue is None or canonical_serialize(asdict(issue)) != canonical_serialize(checkpoint["issue"]):
                raise AuthorityUnavailable("C09 cold actual Authority Graph issue differs")
            verify_graph_rebase_issue_signature_v1(issue, control._key)
        with closing(sqlite3.connect(Path(graph.target_path).as_uri()+"?mode=ro&immutable=1", uri=True)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
            certificate = read_graph_rebase_certificate_v1(db, graph.namespace, operation)
            root, cold = _cold_graph_data_root(Path(graph.target_path), graph.namespace, set(graph.affected_atom_refs),
                graph.new_incarnation, graph.cumulative_erased_key_digests, candidate_connection=db, registry=registry)
            if (certificate != mirror.certificate or root != mirror.new_data_root or cold != mirror.cold_read_digest
                    or issue.certificate_digest != certificate.certificate_digest or issue.issue_digest != mirror.core_issue_digest):
                raise AuthorityUnavailable("C09 cold actual mirrored certificate or installed Graph proof differs")
        verify_retired_prepared_marker_v1(core_path=Path(candidate.core.target_path),
            source_core_path=Path(candidate.core.source_path), execution_path=Path(candidate.execution.target_path),
            namespace=candidate.namespace, operation_id=operation, expected_pin_digest=checkpoint["facts_pin"]["pin_digest"],
            expected_issue_digest=issue.issue_digest, expected_new_journal_id=candidate.new_execution_journal_id,
            maintenance_generation=current.storage_generation+1)
        manifest, prepared = assemble_prepared_storage_v1(control=control, current=current, operation_id=operation,
            graph_candidate=graph, graph_mirror=mirror, candidate=candidate, checkpoint=checkpoint, scan=scan,
            quiescence=old_quiescence)
        # Rewalk every registered managed tree after all candidate cold reads.
        reread_closed_inventory_v3(scan)
        if gate.require_final_continuation_v3(continuation, operation_id=operation) != new_quiescence:
            raise AuthorityUnavailable("C09 cold continuation gate changed")
        control.record_build_original_v1(operation_id=operation,
            kind=QUALIFICATION_PREFIX+canonical_digest(new_quiescence["authority_process_original"]),
            details=dict(schema=QUALIFICATION_SCHEMA, operation_id=operation, intent_digest=intent["event_digest"],
                old_manifest_digest=current.manifest_digest, pointer_version=current.pointer_version,
                checkpoint_original_digest=originals["prepared_checkpoint_inputs_v1"]["original_digest"],
                scan_original_digest=originals["current_inventory_scan_v3"]["original_digest"], scan_digest=scan["scan_digest"],
                old_quiescence_digest=old_quiescence["quiescence_digest"], retired_authority_original=retired,
                quiescence_original=new_quiescence))
        control.record_prepared_storage_v1(manifest=manifest, prepared_original=prepared, closing_continuation=continuation)
    return control.read_verified_current_storage_v1()
