"""Actual compact four-role C09 V2 manifest and PREPARED assembly."""
from __future__ import annotations
from pathlib import Path
import json
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import ROLES,digest
from .c09_storage_manifest_v2 import ROOT_ALGORITHM_V2
from ..runtime_contracts import canonical_digest


def assemble_current_prepared_storage_v2(bound,physical,*,closing_continuation,verified_roles,verified_core_obligations):
    """Only real complete roles and the fresh private physical view can assemble."""
    from .c09_physical_inventory_bound_v2 import InstalledC09PhysicalInventoryBoundV2,record_current_physical_inventory_v2
    from .c09_physical_inventory_stream_v2 import VerifiedPhysicalInventoryV2
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    from .c09_prepared_storage_v3 import VerifiedSegmentedRoleOriginalV3, SCHEMA_V3 as PREPARED_SCHEMA_V3, record_prepared_storage_v3, _read_original
    from .c09_storage_manifest_v3 import SCHEMA_V3 as MANIFEST_SCHEMA_V3, SEGMENTED_ROOT_ALGORITHM_V1
    if type(bound) is not InstalledC09PhysicalInventoryBoundV2 or type(physical) is not VerifiedPhysicalInventoryV2:
        raise AuthorityUnavailable("actual installed completed physical census required")
    bound.require_current();physical.require_current()
    if physical._progress.bound is not bound:
        raise AuthorityUnavailable("physical completion belongs to another actual bound")
    session=bound.session;m=session._control.maintenance;control=bound.control;scope=session.scope
    m.gate.require_final_continuation_v3(closing_continuation,operation_id=scope.operation_id)
    physical_original=record_current_physical_inventory_v2(bound,physical)
    meter=current_c09_sql_meter_v2()
    if (type(verified_roles) is not tuple or len(verified_roles) != len(ROLES)
            or any(type(proof) is not VerifiedSegmentedRoleOriginalV3 for proof in verified_roles)
            or tuple(sorted(proof.role for proof in verified_roles)) != ROLES):
        raise AuthorityUnavailable("actual four private complete segmented role originals required")
    role_proofs = {proof.role: proof for proof in verified_roles}
    for proof in verified_roles:
        proof.require_current(control=control, scope=scope, meter=meter)
    from .c09_natural_final_history_v4 import VerifiedNaturalFinalCoreObligationsV4
    from ..runtime.c09_paged_capture_contract_v2 import C09FrozenRoleSourceV2, c09_paged_value_from_wire_v2
    if (type(verified_core_obligations) is not VerifiedNaturalFinalCoreObligationsV4
            or verified_core_obligations is not bound.actual_core_role.builder.natural_core_obligations_proof_v4):
        raise AuthorityUnavailable('actual source-qualified complete Core closing obligation proof required')
    verified_core_obligations.require_for(session)
    core_header = role_proofs['core'].base_header
    core_source = c09_paged_value_from_wire_v2(core_header['source_original'], C09FrozenRoleSourceV2)
    if (verified_core_obligations.target_path != core_header['target_path']
            or verified_core_obligations.target_file_identity != tuple(core_header['target_file_identity'])[:2]
            or verified_core_obligations.cold_digest != core_header['cold_digest']
            or verified_core_obligations.summary['core_source_original_digest'] != core_source.role_source_digest
            or verified_core_obligations.summary['scope_digest'] != scope.scope_digest
            or verified_core_obligations.summary['pending_count'] != 0):
        raise AuthorityUnavailable('actual Core closing source, cold result, target inode or complete obligations differ')
    current=control.read_verified_current_storage_v2(meter=meter,verify_files=False)
    with control._db() as db:
        facts_original=control._build_original_locked(db,scope.operation_id,"capture_facts_complete_v2")
        issue_original=control._build_original_locked(db,scope.operation_id,"graph_issued_v2")
        mirror_original=control._build_original_locked(db,scope.operation_id,"graph_mirror_v2")
        if facts_original is None or issue_original is None or mirror_original is None:
            raise AuthorityUnavailable("actual complete facts, issue and mirror originals required")
        headers = {role: role_proofs[role].base_header for role in ROLES}
        from .c09_paged_recovery_facts_v2 import _read_one
        transition_ref = _read_one(db, "SELECT original_digest FROM c09_storage_build_originals_v1 "
            "WHERE installation_id=? AND operation_id=? AND original_kind='segmented_storage_transition_v1'",
            (control.installation_id, scope.operation_id), meter)
        if transition_ref is None:
            raise AuthorityUnavailable("actual segmented storage transition original required")
        transition_details = _read_original(control, db, scope.operation_id, "segmented_storage_transition_v1", transition_ref[0], meter)
        if transition_details != session.require_segmented_storage_transition_v1():
            raise AuthorityUnavailable("actual segmented transition changed during publication")
    from .c09_paged_recovery_facts_v2 import _decode_completion
    facts=_decode_completion(facts_original["details"])
    if facts.scope_digest!=scope.scope_digest:
        raise AuthorityUnavailable("PREPARED complete facts crosses actual scope")
    # The accepted deletion continuation is a real generated target row, not a
    # caller-supplied new anchor or fabricated execution journal identifier.
    core_producer=session._control._role_pairs.get("core")
    if core_producer is None or core_producer.pair is None:
        raise AuthorityUnavailable("actual completed Core role pair absent")
    core_pair=core_producer.pair
    core_pair.require_current()
    if core_pair.target_path!=headers["core"]["target_path"]:
        raise AuthorityUnavailable("PREPARED Core header differs from its actual registered pair")
    from contextlib import closing
    import sqlite3
    core_target=Path(headers["core"]["target_path"])
    with closing(sqlite3.connect(core_target.as_uri()+"?mode=ro&immutable=1",uri=True)) as db:
        db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
        row=db.execute("SELECT length(CAST(transition_json AS BLOB)) FROM authority_c09_deletion_continuations_v1 WHERE namespace=? AND operation_id=?",(scope.authority_namespace,scope.operation_id)).fetchone()
        if row is None or row[0]>65536:
            raise AuthorityUnavailable("actual generated deletion continuation absent or too large")
        meter.charge_read(row[0])
        row=db.execute("SELECT transition_json,transition_digest FROM authority_c09_deletion_continuations_v1 WHERE namespace=? AND operation_id=?",(scope.authority_namespace,scope.operation_id)).fetchone()
        transition=json.loads(row[0]);db.rollback()
    if (transition["transition_digest"]!=row[1] or digest({k:v for k,v in transition.items() if k!="transition_digest"})!=row[1]
            or transition["authority_id"]!=scope.authority_id or transition["installation_id"]!=scope.installation_id
            or transition["namespace"]!=scope.authority_namespace or transition["operation_id"]!=scope.operation_id
            or transition["maintenance_generation"]!=scope.maintenance_generation
            or transition["old_manifest_digest"]!=scope.old_manifest_digest
            or transition["accepted_receipt_digest"]!=scope.accepted_receipt_digest):
        raise AuthorityUnavailable("actual generated deletion continuation differs from capture scope")
    members=[];sources=[]
    for role in ROLES:
        header=headers[role];source=header["source_original"];source_stat=json.loads(source["source_identity"])
        identity=tuple(header["target_identity"] if role=="graph" else header["target_file_identity"])
        target=Path(header["target_path"]);stat=target.stat()
        proof = role_proofs[role]
        if proof.target_path != str(target) or proof.base_original_digest != bound._headers[role][0]:
            raise AuthorityUnavailable("PREPARED target differs from its actual complete segmented role")
        if identity!=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns):
            raise AuthorityUnavailable("completed role changed before PREPARED assembly")
        if any(Path(str(target)+suffix).exists() for suffix in ("-wal","-shm","-journal")):
            raise AuthorityUnavailable("PREPARED candidate has an unclosed SQLite companion")
        directory=header["stream_directory"]
        logical=canonical_digest((ROOT_ALGORITHM_V2,role,directory))
        old_member=next(item for item in current.manifest["members"] if item["role"]==role)
        incarnation=(issue_original["details"]["certificate"]["candidate"]["new_incarnation"] if role=="graph"
            else transition["after_anchor"]["execution_journal_id"] if role=="execution"
            else transition["after_anchor"]["deletion_journal_id"] if role=="deletion" else scope.authority_id)
        members.append(dict(role=role,resolved_path=str(target),device=identity[0],file_id=identity[1],
            prepared_size=identity[2],prepared_mtime_ns=identity[3],prepared_sha256=header["target_sha256"],
            store_id=old_member["store_id"],schema_version=old_member["schema_version"],namespace=scope.authority_namespace,
            storage_generation=scope.maintenance_generation,incarnation_or_journal_id=incarnation,
            logical_data_root=logical,schema_objects_digest=header["target_schema_digest"],cold_read_digest=header["cold_digest"],
            wal_policy="checkpointed_closed_before_switch",companion_resource_ids=[role+":wal",role+":shm",role+":journal"]))
        sources.append(dict(resolved_path=source["source_path"],device=source_stat["device"],file_id=source_stat["file_id"],
            prepared_size=source_stat["size"],prepared_mtime_ns=source_stat["mtime_ns"],prepared_sha256=source["source_file_sha256"]))
    certificate=issue_original["details"]["certificate"]
    manifest=dict(schema=MANIFEST_SCHEMA_V3,authority_id=scope.authority_id,installation_id=scope.installation_id,
        cohort_namespaces=[scope.authority_namespace],generation=scope.maintenance_generation,
        prior_manifest_digest=scope.old_manifest_digest,members=members,inventory_manifest_digest=m.inventory_manifest.manifest_digest,
        certificate_digest=mirror_original["details"]["certificate_digest"],graph_issue_digest=issue_original["details"]["issue_digest"],
        recovery_pin_digest=facts.pin_digest,cumulative_tombstone_root=canonical_digest(certificate["candidate"]["tombstones"]),
        deletion_watermark=transition["after_anchor"]["deletion_seq"],root_algorithm=ROOT_ALGORITHM_V2,
        capture_scope_digest=scope.scope_digest,facts_complete_original_digest=facts_original["original_digest"],
        facts_pin_digest=facts.pin_digest,four_role_complete_original_digests={role:bound._headers[role][0] for role in ROLES},
        physical_inventory_complete_original_digest=physical_original["original_digest"],physical_inventory_root=physical.record_root,
        physical_inventory_eof_digest=physical.eof_observation_digest,
        segmented_root_algorithm=SEGMENTED_ROOT_ALGORITHM_V1,
        segmented_layouts={role: dict(layout_id=role_proofs[role].layout_id,
            layout_schema_digest=role_proofs[role].layout_schema_digest,
            storage_instance_id=role_proofs[role].storage_instance_id) for role in ROLES},
        segmented_role_complete_original_digests={role: role_proofs[role].original_digest for role in ROLES})
    manifest["manifest_digest"]=digest(manifest)
    provider_scopes=control.read_build_original_v1(operation_id=scope.operation_id,kind='provider_scope_complete_v3')
    if (provider_scopes is None or provider_scopes['details']['scope_digest']!=scope.scope_digest
            or provider_scopes['details']['model_complete_digest']!=facts.model_stream.complete.digest
            or provider_scopes['details']['record_count']!=facts.model_stream.complete.record_count
            or provider_scopes['details']['complete'] is not True):
        raise AuthorityUnavailable('actual publication provider scope census lacks complete model-source EOF')
    prepared=dict(schema=PREPARED_SCHEMA_V3,authority_id=scope.authority_id,installation_id=scope.installation_id,
        namespace=scope.authority_namespace,operation_id=scope.operation_id,maintenance_generation=scope.maintenance_generation,
        expected_pointer_version=scope.expected_pointer_version,old_manifest_digest=scope.old_manifest_digest,
        new_manifest_digest=manifest["manifest_digest"],prior_prepared_digest=None if current.prepared_original is None else current.prepared_original["prepared_digest"],
        capture_scope_digest=scope.scope_digest,accepted_receipt_digest=scope.accepted_receipt_digest,barrier_receipt_digest=scope.barrier_digest,
        writer_freeze_digest=scope.writer_freeze_digest,facts_complete_original_digest=facts_original["original_digest"],facts_pin_digest=facts.pin_digest,
        graph_issue_original_digest=issue_original["original_digest"],graph_mirror_original_digest=mirror_original["original_digest"],
        four_role_complete_original_digests=manifest["four_role_complete_original_digests"],anchor_transition_original=transition,
        frozen_inventory_digest=m.inventory_manifest.manifest_digest,frozen_scan_digest=canonical_digest(physical_original["details"]),
        cumulative_tombstone_root=manifest["cumulative_tombstone_root"],deletion_watermark=manifest["deletion_watermark"],source_final_fingerprints=sources,
        segmented_storage_transition_original_digest=transition_ref[0],
        segmented_role_complete_original_digests=manifest["segmented_role_complete_original_digests"],
        natural_core_obligations_complete_original_digest=verified_core_obligations.completion_original_digest,
        provider_scope_complete_original_digest=provider_scopes['original_digest'])
    prepared=control.sign_original_v1(prepared["schema"],prepared,"prepared_digest")
    bound.require_current();physical.require_current()
    verified_core_obligations.require_for(session)
    record_prepared_storage_v3(control, manifest=manifest, prepared_original=prepared,
        closing_continuation=closing_continuation, verified_roles=verified_roles, meter=meter)
    verified_core_obligations.consume_committed_for(session, prepared_digest=prepared['prepared_digest'])
    return prepared
