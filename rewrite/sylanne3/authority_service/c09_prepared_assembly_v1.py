"""Common frozen-file PREPARED assembly from installer-retained originals.

This function grants no source qualification and opens no running store.
Live close and cold retired continuation must supply their actual closed scan.
"""
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
import sqlite3
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import ROLES, digest, file_observation_v1
from .c09_authority_storage_rebase import _objects, _root
from .d12_sqlite_backup_v2 import sqlite_companions_present_v2
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest


def assemble_prepared_storage_v1(*, control, current, operation_id, graph_candidate,
        graph_mirror, candidate, checkpoint, scan, quiescence):
    namespace = checkpoint["namespace"]
    old_anchor = RestoreAnchor(**checkpoint["old_anchor"])
    transition = checkpoint["transition"]
    final_sources = [scan["closed_predecessor"]["after_physical"][role][0] for role in ROLES]
    members = []
    candidate_files = {"core":candidate.core,"execution":candidate.execution,"deletion":candidate.deletion}
    for role in ROLES:
        path = graph_candidate.target_path if role == "graph" else candidate_files[role].target_path
        observation = file_observation_v1(path,exclusive=True)
        if sqlite_companions_present_v2(path):
            raise AuthorityUnavailable("C09 closed candidate still has sidecars")
        with closing(sqlite3.connect(Path(path).as_uri()+"?mode=ro&immutable=1",uri=True)) as db:
            schema_root = digest(_objects(db))
            logical_root = graph_mirror.new_data_root if role == "graph" else _root(db)
            schema_version = "4" if role == "execution" else ("2" if role == "deletion" else "1")
        journal = graph_candidate.new_incarnation if role == "graph" else (candidate.new_execution_journal_id if role == "execution" else (old_anchor.deletion_journal_id if role == "deletion" else control.authority_id))
        cold = graph_mirror.cold_read_digest if role == "graph" else candidate_files[role].cold_read_digest
        members.append(dict(role=role,**observation,store_id=control.authority_id+":"+role,
            schema_version=schema_version,namespace=namespace,storage_generation=current.storage_generation+1,
            incarnation_or_journal_id=journal,logical_data_root=logical_root,schema_objects_digest=schema_root,
            cold_read_digest=cold,wal_policy="checkpointed_closed_before_switch",companion_resource_ids=[role+":wal",role+":shm",role+":journal"]))
    manifest = dict(schema="sylanne3.c09.storage_manifest.v1",authority_id=control.authority_id,
        installation_id=control.installation_id,cohort_namespaces=[namespace],
        generation=current.storage_generation+1,prior_manifest_digest=current.manifest_digest,members=members,
        inventory_manifest_digest=checkpoint["inventory"]["manifest_digest"],
        certificate_digest=graph_mirror.certificate.certificate_digest,graph_issue_digest=graph_mirror.core_issue_digest,
        recovery_pin_digest=checkpoint["facts_pin"]["pin_digest"],cumulative_tombstone_root=graph_mirror.certificate.tombstone_root,
        deletion_watermark=checkpoint["accepted_receipt"]["after_anchor"]["deletion_seq"])
    manifest["manifest_digest"] = digest(manifest)
    roots = dict(core=digest([asdict(r) for r in candidate.changed_rows if not r.table_name.startswith(("authority_v2_execution_","deletion_","authority_deletion_"))]),
        execution=candidate.execution.target_data_root,deletion=candidate.deletion.target_data_root,
        graph=graph_mirror.certificate.new_data_root)
    prepared = dict(schema="sylanne3.c09.storage_prepared_original.v1",authority_id=control.authority_id,
        installation_id=control.installation_id,namespace=namespace,operation_id=operation_id,
        maintenance_generation=manifest["generation"],expected_pointer_version=current.pointer_version,
        old_manifest_digest=current.manifest_digest,new_manifest_digest=manifest["manifest_digest"],
        prior_prepared_digest=None if current.prepared_original is None else current.prepared_original["prepared_digest"],
        accepted_receipt_original=checkpoint["accepted_receipt"],barrier_receipt_original=checkpoint["barrier"],
        accepted_receipt_digest=checkpoint["accepted_receipt_digest"],barrier_receipt_digest=checkpoint["barrier_digest"],
        old_core_anchor_original=asdict(old_anchor),new_core_anchor_original=transition["after_anchor"],anchor_transition_original=transition,
        old_deletion_head_original=dict(journal_id=old_anchor.deletion_journal_id,seq=old_anchor.deletion_seq,digest=old_anchor.deletion_digest),
        old_execution_head_original=dict(journal_id=old_anchor.execution_journal_id,seq=old_anchor.execution_seq,digest=old_anchor.execution_digest),
        old_graph_head_original=dict(incarnation=graph_mirror.certificate.old_incarnation,revision=graph_mirror.certificate.old_revision),
        facts_pin_original=checkpoint["facts_pin"],facts_digest=checkpoint["facts_digest"],
        recovery_bindings_digest=checkpoint["bindings_digest"],
        graph_certificate_original=asdict(graph_mirror.certificate),graph_issue_original=checkpoint["issue"],
        frozen_inventory_original=checkpoint["inventory"],frozen_scan_digest=scan["scan_digest"],
        writer_quiescence_original=quiescence,
        source_final_fingerprints=final_sources,four_candidate_disposition_roots=roots,
        four_candidate_cold_reads={m["role"]:m["cold_read_digest"] for m in members},
        cumulative_tombstone_root=manifest["cumulative_tombstone_root"],deletion_watermark=manifest["deletion_watermark"],
        component_verifier_hashes=dict(graph_mirror.certificate.component_hashes))
    prepared = control.sign_original_v1(prepared["schema"],prepared,"prepared_digest")
    return manifest, prepared
