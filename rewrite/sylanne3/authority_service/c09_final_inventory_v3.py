"""Final four-store close/scan under one continuously held C09 exclusion."""
from __future__ import annotations
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
import sqlite3
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest


def _sidecars_absent(path):
    from .current_filesystem_inventory_v3 import _absent
    for suffix in ('-wal','-shm','-journal'):_absent(str(path)+suffix)


def _physical(maintenance,view):
    from .c09_storage_control_v1 import file_observation_v1
    result={}
    for member in view.location.context.manifest['members']:
        observed=[]
        for suffix in ('','-wal','-shm','-journal'):
            path=Path(member['resolved_path']+suffix)
            try:path.lstat()
            except FileNotFoundError:continue
            except OSError as exc:raise AuthorityUnavailable('source companion unreadable') from exc
            observed.append(file_observation_v1(path,exclusive=True))
        result[member['role']]=observed
    return result


def _roots(maintenance,view,*,closed=False):
    return read_source_roots_v3(view.location.context.manifest["members"],
        installation_id=maintenance.control.installation_id, lease=maintenance.control.lease, closed=closed)


def read_source_roots_v3(members, *, installation_id, lease, closed):
    from .c09_authority_storage_rebase import _root,_columns,_rows,_row_commitment
    from .d12_sqlite_backup_v2 import leased_sqlite_read_uri_v2
    result={}
    for member in members:
        path=Path(member['resolved_path'])
        if closed:
            _sidecars_absent(path);uri=path.as_uri()+'?mode=ro&immutable=1';immutable=True
        else:uri,immutable=leased_sqlite_read_uri_v2(path,lease)
        with closing(sqlite3.connect(uri,uri=True,isolation_level=None)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            tables=tuple(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
            all_rows=tuple((table,_columns(db,table),tuple(sorted(_row_commitment(table,_columns(db,table),row) for row in _rows(db,table)))) for table in tables)
            ddl=tuple(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))
            result[member['role']]=dict(algorithm='sylanne3.c09.all-sqlite-rows-ddl.v3',
                store_id=member['store_id'],namespace=member['namespace'],installation_id=installation_id,
                application_rows_root=_root(db),all_rows_root=canonical_digest(all_rows),ddl_root=canonical_digest(ddl),
                persistent_metadata={name:db.execute('PRAGMA '+name).fetchone()[0] for name in ('user_version','application_id','encoding','page_size','auto_vacuum','schema_version')})
        if immutable:_sidecars_absent(path)
    return result


def close_and_scan_current_inventory_v3(maintenance,*,operation_id,continuation,graph_candidate,candidate):
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from .current_filesystem_inventory_v3 import verify_current_inventory_evidence_v3
    from .erasure_closure_inventory import CleanupRunV2,_TABLES
    from .c09_authority_storage_rebase import _files_sha,_identity
    from ..runtime.c09_graph_rebase_candidate_v1 import graph_source_files_fingerprint_v1
    if type(maintenance) is not InstalledC09MaintenanceV1:
        raise AuthorityUnavailable('actual installed C09 close coordinator required')
    qualifier=maintenance.current_source_location;core=maintenance.core
    before_quiescence=maintenance.gate.require_final_continuation_v3(continuation,operation_id=operation_id)
    with core._tx() as db:
        run=maintenance.closure._read_record(db,_TABLES[1],operation_id,CleanupRunV2)
        if run is None:raise AuthorityUnavailable('actual accepted cleanup run absent')
    view=qualifier.observe_installation_inventory_v1(maintenance.inventory_manifest,
        credential=maintenance.credential,subject=maintenance.subject,accepted_mutation_id=run.accepted_mutation_id)
    location=view.location
    if location.stage!='INTENT' or location.control_operation_id!=operation_id:
        raise AuthorityUnavailable('final inventory requires this exact current INTENT')
    graph_path=Path(graph_candidate.source_path)
    if (graph_source_files_fingerprint_v1(graph_path)!=graph_candidate.source_files_fingerprint
            or _identity(graph_path)!=graph_candidate.source_identity):
        raise AuthorityUnavailable('immutable Graph candidate source changed before final capture')
    links={'graph':asdict(graph_candidate)}
    for role in ('core','execution','deletion'):
        original=getattr(candidate,role);path=Path(original.source_path)
        if _identity(path)!=original.source_identity or _files_sha(path)!=original.source_files_sha256:
            raise AuthorityUnavailable('immutable '+role+' candidate source changed before final capture')
        # The concrete maintenance retained originals are checked below against
        # their exact fixed reader, irrespective of the control key name.
        actual=maintenance.read_rebased_file_original_v1(operation_id=operation_id,role=role)
        if actual is None or actual[0]!=original:raise AuthorityUnavailable('actual candidate source original differs')
        links[role]=asdict(original)
    graph_saved=maintenance.control.read_build_original_v1(operation_id=operation_id,kind='graph_candidate')
    if graph_saved is None or graph_saved['details']['candidate']!=asdict(graph_candidate):
        # Normalize tuples exactly as protected control's canonical JSON.
        import json
        from ..runtime_contracts import canonical_serialize
        if graph_saved is None or graph_saved['details']['candidate']!=json.loads(canonical_serialize(asdict(graph_candidate))):
            raise AuthorityUnavailable('actual immutable Graph candidate original differs')
    before_physical=_physical(maintenance,view);before_roots=_roots(maintenance,view)
    for role in ('core','execution','deletion'):
        if before_roots[role]['application_rows_root']!=getattr(candidate,role).source_data_root:
            raise AuthorityUnavailable('candidate snapshot differs from final source rows')
    with core._tx() as db:
        qualifier.require_current_in_tx_v1(db,location)
        scoped_row=tuple(db.execute('SELECT * FROM authority_scoped_erasure_v2 WHERE namespace=?',(qualifier.namespace,)).fetchone())
    closed_handles=maintenance._close_old_bundle_v1(operation_id=operation_id)
    after_roots=_roots(maintenance,view,closed=True)
    if before_roots!=after_roots:raise AuthorityUnavailable('closing changed actual source rows/schema/persistent metadata')
    members={m['role']:m for m in location.context.manifest['members']}
    with closing(sqlite3.connect(Path(members['core']['resolved_path']).as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        row=core._row(db,qualifier.namespace)
        actual=qualifier._fences.fences.mutation_locked(db,location.accepted_receipt.pending.mutation_id)
        if (core._anchor(db,qualifier.namespace,row)!=location.core_anchor or row[0]!=location.holder or row[9]!='accepted'
                or actual is None or qualifier._fences.fences._decode_mutation_row(actual)[2]!=location.accepted_receipt
                or tuple(db.execute('SELECT * FROM authority_scoped_erasure_v2 WHERE namespace=?',(qualifier.namespace,)).fetchone())!=scoped_row):
            raise AuthorityUnavailable('closed Core differs from exact accepted predecessor')
    with closing(sqlite3.connect(Path(members['graph']['resolved_path']).as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        qualifier.require_accepted_graph_snapshot_v1(db,location,graph_db_path=members['graph']['resolved_path'])
    after_physical=_physical(maintenance,view)
    scan=qualifier.scan_installation_inventory_v1(view)
    after_quiescence=maintenance.gate.require_final_continuation_v3(continuation,operation_id=operation_id)
    if after_quiescence!=before_quiescence:raise AuthorityUnavailable('writer exclusion changed during final close/scan')
    scan['closed_predecessor']=dict(operation_id=operation_id,
        accepted_receipt_digest=canonical_digest(location.accepted_receipt),pointer_version=location.pointer_version,
        manifest_digest=location.manifest_digest,quiescence_original=after_quiescence,logical_roots=before_roots,
        before_physical=before_physical,after_physical=after_physical,candidate_source_originals=links,
        candidate_digest=candidate.candidate_digest,graph_candidate_digest=graph_candidate.candidate_digest,
        closed_connections=closed_handles,continuous_exclusion=dict(operation_id=operation_id,
            admission_epoch=continuation[2],thread_id=continuation[3],lease_path=str(maintenance.control.lease.path),
            process_id=__import__('os').getpid()))
    scan['scan_digest']=canonical_digest({k:v for k,v in scan.items() if k!='scan_digest'})
    scan=verify_current_inventory_evidence_v3(scan)
    maintenance.control.record_build_original_v1(operation_id=operation_id,kind='current_inventory_scan_v3',details=scan)
    return scan
