"""Versioned minimal Life audit associations, not anonymous data or rights.

Further deletion of these retained associations requires a new disposition
contract. Maintenance across an earlier archive is explicitly HOLD.
"""
from dataclasses import asdict
import json
from pathlib import Path

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize
from .c09_life_completed_inventory_v1 import (
    SCHEMA, TABLES, _ISSUED, _LifeCompletedScopeV1,
    capture_completed_life_inventory_v1, require_completed_life_inventory_v1,
)

TABLE = 'authority_c09_completed_life_inventory_v1'
COLUMNS = ('namespace','operation_id','original_json','original_digest')
DDL = f'CREATE TABLE {TABLE} (namespace TEXT NOT NULL, operation_id TEXT NOT NULL, original_json TEXT NOT NULL, original_digest TEXT NOT NULL, PRIMARY KEY(namespace,operation_id))'
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'C09 Life inventory immutable'); END" for action in ('UPDATE','DELETE'))
INVENTORY_PREFIX = 'c09-life-completed-inventory:'
_FIELDS = {'schema','authority_id','installation_id','namespace','operation_id','pointer_version',
    'manifest_digest','quiescence_digest','tables','completed_jobs','status','key_id','inventory_digest','signature',
    'graph_barrier_commitment','affected_atom_commitments'}
_DIGESTS = ('manifest_digest','quiescence_digest','inventory_digest','signature','graph_barrier_commitment')


def _hold(message):
    raise AuthorityUnavailable('C09 Life archive '+message+'; HOLD')


def _sha(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        _hold('commitment syntax differs')


def validate_completed_life_original_v1(raw):
    if (type(raw) is not dict or set(raw)!=_FIELDS or raw['schema']!=SCHEMA
            or raw['status']!='authenticated_inventory_only_hold'
            or type(raw['pointer_version']) is not int or raw['pointer_version']<0):
        _hold('closed original fields differ')
    for name in ('authority_id','installation_id','namespace','operation_id','key_id'):
        if type(raw[name]) is not str or not 0<len(raw[name])<=4096:_hold('identity differs')
    for name in _DIGESTS:_sha(raw[name])
    if type(raw['tables']) is not list or len(raw['tables'])!=3:_hold('complete three-table inventory absent')
    if type(raw['affected_atom_commitments']) is not list or raw['affected_atom_commitments']!=sorted(set(raw['affected_atom_commitments'])):
        _hold('closed affected atom inventory differs')
    for digest in raw['affected_atom_commitments']:_sha(digest)
    count=0
    for family, table in zip(raw['tables'],TABLES):
        if (type(family) is not dict or set(family)!= {'table','present','columns','schema_commitment','rows'}
                or family['table']!=table or type(family['present']) is not bool
                or type(family['columns']) is not list or type(family['rows']) is not list):
            _hold('closed family differs')
        expected=['bot','persona','kind','job_id' if table==TABLES[1] else 'original_ref','payload_json','payload_digest','signature']
        if family['columns']!=(expected if family['present'] else []):_hold('family columns differ')
        _sha(family['schema_commitment'])
        if not family['present'] and (family['rows'] or family['schema_commitment']!=canonical_digest(())):
            _hold('absent family contains rows')
        allowed=({'prepared','prepare_commit'} if table==TABLES[0] else
                 {'binding','request','acquire_commit','call'} if table==TABLES[1] else
                 {'read_attempt','result','adoption_commit'})
        seen=set()
        for row in family['rows']:
            if type(row) is not dict or set(row)!={'kind','locator_commitment','row_commitment','job_commitment','disposition'} or row['kind'] not in allowed:
                _hold('closed row kind differs')
            _sha(row['locator_commitment']);_sha(row['row_commitment']);_sha(row['job_commitment'])
            if row['disposition'] not in {'preserved_exact','derived_removed'}:_hold('closed disposition differs')
            if row['locator_commitment'] in seen:_hold('duplicate original locator')
            seen.add(row['locator_commitment']);count+=1
    if count>100000 or type(raw['completed_jobs']) is not list or len(raw['completed_jobs'])>100000:
        _hold('finite inventory bound exceeded')
    seen=set()
    for job in raw['completed_jobs']:
        if type(job) is not dict or set(job)!={'job_commitment','model_original_digest','adoption_commitment','receipt_commitment','source_association_commitment','disposition'}:
            _hold('closed job association differs')
        for key,value in job.items():
            if key!='disposition':_sha(value)
        if job['disposition'] not in {'preserved_exact','derived_removed'}:_hold('closed job disposition differs')
        if job['job_commitment'] in seen:_hold('duplicate job')
        seen.add(job['job_commitment'])
    n=len(seen)
    if (len(raw['tables'][0]['rows'])!=2*n or len(raw['tables'][1]['rows'])!=4*n
            or sum(r['kind']=='result' for r in raw['tables'][2]['rows'])!=n
            or sum(r['kind']=='adoption_commit' for r in raw['tables'][2]['rows'])!=n
            or sum(r['kind']=='read_attempt' for r in raw['tables'][2]['rows'])<n):
        _hold('signed completed inventory cardinality differs')
    jobs={v['job_commitment']:v for v in raw['completed_jobs']}
    grouped={}
    for index,family in enumerate(raw['tables']):
        for row in family['rows']:
            job=jobs.get(row['job_commitment'])
            if job is None or row['disposition']!=job['disposition']:_hold('row/job disposition association differs')
            grouped.setdefault((index,row['job_commitment']),[]).append(row['kind'])
    for job in raw['completed_jobs']:
        kinds=[tuple(sorted(grouped.get((i,job['job_commitment']),()))) for i in range(3)]
        if (kinds[0]!=('prepare_commit','prepared') or kinds[1]!=('acquire_commit','binding','call','request')
                or kinds[2].count('result')!=1 or kinds[2].count('adoption_commit')!=1
                or not 1<=kinds[2].count('read_attempt')<=64):_hold('per-job complete carrier association differs')
    return raw


def require_completed_life_archive_schema_v1(db):
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()!=(DDL,):
        _hold('exact archive DDL differs')
    for sql in TRIGGERS:
        name=sql.split()[2]
        if db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name,)).fetchone()!=(sql,):
            _hold('immutable archive trigger differs')


def validate_life_archive_row_v1(columns,row):
    if tuple(columns)!=COLUMNS or len(row)!=4 or type(row[2]) is not str or len(row[2])>32*1024*1024:
        _hold('finite archive row differs')
    raw=validate_completed_life_original_v1(json.loads(row[2]))
    if (row[0],row[1],row[3])!=(raw['namespace'],raw['operation_id'],raw['inventory_digest']) or canonical_serialize(raw)!=row[2]:
        _hold('archive locator/canonical bytes differ')
    return raw


def read_completed_life_archive_v1(db,control,*,namespace,operation_id):
    if not db.in_transaction:_hold('actual SQL snapshot required')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:return None
    require_completed_life_archive_schema_v1(db)
    size=db.execute(f'SELECT LENGTH(original_json) FROM {TABLE} WHERE namespace=? AND operation_id=?',(namespace,operation_id)).fetchone()
    if size is not None and (type(size[0]) is not int or size[0]>32*1024*1024):_hold('archive exceeds finite preflight bound')
    row=db.execute(f'SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?',(namespace,operation_id)).fetchone()
    if row is None:return None
    raw=validate_life_archive_row_v1(COLUMNS,row)
    if (raw['authority_id'],raw['installation_id'])!=(control.authority_id,control.installation_id):_hold('installation differs')
    control.verify_original_v1(raw,'inventory_digest')
    return raw


def capture_and_store_completed_life_archive_v1(port,*,namespace,operation_id,require_existing=False):
    revoke_completed_life_scope_v1(port)
    scope=capture_completed_life_inventory_v1(port,namespace=namespace,operation_id=operation_id)
    raw=require_completed_life_inventory_v1(scope);db=scope.snapshot[5]
    if len(scope.signed_payload_json.encode('utf-8'))>32*1024*1024:_hold('archive exceeds finite write bound')
    present=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is not None
    if not present:
        if require_existing:_hold('completed Core forbids creating archive')
        db.execute(DDL)
        for sql in TRIGGERS:db.execute(sql)
    require_completed_life_archive_schema_v1(db)
    # The first conversion is approved. A later deletion must explicitly deal
    # with retained linkability; preserving it forever is not a default grant.
    if db.execute(f'SELECT 1 FROM {TABLE} WHERE namespace<>? OR operation_id<>? LIMIT 1',(namespace,operation_id)).fetchone():
        _hold('prior retained audit associations require explicit subsequent deletion disposition')
    old=read_completed_life_archive_v1(db,port._contact_control,namespace=namespace,operation_id=operation_id)
    if old is None:
        if require_existing:_hold('completed Core archive absent')
        validate_completed_life_original_v1(raw)
        db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?)',(namespace,operation_id,scope.signed_payload_json,raw['inventory_digest']))
    elif old!=raw:_hold('replayed complete archive differs')
    port._life_completed_scope=scope
    return raw


def life_inventory_fact_v1(original):
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
    raw=validate_completed_life_original_v1(original)
    return SanitizedGraphFactV4(INVENTORY_PREFIX+raw['operation_id'],
        canonical_digest(('sylanne3.c09.life-completed-inventory-fact.v2',raw['inventory_digest'])),
        canonical_digest(('sylanne3.c09.life-completed-inventory-rows.v2',raw['tables'],raw['completed_jobs'])),None)


def validate_life_archive_frame_v1(db,control,facts,*,required=False):
    original=read_completed_life_archive_v1(db,control,namespace=facts.namespace,operation_id=facts.operation_id)
    actual=tuple(v for v in facts.graph_facts if v.operation_id.startswith(INVENTORY_PREFIX))
    expected=() if original is None else (life_inventory_fact_v1(original),)
    if actual!=expected or required and original is None:_hold('bidirectional complete fact/archive association absent or changed')
    return original


def require_life_table_disposition_v1(db,*,scope,table,columns,rows):
    """Candidate-only authentication, actual selected source and signed archive.

    This does not assert physical disposal, survivor business rights, or closure
    of Body/Snapshot/external/Contact carriers.
    """
    if (type(scope) is not _LifeCompletedScopeV1 or _ISSUED.get(id(scope)) is not scope
            or getattr(scope.port,'_life_completed_scope',None) is not scope
            or not db.in_transaction or table not in TABLES):_hold('actual issued candidate scope absent')
    control=scope.port._contact_control;control.lease.require_held()
    current=control.read_verified_current_storage_v1(verify_files=False)
    raw=validate_completed_life_original_v1(json.loads(scope.signed_payload_json))
    intent=control.read_operation_event_v1(raw['operation_id'],'INTENT')
    if (current.stage,current.pointer_version,current.manifest_digest,
            intent['details']['quiescence_original']['quiescence_digest'])!=('INTENT',scope.pointer_version,scope.manifest_digest,raw['quiescence_digest']):
        _hold('actual INTENT/pointer/quiescence changed')
    selected={m['role']:Path(m['resolved_path']).resolve(strict=True) for m in current.manifest['members']}
    if Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)!=selected['graph']:
        _hold('candidate source path differs')
    from .c09_contact_finish_original_v1 import _scope_core_snapshot_v1
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked
    with _scope_core_snapshot_v1(scope) as core:
        if Path(core.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)!=selected['core']:_hold('actual Core path differs')
        facts=read_execution_recovery_facts_v4_locked(core,raw['namespace'],operation_id=raw['operation_id'])
        if facts is None or validate_life_archive_frame_v1(core,control,facts,required=True)!=raw:_hold('actual signed archive/facts differ')
    family=next(v for v in raw['tables'] if v['table']==table)
    metadata={v['locator_commitment']:{k:v[k] for k in ('disposition','job_commitment')} for v in family['rows']}
    actual={'table':table,'present':True,'columns':list(columns),
        'schema_commitment':canonical_digest(tuple(db.execute('SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name',(table,)))),
        'rows':[{'kind':r[2],'locator_commitment':canonical_digest(tuple(r[:4])),
                 'row_commitment':canonical_digest((table,tuple(columns),tuple(r))),
                 **metadata.get(canonical_digest(tuple(r[:4])), {})} for r in sorted(rows,key=lambda r:tuple(r[:4]))]}
    if actual!=family:_hold('complete candidate table inventory differs')
    return raw['inventory_digest']


def completed_life_table_dispositions_v1(db,*,scope,table,columns,rows,affected,affected_operations):
    """Return the signed, source-specific decisions for this exact row order."""
    require_life_table_disposition_v1(db,scope=scope,table=table,columns=columns,rows=rows)
    raw=json.loads(scope.signed_payload_json)
    from ..runtime.c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1, verify_c09_graph_barrier_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import _dependency_closure, _affected_operations
    barrier=read_c09_erasure_barrier_v1(db,scope.port.namespace_id,raw['operation_id'])
    if barrier is None or canonical_digest(barrier)!=raw['graph_barrier_commitment']:_hold('signed actual Graph barrier differs')
    if verify_c09_graph_barrier_v1(db,scope.port.namespace_id,raw['operation_id'],
            request_digest=barrier.request_digest,pending_receipt_digest=barrier.pending_receipt_digest) is None:
        _hold('actual Graph barrier verification absent')
    actual_affected=_dependency_closure(db,set(barrier.affected_source_refs))
    if (set(affected)!=actual_affected or set(affected_operations)!=_affected_operations(db,actual_affected)
            or sorted(canonical_digest(v) for v in actual_affected)!=raw['affected_atom_commitments']):
        _hold('complete historical ancestor/derived closure differs')
    family=next(v for v in raw['tables'] if v['table']==table)
    decisions={v['row_commitment']:v['disposition'] for v in family['rows']}
    return tuple(decisions[canonical_digest((table,tuple(columns),tuple(r)))] for r in rows)


def validate_selected_life_carriers_v1(db,original):
    """Exact surviving rows after candidate application; rejects resurrection."""
    raw=validate_completed_life_original_v1(original)
    for family in raw['tables']:
        table=family['table']
        present=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None
        if present!=family['present']:_hold('selected family presence differs')
        if not present:continue
        columns=tuple(r[1] for r in db.execute(f'PRAGMA table_info({table})'))
        schema=canonical_digest(tuple(db.execute('SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name',(table,))))
        if list(columns)!=family['columns'] or schema!=family['schema_commitment']:_hold('selected exact schema differs')
        expected=sorted(v['row_commitment'] for v in family['rows'] if v['disposition']=='preserved_exact')
        size,length=db.execute(f'SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)),0) FROM {table}').fetchone()
        if size>100000 or length>32*1024*1024:_hold('selected inventory bound exceeded')
        actual=sorted(canonical_digest((table,columns,tuple(r))) for r in db.execute(f'SELECT * FROM {table}'))
        if actual!=expected:_hold('selected complete inventory differs or removed original resurrected')


def revoke_completed_life_scope_v1(port):
    """End candidate authority on every successful or failed maintenance exit."""
    scope=getattr(port,'_life_completed_scope',None)
    if scope is not None:
        _ISSUED.pop(id(scope),None)
        port._life_completed_scope=None
