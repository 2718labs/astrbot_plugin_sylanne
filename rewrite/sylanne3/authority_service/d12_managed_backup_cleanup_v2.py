"""Bounded actual managed backup cleanup."""
from __future__ import annotations
from contextlib import contextmanager,closing
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from weakref import WeakSet
import json,os,sqlite3,sys
from dataclasses import fields,is_dataclass
from .contract import AuthorityUnavailable
from .c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
from .d12_managed_backup_v2 import decode_managed_backup_v2
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2,read_legacy_sql_cell_fragment_v2
from .c09_paged_recovery_facts_v2 import _read_one,_write,_BoundedReadConnectionV2,_decode_fact,_fact_key,_FAMILIES
from .c09_selected_history_v3 import C09SelectedHistoryReadonlySinkV3,_LegacyReadonlyFrameV3

COVERAGE_SCHEMA='sylanne3.d12.backup-recovery-coverage.v3'
_TOKEN=object();_PROOFS=WeakSet();_BACKUP_SINKS=WeakSet()
_DDLS={
 'c09_d12_backup_registrations_v3':'CREATE TABLE c09_d12_backup_registrations_v3(selection_digest TEXT NOT NULL,backup_key TEXT NOT NULL,observation_ref TEXT NOT NULL,observation_digest TEXT NOT NULL,backup_json TEXT NOT NULL,PRIMARY KEY(selection_digest,backup_key)) STRICT',
 'c09_d12_backup_files_v3':'CREATE TABLE c09_d12_backup_files_v3(selection_digest TEXT NOT NULL,resolved_path TEXT NOT NULL,backup_key TEXT NOT NULL,role TEXT NOT NULL,before_json TEXT NOT NULL,PRIMARY KEY(selection_digest,resolved_path)) STRICT',
 'c09_d12_backup_obligations_v3':'CREATE TABLE c09_d12_backup_obligations_v3(selection_digest TEXT NOT NULL,backup_key TEXT NOT NULL,family TEXT NOT NULL,item_key TEXT NOT NULL,proof_json TEXT NOT NULL,proof_digest TEXT NOT NULL,PRIMARY KEY(selection_digest,backup_key,family,item_key)) STRICT',
 'c09_d12_backup_certificates_v3':'CREATE TABLE c09_d12_backup_certificates_v3(selection_digest TEXT PRIMARY KEY,certificate_json TEXT NOT NULL,certificate_digest TEXT NOT NULL UNIQUE) STRICT',
}

def _retained_heap_v3(value,seen,excluded):
    key=id(value)
    if key in seen or key in excluded:return 0
    seen.add(key);result=sys.getsizeof(value)
    if isinstance(value,dict):return result+sum(_retained_heap_v3(k,seen,excluded)+_retained_heap_v3(v,seen,excluded) for k,v in value.items())
    if isinstance(value,(tuple,list,set,frozenset)):return result+sum(_retained_heap_v3(v,seen,excluded) for v in value)
    if is_dataclass(value) and not isinstance(value,type):return result+sum(_retained_heap_v3(getattr(value,f.name),seen,excluded) for f in fields(value))
    if not isinstance(value,type):
        if hasattr(value,'__dict__'):result+=_retained_heap_v3(value.__dict__,seen,excluded)
        for cls in type(value).__mro__:
            slots=cls.__dict__.get('__slots__',())
            if isinstance(slots,str):slots=(slots,)
            for name in slots:
                if name not in {'__dict__','__weakref__'} and hasattr(value,name):result+=_retained_heap_v3(getattr(value,name),seen,excluded)
    return result

def _execution_semantic_digest_v3(value):
    body=asdict(value)
    for key in ('current_prepared_digest','history_count','history_root'):body.pop(key)
    return canonical_digest(body)

def require_registered_backup_historical_sink_v3(sink):
    if type(sink) is not _RegisteredBackupHistoricalSinkV3 or sink not in _BACKUP_SINKS:raise AuthorityUnavailable('actual registered backup historical sink proof required')
    sink.admission.view.require_current(meter=current_c09_sql_meter_v2())
    if (sink.basis is not sink.admission.view.basis or sink.db is None or sink.db is not sink._actual_graph or not sink.db.in_transaction):raise AuthorityUnavailable('actual registered backup selected Graph RO snapshot required')
    return sink.db

def _schema(control,db,meter,*,install=False):
    for name,ddl in _DDLS.items():
        row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,),meter)
        if row is None and install:_write(db,ddl,(),meter)
        elif row!=(ddl,):raise AuthorityUnavailable('actual managed backup coverage schema differs')
        for action in ('UPDATE','DELETE'):
            trigger=name+'_no_'+action.lower();sql=control._immutable_ddl(name,action)
            row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(trigger,),meter)
            if row is None and install:_write(db,sql,(),meter)
            elif row!=(sql,):raise AuthorityUnavailable('actual managed backup coverage immutable trigger differs')
        if name!='c09_d12_backup_certificates_v3':
            trigger=name+'_closed_insert'
            sql='CREATE TRIGGER '+trigger+" BEFORE INSERT ON "+name+" WHEN EXISTS(SELECT 1 FROM c09_d12_backup_certificates_v3 WHERE selection_digest=NEW.selection_digest) BEGIN SELECT RAISE(ABORT,'sealed actual backup coverage'); END"
            row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(trigger,),meter)
            if row is None and install:_write(db,sql,(),meter)
            elif row!=(sql,):raise AuthorityUnavailable('actual backup coverage insert EOF fence differs')

def _append(control,db,table,columns,row,keys,meter):
    where=' AND '.join(n+'=?' for n in keys);args=tuple(row[columns.index(n)] for n in keys)
    prior=meter.read_fixed_row(db,table,columns,where,args)
    if prior is None:meter.write_row(db,table,columns,row)
    elif tuple(prior)!=tuple(row):raise AuthorityUnavailable('actual backup coverage replay changed')

class VerifiedD12BackupCoverageV3:
    """Private complete signed source/selected/Control/filesystem EOF qualification."""
    def __init__(self,token,reader,original):
        if token is not _TOKEN or type(reader) is not _BackupCleanupReadV3 or reader.phase!='certificate':raise TypeError('actual complete backup coverage issuer required')
        self.view=reader.view;self.service=reader.service;self.original=original;self.selection_digest=reader.selection
        _PROOFS.add(self)
    def require_current(self,*,meter):
        if self not in _PROOFS:raise AuthorityUnavailable('actual private managed backup coverage proof required')
        self.view.require_current(meter=meter)
        if self.view.basis.selection_digest!=self.selection_digest:raise AuthorityUnavailable('actual backup coverage selected cut changed')
        with self.service.control._db() as db:
            row=_read_one(db,'SELECT certificate_json,certificate_digest FROM c09_d12_backup_certificates_v3 WHERE selection_digest=?',(self.selection_digest,),meter)
        if row is None:raise AuthorityUnavailable('actual signed backup coverage certificate absent')
        value=json.loads(row[0]);self.service.control.verify_original_v1(value,'coverage_digest')
        if value!=self.original or row[1]!=value['coverage_digest']:raise AuthorityUnavailable('actual signed backup coverage certificate changed')
        return self

class InstalledD12ManagedBackupCleanupV2(InstalledC09SurfaceCleanupV1):
    def __init__(self,*,control,gate,inventory_manifest,supervisor_journal):
        super().__init__(control=control,gate=gate,inventory_manifest=inventory_manifest,surface='controlled_backups')
        if type(supervisor_journal) is not InstalledPackageSupervisorJournalV2:raise TypeError('actual independently signed backup registry required')
        self.journal=supervisor_journal;self._backup_progress_v3=None;self._backup_recheck_v3=None;self._backup_proof_v3=None
    def clean_installed_surface_v1(self,*,operation_id,storage_reader):
        raise AuthorityUnavailable('registered backups require their actual V3 selected Source coverage continuation')
    def reread_installed_surface_v1(self,*,operation_id,storage_reader,original):
        raise AuthorityUnavailable('registered backup evidence requires its actual V3 selected coverage reread')
    def advance_installed_surface_v3(self,*,operation_id,storage_reader,view,meter):
        return self._advance_v3(operation_id,storage_reader,view,meter,None)
    def advance_installed_surface_reread_v3(self,*,operation_id,storage_reader,view,meter,original):
        self.control.verify_original_v1(original,'evidence_digest')
        return self._advance_v3(operation_id,storage_reader,view,meter,original)
    def _advance_v3(self,operation,storage_reader,view,meter,original):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if (storage_reader is not self.control or type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not self.control
                or meter is not current_c09_sql_meter_v2() or view.basis.prepared['operation_id']!=operation
                or view.basis.prepared['namespace']!=self.inventory.namespace or view.basis.manifest['inventory_manifest_digest']!=self.inventory.manifest_digest):
            raise AuthorityUnavailable('actual selected registered backup cleanup binding required')
        view.require_current(meter=meter);attr='_backup_recheck_v3' if original is not None else '_backup_progress_v3'
        reader=getattr(self,attr)
        if reader is None:reader=_BackupCleanupReadV3(_TOKEN,self,view,operation,original);setattr(self,attr,reader)
        elif reader.view is not view or reader.operation!=operation or reader.saved_original!=original:raise AuthorityUnavailable('actual backup cleanup continuation changed')
        return reader.advance(meter)
    def require_selected_file_coverage_v3(self,before,*,view,meter):
        proof=self._backup_proof_v3
        if type(proof) is not VerifiedD12BackupCoverageV3 or proof.view is not view or proof.service is not self:raise AuthorityUnavailable('actual complete backup coverage required before unlink')
        proof.require_current(meter=meter)
        with self.control._db() as db:
            row=_read_one(db,'SELECT before_json FROM c09_d12_backup_files_v3 WHERE selection_digest=? AND resolved_path=?',(view.basis.selection_digest,before['resolved_path']),meter)
        if row is None:raise AuthorityUnavailable('unlink file lacks actual registered backup coverage')
        registered=json.loads(row[0])
        if any(before[key]!=value for key,value in registered.items() if key!='prepared_sha256') or before['prepared_sha256'] not in (None,registered['prepared_sha256']):raise AuthorityUnavailable('unlink file differs from actual registered backup coverage')
        before['prepared_sha256']=registered['prepared_sha256']
        return proof

class _VerifiedBackupAdmissionV3:
    def __init__(self,token,owner):
        if token is not _TOKEN or type(owner) is not _BackupCleanupReadV3 or owner.phase!='ancestry':raise TypeError('actual authenticated backup admission issuer required')
        self.owner=owner;self.view=owner.view;self.backup=owner.backup;self.backup_key=owner.backup_key

class _RegisteredBackupHistoricalSinkV3(C09SelectedHistoryReadonlySinkV3):
    def _merge(self,family,value,origin,meter):
        row=_read_one(self.history_storage_db_v3(),'SELECT value_digest FROM c09_recovery_history_members_v2 WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',
            (self.scope.scope_digest,self.generation,family,_fact_key(family,value)),meter)
        if row!=(canonical_digest(value),) or origin!=self.prepared_digest:raise AuthorityUnavailable('registered backup exact historical member original differs')

class _RegisteredBackupHistoricalFrameV3(_LegacyReadonlyFrameV3):
    def _lookup_fact(self,family,key):
        value=super()._lookup_fact(family,key)
        if value is not None:
            member=_read_one(self.producer.history_storage_db_v3(),'SELECT value_digest FROM c09_recovery_history_members_v2 WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',
                (self.scope,self.generation,family,key),self.meter)
            if member!=(canonical_digest(value),):raise AuthorityUnavailable('current typed point does not supply this historical frame original')
        return value

class _RegisteredBackupLegacyFrameReadV3:
    def __init__(self,token,admission,summary):
        if token is not _TOKEN:raise TypeError('actual registered legacy backup frame issuer required')
        from .c09_selected_history_v3 import _BASIS
        self.admission=admission;self.summary=summary;self.sink=_RegisteredBackupHistoricalSinkV3(_BASIS,admission.view.basis,admission.view.scope)
        self.sink.generation=summary['maintenance_generation'];self.sink.prepared_digest=summary['prepared_digest'];self.sink.admission=admission;self.sink._actual_graph=None;_BACKUP_SINKS.add(self.sink)
        self.reader=_RegisteredBackupHistoricalFrameV3(self.sink,summary);self.complete=False
    def advance(self,meter):
        owner=self.admission.owner;self.admission.view.require_current(meter=meter);self.summary.require_current(meter=meter)
        with owner._source('core',meter) as old,owner.view.basis.read_database('graph',meter=meter) as graph:
            self.sink.db=graph;self.sink._actual_graph=graph
            try:self.complete=self.reader.advance(old,meter)
            finally:self.sink.db=None;self.sink._actual_graph=None
        return self.complete

def begin_registered_backup_legacy_frame_v3(verifiedBackupAdmission,actualSelectedView,verifiedHistoricalFrameSummary,meter):
    from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    from .c09_paged_recovery_facts_v2 import C09VerifiedLegacyPreparedSummaryV2,C09VerifiedPagedPreparedSummaryV2
    admission=verifiedBackupAdmission;summary=verifiedHistoricalFrameSummary
    if (type(admission) is not _VerifiedBackupAdmissionV3 or type(actualSelectedView) is not VerifiedSelectedHistoryReadV3
            or admission.view is not actualSelectedView or type(summary) is not C09VerifiedLegacyPreparedSummaryV2):raise TypeError('actual registered backup and verified historical legacy frame required')
    actualSelectedView.require_current(meter=meter);summary.require_current(meter=meter)
    backup=admission.backup;generation=summary['maintenance_generation']
    if (generation>backup['storage_identity']['storage_generation'] or summary['namespace']!=backup['namespace']
            or summary['installation_id']!=backup['installation_id']):raise AuthorityUnavailable('registered backup legacy frame scope/generation differs')
    with actualSelectedView.basis.read_database('graph',meter=meter) as graph:
        row=_read_one(graph,'SELECT operation_id,prepared_digest,manifest_digest FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND generation=?',(actualSelectedView.scope.scope_digest,generation),meter)
    if row!=(summary['operation_id'],summary['prepared_digest'],summary['new_manifest_digest']):raise AuthorityUnavailable('legacy backup original lacks complete selected historical membership')
    if generation==backup['storage_identity']['storage_generation']:
        anchor=summary['new_core_anchor_original']
        if (summary['new_manifest_digest']!=backup['storage_identity']['manifest_digest']
                or anchor['execution_journal_id']!=backup['current_anchor']['execution_journal_id']):raise AuthorityUnavailable('registered backup exact legacy manifest/journal differs')
    return _RegisteredBackupLegacyFrameReadV3(_TOKEN,admission,summary)

class _BackupSourceFamilyReadV3:
    """The actual backup family's sealed census/pages and physical item EOF."""
    def __init__(self,owner,locator,family):
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        self.owner=owner;self.locator=locator;self.family=family;self.reader=C09HistoricalSealedStreamReaderV2(locator);self.after=0 if family=='journal' else '';self.count=0;self.complete=False
    def advance(self,meter):
        with self.owner._source('graph',meter) as db:
            def observe(record):
                if self.family=='journal':
                    row=_read_one(db,'SELECT seq,execution_id,row_commitment,mutation_id,chain_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq>? ORDER BY seq LIMIT 1',(self.locator.identity.scope_digest,self.after),meter)
                    if row is None or record.primary_key!=(row[0],) or record.commitment!=row[2]:raise AuthorityUnavailable('actual backup journal sealed census/member differs')
                    binding=self.owner.view.lookup_execution_binding(row[1],meter=meter)
                    if binding is None or row[2] not in binding.source_row_commitments:raise AuthorityUnavailable('actual backup historical journal original is not retained')
                    self.owner._record('journal_member',canonical_digest((self.locator.identity.scope_digest,row[0])),{'execution_id':row[1],'source_row_commitment':row[2]},meter)
                else:
                    row=_read_one(db,'SELECT item_key,value_json,value_digest,origin_digest FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key>? ORDER BY item_key LIMIT 1',(self.locator.identity.scope_digest,self.family,self.after),meter)
                    if row is None or record.primary_key!=(row[0],) or canonical_digest((self.family,row[0],row[2],row[3]))!=record.commitment:raise AuthorityUnavailable('actual backup sealed family omits/reorders/changes source item')
                    value=_decode_fact(self.family,row[1])
                    if canonical_digest(value)!=row[2] or self.owner.view.lookup(self.family,row[0],meter=meter)!=value:raise AuthorityUnavailable('actual backup historical typed item is not retained')
                    self.owner._record('historical_item',canonical_digest((self.locator.identity.scope_digest,self.family,row[0])),{'family':self.family,'item_key':row[0],'value_digest':row[2]},meter)
                self.after=row[0];self.count+=1
            if self.reader.advance(db,meter,observe):
                extra=_read_one(db,'SELECT 1 FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq>? LIMIT 1',(self.locator.identity.scope_digest,self.after),meter) if self.family=='journal' else _read_one(db,'SELECT 1 FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key>? LIMIT 1',(self.locator.identity.scope_digest,self.family,self.after),meter)
                if self.count!=self.locator.complete.record_count or extra is not None:raise AuthorityUnavailable('actual backup family has an unsealed source EOF suffix')
                self.complete=True
        return self.complete

class _BackupGraphRowCommitmentV3:
    """The actual Graph c09_row_commitment_v2 wire, one column/8KiB fragment."""
    def __init__(self,owner,shape,key):
        self.owner=owner;self.shape=shape;self.key=tuple(key);self.column=0;self.kind=None;self.total=None;self.offset=0;self.decoder=None
        self.digest=sha256();current_c09_sql_meter_v2().charge_encode(1);self.digest.update(b'[');self.blob=None;self.complete=False;self.commitment=None
    def advance(self,db,meter):
        import codecs
        from ..runtime.c09_paged_sql_v2 import _quote
        if self.complete:return True
        if self.column==len(self.shape.columns):
            meter.charge_encode(1);self.digest.update(b']');self.commitment=self.digest.hexdigest();self.complete=True;return True
        name=self.shape.columns[self.column];where=' AND '.join(_quote(n)+'=?' for n in self.shape.primary_key_columns)
        if self.kind is None:
            row=_read_one(db,'SELECT typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB)) FROM '+_quote(self.shape.table)+' WHERE '+where,self.key,meter)
            if row is None:raise AuthorityUnavailable('registered backup actual Graph row disappeared')
            self.kind,self.total=row
            if self.column:meter.charge_encode(1);self.digest.update(b',')
            if self.kind=='text':self.decoder=codecs.getincrementaldecoder('utf-8')('strict');meter.charge_encode(1);self.digest.update(b'"');return False
            if self.kind=='blob':self.blob=sha256();return False
            value=_read_one(db,'SELECT '+_quote(name)+' FROM '+_quote(self.shape.table)+' WHERE '+where,self.key,meter)[0]
            self.digest.update(canonical_serialize(value).encode('ascii'));self.column+=1;self.kind=None;return False
        amount=min(8192,self.total-self.offset);self.owner.service.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=amount*16+16384);meter.require_available(amount*8+4096)
        raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table=self.shape.table,column=name,where=where,parameters=self.key,start=self.offset,length=amount,meter=meter)
        if kind!=self.kind or total!=self.total or len(raw)!=amount:raise AuthorityUnavailable('actual backup Graph column fragment changed')
        self.offset+=amount
        if kind=='blob':self.blob.update(raw)
        else:self.digest.update(canonical_serialize(self.decoder.decode(raw,final=self.offset==total)).encode('ascii')[1:-1])
        if self.offset==total:
            if kind=='blob':self.digest.update(canonical_serialize({'blob_sha256':self.blob.hexdigest(),'size':total}).encode('ascii'))
            else:meter.charge_encode(1);self.digest.update(b'"')
            self.column+=1;self.kind=None;self.total=None;self.offset=0;self.decoder=None;self.blob=None
        return False

_GRAPH_DISPOSITION_COLUMNS_V3=('scope_digest','table_name','key_digest','source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal')
_BUDGET_SOURCE_TABLES_V3=frozenset(('runtime_budget_leases','runtime_budget_reservations','runtime_budget_operations'))

def _registered_backup_budget_source_v3(owner,shape,key,commitment,meter,*,legacy_source=None):
    """The three existing budget Source contracts, with an explicit raw-row link."""
    from ..runtime.c09_paged_sql_v2 import _quote
    if shape.table not in _BUDGET_SOURCE_TABLES_V3:return False
    with owner._source('graph',meter) as db:
        where=' AND '.join(_quote(name)+'=?' for name in shape.primary_key_columns)
        names=('lease_id','operation_id') if shape.table=='runtime_budget_reservations' else ('bot_id','persona_id','lease_id') if shape.table=='runtime_budget_leases' else ('bot_id','persona_id','operation_id','phase')
        small=meter.read_fixed_row(db,shape.table,names,where,key)
        ns=_read_one(db,'SELECT bot_id,persona_id FROM runtime_budget_leases WHERE lease_id=?',(small[0],),meter) if shape.table=='runtime_budget_reservations' else small[:2]
    if tuple(ns)!=NamespaceId(**owner.backup['reconciliation']['namespace']).as_tuple:return False
    family,reference=('reservation',canonical_digest(small)) if shape.table=='runtime_budget_reservations' else ('lease',small[2]) if shape.table=='runtime_budget_leases' else ('receipt',canonical_digest(small))
    proof={'table':shape.table,'primary_key':key,'source_commitment':commitment,'coverage_family':family,'coverage_key':reference}
    if legacy_source is not None:proof['legacy_source']=legacy_source
    owner._record('budget_source_row',canonical_digest((shape.table,key)),proof,meter);return True

def _registered_graph_candidate_v3(owner,summary,meter):
    from .c09_prepared_storage_v3 import _read_original
    from ..runtime.c09_paged_capture_contract_v2 import GraphRebaseCandidateV2,c09_paged_value_from_wire_v2
    refs=summary['four_role_complete_original_digests']
    with owner.service.control._db() as db:
        header=_read_original(owner.service.control,db,summary['operation_id'],'capture_role_complete_v2_graph',refs['graph'],meter)
        raw=_read_original(owner.service.control,db,summary['operation_id'],'graph_candidate_v2',None,meter)
    candidate=c09_paged_value_from_wire_v2(raw,GraphRebaseCandidateV2)
    if (candidate.scope.operation_id!=summary['operation_id'] or candidate.scope.maintenance_generation!=summary['maintenance_generation']
            or header['scope_digest']!=candidate.scope.scope_digest or header['role']!='graph' or header['source_original']!=asdict(candidate.source)
            or canonical_serialize(header['schema_directory'])!=canonical_serialize(asdict(candidate.schema_catalogue)) or canonical_serialize(header['stream_directory'])!=canonical_serialize(asdict(candidate.target_directory))):
        raise AuthorityUnavailable('registered backup historical Graph candidate/role/Source originals differ')
    return candidate

class _RegisteredGraphPointReadV3:
    """One real signed directory/Source/disposition membership per quantum."""
    def __init__(self,candidate,shape,key):
        self.candidate=candidate;self.shape=shape;self.key=tuple(key);self.phase='metadata';self.complete=False;self.proof=None
        self.directory=None;self.identity=None;self.seal=None;self.origin=None;self.original=None
    @staticmethod
    def _member(db,stream,seal,pk,digest,meter):
        from ..runtime.c09_paged_sql_v2 import require_c09_capture_member_v2
        row=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),'stream_id=? AND key_digest=?',(stream.stream_id,canonical_digest(pk)))
        if row is None or row[1]!=digest or not 1<=row[0]<=seal.record_count:raise AuthorityUnavailable('registered backup historical member is outside sealed Source bounds')
        require_c09_capture_member_v2(db,stream,row[0],pk,digest,meter=meter);return row[0]
    def advance(self,db,meter):
        from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
        from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2,read_c09_table_shape_v2
        candidate=self.candidate;shape=self.shape;scope=candidate.scope.scope_digest;table=shape.table
        if self.phase=='metadata':
            self.directory=meter.read_fixed_row(db,'c09_graph_disposition_directory_v2',('scope_digest','family','identity_json','complete_json'),'scope_digest=? AND family=?',(scope,table))
            source=meter.read_fixed_row(db,'c09_graph_stream_directory_v2',('identity_json','complete_json'),'scope_digest=? AND directory_kind=? AND family=?',(scope,'source_originals',table))
            if self.directory is None or source is None:raise AuthorityUnavailable('registered backup row lacks actual historical Graph family originals')
            outer=read_c09_table_shape_v2(db,'c09_graph_disposition_directory_v2',meter=meter)
            if candidate.disposition_directory.identity.schema_digest!=outer.schema_digest or candidate.disposition_directory.identity.primary_key_columns!=outer.primary_key_columns:raise AuthorityUnavailable('registered backup actual Graph directory layout differs')
            self.identity=c09_paged_value_from_wire_v2(json.loads(self.directory[2]),C09StreamIdentityV2);self.seal=c09_paged_value_from_wire_v2(json.loads(self.directory[3]),C09CompleteStreamV2)
            self.origin=c09_paged_value_from_wire_v2(json.loads(source[0]),C09StreamIdentityV2);self.original=c09_paged_value_from_wire_v2(json.loads(source[1]),C09CompleteStreamV2)
            for stream,end,kind in ((self.identity,self.seal,'row_dispositions'),(self.origin,self.original,'graph_facts')):
                if (stream.scope_digest!=scope or stream.role_source_digest!=candidate.source.role_source_digest or stream.family!=table or stream.stream_kind!=kind
                        or stream.schema_digest!=shape.schema_digest or stream.primary_key_columns!=shape.primary_key_columns or stream.primary_key_types!=shape.primary_key_types or end.stream_id!=stream.stream_id):raise AuthorityUnavailable('registered backup historical Source schema/fullkey differs')
                saved=meter.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,))
                if saved is None or saved[0]!='sealed' or c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)!=end:raise AuthorityUnavailable('registered backup historical family complete seal differs')
            self.phase='directory_member';return False
        if self.phase=='directory_member':
            self._member(db,candidate.disposition_directory.identity,candidate.disposition_directory.complete,(scope,table),c09_row_commitment_v2(self.directory),meter)
            self.phase='proof';return False
        if self.phase=='proof':
            self.proof=meter.read_fixed_row(db,'c09_graph_dispositions_v2',_GRAPH_DISPOSITION_COLUMNS_V3,'scope_digest=? AND table_name=? AND key_digest=?',(scope,table,canonical_digest((table,self.key))))
            if self.proof is None or self.proof[3]!=canonical_serialize(self.key) or self.proof[7]!=self.origin.stream_id:raise AuthorityUnavailable('registered backup historical disposition/key/Source stream differs')
            from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV1
            GraphRowDispositionV1(self.proof[2],self.proof[4],self.proof[5],self.proof[6]);self.phase='source_member';return False
        if self.phase=='source_member':
            if self._member(db,self.origin,self.original,self.key,self.proof[4],meter)!=self.proof[8]:raise AuthorityUnavailable('registered backup disposition loses exact Source ordinal')
            self.phase='disposition_member';return False
        if self.phase=='disposition_member':
            self._member(db,self.identity,self.seal,self.key,c09_row_commitment_v2(self.proof),meter);self.complete=True;return True
        raise AuthorityUnavailable('unknown actual Graph member quantum')

class _RegisteredBackupGenesisGraphReadV3:
    def __init__(self,token,owner,summary,candidate,*,directory_only=False):
        if token is not _TOKEN:raise TypeError('actual registered genesis Graph issuer required')
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        self.owner=owner;self.summary=summary;self.candidate=candidate;self.directory_only=directory_only;self.phase='directory';self.complete=False
        self.outer=C09HistoricalSealedStreamReaderV2(candidate.disposition_directory);self.directory_after='';self.source_directory_after='';self.source_directory_count=0;self.family=None;self.source=None;self.disposition=None;self.source_after=None;self.disposition_after='';self.source_count=0;self.disposition_count=0;self.inner=None
        self.table_after='';self.shape=None;self.key=None;self.row=None;self.commitment=None;self.proof=None;self.lineage_generation=1;self.lineage_scan=None;self.lineage_candidate=None;self.target=None;self.point_read=None;self.next_candidate=None
    def advance(self,meter):
        from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2
        from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2,read_c09_table_shape_v2,_quote,require_c09_capture_member_v2
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2,begin_next_authenticated_prepared_reader_v2
        owner=self.owner;scope=self.candidate.scope.scope_digest;owner.view.require_current(meter=meter)
        if self.phase=='directory':
            with owner.view.basis.read_database('graph',meter=meter) as db:
                def observe(record):
                    row=_read_one(db,'SELECT scope_digest,family,identity_json,complete_json FROM c09_graph_disposition_directory_v2 WHERE scope_digest=? AND family>? ORDER BY family LIMIT 1',(scope,self.directory_after),meter)
                    if row is None or record.primary_key!=row[:2] or record.commitment!=c09_row_commitment_v2(row):raise AuthorityUnavailable('genesis Graph actual signed disposition directory differs')
                    self.directory_after=row[1]
                done=self.outer.advance(db,meter,observe)
                if done and _read_one(db,'SELECT 1 FROM c09_graph_disposition_directory_v2 WHERE scope_digest=? AND family>? LIMIT 1',(scope,self.directory_after),meter) is not None:raise AuthorityUnavailable('genesis Graph signed directory has an unsealed suffix')
            if done:self.phase='source_directory'
            return False
        if self.phase=='source_directory':
            with owner.view.basis.read_database('graph',meter=meter) as db:
                row=_read_one(db,'SELECT family,identity_json,complete_json FROM c09_graph_stream_directory_v2 WHERE scope_digest=? AND directory_kind=? AND family>? ORDER BY family LIMIT 1',(scope,'source_originals',self.source_directory_after),meter)
                if row is not None:disposition=_read_one(db,'SELECT identity_json,complete_json FROM c09_graph_disposition_directory_v2 WHERE scope_digest=? AND family=?',(scope,row[0]),meter)
            if row is None:
                if self.source_directory_count!=self.candidate.disposition_directory.complete.record_count:raise AuthorityUnavailable('genesis Graph Source/disposition directories omit a complete family')
                if self.directory_only:self.complete=True;return True
                self.phase='backup_tables';return False
            if disposition is None:raise AuthorityUnavailable('genesis Graph extra Source family is not in actual signed disposition directory')
            self.source_directory_count+=1;self.family=row[0];self.source=C09SealedStreamLocatorV2('graph',c09_paged_value_from_wire_v2(json.loads(row[1]),C09StreamIdentityV2),c09_paged_value_from_wire_v2(json.loads(row[2]),C09CompleteStreamV2))
            self.disposition=C09SealedStreamLocatorV2('graph',c09_paged_value_from_wire_v2(json.loads(disposition[0]),C09StreamIdentityV2),c09_paged_value_from_wire_v2(json.loads(disposition[1]),C09CompleteStreamV2))
            for locator,kind in ((self.source,'graph_facts'),(self.disposition,'row_dispositions')):
                if (locator.identity.scope_digest!=scope or locator.identity.family!=self.family or locator.identity.role_source_digest!=self.candidate.source.role_source_digest or locator.identity.stream_kind!=kind):raise AuthorityUnavailable('genesis Graph complete family crossed actual Source identity')
            if (self.source.identity.schema_digest,self.source.identity.primary_key_columns,self.source.identity.primary_key_types,self.source.complete.record_count)!=(self.disposition.identity.schema_digest,self.disposition.identity.primary_key_columns,self.disposition.identity.primary_key_types,self.disposition.complete.record_count):raise AuthorityUnavailable('genesis Graph Source/disposition shape or complete census differs')
            self.inner=C09HistoricalSealedStreamReaderV2(self.source);self.source_count=0;self.phase='source_members';return False
        if self.phase=='source_members':
            with owner.view.basis.read_database('graph',meter=meter) as db:
                def observe(record):
                    proof=meter.read_fixed_row(db,'c09_graph_dispositions_v2',_GRAPH_DISPOSITION_COLUMNS_V3,'scope_digest=? AND table_name=? AND key_digest=?',(scope,self.family,canonical_digest((self.family,record.primary_key))))
                    ordinal=self.inner.cursor.record_offset+self.inner.index+1
                    if proof is None or proof[3]!=canonical_serialize(record.primary_key) or proof[4]!=record.commitment or proof[7:9]!=(self.source.identity.stream_id,ordinal):raise AuthorityUnavailable('genesis Graph Source complete member/disposition original differs')
                    self.source_count+=1
                done=self.inner.advance(db,meter,observe)
            if done:self.inner=C09HistoricalSealedStreamReaderV2(self.disposition);self.disposition_count=0;self.phase='disposition_members'
            return False
        if self.phase=='disposition_members':
            with owner.view.basis.read_database('graph',meter=meter) as db:
                def observe(record):
                    proof=meter.read_fixed_row(db,'c09_graph_dispositions_v2',_GRAPH_DISPOSITION_COLUMNS_V3,'scope_digest=? AND table_name=? AND key_digest=?',(scope,self.family,canonical_digest((self.family,record.primary_key))))
                    if proof is None or proof[3]!=canonical_serialize(record.primary_key) or c09_row_commitment_v2(proof)!=record.commitment:raise AuthorityUnavailable('genesis Graph disposition full record original differs')
                    self.disposition_count+=1
                done=self.inner.advance(db,meter,observe)
            if done:self.phase='disposition_census';self.disposition_after='';self.source_count=0
            return False
        if self.phase=='disposition_census':
            with owner.view.basis.read_database('graph',meter=meter) as db:row=_read_one(db,'SELECT key_digest,source_primary_key_json FROM c09_graph_dispositions_v2 WHERE scope_digest=? AND table_name=? AND key_digest>? ORDER BY key_digest LIMIT 1',(scope,self.family,self.disposition_after),meter)
            if row is not None:self.disposition_after=row[0];self.source_count+=1;return False
            if self.source_count!=self.disposition.complete.record_count or self.disposition_count!=self.source_count:raise AuthorityUnavailable('genesis Graph actual disposition census EOF has omitted/extra rows')
            self.source_directory_after=self.family;self.inner=None;self.phase='source_directory';return False
        if self.phase=='backup_tables':
            with owner._source('graph',meter) as db:row=_read_one(db,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name>? ORDER BY name LIMIT 1",(self.table_after,),meter)
            if row is None:
                owner._record('genesis_graph_eof',self.candidate.scope.scope_digest,{'generation':1,'operation_id':self.summary['operation_id'],'prepared_digest':self.summary['prepared_digest'],'candidate_digest':self.candidate.digest,'source_digest':self.candidate.source.role_source_digest},meter)
                self.complete=True;return True
            with owner._source('graph',meter) as db:self.shape=read_c09_table_shape_v2(db,row[0],meter=meter)
            self.key=None;self.phase='backup_rows';return False
        if self.phase=='backup_rows':
            keys=','.join(_quote(n)+' COLLATE BINARY' for n in self.shape.primary_key_columns);where='' if self.key is None else ' WHERE ('+keys+')>('+','.join('?' for _ in self.key)+')'
            with owner._source('graph',meter) as db:row=_read_one(db,'SELECT '+keys+' FROM '+_quote(self.shape.table)+where+' ORDER BY '+keys+' LIMIT 1',() if self.key is None else self.key,meter)
            if row is None:self.table_after=self.shape.table;self.shape=None;self.phase='backup_tables';return False
            self.key=tuple(row);self.row=_BackupGraphRowCommitmentV3(owner,self.shape,self.key);self.phase='backup_row_bytes';return False
        if self.phase=='backup_row_bytes':
            with owner._source('graph',meter) as db:done=self.row.advance(db,meter)
            if done:self.commitment=self.row.commitment;self.row=None;self.phase='backup_row_origin'
            return False
        if self.phase=='backup_row_origin':
            if _registered_backup_budget_source_v3(owner,self.shape,self.key,self.commitment,meter):self.phase='backup_rows';return False
            if self.point_read is None:self.point_read=_RegisteredGraphPointReadV3(self.candidate,self.shape,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point_read.advance(db,meter)
            if not done:return False
            self.proof=self.point_read.proof;self.point_read=None
            if self.proof[4]!=self.commitment:raise AuthorityUnavailable('genesis backup earlier row has no exact authenticated Source revision commitment')
            self.lineage_generation=1;self.lineage_candidate=self.candidate;self.lineage_scan=None;self.phase='row_lineage';return False
        if self.phase=='row_lineage':
            if self.proof[6] is None:
                self._finish_row(meter);return False
            if self.lineage_generation==owner.view.scope.maintenance_generation:
                with owner.view.basis.read_database('graph',meter=meter) as db:
                    actual=read_c09_table_shape_v2(db,self.shape.table,meter=meter)
                    if actual.columns!=self.shape.columns or actual.primary_key_columns!=self.shape.primary_key_columns:raise AuthorityUnavailable('retained genesis Graph target requires its actual registered schema lineage')
                self.target=_BackupGraphRowCommitmentV3(owner,actual,self.key);self.phase='target_bytes';return False
            if self.next_candidate is not None:
                if self.point_read is None:self.point_read=_RegisteredGraphPointReadV3(self.next_candidate,self.shape,self.key);return False
                with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point_read.advance(db,meter)
                if not done:return False
                proof=self.point_read.proof
                if proof[4]!=self.proof[6]:raise AuthorityUnavailable('retained genesis Graph row lost its actual signed consecutive Source lineage')
                self.proof=proof;self.lineage_candidate=self.next_candidate;self.lineage_generation=self.next_candidate.scope.maintenance_generation;self.lineage_scan=None;self.point_read=None;self.next_candidate=None;return False
            if self.lineage_scan is None:self.lineage_scan=begin_next_authenticated_prepared_reader_v2(owner.service.control,after_generation=self.lineage_generation,through_generation=owner.view.scope.maintenance_generation,meter=meter);return False
            summary=self.lineage_scan.advance(meter=meter)
            if summary is None:return False
            self.next_candidate=_registered_graph_candidate_v3(owner,summary,meter);return False
        if self.phase=='target_bytes':
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.target.advance(db,meter)
            if done:
                if self.target.commitment!=self.proof[6]:raise AuthorityUnavailable('retained genesis Graph current full target commitment differs')
                self.target=None;self._finish_row(meter)
            return False
        raise AuthorityUnavailable('unknown actual genesis Graph source qualification phase')
    def _finish_row(self,meter):
        self.owner._record('genesis_graph_row',canonical_digest((self.shape.table,self.key)),{'table':self.shape.table,'shape':asdict(self.shape),'primary_key':self.key,'source_commitment':self.commitment,'initial_candidate_digest':self.candidate.digest,
            'lineage_generation':self.lineage_generation,'lineage_operation_id':self.lineage_candidate.scope.operation_id,'lineage_candidate_digest':self.lineage_candidate.digest,'disposition':self.proof[5],'target_commitment':self.proof[6]},meter)
        self.proof=None;self.phase='backup_rows'

def begin_registered_backup_genesis_graph_v3(verifiedBackupAdmission,actualSelectedView,verifiedFirstPreparedSummary,meter):
    from .c09_paged_recovery_facts_v2 import C09VerifiedPagedPreparedSummaryV2,C09VerifiedLegacyPreparedSummaryV2
    admission=verifiedBackupAdmission;summary=verifiedFirstPreparedSummary
    if (type(admission) is not _VerifiedBackupAdmissionV3 or admission.view is not actualSelectedView or type(summary) is not C09VerifiedLegacyPreparedSummaryV2 and not isinstance(summary,C09VerifiedPagedPreparedSummaryV2)):raise TypeError('actual registered genesis backup and first paged Source Graph originals required')
    actualSelectedView.require_current(meter=meter);summary.require_current(meter=meter)
    backup=admission.backup
    if (backup['storage_identity']['storage_generation']!=0 or summary['maintenance_generation']!=1 or summary['old_manifest_digest']!=backup['storage_identity']['manifest_digest']
            or summary['namespace']!=backup['namespace'] or summary['installation_id']!=backup['installation_id']):raise AuthorityUnavailable('genesis backup first actual PREPARED Source lineage differs')
    with actualSelectedView.basis.read_database('graph',meter=meter) as db:member=_read_one(db,'SELECT operation_id,prepared_digest,manifest_digest FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND generation=?',(actualSelectedView.scope.scope_digest,1),meter)
    if member!=(summary['operation_id'],summary['prepared_digest'],summary['new_manifest_digest']):raise AuthorityUnavailable('first actual Source Graph lacks complete selected historical membership')
    if type(summary) is C09VerifiedLegacyPreparedSummaryV2:return _RegisteredBackupGenesisLegacyGraphReadV3(_TOKEN,admission,summary)
    return _RegisteredBackupGenesisGraphReadV3(_TOKEN,admission.owner,summary,_registered_graph_candidate_v3(admission.owner,summary,meter))

class _RegisteredBackupLegacyGraphCandidateReadV3:
    """The actual V1 producer original: byte HMAC and each typed manifest EOF."""
    def __init__(self,owner,summary,*,backup_key=None):
        from .c09_paged_recovery_facts_v2 import C09CanonicalSqlCellReaderV2
        self.owner=owner;self.backup_key=owner.backup_key if backup_key is None else backup_key;self.summary=summary;self.phase='scan';self.complete=False;self.db=None;self.meter=None
        self.cell_done=False;self.cell=C09CanonicalSqlCellReaderV2('c09_storage_build_originals_v1','original_json','installation_id=? AND operation_id=? AND original_kind=?',(owner.service.control.installation_id,summary['operation_id'],'graph_candidate'),ensure_ascii=False,observe=self._event)
        self.starts={};self.pending=[];self.original_fields=None;self.fields=None;self.field_index=0;self.position=None;self.digest=sha256();self.digest.update(b'{');self.original_digest=None;self.header=None
        self.manifest_index=None;self.manifest_header=None;self.manifest_after='';self.row_hash=None;self.row_count=0;self.table_after='';self.candidate_digest=None;self.candidate_header={}
    def _event(self,event):
        path=event.path;base=('details','candidate','table_manifests')
        if event.kind in {'object_start','array_start','scalar_start'}:
            if len(path)==3 and path[:2]==('details','candidate') or len(path)==4 and path[:3]==base or len(path)==6 and path[:3]==base and path[4]=='rows':self.starts[path]=event.start_offset
        if event.kind not in {'object_end','array_end','scalar_end'} or path not in self.starts:return
        start=self.starts.pop(path)
        if len(path)==3:self.cell.spans[path]=(start,event.end_offset);return
        if len(path)==6:
            from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV1
            size=event.end_offset-start
            if size>65536:raise AuthorityUnavailable('actual V1 Source row disposition exceeds its finite codec')
            raw=json.loads(self.cell.read(self.db,start,size,self.meter))
            if set(raw)!={'row_key_digest','old_commitment','disposition','new_commitment'}:raise AuthorityUnavailable('actual V1 Source disposition fields differ')
            value=GraphRowDispositionV1(**raw);self.pending.append(('row',path[3],value));return
        self.pending.append(('table',path[3],(start,event.end_offset)))
    def advance(self,meter):
        import hmac
        from .c09_storage_control_v1 import canonical
        from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1
        owner=self.owner;owner.view.require_current(meter=meter);self.summary.require_current(meter=meter)
        if self.phase=='scan':
            if self.pending:
                kind,index,value=self.pending.pop(0)
                if kind=='row':owner._record('legacy_graph_source_member',str(self.summary['maintenance_generation'])+':'+str(index).zfill(10)+':'+value.row_key_digest,{'generation':self.summary['maintenance_generation'],'table_index':index,'row':asdict(value)},meter,backup_key=self.backup_key)
                else:self.manifest_index=index;self.manifest_header=value;self.phase='table_header'
                return False
            if not self.cell_done:
                with owner.service.control._db() as db:
                    self.db,self.meter=db,meter
                    try:self.cell_done=self.cell.advance(db,meter)
                    finally:self.db=self.meter=None
                return False
            if self.cell_done:
                expected={'schema','installation_id','operation_id','original_kind','old_manifest_digest','expected_pointer_version','details','key_id','original_digest','signature'}
                if {path[0] for path in self.cell.spans if len(path)==1}!=expected:raise AuthorityUnavailable('actual V1 Graph producer original exact envelope differs')
                if {path[2] for path in self.cell.spans if len(path)==3 and path[:2]==('details','candidate')}!={f.name for f in fields(GraphRebaseCandidateV1)}:raise AuthorityUnavailable('actual V1 Graph candidate exact field set differs')
                self.fields=tuple(sorted(expected-{'original_digest','signature'}));self.phase='original_hash'
            return False
        if self.phase=='table_header':
            index=self.manifest_index;start,end=self.manifest_header
            # Re-parse only this manifest's four top-level fields. Its row values
            # already reside in the actual protected Control index, never a list.
            from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            self.table_parser=C09CanonicalJSONStreamV2(ensure_ascii=False);self.table_position=start;self.table_end=end;self.table_spans={};self.table_starts={};self.phase='table_scan';return False
        if self.phase=='table_scan':
            def observe(event):
                if len(event.path)==1:
                    if event.kind in {'object_start','array_start','scalar_start'}:self.table_starts[event.path[0]]=event.start_offset
                    elif event.kind in {'object_end','array_end','scalar_end'}:self.table_spans[event.path[0]]=(self.table_starts.pop(event.path[0]),event.end_offset)
            if self.table_position<self.table_end:
                with owner.service.control._db() as db:raw=self.cell.read(db,self.table_position,min(1024,self.table_end-self.table_position),meter)
                self.table_parser.feed(raw,observe);self.table_position+=len(raw);return False
            self.table_parser.finish()
            if set(self.table_spans)!={'table_name','rows','manifest_digest','schema'}:raise AuthorityUnavailable('actual V1 Source table manifest fields differ')
            values={}
            with owner.service.control._db() as db:
                for name in ('table_name','manifest_digest','schema'):
                    a,b=self.table_spans[name];values[name]=json.loads(self.cell.read(db,self.manifest_header[0]+a,b-a,meter))
            if values['table_name']<=self.table_after or values['schema']!='sylanne3.graph.c09_table_disposition.v1':raise AuthorityUnavailable('actual V1 Source tables are not strictly ordered/distinct')
            self.manifest_header=values;self.row_hash=sha256();self.row_hash.update(('['+canonical_serialize(values['table_name'])+',[').encode('ascii'));self.row_count=0;self.manifest_after='';self.phase='table_rows';return False
        if self.phase=='table_rows':
            from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV1
            prefix=str(self.summary['maintenance_generation'])+':'+str(self.manifest_index).zfill(10)+':'
            with owner.service.control._db() as db:row=_read_one(db,'SELECT item_key,proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key>? AND item_key<? ORDER BY item_key LIMIT 1',(owner.selection,self.backup_key,'legacy_graph_source_member',prefix+self.manifest_after,prefix+'g'),meter)
            if row is not None:
                proof=json.loads(row[1]);value=GraphRowDispositionV1(**proof['row'])
                if canonical_digest(proof)!=row[2] or value.row_key_digest<=self.manifest_after:raise AuthorityUnavailable('actual V1 Source manifest indexed row order/digest differs')
                if self.row_count:meter.charge_encode(1);self.row_hash.update(b',')
                self.row_hash.update(canonical_serialize(value).encode('ascii'));self.row_count+=1;self.manifest_after=value.row_key_digest;return False
            suffix='],'+canonical_serialize(self.manifest_header['schema'])+']';meter.charge_encode(len(suffix));self.row_hash.update(suffix.encode('ascii'))
            if self.row_hash.hexdigest()!=self.manifest_header['manifest_digest']:raise AuthorityUnavailable('actual V1 typed Source manifest complete root differs')
            owner._record('legacy_graph_source_table',str(self.summary['maintenance_generation'])+':'+self.manifest_header['table_name'],{'generation':self.summary['maintenance_generation'],'table_index':self.manifest_index,'row_count':self.row_count,**self.manifest_header},meter,backup_key=self.backup_key)
            self.table_after=self.manifest_header['table_name'];self.table_parser=None;self.table_spans={};self.table_starts={};self.phase='scan';return False
        if self.phase=='original_hash':
            if self.field_index==len(self.fields):
                meter.charge_encode(1);self.digest.update(b'}');self.original_digest=self.digest.hexdigest();self.phase='original_verify';return False
            name=self.fields[self.field_index];a,b=self.cell.spans[(name,)]
            if self.position is None:
                prefix=(',' if self.field_index else '')+canonical(name)+':';meter.charge_encode(len(prefix.encode('utf-8')));self.digest.update(prefix.encode('utf-8'));self.position=a
            if self.position<b:
                with owner.service.control._db() as db:raw=self.cell.read(db,self.position,min(1024,b-self.position),meter)
                self.digest.update(raw);self.position+=len(raw);return False
            self.field_index+=1;self.position=None;return False
        if self.phase=='original_verify':
            with owner.service.control._db() as db:
                meta={name:self.cell.value(db,(name,),meter) for name in ('schema','installation_id','operation_id','original_kind','old_manifest_digest','expected_pointer_version','key_id','original_digest','signature')}
                candidate={name:self.cell.value(db,('details','candidate',name),meter) for name in ('schema','status','namespace','operation_id','source_files_fingerprint','source_path','source_identity','maintenance_generation','candidate_digest')}
                stored=_read_one(db,'SELECT original_digest FROM c09_storage_build_originals_v1 WHERE installation_id=? AND operation_id=? AND original_kind=?',self.cell.parameters,meter)
            expected=hmac.new(owner.service.control._key,(meta['schema']+'\n'+self.original_digest).encode(),sha256).hexdigest()
            if (stored!=(self.original_digest,) or meta['original_digest']!=self.original_digest or meta['schema']!='sylanne3.c09.storage-build-original.v1' or meta['key_id']!=owner.service.control.key_id
                    or not hmac.compare_digest(expected,meta['signature']) or meta['installation_id']!=owner.service.control.installation_id or meta['operation_id']!=self.summary['operation_id'] or meta['original_kind']!='graph_candidate'
                    or meta['old_manifest_digest']!=self.summary['old_manifest_digest'] or candidate['schema']!='sylanne3.graph.c09_rebase_candidate.v1' or candidate['status']!='candidate_only_hold'
                    or candidate['operation_id']!=self.summary['operation_id'] or candidate['maintenance_generation']!=self.summary['maintenance_generation']):raise AuthorityUnavailable('actual complete V1 Graph producer signature/identity differs')
            self.candidate_header=candidate;self.candidate_digest=candidate['candidate_digest'];self.complete=True;return True
        raise AuthorityUnavailable('unknown actual V1 Graph original quantum')

class _RegisteredBackupGenesisLegacyGraphReadV3:
    def __init__(self,token,admission,summary):
        if token is not _TOKEN:raise TypeError('actual registered V1 Source issuer required')
        self.owner=admission.owner;self.summary=summary;self.original=_RegisteredBackupLegacyGraphCandidateReadV3(self.owner,summary);self.phase='original';self.complete=False
        self.table_after='';self.shape=None;self.key=None;self.row=None;self.table_proof=None;self.row_count=0;self.source_proof=None;self.lineage_generation=1;self.lineage_reader=None
    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,_quote
        from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
        owner=self.owner
        if self.phase=='original':
            if not self.original.advance(meter):return False
            before=owner.backup['copies']['graph']['source_observation'];header=self.original.candidate_header
            fingerprint=canonical_digest((before['resolved_path'],(('db',before['device'],before['file_id'],before['prepared_size'],before['prepared_sha256']),)))
            if (owner.backup['copies']['graph']['source_wal_observation'] is not None or header['source_files_fingerprint']!=fingerprint
                    or header['source_path']!=before['resolved_path'] or tuple(header['source_identity'])!=(before['device'],before['file_id'],before['prepared_size'],before['prepared_mtime_ns'])
                    or header['namespace']!=owner.backup['reconciliation']['namespace']):raise AuthorityUnavailable('earlier V1 backup lacks exact signed same-Source bytes/schema provenance')
            owner.legacy_graph_original=self.original;self.phase='tables';return False
        if self.phase=='tables':
            with owner._source('graph',meter) as db:row=_read_one(db,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name>? ORDER BY name LIMIT 1",(self.table_after,),meter)
            if row is None:
                owner._record('legacy_genesis_graph_eof',self.summary['operation_id'],{'generation':1,'operation_id':self.summary['operation_id'],'prepared_digest':self.summary['prepared_digest'],'original_digest':self.original.original_digest,'candidate_digest':self.original.candidate_digest},meter)
                self.complete=True;return True
            with owner._source('graph',meter) as db:self.shape=read_c09_table_shape_v2(db,row[0],meter=meter)
            with owner.service.control._db() as db:manifest=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(owner.selection,owner.backup_key,'legacy_graph_source_table','1:'+row[0]),meter)
            if manifest is None:raise AuthorityUnavailable('actual V1 Source candidate omits a backup table')
            self.table_proof=json.loads(manifest[0])
            if canonical_digest(self.table_proof)!=manifest[1]:raise AuthorityUnavailable('actual V1 Source manifest changed')
            self.row_count=0;self.key=None;self.phase='rows';return False
        if self.phase=='rows':
            names=','.join(_quote(n)+' COLLATE BINARY' for n in self.shape.primary_key_columns);where='' if self.key is None else ' WHERE ('+names+')>('+','.join('?' for _ in self.key)+')'
            with owner._source('graph',meter) as db:row=_read_one(db,'SELECT '+names+' FROM '+_quote(self.shape.table)+where+' ORDER BY '+names+' LIMIT 1',() if self.key is None else self.key,meter)
            if row is None:
                if self.row_count!=self.table_proof['row_count']:raise AuthorityUnavailable('actual V1 same-Source backup row census EOF differs')
                self.table_after=self.shape.table;self.shape=None;self.phase='tables';return False
            self.key=tuple(row);self.row=_BackupGraphRowCommitmentV3(owner,self.shape,self.key);self.phase='bytes';return False
        if self.phase=='bytes':
            with owner._source('graph',meter) as db:done=self.row.advance(db,meter)
            if not done:return False
            rowkey=canonical_digest((self.shape.table,self.key));index='1:'+str(self.table_proof['table_index']).zfill(10)+':'+rowkey
            with owner.service.control._db() as db:row=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(owner.selection,owner.backup_key,'legacy_graph_source_member',index),meter)
            if row is None:raise AuthorityUnavailable('actual V1 Source omits a backup full primary key')
            proof=json.loads(row[0]);self.source_proof=proof['row']
            if canonical_digest(proof)!=row[1] or self.source_proof['row_key_digest']!=rowkey or self.source_proof['old_commitment']!=self.row.commitment:raise AuthorityUnavailable('actual V1 Source full backup row commitment differs')
            self.commitment=self.row.commitment;self.row=None
            legacy_source={'generation':1,'table_index':self.table_proof['table_index'],'original_digest':self.original.original_digest,'candidate_digest':self.original.candidate_digest}
            if _registered_backup_budget_source_v3(owner,self.shape,self.key,self.commitment,meter,legacy_source=legacy_source):self.row_count+=1;self.source_proof=None;self.phase='rows';return False
            self.lineage_generation=1;self.lineage_reader=None;self.phase='lineage';return False
        if self.phase=='lineage':
            if self.lineage_reader is None:
                proof={'table':self.shape.table,'shape':asdict(self.shape),'primary_key':self.key,'source_commitment':self.commitment,'original_digest':self.original.original_digest}
                self.lineage_reader=_RegisteredBackupLegacyGraphRowRecheckV3(owner,proof,owner.backup_key);return False
            if not self.lineage_reader.advance(meter):return False
            self.lineage_generation=self.lineage_reader.generation;self.source_proof=dict(self.source_proof,new_commitment=self.lineage_reader.expected);self.lineage_reader=None;self._finish_row(meter);return False
        raise AuthorityUnavailable('unknown actual V1 genesis Source phase')
    def _finish_row(self,meter):
        self.owner._record('legacy_genesis_graph_row',canonical_digest((self.shape.table,self.key)),{'table':self.shape.table,'shape':asdict(self.shape),'primary_key':self.key,'source_commitment':self.commitment,
            'table_index':self.table_proof['table_index'],'candidate_digest':self.original.candidate_digest,'original_digest':self.original.original_digest,'target_commitment':self.source_proof['new_commitment'],'lineage_generation':self.lineage_generation},meter)
        self.row_count+=1;self.source_proof=None;self.phase='rows'

class _RegisteredBackupGraphRowRecheckV3:
    """Re-read actual signed Source/disposition lineage through the current target."""
    def __init__(self,owner,proof):
        from ..runtime.c09_paged_sql_v2 import C09TableShapeV2
        self.owner=owner;self.proof=proof;raw=proof['shape'];self.shape=C09TableShapeV2(raw['table'],tuple(raw['columns']),tuple(raw['primary_key_columns']),tuple(raw['primary_key_types']),raw['schema_digest'])
        self.key=tuple(proof['primary_key']);self.generation=1;self.scan=None;self.point=None;self.target=None;self.complete=False;self.candidate=None;self.point_read=None;self.next_candidate=None
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        owner=self.owner
        if self.point is None:
            candidate=owner.genesis_candidate
            if candidate is None or candidate.digest!=self.proof['initial_candidate_digest']:raise AuthorityUnavailable('actual genesis Graph row needs its verified Source complete original first')
            if self.point_read is None:self.point_read=_RegisteredGraphPointReadV3(candidate,self.shape,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point_read.advance(db,meter)
            if not done:return False
            self.point=self.point_read.proof;self.point_read=None
            if self.point[4]!=self.proof['source_commitment']:raise AuthorityUnavailable('actual retained backup source row commitment changed')
            self.candidate=candidate;return False
        if self.point[6] is None:
            self.complete=True;return True
        if self.generation==owner.view.scope.maintenance_generation:
            if self.target is None:
                with owner.view.basis.read_database('graph',meter=meter) as db:actual=read_c09_table_shape_v2(db,self.shape.table,meter=meter)
                if actual.columns!=self.shape.columns or actual.primary_key_columns!=self.shape.primary_key_columns:raise AuthorityUnavailable('actual retained backup target requires authenticated schema lineage')
                self.target=_BackupGraphRowCommitmentV3(owner,actual,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.target.advance(db,meter)
            if done:
                if self.target.commitment!=self.point[6]:raise AuthorityUnavailable('actual retained backup target full commitment changed')
                self.complete=True
            return self.complete
        if self.next_candidate is not None:
            if self.point_read is None:self.point_read=_RegisteredGraphPointReadV3(self.next_candidate,self.shape,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point_read.advance(db,meter)
            if not done:return False
            point=self.point_read.proof
            if point[4]!=self.point[6]:raise AuthorityUnavailable('actual retained backup Source/disposition lineage changed')
            self.point=point;self.generation=self.next_candidate.scope.maintenance_generation;self.candidate=self.next_candidate;self.next_candidate=None;self.point_read=None;self.scan=None;return False
        if self.scan is None:self.scan=begin_next_authenticated_prepared_reader_v2(owner.service.control,after_generation=self.generation,through_generation=owner.view.scope.maintenance_generation,meter=meter);return False
        summary=self.scan.advance(meter=meter)
        if summary is None:return False
        self.next_candidate=_registered_graph_candidate_v3(owner,summary,meter);return False

class _RegisteredBackupLegacyGraphRowRecheckV3:
    def __init__(self,owner,proof,backup_key):
        from ..runtime.c09_paged_sql_v2 import C09TableShapeV2
        self.owner=owner;self.proof=proof;self.backup_key=backup_key;raw=proof['shape'];self.shape=C09TableShapeV2(raw['table'],tuple(raw['columns']),tuple(raw['primary_key_columns']),tuple(raw['primary_key_types']),raw['schema_digest'])
        self.key=tuple(proof['primary_key']);self.generation=0;self.expected=None;self.scan=None;self.original=None;self.candidate=None;self.point=None;self.target=None;self.complete=False
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2,C09VerifiedLegacyPreparedSummaryV2
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        owner=self.owner
        if self.generation==0:
            original=owner.legacy_graph_original
            if original is None or original.backup_key!=self.backup_key or original.original_digest!=self.proof['original_digest']:raise AuthorityUnavailable('actual V1 backup row needs its authenticated full Source original first')
            self.original=original;self.generation=1
        if self.original is not None:
            if not self.original.complete:
                if not self.original.advance(meter):return False
            with owner.service.control._db() as db:
                table=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(owner.selection,self.backup_key,'legacy_graph_source_table',str(self.generation)+':'+self.shape.table),meter)
                if table is None:raise AuthorityUnavailable('actual V1 retained Source table manifest absent')
                tableproof=json.loads(table[0]);index=str(self.generation)+':'+str(tableproof['table_index']).zfill(10)+':'+canonical_digest((self.shape.table,self.key))
                row=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(owner.selection,self.backup_key,'legacy_graph_source_member',index),meter)
            if row is None or canonical_digest(tableproof)!=table[1] or canonical_digest(json.loads(row[0]))!=row[1]:raise AuthorityUnavailable('actual V1 retained Source member root/index differs')
            value=json.loads(row[0])['row'];expected=self.proof['source_commitment'] if self.expected is None else self.expected
            if value['old_commitment']!=expected:raise AuthorityUnavailable('actual V1 retained row loses its consecutive old commitment')
            self.expected=value['new_commitment'];self.original=None;self.scan=None;return False
        if self.expected is None:self.complete=True;return True
        if self.generation==owner.view.scope.maintenance_generation:
            if self.target is None:
                with owner.view.basis.read_database('graph',meter=meter) as db:shape=read_c09_table_shape_v2(db,self.shape.table,meter=meter)
                if shape.columns!=self.shape.columns or shape.primary_key_columns!=self.shape.primary_key_columns:raise AuthorityUnavailable('actual V1 backup requires an authenticated schema lineage')
                self.target=_BackupGraphRowCommitmentV3(owner,shape,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.target.advance(db,meter)
            if done:
                if self.target.commitment!=self.expected:raise AuthorityUnavailable('actual V1 retained current target full row changed')
                self.complete=True
            return self.complete
        if self.candidate is not None:
            if self.point is None:self.point=_RegisteredGraphPointReadV3(self.candidate,self.shape,self.key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point.advance(db,meter)
            if not done:return False
            if self.point.proof[4]!=self.expected:raise AuthorityUnavailable('actual V1 to paged Source row lineage differs')
            self.expected=self.point.proof[6];self.point=None;self.candidate=None;self.scan=None;return False
        if self.scan is None:self.scan=begin_next_authenticated_prepared_reader_v2(owner.service.control,after_generation=self.generation,through_generation=owner.view.scope.maintenance_generation,meter=meter);return False
        summary=self.scan.advance(meter=meter)
        if summary is None:return False
        self.generation=summary['maintenance_generation']
        if type(summary) is C09VerifiedLegacyPreparedSummaryV2:self.original=_RegisteredBackupLegacyGraphCandidateReadV3(owner,summary,backup_key=self.backup_key)
        else:self.candidate=_registered_graph_candidate_v3(owner,summary,meter)
        return False

class _RegisteredOfflineCancelledReservationReadV3:
    """Actual OFFLINE cancellation originals, Core retirement and no-claim EOF."""
    def __init__(self,owner,lease,operation):
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        from ..runtime.issuers import D11BudgetJobIssuer
        from ..runtime.issuers import D02ResourceIssuer
        m=owner.service.gate._installed_maintenance_v3
        if type(m) is not InstalledC09MaintenanceV1 or m.control is not owner.service.control or m.gate is not owner.service.gate:raise AuthorityUnavailable('actual installed offline original verifier composition required')
        self.owner=owner;self.lease=lease;self.operation=operation;self.issuer=m._installed_d11_budget_job_issuer_v2;self.resource=m._installed_d02_resource_issuer_v2
        if type(self.issuer) is not D11BudgetJobIssuer or type(self.resource) is not D02ResourceIssuer or self.issuer.resource_issuer is not self.resource:raise AuthorityUnavailable('actual installed same-budget D11/D02 verifiers required')
        self.lease_namespace=m.namespace_id;self.phase='gate_scan';self.after='';self.match=None;self.gate=None;self.result=None;self.prepared=None;self.binding_scan=None;self.complete=False
        self.candidate=None;self.source_rows=[];self.source_index=0;self.row_hash=None;self.point=None;self.core_index=0;self.core_rows=[];self.original_digests={}
    def advance(self,meter):
        from ..runtime.d11_offline_originals_v1 import TABLE,SIGN_KIND
        from .d11_offline_unstarted_cancellation_v1 import unstarted_cancellation_from_wire_v1,unstarted_cancellation_operation_id_v1
        from ..runtime.d11_offline_unstarted_cancellation_v1 import _read_signed,unstarted_cancellation_receipt_from_wire_v1,_event_id
        from ..runtime.d11_offline_accounting_v1 import read_offline_accounting_prepared_v1,offline_accounting_original_ref_v1
        from ..domains.d01.production_operations_v1 import plain_v1
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        owner=self.owner;ns=NamespaceId(**owner.backup['reconciliation']['namespace']) if owner.backup is not None else self.lease_namespace
        if self.phase=='gate_scan':
            with owner.view.basis.read_database('graph',meter=meter) as db:row=_read_one(db,'SELECT original_ref,producing_operation_id,payload_json,payload_digest,signature FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref LIMIT 1',(*ns.as_tuple,'cancellation_gate',self.after),meter)
            if row is None:
                if self.match is None:raise AuthorityUnavailable('actual unstarted budget lacks signed offline cancellation gate')
                self.gate=self.match;self.lease_namespace=self.gate.binding.namespace;self.phase='receipt';return False
            raw=json.loads(row[2]);value=unstarted_cancellation_from_wire_v1(raw);digest=canonical_digest(raw)
            self.issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,'cancellation_gate',row[0],digest)),row[4])
            if row[0]!=value.binding.execution_id or row[1]!=unstarted_cancellation_operation_id_v1(value.binding) or digest!=row[3] or canonical_serialize(raw)!=row[2]:raise AuthorityUnavailable('actual offline signed gate identity differs')
            if (value.binding.parent_budget_lease_ref,value.binding.reservation_operation_id)==(self.lease,self.operation):
                if self.match is not None:raise AuthorityUnavailable('offline cancellation reservation has duplicate signed ownership')
                self.match=value;self.original_digests['gate']=digest
            self.after=row[0];return False
        binding=self.gate.binding
        if (binding.authority_namespace!=owner.service.inventory.namespace or binding.installation_id!=owner.service.control.installation_id):raise AuthorityUnavailable('actual offline cancellation scope differs')
        if self.phase=='receipt':
            with owner.view.basis.read_database('graph',meter=meter) as db:self.result=_read_signed(_BoundedReadConnectionV2(db,meter),binding,'cancellation_receipt',self.issuer)
            if self.result is None:raise AuthorityUnavailable('actual signed offline cancellation receipt absent')
            unstarted_cancellation_receipt_from_wire_v1(self.result);self.original_digests['receipt']=canonical_digest(self.result);self.phase='prepared';return False
        if self.phase=='prepared':
            with owner.view.basis.read_database('graph',meter=meter) as db:self.prepared=read_offline_accounting_prepared_v1(_BoundedReadConnectionV2(db,meter),binding=binding,issuer=self.issuer,resource_issuer=self.resource)
            if self.prepared is None or canonical_digest(plain_v1(self.prepared))!=self.gate.accounting_original_digest or self.prepared.prepared_digest!=self.gate.prepared_digest:raise AuthorityUnavailable('actual offline cancellation prepared original absent/different')
            self.original_digests['prepared']=canonical_digest(plain_v1(self.prepared));self.phase='arithmetic';return False
        if self.phase=='arithmetic':
            from dataclasses import replace
            from ..runtime.budget import BudgetLease,BudgetReceipt,_minus,_receipt_json
            from ..runtime.d10_offline_tick_execution_v1 import _decode_json
            result=self.result;gate=self.gate
            expected={'operation_id':unstarted_cancellation_operation_id_v1(binding),'binding_digest':binding.digest,'accounting_original_digest':gate.accounting_original_digest,'prepared_digest':gate.prepared_digest,
                'gate_digest':gate.digest,'no_future_claim_digest':gate.no_future_claim_digest,'claim_gate_id':gate.claim_gate_id,'reservation_operation_id':binding.reservation_operation_id,'reservation_digest':binding.reservation_digest,
                'released_ceiling':{'thread_cpu_ms':binding.cpu_ceiling_ms},'event_id':_event_id(binding)}
            if any(result[key]!=value for key,value in expected.items()):raise AuthorityUnavailable('actual offline cancellation receipt reservation/claim/prepared bindings differ')
            before=_decode_json(result['budget_before_json'],BudgetLease);after=_decode_json(result['budget_after_json'],BudgetLease)
            if (before.lease_id,before.bot_id,before.persona_id)!=(binding.parent_budget_lease_ref,*binding.namespace.as_tuple) or before.state=='closed' or after!=replace(before,reserved=_minus(before.reserved,result['released_ceiling']),version=before.version+1):raise AuthorityUnavailable('actual offline cancellation CPU release arithmetic differs')
            if before.parent_id is None:
                if result['parent_before_json'] is not None or result['parent_after_json'] is not None:raise AuthorityUnavailable('actual offline root cancellation invents parent accounting')
            else:
                parent=_decode_json(result['parent_before_json'],BudgetLease)
                if result['parent_before_json']!=result['parent_after_json'] or (parent.lease_id,parent.bot_id,parent.persona_id,parent.currency)!=(before.parent_id,before.bot_id,before.persona_id,before.currency) or parent.state=='closed' or any(parent.reserved.get(unit,0)<amount for unit,amount in before.limits.items()):raise AuthorityUnavailable('actual offline cancellation parent allocation differs')
            receipt=_decode_json(result['budget_receipt_json'],BudgetReceipt)
            if receipt!=BudgetReceipt('cancelled_unstarted',binding.reservation_operation_id,binding.reservation_digest,after.lease_id,after.version,after.used,after.reserved,after.unconfirmed):raise AuthorityUnavailable('actual offline cancellation immutable budget receipt differs')
            proof_binding=json.dumps({'schema':'d11.unstarted-reservation-cancellation-binding.v1','binding_digest':binding.digest,'accounting_original_digest':gate.accounting_original_digest,'claim_gate_id':gate.claim_gate_id,'no_future_claim_digest':gate.no_future_claim_digest,'cancellation_gate_digest':gate.digest,'ceiling':result['released_ceiling']},sort_keys=True,separators=(',',':'))
            with owner.view.basis.read_database('graph',meter=meter) as db:
                operation=_read_one(db,'SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?',(*binding.namespace.as_tuple,binding.reservation_operation_id,'cancel_unstarted'),meter)
                reservation=_read_one(db,'SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',(self.lease,self.operation),meter)
                conflict=_read_one(db,'SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?',(*binding.namespace.as_tuple,self.operation,'settle'),meter)
            if operation!=(binding.reservation_digest,self.lease,_receipt_json(receipt),proof_binding) or reservation!=(binding.reservation_digest,canonical_serialize(result['released_ceiling']),'cancelled_unstarted',None) or conflict is not None:raise AuthorityUnavailable('actual offline cancelled reservation lacks exact immutable release operation')
            self.phase='source_candidate';return False
        if self.phase=='source_candidate':
            self.candidate=_registered_graph_candidate_v3(owner,owner.view.basis.prepared,meter)
            self.source_rows=[(TABLE,(*binding.namespace.as_tuple,'cancellation_gate',binding.execution_id)),(TABLE,(*binding.namespace.as_tuple,'cancellation_receipt',binding.execution_id)),
                (TABLE,(*binding.namespace.as_tuple,'accounting_prepared',offline_accounting_original_ref_v1(binding))),('runtime_budget_operations',(*binding.namespace.as_tuple,binding.reservation_operation_id,'cancel_unstarted')),
                ('graph_events',(*binding.namespace.as_tuple,binding.activity_id,self.result['event_id']))]
            self.source_index=0;self.phase='source_rows';return False
        if self.phase=='source_rows':
            if self.source_index==len(self.source_rows):self.phase='graph_receipt';return False
            table,key=self.source_rows[self.source_index]
            if self.row_hash is None:
                with owner.view.basis.read_database('graph',meter=meter) as db:shape=read_c09_table_shape_v2(db,table,meter=meter)
                self.row_hash=_BackupGraphRowCommitmentV3(owner,shape,key);return False
            if not self.row_hash.complete:
                with owner.view.basis.read_database('graph',meter=meter) as db:self.row_hash.advance(db,meter)
                return False
            if self.point is None:self.point=_RegisteredGraphPointReadV3(self.candidate,self.row_hash.shape,key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point.advance(db,meter)
            if not done:return False
            if self.point.proof[4]!=self.row_hash.commitment or self.point.proof[5]!='preserved_exact' or self.point.proof[6]!=self.row_hash.commitment:raise AuthorityUnavailable('offline cancellation original logical bytes are not retained by their actual complete Source member')
            self.row_hash=self.point=None;self.source_index+=1;return False
        if self.phase=='graph_receipt':
            from ..graph_types import GraphReceipt,NamespaceEpoch
            from ..graph_store import GraphStore
            from ..runtime.d11_types import runtime_job_key
            with owner.view.basis.read_database('graph',meter=meter) as db:row=_read_one(db,'SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*binding.namespace.as_tuple,binding.activity_id,self.result['event_id']),meter)
            if row is None:raise AuthorityUnavailable('actual offline cancellation Graph event original absent')
            receipt=GraphReceipt('committed',GraphStore._version_rows(row[0]),GraphStore._version_rows(row[1]),NamespaceEpoch(*binding.namespace.as_tuple,row[2]));versions={v.key.token:v.revision for v in receipt.revisions};job=runtime_job_key(*binding.namespace.as_tuple,binding.activity_id,binding.job_id).token
            if canonical_digest(receipt)!=self.result['graph_receipt_digest'] or versions!={v['ref']:v['revision'] for v in self.result['write_commitments']} or set(versions)!=({job} if self.result['job_disposition']=='cancelled' else set()):raise AuthorityUnavailable('actual offline cancellation Graph write set/event receipt differs')
            self.phase='historical_job' if versions else 'core_retirement';return False
        if self.phase=='historical_job':
            from dataclasses import replace
            from ..runtime.d11_types import RuntimeJobValue
            from ..runtime.d10_offline_tick_execution_v1 import _decode_json
            from ..runtime.d11_offline_originals_v1 import WORK_KIND,ALGORITHM_ID
            commitment=self.result['write_commitments'][0];key=commitment['ref'];revision=commitment['revision']
            with owner.view.basis.read_database('graph',meter=meter) as db:
                current=_read_one(db,'SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(key,revision),meter)
                previous=_read_one(db,'SELECT value,valid FROM graph_history WHERE token=? AND revision=?',(key,revision-1),meter)
            if current is None or previous is None or current[0]!=self.result['event_id'] or current[2]!=1 or previous[1]!=1 or canonical_digest(json.loads(current[1]))!=commitment['digest'] or canonical_digest(json.loads(previous[0]))!=self.result['job_observed_digest']:raise AuthorityUnavailable('actual offline historical job cancellation original absent/different')
            old=_decode_json(previous[0],RuntimeJobValue);final=_decode_json(current[1],RuntimeJobValue)
            if ((old.operation_id,old.activity_id,old.bot_id,old.persona_id,old.work_kind,old.parent_budget_lease_ref,old.resource_ref,old.fence,old.lease_holder,old.cancel_epoch,old.effect_id,old.snapshot_ref,old.deadline_utc)
                    !=(binding.operation_id,binding.activity_id,*binding.namespace.as_tuple,WORK_KIND,binding.parent_budget_lease_ref,ALGORITHM_ID,binding.job_fence,binding.job_holder,binding.job_cancel_epoch,None,'offline-tick-input:'+binding.input_digest[:48],binding.deadline_utc)
                    or old.phase not in {'running','draining'} or final!=replace(old,phase='cancelled',lease_holder=None,lease_expires_utc=None,wake_condition_digest=None,result_ref=None)):raise AuthorityUnavailable('actual offline historical job close pure contract differs')
            self.source_rows=[('graph_history',(key,revision-1)),('graph_history',(key,revision))];self.source_index=0;self.phase='job_source_rows';return False
        if self.phase=='job_source_rows':
            if self.source_index==2:self.phase='core_retirement';return False
            table,key=self.source_rows[self.source_index]
            if self.row_hash is None:
                with owner.view.basis.read_database('graph',meter=meter) as db:shape=read_c09_table_shape_v2(db,table,meter=meter)
                self.row_hash=_BackupGraphRowCommitmentV3(owner,shape,key);return False
            if not self.row_hash.complete:
                with owner.view.basis.read_database('graph',meter=meter) as db:self.row_hash.advance(db,meter)
                return False
            if self.point is None:self.point=_RegisteredGraphPointReadV3(self.candidate,self.row_hash.shape,key);return False
            with owner.view.basis.read_database('graph',meter=meter) as db:done=self.point.advance(db,meter)
            if not done:return False
            if self.point.proof[4]!=self.row_hash.commitment or self.point.proof[6]!=self.row_hash.commitment:raise AuthorityUnavailable('actual offline historical job source commitment is not retained')
            self.row_hash=self.point=None;self.source_index+=1;return False
        if self.phase=='core_retirement':
            from .v2_contract import fence_from_wire,canonical_bytes
            from . import c09_authority_storage_rebase as legacy
            raw=json.loads(self.gate.no_future_claim_original_json)
            def fence_row(permit,request,digest):return (permit.operation_id,permit.namespace,permit.subject,permit.token,permit.fence_epoch,permit.revision,'finished',canonical_bytes(permit),request,digest,None)
            if self.gate.no_future_claim_kind=='never_begun':
                receipt=fence_from_wire(raw);table='authority_v2_never_begun';columns=('operation_id','request_id','request_digest','receipt');row=(receipt.operation_id,receipt.request_id,receipt.request_digest,canonical_bytes(receipt));kind='never_begun_operation'
            else:
                permit=fence_from_wire(raw['permit']);table='authority_v2_fences';columns=('operation_id','namespace','subject','token','fence_epoch','revision','state','permit','finish_request_id','finish_request_digest','pending');row=fence_row(permit,raw['request_id'],raw['request_digest']);kind='fence'
            permit=self.gate.permit;cols=('operation_id','namespace','subject','token','fence_epoch','revision','state','permit','finish_request_id','finish_request_digest','pending');account=fence_row(permit,permit.operation_id+':finished','sha256:'+self.gate.digest)
            self.core_rows=[(kind,self.gate.claim_gate_id,legacy._row_commitment(table,columns,row)),('fence',permit.operation_id,legacy._row_commitment('authority_v2_fences',cols,account))];self.core_index=0;self.phase='core_consumed';return False
        if self.phase=='core_consumed':
            if self.core_index==2:self.binding_scan=owner.view.begin_family_consumer('binding',meter=meter);self.phase='binding_eof';return False
            from . import c09_authority_storage_rebase as legacy
            kind,item,commitment=self.core_rows[self.core_index];columns=('namespace','kind','item_id','operation_id','original_commitment','facts_pin_digest');key=(binding.authority_namespace,kind,item)
            current=owner.view.scope.scope_digest
            with owner.view.basis.read_database('core',meter=meter) as db:
                row=meter.read_fixed_row(db,'authority_c09_consumed_execution_v1',columns,'namespace=? AND kind=? AND item_id=?',key)
                if row is None or row[3:5]!=(item,commitment):raise AuthorityUnavailable('actual offline no-future/accounting Core original full commitment is not consumed')
                shape=read_c09_table_shape_v2(db,'authority_c09_consumed_execution_v1',meter=meter);target=legacy._row_commitment(shape.table,shape.columns,row)
                generated=_read_one(db,'SELECT scope_digest,role,table_name,key_digest,key_json,producer,original_digest,new_commitment FROM authority_c09_role_generated_v2 WHERE scope_digest=? AND role=? AND table_name=? AND key_digest=? AND new_commitment=?',(current,'core',shape.table,canonical_digest(key),target),meter)
                if generated is None:
                    disposition=meter.read_fixed_row(db,'authority_c09_role_rows_v2',('old_commitment','disposition','new_commitment'),'scope_digest=? AND role=? AND table_name=? AND key_digest=?',(current,'core',shape.table,canonical_digest(key)))
                    if disposition!=(target,'preserved_exact',target):raise AuthorityUnavailable('actual offline carried consumed proof lacks exact current Source disposition')
                elif generated[4]!=canonical_serialize(key) or generated[5]!='verified_recovery_identity_v2' or generated[6]!=row[5]:raise AuthorityUnavailable('actual offline consumed original generated provenance differs')
            self.core_shape=shape;self.core_key=key;self.core_target=target;self.core_generated=generated;self.phase='core_generated' if generated is not None else 'core_preserved';return False
        if self.phase=='core_generated':
            from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
            current=owner.view.scope.scope_digest;generated=self.core_generated
            with owner.view.basis.read_database('core',meter=meter) as db:
                directory=_read_one(db,'SELECT stream_json,seal_json FROM authority_c09_role_streams_v2 WHERE scope_digest=? AND role=? AND table_name=? AND stream_kind=?',(current,'core','authority_c09_role_generated_v2','generated_rows'),meter)
                if directory is None:raise AuthorityUnavailable('actual current Core generated directory stream absent')
                stream=c09_paged_value_from_wire_v2(json.loads(directory[0]),C09StreamIdentityV2);seal=c09_paged_value_from_wire_v2(json.loads(directory[1]),C09CompleteStreamV2)
                shape=read_c09_table_shape_v2(db,'authority_c09_role_generated_v2',meter=meter);key=tuple(generated[:4])
                if stream.scope_digest!=current or stream.role_source_digest!=next(role for role in owner.view.verified_roles if role.role=='core').base_header['source_original']['role_source_digest'] or stream.family!=shape.table or stream.schema_digest!=shape.schema_digest or stream.primary_key_columns!=shape.primary_key_columns:raise AuthorityUnavailable('actual offline generated member Source/layout identity differs')
                digest=canonical_digest(('sylanne3.c09.authority-directory-row.v2','generated_rows',shape.table,key,generated));_RegisteredGraphPointReadV3._member(db,stream,seal,key,digest,meter)
            self.core_generated=None;self.phase='core_target';return False
        if self.phase=='core_preserved':
            from .c09_natural_final_history_v4 import _verify_core_obligation_disposition_v4
            core_role=next(role for role in owner.view.verified_roles if role.role=='core');shape=self.core_shape;key=self.core_key;target=self.core_target
            obligation={'table':shape.table,'primary_key':key,'key_digest':canonical_digest(key),'source_row_commitment':target,'expected_target_row_commitment':target}
            with owner.view.basis.read_database('core',meter=meter) as db:_verify_core_obligation_disposition_v4(db,obligation,shape,target,owner.view.scope.scope_digest,core_role.base_header['source_original']['role_source_digest'],meter)
            self.phase='core_target';return False
        if self.phase=='core_target':
            from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
            current=owner.view.scope.scope_digest;shape=self.core_shape;key=self.core_key;target=self.core_target
            core_role=next(role for role in owner.view.verified_roles if role.role=='core')
            with owner.view.basis.read_database('core',meter=meter) as db:
                directory=_read_one(db,'SELECT stream_json,seal_json FROM authority_c09_role_streams_v2 WHERE scope_digest=? AND role=? AND table_name=? AND stream_kind=?',(current,'core',shape.table,'target_rows'),meter)
                if directory is None:raise AuthorityUnavailable('actual offline consumed current target complete stream absent')
                stream=c09_paged_value_from_wire_v2(json.loads(directory[0]),C09StreamIdentityV2);seal=c09_paged_value_from_wire_v2(json.loads(directory[1]),C09CompleteStreamV2)
                if stream.scope_digest!=current or stream.role_source_digest!=core_role.base_header['source_original']['role_source_digest'] or stream.family!=shape.table or stream.schema_digest!=shape.schema_digest or stream.primary_key_columns!=shape.primary_key_columns:raise AuthorityUnavailable('actual offline consumed target Source/layout identity differs')
                digest=canonical_digest(('sylanne3.c09.authority-target-row.v2',shape.table,key,target));_RegisteredGraphPointReadV3._member(db,stream,seal,key,digest,meter)
            self.core_shape=self.core_key=self.core_target=None;self.core_index+=1;self.phase='core_consumed';return False
        if self.phase=='binding_eof':
            with owner.view.basis.read_database('graph',meter=meter) as db:
                def observe(record,value):
                    if value.execution_id==binding.execution_id:raise AuthorityUnavailable('actually claimed offline work cannot release an unstarted reservation')
                done=self.binding_scan.advance(db,meter,observe)
            if not done:return False
            self.complete=True;return True
        raise AuthorityUnavailable('unknown actual offline cancellation history phase')

class _BackupCleanupReadV3:
    def __init__(self,token,service,view,operation,saved_original):
        if token is not _TOKEN:raise TypeError('actual installed backup coverage factory required')
        self.service=service;self.view=view;self.operation=operation;self.saved_original=saved_original;self.selection=view.basis.selection_digest
        service.control.register_c09_retained_state_v3(self)
        self.phase='schema';self.registry=None;self.backup=None;self.backup_key=None;self.observation=None;self.intent=None;self.role_index=0;self.file_hash=None
        self.after=None;self.current=None;self.pending_hash=None;self.pending_offset=0;self.pending_total=None;self.index_scope=None;self.binding_scan=None;self.binding_match=None
        self.lease=None;self.old_lease=None;self.amounts=None;self.reservation=None;self.unit_index=0;self.d11_scan=None;self.d11_match=None
        self.count=0;self.root=canonical_digest(('d12.backup-coverage.v3',self.selection));self.ledger_after=None;self.walker=None;self.certificate=None;self.generic=None;self.catalogue_family='registrations';self.catalogue_after=None;self.catalogue_count=0;self.catalogue_root=canonical_digest(('d12.backup-catalogue.v3',self.selection,'registrations'));self.catalogues={};self.old_seals_after=None;self.old_family=None;self.old_seals_count=0;self.scope_scan=None;self.scope_summary=None;self.scope_generation=0;self.backup_admission=None;self.legacy_frame=None;self.sealed_scope=None;self.sealed_families=set();self.prior_coverage=None;self.import_after=None;self.import_count=0;self.import_root=None;self.ledger_pending=None;self.execution_previous='genesis';self.genesis_graph=None;self.ledger_graph=None;self.ledger_graph_key=None;self.genesis_candidate=None;self.genesis_summary=None;self.legacy_graph_original=None;self.cancel_reader=None;self.cancel_row=None
    def _c09_retained_heap_bytes_v3(self):
        excluded={id(self.service),id(self.view),id(self.view.basis),id(self.service.control),id(self.service.journal)}
        maintenance=self.service.gate._installed_maintenance_v3
        if maintenance is not None:excluded.update((id(maintenance),id(maintenance._installed_d11_budget_job_issuer_v2),id(maintenance._installed_d02_resource_issuer_v2)))
        return _retained_heap_v3(self,set(),excluded)
    @contextmanager
    def _source(self,role,meter):
        from .linux_installation_security_v1 import opened_installed_file_v1
        before=self.backup['copies'][role]['backup_observation'];path=Path(before['resolved_path'])
        with opened_installed_file_v1(path,private=True,allowed_gid=0) as fd:
            stat=os.fstat(fd)
            if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=(before['device'],before['file_id'],before['prepared_size'],before['prepared_mtime_ns']):raise AuthorityUnavailable('actual registered backup source inode changed')
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,isolation_level=None)) as db:
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                try:yield db
                finally:db.rollback()
    def _record(self,family,key,proof,meter,*,backup_key=None):
        raw=canonical_serialize(proof);digest=canonical_digest(proof)
        columns=('selection_digest','backup_key','family','item_key','proof_json','proof_digest')
        with self.service.control._db(write=True) as db:_append(self.service.control,db,'c09_d12_backup_obligations_v3',columns,(self.selection,self.backup_key if backup_key is None else backup_key,family,str(key),raw,digest),columns[:4],meter)
    def _finish_backup(self):
        self.backup=self.intent=self.observation=None;self.backup_key=None;self.after=None;self.current=None;self.phase='registry'
    def _permit_path(self,path,meter):
        name=str(path)
        if any(name==m['resolved_path']+suffix for m in self.view.basis.manifest['members'] for suffix in ('','-wal','-shm','-journal')):return True
        with self.service.control._db() as db:
            row=_read_one(db,'SELECT before_json FROM c09_d12_backup_files_v3 WHERE selection_digest=? AND resolved_path=?',(self.selection,name),meter)
        if row is None:raise AuthorityUnavailable('unregistered actual backup bytes block destruction')
        before=json.loads(row[0]);stat=path.stat(follow_symlinks=False)
        if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=(before['device'],before['file_id'],before['prepared_size'],before['prepared_mtime_ns']):raise AuthorityUnavailable('actual registered backup filesystem identity changed')
        return True
    def _lookup_d11(self,lease,operation,unit,amount,meter,*,record=True):
        if self.d11_scan is None:self.d11_scan=self.view.begin_family_consumer('d11_facts',meter=meter);self.d11_match=None;return False
        with self.view.basis.read_database('graph',meter=meter) as db:
            def observe(record,value):
                if (value.parent_budget_id,value.idempotency_id,value.cost_unit)==(lease,operation,unit):
                    if self.d11_match is not None and self.d11_match!=value:raise AuthorityUnavailable('actual backup budget settlement ownership conflict')
                    self.d11_match=value
            done=self.d11_scan.advance(db,meter,observe)
        if not done:return False
        if self.d11_match is None or self.d11_match.actual_cost!=amount:raise AuthorityUnavailable('actual backup unknown unit lacks exact selected settlement')
        if record:self._record('model_unit',self.d11_match.settlement_id,{'settlement_id':self.d11_match.settlement_id,'value_digest':canonical_digest(self.d11_match)},meter)
        self.d11_scan=None;self.d11_match=None;return True
    def advance(self,meter):
        self.service.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=65536)
        result=self._advance(meter)
        self.service.control.require_c09_retained_arena_v3(meter=meter)
        return result
    def _advance(self,meter):
        self.view.require_current(meter=meter);service=self.service
        if self.phase=='schema':
            from .c09_surface_cleanup_v1 import _install_surface_progress_schema_v3
            with service.control._db(write=True) as db:
                _schema(service.control,db,meter,install=True);_install_surface_progress_schema_v3(service.control,db,meter)
                row=_read_one(db,'SELECT certificate_json FROM c09_d12_backup_certificates_v3 WHERE selection_digest=?',(self.selection,),meter)
            if row is not None:
                self.certificate=json.loads(row[0]);service.control.verify_original_v1(self.certificate,'coverage_digest');self.phase='recheck';self.ledger_after=None
            else:self.registry=service.journal.begin_managed_backup_scan_v3(service.inventory.namespace,meter=meter,resource_control=service.control);self.phase='registry'
            return self._progress()
        if self.phase=='registry':
            self.registry=self.registry.advance(meter);registered=self.registry.take_backup()
            if registered is None:
                if self.registry.complete:self.phase='ledger';self.ledger_after=None
                return self._progress()
            self.intent,self.observation=registered;self.backup=decode_managed_backup_v2(self.observation.body);self.backup_key=canonical_digest((self.intent.operation_id,self.observation.observation_ref))
            backup=self.backup
            if backup['installation_id']!=service.control.installation_id or backup['inventory_manifest_digest']!=service.inventory.manifest_digest:raise AuthorityUnavailable('actual registered backup installation/inventory differs')
            with service.control._db(write=True) as db:
                cols=('selection_digest','backup_key','observation_ref','observation_digest','backup_json')
                _append(service.control,db,'c09_d12_backup_registrations_v3',cols,(self.selection,self.backup_key,self.observation.observation_ref,self.observation.observation_digest,canonical_serialize(backup)),cols[:2],meter)
            self.role_index=0;self.index_scope=None;self.scope_scan=None;self.old_seals_after=None;self.old_family=None;self.old_seals_count=0;self.sealed_scope=None;self.sealed_families=set();self.prior_coverage=None;self.phase='files';return self._progress()
        if self.phase=='files':
            from .c09_durable_unlink_v2 import InstalledDurableUnlinkProgressV3
            roles=('core','deletion','execution','graph')
            if self.role_index==4:
                self.phase='ancestry'
                return self._progress()
            role=roles[self.role_index];before=self.backup['copies'][role]['backup_observation'];path=Path(before['resolved_path'])
            root=path.parent if self.backup['backup_phase']=='forward' else path.parent.parent
            if (path.name!=role+'.sqlite3' or root.name!=self.intent.operation_id or root.parent not in service._roots()
                    or self.backup['backup_phase']=='rollback' and path.parent.name!='rollback'):raise AuthorityUnavailable('actual backup path escaped accepted registered artifact')
            if not path.exists():
                with service.control._db() as db:
                    old=_read_one(db,'SELECT selection_digest,effect_json,effect_digest FROM c09_surface_file_effects_v3 WHERE resolved_path=? ORDER BY selection_digest LIMIT 1',(str(path),),meter)
                    plan=None if old is None else _read_one(db,'SELECT plan_json,plan_digest FROM c09_surface_file_plans_v3 WHERE selection_digest=? AND resolved_path=?',(old[0],str(path)),meter)
                    cert=None if old is None else _read_one(db,'SELECT certificate_json,certificate_digest FROM c09_d12_backup_certificates_v3 WHERE selection_digest=?',(old[0],),meter)
                    registration=None if old is None else _read_one(db,'SELECT observation_ref,observation_digest,backup_json FROM c09_d12_backup_registrations_v3 WHERE selection_digest=? AND backup_key=?',(old[0],self.backup_key),meter)
                    covered=None if old is None else _read_one(db,'SELECT backup_key,role,before_json FROM c09_d12_backup_files_v3 WHERE selection_digest=? AND resolved_path=?',(old[0],str(path)),meter)
                if old is None or plan is None or cert is None or registration is None or covered is None:raise AuthorityUnavailable('absent backup lacks complete actual prior coverage and destruction originals')
                effect=json.loads(old[1]);planned=json.loads(plan[0]);coverage=json.loads(cert[0])
                service.control.verify_original_v1(effect,'effect_digest');service.control.verify_original_v1(planned,'plan_digest');service.control.verify_original_v1(coverage,'coverage_digest')
                if (effect['effect_digest']!=old[2] or planned['plan_digest']!=plan[1] or coverage['coverage_digest']!=cert[1]
                        or any(x['selection_digest']!=old[0] for x in (effect,planned,coverage)) or effect['plan_digest']!=planned['plan_digest']
                        or effect['observation']!=dict(kind='removed_file',resolved_path=str(path),state='absent') or planned['before']!=before
                        or effect['resolved_path']!=str(path) or planned['resolved_path']!=str(path) or effect['operation_id']!=coverage['operation_id']
                        or planned['operation_id']!=coverage['operation_id'] or planned['manifest_digest']!=coverage['manifest_digest']
                        or registration!=(self.observation.observation_ref,self.observation.observation_digest,canonical_serialize(self.backup))
                        or covered!=(self.backup_key,role,canonical_serialize(before)) or coverage['schema']!=COVERAGE_SCHEMA
                        or self.prior_coverage is not None and coverage!=self.prior_coverage):raise AuthorityUnavailable('prior backup coverage/destruction exact signed bindings differ')
                self.prior_coverage=coverage
                with service.control._db(write=True) as db:
                    cols=('selection_digest','resolved_path','backup_key','role','before_json')
                    _append(service.control,db,'c09_d12_backup_files_v3',cols,(self.selection,str(path),self.backup_key,role,canonical_serialize(before)),cols[:2],meter)
                self.role_index+=1;return self._progress()
            if self.file_hash is None:self.file_hash=InstalledDurableUnlinkProgressV3(before);return self._progress()
            if not self.file_hash.advance(meter=meter):return self._progress()
            self.file_hash.close();self.file_hash=None
            with service.control._db(write=True) as db:
                cols=('selection_digest','resolved_path','backup_key','role','before_json')
                _append(service.control,db,'c09_d12_backup_files_v3',cols,(self.selection,str(path),self.backup_key,role,canonical_serialize(before)),cols[:2],meter)
            self.role_index+=1;return self._progress()
        if self.phase=='ancestry':
            self.backup_admission=_VerifiedBackupAdmissionV3(_TOKEN,self)
            generation=self.backup['storage_identity']['storage_generation']
            if generation:
                with self.view.basis.read_database('graph',meter=meter) as db:
                    row=_read_one(db,'SELECT manifest_digest FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND generation=?',(self.view.scope.scope_digest,generation),meter)
                if row!=(self.backup['storage_identity']['manifest_digest'],):raise AuthorityUnavailable('actual registered backup is not in selected complete historical lineage')
            if self.prior_coverage is not None:
                with self.view.basis.read_database('graph',meter=meter) as db:
                    prior=_read_one(db,'SELECT prepared_digest,manifest_digest FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND operation_id=?',(self.view.scope.scope_digest,self.prior_coverage['operation_id']),meter)
                if prior!=(self.prior_coverage['prepared_digest'],self.prior_coverage['manifest_digest']):raise AuthorityUnavailable('destroyed backup prior coverage is outside actual selected complete historical lineage')
                self.phase='import_coverage';self.import_after=None;self.import_count=0;self.import_root=canonical_digest(('d12.backup-coverage.v3',self.prior_coverage['selection_digest']))
            else:self.after=None;self.phase='historical_seals'
            return self._progress()
        if self.phase=='historical_seals':
            from ..runtime.c09_paged_capture_contract_v2 import C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2
            if self.old_family is not None:
                if self.old_family.advance(meter):self.old_family=None
                return self._progress()
            with self._source('graph',meter) as db:
                exists=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_recovery_family_seals_v2'",(),meter)
                row=None if exists is None else _read_one(db,'SELECT scope_digest,family,locator_json,locator_digest FROM c09_recovery_family_seals_v2 WHERE (scope_digest,family)>(?,?) ORDER BY scope_digest,family LIMIT 1',self.old_seals_after or ('',''),meter)
            if exists is None and self.backup['storage_identity']['storage_generation']==0:
                self.phase='genesis_graph';self.scope_scan=None;return self._progress()
            if exists is None and self.backup['storage_identity']['storage_generation']:
                self.phase='legacy_frames';self.scope_generation=0;self.scope_scan=None;return self._progress()
            if row is None:
                if self.sealed_scope is not None and self.sealed_families!={'journal',*_FAMILIES,'binding','model'}:raise AuthorityUnavailable('actual backup family seal directory omits a required EOF family')
                if self.backup['storage_identity']['storage_generation'] and self.old_seals_count==0:raise AuthorityUnavailable('actual historical backup sealed family directory is empty')
                self.phase='historical_items';self.after=None;return self._progress()
            raw=json.loads(row[2]);locator=c09_paged_value_from_wire_v2(raw,C09SealedStreamLocatorV2)
            if locator.digest!=row[3] or locator.identity.scope_digest!=row[0] or locator.identity.family!='c09_recovery:'+row[1]:raise AuthorityUnavailable('actual backup family locator original differs')
            with self.view.basis.read_database('graph',meter=meter) as db:
                qualified=_read_one(db,'SELECT generation,operation_id,prepared_digest FROM c09_recovery_history_scopes_v2 WHERE scope_digest=? AND historical_scope_digest=?',(self.view.scope.scope_digest,row[0]),meter)
            if qualified is None or qualified[0]>self.backup['storage_identity']['storage_generation']:raise AuthorityUnavailable('actual backup family has no qualified historical scope')
            if self.sealed_scope!=row[0]:
                if self.sealed_scope is not None and self.sealed_families!={'journal',*_FAMILIES,'binding','model'}:raise AuthorityUnavailable('actual backup historical scope omits a sealed family')
                self.sealed_scope=row[0];self.sealed_families=set()
            if row[1] not in {'journal',*_FAMILIES,'binding','model'} or row[1] in self.sealed_families:raise AuthorityUnavailable('actual backup duplicate/unknown sealed family')
            self.sealed_families.add(row[1]);self.old_seals_after=row[:2];self.old_seals_count+=1;self.old_family=_BackupSourceFamilyReadV3(self,locator,row[1])
            return self._progress()
        if self.phase=='genesis_graph':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
            if self.genesis_graph is not None:
                if self.genesis_graph.advance(meter):self.genesis_graph=None;self.scope_scan=None;self.phase='execution_header';self.after=0
                return self._progress()
            if self.scope_scan is None:self.scope_scan=begin_next_authenticated_prepared_reader_v2(service.control,after_generation=0,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
            summary=self.scope_scan.advance(meter=meter)
            if summary is None:return self._progress()
            self.genesis_graph=begin_registered_backup_genesis_graph_v3(self.backup_admission,self.view,summary,meter);return self._progress()
        if self.phase=='legacy_frames':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
            bound=self.backup['storage_identity']['storage_generation']
            if self.scope_generation==bound:self.phase='execution_header';self.after=0;self.scope_scan=None;return self._progress()
            if self.legacy_frame is not None:
                if self.legacy_frame.advance(meter):
                    summary=self.legacy_frame.summary;self._record('legacy_frame',str(summary['maintenance_generation']),{'generation':summary['maintenance_generation'],'operation_id':summary['operation_id'],'prepared_digest':summary['prepared_digest'],'manifest_digest':summary['new_manifest_digest']},meter)
                    self.scope_generation=summary['maintenance_generation'];self.legacy_frame=None;self.scope_scan=None
                return self._progress()
            if self.scope_scan is None:self.scope_scan=begin_next_authenticated_prepared_reader_v2(service.control,after_generation=self.scope_generation,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
            summary=self.scope_scan.advance(meter=meter)
            if summary is None:return self._progress()
            self.legacy_frame=begin_registered_backup_legacy_frame_v3(self.backup_admission,self.view,summary,meter);return self._progress()
        if self.phase=='historical_items':
            with self._source('graph',meter) as db:
                if _read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_recovery_items_v2'",(),meter) is None:
                    if self.backup['storage_identity']['storage_generation']:raise AuthorityUnavailable('historical backup lacks actual versioned recovery item source')
                    self.phase='execution_header';self.after=0;return self._progress()
                row=_read_one(db,'SELECT scope_digest,family,item_key,value_json,value_digest FROM c09_recovery_items_v2 WHERE (scope_digest,family,item_key)>(?,?,?) ORDER BY scope_digest,family,item_key LIMIT 1',self.after or ('','',''),meter)
            if row is None:self.phase='execution_header';self.after=0;return self._progress()
            with self._source('graph',meter) as db:
                seal=_read_one(db,'SELECT locator_json FROM c09_recovery_family_seals_v2 WHERE scope_digest=? AND family=?',row[:2],meter)
            if seal is None:raise AuthorityUnavailable('actual backup historical item has no sealed family original')
            value=_decode_fact(row[1],row[3]);current=self.view.lookup(row[1],row[2],meter=meter)
            if canonical_digest(value)!=row[4] or current!=value:raise AuthorityUnavailable('actual backup redacted historical prefix is not retained by selected typed facts')
            self._record('historical_item',canonical_digest(row[:3]),{'family':row[1],'item_key':row[2],'value_digest':row[4]},meter);self.after=row[:3];return self._progress()
        if self.phase=='execution_header':
            with self._source('execution',meter) as db:
                namespace=_read_one(db,'SELECT value FROM authority_v2_execution_meta WHERE key=?',('namespace',),meter)
                journal=_read_one(db,'SELECT value FROM authority_v2_execution_meta WHERE key=?',('journal_id',),meter)
            if namespace!=(service.inventory.namespace,) or journal!=(self.backup['current_anchor']['execution_journal_id'],):raise AuthorityUnavailable('actual registered backup execution namespace/journal header differs')
            self.execution_previous='genesis';self.after=0;self.phase='execution';return self._progress()
        if self.phase=='execution':
            with self._source('execution',meter) as db:
                row=_read_one(db,'SELECT seq,mutation_id,request_digest,append_id,previous_digest,chain_digest FROM authority_v2_execution_entries WHERE seq>? ORDER BY seq LIMIT 1',(self.after,),meter)
            if row is None:
                anchor=self.backup['current_anchor']
                if (self.after,self.execution_previous)!=(anchor['execution_seq'],anchor['execution_digest']):raise AuthorityUnavailable('actual backup execution full EOF differs from its registered head')
                self.phase='models';self.after='';return self._progress()
            if row[0]!=self.after+1 or row[4]!=self.execution_previous:raise AuthorityUnavailable('actual backup journal sequence/previous chain is discontinuous')
            self.current=row;self.pending_hash=sha256();self.pending_offset=0;self.pending_total=None;self.phase='execution_bytes';return self._progress()
        if self.phase=='execution_bytes':
            with self._source('execution',meter) as db:
                amount=0 if self.pending_total is None else min(8192,self.pending_total-self.pending_offset)
                raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table='authority_v2_execution_entries',column='pending',where='seq=?',parameters=(self.current[0],),start=self.pending_offset,length=amount,meter=meter)
            if kind!='blob' or self.pending_total is not None and total!=self.pending_total:raise AuthorityUnavailable('actual backup execution pending original changed')
            self.pending_total=total;self.pending_hash.update(raw);self.pending_offset+=len(raw)
            if self.pending_offset==total:
                self.current=(*self.current,canonical_digest((*self.current,self.pending_hash.hexdigest())))
                self.binding_scan=None;self.binding_match=None;self.phase='execution_scope'
            return self._progress()
        if self.phase=='execution_scope':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2,C09VerifiedPagedPreparedSummaryV2
            if self.index_scope is not None:
                with self.view.basis.read_database('graph',meter=meter) as db:
                    index=_read_one(db,'SELECT execution_id,row_commitment,mutation_id,chain_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq=?',(self.index_scope,self.current[0]),meter)
                if index is not None:
                    binding=self.view.lookup_execution_binding(index[0],meter=meter)
                    if index[1:]!=(self.current[-1],self.current[1],self.current[5]) or binding is None or binding.originating_journal_id!=self.backup['current_anchor']['execution_journal_id'] or self.current[-1] not in binding.source_row_commitments:raise AuthorityUnavailable('actual backup scope/seq journal projection differs')
                    self.binding_match=binding;self.phase='execution_covered';return self._progress()
                self.phase='execution_binding';return self._progress()
            target=self.backup['storage_identity']['storage_generation']+1
            if target==self.view.scope.maintenance_generation:
                if self.view.completion.old_journal_id!=self.backup['current_anchor']['execution_journal_id']:raise AuthorityUnavailable('actual backup journal does not belong to its next captured generation')
                self.index_scope=self.view.scope.scope_digest;return self._progress()
            if self.scope_scan is None:self.scope_scan=begin_next_authenticated_prepared_reader_v2(service.control,after_generation=target-1,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
            summary=self.scope_scan.advance(meter=meter)
            if summary is None:return self._progress()
            if not isinstance(summary,C09VerifiedPagedPreparedSummaryV2):self.phase='execution_binding';return self._progress()
            from .c09_prepared_storage_v3 import _read_original
            from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
            with service.control._db() as db:
                completion=_read_original(service.control,db,summary['operation_id'],'capture_facts_complete_v2',summary['facts_complete_original_digest'],meter)
                scope=C09CaptureScopeV2(**_read_original(service.control,db,summary['operation_id'],'capture_scope_v2',None,meter))
            if completion['old_journal_id']!=self.backup['current_anchor']['execution_journal_id'] or scope.maintenance_generation!=target:raise AuthorityUnavailable('actual backup journal historical scope/anchor differs')
            self.index_scope=scope.scope_digest;self.scope_scan=None;return self._progress()
        if self.phase=='execution_binding':
            if self.binding_scan is None:self.binding_scan=self.view.begin_family_consumer('binding',meter=meter);return self._progress()
            with self.view.basis.read_database('graph',meter=meter) as db:
                def observe(record,value):
                    if self.current[-1] in value.source_row_commitments:
                        if self.binding_match is not None and self.binding_match!=value:raise AuthorityUnavailable('ambiguous actual backup execution row ownership')
                        self.binding_match=value
                done=self.binding_scan.advance(db,meter,observe)
            if not done:return self._progress()
            self.phase='execution_covered';return self._progress()
        if self.phase=='execution_covered':
            binding=self.binding_match
            if binding is None or binding.originating_journal_id!=self.backup['current_anchor']['execution_journal_id']:raise AuthorityUnavailable('actual backup execution row lacks selected typed recovery coverage')
            actual=self.view.read_sanitized_execution_v3(namespace=service.inventory.namespace,execution_id=binding.execution_id,meter=meter)
            if actual is None or actual.input_commitment!=binding.input_commitment:raise AuthorityUnavailable('actual registered backup execution cannot independently recover')
            self._record('execution',str(self.current[0]),{'execution_id':binding.execution_id,'source_row_commitment':self.current[-1],'read_digest':_execution_semantic_digest_v3(actual)},meter)
            self.after=self.current[0];self.execution_previous=self.current[5];self.current=None;self.binding_scan=None;self.binding_match=None;self.phase='execution';return self._progress()
        if self.phase=='models':
            with self._source('core',meter) as db:
                exists=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'",(),meter)
                row=None if exists is None else _read_one(db,'SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? AND call_id>? ORDER BY call_id LIMIT 1',(service.inventory.namespace,self.after),meter)
                if row is not None:
                    from .c09_model_budget_original_v1 import read_model_audit_metadata_v1
                    prior=read_model_audit_metadata_v1(_BoundedReadConnectionV2(db,meter),row[0])
            if row is None:self.phase='leases';self.after='';return self._progress()
            original=self.view.lookup_model_original(row[0],meter=meter);fact=self.view.lookup_execution(row[0],meter=meter);binding=self.view.lookup_execution_binding(row[0],meter=meter)
            if original is None or fact is None or binding is None or fact.signature_commitment!=original.original_digest or original.original_digest not in binding.source_row_commitments:raise AuthorityUnavailable('actual model backup lacks selected pinned per-unit original')
            intent=prior.intent
            if ((original.model_operation_id,original.request_digest,original.binding_digest,original.parent_budget_id,original.reservation_operation_id,original.reservation_digest,original.provider_id,original.dispatch_generation)
                    !=(intent.operation_id,intent.request_digest,intent.binding_digest,intent.budget_lease_id,intent.budget_reservation_operation_id,intent.budget_reservation_digest,intent.provider_id,intent.authority_activation_generation)
                    or dict(intent.budget_ceiling)!={u.unit:u.ceiling for u in original.units}
                    or prior.state=='observed' and original.observation_digest_or_none!=prior.observation_digest):raise AuthorityUnavailable('actual model backup input/known terminal identity changed')
            self.current=original;self.unit_index=0;self.phase='model_units';return self._progress()
        if self.phase=='model_units':
            original=self.current
            if self.unit_index==len(original.units):
                self._record('model',original.call_id,{'call_id':original.call_id,'original_digest':original.original_digest},meter);self.after=original.call_id;self.current=None;self.phase='models';return self._progress()
            unit=original.units[self.unit_index]
            if unit.actual_or_none is not None:
                from .c09_model_budget_original_v1 import model_unit_fact_v4
                expected=model_unit_fact_v4(original,unit)
                if self.view.lookup_d11(expected.settlement_id,meter=meter)!=expected:raise AuthorityUnavailable('actual backup model unit is not exactly retained')
            elif original.provider_state=='observed' or self.view.lookup_unknown(original.call_id,meter=meter) is None:raise AuthorityUnavailable('actual backup unresolved model unit lost its selected unknown footprint')
            if unit.actual_or_none is not None:self._record('model_unit',canonical_digest((original.call_id,unit.unit)),{'settlement_id':expected.settlement_id,'value_digest':canonical_digest(expected)},meter)
            else:
                unknown=self.view.lookup_unknown(original.call_id,meter=meter)
                self._record('unknown',original.call_id,{'execution_id':original.call_id,'value_digest':canonical_digest(unknown)},meter)
            self.unit_index+=1;return self._progress()
        if self.phase=='leases':
            from ..runtime.budget import get_budget_lease
            namespace=NamespaceId(**self.backup['reconciliation']['namespace'])
            with self._source('graph',meter) as db:
                exists=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_budget_leases'",(),meter)
                row=None if exists is None else _read_one(db,'SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=? AND lease_id>? ORDER BY lease_id LIMIT 1',(*namespace.as_tuple,self.after),meter)
                prior=None if row is None else get_budget_lease(_BoundedReadConnectionV2(db,meter),row[0])
            if row is None:self._finish_backup();return self._progress()
            with self.view.basis.read_database('graph',meter=meter) as db:now=get_budget_lease(_BoundedReadConnectionV2(db,meter),row[0])
            if ((now.bot_id,now.persona_id,now.parent_id,now.currency)!=(prior.bot_id,prior.persona_id,prior.parent_id,prior.currency)
                    or now.version<prior.version or any(now.used.get(u,0)<v for u,v in prior.used.items())):raise AuthorityUnavailable('actual backup budget identity/spent dimensions lost')
            self.lease=now;self.old_lease=prior;self.amounts={'reserved':{},'unknown':{},'used':{}};self.current=None;self.reservation=None;self.phase='current_reservations';return self._progress()
        if self.phase=='current_reservations':
            with self.view.basis.read_database('graph',meter=meter) as db:
                row=_read_one(db,'SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id>? ORDER BY operation_id LIMIT 1',(self.lease.lease_id,self.current or ''),meter)
            if row is None:
                if any(observed.get(u,0)<v for observed,lower in ((self.lease.reserved,self.amounts['reserved']),(self.lease.unconfirmed,self.amounts['unknown']),(self.lease.used,self.amounts['used'])) for u,v in lower.items()):raise AuthorityUnavailable('actual current aggregate lost per-unit budget obligation')
                self._record('lease',self.lease.lease_id,{'lease_id':self.lease.lease_id,'current_digest':canonical_digest(self.lease),'lease':asdict(self.lease)},meter);self.current=None;self.phase='old_reservations';return self._progress()
            ceiling=json.loads(row[2]);actual=None if row[4] is None else json.loads(row[4]);state=row[3]
            if state=='cancelled_unstarted':
                if actual is not None:raise AuthorityUnavailable('unstarted cancellation cannot fabricate measured CPU')
                self.cancel_row=row;self.cancel_reader=_RegisteredOfflineCancelledReservationReadV3(self,self.lease.lease_id,row[0]);self.phase='current_cancelled';return self._progress()
            if state in {'reserved','unknown'}:
                if actual is not None:raise AuthorityUnavailable('unobserved backup budget has fabricated actual')
                target='reserved' if state=='reserved' else 'unknown';amounts=ceiling
            elif state in {'partial_unknown','partial_overrun'}:
                if actual is None:raise AuthorityUnavailable('actual partial backup budget lost measured dimensions')
                target='unknown';amounts={u:v for u,v in ceiling.items() if u not in actual}
                for u,v in actual.items():self.amounts['used'][u]=self.amounts['used'].get(u,0)+v
            elif state in {'settled','overrun'}:
                if actual is None:raise AuthorityUnavailable('actual settled backup budget lost actual vector')
                target='used';amounts=actual
            else:raise AuthorityUnavailable('unsupported actual backup reservation state')
            for u,v in amounts.items():
                if type(v) is not int or v<0:raise AuthorityUnavailable('invalid actual budget obligation amount')
                self.amounts[target][u]=self.amounts[target].get(u,0)+v
            self.current=row[0];return self._progress()
        if self.phase=='current_cancelled':
            if not self.cancel_reader.advance(meter):return self._progress()
            gate=self.cancel_reader.gate
            self._record('offline_cancelled',canonical_digest((self.lease.lease_id,self.cancel_row[0])),{'lease_id':self.lease.lease_id,'operation_id':self.cancel_row[0],'original_digests':self.cancel_reader.original_digests,'execution_id':gate.binding.execution_id,'no_future_claim_digest':gate.no_future_claim_digest},meter)
            self.current=self.cancel_row[0];self.cancel_reader=self.cancel_row=None;self.phase='current_reservations';return self._progress()
        if self.phase=='old_reservations':
            with self._source('graph',meter) as db:old=_read_one(db,'SELECT operation_id,digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id>? ORDER BY operation_id LIMIT 1',(self.lease.lease_id,self.current or ''),meter)
            if old is None:self.current=None;self.phase='receipts';return self._progress()
            with self.view.basis.read_database('graph',meter=meter) as db:now=meter.read_fixed_row(db,'runtime_budget_reservations',('operation_id','digest','ceiling_json','state','actual_json'),'lease_id=? AND operation_id=?',(self.lease.lease_id,old[0]))
            before=None if old[4] is None else json.loads(old[4]);after=None if now is None or now[4] is None else json.loads(now[4])
            if now is None or tuple(now[:3])!=old[:3] or before is not None and (after is None or any(after.get(u)!=v for u,v in before.items())):raise AuthorityUnavailable('actual backup reservation identity/measured dimensions changed')
            self.reservation=(old,tuple(now));self.unit_index=0;self.phase='reservation_units';return self._progress()
        if self.phase=='reservation_units':
            old,now=self.reservation;after=None if now[4] is None else json.loads(now[4])
            units=tuple(sorted(after or {})) if old[3] in {'unknown','partial_unknown','partial_overrun'} and now!=old else ()
            if old[3] in {'unknown','partial_unknown','partial_overrun'} and now!=old and after is None:raise AuthorityUnavailable('unknown backup reservation lost occupancy without actual settlement')
            if self.unit_index<len(units):
                unit=units[self.unit_index]
                if self._lookup_d11(self.lease.lease_id,old[0],unit,after[unit],meter):self.unit_index+=1
                return self._progress()
            self._record('reservation',canonical_digest((self.lease.lease_id,old[0])),{'lease_id':self.lease.lease_id,'operation_id':old[0],'current_digest':canonical_digest(now),'reservation':now},meter)
            self.current=old[0];self.reservation=None;self.phase='old_reservations';return self._progress()
        if self.phase=='receipts':
            from ..runtime.budget import BudgetReceipt
            namespace=NamespaceId(**self.backup['reconciliation']['namespace'])
            with self._source('graph',meter) as db:
                from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
                shape=read_c09_table_shape_v2(db,'runtime_budget_operations',meter=meter)
                row=_read_one(db,'SELECT '+','.join(shape.columns)+' FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND lease_id=? AND (operation_id,phase)>(?,?) ORDER BY operation_id,phase LIMIT 1',(*namespace.as_tuple,self.lease.lease_id,*(self.current or ('',''))),meter)
            if row is None:self.after=self.lease.lease_id;self.lease=self.old_lease=None;self.amounts=None;self.current=None;self.phase='leases';return self._progress()
            with self.view.basis.read_database('graph',meter=meter) as db:actual=meter.read_fixed_row(db,shape.table,shape.columns,'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',row[:4])
            if tuple(actual or ())!=row:raise AuthorityUnavailable('actual immutable registered backup budget receipt absent/changed')
            receipt=BudgetReceipt(**json.loads(row[6]))
            if (receipt.operation_id,receipt.digest,receipt.lease_id)!=(row[2],row[4],row[5]):raise AuthorityUnavailable('actual backup immutable budget receipt identity differs')
            self._record('receipt',canonical_digest(row[:4]),{'key':row[:4],'row_digest':canonical_digest(row)},meter);self.current=row[2:4];return self._progress()
        if self.phase in {'ledger','recheck','import_coverage'}:return self._advance_ledger(meter)
        if self.phase=='catalogue':
            family=self.catalogue_family
            with service.control._db() as db:
                if family=='registrations':row=_read_one(db,'SELECT backup_key,observation_ref,observation_digest,backup_json FROM c09_d12_backup_registrations_v3 WHERE selection_digest=? AND backup_key>? ORDER BY backup_key LIMIT 1',(self.selection,self.catalogue_after or ''),meter)
                else:row=_read_one(db,'SELECT resolved_path,backup_key,role,before_json FROM c09_d12_backup_files_v3 WHERE selection_digest=? AND resolved_path>? ORDER BY resolved_path LIMIT 1',(self.selection,self.catalogue_after or ''),meter)
            if row is not None:
                self.catalogue_count+=1;self.catalogue_root=canonical_digest(('d12.backup-catalogue-row.v3',self.catalogue_root,self.catalogue_count,tuple(row)));self.catalogue_after=row[0];return self._progress()
            self.catalogues[family]={'record_count':self.catalogue_count,'record_root':self.catalogue_root}
            if family=='registrations':
                self.catalogue_family='files';self.catalogue_after=None;self.catalogue_count=0;self.catalogue_root=canonical_digest(('d12.backup-catalogue.v3',self.selection,'files'))
            else:self.phase='certificate' if self.certificate is not None else 'filesystem'
            return self._progress()
        if self.phase=='filesystem':
            from .c09_surface_cleanup_v1 import InstalledManagedDirectoryReadV3
            if self.walker is None:self.walker=InstalledManagedDirectoryReadV3(service.control,self.view,surface=service.surface,roots=service._roots(),protected=self._permit_path)
            elif self.walker.advance(meter):self.phase='certificate'
            return self._progress()
        if self.phase=='certificate':
            from .c09_selected_history_v3 import record_selected_history_checkpoint_v3
            details={'schema':COVERAGE_SCHEMA,'selection_digest':self.selection,'operation_id':self.operation,'manifest_digest':self.view.basis.manifest['manifest_digest'],
                'installation_id':service.control.installation_id,'namespace':service.inventory.namespace,'inventory_manifest_digest':service.inventory.manifest_digest,'maintenance_generation':self.view.scope.maintenance_generation,'history_root':self.view.history_root,'history_count':self.view.history_count,'prepared_digest':self.view.basis.prepared['prepared_digest'],'obligation_count':self.count,'obligation_root':self.root,'catalogues':self.catalogues,
                'registry_count':self.registry.count if self.registry is not None else self.certificate['registry_count'],
                'registry_root':self.registry.root if self.registry is not None else self.certificate['registry_root'],
                'directory_count':self.walker.directory_count if self.walker is not None else self.certificate['directory_count'],
                'directory_root':self.walker.directory_root if self.walker is not None else self.certificate['directory_root']}
            if self.certificate is None:
                original=service.control.sign_original_v1(COVERAGE_SCHEMA,details,'coverage_digest')
                with service.control._db(write=True) as db:meter.write_row(db,'c09_d12_backup_certificates_v3',('selection_digest','certificate_json','certificate_digest'),(self.selection,canonical_serialize(original),original['coverage_digest']))
                self.certificate=original
            elif any(self.certificate[k]!=v for k,v in details.items()):raise AuthorityUnavailable('actual backup restored coverage complete EOF differs')
            record_selected_history_checkpoint_v3(self.view.basis,consumer='backup_recheck' if self.saved_original is not None else 'backup_coverage',details={'coverage_digest':self.certificate['coverage_digest'],'obligation_count':self.count,'obligation_root':self.root},meter=meter)
            service._backup_proof_v3=VerifiedD12BackupCoverageV3(_TOKEN,self,self.certificate);self.phase='dispose';return self._progress()
        if self.phase=='dispose':
            from .c09_surface_cleanup_v1 import InstalledC09SurfaceProgressV3
            service._backup_proof_v3.require_current(meter=meter)
            if self.generic is None:self.generic=InstalledC09SurfaceProgressV3(service,self.view,self.operation,saved_original=self.saved_original)
            return self.generic.advance(meter)
        raise AuthorityUnavailable('unknown actual managed backup coverage phase')
    def _advance_ledger(self,meter):
        imported=self.phase=='import_coverage';selection=self.prior_coverage['selection_digest'] if imported else self.selection
        after=self.import_after if imported else self.ledger_after
        with self.service.control._db() as db:
            row=_read_one(db,'SELECT backup_key,family,item_key,proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND (backup_key,family,item_key)>(?,?,?) ORDER BY backup_key,family,item_key LIMIT 1',(selection,*(after or ('','',''))),meter)
        if row is None:
            if imported:
                if (self.import_count,self.import_root)!=(self.prior_coverage['obligation_count'],self.prior_coverage['obligation_root']):raise AuthorityUnavailable('prior signed backup coverage ledger full EOF differs')
                self._finish_backup()
            else:self.phase='catalogue'
            return self._progress()
        proof=json.loads(row[3])
        if canonical_digest(proof)!=row[4]:raise AuthorityUnavailable('actual backup coverage protected obligation changed')
        family=row[1]
        if family=='budget_source_row':
            if proof['table'] not in _BUDGET_SOURCE_TABLES_V3 or proof['coverage_family'] not in {'lease','reservation','receipt'}:raise AuthorityUnavailable('unknown independent backup budget source contract')
            legacy_source=proof.get('legacy_source')
            if legacy_source is not None:
                from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2,C09VerifiedLegacyPreparedSummaryV2
                original=self.legacy_graph_original
                if original is None or original.backup_key!=row[0] or original.original_digest!=legacy_source['original_digest']:
                    if self.ledger_graph_key is None:self.ledger_graph_key=row[:3];self.ledger_graph=begin_next_authenticated_prepared_reader_v2(self.service.control,after_generation=0,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
                    if self.ledger_graph_key!=row[:3]:raise AuthorityUnavailable('actual V1 budget Source continuation changed')
                    if type(self.ledger_graph) is not _RegisteredBackupLegacyGraphCandidateReadV3:
                        summary=self.ledger_graph.advance(meter=meter)
                        if summary is None:return self._progress()
                        if type(summary) is not C09VerifiedLegacyPreparedSummaryV2 or summary['maintenance_generation']!=1:raise AuthorityUnavailable('actual V1 budget Source needs its authenticated first PREPARED')
                        self.ledger_graph=_RegisteredBackupLegacyGraphCandidateReadV3(self,summary,backup_key=row[0]);return self._progress()
                    if not self.ledger_graph.advance(meter):return self._progress()
                    if (self.ledger_graph.original_digest,self.ledger_graph.candidate_digest)!=(legacy_source['original_digest'],legacy_source['candidate_digest']):raise AuthorityUnavailable('actual V1 budget Source signature changed')
                    self.legacy_graph_original=self.ledger_graph;self.ledger_graph=None;self.ledger_graph_key=None
                index='1:'+str(legacy_source['table_index']).zfill(10)+':'+canonical_digest((proof['table'],tuple(proof['primary_key'])))
                with self.service.control._db() as db:member=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(self.selection,row[0],'legacy_graph_source_member',index),meter)
                if member is None or canonical_digest(json.loads(member[0]))!=member[1] or json.loads(member[0])['row']['old_commitment']!=proof['source_commitment']:raise AuthorityUnavailable('actual V1 budget Source full member commitment changed')
            with self.service.control._db() as db:covered=_read_one(db,'SELECT proof_json,proof_digest FROM c09_d12_backup_obligations_v3 WHERE selection_digest=? AND backup_key=? AND family=? AND item_key=?',(selection,row[0],proof['coverage_family'],proof['coverage_key']),meter)
            if covered is None or canonical_digest(json.loads(covered[0]))!=covered[1]:raise AuthorityUnavailable('actual backup budget raw Source EOF row lost its specific independent coverage obligation')
        elif family=='legacy_genesis_graph_eof':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2,C09VerifiedLegacyPreparedSummaryV2
            if self.ledger_graph_key is None:self.ledger_graph_key=row[:3];self.ledger_graph=begin_next_authenticated_prepared_reader_v2(self.service.control,after_generation=0,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
            if self.ledger_graph_key!=row[:3]:raise AuthorityUnavailable('actual V1 complete Source continuation changed')
            if type(self.ledger_graph) is not _RegisteredBackupLegacyGraphCandidateReadV3:
                summary=self.ledger_graph.advance(meter=meter)
                if summary is None:return self._progress()
                if type(summary) is not C09VerifiedLegacyPreparedSummaryV2 or (summary['maintenance_generation'],summary['operation_id'],summary['prepared_digest'])!=(proof['generation'],proof['operation_id'],proof['prepared_digest']):raise AuthorityUnavailable('actual V1 first Source PREPARED changed')
                self.ledger_graph=_RegisteredBackupLegacyGraphCandidateReadV3(self,summary,backup_key=row[0]);return self._progress()
            if not self.ledger_graph.advance(meter):return self._progress()
            if (self.ledger_graph.original_digest,self.ledger_graph.candidate_digest)!=(proof['original_digest'],proof['candidate_digest']):raise AuthorityUnavailable('actual V1 signed Source complete digest changed')
            self.legacy_graph_original=self.ledger_graph;self.ledger_graph=None;self.ledger_graph_key=None
        elif family=='legacy_genesis_graph_row':
            if self.ledger_graph_key is None:self.ledger_graph_key=row[:3];self.ledger_graph=_RegisteredBackupLegacyGraphRowRecheckV3(self,proof,row[0]);return self._progress()
            if self.ledger_graph_key!=row[:3] or type(self.ledger_graph) is not _RegisteredBackupLegacyGraphRowRecheckV3:raise AuthorityUnavailable('actual V1 Source row continuation changed')
            if not self.ledger_graph.advance(meter):return self._progress()
            self.ledger_graph=None;self.ledger_graph_key=None
        elif family in {'legacy_graph_source_member','legacy_graph_source_table'}:
            if self.legacy_graph_original is None or self.legacy_graph_original.backup_key!=row[0]:raise AuthorityUnavailable('actual V1 source index lacks completed byte signature/typed manifest EOF')
            if family=='legacy_graph_source_member':
                from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV1
                GraphRowDispositionV1(**proof['row'])
        elif family=='genesis_graph_eof':
            from .c09_paged_recovery_facts_v2 import begin_next_authenticated_prepared_reader_v2
            key=row[:3]
            if self.ledger_graph_key is None:self.ledger_graph_key=key;self.ledger_graph=begin_next_authenticated_prepared_reader_v2(self.service.control,after_generation=0,through_generation=self.view.scope.maintenance_generation,meter=meter);return self._progress()
            if self.ledger_graph_key!=key:raise AuthorityUnavailable('actual backup Graph EOF continuation changed')
            if type(self.ledger_graph) is not _RegisteredBackupGenesisGraphReadV3:
                summary=self.ledger_graph.advance(meter=meter)
                if summary is None:return self._progress()
                candidate=_registered_graph_candidate_v3(self,summary,meter)
                if (summary['maintenance_generation'],summary['operation_id'],summary['prepared_digest'],candidate.digest,candidate.source.role_source_digest)!=(proof['generation'],proof['operation_id'],proof['prepared_digest'],proof['candidate_digest'],proof['source_digest']):raise AuthorityUnavailable('actual backup genesis Source complete original changed')
                self.genesis_candidate=candidate;self.genesis_summary=summary;self.ledger_graph=_RegisteredBackupGenesisGraphReadV3(_TOKEN,self,summary,candidate,directory_only=True);return self._progress()
            if not self.ledger_graph.advance(meter):return self._progress()
            self.ledger_graph=None;self.ledger_graph_key=None
        elif family=='genesis_graph_row':
            if self.ledger_graph_key is None:self.ledger_graph_key=row[:3];self.ledger_graph=_RegisteredBackupGraphRowRecheckV3(self,proof);return self._progress()
            if self.ledger_graph_key!=row[:3] or type(self.ledger_graph) is not _RegisteredBackupGraphRowRecheckV3:raise AuthorityUnavailable('actual backup Graph row continuation changed')
            if not self.ledger_graph.advance(meter):return self._progress()
            self.ledger_graph=None;self.ledger_graph_key=None
        elif family=='execution':
            actual=self.view.read_sanitized_execution_v3(namespace=self.service.inventory.namespace,execution_id=proof['execution_id'],meter=meter)
            if actual is None or _execution_semantic_digest_v3(actual)!=proof['read_digest']:raise AuthorityUnavailable('actual backup retained execution obligation changed')
        elif family=='model':
            actual=self.view.lookup_model_original(proof['call_id'],meter=meter)
            if actual is None or actual.original_digest!=proof['original_digest']:raise AuthorityUnavailable('actual backup retained model obligation changed')
        elif family=='journal_member':
            actual=self.view.lookup_execution_binding(proof['execution_id'],meter=meter)
            if actual is None or proof['source_row_commitment'] not in actual.source_row_commitments:raise AuthorityUnavailable('actual backup retained historical journal member changed')
        elif family=='legacy_frame':
            with self.view.basis.read_database('graph',meter=meter) as db:
                actual=_read_one(db,'SELECT operation_id,prepared_digest,manifest_digest FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND generation=?',(self.view.scope.scope_digest,proof['generation']),meter)
            if actual!=(proof['operation_id'],proof['prepared_digest'],proof['manifest_digest']):raise AuthorityUnavailable('actual retained legacy backup frame membership changed')
        elif family=='model_unit':
            if canonical_digest(self.view.lookup_d11(proof['settlement_id'],meter=meter))!=proof['value_digest']:raise AuthorityUnavailable('actual backup measured model unit changed')
        elif family=='unknown':
            if canonical_digest(self.view.lookup_unknown(proof['execution_id'],meter=meter))!=proof['value_digest']:raise AuthorityUnavailable('actual backup unknown source footprint changed')
        elif family=='historical_item':
            if canonical_digest(self.view.lookup(proof['family'],proof['item_key'],meter=meter))!=proof['value_digest']:raise AuthorityUnavailable('actual backup retained redacted prefix changed')
        elif family=='offline_cancelled':
            if self.ledger_graph_key is None:self.ledger_graph_key=row[:3];self.cancel_reader=_RegisteredOfflineCancelledReservationReadV3(self,proof['lease_id'],proof['operation_id']);return self._progress()
            if self.ledger_graph_key!=row[:3]:raise AuthorityUnavailable('actual offline cancellation history continuation changed')
            if not self.cancel_reader.advance(meter):return self._progress()
            if self.cancel_reader.original_digests!=proof['original_digests'] or self.cancel_reader.gate.binding.execution_id!=proof['execution_id'] or self.cancel_reader.gate.no_future_claim_digest!=proof['no_future_claim_digest']:raise AuthorityUnavailable('actual offline cancellation signed source/retirement originals changed')
            self.ledger_graph_key=None;self.cancel_reader=None
        elif family=='lease':
            from ..runtime.budget import get_budget_lease
            with self.view.basis.read_database('graph',meter=meter) as db:actual=get_budget_lease(_BoundedReadConnectionV2(db,meter),proof['lease_id'])
            if canonical_digest(actual)!=proof['current_digest']:
                prior=proof.get('lease')
                if (prior is None or (actual.bot_id,actual.persona_id,actual.parent_id,actual.currency)!=(prior['bot_id'],prior['persona_id'],prior['parent_id'],prior['currency'])
                        or actual.version<prior['version'] or any(actual.used.get(u,0)<v for u,v in prior['used'].items())):raise AuthorityUnavailable('actual backup retained budget lease identity/spent dimensions changed')
                proof=dict(proof,current_digest=canonical_digest(actual),lease=asdict(actual))
        elif family=='reservation':
            with self.view.basis.read_database('graph',meter=meter) as db:actual=meter.read_fixed_row(db,'runtime_budget_reservations',('operation_id','digest','ceiling_json','state','actual_json'),'lease_id=? AND operation_id=?',(proof['lease_id'],proof['operation_id']))
            if canonical_digest(tuple(actual or ()))!=proof['current_digest']:
                prior=proof.get('reservation');actual=tuple(actual or ())
                if prior is None or len(actual)!=5 or tuple(prior[:3])!=actual[:3]:raise AuthorityUnavailable('actual backup retained reservation identity changed')
                before=None if prior[4] is None else json.loads(prior[4]);now=None if actual[4] is None else json.loads(actual[4])
                if before is not None and (now is None or any(now.get(u)!=v for u,v in before.items())):raise AuthorityUnavailable('actual backup retained reservation measured dimension changed')
                units=tuple(sorted(now or {})) if prior[3] in {'unknown','partial_unknown','partial_overrun'} else ()
                if prior[3] in {'unknown','partial_unknown','partial_overrun'} and now is None:raise AuthorityUnavailable('actual unknown backup reservation lost held occupancy')
                if self.ledger_pending is None:self.ledger_pending=(row[:3],0)
                key,index=self.ledger_pending
                if key!=row[:3]:raise AuthorityUnavailable('actual backup ledger unit continuation changed')
                if index<len(units):
                    unit=units[index]
                    if self._lookup_d11(proof['lease_id'],proof['operation_id'],unit,now[unit],meter,record=imported and row[0]==self.backup_key):self.ledger_pending=(key,index+1)
                    return self._progress()
                self.ledger_pending=None;proof=dict(proof,current_digest=canonical_digest(actual),reservation=actual)
        elif family=='receipt':
            from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
            with self.view.basis.read_database('graph',meter=meter) as db:
                shape=read_c09_table_shape_v2(db,'runtime_budget_operations',meter=meter);actual=meter.read_fixed_row(db,shape.table,shape.columns,'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',tuple(proof['key']))
            if canonical_digest(tuple(actual or ()))!=proof['row_digest']:raise AuthorityUnavailable('actual backup immutable receipt changed')
        else:raise AuthorityUnavailable('unknown actual registered backup obligation family')
        if imported:
            self.import_count+=1;self.import_root=canonical_digest(('d12.backup-coverage-row.v3',self.import_root,self.import_count,*row[:3],row[4]));self.import_after=row[:3]
            if row[0]==self.backup_key:self._record(family,row[2],proof,meter)
        else:
            self.count+=1;self.root=canonical_digest(('d12.backup-coverage-row.v3',self.root,self.count,*row[:3],row[4]));self.ledger_after=row[:3]
        return self._progress()
    def _progress(self):return {'status':'progress','phase':'backup_'+self.phase,'surface':self.service.surface}
