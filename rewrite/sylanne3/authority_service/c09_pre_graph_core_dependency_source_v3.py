"""Authenticated read-only Core dependency Source before Graph construction."""
from __future__ import annotations

from contextlib import contextmanager, closing
from copy import copy
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from time import monotonic_ns
from weakref import WeakSet
import os
import sqlite3
import json
import stat

from .contract import AuthorityUnavailable
from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
from .c09_role_capture_pair_v2 import InstalledC09RolePairV2,_SCHEMA_ORDERING
from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2, _bytes as _sql_returned_bytes
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import C09FrozenRoleSourceV2
from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

_STAGE='capture_pre_graph_core_stage_v3'
_SOURCE='capture_pre_graph_core_source_v3'
_TOKEN=object()
_PROOFS=WeakSet()
_PROGRESS=WeakSet()


def _meter(meter):
    if require_c09_reserved_meter_v3(meter.budget) is not meter:
        raise AuthorityUnavailable('actual original C09 Root quantum required')
    return meter


def _encoded(value,meter):
    from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
    size=c09_canonical_json_size_v3(value,typed=True,exact=True)
    meter.require_available(size*2)
    text=canonical_serialize(value);raw=text.encode('ascii');meter.charge_encode(len(raw))
    return raw


def _actual_core_checkpoint_v3(db,meter):
    # Installed exact maintenance statements; no caller SQL or pragma allow expansion.
    mode_sql='PRAGMA journal_mode'
    checkpoint_sql='PRAGMA wal_checkpoint(TRUNCATE)'
    meter.charge_encode(len(mode_sql.encode('ascii')))
    mode=db.execute(mode_sql).fetchone();meter.charge_read(_sql_returned_bytes(mode))
    meter.charge_encode(len(checkpoint_sql.encode('ascii')));meter.count_mutation()
    checkpoint=db.execute(checkpoint_sql).fetchone();meter.charge_read(_sql_returned_bytes(checkpoint))
    return mode,checkpoint


def _sidecar_identity(path,*,empty):
    try:
        checked=path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(checked.st_mode) or path.is_symlink():
        raise AuthorityUnavailable('pre-Graph Core dependency abnormal sidecar')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        actual=os.fstat(fd)
        if (actual.st_dev,actual.st_ino)!=(checked.st_dev,checked.st_ino) or not stat.S_ISREG(actual.st_mode):
            raise AuthorityUnavailable('pre-Graph Core dependency sidecar opened another file')
        if empty and actual.st_size!=0:
            raise AuthorityUnavailable('pre-Graph Core dependency has uncheckpointed WAL pages')
        return (actual.st_dev,actual.st_ino,actual.st_size) if empty else (actual.st_dev,actual.st_ino)
    finally:
        os.close(fd)


class _PreGraphCoreSourceProgressV3:
    def __init__(self,token,session,graph_pair,meter):
        if token is not _TOKEN:
            raise AuthorityUnavailable('actual pre-Graph dependency factory required')
        _meter(meter)
        if (type(session) is not C09PagedCaptureSessionV2 or type(graph_pair) is not InstalledC09RolePairV2
                or graph_pair._producer.session is not session or graph_pair.source_original.role!='graph'
                or graph_pair.source_original.scope_digest!=session.scope.scope_digest):
            raise AuthorityUnavailable('pre-Graph Core Source requires actual same-session Graph pair')
        session.require_current();graph_pair.require_current()
        self.session,self.graph_pair,self.scope=session,graph_pair,session.scope
        self.maintenance=session._control.maintenance;self.control=self.maintenance.control
        current,intent=session._control._current(self.scope.operation_id)
        members=tuple(member for member in current.manifest['members'] if member['role']=='core')
        if len(members)!=1:
            raise AuthorityUnavailable('pre-Graph actual selected Core member is not unique')
        self.member=dict(members[0]);self.path=Path(self.member['resolved_path'])
        self.control.verify_member_v1(self.member,prepared=False)
        facts=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind='capture_facts_intent_v2')
        scope_original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind='capture_scope_v2')
        quiescence=intent['details']['quiescence_original']
        if (scope_original is None or scope_original['details']!=asdict(self.scope) or facts is None
                or facts['original_digest']!=self.scope.facts_pin_intent_digest
                or facts['details']['namespace']!=self.scope.authority_namespace
                or facts['details']['accepted_receipt_digest']!=self.scope.accepted_receipt_digest
                or facts['details']['barrier_digest']!=self.scope.barrier_digest
                or quiescence['quiescence_digest']!=self.scope.writer_freeze_digest or quiescence['active_writers']!=0
                or current.pointer_version!=self.scope.expected_pointer_version
                or current.manifest_digest!=self.scope.old_manifest_digest or current.stage!='INTENT'):
            raise AuthorityUnavailable('actual pre-Graph Core dependency scope/freeze/facts differs')
        # The pre-Graph Source records an actual empty WAL state. Its SHM
        # is an index/lock companion, not SQL data or a final no-companions claim.
        self.core_handle=self.maintenance.core
        with self.maintenance._maintenance_lock,self.core_handle._lock:
            self.core_db=self.core_handle._db
            if self.core_db is None or self.core_db.in_transaction:
                raise AuthorityUnavailable('pre-Graph Core dependency requires actual idle Core connection')
            row=_BoundedReadConnectionV2(self.core_db,meter).execute('PRAGMA database_list').fetchone()
            if row is None or Path(row[2]).resolve()!=self.path.resolve():
                raise AuthorityUnavailable('pre-Graph dependency names another actual Core connection')
            self.journal_mode,self.checkpoint=_actual_core_checkpoint_v3(self.core_db,meter)
            if (self.journal_mode!=('wal',) or self.checkpoint is None or self.checkpoint[0]!=0
                    or self.checkpoint[1]!=self.checkpoint[2]):
                raise AuthorityUnavailable('pre-Graph Core actual checkpoint has outstanding pages')
            self.wal_identity=_sidecar_identity(Path(str(self.path)+'-wal'),empty=True)
            self.shm_identity=_sidecar_identity(Path(str(self.path)+'-shm'),empty=False)
            if Path(str(self.path)+'-journal').exists():
                raise AuthorityUnavailable('pre-Graph Core checkpoint retains rollback journal')
        descriptor=os.open(self.path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        self.file=os.fdopen(descriptor,'rb')
        stat=os.fstat(self.file.fileno())
        self.stamp=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
        if self.stamp[:2]!=(self.member['device'],self.member['file_id']):
            self.file.close();raise AuthorityUnavailable('actual pre-Graph Core opened another inode')
        details={'schema':'sylanne3.c09.pre-graph-core-source-stage.v3','scope_digest':self.scope.scope_digest,
            'current_member':self.member,'graph_source_digest':graph_pair.source_original.role_source_digest,
            'source_identity':self.stamp,'schema_ordering':_SCHEMA_ORDERING,
            'writer_freeze_digest':self.scope.writer_freeze_digest,'accepted_receipt_digest':self.scope.accepted_receipt_digest,
            'barrier_digest':self.scope.barrier_digest,'facts_intent_digest':facts['original_digest'],
            'actual_checkpoint':{'role':'core','source_identity':self.stamp,
                'journal_mode':self.journal_mode,'checkpoint_result':self.checkpoint,
                'empty_wal_identity':self.wal_identity,'shm_non_data_identity':self.shm_identity}}
        self.stage=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_STAGE)
        self.resume_stage,self.resume_source=None,None
        if self.stage is None:
            self.stage=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind=_STAGE,details=details)
            if self.stage['details']!=json.loads(_encoded(details,meter)):
                self.file.close();raise AuthorityUnavailable('pre-Graph Core actual stage replay differs')
        else:
            historical=self.stage['details']
            anchor=dict(details);anchor['actual_checkpoint']=historical['actual_checkpoint']
            checkpoint=historical['actual_checkpoint']
            if (historical!=json.loads(_encoded(anchor,meter))
                    or checkpoint['role']!='core' or tuple(checkpoint['source_identity'])!=self.stamp
                    or checkpoint['journal_mode']!=['wal'] or checkpoint['checkpoint_result'][0]!=0
                    or checkpoint['checkpoint_result'][1]!=checkpoint['checkpoint_result'][2]):
                self.file.close();raise AuthorityUnavailable('pre-Graph Core historical stage main identity/scope differs')
            resume={'schema':'sylanne3.c09.pre-graph-core-resume-stage.v3','scope_digest':self.scope.scope_digest,
                'historical_stage_digest':self.stage['original_digest'],'current_checkpoint':details['actual_checkpoint'],
                'current_member':self.member,'graph_source_digest':graph_pair.source_original.role_source_digest,
                'source_identity':self.stamp,'writer_freeze_digest':self.scope.writer_freeze_digest,
                'facts_intent_digest':facts['original_digest']}
            self.resume_stage=self.control.record_build_original_v1(operation_id=self.scope.operation_id,
                kind='capture_pre_graph_core_resume_stage_v3:'+canonical_digest(resume),details=resume)
            if self.resume_stage['details']!=json.loads(_encoded(resume,meter)):
                self.file.close();raise AuthorityUnavailable('pre-Graph Core current resume witness differs')
        self.phase,self.offset,self.hash='file',0,sha256()
        self.file_digest,self.schema_last,self.schema_count=None,None,0
        self.schema_root=canonical_digest(('sylanne3.c09.role-schema-chain.v2','core'))
        self.schema_cell=None;self.schema_offset=0;self.schema_hash=None
        self.source_original,self.closed=None,False
        _PROGRESS.add(self);self.control.register_c09_retained_state_v3(self)
        self.require_current(meter)

    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        return 16384+getsizeof(self.member)+getsizeof(self.stage)+(0 if self.schema_cell is None else sum(getsizeof(x) for x in self.schema_cell))

    def require_current(self,meter):
        _meter(meter)
        if self not in _PROGRESS or self.closed:
            raise AuthorityUnavailable('actual pre-Graph Core dependency progress closed')
        self.session.require_current();self.graph_pair.require_current()
        self.control.verify_member_v1(self.member,prepared=False)
        fd=os.fstat(self.file.fileno());path=self.path.stat()
        with self.core_handle._lock:
            if (self.maintenance.core is not self.core_handle or self.core_handle._db is not self.core_db
                    or self.core_db.in_transaction
                    or _sidecar_identity(Path(str(self.path)+'-wal'),empty=True)!=self.wal_identity
                    or _sidecar_identity(Path(str(self.path)+'-shm'),empty=False)!=self.shm_identity
                    or Path(str(self.path)+'-journal').exists()):
                raise AuthorityUnavailable('pre-Graph actual Core connection or empty WAL/SHM state changed')
        if ((fd.st_dev,fd.st_ino,fd.st_size,fd.st_mtime_ns)!=self.stamp
                or (path.st_dev,path.st_ino,path.st_size,path.st_mtime_ns)!=self.stamp):
            raise AuthorityUnavailable('actual pre-Graph Core dependency bytes/inode or companions changed')
        original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_STAGE)
        if original is None or original['original_digest']!=self.stage['original_digest']:
            raise AuthorityUnavailable('actual pre-Graph Core dependency signed stage changed')
        for witness in (self.resume_stage,self.resume_source):
            if witness is not None:
                actual=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=witness['original_kind'])
                if actual is None or actual['original_digest']!=witness['original_digest']:
                    raise AuthorityUnavailable('pre-Graph current resume witness changed')
        self.control.require_c09_retained_arena_v3(meter=meter)
        return self

    def copy(self):
        result=copy(self);result.hash=self.hash.copy()
        result.schema_hash=None if self.schema_hash is None else self.schema_hash.copy()
        _PROGRESS.add(result);self.control.register_c09_retained_state_v3(result)
        return result

    def close(self):
        if not self.closed:self.file.close();self.closed=True


class VerifiedPreGraphCoreDependencySourceV3:
    """Private full file/schema Source; no candidate or final RolePair permission."""
    def __init__(self,token,reader):
        if token is not _TOKEN or reader.phase!='sealed' or reader.source_original is None:
            raise AuthorityUnavailable('actual pre-Graph Core full Source issuer required')
        self.producer,self.session,self.graph_pair=reader,reader.session,reader.graph_pair
        self.source_original,self.path=reader.source_original,reader.path
        self.original=reader.control.read_build_original_v1(operation_id=reader.scope.operation_id,kind=_SOURCE)
        if self.original is None or self.original['details']!=asdict(self.source_original):
            raise AuthorityUnavailable('actual pre-Graph Core full Source signed original absent')
        self.original_digest=self.original['original_digest']
        self._active_reads=0
        _PROOFS.add(self);reader.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 16384

    def require_current(self,session,graph_pair,meter):
        _meter(meter)
        if self not in _PROOFS or session is not self.session or graph_pair is not self.graph_pair:
            raise AuthorityUnavailable('pre-Graph Core dependency Source crossed actual session/Graph pair')
        self.producer.require_current(meter)
        original=self.producer.control.read_build_original_v1(operation_id=session.scope.operation_id,kind=_SOURCE)
        if original is None or original['original_digest']!=self.original_digest or original['details']!=asdict(self.source_original):
            raise AuthorityUnavailable('pre-Graph Core full Source original changed')
        return self

    @contextmanager
    def read_database_v3(self,meter):
        self.require_current(self.session,self.graph_pair,meter)
        started=monotonic_ns()
        db=sqlite3.connect(self.path.as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)
        try:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            with self.producer.core_handle._lock:
                self.require_current(self.session,self.graph_pair,meter)
                self._active_reads+=1
                try:
                    yield db
                    self.require_current(self.session,self.graph_pair,meter)
                finally:
                    self._active_reads-=1
        finally:
            db.rollback();db.close()
        if monotonic_ns()-started>meter.budget.max_read_ns:
            raise AuthorityUnavailable('pre-Graph Core dependency actual read duration exceeded')
        self.require_current(self.session,self.graph_pair,meter)

    def close(self):
        if not self.producer.closed:
            if self._active_reads:
                raise AuthorityUnavailable('cannot close pre-Graph Source during an actual read transaction')
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            self.require_current(self.session,self.graph_pair,current_c09_sql_meter_v2())
            self.producer.close()


def begin_pre_graph_core_dependency_source_v3(session,graph_pair,*,meter):
    _meter(meter)
    if type(session) is not C09PagedCaptureSessionV2:
        raise AuthorityUnavailable('actual pre-Graph dependency session required')
    session.require_current()
    if session._control.maintenance.control.read_build_original_v1(operation_id=session.scope.operation_id,
            kind='capture_pre_graph_paid_owner_links_complete_v3') is not None:
        raise AuthorityUnavailable('completed pre-Graph Core dependency requires historical Graph qualification reader')
    return _PreGraphCoreSourceProgressV3(_TOKEN,session,graph_pair,meter)


def advance_pre_graph_core_dependency_source_v3(progress,*,meter):
    _meter(meter)
    if type(progress) is not _PreGraphCoreSourceProgressV3 or progress not in _PROGRESS:
        raise AuthorityUnavailable('actual pre-Graph Core dependency progress required')
    progress.require_current(meter);result=progress.copy()
    if result.phase=='file':
        amount=min(65536,result.stamp[2]-result.offset)
        if amount:
            meter.require_available(amount);result.file.seek(result.offset);raw=result.file.read(amount)
            if len(raw)!=amount:raise AuthorityUnavailable('pre-Graph Core actual file ended before pinned length')
            meter.charge_read(len(raw));result.hash.update(raw);result.offset+=len(raw)
        else:
            result.file.seek(result.offset)
            if result.file.read(1):raise AuthorityUnavailable('pre-Graph Core file has extra EOF bytes')
            result.file_digest=result.hash.hexdigest();result.phase='schema'
    elif result.phase=='schema':
        with closing(sqlite3.connect(result.path.as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)) as raw_db:
            raw_db.execute('PRAGMA query_only=ON');raw_db.execute('BEGIN');started=monotonic_ns()
            db=_BoundedReadConnectionV2(raw_db,meter)
            if result.schema_cell is None:
                row=db.execute('SELECT rowid,type,name,tbl_name,rootpage,length(CAST(sql AS BLOB)) FROM sqlite_schema '
                    'WHERE rowid>? ORDER BY rowid LIMIT 1',(0 if result.schema_last is None else result.schema_last,)).fetchone()
                if row is None:result.phase='source_seal'
                else:
                    result.schema_cell=tuple(row);result.schema_offset=0;result.schema_hash=sha256()
            else:
                row=result.schema_cell;size=row[5]
                if size is not None and result.schema_offset<size:
                    amount=min(8192,size-result.schema_offset)
                    part=db.execute('SELECT substr(CAST(sql AS BLOB),?,?) FROM sqlite_schema WHERE rowid=?',
                        (result.schema_offset+1,amount,row[0])).fetchone()
                    if part is None or len(part[0])!=amount:raise AuthorityUnavailable('pre-Graph Core schema cell ended before actual length')
                    result.schema_hash.update(part[0]);result.schema_offset+=amount
                else:
                    record={'source_rowid':row[0],'type':row[1],'name':row[2],'table':row[3],'rootpage':row[4],
                        'sql_bytes':size,'sql_sha256':None if size is None else result.schema_hash.hexdigest()}
                    _encoded(record,meter)
                    result.schema_root=canonical_digest(('sylanne3.c09.role-schema-record.v2',_SCHEMA_ORDERING,
                        result.schema_root,result.schema_count,record))
                    result.schema_count+=1;result.schema_last=row[0];result.schema_cell=None
            raw_db.rollback()
            if monotonic_ns()-started>meter.budget.max_read_ns:
                raise AuthorityUnavailable('pre-Graph Core schema transaction exceeded original read limit')
    elif result.phase=='source_seal':
        descriptor=C09FrozenRoleSourceV2(result.scope.scope_digest,'core',str(result.path),
            canonical_serialize({'device':result.stamp[0],'file_id':result.stamp[1],'size':result.stamp[2],'mtime_ns':result.stamp[3]}),
            result.file_digest,canonical_digest(('sylanne3.c09.role-schema-complete.v2',_SCHEMA_ORDERING,result.stamp,
                result.file_digest,result.schema_count,result.schema_root,result.schema_last)),
            _STAGE,result.stage['original_digest'])
        original=result.control.record_build_original_v1(operation_id=result.scope.operation_id,kind=_SOURCE,details=asdict(descriptor))
        if original['details']!=asdict(descriptor):
            raise AuthorityUnavailable('actual pre-Graph Core Source complete seal differs')
        if result.resume_stage is not None:
            resume={'schema':'sylanne3.c09.pre-graph-core-resume-source.v3','scope_digest':result.scope.scope_digest,
                'historical_stage_digest':result.stage['original_digest'],'historical_source_digest':original['original_digest'],
                'historical_source_descriptor':asdict(descriptor),'current_resume_stage_digest':result.resume_stage['original_digest'],
                'current_file_sha256':result.file_digest,'current_schema_root':result.schema_root,
                'current_schema_count':result.schema_count,'current_schema_eof_rowid':result.schema_last,
                'current_source_identity':result.stamp}
            result.resume_source=result.control.record_build_original_v1(operation_id=result.scope.operation_id,
                kind='capture_pre_graph_core_resume_source_v3:'+result.resume_stage['original_digest'],details=resume)
            if result.resume_source['details']!=json.loads(_encoded(resume,meter)):
                raise AuthorityUnavailable('pre-Graph current full Source resume witness differs')
        result.source_original=descriptor;result.phase='sealed'
    elif result.phase=='sealed':
        result.require_current(meter)
        return VerifiedPreGraphCoreDependencySourceV3(_TOKEN,result)
    else:
        raise AuthorityUnavailable('actual pre-Graph Core dependency Source private phase differs')
    result.require_current(meter);return result


_LINK_KIND='capture_pre_graph_paid_owner_link_v3:'
_COMPLETE='capture_pre_graph_paid_owner_links_complete_v3'
_LINK_PROGRESS=WeakSet()
_LINK_PROOFS=WeakSet()


class _PreGraphPaidOwnerLinksReadV3:
    def __init__(self,token,source,graph_pair,meter):
        if token is not _TOKEN or type(source) is not VerifiedPreGraphCoreDependencySourceV3:
            raise AuthorityUnavailable('actual complete pre-Graph Core dependency Source required')
        source.require_current(source.session,graph_pair,meter)
        self.source,self.graph_pair,self.session=source,graph_pair,source.session
        self.control,self.scope=source.producer.control,self.session.scope
        self.phase,self.after,self.row,self.worker,self.original='schema',None,None,None,None
        self.core_row,self.buffer,self.offset,self.total=None,bytearray(),0,None
        self.receipt_hash,self.receipt_offset=sha256(),0
        self.count=0;self.schemas=None
        self.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain.v3',
            self.scope.scope_digest,source.original_digest,graph_pair.source_original.role_source_digest))
        self.complete,self.proof=False,None
        _LINK_PROGRESS.add(self);self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        return 32768+getsizeof(self.buffer)+sum(getsizeof(value) for value in (self.row or ()))+sum(getsizeof(value) for value in (self.worker or ()))

    def copy(self):
        result=copy(self);result.buffer=bytearray(self.buffer);result.receipt_hash=self.receipt_hash.copy()
        _LINK_PROGRESS.add(result);self.control.register_c09_retained_state_v3(result);return result

    def require_current(self,meter):
        if self not in _LINK_PROGRESS:
            raise AuthorityUnavailable('actual pre-Graph paid Owner link progress required')
        self.source.require_current(self.session,self.graph_pair,meter)
        self.graph_pair.require_current()
        self.control.require_c09_retained_arena_v3(meter=meter)
        return self


class VerifiedPreGraphPaidOwnerLinksV3:
    """Complete historical row qualifications; never a current Core file assertion."""
    def __init__(self,token,reader,original):
        if token is not _TOKEN or not reader.complete or reader.phase!='sealed':
            raise AuthorityUnavailable('actual full pre-Graph paid Owner link EOF issuer required')
        self.session,self.graph_pair,self.control,self.scope=reader.session,reader.graph_pair,reader.control,reader.scope
        self.source_original,self.source_original_digest=reader.source.source_original,reader.source.original_digest
        self.original_digest,self.details=original['original_digest'],dict(original['details'])
        self.count,self.root=reader.count,reader.root
        _LINK_PROOFS.add(self);self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 32768

    def require_historical_current_v3(self,session,graph_pair,*,meter):
        _meter(meter)
        if (self not in _LINK_PROOFS or session is not self.session or graph_pair is not self.graph_pair
                or graph_pair.source_original.role_source_digest!=self.details['graph_source_digest']):
            raise AuthorityUnavailable('pre-Graph paid Owner historical qualifier crossed original scope/Graph Source')
        session.require_current();graph_pair.require_current()
        original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_COMPLETE)
        if original is None or original['original_digest']!=self.original_digest or original['details']!=self.details:
            raise AuthorityUnavailable('actual pre-Graph paid Owner full EOF historical original changed')
        return self

    def require_row_v3(self,key,row,*,meter):
        self.require_historical_current_v3(self.session,self.graph_pair,meter=meter)
        from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2
        if type(key) is not tuple or len(key)!=4 or tuple(row[:4])!=key:
            raise AuthorityUnavailable('actual paid Owner exact Graph association primary key required')
        original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,
            kind=_LINK_KIND+canonical_digest(key))
        if original is None:
            raise AuthorityUnavailable('paid Owner Graph link has no actual sealed Core/worker qualification')
        details=original['details']
        if (details['scope_digest']!=self.scope.scope_digest
                or details['pre_graph_core_source_original_digest']!=self.source_original_digest
                or details['graph_source_digest']!=self.graph_pair.source_original.role_source_digest
                or tuple(details['graph_primary_key'])!=key
                or details['graph_link_commitment']!=c09_row_commitment_v2(row)):
            raise AuthorityUnavailable('actual paid Owner historical row qualification differs from Graph Source')
        return dict(details)


def begin_pre_graph_paid_owner_link_qualification_v3(source,graph_pair,meter):
    return _PreGraphPaidOwnerLinksReadV3(_TOKEN,source,graph_pair,meter)


def _core_original_header_v3(reader,meter):
    from .v3_owner_paid_guard_observation import TABLE,COLUMNS
    ns,business,phase,fence=reader.core_key
    with reader.source.read_database_v3(meter) as raw:
        db=_BoundedReadConnectionV2(raw,meter)
        row=db.execute('SELECT '+','.join(COLUMNS[:4])+',payload_digest,length(CAST(payload_json AS BLOB)) FROM '+TABLE+
            ' WHERE authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
            (ns,business,phase,fence)).fetchone()
    if row is None or row[4]!=reader.row[6] or type(row[5]) is not int or row[5]<=0:
        raise AuthorityUnavailable('pre-Graph paid Owner link lacks its actual complete Core observation original')
    reader.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=row[5]*36+65536)
    return tuple(row[:5]),row[5]


def advance_pre_graph_paid_owner_link_qualification_v3(progress,*,meter):
    from .v3_owner_paid_guard_observation import (TABLE,GRAPH_TABLE,GRAPH_COLUMNS,
        require_paid_owner_guard_link_schema_v3,require_owner_paid_guard_observation_schema_v3,
        validate_paid_owner_guard_link_row_v3,validate_owner_paid_guard_observation_row_v3)
    from .v2_contract import from_wire as fence_from_wire
    from .v2_owner_contract import canonical_bytes as owner_bytes,canonical_digest as owner_digest
    from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
    from ..runtime_contracts import namespace_ref,NamespaceId
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,c09_row_commitment_v2,read_c09_table_shape_v2
    _meter(meter)
    if type(progress) is not _PreGraphPaidOwnerLinksReadV3 or progress not in _LINK_PROGRESS:
        raise AuthorityUnavailable('actual pre-Graph paid Owner link progress required')
    progress.require_current(meter);result=progress.copy()
    if result.phase=='schema':
        with legacy_cell_read_transaction_v2(result.graph_pair.source):
            graph=_BoundedReadConnectionV2(result.graph_pair.source,meter)
            require_paid_owner_guard_link_schema_v3(graph)
            shape=read_c09_table_shape_v2(result.graph_pair.source,GRAPH_TABLE,meter=meter)
            worker=read_c09_table_shape_v2(result.graph_pair.source,'graph_d13_worker_attempts_v2',meter=meter)
            expected_worker=('bot','persona','operation_id','request_digest','attempt_id','anchor_json',
                'pre_graph_revision','pre_graph_epoch','permit_json','finish_request_id','finish_request_digest','receipt_json')
            if (shape.columns!=GRAPH_COLUMNS or shape.primary_key_columns!=GRAPH_COLUMNS[:4]
                    or shape.primary_key_types!=('text','text','text','text')
                    or worker.columns!=expected_worker or worker.primary_key_columns!=('bot','persona','operation_id')):
                raise AuthorityUnavailable('pre-Graph paid Owner actual association/worker Source schemas differ')
        with result.source.read_database_v3(meter) as raw:
            core=_BoundedReadConnectionV2(raw,meter)
            require_owner_paid_guard_observation_schema_v3(core)
            AuthorityV2OwnerTicketStore._check_schema(core)
            core_shape=read_c09_table_shape_v2(raw,TABLE,meter=meter)
        result.schemas=(shape.schema_digest,worker.schema_digest,core_shape.schema_digest)
        result.phase='next'
    elif result.phase=='next':
        with legacy_cell_read_transaction_v2(result.graph_pair.source):
            db=_BoundedReadConnectionV2(result.graph_pair.source,meter)
            if result.after is None:
                row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                    ' ORDER BY bot,persona,business_operation_id,phase LIMIT 1').fetchone()
            else:
                row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                    ' WHERE (bot,persona,business_operation_id,phase)>(?,?,?,?) '
                    'ORDER BY bot,persona,business_operation_id,phase LIMIT 1',result.after).fetchone()
        if row is None:
            result.phase='complete_seal'
        else:
            validate_paid_owner_guard_link_row_v3(tuple(row))
            result.row=tuple(row);result.phase='worker'
    elif result.phase=='worker':
        with legacy_cell_read_transaction_v2(result.graph_pair.source):
            db=_BoundedReadConnectionV2(result.graph_pair.source,meter)
            row=db.execute('SELECT bot,persona,operation_id,request_digest,attempt_id,anchor_json,pre_graph_revision,'
                'pre_graph_epoch,permit_json,finish_request_id,finish_request_digest,length(CAST(receipt_json AS BLOB)) '
                'FROM graph_d13_worker_attempts_v2 WHERE bot=? AND persona=? AND operation_id=?',
                result.row[:3]).fetchone()
        if row is None or row[:5]!=(result.row[0],result.row[1],result.row[2],result.row[5],result.row[4]) or type(row[11]) is not int or row[11]<=0:
            raise AuthorityUnavailable('pre-Graph paid Owner link lacks exact committed original worker')
        permit=fence_from_wire(json.loads(row[8]))
        namespace=NamespaceId(row[0],row[1])
        if (permit.operation!='write' or permit.operation_id!=row[4] or permit.namespace!=namespace_ref(namespace)
                or permit.authority_id!=result.scope.authority_id):
            raise AuthorityUnavailable('pre-Graph paid Owner actual worker permit/Authority differs')
        result.worker=tuple(row);result.permit=permit
        result.core_key=(permit.namespace,row[2],result.row[3],permit.operation_id)
        result.phase='core_header'
    elif result.phase=='core_header':
        result.core_row,result.total=_core_original_header_v3(result,meter)
        result.phase='core_payload'
    elif result.phase=='core_payload':
        amount=min(8192,result.total-result.offset)
        with result.source.read_database_v3(meter) as raw:
            db=_BoundedReadConnectionV2(raw,meter)
            row=db.execute('SELECT substr(CAST(payload_json AS BLOB),?,?) FROM '+TABLE+
                ' WHERE authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
                (result.offset+1,amount,*result.core_key)).fetchone()
        if row is None or len(row[0])!=amount:
            raise AuthorityUnavailable('pre-Graph actual Core observation original ended before declared EOF')
        result.buffer.extend(row[0]);result.offset+=amount
        if result.offset==result.total:
            text=result.buffer.decode('ascii')
            value=validate_owner_paid_guard_observation_row_v3((*result.core_row[:4],text,result.core_row[4]))
            if (value.permit!=result.permit or value.request_digest!=result.row[5] or value.phase!=result.row[3]
                    or value.business_operation_id!=result.row[2]
                    or value.guard.namespace!=NamespaceId(*result.row[:2])
                    or value.digest!=result.row[6]):
                raise AuthorityUnavailable('pre-Graph actual Core observation crossed Graph original phase/permit/request')
            result.original=value
            result.core_original_commitment=c09_row_commitment_v2((*result.core_row[:4],text,result.core_row[4]))
            result.buffer.clear();result.phase='core_issue'
    elif result.phase=='core_issue':
        with result.source.read_database_v3(meter) as raw:
            db=_BoundedReadConnectionV2(raw,meter)
            sizes=db.execute('SELECT length(c.proof_bytes),length(c.receipt_bytes),length(c.guard_bytes),'
                'length(p.operation_bytes),length(p.receipt_bytes),length(t.ticket_bytes) '
                'FROM authority_owner_issue_committed_v1 c '
                'JOIN authority_owner_issue_pending_v1 p ON p.operation_id=c.operation_id '
                'JOIN authority_owner_claim_tickets_v1 t '
                'ON t.authority_namespace=p.authority_namespace AND t.ticket_id=p.ticket_id '
                'WHERE c.authority_namespace=? AND c.operation_id=?',
                (result.permit.namespace,result.original.issue_operation_id)).fetchone()
            if sizes is None or any(type(size) is not int for size in sizes):
                raise AuthorityUnavailable('pre-Graph Owner Core issue full payload descriptor absent')
            result.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=sum(sizes)*36+65536)
            issue=AuthorityV2OwnerTicketStore._checked_committed(db,result.permit.namespace,result.original.issue_operation_id)
        if issue is None or issue[1].guard!=result.original.guard:
            raise AuthorityUnavailable('pre-Graph actual Owner observation lacks independent issued Core origin')
        head=(result.permit.namespace,result.original.issue_operation_id,result.original.issue_operation_id,1,'active',owner_bytes(result.original.guard))
        if c09_row_commitment_v2(head)!=result.original.head_commitment:
            raise AuthorityUnavailable('pre-Graph original observed Owner head commitment differs')
        if result.row[:2]==tuple(json.loads(result.scope.graph_namespace)) and result.original.guard.installation_id!=result.scope.installation_id:
            raise AuthorityUnavailable('pre-Graph actual selected paid Owner original installation differs')
        result.issue_digest=owner_digest(issue[0]);result.phase='receipt'
    elif result.phase=='receipt':
        amount=min(8192,result.worker[11]-result.receipt_offset)
        with legacy_cell_read_transaction_v2(result.graph_pair.source):
            db=_BoundedReadConnectionV2(result.graph_pair.source,meter)
            row=db.execute('SELECT substr(CAST(receipt_json AS BLOB),?,?) FROM graph_d13_worker_attempts_v2 '
                'WHERE bot=? AND persona=? AND operation_id=?',(result.receipt_offset+1,amount,*result.row[:3])).fetchone()
        if row is None or len(row[0])!=amount:
            raise AuthorityUnavailable('pre-Graph paid Owner worker receipt ended before actual EOF')
        result.receipt_hash.update(row[0]);result.receipt_offset+=amount
        if result.receipt_offset==result.worker[11]:
            if result.receipt_hash.hexdigest()!=result.row[7]:
                raise AuthorityUnavailable('pre-Graph actual paid Owner link/worker receipt EOF digest differs')
            result.phase='row_seal'
    elif result.phase=='row_seal':
        key=tuple(result.row[:4])
        worker_binding=canonical_digest(('sylanne3.c09.pre-graph-paid-worker-binding.v3',
            result.graph_pair.source_original.role_source_digest,tuple(result.worker[:11]),result.worker[11],result.receipt_hash.hexdigest()))
        details={'schema':'sylanne3.c09.pre-graph-paid-owner-link-qualification.v3',
            'scope_digest':result.scope.scope_digest,'pre_graph_core_source_original_digest':result.source.original_digest,
            'graph_source_digest':result.graph_pair.source_original.role_source_digest,
            'graph_primary_key':key,'graph_link_commitment':c09_row_commitment_v2(result.row),
            'core_observation_primary_key':result.core_key,'core_observation_commitment':result.core_original_commitment,
            'observation_digest':result.row[6],'issue_proof_digest':result.issue_digest,
            'head_commitment':result.original.head_commitment,'worker_binding_commitment':worker_binding,
            'receipt_eof_bytes':result.worker[11],'receipt_eof_sha256':result.receipt_hash.hexdigest(),
            'source_schema_digests':result.schemas}
        result.source.require_current(result.session,result.graph_pair,meter)
        original=result.control.record_build_original_v1(operation_id=result.scope.operation_id,
            kind=_LINK_KIND+canonical_digest(key),details=details)
        if original['details']!=json.loads(_encoded(details,meter)):
            raise AuthorityUnavailable('pre-Graph actual paid Owner row qualification replay differs')
        result.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain-row.v3',
            result.root,result.count,key,original['original_digest']))
        result.count+=1;result.after=key
        result.row=result.worker=result.original=result.core_row=None
        result.buffer.clear();result.offset=0;result.total=None
        result.receipt_hash,result.receipt_offset=sha256(),0;result.phase='next'
    elif result.phase=='complete_seal':
        details={'schema':'sylanne3.c09.pre-graph-paid-owner-links-complete.v3',
            'scope_digest':result.scope.scope_digest,'pre_graph_core_source_original_digest':result.source.original_digest,
            'pre_graph_core_source_descriptor':asdict(result.source.source_original),
            'graph_source_digest':result.graph_pair.source_original.role_source_digest,
            'source_schema_digests':result.schemas,'qualified_link_count':result.count,'qualified_link_root':result.root,
            'actual_eof_primary_key':result.after,'actual_graph_link_collection_eof':True}
        result.source.require_current(result.session,result.graph_pair,meter)
        original=result.control.record_build_original_v1(operation_id=result.scope.operation_id,kind=_COMPLETE,details=details)
        if original['details']!=json.loads(_encoded(details,meter)):
            raise AuthorityUnavailable('pre-Graph complete paid Owner link EOF replay differs')
        result.complete=True;result.phase='sealed'
        result.proof=VerifiedPreGraphPaidOwnerLinksV3(_TOKEN,result,original)
        return result.proof
    else:
        raise AuthorityUnavailable('actual pre-Graph paid Owner qualification private phase differs')
    result.require_current(meter);return result


def close_pre_graph_core_dependencies_v3(session,*,meter):
    """Close actual pre-Graph readers before Core issue/mirror can write."""
    _meter(meter)
    if type(session) is not C09PagedCaptureSessionV2:
        raise AuthorityUnavailable('actual session required for pre-Graph dependency close')
    session.require_current()
    states=tuple(state for state in _PROGRESS if state.session is session and not state.closed)
    if not states:return
    proofs=tuple(proof for proof in _PROOFS if proof.session is session and not proof.producer.closed)
    control=session._control.maintenance.control
    complete=control.read_build_original_v1(operation_id=session.scope.operation_id,kind=_COMPLETE)
    if complete is None:
        raise AuthorityUnavailable('Core issue/mirror requires actual full pre-Graph paid Owner qualification EOF')
    details=complete['details']
    expected_graph={state.graph_pair.source_original.role_source_digest for state in states}
    if (details['schema']!='sylanne3.c09.pre-graph-paid-owner-links-complete.v3'
            or details['scope_digest']!=session.scope.scope_digest or len(expected_graph)!=1
            or details['graph_source_digest'] not in expected_graph
            or details['actual_graph_link_collection_eof'] is not True):
        raise AuthorityUnavailable('Core issue/mirror pre-Graph dependency completed original differs')
    files={}
    for state in states:files.setdefault(id(state.file),state)
    for identity,state in files.items():
        proof=next((proof for proof in proofs if id(proof.producer.file)==identity),None)
        if (proof is None or details['pre_graph_core_source_original_digest']!=proof.original_digest
                or details['pre_graph_core_source_descriptor']!=asdict(proof.source_original)):
            raise AuthorityUnavailable('Core issue/mirror still has an incomplete or unmatched pre-Graph Source')
        proof.require_current(session,proof.graph_pair,meter)
        if proof._active_reads:
            raise AuthorityUnavailable('Core issue/mirror cannot race an actual pre-Graph read scope')
    # Each real FD is closed once. Volatile progress aliases lose the same handle.
    for state in files.values():state.file.close()
    for state in states:state.closed=True
    control.record_build_original_v1(operation_id=session.scope.operation_id,
        kind='capture_pre_graph_core_dependencies_closed_v3',
        details={'schema':'sylanne3.c09.pre-graph-core-dependencies-closed.v3',
            'scope_digest':session.scope.scope_digest,'pre_graph_core_source_original_digest':details['pre_graph_core_source_original_digest'],
            'paid_owner_links_complete_digest':complete['original_digest'],
            'closed_readonly_handle_count':len(files)})


def require_final_core_pre_graph_observation_retention_v3(session,final_pair,value,row,*,meter):
    """Final Core Source is independent; retain exact originals qualified earlier."""
    from .v3_owner_paid_guard_observation import COLUMNS
    from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2
    _meter(meter)
    if (type(session) is not C09PagedCaptureSessionV2 or type(final_pair) is not InstalledC09RolePairV2
            or final_pair._producer.session is not session or final_pair.source_original.role!='core'
            or final_pair.source_original.scope_digest!=session.scope.scope_digest
            or final_pair.source_original.source_stage_original_ref!='capture_role_stage_v2_core'
            or tuple(row[:4])!=(value.authority_namespace,value.business_operation_id,value.phase,value.permit.operation_id)
            or len(row)!=len(COLUMNS)):
        raise AuthorityUnavailable('actual independent final Core Source observation retention required')
    session.require_current();final_pair.require_current()
    control=session._control.maintenance.control
    complete=control.read_build_original_v1(operation_id=session.scope.operation_id,kind=_COMPLETE)
    if complete is None:return value
    if complete['details']['scope_digest']!=session.scope.scope_digest:
        raise AuthorityUnavailable('pre-Graph historical Owner qualifier has another actual final scope')
    key=(*value.guard.namespace.as_tuple,value.business_operation_id,value.phase)
    original=control.read_build_original_v1(operation_id=session.scope.operation_id,kind=_LINK_KIND+canonical_digest(key))
    if original is None:
        # A durable observation without a business link is not execution evidence.
        return value
    details=original['details']
    if (details['scope_digest']!=session.scope.scope_digest
            or tuple(details['core_observation_primary_key'])!=tuple(row[:4])
            or details['pre_graph_core_source_original_digest']!=complete['details']['pre_graph_core_source_original_digest']
            or details['observation_digest']!=row[5]
            or details['core_observation_commitment']!=c09_row_commitment_v2(row)):
        raise AuthorityUnavailable('actual final Core lost an immutable pre-Graph qualified Owner original')
    return value


class _HistoricalPreGraphPaidOwnerLinksReadV3:
    def __init__(self,token,session,graph_pair,meter):
        if (token is not _TOKEN or type(session) is not C09PagedCaptureSessionV2
                or type(graph_pair) is not InstalledC09RolePairV2 or graph_pair._producer.session is not session
                or graph_pair.source_original.role!='graph'):
            raise AuthorityUnavailable('actual historical pre-Graph Owner qualification factory required')
        _meter(meter);session.require_current();graph_pair.require_current()
        self.session,self.graph_pair,self.control,self.scope=session,graph_pair,session._control.maintenance.control,session.scope
        self.original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_COMPLETE)
        if self.original is None:
            raise AuthorityUnavailable('actual historical pre-Graph Owner full EOF qualification absent')
        self.details=self.original['details']
        if (self.details['schema']!='sylanne3.c09.pre-graph-paid-owner-links-complete.v3'
                or self.details['scope_digest']!=self.scope.scope_digest
                or self.details['graph_source_digest']!=graph_pair.source_original.role_source_digest):
            raise AuthorityUnavailable('actual historical pre-Graph Owner complete scope differs')
        source=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_SOURCE)
        if (source is None or source['original_digest']!=self.details['pre_graph_core_source_original_digest']
                or source['details']!=self.details['pre_graph_core_source_descriptor']):
            raise AuthorityUnavailable('historical pre-Graph Owner source descriptor/signature link differs')
        self.after,self.count=None,0
        self.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain.v3',self.scope.scope_digest,
            source['original_digest'],graph_pair.source_original.role_source_digest))
        self.complete=False
        self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 32768

    def advance(self,meter):
        from .v3_owner_paid_guard_observation import GRAPH_TABLE,GRAPH_COLUMNS
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,c09_row_commitment_v2
        _meter(meter);self.session.require_current();self.graph_pair.require_current()
        result=copy(self);self.control.register_c09_retained_state_v3(result)
        with legacy_cell_read_transaction_v2(self.graph_pair.source):
            db=_BoundedReadConnectionV2(self.graph_pair.source,meter)
            if self.after is None:
                row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                    ' ORDER BY bot,persona,business_operation_id,phase LIMIT 1').fetchone()
            else:
                row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                    ' WHERE (bot,persona,business_operation_id,phase)>(?,?,?,?) '
                    'ORDER BY bot,persona,business_operation_id,phase LIMIT 1',self.after).fetchone()
        if row is None:
            if (self.count!=self.details['qualified_link_count'] or self.root!=self.details['qualified_link_root']
                    or self.after!=(None if self.details['actual_eof_primary_key'] is None else tuple(self.details['actual_eof_primary_key']))):
                raise AuthorityUnavailable('actual historical pre-Graph Owner full row/count/root EOF differs')
            result.complete=True
            return _historical_pre_graph_owner_proof_v3(_TOKEN,result)
        key=tuple(row[:4])
        original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_LINK_KIND+canonical_digest(key))
        if (original is None or original['details']['scope_digest']!=self.scope.scope_digest
                or original['details']['pre_graph_core_source_original_digest']!=self.details['pre_graph_core_source_original_digest']
                or original['details']['graph_source_digest']!=self.details['graph_source_digest']
                or tuple(original['details']['graph_primary_key'])!=key
                or original['details']['graph_link_commitment']!=c09_row_commitment_v2(row)):
            raise AuthorityUnavailable('actual Graph Source row lacks exact historical Core-linked qualification')
        result.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain-row.v3',
            self.root,self.count,key,original['original_digest']))
        result.count+=1;result.after=key
        return result


def _historical_pre_graph_owner_proof_v3(token,reader):
    from ..runtime.c09_paged_capture_contract_v2 import c09_paged_value_from_wire_v2
    if token is not _TOKEN or type(reader) is not _HistoricalPreGraphPaidOwnerLinksReadV3 or not reader.complete:
        raise AuthorityUnavailable('actual complete historical Owner qualification issuer required')
    value=object.__new__(VerifiedPreGraphPaidOwnerLinksV3)
    value.session,value.graph_pair,value.control,value.scope=reader.session,reader.graph_pair,reader.control,reader.scope
    value.source_original=c09_paged_value_from_wire_v2(reader.details['pre_graph_core_source_descriptor'],C09FrozenRoleSourceV2)
    if value.source_original.source_stage_original_ref!=_STAGE or value.source_original.scope_digest!=reader.scope.scope_digest:
        raise AuthorityUnavailable('historical Owner Source descriptor has another stage/scope')
    value.source_original_digest=reader.details['pre_graph_core_source_original_digest']
    value.original_digest,value.details=reader.original['original_digest'],dict(reader.details)
    value.count,value.root=reader.count,reader.root
    _LINK_PROOFS.add(value);reader.control.register_c09_retained_state_v3(value)
    return value


def begin_historical_pre_graph_paid_owner_links_v3(session,graph_pair,*,meter):
    """After Core changes, reverify the immutable Graph Source against signed rows."""
    return _HistoricalPreGraphPaidOwnerLinksReadV3(_TOKEN,session,graph_pair,meter)


_FINAL_RETENTION='capture_pre_graph_paid_owner_final_core_retention_v3'
_FINAL_READERS=WeakSet()
_FINAL_PROOFS=WeakSet()


class _FinalCorePaidOwnerRetentionReadV3:
    """Reverse every qualified Graph link into independent final Core Source and target."""
    def __init__(self,token,session,builder,meter):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        _meter(meter)
        if (token is not _TOKEN or type(session) is not C09PagedCaptureSessionV2
                or type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.session is not session
                or type(builder.pair) is not InstalledC09RolePairV2 or builder.pair._producer.session is not session
                or builder.pair.source_original.role!='core'
                or builder.pair.source_original.source_stage_original_ref!='capture_role_stage_v2_core'):
            raise AuthorityUnavailable('actual independent final Core role builder required')
        producer=session._control._role_pairs.get('graph')
        if producer is None or producer.session is not session or type(producer.pair) is not InstalledC09RolePairV2:
            raise AuthorityUnavailable('actual registered original Graph pair required for final Core reverse EOF')
        self.session,self.builder,self.pair,self.graph_pair=session,builder,builder.pair,producer.pair
        self.control,self.scope=session._control.maintenance.control,session.scope
        self.complete_original=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_COMPLETE)
        self.details=None if self.complete_original is None else self.complete_original['details']
        if self.details is not None:
            if (self.details['scope_digest']!=self.scope.scope_digest
                    or self.details['graph_source_digest']!=self.graph_pair.source_original.role_source_digest):
                raise AuthorityUnavailable('final Core reverse qualifier belongs to another Graph Source/scope')
            anchor=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_SOURCE)
            if (anchor is None or anchor['original_digest']!=self.details['pre_graph_core_source_original_digest']
                    or anchor['details']!=self.details['pre_graph_core_source_descriptor']):
                raise AuthorityUnavailable('final Core reverse historical Source anchor differs')
            self.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain.v3',self.scope.scope_digest,
                anchor['original_digest'],self.graph_pair.source_original.role_source_digest))
        else:
            self.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-no-linked-family.v3',
                self.scope.scope_digest,self.graph_pair.source_original.role_source_digest))
        self.retained_root=canonical_digest(('sylanne3.c09.final-core-paid-owner-retention-chain.v3',
            self.scope.scope_digest,self.pair.source_original.role_source_digest,self.graph_pair.source_original.role_source_digest))
        self.phase,self.after,self.count='schema',None,0
        self.row,self.qualification,self.header=None,None,None
        self.buffer,self.offset,self.total=bytearray(),0,0
        self.complete,self.proof=False,None
        _FINAL_READERS.add(self);self.control.register_c09_retained_state_v3(self)
        self.require_current(meter)

    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        return 32768+getsizeof(self.buffer)+sum(getsizeof(value) for value in (self.row or ()))

    def require_current(self,meter):
        _meter(meter)
        if self not in _FINAL_READERS:
            raise AuthorityUnavailable('actual final Core reverse retention reader required')
        self.builder.require_current();self.graph_pair.require_current()
        producer=self.session._control._role_pairs.get('graph')
        if producer is None or producer.pair is not self.graph_pair:
            raise AuthorityUnavailable('final Core reverse Graph pair registration changed')
        actual=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=_COMPLETE)
        if (actual is None)!=(self.complete_original is None) or (actual is not None
                and actual['original_digest']!=self.complete_original['original_digest']):
            raise AuthorityUnavailable('final Core reverse complete historical original changed')
        self.control.require_c09_retained_arena_v3(meter=meter)
        return self

    def copy(self,meter):
        self.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=len(self.buffer)+32768)
        result=copy(self);result.buffer=bytearray(self.buffer)
        _FINAL_READERS.add(result);self.control.register_c09_retained_state_v3(result)
        return result

    def advance(self,meter):
        from .v3_owner_paid_guard_observation import (TABLE,COLUMNS,GRAPH_TABLE,GRAPH_COLUMNS,
            require_paid_owner_guard_link_schema_v3,require_owner_paid_guard_observation_schema_v3,
            validate_owner_paid_guard_observation_row_v3)
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,c09_row_commitment_v2
        self.require_current(meter);result=self.copy(meter)
        if result.phase=='schema':
            with legacy_cell_read_transaction_v2(result.graph_pair.source):
                db=_BoundedReadConnectionV2(result.graph_pair.source,meter)
                present=db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name=?",(GRAPH_TABLE,)).fetchone()
                if present is not None:require_paid_owner_guard_link_schema_v3(db)
            result.graph_family_present=present is not None
            if result.details is not None and not result.graph_family_present:
                raise AuthorityUnavailable('final Core reverse signed qualified Graph family is missing')
            if result.details is not None:
                with legacy_cell_read_transaction_v2(result.pair.source):
                    require_owner_paid_guard_observation_schema_v3(_BoundedReadConnectionV2(result.pair.source,meter))
                with legacy_cell_read_transaction_v2(result.pair.candidate):
                    require_owner_paid_guard_observation_schema_v3(_BoundedReadConnectionV2(result.pair.candidate,meter))
            result.phase='next'
        elif result.phase=='next':
            row=None
            if result.graph_family_present:
                with legacy_cell_read_transaction_v2(result.graph_pair.source):
                    db=_BoundedReadConnectionV2(result.graph_pair.source,meter)
                    if result.after is None:
                        row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                            ' ORDER BY bot,persona,business_operation_id,phase LIMIT 1').fetchone()
                    else:
                        row=db.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
                            ' WHERE (bot,persona,business_operation_id,phase)>(?,?,?,?) '
                            'ORDER BY bot,persona,business_operation_id,phase LIMIT 1',result.after).fetchone()
            if row is None:
                if result.details is not None and (result.count!=result.details['qualified_link_count']
                        or result.root!=result.details['qualified_link_root']
                        or result.after!=(None if result.details['actual_eof_primary_key'] is None else tuple(result.details['actual_eof_primary_key']))):
                    raise AuthorityUnavailable('final Core reverse qualified count/root/Graph collection EOF differs')
                result.phase='seal'
            else:
                if result.details is None:
                    raise AuthorityUnavailable('actual final Core linked Owner family lacks pre-Graph full qualification')
                key=tuple(row[:4])
                original=result.control.read_build_original_v1(operation_id=result.scope.operation_id,
                    kind=_LINK_KIND+canonical_digest(key))
                if (original is None or original['details']['scope_digest']!=result.scope.scope_digest
                        or original['details']['pre_graph_core_source_original_digest']!=result.details['pre_graph_core_source_original_digest']
                        or original['details']['graph_source_digest']!=result.graph_pair.source_original.role_source_digest
                        or tuple(original['details']['graph_primary_key'])!=key
                        or original['details']['graph_link_commitment']!=c09_row_commitment_v2(row)):
                    raise AuthorityUnavailable('final Core reverse Graph row qualification differs')
                result.row,result.qualification=tuple(row),original
                result.phase='source_header'
        elif result.phase in ('source_header','target_header'):
            connection=result.pair.source if result.phase=='source_header' else result.pair.candidate
            key=tuple(result.qualification['details']['core_observation_primary_key'])
            with legacy_cell_read_transaction_v2(connection):
                db=_BoundedReadConnectionV2(connection,meter)
                row=db.execute('SELECT '+','.join(COLUMNS[:4])+',payload_digest,length(CAST(payload_json AS BLOB)) FROM '+TABLE+
                    ' WHERE authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',key).fetchone()
            if (row is None or tuple(row[:4])!=key or row[4]!=result.qualification['details']['observation_digest']
                    or type(row[5]) is not int or row[5]<=0):
                raise AuthorityUnavailable('qualified paid Owner original is missing from actual final Core '+result.phase.split('_')[0])
            result.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=row[5]*36+65536)
            result.header=tuple(row[:5]);result.total=row[5];result.offset=0;result.buffer.clear()
            result.phase='source_payload' if result.phase=='source_header' else 'target_payload'
        elif result.phase in ('source_payload','target_payload'):
            connection=result.pair.source if result.phase=='source_payload' else result.pair.candidate
            key=tuple(result.header[:4]);amount=min(8192,result.total-result.offset)
            with legacy_cell_read_transaction_v2(connection):
                row=_BoundedReadConnectionV2(connection,meter).execute(
                    'SELECT substr(CAST(payload_json AS BLOB),?,?) FROM '+TABLE+
                    ' WHERE authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',
                    (result.offset+1,amount,*key)).fetchone()
            if row is None or len(row[0])!=amount:
                raise AuthorityUnavailable('final Core retained Owner original ended before actual full EOF')
            result.buffer.extend(row[0]);result.offset+=amount
            if result.offset==result.total:
                text=result.buffer.decode('ascii');fullrow=(*result.header[:4],text,result.header[4])
                validate_owner_paid_guard_observation_row_v3(fullrow)
                commitment=c09_row_commitment_v2(fullrow)
                if commitment!=result.qualification['details']['core_observation_commitment']:
                    raise AuthorityUnavailable('actual final Core Source/target qualified Owner original was changed')
                result.buffer.clear();result.header=None;result.offset=0;result.total=0
                if result.phase=='source_payload':result.phase='target_header'
                else:
                    key=tuple(result.row[:4]);original=result.qualification
                    result.retained_root=canonical_digest(('sylanne3.c09.final-core-paid-owner-retention-row.v3',
                        result.retained_root,result.count,key,original['original_digest'],commitment))
                    result.root=canonical_digest(('sylanne3.c09.pre-graph-paid-owner-link-chain-row.v3',
                        result.root,result.count,key,original['original_digest']))
                    result.count+=1;result.after=key;result.row=result.qualification=None;result.phase='next'
        elif result.phase=='seal':
            stamp=Path(result.pair.target_path).stat()
            target_identity=(stamp.st_dev,stamp.st_ino,stamp.st_size,stamp.st_mtime_ns)
            details={'schema':'sylanne3.c09.final-core-paid-owner-retention-complete.v3','scope_digest':result.scope.scope_digest,
                'pre_graph_links_complete_digest':None if result.complete_original is None else result.complete_original['original_digest'],
                'graph_source_digest':result.graph_pair.source_original.role_source_digest,
                'final_core_source_digest':result.pair.source_original.role_source_digest,
                'target_path':result.pair.target_path,'target_identity':target_identity,
                'qualified_link_count':result.count,'qualified_link_root':result.root,
                'retained_original_root':result.retained_root,'actual_graph_link_eof_primary_key':result.after,
                'actual_graph_link_collection_eof':True,'source_and_target_originals_eof':True}
            result.require_current(meter)
            original=result.control.record_build_original_v1(operation_id=result.scope.operation_id,kind=_FINAL_RETENTION,details=details)
            if original['details']!=json.loads(_encoded(details,meter)):
                raise AuthorityUnavailable('actual final Core reverse retention complete original replay differs')
            result.complete=True;result.phase='sealed'
            result.proof=VerifiedFinalCorePaidOwnerRetentionV3(_TOKEN,result,original,target_identity)
        else:
            raise AuthorityUnavailable('actual final Core reverse qualification phase differs')
        result.require_current(meter)
        return result


class VerifiedFinalCorePaidOwnerRetentionV3:
    def __init__(self,token,reader,original,target_identity):
        if token is not _TOKEN or reader.phase!='sealed' or not reader.complete:
            raise AuthorityUnavailable('actual full reverse final Core Owner original EOF issuer required')
        self.reader,self.builder,self.session=reader,reader.builder,reader.session
        self.pair,self.graph_pair=reader.pair,reader.graph_pair
        self.original,self.target_identity=original,target_identity
        _FINAL_PROOFS.add(self);reader.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):return 32768

    def require_current(self,builder,*,meter):
        _meter(meter)
        if self not in _FINAL_PROOFS or builder is not self.builder:
            raise AuthorityUnavailable('actual same-builder final Core reverse qualification required')
        self.reader.require_current(meter)
        stamp=Path(self.pair.target_path).stat()
        if (stamp.st_dev,stamp.st_ino,stamp.st_size,stamp.st_mtime_ns)!=self.target_identity:
            raise AuthorityUnavailable('final Core target changed after reverse Owner original EOF')
        actual=self.reader.control.read_build_original_v1(operation_id=self.session.scope.operation_id,kind=_FINAL_RETENTION)
        if actual is None or actual['original_digest']!=self.original['original_digest']:
            raise AuthorityUnavailable('actual final Core retained-original full EOF original changed')
        return self


def begin_final_core_paid_owner_retention_v3(session,builder,*,meter):
    return _FinalCorePaidOwnerRetentionReadV3(_TOKEN,session,builder,meter)
