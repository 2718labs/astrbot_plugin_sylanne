"""Actual C09 role-source seals and same-INTENT registered candidate pairs.

A call advances at most one installed capture quantum. Hash state is volatile;
restart revalidates the same frozen file and keeps the registered target inode.
No source rows or caller paths enter the public producer.
"""
from __future__ import annotations

from dataclasses import asdict,dataclass
import hashlib,json,os,secrets,sqlite3
from pathlib import Path
from time import monotonic_ns

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import C09FrozenRoleSourceV2,ROLES_V2

_PAIR=object()
_CHUNK=16384
_SCHEMA_ORDERING="sqlite_schema.frozen-rowid.asc.v2"

@dataclass(frozen=True,slots=True)
class C09RolePairProgressV2:
    role:str
    phase:str
    bytes_processed:int
    batch_bytes:int
    local_ns:int
    status:str='progress'

@dataclass(frozen=True,slots=True,init=False)
class InstalledC09RolePairV2:
    _issuer:object
    _producer:object
    source_original:C09FrozenRoleSourceV2
    source:sqlite3.Connection
    candidate:sqlite3.Connection
    target_path:str
    target_identity:tuple
    build_plan:object
    _closed:bool
    def __init__(self,token,producer,source_original,source,candidate,target_path,target_identity,build_plan):
        if token is not _PAIR:raise AuthorityUnavailable('actual installed role pair required')
        from types import MappingProxyType
        for name,value in (('_issuer',token),('_producer',producer),('source_original',source_original),
                ('source',source),('candidate',candidate),('target_path',target_path),('target_identity',target_identity),
                ('build_plan',MappingProxyType(dict(build_plan))),('_closed',False)):
            object.__setattr__(self,name,value)
    def require_current(self):
        if self._closed or self._issuer is not _PAIR:raise AuthorityUnavailable('C09 role pair closed')
        self._producer.session.require_current();self._producer.check_source()
        actual=self._producer.control.read_build_original_v1(operation_id=self._producer.scope.operation_id,kind='allocation_'+self.source_original.role)
        stat=Path(self.target_path).stat()
        if actual['details']!={'role':self.source_original.role,'target_path':self.target_path,
                'device':stat.st_dev,'file_id':stat.st_ino,'source_root':self.source_original.role_source_digest}:
            raise AuthorityUnavailable('C09 candidate allocation or source root changed')
        if self.target_identity!=(stat.st_dev,stat.st_ino):raise AuthorityUnavailable('C09 candidate inode changed')
        return self
    def check_source(self):
        self.require_current()
    def close(self):
        if not self._closed:
            self.candidate.close();self.source.close();self._producer.file.close();object.__setattr__(self,'_closed',True)

class _RoleSourceProducerV2:
    def __init__(self,session,role):
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        if type(session) is not C09PagedCaptureSessionV2 or role not in ROLES_V2:
            raise AuthorityUnavailable('actual capture session and fixed role required')
        self.session,self.scope,self.role=session,session.require_current(),role
        self.maintenance=session._control.maintenance;self.control=self.maintenance.control
        current,intent=session._control._current(self.scope.operation_id)
        members=[member for member in current.manifest['members'] if member['role']==role]
        if len(members)!=1:raise AuthorityUnavailable('current manifest role is not unique')
        self.member=members[0];self.path=Path(self.member['resolved_path'])
        self.target=Path(intent['details']['targets'][role])
        self.completion=None
        self._stage()
        self.control.verify_member_v1(self.member,prepared=False)
        descriptor=os.open(self.path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        self.file=os.fdopen(descriptor,'rb')
        stat=os.fstat(self.file.fileno())
        if (stat.st_dev,stat.st_ino)!=(self.member['device'],self.member['file_id']):
            self.file.close();raise AuthorityUnavailable('actual source opened another inode')
        self.stat=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
        self.db=None
        try:
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)
            self.hash=hashlib.sha256();self.file_digest=None;self.phase='file_hash';self.offset=0
            self.schema_root=canonical_digest(('sylanne3.c09.role-schema-chain.v2',role))
            self.schema_last=None;self.schema_cell=None;self.schema_count=0;self.pair=None
            self.check_source()
        except BaseException:
            if self.db is not None:self.db.close()
            self.file.close();raise
    def _stage(self):
        m=self.maintenance
        if self.role=='graph':
            m._checkpoint(m.graph,close=True)
            closed=m._closed_connection_originals_v3.get(id(m.graph))
            if closed is None or closed[0] is not m.graph or closed[2]['connection_id']!=id(closed[1]):
                raise AuthorityUnavailable('Graph role has no actual same-handle close completion')
            if Path(closed[2]['path'])!=self.path:raise AuthorityUnavailable('Graph close completion names another source')
            evidence={'graph_close_completion':closed[2]}
        else:
            qualifier=getattr(self.session._control,'require_graph_rebase_completion_v2',None)
            if qualifier is None:raise AuthorityUnavailable('actual V2 Core issue and mirror completion reader pending')
            self.completion=qualifier(self.session)
            handle={'core':m.core,'execution':m.closure.execution,'deletion':m.closure.deletion}[self.role]
            m._checkpoint(handle)
            evidence={'graph_issue_digest':self.completion.graph_issue_digest,
                'graph_mirror_digest':self.completion.graph_mirror_digest,'facts_pin_digest':self.completion.facts_pin_digest}
        kind='capture_role_stage_v2_'+self.role
        prior=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=kind)
        if prior is None:
            prior=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind=kind,
                details={'schema':'sylanne3.c09.role-source-stage.v2','scope_digest':self.scope.scope_digest,
                    'role':self.role,'current_member':self.member,'schema_ordering':_SCHEMA_ORDERING,'evidence':evidence})
        details=prior['details']
        if (details['schema'],details['scope_digest'],details['role'],details['current_member'])!=(
                'sylanne3.c09.role-source-stage.v2',self.scope.scope_digest,self.role,self.member):
            raise AuthorityUnavailable('role source stage original changed')
        if self.role!='graph' and details['evidence']!=evidence:
            raise AuthorityUnavailable('Core role stage actual issue or mirror changed')
        self.stage=prior
    def check_source(self):
        self.session.require_current()
        self.control.verify_member_v1(self.member,prepared=False)
        before=os.fstat(self.file.fileno());path=self.path.stat()
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=self.stat or (
                path.st_dev,path.st_ino,path.st_size,path.st_mtime_ns)!=self.stat:
            raise AuthorityUnavailable('C09 frozen role source inode or bytes changed')
        if any(Path(str(self.path)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
            raise AuthorityUnavailable('C09 frozen role source has unclosed companion')
        if self.role!='graph':
            current=self.session._control.require_graph_rebase_completion_v2(self.session)
            if current!=self.completion:raise AuthorityUnavailable('C09 source stage completion changed')
    def _schema_step(self,remaining):
        if self.schema_cell is None:
            row=self.db.execute('SELECT rowid,type,name,tbl_name,rootpage,length(CAST(sql AS BLOB)) FROM sqlite_schema WHERE rowid>? ORDER BY rowid LIMIT 1',
                (0 if self.schema_last is None else self.schema_last,)).fetchone()
            if row is None:return 0,True
            header={'source_rowid':row[0],'type':row[1],'name':row[2],'table':row[3],'rootpage':row[4],
                'sql_bytes':row[5],'sql_sha256':'0'*64}
            if len(canonical_serialize(header).encode())>65536:
                raise AuthorityUnavailable('actual schema catalogue header exceeds descriptor bound')
            self.schema_cell=[row,0,hashlib.sha256()]
        row,offset,digest=self.schema_cell
        size=row[5]
        if size is not None and offset<size:
            chunk=self.db.execute('SELECT substr(CAST(sql AS BLOB),?,?) FROM sqlite_schema WHERE rowid=?',
                (offset+1,min(_CHUNK,remaining),row[0])).fetchone()[0]
            if not chunk:raise AuthorityUnavailable('schema cell ended before its actual length')
            digest.update(chunk);self.schema_cell[1]+=len(chunk)
            if self.schema_cell[1]<size:return len(chunk),False
            used=len(chunk)
        else:used=0
        record={'source_rowid':row[0],'type':row[1],'name':row[2],'table':row[3],'rootpage':row[4],
            'sql_bytes':size,'sql_sha256':None if size is None else digest.hexdigest()}
        self.schema_root=canonical_digest(('sylanne3.c09.role-schema-record.v2',_SCHEMA_ORDERING,self.schema_root,self.schema_count,record))
        self.schema_count+=1;self.schema_last=row[0];self.schema_cell=None
        return used+len(canonical_serialize(record).encode()),False
    def advance(self,budget,start):
        self.check_source()
        used=0
        records=0
        while self.phase in {'file_hash','schema_root'} and used<budget.max_bytes-_CHUNK-65536 and records<budget.max_records and monotonic_ns()-start<budget.max_local_ns:
            if self.phase=='file_hash':
                block=self.file.read(min(_CHUNK,budget.max_bytes-used))
                if block:self.hash.update(block);used+=len(block);self.offset+=len(block)
                else:self.file_digest=self.hash.hexdigest();self.phase='schema_root'
            elif self.phase=='schema_root':
                before=self.schema_count;amount,eof=self._schema_step(budget.max_bytes-used)
                used+=amount;records+=self.schema_count-before
                if eof:self.phase='source_seal';break
        self.check_source()
        if self.phase=='source_seal':
            self.pair=self._seal();return self.pair
        return C09RolePairProgressV2(self.role,self.phase,self.offset,used,monotonic_ns()-start)
    def _plan(self,source):
        if self.role=='graph':
            kind='capture_graph_build_plan_v2'
            prior=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=kind)
            old=self.db.execute("SELECT json_extract(requirements_json,'$.graph_incarnation') FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",self.maintenance.namespace_id.as_tuple).fetchone()
            if old is None or old[0]!=self.member['incarnation_or_journal_id']:
                raise AuthorityUnavailable('Graph current recovery incarnation differs from manifest source')
            binding={'schema':'sylanne3.c09.graph-build-plan.v2','scope_digest':self.scope.scope_digest,'source_role_digest':source.role_source_digest,
                'old_incarnation':old[0],'maintenance_generation':self.scope.maintenance_generation}
            if prior is None:prior=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind=kind,
                details={**binding,'new_incarnation':secrets.token_hex(16)})
            if {key:prior['details'].get(key) for key in binding}!=binding:
                raise AuthorityUnavailable('Graph stable build plan binding changed')
        else:
            kind='capture_authority_build_plan_v2'
            prior=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind=kind)
            c=self.completion
            binding={'schema':'sylanne3.c09.authority-build-plan.v2','scope_digest':self.scope.scope_digest,'facts_pin_digest':c.facts_pin_digest,
                'graph_issue_digest':c.graph_issue_digest,'graph_mirror_digest':c.graph_mirror_digest,
                'old_execution_journal_id':c.old_execution_journal_id,'old_execution_seq':c.old_execution_seq,
                'old_execution_digest':c.old_execution_digest}
            if prior is None:prior=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind=kind,
                details={**binding,'new_execution_journal_id':'c09-execution-'+secrets.token_hex(16),
                    'new_anchor_nonce':secrets.token_hex(32),'continuation_permit_token':secrets.token_hex(32)})
            if {key:prior['details'].get(key) for key in binding}!=binding:
                raise AuthorityUnavailable('Authority stable build plan originals changed')
        return prior['details']
    def _seal(self):
        self.check_source()
        source=C09FrozenRoleSourceV2(self.scope.scope_digest,self.role,str(self.path),
            canonical_serialize({'device':self.stat[0],'file_id':self.stat[1],'size':self.stat[2],'mtime_ns':self.stat[3]}),
            self.file_digest,canonical_digest(('sylanne3.c09.role-schema-complete.v2',_SCHEMA_ORDERING,self.stat,self.file_digest,self.schema_count,self.schema_root,self.schema_last)),self.stage['original_kind'],self.stage['original_digest'])
        sealed=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind='capture_role_source_v2_'+self.role,details=asdict(source))
        if sealed['details']!=asdict(source):raise AuthorityUnavailable('actual frozen role source replay changed')
        plan=self._plan(source)
        from .c09_storage_control_v1 import _regular_path
        target=_regular_path(self.target,exists=False)
        allocation=self.control.read_build_original_v1(operation_id=self.scope.operation_id,kind='allocation_'+self.role)
        if allocation is None:
            if target.exists():
                if target.stat().st_size!=0:raise AuthorityUnavailable('unregistered nonempty C09 target retained')
            else:
                fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
                os.fsync(fd);os.close(fd)
            stat=target.stat()
            allocation=self.control.record_build_original_v1(operation_id=self.scope.operation_id,kind='allocation_'+self.role,
                details={'role':self.role,'target_path':str(target),'device':stat.st_dev,'file_id':stat.st_ino,
                    'source_root':source.role_source_digest})
        stat=target.stat()
        if allocation['details']!={'role':self.role,'target_path':str(target),'device':stat.st_dev,
                'file_id':stat.st_ino,'source_root':source.role_source_digest}:
            raise AuthorityUnavailable('registered C09 target inode or source differs')
        candidate=sqlite3.connect(target,isolation_level=None)
        try:
            candidate.execute('PRAGMA synchronous=FULL');candidate.execute('PRAGMA journal_mode=DELETE')
            pair=InstalledC09RolePairV2(_PAIR,self,source,self.db,candidate,str(target),(stat.st_dev,stat.st_ino),plan)
            pair.require_current();return pair
        except BaseException:
            candidate.close();raise


def open_current_c09_role_pair_v2(session,role):
    with session._control.maintenance._maintenance_lock:
        start=monotonic_ns()
        with session.reserve_batch() as budget:
            if role not in ROLES_V2:raise AuthorityUnavailable('unknown installed capture role')
            cache=session._control._role_pairs
            prior=cache.get(role)
            if prior is None:
                prior=_RoleSourceProducerV2(session,role);cache[role]=prior
            if prior.session is not session:raise AuthorityUnavailable('role pair belongs to another actual session')
            if prior.pair is not None:return prior.pair.require_current()
            return prior.advance(budget,start)


def close_current_c09_role_pairs_v2(session):
    cache=session._control._role_pairs
    for producer in cache.values():
        if producer.session is not session:raise AuthorityUnavailable('closing another capture session is forbidden')
        if producer.pair is not None:producer.pair.close()
        else:producer.db.close();producer.file.close()
    cache.clear()


def close_completed_c09_authority_sources_v2(session):
    """Last actual close after independently issued and post-cold mirrored Graph.

    This consumes the real live Core issue before closing its connection. It
    records actual local close completions; replay after close verifies the
    immutable source through the installed completion reader.
    """
    from contextlib import closing
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_graph_rebase_issue_v2 import _read_issue,_verify_signature,_wire,require_graph_rebase_completion_v2
    from .c09_paged_recovery_facts_v2 import _decode_completion
    from ..runtime.c09_paged_capture_contract_v2 import c09_paged_value_to_wire_v2
    if type(session) is not C09PagedCaptureSessionV2:
        raise AuthorityUnavailable('actual installed C09 close session required')
    m=session._control.maintenance
    with m._maintenance_lock:
        session.require_current()
        m.core._require(m.credential,'execution_redaction_install',m.closure.namespace)
        current,intent=session._control._current(session.scope.operation_id)
        members={member['role']:member for member in current.manifest['members']}
        def record_closed(completed,closed):
            binding={'schema':'sylanne3.c09.authority-sources-closed.v2','scope_digest':session.scope.scope_digest,
                'graph_issue_digest':completed.graph_issue_digest,'graph_mirror_digest':completed.graph_mirror_digest,
                'facts_pin_digest':completed.facts_pin_digest}
            prior=m.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='capture_authority_sources_closed_v2')
            if prior is None:
                prior=m.control.record_build_original_v1(operation_id=session.scope.operation_id,kind='capture_authority_sources_closed_v2',
                    details={**binding,'closed_connections':closed})
            if {key:prior['details'].get(key) for key in binding}!=binding:
                raise AuthorityUnavailable('actual closed authority source stage replay changed')
            return completed
        if m.core._db is None:
            completed=require_graph_rebase_completion_v2(session)
            closed=[]
            for role,handle in (('core',m.core),('execution',m.closure.execution),('deletion',m.closure.deletion)):
                actual=m._closed_connection_originals_v3.get(id(handle))
                if actual is None or actual[0] is not handle or actual[2]['connection_id']!=id(actual[1]):
                    raise AuthorityUnavailable('closed Core replay lacks actual three-role close completion')
                if Path(actual[2]['path'])!=Path(members[role]['resolved_path']):
                    raise AuthorityUnavailable('closed role proof differs from current manifest')
                m.control.verify_member_v1(members[role],prepared=False)
                if any(Path(members[role]['resolved_path']+suffix).exists() for suffix in ('-wal','-shm','-journal')):
                    raise AuthorityUnavailable('actual closed source replay retains a companion')
                closed.append({'role':role,'member':members[role],'close_completion':actual[2]})
            return record_closed(completed,closed)
        issued=m.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='graph_issued_v2')
        mirror=m.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='graph_mirror_v2')
        facts_original=m.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='capture_facts_complete_v2')
        if issued is None or mirror is None or facts_original is None:
            raise AuthorityUnavailable('actual V2 issue, post-cold mirror and complete facts required before source close')
        with m.core._tx() as db:
            issue=_read_issue(db,session.scope.authority_namespace,session.scope.operation_id)
        installed=m.core._c09_maintenance_authority_v1
        if issue is None or installed is None:
            raise AuthorityUnavailable('actual live Core issue and installed signer required')
        _verify_signature(issue,installed[0])
        if issue.certificate.candidate.scope!=session.scope or issued['details']!=_wire(issue):
            raise AuthorityUnavailable('live Core signed issue differs from this registered operation')
        details=mirror['details']
        fields={'schema','scope_digest','certificate_digest','graph_issue_digest','target_path','target_identity','target_file_sha256','cold_read_digest'}
        if (set(details)!=fields or details['schema']!='sylanne3.c09.graph-mirror-completion.v2'
                or details['scope_digest']!=session.scope.scope_digest
                or details['certificate_digest']!=issue.certificate.certificate_digest
                or details['graph_issue_digest']!=issue.issue_digest):
            raise AuthorityUnavailable('actual post-cold mirror commitment differs')
        producer=session._control._role_pairs.get('graph')
        pair=None if producer is None else producer.pair
        if type(pair) is not InstalledC09RolePairV2:
            raise AuthorityUnavailable('actual registered Graph pair required before authority source close')
        pair.require_current()
        target=Path(pair.target_path);stat=target.stat()
        if (details['target_path']!=pair.target_path or tuple(details['target_identity'])!=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
                or str(intent['details']['targets']['graph'])!=pair.target_path):
            raise AuthorityUnavailable('actual post-mirror target inode or file version changed')
        if any(Path(str(target)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
            raise AuthorityUnavailable('post-cold mirror target has unclosed companion')
        if any(type(details[name]) is not str or len(details[name])!=64 or any(c not in '0123456789abcdef' for c in details[name])
                for name in ('target_file_sha256','cold_read_digest')):
            raise AuthorityUnavailable('actual fullfile and independent post-cold commitments absent')
        with closing(sqlite3.connect(target.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            namespace=json.loads(session.scope.graph_namespace)
            row=db.execute('SELECT certificate_json,issue_digest FROM graph_c09_rebase_certificates_v2 WHERE bot=? AND persona=? AND operation_id=?',
                (*namespace,session.scope.operation_id)).fetchone()
        if row!=(canonical_serialize(c09_paged_value_to_wire_v2(issue.certificate)),issue.issue_digest):
            raise AuthorityUnavailable('actual target certificate row differs from independently signed Core issue')
        facts=_decode_completion(facts_original['details'])
        if (facts.scope_digest!=session.scope.scope_digest or facts.facts_intent_digest!=session.scope.facts_pin_intent_digest
                or facts.pin_digest!=issue.certificate.facts_pin_digest):
            raise AuthorityUnavailable('actual complete facts pin differs from Core signed certificate')
        session.require_current()
        closed=[]
        for role,handle in (('execution',m.closure.execution),('deletion',m.closure.deletion),('core',m.core)):
            m.control.verify_member_v1(members[role],prepared=False)
            m._checkpoint(handle,close=True)
            original=m._closed_connection_originals_v3.get(id(handle))
            if original is None or original[0] is not handle or original[2]['connection_id']!=id(original[1]):
                raise AuthorityUnavailable('authority source has no actual same-handle close completion')
            if Path(original[2]['path'])!=Path(members[role]['resolved_path']):
                raise AuthorityUnavailable('authority source close completion names another member')
            if any(Path(members[role]['resolved_path']+suffix).exists() for suffix in ('-wal','-shm','-journal')):
                raise AuthorityUnavailable('actual closed authority source retains a companion')
            closed.append({'role':role,'member':members[role],'close_completion':original[2]})
        completed=require_graph_rebase_completion_v2(session)
        return record_closed(completed,closed)
