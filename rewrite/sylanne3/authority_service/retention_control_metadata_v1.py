"""Finite, read-only C09 protection metadata for one admitted retention Work.

The durable original READ is the execution-prefix proof. Deletion roots and
transitions are independently streamed to their real EOF. No business intent,
Source body, maintenance lease, persistent cursor or new grant is issued here.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict
from hashlib import sha256
import json
import secrets
import sqlite3
from threading import RLock
from time import time

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, from_wire, to_wire, canonical_bytes
from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2, _read_one
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    runtime_storage_v3, runtime_storage_quantum_v3, runtime_source_identity_v4)

METHOD = 'read_current_retention_control_metadata_v1'
SIGN_KIND = 'd06.retention-control-metadata.v1'
SCHEMA = 'sylanne3.d06.retention-control-metadata.v1'
OPERATION = 'reconcile_memory_retention_tier_v1'
_CURRENT = ('installation_id','pointer_version','current_manifest_digest',
    'active_operation_id','stage','last_event_seq','last_event_digest',
    'deletion_watermark','cumulative_tombstone_root')
_LEGACY = ('seq','namespace','operation_id','epoch','policy_ref','phase',
    'prev_digest','chain_digest')
_TAIL = ('seq','mutation_id','request_digest','namespace','operation_id','phase',
    'subject','holder','token_digest','fence_epoch','revision','before_seq',
    'before_digest','evidence_digest','epoch','policy_ref','prev_digest','chain_digest')
_REQUEST = frozenset(('namespace','graph_namespace','permit','original_permit',
    'owner_actor_id','owner_session_token','owner_session_request','operation_kind',
    'source_ref','work_identity','selection_digest','graph_stamp_digest',
    'deadline_utc','action','continuation'))
_PAYLOAD = frozenset(('schema','namespace','source_ref','work_identity','operation_kind',
    'selection_digest','graph_stamp_digest','original_permit_digest','cohort_digest',
    'deletion_count','deletion_seq','deletion_digest','protected','owner_digest','storage_generation'))


def verify_retention_control_metadata_v1(value, *, signer):
    if type(value) is not dict or set(value) != {'payload','signature_kind','signature'}:
        raise AuthorityUnavailable('exact signed retention metadata response required')
    payload = value['payload']
    if (type(payload) is not dict or set(payload)!=_PAYLOAD or payload['schema'] != SCHEMA
            or value['signature_kind'] != SIGN_KIND):
        raise AuthorityUnavailable('retention metadata signing domain differs')
    signer.verify(SIGN_KIND, canonical_serialize(payload), value['signature'])
    return payload


def _tail(db, table, meter):
    row = _read_one(db, 'SELECT seq,chain_digest FROM '+table+' ORDER BY seq DESC LIMIT 1', (), meter)
    return (0, 'genesis') if row is None else tuple(row)


def _origin(handle, meter):
    value = runtime_source_identity_v4(handle, meter=meter)
    return value, (value.authority_id,value.installation_id,value.authority_namespace,
        value.selection_digest,value.storage_generation,value.instance,
        value.origin_kind,value.genesis_digest,value.capture_scope_digest,
        canonical_digest(value.member))


class _DeletionEOF:
    def __init__(self, namespace, source_ref):
        self.namespace,self.source_ref = namespace,source_ref
        self.phase='prefix';self.seq=0;self.previous='genesis';self.count=0
        self.row=self.cell=None;self.fields=None;self.field_index=self.offset=0
        self.hasher=None;self.scalar=bytearray();self.roots_count=0;self.match=False;self.roots_seen=set()
        self.operations={};self.complete=False

    def _observe(self, event):
        path=event.path
        if event.kind=='array_start' and path!=():
            raise AuthorityUnavailable('deletion closure roots are not a flat canonical array')
        if event.kind=='object_start':
            raise AuthorityUnavailable('deletion closure root cannot be an object')
        if event.kind=='scalar_start':
            if len(path)!=1 or type(path[0]) is not int or event.scalar_kind!='string':
                raise AuthorityUnavailable('deletion closure root must be an actual string')
            self.scalar.clear()
        elif event.kind=='scalar_chunk':
            if len(self.scalar)+len(event.raw)>4096:
                raise AuthorityUnavailable('deletion closure root exceeds its installed identifier bound')
            self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            root=json.loads(self.scalar)
            if type(root) is not str or not root:
                raise AuthorityUnavailable('deletion closure root identity is absent')
            if root in self.roots_seen:
                raise AuthorityUnavailable('deletion closure roots contain a duplicate original selector')
            self.roots_seen.add(root)
            self.roots_count+=1;self.match|=root==self.source_ref
            self.scalar.clear()

    def advance(self, db, meter, metadata):
        from .c09_paged_recovery_facts_v2 import C09CanonicalSqlCellReaderV2
        if self.complete:return True
        if self.row is None:
            columns=_LEGACY if self.phase=='prefix' else _TAIL
            if self.phase=='tail' and metadata['schema_version']=='2':
                columns=(*_TAIL,'schema','kind','append_id')
            table='deletion_events' if self.phase=='prefix' else 'authority_deletion_v2_tail'
            row=_read_one(db,'SELECT '+','.join(columns)+' FROM '+table+
                ' WHERE seq>? ORDER BY seq LIMIT 1',(self.seq,),meter)
            if row is None:
                if self.phase=='prefix':
                    if (self.seq,self.previous)!=(int(metadata['cut_seq']),metadata['cut_digest']):
                        raise AuthorityUnavailable('actual deletion historical cut differs from its complete prefix')
                    self.phase='tail';return False
                self.complete=True;return True
            value=dict(zip(columns,row))
            if (value['seq']!=self.seq+1 or value['prev_digest']!=self.previous
                    or value['phase'] not in {'pending','accepted','closed'}
                    or type(value['epoch']) is not int or value['epoch']<0):
                raise AuthorityUnavailable('actual deletion chain or phase is discontinuous')
            if self.phase=='tail' and (value['namespace']!=self.namespace
                    or (value['before_seq'],value['before_digest'])!=(self.seq,self.previous)):
                raise AuthorityUnavailable('actual deletion tail predecessor or namespace differs')
            if self.phase=='tail' and metadata['schema_version']=='2' and (
                    value['schema']!='sylanne3.deletion-tail.v2' or value['kind']!='deletion'
                    or type(value['append_id']) is not str or not value['append_id']):
                raise AuthorityUnavailable('actual deletion tail append identity differs')
            self.row=(table,columns,tuple(row),value)
            self.cell=C09CanonicalSqlCellReaderV2(table,'roots_json','seq=?',
                (value['seq'],),ensure_ascii=True,observe=self._observe)
            self.roots_count=0;self.match=False;self.roots_seen.clear();return False
        table,columns,row,value=self.row
        actual=_read_one(db,'SELECT '+','.join(columns)+' FROM '+table+' WHERE seq=?',
            (value['seq'],),meter)
        if tuple(actual or ())!=row:
            raise AuthorityUnavailable('immutable deletion original changed during its metadata EOF')
        if not self.cell.complete:
            self.cell.advance(db,meter);return False
        if not self.roots_count:
            raise AuthorityUnavailable('actual deletion intent has empty closure roots')
        if self.fields is None:
            if self.phase=='prefix':
                body={key:value[key] for key in ('seq','namespace','operation_id','epoch','policy_ref','phase')}
            else:
                body={key:item for key,item in value.items() if key not in {'prev_digest','chain_digest'}}
            body['previous']=value['prev_digest'];body['roots']=None
            self.fields=tuple(sorted(body));self.body=body;self.hasher=sha256(b'{')
            self.field_index=self.offset=0;return False
        if self.field_index<len(self.fields):
            name=self.fields[self.field_index]
            if self.offset==0:
                prefix=(b',' if self.field_index else b'')+json.dumps(name).encode()+b':'
                meter.charge_encode(len(prefix));self.hasher.update(prefix)
            if name=='roots':
                size=min(1024,self.cell.length-self.offset)
                self.hasher.update(self.cell.read(db,self.offset,size,meter));self.offset+=size
                if self.offset<self.cell.length:return False
            else:
                encoded=json.dumps(self.body[name],sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
                meter.charge_encode(len(encoded));self.hasher.update(encoded)
            self.field_index+=1;self.offset=0;return False
        meter.charge_encode(1);self.hasher.update(b'}')
        if 'sha256:'+self.hasher.hexdigest()!=value['chain_digest']:
            raise AuthorityUnavailable('actual deletion intent canonical whole-root digest differs')
        key=(value['namespace'],value['operation_id']);prior=self.operations.get(key)
        transition=(None if prior is None else prior[0],value['phase'])
        if transition not in {(None,'pending'),('pending','accepted'),('accepted','closed')}:
            raise AuthorityUnavailable('actual deletion intent phase history is incomplete')
        identity=(value['epoch'],value['policy_ref'],self.cell.parser._sha256.hexdigest())
        if prior is not None and prior[1]!=identity:
            raise AuthorityUnavailable('actual deletion intent changed roots/epoch/policy across phases')
        self.operations[key]=(value['phase'],identity,self.match)
        self.seq,self.previous=value['seq'],value['chain_digest'];self.count+=1
        self.row=self.cell=self.fields=self.hasher=None;return False


class _RetentionControlRead:
    def __init__(self, server, fences, installed, model, command, credential):
        self.server,self.fences,self.installed,self.model=server,fences,installed,model
        self.command={key:value for key,value in command.items() if key not in {'action','continuation','permit'}}
        self.credential=credential;self.original=from_wire(command['original_permit'])
        self.namespace=NamespaceId(**command['graph_namespace']);self.token=secrets.token_urlsafe(32)
        self.lock=RLock();self.initial=None;self.result=None;self.closed=False
        self.scan=_DeletionEOF(command['namespace'],command['source_ref'])
        self.leases={}
        try:
            core_handle=runtime_storage_v3(self.databases['core'])
            if core_handle is None:
                raise AuthorityUnavailable('retention metadata requires its actual installed Core handle')
            for role,db in self.databases.items():
                handle=runtime_storage_v3(db)
                if (handle is None or handle.pool is not core_handle.pool
                        or handle.selection_digest!=core_handle.selection_digest):
                    raise AuthorityUnavailable('retention role handles require the same actual installed pool/selection')
            lease=begin_runtime_storage_operation_v3(self.databases['core'],
                'retention-control:'+self.token,command['deadline_utc'])
            self.leases={role:lease for role in self.databases}
            self.leases['core'].register_retained_state_v3(self)
        except BaseException:
            self.close();raise

    @property
    def databases(self):
        return {'core':self.fences.core._db,'deletion':self.fences.deletion._db,
            'execution':self.fences.execution._db}

    def _runtime_retained_heap_bytes_v3(self):
        from ..runtime.source_correction_read_v3 import _heap
        cell=self.scan.cell
        return 16384+_heap((self.command,self.initial,self.result,self.scan.operations,self.scan.row,
            self.scan.scalar,self.scan.fields,self.scan.roots_seen,getattr(self.scan,'body',None),
            None if cell is None else (cell.spans,cell.starts,cell.parser._stack,cell.parser._string)))

    @contextmanager
    def snapshot(self, permit, *, recheck=False):
        core=self.fences.core;dbs=self.databases
        handle=runtime_storage_v3(dbs['core'])
        basis=handle.initial if handle.source_kind=='initial_segmented_v4' else handle.selected.basis
        expected_control=basis.control
        with expected_control._lock,self.fences.deletion._lock,self.fences.execution._lock,core._lock,ExitStack() as stack:
            meters={}
            for role,db in dbs.items():
                if db.in_transaction:raise AuthorityUnavailable('retention metadata cannot borrow another transaction')
                stack.enter_context(bind_runtime_storage_operation_v3(self.leases[role],db))
                meters[role]=stack.enter_context(runtime_storage_quantum_v3(db))
                if meters[role] is None:raise AuthorityUnavailable('actual selected installed storage/meter required')
                db.execute('BEGIN');stack.callback(db.rollback)
            origins={role:_origin(runtime_storage_v3(db),meters[role]) for role,db in dbs.items()}
            source=origins['core'][0];control=source.control
            if (control is not expected_control or source.installation_id!=self.installed.installation_id
                    or source.namespace!=self.namespace or source.authority_namespace!=self.command['namespace']
                    or any(value[0].control is not control or value[0].storage_generation!=source.storage_generation
                        or value[0].selection_digest!=source.selection_digest for value in origins.values())):
                raise AuthorityUnavailable('retention metadata crossed actual installed storage cohort')
            with sqlite3.connect(control.path.as_uri()+'?mode=ro',uri=True,isolation_level=None) as cdb:
                cdb.execute('PRAGMA query_only=ON');cdb.execute('BEGIN')
                current=_read_one(cdb,'SELECT '+','.join(_CURRENT)+' FROM c09_storage_current_v1 WHERE installation_id=?',
                    (control.installation_id,),meters['core'])
                if current is None or current[4] not in {'READY','RELEASED'}:
                    raise AuthorityUnavailable('retention original READ is unavailable during Control maintenance')
                self._owner(db=dbs['core'],meter=meters['core'],permit=permit,recheck=recheck)
                facts=self._facts(dbs,meters,current,origins)
                if self.initial is not None and facts!=self.initial:
                    raise AuthorityUnavailable('retention Control/journal/Core cohort changed before complete EOF')
                yield dbs,meters,facts

    def _owner(self, *, db, meter, permit, recheck):
        from .v2_owner_session import OwnerSessionLoginRequestV1
        from .v2_fence_store import AuthorityV2FenceStore
        read=_BoundedReadConnectionV2(db,meter);tickets=self.server._v2_owner_tickets
        sessions=self.server._v2_owner_sessions;source=self.server._v2_owner_pairings
        original=AuthorityV2FenceStore._row(read,self.original.operation_id)
        if (original is None or original[7]!=canonical_bytes(self.original)
                or AuthorityV2FenceStore._permit(original)!=self.original
                or original[10] is not None or original[6]!=('finished' if recheck else 'active')
                or self.original.operation!='read' or permit.operation!=('write' if recheck else 'read')
                or permit.subject!=self.original.subject or permit.holder!=self.original.holder
                or permit.generation!=self.original.generation or permit.pinned_anchor!=self.original.pinned_anchor
                or not recheck and permit!=self.original):
            raise AuthorityUnavailable('retention proof requires its actual durable original admitted READ')
        guard=tickets._current_guard_for_verified_permit_in_tx_v3(read,
            authority_namespace=self.command['namespace'],installation_id=self.installed.installation_id,
            subject=permit.subject,permit=permit)
        kwargs=self.server._owner_session_kwargs(self.command,self.command['namespace'],self.installed.installation_id)
        request=kwargs['session_request']
        if type(request) is not OwnerSessionLoginRequestV1 or request.principal is None:
            raise AuthorityUnavailable('retention metadata requires the actual original Owner session')
        # These installed verifiers intentionally require the actual Core
        # connection, rather than a SQL wrapper. Their bounded session claim is
        # measured before either verifier may materialize it.
        from .v2_owner_session import _verifier
        session=_read_one(db,'SELECT request_json,principal_epoch,boot_id,expires_at_utc,revoked_at_utc '
            'FROM authority_owner_sessions_v1 WHERE verifier=?',(_verifier(kwargs['session_token']),),meter)
        if session is None:
            raise AuthorityUnavailable('retention original Owner session is absent')
        meter.charge_read(sum(len(v) if type(v) is bytes else len(v.encode()) if type(v) is str else 8
            for v in session if v is not None))
        sessions.require_current_in_tx(db,token=kwargs['session_token'],request=request)
        source.require_current_actor_in_tx(db,authority_namespace=self.command['namespace'],
            installation_id=self.installed.installation_id,actor_id=self.command['owner_actor_id'],principal=request.principal)
        owner_row=_read_one(db,'SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 '
            'WHERE authority_namespace=?',(self.command['namespace'],),meter)
        pending=None if owner_row is None else tickets._checked_pending(read,self.command['namespace'],owner_row[0])
        if pending is None or pending[0].principal!=request.principal:
            raise AuthorityUnavailable('retention session differs from the actual current Owner grant')
        if guard is None or guard.pending_revoke_operation_id is not None:
            raise AuthorityUnavailable('retention original current Owner has been revoked')
        self.owner_digest=canonical_digest(guard)

    def _facts(self, dbs, meters, current, origins):
        from .v2_scoped_erasure_store import read_scoped_erasure_state_in_tx_v1
        from .c09_connection_state_v1 import namespace_row_in_tx_v1
        ns=self.command['namespace'];read=_BoundedReadConnectionV2(dbs['core'],meters['core'])
        state=read_scoped_erasure_state_in_tx_v1(read,namespace=ns)
        namespace=namespace_row_in_tx_v1(read,ns)
        reserved=_read_one(dbs['core'],'SELECT mutation_id,request_digest,state FROM authority_v2_mutations '
            "WHERE namespace=? AND state='pending' LIMIT 1",(ns,),meters['core'])
        if reserved is not None or state.aggregate_phase!='clear' or namespace[9]!='clear':
            raise AuthorityUnavailable('retention original content READ is invalidated by pending erasure')
        deletion=dbs['deletion'];dm=meters['deletion']
        metadata=dict(_BoundedReadConnectionV2(deletion,dm).execute('SELECT key,value FROM authority_deletion_v2_meta').fetchall())
        jid=_read_one(deletion,"SELECT value FROM deletion_meta WHERE key='journal_id'",(),dm)
        if (set(metadata)!={'schema_version','journal_id','namespace','cut_seq','cut_digest'}
                or metadata['schema_version'] not in {'1','2'} or metadata['namespace']!=ns
                or jid!=(metadata['journal_id'],) or int(metadata['cut_seq'])<0):
            raise AuthorityUnavailable('retention actual deletion metadata schema/identity differs')
        from .v2_deletion_guard import (_V2_META_DDL,_V2_TAIL_DDL,_V2_TAIL_DDL_V2,
            _PREFIX_TRIGGERS,_TAIL_TRIGGERS,_TAIL_TRIGGERS_V2)
        objects={('table','authority_deletion_v2_meta'):_V2_META_DDL,
            ('table','authority_deletion_v2_tail'):_V2_TAIL_DDL_V2 if metadata['schema_version']=='2' else _V2_TAIL_DDL,
            **{('trigger',name):sql for name,sql in {**_PREFIX_TRIGGERS,
                **(_TAIL_TRIGGERS_V2 if metadata['schema_version']=='2' else _TAIL_TRIGGERS)}.items()}}
        for (kind,name),sql in objects.items():
            if _read_one(deletion,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name),dm)!=(sql,):
                raise AuthorityUnavailable('retention actual immutable deletion schema differs')
        prefix=_tail(deletion,'deletion_events',dm);tail=_tail(deletion,'authority_deletion_v2_tail',dm)
        head=prefix if tail[0]==0 else tail
        anchor=self.original.pinned_anchor
        if (jid[0],*head)!=(anchor.deletion_journal_id,anchor.deletion_seq,anchor.deletion_digest):
            raise AuthorityUnavailable('actual deletion tail differs from the admitted original READ anchor')
        em=meters['execution'];execution=dbs['execution']
        execution_meta=dict(_BoundedReadConnectionV2(execution,em).execute('SELECT key,value FROM authority_v2_execution_meta').fetchall())
        execution_tail=_tail(execution,'authority_v2_execution_entries',em)
        if (execution_meta.get('namespace')!=ns or execution_meta.get('journal_id')!=anchor.execution_journal_id
                or execution_meta.get('schema_version') not in {'1','2','4'}
                or execution_tail!=(anchor.execution_seq,anchor.execution_digest)):
            raise AuthorityUnavailable('actual execution identity/tail left its durable admitted READ prefix')
        schemas=tuple((role,dbs[role].execute('PRAGMA schema_version').fetchone()[0]) for role in dbs)
        for role in dbs:meters[role].charge_read(8)
        return dict(control=tuple(current),origins=tuple((role,value[1])for role,value in origins.items()),
            namespace=tuple(namespace),erasure=asdict(state),reserved=reserved,deletion_metadata=metadata,
            prefix=prefix,deletion_head=head,execution_metadata=execution_meta,execution_head=execution_tail,
            schemas=schemas,owner_digest=self.owner_digest)

    def advance(self, permit):
        if self.closed or self.command['deadline_utc']<=time():
            raise AuthorityUnavailable('retention metadata exceeded its original Work lifetime')
        with self.lock,self.growth(),self.snapshot(permit) as (dbs,meters,facts):
            if self.initial is None:self.initial=facts
            done=self.scan.advance(dbs['deletion'],meters['deletion'],facts['deletion_metadata'])
            if done:
                if (self.scan.seq,self.scan.previous)!=tuple(facts['deletion_head']):
                    raise AuthorityUnavailable('complete deletion intent EOF differs from its actual current tail')
                protected=any(value[0]!='closed' for key,value in self.scan.operations.items() if key[0]==self.command['namespace'])
                if protected:
                    raise AuthorityUnavailable('unfinished deletion intent invalidates the original retention READ')
                payload=dict(schema=SCHEMA,namespace=asdict(self.namespace),source_ref=self.command['source_ref'],
                    work_identity=self.command['work_identity'],operation_kind=OPERATION,
                    selection_digest=self.command['selection_digest'],graph_stamp_digest=self.command['graph_stamp_digest'],
                    original_permit_digest=canonical_digest(to_wire(self.original)),cohort_digest=canonical_digest(facts),
                    deletion_count=self.scan.count,deletion_seq=self.scan.seq,deletion_digest=self.scan.previous,
                    protected=protected,owner_digest=self.owner_digest,storage_generation=dict(facts['origins'])['core'][4])
                signer=self.model._graph_verifier._issuer._signer
                self.result={'payload':payload,'signature_kind':SIGN_KIND,'signature':signer.sign(SIGN_KIND,canonical_serialize(payload))}
            return {'continuation':self.token,'complete':done,'original':self.result}

    @contextmanager
    def growth(self):
        lease=self.leases['core']
        lease.reserve_retained_state_growth_v3(self,196608)
        try:yield
        finally:lease.finish_retained_state_growth_v3(self)

    def recheck(self, permit):
        if self.result is None or not self.scan.complete or self.closed:
            raise AuthorityUnavailable('retention requires its actual complete private EOF cohort')
        with self.lock,self.snapshot(permit,recheck=permit.operation=='write'):
            return {'continuation':self.token,'complete':True,'original':self.result}

    def close(self):
        if self.closed:return
        self.closed=True
        lease=self.leases.get('core')
        if lease is not None:lease.unregister_retained_state_v3(self)
        for lease in set(self.leases.values()):finish_runtime_storage_operation_v3(lease)
        self.leases.clear();self.scan.operations.clear();self.result=None


def dispatch_retention_control_metadata_v1(server, method, credential, profile_id, manifest_digest, command):
    if method!=METHOD:return None
    if type(command) is not dict or set(command)!=_REQUEST:
        raise AuthorityUnavailable('retention metadata requires its exact fixed Method command')
    from ..graph_types import AtomKey
    from ..memory_types import source_key
    namespace=NamespaceId(**command['graph_namespace']);key=AtomKey.from_token(command['source_ref'])
    if (command['operation_kind']!=OPERATION or key!=source_key(*namespace.as_tuple,key.owner.subject)
            or command['action'] not in {'advance','recheck','release'}
            or type(command['deadline_utc']) not in {int,float}
            or command['action']!='release' and command['deadline_utc']<=time()):
        raise AuthorityUnavailable('retention metadata escaped its actual fixed operation/Source/lifetime')
    fences=server._bound_v2_service(credential,profile_id,manifest_digest,command['namespace'])
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    if server._namespace_bindings_v2.get((credential.certificate_sha256,profile_id,namespace))!=command['namespace']:
        raise AuthorityUnavailable('retention metadata crossed its actual installed namespace mapping')
    permit=from_wire(command['permit']);original=from_wire(command['original_permit'])
    if (type(permit) is not FencePermitV2 or type(original) is not FencePermitV2
            or permit.namespace!=command['namespace'] or original.namespace!=command['namespace']
            or permit.holder!=installed.administrator_holder
            or permit.subject!='mtls:sha256:'+credential.certificate_sha256):
        raise AuthorityUnavailable('retention metadata requires this installed original content permit')
    fences.core._require(credential,'read',command['namespace'],permit.holder)
    states=getattr(server,'_retention_control_reads_v1',None)
    if states is None:states={};server._retention_control_reads_v1=states
    token=command['continuation'];state=states.get(token)
    if state is None:
        if token is not None or command['action']!='advance' or permit!=original:
            raise AuthorityUnavailable('retention metadata continuation has no actual private issuer')
        model=server._v2_model_egress.get(command['namespace'])
        if model is None or model._graph_verifier._artifact_draft_bundle.installation_policy.installation_id!=installed.installation_id:
            raise AuthorityUnavailable('retention metadata installed signer/namespace unavailable')
        state=_RetentionControlRead(server,fences,installed,model,command,credential);states[state.token]=state
    expected={key:value for key,value in command.items() if key not in {'action','continuation','permit'}}
    if (state.command!=expected or state.fences is not fences or state.installed is not installed
            or state.credential.certificate_sha256!=credential.certificate_sha256):
        raise AuthorityUnavailable('retention metadata continuation crossed its exact original Work')
    try:
        if command['action']=='release':
            state.close();states.pop(state.token,None)
            return {'continuation':state.token,'complete':True,'original':None}
        return state.recheck(permit) if command['action']=='recheck' else state.advance(permit)
    except BaseException:
        state.close();states.pop(state.token,None);raise


def release_retention_control_metadata_v1(server):
    """Release retained metadata when this actual server composition closes."""
    states=getattr(server,'_retention_control_reads_v1',{})
    for state in tuple(states.values()):state.close()
    states.clear()
