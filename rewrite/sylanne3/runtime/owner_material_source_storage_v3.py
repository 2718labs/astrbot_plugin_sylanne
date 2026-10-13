"""Actual Owner material-source storage preparation and immutable cell staging.

This is the existing D06 Owner intake, using the same business payload bytes,
typed Source validation and W01 writer. Physical staging grants no adoption.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
from weakref import WeakSet,WeakKeyDictionary,ref
from uuid import uuid4

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import StaleRead
from ..graph_types import GraphWrite
from ..runtime_contracts import canonical_digest, canonical_serialize, _canonical_value
from ..runtime_storage_v3 import (
    runtime_storage_v3, _operation, runtime_storage_quantum_v3,
    _runtime_bounded_fixed_row_v3,
)
from ..segmented_sql_cell_v1 import MAX_SEGMENT_BYTES

_PREPARED = object()
_SEAL = object()
_STAGE = object()
_PREPARATIONS = WeakSet()
_COMMANDS = WeakSet()
_COMMAND_ISSUER = object()
_PROCESS_ID_V3 = uuid4().hex
_SEALS = WeakSet()
_WRITES = WeakSet()
_SOURCE_VALUES = {}
_INPUT_WITNESSES = WeakSet()
_INPUT_WITNESS_BINDINGS = WeakKeyDictionary()
_INPUT_WITNESS = object()

PREPARED_DDL = """CREATE TABLE IF NOT EXISTS graph_owner_source_prepared_v3 (
    prepared_digest TEXT PRIMARY KEY,bot TEXT NOT NULL,persona TEXT NOT NULL,
    operation_id TEXT NOT NULL,attempt_id TEXT NOT NULL,request_claim_digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL,input_sha256 TEXT NOT NULL,input_bytes INTEGER NOT NULL,
    original_digest TEXT NOT NULL,original_bytes INTEGER NOT NULL,
    source_sha256 TEXT NOT NULL,source_bytes INTEGER NOT NULL,phase TEXT NOT NULL,
    CHECK(input_bytes>=0 AND original_bytes>=0 AND source_bytes>=0)) STRICT"""


def _prepared_segment_v3(db,meter,cell_id,ordinal):
    # The actual producer's retained parser/fragment allowance covers this one row.
    length=db.execute('SELECT length(payload) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?',
        (cell_id,ordinal)).fetchone()
    if length is None:return None
    if not 0<length[0]<=MAX_SEGMENT_BYTES:
        raise AuthorityUnavailable('actual staged Source segment exceeds its fixed physical bound')
    meter.require_available(MAX_SEGMENT_BYTES+1024)
    return meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
        'cell_id=? AND ordinal=?',(cell_id,ordinal))


COMMAND_SEED_DDL = """CREATE TABLE IF NOT EXISTS graph_owner_source_command_seeds_v3 (
    bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,attempt_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,seed_digest TEXT NOT NULL,payload_json TEXT NOT NULL,
    PRIMARY KEY(bot,persona,operation_id),UNIQUE(bot,persona,attempt_id)) STRICT"""


DISPOSITION_DDL = """CREATE TABLE IF NOT EXISTS graph_owner_source_dispositions_v3 (
    prepared_digest TEXT PRIMARY KEY,operation_id TEXT NOT NULL,attempt_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('committed','aborted')),
    receipt_digest TEXT,disposition_digest TEXT NOT NULL,cell_ids_json TEXT NOT NULL) STRICT"""


class CanonicalValueStreamV3:
    """Exact compact ASCII canonical JSON, bounded even for one large string."""
    def __init__(self,value):
        self.value=value
        self.active_meter=None
        self.iterator=self._value(value,lambda:self.active_meter)
        self.pending=b''
        self.offset=0
        self.hash=sha256()
        self.complete=False

    @staticmethod
    def _quoted(value,meter_getter=None):
        yield b'"'
        for offset in range(0,len(value),1024):
            meter=None if meter_getter is None else meter_getter()
            if meter is not None:meter.require_available(1024*36+8192)
            raw=json.dumps(value[offset:offset+1024],ensure_ascii=True,separators=(',',':'))
            encoded=raw.encode('ascii')
            stripped=encoded[1:-1]
            if meter is not None:meter.charge_encode(len(raw)+len(encoded)+len(stripped))
            yield stripped
        yield b'"'

    @classmethod
    def _value(cls,value,meter_getter=None):
        if type(value) is str:
            yield from cls._quoted(value,meter_getter)
        elif type(value) is dict:
            yield b'{'
            for index,key in enumerate(sorted(value)):
                if index:yield b','
                yield from cls._quoted(key,meter_getter);yield b':';yield from cls._value(value[key],meter_getter)
            yield b'}'
        elif type(value) in (tuple,list):
            yield b'['
            for index,part in enumerate(value):
                if index:yield b','
                yield from cls._value(part,meter_getter)
            yield b']'
        elif value is None or type(value) in (bool,int,float):
            raw=json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False)
            encoded=raw.encode('ascii')
            meter=None if meter_getter is None else meter_getter()
            if meter is not None:meter.charge_encode(len(raw)+len(encoded))
            yield encoded
        else:
            raise TypeError('canonical Source stream requires its actual primitive business value')

    def read_fragment(self,meter):
        if self.complete:return None
        self.active_meter=meter
        maximum=MAX_SEGMENT_BYTES
        meter.require_available(maximum*4+8192)
        output=bytearray()
        while len(output)<maximum:
            if not self.pending:
                try:self.pending=next(self.iterator)
                except StopIteration:
                    self.complete=True;break
            take=min(maximum-len(output),len(self.pending))
            output.extend(self.pending[:take]);self.pending=self.pending[take:]
        data=bytes(output)
        meter.charge_encode(len(data))
        self.hash.update(data);self.offset+=len(data)
        return data if data else None


@dataclass(frozen=True,slots=True)
class DomainOriginalPayloadRefV3:
    cell_id:str
    payload_sha256:str
    total_bytes:int
    prepared_digest:str


class SealedOwnerSourceCellV3:
    def __init__(self,issuer,prepared,name,cell_id,header):
        if issuer is not _SEAL or prepared not in _PREPARATIONS:
            raise AuthorityUnavailable('actual independently verified Owner Source cell required')
        self.prepared,self.name,self.cell_id,self.header=prepared,name,cell_id,header
        _SEALS.add(self)

    def require_current(self,prepared,name):
        if self not in _SEALS or self.prepared is not prepared or self.name!=name:
            raise AuthorityUnavailable('Owner Source seal crossed its actual preparation/descriptor')
        prepared.require_current()
        return self


class SealedSourceGraphWriteV3:
    """Private ownership of an exact GraphWrite, preserving the v1 type tag."""
    def __init__(self,issuer,prepared,seal):
        if issuer is not _SEAL or prepared not in _PREPARATIONS:
            raise AuthorityUnavailable('actual sealed Source writer required')
        seal.require_current(prepared,'source')
        if not prepared.source_verified:
            raise AuthorityUnavailable('complete SourceRecord streaming semantic validation required')
        self.prepared,self.seal=prepared,seal
        write=GraphWrite.__new__(GraphWrite)
        object.__setattr__(write,'key',prepared.source_key)
        object.__setattr__(write,'value',prepared.source.to_dict())
        object.__setattr__(write,'dependencies',())
        object.__setattr__(write,'_sealed_source_v3',self)
        self._pending_write=write
        self._write_ref=ref(write)
        _WRITES.add(self)
        identity=id(write.value)
        _SOURCE_VALUES[identity]=ref(self,lambda _,identity=identity: _SOURCE_VALUES.pop(identity,None))

    @property
    def write(self):
        return self._write_ref()

    def take_write_v3(self):
        write=self._pending_write
        if write is None:
            raise AuthorityUnavailable('issued Source write ownership already transferred')
        self._pending_write=None
        return write


def issued_sealed_source_graph_write_v3(write):
    holder=getattr(write,'_sealed_source_v3',None)
    return type(write) is GraphWrite and type(holder) is SealedSourceGraphWriteV3 and holder in _WRITES and holder.write is write


def require_sealed_source_graph_write_v3(write):
    if not issued_sealed_source_graph_write_v3(write):
        raise AuthorityUnavailable('actual issued sealed Source graph write required')
    holder=write._sealed_source_v3
    holder.seal.require_current(holder.prepared,'source')
    if write.value!=holder.prepared.source.to_dict():
        raise AuthorityUnavailable('sealed Source full typed value changed after canonical verification')
    return holder


def clone_sealed_source_graph_write_v3(write):
    holder=require_sealed_source_graph_write_v3(write)
    return SealedSourceGraphWriteV3(_SEAL,holder.prepared,holder.seal).take_write_v3()


def sealed_source_value_v3(key,value):
    weak=_SOURCE_VALUES.get(id(value))
    holder=None if weak is None else weak()
    if holder is None or holder not in _WRITES or holder.write.value is not value:
        return None
    require_sealed_source_graph_write_v3(holder.write)
    if key!=holder.write.key or key.type_name!='memory.source':
        raise AuthorityUnavailable('sealed source validation cannot authorize another graph type')
    return value


class OwnerMaterialInputWitnessV3:
    """One EOF digest of the actual Workbench request; no permission in wire."""
    def __init__(self,issuer,prepared):
        if (issuer is not _INPUT_WITNESS or prepared not in _PREPARATIONS and prepared not in _COMMANDS
                or 'http_request' not in prepared.expected):
            raise AuthorityUnavailable('complete actual Owner input canonical EOF required')
        self.request,self.operation_id=prepared.request,prepared.operation_id
        self.digest,self.total_bytes=prepared.expected['http_request']
        _INPUT_WITNESSES.add(self)
        _INPUT_WITNESS_BINDINGS[self]=(self.request,self.operation_id,self.digest,self.total_bytes)


def require_owner_material_input_witness_v3(witness,*,request,operation_id):
    binding=_INPUT_WITNESS_BINDINGS.get(witness) if type(witness) is OwnerMaterialInputWitnessV3 else None
    if (type(witness) is not OwnerMaterialInputWitnessV3 or witness not in _INPUT_WITNESSES
            or binding is None or witness.request is not binding[0]
            or (witness.operation_id,witness.digest,witness.total_bytes)!=binding[1:]
            or witness.operation_id!=operation_id):
        raise AuthorityUnavailable('actual Owner material input witness identity differs')
    # The mapper receives the original raw request; retain exactly the same text.
    actual=request.get('request') if type(request) is dict else None
    if type(actual) is not dict or set(request)!={'request'} or set(actual)!={'text'} or actual['text'] is not witness.request.text:
        raise AuthorityUnavailable('Owner input witness is bound to its actual raw request object')
    return witness.digest


def _owner_source_bundle_value_v3(frame,source_key,source_value,access_write):
    from ..runtime_contracts import DomainBundle,DomainProposal,DependencySet
    from ..domains.d06 import D06DomainProvider
    dependencies=DependencySet(current_invalidation=tuple(v for v in frame.snapshot.versions if v.key==source_key),
        historical_provenance=tuple(v for v in frame.snapshot.versions if v.key.type_name=='memory.source' and v.revision>0))
    source={'$type':GraphWrite.__module__+'.'+GraphWrite.__qualname__,
        'key':_canonical_value(source_key,set()),'value':source_value,'dependencies':[]}
    proposal={'$type':DomainProposal.__module__+'.'+DomainProposal.__qualname__,
        'domain':'d06','proposal_schema':'d06.proposal.v1',
        'proposal_schema_hash':D06DomainProvider().descriptor.request_schema_hash,
        'envelope':_canonical_value(frame.envelope,set()),'typed_writes':[source,_canonical_value(access_write,set())],
        'dependencies':_canonical_value(dependencies,set()),'contribution_keys':[],'required_bundle_parts':[]}
    return {'$type':DomainBundle.__module__+'.'+DomainBundle.__qualname__,
        'envelope':_canonical_value(frame.envelope,set()),'proposals':[proposal],
        'experience_refs':[],'choice_refs':[],'d02_settlement_refs':[],'d11_cost_settlement_refs':[],
        'idempotency_keys':[frame.envelope.identity.operation_id],'persistent_job_refs':[],'outbox_refs':[]}


def issued_owner_source_bundle_digest_v3(bundle):
    """The complete old typed canonical SHA, issued only by actual sealed Work."""
    from ..runtime_contracts import DomainBundle
    from dataclasses import fields
    if type(bundle) is not DomainBundle or len(bundle.proposals)!=1:
        return None
    writes=bundle.proposals[0].typed_writes
    if not writes or not issued_sealed_source_graph_write_v3(writes[0]):
        return None
    holder=require_sealed_source_graph_write_v3(writes[0]);prepared=holder.prepared
    if prepared.phase not in ('sealed','committed') or bundle.product_advance is not None or bundle.root_adoption is not None:
        raise AuthorityUnavailable('actual sealed Owner Source bundle required')
    value={'$type':DomainBundle.__module__+'.'+DomainBundle.__qualname__,
        **{field.name:_canonical_value(getattr(bundle,field.name),set()) for field in fields(bundle)
           if field.name not in {'product_advance','root_adoption'}}}
    if value!=prepared.bundle_value:
        raise AuthorityUnavailable('sealed Owner Source bundle changed its full v1 canonical business payload')
    prepared.seals['bundle'].require_current(prepared,'bundle')
    return prepared.expected['bundle'][0]


class PreparedOwnerMaterialWriteV3:
    """Private preparation of the actual admitted Source operation, never a job."""
    def __init__(self,issuer,runtime,db,frame,request,readers,scope,owner,guard,metadata,epoch):
        from .owner_material_source_v1 import validated_owner_material_source_v1,OPERATION
        from ..domains.d01.production_operations_v1 import plain_v1,current_stage_payload_v1
        if issuer is not _PREPARED or runtime.graph._GraphCoordinator__store._db is not db:
            raise AuthorityUnavailable('actual Owner Source runtime/store producer required')
        self.runtime,self.db,self.frame,self.request,self.readers=runtime,db,frame,request,readers
        self.scope,self.owner,self.guard,self.metadata,self.epoch=scope,owner,guard,metadata,epoch
        self.handle=runtime_storage_v3(db)
        self.operation=_operation(self.handle)
        if (frame.envelope.identity.phase!=OPERATION or scope.operation!='write'
                or self.operation.operation_id!=frame.envelope.identity.operation_id):
            raise AuthorityUnavailable('actual Owner Source command/write/retention operation required')
        self.source,self.access,self.source_key,self.access_key=validated_owner_material_source_v1(
            db,frame=frame,request=request,installed_readers=readers)
        self.namespace=frame.envelope.authority.namespace
        self.operation_id=frame.envelope.identity.operation_id
        self.deadline=frame.envelope.deadline_utc
        attempt=db.execute('SELECT request_digest,attempt_id,graph_revision,graph_epoch,permit_json,receipt_json '
            'FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
            (*self.namespace.as_tuple,self.operation_id)).fetchone()
        if (attempt is None or attempt[1]!=scope.operation_id or attempt[2:4]!=(metadata.graph_revision,epoch.revision)
                or attempt[4] is None or attempt[5] is not None):
            raise AuthorityUnavailable('actual unresolved signed Owner Source attempt/fence required')
        self.attempt=attempt
        self.operation.retain(524288)
        self.source_value=self.source.to_dict()
        self.access_write=GraphWrite(self.access_key,self.access,(self.source_key,))
        source_write=plain_v1(dict(key=self.source_key,value=self.source_value,dependencies=()))
        self.payload=current_stage_payload_v1(frame,'d06',OPERATION,request,
            writes=(source_write,self.access_write),
            provenance=dict(source_ref=self.source_key.token,source=self.source,source_access=self.access))
        self.values={'input':plain_v1(request),'source':self.source_value,'original':self.payload,
            'stage_request':_canonical_value(dict(request=request,envelope=frame.envelope),set()),
            'http_request':plain_v1(dict(request=request))}
        self.bundle_value=_owner_source_bundle_value_v3(frame,self.source_key,self.source_value,self.access_write)
        self.values['bundle']=self.bundle_value
        self.expected={}
        self.streams={name:CanonicalValueStreamV3(value) for name,value in self.values.items()}
        self.phase,self.index='hash',0
        self.names=('input','source','original','stage_request','http_request','bundle')
        self.prepared_digest=None
        self.metadata_value=plain_v1(dict(schema='d06.owner-source-prepared.v3',
            authority_id=self.handle.selected.basis.control.authority_id,
            installation_id=self.handle.selected.basis.control.installation_id,namespace=self.namespace,
            operation_kind=OPERATION,operation_id=self.operation_id,attempt_id=attempt[1],
            request_claim_ref='graph_owner_domain_attempts_v3:'+self.operation_id,
            request_claim_digest=attempt[0],owner_guard_digest=canonical_digest(frame.owner_guard),
            envelope=frame.envelope,frame_snapshot_versions=frame.snapshot.versions,
            query_coverage=frame.query_coverage,policy_refs=frame.installed_policy_refs,
            catalogue_hash=frame.envelope.version_guard.catalogue_version,
            access_epoch=frame.envelope.version_guard.access_epoch,delete_epoch=frame.envelope.version_guard.delete_epoch,
            parent_budget_original_ref=frame.envelope.parent_budget_lease_ref,
            parent_budget_original_digest=canonical_digest(readers.installed_bundle.installation_policy.root_grant),
            graph_incarnation=metadata.requirements.graph_incarnation,
            original_now_utc=frame.now_utc,original_deadline_utc=self.deadline,
            graph_requirements=metadata.requirements,graph_revision=metadata.graph_revision,
            pinned_anchor=scope.pinned_anchor,namespace_epoch=epoch,source_ref=self.source_key.token,access_ref=self.access_key.token,
            selected_binding=self.handle.selection_digest,storage_instance=self.handle.instance))
        self.cursors={}
        self.replay_ordinals={name:0 for name in self.names}
        self.verifiers={}
        self.source_parser=None
        self.source_verified=False
        self.source_fragment=None
        self.source_fragment_offset=0
        self.seals={}
        _PREPARATIONS.add(self)

    def require_current(self):
        if self not in _PREPARATIONS or self.operation.closed:
            raise AuthorityUnavailable('Owner Source preparation ended or lacks its actual issuer')
        if self.handle.selection_digest!=self.operation.selection_digest:
            raise AuthorityUnavailable('Owner Source preparation changed selected storage')
        return self

    @contextmanager
    def _tx(self):
        if self.db.in_transaction:
            raise AuthorityUnavailable('Source staging requires its own short transaction')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield self.db
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise

    def _cell_id(self,name):
        return canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',
            instance=self.handle.instance,prepared_digest=self.prepared_digest,name=name,
            sha256=self.expected[name][0]))

    def _cursor(self,name,*,phase='staging',ordinal=0,offset=0,root=None,digest=None,revision=0):
        cell=self._cell_id(name)
        root=root or canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell))
        digest=digest or sha256().hexdigest()
        return (cell,self.prepared_digest,canonical_serialize(dict(schema='d06.owner-source-cell-locator.v3',
            prepared_digest=self.prepared_digest,name=name,source_ref=self.source_key.token)),
            'canonical-json.ascii.v1',self.operation_id,self.source_key.token,phase,ordinal,offset,root,digest,
            canonical_serialize(dict(name=name,source_byte_offset=offset)),self.expected[name][1],
            0,0,canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell)),sha256().hexdigest(),revision)

    def _register(self,meter):
        descriptors={name:dict(payload_sha256=digest,total_bytes=size) for name,(digest,size) in self.expected.items()}
        metadata_value=dict(self.metadata_value,expected_outputs=descriptors)
        self.prepared_digest=canonical_digest(metadata_value)
        encoded=canonical_serialize(metadata_value)
        record=(self.prepared_digest,*self.namespace.as_tuple,self.operation_id,self.attempt[1],self.attempt[0],
            encoded,*self.expected['input'],*self.expected['original'],*self.expected['source'],'prepared')
        with self._tx() as db:
            old=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_prepared_v3',
                ('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json',
                 'input_sha256','input_bytes','original_digest','original_bytes','source_sha256','source_bytes','phase'),
                'prepared_digest=?',(self.prepared_digest,))
            if old is None:
                meter.charge_write(len(encoded)+2048)
                db.execute('INSERT INTO graph_owner_source_prepared_v3 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',record)
            elif old!=record:
                raise AuthorityUnavailable('Owner Source immutable preparation replay differs')
            for name in self.names:
                cursor=self._cursor(name)
                old=_runtime_bounded_fixed_row_v3(db,meter,'segmented_cell_writes_v1',
                    ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id',
                     'erasure_owner_ref','phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256',
                     'source_cursor_json','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset',
                     'verify_prefix_root','verify_prefix_sha256','cursor_revision'),'cell_id=?',(cursor[0],))
                if old is None:
                    meter.charge_write(2048)
                    db.execute('INSERT INTO segmented_cell_writes_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',cursor)
                    old=cursor
                elif old[:6]!=cursor[:6] or old[12]!=cursor[12]:
                    raise AuthorityUnavailable('Source stage replay changed actual prepared locator/input')
                self.cursors[name]=old
        self.streams={name:CanonicalValueStreamV3(value) for name,value in self.values.items()}
        self.phase,self.index='stage',0

    def _stage(self,name,meter):
        stream=self.streams[name];saved=self.cursors[name]
        prefix_hash=stream.hash.hexdigest()
        prefix_offset=stream.offset
        fragment=stream.read_fragment(meter)
        if prefix_offset==saved[8] and (self.replay_ordinals[name]!=saved[7] or prefix_hash!=saved[10]):
            raise AuthorityUnavailable('Source cold cursor count/canonical prefix SHA differs')
        if fragment is None:
            if (stream.hash.hexdigest(),stream.offset)!=self.expected[name]:
                raise AuthorityUnavailable('Source immutable input/output canonical stream changed')
            if saved[8]!=stream.offset:
                raise AuthorityUnavailable('Source stage cursor does not cover the exact immutable input')
            self.index+=1
            return
        offset=stream.offset-len(fragment)
        cell=self._cell_id(name)
        # Cold continuation rereads each real prefix segment instead of trusting
        # cursor/hash state. The same immutable Owner request regenerates bytes.
        if offset<saved[8]:
            prior=_prepared_segment_v3(self.db,meter,cell,self.replay_ordinals[name])
            if prior is None or prior[0]!=offset or prior[1]!=fragment or prior[2]!=sha256(fragment).hexdigest():
                raise AuthorityUnavailable('Source cold stage prefix differs from actual original input')
            self.replay_ordinals[name]+=1
            return
        ordinal=saved[7];segment_sha=sha256(fragment).hexdigest()
        root=canonical_digest(('sylanne3.segmented-cell-link.v1',saved[9],cell,ordinal,offset,len(fragment),segment_sha))
        with self._tx() as db:
            actual=db.execute('SELECT cursor_revision,next_ordinal,next_byte_offset,prefix_root FROM segmented_cell_writes_v1 '
                'WHERE cell_id=?',(cell,)).fetchone()
            if actual!=(saved[-1],ordinal,offset,saved[9]):
                raise StaleRead('Owner Source stage cursor changed')
            meter.charge_write(len(fragment)+4096)
            db.execute('INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',(cell,ordinal,offset,fragment,segment_sha))
            changed=db.execute("UPDATE segmented_cell_writes_v1 SET next_ordinal=?,next_byte_offset=?,prefix_root=?,"
                "prefix_sha256=?,source_cursor_json=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?",
                (ordinal+1,stream.offset,root,stream.hash.hexdigest(),canonical_serialize(dict(name=name,source_byte_offset=stream.offset)),
                 cell,saved[-1]))
            if changed.rowcount!=1:raise StaleRead('Owner Source stage cursor CAS failed')
        self.replay_ordinals[name]+=1
        self.cursors[name]=(*saved[:7],ordinal+1,stream.offset,root,stream.hash.hexdigest(),
            canonical_serialize(dict(name=name,source_byte_offset=stream.offset)),*saved[12:17],saved[-1]+1)

    def _verify(self,name,meter):
        saved=self.cursors[name];cell=self._cell_id(name)
        if name=='source':
            from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
            if self.source_parser is None:
                self.source_parser=C09MemorySourceJSONStreamV3(ensure_ascii=True)
            if self.source_fragment is not None:
                end=min(self.source_fragment_offset+1024,len(self.source_fragment))
                self.source_parser.feed(self.source_fragment[self.source_fragment_offset:end],lambda event:None)
                self.source_fragment_offset=end
                if end==len(self.source_fragment):self.source_fragment=None
                return
        state=self.verifiers.setdefault(name,dict(ordinal=0,offset=0,hash=sha256(),
            root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell))))
        if state['ordinal']<saved[7]:
            row=_prepared_segment_v3(self.db,meter,cell,state['ordinal'])
            if row is None or row[0]!=state['offset'] or not 0<len(row[1])<=MAX_SEGMENT_BYTES or sha256(row[1]).hexdigest()!=row[2]:
                raise AuthorityUnavailable('independent Source seal segment offset/SHA differs')
            state['hash'].update(row[1])
            state['root']=canonical_digest(('sylanne3.segmented-cell-link.v1',state['root'],cell,
                state['ordinal'],state['offset'],len(row[1]),row[2]))
            state['ordinal']+=1;state['offset']+=len(row[1])
            if name=='source':self.source_fragment,self.source_fragment_offset=row[1],0
            return
        extra=self.db.execute('SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
            (cell,state['ordinal'])).fetchone()
        if (extra is not None or (state['hash'].hexdigest(),state['offset'])!=self.expected[name]
                or state['root']!=saved[9]):
            raise AuthorityUnavailable('independent Source complete byte/SHA/root/EOF differs')
        if name=='source':
            parsed=self.source_parser.finish()
            metadata={key:value for key,value in self.source_value.items() if key!='text'}
            if (parsed.sha256,parsed.byte_count)!=(state['hash'].hexdigest(),state['offset']) or self.source_parser._source_metadata!=metadata:
                raise AuthorityUnavailable('full SourceRecord stream schema/metadata/EOF differs')
            self.source_verified=True
        header=(cell,'canonical-json.ascii.v1',self.source_key.token,self.operation_id,state['offset'],
            state['ordinal'],state['hash'].hexdigest(),state['root'],self.prepared_digest)
        with self._tx() as db:
            prior=db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?',(cell,)).fetchone()
            if prior is None:
                meter.charge_write(2048);db.execute('INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
            elif prior!=header:
                raise AuthorityUnavailable('Source staged immutable seal replay differs')
            db.execute("UPDATE segmented_cell_writes_v1 SET phase='sealed',verify_next_ordinal=?,verify_next_byte_offset=?,"
                'verify_prefix_root=?,verify_prefix_sha256=?,cursor_revision=cursor_revision+1 WHERE cell_id=? AND cursor_revision=?',
                (state['ordinal'],state['offset'],state['root'],state['hash'].hexdigest(),cell,saved[-1]))
        self.seals[name]=SealedOwnerSourceCellV3(_SEAL,self,name,cell,header)
        self.index+=1

    def advance(self):
        from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
        from .first_ingress_v2 import trusted_upper
        self.require_current()
        clock=self.runtime.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.runtime.graph._GraphCoordinator__scene_clock_policy)
        if trusted_upper(clock)>=self.deadline:
            raise AuthorityUnavailable('Owner Source original trusted production deadline expired')
        with bind_runtime_storage_operation_v3(self.operation,self.db),runtime_storage_quantum_v3(self.db) as meter:
            if self.phase=='hash':
                name=self.names[self.index];stream=self.streams[name]
                if name=='http_request' and getattr(self,'command',None) in _COMMANDS:
                    self.expected[name]=self.command.expected['http_request'];self.index+=1
                elif stream.read_fragment(meter) is None:
                    self.expected[name]=(stream.hash.hexdigest(),stream.offset);self.index+=1
                if self.index==len(self.names):self.phase='register'
            elif self.phase=='register':
                self._register(meter)
            elif self.phase=='stage':
                self._stage(self.names[self.index],meter)
                if self.index==len(self.names):self.phase,self.index='verify',0
            elif self.phase=='verify':
                self._verify(self.names[self.index],meter)
                if self.index==len(self.names):self.phase='sealed'
            elif self.phase!='sealed':
                raise AuthorityUnavailable('Owner Source preparation has no executable phase')
        return dict(status='complete' if self.phase=='sealed' else 'progress',
            phase=self.phase,prepared_digest=self.prepared_digest)

    def input_witness_v3(self):
        return OwnerMaterialInputWitnessV3(_INPUT_WITNESS,self)

    def sealed_stage_v3(self):
        if self.phase!='sealed':raise AuthorityUnavailable('Owner Source exact canonical outputs are not all sealed')
        return StagedDomainOperationV3(_STAGE,self)


def prepare_owner_material_source_storage_v3(runtime,db,*,frame,request,installed_readers,scope,owner,guard,metadata,epoch):
    return PreparedOwnerMaterialWriteV3(_PREPARED,runtime,db,frame,request,installed_readers,
        scope,owner,guard,metadata,epoch)


class StagedDomainOperationV3:
    """Same v1 business stage semantics, with an issued physical payload reference."""
    def __init__(self,issuer,prepared):
        if issuer is not _STAGE or prepared not in _PREPARATIONS or prepared.phase!='sealed':
            raise AuthorityUnavailable('actual fully sealed Owner Source stage required')
        from ..domains.d06 import D06DomainProvider
        from ..runtime_contracts import DomainProposal,DependencySet
        prepared.require_current()
        self.prepared=prepared
        frame=prepared.frame
        self.domain,self.operation_kind='d06','admit_owner_material_source_v1'
        self.namespace,self.activity_id=prepared.namespace,frame.envelope.identity.activity_id
        self.operation_id=prepared.operation_id
        self.request_digest=prepared.expected['stage_request'][0]
        self.read_versions,self.query_coverage=frame.snapshot.versions,frame.query_coverage
        provider=D06DomainProvider()
        source_write=SealedSourceGraphWriteV3(_SEAL,prepared,prepared.seals['source']).take_write_v3()
        dependencies=DependencySet(current_invalidation=tuple(v for v in frame.snapshot.versions if v.key==prepared.source_key))
        self.proposals=(DomainProposal('d06','d06.proposal.v1',provider.descriptor.request_schema_hash,
            frame.envelope,(source_write,prepared.access_write),dependencies,(),()),)
        self.jobs,self.outbox,self.paid_cost_originals=(),(),()
        self.coverage,self.missing_inputs,self.continuation_ref='complete',(),None
        seal=prepared.seals['original']
        self.original_digest=prepared.expected['original'][0]
        self.original_payload_ref=DomainOriginalPayloadRefV3(seal.cell_id,self.original_digest,
            prepared.expected['original'][1],prepared.prepared_digest)
        self.schema='sylanne.domain-production-physical-stage.v3'


def require_owner_material_sealed_stage_v3(stage,runtime,db,*,frame,request,scope,installed_readers):
    from .owner_material_source_v1 import validated_owner_material_source_v1
    if type(stage) is not StagedDomainOperationV3 or stage.prepared not in _PREPARATIONS:
        raise AuthorityUnavailable('actual issued Owner Source physical stage required')
    prepared=stage.prepared
    prepared.require_current()
    if (prepared.runtime is not runtime or prepared.db is not db or prepared.frame!=frame
            or prepared.request!=request or prepared.scope!=scope or not db.in_transaction):
        raise AuthorityUnavailable('sealed Source stage changed actual writer/frame/request/fence')
    source,access,source_key,access_key=validated_owner_material_source_v1(db,
        frame=frame,request=request,installed_readers=installed_readers)
    from .budget import get_budget_lease
    parent=get_budget_lease(db,frame.envelope.parent_budget_lease_ref)
    current_grant=installed_readers.issuer.current_budget_grant(db,parent.lease_id)
    prepared.command.require_original_root_v3(db,current_grant,parent)
    if (source!=prepared.source or access!=prepared.access or source_key!=prepared.source_key
            or access_key!=prepared.access_key or frame.snapshot.versions!=stage.read_versions):
        raise AuthorityUnavailable('actual Owner/source/access/readset changed before original W01 attach')
    actual=db.execute('SELECT request_digest,attempt_id,graph_revision,graph_epoch,permit_json '
        'FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*prepared.namespace.as_tuple,prepared.operation_id)).fetchone()
    if actual!=prepared.attempt[:5]:
        raise AuthorityUnavailable('actual Owner Source signed attempt changed before attach')
    for name in prepared.names:
        seal=prepared.seals[name]
        seal.require_current(prepared,name)
        actual=db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?',(seal.cell_id,)).fetchone()
        if actual!=seal.header:
            raise AuthorityUnavailable('actual independently sealed Owner Source cell changed')
    return prepared


def source_graph_cell_ref_v3(write,db,*,revision,event_digest,scope_key,read_versions,epochs):
    holder=require_sealed_source_graph_write_v3(write)
    prepared=holder.prepared
    if (db is not prepared.db or not db.in_transaction or scope_key[3]!=prepared.operation_id
            or revision!=1 or tuple(read_versions)!=prepared.frame.snapshot.versions
            or tuple(epochs)!=(prepared.epoch,)):
        raise AuthorityUnavailable('Source cell attach changed its actual W01 operation/readset/revision')
    from ..contracts import Event,Scope
    expected_event=Event(Scope(*prepared.namespace.as_tuple,prepared.frame.envelope.identity.activity_id),
        prepared.operation_id,prepared.frame.envelope.source_qualification.learned_at,
        'domain_bundle',{'bundle_digest':prepared.expected['bundle'][0]})
    if scope_key!=(*prepared.namespace.as_tuple,prepared.frame.envelope.identity.activity_id,prepared.operation_id) or event_digest!=expected_event.digest:
        raise AuthorityUnavailable('Source sealed attachment changed its actual complete domain bundle event')
    seal=holder.seal
    actual=db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?',(seal.cell_id,)).fetchone()
    if actual!=seal.header:
        raise AuthorityUnavailable('actual Source sealed bytes are absent')
    return seal.cell_id


def finish_owner_source_preparation_v3(prepared,*,receipt=None,error=None):
    """Terminal dispositions never turn an unknown commit into an abort."""
    if prepared not in _PREPARATIONS or prepared.operation.closed:
        raise AuthorityUnavailable('actual retained Owner Source preparation required for terminal recovery')
    db=prepared.db
    saved=db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*prepared.namespace.as_tuple,prepared.operation_id)).fetchone()
    bundle=db.execute('SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*prepared.namespace.as_tuple,prepared.operation_id)).fetchone()
    if receipt is not None:
        if bundle is None:raise AuthorityUnavailable('Source terminal success lacks its actual W01 receipt')
        phase='committed'
    elif saved is None or saved[0] is not None or bundle is not None:
        raise AuthorityUnavailable('Source unknown COMMIT requires actual receipt/ref recovery before abort')
    elif error is not None:
        phase='aborted'
    else:
        raise AuthorityUnavailable('Source preparation has no real terminal disposition')
    if prepared.prepared_digest is None:
        if phase!='aborted':raise AuthorityUnavailable('unregistered preparation cannot have a committed receipt')
        prepared.phase='aborted'
        return
    cells=canonical_serialize({name:prepared._cell_id(name) for name in prepared.names})
    receipt_digest=None if receipt is None else canonical_digest(receipt)
    disposition=canonical_digest(dict(schema='d06.owner-source-disposition.v3',
        prepared_digest=prepared.prepared_digest,operation_id=prepared.operation_id,
        attempt_id=prepared.attempt[1],phase=phase,receipt_digest=receipt_digest,cell_ids=json.loads(cells)))
    with prepared._tx():
        prior=db.execute('SELECT operation_id,attempt_id,phase,receipt_digest,disposition_digest,cell_ids_json '
            'FROM graph_owner_source_dispositions_v3 WHERE prepared_digest=?',(prepared.prepared_digest,)).fetchone()
        content=(prepared.operation_id,prepared.attempt[1],phase,receipt_digest,disposition,cells)
        if prior is None:
            db.execute('INSERT INTO graph_owner_source_dispositions_v3 VALUES(?,?,?,?,?,?,?)',
                (prepared.prepared_digest,*content))
        elif prior!=content:
            raise AuthorityUnavailable('actual Owner Source terminal disposition replay differs')
        db.execute('UPDATE graph_owner_source_prepared_v3 SET phase=? WHERE prepared_digest=?',
            (phase,prepared.prepared_digest))
        db.execute('UPDATE segmented_cell_writes_v1 SET phase=?,cursor_revision=cursor_revision+1 '
            'WHERE origin_scope_digest=?',(phase,prepared.prepared_digest))
    prepared.phase=phase


def read_selected_owner_source_cell_v3(db,*,basis,cell_id,header,meter):
    """Pure cold producer qualification; pending never becomes ordinary read authority."""
    from ..runtime_contracts import NamespaceId,namespace_ref
    from ..graph_types import AtomKey
    columns=('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json',
        'input_sha256','input_bytes','original_digest','original_bytes','source_sha256','source_bytes','phase')
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_owner_source_prepared_v3'").fetchone()
    if exists is None:return None
    row=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_prepared_v3',columns,
        'prepared_digest=?',(header[7],))
    if row is None:return None
    value=json.loads(row[6]);ns=NamespaceId(row[1],row[2])
    cursor=_runtime_bounded_fixed_row_v3(db,meter,'segmented_cell_writes_v1',
        ('origin_scope_digest','logical_locator_json','producer_operation_id','erasure_owner_ref','phase',
         'next_ordinal','next_byte_offset','prefix_root','prefix_sha256','expected_total_bytes',
         'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256'),
        'cell_id=?',(cell_id,))
    attempt=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,row[3]))
    bundle=_runtime_bounded_fixed_row_v3(db,meter,'graph_bundle_operations',
        ('digest','activity_id','effect_id','commit_seq','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,row[3]))
    original=history=event=None
    if bundle is not None:
        original=_runtime_bounded_fixed_row_v3(db,meter,'graph_domain_production_originals_v3',
            ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest','bundle_digest'),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,row[3]))
        key=AtomKey.from_token(value['source_ref'])
        history=_runtime_bounded_fixed_row_v3(db,meter,'graph_history',
            ('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=1',(key.token,))
        event=_runtime_bounded_fixed_row_v3(db,meter,'graph_events',('digest','reads','epoch_reads'),
            'bot=? AND persona=? AND session=? AND event_id=?',(*ns.as_tuple,bundle[1],row[3]))
    return _qualify_owner_source_cell_values_v3(row,cursor,attempt,bundle,original,history,event,
        cell_id=cell_id,header=header,authority_id=basis.control.authority_id,
        installation_id=basis.control.installation_id,authority_namespace=basis.prepared['namespace'])


_SELECTED_OWNER_STAGE_READS_V3=WeakSet()


class SelectedOwnerSourceStageReadV3:
    """Cold prefix verification of a real uncommitted Source staging cursor."""
    def __init__(self,issuer,db,basis,cell_id,cursor,prepared):
        if issuer is not _PREPARED:raise AuthorityUnavailable('actual selected staged Source reader required')
        self.db,self.basis,self.cell_id,self.cursor,self.prepared=db,basis,cell_id,cursor,prepared
        self.ordinal,self.offset=0,0;self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id));self.complete=False
        _SELECTED_OWNER_STAGE_READS_V3.add(self)

    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from .c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self) is not SelectedOwnerSourceStageReadV3 or self not in _SELECTED_OWNER_STAGE_READS_V3
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual private staged Source progress and Root quantum required')
        self.basis.require_current(meter=meter)
        result=copy(self);result.hash=self.hash.copy()
        _SELECTED_OWNER_STAGE_READS_V3.add(result)
        return result

    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        return (8192+getsizeof(self.cursor)+sum(getsizeof(value) for value in self.cursor)
            +getsizeof(self.prepared)+sum(getsizeof(value) for value in self.prepared))

    def advance(self,*,db,meter):
        from pathlib import Path
        import sqlite3
        self.basis.require_current(meter=meter)
        if type(db) is not sqlite3.Connection:
            raise AuthorityUnavailable('actual selected cold SQLite snapshot required for pending Source')
        database=db.execute('PRAGMA database_list').fetchall()
        if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(self.basis.member('graph')['resolved_path']).resolve(strict=True):
            raise AuthorityUnavailable('pending Source continuation crossed its actual selected Graph inode/path')
        self.db=db
        columns=('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id',
            'erasure_owner_ref','phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256',
            'source_cursor_json','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset',
            'verify_prefix_root','verify_prefix_sha256','cursor_revision')
        actual=_runtime_bounded_fixed_row_v3(self.db,meter,'segmented_cell_writes_v1',columns,
            'cell_id=?',(self.cell_id,))
        if actual!=self.cursor:raise StaleRead('selected pending Source prefix cursor changed')
        if self.complete:return {'status':'complete','phase':self.cursor[6],
            'prepared_digest':self.cursor[1],'cell_id':self.cell_id,'prefix_sha256':self.hash.hexdigest()}
        if self.ordinal<self.cursor[7]:
            segment=_prepared_segment_v3(self.db,meter,self.cell_id,self.ordinal)
            if segment is None or segment[0]!=self.offset or sha256(segment[1]).hexdigest()!=segment[2]:
                raise AuthorityUnavailable('actual pending Source prefix segment offset/SHA differs')
            self.hash.update(segment[1])
            self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,
                self.ordinal,self.offset,len(segment[1]),segment[2]))
            self.ordinal+=1;self.offset+=len(segment[1]);return {'status':'progress'}
        extra=self.db.execute('SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
            (self.cell_id,self.ordinal)).fetchone();meter.charge_read(8 if extra else 0)
        if (extra is not None or self.offset!=self.cursor[8] or self.root!=self.cursor[9]
                or self.hash.hexdigest()!=self.cursor[10]):
            raise AuthorityUnavailable('actual pending Source prefix count/root/SHA/EOF differs')
        self.complete=True
        return {'status':'complete','phase':self.cursor[6],
            'prepared_digest':self.cursor[1],'cell_id':self.cell_id,'prefix_sha256':self.hash.hexdigest()}


def begin_selected_owner_source_stage_read_v3(db,*,selected_basis,cell_id,meter):
    """Actual private selected role + registered prepared producer, no business grant."""
    from pathlib import Path
    import sqlite3
    from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3,VerifiedSelectedHistoryReadV3
    from ..runtime_contracts import NamespaceId,namespace_ref
    basis=selected_basis.basis if type(selected_basis) is VerifiedSelectedHistoryReadV3 else selected_basis
    if type(basis) is not _InstalledSelectedStorageBasisV3 or type(db) is not sqlite3.Connection:
        raise AuthorityUnavailable('actual private selected staged Source cold basis/SQLite required')
    basis.require_current(meter=meter)
    database=db.execute('PRAGMA database_list').fetchall()
    if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(basis.member('graph')['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('pending Source cursor database differs from actual selected Graph')
    columns=('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id',
        'erasure_owner_ref','phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256',
        'source_cursor_json','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset',
        'verify_prefix_root','verify_prefix_sha256','cursor_revision')
    cursor=_runtime_bounded_fixed_row_v3(db,meter,'segmented_cell_writes_v1',columns,'cell_id=?',(cell_id,))
    if cursor is None:return None
    prepared=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_prepared_v3',
        ('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json','phase'),
        'prepared_digest=?',(cursor[1],))
    if prepared is None:return None
    value=json.loads(prepared[6]);locator=json.loads(cursor[2]);ns=NamespaceId(prepared[1],prepared[2])
    name=locator.get('name');expected=value['expected_outputs'].get(name)
    if (canonical_serialize(value)!=prepared[6] or canonical_digest(value)!=prepared[0]
            or value['schema']!='d06.owner-source-prepared.v3'
            or value['authority_id']!=basis.control.authority_id or value['installation_id']!=basis.control.installation_id
            or value['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id} or namespace_ref(ns)!=basis.prepared['namespace']
            or value['operation_kind']!='admit_owner_material_source_v1' or value['operation_id']!=prepared[3]
            or value['attempt_id']!=prepared[4] or value['request_claim_digest']!=prepared[5]
            or name not in ('input','source','original','stage_request','http_request','bundle') or expected is None
            or locator!={'schema':'d06.owner-source-cell-locator.v3','prepared_digest':prepared[0],
                'name':name,'source_ref':value['source_ref']} or canonical_serialize(locator)!=cursor[2]
            or cursor[3]!='canonical-json.ascii.v1' or cursor[4]!=prepared[3] or cursor[5]!=value['source_ref']
            or cursor[6] not in ('staging','sealed','committed','aborted')
            or not 0<=cursor[8]<=expected['total_bytes'] or cursor[12]!=expected['total_bytes']
            or not 0<=cursor[7]<=cursor[8] or cursor[-1]<0):
        raise AuthorityUnavailable('actual pending Source prepared scope/locator/finite prefix differs')
    identity=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=value['storage_instance'],
        prepared_digest=prepared[0],name=name,sha256=expected['payload_sha256']))
    if identity!=cell_id:raise AuthorityUnavailable('pending Source cursor changed its actual prepared descriptor')
    attempt=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch','permit_json'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,prepared[3]))
    if (attempt is None or attempt[:4]!=(prepared[5],prepared[4],value['graph_revision'],value['namespace_epoch']['revision'])
            or attempt[4] is None):
        raise AuthorityUnavailable('pending Source real Owner signed attempt is absent')
    return SelectedOwnerSourceStageReadV3(_PREPARED,db,basis,cell_id,cursor,prepared)


def release_owner_source_preparation_workspace_v3(prepared):
    """Terminal disposition is separate from dropping volatile Python references."""
    if prepared not in _PREPARATIONS or prepared.phase not in ('committed','aborted'):
        raise AuthorityUnavailable('actual terminal Owner Source producer required before workspace release')
    discard_owner_source_preparation_volatile_workspace_v3(prepared)


def discard_owner_source_preparation_volatile_workspace_v3(prepared):
    """Drop volatile memory after failure/unknown COMMIT; never change durable state."""
    if prepared not in _PREPARATIONS:
        raise AuthorityUnavailable('actual issued Owner Source producer workspace required')
    command=getattr(prepared,'command',None)
    if command in _COMMANDS:
        command.streams.clear();command.work=None;command.request=None
        command.owner_session_proof=None
    prepared.streams.clear();prepared.values.clear();prepared.verifiers.clear();prepared.cursors.clear()
    prepared.source_parser=None;prepared.source_fragment=None
    prepared.bundle_value=None;prepared.payload=None;prepared.source_value=None
    prepared.source=None;prepared.access=None;prepared.access_write=None
    prepared.readers=None;prepared.owner=None;prepared.guard=None
    prepared.frame=None;prepared.metadata_value=None;prepared.external_originals=()
    prepared.command=None;prepared.request=None
    prepared.seals.clear()


class OwnerMaterialCommandDigestV3:
    """Real initial action canonical digest Work; no effect before complete EOF."""
    def __init__(self,issuer,runtime,authority,owner_lease,request,operation_id,activity_id,audience_ref,parent_budget_lease_ref):
        from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
        from .owner_material_source_v1 import AdmitOwnerMaterialSourceRequestV1,OPERATION
        from ..graph_worker import require_graph_storage_work_admission_v3
        from ..graph_coordinator import OwnerLeaseBindingV1
        if issuer is not _COMMAND_ISSUER or type(runtime) is not InstalledDomainOperationRuntimeV1:
            raise AuthorityUnavailable('actual installed Owner material initial command producer required')
        graph=runtime.graph;self.ticket=require_graph_storage_work_admission_v3(graph)
        binding=graph._GraphCoordinator__owner_leases.get(owner_lease)
        proof=graph._GraphCoordinator__owner_session_proofs.get(owner_lease)
        if (type(request) is not AdmitOwnerMaterialSourceRequestV1 or type(binding) is not OwnerLeaseBindingV1
                or proof is None or binding.namespace!=authority.namespace or binding.actor!=authority.actor
                or 'workbench.create' not in binding.capabilities or audience_ref!='owner'):
            raise AuthorityUnavailable('actual registered Owner material session/action binding required')
        self.runtime,self.authority,self.owner_lease,self.request=runtime,authority,owner_lease,request
        self.operation_id,self.activity_id,self.audience_ref=operation_id,activity_id,audience_ref
        self.parent_budget_lease_ref=parent_budget_lease_ref
        self.handle=runtime_storage_v3(graph._GraphCoordinator__store._db)
        if self.handle is None:raise AuthorityUnavailable('initial bounded Source digest requires actual selected storage')
        self.owner_binding,self.owner_session_proof=binding,proof
        command=('sylanne.domain-production-command.v1',authority.namespace,authority.actor,OPERATION,
            request,operation_id,activity_id,audience_ref,parent_budget_lease_ref)
        self.streams={'command':CanonicalValueStreamV3(_canonical_value(command,set())),
            'http_request':CanonicalValueStreamV3({'request':{'text':request.text}})}
        self.names=('command','http_request');self.index=0;self.expected={}
        self.operation=None;self.work=None;self.consumed=False;self.complete=False;self.initial_now_utc=None;self.deadline_utc=None
        self.monotonic_deadline=None
        _COMMANDS.add(self)

    def bind_operation_v3(self,operation,*,clock):
        from ..runtime_storage_v3 import _operation
        from .first_ingress_v2 import trusted_upper
        from .budget import get_budget_lease,require_budget_family_admissible
        from time import monotonic
        db=self.handle.db
        if self not in _COMMANDS or self.operation is not None or not db.in_transaction:
            raise AuthorityUnavailable('actual initial Source command can bind once in its Owner read snapshot')
        if _operation(self.handle) is not operation or operation.operation_id!=self.operation_id:
            raise AuthorityUnavailable('initial Source digest crossed actual retained operation')
        graph=self.runtime.graph
        if (graph._GraphCoordinator__owner_leases.get(self.owner_lease) is not self.owner_binding
                or graph._GraphCoordinator__owner_session_proofs.get(self.owner_lease)!=self.owner_session_proof):
            raise AuthorityUnavailable('initial Source command changed actual Owner session binding')
        now=trusted_upper(clock)
        budget=get_budget_lease(db,self.parent_budget_lease_ref)
        require_budget_family_admissible(db,budget.lease_id)
        grant=graph._GraphCoordinator__d11_issuer.current_budget_grant(db,self.parent_budget_lease_ref)
        if (budget.state!='active' or grant.valid_until_utc<=now
                or (grant.bot_id,grant.persona_id)!=self.authority.namespace.as_tuple):
            raise AuthorityUnavailable('initial Source digest lacks actual original active Root budget')
        self.operation=operation;operation.retain(262144)
        self.root_grant=grant;self.root_grant_digest=canonical_digest(grant)
        self.budget_scope=(budget.lease_id,budget.parent_id,budget.bot_id,budget.persona_id,
            budget.currency,dict(budget.limits),budget.state)
        self.initial_now_utc=now;self.deadline_utc=min(now+60.0,grant.valid_until_utc)
        self.monotonic_deadline=monotonic()+self.deadline_utc-now
        self.seed=None;self.seed_digest=None
        meter=__import__(__package__+'.c09_paged_sql_v2',fromlist=['current_c09_sql_meter_v2']).current_c09_sql_meter_v2()
        seed=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_command_seeds_v3',
            ('attempt_id','request_digest','seed_digest','payload_json'),
            'bot=? AND persona=? AND operation_id=?',(*self.authority.namespace.as_tuple,self.operation_id))
        attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',('request_digest','attempt_id'),
            'bot=? AND persona=? AND operation_id=?',(*self.authority.namespace.as_tuple,self.operation_id))
        if attempt is not None and seed is None:
            raise AuthorityUnavailable('original Owner Source attempt has no immutable command deadline seed; cannot renew')
        if seed is not None:
            value=json.loads(seed[3]);self._require_seed_identity_v3(value)
            if (canonical_serialize(value)!=seed[3] or canonical_digest(value)!=seed[2]
                    or attempt!=(seed[1],seed[0]) or value['attempt_id']!=seed[0]
                    or value['request_digest']!=seed[1]):
                raise AuthorityUnavailable('original Owner Source command seed/attempt exact bytes differ')
            self.seed,self.seed_digest=value,seed[2]
            self.initial_now_utc=value['initial_now_utc'];self.deadline_utc=value['deadline_utc']
            if now>=self.deadline_utc:raise AuthorityUnavailable('original Owner Source seeded deadline expired')
            self.monotonic_deadline=value['monotonic_deadline'] if value['process_id']==_PROCESS_ID_V3 else monotonic()+self.deadline_utc-now

    def _require_seed_identity_v3(self,value):
        from ..domains.d01.production_operations_v1 import plain_v1
        expected=dict(schema='d06.owner-source-command-seed.v3',
            authority_id=self.handle.selected.basis.control.authority_id,
            installation_id=self.handle.selected.basis.control.installation_id,
            namespace=plain_v1(self.authority.namespace),actor=self.authority.actor,
            operation_kind='admit_owner_material_source_v1',operation_id=self.operation_id,
            activity_id=self.activity_id,audience_ref=self.audience_ref,parent_budget_lease_ref=self.parent_budget_lease_ref,
            root_grant_digest=self.root_grant_digest,root_grant=plain_v1(self.root_grant),
            budget_scope=plain_v1(self.budget_scope),owner_session_digest=canonical_digest(self.owner_session_proof),
            selection_digest=self.handle.selection_digest,storage_instance=self.handle.instance)
        if any(value.get(key)!=item for key,item in expected.items()):
            raise AuthorityUnavailable('original Owner Source seed changed Root/session/selection/command identity')
        if not value['initial_now_utc']<value['deadline_utc']<=self.root_grant.valid_until_utc:
            raise AuthorityUnavailable('original Source seed exceeds its original signed Root deadline')

    def persist_command_seed_in_transaction_v3(self,db,*,attempt_id,request_digest,metadata,epoch,anchor):
        from ..domains.d01.production_operations_v1 import plain_v1
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if (self not in _COMMANDS or not self.complete or not self.consumed or self.work is None
                or not db.in_transaction or db is not self.handle.db or _operation(self.handle) is not self.operation
                or request_digest!=self.expected['command'][0]):
            raise AuthorityUnavailable('first Source seed needs its actual once-consumed Owner attempt transaction')
        actual=db.execute('SELECT request_digest,attempt_id,graph_revision,graph_epoch FROM graph_owner_domain_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?',(*self.authority.namespace.as_tuple,self.operation_id)).fetchone()
        if actual!=(request_digest,attempt_id,metadata.graph_revision,epoch.revision):
            raise AuthorityUnavailable('Source seed does not bind actual first same-transaction Owner attempt')
        value=plain_v1(dict(schema='d06.owner-source-command-seed.v3',
            authority_id=self.handle.selected.basis.control.authority_id,
            installation_id=self.handle.selected.basis.control.installation_id,namespace=self.authority.namespace,
            actor=self.authority.actor,operation_kind='admit_owner_material_source_v1',operation_id=self.operation_id,
            activity_id=self.activity_id,audience_ref=self.audience_ref,parent_budget_lease_ref=self.parent_budget_lease_ref,
            root_grant_digest=self.root_grant_digest,root_grant=self.root_grant,budget_scope=self.budget_scope,
            owner_session_digest=canonical_digest(self.owner_session_proof),selection_digest=self.handle.selection_digest,
            storage_instance=self.handle.instance,attempt_id=attempt_id,request_digest=request_digest,
            initial_now_utc=self.initial_now_utc,deadline_utc=self.deadline_utc,
            monotonic_deadline=self.monotonic_deadline,process_id=_PROCESS_ID_V3,
            graph_revision=metadata.graph_revision,namespace_epoch=epoch,anchor=anchor))
        self._require_seed_identity_v3(value)
        encoded=canonical_serialize(value);digest=canonical_digest(value)
        meter=current_c09_sql_meter_v2();meter.charge_write(len(encoded)+2048)
        prior=meter.read_fixed_row(db,'graph_owner_source_command_seeds_v3',('attempt_id','request_digest','seed_digest','payload_json'),
            'bot=? AND persona=? AND operation_id=?',(*self.authority.namespace.as_tuple,self.operation_id))
        if prior is None:
            db.execute('INSERT INTO graph_owner_source_command_seeds_v3 VALUES(?,?,?,?,?,?,?)',
                (*self.authority.namespace.as_tuple,self.operation_id,attempt_id,request_digest,digest,encoded))
        elif prior!=(attempt_id,request_digest,digest,encoded):
            raise AuthorityUnavailable('Source original command seed cannot be replaced on reentry')
        self.seed,self.seed_digest=value,digest

    def bind_work_v3(self,work):
        from ..graph_worker import GraphStorageWorkV3,require_graph_storage_work_admission_v3
        if (self not in _COMMANDS or self.work is not None or type(work) is not GraphStorageWorkV3
                or work.coordinator is not self.runtime.graph or work.operation is not self.operation
                or work.selection_digest!=self.handle.selection_digest or work.operation_id!=self.operation_id
                or work.kind!='owner_material_source_write_v3'
                or require_graph_storage_work_admission_v3(self.runtime.graph)!=self.ticket):
            raise AuthorityUnavailable('initial Source canonical EOF must belong to the same actual worker Work')
        work._require_invocation(self.runtime.graph,initial=True)
        self.work=work

    def require_command_seed_v3(self,db,attempt_id,request_digest):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self.seed is None or self.seed_digest is None:
            raise AuthorityUnavailable('actual first Owner Source command seed was not atomically persisted')
        row=_runtime_bounded_fixed_row_v3(db,current_c09_sql_meter_v2(),'graph_owner_source_command_seeds_v3',
            ('attempt_id','request_digest','seed_digest','payload_json'),
            'bot=? AND persona=? AND operation_id=?',(*self.authority.namespace.as_tuple,self.operation_id))
        if row!=(attempt_id,request_digest,self.seed_digest,canonical_serialize(self.seed)):
            raise AuthorityUnavailable('Source preparation changed its immutable original attempt/clock seed')
        return self.seed_digest

    def require_original_root_v3(self,db,grant,budget):
        if (self not in _COMMANDS or self.operation is None or self.operation.closed or db is not self.handle.db
                or grant!=self.root_grant or canonical_digest(grant)!=self.root_grant_digest
                or (budget.lease_id,budget.parent_id,budget.bot_id,budget.persona_id,
                    budget.currency,dict(budget.limits),budget.state)!=self.budget_scope):
            raise AuthorityUnavailable('initial Owner Source original signed Root/scope changed during continuation')

    def advance(self):
        from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
        from .first_ingress_v2 import trusted_upper
        if self not in _COMMANDS or self.operation is None or self.operation.closed or self.work is None:
            raise AuthorityUnavailable('actual initial retained Owner Source command Work required')
        self.work._require_invocation(self.runtime.graph)
        graph=self.runtime.graph
        clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        if trusted_upper(clock)>=self.deadline_utc:
            raise AuthorityUnavailable('initial Owner Source original command deadline expired')
        if not self.complete:
            with bind_runtime_storage_operation_v3(self.operation,self.handle.db),runtime_storage_quantum_v3(self.handle.db) as meter:
                name=self.names[self.index];stream=self.streams[name]
                if stream.read_fragment(meter) is None:
                    self.expected[name]=(stream.hash.hexdigest(),stream.offset);self.index+=1
                    self.complete=self.index==len(self.names)
        return {'status':'complete' if self.complete else 'progress','phase':'command_digest'}

    def input_witness_v3(self):
        return OwnerMaterialInputWitnessV3(_INPUT_WITNESS,self)


def prepare_owner_material_command_digest_v3(runtime,authority,owner_lease,*,request,
        operation_id,activity_id,audience_ref,parent_budget_lease_ref):
    return OwnerMaterialCommandDigestV3(_COMMAND_ISSUER,runtime,authority,owner_lease,request,
        operation_id,activity_id,audience_ref,parent_budget_lease_ref)


def require_owner_material_command_digest_v3(command,runtime,authority,owner_lease,*,request,
        operation_id,activity_id,audience_ref,parent_budget_lease_ref,storage_work):
    if (type(command) is not OwnerMaterialCommandDigestV3 or command not in _COMMANDS or not command.complete
            or command.runtime is not runtime or command.authority is not authority or command.owner_lease is not owner_lease
            or command.request is not request or command.operation_id!=operation_id or command.activity_id!=activity_id
            or command.audience_ref!=audience_ref or command.parent_budget_lease_ref!=parent_budget_lease_ref
            or command.operation is None or command.operation.closed or command.consumed
            or command.work is not storage_work or storage_work.operation is not command.operation
            or storage_work.selection_digest!=command.handle.selection_digest):
        raise AuthorityUnavailable('Owner material canonical command EOF/witness identity differs')
    from ..graph_worker import require_graph_storage_work_admission_v3
    if require_graph_storage_work_admission_v3(runtime.graph)!=command.ticket:
        raise AuthorityUnavailable('Owner Source command witness crossed its original worker ticket')
    storage_work._require_invocation(runtime.graph)
    if command.seed is not None and command.seed['request_digest']!=command.expected['command'][0]:
        raise AuthorityUnavailable('Source reentry request changed its original seeded typed canonical digest')
    command.consumed=True
    return command.expected['command'][0]


def _qualified_owner_source_refusal_v3(encoded,*,metadata,permit_json):
    if encoded is None:return True
    raw=json.loads(encoded)
    expected={'schema','status','operation_id','attempt_id','request_digest','reason_code','permit_digest',
        'anchor_digest','graph_revision','graph_epoch'}
    return (type(raw) is dict and set(raw)==expected and canonical_serialize(raw)==encoded
        and raw['schema']=='sylanne.owner-domain-write-refusal.v3' and raw['status']=='held'
        and raw['operation_id']==metadata['operation_id'] and raw['attempt_id']==metadata['attempt_id']
        and raw['request_digest']==metadata['request_claim_digest']
        and raw['permit_digest']==canonical_digest(json.loads(permit_json))
        and raw['anchor_digest']==canonical_digest(metadata['pinned_anchor'])
        and raw['graph_revision']==metadata['graph_revision']
        and raw['graph_epoch']==metadata['namespace_epoch']['revision'])


def read_selected_owner_source_prepared_v3(db,*,basis,prepared_digest,meter):
    """Qualified real prepared row, including entries with no attached header."""
    from pathlib import Path
    import sqlite3
    from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    from ..runtime_contracts import NamespaceId,namespace_ref
    if type(basis) is not _InstalledSelectedStorageBasisV3 or type(db) is not sqlite3.Connection:
        raise AuthorityUnavailable('actual private selected Graph prepared original reader required')
    basis.require_current(meter=meter)
    database=db.execute('PRAGMA database_list').fetchall()
    if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(basis.member('graph')['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('prepared Source point read crossed actual selected Graph')
    row=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_prepared_v3',
        ('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json',
         'input_sha256','input_bytes','original_digest','original_bytes','source_sha256','source_bytes','phase'),
        'prepared_digest=?',(prepared_digest,))
    if row is None:return None
    ns=NamespaceId(row[1],row[2])
    seed=read_selected_owner_source_command_seed_v3(db,basis=basis,namespace=ns,operation_id=row[3],meter=meter)
    attempt=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,row[3]))
    bundle=meter.read_fixed_row(db,'graph_bundle_operations',('digest',),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,row[3]))
    return _qualify_owner_source_prepared_values_v3(row,seed,attempt,bundle,
        authority_id=basis.control.authority_id,installation_id=basis.control.installation_id,
        authority_namespace=basis.prepared['namespace'],prepared_digest=prepared_digest)


def read_selected_owner_source_disposition_v3(db,*,basis,prepared_digest,meter):
    prepared=read_selected_owner_source_prepared_v3(db,basis=basis,prepared_digest=prepared_digest,meter=meter)
    if prepared is None:raise AuthorityUnavailable('Source disposition lacks its actual prepared original')
    row=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_dispositions_v3',
        ('prepared_digest','operation_id','attempt_id','phase','receipt_digest','disposition_digest','cell_ids_json'),
        'prepared_digest=?',(prepared_digest,))
    if row is None:return None
    actual=None
    if row[3]=='committed':
        actual=meter.read_fixed_row(db,'graph_domain_production_originals_v3',('receipt_digest',),
            'bot=? AND persona=? AND operation_id=?',(*prepared['namespace'].as_tuple,row[1]))
    return _qualify_owner_source_disposition_values_v3(row,prepared,actual,prepared_digest=prepared_digest)


def read_selected_owner_source_command_seed_v3(db,*,basis,namespace,operation_id,meter):
    from pathlib import Path
    import sqlite3
    from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    from ..runtime_contracts import NamespaceId,namespace_ref
    if (type(basis) is not _InstalledSelectedStorageBasisV3 or type(db) is not sqlite3.Connection
            or type(namespace) is not NamespaceId or namespace_ref(namespace)!=basis.prepared['namespace']):
        raise AuthorityUnavailable('actual private selected Owner command-seed namespace required')
    basis.require_current(meter=meter)
    database=db.execute('PRAGMA database_list').fetchall()
    if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(basis.member('graph')['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('command seed point crossed actual selected Graph')
    row=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_source_command_seeds_v3',
        ('bot','persona','operation_id','attempt_id','request_digest','seed_digest','payload_json'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id))
    if row is None:return None
    value=json.loads(row[6])
    attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id))
    return _qualify_owner_source_command_seed_values_v3(row,attempt,
        authority_id=basis.control.authority_id,installation_id=basis.control.installation_id,
        namespace=namespace,operation_id=operation_id)

def _qualify_owner_source_command_seed_values_v3(row,attempt,*,authority_id,installation_id,namespace,operation_id):
    """Pure immutable seed semantics; callers establish their actual read authority."""
    if row is None:return None
    value=json.loads(row[6])
    if (canonical_serialize(value)!=row[6] or canonical_digest(value)!=row[5]
            or value['schema']!='d06.owner-source-command-seed.v3' or value['authority_id']!=authority_id
            or value['installation_id']!=installation_id
            or value['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
            or row[:3]!=(*namespace.as_tuple,operation_id) or value['operation_id']!=operation_id
            or value['operation_kind']!='admit_owner_material_source_v1'
            or value['attempt_id']!=row[3] or value['request_digest']!=row[4]
            or not value['initial_now_utc']<value['deadline_utc']<=value['root_grant']['valid_until_utc']):
        raise AuthorityUnavailable('actual Owner Source command-seed canonical scope/deadline binding differs')
    if attempt!=(row[4],row[3],value['graph_revision'],value['namespace_epoch']['revision']):
        raise AuthorityUnavailable('immutable Source command seed lacks actual original same-transaction Owner attempt')
    return {'row':row,'metadata':value}


def _qualify_owner_source_prepared_values_v3(row,qualified_seed,attempt,bundle,*,authority_id,installation_id,authority_namespace,prepared_digest):
    """Pure prepared/seed/attempt/bundle relations, without Source or selected capability."""
    from ..runtime_contracts import NamespaceId,namespace_ref
    from .owner_material_source_v1 import owner_material_source_id_v1
    from ..memory_types import source_key,access_key
    if row is None:return None
    seed=qualified_seed
    value=json.loads(row[6]);ns=NamespaceId(row[1],row[2]);outputs=value['expected_outputs']
    expected_names={'input','source','original','stage_request','http_request','bundle'}
    source_id=owner_material_source_id_v1(ns,row[3])
    if (canonical_serialize(value)!=row[6] or canonical_digest(value)!=row[0] or row[0]!=prepared_digest
            or value['schema']!='d06.owner-source-prepared.v3' or value['authority_id']!=authority_id
            or value['installation_id']!=installation_id or namespace_ref(ns)!=authority_namespace
            or value['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}
            or value['operation_kind']!='admit_owner_material_source_v1' or value['operation_id']!=row[3]
            or value['attempt_id']!=row[4] or value['request_claim_digest']!=row[5]
            or value['source_ref']!=source_key(*ns.as_tuple,source_id).token
            or value['access_ref']!=access_key(*ns.as_tuple,source_id).token or set(outputs)!=expected_names
            or row[7:9]!=(outputs['input']['payload_sha256'],outputs['input']['total_bytes'])
            or row[9:11]!=(outputs['original']['payload_sha256'],outputs['original']['total_bytes'])
            or row[11:13]!=(outputs['source']['payload_sha256'],outputs['source']['total_bytes'])
            or row[13] not in ('prepared','committed','aborted')
            or value['initial_parent_budget_digest']!=value['parent_budget_original_digest']):
        raise AuthorityUnavailable('actual prepared Source row canonical/scope/input/output/Root binding differs')
    if (seed is None or seed['row'][5]!=value['command_seed_digest']
            or seed['metadata']['root_grant_digest']!=value['initial_parent_budget_digest']
            or seed['metadata']['initial_now_utc']!=value['original_now_utc']
            or seed['metadata']['deadline_utc']!=value['original_deadline_utc']):
        raise AuthorityUnavailable('prepared Source changed its actual immutable original command clock/Root seed')
    for descriptor in outputs.values():
        if (set(descriptor)!={'payload_sha256','total_bytes'} or type(descriptor['total_bytes']) is not int
                or descriptor['total_bytes']<=0 or len(descriptor['payload_sha256'])!=64
                or any(char not in '0123456789abcdef' for char in descriptor['payload_sha256'])):
            raise AuthorityUnavailable('actual prepared Source fixed output descriptor differs')
    if (attempt is None or attempt[:4]!=(row[5],row[4],value['graph_revision'],value['namespace_epoch']['revision'])
            or attempt[4] is None):
        raise AuthorityUnavailable('actual prepared Source signed Owner attempt/fence differs')
    if bundle is not None and bundle!=(outputs['bundle']['payload_sha256'],):
        raise AuthorityUnavailable('prepared Source changed its actual adopted full typed bundle SHA')
    if row[13]=='committed' and bundle is None or row[13]=='aborted' and (bundle is not None or not _qualified_owner_source_refusal_v3(attempt[5],metadata=value,permit_json=attempt[4])):
        raise AuthorityUnavailable('prepared Source terminal phase contradicts actual receipt evidence')
    return {'row':row,'metadata':value,'phase':row[13],'namespace':ns,
        'actual_committed':bundle is not None,'operation_id':row[3]}


def _qualify_owner_source_disposition_values_v3(row,qualified_prepared,domain_receipt,*,prepared_digest):
    """Pure terminal evidence; expected original cell IDs remain immutable."""
    if row is None:return None
    prepared=qualified_prepared
    actual=domain_receipt
    metadata=prepared['metadata'];cells=json.loads(row[6])
    expected={name:canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=metadata['storage_instance'],
        prepared_digest=prepared_digest,name=name,sha256=descriptor['payload_sha256']))
        for name,descriptor in metadata['expected_outputs'].items()}
    digest=canonical_digest(dict(schema='d06.owner-source-disposition.v3',prepared_digest=prepared_digest,
        operation_id=row[1],attempt_id=row[2],phase=row[3],receipt_digest=row[4],cell_ids=cells))
    if (row[0]!=prepared_digest or row[1]!=prepared['operation_id'] or row[2]!=metadata['attempt_id']
            or row[3]!=prepared['phase'] or row[3] not in ('committed','aborted')
            or row[5]!=digest or canonical_serialize(cells)!=row[6] or cells!=expected):
        raise AuthorityUnavailable('Source terminal disposition exact canonical/attempt/cell binding differs')
    if row[3]=='committed':
        if actual!=(row[4],) or not prepared['actual_committed']:
            raise AuthorityUnavailable('Source committed disposition lacks its actual same-W01 receipt digest')
    elif row[4] is not None or prepared['actual_committed']:
        raise AuthorityUnavailable('Source aborted disposition contradicts actual W01 evidence')
    return {'row':row,'prepared':prepared}

def _qualify_owner_source_cell_values_v3(row,cursor,attempt,bundle,original,history,event,*,cell_id,header,authority_id,installation_id,authority_namespace):
    """Pure complete-cell provenance; Source/selected wrappers establish read capability."""
    from ..runtime_contracts import NamespaceId,namespace_ref
    from ..graph_types import AtomKey
    if row is None:return None
    value=json.loads(row[6]);ns=NamespaceId(row[1],row[2])
    if (canonical_serialize(value)!=row[6] or canonical_digest(value)!=row[0]
            or value['schema']!='d06.owner-source-prepared.v3'
            or value['authority_id']!=authority_id
            or value['installation_id']!=installation_id
            or value['namespace']!={'bot_id':row[1],'persona_id':row[2]}
            or namespace_ref(ns)!=authority_namespace
            or value['operation_kind']!='admit_owner_material_source_v1'
            or value['operation_id']!=row[3] or value['attempt_id']!=row[4]
            or value['request_claim_digest']!=row[5] or header[2]!=row[3]
            or header[1]!=value['source_ref']):
        raise AuthorityUnavailable('Owner Source actual prepared original scope/identity/canonical SHA differs')
    if cursor is None:raise AuthorityUnavailable('Owner Source cell lacks its actual registered cursor')
    locator=json.loads(cursor[1]);name=locator.get('name')
    if (canonical_serialize(locator)!=cursor[1] or locator!={'schema':'d06.owner-source-cell-locator.v3',
            'prepared_digest':row[0],'name':name,'source_ref':value['source_ref']}
            or name not in ('input','source','original','stage_request','http_request','bundle')
            or cursor[0]!=row[0] or cursor[2]!=row[3] or cursor[3]!=header[1]):
        raise AuthorityUnavailable('Owner Source actual immutable locator/cursor identity differs')
    expected=value['expected_outputs'][name]
    identity=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=value['storage_instance'],
        prepared_digest=row[0],name=name,sha256=expected['payload_sha256']))
    if (cell_id!=identity or header[0]!='canonical-json.ascii.v1'
            or (header[5],header[3])!=(expected['payload_sha256'],expected['total_bytes'])
            or cursor[5:9]!=(header[4],header[3],header[6],header[5])
            or cursor[9]!=header[3] or cursor[10:14]!=(header[4],header[3],header[6],header[5])
            or cursor[4] not in ('sealed','committed','aborted')):
        raise AuthorityUnavailable('Owner Source complete seal/cursor/header exact binding differs')
    if (attempt is None or attempt[:4]!=(row[5],row[4],value['graph_revision'],value['namespace_epoch']['revision'])
            or attempt[4] is None):
        raise AuthorityUnavailable('Owner Source real signed Owner attempt/fence is absent or differs')
    if bundle is None:
        if row[13]=='committed' or cursor[4]=='committed':
            raise AuthorityUnavailable('Owner Source committed phase lacks its actual W01 bundle')
        return {'producer_kind':'owner_material_source_prepared_v3','phase':row[13],
            'prepared_digest':row[0],'cell_name':name,'operation_id':row[3]}
    if bundle[0]!=value['expected_outputs']['bundle']['payload_sha256']:
        raise AuthorityUnavailable('Owner Source actual W01 bundle changed the exact typed canonical bytes')
    original_cell=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=value['storage_instance'],
        prepared_digest=row[0],name='original',sha256=value['expected_outputs']['original']['payload_sha256']))
    if original!=('d06','admit_owner_material_source_v1',row[9],original_cell,row[0],bundle[0]):
        raise AuthorityUnavailable('Owner Source actual adopted physical original/ref is absent or differs')
    key=AtomKey.from_token(value['source_ref'])
    source_cell=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=value['storage_instance'],
        prepared_digest=row[0],name='source',sha256=value['expected_outputs']['source']['payload_sha256']))
    if (history is None or history[0]!=source_cell or history[2:4]!=ns.as_tuple
            or history[4:6]!=(bundle[1],row[3])):
        raise AuthorityUnavailable('Owner Source actual first Graph history/event reference differs')
    from ..contracts import Event,Scope
    expected_event=Event(Scope(*ns.as_tuple,bundle[1]),row[3],
        value['envelope']['source_qualification']['learned_at'],'domain_bundle',{'bundle_digest':bundle[0]})
    expected_reads=canonical_serialize(sorted([[part['key'],part['revision']] for part in value['frame_snapshot_versions']]))
    expected_epochs=canonical_serialize([[ns.bot_id,ns.persona_id,value['namespace_epoch']['revision']]])
    if event is None or event!=(expected_event.digest,expected_reads,expected_epochs):
        raise AuthorityUnavailable('Owner Source committed Graph event/readset/epoch exact original differs')
    return {'producer_kind':'owner_material_source_prepared_v3','phase':'committed',
        'prepared_digest':row[0],'cell_name':name,'operation_id':row[3],'event_digest':event[0]}
