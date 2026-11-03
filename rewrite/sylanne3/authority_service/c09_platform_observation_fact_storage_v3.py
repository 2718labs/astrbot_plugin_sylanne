"""Registered physical cells for the nine-column platform observation Fact."""
from __future__ import annotations
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize

TABLE='authority_platform_observation_facts_v3'
COLUMNS=('namespace','fact_operation_id','mutation_id','subject','request_digest','state',
    'pending','receipt','updated_fact_permit')
BLOB_COLUMNS=COLUMNS[6:]
CELL_COLUMNS=tuple(name+'_cell_id' for name in BLOB_COLUMNS)
PHYSICAL_COLUMNS=COLUMNS[:6]+CELL_COLUMNS
NATIVE_DDL="CREATE TABLE authority_platform_observation_facts_v3(\n    namespace TEXT NOT NULL, fact_operation_id TEXT PRIMARY KEY,\n    mutation_id TEXT NOT NULL UNIQUE, subject TEXT NOT NULL,\n    request_digest TEXT NOT NULL,\n    state TEXT NOT NULL CHECK(state IN ('pending','committed')),\n    pending BLOB NOT NULL, receipt BLOB, updated_fact_permit BLOB,\n    CHECK((state='pending' AND receipt IS NULL AND updated_fact_permit IS NULL)\n       OR (state='committed' AND receipt IS NOT NULL AND updated_fact_permit IS NOT NULL))\n) STRICT"
PHYSICAL_DDL="""CREATE TABLE authority_platform_observation_facts_v3(
    namespace TEXT NOT NULL, fact_operation_id TEXT PRIMARY KEY,
    mutation_id TEXT NOT NULL UNIQUE, subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    pending_cell_id TEXT NOT NULL REFERENCES segmented_cells_v1(cell_id),
    receipt_cell_id TEXT REFERENCES segmented_cells_v1(cell_id),
    updated_fact_permit_cell_id TEXT REFERENCES segmented_cells_v1(cell_id),
    CHECK((state='pending' AND receipt_cell_id IS NULL AND updated_fact_permit_cell_id IS NULL)
       OR (state='committed' AND receipt_cell_id IS NOT NULL AND updated_fact_permit_cell_id IS NOT NULL))
) STRICT"""
CODEC='canonical-json.utf8.v1'
PROFILE='sylanne3.platform-observation-fact-cells.v3'
FENCE_MARKER='platform_observation_refinement_cell_v3'


def fact_cell_owner_v3(namespace,operation_id):
    return canonical_serialize(('platform-observation-fact-v3',namespace,operation_id))


def fact_columns_v3(columns):
    return tuple(name+'_cell_id' if name in BLOB_COLUMNS else name for name in columns)


def fact_storage_schema_v3(db):
    from .c09_graph_application_v1 import c09_actual_root_read_v3
    row=c09_actual_root_read_v3(db).execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    if row not in ((NATIVE_DDL,),(PHYSICAL_DDL,)):
        raise AuthorityUnavailable('exact registered observation Fact physical schema required')
    return row[0]


def require_fact_cell_binding_v3(*,namespace,operation_id,column,header):
    if (column not in BLOB_COLUMNS or type(operation_id)is not str
            or not operation_id.startswith('observation-fact-v3:')
            or header[1]!=CODEC or header[2]!=fact_cell_owner_v3(namespace,operation_id)):
        raise AuthorityUnavailable('observation Fact cell codec/column/owner differs')
    return header


def fact_fence_marker_v3(pending,payload_sha256):
    from .observation_refinement_contract_v3 import PlatformObservationRefinementPendingV3
    if type(pending)is not PlatformObservationRefinementPendingV3:
        raise AuthorityUnavailable('actual typed Fact pending required')
    return dict(kind=FENCE_MARKER,schema=PROFILE,
        namespace=pending.fact_write_permit.namespace,
        fact_operation_id=pending.fact_write_permit.operation_id,
        mutation_id=pending.mutation_id,request_digest=pending.request_digest,
        pending_sha256=payload_sha256)


def fact_fence_bytes_v3(db,pending):
    """Exact marker only for this installed physical schema; legacy bytes stay native."""
    from .observation_refinement_contract_v3 import canonical_bytes
    from ..runtime_contracts import canonical_serialize
    if fact_storage_schema_v3(db)==NATIVE_DDL:return canonical_bytes(pending)
    row=db.execute('SELECT namespace,fact_operation_id,mutation_id,request_digest,pending_cell_id FROM '+TABLE+
        ' WHERE fact_operation_id=?',(pending.fact_write_permit.operation_id,)).fetchone()
    if row is None or row[:4]!=(pending.fact_write_permit.namespace,pending.fact_write_permit.operation_id,
            pending.mutation_id,pending.request_digest):
        raise AuthorityUnavailable('Fact fence marker lacks its actual pending row')
    header=db.execute('SELECT cell_id,codec_id,erasure_owner_ref,producer_operation_id,total_bytes,segment_count,'
        'payload_sha256,ordered_segment_root,origin_scope_digest FROM segmented_cells_v1 WHERE cell_id=?',
        (row[4],)).fetchone()
    if header is None:raise AuthorityUnavailable('Fact pending lacks its sealed header')
    require_fact_cell_binding_v3(namespace=row[0],operation_id=row[1],column='pending',header=header)
    return canonical_serialize(fact_fence_marker_v3(pending,header[6])).encode('utf-8')

class _FactUTF8StreamV3:
    """Use the registered canonical producer with exact native UTF-8 spelling."""
    @staticmethod
    def begin(value):
        from ..runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
        import json
        class Stream(CanonicalValueStreamV3):
            @staticmethod
            def _quoted(value,meter_getter=None):
                yield b'"'
                for offset in range(0,len(value),1024):
                    meter=None if meter_getter is None else meter_getter()
                    if meter is not None:meter.require_available(45056)
                    raw=json.dumps(value[offset:offset+1024],ensure_ascii=False,separators=(',',':')).encode('utf-8')[1:-1]
                    if meter is not None:meter.charge_encode(len(raw)*2+1024)
                    yield raw
                yield b'"'
        return Stream(value)


def _fact_runtime_v3(db):
    from ..runtime_storage_v3 import runtime_storage_v3,_operation,runtime_source_identity_v4
    handle=runtime_storage_v3(db)
    if handle is None or handle.role!='core' or not db.in_transaction:
        raise AuthorityUnavailable('actual Core Fact operation and transaction required')
    operation=_operation(handle)
    return handle,operation,runtime_source_identity_v4(handle)


def write_fact_cell_in_transaction_v3(db,*,pending,column,value):
    """Stage chunks and seal inside the caller's single business transaction."""
    from hashlib import sha256
    from ..runtime_contracts import canonical_digest,canonical_serialize
    from ..runtime.source_correction_read_v3 import _heap
    from .observation_refinement_contract_v3 import to_wire
    if column not in BLOB_COLUMNS:raise AuthorityUnavailable('registered Fact BLOB column required')
    handle,operation,identity=_fact_runtime_v3(db)
    permit=pending.fact_write_permit
    if permit.namespace!=identity.authority_namespace:
        raise AuthorityUnavailable('Fact writer namespace differs from current storage')
    operation.retain(_heap(value)*3+131072)
    wire=to_wire(value);stream=_FactUTF8StreamV3.begin(wire)
    while not stream.complete:
        with handle.quantum() as meter:stream.read_fragment(meter)
    digest,size=stream.hash.hexdigest(),stream.offset
    locator=dict(table=TABLE,primary_key=(permit.operation_id,),column=column)
    proof=dict(schema=PROFILE,namespace=permit.namespace,fact_operation_id=permit.operation_id,
        mutation_id=pending.mutation_id,subject=permit.subject,request_digest=pending.request_digest,
        column=column,payload_sha256=digest)
    origin=dict(schema='sylanne3.runtime-cell-origin.v3',selection_digest=handle.selection_digest,
        role='core',authority_id=identity.authority_id,installation_id=identity.installation_id,
        namespace=permit.namespace,operation_id=permit.operation_id,event_digest=digest,locator=locator,read_proof=proof)
    od=canonical_digest(origin)
    cell=canonical_digest(dict(schema='sylanne3.runtime-cell-identity.v3',instance=handle.instance,
        origin_digest=od,locator=locator,payload_sha256=digest))
    row=(od,handle.selection_digest,'core',identity.authority_id,identity.installation_id,
        canonical_serialize(permit.namespace),permit.operation_id,digest,canonical_serialize(locator),canonical_serialize(proof))
    with handle.quantum() as meter:
        prior=meter.read_fixed_row(db,'runtime_cell_origins_v3',tuple(('origin_digest','selection_digest','role','authority_id',
            'installation_id','namespace_json','operation_id','event_digest','locator_json','read_proof_json')),
            'origin_digest=?',(od,))
        if prior is None:
            meter.charge_write(sum(len(v.encode('utf-8'))for v in row))
            db.execute('INSERT INTO runtime_cell_origins_v3 VALUES(?,?,?,?,?,?,?,?,?,?)',row)
        elif prior!=row:raise AuthorityUnavailable('Fact cell immutable producer replay differs')
    stream=_FactUTF8StreamV3.begin(wire);ordinal=offset=0
    root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell))
    while not stream.complete:
        with handle.quantum() as meter:
            fragment=stream.read_fragment(meter)
            if fragment:
                h=sha256(fragment).hexdigest()
                prior=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                    'cell_id=? AND ordinal=?',(cell,ordinal))
                if prior is None:
                    meter.charge_write(len(fragment)+128)
                    db.execute('INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',(cell,ordinal,offset,fragment,h))
                elif prior!=(offset,fragment,h):raise AuthorityUnavailable('Fact cell chunk replay differs')
                root=canonical_digest(('sylanne3.segmented-cell-link.v1',root,cell,ordinal,offset,len(fragment),h))
                ordinal+=1;offset+=len(fragment)
    if (stream.hash.hexdigest(),offset)!=(digest,size):
        raise AuthorityUnavailable('Fact canonical second pass differs')
    header=(cell,CODEC,fact_cell_owner_v3(permit.namespace,permit.operation_id),permit.operation_id,size,ordinal,digest,root,od)
    with handle.quantum() as meter:
        prior=meter.read_fixed_row(db,'segmented_cells_v1',('cell_id','codec_id','erasure_owner_ref','producer_operation_id',
            'total_bytes','segment_count','payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell,))
        if prior is None:
            meter.charge_write(sum(len(v.encode('utf8'))if type(v)is str else 8 for v in header))
            db.execute('INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
        elif prior!=header:raise AuthorityUnavailable('Fact cell immutable header replay differs')
    # The actual row is attached by the DAO before ordinary read-back origin checks.
    return cell,digest


def read_fact_cell_v3(db,*,namespace,operation_id,column,cell_id):
    from ..runtime_storage_v3 import RuntimeCellReadV3,_CorePayloadDecodedJSONV3
    from .observation_refinement_contract_v3 import from_wire
    handle,operation,identity=_fact_runtime_v3(db)
    if namespace!=identity.authority_namespace:
        raise AuthorityUnavailable('Fact reader namespace differs from current storage')
    with handle.quantum() as meter:
        reader=RuntimeCellReadV3(handle,cell_id,erasure_owner_ref=fact_cell_owner_v3(namespace,operation_id),meter=meter)
    require_fact_cell_binding_v3(namespace=namespace,operation_id=operation_id,column=column,header=(cell_id,*reader.header))
    # The actual cell reader owns the same retained business operation.
    reader.operation=operation
    decoder=_CorePayloadDecodedJSONV3(reader,ensure_ascii=False)
    while reader.ordinal<reader.header[4]:
        with handle.quantum() as meter:
            raw=reader.read_fragment(meter=meter)
            decoder.feed_v3(raw);decoder.parser._emit_callback=None;meter.charge_encode(len(raw))
    with handle.quantum() as meter:
        reader.finish(meter=meter);parsed=decoder.finish_v3()
        if (parsed.sha256,parsed.byte_count)!=(reader.header[5],reader.header[3]):
            raise AuthorityUnavailable('Fact typed JSON and physical EOF differ')
    from ..runtime.source_correction_read_v3 import _heap
    operation.retain(_heap(decoder.value)*2)
    result=from_wire(decoder.value);decoder.release_payload_v3()
    return result


def fact_row_runtime_v3(db,mutation_id):
    """Return the unchanged nine logical values after actual cell EOF."""
    from ..runtime_storage_v3 import runtime_storage_operation_v3
    row=db.execute('SELECT '+','.join(PHYSICAL_COLUMNS)+' FROM '+TABLE+' WHERE mutation_id=?',(mutation_id,)).fetchone()
    if row is None:return None
    with runtime_storage_operation_v3(db,operation_id=row[1]):
        decoded=tuple(None if value is None else read_fact_cell_v3(db,namespace=row[0],operation_id=row[1],
            column=column,cell_id=value) for column,value in zip(BLOB_COLUMNS,row[6:]))
        # Decoder consumers accept typed values, avoiding an unbounded re-encode.
        return row[:6]+decoded


def verify_fact_runtime_origin_v3(db,*,identity,cell_id,header,original,meter):
    """Exact registered Fact column, actual row and physical commitment."""
    locator=original['locator'];proof=original['read_proof'];key=locator.get('primary_key')
    if (set(locator)!={'table','primary_key','column'} or locator['table']!=TABLE
            or type(key)not in(tuple,list) or len(key)!=1 or locator['column']not in BLOB_COLUMNS
            or set(proof)!={'schema','namespace','fact_operation_id','mutation_id','subject','request_digest','column','payload_sha256'}
            or proof['schema']!=PROFILE or proof['namespace']!=identity.authority_namespace
            or proof['fact_operation_id']!=key[0] or proof['mutation_id']!=key[0]
            or proof['column']!=locator['column'] or proof['payload_sha256']!=header[5]
            or original['event_digest']!=header[5] or original['operation_id']!=key[0]
            or original['namespace']!=proof['namespace']):
        raise AuthorityUnavailable('Fact runtime origin closed grammar differs')
    require_fact_cell_binding_v3(namespace=proof['namespace'],operation_id=key[0],
        column=locator['column'],header=(cell_id,*header))
    field=locator['column']+'_cell_id'
    actual=meter.read_fixed_row(db,TABLE,('namespace','fact_operation_id','mutation_id','subject','request_digest',field),
        'fact_operation_id=?',tuple(key))
    if actual!=(proof['namespace'],key[0],key[0],proof['subject'],proof['request_digest'],cell_id):
        raise AuthorityUnavailable('Fact cell lacks its actual nine-column producer row')
    return original

def insert_fact_pending_v3(db,pending):
    """Existing DAO calls after its WRITE-fence check, in the same Core TX."""
    from ..runtime_storage_v3 import runtime_storage_operation_v3
    p=pending.fact_write_permit
    with runtime_storage_operation_v3(db,operation_id=p.operation_id):
        cell,_=write_fact_cell_in_transaction_v3(db,pending=pending,column='pending',value=pending)
        db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,NULL,NULL)',
            (p.namespace,p.operation_id,pending.mutation_id,p.subject,pending.request_digest,'pending',cell))
        logical=fact_row_runtime_v3(db,pending.mutation_id)
        if logical!=(p.namespace,p.operation_id,pending.mutation_id,p.subject,pending.request_digest,'pending',pending,None,None):
            raise AuthorityUnavailable('new Fact pending lacks complete typed physical read-back')


def commit_fact_cells_v3(db,receipt,updated):
    from ..runtime_storage_v3 import runtime_storage_operation_v3
    p=receipt.pending
    with runtime_storage_operation_v3(db,operation_id=p.fact_write_permit.operation_id):
        before=fact_row_runtime_v3(db,p.mutation_id)
        if before is None or before[5:]!=('pending',p,None,None):
            raise AuthorityUnavailable('Fact commit no longer owns its exact pending original')
        rc,_=write_fact_cell_in_transaction_v3(db,pending=p,column='receipt',value=receipt)
        uc,_=write_fact_cell_in_transaction_v3(db,pending=p,column='updated_fact_permit',value=updated)
        changed=db.execute('UPDATE '+TABLE+
            " SET state='committed',receipt_cell_id=?,updated_fact_permit_cell_id=? WHERE mutation_id=? AND state='pending'",
            (rc,uc,p.mutation_id)).rowcount
        after=fact_row_runtime_v3(db,p.mutation_id)
        if changed!=1 or after is None or after[5:]!=('committed',p,receipt,updated):
            raise AuthorityUnavailable('committed Fact lacks complete three-cell typed read-back')
        return changed

class _FactMetadataJSONV3:
    @staticmethod
    def begin(owner):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from copy import copy,deepcopy
        class Parser(C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3):
            def __init__(self,owner):
                C09CanonicalJSONStreamV2.__init__(self,ensure_ascii=False)
                self.owner=owner;self._source_arena=owner.builder.session._source_parser_arena_v3
                self._initialize_json_value_v3(incremental_retention=False,frozen_object_type=None,frozen_array_type=None)
            def _reserve(self,extra=0):self.owner._require_arena(extra+65536)
            def _require_arena(self,extra=0):self.owner._require_arena(extra)
            def copy_for_v3(self,owner):
                base=C09CanonicalJSONStreamV2(ensure_ascii=False)
                for name in C09CanonicalJSONStreamV2.__slots__:setattr(base,name,getattr(self,name))
                cloned=base.copy();result=copy(self)
                for name in C09CanonicalJSONStreamV2.__slots__:setattr(result,name,getattr(cloned,name))
                result.owner=owner
                result.nodes,result.value,result.scalar=deepcopy((self.nodes,self.value,self.scalar));result.source_members=[]
                return result
        return Parser(owner)


class ActualFactSourceCaptureV3:
    """Complete frozen native/mapped Fact row, never a PendingMutation alias."""
    def __init__(self,builder,shape,key,*,meter):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        from ..runtime_contracts import canonical_digest
        from .c09_paged_recovery_facts_v2 import _read_one
        if (type(builder)is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core'
                or shape.table!=TABLE or shape.primary_key_columns!=('fact_operation_id',)
                or shape.primary_key_types!=('text',) or type(key)is not tuple or len(key)!=1):
            raise AuthorityUnavailable('actual registered Core Fact source capture required')
        builder.require_current()
        actual=_read_one(builder.pair.source,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,),meter)
        if actual not in ((NATIVE_DDL,),(PHYSICAL_DDL,)):
            raise AuthorityUnavailable('Fact frozen Source has an unregistered physical schema')
        self.builder,self.shape,self.key=builder,shape,key
        self.mapped=actual==(PHYSICAL_DDL,)
        if shape.columns!=(PHYSICAL_COLUMNS if self.mapped else COLUMNS):
            raise AuthorityUnavailable('Fact frozen Source exact column inventory differs')
        with legacy_cell_read_transaction_v2(builder.pair.source):
            self.identity=meter.read_fixed_row(builder.pair.source,TABLE,COLUMNS[:6],'fact_operation_id=?',key)
        if (self.identity is None or self.identity[0]!=builder.scope.authority_namespace
                or self.identity[1]!=key[0] or self.identity[2]!=key[0] or self.identity[5]!='committed'):
            raise AuthorityUnavailable('Fact source namespace/identity or committed state differs')
        self.source_scope=None;self.logical_shape=None;self.logical_reader=None;self.logical_original=None
        self.source_original=builder.pair.source_original
        if self.mapped:
            from ..runtime.c09_logical_source_v3 import read_c09_logical_source_shape_v3,begin_logical_source_row_v3
            self.source_scope=builder.session.begin_source_physical_read_v3(builder.pair,meter=meter)
            self.logical_shape=read_c09_logical_source_shape_v3(self.source_scope,TABLE,meter=meter)
            self.logical_reader=begin_logical_source_row_v3(self.source_scope,self.logical_shape,key,meter)
        self.phase='logical'if self.mapped else'column';self.index=0;self.offset=0;self.total=None
        self.parser=None;self.values={};self.typed={};self.hashes={};self.sizes={};self.cell_ids={}
        self.complete=False;self.quantum_completed=False
        from hashlib import sha256
        from . import c09_authority_storage_rebase as legacy
        self.row_hash=sha256(legacy._canonical((TABLE,COLUMNS))[:-1]+b',['+
            b','.join(legacy._canonical(legacy._cell(value))for value in self.identity))
        self.commitment=None
        builder.session._source_parser_arena_v3.add(self)
        self._require_arena()
    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        skip={'builder','source_scope','logical_reader','logical_shape','source_original'}
        parser=self.parser
        retained=()if parser is None else (parser.nodes,parser.value,parser.scalar,
            parser._stack,parser._string,parser._number,parser._literal)
        return 8192+_retained_size(({k:v for k,v in self.__dict__.items()if k not in skip|{'parser'}},retained),set())
    def _require_arena(self,extra=0):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter=current_c09_sql_meter_v2()
        if sum(value._source_heap_bytes()for value in self.builder.session._source_parser_arena_v3)+extra>meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('Fact frozen Source exceeds its actual retained arena')
    def copy(self):
        from copy import copy
        self._require_arena(self._source_heap_bytes());result=copy(self)
        result.values=dict(self.values);result.typed=dict(self.typed);result.hashes=dict(self.hashes);result.sizes=dict(self.sizes)
        result.cell_ids=dict(self.cell_ids);result.row_hash=None if self.row_hash is None else self.row_hash.copy()
        result.parser=None if self.parser is None else self.parser.copy_for_v3(result)
        result.quantum_completed=False;self.builder.session._source_parser_arena_v3.add(result)
        return result
    def advance(self,meter):
        from hashlib import sha256
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .observation_refinement_contract_v3 import from_wire,PlatformObservationRefinementPendingV3,PlatformObservationRefinementReceiptV3
        from .v2_contract import FencePermitV2
        from dataclasses import replace
        self.builder.require_current()
        if self.source_original!=self.builder.pair.source_original:
            raise AuthorityUnavailable('Fact frozen Core source identity changed')
        result=self.copy();db=self.builder.pair.source
        if result.phase=='logical':
            result.logical_reader=result.logical_reader.advance(meter)
            if result.logical_reader.complete:
                result.logical_original=result.logical_reader.result;result.phase='column'
        elif result.phase=='column':
            if result.index==3:result.phase='identity'
            else:
                column=BLOB_COLUMNS[result.index]
                if result.mapped:
                    field=CELL_COLUMNS[result.index]
                    row=meter.read_fixed_row(db,TABLE,(field,),'fact_operation_id=?',result.key)
                    if row is None or type(row[0])is not str:raise AuthorityUnavailable('committed Fact lacks its three actual cells')
                    header=result.source_scope.read_cell_header_v3(row[0],meter=meter)
                    require_fact_cell_binding_v3(namespace=result.identity[0],operation_id=result.key[0],column=column,header=header)
                    result.cell_ids[column]=row[0];result.total=header[4]
                else:
                    with legacy_cell_read_transaction_v2(db):
                        _,result.total,kind=read_legacy_sql_cell_fragment_v2(db,table=TABLE,column=column,
                            where='fact_operation_id=?',parameters=result.key,start=0,length=0,meter=meter)
                    if kind!='blob' or result.total<1:raise AuthorityUnavailable('committed Fact requires all three canonical BLOBs')
                result.offset=0;result.parser=_FactMetadataJSONV3.begin(result);result.phase='bytes'
                result.row_hash.update(b',["blob","')
        elif result.phase=='bytes':
            column=BLOB_COLUMNS[result.index];amount=min(4096,result.total-result.offset)
            if result.mapped:
                raw,total=result.source_scope.read_cell_fragment_v3(result.cell_ids[column],start=result.offset,length=amount,meter=meter)
            else:
                with legacy_cell_read_transaction_v2(db):
                    raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table=TABLE,column=column,
                        where='fact_operation_id=?',parameters=result.key,start=result.offset,length=amount,meter=meter)
                if kind!='blob':raise AuthorityUnavailable('Fact native BLOB kind changed')
            if total!=result.total or len(raw)!=amount:raise AuthorityUnavailable('Fact frozen complete cell bytes changed')
            result.parser.feed(raw,result.parser._emit);result.parser._emit_callback=None;result.offset+=amount
            meter.charge_encode(len(raw)*2);result.row_hash.update(raw.hex().encode('ascii'))
            if result.offset==result.total:
                eof=result.parser.finish()
                if (eof.byte_count!=result.total or result.mapped and eof.sha256!=result.source_scope.read_cell_header_v3(
                        result.cell_ids[column],meter=meter)[6]):
                    raise AuthorityUnavailable('Fact canonical EOF and actual cell SHA differ')
                from ..runtime.c09_logical_source_v3 import _retained_size
                result._require_arena(_retained_size(result.parser.value,set())*3)
                result.values[column]=result.parser.value;result.typed[column]=from_wire(result.parser.value)
                result.hashes[column]=eof.sha256;result.sizes[column]=eof.byte_count
                result.row_hash.update(b'\"]');result.index+=1;result.phase='column'
        else:
            p,r,u=(result.typed[name]for name in BLOB_COLUMNS)
            if (type(p)is not PlatformObservationRefinementPendingV3 or type(r)is not PlatformObservationRefinementReceiptV3
                    or type(u)is not FencePermitV2 or result.identity[:5]!=(p.fact_write_permit.namespace,
                        p.fact_write_permit.operation_id,p.mutation_id,p.fact_write_permit.subject,p.request_digest)
                    or r.pending!=p or u!=replace(p.fact_write_permit,revision=r.updated_revision,pinned_anchor=r.after_anchor)):
                raise AuthorityUnavailable('Fact source closed typed row/receipt identity differs')
            result.row_hash.update(b']]')
            result.commitment=result.row_hash.hexdigest()
            if result.mapped and result.commitment!=result.logical_original.logical_row_commitment:
                raise AuthorityUnavailable('Fact native-BLOB logical commitment differs from its complete mapped Source')
            result.complete=True
        result._require_arena();return result
    def require_complete(self,builder,shape,key):
        if (self.builder is not builder or self.shape!=shape or self.key!=tuple(key)
                or not self.complete or not self.quantum_completed or self.source_original!=builder.pair.source_original):
            raise AuthorityUnavailable('actual successfully completed Fact frozen Source required')
        builder.require_current();self._require_arena()
        return self.commitment
