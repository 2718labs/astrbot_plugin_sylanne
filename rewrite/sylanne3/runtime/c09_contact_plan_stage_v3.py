"""Selected Graph physical Contact staging prefixes, never ordinary Source permission."""
from hashlib import sha256
from pathlib import Path
import json
from weakref import WeakSet
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId,namespace_ref
from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
from .contact_plan_physical_write_v3 import STREAM_TABLE,validate_contact_plan_stream_row_v3

_ISSUER=object()
_READERS=WeakSet()
_COLUMNS=('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref',
    'phase','next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
    'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision')
_STREAM_COLUMNS=('bot','persona','operation_id','request_digest','attempt_id','permit_digest','graph_revision',
    'graph_epoch','selection_digest','descriptor_json','phase')


class ContactPlanStagePrefixReadV3:
    def __init__(self,issuer,db,basis,cursor,stream,descriptor,meter):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('actual selected Contact physical prefix issuer required')
        self.db,self.basis,self.cursor,self.stream,self.descriptor=db,basis,tuple(cursor),tuple(stream),descriptor
        self.cell_id=self.cursor[0];self.ordinal=self.offset=0;self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id));self.complete=False
        _READERS.add(self)
        basis.control.register_c09_retained_state_v3(self)
        self.require_current(db,meter)
    def _source_heap_bytes(self):
        return 65536+sum(len(str(v).encode())for v in (*self.cursor,*self.stream))
    def _c09_retained_heap_bytes_v3(self):
        return self._source_heap_bytes()
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        self.require_current(self.db,meter)
        result=copy(self);result.hash=self.hash.copy()
        _READERS.add(result)
        self.basis.control.register_c09_retained_state_v3(result)
        self.basis.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=result._source_heap_bytes())
        return result
    def require_current(self,db,meter):
        if self not in _READERS or db is not self.db:
            raise AuthorityUnavailable('actual same selected Contact prefix required')
        self.basis.require_current(meter=meter)
        member=self.basis.member('graph')
        rows=db.execute('PRAGMA database_list').fetchall()
        if len(rows)!=1 or Path(rows[0][2]).resolve(strict=True)!=Path(member['resolved_path']).resolve(strict=True):
            raise AuthorityUnavailable('Contact prefix crossed its actual selected Graph connection')
        actual=_runtime_bounded_fixed_row_v3(db,meter,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(self.cell_id,))
        stored=_runtime_bounded_fixed_row_v3(db,meter,STREAM_TABLE,_STREAM_COLUMNS,
            'bot=? AND persona=? AND operation_id=?',self.stream[:3])
        if actual!=self.cursor or stored!=self.stream:
            raise AuthorityUnavailable('Contact selected physical prefix or original stream changed')
    def advance(self,*,db,meter):
        self.require_current(db,meter)
        if self.complete:
            return True
        if self.ordinal<self.cursor[7]:
            row=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                'cell_id=? AND ordinal=?',(self.cell_id,self.ordinal))
            if (row is None or row[0]!=self.offset or type(row[1]) is not bytes or not 0<len(row[1])<=16384
                    or sha256(row[1]).hexdigest()!=row[2]):
                raise AuthorityUnavailable('Contact selected physical prefix segment order/hash differs')
            self.hash.update(row[1]);self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,
                self.cell_id,self.ordinal,self.offset,len(row[1]),row[2]))
            self.ordinal+=1;self.offset+=len(row[1]);return False
        extra=meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal',(self.cell_id,self.ordinal))
        if extra is not None or (self.ordinal,self.offset,self.root,self.hash.hexdigest())!=self.cursor[7:11]:
            raise AuthorityUnavailable('Contact actual selected finite prefix full EOF differs')
        self.complete=True
        return True


def begin_selected_contact_plan_stage_read_v3(db,*,selected_basis,cell_id,meter):
    from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    if type(selected_basis) is not _InstalledSelectedStorageBasisV3:
        raise AuthorityUnavailable('actual installed selected Graph basis required for Contact prefix')
    selected_basis.require_current(meter=meter)
    cursor=_runtime_bounded_fixed_row_v3(db,meter,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(cell_id,))
    if cursor is None:
        return None
    locator=json.loads(cursor[2])
    if type(locator) is not dict or locator.get('schema')!='d10.contact-plan-cell-locator.v3':
        return None
    if set(locator)!={'schema','stream_ref','name','namespace','operation_id','owner_ref'}:
        raise AuthorityUnavailable('Contact selected stage locator exact fields differ')
    ns=NamespaceId(*locator['namespace'])
    if namespace_ref(ns)!=selected_basis.prepared['namespace']:
        raise AuthorityUnavailable('Contact selected prefix namespace differs')
    stream=_runtime_bounded_fixed_row_v3(db,meter,STREAM_TABLE,_STREAM_COLUMNS,
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,locator['operation_id']))
    if stream is None:
        raise AuthorityUnavailable('Contact selected prefix has no actual durable same-WRITE stream')
    descriptor=validate_contact_plan_stream_row_v3(_STREAM_COLUMNS,stream)
    cell=descriptor['cells'].get(locator['name'])
    if cell is None or cell['cell_id']!=cell_id or cell['origin'] is None:
        raise AuthorityUnavailable('Contact selected prefix is outside its actual original six-cell producer')
    origin=cell['origin'];origin_digest=canonical_digest(origin)
    instance=selected_basis.manifest['segmented_layouts']['graph']['storage_instance_id']
    expected=canonical_digest({'schema':'sylanne3.runtime-cell-identity.v3','instance':instance,
        'origin_digest':origin_digest,'locator':cell['locator'],'payload_sha256':cell['payload_sha256']})
    if (canonical_serialize(locator)!=cursor[2] or expected!=cell_id or cell['origin_digest']!=origin_digest
            or origin['operation_id']!=locator['operation_id'] or origin['namespace']!=locator['namespace']
            or origin['read_proof']['stream_ref']!=locator['stream_ref'] or cursor[1]!=locator['stream_ref']
            or cursor[3:6]!=('canonical-json.ascii.v1',locator['operation_id'],locator['owner_ref'])
            or cursor[12]!=cell['byte_count'] or cursor[7]<0 or not 0<=cursor[8]<=cursor[12]
            or cursor[6] not in ('staging','sealed','committed','aborted')):
        raise AuthorityUnavailable('Contact selected prefix actual identity/producer/locator/expected bytes differ')
    attempt=_runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',stream[:3])
    if (attempt is None or attempt[:4]!=(stream[3],stream[4],stream[6],stream[7]) or attempt[4] is None
            or canonical_digest(json.loads(attempt[4]))!=stream[5]):
        raise AuthorityUnavailable('Contact selected prefix has no actual original durable WRITE fence attempt')
    header=meter.read_fixed_row(db,'segmented_cells_v1',
        ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
            'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
    if header is None:
        if cursor[6] not in ('staging','sealed') or stream[10]=='committed' or attempt[5] is not None:
            raise AuthorityUnavailable('Contact uncommitted prefix contradicts actual original terminal evidence')
    elif (cursor[6]!='committed' or stream[10]!='committed' or attempt[5] is None
            or cursor[3:6]!=(header[1],header[3],header[2]) or cursor[7:11]!=(header[5],header[4],header[7],header[6])
            or cursor[12:17]!=(header[4],header[5],header[4],header[7],header[6])):
        raise AuthorityUnavailable('Contact selected complete cursor/header/actual COMMIT differs')
    return ContactPlanStagePrefixReadV3(_ISSUER,db,selected_basis,cursor,stream,descriptor,meter)


_FROZEN_READERS=WeakSet()

class FrozenContactPlanStagePrefixReadV3:
    """Actual Graph-role frozen Source prefix; complete means prefix EOF only."""
    def __init__(self,issuer,scope,cursor,stream,descriptor):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('Contact frozen prefix requires its exact actual Graph-role producer')
        self.scope,self.cursor,self.stream,self.descriptor=scope,tuple(cursor),tuple(stream),descriptor
        self.history_row=None;self.original_instance=None
        self.cell_id=self.cursor[0];self.ordinal=self.offset=0;self.hash=sha256()
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id));self.complete=False
        _FROZEN_READERS.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):
        return 65536+sum(len(str(v).encode())for v in (*self.cursor,*self.stream))
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        self.require_current(meter=meter)
        result=copy(self);result.hash=self.hash.copy()
        _FROZEN_READERS.add(result);self.scope.arena.add(result)
        return result
    def require_current(self,*,meter):
        from ..authority_service.c09_source_physical_read_v3 import SourcePhysicalReadScopeV3
        if self not in _FROZEN_READERS or type(self.scope)is not SourcePhysicalReadScopeV3:
            raise AuthorityUnavailable('Contact frozen prefix lost its actual C09 Source issuer')
        self.scope.require_current(meter=meter)
        if self.scope.role!='graph' or self.scope.source_original is not self.scope.pair.source_original:
            raise AuthorityUnavailable('Contact prefix cannot borrow Owner-only or another Source-role selection')
    def advance(self,meter):
        result=self.copy_for_c09_quantum_v3(meter=meter)
        with self.scope.read_database_v3(meter=meter)as db:
            actual=meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(self.cell_id,))
            stream=meter.read_fixed_row(db,STREAM_TABLE,_STREAM_COLUMNS,'bot=? AND persona=? AND operation_id=?',self.stream[:3])
            if self.history_row is not None:
                from .c09_contact_plan_prefix_history_v3 import require_contact_prefix_source_history_v3
                require_contact_prefix_source_history_v3(self.scope,db,self.cursor,meter,expected_row=self.history_row)
                matches=actual==self.cursor
            else:matches=actual==self.cursor and stream==self.stream
            if not matches:
                raise AuthorityUnavailable('Contact frozen prefix/cause changed before full prefix EOF')
            if self.ordinal<self.cursor[7]:
                row=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                    'cell_id=? AND ordinal=?',(self.cell_id,self.ordinal))
                if row is None or row[0]!=self.offset or type(row[1])is not bytes or not 0<len(row[1])<=16384 or sha256(row[1]).hexdigest()!=row[2]:
                    raise AuthorityUnavailable('Contact frozen prefix segment/order/hash differs')
                result.hash.update(row[1]);result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,
                    self.cell_id,self.ordinal,self.offset,len(row[1]),row[2]))
                result.ordinal+=1;result.offset+=len(row[1])
            else:
                extra=meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),
                    'cell_id=? AND ordinal>=? ORDER BY ordinal',(self.cell_id,self.ordinal))
                if extra is not None or (self.ordinal,self.offset,self.root,self.hash.hexdigest())!=self.cursor[7:11]:
                    raise AuthorityUnavailable('Contact frozen prefix actual byte/count/root/SHA/extra EOF differs')
                result.complete=True
        return result


def begin_frozen_contact_plan_stage_prefix_v3(scope,cursor,*,meter):
    from ..authority_service.c09_source_physical_read_v3 import SourcePhysicalReadScopeV3
    from ..segmented_sql_cell_v1 import DDLS
    if type(scope)is not SourcePhysicalReadScopeV3:
        raise AuthorityUnavailable('Contact frozen prefix requires its actual installed SourcePhysicalReadScope')
    scope.require_current(meter=meter)
    if scope.role!='graph':
        raise AuthorityUnavailable('Contact frozen prefix requires actual Graph-role maintenance admission')
    locator=json.loads(cursor[2])
    if type(locator)is not dict or locator.get('schema')!='d10.contact-plan-cell-locator.v3':return None
    if set(locator)!={'schema','stream_ref','name','namespace','operation_id','owner_ref'} or tuple(locator['namespace'])!=tuple(json.loads(scope.session.scope.graph_namespace)):
        raise AuthorityUnavailable('Contact frozen prefix locator escaped actual admitted Graph namespace')
    from contextlib import nullcontext
    # The actual selected-runtime census already owns this same Graph-role Source quantum.
    context=nullcontext(scope.source)if scope.source.in_transaction else scope.read_database_v3(meter=meter)
    with context as db:
        for table in ('segmented_storage_layout_v1','segmented_cells_v1','segmented_cell_segments_v1','segmented_cell_writes_v1'):
            if meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",(table,))!=(DDLS[table],):
                raise AuthorityUnavailable('Contact frozen prefix requires actual registered physical table shape')
        from .contact_plan_physical_write_v3 import STREAM_DDL
        if meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",(STREAM_TABLE,))!=(STREAM_DDL,):
            raise AuthorityUnavailable('Contact frozen prefix has no exact actual Contact stream producer schema')
        layout=meter.read_fixed_row(db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=1',())
        actual=meter.read_fixed_row(db,'segmented_cell_writes_v1',_COLUMNS,'cell_id=?',(cursor[0],))
        stream=meter.read_fixed_row(db,STREAM_TABLE,_STREAM_COLUMNS,
            'bot=? AND persona=? AND operation_id=?',(*locator['namespace'],locator['operation_id']))
        if layout is None or actual!=tuple(cursor):
            raise AuthorityUnavailable('Contact frozen prefix lacks its actual layout/current cursor')
        from .c09_contact_plan_prefix_history_v3 import require_contact_prefix_source_history_v3
        history=require_contact_prefix_source_history_v3(scope,db,tuple(cursor),meter)
        if history is not None:
            row,raw=history
            frozen_stream=tuple(raw['original_stream'])
            descriptor=validate_contact_plan_stream_row_v3(_STREAM_COLUMNS,frozen_stream)
            result=FrozenContactPlanStagePrefixReadV3(_ISSUER,scope,cursor,frozen_stream,descriptor)
            result.history_row,result.original_instance=row,raw['old_storage_instance']
            return result
        if stream is None:
            raise AuthorityUnavailable('Contact frozen prefix has no actual original WRITE stream or authenticated non-executable history')
        descriptor=validate_contact_plan_stream_row_v3(_STREAM_COLUMNS,stream)
        cell=descriptor['cells'].get(locator['name'])
        if cell is None or cell['origin']is None:
            raise AuthorityUnavailable('Contact prefix is outside its actual six-cell producer descriptor')
        origin=cell['origin'];digest=canonical_digest(origin)
        expected=canonical_digest({'schema':'sylanne3.runtime-cell-identity.v3','instance':layout[0],
            'origin_digest':digest,'locator':cell['locator'],'payload_sha256':cell['payload_sha256']})
        attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',
            ('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),
            'bot=? AND persona=? AND operation_id=?',stream[:3])
        header=meter.read_fixed_row(db,'segmented_cells_v1',('cell_id',),'cell_id=?',(cursor[0],))
        if (expected!=cursor[0] or cell['cell_id']!=cursor[0] or cell['origin_digest']!=digest
                or canonical_serialize(locator)!=cursor[2] or origin['operation_id']!=locator['operation_id']
                or tuple(origin['namespace'])!=tuple(locator['namespace'])
                or origin['read_proof']['stream_ref']!=locator['stream_ref'] or cursor[1]!=locator['stream_ref']
                or cursor[3:6]!=('canonical-json.ascii.v1',locator['operation_id'],locator['owner_ref'])
                or cursor[12]!=cell['byte_count'] or not 0<=cursor[8]<=cursor[12]
                or cursor[6]not in ('staging','sealed') or stream[10]not in ('preparing','sealed') or header is not None
                or attempt is None or attempt[:4]!=(stream[3],stream[4],stream[6],stream[7]) or attempt[4]is None or attempt[5]is not None
                or canonical_digest(json.loads(attempt[4]))!=stream[5]):
            raise AuthorityUnavailable('Contact frozen prefix is not its actual uncommitted original WRITE/instance/attempt')
    return FrozenContactPlanStagePrefixReadV3(_ISSUER,scope,cursor,stream,descriptor)
