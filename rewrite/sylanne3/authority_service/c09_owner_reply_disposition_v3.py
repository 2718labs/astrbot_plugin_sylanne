"""Exact post-mirror StopReply carrier commitments under the existing C09 root.

The caller passes a private prospective state and adopts it only after its real
reserved quantum exits successfully. No payload or new permission is retained.
"""
from copy import copy
import codecs

from .contract import AuthorityUnavailable
from ..runtime.c09_paged_sql_v2 import (
    _quote, _sql_scalar_size_v2, read_c09_table_shape_v2,
    begin_c09_row_commitment_v2, advance_c09_row_commitment_v2,
    require_c09_reserved_meter_v3, legacy_cell_read_transaction_v2,
)


def copy_owner_reply_disposition_state_v3(state):
    """Cursor advancement forks the selected entry, so other entries are immutable."""
    return dict(state)


def _metadata_v3(db, shape, key, point):
    where = ' AND '.join(_quote(name) + ' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    columns = ','.join('typeof(' + _quote(name) + '),length(CAST(' + _quote(name) + ' AS BLOB))'
        for name in shape.columns)
    sql = 'SELECT ' + columns + ' FROM ' + _quote(shape.table) + ' WHERE ' + where + ' LIMIT 1'
    point.charge_encode(len(sql.encode('utf-8')) + sum(_sql_scalar_size_v2(value) for value in key))
    row = db.execute(sql, key).fetchone()
    if row is None:
        return None
    point.charge_read(sum(_sql_scalar_size_v2(value) for value in row))
    metadata = tuple((row[index], row[index + 1]) for index in range(0, len(row), 2))
    if any(kind not in {'null', 'integer', 'real', 'text', 'blob'} for kind, _ in metadata):
        raise AuthorityUnavailable('StopReply carrier has an unregistered actual SQLite cell kind')
    return metadata


def _copy_cursor_v3(cursor):
    result = copy(cursor)
    result.row_hash = cursor.row_hash.copy()
    if cursor.blob_hash is not None:
        result.blob_hash = cursor.blob_hash.copy()
    if cursor.utf8 is not None:
        result.utf8 = codecs.getincrementaldecoder('utf-8')('strict')
        result.utf8.setstate(cursor.utf8.getstate())
    return result


def advance_owner_reply_graph_disposition_v3(basis, *, verified, shape, key, point, state):
    """Return the exact disposition, or None while this same carrier is streaming.

    ``state`` is owned by the real RoleBasis for one actual StopReply original.
    The outer builder must retain it through its normal successful-quantum
    pending/adopt path, and must not run the Core row transform until complete.
    A restart creates a new reader and starts the same original from byte zero.
    """
    basis.require_current()
    if verified is not basis.session.require_actual_post_mirror_graph_v3():
        raise AuthorityUnavailable('StopReply carrier lost its actual post-mirror verifier')
    verified.require_current()
    source, target = verified.pair.source, verified._read_db
    # Use the already reserved C09SqlByteMeterV2. The readonly point wrapper
    # borrows that root; replacing its ContextVar would create a false quantum.
    budget = point.budget
    actual = require_c09_reserved_meter_v3(budget)
    parent = point.parent
    if actual is not parent and actual is not getattr(parent, 'parent', None):
        raise AuthorityUnavailable('StopReply carrier point meter crossed the actual reserved root')
    key = tuple(key)
    if len(key) != len(shape.primary_key_columns):
        raise AuthorityUnavailable('StopReply carrier requires its complete original primary key')
    with legacy_cell_read_transaction_v2(source), legacy_cell_read_transaction_v2(target):
        if read_c09_table_shape_v2(source, shape.table, meter=point) != shape:
            raise AuthorityUnavailable('StopReply carrier Source shape changed')
        physical = shape.table == 'graph_domain_production_originals_v3' or (
            shape.table in {'graph_atoms', 'graph_history'} and 'value_cell_id' in shape.columns)
        if physical:
            # These physical rows contain cell references, not the JSON body;
            # retain the registered table+columns commitment and mapped proof.
            return basis._graph_disposition_key_v3(verified, shape, key, point)
        proof = basis._graph_disposition_original_v3(verified, shape, key, point)
        target_shape = read_c09_table_shape_v2(target, shape.table, meter=point)
        if (target_shape.primary_key_columns, target_shape.primary_key_types) != (
                shape.primary_key_columns, shape.primary_key_types):
            raise AuthorityUnavailable('StopReply carrier Target changed its Source primary key contract')
        source_metadata = _metadata_v3(source, shape, key, point)
        metadata = _metadata_v3(target, target_shape, key, point)
        if source_metadata is None:
            raise AuthorityUnavailable('StopReply original carrier disappeared from actual frozen Source')
        identity = (shape.table, key)
        prior = state.get(identity)
        binding = (verified, source, target, shape, target_shape, key, proof, source_metadata, metadata)
        if prior is not None and prior[0] != binding:
            raise AuthorityUnavailable('StopReply carrier continuation crossed its exact Source/Target original')
        source_cursor = (begin_c09_row_commitment_v2(source, shape, key, source_metadata)
            if prior is None else _copy_cursor_v3(prior[1]))
        target_cursor = None if prior is None else prior[2]
        if not source_cursor.complete:
            advance_c09_row_commitment_v2(source, shape, budget, cursor=source_cursor, meter=actual)
            if source_cursor.complete and source_cursor.commitment != proof.old_commitment:
                raise AuthorityUnavailable('StopReply full frozen Source commitment differs from sealed member')
            state[identity] = (binding, source_cursor, target_cursor)
            # Do not start another body in a quantum that advanced the Source.
            verified.require_current(); basis.require_current()
            return None
        if source_cursor.commitment != proof.old_commitment:
            raise AuthorityUnavailable('StopReply Source EOF lost its actual sealed member commitment')
        if proof.disposition == 'derived_removed':
            if metadata is not None:
                raise AuthorityUnavailable('removed StopReply carrier retained an actual Target row')
            state[identity] = (binding, source_cursor, None)
        else:
            if metadata is None:
                raise AuthorityUnavailable('retained StopReply carrier lost its actual Target row')
            cursor = (begin_c09_row_commitment_v2(target, target_shape, key, metadata)
                if target_cursor is None else _copy_cursor_v3(target_cursor))
            if not cursor.complete:
                advance_c09_row_commitment_v2(target, target_shape, budget, cursor=cursor, meter=actual)
            if cursor.complete and cursor.commitment != proof.new_commitment:
                raise AuthorityUnavailable('StopReply full streamed Target commitment differs from certified disposition')
            # Only the prospective state changes; failed outer quanta do not
            # adopt hashes, decoder state or an apparent EOF.
            state[identity] = (binding, source_cursor, cursor)
            if not cursor.complete:
                verified.require_current(); basis.require_current()
                return None
    verified.require_current(); basis.require_current()
    return proof


from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass
import sys
from hashlib import sha256
import json

from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import NamespaceId, CommitReceipt, canonical_digest, canonical_serialize
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

_CORE_TABLE_V3 = 'authority_d12_operation_originals_v1'
_JOB_META_V3 = ('job_id','operation_id','activity_id','effect_id','bot_id','persona_id',
    'phase','work_kind','deadline_utc','budget_ref','cancel_epoch')
_BORN_META_V3 = tuple(name for name in _JOB_META_V3 if name != 'effect_id')



def _metadata_heap_v3(value,seen=None):
    """Retained metadata only; installed capabilities are never traversed."""
    if seen is None:seen=set()
    if id(value) in seen:return 0
    seen.add(id(value));size=sys.getsizeof(value)
    if type(value) is dict:
        return size+sum(_metadata_heap_v3(key,seen)+_metadata_heap_v3(item,seen) for key,item in value.items())
    if type(value) in (tuple,list,set,frozenset):
        return size+sum(_metadata_heap_v3(item,seen) for item in value)
    if is_dataclass(value) and not isinstance(value,type):
        return size+sum(_metadata_heap_v3(getattr(value,field.name),seen) for field in fields(value))
    from types import SimpleNamespace
    if type(value) is SimpleNamespace:return size+_metadata_heap_v3(vars(value),seen)
    return size

class _OwnerReplyJSONReadV3:
    """Actual immutable JSON EOF; only fixed metadata subtrees are retained."""
    def __init__(self, owner, table, column, keys, key, *, paths=(), hashes=()):
        self.builder,self.verified = owner.builder,owner.verified
        self.table,self.column = table,column
        self.physical = None;self.physical_ordinal = 0;self.physical_root = None
        self.keys, self.key = tuple(keys), tuple(key)
        self.where = ' AND '.join(_quote(name)+'=?' for name in self.keys)
        self.paths, self.hash_paths = tuple(paths), tuple(hashes)
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.values, self.nodes, self.starts, self.spans = {}, {}, {}, {}
        self.scalar = bytearray(); self.length = None; self.header = None
        self.offset = 0; self.phase = 'scan'; self.hash_index = 0
        self.hash_offset = 0; self.hasher = None; self.hashes = {}
        self.complete = False; self.digest = None

    def copy(self):
        out = copy(self); out.parser = self.parser.copy()
        out.values, out.nodes, out.scalar = deepcopy((self.values,self.nodes,self.scalar))
        out.starts, out.spans, out.hashes = dict(self.starts),dict(self.spans),dict(self.hashes)
        out.hasher = None if self.hasher is None else self.hasher.copy()
        return out

    def _selected(self,path):
        return any(path[:len(root)] == root for root in self.paths)

    def _put(self,path,value):
        if path in self.paths:
            self.values[path] = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list:
                if path[-1] != len(parent):
                    raise AuthorityUnavailable('StopReply metadata array order differs')
                parent.append(value)
            else:
                parent[path[-1]] = value

    def _event(self,event):
        path = event.path
        if path in self.hash_paths:
            if event.kind in {'object_start','array_start','scalar_start'}:
                self.starts[path] = event.start_offset
            elif event.kind in {'object_end','array_end','scalar_end'}:
                self.spans[path] = (self.starts.pop(path),event.end_offset)
        if not self._selected(path):
            return
        if event.kind in {'object_start','array_start'}:
            value = {} if event.kind == 'object_start' else []
            self.nodes[path] = value; self._put(path,value)
        elif event.kind == 'scalar_start':
            self.scalar = bytearray()
        elif event.kind == 'scalar_chunk':
            self.scalar.extend(event.raw)
        elif event.kind == 'scalar_end':
            self._put(path,json.loads(self.scalar)); self.scalar = bytearray()

    def _read(self,start,amount,point):
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        graph = self.verified.pair.source
        if self.header is not None:
            scope = self.physical
            scope.require_current(meter=point.parent)
            raw,total = scope.read_cell_fragment_v3(self.header[0],start=start,length=amount,meter=point.parent)
        else:
            raw,total,kind = read_legacy_sql_cell_fragment_v2(graph,table=self.table,
                column=self.column,where=self.where,parameters=self.key,start=start,length=amount,meter=point)
            if kind != 'text':
                raise AuthorityUnavailable('StopReply actual metadata JSON is not TEXT')
        if self.length is not None and total != self.length or len(raw) != amount:
            raise AuthorityUnavailable('StopReply actual immutable JSON range changed')
        self.length = total
        return raw

    def advance(self,point):
        out = self.copy()
        graph = self.verified.pair.source
        if out.length is None:
            shape = read_c09_table_shape_v2(graph,out.table,meter=point)
            if out.column == 'value' and 'value_cell_id' in shape.columns:
                row = point.read_fixed_row(graph,out.table,('value_cell_id',),out.where,out.key)
                if row is None:
                    raise AuthorityUnavailable('StopReply physical JSON original disappeared')
                if out.physical is None:
                    out.physical = out.builder.session.begin_source_physical_read_v3(out.verified.pair,meter=point.parent)
                out.header = out.physical.read_cell_header_v3(row[0],meter=point.parent)
                if out.header[1] != 'canonical-json.ascii.v1' or out.header[2] != out.key[0]:
                    raise AuthorityUnavailable('StopReply physical metadata has another registered codec')
                out.length = out.header[4]
                out.physical_root = canonical_digest(('sylanne3.segmented-cell-genesis.v1',out.header[0]))
            else:
                out._read(0,0,point)
            return out
        if out.phase == 'scan':
            amount = min(1024,out.length-out.offset)
            if amount:
                if out.header is None:
                    raw = out._read(out.offset,amount,point)
                else:
                    segment = out.physical.read_cell_segment_v3(out.header[0],out.physical_ordinal,meter=point.parent)
                    if segment is None or segment[0] != out.offset:
                        raise AuthorityUnavailable('StopReply physical Source segment EOF/order differs')
                    raw = segment[1];amount = len(raw)
                    out.physical_root = canonical_digest(('sylanne3.segmented-cell-link.v1',out.physical_root,
                        out.header[0],out.physical_ordinal,out.offset,amount,segment[2]))
                    out.physical_ordinal += 1
                out.parser.feed(raw,out._event); out.parser._emit_callback = None
                out.offset += amount
                return out
            eof = out.parser.finish()
            if eof.byte_count != out.length or out.starts:
                raise AuthorityUnavailable('StopReply metadata did not reach its exact canonical EOF')
            if out.header is not None:
                out.physical.require_cell_eof_v3(out.header[0],out.physical_ordinal,meter=point.parent)
                if (out.physical_ordinal,out.offset,eof.sha256,out.physical_root) != (
                        out.header[5],out.header[4],out.header[6],out.header[7]):
                    raise AuthorityUnavailable('StopReply physical payload full EOF/SHA/ordered root differs')
            out.digest = eof.sha256
            out.phase = 'hash'
            return out
        if out.hash_index < len(out.hash_paths):
            path = out.hash_paths[out.hash_index]
            if path not in out.spans:
                raise AuthorityUnavailable('StopReply actual original omits its required commitment subtree')
            left,right = out.spans[path]
            if out.hasher is None:
                out.hasher = sha256()
            amount = min(1024,right-left-out.hash_offset)
            if amount:
                out.hasher.update(out._read(left+out.hash_offset,amount,point))
                out.hash_offset += amount
                return out
            out.hashes[path] = out.hasher.hexdigest()
            out.hasher = None; out.hash_offset = 0; out.hash_index += 1
            return out
        out.complete = True
        return out


class _OwnerReplyStopReadV3:
    """Private current proof issued by actual Core preflight and successful quanta."""
    def __init__(self,builder,shape,key,row,meter):
        from .owner_stop_reply_v1 import (validate_owner_stop_reply_core_row_v1,
            decode_owner_stop_reply_plan_v1)
        builder.require_current(); validate_owner_stop_reply_core_row_v1(row)
        self.builder,self.shape,self.key,self.row = builder,shape,tuple(key),tuple(row)
        from .c09_authority_storage_rebase import _canonical,_cell
        encoded = _canonical((shape.table,shape.columns,tuple(_cell(value) for value in row)))
        meter.charge_encode(len(encoded));self.core_commitment = sha256(encoded).hexdigest()
        self.basis = builder.transform.facts._authority_basis()
        self.verified = builder.session.require_actual_post_mirror_graph_v3()
        self.pin = (builder.pair.source_original.role_source_digest,self.basis.pin_digest,
            self.basis.graph_issue_digest,builder.scope.scope_digest)
        self.plan = json.loads(row[7])
        self.request,_ = decode_owner_stop_reply_plan_v1(self.plan)
        if (row[:3] != self.key or row[0] != builder.scope.authority_namespace
                or self.request.installation_id != builder.scope.installation_id):
            raise AuthorityUnavailable('StopReply preflight crossed its actual Core/installation scope')
        self.scope = self.plan['scope']; self.namespace = self.request.namespace
        self.phase = 'common'; self.index = 0; self.complete = False
        self.quantum_completed = False; self.active = None
        self.values = {}; self.common = None; self.cycle = None
        self.children = {}; self.child_index = 0; self.child = None; self.child_kind = None
        self.carriers = (); self.carrier_index = 0; self.dispositions = {}
        self.removed = False
        self.sibling_key = None; self.projection_refs = (); self.projection_index = 0
        self.projection = None; self.natural = {}
        self._register()

    def _source_heap_bytes(self):
        retained = _metadata_heap_v3((self.row,self.plan,self.scope,self.values,self.common,self.cycle,
            self.children,self.child,self.carriers,self.sibling_key,self.projection_refs,self.natural))
        if self.active is not None:
            retained += _metadata_heap_v3((self.active.values,self.active.nodes,self.active.scalar,self.active.spans))
            retained += sum(_metadata_heap_v3(getattr(self.active.parser,name))
                for name in C09CanonicalJSONStreamV2.__slots__ if name != '_emit_callback')
        return retained + 8192 + len(self.dispositions)*4096

    def _register(self):
        self.builder.session._source_parser_arena_v3.add(self)
        self.builder.session.require_current()

    def copy(self):
        out = copy(self); out.quantum_completed = False
        out.values = dict(self.values); out.children = dict(self.children)
        out.natural = dict(self.natural); out.dispositions = dict(self.dispositions)
        out.active = None if self.active is None else self.active.copy()
        return out

    def _one(self,point,table,names,keys,key,*,required=True,db=None):
        row = point.read_fixed_row(self.verified.pair.source if db is None else db,table,names,
            ' AND '.join(_quote(name)+'=?' for name in keys),tuple(key))
        if row is None and required:
            raise AuthorityUnavailable('StopReply actual original is absent: '+table)
        return row

    def _job(self,point,ref):
        from types import SimpleNamespace
        from ..runtime.d11_types import runtime_job_key
        key = AtomKey.from_token(ref)
        row = self._one(point,'runtime_jobs',_JOB_META_V3,('job_id',),(key.name,))
        job = SimpleNamespace(**dict(zip(_JOB_META_V3,row,strict=True)))
        if (job.bot_id,job.persona_id) != self.namespace.as_tuple or runtime_job_key(
                job.bot_id,job.persona_id,job.activity_id,job.job_id).token != ref:
            raise AuthorityUnavailable('StopReply accepted job ref crossed actual namespace/activity')
        return job

    def _carrier(self,table,keys,key):
        entry = (table,tuple(keys),tuple(key))
        if entry not in self.carriers:
            self.carriers = (*self.carriers,entry)

    def _json(self,point,label,table,column,keys,key,*,paths=(),hashes=()):
        if self.active is None:
            self.active = _OwnerReplyJSONReadV3(self,table,column,keys,key,paths=paths,hashes=hashes)
            return False
        reader = self.active
        if (reader.table,reader.column,reader.keys,reader.key) != (table,column,tuple(keys),tuple(key)):
            raise AuthorityUnavailable('StopReply pending JSON crossed its actual selected original')
        self.active = reader.advance(point)
        if not self.active.complete:
            return False
        self.values[label] = (self.active.values,self.active.digest,self.active.hashes,self.active.length)
        self.active = None
        return True

    def _root(self,label):
        return self.values[label][0][()]

    def _common_step(self,point):
        from ..runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
        ns = self.namespace.as_tuple; c02 = self.request.c02_operation_id
        if self.common is None:
            activity,job_id = foreground_cycle_ids_v1(self.namespace,c02)
            self.cycle = self._job(point,self.request.cycle_job_ref)
            if (self.cycle.job_id,self.cycle.activity_id,self.cycle.operation_id) != (
                    job_id,activity,self.scope['create_operation_id']):
                raise AuthorityUnavailable('StopReply historical deterministic cycle/create identity differs')
            names = ('domain','operation_kind','original_digest','bundle_digest','receipt_digest')
            self.common = self._one(point,'graph_domain_production_originals_v1',names,
                ('bot','persona','operation_id'),(*ns,self.cycle.operation_id))
            if (self.common[:2] not in {('d11','create_foreground_cycle'),('d11','create_foreground_cycle_v2')}
                    or self.common[2] != self.scope['create_original_digest']
                    or self.scope['create_original_ref'] != 'd11-current:'+self.common[2][:48]):
                raise AuthorityUnavailable('StopReply accepted create digest differs from actual registered producer')
            self._carrier('runtime_jobs',('job_id',),(job_id,))
            self._carrier('graph_atoms',('token',),(self.request.cycle_job_ref,))
            self._carrier('graph_domain_production_originals_v1',('bot','persona','operation_id'),(*ns,self.cycle.operation_id))
            self._carrier('runtime_job_operations',('bot_id','persona_id','operation_id','phase'),(*ns,self.cycle.operation_id,'create'))
            for operation in (self.cycle.operation_id,c02):
                self._carrier('graph_bundle_operations',('bot','persona','operation_id'),(*ns,operation))
            return
        create_key = (*ns,self.cycle.operation_id)
        born = ('provenance','after_job')
        paths = (('namespace',),('identity','operation_id'),('provenance','before_job'),
            ('provenance','foreground_responsibility'),
            *(born+(name,) for name in _BORN_META_V3),
            born+('continuation','c02_operation_id'),
            born+('continuation','responsibility_ref'),born+('continuation','responsibility_digest'))
        jobs = (
            ('create','graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),create_key,paths,(born,born+('continuation',))),
            ('create_receipt','graph_domain_production_originals_v1','receipt_json',('bot','persona','operation_id'),create_key,((),),()),
            ('create_reads','graph_domain_production_originals_v1','read_versions_json',('bot','persona','operation_id'),create_key,((),),()),
            ('continuation','runtime_jobs','continuation_json',('job_id',),(self.cycle.job_id,),
                (('c02_operation_id',),('responsibility_ref',),('responsibility_digest',),
                 ('call_plan','protected_reply_lease_ref')),()),
            ('birth','runtime_job_operations','job_json',('bot_id','persona_id','operation_id','phase'),
                (*create_key,'create'),(),()),
            ('c02','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),(*ns,c02),
                (('commit_seq',),('ledger_refs',),('outbox_refs',)),(('first_ingress_c02',),)),
        )
        if self.index < len(jobs):
            label,table,column,keys,key,select,hashes = jobs[self.index]
            if self._json(point,label,table,column,keys,key,paths=select,hashes=hashes):
                self.index += 1
            return
        c02_bundle = self._one(point,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            ('bot','persona','operation_id'),(*ns,c02))
        event_key = (*ns,c02_bundle[1],c02)
        if self.index < len(jobs)+2:
            name = ('reads','revisions')[self.index-len(jobs)]
            if self._json(point,'c02_'+name,'graph_events',name,('bot','persona','session','event_id'),
                    event_key,paths=((),)):
                self.index += 1
            return
        from ..runtime.domain_production_originals_v1 import _receipt
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime.foreground_cycle_v1 import ForegroundResponsibilityV1
        values,digest,hashes,_ = self.values['create']
        if (digest != self.common[2] or values[('namespace',)] != asdict(self.namespace)
                or values[('identity','operation_id')] != self.cycle.operation_id
                or values[('provenance','before_job')] is not None):
            raise AuthorityUnavailable('StopReply complete create payload differs from accepted original')
        for name in ('job_id','operation_id','activity_id','bot_id','persona_id','budget_ref','deadline_utc'):
            if values[born+(name,)] != getattr(self.cycle,name):
                raise AuthorityUnavailable('StopReply current cycle differs from immutable create job metadata')
        if values[born+('phase',)] != 'queued' or values[born+('cancel_epoch',)] != 0:
            raise AuthorityUnavailable('StopReply create original has another birth/cancel state')
        birth = self._one(point,'runtime_job_operations',('digest','job_id'),
            ('bot_id','persona_id','operation_id','phase'),(*create_key,'create'))
        if (birth != (hashes[born+('continuation',)],self.cycle.job_id)
                or self.values['birth'][1] != hashes[born]):
            raise AuthorityUnavailable('StopReply actual create job occurrence lost its complete payload commitment')
        cont = self.values['continuation'][0]
        for name in ('c02_operation_id','responsibility_ref','responsibility_digest'):
            expected = c02 if name == 'c02_operation_id' else self.scope[name]
            if cont.get((name,)) != expected or values.get(born+('continuation',name)) != expected:
                raise AuthorityUnavailable('StopReply current/birth continuation changed accepted responsibility/C02')
        receipt = _receipt(self._root('create_receipt'))
        create_bundle = self._one(point,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            ('bot','persona','operation_id'),create_key)
        if (receipt.status != 'committed' or receipt.operation_id != self.cycle.operation_id
                or canonical_digest(receipt) != self.common[4] or receipt.operation_digest != self.common[3]
                or create_bundle != (receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
            raise AuthorityUnavailable('StopReply create original lost its actual same-W01 adopting receipt')
        reads = self._root('create_reads')
        if len(reads) > 1024 or any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace
                for ref,revision in reads):
            raise AuthorityUnavailable('StopReply create read inventory crossed its original namespace/bound')
        c02_values = self.values['c02'][0]
        if ('first_ingress_c02',) not in self.values['c02'][2] or c02_values[('commit_seq',)] != c02_bundle[3]:
            raise AuthorityUnavailable('StopReply C02 is not the actual first-ingress committed original')
        epoch = self._one(point,'graph_events',('epoch_revision',),('bot','persona','session','event_id'),event_key)[0]
        def versions(label):
            return tuple(GraphVersion(AtomKey.from_token(ref),revision) for ref,revision in self._root(label))
        c02_receipt = CommitReceipt('committed',c02,*c02_bundle,
            versions('c02_reads'),versions('c02_revisions'),
            (NamespaceEpoch(*ns,epoch),),tuple(c02_values[('ledger_refs',)]),tuple(c02_values[('outbox_refs',)]))
        if canonical_digest(c02_receipt) != self.scope['c02_receipt_digest']:
            raise AuthorityUnavailable('StopReply C02 bundle/event actual CommitReceipt differs from accepted scope')
        self._carrier('graph_events',('bot','persona','session','event_id'),event_key)
        if self.scope['responsibility_ref'] is not None:
            responsibility = decode_typed_production_value_v1(
                values[('provenance','foreground_responsibility')],ForegroundResponsibilityV1)
            if (responsibility.digest != self.scope['responsibility_digest']
                    or responsibility.namespace != self.namespace or responsibility.c02_operation_id != c02):
                raise AuthorityUnavailable('StopReply signed create responsibility commitment differs')
            kind = 'foreground_post_c02_cause' if responsibility.mode == 'bounded_causal_window_v1' else 'draft_root_capability'
            self._carrier('graph_d11_life_originals_v1',('bot','persona','kind','original_ref'),
                (*ns,kind,responsibility.cause_original_ref))
        self.phase = 'children'; self.index = 0

    def _signed_child(self,point,job,ref,digest,table,kind):
        ns = self.namespace.as_tuple
        names = ('payload_digest','signature') if table == 'graph_d07_execution_originals_v1' else ('producing_operation_id','payload_digest','signature')
        meta = self._one(point,table,names,('bot','persona','kind','original_ref'),(*ns,kind,ref))
        if meta[-2] != digest:
            raise AuthorityUnavailable('StopReply accepted child differs from actual signed payload metadata')
        paths = (('namespace',),('job_id',),('operation_id',),('activity_id',),('schema',),
            ('selector','cycle_job_ref'),('selector','c02_operation_id'),('selector','namespace'),
            ('selector','task','cycle_job_ref'),('selector','task','c02_operation_id'),('selector','task','namespace'),
            ('binding','namespace'),('binding','job_id'),('binding','operation_id'),('binding','activity_id'),
            ('cycle_ref','key'),('c02_operation_id',),('work_kind',),('cancel_generation',))
        if not self._json(point,'child',table,'payload_json',('bot','persona','kind','original_ref'),
                (*ns,kind,ref),paths=paths):
            return False
        values,actual,_,_ = self.values['child']
        if actual != digest:
            raise AuthorityUnavailable('StopReply full canonical child EOF differs from accepted/signed payload digest')
        issuer = self.builder.session._control.maintenance._installed_d11_budget_job_issuer_v2
        sign_kind = 'd07.execution-original.v1' if table == 'graph_d07_execution_originals_v1' else 'd11.life-original.v1'
        issuer._signer.verify(sign_kind,canonical_serialize((self.namespace,kind,ref,digest)),meta[-1])
        producer = 'd07-prepare:'+job.operation_id if table == 'graph_d07_execution_originals_v1' else meta[0]
        committed = self._one(point,'graph_bundle_operations',('activity_id','commit_seq'),
            ('bot','persona','operation_id'),(*ns,producer))
        if committed[0] != job.activity_id or type(committed[1]) is not int or committed[1] < 1:
            raise AuthorityUnavailable('StopReply signed child lost its actual adopting W01 operation')
        self._carrier('graph_bundle_operations',('bot','persona','operation_id'),(*ns,producer))

        prefix = ('binding',) if kind == 'prepared' and table == 'graph_d11_life_originals_v1' else ()
        for name in ('job_id','operation_id','activity_id'):
            if values.get(prefix+(name,)) != getattr(job,name):
                raise AuthorityUnavailable('StopReply signed child job/operation/activity differs')
        child_ns = values.get(prefix+('namespace',),values.get(('namespace',)))
        if child_ns is not None and child_ns != asdict(self.namespace):
            raise AuthorityUnavailable('StopReply signed child namespace differs')
        if table == 'graph_d07_execution_originals_v1':
            if (values.get(('schema',)) != 'd07.artifact-observation-prepared.v3'
                    or values.get(('work_kind',)) != 'concern' or values.get(('cancel_generation',)) != 0
                    or values.get(('cycle_ref','key')) != self.request.cycle_job_ref
                    or values.get(('c02_operation_id',)) != self.request.c02_operation_id):
                raise AuthorityUnavailable('StopReply Artifact D07 child belongs to another original cycle')
        elif kind in {'c4_prepared','c4_phase_prepared'}:
            prefix = ('selector','task') if kind == 'c4_phase_prepared' else ('selector',)
            expected_schema = 'd11.artifact-draft-phase-model-prepared.v2' if kind == 'c4_phase_prepared' else 'd11.artifact-draft-model-prepared.v1'
            if (values.get(('schema',)) != expected_schema or values.get(prefix+('namespace',)) != asdict(self.namespace)
                    or values.get(prefix+('cycle_job_ref',)) != self.request.cycle_job_ref
                    or values.get(prefix+('c02_operation_id',)) != self.request.c02_operation_id):
                raise AuthorityUnavailable('StopReply C4 child belongs to another accepted reply cycle')
        elif job.activity_id != self.cycle.activity_id:
            raise AuthorityUnavailable('StopReply Life child belongs to another original reply activity')
        return True

    def _child_step(self,point):
        if self.child_index == len(self.plan['child_originals']):
            self.phase = 'siblings'; return
        ref,original_ref,digest = self.plan['child_originals'][self.child_index]
        ns = self.namespace.as_tuple
        if self.child is None:
            self.child = self._job(point,ref)
            self._carrier('runtime_jobs',('job_id',),(self.child.job_id,))
            self._carrier('graph_atoms',('token',),(ref,))
            self.child_kind = None; return
        job = self.child
        from .c09_authority_storage_rebase import owner_stop_reply_child_carrier_keys_v3
        exact = owner_stop_reply_child_carrier_keys_v3(
            _OwnerReplyMetadataConnectionV3(self,point),self.namespace,self.cycle,job,original_ref,digest)
        if exact is not None:
            for table,keys,key in exact:self._carrier(table,keys,key)
            if job.work_kind == 'artifact_draft_v1':
                done = self._signed_child(point,job,original_ref,digest,'graph_d11_life_originals_v1','c4_phase_prepared')
            elif job.work_kind == 'd07.concern':
                done = self._signed_child(point,job,original_ref,digest,'graph_d07_execution_originals_v1','prepared')
            elif job.work_kind == 'message':
                done = self._receipt_child(point,job,original_ref,digest)
            else:
                raise AuthorityUnavailable('StopReply typed carrier selected another child family')
        elif job.work_kind in {'artifact_draft_v1','d10.life.source_note.v1','d10.life.artifact_draft.v1'}:
            kind = 'c4_prepared' if job.work_kind == 'artifact_draft_v1' else 'prepared'
            self._carrier('graph_d11_life_originals_v1',('bot','persona','kind','original_ref'),(*ns,kind,original_ref))
            done = self._signed_child(point,job,original_ref,digest,'graph_d11_life_originals_v1',kind)
        elif job.work_kind == 'd04.appraisal':
            from ..runtime.d04_product_pipeline_v3 import ids
            if ids(self.namespace,self.request.c02_operation_id)['job'] != job.job_id:
                raise AuthorityUnavailable('StopReply appraisal child belongs to another C02')
            meta = self._one(point,'graph_d04_originals_v3',('payload_digest',),('bot','persona','kind','original_ref'),
                (*ns,'appraisal',original_ref))
            done = self._json(point,'child','graph_d04_originals_v3','payload_json',
                ('bot','persona','kind','original_ref'),(*ns,'appraisal',original_ref),
                paths=(('namespace',),('job_id',),('operation_id',)))
            if done:
                values,actual,_,_ = self.values['child']
                if (actual != digest or meta != (digest,) or values[('namespace',)] != asdict(self.namespace)
                        or values[('job_id',)] != job.job_id or values[('operation_id',)] != job.operation_id):
                    raise AuthorityUnavailable('StopReply actual appraisal payload lineage differs')
                self._carrier('graph_d04_originals_v3',('bot','persona','kind','original_ref'),(*ns,'appraisal',original_ref))
        elif job.work_kind in {'natural_generation','natural_review'}:
            done = self._natural_child(point,job,original_ref,digest)
        elif job.work_kind == 'message':
            done = self._natural_message(point,job,original_ref,digest)
        else:
            raise AuthorityUnavailable('StopReply child has no registered immutable metadata codec')
        if done:
            self.children[ref] = (job,original_ref,digest)
            self.child_index += 1; self.child = None; self.child_kind = None; self.index = 0


    def _ensure_natural(self,point,stage):
        from ..runtime.natural_reply_job_v2 import _table,_seal,natural_job_ids_v2
        from ..domains.d01.production_operations_v1 import plain_v1
        from ..runtime.d11_types import runtime_job_key
        if stage in self.natural:return True
        ns = self.namespace.as_tuple; c02 = self.request.c02_operation_id; table = _table(stage)
        ids = natural_job_ids_v2(self.namespace,c02,stage)
        meta = self._one(point,table,('job_id','original_operation_id','state','terminal_receipt_digest'),
            ('bot','persona','parent_original_id'),(*ns,c02))
        if (meta[:2] != ids[:2] or meta[2] not in {'queued','acquired','terminal'}
                or (meta[2] == 'terminal') != (meta[3] is not None)):
            raise AuthorityUnavailable('StopReply natural original changed its actual closed seal/state metadata')
        seal_label = 'natural_'+stage
        if seal_label not in self.values:
            self._json(point,seal_label,table,'seal_json',('bot','persona','parent_original_id'),
                (*ns,c02),paths=((),))
            return False
        seal = _seal(stage,self._root(seal_label))
        if (seal.namespace != self.namespace or
                (seal.job_id,seal.original_operation_id,seal.acquire_operation_id,seal.call_id,seal.reservation_operation_id) != ids
                or canonical_digest(plain_v1(seal)) != self.values[seal_label][1]):
            raise AuthorityUnavailable('StopReply natural actual typed seal differs from full canonical EOF')
        row = self._one(point,'runtime_jobs',_JOB_META_V3,('job_id',),(seal.job_id,))
        from types import SimpleNamespace
        job = SimpleNamespace(**dict(zip(_JOB_META_V3,row,strict=True)))
        ref = runtime_job_key(*ns,job.activity_id,job.job_id).token
        protected = self.values['continuation'][0].get(('call_plan','protected_reply_lease_ref'))
        if ((job.bot_id,job.persona_id) != ns or job.operation_id != seal.original_operation_id
                or job.work_kind != 'natural_'+stage or job.budget_ref != seal.parent_budget_lease_id
                or seal.parent_budget_lease_id != protected):
            raise AuthorityUnavailable('StopReply natural job changed its original protected child budget/producer')
        receipt_label = seal_label+'_receipt'
        if receipt_label not in self.values:
            paths = tuple((name,) for name in ('seal_digest','job_ref','review_seal_digest','review_job_ref',
                'c02_operation_id','source_ref','generation_original_operation_id'))
            self._json(point,receipt_label,'graph_bundle_operations','receipt_json',
                ('bot','persona','operation_id'),(*ns,seal.original_operation_id),paths=paths)
            return False
        bundle = self._one(point,'graph_bundle_operations',('activity_id',),('bot','persona','operation_id'),
            (*ns,seal.original_operation_id))
        receipt = self.values[receipt_label][0]
        digest_key,ref_key = ('seal_digest','job_ref') if stage == 'generation' else ('review_seal_digest','review_job_ref')
        if (bundle != (job.activity_id,) or receipt.get((digest_key,)) != self.values[seal_label][1]
                or receipt.get((ref_key,)) != ref):
            raise AuthorityUnavailable('StopReply natural seal lost its actual adopting W01 receipt/job')
        if stage == 'generation':
            if receipt.get(('c02_operation_id',)) != c02 or receipt.get(('source_ref',)) != seal.source_ref:
                raise AuthorityUnavailable('StopReply natural generation changed actual adopted C02/Source')
        else:
            if not self._ensure_natural(point,'generation'):return False
            generation = self.natural['generation'][0]
            if (seal.generation_original_operation_id != generation.original_operation_id
                    or receipt.get(('generation_original_operation_id',)) != generation.original_operation_id
                    or seal.generation_call_id != generation.call_id
                    or seal.parent_budget_lease_id != generation.parent_budget_lease_id):
                raise AuthorityUnavailable('StopReply natural review changed its actual generation lineage')
        event_key = (*ns,job.activity_id,seal.original_operation_id)
        revision_label = seal_label+'_revisions'
        if revision_label not in self.values:
            self._json(point,revision_label,'graph_events','revisions',
                ('bot','persona','session','event_id'),event_key,paths=((),))
            return False
        versions = tuple(revision for token,revision in self._root(revision_label) if token == ref)
        if len(versions) != 1:
            raise AuthorityUnavailable('StopReply natural job birth lost exact single W01 CAS member')
        history = self._one(point,'graph_history',('valid','event_bot','event_persona','event_id'),
            ('token','revision'),(ref,versions[0]))
        if history != (1,*ns,seal.original_operation_id):
            raise AuthorityUnavailable('StopReply natural job has another original adopting event')
        self._carrier(table,('bot','persona','parent_original_id'),(*ns,c02))
        self._carrier('graph_bundle_operations',('bot','persona','operation_id'),(*ns,seal.original_operation_id))
        self._carrier('graph_events',('bot','persona','session','event_id'),event_key)
        self._carrier('graph_history',('token','revision'),(ref,versions[0]))
        self.natural[stage] = (seal,job,ref,self.values[seal_label][1])
        return True

    def _natural_child(self,point,job,ref,digest):
        stage = job.work_kind.removeprefix('natural_')
        if not self._ensure_natural(point,stage):return False
        seal,actual,job_ref,actual_digest = self.natural[stage]
        if (seal.original_operation_id,seal.job_id,actual_digest) != (ref,job.job_id,digest):
            raise AuthorityUnavailable('StopReply natural child differs from its accepted original')
        return True

    def _natural_message(self,point,job,ref,digest):
        if not self._ensure_natural(point,'generation'):return False
        if not self._ensure_natural(point,'review'):return False
        generation = self.natural['generation'][0]; review = self.natural['review'][0]
        ns = self.namespace.as_tuple; key = AtomKey.from_token(ref)
        if self.child_kind is None:
            where = 'token=? AND event_bot=? AND event_persona=? AND event_id=? AND valid=1'
            parameters = (ref,*ns,job.operation_id)
            first = point.read_fixed_row(self.verified.pair.source,'graph_history',
                ('revision',),where+' ORDER BY revision',parameters)
            if (first is None or point.read_fixed_row(self.verified.pair.source,'graph_history',
                    ('revision',),where+' AND revision>? ORDER BY revision',(*parameters,first[0])) is not None):
                raise AuthorityUnavailable('StopReply natural batch lacks unique actual adopting history')
            self.child_kind = ('natural_message',first[0]);return False
        revision = self.child_kind[1]
        if self.index == 0:
            paths = tuple((name,) for name in ('schema','activity_id','operation_id','effect_id','batch_id'))+tuple(
                ('paid_review',name) for name in ('generation_call_id','review_call_id',
                    'generation_original_operation_id','review_original_operation_id'))
            if self._json(point,'message','graph_history','value',('token','revision'),(ref,revision),paths=paths):
                self.index = 1
            return False
        if self.index == 1:
            if self._json(point,'message_receipt','graph_bundle_operations','receipt_json',
                    ('bot','persona','operation_id'),(*ns,job.operation_id),paths=(('natural_dispatch_candidate',),)):
                self.index = 2
            return False
        if self.index == 2:
            if self._json(point,'message_revisions','graph_events','revisions',
                    ('bot','persona','session','event_id'),(*ns,job.activity_id,job.operation_id),paths=((),)):
                self.index = 3
            return False
        values = self.values['message'][0]
        schema = values.get(('schema',))
        if (schema not in {'d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3'}
                or key.type_name != schema or NamespaceId.from_key(key) != self.namespace
                or key.name != values.get(('batch_id',)) or key.owner.subject != job.activity_id
                or tuple(values.get((name,)) for name in ('activity_id','operation_id','effect_id'))
                    != (job.activity_id,job.operation_id,job.effect_id)
                or tuple(values.get(('paid_review',name)) for name in (
                    'generation_call_id','review_call_id','generation_original_operation_id','review_original_operation_id'))
                    != (generation.call_id,review.call_id,generation.original_operation_id,review.original_operation_id)):
            raise AuthorityUnavailable('StopReply actual natural batch lost its whole-message paid lineage')
        bundle = self._one(point,'graph_bundle_operations',('activity_id','effect_id'),
            ('bot','persona','operation_id'),(*ns,job.operation_id))
        candidate = self.values['message_receipt'][0][('natural_dispatch_candidate',)]
        if (bundle != (job.activity_id,job.effect_id)
                or candidate['schema'] != 'sylanne.d11.natural_dispatch_candidate.v2'
                or candidate['status'] != 'natural_paid_review_current_hold'
                or len(candidate['refs']) != 4 or candidate['refs'][3] != [ref,revision]):
            raise AuthorityUnavailable('StopReply natural message lost its actual closed final receipt')
        versions = dict(self._root('message_revisions'))
        if any(versions.get(token) != rev for token,rev in candidate['refs']):
            raise AuthorityUnavailable('StopReply natural final lost actual action/schema/grant/batch CAS members')
        where = "bot_id=? AND persona_id=? AND operation_id=? AND work_kind='message'"
        parameters = (*ns,job.operation_id)
        first = point.read_fixed_row(self.verified.pair.source,'runtime_jobs',('job_id',),
            where+' ORDER BY job_id',parameters)
        if (first != (job.job_id,) or point.read_fixed_row(self.verified.pair.source,'runtime_jobs',('job_id',),
                where+' AND job_id COLLATE BINARY>? ORDER BY job_id',(*parameters,job.job_id)) is not None
                or job.budget_ref != generation.parent_budget_lease_id):
            raise AuthorityUnavailable('StopReply natural message changed its unique original protected child job')
        actual_digest = canonical_digest(('d11.reply-message-metadata.v1',self.namespace,ref,revision,
            job.operation_id,job.activity_id,job.effect_id,generation.original_operation_id,
            review.original_operation_id,candidate['digest']))
        if actual_digest != digest:
            raise AuthorityUnavailable('StopReply natural message metadata differs from accepted original domain')
        self._carrier('graph_history',('token','revision'),(ref,revision))
        self._carrier('graph_bundle_operations',('bot','persona','operation_id'),(*ns,job.operation_id))
        self._carrier('graph_events',('bot','persona','session','event_id'),(*ns,job.activity_id,job.operation_id))
        return True

    def _receipt_child(self,point,job,ref,digest):
        ns = self.namespace.as_tuple
        if self.child_kind is None:
            history = self._one(point,'graph_history',('revision','event_id'),('token','event_bot','event_persona','event_id'),
                (ref,*ns,job.operation_id))
            self.child_kind = ('receipt',history[0]); return False
        revision = self.child_kind[1]
        if not self._json(point,'child','graph_history','value',('token','revision'),(ref,revision),
                paths=(('schema',),('batch_id',),('segments',0,'effect_id'))):
            return False
        values,actual,_,_ = self.values['child']
        key = AtomKey.from_token(ref)
        if (actual != digest or values[('schema',)] != 'd09.verified_segment_batch.v1'
                or values[('batch_id',)] != key.name or key.owner.subject != job.activity_id
                or values[('segments',0,'effect_id')] != job.effect_id):
            raise AuthorityUnavailable('StopReply actual receipt batch payload differs from accepted child/whole message')
        producer = 'artifact-completion-source:'+job.operation_id.removeprefix('artifact-receipt-message:')
        meta = self._one(point,'graph_domain_production_originals_v1',
            ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
            ('bot','persona','operation_id'),(*ns,producer))
        from ..runtime.artifact_completion_receipt_v1 import OPERATION
        if meta[:2] != ('d06',OPERATION):
            raise AuthorityUnavailable('StopReply receipt lost actual dedicated D06 producer')
        # The full producer payload and actual W01 receipt are independently
        # streamed with the same domain-original semantic validator below.
        self.projection = ('receipt',producer,meta)
        self.phase = 'child_projection'; self.index = 0
        return False

    def _projection_step(self,point):
        label,operation,meta = self.projection; ns = self.namespace.as_tuple
        paths = (('namespace',),('identity','operation_id'),('provenance','cycle_identity'),
            ('provenance','artifact_completion_receipt'))
        jobs = (('projection','original_payload_json',paths),('projection_receipt','receipt_json',((),)),
            ('projection_reads','read_versions_json',((),)))
        if self.index < len(jobs):
            name,column,select = jobs[self.index]
            if self._json(point,name,'graph_domain_production_originals_v1',column,
                    ('bot','persona','operation_id'),(*ns,operation),paths=select):
                self.index += 1
            return
        from ..runtime.domain_production_originals_v1 import _receipt
        value,actual,_,_ = self.values['projection']
        receipt = _receipt(self._root('projection_receipt'))
        bundle = self._one(point,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            ('bot','persona','operation_id'),(*ns,operation))
        if (actual != meta[2] or value[('namespace',)] != asdict(self.namespace)
                or value[('identity','operation_id')] != operation
                or receipt.status != 'committed' or receipt.operation_id != operation
                or canonical_digest(receipt) != meta[4] or receipt.operation_digest != meta[3]
                or bundle != (receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
            raise AuthorityUnavailable('StopReply derived producer payload/actual same-W01 receipt differs')
        reads = self._root('projection_reads')
        if len(reads) > 1024 or any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace
                for ref,revision in reads):
            raise AuthorityUnavailable('StopReply projection read inventory crossed original namespace/bound')
        if label == 'receipt':
            from ..runtime.artifact_completion_receipt_v1 import ArtifactCompletionReceiptOriginalV1
            from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            receipt_original = decode_typed_production_value_v1(value[('provenance','artifact_completion_receipt')],ArtifactCompletionReceiptOriginalV1)
            if (receipt_original.selector.task.namespace != self.namespace
                    or receipt_original.selector.task.c02_operation_id != self.request.c02_operation_id
                    or receipt_original.selector.task.cycle_job_ref != self.request.cycle_job_ref
                    or receipt_original.producer_operation_id != operation
                    or receipt_original.message_operation_id != self.child.operation_id
                    or receipt_original.effect_id != self.child.effect_id):
                raise AuthorityUnavailable('StopReply receipt actual D06 payload belongs to another accepted child/cycle')
        if label == 'stop':
            if meta[:2] != ('d11','owner_stop_reply_v1') or value.get(('provenance','cycle_identity')) != self.scope:
                raise AuthorityUnavailable('StopReply derived D11 payload differs from accepted historical scope')
        self._carrier('graph_domain_production_originals_v1',('bot','persona','operation_id'),(*ns,operation))
        self._carrier('graph_bundle_operations',('bot','persona','operation_id'),(*ns,operation))
        self.projection = None; self.index = 0
        if label == 'receipt':
            # New receipt exact carrier API already authenticates producer ID;
            # its payload EOF+adoption is now complete, so finish this child.
            ref,original_ref,digest = self.plan['child_originals'][self.child_index]
            self.children[ref] = (self.child,original_ref,digest)
            self.child_index += 1; self.child = None; self.child_kind = None
            self.phase = 'children'
        else:
            self.projection_index += 1; self.phase = 'siblings'

    def _sibling_step(self,point):
        from .owner_stop_reply_v1 import validate_owner_stop_reply_core_row_v1
        from ..runtime.lifecycle_operations_v1 import decode_original
        ns = self.namespace.as_tuple
        if self.projection_index < len(self.projection_refs):
            ref = self.projection_refs[self.projection_index]
            # Existing derived ref is an original-digest prefix, never an op ID.
            names = ('operation_id','domain','operation_kind','original_digest','bundle_digest','receipt_digest')
            where = "bot=? AND persona=? AND domain='d11' AND substr(original_digest,1,48)=?"
            first = point.read_fixed_row(self.verified.pair.source,'graph_domain_production_originals_v1',
                names,where+' ORDER BY operation_id COLLATE BINARY',(*ns,ref.removeprefix('d11-current:')))
            if first is None or point.read_fixed_row(self.verified.pair.source,'graph_domain_production_originals_v1',
                    ('operation_id',),where+' AND operation_id COLLATE BINARY>? ORDER BY operation_id COLLATE BINARY',
                    (*ns,ref.removeprefix('d11-current:'),first[0])) is not None:
                raise AuthorityUnavailable('StopReply derived ref lacks its unique actual D11 original')
            self.projection = ('stop',first[0],first[1:]); self.phase = 'projection'; self.index = 0; return
        where = 'authority_namespace=? AND operation_id=?'
        parameters = self.row[:2]
        if self.sibling_key is not None:
            where += ' AND original_ref COLLATE BINARY>?'; parameters = (*parameters,self.sibling_key)
        row = point.read_fixed_row(self.builder.pair.source,_CORE_TABLE_V3,self.shape.columns,
            where+' ORDER BY original_ref COLLATE BINARY',parameters)
        if row is None:
            self.phase = 'carriers'; return
        validate_owner_stop_reply_core_row_v1(row)
        if row[4:] != self.row[4:] or json.loads(row[7]) != self.plan:
            raise AuthorityUnavailable('StopReply initial/derived group changed actual accepted Owner scope')
        original = decode_original(json.loads(row[3]))
        self.sibling_key = row[2]
        self.projection_refs = tuple(original.result.domain_receipt_refs)
        self.projection_index = 0

    def _carrier_step(self,point):
        if self.carrier_index == len(self.carriers):
            self.complete = True; self.phase = 'complete'; return
        table,keys,key = self.carriers[self.carrier_index]
        shape = read_c09_table_shape_v2(self.verified.pair.source,table,meter=point)
        if shape.primary_key_columns != keys:
            raise AuthorityUnavailable('StopReply selected carrier lost its complete actual primary key')
        result = advance_owner_reply_graph_disposition_v3(self.basis,verified=self.verified,
            shape=shape,key=key,point=point,state=self.dispositions)
        if result is None:return
        if result.disposition == 'rebuilt_from_surviving_sources' and table == 'graph_atoms':
            if not self._migration(point,shape,key):return
        elif result.disposition == 'logical_preserved_v3':
            from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV3
            if (type(result) is not GraphRowDispositionV3 or table not in {'graph_atoms','graph_history'}
                    or 'value_cell_id' not in shape.columns):
                raise AuthorityUnavailable('StopReply logical preservation lacks actual typed physical equivalence')
            # The actual retained Graph verifier has already requalified the
            # complete Source descriptor, full cell EOF, target seal, ordered
            # member and equivalence original in their registered V3 domain.
        elif result.disposition not in {'preserved_exact','derived_removed'}:
            raise AuthorityUnavailable('StopReply carrier has another certified disposition')
        self.removed = self.removed or result.disposition == 'derived_removed'
        self.carrier_index += 1

    def _migration(self,point,shape,key):
        from .c09_segmented_census_v3 import require_segmented_target_row_v3
        if 'value' not in shape.columns:
            raise AuthorityUnavailable('StopReply rebuilt carrier is not original TEXT-to-ref migration')
        target_shape = read_c09_table_shape_v2(self.verified._read_db,shape.table,meter=point)
        if tuple(name for name in target_shape.columns if name != 'value_cell_id') != tuple(
                name for name in shape.columns if name != 'value'):
            raise AuthorityUnavailable('StopReply migrated carrier changed its actual non-payload schema')
        small = tuple(name for name in shape.columns if name != 'value')
        before = self._one(point,shape.table,small,shape.primary_key_columns,key)
        after = self._one(point,shape.table,(*small,'value_cell_id'),target_shape.primary_key_columns,key,db=self.verified._read_db)
        if before != after[:-1]:
            raise AuthorityUnavailable('StopReply migration changed original identity/revision/validity metadata')
        if not self._json(point,'migration',shape.table,'value',shape.primary_key_columns,key):
            return False
        columns = ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
            'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
        header = self._one(point,'segmented_cells_v1',columns,('cell_id',),(after[-1],),db=self.verified._read_db)
        if (header[1] != 'canonical-json.ascii.v1' or header[2] != key[0]
                or header[3] != self.builder.scope.operation_id or header[4] != self.values['migration'][3]
                or header[6] != self.values['migration'][1] or header[8] != self.builder.scope.scope_digest):
            raise AuthorityUnavailable('StopReply migration changed complete original payload bytes')
        require_segmented_target_row_v3(self.verified.segmented_sweep_v3,'segmented_cells_v1',
            (header[0],),tuple(header),meter=point)
        return True

    def advance_v3(self,meter):
        from .c09_paged_recovery_facts_v2 import _C09ReadonlyPointMeterV3
        self.builder.require_current();self.basis.require_current();self.verified.require_current()
        out = self.copy()
        point = _C09ReadonlyPointMeterV3(meter.parent)
        from ..runtime_contracts import meter_canonical_outputs
        with meter_canonical_outputs(point), legacy_cell_read_transaction_v2(self.builder.pair.source), \
                legacy_cell_read_transaction_v2(self.verified.pair.source), \
                legacy_cell_read_transaction_v2(self.verified._read_db):
            if out.phase == 'common':out._common_step(point)
            elif out.phase == 'children':out._child_step(point)
            elif out.phase in {'projection','child_projection'}:out._projection_step(point)
            elif out.phase == 'siblings':out._sibling_step(point)
            elif out.phase == 'carriers':out._carrier_step(point)
            elif out.phase != 'complete':raise AuthorityUnavailable('StopReply preflight has another phase')
        out._register();return out


class _OwnerReplyMetadataConnectionV3:
    """Metered metadata SQL for the closed installed child locator, no body reads."""
    def __init__(self,owner,point):self.owner,self.point=owner,point
    def execute(self,sql,args=()):
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        return _BoundedReadConnectionV2(self.owner.verified.pair.source,self.point).execute(sql,args)


def prepare_owner_reply_stop_core_row_v3(builder,shape,key,meter):
    from .owner_stop_reply_v1 import PLAN_SCHEMA
    state = builder.owner_stop_read_v3
    if type(state) is _OwnerReplyStopReadV3 and state.shape == shape and state.key == tuple(key):
        return state
    row = meter.read_one(builder.pair.source,shape.table,shape.columns,
        ' AND '.join(_quote(name)+'=?' for name in shape.primary_key_columns),key)
    if row is None:
        raise AuthorityUnavailable('StopReply actual selected Core row disappeared')
    if row[0] != builder.scope.authority_namespace or json.loads(row[7]).get('schema') != PLAN_SCHEMA:
        return None
    return _OwnerReplyStopReadV3(builder,shape,key,row,meter)


def advance_owner_reply_stop_core_source_row_v3(builder,budget,position,meter):
    from .c09_authority_storage_rebase_v2 import _table_shape,_stream
    from ..runtime.c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    from ..runtime.c09_paged_sql_v2 import read_capture_cursor_v2
    shape = _table_shape(builder.pair.source,position['table'])
    stream = _stream(builder.pair,builder.scope,shape,'row_dispositions')
    cursor = read_capture_cursor_v2(builder.pair.candidate,stream)
    with legacy_cell_read_transaction_v2(builder.pair.source):
        found = read_c09_next_row_metadata_v2(builder.pair.source,shape,cursor.last_key)
    if found is None:return None
    state = prepare_owner_reply_stop_core_row_v3(builder,shape,found[0],meter)
    if state is None or state.complete and state.quantum_completed:return None
    builder._pending_owner_stop_read_v3 = state.advance_v3(meter)
    return {'status':'progress','role':'core','phase':'owner_stop_reply_source',
        'completed_records':state.carrier_index,'actual_io_bytes':meter.related_read_bytes}


def require_complete_owner_reply_stop_v3(basis,key,row,meter):
    from .owner_stop_reply_v1 import owner_reply_cycle_retirement_commitment_v1
    state = basis._owner_reply_stop_ready_v3
    if (type(state) is not _OwnerReplyStopReadV3 or not state.complete or not state.quantum_completed
            or state.basis is not basis or state.builder.owner_stop_read_v3 is not state
            or state.builder.transform.facts._authority_basis() is not basis
            or tuple(key) != state.key or tuple(row) != state.row
            or state.pin != (state.builder.pair.source_original.role_source_digest,basis.pin_digest,
                basis.graph_issue_digest,basis.scope.scope_digest)
            or state.verified is not basis.session.require_actual_post_mirror_graph_v3()):
        raise AuthorityUnavailable('StopReply transform needs exact actual completed preflight proof')
    state.builder.require_current();basis.require_current();state.verified.require_current()
    from .c09_authority_storage_rebase import _canonical,_cell
    encoded = _canonical((state.shape.table,state.shape.columns,tuple(_cell(value) for value in row)))
    meter.charge_encode(len(encoded))
    if sha256(encoded).hexdigest() != state.core_commitment:
        raise AuthorityUnavailable('StopReply finite proof lost exact actual Core row commitment')

    return (state.row,'derived_removed' if state.removed else 'preserved_exact',
        AtomKey.from_token(state.request.cycle_job_ref).name,
        owner_reply_cycle_retirement_commitment_v1(row[0],state.request.cycle_job_ref,row[1]))


def verify_owner_reply_stop_core_cold_record_v3(builder,reader,stream,record,meter):
    from .c09_authority_storage_rebase_v2 import _table_shape,_json
    from .c09_authority_storage_rebase import _row_commitment
    shape = _table_shape(builder.pair.source,stream.family)
    state = prepare_owner_reply_stop_core_row_v3(builder,shape,record.primary_key,meter)
    if state is None:return None
    if not (state.complete and state.quantum_completed):
        builder._pending_owner_stop_read_v3 = state.advance_v3(meter);return False
    builder.transform.origin = ('source_row',shape.table,_json(record.primary_key))
    expected,disposition = builder.transform._core(shape,state.row,meter)
    old_digest = _row_commitment(shape.table,shape.columns,state.row)
    new_digest = None if expected is None else _row_commitment(shape.table,shape.columns,expected)
    proof = meter.read_one(reader,'authority_c09_role_rows_v2',('old_commitment','disposition','new_commitment'),
        'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
        (builder.scope.scope_digest,'core',shape.table,canonical_digest(record.primary_key)))
    if proof != (old_digest,disposition,new_digest):
        raise AuthorityUnavailable('StopReply cold disposition differs from independently repeated Source EOF')
    target = meter.read_one(reader,shape.table,shape.columns,
        ' AND '.join(_quote(name)+'=?' for name in shape.primary_key_columns),record.primary_key)
    if target != expected:
        raise AuthorityUnavailable('StopReply cold Target differs from actual source-derived preservation/retirement')
    values = (builder.scope.scope_digest,'core',shape.table,canonical_digest(record.primary_key),
        _json(record.primary_key),old_digest,disposition,new_digest)
    if canonical_digest(('sylanne3.c09.authority-row-disposition.v2',values)) != record.commitment:
        raise AuthorityUnavailable('StopReply cold record lost exact complete stream membership')
    return True
