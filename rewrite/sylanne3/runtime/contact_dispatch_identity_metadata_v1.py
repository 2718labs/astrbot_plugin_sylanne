"""Contact identity-only metadata EOF, bound to its actual installed Host Work.

Canonical bytes are checked in full; expression and qualification bodies are
never decoded or released by this reader. Identity evidence grants no send.
"""
from dataclasses import dataclass
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import RuntimeCellReadV3, _runtime_bounded_fixed_row_v3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2


@dataclass(frozen=True, slots=True)
class ContactDispatchSegmentMetadataV1:
    schema: str
    namespace: NamespaceId
    contact_id: str
    segment_index: int
    segment_count: int
    operation_id: str
    effect_id: str
    request_digest: str
    dispatch_request_digest: str
    payload_digest: str
    whole_manifest_digest: str
    first_operation_id: str
    first_admission_ref: str
    first_admission_receipt_digest: str
    plan_ref: str
    plan_revision: int
    plan_digest: str
    batch_ref: str
    job_ref: str
    outbox_ref: str
    admission_ref: str
    admission_receipt_digest: str
    producing_receipt_digest: str
    deadline_utc: float
    digest: str


class _IdentityJSONEOFV1:
    def __init__(self, state, *, table=None, column=None, where=None, key=(), prefixes=(), cell=None):
        self.state, self.table, self.column, self.where, self.key = state, table, column, where, key
        self.prefixes, self.cell = tuple(prefixes), cell
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.phase, self.total, self.offset = 'header', None, 0
        self.fragment, self.cursor, self.scalar = b'', 0, bytearray()
        self.nodes, self.value, self.digest = {}, None, None
        self.complete, self.reserved = False, 0
    def _selected(self, path):
        return any(path[:len(prefix)] == prefix for prefix in self.prefixes)
    def _container(self, path):
        return self._selected(path) or any(prefix[:len(path)] == path for prefix in self.prefixes)
    def _reserve(self, extra=0):
        from .source_correction_read_v3 import _heap
        size = _heap((self.nodes,self.value,self.scalar,self.fragment)) + extra + 65536
        if size > self.reserved:
            self.state.operation.retain(size-self.reserved)
            self.reserved = size
    def _put(self, path, value):
        if not path:
            self.value = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list:
                if path[-1] != len(parent):
                    raise AuthorityUnavailable('Contact identity metadata array cursor differs')
                parent.append(value)
            else:
                parent[path[-1]] = value
    def _emit(self, event):
        if event.kind in ('object_start','array_start') and self._container(event.path):
            value = {} if event.kind == 'object_start' else []
            self.nodes[event.path] = value
            self._put(event.path,value)
            self._reserve()
        elif self._selected(event.path):
            if event.kind == 'scalar_start':
                self.scalar = bytearray()
            elif event.kind == 'scalar_chunk':
                self._reserve(len(event.raw)*4+128)
                self.scalar.extend(event.raw)
            elif event.kind == 'scalar_end':
                value = json.loads(self.scalar)
                self.scalar = bytearray()
                self._put(event.path,value)
                self._reserve()
    def advance(self, meter):
        if self.complete:
            return
        if self.phase == 'header':
            if self.cell is not None:
                self.total = self.cell.header[3]
            else:
                row = self.state.db.execute('SELECT length(CAST('+self.column+' AS BLOB)),typeof('+self.column+') FROM '+self.table+' WHERE '+self.where,self.key).fetchone()
                meter.charge_read(32)
                if row is None or row[1] != 'text':
                    raise AuthorityUnavailable('Contact identity canonical metadata column absent')
                self.total = row[0]
            self.phase = 'bytes'
            return
        if self.cursor < len(self.fragment):
            end = min(self.cursor+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.cursor:end],self._emit)
            self.cursor = end
            return
        if self.offset < self.total:
            if self.cell is None:
                fragment,total,kind = read_legacy_sql_cell_fragment_v2(self.state.db,table=self.table,column=self.column,
                    where=self.where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                if total != self.total or kind != 'text':
                    raise AuthorityUnavailable('Contact identity metadata bytes changed during EOF')
            else:
                fragment = self.cell.read_fragment(meter=meter)
            if not fragment:
                raise AuthorityUnavailable('Contact identity metadata ended before complete EOF')
            self._reserve(len(fragment)+1024)
            self.fragment,self.cursor = fragment,0
            self.offset += len(fragment)
            return
        result = self.parser.finish()
        if result.byte_count != self.total or self.cell is not None and self.cell.finish(meter=meter) != result.sha256:
            raise AuthorityUnavailable('Contact identity canonical hash/cell EOF differs')
        self.digest = result.sha256
        self.parser,self.fragment,self.scalar,self.nodes = None,b'',bytearray(),{}
        self.complete = True


_SEGMENT_FIELDS = frozenset(('schema','namespace','contact_id','segment_index','segment_count','operation_id','effect_id',
    'request_digest','dispatch_request_digest','payload_digest','whole_manifest_digest','first_operation_id','first_admission_ref',
    'first_admission_receipt_digest','plan_ref','plan_revision','plan_digest','batch_ref','job_ref','outbox_ref',
    'admission_ref','admission_receipt_digest','producing_receipt_digest','deadline_utc'))


class ContactDispatchIdentityMetadataReadV1:
    def __init__(self, state):
        self.state, self.namespace, self.operation_id = state, state.namespace, state.selector.operation_id
        self.locator_complete, self.complete, self.closed = False, False, False
        self.segment_original, self.result, self.task = None, None, None
        self.segment_row, self.domain_row, self.admission_row = None, None, None
        self.phase, self.members, self.member_index = 'segment', (), 0
    def _require(self, meter, *, owner):
        from .contact_dispatch_host_read_v1 import require_contact_dispatch_identity_work_v3
        state = require_contact_dispatch_identity_work_v3(self.state,db=self.state.db)
        state.operation.handle.require_current(meter)
        if self.closed or state.selector.operation_id != self.operation_id or state.namespace != self.namespace:
            raise AuthorityUnavailable('Contact identity EOF left its original private selector')
        if owner and state.owner_entry.require_for_v3(state) != state.expected_owner_binding:
            raise AuthorityUnavailable('Contact identity EOF lacks its actual current Owner metadata')
        if state.graph._v2_graph_stamp(self.namespace) != state.graph_stamp:
            raise AuthorityUnavailable('Contact identity EOF crossed its original Graph stamp')
        return state
    def _row(self,meter,table,columns,where,key):
        return _runtime_bounded_fixed_row_v3(self.state.db,meter,table,columns,where,key)
    def _json(self,table,column,where,key,prefixes):
        self.task = _IdentityJSONEOFV1(self.state,table=table,column=column,where=where,key=key,prefixes=prefixes)
    def advance_locator_v1(self,meter):
        state = self._require(meter,owner=False)
        from .contact_continuation_v1 import TABLE,SIGN_KIND
        key = (*self.namespace.as_tuple,self.operation_id)
        row = self._row(meter,TABLE,('contact_id','segment_index','operation_id','effect_id','payload_digest','signature'),
            'bot=? AND persona=? AND operation_id=?',key)
        if row is None or self.segment_row is not None and row != self.segment_row:
            raise AuthorityUnavailable('Contact identity signed segment locator absent or changed')
        if self.task is None:
            self.segment_row = row
            self._json(TABLE,'payload_json','bot=? AND persona=? AND operation_id=?',key,tuple((name,) for name in _SEGMENT_FIELDS))
            return
        self.task.advance(meter)
        if not self.task.complete:
            return
        value = self.task.value
        state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((self.namespace,row[0],row[1],self.task.digest)),row[5])
        if (self.task.digest != row[4] or value['schema'] != SIGN_KIND
                or value['namespace'] != {'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or (value['contact_id'],value['segment_index'],value['operation_id'],value['effect_id']) != row[:4]
                or not 0 <= value['segment_index'] < value['segment_count'] <= 3):
            raise AuthorityUnavailable('Contact identity signed segment complete EOF differs')
        value['namespace'] = self.namespace
        self.segment_original = ContactDispatchSegmentMetadataV1(**value,digest=self.task.digest)
        self.task = None
        self.locator_complete = True
        self.phase = 'domain'
    def _check_domain(self,meter):
        row = self._row(meter,'graph_domain_production_originals_v1',
            ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
        if row is None or row[:2] != ('d08','prepare_contact_dispatch_v3') or self.domain_row is not None and row != self.domain_row:
            raise AuthorityUnavailable('Contact identity actual adopted original metadata differs')
        return row
    def advance_metadata_v1(self,meter):
        state = self._require(meter,owner=True)
        if not self.locator_complete or self.complete:
            if self.complete:return
            raise AuthorityUnavailable('Contact identity Owner phase preceded signed locator EOF')
        key,where = (*self.namespace.as_tuple,self.operation_id),'bot=? AND persona=? AND operation_id=?'
        segment = self._row(meter,'graph_contact_segment_originals_v1',
            ('contact_id','segment_index','operation_id','effect_id','payload_digest','signature'),where,key)
        if segment != self.segment_row:
            raise AuthorityUnavailable('Contact identity signed locator changed after complete EOF')
        row = self._check_domain(meter)
        if self.domain_row is None:self.domain_row = row
        if row[2] != self.segment_original.request_digest:
            raise AuthorityUnavailable('Contact identity adopted request differs from its signed segment producer')
        if self.task is not None:
            self.task.advance(meter)
            if not self.task.complete:return
            task,self.task = self.task,None
            if self.phase == 'domain':
                if task.digest != row[3] or task.value['namespace'] != {'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id} or task.value['identity']['operation_id'] != self.operation_id:
                    raise AuthorityUnavailable('Contact identity adopted canonical original digest/identity differs')
                self.proof = task.value['provenance'];self.phase = 'receipt'
            elif self.phase == 'receipt':
                from .domain_production_originals_v1 import _receipt
                self.receipt = _receipt(task.value)
                if self.receipt.status != 'committed' or canonical_digest(self.receipt) != row[5] or self.receipt.operation_id != self.operation_id or self.receipt.operation_digest != row[4]:
                    raise AuthorityUnavailable('Contact identity actual producing receipt differs')
                bundle = self._row(meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),where,key)
                if bundle != (row[4],self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                    raise AuthorityUnavailable('Contact identity actual W01 COMMIT is absent')
                self.phase = 'reads'
            elif self.phase == 'reads':
                if len(task.value)>1024 or any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace for ref,revision in task.value):
                    raise AuthorityUnavailable('Contact identity original read set crossed namespace/bound')
                self.phase = 'owner_result'
            elif self.phase == 'owner_result':
                self.saved_result = task.value
                if (task.value.get('operation_id'),task.value.get('original_digest'),task.value.get('coverage')) != (self.operation_id,row[3],'complete'):
                    raise AuthorityUnavailable('Contact identity actual saved Owner result differs')
                self.phase = 'admission'
            elif self.phase == 'admission':
                from .dispatch_admission import DispatchAdmissionV1, DispatchAdmissionReceiptV1, _decode_check, namespace_of
                data = task.value
                data['check_receipts'] = tuple(_decode_check(item) for item in data['check_receipts'])
                data['audience'] = tuple(data['audience']);data['graph_reads'] = tuple(tuple(item) for item in data['graph_reads'])
                admission = DispatchAdmissionV1(**data)
                a = self.admission_row
                if (admission.operation_id,admission.effect_id,admission.digest) != a[:3] or namespace_of(admission) != self.namespace or admission.admission_ref != self.proof['admission_ref']:
                    raise AuthorityUnavailable('Contact identity actual dispatch admission differs')
                self.admission = DispatchAdmissionReceiptV1(admission,*a[3:])
                self.phase = 'request'
            elif self.phase == 'request':
                from .dispatch_admission import _decode_request, _request_matches
                self.request = _decode_request(canonical_serialize(task.value))
                if not _request_matches(self.admission.admission,self.request):
                    raise AuthorityUnavailable('Contact identity actual stored command differs')
                self._validate_members_v1();self.phase = 'history'
            elif self.phase == 'history':
                member = self.members[self.member_index]
                if task.digest != member['digest']:
                    raise AuthorityUnavailable('Contact identity producing history whole canonical EOF differs')
                self.member_index += 1
            return
        if self.phase == 'domain':
            self._json('graph_domain_production_originals_v1','original_payload_json',where,key,
                (('namespace',),('identity','operation_id'),('provenance','admission_ref'),('provenance','admission_receipt_digest'),('provenance','outbox_ref'),('provenance','write_commitments')))
        elif self.phase in ('receipt','reads'):
            self._json('graph_domain_production_originals_v1','receipt_json' if self.phase=='receipt' else 'read_versions_json',where,key,((),))
        elif self.phase == 'owner_result':
            self._json('graph_owner_domain_attempts_v3','receipt_json',where,key,(('operation_id',),('original_digest',),('coverage',)))
        elif self.phase in ('admission','request'):
            akey = (*self.namespace.as_tuple,self.proof['admission_ref'])
            actual = self._row(meter,'graph_dispatch_admissions',('operation_id','effect_id','admission_digest','graph_revision','graph_epoch','receipt_digest'),
                'bot=? AND persona=? AND admission_ref=?',akey)
            if actual is None or self.admission_row is not None and actual != self.admission_row:
                raise AuthorityUnavailable('Contact identity admission metadata changed')
            self.admission_row = actual
            self._json('graph_dispatch_admissions','admission_json' if self.phase=='admission' else 'request_json',
                'bot=? AND persona=? AND admission_ref=?',akey,((),))
        elif self.phase == 'history':
            if self.member_index == len(self.members):
                from ..host.contact_dispatch_driver_v3 import OriginalContactDispatchV3
                s = self.segment_original
                self.result = (OriginalContactDispatchV3(self.namespace,self.operation_id,s.outbox_ref,s.batch_ref,
                    self.request,self.admission,self.receipt),self.saved_result)
                self.complete = True
                return
            member = self.members[self.member_index]
            history = self._row(meter,'graph_history',('event_id','valid','value_cell_id','event_bot','event_persona'),
                'token=? AND revision=?',(member['ref'],member['revision']))
            if history is None or (history[0],history[1],history[3],history[4]) != (self.operation_id,1,*self.namespace.as_tuple):
                raise AuthorityUnavailable('Contact identity exact producing history is absent')
            cell = RuntimeCellReadV3(state.operation.handle,history[2],erasure_owner_ref=member['ref'],meter=meter)
            if cell.header[2] != self.operation_id or cell.header[5] != member['digest'] or cell.header[0] != 'canonical-json.ascii.v1':
                raise AuthorityUnavailable('Contact identity actual history producer/header differs')
            self.task = _IdentityJSONEOFV1(state,cell=cell)
    def _validate_members_v1(self):
        s,r,p,a,q = self.segment_original,self.receipt,self.proof,self.admission,self.request
        self.members = tuple(p['write_commitments'])
        count = 11 if s.segment_index == 0 else 5
        if (q.operation_id != self.operation_id or q.effect_id != s.effect_id or q.footprint.contact_id != s.contact_id
                or (q.segment_index,q.segment_count) != (s.segment_index,s.segment_count)
                or r.effect_id != q.effect_id or q.payload_digest != s.payload_digest or canonical_digest(q) != s.dispatch_request_digest
                or p['admission_ref'] != s.admission_ref or p['admission_receipt_digest'] != s.admission_receipt_digest
                or a.receipt_digest != s.admission_receipt_digest or canonical_digest(r) != s.producing_receipt_digest
                or r.outbox_refs != (s.outbox_ref,) or len(r.write_versions) != count or len(self.members) != count
                or len({(v['ref'],v['revision']) for v in self.members}) != count
                or {(v['ref'],v['revision']) for v in self.members} != {(v.key.token,v.revision) for v in r.write_versions}
                or any(NamespaceId.from_key(v.key) != self.namespace for v in r.write_versions)
                or s.segment_index > 0 and q.footprint.quota_occupancies):
            raise AuthorityUnavailable('Contact identity exact signed first/continuation COMMIT membership differs')
        if s.segment_index == 0:
            batches = tuple(v.key.token for v in r.write_versions if v.key.type_name == 'd09.contact_verified_batch.v3')
            if batches != (s.batch_ref,):
                raise AuthorityUnavailable('Contact identity first whole batch producer differs')
    def require_for_v1(self,state,db):
        from .contact_dispatch_host_read_v1 import require_contact_dispatch_identity_work_v3
        require_contact_dispatch_identity_work_v3(state,db=db)
        if state is not self.state or not self.complete or self.closed or state.graph._v2_graph_stamp(self.namespace) != state.graph_stamp:
            raise AuthorityUnavailable('Contact identity result left its completed original Work')
        if state.owner_entry.require_for_v3(state) != state.expected_owner_binding:
            raise AuthorityUnavailable('Contact identity result lost its current Owner EOF')
        return self.result
    def release_v3(self):
        self.task,self.result,self.segment_original = None,None,None
        self.closed = True
