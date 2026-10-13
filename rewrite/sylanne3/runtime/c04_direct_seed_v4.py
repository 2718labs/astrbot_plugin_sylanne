"""Exact C03 direct-seed C04 contracts. Legacy V3 wire stays unchanged."""
from dataclasses import dataclass, fields, is_dataclass
import json
import hashlib
from types import SimpleNamespace
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakSet, ref
from typing import get_type_hints

from ..contracts import canonical_json
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from . import c04_v3_contracts as v3
from .c04_v3_contracts import (
    AssociationWorkInputV3, AssociationWorkResultV3, canonical_v3_digest,
    _validate_c04_common_input_fields_v3, _validate_c04_common_result_fields_v3,
)
from .d06_ingress_c03_selection_v1 import C03DirectSelectionOriginalV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1

ALGORITHM_ID_V4 = "d06.association_activation.direct_seed.v4"
INPUT_SCHEMA_V4 = "c04.current_association.direct_seed.v4.input"
AUTHORED_INPUT_SCHEMA_V4 = "c04.current_association.authored.direct_seed.v4.input"
RESULT_SCHEMA_V4 = "c04.current_association.direct_seed.v4.result"


def _loads_exact(wire):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("C04 V4 wire repeats a field")
            result[key] = value
        return result
    raw = json.loads(wire, object_pairs_hook=pairs)
    if canonical_json(raw) != wire:
        raise ValueError("C04 V4 wire is not canonical")
    return raw


def _encode_v4(value):
    return canonical_json({"$type": type(value).__name__,
        **{field.name: v3._encode(getattr(value, field.name)) for field in fields(value)}})


def _decode_v4(wire, expected):
    bound=_PREPARED_CONTEXT_V4.get()
    if bound is not None:
        owner,drivers=bound
        for driver in drivers:
            if driver.expected is expected and driver.wire_original.wire is wire:
                return driver.require_typed_v4(owner)
        raise PreparedC04DecodeRequiredV4(wire,expected)
    raw = _loads_exact(wire)
    if (type(raw) is not dict or raw.get("$type") != expected.__name__
            or set(raw) != {"$type", *(field.name for field in fields(expected))}):
        raise ValueError("C04 V4 exact wire type/fields differ")
    hints = get_type_hints(expected)
    result = expected(**{field.name: v3._decode(hints[field.name], raw[field.name])
        for field in fields(expected)})
    if _encode_v4(result) != wire:
        raise ValueError("C04 V4 round-trip bytes differ")
    return result


@dataclass(frozen=True, slots=True, kw_only=True, weakref_slot=True)
class AssociationWorkInputV4(AssociationWorkInputV3):
    c03_selection_ref: str
    c03_selection_original_digest: str
    c03_selection_json: str
    self_scope_digest: str
    schema: str = INPUT_SCHEMA_V4

    @property
    def direct_selection(self):
        prepared=_prepared_typed_driver_v4(self)
        building=_BUILD_CONTEXT_V4.get()
        if prepared is not None:return prepared.selection
        if building is not None and self.c03_selection_json is building.raw.get('c03_selection_json'):
            return building.selection
        from ..domains.d01.production_operations_v1 import plain_v1
        raw = _loads_exact(self.c03_selection_json)
        value = decode_typed_production_value_v1(raw, C03DirectSelectionOriginalV1)
        if canonical_json(plain_v1(value)) != self.c03_selection_json:
            raise ValueError("C03 selection wire is not its exact typed original")
        return value

    @property
    def activation_roots(self):
        return (self.cue_source_ref, self.direct_selection.selected_source_ref)

    def __post_init__(self):
        if (self.schema not in {INPUT_SCHEMA_V4, AUTHORED_INPUT_SCHEMA_V4}
                or type(self.namespace) is not NamespaceId or self.algorithm_id != ALGORITHM_ID_V4):
            raise ValueError("C04 direct-seed input schema/algorithm differs")
        for name in ("activity_id", "operation_id", "audience", "purpose"):
            v3._text(getattr(self, name), name)
        _validate_c04_common_input_fields_v3(self, authored=self.schema == AUTHORED_INPUT_SCHEMA_V4)
        v3._text(self.c03_selection_ref, "C03 selection original ref")
        for value in (self.c03_selection_original_digest, self.self_scope_digest):
            v3._sha(value, "C04 Self original digest")
        selected = self.direct_selection
        if (selected.selected_source_ref is None or selected.selection_ticket is None
                or selected.namespace != self.namespace or selected.child_activity_id != self.activity_id
                or selected.cue_source_ref != self.cue_source_ref
                or selected.purpose != self.purpose or selected.audience != (self.audience,)
                or (selected.access_epoch, selected.delete_epoch) != (self.access_epoch, self.delete_epoch)
                or selected.selection_ticket != self.selection_ticket
                or canonical_v3_digest(selected.selection_ticket) != self.selection_ticket_digest
                or selected.query_epoch.revision >= self.graph_epoch):
            raise ValueError("C04 direct seed lost its actual historical C03 selection")
        # C03 query_epoch is historical; its own metadata commit advanced Graph.
        # Never replace it with this later C04 input epoch.
        row = next((row for row in self.reads if row.ref == selected.selected_source_ref), None)
        if (row is None or not row.valid or row.revision != selected.selected_source_revision
                or row.value_digest != selected.selected_source_digest
                or selected.selected_source_ref not in {target.source_ref for target in self.targets}):
            raise ValueError("C04 direct seed lacks its own exact Source and D04 target")
        self._validate_closure()

    def _validate_closure(self):
        from ..domains.d06.c04_work_input_v2 import (
            FrozenGraphReadV2, AssociationQueryCoverageV2,
            _validate_complete_graph_closure_from_roots_v1,
        )
        by_ref = {row.ref: row for row in self.reads}
        for target in self.targets:
            row = by_ref.get(target.source_ref)
            if (row is None or not row.valid or row.revision < 1
                    or target.baseline.source.revision != row.revision
                    or target.condition.current_mood.revision != by_ref[self.mood_ref].revision):
                raise ValueError("C04 V4 target baseline/Mood differs from its frozen heads")
        reachable = set(self.activation_roots)
        for hop in range(self.budget.max_hops):
            reached = tuple(reachable)
            for page in self.edge_pages:
                if page.hop != hop or page.source_ref not in reached:
                    continue
                for edge in page.edge_refs:
                    value = by_ref[edge].value
                    if not value["context_tags"] or set(value["context_tags"]) & set(self.context_tags):
                        reachable.add(value["target_ref"])
        if any(target.source_ref not in reachable for target in self.targets):
            raise ValueError("C04 V4 target is outside its two-root real-edge closure")
        # A pure validation view, not a V2 original, fake graph edge, or authority.
        view = SimpleNamespace(namespace=self.namespace, cue_source_ref=self.cue_source_ref,
            focus_ref=self.focus_ref, attention_ticket_ref=self.attention_ticket_ref,
            mood_ref=self.mood_ref, selection_ticket=self.selection_ticket,
            audience=self.audience, purpose=self.purpose, context_tags=self.context_tags,
            budget=self.budget, truncated=self.truncated,
            reads=tuple(FrozenGraphReadV2(AtomKey.from_token(row.ref), row.revision, row.valid, row.value_json,
                _canonical_original=canonical_original_for_c04_head_v4(row))
                for row in self.reads),
            edge_queries=tuple(AssociationQueryCoverageV2(page.source_ref, page.hop, page.edge_refs, page.next_after)
                for page in self.edge_pages))
        _validate_complete_graph_closure_from_roots_v1(view,
            mood_type=AtomKey.from_token(self.mood_ref).type_name, activation_roots=self.activation_roots)

    @property
    def input_digest(self):
        prepared=_prepared_typed_driver_v4(self)
        if prepared is not None:return 'sha256:'+prepared.wire_original.sha256
        return "sha256:" + hashlib.sha256(self.to_json().encode()).hexdigest()

    def to_json(self):
        prepared=_prepared_typed_driver_v4(self)
        return prepared.wire_original.wire if prepared is not None else _encode_v4(self)

    @classmethod
    def from_json(cls, wire):
        if cls is not AssociationWorkInputV4:
            raise TypeError("exact C04 V4 input class required")
        return _decode_v4(wire, cls)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class AssociationWorkResultV4(AssociationWorkResultV3):
    schema: str = RESULT_SCHEMA_V4

    def __post_init__(self):
        if (self.schema != RESULT_SCHEMA_V4 or type(self.namespace) is not NamespaceId
                or self.algorithm_id != ALGORITHM_ID_V4):
            raise ValueError("C04 V4 result schema/algorithm differs")
        _validate_c04_common_result_fields_v3(self)

    def validate_input(self, work):
        if type(work) is not AssociationWorkInputV4:
            raise TypeError("C04 V4 result needs its exact direct-seed input")
        v3._validate_c04_result_against_input_v3(self, work)
        if any(item.source_ref == work.cue_source_ref for item in self.candidates):
            raise ValueError("current cue is not a historical direct-seed result")
        if (self.visited_nodes > work.budget.max_nodes or self.visited_edges > work.budget.max_edges
                or self.iterations > work.budget.max_iterations):
            raise ValueError("C04 V4 result exceeded its original bounded work")

    @property
    def result_digest(self):
        prepared=_prepared_typed_driver_v4(self)
        if prepared is not None:return 'sha256:'+prepared.wire_original.sha256
        return "sha256:" + hashlib.sha256(self.to_json().encode()).hexdigest()

    def to_json(self):
        prepared=_prepared_typed_driver_v4(self)
        return prepared.wire_original.wire if prepared is not None else _encode_v4(self)

    @classmethod
    def from_json(cls, wire):
        if cls is not AssociationWorkResultV4:
            raise TypeError("exact C04 V4 result class required")
        return _decode_v4(wire, cls)


def c04_candidate_origin_v4(work, source_ref):
    if type(work) is not AssociationWorkInputV4:
        raise TypeError("exact C04 V4 input required")
    return ("c03_direct_selection_v1" if source_ref == work.direct_selection.selected_source_ref
        else "c04_current_association_v4")



_DECODER_ISSUER_V4=object()
_DECODERS_V4=WeakSet()
_HEAD_PROOFS_V4=WeakSet()
_HEAD_BINDINGS_V4={}
_TYPED_BINDINGS_V4={}
_PREPARED_CONTEXT_V4=ContextVar('prepared_c04_decodes_v4',default=None)
_BUILD_CONTEXT_V4=ContextVar('building_c04_decode_v4',default=None)


class PreparedC04DecodeRequiredV4(Exception):
    def __init__(self,wire,expected):
        self.wire,self.expected=wire,expected
        super().__init__('C04 typed input needs its actual same-Work prepared decoder')


def _remember_v4(bindings,obj,value):
    identity=id(obj)
    def released(dead):
        found=bindings.get(identity)
        if found is not None and found[0]is dead:bindings.pop(identity,None)
    bindings[identity]=(ref(obj,released),value)


def _bound_v4(bindings,obj):
    found=bindings.get(id(obj))
    return None if found is None or found[0]()is not obj else found[1]


def _prepared_typed_driver_v4(value):
    found=_bound_v4(_TYPED_BINDINGS_V4,value)
    if found is None:return None
    driver=found()
    if driver is None:raise ValueError('prepared C04 original lifetime ended')
    driver._actual()
    if not driver.complete or driver.result is not value:raise ValueError('prepared C04 typed object changed')
    return driver


class PreparedC04CanonicalHeadV4:
    def __init__(self,issuer,driver,index,value,digest,count):
        if issuer is not _DECODER_ISSUER_V4 or driver not in _DECODERS_V4:
            raise ValueError('actual C04 canonical head issuer required')
        raw=driver.raw['reads'][index]
        self.driver=ref(driver);self.path=('reads',index,'value_json')
        self.ref,self.revision,self.valid,self.wire=raw['ref'],raw['revision'],raw['valid'],raw['value_json']
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        driver._reserve(_container_bytes_v3(value)+4096)
        self._value=_freeze_value_v3(value);self.sha256,self.byte_count=digest,count
        self._identity=(self.driver,self.path,self.ref,self.revision,self.valid,self.wire,self._value,digest,count)
        _HEAD_PROOFS_V4.add(self)
    def require_head_v4(self,ref_value,revision,valid,wire):
        driver=self.driver()
        if(self not in _HEAD_PROOFS_V4 or driver is None
                or self._identity!=(self.driver,self.path,self.ref,self.revision,self.valid,self.wire,self._value,self.sha256,self.byte_count)
                or(ref_value,revision,valid)!=(self.ref,self.revision,self.valid)or wire is not self.wire):
            raise ValueError('C04 canonical head lost its actual original identity')
        driver._actual()
        raw=driver.raw['reads'][self.path[1]]
        if(raw['ref'],raw['revision'],raw['valid'],raw['value_json'])!=(self.ref,self.revision,self.valid,self.wire):
            raise ValueError('C04 canonical head no longer belongs to its exact outer original')
        return self
    def value_v4(self):
        self.require_head_v4(self.ref,self.revision,self.valid,self.wire)
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        self.driver().owner.reader.operation.retain(_container_bytes_v3(self._value)+256)
        return _detach_value_v3(self._value)


def retain_c04_canonical_head_v4(head,original,*,ref_value,revision,valid,wire):
    if type(original)is not PreparedC04CanonicalHeadV4:
        raise TypeError('exact prepared C04 canonical head original required')
    original.require_head_v4(ref_value,revision,valid,wire)
    _remember_v4(_HEAD_BINDINGS_V4,head,original)


def canonical_original_for_c04_head_v4(head):
    original=_bound_v4(_HEAD_BINDINGS_V4,head)
    if original is not None:
        reference=head.ref if type(head)is v3.GraphHeadV3 else head.key.token
        original.require_head_v4(reference,head.revision,head.valid,head.value_json)
    return original


class _CanonicalObjectReadV4:
    def __init__(self,driver,wire):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.driver,self.wire=driver,wire
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.offset=0;self.nodes={};self.scalar=bytearray();self.value=None;self.complete=False
        self.sha256=None;self.byte_count=0
    def _put(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:parent.append(value)
            else:parent[path[-1]]=value
    def _emit(self,event):
        if event.kind in('object_start','array_start'):
            self.driver._reserve(4096)
            value={}if event.kind=='object_start'else[];self.nodes[event.path]=value;self._put(event.path,value)
        elif event.kind=='scalar_start':self.scalar=bytearray()
        elif event.kind=='scalar_chunk':
            self.driver._reserve(len(event.raw)*4+4096);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            self.driver._reserve(len(self.scalar)*8+65536)
            value=json.loads(self.scalar);self.scalar=bytearray();self._put(event.path,value)
    def advance(self,meter):
        if self.complete:raise ValueError('complete C04 inner object cannot advance')
        if self.offset<len(self.wire):
            end=min(self.offset+1024,len(self.wire));chunk=self.wire[self.offset:end].encode('utf-8')
            meter.charge_encode(len(chunk));self.parser.feed(chunk,self._emit);self.offset=end;return
        parsed=self.parser.finish()
        if type(self.value)is not dict:raise ValueError('C04 graph read requires a complete canonical object')
        self.sha256,self.byte_count=parsed.sha256,parsed.byte_count;self.complete=True
        self.parser=None;self.nodes={};self.scalar=bytearray()


def _prepared_c04_payload_heap_v4(value,seen=None):
    """Owned wire/payload structures only; never traverse issuer or storage capabilities."""
    import sys
    from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
    if seen is None:seen=set()
    if id(value)in seen:return 0
    seen.add(id(value));size=sys.getsizeof(value)
    if type(value)is _FrozenObjectV3:
        return size+_prepared_c04_payload_heap_v4(value.items,seen)
    if type(value)is _FrozenArrayV3:
        return size+_prepared_c04_payload_heap_v4(value.items,seen)
    if type(value)is dict:
        return size+sum(_prepared_c04_payload_heap_v4(k,seen)+_prepared_c04_payload_heap_v4(v,seen)for k,v in value.items())
    if type(value)in(tuple,list):return size+sum(_prepared_c04_payload_heap_v4(part,seen)for part in value)
    if is_dataclass(value):return size+sum(_prepared_c04_payload_heap_v4(getattr(value,field.name),seen)for field in fields(value))
    if type(value)in(str,bytes,bytearray,int,float,bool,type(None)):return size
    return 0


class PreparedC04DecodeV4:
    def __init__(self,issuer,owner,wire_original,expected):
        if issuer is not _DECODER_ISSUER_V4:raise ValueError('actual C04 decoder factory required')
        self.owner,self.wire_original,self.expected=owner,wire_original,expected
        self.raw=wire_original.parsed_value
        if(type(self.raw)is not dict or self.raw.get('$type')!=expected.__name__
                or set(self.raw)!={'$type',*(field.name for field in fields(expected))}):
            raise ValueError('C04 V4 exact wire type/fields differ')
        self.phase='heads'if expected is AssociationWorkInputV4 else'construct'
        self.position=0;self.inner=None;self.heads=[];self.selection=None
        self.selection_stream=None;self.selection_wire=None
        self.result=None;self.roundtrip=None;self.complete=False;self.reserved=0
        _DECODERS_V4.add(self);self._reserve(65536)
    def _actual(self):
        if self not in _DECODERS_V4:raise ValueError('actual originating C04 decoder required')
        from .natural_producer_qualification_v1 import PreparedHostC04WireOriginalV3
        from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityC04WireOriginalV3
        if type(self.wire_original)not in(PreparedHostC04WireOriginalV3,PreparedAuthorityC04WireOriginalV3):
            raise ValueError('actual C04 outer wire original required')
        self.wire_original.require_for_v4(self.owner)
        if self.raw is not self.wire_original.parsed_value:
            raise ValueError('C04 decoder lost the complete outer canonical tree')
        return self
    def _reserve(self,extra=0):
        payloads=[self.raw,self.heads,self.selection,self.result]
        for head in self.heads:
            original=_bound_v4(_HEAD_BINDINGS_V4,head)
            if original is not None:payloads.append(original._value)
        if self.inner is not None:payloads.extend((self.inner.nodes,self.inner.scalar,self.inner.value))
        for stream in(self.selection_stream,self.roundtrip):
            if stream is not None:payloads.extend((stream.value,stream.pending))
        size=_prepared_c04_payload_heap_v4(payloads)+extra+65536
        if size>self.reserved:self.owner.reader.operation.retain(size-self.reserved);self.reserved=size
    def advance(self,*,meter):
        self._actual()
        from .c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if meter is not require_c09_reserved_meter_v3(meter.budget):raise ValueError('actual C04 caller quantum required')
        if self.complete:raise ValueError('complete C04 decoder cannot advance')
        self._advance(meter);self._actual();self._reserve();return self
    def _advance(self,meter):
        if self.phase=='heads':
            reads=self.raw['reads']
            if type(reads)is not list or len(reads)>1024:raise ValueError('C04 graph reads must be bounded')
            if self.position==len(reads):
                self.inner=_CanonicalObjectReadV4(self,self.raw['c03_selection_json']);self.phase='selection';return
            raw=reads[self.position]
            if(type(raw)is not dict or set(raw)!={'$type','ref','revision','valid','value_json'}or raw['$type']!='GraphHeadV3'):
                raise ValueError('C04 exact graph head fields differ')
            if raw['revision']==0:
                proof=PreparedC04CanonicalHeadV4(_DECODER_ISSUER_V4,self,self.position,None,None,0)
                self.heads.append(v3._decode(v3.GraphHeadV3,raw,_canonical_original=proof));self.position+=1;return
            if self.inner is None:self.inner=_CanonicalObjectReadV4(self,raw['value_json']);return
            self.inner.advance(meter)
            if self.inner.complete:
                proof=PreparedC04CanonicalHeadV4(_DECODER_ISSUER_V4,self,self.position,self.inner.value,self.inner.sha256,self.inner.byte_count)
                self.heads.append(v3._decode(v3.GraphHeadV3,raw,_canonical_original=proof));self.inner=None;self.position+=1
            return
        if self.phase=='selection':
            self.inner.advance(meter)
            if self.inner.complete:
                self.selection_wire=self.inner.wire
                from .dispatch_initial_source_read_v3 import _container_bytes_v3
                self._reserve(_container_bytes_v3(self.inner.value)*3+65536)
                self.selection=decode_typed_production_value_v1(self.inner.value,C03DirectSelectionOriginalV1)
                from ..domains.d01.production_operations_v1 import plain_v1
                from .owner_material_source_storage_v3 import CanonicalValueStreamV3
                self.selection_stream=CanonicalValueStreamV3(plain_v1(self.selection));self.phase='selection_roundtrip'
            return
        if self.phase=='selection_roundtrip':
            if self.selection_stream.read_fragment(meter)is not None:return
            if(self.selection_stream.hash.hexdigest(),self.selection_stream.offset)!=(self.inner.sha256,self.inner.byte_count):
                raise ValueError('C03 selection wire is not its exact typed original')
            self.inner=None;self.selection_stream=None;self.phase='construct';return
        if self.phase=='construct':
            from .dispatch_initial_source_read_v3 import _container_bytes_v3
            self._reserve(_container_bytes_v3(self.raw)*3+65536)
            hints=get_type_hints(self.expected)
            values={field.name:(tuple(self.heads)if field.name=='reads'else v3._decode(hints[field.name],self.raw[field.name]))
                for field in fields(self.expected)}
            token=_BUILD_CONTEXT_V4.set(self)
            try:self.result=self.expected(**values)
            finally:_BUILD_CONTEXT_V4.reset(token)
            from .owner_material_source_storage_v3 import CanonicalValueStreamV3
            self.roundtrip=CanonicalValueStreamV3({'$type':self.expected.__name__,
                **{field.name:v3._encode(getattr(self.result,field.name))for field in fields(self.expected)}})
            self.phase='roundtrip';return
        if self.phase=='roundtrip':
            if self.roundtrip.read_fragment(meter)is not None:return
            if(self.roundtrip.hash.hexdigest(),self.roundtrip.offset)!=(self.wire_original.sha256,self.wire_original.byte_count):
                raise ValueError('C04 V4 round-trip bytes differ')
            self.complete=True;_remember_v4(_TYPED_BINDINGS_V4,self.result,ref(self));self.phase='complete';return
        raise ValueError('C04 prepared decoder phase differs')
    def require_typed_v4(self,owner):
        self._actual()
        if owner is not self.owner or not self.complete or _prepared_typed_driver_v4(self.result)is not self:
            raise ValueError('actual completed same-Work C04 roundtrip required')
        return self.result


def begin_prepared_c04_decode_v4(owner,wire_original,expected):
    from .natural_producer_qualification_v1 import PreparedHostC04WireOriginalV3
    from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityC04WireOriginalV3
    if type(wire_original)not in(PreparedHostC04WireOriginalV3,PreparedAuthorityC04WireOriginalV3)or expected not in(AssociationWorkInputV4,AssociationWorkResultV4):
        raise TypeError('actual C04 V4 wire original/expected type required')
    wire_original.require_for_v4(owner)
    return PreparedC04DecodeV4(_DECODER_ISSUER_V4,owner,wire_original,expected)


@contextmanager
def bind_prepared_c04_decodes_v4(owner,prepared_decodes):
    drivers=tuple(prepared_decodes)
    for driver in drivers:
        if type(driver)is not PreparedC04DecodeV4:raise TypeError('exact actual prepared C04 decoder required')
        driver.require_typed_v4(owner)
    token=_PREPARED_CONTEXT_V4.set((owner,drivers))
    try:yield
    finally:_PREPARED_CONTEXT_V4.reset(token)
