"""Historical C09 joins for the exact D12 labor rebuild selection binding.

This consumer verifies an existing signed command/attempt/W01 association.
It never creates a selector capability, Body permission or execution grant.
"""
from weakref import WeakSet
from hashlib import sha256
import json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold,current_c09_sql_meter_v2

_READS=WeakSet()
_GRAPH_READS=WeakSet()
_GRAPH_TOKEN=object()
KIND="character_labor_rebuild_selection_binding_v1"


def _scope_v1(owner):
    from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    from .c09_character_labor_execution_v1 import _FinalLaborGraphHistoryScopeV1
    if type(owner)is InstalledGraphRebaseBuildV2:return owner.scope
    if type(owner)is _FinalLaborGraphHistoryScopeV1:
        owner.require_current();return owner.owner.builder.scope
    raise C09PagedCaptureHold("actual registered labor binding Graph owner required")


def _owner_identity_v1(owner):
    from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    scope=_scope_v1(owner)
    actual=owner if type(owner)is InstalledGraphRebaseBuildV2 else owner.owner.builder
    return actual,owner.session,owner.pair,scope.scope_digest,owner.pair.source_original.role_source_digest


class _BindingSourceReadV1:
    def __init__(self,owner,meter,value):
        from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from .c09_character_labor_execution_v1 import _FinalLaborGraphHistoryScopeV1
        if type(owner)not in (InstalledGraphRebaseBuildV2,_FinalLaborGraphHistoryScopeV1):
            raise C09PagedCaptureHold("actual frozen Graph labor binding owner required")
        owner.require_current()
        if current_c09_sql_meter_v2()is not meter or owner.pair.source_original.role!="graph":
            raise C09PagedCaptureHold("labor binding left its actual Graph Source quantum")
        self.owner,self.meter=owner,meter
        self.rows=[];self.values=[value]
        _READS.add(self);owner.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.rows,self.values),set())

    def point(self,table,columns,where,key):
        from ..runtime.c09_paged_sql_v2 import _quote
        if self not in _READS or current_c09_sql_meter_v2()is not self.meter:
            raise C09PagedCaptureHold("registered frozen labor binding read required")
        self.owner.require_current();db=self.owner.pair.source
        sizes=db.execute("SELECT "+",".join("length(CAST("+_quote(name)+" AS BLOB))"for name in columns)
            +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",key).fetchone()
        self.meter.charge_read(8*len(columns))
        if sizes is None:return None
        self.owner.session._control.require_c09_retained_arena_v3(meter=self.meter,
            additional_bytes=sum(v or 0 for v in sizes)*12+32768)
        row=self.meter.read_fixed_row(db,table,columns,where,key)
        self.rows.append(row)
        return row

    def retain(self,value):
        self.values.append(value)
        self.owner.session._control.require_c09_retained_arena_v3(meter=self.meter)
        return value

    def close(self):
        self.rows.clear();self.values.clear();_READS.discard(self)


def _qualify_character_labor_rebuild_binding_graph_v1(owner,value,*,meter):
    from ..runtime.d02_character_labor_rebuild_v1 import (
        CharacterLaborRebuildSelectionBindingV1,character_labor_rebuild_request_from_wire_v1)
    from ..runtime.domain_production_original_codec_v1 import ORIGINAL_COLUMNS,decode_domain_production_original_row_v1
    from ..runtime.domain_production_originals_v1 import _receipt
    from ..graph_types import GraphReceipt,NamespaceEpoch
    from ..graph_store import GraphStore
    from ..authority_service.v2_contract import from_wire
    if type(value)is not CharacterLaborRebuildSelectionBindingV1:
        raise C09PagedCaptureHold("official closed historical labor rebuild binding required")
    read=_BindingSourceReadV1(owner,meter,value)
    try:
        ns=value.namespace;op=value.command.mutation_operation_id;a=value.attempt
        if (ns.as_tuple!=tuple(json.loads(_scope_v1(owner).graph_namespace))
                or value.authority_namespace!=_scope_v1(owner).authority_namespace
                or value.authority_id!=_scope_v1(owner).authority_id or value.installation_id!=_scope_v1(owner).installation_id):
            raise C09PagedCaptureHold("labor rebuild binding crossed its actual captured installation")
        row=read.point("graph_domain_production_originals_v1",ORIGINAL_COLUMNS,
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        if row is None:raise C09PagedCaptureHold("labor rebuild binding lacks its actual Domain original")
        registry=owner.session._control.maintenance.graph._registry
        original=read.retain(decode_domain_production_original_row_v1(row,ns,registry=registry))
        payload=read.retain(json.loads(row[7]));receipt=read.retain(_receipt(json.loads(row[10])))
        request=read.retain(character_labor_rebuild_request_from_wire_v1(payload["request"]))
        authority=payload["authority"];requirements=value.graph_stamp[0].requirements
        native=value.native_result
        if ((row[3],row[4],row[5],row[6],row[9],row[11])!=(
                "d02","rebuild_character_labor_body",value.domain_request_digest,
                value.domain_original.original_digest,value.operation_digest,value.receipt_digest)
                or original["operation_id"]!=op or request!=value.request
                or payload["schema"]!="d02.current-rebuild_character_labor_body.v1"
                or authority["actor"]!=value.actor or authority["issuer_domain"]!="d12"
                or authority["purpose"]!=value.command.purpose or tuple(authority["audience"])!=(value.command.audience,)
                or authority["activation_generation"]!=a.permit.generation
                or payload["parent_budget"]!=value.parent_budget_lease_ref
                or payload["now_utc"]>value.deadline_utc
                or requirements.namespace!=ns or requirements.authority_id!=value.authority_id
                or requirements.authority_namespace!=value.authority_namespace
                or requirements.activation_generation!=a.permit.generation
                or native["coverage"]!=payload["coverage"] or native["missing_inputs"]!=payload["missing_inputs"]
                or native["continuation_ref"]!=payload["continuation_ref"]
                or _receipt(native["receipt"])!=receipt
                or (receipt.status,receipt.operation_id,receipt.activity_id,receipt.operation_digest,
                    receipt.commit_seq,canonical_digest(receipt))!=(
                    "committed",op,value.activity_id,value.operation_digest,value.commit_seq,value.receipt_digest)):
            raise C09PagedCaptureHold("labor rebuild binding changed its full actual request/Owner/parent/W01")
        bundle=read.point("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        event=read.point("graph_events",("digest","reads","epoch_reads","revisions","invalidated","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,value.activity_id,op))
        attempt=read.point("graph_owner_domain_attempts_v3",("request_digest","attempt_id","permit_json"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        fence=read.point("graph_bundle_fences_v2",("permit_json","pre_graph_revision","pre_graph_epoch",
            "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        if (bundle!=(value.operation_digest,value.activity_id,receipt.effect_id,value.commit_seq)
                or event is None or attempt is None or fence is None
                or attempt[:2]!=(a.request_digest,a.attempt_id)
                or from_wire(json.loads(attempt[2]))!=a.permit or from_wire(json.loads(fence[0]))!=a.permit
                or fence[5:]!=(a.finish_request_id,a.finish_digest)
                or fence[1:3]!=(value.graph_stamp[0].graph_revision,value.graph_stamp[1].revision)
                or fence[3:5]!=(fence[1]+1,fence[2]+1)or fence[4]!=event[5]
                or fence[1:5]!=(value.before_graph_revision,value.before_graph_epoch,value.post_graph_revision,value.post_graph_epoch)
                or event[0]!=value.event_digest):
            raise C09PagedCaptureHold("labor rebuild binding lacks its actual same-attempt Graph fence/finish")
        graph=read.retain(GraphReceipt("committed",GraphStore._version_rows(event[3]),
            GraphStore._version_rows(event[4]),NamespaceEpoch(*ns.as_tuple,event[5])))
        reads=tuple(tuple(v)for v in json.loads(row[8]))
        event_reads=tuple(tuple(v)for v in json.loads(event[1]))
        if (len(reads)!=len(event_reads)or set(reads)!=set(event_reads)
                or set(reads)!={(v.key.token,v.revision)for v in receipt.read_versions}
                or graph.revisions!=receipt.write_versions or receipt.invalidated_epochs!=(graph.epoch,)
                or (value.request.action_intent.ref,value.request.action_intent.version)not in set(reads)
                or json.loads(event[2])!=[[*ns.as_tuple,value.before_graph_epoch]]
                or (sha256(event[4].encode("ascii")).hexdigest(),len(event[4].encode("ascii")),len(graph.invalidated))!=(
                    value.invalidated_vector_sha256,value.invalidated_vector_bytes,value.invalidated_vector_count)
                or canonical_serialize(json.loads(event[4]))!=event[4]):
            raise C09PagedCaptureHold("labor rebuild binding changed complete actual event/read/write membership")
        roles=tuple((v.key.token,v.revision,1)for v in graph.revisions)+tuple((v.key.token,v.revision,0)for v in graph.invalidated)
        if len({(ref,revision)for ref,revision,_ in roles})!=len(roles):
            raise C09PagedCaptureHold("labor rebuild event repeats a write/invalidation member")
        return canonical_digest((KIND,op,value.domain_original.original_digest,value.receipt_digest,
            a.request_digest,a.permit,a.finish_request_id,a.finish_digest,event[0],event[5])),roles
    finally:
        read.close()


def require_character_labor_rebuild_binding_core_v1(builder,value,core,*,meter):
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
    from .c09_character_labor_execution_v1 import _LaborFrozenSourcesV1
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_contract import canonical_bytes
    if type(builder)is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!="core":
        raise C09PagedCaptureHold("actual final Core role builder required for labor selection binding")
    source=core._character_labor_source_v1
    if type(source)is not _LaborFrozenSourcesV1 or source.session is not builder.session or source.pairs[1]is not builder.pair:
        raise C09PagedCaptureHold("actual same-scope frozen Core/Graph/execution source required")
    source.require_current(core);builder.require_current()
    a=value.attempt
    row=AuthorityV2FenceStore._row(core,a.permit.operation_id)
    if (row is None or AuthorityV2FenceStore._permit(row)!=a.permit
            or row[6]!="finished"or row[10]is not None or row[7]!=canonical_bytes(a.permit)
            or row[8:10]!=(a.finish_request_id,a.finish_digest)):
        raise C09PagedCaptureHold("labor rebuild selection binding has no exact actual terminal Core attempt")
    return canonical_digest((KIND,value.command.mutation_operation_id,canonical_digest(row),
        builder.pair.source_original.role_source_digest))


def read_frozen_character_labor_rebuild_binding_v1(owner,namespace,original_ref,*,meter):
    from ..runtime.c09_character_labor_originals_v1 import (
        read_character_labor_inventory_row_v1,decode_character_labor_original_v1)
    from ..runtime.d11_character_labor_accounting_v1 import COLUMNS
    read=_BindingSourceReadV1(owner,meter,None)
    try:
        row=read.point("graph_d11_life_originals_v1",COLUMNS,
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,KIND,original_ref))
        if row is None:raise C09PagedCaptureHold("actual frozen labor rebuild binding disappeared")
        kind,ref,raw,digest=read_character_labor_inventory_row_v1(COLUMNS,row,
            authority_namespace=_scope_v1(owner).authority_namespace,
            issuer=owner.session.get_c09_domain_original_issuer_v2())
        value=read.retain(decode_character_labor_original_v1(kind,raw))
        return value,digest
    finally:
        read.close()


class _RebuildBindingGraphReadV1:
    def __init__(self,token,owner,value):
        if token is not _GRAPH_TOKEN:raise TypeError("actual frozen labor rebuild binding reader required")
        self.identity=_owner_identity_v1(owner);self.value=value
        from ..runtime.d02_character_labor_rebuild_v1 import character_labor_rebuild_selection_binding_wire_v1
        self.digest=canonical_digest(character_labor_rebuild_selection_binding_wire_v1(value))
        self.fixed=False;self.roles=();self.index=0;self.proof=None;self.complete=False
        self.history_header=None;self.history_ordinal=0;self.history_root=None;self.history_parser=None
        _GRAPH_READS.add(self);owner.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.value,self.roles,self.proof,self.history_header,self.history_parser),set())

    def require_current_v1(self,owner):
        if self not in _GRAPH_READS or _owner_identity_v1(owner)!=self.identity:
            raise C09PagedCaptureHold("labor binding graph proof crossed its actual source owner")
        owner.require_current()

    def advance_v1(self,owner,*,meter):
        from copy import copy
        self.require_current_v1(owner)
        result=copy(self);_GRAPH_READS.add(result);owner.session._source_parser_arena_v3.add(result)
        if not self.fixed:
            result.proof,result.roles=_qualify_character_labor_rebuild_binding_graph_v1(owner,self.value,meter=meter)
            result.fixed=True
        elif self.index<len(self.roles):
            from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            ref,revision,valid=self.roles[self.index]
            read=_BindingSourceReadV1(owner,meter,self.value)
            try:
                scope=None
                if self.history_header is None:
                    from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
                    shape=read_c09_table_shape_v2(owner.pair.source,"graph_history",meter=meter)
                    column="value_cell_id"if"value_cell_id"in shape.columns else"value"
                    row=read.point("graph_history",(column,"valid","event_bot","event_persona","event_session","event_id"),
                        "token=? AND revision=?",(ref,revision))
                    if row is None or row[1:]!=(valid,*self.value.namespace.as_tuple,self.value.activity_id,self.value.command.mutation_operation_id):
                        raise C09PagedCaptureHold("labor rebuild binding has no exact same-event history member")
                    if column=="value":
                        block=row[0].encode("ascii");meter.charge_encode(len(block))
                        parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
                        for offset in range(0,len(block),4096):parser.feed(block[offset:offset+4096],lambda event:None)
                        parser.finish();parser._emit_callback=None
                        result.index+=1
                    else:
                        scope=owner.session.begin_source_physical_read_v3(owner.pair,meter=meter)
                        header=scope.read_cell_header_v3(row[0],meter=meter)
                        if header[1:3]!=("canonical-json.ascii.v1",ref):
                            raise C09PagedCaptureHold("labor rebuild history changed its canonical physical owner")
                        result.history_header=header;result.history_ordinal=0
                        result.history_root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",header[0]))
                        result.history_parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
                elif self.history_ordinal<self.history_header[5]:
                    scope=owner.session.begin_source_physical_read_v3(owner.pair,meter=meter)
                    header=self.history_header
                    segment=scope.read_cell_segment_v3(header[0],self.history_ordinal,meter=meter)
                    if segment is None or segment[0]!=self.history_parser.byte_count:
                        raise C09PagedCaptureHold("labor rebuild history fragment range changed")
                    result.history_parser=self.history_parser.copy()
                    result.history_parser.feed(segment[1],lambda event:None);result.history_parser._emit_callback=None
                    result.history_root=canonical_digest(("sylanne3.segmented-cell-link.v1",self.history_root,
                        header[0],self.history_ordinal,segment[0],len(segment[1]),segment[2]))
                    result.history_ordinal+=1
                else:
                    scope=owner.session.begin_source_physical_read_v3(owner.pair,meter=meter)
                    header=self.history_header;parser=self.history_parser.copy()
                    eof=parser.finish();parser._emit_callback=None
                    scope.require_cell_eof_v3(header[0],header[5],meter=meter)
                    if (eof.byte_count,eof.sha256,result.history_root)!=(header[4],header[6],header[7]):
                        raise C09PagedCaptureHold("labor rebuild history full canonical EOF/SHA/root changed")
                    result.history_header=None;result.history_parser=None;result.history_root=None
                    result.history_ordinal=0;result.index+=1
                if scope is not None:scope.require_current(meter=meter)
            finally:read.close()
        else:result.complete=True
        owner.session._control.require_c09_retained_arena_v3(meter=meter)
        return result

    def require_complete_v1(self,owner,value):
        self.require_current_v1(owner)
        if not self.complete or self.value!=value or self.index!=len(self.roles):
            raise C09PagedCaptureHold("complete frozen labor rebuild binding graph proof required")
        return self.proof


def begin_character_labor_rebuild_binding_graph_v1(owner,value):
    return _RebuildBindingGraphReadV1(_GRAPH_TOKEN,owner,value)


def prepare_character_labor_rebuild_binding_source_v1(build,shape,key,row,meter):
    if shape.table!="graph_d11_life_originals_v1"or row[2]!=KIND:return True
    from ..runtime.c09_character_labor_originals_v1 import (
        read_character_labor_inventory_row_v1,decode_character_labor_original_v1)
    prior=build.labor_rebuild_binding_reader_v1
    if prior is not None and (prior.value.original_ref,prior.digest)==(row[3],row[6]):
        prior.require_current_v1(build)
        if prior.complete:return True
        task=prior
    else:
        _,_,raw,_=read_character_labor_inventory_row_v1(shape.columns,row,
            authority_namespace=build.scope.authority_namespace,issuer=build.session.get_c09_domain_original_issuer_v2())
        value=decode_character_labor_original_v1(KIND,raw)
        task=begin_character_labor_rebuild_binding_graph_v1(build,value)
    build.labor_rebuild_binding_pending_v1=task.advance_v1(build,meter=meter)
    return False


def require_character_labor_rebuild_binding_graph_v1(owner,value,*,meter):
    from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    if type(owner)is not InstalledGraphRebaseBuildV2:
        raise C09PagedCaptureHold("actual Graph builder must consume its completed binding Source reader")
    task=owner.labor_rebuild_binding_reader_v1
    if task is None:raise C09PagedCaptureHold("labor selection binding lacks its full frozen Source reader")
    return task.require_complete_v1(owner,value)
