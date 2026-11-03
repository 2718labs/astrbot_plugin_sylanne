"""Frozen C09 consumers of actual labor adoption and initial Body metadata."""
from weakref import WeakSet
import json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold

_READERS=WeakSet()
_TABLE="graph_d11_life_originals_v1"
_KIND="character_labor_adoption_metadata_v1"
_HEADER=("cell_id","codec_id","erasure_owner_ref","producer_operation_id","total_bytes",
    "segment_count","payload_sha256","ordered_segment_root","origin_scope_digest")
_HISTORY=("token","revision","value_cell_id","valid","dependencies","event_bot","event_persona","event_session","event_id")
_ROWS=frozenset((
    ("graph_c09_rebase_certificates_v2",("operation_id",),"bot=? AND persona=? AND operation_id>? ORDER BY operation_id"),
    ("c09_capture_streams_v2",("status","seal_json"),"stream_id=?"),
    ("c09_capture_streams_v2",("identity_json","status","seal_json"),"stream_id=?"),
    ("c09_capture_pages_v2",("page_index",),"stream_id=? AND page_index>=?"),
    ("c09_capture_members_v2",("record_ordinal",),"stream_id=? AND record_ordinal>?"),
    ("c09_graph_disposition_directory_v2",("scope_digest","family","identity_json","complete_json"),"scope_digest=? AND family=?"),
    ("graph_history",_HISTORY,"token=? AND revision=?"),
    ("segmented_cells_v1",_HEADER,"cell_id=?"),
    ("segmented_cell_segments_v1",("ordinal",),"cell_id=? AND ordinal>=?")))


class _CharacterLaborAdoptionSourceReadV1:
    def __init__(self,build,shape,key,row,*,meter):
        from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from ..runtime.c09_character_labor_originals_v1 import read_character_labor_inventory_row_v1
        from ..runtime.character_labor_adoption_metadata_v1 import (
            character_labor_adoption_metadata_from_wire_v1,CharacterLaborHistoricalMembersPlanV1)
        if type(build)is not InstalledGraphRebaseBuildV2 or shape.table!=_TABLE or row[2]!=_KIND:
            raise C09PagedCaptureHold("actual frozen Graph labor metadata producer required")
        build.require_current()
        self.builder=self.verified=build
        self.control=build.session._control.maintenance.control
        self.shape,self.key=shape,tuple(key)
        self.digest=row[6]
        _,_,raw,_=read_character_labor_inventory_row_v1(shape.columns,row,
            authority_namespace=build.scope.authority_namespace,
            issuer=build.session.get_c09_domain_original_issuer_v2())
        self.metadata=character_labor_adoption_metadata_from_wire_v1(raw)
        self.physical=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
        self.physical.require_current(meter=meter)
        basis=self.physical.previous_selected_basis
        selected=None if basis is None else (
            basis.manifest["certificate_digest"],basis.prepared["capture_scope_digest"],
            basis.control.authority_id,basis.prepared["namespace"],basis.control.installation_id)
        if selected is not None and selected[3]!=build.scope.authority_namespace:
            raise C09PagedCaptureHold("labor metadata Source selection crossed Authority namespace")
        members=(*self.metadata.write_members,*self.metadata.invalidated_members,
            self.metadata.checkpoint,*(()if self.metadata.body_read is None else(self.metadata.body_read,)))
        self.plan=CharacterLaborHistoricalMembersPlanV1(namespace=self.metadata.namespace,members=members,
            selection_basis=selected,current_incarnation=build.pair.build_plan["old_incarnation"])
        self.iterator=self.plan.requests_v1()
        self.request=None;self.answer=None;self.has_answer=False
        self.column=None;self.pending=None;self.complete=False
        self.proof=None;self.headers_verified=False;self.vectors={};self.vector_index=0;self.vectors_verified=False
        _READERS.add(self);build.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.metadata,self.plan.retained_payload_v1(),self.request,self.answer,
            None if self.column is None else self.column.inner.values,self.pending,self.proof,self.vectors),set())

    def require_current_v3(self):
        if self not in _READERS or self.builder is not self.verified:
            raise C09PagedCaptureHold("registered labor metadata Source reader required")
        self.builder.require_current()
        if (self.builder.scope.scope_digest!=self.builder.pair.source_original.scope_digest
                or self.builder.pair.source_original.role!="graph"):
            raise C09PagedCaptureHold("labor metadata crossed its frozen Graph Source")
        return self

    def confirm_quantum_v1(self):
        if self.pending is None:return
        kind,value=self.pending;self.pending=None
        if kind=="headers":self.headers_verified=True
        elif kind=="vector":
            name,data=value;self.vectors[name]=data;self.vector_index+=1;self.column=None
        elif kind=="column":self.column=value
        else:self.answer=value;self.has_answer=True;self.request=None;self.column=None

    def advance_v1(self,meter):
        self.require_current_v3();self.physical.require_current(meter=meter)
        self.builder.session._control.require_c09_retained_arena_v3(meter=meter,additional_bytes=65536)
        if self.complete:return True
        if not self.headers_verified:
            self._headers_v1(meter);self.pending=("headers",True);return False
        if self.column is not None:
            column=self.column.advance_v3(meter)
            if column.complete:
                if column.tag.startswith("event:"):
                    self.pending=("vector",(column.tag[6:],(column.value_v3(),column.inner.digest,column.inner.length)))
                else:self.pending=("answer",(column.value_v3(),column.inner.digest))
            else:self.pending=("column",column)
            return False
        if self.vector_index<3:
            from .c09_platform_observation_lineage_v3 import _LineageJSONReadV3
            name=("reads","revisions","invalidated")[self.vector_index];m=self.metadata
            self.column=_LineageJSONReadV3(self,"event:"+name,"graph_events",name,
                ("bot","persona","session","event_id"),(*m.namespace.as_tuple,m.activity_id,m.operation_id))
            return False
        if not self.vectors_verified:
            self._vectors_v1();self.vectors_verified=True
        if self.request is None:
            try:
                if self.has_answer:
                    answer=self.answer;self.answer=None;self.has_answer=False
                    self.request=self.iterator.send(answer)
                else:self.request=next(self.iterator)
            except StopIteration as result:
                self.proof=result.value;self.complete=True
                self.plan.release_v1()
                return True
        request=self.request;kind=request[0];db=self.builder.pair.source
        if kind=="row":
            _,table,columns,where,key=request
            if (table,columns,where)not in _ROWS:
                raise C09PagedCaptureHold("unregistered labor metadata history selector")
            if table=="segmented_cells_v1":
                value=self.physical.read_cell_header_v3(key[0],meter=meter)
            else:value=meter.read_fixed_row(db,table,columns,where,key)
        elif kind=="column":
            _,table,column,keys,key=request
            if (table,column,keys)!=("graph_c09_rebase_certificates_v2","certificate_json",("bot","persona","operation_id")):
                raise C09PagedCaptureHold("unregistered labor metadata certificate column")
            from .c09_platform_observation_lineage_v3 import _LineageJSONReadV3
            self.column=_LineageJSONReadV3(self,"certificate",table,column,keys,key)
            return False
        elif kind=="origin":
            value=self._origin_v1(request[1],meter)
        elif kind=="segment":
            meter.charge_read(80)
            value=db.execute("SELECT byte_offset,length(payload),payload_sha256 FROM segmented_cell_segments_v1 "
                "WHERE cell_id=? AND ordinal=?",request[1]).fetchone()
        elif kind=="page":
            from ..runtime.c09_paged_sql_v2 import read_capture_page_v2
            _,identity,index=request
            lengths=db.execute("SELECT length(CAST(descriptor_json AS BLOB)),length(CAST(records_json AS BLOB)) "
                "FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index=?",(identity.stream_id,index)).fetchone()
            meter.charge_read(16)
            if lengths is None:raise C09PagedCaptureHold("actual labor history page is absent")
            self.builder.session._control.require_c09_retained_arena_v3(meter=meter,
                additional_bytes=sum(lengths)*12+32768)
            value=read_capture_page_v2(db,identity,index)
        elif kind=="member":
            from ..runtime.c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
            _,locator,key,row=request
            member=meter.read_fixed_row(db,"c09_capture_members_v2",("record_ordinal","commitment"),
                "stream_id=? AND primary_key_json=?",(locator.identity.stream_id,canonical_serialize(key)))
            if member is None or member[1]!=c09_row_commitment_v2(row):
                raise C09PagedCaptureHold("labor historical metadata is outside its exact signed stream")
            require_c09_capture_member_v2(db,locator.identity,member[0],key,member[1],meter=meter)
            value=None
        elif kind=="descriptor":
            from ..runtime.c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
            _,identity,key,ordinal=request
            value=require_c09_logical_source_row_member_v3(db,identity,role="graph",
                table_name="graph_history",key=key,record_ordinal=ordinal,meter=meter)
        elif kind=="disposition":
            from ..runtime.c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
            _,scope,key=request
            value=_read_graph_disposition_original_row_v3(db,scope,"graph_history",key,meter)
        else:raise C09PagedCaptureHold("unregistered labor metadata history request")
        self.pending=("answer",value)
        self.builder.session._control.require_c09_retained_arena_v3(meter=meter)
        return False

    def _vectors_v1(self):
        m=self.metadata;values={}
        for name,(items,digest,size)in self.vectors.items():
            minimum=0 if name=="reads"else 1
            if type(items)is not list or any(type(v)is not list or len(v)!=2 or type(v[0])is not str
                    or type(v[1])is not int or v[1]<minimum for v in items):
                raise C09PagedCaptureHold("labor actual event vector has another closed version shape")
            if len({v[0]for v in items})!=len(items):
                raise C09PagedCaptureHold("labor actual event repeats a Graph key")
            from ..graph_types import AtomKey
            if any(NamespaceId.from_key(AtomKey.from_token(v[0]))!=m.namespace for v in items):
                raise C09PagedCaptureHold("labor actual event crossed namespace")
            values[name]={tuple(v)for v in items}
        if values["revisions"]!={(v.ref,v.revision)for v in m.write_members}or values["invalidated"]!={
                (v.ref,v.revision)for v in m.invalidated_members}:
            raise C09PagedCaptureHold("labor metadata does not enumerate its complete actual event writes/invalidation")
        invalidated=self.vectors["invalidated"]
        if (invalidated[1],invalidated[2],len(invalidated[0]))!=(
                m.invalidated_vector_sha256,m.invalidated_vector_bytes,m.invalidated_vector_count):
            raise C09PagedCaptureHold("labor actual invalidation EOF differs from the signed metadata commitment")
        if m.body_read is not None and (m.body_read.ref,m.body_read.revision)not in values["reads"]:
            raise C09PagedCaptureHold("labor unchanged Body lacks its actual event read membership")

    def _headers_v1(self,meter):
        from ..runtime.d11_life_preparation_v1 import SIGN_KIND
        from ..runtime.d11_character_labor_accounting_v1 import SIGN_KIND as BASIS_SIGN
        m=self.metadata;ns=m.namespace
        for kind,original,producer,sign in (
                ("character_labor_prepared_v1",m.prepared_original,None,SIGN_KIND),
                ("character_labor_prepared_metadata_v1",m.prepared_metadata_original,None,SIGN_KIND),
                ("character_labor_accounting_basis_v1",m.basis_original,None,BASIS_SIGN),
                ("character_work_segment_v1",m.segment_original,m.operation_id,SIGN_KIND),
                ("adopted_life",m.adopted_original,m.operation_id,SIGN_KIND)):
            row=meter.read_fixed_row(self.builder.pair.source,_TABLE,
                ("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,kind,original.original_ref))
            if row is None or row[1]!=original.original_digest or producer is not None and row[0]!=producer:
                raise C09PagedCaptureHold("labor adoption metadata lost its exact signed producer member")
            self.builder.session.get_c09_domain_original_issuer_v2()._signer.verify(sign,
                canonical_serialize((ns,kind,original.original_ref,row[1])),row[2])
        for kind,digest in (("adoption_bridge",m.bridge_original_digest),("adoption_receipt",m.adoption_receipt_digest)):
            row=meter.read_fixed_row(self.builder.pair.source,_TABLE,
                ("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,kind,m.execution_id))
            if row is None or row[:2]!=(m.operation_id,digest):
                raise C09PagedCaptureHold("labor adoption metadata changed its exact bridge/receipt member")
            self.builder.session.get_c09_domain_original_issuer_v2()._signer.verify(SIGN_KIND,
                canonical_serialize((ns,kind,m.execution_id,digest)),row[2])
        bundle=meter.read_fixed_row(self.builder.pair.source,"graph_bundle_operations",
            ("activity_id","effect_id","digest","commit_seq"),"bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,m.operation_id))
        event=meter.read_fixed_row(self.builder.pair.source,"graph_events",("digest",),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,m.activity_id,m.operation_id))
        if bundle!=(m.activity_id,m.effect_id,m.operation_digest,m.commit_seq)or event!=(m.event_digest,):
            raise C09PagedCaptureHold("labor adoption metadata has another actual W01 producer")

    def _origin_v1(self,header,meter):
        scope=self.physical
        actual=scope.read_cell_header_v3(header[0],meter=meter)
        if tuple(actual)!=tuple(header):raise C09PagedCaptureHold("labor metadata source header changed")
        basis=scope.previous_selected_basis
        if basis is not None:
            if header[8]==basis.prepared["capture_scope_digest"]:return None
            from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
            return read_selected_runtime_cell_origin_v3(scope.source,selected_basis=basis,role="graph",
                cell_id=header[0],header=tuple(header[1:]),meter=meter)
        from .c09_source_physical_read_v3 import (
            _initial_physical_source_qualification_v3,_initial_owner_source_qualification_v3,
            _initial_owner_cell_values_read_v3)
        qualification=_initial_physical_source_qualification_v3(scope,meter)
        if qualification.origin_kind=="initial_segmented_v4":
            from ..runtime_storage_v3 import read_initial_runtime_cell_origin_for_capture_v4
            return read_initial_runtime_cell_origin_for_capture_v4(scope.source,qualification=qualification,
                role="graph",cell_id=header[0],header=tuple(header[1:]),meter=meter)
        owner=_initial_owner_source_qualification_v3(scope,meter)
        return _initial_owner_cell_values_read_v3(owner,header[0],tuple(header[1:]),meter)


def prepare_character_labor_adoption_metadata_source_v1(build,shape,key,row,meter):
    if shape.table!=_TABLE or row[2]!=_KIND:return True
    reader=build.labor_metadata_reader_v1
    if reader is None or reader.shape!=shape or reader.key!=tuple(key):
        if reader is not None:reader.plan.release_v1();_READERS.discard(reader)
        reader=_CharacterLaborAdoptionSourceReadV1(build,shape,key,row,meter=meter)
        build.labor_metadata_reader_v1=reader
    if reader.digest!=row[6]:raise C09PagedCaptureHold("labor metadata original changed during its frozen read")
    return reader.advance_v1(meter)


def confirm_character_labor_metadata_quantum_v1(build):
    reader=build.labor_metadata_reader_v1
    if reader is not None:reader.confirm_quantum_v1()


def require_character_labor_adoption_metadata_source_v1(build,value):
    reader=build.labor_metadata_reader_v1
    if (reader is None or reader not in _READERS or not reader.complete or reader.metadata!=value
            or reader.builder is not build):
        raise C09PagedCaptureHold("complete actual frozen labor adoption membership proof required")
    reader.require_current_v3()
    return reader.proof


def require_body_policy_checkpoint_history_v1(build,value,*,meter):
    """Actual small installation Event/GraphReceipt, not a synthetic W01 receipt."""
    from ..runtime.d10_offline_tick_execution_v1 import _decode_json
    from ..domains.d02.body_quote_original import FixedBodyPolicyV1
    from ..contracts import Event,Scope
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt,NamespaceEpoch
    from ..runtime.c09_native_outbox_v1 import _C09NativeOutboxReadV1
    build.require_current()
    if value.authority_namespace!=build.scope.authority_namespace:
        raise C09PagedCaptureHold("initial Body checkpoint crossed the actual Authority namespace")
    policy=_decode_json(value.policy_json,FixedBodyPolicyV1)
    signed_policy=meter.read_fixed_row(build.pair.source,"d02_fixed_body_policies_v1",
        ("policy_json","signature"),"bot=? AND persona=? AND policy_id=? AND version=?",
        (*value.namespace.as_tuple,policy.policy_id,policy.version))
    if signed_policy!=(value.policy_json,value.policy_signature):
        raise C09PagedCaptureHold("initial checkpoint changed its original signed numeric Body policy")
    event=json.loads(value.event_json);ns=value.namespace
    actual=meter.read_fixed_row(build.pair.source,"graph_events",("digest","reads","epoch_reads","revisions","invalidated","epoch_revision"),
        "bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple,event["scope"]["session"],value.producing_operation_id))
    if actual is None:raise C09PagedCaptureHold("initial Body checkpoint lost its actual installation event")
    actual_event=Event(Scope(**event["scope"]),event["event_id"],event["occurred_at"],event["kind"],event["payload"])
    if actual[0]!=actual_event.digest:
        raise C09PagedCaptureHold("initial Body checkpoint event digest differs")
    receipt=GraphReceipt("committed",GraphStore._version_rows(actual[3]),GraphStore._version_rows(actual[4]),
        NamespaceEpoch(*ns.as_tuple,actual[5]))
    if receipt!=value.graph_receipt or tuple(GraphStore._version_rows(actual[1]))!=tuple(
            type(v)(v.key,0)for v in receipt.revisions) or json.loads(actual[2])!=[[*ns.as_tuple,value.before_epoch]]:
        raise C09PagedCaptureHold("initial Body checkpoint actual READ0/two-write receipt differs")
    reader=_C09NativeOutboxReadV1(build,meter)
    try:
        for version,(_,expected)in zip(receipt.revisions,value.write_digests,strict=True):
            digest=reader._history_value(ns,version,event["scope"]["session"],value.producing_operation_id,retain=False)
            if digest!=expected:raise C09PagedCaptureHold("initial Body checkpoint actual numeric history differs")
    finally:reader.close()
