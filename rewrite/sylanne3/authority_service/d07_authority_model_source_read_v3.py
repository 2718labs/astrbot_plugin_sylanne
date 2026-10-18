
"""Exact D07 model Source qualification on the original Authority model permit."""
from __future__ import annotations
from dataclasses import fields
import json
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from .current_authority_graph_read_v3 import (
    AuthorityGraphReadWorkV3,require_actual_authority_graph_attachment_owner_v3)
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime_contracts import AuthorityContext,NamespaceId,canonical_serialize
from ..graph_types import AtomKey

_ISSUER=object()
_READERS=WeakKeyDictionary()
_HEADERS=WeakKeyDictionary()
_MATERIALS=WeakKeyDictionary()
_WORK_SOURCE_READERS=WeakKeyDictionary()

def _require_d07_authority_work_v3(work,bundle):
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_model_egress_contract import ModelEgressIntentV1
    from ..host.authority_profile import AdminInstallationBundle
    if (type(work)is not AuthorityGraphReadWorkV3
            or type(work.controller.service)is not AuthorityV2ModelEgressService
            or type(work.request)is not ModelEgressIntentV1
            or type(bundle)is not AdminInstallationBundle
            or work.controller.kind!="model"
            or work.controller.verifier._artifact_draft_bundle is not bundle
            or bundle.installation_policy.namespace!=work.namespace
            or work.permit.subject!=work.request.subject or work.subject!=work.request.subject
            or work.request.operation_id!=work.permit.operation_id):
        raise AuthorityUnavailable("D07 Source read requires its actual installed Authority model Work/permit/bundle")
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    return work


from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

def _d07_canonical_parser_heap_bytes_v3(parser):
    from ..runtime.source_correction_read_v3 import _heap
    containers=tuple((item.kind,item.path,item.state,item.previous_key,item.current_key,item.index)
        for item in parser._stack)
    decoder_state=(None if parser._string is None or parser._string["decoder"]is None
        else parser._string["decoder"].getstate())
    return _heap((containers,parser._string,parser._literal,parser._number,parser._active_scalar,decoder_state))

class _D07AuthorityFrozenMetadataReadV3:
    def __init__(self,column):
        self.column=column
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.nodes={};self.scalar=bytearray();self.value=None;self.complete=False
    def _retain_v3(self,path):
        if not path:return True
        if path[0]=="installation":return True
        if path[0]!="input":return False
        if len(path)==1:return True
        permitted={"namespace","activity_id","work_kind","question_key","target_ref","causal_depth",
            "c02_operation_id","cycle_job_ref","need_ref","need_digest","cue","known_sources","sources",
            "context_sources","support_sources","ordinary_block_id","scope","target_original_digest"}
        if path[1]not in permitted:return False
        if path[1]in {"sources","known_sources","context_sources","support_sources"}:
            return len(path)<=3 or path[3]=="source_ref"
        if path[1]=="cue":
            return len(path)<=2 or path[2]in {"source_ref","source_digest"}
        return True
    def _put_v3(self,path,value):
        if not path:self.value=value;return
        parent=self.nodes[path[:-1]]
        if type(parent)is list:parent.append(value)
        else:parent[path[-1]]=value
    def _emit_v3(self,event):
        if not self._retain_v3(event.path):return
        if event.kind in ("object_start","array_start"):
            from ..runtime.source_correction_read_v3 import _heap
            self.column._reserve(_heap(event.path)+1024)
            value={}if event.kind=="object_start"else[]
            self.nodes[event.path]=value;self._put_v3(event.path,value)
        elif event.kind=="scalar_start":self.scalar=bytearray()
        elif event.kind=="scalar_chunk":
            self.column._reserve(len(event.raw)*4+1024)
            self.scalar.extend(event.raw)
        elif event.kind=="scalar_end":
            self.column._reserve(len(self.scalar)*4+1024)
            self._put_v3(event.path,json.loads(self.scalar));self.scalar=bytearray()
    def feed_codepoint_v3(self,codepoint):
        self.parser.feed(chr(codepoint).encode("utf8"),self._emit_v3)
    def finish_v3(self):
        self.parser.finish();self.column._reserve();self.complete=True;return self.value

class _D07AuthorityPreparedLocatorStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self,column):
        self.column=column
        super().__init__(ensure_ascii=True)
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is not None and state["mode"]=="value" and state["path"]==("frozen_json",):
            self.column.frozen_metadata.feed_codepoint_v3(codepoint)
        return super()._append_decoded_codepoint(codepoint)

class _D07AuthorityLocatorColumnV3(DispatchOriginalJSONReadV3):
    """Authenticates all bytes, retaining only exact declared metadata."""
    def __init__(self,work,*,kind,original_ref,retained_fields):
        from ..runtime.d07_execution_v1 import TABLE
        self.retained_fields=frozenset(retained_fields)
        self.fields_seen=set();self.frozen_metadata=_D07AuthorityFrozenMetadataReadV3(self)
        super().__init__(work,table=TABLE,column="payload_json",
            key_columns=("bot","persona","kind","original_ref"),
            key=(*work.namespace.as_tuple,kind,original_ref))
        self.parser=_D07AuthorityPreparedLocatorStreamV3(self)
    def _reserve(self,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        nested=self.frozen_metadata
        size=_heap((self.nodes,self.scalar,self.fragment,self.value,self.fields_seen,
            nested.nodes,nested.scalar,nested.value))+_d07_canonical_parser_heap_bytes_v3(self.parser)
        size+=_d07_canonical_parser_heap_bytes_v3(nested.parser)+extra+65536
        if size>self.reserved:
            self.operation.retain(size-self.reserved);self.reserved=size
    def _emit(self,event):
        if event.kind=="key" and len(event.path)==1:self.fields_seen.add(event.key)
        path=event.path
        if path==("frozen_json",) and event.kind=="scalar_end":self.frozen_metadata.finish_v3()
        if path and path[0]not in self.retained_fields:return
        if path and path[0]=="read_rows" and (len(path)>3
                or len(path)==3 and path[2]not in {"ref","revision","valid"}):
            return
        super()._emit(event)

class _D07AuthorityPreparedHeaderReadV3:
    def __init__(self,reader,*,job_id,expected_digest=None):
        self.reader,self.work,self.job_id=reader,reader.work,job_id
        self.expected_digest=expected_digest
        self.phase="identity";self.metadata=self.column=self.value=None;self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.d07_execution_v1 import (TABLE,SIGN_KIND,D07PreparedExecutionV1,
            D07RelationshipPreparedV2,D07ReflectionPreparedV3,D07IngressRecallPreparedV1)
        from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from ..runtime.d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
        work=self.work;self.reader.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(work.db,meter,TABLE,
                ("payload_digest","signature"),"bot=? AND persona=? AND kind=? AND original_ref=?",
                (*work.namespace.as_tuple,"prepared",self.job_id))
            if self.metadata is None or self.expected_digest is not None and self.metadata[0]!=self.expected_digest:
                raise AuthorityUnavailable("D07 Source header lost its exact signed prepared original")
            retained=frozenset().union(*(frozenset(item.name for item in fields(cls))for cls in (
                D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,
                D07IngressRecallPreparedV1,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1,D07ArtifactObservationPreparedV3)))
            retained=retained-{"frozen_json","external_content_originals_json"}
            self.column=_D07AuthorityLocatorColumnV3(work,kind="prepared",original_ref=self.job_id,
                retained_fields=retained)
            self.phase="canonical";return
        if not self.column.advance(meter):return
        if self.column.sha256!=self.metadata[0]:
            raise AuthorityUnavailable("D07 Source header canonical raw EOF differs from its signed digest")
        issuer=work.controller.verifier._issuer
        issuer._signer.verify(SIGN_KIND,canonical_serialize((work.namespace,"prepared",self.job_id,
            self.metadata[0])),self.metadata[1])
        raw=self.column.require_v3(work)
        classes={cls.__dataclass_fields__["schema"].default:cls for cls in (
            D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,
            D07IngressRecallPreparedV1,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1,D07ArtifactObservationPreparedV3)}
        cls=classes.get(raw.get("schema"))
        if (cls is None or self.column.fields_seen!={field.name for field in fields(cls)}
                or raw["namespace"]!={"bot_id":work.namespace.bot_id,"persona_id":work.namespace.persona_id}
                or raw["job_id"]!=self.job_id):
            raise AuthorityUnavailable("D07 Source header has another exact schema/namespace/job")
        if cls is D07IngressRecallPreparedV1:
            if raw["work_kind"]!="recall_need":raise AuthorityUnavailable("D07 Self header work kind changed")
            authority_json=raw["self_authority_json"]
        else:
            if raw["work_kind"]not in {"concern","reflection","simulation"}:
                raise AuthorityUnavailable("D07 Source header work kind is unregistered")
            authority_json=raw["owner_authority_json"]
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        authority=decode_typed_production_value_v1(json.loads(authority_json),AuthorityContext)
        if (authority.namespace!=work.namespace or authority.activation_generation!=raw["activation_generation"]
                or authority.purpose!=raw["purpose"] or authority.audience!=tuple(raw["audience"])):
            raise AuthorityUnavailable("D07 original Source authority differs from its exact signed header")
        source_rows=tuple(row for row in raw["read_rows"]
            if AtomKey.from_token(row["ref"]).type_name=="memory.source" and row["valid"])
        if (not source_rows or len(source_rows)>256 or any(set(row)!={"ref","revision","valid"}
                or NamespaceId.from_key(AtomKey.from_token(row["ref"]))!=work.namespace
                or type(row["revision"])is not int or row["revision"]<1 for row in source_rows)):
            raise AuthorityUnavailable("D07 prepared header has no exact bounded namespace Source versions")
        frozen_metadata=self.column.frozen_metadata.value["input"]
        if frozen_metadata["namespace"]!=raw["namespace"] or frozen_metadata["activity_id"]!=raw["activity_id"]:
            raise AuthorityUnavailable("D07 frozen metadata changed its signed namespace/activity identity")
        selected=([frozen_metadata["cue"],*frozen_metadata["known_sources"]]
            if cls is D07IngressRecallPreparedV1 else
            (*frozen_metadata["context_sources"],*frozen_metadata["support_sources"])if cls is D07GeneralGrowthPreparedV1
            else frozen_metadata["sources"])
        declared={(row["ref"],row["revision"])for row in source_rows}
        if (not selected or any(set(item["source_ref"])!={"ref","version"}
                or (item["source_ref"]["ref"],item["source_ref"]["version"])not in declared for item in selected)):
            raise AuthorityUnavailable("D07 exact model Source locators are outside their signed prepared versions")
        self.value,self.authority,self.source_rows,self.prepared_class=raw,authority,source_rows,cls
        self.complete=True
        _HEADERS[self]=(self.reader,work,self.job_id,self.metadata,self.column,self.column.sha256,
            self.value,self.authority,self.source_rows,self.prepared_class,work.operation,work.scope)
    def require_v3(self,reader):
        if (not self.complete or reader is not self.reader or _HEADERS.get(self)!=(
                reader,self.work,self.job_id,self.metadata,self.column,self.column.sha256,
                self.value,self.authority,self.source_rows,self.prepared_class,self.work.operation,self.work.scope)):
            raise AuthorityUnavailable("D07 Source header was not emitted by this actual complete Work")
        _require_d07_authority_work_v3(self.work,reader.bundle)
        return self


def _require_d07_owner_header_v3(reader,phase):
    from .owner_location_read_v3 import (
        OwnerLocationCallerProofV3,require_owner_location_caller_proof_v3)
    proof=reader.owner_header_proof
    if type(proof)is not OwnerLocationCallerProofV3:
        raise TypeError("D07 model Source read requires the actual private Owner header proof")
    work=reader.work
    current=require_owner_location_caller_proof_v3(proof,phase=phase,graph_stamp=None)
    if (current is not proof or proof.kind!="authority_model_header" or proof.request is not work
            or proof.controller is not work.controller or proof.retained_operation is not work.operation
            or proof.original_permit is not work.permit or proof.subject!=work.subject
            or proof.namespace!=work.namespace or proof.deadline!=work.deadline_utc
            or proof.model_source_phase!=reader.model_source_phase):
        raise AuthorityUnavailable("D07 Owner metadata header crossed its actual Authority Work/permit/deadline")
    return proof

class D07AuthorityModelSourceReadV3:
    def __init__(self,issuer,work,*,owner_header_proof,owner_acl_authority,bundle,location_observation=None):
        if issuer is not _ISSUER:raise TypeError("actual D07 Authority Source reader issuer required")
        _require_d07_authority_work_v3(work,bundle)
        if (type(owner_acl_authority)is not AuthorityContext or owner_acl_authority.namespace!=work.namespace
                or owner_acl_authority.issuer_domain!="d12" or owner_acl_authority.owner_scope!=("d11",)):
            raise AuthorityUnavailable("D07 Source frontend requires actual Owner metadata ACL separately")
        self.work,self.bundle,self.owner_header_proof=work,bundle,owner_header_proof
        self.owner_acl_authority=owner_acl_authority
        self.model_source_phase=owner_header_proof.model_source_phase
        if self.model_source_phase not in {"model_seal_observer","model_policy"}:
            raise AuthorityUnavailable("D07 Source header has no actual closed model phase issuer")
        self.location_observation=location_observation
        location=work.controller.location
        if location is not None:
            observation=location._require_issued(location_observation)
            if observation.subject!=work.subject or observation.permit is not work.permit:
                raise AuthorityUnavailable("D07 generic Graph check requires its actual installed SourceLocation observation")
        elif location_observation is not None:
            raise AuthorityUnavailable("D07 SourceLocation observation lacks its actual installed controller")
        self.phase="header";self.header=_D07AuthorityPreparedHeaderReadV3(self,job_id=work.request.job_id)
        self.parent_headers={};self.pending_parent=None
        self.complete=False;self.failure=None;self.result=None;self.metadata_qualified=None
        self.generic_graph_verified=False;self.generic_graph_certificate=None
        self.originals={};self.pending_original=None;self.qualification=None
        self.metadata_atoms={};self.metadata_columns={}
        _READERS[self]=(work,owner_header_proof,owner_acl_authority,bundle,work.operation,work.scope,
            work.permit,work.request,work.deadline_utc,self.location_observation)
        _WORK_SOURCE_READERS[work]=self
        work.operation.register_retained_state_v3(self)
        _require_d07_owner_header_v3(self,"before")
    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from ..runtime.source_correction_read_v3 import _heap
        headers=(self.header,*self.parent_headers.values())
        # Columns own their parsed payload. This provider owns the derived
        # header tuple/authority and the reader's maps and live header objects.
        header_values=[]
        for header in headers:
            if header.complete:
                header_values.append((tuple(getattr(header.authority,field.name)for field in fields(AuthorityContext)),
                    header.source_rows))
        return (_heap((self.parent_headers,self.originals,self.metadata_atoms,self.metadata_columns,header_values))
            +sum(sys.getsizeof(header)for header in headers))
    def _reserve_header_growth_v3(self,header):
        import sys
        from ..runtime.source_correction_read_v3 import _heap
        growth=2*sys.getsizeof(self.parent_headers)+_heap(header.job_id)+sys.getsizeof(header)
        if header.column is not None and header.column.complete:
            raw=header.column.value
            authority_json=raw["self_authority_json"]if raw["schema"]=="d07.ingress-recall-prepared.v1"else raw["owner_authority_json"]
            growth+=len(authority_json)*4+2*sys.getsizeof(raw["read_rows"])
        self.work.operation.reserve_retained_state_growth_v3(self,growth)
    def require_registered_v3(self):
        work=self.work
        if (_WORK_SOURCE_READERS.get(work)is not self or _READERS.get(self)!=(work,self.owner_header_proof,
                self.owner_acl_authority,self.bundle,work.operation,work.scope,work.permit,work.request,work.deadline_utc,self.location_observation)):
            raise AuthorityUnavailable("D07 actual Source reader/namespace recipe registry changed")
        _require_d07_authority_work_v3(work,self.bundle)
        return self
    def require_current_v3(self,meter):
        work=self.work
        if (_READERS.get(self)!=(work,self.owner_header_proof,self.owner_acl_authority,self.bundle,
                work.operation,work.scope,work.permit,work.request,work.deadline_utc,self.location_observation)
                or self.failure is not None):
            raise AuthorityUnavailable("D07 Source reader changed its actual issuer/permit/operation")
        _require_d07_authority_work_v3(work,self.bundle)
        work.require_current(meter=meter)
    def advance(self):
        if self.failure is not None:raise self.failure
        if self.complete:return self.result
        _require_d07_owner_header_v3(self,"before")
        clock=self.work.controller.verifier._paired_clock()
        import math
        if (type(clock)is not tuple or len(clock)!=2 or type(clock[0])not in (int,float)
                or not math.isfinite(clock[0])or type(clock[1])is not str or not clock[1]):
            raise AuthorityUnavailable("D07 generic current Graph requires its actual paired trusted UTC/epoch sample")
        self.generic_clock=clock
        try:
            with self.work.quantum_v3()as meter:
                self.require_current_v3(meter)
                self._advance_v3(meter)
            _require_d07_owner_header_v3(self,"after")
            return self.result if self.complete else {"phase":self.phase,"complete":False}
        except BaseException as error:
            self.failure=error
            raise

    def require_body_qualification_v3(self):
        self.require_registered_v3()
        if self.failure is not None:raise self.failure
        proof=self.metadata_qualified
        if proof is None or not self.qualification.complete:
            raise AuthorityUnavailable("D07 protected body cannot precede actual parent/current Source metadata qualification")
        proof.require_for_v3(self)
        if self.work.controller.clock()>=proof.original_deadline_utc:
            raise AuthorityUnavailable("D07 body continuation cannot renew its original parent deadline")
        return self
    def require_selected_graph_body_v3(self,request):
        self.require_body_qualification_v3()
        if request[0]not in {"graph_atoms","graph_history","graph_dependencies"}:return
        token=request[3][0]
        declared={row["ref"]for h in (self.header,*self.parent_headers.values())for row in h.value["read_rows"]}
        declared.update(self.qualification.qualified)
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        for ref in self.qualification.qualified:
            source_id=AtomKey.from_token(ref).owner.subject
            declared.add(access_key(*self.work.namespace.as_tuple,source_id).token)
            declared.add(source_correction_head_key(self.work.namespace,source_id).token)
        if token not in declared:
            raise AuthorityUnavailable("D07 protected Graph body is outside its authenticated read set/Source closure")
        if request[0]=="graph_history":
            versions={(row["ref"],row["revision"])for h in (self.header,*self.parent_headers.values())for row in h.value["read_rows"]}
            versions.update((version.key.token,version.revision)for version in self.qualification.versions.values())
            if (token,request[3][1])not in versions:
                raise AuthorityUnavailable("D07 protected Graph history is outside its authenticated exact revisions")

    def _register_body_originals_v3(self):
        headers=(self.header,*self.parent_headers.values())
        allowed=set()
        for header in headers:
            header.require_v3(self)
            raw=header.value
            for kind in ("prepared","request","prepare_commit","call"):
                allowed.add((kind,header.job_id))
            if "semantic_question_ref"in raw:allowed.add(("semantic_question",raw["semantic_question_ref"]))
            if raw["schema"]=="d07.general-growth-prepared.v1":
                allowed.add(("general_growth_attention_v1",raw["general_growth_attention_ref"]))
            if raw["schema"]=="d07.reflection-prepared.v3":
                for kind,name in (("reflection_continuation","reflection_continuation_ref"),
                        ("reflection_request","reflection_request_ref"),("execution","parent_execution_ref")):
                    allowed.add((kind,raw[name]))
            allowed.add(("execution","d07-terminal:"+raw["call_id"]))
        self.allowed_originals=frozenset(allowed)
        self.allowed_query_types=frozenset()
    def _advance_v3(self,meter):
        from .current_authority_graph_read_v3 import (_advance_authority_local_materials_v3,
            bind_authority_graph_original_preparation_v3,AuthorityGraphAttachmentRequiredV3,
            _prepare_authority_attachment_v3)
        if self.phase=="header":
            self._reserve_header_growth_v3(self.header)
            try:self.header.advance(meter)
            finally:self.work.operation.finish_retained_state_growth_v3(self)
            if self.header.complete:
                current=self.header
                seen={current.job_id}
                while current.value["schema"]=="d07.reflection-prepared.v3":
                    parent_id=current.value["parent_prepared_ref"]
                    if parent_id in seen or len(seen)>2:
                        raise AuthorityUnavailable("D07 reflection metadata parent chain is cyclic or exceeds original depth")
                    parent=self.parent_headers.get(parent_id)
                    if parent is None:
                        self._reserve_header_growth_v3(current)
                        parent=_D07AuthorityPreparedHeaderReadV3(self,job_id=parent_id,
                            expected_digest=current.value["parent_prepared_digest"])
                        self.parent_headers[parent_id]=parent
                        self.work.operation.finish_retained_state_growth_v3(self)
                    if not parent.complete:
                        self.pending_parent=parent;self.phase="parent_header";return
                    parent.require_v3(self);seen.add(parent_id);current=parent
                self.phase="namespace"
            return
        if self.phase=="parent_header":
            self._reserve_header_growth_v3(self.pending_parent)
            try:self.pending_parent.advance(meter)
            finally:self.work.operation.finish_retained_state_growth_v3(self)
            if self.pending_parent.complete:self.pending_parent=None;self.phase="header"
            return
        if self.phase=="namespace":
            _advance_authority_local_materials_v3(self.work,meter)
            if self.work.phase=="validate":
                self.parent_task=prepare_d07_authority_special_parent_metadata_read_v3(self)
                self.phase="parent_metadata"
            return
        if self.phase=="parent_metadata":
            self.parent_task.advance_v3(meter)
            if self.parent_task.complete:
                self.metadata_qualified=qualify_d07_authority_special_parent_metadata_v3(self,self.parent_task)
                self.metadata_qualified.require_for_v3(self)
                self.effective_source_authority=self.metadata_qualified.effective_source_authority
                self.qualification=_D07AuthoritySourceQualificationV3(self)
                self.phase="source_rights"
            return
        if self.phase=="source_rights":
            self.qualification.advance_v3(meter)
            if self.qualification.complete:
                self._register_body_originals_v3();self.phase="body"
            return
        if self.phase=="body":
            self.require_body_qualification_v3()
            if self.pending_original is not None:
                self.pending_original.advance_v3(meter)
                if self.pending_original.complete:
                    original=self.pending_original
                    self.originals[(original.kind,original.original_ref)]=original
                    if original.kind=="prepare_commit" and original.original_ref==self.header.job_id:
                        if original.value is None or original.value["prepared_digest"]!=self.header.metadata[0]:
                            raise AuthorityUnavailable("D07 body current pages lost their exact preparation CAS")
                        pages=json.loads(original.value["post_query_inventory_json"])
                        if any(set(page)!={"type_id","rows","complete"} or not page["complete"]for page in pages):
                            raise AuthorityUnavailable("D07 body requires its exact complete current selection pages")
                        self.allowed_query_types=frozenset(page["type_id"]for page in pages)
                    self.pending_original=None
                return
            if self.work.pending is not None:
                _advance_authority_local_materials_v3(self.work,meter);return
            if ("prepare_commit",self.header.job_id)not in self.originals:
                self.pending_original=_D07AuthorityOriginalBodyReadV3(self,"prepare_commit",self.header.job_id);return
            from .d07_current_execution_v1 import read_current_d07_execution_graph_v1
            from ..runtime.d07_execution_v1 import read_original_d07_request_v1
            with bind_authority_graph_original_preparation_v3(self.work):
                try:
                    prepared,job,frozen=read_current_d07_execution_graph_v1(self.work.db,self.work.request,
                        self.work.controller.verifier._issuer,self.work.controller.clock(),
                        allow_unsealed_prepare=self.model_source_phase=="model_seal_observer",installed_bundle=self.bundle)
                    request=read_original_d07_request_v1(self.work.db,self.work.controller.verifier._issuer,prepared)
                    basis=read_current_d07_content_scope_basis_v3(self.work.db,issuer=self.work.controller.verifier._issuer,
                        prepared=prepared,request=request,frozen=frozen,bundle=self.bundle,
                        now=self.work.controller.clock(),owner_acl_authority=self.owner_acl_authority)
                except _D07AuthorityOriginalRequiredV3 as required:
                    self.pending_original=_D07AuthorityOriginalBodyReadV3(self,required.kind,required.original_ref);return
                except AuthorityGraphAttachmentRequiredV3 as required:
                    self.work.pending=_prepare_authority_attachment_v3(self.work,required.request);return
            if basis.effective_source_authority!=self.effective_source_authority:
                raise AuthorityUnavailable("D07 full body Source authority differs from its authenticated metadata parent chain")
            self.body_result=(prepared,job,frozen,request,basis)
            self.phase="generic_graph"
            return
        if self.phase=="generic_graph":
            self.require_body_qualification_v3()
            if self.work.pending is not None:
                _advance_authority_local_materials_v3(self.work,meter);return
            with bind_authority_graph_original_preparation_v3(self.work):
                try:
                    current=self.work.controller.verifier._current_graph_in_db_v3(self.work.db,self.work.request,
                        *self.generic_clock,include_binding=self.model_source_phase=="model_policy",source_location=self.work.controller.location,
                        location_observation=self.location_observation)
                except AuthorityGraphAttachmentRequiredV3 as required:
                    self.work.pending=_prepare_authority_attachment_v3(self.work,required.request);return
                except _D07AuthorityOriginalRequiredV3 as required:
                    self.pending_original=_D07AuthorityOriginalBodyReadV3(self,required.kind,required.original_ref)
                    self.phase="body";return
            if current is not True:
                raise AuthorityUnavailable("D07 actual generic version/scene/clock/model bindings are not current")
            self.generic_graph_verified=True
            self.generic_graph_certificate=(self.work.graph_stamp,self.generic_clock,self.location_observation,
                self.model_source_phase,self.work.operation,self.work.scope,self.work.permit,self.work.request)
            self.validation_rows=iter(tuple(self.work.attachments.values()))
            self.phase="validate_body";return
        if self.phase=="validate_body":
            self.require_body_qualification_v3()
            try:attachment=next(self.validation_rows)
            except StopIteration:self.phase="final";return
            attachment.require_row_v3(self.work,meter)
            return
        if self.phase=="final":
            self.require_body_qualification_v3()
            self.work.require_current(meter=meter)
            self.result=PreparedD07AuthoritySourceMaterialV3(_ISSUER,self)
            self.complete=True;return
        raise AuthorityUnavailable("unregistered D07 Authority Source read phase")

    def release_v3(self):
        self.work.operation.unregister_retained_state_v3(self)
        _READERS.pop(self,None)
        if _WORK_SOURCE_READERS.get(self.work)is self:_WORK_SOURCE_READERS.pop(self.work,None)
        for column in self.metadata_columns.values():_GRAPH_METADATA.pop(column,None)
        self.metadata_columns.clear();self.metadata_atoms.clear()
        for header in (self.header,*self.parent_headers.values()):_HEADERS.pop(header,None)
        if self.result is not None:
            _MATERIALS.pop(self.result,None)
            self.result.body=None
        if self.metadata_qualified is not None:_PARENT_PROOFS_V3.pop(self.metadata_qualified,None)
        task=self.__dict__.pop("parent_task",None)
        if task is not None:
            _PARENT_TASKS_V3.pop(task,None)
            if task.result is not None:_PARENT_PROOFS_V3.pop(task.result,None)
            task.pending=None;task.leaves.clear();task.headers.clear();task.result=None
        for header in (self.header,*self.parent_headers.values()):
            header.value=header.authority=header.source_rows=None
            if header.column is not None:
                header.column.nodes.clear();header.column.scalar.clear();header.column.value=None
                nested=header.column.frozen_metadata
                nested.nodes.clear();nested.scalar.clear();nested.value=None
                header.column.fragment=b"";header.column=None
        self.parent_headers.clear();self.originals.clear()
        self.body_result=None
        if self.qualification is not None:self.qualification.release_v3()
        self.pending_parent=self.pending_original=self.qualification=self.metadata_qualified=self.result=None

def prepare_current_d07_authority_model_source_read_v3(work,*,owner_header_proof,owner_acl_authority,bundle,location_observation=None):
    return D07AuthorityModelSourceReadV3(_ISSUER,work,owner_header_proof=owner_header_proof,
        owner_acl_authority=owner_acl_authority,bundle=bundle,location_observation=location_observation)


class _D07AuthoritySourceQualificationV3:
    def __init__(self,reader):
        self.reader,self.work=reader,reader.work
        headers=(reader.header,*reader.parent_headers.values())
        self.expected={};self.pending=[];self.qualified={};self.versions={}
        self.work.operation.register_retained_state_v3(self)
        from ..runtime.source_correction_read_v3 import _heap
        growth=sum(_heap(header.source_rows)for header in headers)*2
        self.work.operation.reserve_retained_state_growth_v3(self,growth)
        for header in headers:
            header.require_v3(reader)
            for row in header.source_rows:
                prior=self.expected.get(row["ref"])
                if prior is not None and prior!=row["revision"]:
                    raise AuthorityUnavailable("D07 original parent chain has conflicting Source versions")
                self.expected[row["ref"]]=row["revision"]
        if not self.expected or len(self.expected)>256:
            raise AuthorityUnavailable("D07 Authority Source roots exceed the declared original bound")
        self.pending=list(self.expected)
        self.complete=False
        self.work.operation.finish_retained_state_growth_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from ..runtime.source_correction_read_v3 import _heap
        records=tuple((ref,tuple(record.metadata.items()))for ref,(_,record)in self.qualified.items())
        return _heap((self.expected,self.pending,self.qualified,self.versions,records))
    def release_v3(self):
        self.work.operation.unregister_retained_state_v3(self)
        self.expected.clear();self.pending.clear();self.qualified.clear();self.versions.clear()
    def advance_v3(self,meter):
        from ..runtime.source_correction_read_v3 import _heap
        import sys
        if not self.pending:
            growth=_heap(tuple(self.expected))*2+sys.getsizeof(set())*2
        else:
            ref=self.pending[-1];witness=self.work.sources.get(ref)
            metadata=()if witness is None else tuple(witness.metadata.items())
            # Actual metadata bounds the newly copied record, three version/key
            # objects, ancestor tokens, and resizing of the four owned containers.
            growth=4*_heap((ref,metadata))+2*sum(sys.getsizeof(value)for value in(
                self.expected,self.pending,self.qualified,self.versions))
        self.work.operation.reserve_retained_state_growth_v3(self,growth)
        try:return self._advance_source_rights_v3(meter)
        finally:self.work.operation.finish_retained_state_growth_v3(self)
    def _advance_source_rights_v3(self,meter):
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        from ..graph_types import GraphVersion
        r=self.reader;work=self.work;r.require_current_v3(meter)
        if not self.pending:
            active,done=set(),set()
            def visit(ref):
                if ref in active:raise AuthorityUnavailable("D07 current Source ancestry is cyclic")
                if ref in done:return
                active.add(ref)
                for parent in self.qualified[ref][1].parent_source_ids:
                    visit(source_key(*work.namespace.as_tuple,parent).token)
                active.remove(ref);done.add(ref)
            for ref in self.expected:visit(ref)
            self.complete=True;return
        ref=self.pending.pop()
        if ref in self.qualified:return
        if len(self.qualified)>=256:
            raise AuthorityUnavailable("D07 current Source ancestors exceed the original bounded family")
        key=AtomKey.from_token(ref);witness=work.sources.get(ref)
        if (key!=source_key(*work.namespace.as_tuple,key.owner.subject)
                or witness is None or not witness.valid
                or ref in self.expected and witness.revision!=self.expected[ref]):
            raise AuthorityUnavailable("D07 current Source metadata is absent or differs from its declared original")
        witness.require_current_v3()
        access=access_key(*work.namespace.as_tuple,key.owner.subject)
        correction=source_correction_head_key(work.namespace,key.owner.subject)
        from ..graph_types import GraphAtom
        access_atom=r.metadata_atoms.get(access)
        current_correction=work.heads.get(correction.token)
        correction_atom=(GraphAtom(correction,0,{},False)if current_correction is None
            else GraphAtom(correction,current_correction[0],{},bool(current_correction[1])))
        record=None
        for audience in r.effective_source_authority.audience:
            record=_qualify_source_rights_values_v3(work.namespace,ref,witness,access_atom,correction_atom,
                audience=audience,purpose=r.effective_source_authority.purpose,metadata_only=True)
            if record is None:
                raise AuthorityUnavailable("D07 current Source metadata ACL/purpose/audience/correction is denied")
        self.qualified[ref]=(witness,record)
        for atom in (access_atom,correction_atom):self.versions[atom.key]=GraphVersion(atom.key,atom.revision)
        self.versions[key]=GraphVersion(key,witness.revision)
        self.pending.extend(source_key(*work.namespace.as_tuple,parent).token for parent in record.parent_source_ids)


_GRAPH_METADATA=WeakKeyDictionary()

class _D07AuthorityGraphMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,reader,key,revision,valid,cell_id):
        from ..memory_types import _ACCESS_FIELDS
        from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
        from ..graph_types import owner_grant_key
        from ..memory_types import access_key
        work=reader.work
        reader.require_registered_v3()
        if NamespaceId.from_key(key)!=work.namespace:
            raise AuthorityUnavailable("D07 metadata column crossed its actual namespace")
        if key==owner_grant_key(*work.namespace.as_tuple):
            # The existing OwnerGrant schema is metadata; validate its complete exact schema below.
            self.retained_fields=None
        elif key==self_mapping_key(work.namespace):
            self.retained_fields={field.name for field in fields(SelfIdentityMapping)}
        elif key.type_name==access_key(*work.namespace.as_tuple,"source-metadata-type").type_name:
            self.retained_fields=frozenset(_ACCESS_FIELDS)
        else:
            raise AuthorityUnavailable("D07 metadata projection has no exact declared schema")
        self.reader,self.key,self.revision,self.valid=reader,key,revision,bool(valid)
        self.fields_seen=set()
        super().__init__(work,table="graph_atoms",column="value",
            key_columns=("token","bot","persona"),key=(key.token,*work.namespace.as_tuple),cell_id=cell_id)
        import codecs
        from hashlib import sha256
        self.canonical_semantic_digest=None
        self.semantic_decoder=(codecs.getincrementaldecoder("utf8")("strict")if self.cell.header[0]=="canonical-json.utf8.v1"else None)
        self.semantic_hash=sha256()if self.semantic_decoder is not None else None
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.semantic_decoder is None)
    def _emit(self,event):
        if event.kind=="key" and len(event.path)==1:self.fields_seen.add(event.key)
        if event.path and self.retained_fields is not None and event.path[0]not in self.retained_fields:return
        super()._emit(event)
    def advance(self,meter):
        self.reader.require_current_v3(meter)
        if self.complete:return True
        if self.semantic_decoder is not None and self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self._semantic_v3(self.fragment[self.fragment_offset:end],meter)
        complete=super().advance(meter)
        if complete:
            if self.semantic_decoder is None:self.canonical_semantic_digest=self.sha256
            else:
                self._semantic_v3(b"",meter,final=True)
                self.canonical_semantic_digest=self.semantic_hash.hexdigest()
            self.semantic_decoder=self.semantic_hash=None
        return complete
    def _semantic_v3(self,fragment,meter,*,final=False):
        text=self.semantic_decoder.decode(fragment,final=final)
        encoded=[]
        for char in text:
            codepoint=ord(char)
            if codepoint<127:encoded.append(char)
            elif codepoint<=65535:encoded.append(chr(92)+"u"+format(codepoint,"04x"))
            else:
                codepoint-=65536
                encoded.append(chr(92)+"u"+format(55296+(codepoint>>10),"04x")+chr(92)+"u"+format(56320+(codepoint&1023),"04x"))
        raw="".join(encoded).encode("ascii");meter.charge_encode(len(raw));self.semantic_hash.update(raw)
    def finish_metadata_v3(self):
        from ..graph_types import GraphAtom,owner_grant_key,validate_owner_grant_v1
        from ..memory_types import validate_access,access_key
        from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
        work=self.owner;reader=self.reader;reader.require_registered_v3()
        if not self.complete:raise AuthorityUnavailable("D07 Graph metadata has no whole canonical cell EOF")
        value=self.require_v3(work)
        if self.key==owner_grant_key(*work.namespace.as_tuple):
            validate_owner_grant_v1(value)
        elif self.key==self_mapping_key(work.namespace):
            if self.fields_seen!=self.retained_fields:
                raise AuthorityUnavailable("D07 Self mapping metadata shape differs from its exact schema")
            SelfIdentityMapping(**value)
        elif self.key.type_name==access_key(*work.namespace.as_tuple,"source-metadata-type").type_name:
            if self.fields_seen!=self.retained_fields:
                raise AuthorityUnavailable("D07 Source Access metadata has another fieldset")
            validate_access(value)
        atom=GraphAtom(self.key,self.revision,value,self.valid)
        _GRAPH_METADATA[self]=(reader,work,self.key,self.revision,self.valid,self.cell.cell_id,
            tuple(self.cell.header),self.sha256,self.byte_count,work.operation,work.scope,atom)
        reader.metadata_atoms[self.key]=atom
        reader.metadata_columns[self.key]=self
        return atom

def require_current_d07_authority_namespace_recipe_v3(work):
    reader=_WORK_SOURCE_READERS.get(work)
    if reader is None:return None
    reader.require_registered_v3()
    return reader

def d07_authority_namespace_retains_type_v3(reader,key):
    from ..graph_types import owner_grant_key
    from ..memory_types import access_key
    from ..domains.d03.self_perspective import self_mapping_key
    reader.require_registered_v3()
    return (key==owner_grant_key(*reader.work.namespace.as_tuple)
        or key==self_mapping_key(reader.work.namespace)
        or key.type_name==access_key(*reader.work.namespace.as_tuple,"source-metadata-type").type_name)

def prepare_d07_authority_namespace_metadata_column_v3(reader,key,revision,valid,cell_id):
    reader.require_registered_v3()
    if not d07_authority_namespace_retains_type_v3(reader,key):
        raise AuthorityUnavailable("D07 actual namespace recipe did not select this metadata-only Graph leaf")
    return _D07AuthorityGraphMetadataColumnV3(reader,key,revision,valid,cell_id)


def release_current_d07_authority_source_reader_v3(work):
    reader=_WORK_SOURCE_READERS.get(work)
    if reader is None:return
    reader.require_registered_v3()
    reader.release_v3()


class PreparedD07AuthoritySourceMaterialV3:
    def __init__(self,issuer,reader):
        if (issuer is not _ISSUER or reader.phase!="final" or reader.body_result is None
                or reader.generic_graph_verified is not True):
            raise TypeError("actual whole-body current D07 Authority Source material required")
        reader.require_body_qualification_v3()
        self.reader,self.work=reader,reader.work
        self.body=reader.body_result
        self.graph_stamp=self.work.graph_stamp
        self.parent_proof=reader.metadata_qualified
        self.source_versions=tuple(reader.qualification.versions.values())
        self.generic_graph_certificate=reader.generic_graph_certificate
        _MATERIALS[self]=(reader,self.work,self.body,self.graph_stamp,self.parent_proof,
            self.source_versions,self.generic_graph_certificate,self.work.operation,self.work.scope,self.work.permit,self.work.request)
    def require_for_observer_v3(self,work):
        if (work is not self.work or not self.reader.complete or _MATERIALS.get(self)!=(self.reader,work,
                self.body,self.graph_stamp,self.parent_proof,self.source_versions,self.generic_graph_certificate,
                work.operation,work.scope,work.permit,work.request)):
            raise AuthorityUnavailable("D07 observer has no actual same-Work complete Source/body material")
        certificate=self.generic_graph_certificate
        if (certificate is not self.reader.generic_graph_certificate or type(certificate)is not tuple
                or certificate[0]!=work.graph_stamp or certificate[2]is not self.reader.location_observation
                or certificate[3]!=self.reader.model_source_phase
                or certificate[4:]!=(work.operation,work.scope,work.permit,work.request)):
            raise AuthorityUnavailable("D07 Source material lost its actual same-Work generic Graph validation")
        _require_d07_owner_header_v3(self.reader,"before")
        with work.quantum_v3()as meter:
            self.reader.require_current_v3(meter)
            self.reader.require_body_qualification_v3()
        _require_d07_owner_header_v3(self.reader,"after")
        return self.body


class _D07AuthorityOriginalBodyReadV3:
    """One exact immutable D07 original; protected JSON is retained only after the metadata gate."""
    def __init__(self,reader,kind,original_ref):
        from ..runtime.d07_execution_v1 import TABLE,KINDS
        reader.require_body_qualification_v3()
        if kind not in KINDS or (kind,original_ref)not in reader.allowed_originals:
            raise AuthorityUnavailable("D07 body request is outside its actual authenticated parent/read set")
        self.reader,self.work,self.kind,self.original_ref=reader,reader.work,kind,original_ref
        self.phase="metadata";self.metadata=self.column=self.value=None;self.complete=False
        self.table=TABLE
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.d07_execution_v1 import SIGN_KIND
        reader=self.reader;reader.require_current_v3(meter);reader.require_body_qualification_v3()
        work=self.work
        if self.phase=="metadata":
            self.metadata=_runtime_bounded_fixed_row_v3(work.db,meter,self.table,
                ("payload_digest","signature"),"bot=? AND persona=? AND kind=? AND original_ref=?",
                (*work.namespace.as_tuple,self.kind,self.original_ref))
            if self.metadata is None:self.complete=True;return
            self.column=DispatchOriginalJSONReadV3(work,table=self.table,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),
                key=(*work.namespace.as_tuple,self.kind,self.original_ref))
            self.phase="body";return
        if not self.column.advance(meter):return
        if self.column.sha256!=self.metadata[0]:
            raise AuthorityUnavailable("D07 protected original lacks its complete original raw-byte digest")
        issuer=work.controller.verifier._issuer
        issuer._signer.verify(SIGN_KIND,canonical_serialize((work.namespace,self.kind,
            self.original_ref,self.metadata[0])),self.metadata[1])
        self.value=self.column.require_v3(work)
        self.complete=True
    def require_original_v3(self,reader):
        reader.require_body_qualification_v3()
        if reader is not self.reader or not self.complete or reader.originals.get((self.kind,self.original_ref))is not self:
            raise AuthorityUnavailable("D07 full original was not prepared by this actual qualified Work")
        return None if self.metadata is None else (self.value,self.metadata[0])

class _D07AuthorityOriginalRequiredV3(Exception):
    def __init__(self,kind,original_ref):
        self.kind,self.original_ref=kind,original_ref

def read_bound_current_d07_authority_original_v3(db,issuer,namespace,kind,original_ref):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None:return False,None
    reader=require_current_d07_authority_namespace_recipe_v3(work)
    if reader is None:return False,None
    reader.require_body_qualification_v3()
    if namespace!=work.namespace or issuer is not work.controller.verifier._issuer:
        raise AuthorityUnavailable("D07 immutable original crossed its actual Authority signer/namespace")
    if (kind,original_ref)not in reader.allowed_originals:
        raise AuthorityUnavailable("D07 original is outside its exact authenticated body read set")
    original=reader.originals.get((kind,original_ref))
    if original is None or not original.complete:
        raise _D07AuthorityOriginalRequiredV3(kind,original_ref)
    return True,original.require_original_v3(reader)

def read_bound_current_d07_authority_query_rows_v3(db,namespace,type_id):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None:return False,None
    reader=require_current_d07_authority_namespace_recipe_v3(work)
    if reader is None:return False,None
    reader.require_body_qualification_v3()
    if namespace!=work.namespace or type_id not in reader.allowed_query_types:
        raise AuthorityUnavailable("D07 query metadata is outside the actual signed preparation read set")
    rows=tuple(sorted((token,head[0])for token,head in work.heads.items()
        if AtomKey.from_token(token).type_name==type_id))
    if len(rows)>128:
        raise AuthorityUnavailable("D07 complete current query exceeds its original 128-row contract")
    return True,rows

from dataclasses import dataclass

@dataclass(frozen=True,slots=True)
class D07ContentScopeBasisV3:
    kind:str
    owner_acl_authority:object
    effective_source_authority:object
    delegation_originals:tuple
    source_versions:tuple
    source_authorization_digest:str
    query_inventory_digest:str
    original_deadline_utc:float

def read_current_d07_content_scope_basis_v3(db,*,issuer,prepared,request,frozen,bundle,now,owner_acl_authority):
    """Actual qualified model-read input only; this result issues no Source scope."""
    from ..runtime_contracts import AuthorityContext,canonical_digest,NamespaceId
    from ..graph_types import AtomKey,GraphVersion
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    from ..runtime.d07_execution_v1 import (D07PreparedExecutionV1,D07RelationshipPreparedV2,
        D07IngressRecallPreparedV1,D07ReflectionPreparedV3,read_prepared_d07_execution_v1,
        read_original_d07_request_v1,read_d07_original_v1,require_current_d07_content_reads_v1)
    from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from ..runtime.d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    from ..runtime.foreground_call_plan_v1 import require_current_named_c3_cycle_v2
    if (not db.in_transaction or type(owner_acl_authority)is not AuthorityContext
            or owner_acl_authority.namespace!=prepared.namespace or owner_acl_authority.owner_scope!=("d11",)
            or owner_acl_authority.issuer_domain!="d12"):
        raise ValueError("actual qualified model Work/current Owner metadata ACL required")
    actual=read_prepared_d07_execution_v1(db,issuer,prepared.namespace,prepared.job_id)
    call=read_original_d07_request_v1(db,issuer,prepared)
    if actual!=prepared or call.digest!=request.digest:
        raise ValueError("D07 Source basis changed its actual signed prepared/request")
    require_current_d07_content_reads_v1(db,prepared,issuer=issuer)
    originals=[ProductionOriginalRefV1("d07.prepared",prepared.job_id,prepared.digest)]
    if type(prepared)is D07IngressRecallPreparedV1:
        from .d07_current_execution_v1 import _require_current_ingress_recall_parent_v1
        _require_current_ingress_recall_parent_v1(db,prepared=prepared,frozen=frozen,request=request,
            issuer=issuer,installed_bundle=bundle,now=now)
        source=decode_typed_production_value_v1(background_json_loads_v3(prepared.self_authority_json),AuthorityContext)
        kind="ingress_recall_self"
        from ..runtime.d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        need=read_adopted_domain_operation_v1(db,prepared.namespace,
            ingress_recall_need_operation_id_v1(prepared.namespace,prepared.c02_operation_id))
        if need is None:raise ValueError("actual Self Need adoption missing")
        originals.append(ProductionOriginalRefV1(need["domain"]+".current-"+need["operation_kind"],prepared.need_ref,need["original_digest"]))
    elif type(prepared)is D07ReflectionPreparedV3:
        from ..runtime.d07_reflection_execution_v1 import read_reflection_continuation_v3,require_current_reflection_parent_v3
        continuation=read_reflection_continuation_v3(db,issuer,prepared.namespace,prepared.reflection_continuation_ref)
        if continuation is None or continuation[1]!=prepared.reflection_continuation_digest:
            raise ValueError("actual reflection Source continuation missing")
        _,parent,_,_=require_current_reflection_parent_v3(db,issuer=issuer,namespace=prepared.namespace,
            continuation=continuation[0],now_utc=now)
        parent_call=read_original_d07_request_v1(db,issuer,parent)
        from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1,thaw_d07_ingress_recall_request_v1
        from ..runtime.d07_general_growth_execution_v1 import thaw_current_general_growth_prepared_request_v1
        parent_frozen=(thaw_d07_ingress_recall_request_v1(background_json_loads_v3(parent.frozen_json))
            if type(parent)is D07IngressRecallPreparedV1 else
            thaw_current_general_growth_prepared_request_v1(parent)if type(parent)is D07GeneralGrowthPreparedV1
            else thaw_d07_cognition_request_v1(background_json_loads_v3(parent.frozen_json)))
        basis=read_current_d07_content_scope_basis_v3(db,issuer=issuer,prepared=parent,request=parent_call,
            frozen=parent_frozen,bundle=bundle,now=now,owner_acl_authority=owner_acl_authority)
        source=basis.effective_source_authority;kind="reflection"
        originals.extend(basis.delegation_originals)
        originals.append(ProductionOriginalRefV1("d07.reflection_continuation",prepared.reflection_continuation_ref,continuation[1]))
        if prepared.cycle_ref is not None:
            require_current_named_c3_cycle_v2(db,namespace=prepared.namespace,prepared=prepared,issuer=issuer)
    elif type(prepared)is D07ArtifactObservationPreparedV3:
        from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
        from ..runtime.artifact_observation_parentage_v3 import require_qualified_artifact_observation_basis_v3
        work=_authority_attachment_owner_v3(db)
        reader=None if work is None else require_current_d07_authority_namespace_recipe_v3(work)
        if reader is None:raise AuthorityUnavailable("Artifact observation requires its actual Source Work")
        artifact_basis=require_qualified_artifact_observation_basis_v3(reader,prepared)
        require_current_named_c3_cycle_v2(db,namespace=prepared.namespace,prepared=prepared,issuer=issuer)
        source=reader.metadata_qualified.require_for_v3(reader).effective_source_authority
        kind="artifact_observation_self"
        originals.extend((ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,
            prepared.semantic_question_digest),ProductionOriginalRefV1("d11.life_artifact_phase_observation_basis_v1",
            artifact_basis.original_ref,artifact_basis.digest)))
    elif type(prepared)is D07MethodGrowthPreparedV2:
        from ..runtime.d07_execution_v1 import read_current_d07_semantic_question_v1,require_current_method_growth_question_v2
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        from ..runtime.natural_producer_qualification_v1 import _producer_original_point_v3
        question=read_current_d07_semantic_question_v1(db,issuer,prepared.namespace,prepared.semantic_question_ref)
        if question is None:raise ValueError("actual Method semantic Source question missing")
        require_current_method_growth_question_v2(db,namespace=prepared.namespace,question=question,issuer=issuer)
        require_current_named_c3_cycle_v2(db,namespace=prepared.namespace,prepared=prepared,issuer=issuer)
        history=_producer_original_point_v3(db,table="graph_history",columns=("event_id",),
            key_columns=("token","revision"),key=(prepared.proposal_head.key.token,prepared.proposal_head.revision),
            legacy_reader=lambda:db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
                (prepared.proposal_head.key.token,prepared.proposal_head.revision)).fetchone())
        adoption=None if history is None else read_adopted_domain_operation_v1(db,prepared.namespace,history[0])
        if adoption is None or adoption["operation_kind"]!="register_method_trial_proposal_v2":
            raise ValueError("actual Method semantic Self scope adoption missing")
        source=decode_typed_production_value_v1(adoption["payload"]["authority"],AuthorityContext)
        kind="method_growth_self"
        originals.append(ProductionOriginalRefV1("d01.actual-method-proposal",prepared.proposal_head.key.token,prepared.proposal_digest))
        originals.append(ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,prepared.semantic_question_digest))
    elif type(prepared)is D07GeneralGrowthPreparedV1:
        from ..runtime.d07_general_growth_execution_v1 import require_current_general_growth_prepared_v1
        question,attention,_=require_current_general_growth_prepared_v1(db,issuer=issuer,prepared=prepared,
            installed_bundle=bundle,now=now,frozen=frozen)
        source=decode_typed_production_value_v1(background_json_loads_v3(prepared.owner_authority_json),AuthorityContext)
        if source!=attention[0].source_authority:
            raise AuthorityUnavailable("General actual Source authority differs from its signed attention parent")
        kind="general_growth_owner"
        originals.extend((ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,
            prepared.semantic_question_digest),ProductionOriginalRefV1("d07.general_growth_attention_v1",
            prepared.general_growth_attention_ref,prepared.general_growth_attention_digest)))
    elif type(prepared)in (D07PreparedExecutionV1,D07RelationshipPreparedV2):
        source=decode_typed_production_value_v1(background_json_loads_v3(prepared.owner_authority_json),AuthorityContext)
        kind="ordinary_owner"
        if type(prepared)is D07RelationshipPreparedV2:
            require_current_named_c3_cycle_v2(db,namespace=prepared.namespace,prepared=prepared,issuer=issuer)
            kind="relationship_self"
            originals.append(ProductionOriginalRefV1("d07.semantic_question",prepared.semantic_question_ref,prepared.semantic_question_digest))
    else:
        raise TypeError("D07 Source basis has an unregistered exact prepared variant")
    if (source.namespace!=prepared.namespace or source.purpose!=prepared.purpose or source.audience!=prepared.audience
            or source.activation_generation!=prepared.activation_generation):
        raise ValueError("actual original D07 Source authority crossed namespace/purpose/audience/activation")
    versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)for row in prepared.read_rows
        if AtomKey.from_token(row.ref).type_name in ("memory.source","memory.access","d06.source_correction_head.v1"))
    if not versions or any(NamespaceId.from_key(version.key)!=prepared.namespace for version in versions):
        raise ValueError("D07 Source basis lacks its exact positive source metadata closure")
    query_digest=canonical_digest(background_json_loads_v3(prepared.query_inventory_json))
    delegation=tuple(dict.fromkeys(originals))
    authorization=canonical_digest((source,delegation,versions,query_digest,prepared.digest))
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    actual_work=_authority_attachment_owner_v3(db)
    reader=None if actual_work is None else require_current_d07_authority_namespace_recipe_v3(actual_work)
    if reader is None:
        raise AuthorityUnavailable("D07 Source basis requires its actual qualified original Authority Work")
    reader.require_body_qualification_v3()
    parent_proof=reader.metadata_qualified.require_for_v3(reader)
    if parent_proof.effective_source_authority!=source:
        raise AuthorityUnavailable("D07 Source basis changed its metadata-qualified original Source actor")
    deadline=parent_proof.original_deadline_utc
    if now>=deadline:
        raise AuthorityUnavailable("D07 Source basis exceeded its actual original ancestor deadline")
    return D07ContentScopeBasisV3(kind,owner_acl_authority,source,delegation,versions,authorization,query_digest,deadline)


def read_d07_authority_metadata_commitment_v3(reader,key):
    reader.require_registered_v3()
    column=reader.metadata_columns.get(key)
    if type(column)is not _D07AuthorityGraphMetadataColumnV3:
        raise AuthorityUnavailable("D07 requested metadata commitment has no exact whole-cell issuer")
    atom=reader.metadata_atoms.get(key)
    expected=(reader,reader.work,key,column.revision,column.valid,column.cell.cell_id,
        tuple(column.cell.header),column.sha256,column.byte_count,reader.work.operation,reader.work.scope,atom)
    if _GRAPH_METADATA.get(column)!=expected or not column.complete:
        raise AuthorityUnavailable("D07 metadata commitment changed its actual complete cell/header/Work")
    return column.revision,column.valid,column.sha256,column.canonical_semantic_digest

# Special-parent metadata is qualified before any prepared Source body is decoded.
_PARENT_TASKS_V3=WeakKeyDictionary()
_PARENT_PROOFS_V3=WeakKeyDictionary()

class _D07ParentMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,work,*,table,column,key_columns,key,mode,cell_id=None,erasure_owner_ref=None):
        self.mode=mode;self.fields_seen=set()
        super().__init__(work,table=table,column=column,key_columns=key_columns,key=key)
        if cell_id is not None:
            from ..runtime_storage_v3 import begin_runtime_cell_read_v3
            self.cell=begin_runtime_cell_read_v3(work.db,cell_id,erasure_owner_ref=erasure_owner_ref)
            if self.cell.header[0]not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
                raise AuthorityUnavailable("D07 parent metadata requires an actual canonical JSON cell")
            self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")
        import codecs
        from hashlib import sha256
        self.canonical_semantic_digest=None
        self.semantic_decoder=(codecs.getincrementaldecoder("utf8")("strict")
            if self.cell is not None and self.cell.header[0]=="canonical-json.utf8.v1"else None)
        self.semantic_hash=sha256()if self.semantic_decoder is not None else None
    def advance(self,meter):
        if self.complete:return True
        if self.semantic_decoder is not None and self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self._semantic_v3(self.fragment[self.fragment_offset:end],meter)
        complete=super().advance(meter)
        if complete:
            if self.semantic_decoder is None:self.canonical_semantic_digest=self.sha256
            else:
                self._semantic_v3(b"",meter,final=True)
                self.canonical_semantic_digest=self.semantic_hash.hexdigest()
            self.semantic_decoder=self.semantic_hash=None
        return complete
    _semantic_v3=_D07AuthorityGraphMetadataColumnV3._semantic_v3
    def _retain_v3(self,path):
        if not path:return True
        mode=self.mode
        if mode in {"graph_job","graph_proposal","checkpoint"}:
            fields={
                "graph_job":{"bot_id","persona_id","activity_id","operation_id","effect_id","job_id","snapshot_ref",
                    "phase","work_kind","continuation_digest","wake_condition_digest","deadline_utc","parent_budget_lease_ref",
                    "resource_ref","operator_versions_digest","lease_holder","lease_expires_utc","fence","cancel_epoch","usage_digest","result_ref"},
                "graph_proposal":{"namespace","trial_id","growth_proposal_ref","base_persona_head","target_block","protocol_ref",
                    "protocol_digest","goal_refs","source_refs","valid_from","valid_until","schema"},
                "checkpoint":{"schema","reflection_id","meta_depth","no_progress_count","status"}}
            return path[0]in fields[mode]
        if mode=="general_ticket":
            from ..domains.d07 import AttentionTicket
            return path[0]in {"schema",*(field.name for field in fields(AttentionTicket))}
        if mode in {"artifact_goal","artifact_plan"}:
            return path[0]in ({"goal_id","revision","state"}if mode=="artifact_goal"else
                {"schema","plan_id","revision","goal_ref","goal_revision","state","actor_ref"})
        if mode=="artifact_file":
            prefixes=(("schema",),("namespace",),("result_ref",),("producing_operation_id",),
                ("terminal","payload","status"),("terminal","payload","readback"))
            return any(path[:len(prefix)]==prefix or prefix[:len(path)]==path for prefix in prefixes)
        if mode=="artifact_observation_registration":
            if path[0]in {"schema","namespace","identity","authority","request"}:return True
            return path[0]=="provenance"and(len(path)==1 or
                path[1]in {"artifact_observation_basis","artifact_observation_ticket"})
        if mode=="semantic_question":return path[0]!="question"
        if mode=="reflection_request":return path[0]not in {"question","unresolved_slots"}
        if mode=="execution":
            return path[0]in {"schema","namespace","work_kind","prepared_digest","source_refs",
                "causal_depth","terminal_ref","activity_id","operation_id","call_id","output_digest",
                "effect_id","attempt_id","execution_id","input_digest","parent_budget_ref","activation_generation","status","cost_receipt_refs"}
        if mode=="continuation":
            if path[0]=="request":return len(path)==1 or path[1]=="category"
            if path[0]=="choice":return len(path)==1 or path[1]=="ticket_id"
            return path[0]in {"schema","source_ref","source_revision","c02_operation_id",
                "ingress_operation_id","cancel_generation","call_plan","responsibility_ref",
                "responsibility_digest","stage","source_barrier_epoch","stage_cursor","pending_effect_refs","completed_operation_refs","wait","request","choice"}
        if mode=="domain":
            if path[0]in {"schema","namespace","identity","authority"}:return True
            if path[0]!="provenance":return False
            if len(path)==1:return True
            return path[1]in {"need","foreground_responsibility","reply_allocation",
                "before_job","after_job","method_trial_proposal","work_kind"}
        if mode=="create":
            if path[0]in {"schema","namespace","identity","authority"}:return True
            if path[0]!="provenance":return False
            if len(path)==1:return True
            if path[1]in {"foreground_responsibility","reply_allocation","before_job"}:return True
            if path[1]!="after_job":return False
            if len(path)<=2:return True
            if path[2]in {"wake_condition","operator_versions","usage"}:return True
            if path[2]!="continuation":return True
            if path[2]=="continuation":
                return len(path)<=3 or path[3]in {"schema","source_ref","source_revision",
                    "c02_operation_id","ingress_operation_id","cancel_generation","call_plan",
                    "responsibility_ref","responsibility_digest","stage","source_barrier_epoch","stage_cursor",
                    "pending_effect_refs","completed_operation_refs","wait"}
            return False
        return True
    def _emit(self,event):
        if event.kind=="key"and len(event.path)==1:self.fields_seen.add(event.key)
        if self._retain_v3(event.path):super()._emit(event)

class _D07SignedParentMetadataReadV3:
    def __init__(self,reader,*,family,kind,ref,expected_digest=None):
        self.reader,self.work=reader,reader.work
        self.family,self.kind,self.ref,self.expected_digest=family,kind,ref,expected_digest
        self.phase="identity";self.complete=False;self.column=None;self.value=None
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.d07_execution_v1 import TABLE as D07_TABLE,SIGN_KIND as D07_KIND
        from ..runtime.d11_life_preparation_v1 import TABLE as LIFE_TABLE,SIGN_KIND as LIFE_KIND
        r=self.reader;w=self.work;r.require_current_v3(meter)
        table,sign_kind=(D07_TABLE,D07_KIND)if self.family=="d07"else(LIFE_TABLE,LIFE_KIND)
        if self.phase=="identity":
            columns=("payload_digest","signature")if self.family=="d07"else("payload_digest","signature","producing_operation_id")
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,table,columns,
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*w.namespace.as_tuple,self.kind,self.ref))
            if self.metadata is None or self.expected_digest is not None and self.metadata[0]!=self.expected_digest:
                raise AuthorityUnavailable("D07 special parent lost its actual signed original commitment")
            mode=("artifact_file"if self.family=="life"and self.kind=="adopted_life"else
                self.kind if self.kind in {"semantic_question","reflection_request","execution"}else"metadata")
            self.column=_D07ParentMetadataColumnV3(w,table=table,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*w.namespace.as_tuple,self.kind,self.ref),mode=mode)
            self.phase="bytes";return
        if self.phase=="bytes":
            if not self.column.advance(meter):return
            if self.column.sha256!=self.metadata[0]:
                raise AuthorityUnavailable("D07 special-parent signed metadata differs from complete canonical EOF")
            w.controller.verifier._issuer._signer.verify(sign_kind,
                canonical_serialize((w.namespace,self.kind,self.ref,self.metadata[0])),self.metadata[1])
            self.value=self.column.require_v3(w)
            self.phase="producer"if self.family=="life"else"done";return
        if self.phase=="producer":
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.metadata[2]))
            if row is None:raise AuthorityUnavailable("D07 special-parent Life metadata has no actual W01 producer")
            self.producing_operation_id=self.metadata[2];self.phase="done";return
        self.complete=True

class _D07AdoptedParentMetadataReadV3:
    def __init__(self,reader,operation_id,mode="domain"):
        self.reader,self.work=reader,reader.work
        self.operation_id,self.mode=operation_id,mode
        self.phase="identity";self.complete=False;self.columns={};self.index=0
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.domain_production_originals_v1 import TABLE,_receipt,_receipt_wire
        from ..runtime_contracts import canonical_digest
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,TABLE,
                ("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if self.metadata is None:raise AuthorityUnavailable("D07 special-parent actual W01 adopted original absent")
            names=("original_payload_json","read_versions_json","receipt_json")
            for name in names:
                self.columns[name]=_D07ParentMetadataColumnV3(w,table=TABLE,column=name,
                    key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,self.operation_id),
                    mode=self.mode if name=="original_payload_json"else"metadata")
            self.names=names;self.phase="bytes";return
        if self.phase=="bytes":
            column=self.columns[self.names[self.index]]
            if not column.advance(meter):return
            self.index+=1
            if self.index==len(self.names):self.phase="receipt"
            return
        if self.phase=="receipt":
            domain,kind,request,digest,bundle,receipt_digest=self.metadata
            payload=self.columns["original_payload_json"]
            if payload.sha256!=digest:raise AuthorityUnavailable("D07 parent actual adoption payload EOF digest differs")
            self.payload=payload.require_v3(w);self.read_versions=self.columns["read_versions_json"].require_v3(w)
            if len(self.read_versions)>1024 or any(NamespaceId.from_key(AtomKey.from_token(ref))!=w.namespace
                    for ref,revision in self.read_versions):
                raise AuthorityUnavailable("D07 actual parent adoption read set crossed original namespace/bound")
            raw=self.columns["receipt_json"].require_v3(w);self.receipt=_receipt(raw)
            if (canonical_digest(self.receipt)!=receipt_digest or _receipt_wire(self.receipt)!=raw
                    or self.receipt.operation_id!=self.operation_id or self.receipt.operation_digest!=bundle
                    or self.receipt.status!="committed" or self.payload["namespace"]!={
                        "bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}
                    or self.payload["identity"]["operation_id"]!=self.operation_id):
                raise AuthorityUnavailable("D07 special parent actual adoption receipt/namespace/operation differs")
            self.phase="producer";return
        if self.phase=="producer":
            actual=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if actual!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise AuthorityUnavailable("D07 special-parent receipt has no matching actual shared W01 occurrence")
            self.complete=True

class _D07ParentJobMetadataReadV3:
    _FIXED=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
        "phase","work_kind","deadline_utc","budget_ref","resource_ref","lease_holder",
        "lease_expires_utc","fence","cancel_epoch","result_ref")
    def __init__(self,reader,job_id):
        self.reader,self.work,self.job_id=reader,reader.work,job_id
        self.phase="identity";self.complete=False;self.columns={};self.index=0
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.d11_types import runtime_job_key
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_jobs",self._FIXED,"job_id=?",(self.job_id,))
            if row is None or row[4:6]!=w.namespace.as_tuple:
                raise AuthorityUnavailable("D07 actual parent runtime job absent or crossed namespace")
            self.value=dict(zip(self._FIXED,row))
            self.names=("continuation_json","wake_condition_json","operator_versions_json","usage_json")
            for name in self.names:
                # NULL wake conditions are represented by their real SQL absence.
                if name=="wake_condition_json":
                    length=w.db.execute("SELECT length(wake_condition_json) FROM runtime_jobs WHERE job_id=?",(self.job_id,)).fetchone()
                    meter.charge_read(8)
                    if length is not None and length[0]is None:
                        self.columns[name]=None;continue
                self.columns[name]=_D07ParentMetadataColumnV3(w,table="runtime_jobs",column=name,
                    key_columns=("job_id",),key=(self.job_id,),mode="continuation"if name=="continuation_json"else"metadata")
            self.phase="bytes";return
        if self.phase=="bytes":
            name=self.names[self.index];column=self.columns[name]
            if column is not None and not column.advance(meter):return
            self.index+=1
            if self.index==len(self.names):self.phase="projection"
            return
        job=self.value;key=runtime_job_key(*w.namespace.as_tuple,job["activity_id"],self.job_id)
        if not hasattr(self,"graph_head"):self.graph_head=_D07GraphParentMetadataReadV3(r,key.token)
        if not self.graph_head.complete:self.graph_head.advance_v3(meter);return
        atom_value=self.graph_head.value
        expected={name:job[name]for name in self._FIXED if name!="budget_ref"}
        expected["parent_budget_lease_ref"]=job["budget_ref"]
        for column,name in (("continuation_json","continuation_digest"),("wake_condition_json","wake_condition_digest"),
                ("operator_versions_json","operator_versions_digest"),("usage_json","usage_digest")):
            item=self.columns[column];expected[name]=None if item is None else item.sha256
        # RuntimeJobValue's registered projection has no Source body.
        if atom_value!=expected:raise AuthorityUnavailable("D07 runtime parent and actual Graph projection commitments differ")
        self.continuation=self.columns["continuation_json"].require_v3(w)
        self.operator_versions=self.columns["operator_versions_json"].require_v3(w)
        self.version=self.graph_head.revision
        from ..runtime_contracts import canonical_digest
        self.digest=canonical_digest(atom_value)
        self.complete=True

class _D07ParentBudgetMetadataReadV3:
    def __init__(self,reader,lease_id):
        self.reader,self.work,self.lease_id=reader,reader.work,lease_id
        self.phase="latest";self.complete=False;self.family=[];self.pending=lease_id
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.issuers import _decode_grant
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="latest":
            self.latest=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_grants",
                ("version","status","signature"),"lease_id=? ORDER BY version DESC",(self.lease_id,))
            if self.latest is None or self.latest[1]!="active":
                raise AuthorityUnavailable("D07 original parent budget grant is no longer active")
            self.column=_D07ParentMetadataColumnV3(w,table="runtime_budget_grants",column="grant_json",
                key_columns=("lease_id","version"),key=(self.lease_id,self.latest[0]),mode="metadata")
            self.phase="grant";return
        if self.phase=="grant":
            if not self.column.advance(meter):return
            raw=self.column.require_v3(w);wire=canonical_serialize(raw)
            w.controller.verifier._issuer._signer.verify("budget-grant.v1",wire,self.latest[2])
            self.grant=_decode_grant(wire)
            if (self.grant.lease_id,self.grant.version,self.grant.bot_id,self.grant.persona_id)!=(
                    self.lease_id,self.latest[0],*w.namespace.as_tuple):
                raise AuthorityUnavailable("D07 current signed grant crossed its actual lease/version/namespace")
            self.phase="family";return
        if self.pending is None:self.complete=True;return
        lease_id=self.pending
        if lease_id in self.family:raise AuthorityUnavailable("D07 original budget family is cyclic")
        row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_leases",
            ("parent_id","bot_id","persona_id","state"),"lease_id=?",(lease_id,))
        debt=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_debt_blocks",
            ("lease_id",),"lease_id=?",(lease_id,))
        if row is None or row[1:3]!=w.namespace.as_tuple or lease_id==self.lease_id and row[3]!="active" or debt is not None:
            raise AuthorityUnavailable("D07 original parent budget family changed or has actual unresolved debt")
        self.family.append(lease_id);self.pending=row[0]

def _d07_parent_head_v3(reader,ref,*,revision=None,digest=None):
    from ..runtime_contracts import canonical_digest
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=reader.work.namespace:raise AuthorityUnavailable("D07 parent metadata crossed namespace")
    if key.type_name=="memory.source":
        witness=reader.work.sources.get(ref)
        if witness is None or not witness.valid:raise AuthorityUnavailable("D07 actual parent Source metadata absent")
        witness.require_current_v3()
        actual_revision,actual_digest=witness.revision,witness.canonical_semantic_digest
        value=witness.metadata
    else:
        atom=reader.metadata_atoms.get(key)
        actual_revision,actual_valid,_,actual_digest=read_d07_authority_metadata_commitment_v3(reader,key)
        if atom is None or not actual_valid:raise AuthorityUnavailable("D07 actual parent metadata head absent")
        value=atom.value
    if revision is not None and actual_revision!=revision or digest is not None and actual_digest!=digest:
        raise AuthorityUnavailable("D07 actual special parent metadata head commitment changed")
    return actual_revision,actual_digest,value

def _d07_parent_source_authority_v3(reader,header):
    from ..runtime_contracts import canonical_digest
    from ..domains.d03.self_perspective import self_mapping_key
    source=header.authority
    if source.actor==reader.owner_acl_authority.actor:return source
    from ..runtime.d07_execution_v1 import D07PreparedExecutionV1,D07ReflectionPreparedV3
    from ..runtime.d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    if header.prepared_class in {D07PreparedExecutionV1,D07GeneralGrowthPreparedV1}:
        raise AuthorityUnavailable("ordinary Owner Source authority has no exact current Owner pairing")
    if header.prepared_class is D07ReflectionPreparedV3 and header.value["cycle_ref"]is None:
        raise AuthorityUnavailable("ordinary Reflection Source authority cannot introduce an unregistered Self parent")
    _,_,mapping=_d07_parent_head_v3(reader,self_mapping_key(reader.work.namespace).token)
    if mapping["status"]!="active" or mapping["self_entity_ref"]!=source.actor:
        raise AuthorityUnavailable("D07 original effective Source actor differs from current certified Self mapping")
    return source

class D07AuthorityParentMetadataQualifiedV3:
    def __init__(self,issuer,task,*,kind,authority,parent_originals,deadline,source_versions):
        if issuer is not _ISSUER or not task.complete:
            raise TypeError("D07 special-parent proof requires its actual completed metadata task")
        self.task,self.reader,self.work=task,task.reader,task.work
        self.kind,self.effective_source_authority=kind,authority
        self.parent_originals,self.original_deadline_utc,self.source_versions=tuple(parent_originals),deadline,tuple(source_versions)
        _PARENT_PROOFS_V3[self]=(task,self.reader,self.work,self.kind,self.effective_source_authority,
            self.parent_originals,self.original_deadline_utc,self.source_versions,self.work.operation,self.work.scope,self.work.graph_stamp)
        self.work.issued_capabilities.append((_PARENT_PROOFS_V3,self))
    def require_for_v3(self,reader):
        if (reader is not self.reader or _PARENT_PROOFS_V3.get(self)!=(self.task,reader,self.work,
                self.kind,self.effective_source_authority,self.parent_originals,self.original_deadline_utc,
                self.source_versions,self.work.operation,self.work.scope,self.work.graph_stamp)):
            raise AuthorityUnavailable("D07 parent qualification is not the actual same-reader private completed proof")
        reader.require_registered_v3()
        if (not self.task.complete or self.task.result is not self
                or self.work.controller.clock()>=self.original_deadline_utc):
            raise AuthorityUnavailable("D07 actual special-parent metadata qualification changed")
        return self

class _D07SpecialParentMetadataReadV3:
    def __init__(self,reader):
        reader.require_registered_v3();reader.header.require_v3(reader)
        self.reader,self.work=reader,reader.work
        self.headers=[];self.phase="chain";self.complete=False;self.result=None
        self.pending=None;self.leaves={};self.index=0;self.deadlines=[];self.originals=[]
        self.current=reader.header;self.seen=set()
        _PARENT_TASKS_V3[self]=(reader,self.work,self.work.operation,self.work.scope,self.work.graph_stamp)
    def _leaf_v3(self,name,leaf):
        existing=self.leaves.get(name)
        if existing is None:
            self.leaves[name]=leaf;self.pending=leaf;return None
        if not existing.complete:self.pending=existing;return None
        return existing
    def advance_v3(self,meter):
        from dataclasses import asdict
        from ..runtime_contracts import canonical_digest
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
        from ..runtime.d07_execution_v1 import D07IngressRecallPreparedV1,D07ReflectionPreparedV3,D07RelationshipPreparedV2
        from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from ..runtime.d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if _PARENT_TASKS_V3.get(self)!=(r,w,w.operation,w.scope,w.graph_stamp):
            raise AuthorityUnavailable("D07 special-parent metadata task lost original Work/retention/stamp")
        if self.complete:return
        if self.pending is not None:
            self.pending.advance_v3(meter)
            if self.pending.complete:self.pending=None
            return
        if self.phase=="chain":
            header=self.current.require_v3(r);raw=header.value
            if header.job_id in self.seen or len(self.headers)>=3:
                raise AuthorityUnavailable("D07 original Reflection parent chain is cyclic or exceeds original causal depth")
            self.seen.add(header.job_id);self.headers.append(header)
            if header.prepared_class is D07ReflectionPreparedV3:
                parent=r.parent_headers.get(raw["parent_prepared_ref"])
                if parent is None or not parent.complete:
                    raise AuthorityUnavailable("D07 Reflection requires its actual independently completed parent header")
                parent.require_v3(r)
                if parent.metadata[0]!=raw["parent_prepared_digest"]:
                    raise AuthorityUnavailable("D07 Reflection original parent prepared digest changed")
                self.current=parent;return
            self.headers.reverse();self.phase="parent";return
        if self.phase=="parent":
            if self.index==len(self.headers):
                self.phase="finish";return
            self.header=self.headers[self.index];self.raw=self.header.value;self.parent_kind=self.header.prepared_class
            self.source=_d07_parent_source_authority_v3(r,self.header)
            if self.index:
                previous=self.headers[self.index-1]
                if (self.source.actor,self.source.purpose,self.source.audience,self.source.activation_generation)!=(
                        previous.authority.actor,previous.authority.purpose,previous.authority.audience,previous.authority.activation_generation):
                    raise AuthorityUnavailable("D07 Reflection cannot replace the original Source actor/purpose/audience/generation")
                if not {(row["ref"],row["revision"])for row in self.header.source_rows}<={
                        (row["ref"],row["revision"])for row in previous.source_rows}:
                    raise AuthorityUnavailable("D07 Reflection expanded its original parent Source versions")
            self.phase="owner";return
        raw=self.raw;header=self.header;kind=self.parent_kind
        if self.phase=="owner":
            owner=decode_typed_production_value_v1(json.loads(raw["owner_guard_json"]),ProductionOwnerGuardV1)
            _d07_parent_head_v3(r,owner.grant_ref,revision=owner.grant_revision,digest=owner.grant_digest)
            actual_guard=r.owner_header_proof.current_owner_authority.guard
            from ..graph_types import owner_grant_key
            if (owner.grant_ref!=owner_grant_key(*w.namespace.as_tuple).token
                    or owner.owner_head_digest!=actual_guard.authorization_head.removeprefix("sha256:")):
                raise AuthorityUnavailable("D07 special parent original Owner head differs from its current protected Core guard")
            self.owner=owner
            if kind is D07ReflectionPreparedV3:self.phase="reflection"
            elif kind is D07IngressRecallPreparedV1:self.phase="need"
            elif kind in {D07MethodGrowthPreparedV2,D07RelationshipPreparedV2}:self.phase="question"
            elif kind is D07GeneralGrowthPreparedV1:self.phase="general_question"
            elif kind is D07ArtifactObservationPreparedV3:self.phase="artifact_observation"
            else:self.phase="ordinary_job"
            return
        if self.phase=="artifact_observation":
            from ..runtime.artifact_observation_parentage_v3 import ArtifactObservationParentMetadataReadV3
            leaf=self._leaf_v3(("artifact-observation-parent",header.job_id),ArtifactObservationParentMetadataReadV3(self))
            if leaf is None:return
            self.artifact_observation=leaf.basis
            self.cycle_ref=leaf.basis.request.selector.task.cycle_job_ref
            self.phase="cycle";return
        if self.phase=="general_question":
            from ..runtime.d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1,QUESTION_SCHEMA
            leaf=self._leaf_v3(("general-question",header.job_id),_D07SignedParentMetadataReadV3(r,
                family="d07",kind="semantic_question",ref=raw["semantic_question_ref"],
                expected_digest=raw["semantic_question_digest"]))
            if leaf is None:return
            question=leaf.value;frozen=header.column.frozen_metadata.value["input"]
            if (leaf.column.fields_seen!={field.name for field in fields(D07GeneralGrowthQuestionV1)}
                    or question["schema"]!=QUESTION_SCHEMA or question["depth_basis"]!="independent_outcome_stage.v1"
                    or type(question["stage_causal_depth"])is not int or question["stage_causal_depth"]!=0
                    or (question["depth_basis"],question["stage_causal_depth"],question["outcome_original_ref"],
                        question["outcome_original_digest"],question["causal_operation_id"],question["general_growth_attention_ref"],question["outcome_trigger_ref"],
                        question["outcome_trigger_digest"],question["causal_receipt_digest"])!=(
                        raw["depth_basis"],raw["stage_causal_depth"],raw["outcome_original_ref"],raw["outcome_original_digest"],
                        raw["causal_operation_id"],raw["general_growth_attention_ref"],raw["outcome_trigger_ref"],
                        raw["outcome_trigger_digest"],raw["causal_receipt_digest"])
                    or (question["target_block"],question["scope"],question["target_ref"],question["target_digest"])!=(
                        frozen["ordinary_block_id"],frozen["scope"],frozen["target_ref"],frozen["target_original_digest"])
                    or question["question_key"]!="d01.growth:"+question["target_block"]+":"+question["scope"]
                    or question["context_source_refs"]!=raw["context_source_refs"]
                    or question["support_source_refs"]!=raw["support_source_refs"]
                    or question["source_refs"]!=[*question["context_source_refs"],*question["support_source_refs"]]
                    or raw["purpose"]!="consolidation" or raw["work_kind"]!="concern"
                    or raw["original_deadline_utc"]>question["original_deadline_utc"]):
                raise AuthorityUnavailable("General Source metadata differs from its exact signed outcome/question/depth/Source columns")
            self.general_question=question;self.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
            self.deadlines.extend((raw["original_deadline_utc"],question["original_deadline_utc"]))
            self.phase="general_attention";return
        if self.phase=="general_attention":
            from ..runtime.d07_general_growth_attention_v1 import D07GeneralGrowthAttentionOriginalV1,general_growth_attention_original_ref_v1
            leaf=self._leaf_v3(("general-attention",header.job_id),_D07SignedParentMetadataReadV3(r,
                family="d07",kind="general_growth_attention_v1",ref=raw["general_growth_attention_ref"],
                expected_digest=raw["general_growth_attention_digest"]))
            if leaf is None:return
            attention=decode_typed_production_value_v1(leaf.value,D07GeneralGrowthAttentionOriginalV1)
            question=self.general_question
            if (leaf.column.fields_seen!={field.name for field in fields(D07GeneralGrowthAttentionOriginalV1)}
                    or attention.namespace!=w.namespace or attention.original_ref!=raw["general_growth_attention_ref"]
                    or attention.original_ref!=general_growth_attention_original_ref_v1(w.namespace,
                        raw["outcome_original_digest"],question["target_block"],question["scope"])
                    or (attention.semantic_question_ref,attention.semantic_question_digest,attention.source_authority,attention.owner_guard)!=(
                        raw["semantic_question_ref"],raw["semantic_question_digest"],self.source,self.owner)
                    or (attention.outcome_trigger_ref,attention.outcome_trigger_digest,attention.causal_operation_id,
                        attention.causal_receipt_digest,attention.original_parent_budget_lease_ref,attention.original_parent_grant_digest)!=(
                        question["outcome_trigger_ref"],question["outcome_trigger_digest"],question["causal_operation_id"],
                        question["causal_receipt_digest"],question["original_parent_budget_lease_ref"],question["original_parent_grant_digest"])
                    or attention.context_source_refs!=tuple(raw["context_source_refs"])
                    or attention.support_source_refs!=tuple(raw["support_source_refs"])
                    or raw["original_deadline_utc"]>attention.original_deadline_utc):
                raise AuthorityUnavailable("General Source parent lost actual unique attention registration/Owner/root lineage")
            self.general_attention=attention;self.deadlines.append(attention.original_deadline_utc)
            self.originals.append(("d07.general_growth_attention_v1",attention.original_ref,leaf.metadata[0]))
            self.phase="general_registration";return
        if self.phase=="general_registration":
            attention=self.general_attention
            leaf=self._leaf_v3(("general-registration",header.job_id),
                _D07AdoptedParentMetadataReadV3(r,attention.registration_operation_id))
            if leaf is None:return
            if (leaf.metadata[:2]!=("d07","register_general_growth_attention_v1")
                    or canonical_digest(leaf.receipt)!=attention.registration_receipt_digest
                    or attention.ticket_ref not in leaf.receipt.write_versions):
                raise AuthorityUnavailable("General attention has no exact actual W01 registration receipt/member")
            self.phase="general_ticket_history";return
        if self.phase=="general_ticket_history":
            attention=self.general_attention
            leaf=self._leaf_v3(("general-ticket-history",header.job_id),_D07HistoryParentMetadataReadV3(r,
                attention.ticket_ref.key.token,attention.ticket_ref.revision,
                expected_operation=attention.registration_operation_id,expected_digest=attention.ticket_digest))
            if leaf is None:return
            if (leaf.value["ticket_id"]!=attention.ticket_ref.key.name or leaf.value["category"]!="background"
                    or leaf.value["question_key"]!=self.general_question["question_key"]
                    or tuple(leaf.value["source_refs"])!=(*attention.context_source_refs,*attention.support_source_refs)
                    or leaf.value["valid_until"]>attention.original_deadline_utc):
                raise AuthorityUnavailable("General attention birth ticket changed its actual question/Source/deadline")
            self.phase="ordinary_job";return
        if self.phase=="ordinary_job":
            leaf=self._leaf_v3(("ordinary-job",header.job_id),_D07ParentJobMetadataReadV3(r,header.job_id))
            if leaf is None:return
            job=leaf.value
            if ((job["operation_id"],job["activity_id"],job["effect_id"],job["work_kind"])!=
                    (raw["operation_id"],raw["activity_id"],raw["effect_id"],"d07."+raw["work_kind"])
                    or job["cancel_epoch"] or job["phase"]not in {"running","completed"}):
                raise AuthorityUnavailable("D07 ordinary signed metadata lost its actual live/completed original cognition job")
            if header is r.header and (job["phase"],job["fence"],job["lease_holder"])!=(
                    "running",w.request.worker_fence,w.request.subject):
                raise AuthorityUnavailable("D07 ordinary metadata crossed its original acquired model worker")
            self.ordinary_job=job
            self.deadlines.append(_d07_parent_utc_v3(job["deadline_utc"]))
            if header is r.header:
                if job["lease_expires_utc"]is None:
                    raise AuthorityUnavailable("D07 ordinary original worker has no actual lease expiry")
                self.deadlines.append(_d07_parent_utc_v3(job["lease_expires_utc"]))
            self.phase="ordinary_budget";return
        if self.phase=="ordinary_budget":
            leaf=self._leaf_v3(("ordinary-budget",header.job_id),
                _D07ParentBudgetMetadataReadV3(r,self.ordinary_job["budget_ref"]))
            if leaf is None:return
            if "d07.cognition"not in leaf.grant.allowed_work_kinds or w.controller.clock()>=leaf.grant.valid_until_utc:
                raise AuthorityUnavailable("D07 ordinary current original grant no longer permits cognition")
            if kind is D07GeneralGrowthPreparedV1:
                if (self.ordinary_job["budget_ref"]!=self.general_attention.original_parent_budget_lease_ref
                        or canonical_digest(leaf.grant)!=self.general_attention.original_parent_grant_digest):
                    raise AuthorityUnavailable("General cognition replaced its actual original parent budget/grant")
                from ..host.model_workflows_v8 import AdminModelWorkflowsV8
                from ..host.model_workflows_v9 import AdminModelWorkflowsV9
                from ..model_broker.general_growth_cognition_v1 import TEMPLATE_VERSION
                policy=r.bundle.model_workflows
                workflow=policy.general_growth_cognition if type(policy) in (AdminModelWorkflowsV8, AdminModelWorkflowsV9) else None
                installed=header.column.frozen_metadata.value["installation"]
                if (workflow is None or workflow.template_version!=TEMPLATE_VERSION
                        or workflow.purpose!="consolidation" or workflow.work_kind!="d07.cognition"
                        or any(installed[name]!=getattr(workflow,name)for name in(
                            "provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
                    raise AuthorityUnavailable("General metadata lost its actual installed named V8 workflow")
            self.deadlines.append(leaf.grant.valid_until_utc);self.phase="next";return
        if self.phase=="need":
            from ..runtime.d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1,NEED_OPERATION
            from ..domains.d07 import IngressRecallNeedV1
            need_id=ingress_recall_need_operation_id_v1(w.namespace,raw["c02_operation_id"])
            leaf=self._leaf_v3(("need",header.job_id),_D07AdoptedParentMetadataReadV3(r,need_id))
            if leaf is None:return
            if leaf.metadata[:2]!=("d07",NEED_OPERATION):
                raise AuthorityUnavailable("D07 Self Need names another actual adopted producer")
            need=decode_typed_production_value_v1(leaf.payload["provenance"]["need"],IngressRecallNeedV1)
            frozen=header.column.frozen_metadata.value
            if (raw["need_ref"]!="d07-current:"+leaf.metadata[3][:48] or canonical_digest(need)!=raw["need_digest"]
                    or need.routing=="no_search" or need.cancel_generation!=raw["cancel_generation"]
                    or need.policy_digest!=raw["recall_policy_digest"]
                    or (need.c02_operation_id,need.cycle_job_ref,need.responsibility_ref,need.responsibility_digest)!=(
                        raw["c02_operation_id"],raw["cycle_job_ref"],raw["responsibility_ref"],raw["responsibility_digest"])
                    or (frozen["input"]["need_ref"],frozen["input"]["need_digest"],frozen["input"]["c02_operation_id"],
                        frozen["input"]["cycle_job_ref"],frozen["input"]["activity_id"])!=(
                        raw["need_ref"],raw["need_digest"],raw["c02_operation_id"],raw["cycle_job_ref"],raw["activity_id"])):
                raise AuthorityUnavailable("D07 Self Need/C02/cycle/responsibility/cancel/policy changed")
            _d07_parent_head_v3(r,need.source_ref,revision=need.source_revision,digest=need.source_digest)
            self.need=need;self.originals.append(("d07.actual-need",raw["need_ref"],leaf.metadata[3]))
            self.deadlines.append(need.deadline_utc);self.phase="recall_policy";return
        if self.phase=="recall_policy":
            from ..host.authority_profile import AdminD06RecallPolicyV1
            from ..model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
            policy=r.bundle.d06_recall;workflow=r.bundle.model_workflows.d07_cognition
            installed=header.column.frozen_metadata.value["installation"]
            if (type(policy)is not AdminD06RecallPolicyV1 or policy.policy_digest!=raw["recall_policy_digest"]
                    or workflow is None or workflow.template_version!=RECALL_TEMPLATE_VERSION_V1
                    or workflow.purpose!="proposal" or workflow.work_kind!="d07.cognition"
                    or (raw["body_policy_id"],raw["body_policy_version"])!=(
                        policy.cognition_body_policy_id,policy.cognition_body_policy_version)
                    or any(installed[name]!=getattr(workflow,name)for name in(
                        "provider_id","model_id","provider_config_digest","provider_config_ref","max_output_tokens"))):
                raise AuthorityUnavailable("D07 Self Recall lost exact installed policy/template/provider/Body policy metadata")
            self.cycle_ref=raw["cycle_job_ref"];self.phase="cycle";return
        if self.phase=="question":
            leaf=self._leaf_v3(("question",header.job_id),_D07SignedParentMetadataReadV3(r,family="d07",
                kind="semantic_question",ref=raw["semantic_question_ref"],expected_digest=raw["semantic_question_digest"]))
            if leaf is None:return
            question=leaf.value
            expected="d07.method-growth-semantic-question.v2"if kind is D07MethodGrowthPreparedV2 else"d07.relationship-semantic-question.v2"
            if question["schema"]!=expected:
                raise AuthorityUnavailable("D07 named C3 has another exact signed semantic kind")
            frozen=header.column.frozen_metadata.value["input"]
            if question["question_key"]!=frozen["question_key"] or question["target_ref"]["ref"]!=frozen["target_ref"]:
                raise AuthorityUnavailable("D07 named C3 signed semantic question differs from original frozen metadata")
            self.question=question;self.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
            if kind is D07MethodGrowthPreparedV2:self.phase="proposal"
            else:
                self.cycle_ref=_d07_parent_version_key_v3(raw["cycle_ref"])
                self.phase="relationship_policy"
            return
        if self.phase=="relationship_policy":
            policy=self._leaf_v3(("relationship_policy",header.job_id),_D07RelationshipParentPolicyReadV3(r,self.question))
            if policy is None:return
            self.phase="cycle";return
        if self.phase=="proposal":
            from ..graph_types import GraphVersion
            from ..domains.d01.method_learning_v1 import MethodTrialProposalV2
            from ..runtime.d01_method_learning_v1 import trial_question_v2
            version=decode_typed_production_value_v1(raw["proposal_head"],GraphVersion)
            source_version=decode_typed_production_value_v1(raw["source_head"],GraphVersion)
            proposal_leaf=self._leaf_v3(("proposal_head",header.job_id),_D07GraphParentMetadataReadV3(r,version.key.token))
            if proposal_leaf is None:return
            proposal_raw=proposal_leaf.value
            if proposal_leaf.revision!=version.revision or canonical_digest(proposal_raw)!=raw["proposal_digest"]:
                raise AuthorityUnavailable("D07 Method proposal actual current metadata EOF commitment changed")
            _d07_parent_head_v3(r,source_version.key.token,revision=source_version.revision,digest=raw["source_digest"])
            proposal=decode_typed_production_value_v1(proposal_raw,MethodTrialProposalV2)
            history=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",(version.key.token,version.revision))
            if history is None or history[:2]!=w.namespace.as_tuple or history[3]!=1:
                raise AuthorityUnavailable("D07 Method proposal has no exact actual adopting history member")
            leaf=self._leaf_v3(("proposal",header.job_id),_D07AdoptedParentMetadataReadV3(r,history[2]))
            if leaf is None:return
            authority=decode_typed_production_value_v1(leaf.payload["authority"],AuthorityContext)
            if (leaf.metadata[:2]!=("d01","register_method_trial_proposal_v2")
                    or leaf.payload["provenance"]["method_trial_proposal"]!=proposal_raw
                    or version not in leaf.receipt.write_versions
                    or authority!=header.authority or self.question["question_key"]!=trial_question_v2(version.key.token,raw["proposal_digest"])
                    or set(self.question["source_refs"])!=set(proposal.source_refs)
                    or any(self.question[name]!=raw[name]for name in("proposal_head","proposal_digest","source_head",
                        "source_digest","parent_budget_lease_ref","original_deadline_utc","c02_operation_id"))
                    or not proposal.valid_from<=w.controller.clock()<proposal.valid_until):
                raise AuthorityUnavailable("D07 Method actual adopted proposal authority/source/question/root deadline changed")
            self.proposal=proposal
            self.originals.append(("d01.actual-method-proposal",version.key.token,leaf.metadata[3]))
            self.deadlines.extend((raw["original_deadline_utc"],proposal.valid_until))
            self.cycle_ref=decode_typed_production_value_v1(raw["cycle_ref"],GraphVersion).key.token
            self.phase="cycle";return
        if self.phase=="cycle":
            leaf=self._leaf_v3(("cycle",header.job_id),_D07ParentJobMetadataReadV3(r,AtomKey.from_token(self.cycle_ref).name))
            if leaf is None:return
            job=leaf.value;cycle=leaf.continuation
            if (job["work_kind"]!="d11.foreground_cycle.v1"
                    or job["phase"]in {"completed","failed","cancelled","draining","pending_confirmation"} or job["cancel_epoch"]
                    or cycle["cancel_generation"] or cycle["c02_operation_id"]!=raw["c02_operation_id"]
                    or kind is D07IngressRecallPreparedV1 and job["activity_id"]!=raw["activity_id"]
                    or cycle["call_plan"]["parent_budget_lease_ref"]!=job["budget_ref"]):
                raise AuthorityUnavailable("D07 special parent current cycle/cancel/C02/activity/root budget changed")
            if kind is D07IngressRecallPreparedV1 and cycle["source_ref"]!=self.need.source_ref:
                raise AuthorityUnavailable("D07 Recall original Need cue differs from actual current cycle")
            if kind is D07MethodGrowthPreparedV2:
                from ..graph_types import GraphVersion
                source=decode_typed_production_value_v1(raw["source_head"],GraphVersion)
                if cycle["source_ref"]!=source.key.token or job["budget_ref"]!=raw["parent_budget_lease_ref"]:
                    raise AuthorityUnavailable("D07 Method actual cue/root paying lease changed")
            if kind is D07ArtifactObservationPreparedV3:
                from ..runtime.foreground_artifact_observation_plan_v3 import foreground_call_plan_from_wire_v3
                basis=self.artifact_observation
                plan=foreground_call_plan_from_wire_v3(cycle["call_plan"])
                if (plan.phase_group.selector!=basis.request.selector or cycle["source_ref"]!=basis.task_root_source_head.key.token
                        or job["budget_ref"]!=basis.parent_budget_lease_ref
                        or(plan.observer_policy_ref,plan.observer_policy_digest)!=(basis.observer_asset_ref,basis.observer_asset_digest)):
                    raise AuthorityUnavailable("Artifact observation changed its actual V3 task/cycle/Root/policy")
            self.cycle,self.cycle_job,self.cycle_leaf=cycle,job,leaf
            self.deadlines.append(_d07_parent_utc_v3(job["deadline_utc"]))
            self.phase="budget";return
        if self.phase=="budget":
            lease_id=self.cycle_job["budget_ref"]
            leaf=self._leaf_v3(("budget",header.job_id),_D07ParentBudgetMetadataReadV3(r,lease_id))
            if leaf is None:return
            if "d07.cognition"not in leaf.grant.allowed_work_kinds:
                raise AuthorityUnavailable("D07 special parent original grant does not allow original cognition Work")
            if kind is D07MethodGrowthPreparedV2 and raw["original_deadline_utc"]!=min(
                    _d07_parent_utc_v3(self.cycle_job["deadline_utc"]),leaf.grant.valid_until_utc):
                raise AuthorityUnavailable("D07 Method original deadline is not its original job/grant minimum")
            if kind is D07ArtifactObservationPreparedV3 and canonical_digest(leaf.grant)!=self.artifact_observation.parent_grant_digest:
                raise AuthorityUnavailable("Artifact observation changed its actual original Root grant")
            self.budget=leaf;self.deadlines.append(leaf.grant.valid_until_utc);self.phase="responsibility";return
        if self.phase=="responsibility":
            create=self._leaf_v3(("create",header.job_id),_D07AdoptedParentMetadataReadV3(r,self.cycle_job["operation_id"],"create"))
            if create is None:return
            from ..runtime.foreground_cycle_v1 import ForegroundResponsibilityV1,foreground_responsibility_ref_v1
            responsibility=decode_typed_production_value_v1(create.payload["provenance"]["foreground_responsibility"],ForegroundResponsibilityV1)
            if (create.metadata[:2]!=("d11","create_foreground_cycle_v2")
                    or (self.cycle["responsibility_ref"],self.cycle["responsibility_digest"])!=(
                        foreground_responsibility_ref_v1(w.namespace,raw["c02_operation_id"]),responsibility.digest)
                    or responsibility.owner_guard!=self.owner or responsibility.c02_operation_id!=raw["c02_operation_id"]
                    or responsibility.parent_budget_lease_ref!=self.cycle_job["budget_ref"]
                    or (responsibility.parent_grant_id,responsibility.parent_grant_version,responsibility.parent_grant_digest)!=(
                        self.budget.grant.grant_id,self.budget.grant.version,canonical_digest(self.budget.grant))
                    or responsibility.foreground_policy_digest!=canonical_digest(asdict(r.bundle.foreground))
                    or responsibility.deadline_policy_digest!=canonical_digest(asdict(r.bundle.foreground.deadline_policy))
                    or responsibility.deadline_utc!=_d07_parent_utc_v3(self.cycle_job["deadline_utc"])):
                raise AuthorityUnavailable("D07 actual create responsibility lost original Owner/C02/grant/policy/deadline")
            if kind is D07IngressRecallPreparedV1 and responsibility.digest!=raw["responsibility_digest"]:
                raise AuthorityUnavailable("D07 Recall signed responsibility differs from actual adopted create")
            if kind is D07MethodGrowthPreparedV2 and responsibility.mode!="bounded_causal_window_v1":
                raise AuthorityUnavailable("D07 Method requires actual independent natural C02 responsibility")
            _,_,mapping=_d07_parent_head_v3(r,responsibility.self_mapping_ref,digest=responsibility.self_mapping_digest)
            _d07_parent_head_v3(r,responsibility.source_ref,revision=responsibility.source_revision,digest=responsibility.source_digest)
            if create.payload["authority"]["actor"]!=mapping["self_entity_ref"]:
                raise AuthorityUnavailable("D07 actual create responsibility actor differs from its certified Self mapping")
            self.responsibility,self.create=responsibility,create;self.deadlines.append(responsibility.deadline_utc)
            self.phase="create_birth";return
        if self.phase=="create_birth":
            from ..runtime.foreground_cycle_v1 import decode_foreground_job_v1,foreground_cycle_from_wire_v1
            from ..runtime.d11_types import job_graph_write
            from ..graph_types import GraphVersion
            created=decode_foreground_job_v1(self.create.payload["provenance"]["after_job"],namespace=w.namespace)
            birth=foreground_cycle_from_wire_v1(created.continuation)
            if (self.create.payload["provenance"]["before_job"]is not None or created.phase!="queued"or created.fence
                    or any(getattr(created,name)!=self.cycle_job[name]for name in(
                        "job_id","operation_id","activity_id","budget_ref","deadline_utc"))
                    or (birth.responsibility_ref,birth.responsibility_digest)!=(
                        self.cycle["responsibility_ref"],self.cycle["responsibility_digest"])):
                raise AuthorityUnavailable("D07 responsibility lost exact actual immutable create job/root/deadline")
            write=job_graph_write(created)
            versions=tuple(version for version in self.create.receipt.write_versions if version.key==write.key)
            if len(versions)!=1:
                raise AuthorityUnavailable("D07 responsibility actual create receipt has no unique original job member")
            history=self._leaf_v3(("create_birth",header.job_id),_D07HistoryParentMetadataReadV3(
                r,write.key.token,versions[0].revision,expected_operation=created.operation_id,
                expected_digest=canonical_digest(write.value)))
            if history is None:return
            if history.value!=write.value:
                raise AuthorityUnavailable("D07 responsibility actual create history differs from its real producer")
            responsibility=self.responsibility
            for ref,revision in ((responsibility.source_ref,responsibility.source_revision),
                    (responsibility.owner_guard.grant_ref,responsibility.owner_guard.grant_revision)):
                if [ref,revision]not in self.create.read_versions:
                    raise AuthorityUnavailable("D07 responsibility has no original positive Source/Owner read member")
            mapping_revision,valid,_,_=read_d07_authority_metadata_commitment_v3(
                r,AtomKey.from_token(responsibility.self_mapping_ref))
            if not valid or [responsibility.self_mapping_ref,mapping_revision]not in self.create.read_versions:
                raise AuthorityUnavailable("D07 responsibility has no original certified Self read member")
            self.phase="cause";return
        if self.phase=="cause":
            responsibility=self.responsibility
            life_kind="foreground_post_c02_cause"if responsibility.mode=="bounded_causal_window_v1"else"draft_root_capability"
            ref=responsibility.cause_original_ref if responsibility.mode=="bounded_causal_window_v1"else responsibility.root_registration_ref
            digest=responsibility.cause_original_digest if responsibility.mode=="bounded_causal_window_v1"else responsibility.root_registration_digest
            leaf=self._leaf_v3(("cause",header.job_id),_D07SignedParentMetadataReadV3(r,family="life",
                kind=life_kind,ref=ref,expected_digest=digest))
            if leaf is None:return
            if responsibility.mode=="bounded_causal_window_v1":
                cause=leaf.value
                names=("installation_id","manifest_digest","ingress_operation_id","c02_operation_id","source_ref",
                    "source_revision","source_digest","c02_receipt_digest","foreground_policy_digest","deadline_policy_digest","cause_frozen_at_utc")
                if (any(cause[name]!=getattr(responsibility,name)for name in names)
                        or cause["commit_seq"]!=responsibility.c02_commit_seq
                        or leaf.producing_operation_id!=responsibility.cause_operation_id):
                    raise AuthorityUnavailable("D07 natural responsibility lost actual signed original causal transition")
            else:
                root=leaf.value
                if (leaf.producing_operation_id!=responsibility.root_setup_operation_id
                        or (root["owner_grant_ref"],root["owner_grant_revision"],root["owner_grant_digest"])!=(
                            self.owner.grant_ref,self.owner.grant_revision,self.owner.grant_digest)
                        or root["source_ref"]!=responsibility.source_ref
                        or responsibility.deadline_utc>_d07_parent_utc_v3(root["valid_until_utc"])):
                    raise AuthorityUnavailable("D07 signed-scope responsibility lost its original Root grant/Source/deadline")
                self.deadlines.append(_d07_parent_utc_v3(root["valid_until_utc"]))
            from ..runtime.domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
            event_kind="foreground_post_c02_cause_available"if life_kind=="foreground_post_c02_cause"else"artifact_draft_root_registered"
            event=ProductionOutboxStageV1(w.namespace,leaf.producing_operation_id,"d11",event_kind,
                ProductionOriginalRefV1("d11.life_"+life_kind,ref,leaf.metadata[0]))
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_domain_production_outbox_v1",
                ("causal_operation_id","receiver_domain","event_kind","original_ref","original_digest","state"),
                "bot=? AND persona=? AND dedupe_key=?",(*w.namespace.as_tuple,event.dedupe_key))
            if row is None or row[:5]!=(leaf.producing_operation_id,"d11",event_kind,ref,leaf.metadata[0])or row[5]not in{"pending","consumed"}:
                raise AuthorityUnavailable("D07 parent cause has no actual same-producer durable locator event")
            self.originals.append((life_kind,ref,leaf.metadata[0]));self.phase="c02";return
        if self.phase=="c02":
            leaf=self._leaf_v3(("c02",header.job_id),_D07BundleParentMetadataReadV3(r,raw["c02_operation_id"]))
            if leaf is None:return
            from ..runtime.domain_production_originals_v1 import _receipt
            from ..runtime_contracts import CommitReceipt
            receipt=_receipt({name:leaf.value[name]for name in CommitReceipt.__dataclass_fields__})
            responsibility=self.responsibility
            if ("first_ingress_c02"not in leaf.value or (canonical_digest(receipt),receipt.commit_seq)!=(
                    responsibility.c02_receipt_digest,responsibility.c02_commit_seq)):
                raise AuthorityUnavailable("D07 special parent lost exact actual independent first-ingress C02 receipt")
            self.phase="attempt";return
        if self.phase=="attempt":
            attempts=[item for item in self.cycle["call_plan"]["attempts"]if item["call_id"]==raw["call_id"]]
            if len(attempts)!=1:
                raise AuthorityUnavailable("D07 parent has no unique original registered C3 call")
            member=attempts[0];workflow=(r.bundle.model_workflows.artifact_observation_cognition
                if kind is D07ArtifactObservationPreparedV3 else r.bundle.model_workflows.d07_cognition)
            if (member["slot"]!="C3" or member["original_call_id"]is not None
                    or (member["reservation_operation_id"],member["reservation_digest"],member["budget_lease_ref"])!=(
                        raw["operation_id"],raw["reservation_digest"],self.cycle_job["budget_ref"])
                    or (member["input_ceiling"],member["output_ceiling"])!=(
                        workflow.quote_ceiling["input_tokens"],workflow.quote_ceiling["output_tokens"])):
                raise AuthorityUnavailable("D07 original C3 member/reservation/quote ceilings/root budget changed")
            if kind is D07ArtifactObservationPreparedV3:
                from ..runtime.foreground_artifact_observation_plan_v3 import ForegroundArtifactObservationAttemptV3
                from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                basis=self.artifact_observation
                attempt=decode_typed_production_value_v1(member,ForegroundArtifactObservationAttemptV3)
                if (attempt.phase_selector!=basis.request.selector or attempt.condition_id!=basis.request.condition_id
                        or(attempt.observation_basis_ref,attempt.observation_basis_digest)!=(basis.original_ref,basis.digest)
                        or attempt.state!="reserved"):
                    raise AuthorityUnavailable("Artifact observation borrowed a non-dedicated C3 attempt")
            if kind is not D07IngressRecallPreparedV1:
                acquire_id="d07-acquire:"+canonical_digest((w.namespace,raw["operation_id"]))[:48]
                leaf=self._leaf_v3(("acquire",header.job_id),_D07BundleParentMetadataReadV3(r,acquire_id,prepared_header=header))
                if leaf is None:return
                name=("artifact_observation_c3"if kind is D07ArtifactObservationPreparedV3 else
                    "method_growth_c3"if kind is D07MethodGrowthPreparedV2 else"relationship_c3")
                expected={"cycle_ref":self.cycle_ref,"before_cycle_digest":raw["cycle_digest"],
                    "before_call_plan_digest":raw["call_plan_digest"],"call_id":raw["call_id"],
                    "semantic_question_digest":raw["semantic_question_digest"]}
                if kind is D07ArtifactObservationPreparedV3:
                    expected.update(observation_basis_ref=raw["observation_basis_ref"],observation_basis_digest=raw["observation_basis_digest"])
                if leaf.value["phase"]!="execution_acquired" or leaf.value["prepared_digest"]!=header.metadata[0] or leaf.value[name]!=expected:
                    raise AuthorityUnavailable("D07 named C3 member has no exact original acquire W01 binding")
            self.phase="next";return

        if self.phase=="reflection":
            continuation=self._leaf_v3(("reflection",header.job_id),_D07SignedParentMetadataReadV3(r,family="d07",
                kind="reflection_continuation",ref=raw["reflection_continuation_ref"],expected_digest=raw["reflection_continuation_digest"]))
            if continuation is None:return
            value=continuation.value
            names=("reflection_request_ref","reflection_request_digest","parent_prepared_digest","parent_execution_ref",
                "parent_execution_digest","checkpoint_ref","checkpoint_digest","parent_budget_lease_ref","parent_grant_digest","original_deadline_utc")
            if (value["schema"]!="d07.reflection-continuation.v3"
                    or any(value[name]!=raw[name]for name in names)
                    or value["parent_job_id"]!=raw["parent_prepared_ref"]
                    or value["source_refs"]!=raw["source_refs"]
                    or value["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}):
                raise AuthorityUnavailable("D07 Reflection actual signed continuation changed parent/source/checkpoint/deadline")
            self.reflection_continuation=value
            self.originals.append(("d07.reflection_continuation",raw["reflection_continuation_ref"],continuation.metadata[0]))
            self.deadlines.append(value["original_deadline_utc"]);self.phase="reflection_request";return
        if self.phase=="reflection_request":
            request=self._leaf_v3(("reflection_request",header.job_id),_D07SignedParentMetadataReadV3(r,family="d07",
                kind="reflection_request",ref=raw["reflection_request_ref"],expected_digest=raw["reflection_request_digest"]))
            if request is None:return
            value=request.value;continuation=self.reflection_continuation
            frozen=header.column.frozen_metadata.value["input"]
            if (value["reflection_ref"]!=_d07_parent_version_key_v3(raw["checkpoint_ref"])
                    or value["source_refs"]!=continuation["source_refs"] or value["causal_depth"]>=2
                    or frozen["causal_depth"]!=value["causal_depth"]
                    or value["causal_depth_original_ref"]!=raw["parent_execution_ref"]):
                raise AuthorityUnavailable("D07 Reflection actual request/root-depth/source commitments changed")
            self.reflection_request=value;self.phase="reflection_execution";return
        if self.phase=="reflection_execution":
            execution=self._leaf_v3(("reflection_execution",header.job_id),_D07SignedParentMetadataReadV3(r,family="d07",
                kind="execution",ref=raw["parent_execution_ref"],expected_digest=raw["parent_execution_digest"]))
            if execution is None:return
            value=execution.value
            parent=r.parent_headers[raw["parent_prepared_ref"]].require_v3(r)
            parent_raw=parent.value
            if (value["source_refs"]!=raw["source_refs"] or value["work_kind"]=="simulation"
                    or any(value[name]!=parent_raw[name]for name in(
                        "operation_id","activity_id","effect_id","attempt_id","execution_id","work_kind","activation_generation"))
                    or value["input_digest"]!=parent_raw["stage_input_digest"]
                    or value["parent_budget_ref"]!=raw["parent_budget_lease_ref"] or value["status"]!="completed"
                    or value["terminal_ref"]!="d07-terminal:"+parent_raw["call_id"]
                    or value["causal_depth"]!=self.reflection_request["causal_depth"]):
                raise AuthorityUnavailable("D07 Reflection lost exact real parent execution/prepared/Source chain")
            self.reflection_execution=value;self.phase="reflection_paid";return
        if self.phase=="reflection_paid":
            paid=self._leaf_v3(("reflection_paid",header.job_id),_D07SignedParentMetadataReadV3(r,family="d07",
                kind="paid_cost",ref=raw["parent_prepared_ref"]))
            if paid is None:return
            if (paid.value["prepared_digest"]!=raw["parent_prepared_digest"] or paid.value["paid"]is not True
                    or paid.value["unknown_dimensions"] or paid.value["cost_ref"]not in self.reflection_execution["cost_receipt_refs"]):
                raise AuthorityUnavailable("D07 Reflection original parent has no exact fully settled paid preparation")
            self.phase="reflection_parent_job";return
        if self.phase=="reflection_parent_job":
            leaf=self._leaf_v3(("reflection_parent_job",header.job_id),_D07ParentJobMetadataReadV3(r,raw["parent_prepared_ref"]))
            if leaf is None:return
            parent=leaf.value;continuation=self.reflection_continuation
            if (parent["phase"]!="completed" or parent["cancel_epoch"] or parent["result_ref"]!=raw["parent_execution_ref"]
                    or parent["operation_id"]!=r.parent_headers[raw["parent_prepared_ref"]].value["operation_id"]
                    or parent["budget_ref"]!=raw["parent_budget_lease_ref"]
                    or _d07_parent_utc_v3(parent["deadline_utc"])!=raw["original_deadline_utc"]
                    or leaf.continuation["choice"]["ticket_id"]!=continuation["ticket_id"]
                    or leaf.continuation["request"]["category"]!=continuation["category"]):
                raise AuthorityUnavailable("D07 Reflection original parent paid job/root ticket/category/deadline changed")
            self.reflection_parent_job=parent;self.phase="reflection_budget";return
        if self.phase=="reflection_budget":
            budget=self._leaf_v3(("reflection_budget",header.job_id),_D07ParentBudgetMetadataReadV3(r,raw["parent_budget_lease_ref"]))
            if budget is None:return
            if canonical_digest(budget.grant)!=raw["parent_grant_digest"] or "d07.cognition"not in budget.grant.allowed_work_kinds:
                raise AuthorityUnavailable("D07 Reflection changed original parent grant or Work authorization")
            self.deadlines.append(budget.grant.valid_until_utc);self.phase="reflection_checkpoint";return
        if self.phase=="reflection_checkpoint":
            from ..graph_types import GraphVersion
            version=decode_typed_production_value_v1(raw["checkpoint_ref"],GraphVersion)
            history=self._leaf_v3(("reflection_checkpoint",header.job_id),_D07HistoryParentMetadataReadV3(
                r,version.key.token,version.revision,expected_operation=self.reflection_parent_job["operation_id"],
                expected_digest=raw["checkpoint_digest"]))
            if history is None:return
            checkpoint=self._leaf_v3(("reflection_current_checkpoint",header.job_id),_D07GraphParentMetadataReadV3(r,version.key.token))
            if checkpoint is None:return
            if (history.value["status"]!="continue" or checkpoint.revision!=version.revision
                    or checkpoint.semantic_digest!=raw["checkpoint_digest"] or checkpoint.value!=history.value):
                raise AuthorityUnavailable("D07 before-call Reflection checkpoint lost its actual parent birth/current continuation")
            self.phase="reflection_cycle";return
        if self.phase=="reflection_cycle":
            cycle_ref=self.reflection_continuation["cycle_job_ref"]
            if cycle_ref is None:
                if raw["cycle_ref"]is not None:
                    raise AuthorityUnavailable("D07 Reflection introduced a new Self cycle")
                self.phase="next";return
            if raw["cycle_ref"]is None or _d07_parent_version_key_v3(raw["cycle_ref"])!=cycle_ref:
                raise AuthorityUnavailable("D07 Reflection changed original Self cycle")
            leaf=self._leaf_v3(("reflection_cycle",header.job_id),_D07ParentJobMetadataReadV3(r,AtomKey.from_token(cycle_ref).name))
            if leaf is None:return
            job=leaf.value;cycle=leaf.continuation
            if (job["phase"]not in {"queued","running","waiting"} or job["cancel_epoch"] or cycle["cancel_generation"]
                    or cycle["stage"]=="completed" or cycle["call_plan"]["parent_budget_lease_ref"]!=raw["parent_budget_lease_ref"]
                    or cycle["c02_operation_id"]!=raw["c02_operation_id"]):
                raise AuthorityUnavailable("D07 Reflection cannot revive its closed/cancelled original Self cycle")
            attempts=[item for item in cycle["call_plan"]["attempts"]if item["call_id"]==raw["call_id"]]
            if len(attempts)!=1:
                raise AuthorityUnavailable("D07 Reflection has no unique actual original C3 member")
            member=attempts[0];workflow=r.bundle.model_workflows.d07_cognition
            if (member["slot"]!="C3" or member["original_call_id"]is not None
                    or (member["reservation_operation_id"],member["reservation_digest"],member["budget_lease_ref"])!=(
                        raw["operation_id"],raw["reservation_digest"],raw["parent_budget_lease_ref"])
                    or (member["input_ceiling"],member["output_ceiling"])!=(
                        workflow.quote_ceiling["input_tokens"],workflow.quote_ceiling["output_tokens"])):
                raise AuthorityUnavailable("D07 Reflection changed original C3 reservation/root lease/quote ceiling")
            acquire_id="d07-acquire:"+canonical_digest((w.namespace,raw["operation_id"]))[:48]
            acquisition=self._leaf_v3(("reflection_acquire",header.job_id),_D07BundleParentMetadataReadV3(r,acquire_id,prepared_header=header))
            if acquisition is None:return
            expected={"cycle_ref":cycle_ref,"before_cycle_digest":raw["cycle_digest"],
                "before_call_plan_digest":raw["call_plan_digest"],"call_id":raw["call_id"],
                "reflection_request_digest":raw["reflection_request_digest"]}
            if (acquisition.value["phase"]!="execution_acquired"
                    or acquisition.value["prepared_digest"]!=header.metadata[0]
                    or acquisition.value["reflection_c3"]!=expected):
                raise AuthorityUnavailable("D07 Reflection original registered C3 has no exact actual acquire receipt")
            self.deadlines.append(_d07_parent_utc_v3(job["deadline_utc"]));self.phase="next";return
        if self.phase=="next":
            self.originals.append(("d07.prepared",header.job_id,header.metadata[0]))
            self.index+=1;self.phase="parent";return
        if self.phase=="finish":
            original=r.header.require_v3(r);source=_d07_parent_source_authority_v3(r,original)
            deadline=min((w.deadline_utc,*self.deadlines))
            if w.controller.clock()>=deadline:
                raise AuthorityUnavailable("D07 special parent exceeded its original ancestor deadline minimum")
            source_versions=tuple(sorted({(row["ref"],row["revision"])for item in self.headers for row in item.source_rows}))
            names={D07IngressRecallPreparedV1:"ingress_recall_self",D07MethodGrowthPreparedV2:"method_growth_self",
                D07ReflectionPreparedV3:"reflection",D07RelationshipPreparedV2:"relationship_self",
                D07GeneralGrowthPreparedV1:"general_growth_owner",D07ArtifactObservationPreparedV3:"artifact_observation_self"}
            self.complete=True
            self.result=D07AuthorityParentMetadataQualifiedV3(_ISSUER,self,kind=names.get(original.prepared_class,"ordinary_owner"),
                authority=source,parent_originals=self.originals,deadline=deadline,source_versions=source_versions)
            return
        raise AuthorityUnavailable("D07 special-parent metadata task has an unregistered phase")

def _d07_parent_utc_v3(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

def _d07_parent_version_key_v3(raw):
    from ..graph_types import GraphVersion
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,GraphVersion).key.token

class _D07GraphParentMetadataReadV3:
    def __init__(self,reader,ref):
        self.reader,self.work,self.ref=reader,reader.work,ref
        self.phase="identity";self.complete=False;self.column=None
    def advance_v3(self,meter):
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            key=AtomKey.from_token(self.ref)
            if NamespaceId.from_key(key)!=w.namespace or key.type_name not in{
                    "runtime.job","d01.method_trial_proposal.v2","d07.reflection_checkpoint.v1",
                    "d03.self_identity_mapping.v1"}:
                raise AuthorityUnavailable("D07 special-parent metadata leaf has an unregistered exact head schema")
            head=w.heads.get(self.ref)
            if head is None or not head[1]or head[2]is None:
                raise AuthorityUnavailable("D07 actual special-parent metadata head/cell absent")
            self.revision,self.valid,self.cell_id=head
            self.column=_D07ParentMetadataColumnV3(w,table="graph_atoms",column="value",
                key_columns=("token",),key=(self.ref,),
                mode={"runtime.job":"graph_job","d01.method_trial_proposal.v2":"graph_proposal",
                    "d07.reflection_checkpoint.v1":"checkpoint","d03.self_identity_mapping.v1":"metadata"}[key.type_name],
                cell_id=self.cell_id,erasure_owner_ref=self.ref)
            self.phase="bytes";return
        if not self.column.advance(meter):return
        self.value=self.column.require_v3(w)
        key=AtomKey.from_token(self.ref)
        expected_fields=({"reflection_id","meta_depth","no_progress_count","unresolved_slots","discriminating_refs","status"}
            if key.type_name=="d07.reflection_checkpoint.v1"else set(self.value))
        if key.type_name=="d07.reflection_checkpoint.v1" and self.column.fields_seen==expected_fields|{"schema"}:
            if self.value["schema"]!=key.type_name:
                raise AuthorityUnavailable("D07 checkpoint registered Graph writer schema differs")
            expected_fields=expected_fields|{"schema"}
        if self.column.fields_seen!=expected_fields:
            raise AuthorityUnavailable("D07 current parent metadata head has fields outside its exact safe schema")
        from ..runtime_contracts import canonical_digest
        self.semantic_digest=self.column.canonical_semantic_digest;self.complete=True

class _D07HistoryParentMetadataReadV3:
    def __init__(self,reader,ref,revision,*,expected_operation,expected_digest=None):
        self.reader,self.work,self.ref,self.revision=reader,reader.work,ref,revision
        self.expected_operation,self.expected_digest=expected_operation,expected_digest
        self.phase="identity";self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_history",
                ("event_bot","event_persona","event_id","valid","value_cell_id"),
                "token=? AND revision=?",(self.ref,self.revision))
            if self.metadata is None or self.metadata[:4]!=(*w.namespace.as_tuple,self.expected_operation,1):
                raise AuthorityUnavailable("D07 special-parent immutable history lost actual W01 event/member")
            self.column=_D07ParentMetadataColumnV3(w,table="graph_history",column="value",
                key_columns=("token","revision"),key=(self.ref,self.revision),
                mode="checkpoint"if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1"else
                    "general_ticket"if AtomKey.from_token(self.ref).type_name=="d07.attention_ticket.v1"else"graph_job",
                cell_id=self.metadata[4],erasure_owner_ref=self.ref)
            self.phase="bytes";return
        if not self.column.advance(meter):return
        self.value=self.column.require_v3(w)
        from ..domains.d07 import AttentionTicket
        expected_fields=({"schema",*(field.name for field in fields(AttentionTicket))}if AtomKey.from_token(self.ref).type_name=="d07.attention_ticket.v1"else
            {"reflection_id","meta_depth","no_progress_count","unresolved_slots","discriminating_refs","status"}if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1"else set(self.value))
        if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1" and self.column.fields_seen==expected_fields|{"schema"}:
            if self.value["schema"]!="d07.reflection_checkpoint.v1":
                raise AuthorityUnavailable("D07 checkpoint birth writer schema differs")
            expected_fields=expected_fields|{"schema"}
        if self.column.fields_seen!=expected_fields:
            raise AuthorityUnavailable("D07 parent history metadata contains another head schema")
        from ..runtime_contracts import canonical_digest
        self.semantic_digest=self.column.canonical_semantic_digest
        if self.expected_digest is not None and self.semantic_digest!=self.expected_digest:
            raise AuthorityUnavailable("D07 special-parent immutable history full canonical semantic EOF digest changed")
        self.complete=True

class _D07C02EventMetadataReadV3:
    def __init__(self,reader,operation_id,activity_id):
        self.reader,self.work,self.operation_id,self.activity_id=reader,reader.work,operation_id,activity_id
        self.phase="identity";self.columns={};self.index=0;self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_events",("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",
                (*w.namespace.as_tuple,self.activity_id,self.operation_id))
            if row is None:
                raise AuthorityUnavailable("C02 Source metadata has no actual same-activity Graph event")
            self.epoch_revision=row[0]
            for name in ("reads","revisions"):
                self.columns[name]=_D07ParentMetadataColumnV3(w,table="graph_events",column=name,
                    key_columns=("bot","persona","session","event_id"),
                    key=(*w.namespace.as_tuple,self.activity_id,self.operation_id),mode="metadata")
            self.phase="arrays";return
        names=("reads","revisions")
        column=self.columns[names[self.index]]
        if not column.advance(meter):return
        self.index+=1
        if self.index==len(names):
            self.value=(canonical_serialize(self.columns["reads"].require_v3(w)),
                canonical_serialize(self.columns["revisions"].require_v3(w)),self.epoch_revision)
            self.complete=True

class _D07BundleParentMetadataReadV3:
    def __init__(self,reader,operation_id,*,prepared_header=None):
        self.reader,self.work,self.operation_id=reader,reader.work,operation_id
        self.prepared_header=prepared_header
        self.phase="identity";self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if self.metadata is None:raise AuthorityUnavailable("D07 parent original bundle metadata absent")
            self.column=_D07ParentMetadataColumnV3(w,table="graph_bundle_operations",column="receipt_json",
                key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,self.operation_id),mode="metadata")
            self.phase="bytes";return
        if not self.column.advance(meter):return
        value=self.column.require_v3(w)
        if value.get("schema")=="d07.actual-graph-stage.v1":
            header=self.prepared_header
            if type(header)is not _D07AuthorityPreparedHeaderReadV3:
                raise AuthorityUnavailable("D07 actual acquired-stage receipt needs its exact authenticated prepared header")
            header.require_v3(r)
            raw=header.value
            from ..runtime_contracts import canonical_digest
            from ..runtime.d07_execution_v1 import D07ReflectionPreparedV3,D07RelationshipPreparedV2
            from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
            from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
            tags={D07ReflectionPreparedV3:"reflection_c3",D07RelationshipPreparedV2:"relationship_c3",
                D07MethodGrowthPreparedV2:"method_growth_c3",D07ArtifactObservationPreparedV3:"artifact_observation_c3"}
            tag=tags.get(header.prepared_class)
            fields_expected={"schema","status","commit_seq","phase","prepared_digest","graph_receipt_digest"}
            if tag is not None:fields_expected.add(tag)
            if (set(value)!=fields_expected or value["status"]!="committed"
                    or value["phase"]!="execution_acquired" or value["prepared_digest"]!=header.metadata[0]
                    or value["commit_seq"]!=self.metadata[3] or self.metadata[1:3]!=(raw["activity_id"],None)
                    or self.operation_id!="d07-acquire:"+canonical_digest((w.namespace,raw["operation_id"]))[:48]
                    or type(value["graph_receipt_digest"])is not str or len(value["graph_receipt_digest"])!=64):
                raise AuthorityUnavailable("D07 acquire table identity and actual closed stage receipt differ")
        else:
            if "first_ingress_c02"not in value:
                raise AuthorityUnavailable("D07 original C02 Source parent lost actual first-ingress receipt metadata")
            if self.phase!="c02_event":
                self.event=_D07C02EventMetadataReadV3(r,self.operation_id,self.metadata[1])
                self.phase="c02_event";return
            if not self.event.complete:
                self.event.advance_v3(meter);return
            from ..runtime.domain_production_originals_v1 import (
                reconstruct_graph_bundle_commit_receipt_v1,_receipt_wire)
            receipt=reconstruct_graph_bundle_commit_receipt_v1(w.namespace,self.operation_id,
                (*self.metadata,canonical_serialize(value)),self.event.value)
            value={**_receipt_wire(receipt),"first_ingress_c02":value["first_ingress_c02"]}
        self.value=value;self.complete=True

def prepare_d07_authority_special_parent_metadata_read_v3(reader):
    return _D07SpecialParentMetadataReadV3(reader)

def qualify_d07_authority_special_parent_metadata_v3(reader,task):
    reader.require_registered_v3()
    if (type(task)is not _D07SpecialParentMetadataReadV3 or task.reader is not reader
            or _PARENT_TASKS_V3.get(task)!=(reader,reader.work,reader.work.operation,reader.work.scope,reader.work.graph_stamp)
            or not task.complete or type(task.result)is not D07AuthorityParentMetadataQualifiedV3):
        raise AuthorityUnavailable("D07 special-parent qualification requires this actual complete metadata task")
    return task.result.require_for_v3(reader)

class _D07RelationshipParentPolicyReadV3:
    def __init__(self,reader,question):
        self.reader,self.work,self.question=reader,reader.work,question
        self.phase="identity";self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2,RelationshipScopeV2
        from ..runtime_contracts import canonical_digest
        r=self.reader;w=self.work;question=self.question;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_d05_production_policies_v1",
                ("revision","payload_digest","signature"),
                "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC",
                (*w.namespace.as_tuple,question["policy_ref"]))
            if self.metadata is None or self.metadata[:2]!=(question["policy_revision"],question["policy_digest"]):
                raise AuthorityUnavailable("D07 Relationship actual latest policy metadata changed")
            self.column=_D07ParentMetadataColumnV3(w,table="graph_d05_production_policies_v1",column="payload_json",
                key_columns=("bot","persona","policy_ref","revision"),
                key=(*w.namespace.as_tuple,question["policy_ref"],self.metadata[0]),mode="metadata")
            self.phase="bytes";return
        if not self.column.advance(meter):return
        value=self.column.require_v3(w)
        if self.column.sha256!=self.metadata[1]:
            raise AuthorityUnavailable("D07 Relationship policy full signed canonical EOF digest changed")
        w.controller.verifier._issuer._signer.verify("d11.d05-production-policy.v2",canonical_serialize(value),self.metadata[2])
        policy=decode_typed_production_value_v1(value,InstalledRelationshipPolicyV2)
        scope=decode_typed_production_value_v1(question["scope"],RelationshipScopeV2)
        if canonical_digest(policy)!=question["policy_digest"]:
            raise AuthorityUnavailable("D07 Relationship policy exact typed commitment changed")
        policy.rule(scope);self.complete=True


def read_bound_d07_authority_complete_row_v3(work,attachment,meter):
    reader=require_current_d07_authority_namespace_recipe_v3(work)
    if reader is None:return False,None
    reader.require_current_v3(meter);reader.require_body_qualification_v3()
    if attachment.table in {"runtime_jobs","runtime_budget_leases","runtime_budget_reservations"}:
        return False,None
    if (attachment.owner is not work or not attachment.complete
            or work.attachments.get(attachment.request)is not attachment):
        raise AuthorityUnavailable("D07 immutable EOF attachment changed its actual selected Work")
    if attachment.table in {"graph_atoms","graph_history","graph_dependencies"}:
        reader.require_selected_graph_body_v3(attachment.request)
    return True,attachment.row
