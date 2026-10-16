"""Artifact model Source on its actual Authority MODEL Work and original permit."""
from __future__ import annotations
from dataclasses import fields
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
from ..runtime.b3_managed_metadata_v1 import (JOINT_TABLE,HABIT_TABLE,metadata_columns_v1,validate_managed_metadata_row_v1)

_PHASES=WeakKeyDictionary()
_READERS=WeakKeyDictionary()
_CAPABILITIES=WeakKeyDictionary()
_HEADERS=WeakKeyDictionary()
_PHASE="actual_artifact_model_policy"
_KEY=object()
from ..runtime.artifact_joint_source_groups_v3 import JOINT_SOURCE_METADATA_FIELDS_V3 as _JOINT_METADATA_FIELDS

def _actual_work_v3(work,installed):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3,require_actual_authority_graph_attachment_owner_v3
    from .artifact_model_graph_v3 import InstalledArtifactDraftModelGraphReaderV3
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_model_egress_contract import ModelEgressIntentV1
    from .artifact_model_result_source_v3 import require_artifact_result_source_bridge_v3
    result=require_artifact_result_source_bridge_v3(work)
    if(type(work)is not AuthorityGraphReadWorkV3 or type(installed)is not InstalledArtifactDraftModelGraphReaderV3
            or type(work.service)is not AuthorityV2ModelEgressService or type(work.request)is not ModelEgressIntentV1
            or work.controller.kind!="model"or work.controller.verifier._artifact_model_reader_v3 is not installed
            or work.controller.service is not work.service or work.controller.control is not installed.owner_storage.control
            or work.controller.fences is not installed.owner_storage.fences
            or work.controller.location._graph_db_path!=installed.owner_storage.graph_path
            or work.controller.verifier._artifact_draft_bundle is not installed.bundle
            or work.namespace!=installed.owner_storage.namespace_id or work.owner_model_work_kind!="artifact_draft_v1"
            or result is None and(work.permit.operation!="model_egress"or work.request.operation_id!=work.permit.operation_id)
            or result is None and work.subject!=work.request.subject or work.permit.subject!=work.subject or work.deadline_utc is None):
        raise AuthorityUnavailable("Artifact Source requires its actual installed model reader/service/Work/permit")
    require_actual_authority_graph_attachment_owner_v3(work);return work

def require_artifact_model_phase_v3(work,installed):
    _actual_work_v3(work,installed)
    identity=(installed,work.controller,work.service,installed.owner_storage,installed.bundle,
        work.operation,work.scope,work.permit,work.request,work.selection_digest,work.deadline_utc)
    prior=_PHASES.get(work)
    if prior is None:_PHASES[work]=identity
    elif prior!=identity:raise AuthorityUnavailable("Artifact model phase changed its original installed call")
    if work not in _READERS:_READERS[work]=ArtifactAuthoritySourceReadV3(_KEY,work,installed)
    return _PHASE

def require_artifact_model_owner_header_v3(proof):
    from .owner_location_read_v3 import OwnerLocationCallerProofV3
    if(type(proof)is not OwnerLocationCallerProofV3 or proof.kind!="authority_artifact_model_header"
            or proof.model_source_phase!=_PHASE):
        raise AuthorityUnavailable("Artifact Owner header lacks its actual independent model Source phase")
    work=proof.request;state=_PHASES.get(work)
    if state is None:raise AuthorityUnavailable("Artifact Owner header has no actual registered model Work")
    installed=state[0];_actual_work_v3(work,installed)
    if(state!=(installed,work.controller,work.service,installed.owner_storage,installed.bundle,
                work.operation,work.scope,work.permit,work.request,work.selection_digest,work.deadline_utc)
            or proof.controller is not work.controller or proof.service is not work.service
            or proof.owner_service is not installed.owner_storage or proof.bundle is not installed.bundle
            or proof.retained_operation is not work.operation or proof.scope is not work.scope
            or proof.original_permit is not work.permit or proof.credential is not work.credential
            or proof.subject!=work.subject or proof.namespace!=work.namespace
            or proof.selection_digest!=work.selection_digest or proof.deadline_utc!=work.deadline_utc):
        raise AuthorityUnavailable("Artifact Owner header changed its actual original reader/Scope/subject")
    return proof

def _retain_v3(profile,path):
    if not path:return True
    if profile=="frozen":
        from ..runtime.artifact_frozen_metadata_v3 import artifact_frozen_metadata_path_v3
        return artifact_frozen_metadata_path_v3(path)
    if profile=="quote":
        from ..runtime.issuers import ResourceQuote
        if path[0]not in{f.name for f in fields(ResourceQuote)}:return False
        return path[0]!="job_continuation"or len(path)<2 or path[1]in{"schema","selector","prepared_digest"}
    if profile=="grant":
        from ..runtime.issuers import BudgetLeaseGrant
        return path[0]in{f.name for f in fields(BudgetLeaseGrant)}
    if profile=="phase_prepared_index":
        return path[0]in{"schema","selector","operation_id"}
    if profile=="habit_interpretation":return path[0]=="source_refs"
    if profile=="task_scope_joint":return path[0]in {"schema","namespace","c02_operation_id"}
    if profile=="joint_graph":return path[0]in _JOINT_METADATA_FIELDS
    if profile=="joint_producer":
        if path[0]in {"schema","namespace","identity"}:return True
        if path[0]!="writes":return False
        if len(path)<4 or path[2]!="value":return True
        return path[3]in _JOINT_METADATA_FIELDS
    if profile=="producer":
        if path[0]in {"schema","namespace","identity","request"}:return True
        return path[0]=="provenance"and(len(path)==1 or path[1]=="artifact_model_control_reads_v1")
    return True

class _MetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,reader,profile,*,table,column,key_columns,key,cell_id=None):
        self.reader,self.profile=reader,profile
        self.source_fields={};self.record_fields={};self.object_fields={}
        super().__init__(reader.work,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:_retain_v3(profile,path)
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,ensure_ascii=self.cell is None or self.cell.header[0]=="canonical-json.ascii.v1")
    def _actual(self):self.reader.require_registered_v3();return self
    def _emit(self,event):
        if self.profile=="frozen"and event.kind=="key":
            self.object_fields.setdefault(event.path[:-1],set()).add(event.key)
        if self.profile=="frozen"and event.kind=="key"and event.path[0]=="sources":
            if len(event.path)==3:self.source_fields.setdefault(event.path[1],set()).add(event.key)
            elif len(event.path)==4 and event.path[2]=="record":self.record_fields.setdefault(event.path[1],set()).add(event.key)
        self.capture._emit_v3(event);self.value=self.capture.value
    def require_frozen_fields_v3(self):
        from ..runtime.artifact_frozen_metadata_v3 import validate_artifact_frozen_metadata_fields_v3
        validate_artifact_frozen_metadata_fields_v3(self.value,top_fields=self.capture.fields_seen,
            source_fields=self.source_fields,record_fields=self.record_fields,object_fields=self.object_fields)

class _RequestMetadataColumnV3(DispatchOriginalJSONReadV3):
    """Complete signed outer and inner request EOF; retain no model payload."""
    def __init__(self,reader,kind,ref):
        from .internal_life_model_source_read_v3 import _FilteredMetadataV3
        from ..runtime.d11_life_preparation_v1 import TABLE
        self.reader=reader;self.fields_seen=set();self.embedded_field="request_json"
        self.embedded=_FilteredMetadataV3(self,lambda path:not path or path[0]!="payload")
        super().__init__(reader.work,table=TABLE,column="payload_json",key_columns=("bot","persona","kind","original_ref"),
            key=(*reader.work.namespace.as_tuple,kind,ref))
        from .internal_life_model_source_read_v3 import _EmbeddedMetadataStreamV3
        self.parser=_EmbeddedMetadataStreamV3(self)
    def _actual(self):self.reader.require_registered_v3();return self
    def _emit(self,event):
        if event.kind=="key"and len(event.path)==1:self.fields_seen.add(event.key)
        if event.path==("request_json",)and event.kind=="scalar_end":self.embedded.finish()
        if event.path and event.path[0]=="request_json":return
        super()._emit(event)

class _SignedMetadataV3:
    def __init__(self,reader,kind,ref,profile):
        self.reader,self.kind,self.ref,self.profile=reader,kind,ref,profile
        self.header=self.column=self.value=self.embedded=None;self.complete=False
    def advance_v3(self,meter):
        r=self.reader;w=r.work;r.require_current_v3(meter)
        from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
        if self.column is None:
            self.header=meter.read_fixed_row(w.db,TABLE,("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*w.namespace.as_tuple,self.kind,self.ref))
            if self.header is None:raise AuthorityUnavailable("Artifact model signed locator original absent")
            w.operation.retain(4096)
            self.column=(_RequestMetadataColumnV3(r,self.kind,self.ref)if self.profile=="request"else
                _MetadataColumnV3(r,self.profile,table=TABLE,column="payload_json",
                    key_columns=("bot","persona","kind","original_ref"),key=(*w.namespace.as_tuple,self.kind,self.ref)))
            return
        if not self.column.advance(meter):return
        if self.column.sha256!=self.header[1]:raise AuthorityUnavailable("Artifact model signed metadata lacks actual canonical whole EOF")
        r.installed.issuer._signer.verify(SIGN_KIND,canonical_serialize((w.namespace,self.kind,self.ref,self.header[1])),self.header[2])
        self.value=self.column.require_v3(w)
        if self.profile=="frozen":self.column.require_frozen_fields_v3()
        if self.profile=="request":
            if not self.column.embedded.complete:raise AuthorityUnavailable("Artifact model inner request did not reach full EOF")
            self.embedded=self.column.embedded.value
        self.complete=True
        _HEADERS[self]=(r,w,self.kind,self.ref,self.header,self.column,self.value,self.embedded,w.operation,w.scope)
    def require_v3(self,reader):
        if(reader is not self.reader or not self.complete or _HEADERS.get(self)!=(reader,reader.work,self.kind,self.ref,
                self.header,self.column,self.value,self.embedded,reader.work.operation,reader.work.scope)):
            raise AuthorityUnavailable("Artifact metadata lost its actual complete signed Work/Scope")
        reader.require_registered_v3();return self

class ArtifactAuthoritySourceReadV3:
    def __init__(self,key,work,installed):
        if key is not _KEY:raise AuthorityUnavailable("Actual Artifact model Source factory required")
        self.work,self.installed=work,installed
        self.phase="job";self.complete=False;self.capability=None;self.column=None;self.pending_column=None
        self.selector=self.ids=self.prepared=self.frozen=self.request=self.root=None
        self.expires_at=None;self.budget_metadata=None;self.grants={};self.quote=None
        self.task_model_preparations=[];self.task_preparation_cursor="";self.task_preparation_column=None
        self.finished_metadata={};self.producer_metadata={};self.control=None;self.request_body=None
        self.metadata_atoms={};self.occurrences={};self.invalid_occurrences={};self.policies={}
        self.managed={JOINT_TABLE:[],HABIT_TABLE:[]};self.managed_phase=JOINT_TABLE;self.managed_cursor=""
        self.groups=();self.pending=[];self.checked=set();self.qualified={};self.versions={}
        self.expected={};self.graph_versions=set();self.graph_tokens=set()
        self.body_graph_tokens=set();self.metadata_history_versions=set();self.control_frame=None
        self.qualified_frozen_originals=set();self.negative_originals=set()
        self.proof_original_refs=set();self.proof_original_domains={};self.proof_original_digests={};self.proof_original_values={};self.frame_originals={};self.candidate_family=None
        self.original_operations=set();self.original_keys=set();self.parent_refs=set();self.quote_versions=set();self.job_ids=set()
        self.joint_inventory=None;self.joint_metadata=None;self.joint_source_groups=()
        self.habit_metadata=None;self.habit_context_roots=set()
        self.metadata_eof=canonical_digest(("sylanne.artifact-model-managed-eof.v3",work.namespace))
    def require_registered_v3(self):
        _actual_work_v3(self.work,self.installed)
        if _READERS.get(self.work)is not self or self.work not in _PHASES:
            raise AuthorityUnavailable("Artifact model Source lost its actual installed private registry")
        return self
    def require_current_v3(self,meter):
        self.require_registered_v3();self.work.require_current(meter=meter)
        if self.expires_at is not None and self.work.controller.clock()>=self.expires_at:
            raise AuthorityUnavailable("Artifact original signed Root/quote/window expired during Source read")
        from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
        require_owner_location_for_model_graph_read_v3(self.work.db,installed_reader=self.installed,intent=self.work.request)
    def _job_v3(self,meter):
        w=self.work
        if self.column is None:
            row=meter.read_fixed_row(w.db,"runtime_jobs",("bot_id","persona_id","work_kind"),"job_id=?",(w.request.job_id,))
            if row!=(*w.namespace.as_tuple,"artifact_draft_v1"):raise AuthorityUnavailable("Artifact original job metadata differs")
            self.column=_MetadataColumnV3(self,"job",table="runtime_jobs",column="continuation_json",
                key_columns=("job_id",),key=(w.request.job_id,));return
        if not self.column.advance(meter):return
        raw=self.column.require_v3(w)
        from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,
            artifact_draft_from_wire_v1,artifact_draft_from_wire_v2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2)
        phase=raw["schema"]=="d11.artifact-draft-phase-model-job.v2"
        if set(raw)!={"schema","selector","prepared_digest"}or raw["schema"]not in {
                "d11.artifact-draft-model-job.v1","d11.artifact-draft-phase-model-job.v2"}:
            raise AuthorityUnavailable("Artifact current job lacks its exact closed prepared selector")
        self.selector=(artifact_draft_from_wire_v2(raw["selector"],ArtifactDraftPhaseSelectorV2)if phase else
            artifact_draft_from_wire_v1(raw["selector"],ArtifactDraftTaskSelectorV1))
        self.ids=artifact_draft_model_ids_v2(self.selector)if phase else artifact_draft_model_ids_v1(self.selector)
        if(self.ids["job"],self.ids["call"],self.ids["acquire"])!=(w.request.job_id,w.request.call_id,w.request.operation_id):
            raise AuthorityUnavailable("Artifact job selector changed original once IDs")
        self.prefix="c4_phase_"if phase else"c4_";self.phase_variant=phase;self.job_prepared_digest=raw["prepared_digest"]
        self.prepared=_SignedMetadataV3(self,self.prefix+"prepared",self.ids["job"],"prepared")
        self.column=None;self.phase="prepared"
    def _producer_metadata_v3(self,operation,meter):
        old=self.producer_metadata.get(operation)
        if old is not None:return old
        w=self.work
        if self.column is None:
            header=meter.read_fixed_row(w.db,"graph_domain_production_originals_v1",
                ("domain","operation_kind","original_digest","receipt_digest","bundle_digest"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,operation))
            bundle=meter.read_fixed_row(w.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,operation))
            if(header is None or bundle is None or header[4]!=bundle[0]or type(bundle[1])is not int or bundle[1]<1):
                raise AuthorityUnavailable("Artifact metadata lacks its real positive producer COMMIT")
            self.pending_column=(operation,header,bundle)
            self.column=_MetadataColumnV3(self,"producer",table="graph_domain_production_originals_v1",
                column="original_payload_json",key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,operation))
            return None
        if self.pending_column is None or self.pending_column[0]!=operation:
            raise AuthorityUnavailable("Artifact producer metadata cursor changed actual operation")
        if not self.column.advance(meter):return None
        raw=self.column.require_v3(w);_,header,bundle=self.pending_column
        if(self.column.sha256!=header[2]or raw["schema"]!=header[0]+".current-"+header[1]+".v1"
                or raw["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}
                or(raw["identity"]["operation_id"],raw["identity"]["phase"])!=(operation,header[1])):
            raise AuthorityUnavailable("Artifact producer metadata canonical identity/whole EOF differs")
        self.producer_metadata[operation]=(header,raw,bundle);self.column=self.pending_column=None
        return self.producer_metadata[operation]
    def _plan_v3(self):
        w=self.work;p=self.prepared.require_v3(self).value;f=self.frozen.require_v3(self).value
        saved=self.request.require_v3(self);r=saved.value;wire=saved.embedded
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_contracts import CommandEnvelope
        envelope=decode_typed_production_value_v1(wire["envelope"],CommandEnvelope)
        expected_prepared_schema="d11.artifact-draft-phase-model-prepared.v2"if self.phase_variant else"d11.artifact-draft-model-prepared.v1"
        if(p["schema"]!=expected_prepared_schema or p["job_id"]!=w.request.job_id
                or p["call_id"]!=w.request.call_id or p["acquire_operation_id"]!=w.request.operation_id
                or p["installation_id"]!=self.installed.bundle.installation_policy.installation_id
                or p["worker_subject"]!=w.request.subject or self.prepared.header[1]!=w.request.binding_digest
                or self.job_prepared_digest!=self.prepared.header[1]
                or p["frozen_digest"]!=self.frozen.header[1]or r["prepared_digest"]!=self.prepared.header[1]
                or r["request_digest"]!=w.request.request_digest or envelope.identity.operation_id!=w.request.operation_id
                or envelope.identity.phase!="artifact_draft_v1"or envelope.authority.purpose!="consolidation"
                or envelope.authority.namespace!=w.namespace or envelope.authority.actor!=w.request.subject
                or envelope.authority.audience!=tuple(p["audiences"])
                or envelope.parent_budget_lease_ref!=p["parent_budget_lease_ref"]):
            raise AuthorityUnavailable("Artifact signed metadata changed original model request/worker/Root/Scope")
        if self.prepared.header[0]!=p["operation_id"]or self.frozen.header[0]!=p["operation_id"]or self.request.header[0]!=p["acquire_operation_id"]:
            raise AuthorityUnavailable("Artifact signed preparation/frozen/request lost actual producing operations")
        task=self.selector.task if self.phase_variant else self.selector
        from ..runtime.d11_offline_originals_v1 import _utc
        self.expires_at=min(w.deadline_utc,float(f["deadline_utc"]),_utc(p["deadline_utc"]).timestamp(),
            _utc(self.root.require_v3(self).value["valid_until_utc"]).timestamp())
        self.envelope=envelope
        self.business_versions=tuple(envelope.version_guard.read_versions)
        self.graph_versions={(v.key.token,v.revision)for v in self.business_versions}
        self.graph_tokens={ref for ref,_ in self.graph_versions}
        self.expected={v.key.token:v.revision for v in self.business_versions if v.key.type_name=="memory.source"}
        self.business_source_versions=dict(self.expected)
        business_access={v.key.owner.subject:v.revision for v in self.business_versions if v.key.type_name=="memory.access"and v.revision>0}
        if dict(w.request.access_revisions)!=business_access:
            raise AuthorityUnavailable("Artifact actual ModelIntent SourceAccess revisions differ from exact signed B")
        from ..memory_types import source_key
        intent_sources={source_key(*w.namespace.as_tuple,source_id).token:revision for source_id,revision in w.request.source_revisions}
        intent_refs={source_key(*w.namespace.as_tuple,source_id).token for source_id in w.request.source_refs}
        if intent_sources!=self.business_source_versions or intent_refs!=set(self.business_source_versions):
            raise AuthorityUnavailable("Artifact actual model intent Source family differs from exact signed business B")
        source_refs=tuple(source["ref"]for source in f["sources"])
        if(not self.expected or set(source_refs)!=set(self.expected)or f["task_source_ref"]not in self.expected
                or any(self.expected[source["ref"]]!=source["revision"]for source in f["sources"])
                or not set(envelope.source_qualification.source_refs)<=set(self.expected)):
            raise AuthorityUnavailable("Artifact business Source family differs from its actual signed acquired/frozen readset")
        self.groups=(("model_business",tuple(sorted(self.expected)),("consolidation",),tuple(p["audiences"])),)
        self.original_operations.update((p["operation_id"],p["acquire_operation_id"],task.c02_operation_id))
        self.original_keys.update(((self.prefix+"prepared",self.ids["job"]),(self.prefix+"frozen",p["frozen_ref"]),
            (self.prefix+"request",self.ids["request"]),(self.prefix+"call",p["call_id"]),
            ("draft_root_capability",task.root_registration_ref)))
        self.parent_refs.add(p["parent_budget_lease_ref"]);self.quote_versions.add((p["quote_id"],1))
        self.job_ids.update((p["job_id"],AtomKey.from_token(task.cycle_job_ref).name))
        from ..runtime.d11_types import runtime_job_key
        self.model_job_token=runtime_job_key(*w.namespace.as_tuple,p["activity_id"],p["job_id"]).token
        self.graph_tokens.add(self.model_job_token)
        from .artifact_model_original_family_v3 import seed_artifact_original_family_v3
        seed_artifact_original_family_v3(self)
        self.phase="producer_prepare"
    def advance_v3(self,meter):
        self.require_current_v3(meter);w=self.work
        if self.phase=="job":self._job_v3(meter);return
        if self.phase in {"prepared","frozen","request","root"}:
            header={"prepared":self.prepared,"frozen":self.frozen,"request":self.request,"root":self.root}[self.phase]
            header.advance_v3(meter)
            if not header.complete:return
            if self.phase=="prepared":
                self.frozen=_SignedMetadataV3(self,self.prefix+"frozen",self.prepared.value["frozen_ref"],"frozen");self.phase="frozen"
            elif self.phase=="frozen":
                self.request=_SignedMetadataV3(self,self.prefix+"request",self.ids["request"],"request");self.phase="request"
            elif self.phase=="request":
                task=self.selector.task if self.phase_variant else self.selector
                self.root=_SignedMetadataV3(self,"draft_root_capability",task.root_registration_ref,"root");self.phase="root"
            else:self._plan_v3()
            return
        if self.phase in {"producer_prepare","producer_acquire"}:
            preparing=self.phase=="producer_prepare";p=self.prepared.value
            operation=p["operation_id"]if preparing else p["acquire_operation_id"]
            actual=self._producer_metadata_v3(operation,meter)
            if actual is None:return
            expected_kind=("prepare_artifact_draft_model_v2"if preparing else"acquire_artifact_draft_model_v2")if self.phase_variant else(
                "prepare_artifact_draft_model"if preparing else"acquire_artifact_draft_model")
            if actual[0][:2]!=("d11",expected_kind):raise AuthorityUnavailable("Artifact producer operation family differs")
            if self.phase_variant:
                from ..runtime.artifact_model_control_contract_v1 import artifact_model_control_reads_from_wire_v1
                control=artifact_model_control_reads_from_wire_v1(actual[1]["provenance"]["artifact_model_control_reads_v1"])
                from .current_foreground_activity_v1 import foreground_typed_command_digest_v1
                from ..runtime.domain_production_registry_v1 import installed_operation_v1
                from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                installed=installed_operation_v1(expected_kind)
                command=decode_typed_production_value_v1(actual[1]["request"],installed.request_type)
                digest=foreground_typed_command_digest_v1(installed,command)
                if(control.operation_kind!=expected_kind or control.request_digest!=digest
                        or control.habit_classification.phase_selector!=self.selector):
                    raise AuthorityUnavailable("Artifact producer control carrier changed its actual selected phase")
                if preparing:self.prepare_control=control
                else:self.control=control
            self.phase="producer_acquire"if preparing else"budget_metadata"
            return
        if self.phase=="budget_metadata":
            if self.budget_metadata is None:self.budget_metadata=_ArtifactBudgetMetadataV3(self)
            self.budget_metadata.advance_v3(meter)
            if self.budget_metadata.complete:self.phase="task_preparations"
            return
        if self.phase=="task_preparations":
            self._advance_task_preparation_metadata_v3(meter);return
        if self.phase=="managed":
            table=self.managed_phase;columns=metadata_columns_v1(table)
            cursor_name="selector_digest"if table==JOINT_TABLE else"selector_commitment"
            row=meter.read_fixed_row(w.db,table,columns,"bot=? AND persona=? AND "+cursor_name+">? ORDER BY "+cursor_name,
                (*w.namespace.as_tuple,self.managed_cursor))
            if row is not None:
                ns,_=validate_managed_metadata_row_v1(table,columns,row,issuer=self.installed.issuer)
                if ns!=w.namespace:raise AuthorityUnavailable("Artifact managed metadata crossed actual namespace")
                w.operation.retain(4096);self.managed[table].append(tuple(row));self.managed_cursor=row[2]
                self.metadata_eof=canonical_digest((self.metadata_eof,table,tuple(row)));return
            self.metadata_eof=canonical_digest((self.metadata_eof,table,"eof",self.managed_cursor))
            if table==JOINT_TABLE:self.managed_phase=HABIT_TABLE;self.managed_cursor="";return
            self.phase="habit_metadata";return
        if self.phase=="habit_metadata":
            if self.habit_metadata is None:self.habit_metadata=_ArtifactHabitSourceMetadataV3(self)
            self.habit_metadata.advance_v3(meter)
            if self.habit_metadata.complete:self.phase="joint_metadata"
            return
        if self.phase=="joint_metadata":
            if self.joint_metadata is None:self.joint_metadata=_ArtifactJointMetadataV3(self)
            self.joint_metadata.advance_v3(meter)
            if self.joint_metadata.complete:self._source_groups_v3();self.phase="rights"
            return
        if self.phase!="rights":raise AuthorityUnavailable("Artifact model Source has another actual fixed phase")
        self._advance_rights_v3(meter)
    def _advance_task_preparation_metadata_v3(self,meter):
        from ..runtime.d11_life_preparation_v1 import TABLE
        w=self.work;task=self.selector.task if self.phase_variant else self.selector
        if self.task_preparation_column is None:
            row=meter.read_fixed_row(w.db,TABLE,("original_ref",),
                "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
                (*w.namespace.as_tuple,"c4_phase_prepared",self.task_preparation_cursor))
            if row is None:
                self.metadata_eof=canonical_digest((self.metadata_eof,"task_preparations","eof",self.task_preparation_cursor))
                self.phase="managed";return
            self.task_preparation_cursor=row[0]
            self.task_preparation_column=_SignedMetadataV3(self,"c4_phase_prepared",row[0],"phase_prepared_index");return
        column=self.task_preparation_column;column.advance_v3(meter)
        if not column.complete:return
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
        raw=column.value
        if raw["schema"]!="d11.artifact-draft-phase-model-prepared.v2"or raw["operation_id"]!=column.header[0]:
            raise AuthorityUnavailable("Artifact phase preparation metadata has unknown/retired actual schema/producer")
        selected=artifact_draft_from_wire_v2(raw["selector"],ArtifactDraftPhaseSelectorV2)
        if selected.task.namespace!=w.namespace:raise AuthorityUnavailable("Artifact phase preparation census crossed namespace")
        self.metadata_eof=canonical_digest((self.metadata_eof,"task_preparation",column.ref,column.header,column.value))
        if selected.task.c02_operation_id==task.c02_operation_id:
            bundle=meter.read_fixed_row(w.db,"graph_bundle_operations",("commit_seq",),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,column.header[0]))
            if bundle is None or type(bundle[0])is not int or bundle[0]<1:
                raise AuthorityUnavailable("Artifact exact task preparation metadata has no actual positive COMMIT")
            self.task_model_preparations.append(column.header[0]);self.original_operations.add(column.header[0])
        self.task_preparation_column=None
    def _source_groups_v3(self):
        w=self.work
        if self.control is not None:
            if self.control.business_read_versions!=self.business_versions:
                raise AuthorityUnavailable("Artifact acquired control carrier changed exact signed model business B")
            first,last=self.prepare_control.habit_classification,self.control.habit_classification
            stable=("kind","phase_selector","selector_commitment","selection_operation_id","selection_original_digest",
                "selection_receipt_digest","prepared_candidates_operation_id","prepared_candidates_original_digest",
                "prepared_candidates_receipt_digest","qualification_original")
            if any(getattr(first,name)!=getattr(last,name)for name in stable):
                raise AuthorityUnavailable("Artifact preparation/acquisition changed actual immutable ordinary/Habit selection")
            controls=(self.prepare_control,self.control)
            groups=tuple(group for control in controls for group in control.control_source_purpose_groups)
            declared={}
            for control in controls:
                for version in control.control_read_versions:
                    if version.key.type_name!="memory.source":continue
                    prior=declared.get(version.key.token)
                    if prior is not None and prior!=version.revision:
                        raise AuthorityUnavailable("Artifact actual preparation/acquisition control Source version conflicts")
                    declared[version.key.token]=version.revision
            for ref,revision in declared.items():
                if ref in self.expected and self.expected[ref]!=revision:raise AuthorityUnavailable("Artifact current B/C Source version conflicts")
                self.expected[ref]=revision
            self.groups=(*self.groups,*groups)
            context=tuple(group for group in groups if group[0]=="habit_context")
            if self.habit_context_roots and not any(self.habit_context_roots<=set(group[1])for group in context):
                raise AuthorityUnavailable("Artifact actual Habit context policy/cue/stop roots were omitted from independent context ALL")
            declared_joint={group for group in groups if group[0]in {"joint_longterm_plan","joint_window_node"}}
            if declared_joint!=set(self.joint_source_groups):
                raise AuthorityUnavailable("Artifact declared Joint purpose groups differ from independently authenticated actual R metadata")
            self.graph_versions.update((v.key.token,v.revision)for control in controls for v in control.control_read_versions)
            self.graph_tokens.update(ref for ref,_ in self.graph_versions)
            h=self.control.habit_classification
            if h.qualification_original is not None:
                self.expires_at=min(self.expires_at,h.qualification_original.original_deadline_utc,h.qualification_original.selector.original_deadline_utc)
            self.original_operations.update((h.selection_operation_id,h.prepared_candidates_operation_id))
            if h.qualification_original is not None:
                q=h.qualification_original
                self.original_operations.update((q.selector.operation_id,h.core_current.request.foreground_request.operation_id))
        from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
        owner=require_owner_location_for_model_graph_read_v3(w.db,installed_reader=self.installed,intent=w.request)
        for name,roots,purposes,audiences in self.groups:
            if not set(purposes)<=set(owner.grant["purposes"])or not set(audiences)<=set(owner.grant["audiences"]):
                raise AuthorityUnavailable("Artifact current Owner lacks an actual independent Source purpose/audience")
            self.pending.extend((name,ref,purpose,audience)for ref in roots for purpose in purposes for audience in audiences)
    def _advance_rights_v3(self,meter):
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        w=self.work
        if self.pending:
            group,ref,purpose,audience=self.pending.pop();identity=(group,ref,purpose,audience)
            if identity in self.checked:return
            if ref not in self.qualified and len(self.qualified)>=256:raise AuthorityUnavailable("Artifact Source ancestors exceed existing fixed family")
            if group=="model_business"and ref not in self.business_source_versions:
                raise AuthorityUnavailable("Artifact business Source ancestor cannot be borrowed from control C")
            key=AtomKey.from_token(ref);witness=w.sources.get(ref)
            if(witness is None or not witness.valid or ref not in self.expected or witness.revision!=self.expected[ref]):
                raise AuthorityUnavailable("Artifact Source differs from actual signed B/C family")
            witness.require_current_v3();access=self.metadata_atoms.get(access_key(*w.namespace.as_tuple,key.owner.subject))
            correction=source_correction_head_key(w.namespace,key.owner.subject);head=w.heads.get(correction.token)
            correction_atom=GraphAtom(correction,0,{},False)if head is None else GraphAtom(correction,head[0],{},bool(head[1]))
            record=_qualify_source_rights_values_v3(w.namespace,ref,witness,access,correction_atom,
                audience=audience,purpose=purpose,metadata_only=True)
            if record is None:raise AuthorityUnavailable("Artifact Source/Access/Correction denies actual purpose/audience")
            self.qualified[ref]=(witness,record);self.checked.add(identity)
            for atom in(access,correction_atom):self.versions[atom.key]=GraphVersion(atom.key,atom.revision)
            self.versions[key]=GraphVersion(key,witness.revision)
            self.pending.extend((group,source_key(*w.namespace.as_tuple,parent).token,purpose,audience)for parent in record.parent_source_ids)
            return
        active,done=set(),set()
        def visit(ref):
            if ref in active:raise AuthorityUnavailable("Artifact current Source ancestry is cyclic")
            if ref in done:return
            active.add(ref)
            for parent in self.qualified[ref][1].parent_source_ids:visit(source_key(*w.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref)
        for _,roots,_,_ in self.groups:
            for ref in roots:visit(ref)
        self.body_graph_tokens={v.key.token for v in self.business_versions}
        self.body_graph_tokens.add(self.model_job_token)
        if self.control is not None:
            self.body_graph_tokens.update(v.key.token for c in(self.prepare_control,self.control)for v in c.control_body_versions)
        self.body_graph_tokens.update(key.token for key in self.versions)
        self.graph_tokens.update(key.token for key in self.versions)
        self.graph_versions.update((v.key.token,v.revision)for v in self.versions.values())
        self.qualified_frozen_originals.add((self.prefix+"frozen",self.prepared.value["frozen_ref"]))
        self.complete=True;self.capability=ArtifactModelSourceCapabilityV3(_KEY,self)

class ArtifactModelSourceCapabilityV3:
    def __init__(self,key,reader):
        if key is not _KEY or not reader.complete:raise AuthorityUnavailable("Artifact Body requires all independent Source groups")
        self.reader,self.work=reader,reader.work;self.body=None
        _CAPABILITIES[self]=self._identity_v3()
    def _identity_v3(self):
        r=self.reader;w=self.work
        return(r,w,r.installed,w.controller,w.operation,w.scope,w.permit,w.request,w.selection_digest,
            w.graph_stamp,w.deadline_utc,r.expires_at,r.groups,frozenset(r.checked),self.body)
    def require_v3(self):
        r=self.reader;r.require_registered_v3()
        if(_CAPABILITIES.get(self)!=self._identity_v3()or r.capability is not self or not r.complete
                or self.work.controller.clock()>=r.expires_at):
            raise AuthorityUnavailable("Artifact Body proof lost actual current model Scope/Source/Owner/Root lifetime")
        for witness,_ in r.qualified.values():witness.require_current_v3()
        return self
    def seal_v3(self,body):
        self.require_v3()
        if self.body is not None and self.body!=body:raise AuthorityUnavailable("Artifact model changed actual same-Work verified Body")
        self.body=body;_CAPABILITIES[self]=self._identity_v3();return body

def artifact_model_namespace_recipe_v3(work):
    reader=_READERS.get(work)
    return None if reader is None else reader.require_registered_v3()

def artifact_model_namespace_retains_type_v3(reader,key):
    reader.require_registered_v3()
    return key.type_name in {"memory.access","d10.habit_occurrence.v1","d10.habit_policy.v1"}

class _ArtifactNamespaceMetadataColumnV3(_MetadataColumnV3):
    def __init__(self,reader,key,revision,valid,cell_id):
        self.graph_key,self.revision,self.valid=key,revision,bool(valid)
        profile="access"if key.type_name=="memory.access"else"occurrence"if key.type_name=="d10.habit_occurrence.v1"else"policy"
        super().__init__(reader,profile,table="graph_atoms",column="value",
            key_columns=("token","bot","persona"),key=(key.token,*reader.work.namespace.as_tuple),cell_id=cell_id)
    def finish_metadata_v3(self):
        r=self.reader;value=self.require_v3(r.work)
        r.metadata_eof=canonical_digest((r.metadata_eof,self.graph_key.token,self.revision,self.valid,self.sha256,self.byte_count))
        if self.graph_key.type_name=="memory.access":
            from ..memory_types import validate_access
            if self.valid:validate_access(value)
            r.metadata_atoms[self.graph_key]=GraphAtom(self.graph_key,self.revision,value,self.valid)
        elif self.graph_key.type_name=="d10.habit_occurrence.v1"and not self.valid:
            r.invalid_occurrences[self.graph_key]=value
        elif self.valid:
            if self.graph_key.type_name=="d10.habit_occurrence.v1":
                from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceV1,habit_value_from_wire_v1,habit_occurrence_key_v1
                if self.capture.fields_seen!={f.name for f in fields(HabitOccurrenceV1)}:
                    raise AuthorityUnavailable("Artifact occurrence census has another declared actual schema")
                occurrence=habit_value_from_wire_v1("d10.habit_occurrence.v1",value)
                if occurrence.namespace!=r.work.namespace or habit_occurrence_key_v1(occurrence.namespace,occurrence.occurrence_id)!=self.graph_key:
                    raise AuthorityUnavailable("Artifact occurrence census fullPK/namespace differs")
                r.occurrences[self.graph_key]=(self.revision,occurrence,canonical_digest(value))
            else:
                from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
                policy=graph_adopted_habit_policy_from_wire_v1(value)
                if policy.definition.namespace!=r.work.namespace:raise AuthorityUnavailable("Artifact policy metadata crossed namespace")
                r.policies[self.graph_key]=(self.revision,policy)
        return self

def artifact_model_namespace_metadata_column_v3(reader,key,revision,valid,cell_id):
    if not artifact_model_namespace_retains_type_v3(reader,key):
        raise AuthorityUnavailable("Artifact namespace cannot read unqualified protected business Body")
    return _ArtifactNamespaceMetadataColumnV3(reader,key,revision,valid,cell_id)

def record_artifact_namespace_header_v3(reader,key,revision,valid,cell_id):
    reader.require_registered_v3()
    reader.metadata_eof=canonical_digest((reader.metadata_eof,"header",key.token,revision,valid,cell_id))

def advance_artifact_model_source_v3(work,meter):
    reader=artifact_model_namespace_recipe_v3(work)
    if reader is None:raise AuthorityUnavailable("Artifact Source phase lacks its actual installed reader")
    reader.advance_v3(meter)
    if reader.complete:work.phase="validate"

def require_artifact_model_body_v3(db,installed,intent):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);reader=_READERS.get(work)
    if(work is None or reader is None or reader.installed is not installed or work.request is not intent
            or not db.in_transaction or reader.capability is None):
        raise AuthorityUnavailable("Artifact model Body lacks actual same-Work Source/Scope/intent")
    from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
    require_owner_location_for_model_graph_read_v3(db,installed_reader=installed,intent=intent)
    return reader.capability.require_v3()

def require_artifact_model_body_request_v3(work,request):
    reader=_READERS.get(work)
    if reader is None:return False
    if reader.capability is None:raise AuthorityUnavailable("Artifact protected Body precedes complete metadata and independent Source ALL")
    reader.capability.require_v3()
    if request[0]=="life_model.graph_body.v3":request=request[1:]
    if len(request)!=4:raise AuthorityUnavailable("Artifact model Body needs its exact private point recipe")
    table,columns,key_columns,key=request;where=dict(zip(key_columns,key))
    if len(where)!=len(key_columns)or len(key_columns)!=len(key):
        raise AuthorityUnavailable("Artifact point fullPK shape differs")
    if table in {"graph_atoms","graph_history"}:
        token=where["token"]
        allowed=(token in reader.body_graph_tokens and(table!="graph_history"or(token,where["revision"])in reader.graph_versions)
            or table=="graph_history"and(token,where["revision"])in reader.metadata_history_versions)
        if table=="graph_history"and AtomKey.from_token(token).type_name=="memory.source":
            actual=reader.qualified.get(token)
            allowed=allowed and actual is not None and where["revision"]==actual[0].revision
    elif table=="graph_dependencies":allowed=where.get("dependent_token")in reader.graph_tokens
    elif table=="runtime_jobs":allowed=where.get("job_id")in reader.job_ids
    elif table in {"graph_domain_production_originals_v1","graph_bundle_operations","graph_bundle_fences_v2","graph_owner_domain_attempts_v3"}:
        allowed=where.get("operation_id")in reader.original_operations
    elif table=="graph_events":allowed=where.get("event_id")in reader.original_operations
    elif table=="graph_d11_life_originals_v1":
        pair=(where.get("kind"),where.get("original_ref"));allowed=pair in reader.original_keys
        if allowed:
            from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
            if pair[0]in{"c4_frozen","c4_phase_frozen"}and pair not in reader.qualified_frozen_originals:
                raise AuthorityGraphAttachmentRequiredV3(("artifact_model.frozen_metadata.v3",*pair))
            if pair in{(reader.prefix+"paid",reader.ids["paid"]),(reader.prefix+"result",reader.ids["result"])}and work.permit.operation=="model_egress"and pair not in reader.negative_originals:
                raise AuthorityGraphAttachmentRequiredV3(("artifact_model.negative_original.v3",*pair))
    elif table in {"graph_d01_production_inputs_v1","graph_d02_production_inputs_v1","graph_d03_production_inputs_v1","graph_d08_joint_node_originals_v1",
            "graph_d05_boundary_intents_v1","graph_d08_joint_plan_intents_v1","graph_d08_party_consents_v1","graph_d02_action_components_v1",
            "graph_d05_production_inputs_v1","graph_d07_production_inputs_v1","graph_d08_production_inputs_v1","graph_d10_production_inputs_v1"}:
        allowed=where.get("original_ref")in reader.proof_original_refs
    elif table=="runtime_resource_quotes":allowed=(where.get("quote_id"),where.get("version"))in reader.quote_versions
    elif table in {"runtime_budget_grants","runtime_budget_leases"}:allowed=where.get("lease_id")in reader.parent_refs
    elif table in {"runtime_budget_reservations","runtime_budget_operations"}:
        allowed=where.get("lease_id")in reader.parent_refs and where.get("operation_id")in reader.original_operations
    elif table in {"graph_recovery_metadata_v2","graph_epochs","graph_authority_epochs"}:allowed=tuple(key)==work.namespace.as_tuple
    else:allowed=False
    if not allowed:raise AuthorityUnavailable("Artifact model Body point escaped actual signed B/C/producer family")
    return True

def release_artifact_model_source_v3(work):
    from .artifact_model_finished_producer_v3 import release_artifact_finished_producers_v3
    release_artifact_finished_producers_v3(work)
    from .artifact_model_graph_v3 import release_artifact_model_graph_v3
    release_artifact_model_graph_v3(work)
    reader=_READERS.pop(work,None)
    if reader is not None:
        _CAPABILITIES.pop(reader.capability,None)
        for header,state in tuple(_HEADERS.items()):
            if state[0]is reader:_HEADERS.pop(header,None)
        reader.metadata_atoms.clear();reader.occurrences.clear();reader.policies.clear();reader.managed.clear()
        reader.qualified.clear();reader.versions.clear();reader.pending.clear()
        reader.capability=reader.column=None
    _PHASES.pop(work,None)
    from .artifact_model_result_source_v3 import release_artifact_result_source_v3
    release_artifact_result_source_v3(work)

_REQUEST_EOFS=WeakKeyDictionary()

class _ArtifactRequestBodyV3(_RequestMetadataColumnV3):
    def __init__(self,reader):
        super().__init__(reader,reader.prefix+"request",reader.ids["request"])
        from .internal_life_model_source_read_v3 import _FilteredMetadataV3
        self.embedded=_FilteredMetadataV3(self,lambda path:True)
        self.request=("artifact_model.request_body.v3",)
        self.complete=False;self.comparison=None
    def advance(self,meter):
        r=self.reader;r.capability.require_v3()
        if self.comparison is None:
            if not super().advance(meter):return
            self.require_v3(r.work)
            if self.sha256!=r.request.header[1] or self.value!=r.request.value or not self.embedded.complete:
                raise AuthorityUnavailable("Artifact request Body differs from independent signed whole metadata EOF")
            raw=self.embedded.value
            if {k:v for k,v in raw.items()if k!="payload"}!=r.request.embedded:
                raise AuthorityUnavailable("Artifact request Body changed original retained envelope/config")
            from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
            envelope=r.envelope
            recipe={"envelope":envelope,"call_id":raw["call_id"],"provider_id":raw["provider_id"],
                "model_id":raw["model_id"],"purpose":envelope.authority.purpose,
                "required_capabilities":sorted(raw["required_capabilities"]),"privacy_tier":raw["privacy_tier"],
                "template":raw["prompt_template_digest"],"payload":raw["payload"],
                "timeout_seconds":float(raw["timeout_seconds"]),"max_output_tokens":raw["max_output_tokens"]}
            self.comparison=_CanonicalComparisonV3(recipe,operation=r.work.operation);self.complete=False;return
        if not self.comparison.advance(meter):return
        if self.comparison.digest!=r.work.request.request_digest:
            raise AuthorityUnavailable("Artifact actual model request canonical recipe digest differs")
        self.complete=True;r.request_body=self
    def payload_eof_v3(self,raw,envelope):
        r=self.reader;r.capability.require_v3()
        if not self.complete or r.request_body is not self or raw!=self.embedded.value or envelope!=r.envelope:
            raise AuthorityUnavailable("Artifact constructor needs this same actual whole request EOF")
        return _ArtifactModelPayloadEOFV3(_KEY,self,raw,envelope)

class _ArtifactModelPayloadEOFV3:
    def __init__(self,key,body,raw,envelope):
        if key is not _KEY:raise AuthorityUnavailable("actual Artifact request EOF factory required")
        self.body,self.raw,self.envelope=body,raw,envelope
        _REQUEST_EOFS[self]=(body,body.reader.work,raw,envelope,body.comparison.digest)
    def require_for_v3(self,request):
        from ..runtime.reply_model_job import reply_request_wire_v1
        state=_REQUEST_EOFS.get(self);r=self.body.reader
        r.capability.require_v3()
        if(state!=(self.body,r.work,self.raw,self.envelope,self.body.comparison.digest)
                or not self.body.complete or r.request_body is not self.body
                or request.envelope!=self.envelope or reply_request_wire_v1(request.envelope,request)!=self.raw):
            raise AuthorityUnavailable("Artifact typed request changed same actual payload EOF")
        from .current_authority_graph_read_v3 import _retain_authority_model_digest_v3
        _retain_authority_model_digest_v3(request,self.body.comparison.digest)

def require_artifact_model_payload_eof_v3(witness,request):
    if type(witness)is not _ArtifactModelPayloadEOFV3:return False
    witness.require_for_v3(request);return True

def prepare_artifact_model_attachment_v3(work,request):
    if len(request)==3 and request[0]in{"artifact_model.frozen_metadata.v3","artifact_model.negative_original.v3"}:
        r=_READERS.get(work)
        if r is None:raise AuthorityUnavailable("Artifact Original metadata has no actual Source profile")
        r.capability.require_v3()
        return _ArtifactOriginalMetadataV3(r,request)
    from .artifact_model_finished_producer_v3 import prepare_artifact_finished_attachment_v3
    finished=prepare_artifact_finished_attachment_v3(work,request)
    if finished is not None:return finished
    r=_READERS.get(work)
    if r is None or request!=("artifact_model.request_body.v3",):return None
    r.capability.require_v3();return _ArtifactRequestBodyV3(r)

def read_bound_artifact_model_request_v3(db,prepared,original):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3,AuthorityGraphAttachmentRequiredV3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return False,None
    r.capability.require_v3()
    if(prepared.selector!=r.selector or prepared.digest!=r.prepared.header[1]
            or original.request_digest!=work.request.request_digest or original.prepared_digest!=prepared.digest):
        raise AuthorityUnavailable("Artifact constructor crossed actual current prepared/request")
    if r.request_body is None:raise AuthorityGraphAttachmentRequiredV3(("artifact_model.request_body.v3",))
    body=r.request_body
    if canonical_serialize(body.embedded.value)!=original.request_json:
        raise AuthorityUnavailable("Artifact current acquired request differs from complete saved Body EOF")
    from ..runtime.natural_reply_job_v2 import _request_from_wire
    return True,_request_from_wire(original.request_json,prepared_value=body.embedded.value,prepared_originals=body)

def artifact_model_graph_point_v3(db,columns,*,token,revision=None):
    """The existing C4 point recipe, on actual Source-qualified model Work."""
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3,read_bound_authority_graph_attachment_v3
    work=_authority_attachment_owner_v3(db)
    if work is not None and work in _READERS:
        if revision is None:
            handled,row=read_bound_authority_graph_attachment_v3(db,table="graph_atoms",columns=columns,
                key_columns=("token","bot","persona"),key=(token,*work.namespace.as_tuple))
        else:
            handled,row=read_bound_authority_graph_attachment_v3(db,table="graph_history",columns=columns,
                key_columns=("token","revision"),key=(token,revision))
        if not handled:raise AuthorityUnavailable("Artifact exact model Work has no actual point attachment")
        return row
    from ..runtime_storage_v3 import read_graph_row_v3
    return read_graph_row_v3(db,columns,where="token=?"if revision is None else"token=? AND revision=?",
        parameters=(token,)if revision is None else(token,revision),history=revision is not None)

def read_bound_artifact_model_inventory_v3(db,namespace,type_id,*,valid_only):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return False,None
    r.capability.require_v3()
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE
    from ..domains.d01.method_learning_v1 import EXPERIMENT_TYPE
    if namespace!=work.namespace or type_id not in {CHECKPOINT_TYPE,"runtime.job",EXPERIMENT_TYPE}:
        raise AuthorityUnavailable("Artifact model inventory escaped the actual C4 capacity/pair recipe")
    selected=tuple((AtomKey.from_token(token),head)for token,head in sorted(work.heads.items())
        if AtomKey.from_token(token).type_name==type_id and(not valid_only or head[1]))
    if len(selected)>128:raise AuthorityUnavailable("Artifact complete inventory exceeds original 128-row contract")
    atoms=[]
    for key,head in selected:
        row=artifact_model_graph_point_v3(db,("revision","value","valid"),token=key.token)
        if row is None or(row[0],row[2])!=head[:2]:
            raise AuthorityUnavailable("Artifact inventory lost its complete namespace header identity")
        from .current_authority_graph_read_v3 import authority_current_json_v3
        atoms.append(GraphAtom(key,row[0],authority_current_json_v3(row[1]),bool(row[2])))
    return True,tuple(atoms)

def artifact_model_current_type_versions_v3(db,namespace,type_id,*,limit):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:
        from ..runtime_storage_v3 import read_graph_rows_v3
        return tuple(read_graph_rows_v3(db,("token","revision"),where="bot=? AND persona=? AND type_name=?",
            parameters=(*namespace.as_tuple,type_id),order_by=("token",),limit=limit))
    r.capability.require_v3()
    if namespace!=work.namespace:
        raise AuthorityUnavailable("Artifact actual type metadata crossed namespace")
    coverages=tuple((*r.control.business_query_coverage,*r.control.control_query_coverage))if r.control is not None else()
    rows=tuple((token,head[0])for token,head in sorted(work.heads.items())if AtomKey.from_token(token).type_name==type_id)
    if r.control is None:
        from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE
        business={v.key.token:v.revision for v in r.business_versions}
        if type_id not in {CHECKPOINT_TYPE,"runtime.job"}or any(business.get(token)!=revision for token,revision in rows):
            raise AuthorityUnavailable("Artifact V1 fixed capacity inventory escapes its actual complete signed business B")
    elif not any(c.type_id==type_id and c.complete for c in coverages):
        raise AuthorityUnavailable("Artifact current type query has no complete signed original B/C coverage")
    return rows[:limit]

def artifact_model_source_family_v3(db,*,namespace,roots,purpose,audiences):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return None
    r.capability.require_v3()
    if namespace!=work.namespace:raise AuthorityUnavailable("Artifact Source family crossed actual namespace")
    pending=list(roots);selected=set()
    while pending:
        ref=pending.pop()
        if ref in selected:continue
        if not any(all((name,ref,purpose,audience)in r.checked for audience in audiences)for name,_,_,_ in r.groups):
            raise AuthorityUnavailable("Artifact Source lacks every independent current purpose/audience")
        selected.add(ref)
        from ..memory_types import source_key
        pending.extend(source_key(*namespace.as_tuple,parent).token for parent in r.qualified[ref][1].parent_source_ids)
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    keys=set()
    for ref in selected:
        source=AtomKey.from_token(ref);keys.add(source)
        keys.add(access_key(*namespace.as_tuple,source.owner.subject))
        keys.add(source_correction_head_key(namespace,source.owner.subject))
    return tuple(r.versions[key]for key in sorted(keys,key=lambda key:key.token))

def register_artifact_model_source_body_v3(work,attachment,key,value):
    r=_READERS.get(work)
    if r is None or key.type_name!="memory.source":return
    r.capability.require_v3()
    witness,_=r.qualified[key.token]
    column=attachment.json_columns["value"];data=dict(zip(attachment.columns,attachment.row))
    if column.canonical_semantic_digest!=witness.canonical_semantic_digest or data["revision"]!=witness.revision:
        raise AuthorityUnavailable("Artifact current Source Body differs from independently qualified whole metadata EOF")

def read_bound_artifact_model_graph_atom_v3(db,namespace,key):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return False,None
    r.capability.require_v3()
    if namespace!=work.namespace or NamespaceId.from_key(key)!=namespace:
        raise AuthorityUnavailable("Artifact actual Graph atom crossed namespace")
    row=artifact_model_graph_point_v3(db,("revision","value","valid"),token=key.token)
    if row is None:return True,GraphAtom(key,0,{},False)
    atom=work.members.get(key)
    if atom is None or(atom.revision,int(atom.valid))!=(row[0],row[2]):
        raise AuthorityUnavailable("Artifact actual Graph atom lacks whole Body EOF on this Work")
    return True,atom

class _ArtifactJointInventoryV3:
    def __init__(self,key,reader):
        if key is not _KEY:raise AuthorityUnavailable("actual Artifact joint metadata projection factory required")
        self.reader=reader;self.operation=reader.work.operation;self.epoch=tuple(reader.work.graph_stamp)
        columns=metadata_columns_v1(JOINT_TABLE)
        self.rows=tuple({name:value for name,value in zip(columns,row)if name not in{"bot","persona","signature"}}
            for row in reader.managed[JOINT_TABLE])
        self.digest=canonical_digest((reader.metadata_eof,self.rows,self.epoch))
        self.identity=(reader,reader.work,reader.work.scope,reader.work.permit,self.operation,reader.metadata_eof,
            tuple(reader.managed[JOINT_TABLE]),tuple(reader.managed[HABIT_TABLE]))
    def require(self):
        r=self.reader;r.require_registered_v3();r.capability.require_v3()
        if(not r.complete or r.phase!="rights"or self.identity!=(r,r.work,r.work.scope,r.work.permit,self.operation,r.metadata_eof,
                tuple(r.managed[JOINT_TABLE]),tuple(r.managed[HABIT_TABLE]))or self.epoch!=tuple(r.work.graph_stamp)):
            raise AuthorityUnavailable("Artifact Joint inventory lost actual same Work/Owner/complete HMAC EOF")
        from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
        require_owner_location_for_model_graph_read_v3(r.work.db,installed_reader=r.installed,intent=r.work.request)
        return self

def current_artifact_model_joint_inventory_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return None
    r.capability.require_v3()
    if r.joint_inventory is None:r.joint_inventory=_ArtifactJointInventoryV3(_KEY,r)
    return r.joint_inventory.require()

def artifact_model_task_preparation_operations_v3(db,namespace,c02_operation_id,*,legacy_reader):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db);r=_READERS.get(work)
    if r is None:return legacy_reader()
    r.capability.require_v3()
    task=r.selector.task if r.phase_variant else r.selector
    if namespace!=work.namespace or c02_operation_id!=task.c02_operation_id:
        raise AuthorityUnavailable("Artifact phase-preparation census changed actual task")
    return tuple((operation,)for operation in r.task_model_preparations)

def artifact_model_life_payload_point_v3(db,columns,*,namespace,kind,ref,issuer):
    from .artifact_model_original_family_v3 import _reader_v3
    r=_reader_v3(db)
    if r is not None:
        r.capability.require_v3()
        if namespace!=r.work.namespace or issuer is not r.installed.issuer or(kind,ref)not in r.original_keys:
            raise AuthorityUnavailable("Artifact exact Original point escaped actual signed parent family")
    from ..runtime.d11_life_preparation_v1 import _read
    saved=_read(db,namespace=namespace,issuer=issuer,kind=kind,ref=ref)
    if saved is None:return None
    raw,producer=saved
    data={"payload_json":canonical_serialize(raw),"payload_digest":canonical_digest(raw),"producing_operation_id":producer}
    return tuple(data[name]for name in columns)

def artifact_model_graph_event_point_v3(db,columns,*,token,event_id,legacy_reader):
    from .artifact_model_original_family_v3 import _reader_v3
    r=_reader_v3(db)
    if r is None:return legacy_reader()
    r.capability.require_v3()
    if token not in r.body_graph_tokens or event_id not in r.original_operations:
        raise AuthorityUnavailable("Artifact actual history event escaped signed business/control parents")
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        rows=db.execute("SELECT revision FROM graph_history WHERE token=? AND event_id=? ORDER BY revision DESC LIMIT 2",
            (token,event_id)).fetchall();meter.charge_read(32*len(rows)+32)
    if not rows:return None
    if len(rows)!=1:raise AuthorityUnavailable("Artifact exact positive producer has multiple writes of one history key")
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    original=read_adopted_domain_operation_v1(db,r.work.namespace,event_id)
    if original is None or GraphVersion(AtomKey.from_token(token),rows[0][0])not in original["receipt"].write_versions:
        raise AuthorityUnavailable("Artifact actual history event is not an exact positive COMMIT member")
    r.graph_versions.add((token,rows[0][0]))
    return artifact_model_graph_point_v3(db,columns,token=token,revision=rows[0][0])

class _ArtifactOriginalMetadataV3:
    def __init__(self,reader,request):
        self.reader,self.request=reader,request
        if request[1:]not in reader.original_keys:raise AuthorityUnavailable("Artifact metadata Original is not an actual selected child")
        self.table=self.row=None;self.complete=False
        self.column=None if request[0]=="artifact_model.negative_original.v3"else _SignedMetadataV3(reader,request[1],request[2],"frozen")
    def advance(self,meter):
        r=self.reader;r.capability.require_v3();w=r.work;mode,kind,ref=self.request
        if self.column is None:
            from ..runtime.d11_life_preparation_v1 import TABLE
            row=meter.read_fixed_row(w.db,TABLE,("payload_digest",),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*w.namespace.as_tuple,kind,ref))
            if row is not None:raise AuthorityUnavailable("Artifact current generation is already paid/result-bearing; model egress cannot reread result Body")
            r.negative_originals.add((kind,ref));self.complete=True;return
        self.column.advance_v3(meter)
        if not self.column.complete:return
        for source in self.column.value["sources"]:
            if source["ref"]not in r.business_source_versions or r.business_source_versions[source["ref"]]!=source["revision"]:
                raise AuthorityUnavailable("Artifact historical frozen Source text is outside actual signed business B")
            actual=r.qualified.get(source["ref"])
            if actual is None or actual[0].revision!=source["revision"]:
                raise AuthorityUnavailable("Artifact historical frozen Body lacks independent current Source ALL")
        r.qualified_frozen_originals.add((kind,ref));self.complete=True

class _ArtifactBudgetMetadataV3:
    def __init__(self,reader):
        self.reader=reader;self.phase="quote";self.column=None;self.signature=None;self.version=None
        self.lease=reader.prepared.value["parent_budget_lease_ref"];self.complete=False;self.visited=set()
    def _canonical_v3(self,meter):
        import hashlib,json
        raw=self.column.require_v3(self.reader.work)
        ascii_codec=self.column.cell is None or self.column.cell.header[0]=="canonical-json.ascii.v1"
        encoded=json.dumps(raw,ensure_ascii=ascii_codec,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
        meter.charge_encode(len(encoded))
        if(len(encoded),hashlib.sha256(encoded).hexdigest())!=(self.column.byte_count,self.column.sha256):
            raise AuthorityUnavailable("Artifact budget metadata contains unknown Body outside its closed fields")
        return raw
    def advance_v3(self,meter):
        r=self.reader;r.require_current_v3(meter);w=r.work;p=r.prepared.value
        from ..runtime.issuers import ResourceQuote,BudgetLeaseGrant,_decode_quote,_decode_grant
        if self.phase=="quote":
            if self.column is None:
                row=meter.read_fixed_row(w.db,"runtime_resource_quotes",("signature",),"quote_id=? AND version=?",(p["quote_id"],1))
                if row is None:raise AuthorityUnavailable("Artifact actual signed original model quote absent")
                self.signature=row[0]
                self.column=_MetadataColumnV3(r,"quote",table="runtime_resource_quotes",column="quote_json",
                    key_columns=("quote_id","version"),key=(p["quote_id"],1));return
            if not self.column.advance(meter):return
            raw=self._canonical_v3(meter)
            if set(raw)!={f.name for f in fields(ResourceQuote)}:raise AuthorityUnavailable("Artifact actual quote closed metadata fields differ")
            continuation=raw["job_continuation"]
            if continuation is not None and(set(continuation)!={"schema","selector","prepared_digest"}
                    or continuation["schema"]!=("d11.artifact-draft-phase-model-job.v2"if r.phase_variant else"d11.artifact-draft-model-job.v1")
                    or continuation["selector"]!=r.prepared.value["selector"]or continuation["prepared_digest"]!=r.prepared.header[1]):
                raise AuthorityUnavailable("Artifact original model quote has another actual job continuation")
            text=canonical_serialize(raw)
            r.installed.issuer.resource_issuer._signer.verify("resource-quote.v1",text,self.signature)
            quote=_decode_quote(text)
            if((quote.bot_id,quote.persona_id)!=w.namespace.as_tuple or quote.quote_id!=p["quote_id"]or quote.version!=1
                    or quote.work_kind!="artifact_draft_v1"or quote.parent_budget_lease_ref!=p["parent_budget_lease_ref"]
                    or canonical_digest(quote)!=p["quote_digest"]or tuple(sorted(quote.ceiling.items()))!=w.request.budget_ceiling):
                raise AuthorityUnavailable("Artifact actual signed quote differs from current intent/prepared/Root")
            r.quote=quote;r.expires_at=min(r.expires_at,quote.valid_until_utc,quote.deadline_utc)
            self.column=None;self.phase="grant";return
        if self.column is None:
            if self.lease in self.visited:raise AuthorityUnavailable("Artifact actual budget parent lineage is cyclic")
            row=meter.read_fixed_row(w.db,"runtime_budget_grants",("version","signature","status"),
                "lease_id=? ORDER BY version DESC",(self.lease,))
            lease=meter.read_fixed_row(w.db,"runtime_budget_leases",("bot_id","persona_id","parent_id","state"),"lease_id=?",(self.lease,))
            if row is None or row[2]!="active"or lease is None or lease[:2]!=w.namespace.as_tuple or lease[3]!="active":
                raise AuthorityUnavailable("Artifact current signed grant or actual Root ancestor lease is inactive")
            self.version,self.signature=row[:2];self.lease_header=lease
            self.column=_MetadataColumnV3(r,"grant",table="runtime_budget_grants",column="grant_json",
                key_columns=("lease_id","version"),key=(self.lease,self.version));return
        if not self.column.advance(meter):return
        raw=self._canonical_v3()
        if set(raw)!={f.name for f in fields(BudgetLeaseGrant)}:raise AuthorityUnavailable("Artifact actual grant metadata fields differ")
        text=canonical_serialize(raw);r.installed.issuer._signer.verify("budget-grant.v1",text,self.signature)
        grant=_decode_grant(text)
        if((grant.bot_id,grant.persona_id)!=w.namespace.as_tuple or(grant.lease_id,grant.version)!=(self.lease,self.version)
                or "artifact_draft_v1"not in grant.allowed_work_kinds):
            raise AuthorityUnavailable("Artifact actual signed Root ancestor grant changed namespace/work kind")
        r.grants[self.lease]=(grant,self.version,self.signature);r.parent_refs.add(self.lease)
        r.expires_at=min(r.expires_at,grant.valid_until_utc)
        self.visited.add(self.lease);self.column=None
        if self.lease_header[2]is None:self.complete=True;return
        self.lease=self.lease_header[2]

def read_bound_artifact_model_budget_grant_v3(db,issuer,lease_id,*,version=None):
    from .artifact_model_original_family_v3 import _reader_v3
    r=_reader_v3(db)
    if r is None:return False,None
    r.capability.require_v3()
    if issuer is not r.installed.issuer or lease_id not in r.grants:
        raise AuthorityUnavailable("Artifact budget request escaped actual signed Root ancestor family")
    grant,actual_version,signature=r.grants[lease_id]
    if version is not None and version!=actual_version:raise AuthorityUnavailable("Artifact current model cannot borrow historical grant version")
    return True,(grant,signature)

def read_bound_artifact_model_quote_v3(db,issuer,quote_id,version):
    from .artifact_model_original_family_v3 import _reader_v3
    r=_reader_v3(db)
    if r is None:return False,None
    r.capability.require_v3()
    if issuer is not r.installed.issuer.resource_issuer or(quote_id,version)!=(r.prepared.value["quote_id"],1):
        return False,None
    return True,r.quote

class _ArtifactJointMetadataV3:
    """Fixed signed-R LongPlan/Window metadata and their actual positive producer."""
    def __init__(self,r):
        self.reader=r;self.complete=False;self.cursor=0;self.column=None;self.producer=None;self.receipt=None
        versions=(*r.business_versions,*(v for c in (getattr(r,"prepare_control",None),r.control)if c is not None for v in c.control_read_versions))
        selected={}
        for version in versions:
            if version.key.type_name not in {"d08.long_term_plan.v1","d08.joint_window.v1"}:continue
            prior=selected.get(version.key.token)
            if prior is not None and prior!=version.revision:raise AuthorityUnavailable("Artifact Joint metadata R revision conflicts")
            selected[version.key.token]=version.revision
        self.selected=selected;self.items=None;self.groups=set();self.values={}
        from ..runtime.ingress_artifact_task_scope_v1 import task_scope_ref_v1
        task=r.selector.task if r.phase_variant else r.selector
        self.scope=_SignedMetadataV3(r,"artifact_task_scope",task_scope_ref_v1(task.root_registration_ref),"task_scope_joint")
        self.rows=None
    def advance_v3(self,meter):
        r=self.reader;w=r.work;r.require_current_v3(meter)
        if self.rows is None:
            self.scope.advance_v3(meter)
            if not self.scope.complete:return
            from ..runtime.joint_window_management_v1 import managed_window_selector_digest_v1
            selector=managed_window_selector_digest_v1(w.namespace,"draft_file",self.scope.ref,self.scope.header[1])
            columns=metadata_columns_v1(JOINT_TABLE)
            self.rows=tuple(dict(zip(columns,row))for row in r.managed[JOINT_TABLE]if dict(zip(columns,row))["selector_digest"]==selector)
            if len(self.rows)>1 or any(row["retired"]for row in self.rows):
                raise AuthorityUnavailable("Artifact actual Joint selector is ambiguous or opaquely retired")
            wanted={ref for row in self.rows for ref in (row["window_ref"],row["plan_ref"])}
            if not wanted<=set(self.selected):raise AuthorityUnavailable("Artifact current Joint metadata is outside actual signed R")
            self.items=tuple(sorted((ref,self.selected[ref])for ref in wanted))
            r.original_operations.add(self.scope.header[0])
            for row in self.rows:r.original_operations.add(row["registration_operation_id"])
            return
        if self.cursor==len(self.items):
            from ..runtime.artifact_joint_source_groups_v3 import artifact_joint_source_groups_from_metadata_v3
            r.joint_source_groups=artifact_joint_source_groups_from_metadata_v3(namespace=w.namespace,matched_rows=self.rows,
                metadata={ref:(data[0],data[1])for ref,data in self.values.items()})
            self.complete=True;return
        token,revision=self.items[self.cursor]
        if self.column is None:
            head=w.heads.get(token)
            if head is None or head[:2]!=(revision,1):raise AuthorityUnavailable("Artifact actual R Joint metadata is not current and valid")
            self.history=meter.read_fixed_row(w.db,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",(token,revision))
            if self.history is None or self.history[:2]!=w.namespace.as_tuple or self.history[3]!=1:
                raise AuthorityUnavailable("Artifact Joint metadata lacks exact actual positive history")
            self.column=_MetadataColumnV3(r,"joint_graph",table="graph_atoms",column="value",
                key_columns=("token","bot","persona"),key=(token,*w.namespace.as_tuple),cell_id=head[2]);return
        if not self.column.advance(meter):return
        if self.producer is None:
            operation=self.history[2]
            self.header=meter.read_fixed_row(w.db,"graph_domain_production_originals_v1",
                ("domain","operation_kind","original_digest","bundle_digest","receipt_digest"),"bot=? AND persona=? AND operation_id=?",
                (*w.namespace.as_tuple,operation))
            self.bundle=meter.read_fixed_row(w.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,operation))
            from ..runtime.domain_production_originals_v1 import _registered_domain_original_v1
            if(self.header is None or not _registered_domain_original_v1(*self.header[:2])or self.bundle is None
                    or self.bundle[0]!=self.header[3]or type(self.bundle[1])is not int or self.bundle[1]<1):
                raise AuthorityUnavailable("Artifact Joint metadata has no actual registered domain COMMIT producer")
            self.producer=_MetadataColumnV3(r,"joint_producer",table="graph_domain_production_originals_v1",
                column="original_payload_json",key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,operation));return
        if not self.producer.advance(meter):return
        operation=self.history[2]
        if self.receipt is None:
            self.receipt=_MetadataColumnV3(r,"receipt",table="graph_domain_production_originals_v1",column="receipt_json",
                key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,operation));return
        if not self.receipt.advance(meter):return
        from ..runtime.domain_production_originals_v1 import _receipt
        receipt=_receipt(self.receipt.require_v3(w))
        if(receipt.operation_id!=operation or receipt.operation_digest!=self.bundle[0]or receipt.commit_seq!=self.bundle[1]
                or receipt.status!="committed"or canonical_digest(receipt)!=self.header[4]
                or GraphVersion(AtomKey.from_token(token),revision)not in receipt.write_versions):
            raise AuthorityUnavailable("Artifact Joint metadata lacks exact actual positive receipt write member")
        raw=self.producer.require_v3(w);value=self.column.require_v3(w)
        writes=tuple(item for item in raw["writes"]if item["key"]==token)
        if(self.producer.sha256!=self.header[2]or raw["schema"]!=self.header[0]+".current-"+self.header[1]+".v1"or raw["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}
                or(raw["identity"]["operation_id"],raw["identity"]["phase"])!=(operation,self.header[1])
                or len(writes)!=1 or writes[0]["value"]!=value or not writes[0]["valid"]):
            raise AuthorityUnavailable("Artifact Joint projected metadata differs from actual whole EOF producer write")
        r.original_operations.add(operation);r.graph_versions.add((token,revision))
        self.values[token]=(revision,value,self.column.sha256,operation)
        if value["schema"]=="d08.joint-window.v1":r.expires_at=min(r.expires_at,value["original_deadline_utc"])
        self.cursor+=1;self.column=self.producer=self.receipt=None

def register_artifact_model_history_parent_v3(work,table,key,data):
    r=_READERS.get(work)
    if r is None or table!="graph_history":return
    r.capability.require_v3()
    ordinary=key[0]in r.body_graph_tokens and(key[0],key[1])in r.graph_versions
    metadata=(key[0],key[1])in r.metadata_history_versions and AtomKey.from_token(key[0]).type_name=="d10.habit_occurrence.v1"
    if(not(ordinary or metadata)or(data["event_bot"],data["event_persona"])!=work.namespace.as_tuple):
        raise AuthorityUnavailable("Artifact history producer escaped actual signed R history point")
    r.original_operations.add(data["event_id"])

class _ArtifactHabitSourceMetadataV3:
    """Actual Core policy and fixed R interpretation Source metadata before Body."""
    def __init__(self,r):
        self.reader=r;self.complete=r.control is None or r.control.habit_classification.kind=="ordinary"
        self.cursor=0;self.column=None;self.items=()
        if self.complete:return
        from .artifact_model_graph_v3 import _CORE
        state=_CORE.get(r.work)
        if state is None:raise AuthorityUnavailable("Artifact managed Source metadata precedes actual independent Core policy observation")
        definition=state[5].definition;selection=state[6].selector
        r.habit_context_roots.update(definition.source_refs)
        refs=[]
        if definition.cue_predicate.observation_provider=="d07.habit-cue.v1":refs.append(selection.cue_original_ref)
        if definition.stop_predicate.observation_provider=="d07.habit-stop.v1":
            refs.append(dict(definition.stop_predicate.parameters)["interpretation_ref"])
        self.items=tuple(dict.fromkeys(refs))
    def advance_v3(self,meter):
        if self.complete:return
        r=self.reader;w=r.work;r.require_current_v3(meter)
        if self.cursor==len(self.items):self.complete=True;return
        ref=self.items[self.cursor]
        if self.column is None:
            head=w.heads.get(ref)
            versions=(*r.business_versions,*(v for c in(r.prepare_control,r.control)for v in c.control_read_versions))
            if head is None or not head[1]or not any(v.key.token==ref and v.revision==head[0]for v in versions):
                raise AuthorityUnavailable("Artifact actual Habit interpretation metadata is outside signed current R")
            self.column=_MetadataColumnV3(r,"habit_interpretation",table="graph_atoms",column="value",
                key_columns=("token","bot","persona"),key=(ref,*w.namespace.as_tuple),cell_id=head[2]);return
        if not self.column.advance(meter):return
        raw=self.column.require_v3(w)
        r.habit_context_roots.update(raw["source_refs"])
        self.cursor+=1;self.column=None
