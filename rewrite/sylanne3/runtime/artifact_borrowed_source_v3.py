"""Artifact Source for its actual Borrowed Foreground WRITE and fixed recipe."""
from __future__ import annotations
from dataclasses import dataclass,InitVar
from weakref import WeakKeyDictionary
import time
import json
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import canonical_digest
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3

ARTIFACT_BORROWED_OPERATIONS_V3=frozenset({
    "prepare_artifact_draft_model","acquire_artifact_draft_model",
    "prepare_artifact_draft_model_v2","acquire_artifact_draft_model_v2",
    "propose_artifact_draft_phase_action_v2","prepare_artifact_draft_body",
    "input:register_artifact_phase_draft_plan_v2","prepare_life"})
_MODEL_V2=frozenset({"prepare_artifact_draft_model_v2","acquire_artifact_draft_model_v2"})
_KEY=object()
_STATES=WeakKeyDictionary()
_CAPABILITIES=WeakKeyDictionary()
_SIGNATURE_COLUMNS=WeakKeyDictionary()
_FRAME_READS=WeakKeyDictionary()
_FRAME_FACTS={}

def _ctor_identity_v3(reader):
    return(reader.graph,reader.runtime,reader.operation,reader.issued,reader.issued.scope,reader.selector,
        reader.operation_kind,reader.request,reader.request_digest,reader.namespace,reader.graph_stamp,
        reader.expected_rights,reader.evidence,reader.deadline_utc,reader.initial_now_utc)

def register_artifact_borrowed_constructor_v3(reader):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
    from .domain_production_registry_v1 import installed_operation_v1
    if reader.operation_kind not in ARTIFACT_BORROWED_OPERATIONS_V3:return
    if reader.operation_kind=="prepare_life"and type(reader.issued)is not _IssuedForegroundActivityV1:
        from .owner_source_note_task_issuance_v1 import _IssuedOwnerSourceNoteTaskV1
        if type(reader.issued)is not _IssuedOwnerSourceNoteTaskV1:
            raise AuthorityUnavailable("Shared Life constructor has no actual installed issuance family")
        return
    if(type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or type(reader.issued)is not _IssuedForegroundActivityV1
            or type(reader.request)is not installed_operation_v1(reader.operation_kind).request_type
            or reader.issued.scope.operation!="write"or reader.issued.scope.namespace!=reader.namespace
            or reader.work is not None or reader.operation.closed or reader.authority is not None):
        raise AuthorityUnavailable("Artifact private Source constructor needs its exact actual Borrowed Foreground issuance")
    if reader in _STATES:raise AuthorityUnavailable("Artifact Source constructor may register its original monotonic window once")
    _STATES[reader]=_ArtifactBorrowedStateV3(_KEY,reader)
    if reader.operation_kind!="prepare_life":reader.projection_types=frozenset()

class _ArtifactBorrowedStateV3:
    def __init__(self,key,reader):
        if key is not _KEY:raise AuthorityUnavailable("actual Artifact private Borrowed factory required")
        self.reader=reader;self.identity=_ctor_identity_v3(reader);self.work=None
        self.initial_monotonic_time=time.monotonic()
        self.initial_monotonic_deadline=self.initial_monotonic_time+max(0.0,reader.deadline_utc-reader.initial_now_utc)
        self.current_monotonic_deadline=self.initial_monotonic_deadline
        self.active=None if reader.operation_kind=="prepare_life"else True
        self.phase="classify"if self.active is None else"owner"
        self.headers={};self.metadata={};self.tasks={};self.pending=None
        self.owner_entry=None;self.metadata_eof=None;self.preplan=None;self.plan=None
        self.groups=();self.pending_sources=[];self.checked=set();self.qualified={};self.support={}
        self.capability=None;self.carrier=None;self.classification=None
        self.control_body=();self.control_originals=();self.control_reads=();self.control_queries=()
        self.control_metadata={};self.source_versions={};self.business_source_refs=set();self.joint_rows=()
        self.signed_pairs=set();self.signed_operations=set();self.d07_pairs=set();self.joint_pairs=set();self.joint_kinds={}
        self.current=None;self.qualification=None;self.restriction_selector=None
    def require_v3(self):
        from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS,_require_borrowed_issuance_v3
        r=self.reader
        if(type(r)is not BorrowedMethodLearningReadV3 or r not in _READERS or _STATES.get(r)is not self
                or self.identity!=_ctor_identity_v3(r)or r.work is None or r.work.kind!="current_method_learning_read_v3"
                or r.work.state is not r or r.work.operation is not r.operation or r.work.coordinator is not r.graph
                or r.operation.closed or _require_borrowed_issuance_v3(r.issued,r.graph)!=r.evidence
                or time.monotonic()>=min(self.initial_monotonic_deadline,self.current_monotonic_deadline)):
            raise AuthorityUnavailable("Artifact Source lost its actual original Borrowed Work/WRITE/deadline")
        if self.work is None:self.work=r.work
        elif self.work is not r.work:raise AuthorityUnavailable("Artifact Source cannot move between Work instances")
        return self

def require_artifact_borrowed_owner_reader_v3(reader):
    state=_STATES.get(reader)
    if state is None or state.active is not True:
        raise AuthorityUnavailable("Artifact Owner17 has no exact actual private Source factory")
    return state.require_v3()

def is_artifact_borrowed_source_reader_v3(reader):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False
    state.require_v3();return True

def record_artifact_borrowed_header_v3(reader):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return
    state.require_v3()
    if reader.pending is not None:
        key,revision,valid,type_name,cell=reader.pending
        if key.type_name!=type_name:raise AuthorityUnavailable("Artifact header type differs from its actual canonical key")
        state.headers[key.token]=(revision,bool(valid),cell)

class _ArtifactBorrowedMetadataStreamV3:
    def __init__(self,capture,*,ensure_ascii,wire_metadata=None):
        self.column=capture.column
        self.inner=ConditionedMetadataJSONStreamV3(capture,ensure_ascii=ensure_ascii,wire_metadata=wire_metadata)
    def feed(self,chunk,emit):
        if self.column.signature_state is not None:self.column.signature_state.update(chunk)
        if self.column.request_payload_hash is not None:self.column.request_payload_hash.update(chunk)
        return self.inner.feed(chunk,emit)
    def finish(self):return self.inner.finish()

class _ArtifactBorrowedColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,*,table,column,key_columns,key,retain,cell_id=None,wire_metadata=None):
        self.state=state
        super().__init__(state.reader,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        self.capture=ConditionedLocatorJSONV3(self);self.capture.retain_path_v3=retain
        self.request_payload_hash=None
        self.frozen_profile=(table=="graph_d11_life_originals_v1"and key_columns==("bot","persona","kind","original_ref")and key[2]in{"c4_frozen","c4_phase_frozen"})
        self.source_fields={};self.record_fields={};self.object_fields={};self.frozen_fields_checked=False
        self.signature_state=None;self.signature_signer=None;self.signature_kind=None;self.signature=None;self.signature_verified=False
        self.capture.column=self
        self.parser=_ArtifactBorrowedMetadataStreamV3(self.capture,
            ensure_ascii=self.cell is None or self.cell.header[0]=="canonical-json.ascii.v1",wire_metadata=wire_metadata)
    def _actual(self):self.state.require_v3();return self
    def sign_stream_v3(self,signer,kind,signature):
        from .artifact_joint_recipe_metadata_v3 import _JOINT_REGISTERED_PROFILES_V3
        joint_profiles={(profile[0],"payload_json",("bot","persona","original_ref"),profile[2])for profile in _JOINT_REGISTERED_PROFILES_V3.values()}
        if (self.table,self.column,self.key_columns,kind)not in joint_profiles|{
                ("graph_d05_production_policies_v1","payload_json",("bot","persona","policy_ref","revision"),"d11.d05-production-policy.v1"),
                ("graph_d05_production_policies_v1","payload_json",("bot","persona","policy_ref","revision"),"d11.d05-production-policy.v2")}:
            raise AuthorityUnavailable("Artifact metadata signature is not a fixed installed policy profile")
        self.signature_signer,self.signature_kind,self.signature=signer,kind,signature
        _SIGNATURE_COLUMNS[self]=(self.state,self.owner,self.table,self.column,self.key_columns,self.key,signer,kind,signature)
        self.signature_state=signer.begin_original_stream_verification_v3(kind,self)
    def advance(self,meter):
        complete=super().advance(meter)
        if complete and self.frozen_profile and not self.frozen_fields_checked:
            from .artifact_frozen_metadata_v3 import validate_artifact_frozen_metadata_fields_v3
            validate_artifact_frozen_metadata_fields_v3(self.value,top_fields=self.capture.fields_seen,
                source_fields=self.source_fields,record_fields=self.record_fields,object_fields=self.object_fields)
            self.frozen_fields_checked=True
        if complete and self.signature_state is not None and not self.signature_verified:
            self.signature_signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
            self.signature_verified=True
        return complete
    def _emit(self,event):
        if self.frozen_profile and event.kind=="key":
            self.object_fields.setdefault(event.path[:-1],set()).add(event.key)
            if event.path[0]=="sources":
                if len(event.path)==3:self.source_fields.setdefault(event.path[1],set()).add(event.key)
                elif len(event.path)==4 and event.path[2]=="record":self.record_fields.setdefault(event.path[1],set()).add(event.key)
        self.capture._emit_v3(event);self.value=self.capture.value

class _ArtifactBorrowedSignedMetadataV3:
    def __init__(self,state,kind,ref,retain):
        self.state,self.kind,self.ref,self.retain=state,kind,ref,retain
        self.header=self.column=self.value=None;self.complete=False
    def advance_v3(self,meter):
        from .d11_life_preparation_v1 import TABLE,SIGN_KIND
        from ..runtime_contracts import canonical_serialize
        s=self.state;r=s.require_v3().reader;r.require_current(meter=meter)
        if self.column is None:
            self.header=meter.read_fixed_row(r.db,TABLE,("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,self.kind,self.ref))
            if self.header is None:self.complete=True;return
            self.column=_ArtifactBorrowedColumnV3(s,table=TABLE,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*r.namespace.as_tuple,self.kind,self.ref),retain=self.retain)
            return
        if not self.column.advance(meter):return
        if self.column.sha256!=self.header[1]:raise AuthorityUnavailable("Artifact Borrowed signed metadata lacks complete canonical EOF")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,self.kind,self.ref,self.header[1])),self.header[2])
        self.value=self.column.require_v3(r);self.complete=True

def advance_artifact_borrowed_classification_v3(reader,meter):
    state=_STATES.get(reader)
    if state is None or state.active is not None:return False
    state.require_v3()
    key=("life_classification",reader.request.plan_original_ref)
    task=state.tasks.get(key)
    if task is None:
        task=_ArtifactBorrowedSignedMetadataV3(state,"plan",reader.request.plan_original_ref,
            lambda path:not path or path[0]=="schema");state.tasks[key]=task
    task.advance_v3(meter)
    if not task.complete:return True
    if task.value is None:raise AuthorityUnavailable("Artifact/SourceNote Life classification lacks its actual signed plan")
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from dataclasses import fields
    schema=next(field.default for field in fields(RegisteredDraftFilePlanV3)if field.name=="schema")
    state.active=task.value["schema"]==schema
    if state.active:reader.projection_types=frozenset();state.phase="owner"
    return False

class ArtifactBorrowedSourceCapabilityV3:
    def __init__(self,key,state):
        if key is not _KEY or state.phase!="qualified"or state.preplan is None:
            raise AuthorityUnavailable("Artifact Body requires its actual fixed metadata plan and independent ALL")
        self.state=state;self.identity=self._identity_v3();_CAPABILITIES[self]=self.identity
    def _identity_v3(self):
        s=self.state;r=s.reader
        return(s,s.identity,s.work,s.metadata_eof,s.preplan,s.groups,frozenset(s.checked),r.owner_binding,
            tuple(sorted(s.support.items(),key=lambda row:row[0].token)),tuple(sorted(s.control_metadata.items(),key=lambda row:row[0].token)),frozenset(s.control_body_keys))
    def require_v3(self):
        s=self.state;s.require_v3()
        if s.capability is not self or _CAPABILITIES.get(self)!=self._identity_v3():
            raise AuthorityUnavailable("Artifact Body capability changed its original metadata/Owner/Source recipe")
        with s.reader.store._lock:
            s.reader.require_current();s.owner_entry.require_for_v3(s.reader)
        for witness,_ in s.qualified.values():_require_source_witness_v3(s,witness)
        return self

def release_artifact_borrowed_source_v3(reader):
    state=_STATES.pop(reader,None)
    if state is None:return
    _CAPABILITIES.pop(state.capability,None)
    if type(state.carrier)is _ArtifactBorrowedWriteFrameReadsV3:_FRAME_READS.pop(state.carrier,None)
    for column in tuple(_SIGNATURE_COLUMNS):
        if column.state is state:_SIGNATURE_COLUMNS.pop(column,None)
    for identity,record in tuple(_FRAME_FACTS.items()):
        if record[2]is state:_FRAME_FACTS.pop(identity,None)
    if state.owner_entry is not None:state.owner_entry.release_v3()
    state.headers.clear();state.metadata.clear();state.tasks.clear();state.qualified.clear()
    state.pending=state.owner_entry=state.capability=None

class _ArtifactBorrowedLocatorTaskV3:
    def __init__(self,state,locator):
        from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
        if type(locator)is not ArtifactMetadataLocatorV3:raise TypeError("actual fixed Artifact metadata locator required")
        self.state,self.locator=state,locator;self.column=None;self.header=None;self.complete=False;self.value=None
        self.phase="header";self.payload=self.receipt=self.reads=None;self.actual_locator=None
    def _column_v3(self,table,column,key_columns,key,*,cell_id=None,actual_domain_kind=None):
        from .artifact_recipe_metadata_v3 import artifact_recipe_metadata_retain_path_v3
        locator=self.actual_locator or self.locator
        retain=lambda path:_host_artifact_metadata_path_v3(locator,path,actual_domain_kind=actual_domain_kind)
        retain(())
        return _ArtifactBorrowedColumnV3(self.state,table=table,column=column,key_columns=key_columns,key=key,
            retain=retain,cell_id=cell_id)
    def advance_v3(self,meter):
        from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
        from ..runtime_contracts import NamespaceId,canonical_serialize
        state=self.state;r=state.require_v3().reader;r.require_current(meter=meter);loc=self.locator;ns=r.namespace
        if self.complete:return
        if loc.family=="inventory":
            if loc.ref!=loc.kind:raise AuthorityUnavailable("Artifact fixed inventory metadata selector differs")
            if self.header is None:
                self.header=tuple(ref for ref in sorted(state.headers)if AtomKey.from_token(ref).type_name==loc.kind)
                self.inventory_rows=[];self.inventory_cursor=0;self.child=None
            if self.child is not None:
                self.child.advance_v3(meter)
                if not self.child.complete:return
                self.inventory_rows.append(self.child.value);self.child=None;self.inventory_cursor+=1;return
            if self.inventory_cursor==len(self.header):
                self.value=tuple(self.inventory_rows);self.complete=True;return
            ref=self.header[self.inventory_cursor]
            self.child=_ArtifactBorrowedLocatorTaskV3(state,ArtifactMetadataLocatorV3("graph",loc.kind,ref));return
        if loc.family in{"joint_registered","joint_registered_index"}:
            _advance_joint_artifact_metadata_v3(self,meter);return
        if loc.family in{"history_index","life_index"}:
            _advance_artifact_metadata_index_v3(self,meter);return
        if loc.family=="d04_before":
            _advance_artifact_d04_before_metadata_v3(self,meter);return
        if loc.family=="installation":
            self.value=_installed_personal_metadata_v3(state,loc);self.complete=True;return
        if loc.family in{"d07_execution","relationship_policy","policy_index","artifact_milestone","owner_task","source_note_authorization"}:
            _advance_fixed_family_metadata_v3(self,meter);return
        if loc.family=="graph":
            key=AtomKey.from_token(loc.ref)
            if NamespaceId.from_key(key)!=ns or key.type_name!=loc.kind:raise AuthorityUnavailable("Artifact metadata point crossed actual namespace/type")
            header=state.headers.get(loc.ref)
            if header is None:self.complete=True;return
            if key.type_name=="memory.source":
                witness=r.sources.get(loc.ref)
                self.value=(GraphVersion(key,header[0]),header[1],{}if witness is None else dict(witness.metadata))
                self.complete=True;return
            if self.column is None:
                self.header=header;self.column=self._column_v3("graph_atoms","value",("token","bot","persona"),(loc.ref,*ns.as_tuple),cell_id=header[2]);return
            if not self.column.advance(meter):return
            if state.headers.get(loc.ref)!=self.header:raise AuthorityUnavailable("Artifact metadata head changed during whole EOF")
            self.value=(GraphVersion(key,self.header[0]),self.header[1],self.column.require_v3(r));self.complete=True;return
        if loc.family=="history":
            key=AtomKey.from_token(loc.ref)
            if NamespaceId.from_key(key)!=ns or type(loc.revision)is not int or loc.revision<1:
                raise AuthorityUnavailable("Artifact historical metadata needs its actual positive namespace revision")
            if self.header is None:
                self.header=meter.read_fixed_row(r.db,"graph_history",("event_bot","event_persona","event_id","valid"),
                    "token=? AND revision=?",(loc.ref,loc.revision))
                if self.header is None:self.complete=True;return
                if self.header[:2]!=ns.as_tuple:raise AuthorityUnavailable("Artifact historical producer metadata crossed namespace")
                if loc.kind=="event":
                    self.value={"event_id":self.header[2],"valid":bool(self.header[3])};self.complete=True;return
                self.column=self._column_v3("graph_history","value",("token","revision"),(loc.ref,loc.revision));return
            if not self.column.advance(meter):return
            self.value={"event_id":self.header[2],"valid":bool(self.header[3]),"value":self.column.require_v3(r)}
            self.complete=True;return
        if loc.family in{"life","life_header"}:
            from .d11_life_preparation_v1 import TABLE,SIGN_KIND
            if self.header is None:
                self.header=meter.read_fixed_row(r.db,TABLE,("producing_operation_id","payload_digest","signature"),
                    "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,loc.kind,loc.ref))
                if self.header is None:self.complete=True;return
                self.actual_locator=ArtifactMetadataLocatorV3("life",loc.kind,loc.ref)
                self.column=self._column_v3(TABLE,"payload_json",("bot","persona","kind","original_ref"),(*ns.as_tuple,loc.kind,loc.ref));return
            if not self.column.advance(meter):return
            if self.column.sha256!=self.header[1]:raise AuthorityUnavailable("Artifact signed Original metadata lacks its actual whole canonical EOF")
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((ns,loc.kind,loc.ref,self.header[1])),self.header[2])
            bundle=meter.read_fixed_row(r.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,self.header[0]))
            if bundle is None or type(bundle[1])is not int or bundle[1]<1:
                raise AuthorityUnavailable("Artifact signed Original metadata lacks its actual positive W01 producer")
            state.signed_pairs.add((loc.kind,loc.ref));state.signed_operations.add(self.header[0])
            self.value=(self.column.require_v3(r)if loc.family=="life"else
                {"operation_id":self.header[0],"payload_digest":self.header[1],"signature":self.header[2]})
            self.complete=True;return
        if loc.family=="domain":
            from .domain_production_originals_v1 import _registered_domain_original_v1,_receipt
            if self.header is None:
                if loc.kind=="original_ref":
                    rows=r.db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
                        "AND domain||'-current:'||substr(original_digest,1,48)=? LIMIT 2",(*ns.as_tuple,loc.ref)).fetchall()
                    meter.charge_read(sum(len(row[0].encode())for row in rows)+32)
                    if not rows:self.complete=True;return
                    if len(rows)!=1:raise AuthorityUnavailable("Artifact metadata Original reference has multiple actual producers")
                    self.operation_id=rows[0][0]
                elif loc.kind=="operation":self.operation_id=loc.ref
                else:raise AuthorityUnavailable("Artifact Domain metadata has an unknown actual locator variant")
                self.header=meter.read_fixed_row(r.db,"graph_domain_production_originals_v1",
                    ("domain","operation_kind","original_digest","receipt_digest","bundle_digest"),
                    "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,self.operation_id))
                if self.header is None:self.complete=True;return
                if not _registered_domain_original_v1(*self.header[:2]):raise AuthorityUnavailable("Artifact metadata producer has no actual installed operation")
                self.bundle=meter.read_fixed_row(r.db,"graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
                    "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,self.operation_id))
                if self.bundle is None or self.bundle[0]!=self.header[4]or type(self.bundle[3])is not int or self.bundle[3]<1:
                    raise AuthorityUnavailable("Artifact metadata producer lacks its actual W01 COMMIT")
                self.column=self._column_v3("graph_domain_production_originals_v1","original_payload_json",
                    ("bot","persona","operation_id"),(*ns.as_tuple,self.operation_id),actual_domain_kind=self.header[:2])
                self.phase="payload";return
            if self.phase=="payload":
                if not self.column.advance(meter):return
                if self.column.sha256!=self.header[2]:raise AuthorityUnavailable("Artifact Domain metadata differs from its actual whole Original EOF")
                self.payload=self.column.require_v3(r)
                if(self.payload["namespace"]!={"bot_id":ns.bot_id,"persona_id":ns.persona_id}
                        or(self.payload["identity"]["operation_id"],self.payload["identity"]["phase"])!=(self.operation_id,self.header[1])):
                    raise AuthorityUnavailable("Artifact Domain metadata changed actual namespace/identity/phase")
                self.column=_ArtifactBorrowedColumnV3(state,table="graph_domain_production_originals_v1",column="read_versions_json",
                    key_columns=("bot","persona","operation_id"),key=(*ns.as_tuple,self.operation_id),
                    retain=lambda path:len(path)<=2 and(all(type(x)is int for x in path))and(len(path)<2 or path[1]<2))
                self.phase="reads";return
            if self.phase=="reads":
                if not self.column.advance(meter):return
                self.reads=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in self.column.require_v3(r))
                if any(NamespaceId.from_key(version.key)!=ns for version in self.reads):
                    raise AuthorityUnavailable("Artifact Domain metadata readset crossed namespace")
                self.column=_ArtifactBorrowedColumnV3(state,table="graph_domain_production_originals_v1",column="receipt_json",
                    key_columns=("bot","persona","operation_id"),key=(*ns.as_tuple,self.operation_id),retain=_receipt_metadata_path_v3)
                self.phase="receipt";return
            if not self.column.advance(meter):return
            receipt=_receipt(self.column.require_v3(r))
            if(receipt.status!="committed"or receipt.operation_id!=self.operation_id
                    or(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)!=self.bundle
                    or canonical_digest(receipt)!=self.header[3]):
                raise AuthorityUnavailable("Artifact Domain metadata lost its exact actual positive receipt tuple")
            self.value={"domain":self.header[0],"operation_kind":self.header[1],"original_digest":self.header[2],
                "payload":self.payload,"read_versions":self.reads,"receipt":receipt}
            self.complete=True;return
        if loc.family=="job":
            if self.header is None:
                self.header=meter.read_fixed_row(r.db,"runtime_jobs",("bot_id","persona_id","activity_id","operation_id"),
                    "job_id=?",(loc.ref,))
                if self.header is None:self.complete=True;return
                if self.header[:2]!=ns.as_tuple:raise AuthorityUnavailable("Artifact metadata job crossed namespace")
                self.column=self._column_v3("runtime_jobs","continuation_json",("job_id",),(loc.ref,));return
            if not self.column.advance(meter):return
            self.value={"activity_id":self.header[2],"operation_id":self.header[3],"continuation":self.column.require_v3(r)}
            self.complete=True;return
        raise AuthorityUnavailable("Artifact Source metadata task requires its actual fixed installed family")

def _receipt_metadata_path_v3(path):
    if not path:return True
    if path[0]in{"operation_id","operation_digest","activity_id","effect_id","status","commit_seq"}:return len(path)==1
    if path[0]in{"read_versions","write_versions"}:
        return len(path)<=3 and all(type(item)is int for item in path[1:])and(len(path)<3 or path[2]<2)
    if path[0]in{"ledger_refs","outbox_refs"}:return len(path)==1 or len(path)==2 and type(path[1])is int
    if path[0]=="invalidated_epochs":
        return len(path)==1 or len(path)==2 and type(path[1])is int or len(path)==3 and type(path[1])is int and path[2]in{"bot","persona","revision"}
    return False

def _require_source_witness_v3(state,witness,meter=None):
    from .dispatch_current_inventory_v3 import VerifiedDispatchSourceMetadataV3,_SOURCE_ISSUED
    r=state.require_v3().reader
    actual=(r.db,witness.source_key,witness.revision,witness.valid,witness.cell_id,witness.header,
        witness.payload_sha256,witness.metadata,witness.scope,witness.graph_stamp,witness.query,
        witness.operation_id,witness.selection_digest)
    if(type(witness)is not VerifiedDispatchSourceMetadataV3 or _SOURCE_ISSUED.get(witness)!=actual
            or r.sources.get(witness.source_key.token)is not witness or witness.scope is not r.fence.scope
            or witness.operation_id!=r.operation.operation_id or witness.selection_digest!=r.selection_digest
            or witness.graph_stamp!=r.graph_stamp or witness.query!=r.query or not witness.valid
            or state.headers.get(witness.source_key.token)!=(witness.revision,witness.valid,witness.cell_id)):
        raise AuthorityUnavailable("Artifact Source lost the actual same-Work canonical full-EOF witness")
    if meter is not None:
        head=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),
            "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,witness.source_key.token))
        if head!=(witness.revision,int(witness.valid),witness.cell_id):
            raise AuthorityUnavailable("Artifact Source actual current head changed")
    return witness

def _installed_personal_metadata_v3(state,loc):
    if(loc.kind,loc.ref)==("life_before_policy","current"):
        return state.reader.graph._GraphCoordinator__life_d04_before_capture_policy
    if(loc.kind,loc.ref)!=("personal_candidate","current"):
        raise AuthorityUnavailable("Artifact metadata has no such installed reader selector")
    runtime=state.reader.runtime
    personal=getattr(runtime,"_personal_candidate_readers_v1",None)
    if personal is None:return {"reader_present":False}
    current=personal.current()
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    if type(current)is not InstalledPersonalCandidateReadersV1:
        raise AuthorityUnavailable("Artifact recipe requires its actual installed PersonalCandidate reader")
    from .d02_artifact_phase_price_v1 import InstalledArtifactPhasePriceReaderV1
    from .personal_candidate_eligibility_v1 import InstalledCurrentSourceNotePriceReaderV1
    price=current.phase_price_reader
    if type(price)not in{InstalledArtifactPhasePriceReaderV1,InstalledCurrentSourceNotePriceReaderV1}:
        raise AuthorityUnavailable("Artifact installed price profile has no fixed metadata recipe")
    return {"reader_present":True,"standing_scope_kind":type(current.bundle.artifact_draft.standing_scope).__name__,
        "phase_price_kind":type(price).__name__}

def require_artifact_borrowed_signature_column_v3(column,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(column)is not _ArtifactBorrowedColumnV3:
        raise AuthorityUnavailable("Actual Artifact fixed metadata signature column required")
    state=column.state;state.require_v3()
    if(_SIGNATURE_COLUMNS.get(column)!=(state,column.owner,column.table,column.column,column.key_columns,column.key,signer,kind,column.signature)
            or signer is not state.reader.graph._GraphCoordinator__d11_issuer._signer
            or signature is not None and signature!=column.signature
            or verifier is not None and verifier is not column.signature_state or complete and not column.complete):
        raise AuthorityUnavailable("Artifact metadata signature changed its actual same-Work installed policy")
    return column

def _advance_fixed_family_metadata_v3(task,meter):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3,artifact_recipe_metadata_retain_path_v3
    from ..runtime_contracts import canonical_serialize
    state=task.state;r=state.reader;loc=task.locator;ns=r.namespace
    if loc.family=="policy_index":
        from .d02_artifact_phase_price_v1 import TABLE,POLICY_KIND
        if(loc.kind,loc.ref)!=("artifact_phase_price","active"):
            raise AuthorityUnavailable("Artifact policy index metadata has another fixed selector")
        if task.header is None:task.header="";task.rows=[]
        row=meter.read_fixed_row(r.db,TABLE,("policy_ref",),
            "bot=? AND persona=? AND kind=? AND policy_ref>? ORDER BY policy_ref",
            (*ns.as_tuple,POLICY_KIND,task.header))
        if row is None:task.value=tuple(task.rows);task.complete=True;return
        if len(task.rows)==1:raise AuthorityUnavailable("Artifact actual phase price policy is not unique")
        task.header=row[0];task.rows.append(row[0]);return
    if loc.family=="relationship_policy":
        table="graph_d05_production_policies_v1"
        if task.header is None:
            task.header=meter.read_fixed_row(r.db,table,("revision","payload_digest","signature"),
                "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC",(*ns.as_tuple,loc.ref))
            if task.header is None:task.complete=True;return
            task.column=_ArtifactBorrowedColumnV3(state,table=table,column="payload_json",
                key_columns=("bot","persona","policy_ref","revision"),key=(*ns.as_tuple,loc.ref,task.header[0]),
                retain=lambda path:artifact_recipe_metadata_retain_path_v3(loc,path)or path==("schema_version",))
            return
        if not task.column.advance(meter):return
        if task.column.sha256!=task.header[1]:
            raise AuthorityUnavailable("Artifact relationship metadata differs from whole installed-policy EOF")
        value=task.column.require_v3(r)
        if task.phase!="verify_policy":
            kind="d11.d05-production-policy.v2"if value.get("schema_version")==2 else"d11.d05-production-policy.v1"
            task.column=_ArtifactBorrowedColumnV3(state,table=table,column="payload_json",
                key_columns=("bot","persona","policy_ref","revision"),key=(*ns.as_tuple,loc.ref,task.header[0]),
                retain=lambda path:artifact_recipe_metadata_retain_path_v3(loc,path))
            task.column.sign_stream_v3(r.graph._GraphCoordinator__d11_issuer._signer,kind,task.header[2])
            task.phase="verify_policy";return
        latest=meter.read_fixed_row(r.db,table,("revision","payload_digest","signature"),
            "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC",(*ns.as_tuple,loc.ref))
        if latest!=task.header:raise AuthorityUnavailable("Artifact relationship metadata latest policy changed")
        task.value=value;task.complete=True;return
    if loc.family=="d07_execution":
        from .d07_execution_v1 import TABLE,SIGN_KIND
        if loc.kind!="prepared":raise AuthorityUnavailable("Artifact Need has no such D07 metadata profile")
        if task.header is None:
            task.header=meter.read_fixed_row(r.db,TABLE,("payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,"prepared",loc.ref))
            if task.header is None:task.complete=True;return
            task.column=task._column_v3(TABLE,"payload_json",("bot","persona","kind","original_ref"),(*ns.as_tuple,"prepared",loc.ref));return
        if not task.column.advance(meter):return
        if task.column.sha256!=task.header[0]:raise AuthorityUnavailable("Artifact Need D07 metadata whole EOF differs")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((ns,"prepared",loc.ref,task.header[0])),task.header[1])
        state.d07_pairs.add(("prepared",loc.ref))
        task.value=task.column.require_v3(r);task.complete=True;return
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    if loc.family=="artifact_milestone":
        from .artifact_task_observer_v1 import ARTIFACT_TASK_MILESTONE_KIND_V2
        kind=ARTIFACT_TASK_MILESTONE_KIND_V2
    elif loc.family=="owner_task":
        from .owner_source_note_task_v1 import AUTHORIZATION_KIND
        from .owner_source_note_task_contract_v1 import RESPONSIBILITY_KIND
        if loc.kind not in{"authorization","responsibility"}:raise AuthorityUnavailable("Artifact metadata has no such Owner-task profile")
        kind=AUTHORIZATION_KIND if loc.kind=="authorization"else RESPONSIBILITY_KIND
    elif loc.family=="source_note_authorization":
        if loc.kind!="by_need":raise AuthorityUnavailable("Artifact SourceNote price has another Need locator")
        if not hasattr(task,"need_task"):
            task.need_task=_ArtifactBorrowedLocatorTaskV3(state,ArtifactMetadataLocatorV3("domain","original_ref",loc.ref))
        child=task.need_task;child.advance_v3(meter)
        if not child.complete:return
        from .owner_source_note_need_v1 import OPERATION
        if child.value is None or(child.value["domain"],child.value["operation_kind"])!=("d07",OPERATION):
            raise AuthorityUnavailable("Artifact SourceNote price metadata lacks its actual positive Owner Need")
        ref=child.value["payload"]["request"]["authorization_original_ref"]
        from .owner_source_note_task_v1 import AUTHORIZATION_KIND
        kind=AUTHORIZATION_KIND
    else:raise AuthorityUnavailable("Artifact metadata family has no actual fixed producer")
    ref=ref if loc.family=="source_note_authorization"else loc.ref
    if task.header is None:
        task.header=meter.read_fixed_row(r.db,TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,kind,ref))
        if task.header is None:task.complete=True;return
        task.column=task._column_v3(TABLE,"payload_json",("bot","persona","kind","original_ref"),(*ns.as_tuple,kind,ref));return
    if task.phase!="producer":
        if not task.column.advance(meter):return
        if task.column.sha256!=task.header[1]:raise AuthorityUnavailable("Artifact fixed signed metadata whole EOF differs")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((ns,kind,ref,task.header[1])),task.header[2])
        task.payload=task.column.require_v3(r)
        task.child=_ArtifactBorrowedLocatorTaskV3(state,ArtifactMetadataLocatorV3("domain","operation",task.header[0]))
        task.phase="producer";return
    task.child.advance_v3(meter)
    if not task.child.complete:return
    if task.child.value is None:raise AuthorityUnavailable("Artifact fixed signed metadata lost actual positive W01 producer")
    state.signed_pairs.add((kind,ref));state.signed_operations.add(task.header[0])
    task.value=({"value":task.payload,"producer":task.child.value}
        if loc.family=="owner_task"and loc.kind=="responsibility"else task.payload)
    task.complete=True

def _advance_recipe_metadata_v3(state,meter):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorNeededV3
    r=state.require_v3().reader
    if state.pending is not None:
        task=state.pending;task.advance_v3(meter)
        if not task.complete:return False
        state.metadata[task.locator]=task.value;state.pending=None;return False
    try:
        plan=_compose_actual_artifact_metadata_plan_v3(state)
    except ArtifactMetadataLocatorNeededV3 as needed:
        task=state.tasks.get(needed.locator)
        if task is None:task=_ArtifactBorrowedLocatorTaskV3(state,needed.locator);state.tasks[needed.locator]=task
        state.pending=task;return False
    roots={version.key.token for version in r.evidence.read_versions if version.key.type_name=="memory.source"}
    actual_source_roots=set(plan.source_roots)|{key.token for key in plan.exact_keys if key.type_name=="memory.source"}
    if not actual_source_roots<=roots:
        raise AuthorityUnavailable("Artifact complete metadata recipe exceeds actual Foreground Source qualification")
    state.preplan=plan
    return True

def _host_artifact_metadata_path_v3(locator,path,*,actual_domain_kind=None):
    from .artifact_recipe_metadata_v3 import artifact_recipe_metadata_retain_path_v3,_wire_shape_v3,_shape_retains_v3
    if not path:return True
    if locator.family=="life"and locator.kind in{"prepared","adopted_life","activity_scope","artifact_task_objective"}:
        own=_host_write_metadata_path_v3(locator,path,actual_domain_kind=actual_domain_kind)
        if own is not None:return own
    from .artifact_joint_recipe_metadata_v3 import artifact_joint_business_metadata_path_v3
    joint=artifact_joint_business_metadata_path_v3(locator,path,actual_domain_kind=actual_domain_kind)
    if joint is not None:return joint
    if locator.family=="domain"and actual_domain_kind==("d08","adopt_joint_plan")and path[0]=="request":
        return _shape_retains_v3({"joint_plan_proposal_ref":"scalar","party_consent_original_refs":("array","scalar")},path[1:])
    extra=_host_write_metadata_path_v3(locator,path,actual_domain_kind=actual_domain_kind)
    if extra is not None:return extra
    if locator.family=="graph":
        if locator.kind=="memory.access":
            from ..memory_types import _ACCESS_FIELDS
            return path[0]in _ACCESS_FIELDS
        if locator.kind=="d10.habit_policy.v1":
            from ..domains.d10.habit_policy_v1 import GraphAdoptedHabitPolicyV1
            return _shape_retains_v3(_wire_shape_v3(GraphAdoptedHabitPolicyV1),path)
        if locator.kind in{"d08.long_term_plan.v1","d08.joint_window.v1"}:
            from .artifact_joint_source_groups_v3 import artifact_joint_metadata_path_v3
            return artifact_joint_metadata_path_v3(path)
    if locator.family=="job"and path[0]=="call_plan":
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
        return _shape_retains_v3({"phase_group":{"selector":_wire_shape_v3(ArtifactDraftPhaseSelectorV2)}},path[1:])
    if locator.family=="life"and locator.kind=="plan":
        from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
        return _shape_retains_v3(_wire_shape_v3(RegisteredDraftFilePlanV3),path)
    if locator.family=="domain"and actual_domain_kind is not None:
        domain,kind=actual_domain_kind
        if(domain,kind)==("d10","qualify_habit_occurrence_v1")and path[0]=="provenance":
            from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
            return _shape_retains_v3({"core_qualification":_wire_shape_v3(HabitOccurrenceQualificationOriginalV1)},path[1:])
        if path[0]=="writes":
            from .artifact_joint_source_groups_v3 import artifact_joint_metadata_path_v3
            if len(path)<3:return True
            if path[2]in{"key","expected_revision","valid"}:return len(path)==3
            return path[2]=="value"and artifact_joint_metadata_path_v3(path[3:])
    return artifact_recipe_metadata_retain_path_v3(locator,path,actual_domain_kind=actual_domain_kind)

def _needed_value_v3(state,family,kind,ref,revision=None):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3,ArtifactMetadataLocatorNeededV3
    loc=ArtifactMetadataLocatorV3(family,kind,ref,revision)
    if loc not in state.metadata:raise ArtifactMetadataLocatorNeededV3(loc)
    return state.metadata[loc]

def _metadata_graph_v3(state,ref):
    return _needed_value_v3(state,"graph",AtomKey.from_token(ref).type_name,ref)

def _metadata_domain_v3(state,operation):
    return _needed_value_v3(state,"domain","operation",operation)

def _derive_artifact_classification_v3(state):
    from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
    from .b3_managed_metadata_v1 import HABIT_TABLE,metadata_columns_v1
    from .artifact_recipe_metadata_v3 import ArtifactRecipeMetadataV3,_selected_phase_metadata_v3
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    r=state.reader;proof=require_borrowed_habit_metadata_eof_v3(r);proof.require_current_v3(r)
    state.metadata_eof=canonical_digest(("sylanne.artifact-borrowed-metadata-eof.v3",proof.commitment,r.root,r.count))
    selector=_actual_artifact_phase_selector_v3(state)
    state.artifact_phase_selector=selector
    if type(selector)is not ArtifactDraftPhaseSelectorV2:
        task=r.request.selector
        cycle=_needed_value_v3(state,"job","continuation",AtomKey.from_token(task.cycle_job_ref).name)
        from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
        scope=_needed_value_v3(state,"life","artifact_task_scope",task_scope_ref_v1(task.root_registration_ref))
        root=_needed_value_v3(state,"life","draft_root_capability",task.root_registration_ref)
        producer=_metadata_domain_v3(state,cycle["operation_id"])
        c02=_metadata_domain_v3(state,task.c02_operation_id)
        if(scope is None or root is None or producer is None or c02 is None
                or(producer["domain"],producer["operation_kind"])!=("d11","create_foreground_cycle_v2")
                or scope["c02_operation_id"]!=task.c02_operation_id or scope["namespace"]!={"bot_id":r.namespace.bot_id,"persona_id":r.namespace.persona_id}
                or root["registration_ref"]!=task.root_registration_ref):
            raise AuthorityUnavailable("Legacy Artifact ordinary classification lost its actual signed task/Root/cycle positive producer")
        rows=tuple(dict(zip(metadata_columns_v1(HABIT_TABLE),row))for row in proof.managed_rows_v3(HABIT_TABLE))
        if any(row["decision_ref"]in{key.token for key in state.preplan.exact_keys}for row in rows):
            raise AuthorityUnavailable("Legacy Artifact cannot borrow a current or retired managed phase Decision")
        state.ordinary_producer=(scope,root,producer,c02);state.classification_kind="ordinary";return True
    _,raw,chosen,_,preparation,selection=_selected_phase_metadata_v3(ArtifactRecipeMetadataV3(state.metadata),selector)
    from ..domains.d08.personal_candidate_v1 import PersonalCandidateFutureIdentityV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    future=decode_typed_production_value_v1(chosen["future_identity"],PersonalCandidateFutureIdentityV1)
    from .d10_habit_v1 import habit_draft_selector_commitment_v1
    commitment=habit_draft_selector_commitment_v1(r.namespace,decision_ref=selector.decision_ref,
        decision_digest=selector.decision_digest,phase_selector=selector,future_identity=future,
        issuer=r.graph._GraphCoordinator__d11_issuer)
    rows=tuple(dict(zip(metadata_columns_v1(HABIT_TABLE),row))for row in proof.managed_rows_v3(HABIT_TABLE))
    matched=tuple(row for row in rows if row["selector_commitment"]==commitment)
    occurrences=tuple(entry for entry in proof.occurrences if entry[1]is not None and(
        entry[1].occurrence_operation_id==future.action_operation_id or entry[1].action_intent_ref==future.action_ref))
    state.choice=(raw,chosen,future,preparation,selection,commitment)
    if not matched:
        if occurrences:raise AuthorityUnavailable("Artifact ordinary choice matches a real current or retired Habit occurrence")
        state.classification_kind="ordinary";return True
    if(len(matched)!=1 or matched[0]["retired"]or matched[0]["current_state"]!="enabled"
            or len(occurrences)!=1 or occurrences[0][0][2]!=1):
        raise AuthorityUnavailable("Artifact matched Habit row/occurrence is ambiguous, retired or disabled")
    row=matched[0];header,occurrence,_,_=occurrences[0]
    if(occurrence.state!="qualified"or occurrence.actual_started_at_utc is not None
            or(row["decision_ref"],row["decision_digest"],row["phase_selector_digest"],row["future_identity_digest"])!=(
                selector.decision_ref,selector.decision_digest,canonical_digest(selector),canonical_digest(future))):
        raise AuthorityUnavailable("Artifact current HMAC match differs from actual selected generation/qualified occurrence")
    history=_needed_value_v3(state,"history","event",header[0],header[1])
    if history is None or not history["valid"]:raise AuthorityUnavailable("Artifact Habit occurrence lacks its actual positive history")
    origin=_metadata_domain_v3(state,history["event_id"])
    if origin is None or(origin["domain"],origin["operation_kind"])!=("d10","qualify_habit_occurrence_v1"):
        raise AuthorityUnavailable("Artifact Habit occurrence has no actual qualification producer")
    from ..authority_service.d10_habit_contract_v1 import habit_occurrence_qualification_from_wire_v1
    qualification=habit_occurrence_qualification_from_wire_v1(origin["payload"]["provenance"]["core_qualification"])
    if(qualification.original_ref!=occurrence.qualification_original_ref
            or qualification.selector.operation_id!=origin["receipt"].operation_id
            or GraphVersion(AtomKey.from_token(header[0]),header[1])not in origin["receipt"].write_versions
            or(qualification.selector.policy_ref,qualification.selector.policy_revision)!=(row["policy_ref"],row["policy_revision"])):
        raise AuthorityUnavailable("Artifact Habit exact qualification/original receipt member differs")
    state.qualification=qualification;state.occurrence_metadata=occurrences[0];state.managed_row=row
    from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3
    cls=HabitArtifactModelReadSelectorV3 if r.operation_kind in _MODEL_V2 else HabitArtifactAdditionalSelectorV1
    state.restriction_selector=cls(r.namespace,qualification.selector,qualification.original_ref,qualification.digest,
        header[0],header[1],r.selector,selector)
    state.classification_kind="habit";return True

def _actual_artifact_phase_selector_v3(state):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,artifact_draft_file_ids_v2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    r=state.reader
    if r.operation_kind in{"prepare_artifact_draft_model","acquire_artifact_draft_model"}:
        if type(r.request.selector)is not ArtifactDraftTaskSelectorV1:
            raise AuthorityUnavailable("Legacy Artifact requires its actual typed task selector")
        return r.request.selector
    cycle=_needed_value_v3(state,"job","continuation",AtomKey.from_token(r.selector.cycle_job_ref).name)
    if cycle is None:raise AuthorityUnavailable("Artifact Source lacks actual durable Foreground cycle")
    from .foreground_cycle_v1 import ForegroundCycleContinuationV1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    phase=decode_typed_production_value_v1(cycle["continuation"]["call_plan"]["phase_group"]["selector"],ArtifactDraftPhaseSelectorV2)
    if(phase.task.namespace!=r.namespace or(phase.task.c02_operation_id,phase.task.cycle_job_ref,phase.task.root_registration_ref,phase.plan_ref)!=(
            r.selector.c02_operation_id,r.selector.cycle_job_ref,r.selector.draft_root_registration_ref,r.selector.plan_ref)):
        raise AuthorityUnavailable("Artifact current cycle phase differs from original Foreground selector")
    if r.operation_kind in _MODEL_V2|{"propose_artifact_draft_phase_action_v2","input:register_artifact_phase_draft_plan_v2"}:
        if r.request.selector!=phase:raise AuthorityUnavailable("Artifact typed command changed actual current phase selector")
    else:
        from ..graph_types import Owner
        ids=artifact_draft_file_ids_v2(phase)
        action=AtomKey(Owner("activity",*r.namespace.as_tuple,ids["activity_id"]),"d08.action_intent.v1",ids["action"]).token
        if r.operation_kind=="prepare_artifact_draft_body":
            if r.request.action_intent_ref!=action:raise AuthorityUnavailable("Artifact Body command changed actual phase Action")
        elif r.operation_kind=="prepare_life":
            plan=_needed_value_v3(state,"life","plan",r.request.plan_original_ref)
            if plan is None or plan["action_intent"]["ref"]!=action or plan["activity_id"]!=ids["activity_id"]:
                raise AuthorityUnavailable("Artifact Life command changed actual registered phase Action/plan")
        else:raise AuthorityUnavailable("Artifact phase factory has no fixed actual command")
    return phase

def _derive_joint_groups_v3(state):
    from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
    from .b3_managed_metadata_v1 import JOINT_TABLE,metadata_columns_v1
    from .joint_window_management_v1 import managed_window_selector_digest_v1
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .artifact_joint_source_groups_v3 import artifact_joint_source_groups_from_metadata_v3
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    r=state.reader;phase=state.artifact_phase_selector;task=phase.task if type(phase)is ArtifactDraftPhaseSelectorV2 else phase
    ref=task_scope_ref_v1(task.root_registration_ref)
    scope=_needed_value_v3(state,"life","artifact_task_scope",ref)
    head=_needed_value_v3(state,"life_header","artifact_task_scope",ref)
    if scope is None or head is None:raise AuthorityUnavailable("Artifact Joint classifier lacks actual immutable task scope")
    selector=managed_window_selector_digest_v1(r.namespace,"draft_file",ref,head["payload_digest"])
    proof=require_borrowed_habit_metadata_eof_v3(r)
    rows=tuple(dict(zip(metadata_columns_v1(JOINT_TABLE),row))for row in proof.managed_rows_v3(JOINT_TABLE))
    rows=tuple(row for row in rows if row["selector_digest"]==selector)
    if len(rows)>1 or any(row["retired"]for row in rows):raise AuthorityUnavailable("Artifact task matches conflicting or retired real Joint metadata")
    metadata={}
    for row in rows:
        for token in(row["plan_ref"],row["window_ref"]):
            actual=_metadata_graph_v3(state,token)
            if actual is None or not actual[1]:raise AuthorityUnavailable("Artifact matched Joint graph metadata is not current")
            version,_,value=actual
            event=_needed_value_v3(state,"history","event",token,version.revision)
            if event is None or not event["valid"]:raise AuthorityUnavailable("Artifact matched Joint metadata lost exact history")
            producer=_metadata_domain_v3(state,event["event_id"])
            if producer is None or version not in producer["receipt"].write_versions:
                raise AuthorityUnavailable("Artifact matched Joint metadata has no actual producer receipt write member")
            writes=tuple(write for write in producer["payload"]["writes"]if write["key"]==token)
            if len(writes)!=1 or not writes[0]["valid"]or writes[0]["value"]!=value:
                raise AuthorityUnavailable("Artifact matched Joint metadata differs from actual producing projected write")
            metadata[token]=(version.revision,value)
            state.control_metadata[version.key]=version
    state.joint_rows=rows
    state.joint_window_roots=tuple(dict.fromkeys(ref for row in rows for ref in metadata[row["window_ref"]][1]["source_refs"]))
    return artifact_joint_source_groups_from_metadata_v3(namespace=r.namespace,matched_rows=rows,metadata=metadata)

def _derive_source_groups_v3(state):
    from .artifact_habit_source_groups_v3 import artifact_habit_context_source_recipe_v3
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    r=state.reader
    groups=[("model_business",tuple(sorted(set(state.preplan.source_roots)|{key.token for key in state.preplan.exact_keys if key.type_name=="memory.source"})),("consolidation",),r.audiences)]
    control_consolidation=set()
    if r.operation_kind=="prepare_artifact_draft_body":
        action=_metadata_graph_v3(state,r.request.action_intent_ref)
        root=_needed_value_v3(state,"life","draft_action","life-draft-root:"+action[2]["identity"]["operation_id"])
        groups.append(("body_context",(root["input_source_ref"],),("context","consolidation"),tuple(root["audiences"])))
    elif r.operation_kind=="prepare_life":
        plan=_needed_value_v3(state,"life","plan",r.request.plan_original_ref)
        groups.append(("body_context",tuple(dict.fromkeys((plan["input_source"]["ref"],*plan["content"]["source_refs"]))),("context","consolidation"),tuple(plan["audiences"])))
    if state.classification_kind=="habit":
        if state.current is None:raise AuthorityUnavailable("Artifact Source requires its independent actual paired Habit current observation")
        d=state.current.policy_original.definition;selection=state.qualification.selector
        mirror=_metadata_graph_v3(state,selection.policy_ref)
        if mirror is None or not mirror[1]:
            raise AuthorityUnavailable("Artifact actual current Habit policy mirror is unavailable")
        from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
        actual_policy=graph_adopted_habit_policy_from_wire_v1(mirror[2])
        if(actual_policy.definition!=d or actual_policy.core_original_ref!=state.current.policy_original.original_ref
                or actual_policy.core_original_digest!=state.current.policy_original.digest or actual_policy.digest!=selection.policy_digest):
            raise AuthorityUnavailable("Artifact actual current policy mirror differs from independent Core original")
        state.control_metadata[mirror[0].key]=mirror[0]
        refs=[]
        if d.cue_predicate.observation_provider=="d07.habit-cue.v1":refs.append(selection.cue_original_ref)
        if d.stop_predicate.observation_provider=="d07.habit-stop.v1":refs.append(dict(d.stop_predicate.parameters)["interpretation_ref"])
        values={}
        for ref in refs:
            head=_metadata_graph_v3(state,ref)
            if head is None or not head[1]:raise AuthorityUnavailable("Artifact actual Habit interpretation metadata unavailable")
            event=_needed_value_v3(state,"history","event",ref,head[0].revision)
            if event is None or not event["valid"]:raise AuthorityUnavailable("Artifact Habit interpretation lacks actual positive history")
            producer=_metadata_domain_v3(state,event["event_id"])
            if producer is None or producer["domain"]!="d07"or head[0]not in producer["receipt"].write_versions:
                raise AuthorityUnavailable("Artifact Habit interpretation lost actual same-W01 D07 producer")
            writes=tuple(write for write in producer["payload"]["writes"]if write["key"]==ref)
            if len(writes)!=1 or not writes[0]["valid"]or writes[0]["value"]["source_refs"]!=head[2]["source_refs"]:
                raise AuthorityUnavailable("Artifact Habit interpretation Source metadata differs from actual producer write")
            values[ref]=head[2];state.control_metadata[head[0].key]=head[0]
        groups.append(artifact_habit_context_source_recipe_v3(definition=d,cue_original_ref=selection.cue_original_ref,interpretation_metadata=values))
        context_roots=groups[-1][1]
        context=set()
        def context_ancestor(ref):
            if ref in context:return
            witness=r.sources.get(ref)
            if witness is None:raise AuthorityUnavailable("Artifact actual context Source EOF is absent")
            context.add(ref)
            from ..memory_types import source_key
            for parent in witness.metadata["parent_source_ids"]:context_ancestor(source_key(*r.namespace.as_tuple,parent).token)
        for ref in context_roots:context_ancestor(ref)
        control_consolidation.update(state.occurrence_metadata[1].source_refs)
        for version in state.current.read_versions:
            header=state.headers.get(version.key.token)
            if (0 if header is None else header[0])!=version.revision:
                raise AuthorityUnavailable("Artifact independent current control metadata differs from actual same-Work head")
            if version.key.type_name=="memory.source":
                if version.key.token not in context:control_consolidation.add(version.key.token)
                continue
            prior=state.control_metadata.get(version.key)
            if prior is not None and prior!=version:raise AuthorityUnavailable("Artifact current control metadata version conflicts")
            state.control_metadata[version.key]=version
    groups.extend(_derive_joint_groups_v3(state))
    control_consolidation.update(state.joint_window_roots)
    if control_consolidation:
        from ..memory_types import source_key
        parents={source_key(*r.namespace.as_tuple,parent).token for ref in control_consolidation
            for parent in r.sources[ref].metadata["parent_source_ids"]}
        roots=tuple(sorted(control_consolidation-parents))
        groups.append(("business_consolidation",roots,("consolidation",),r.audiences))
    owner=state.owner_entry.require_for_v3(r)
    for _,roots,purposes,audiences in groups:
        if not roots or not set(purposes)<=set(owner.purposes)or not set(audiences)<=set(owner.audiences):
            raise AuthorityUnavailable("Artifact actual Owner does not permit the full independent Source purpose/audience")
    state.groups=tuple(groups)
    state.pending_sources=[(name,ref,purpose,audience)for name,roots,purposes,audiences in groups for ref in roots for purpose in purposes for audience in audiences]

def _advance_source_rights_v3(state,meter):
    from ..memory_types import source_key,access_key,validate_access
    from ..domains.d06 import source_correction_head_key
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    from ..graph_types import GraphAtom
    r=state.reader
    if state.pending_sources:
        name,ref,purpose,audience=state.pending_sources[-1];identity=(name,ref,purpose,audience)
        if identity in state.checked:state.pending_sources.pop();return False
        key=AtomKey.from_token(ref)
        if key!=source_key(*r.namespace.as_tuple,key.owner.subject or""):
            raise AuthorityUnavailable("Artifact Source group crossed canonical namespace")
        source=r.sources.get(ref)
        if source is None:raise AuthorityUnavailable("Artifact Source metadata was not present at actual namespace EOF")
        _require_source_witness_v3(state,source,meter)
        if name=="model_business":
            allowed={v.key.token:v.revision for v in r.evidence.read_versions if v.key.type_name=="memory.source"}
            if allowed.get(ref)!=source.revision:
                raise AuthorityUnavailable("Artifact business Source/ancestor escaped original Foreground qualified upper bound")
        access_ref=access_key(*r.namespace.as_tuple,key.owner.subject).token
        access=_metadata_graph_v3(state,access_ref)
        if access is None or not access[1]:raise AuthorityUnavailable("Artifact current SourceAccess metadata unavailable")
        validate_access(access[2])
        access_atom=GraphAtom(access[0].key,access[0].revision,access[2],access[1])
        correction_key=source_correction_head_key(r.namespace,key.owner.subject)
        correction=state.headers.get(correction_key.token)
        correction_atom=GraphAtom(correction_key,0 if correction is None else correction[0],{},False if correction is None else correction[1])
        record=_qualify_source_rights_values_v3(r.namespace,ref,source,access_atom,correction_atom,
            audience=audience,purpose=purpose,metadata_only=True)
        if record is None:raise AuthorityUnavailable("Artifact Source/access/correction denies exact independent purpose/audience")
        state.qualified[ref]=(source,record);state.checked.add(identity);state.pending_sources.pop()
        versions=(GraphVersion(key,source.revision),access[0],GraphVersion(correction_key,correction_atom.revision))
        for version in versions:
            prior=state.source_versions.get(version.key)
            if prior is not None and prior!=version:raise AuthorityUnavailable("Artifact independent Source group version conflict")
            state.source_versions[version.key]=version
        if name=="model_business":
            state.business_source_refs.add(ref)
            for version in versions:state.support[version.key]=version
        else:
            for version in versions:state.control_metadata[version.key]=version
        state.pending_sources.extend((name,source_key(*r.namespace.as_tuple,parent).token,purpose,audience)for parent in record.parent_source_ids)
        return False
    active,done=set(),set()
    def visit(ref):
        if ref in active:raise AuthorityUnavailable("Artifact Source ancestry is cyclic")
        if ref in done:return
        active.add(ref)
        for parent in state.qualified[ref][1].parent_source_ids:visit(source_key(*r.namespace.as_tuple,parent).token)
        active.remove(ref);done.add(ref)
    for _,roots,_,_ in state.groups:
        for ref in roots:visit(ref)
    _select_control_body_v3(state)
    state.phase="qualified";state.capability=ArtifactBorrowedSourceCapabilityV3(_KEY,state)
    return True

def _advance_metadata_computation_v3(state,meter,compute):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorNeededV3
    if state.pending is not None:
        task=state.pending;task.advance_v3(meter)
        if not task.complete:return False
        state.metadata[task.locator]=task.value;state.pending=None;return False
    try:return compute(state)
    except ArtifactMetadataLocatorNeededV3 as needed:
        task=state.tasks.get(needed.locator)
        if task is None:task=_ArtifactBorrowedLocatorTaskV3(state,needed.locator);state.tasks[needed.locator]=task
        state.pending=task;return False

def advance_artifact_borrowed_source_v3(reader):
    """The caller is the actual Work's plan phase, outside any SQL transaction."""
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False
    state.require_v3()
    if reader.db.in_transaction:raise AuthorityUnavailable("Artifact Source advancement inherited a transaction")
    if state.phase=="qualified":state.capability.require_v3();return False
    if state.phase=="owner":
        from ..authority_service.artifact_borrowed_owner_location_v3 import prepare_current_host_artifact_borrowed_owner_read_entry_v3
        if state.owner_entry is None:state.owner_entry=prepare_current_host_artifact_borrowed_owner_read_entry_v3(reader)
        state.owner_entry.require_permission_v3(reader)
        with reader.store._lock:reader.owner_binding=state.owner_entry.require_for_v3(reader)
        state.phase="recipe";return True
    if state.phase=="paired":
        if state.classification_kind=="habit":
            port=reader.graph._GraphCoordinator__habit_occurrence_port_v1
            if reader.operation_kind in _MODEL_V2:
                current,permit=port.observe_current_habit_artifact_model_read_for_fence_v3(
                    scope=reader.issued.scope,request=state.restriction_selector)
                port.require_issued_artifact_model_read_v3(scope=reader.issued.scope,request=state.restriction_selector,evidence=current)
            else:
                current,permit=port.observe_current_habit_artifact_restriction_for_fence_v1(
                    scope=reader.issued.scope,request=state.restriction_selector)
                port.require_issued_artifact_restriction_v1(scope=reader.issued.scope,request=state.restriction_selector,evidence=current)
            if(permit!=reader.issued.scope.permit or current.qualification_original!=state.qualification
                    or current.current_self!=reader.evidence.current_self or current.owner_guard!=reader.evidence.owner_guard
                    or current.query_epoch.revision!=reader.evidence.query_epoch.revision
                    or(current.access_epoch,current.delete_epoch)!=reader.expected_rights):
                raise AuthorityUnavailable("Artifact independent Habit current differs from actual original FG Self/Owner/Graph/Root")
            state.current=current
            state.current_monotonic_deadline=min(state.current_monotonic_deadline,
                state.initial_monotonic_time+current.valid_until_utc-reader.initial_now_utc)
        state.phase="groups";return True
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
        reader.require_current(meter=meter);state.owner_entry.require_for_v3(reader)
        if state.phase=="recipe":
            if _advance_recipe_metadata_v3(state,meter):state.phase="classification"
        elif state.phase=="classification":
            if _advance_metadata_computation_v3(state,meter,_derive_artifact_classification_v3):state.phase="paired"
        elif state.phase=="groups":
            if _advance_metadata_computation_v3(state,meter,lambda s:(_derive_source_groups_v3(s),True)[1]):state.phase="rights"
        elif state.phase=="rights":_advance_metadata_computation_v3(state,meter,lambda s:_advance_source_rights_v3(s,meter))
        else:raise AuthorityUnavailable("Artifact Source has no such actual fixed phase")
    return True

def _compose_actual_artifact_metadata_plan_v3(state):
    from .artifact_recipe_metadata_v3 import ArtifactRecipeMetadataV3,compose_artifact_borrowed_metadata_plan_v3
    from .artifact_joint_recipe_metadata_v3 import augment_artifact_joint_business_metadata_plan_v3
    r=state.reader;metadata=ArtifactRecipeMetadataV3(state.metadata)
    if r.operation_kind in{"prepare_artifact_draft_model","acquire_artifact_draft_model",*_MODEL_V2}:
        plan=compose_artifact_borrowed_metadata_plan_v3(namespace=r.namespace,operation_kind=r.operation_kind,
            activity_id=r.activity_id,metadata=metadata,request=r.request)
    else:
        from .artifact_write_recipe_metadata_v3 import compose_artifact_write_metadata_plan_v3
        plan=compose_artifact_write_metadata_plan_v3(namespace=r.namespace,operation_kind=r.operation_kind,
            activity_id=r.activity_id,operation_id=r.operation_id,request=r.request,
            phase=_actual_artifact_phase_selector_v3(state),metadata=metadata,now_utc=r.initial_now_utc)
    action_ref=None
    if r.operation_kind=="prepare_artifact_draft_body":action_ref=r.request.action_intent_ref
    elif r.operation_kind=="prepare_life":action_ref=metadata.life_v3("plan",r.request.plan_original_ref)["action_intent"]["ref"]
    plan=augment_artifact_joint_business_metadata_plan_v3(namespace=r.namespace,
        phase=_actual_artifact_phase_selector_v3(state),plan=plan,metadata=metadata,action_ref=action_ref)
    from .foreground_mesh_issuance_v1 import augment_personal_mesh_plan_v1
    return augment_personal_mesh_plan_v1(r.graph,r.issued,plan)

def _host_write_metadata_path_v3(locator,path,*,actual_domain_kind=None):
    from .artifact_recipe_metadata_v3 import _shape_retains_v3,_wire_shape_v3
    if locator.family=="graph":
        if locator.kind=="d04.numeric_checkpoint.v2":
            return _shape_retains_v3({"namespace":("array","scalar"),"graph_state":{"ref":"scalar"},
                "block":{"kind":"scalar"}},path)
        if locator.kind in{"d04.authored_feeling_state.v1","d04.authored_mood_state.v1"}:
            return _shape_retains_v3({"root_operation_id":"scalar","revision":"scalar",
                "historical_source_refs":("array","scalar"),"source_refs":("array","scalar"),
                "active_driver_refs":("array","scalar"),"interpretation_refs":("array","scalar")},path)
        common={"source_refs":("array","scalar"),"creation_evidence_refs":("array","scalar"),"reason_refs":("array","scalar")}
        from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
        if locator.kind not in LIFE_CURRENT_TYPES:return None
        shape=dict(common)
        if locator.kind=="d03.role_binding":
            from ..domains.d03.context import RoleBinding
            shape=_wire_shape_v3(RoleBinding)
        elif locator.kind=="d05.boundary_rule":
            from ..domains.d05.relationship import BoundaryRule
            shape=_wire_shape_v3(BoundaryRule)
        elif locator.kind=="d08.action_intent.v1":
            from ..runtime_contracts import OperationIdentity
            shape.update({name:"scalar"for name in("schema","action_id","action_kind","goal_ref","target_ref")})
            shape.update({"commitment_refs":("array","scalar"),"identity":_wire_shape_v3(OperationIdentity)})
        elif locator.kind=="d08.goal.v1":
            from .artifact_recipe_metadata_v3 import artifact_recipe_metadata_retain_path_v3
            return path==("goal_id",)or _shape_retains_v3(common,path)or artifact_recipe_metadata_retain_path_v3(locator,path)
        elif locator.kind=="d08.commitment.v1":shape.update({name:"scalar"for name in("commitment_id","fulfillment_state","counterparty_ref","deadline_ref")})
        elif locator.kind=="d03.entity_anchor":shape["entity_id"]="scalar"
        elif locator.kind=="d01.persona_activation.v1":shape["plan_id"]="scalar"
        elif locator.kind=="d08.action_schema.v1":shape["action_ref"]="scalar"
        elif locator.kind in{"d08.action_outcome.v1","d08.action_cancellation.v1"}:shape["action_id"]="scalar"
        elif locator.kind=="d07.attention_ticket.v1":shape["concern_ref"]="scalar"
        elif locator.kind=="d07.focus.v1":shape["primary_ticket_ref"]="scalar"
        return _shape_retains_v3(shape,path)
    if locator.family=="life":
        if locator.kind=="draft_action":
            from .d08_life_admission_v1 import DraftActionRootV1
            shape=_wire_shape_v3(DraftActionRootV1)
        elif locator.kind=="life_body_preparation":
            from .d02_life_body_preparation_v1 import LifeBodyPreparationOriginalV1
            shape=_wire_shape_v3(LifeBodyPreparationOriginalV1)
        elif locator.kind=="c4_phase_adopted":
            from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV2
            shape=_wire_shape_v3(ArtifactDraftContentAdoptionV2)
        elif locator.kind=="c4_phase_paid":shape={"cost_ref":"scalar"}
        elif locator.kind=="activity_scope":
            from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1
            shape=_wire_shape_v3(DraftActivityScopeV1)
        elif locator.kind=="artifact_task_objective":shape={name:"scalar"for name in("schema","project_ref","recipe_ref","source_ref","goal_ref","initial_c02_operation_id","completion_rule","valid_until_utc")}
        elif locator.kind=="prepared":
            from .d11_life_preparation_v1 import D11DraftPreparedV1
            from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
            from typing import get_type_hints
            hints=get_type_hints(D11DraftPreparedV1)
            shape={"schema":"scalar","binding":_wire_shape_v3(hints["binding"]),"plan":_wire_shape_v3(RegisteredDraftFilePlanV3),
                "admission_ref":"scalar","read_rows":("array",{"ref":"scalar","revision":"scalar","valid":"scalar"})}
        elif locator.kind=="adopted_life":
            from .d11_life_contract_v1 import D11DraftExecutionBindingV1
            from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1
            shape={"terminal":{"binding":_wire_shape_v3(D11DraftExecutionBindingV1),"original_ref":"scalar",
                "claim":{"original_ref":"scalar"},"payload":{"readback":_wire_shape_v3(DraftFileReadbackV1)}},
                "write_commitments":("array",{"ref":"scalar","revision":"scalar","digest":"scalar"})}
        else:return None
        return _shape_retains_v3(shape,path)
    if locator.family=="domain"and actual_domain_kind is not None:
        if actual_domain_kind in{("d10","create_artifact_project"),("d10","create_artifact_task_project_v1"),("d08","revise_existing_artifact_v1")}and path[0]=="provenance":
            from ..graph_types import GraphVersion
            gv=_wire_shape_v3(GraphVersion)
            shape={"task_project_basis":{"plan_head":gv,"goal_head":gv},"basis":{"plan_ref":"scalar","goal_ref":"scalar"},
                "artifact_plan_ref":"scalar","artifact_goal_ref":"scalar"}
            return _shape_retains_v3(shape,path[1:])
    return None

def _advance_artifact_metadata_index_v3(task,meter):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
    state=task.state;r=state.reader;loc=task.locator
    if loc.family=="history_index":
        if loc.kind!="valid_cycle_events"or AtomKey.from_token(loc.ref)!=AtomKey.from_token(r.selector.cycle_job_ref):
            raise AuthorityUnavailable("Artifact completed-phase history index changed actual cycle selector")
        if task.header is None:task.header=0;task.rows=[]
        row=meter.read_fixed_row(r.db,"graph_history",("revision","event_bot","event_persona","event_id"),
            "token=? AND valid=1 AND revision>? ORDER BY revision",(loc.ref,task.header))
        if row is None:task.value=tuple(task.rows);task.complete=True;return
        if row[1:3]!=r.namespace.as_tuple:raise AuthorityUnavailable("Artifact cycle history index crossed namespace")
        if len(task.rows)>=128:raise AuthorityUnavailable("Artifact completed phase cycle history exceeds actual existing bound")
        task.header=row[0];task.rows.append(row[3]);return
    from .d11_life_preparation_v1 import TABLE
    if loc.kind not in{"prepared_by_action","adopted_by_marker"}:
        raise AuthorityUnavailable("Artifact metadata has no such fixed Life-key index")
    kind="prepared"if loc.kind=="prepared_by_action"else"adopted_life"
    if task.header is None:task.header="";task.rows=[];task.child=None
    if task.child is not None:
        task.child.advance_v3(meter)
        if not task.child.complete:return
        value=task.child.value
        if value is None:raise AuthorityUnavailable("Artifact actual Life index member disappeared before signed EOF")
        matched=(value["binding"]["operation_id"]==loc.ref if loc.kind=="prepared_by_action"else
            value["terminal"]["payload"].get("readback")is not None and value["terminal"]["payload"]["readback"]["effect_marker"]==loc.ref)
        if matched:
            task.rows.append((task.child.locator.ref,value))
            if len(task.rows)>1:raise AuthorityUnavailable("Artifact exact Life metadata selector has conflicting actual members")
        task.child=None;return
    row=meter.read_fixed_row(r.db,TABLE,("original_ref",),"bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
        (*r.namespace.as_tuple,kind,task.header))
    if row is None:task.value=tuple(task.rows);task.complete=True;return
    task.header=row[0];task.child=_ArtifactBorrowedLocatorTaskV3(state,ArtifactMetadataLocatorV3("life",kind,row[0]))

class _ArtifactD04RootOutputMetadataV3:
    """Decode only actual output-row refs/revisions; discard authored numeric Body."""
    def __init__(self,state):
        self.state=state;self.capture=None;self.parser=None;self.complete=False;self.value=None
    def bind_v3(self,column):
        self.capture=ConditionedLocatorJSONV3(column)
        self.capture.retain_path_v3=lambda path:not path or path[0]=="rows"and(
            len(path)<3 or len(path)==3 and path[2]in(0,1))
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,ensure_ascii=True)
    def consume_codepoint_v3(self,path,codepoint):
        if path!=("output_json",):return False
        self.state.require_v3()
        self.parser.feed(chr(codepoint).encode("utf-8"),self.capture._emit_v3)
        return True
    def finish_v3(self):
        self.parser.finish();self.value=self.capture.value;self.complete=True
        return self.value

def _advance_artifact_d04_before_metadata_v3(task,meter):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3,ArtifactMetadataLocatorNeededV3
    from ..runtime_contracts import canonical_serialize
    from ..domains.d04.authored_lineage_v3 import CHECKPOINT_TYPE
    state=task.state;r=state.reader;ns=r.namespace;loc=task.locator
    policy=r.graph._GraphCoordinator__life_d04_before_capture_policy
    if policy is None or loc.kind!="selected_root"or loc.ref!=policy.root_operation_id or policy.namespace!=ns:
        raise AuthorityUnavailable("Artifact D04-before metadata differs from actual installed capture root")
    if task.header is None:
        task.header=meter.read_fixed_row(r.db,"graph_d04_root_originals_v3",("original_digest",),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,loc.ref))
        if task.header is None:raise AuthorityUnavailable("Artifact D04-before actual root Original is absent")
        task.output=_ArtifactD04RootOutputMetadataV3(state)
        task.column=_ArtifactBorrowedColumnV3(state,table="graph_d04_root_originals_v3",column="original_json",
            key_columns=("bot","persona","operation_id"),key=(*ns.as_tuple,loc.ref),wire_metadata=task.output,
            retain=lambda path:not path or path[0]in{"namespace","operation_id","graph_event_digest","graph_receipt_digest"})
        task.output.bind_v3(task.column);task.phase="root";return
    if task.phase=="root":
        if not task.column.advance(meter):return
        raw=task.column.require_v3(r);output=task.output.finish_v3()
        if(task.column.sha256!=task.header[0]or raw["operation_id"]!=loc.ref
                or raw["namespace"]!=json.loads(canonical_serialize(ns))):
            raise AuthorityUnavailable("Artifact D04 root metadata differs from actual full canonical Original")
        event=meter.read_fixed_row(r.db,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,"d04.authored_root.v3",loc.ref))
        if event is None or event[0]!=raw["graph_event_digest"]:
            raise AuthorityUnavailable("Artifact D04 root metadata lacks actual positive graph event")
        task.root=raw;task.event=event
        task.refs=tuple(sorted(row[0]for row in output["rows"]if AtomKey.from_token(row[0]).type_name==CHECKPOINT_TYPE))
        if not 1<=len(task.refs)<=16 or len(set(task.refs))!=len(task.refs):
            raise AuthorityUnavailable("Artifact D04 root metadata differs from actual bounded checkpoint family")
        task.output_rows=tuple((row[0],row[1])for row in output["rows"])
        task.column=_ArtifactBorrowedColumnV3(state,table="graph_events",column="revisions",
            key_columns=("bot","persona","session","event_id"),key=(*ns.as_tuple,"d04.authored_root.v3",loc.ref),
            retain=lambda path:len(path)<=2 and all(type(x)is int for x in path)and(len(path)<2 or path[1]<2))
        task.phase="event";return
    if task.phase=="event":
        if not task.column.advance(meter):return
        revisions=task.column.require_v3(r)
        receipt={"status":"committed","revisions":revisions,"invalidated":[],
            "epoch":{"bot":ns.bot_id,"persona":ns.persona_id,"revision":task.event[1]}}
        if tuple(tuple(row)for row in revisions)!=task.output_rows or canonical_digest(receipt)!=task.root["graph_receipt_digest"]:
            raise AuthorityUnavailable("Artifact D04 root metadata actual graph receipt members differ")
        task.cursor=0;task.keys=[];task.roots=set();task.phase="pairs";return
    if task.cursor==len(task.refs):
        if len(set(task.keys))>128 or len(task.roots)>32:
            raise AuthorityUnavailable("Artifact D04 before metadata exceeds existing context/Source bounds")
        task.value={"keys":tuple(AtomKey.from_token(ref)for ref in sorted(set(task.keys))),
            "source_roots":tuple(sorted(task.roots))}
        task.complete=True;return
    ref=task.refs[task.cursor]
    try:
        checkpoint=_metadata_graph_v3(state,ref)
        if checkpoint is None or not checkpoint[1]or tuple(checkpoint[2]["namespace"])!=ns.as_tuple:
            raise AuthorityUnavailable("Artifact D04 current checkpoint metadata unavailable")
        state_ref=checkpoint[2]["graph_state"]["ref"];current=_metadata_graph_v3(state,state_ref)
        if(current is None or not current[1]or current[2]["root_operation_id"]!=policy.root_operation_id
                or current[2]["revision"]!=current[0].revision):
            raise AuthorityUnavailable("Artifact D04 current state metadata changed installed original root/version")
        for version in(checkpoint[0],current[0]):
            event=_needed_value_v3(state,"history","event",version.key.token,version.revision)
            if event is None or not event["valid"]:raise AuthorityUnavailable("Artifact D04 current metadata lost actual positive history")
        value=current[2]
        task.keys.extend((ref,state_ref,*value["active_driver_refs"],*value.get("interpretation_refs",())))
        task.roots.update(value["historical_source_refs"]if checkpoint[2]["block"]["kind"]=="feeling"else value["source_refs"])
        task.cursor+=1
    except ArtifactMetadataLocatorNeededV3 as exc:
        if not hasattr(task,"child")or task.child is None:task.child=_ArtifactBorrowedLocatorTaskV3(state,exc.locator)
        task.child.advance_v3(meter)
        if task.child.complete:
            state.metadata[task.child.locator]=task.child.value;task.child=None

def _select_control_body_v3(state):
    from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
    from ..memory_types import source_key,access_key
    from ..domains.d06 import source_correction_head_key
    r=state.reader;keys=set()
    if state.classification_kind=="habit":
        keys.update((AtomKey.from_token(state.restriction_selector.occurrence_ref),AtomKey.from_token(state.qualification.selector.policy_ref)))
        d=state.current.policy_original.definition
        if d.cue_predicate.observation_provider=="d07.habit-cue.v1":keys.add(AtomKey.from_token(state.qualification.selector.cue_original_ref))
        if d.stop_predicate.observation_provider=="d07.habit-stop.v1":keys.add(AtomKey.from_token(dict(d.stop_predicate.parameters)["interpretation_ref"]))
        proof=require_borrowed_habit_metadata_eof_v3(r)
        for header,_,_,_ in proof.occurrences:state.control_metadata[AtomKey.from_token(header[0])]=GraphVersion(AtomKey.from_token(header[0]),header[1])
    for row in state.joint_rows:keys.update((AtomKey.from_token(row["plan_ref"]),AtomKey.from_token(row["window_ref"])))
    for name,ref,_,_ in state.checked:
        if name=="model_business":continue
        key=AtomKey.from_token(ref)
        keys.update((key,access_key(*r.namespace.as_tuple,key.owner.subject),source_correction_head_key(r.namespace,key.owner.subject)))
    for key in keys:
        header=state.headers.get(key.token);version=GraphVersion(key,0 if header is None else header[0])
        prior=state.control_metadata.get(key)
        if prior is not None and prior!=version:raise AuthorityUnavailable("Artifact actual control Body/metadata revision conflict")
        state.control_metadata[key]=version
    state.control_body_keys=frozenset(keys)

def _require_artifact_prepared_v3(prepared):
    from .current_method_learning_read_v3 import PreparedBorrowedMethodDomainInputsV3,_BORROWED_INPUTS
    if type(prepared)is not PreparedBorrowedMethodDomainInputsV3:raise AuthorityUnavailable("Actual Artifact prepared Borrowed inputs required")
    r=prepared.owner;s=_STATES.get(r)
    if(s is None or s.active is not True or s.capability is None
            or _BORROWED_INPUTS.get(prepared)!=(r,prepared.plan,prepared.issued,r.graph_stamp,r.expected_rights)
            or prepared.plan!=r.selected_plan or prepared.issued is not r.issued):
        raise AuthorityUnavailable("Artifact frame lost actual private Source Work/typed command")
    prepared.require_issued_current_v3(r.db,r.issued.scope,r.issued);s.capability.require_v3();return s

def require_artifact_borrowed_seal_plan_v3(reader,plan):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False
    state.capability.require_v3()
    if plan!=state.preplan:raise AuthorityUnavailable("Artifact actual Body recipe differs from complete independent metadata preplan")
    state.plan=plan;return True

def _business_versions_v3(state):
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    from ..runtime_contracts import QueryEpoch
    r=state.reader;plan=r.selected_plan
    if plan is None or state.plan is None:raise AuthorityUnavailable("Artifact frame has no exact recomputed sealed recipe")
    keys={owner_grant_key(*r.namespace.as_tuple),*plan.exact_keys}
    epoch=QueryEpoch(r.namespace,"namespace",r.graph_stamp[1].revision);pages=[]
    for kind in plan.fixed_type_ids:
        versions=tuple(GraphVersion(AtomKey.from_token(ref),head[0])for ref,head in sorted(state.headers.items())if AtomKey.from_token(ref).type_name==kind)
        if len(versions)>128:raise AuthorityUnavailable("Artifact complete business inventory exceeds original page bound")
        pages.append(ProductionQueryCoverageV1(epoch,kind,versions,True,None));keys.update(v.key for v in versions)
    keys.update(state.support)
    for original in r.observed_originals:keys.update(version.key for version in original.read_versions)
    versions=tuple(GraphVersion(key,0 if key.token not in state.headers else state.headers[key.token][0])for key in sorted(keys,key=lambda key:key.token))
    return versions,tuple(pages)

@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _ArtifactBorrowedWriteFrameReadsV3:
    issuer:InitVar[object]
    business_read_versions:tuple
    business_query_coverage:tuple
    control_read_versions:tuple
    control_query_coverage:tuple
    control_body_versions:tuple
    control_metadata_versions:tuple
    artifact_phase_selector:object
    def __post_init__(self,issuer):
        if issuer is not _KEY:raise AuthorityUnavailable("Actual Artifact private WRITE readset producer required")

def require_artifact_borrowed_write_frame_reads_v3(value,reader):
    state=_STATES.get(reader)
    if(type(value)is not _ArtifactBorrowedWriteFrameReadsV3 or state is None
            or _FRAME_READS.get(value)!=(state,state.capability,state.plan)or state.carrier is not value):
        raise AuthorityUnavailable("Artifact private WRITE readset has no actual same-Work Source issuer")
    state.capability.require_v3();return value

def artifact_borrowed_frame_control_v3(prepared):
    from .artifact_model_control_contract_v1 import ArtifactModelControlReadsV1,ArtifactHabitClassificationV3
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    from ..runtime_contracts import QueryEpoch
    s=_require_artifact_prepared_v3(prepared);r=s.reader
    if s.carrier is not None:
        if r.operation_kind not in _MODEL_V2:return require_artifact_borrowed_write_frame_reads_v3(s.carrier,r)
        return s.carrier
    b,bq=_business_versions_v3(s);body=artifact_borrowed_control_body_atoms_v3(prepared)
    body_versions=tuple(sorted((GraphVersion(atom.key,atom.revision)for atom in body),key=lambda v:v.key.token))
    c=tuple(sorted(s.control_metadata.values(),key=lambda v:v.key.token))
    cq=()
    if s.classification_kind=="habit":
        from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
        proof=require_borrowed_habit_metadata_eof_v3(r)
        occurrences=tuple(GraphVersion(AtomKey.from_token(header[0]),header[1])for header,_,_,_ in proof.occurrences)
        cq=(ProductionQueryCoverageV1(QueryEpoch(r.namespace,"namespace",r.graph_stamp[1].revision),
            "d10.habit_occurrence.v1",occurrences,True,None),)
    metadata=tuple(version for version in c if version.key not in s.control_body_keys)
    if r.operation_kind in _MODEL_V2:
        raw,chosen,future,preparation,selection,commitment=s.choice
        classification=ArtifactHabitClassificationV3(s.classification_kind,s.artifact_phase_selector,commitment,s.metadata_eof,
            selection["receipt"].operation_id,selection["original_digest"],canonical_digest(selection["receipt"]),
            preparation["receipt"].operation_id,preparation["original_digest"],canonical_digest(preparation["receipt"]),
            s.qualification,s.current)
        groups=tuple(group for group in s.groups if group[0]!="model_business")
        s.carrier=ArtifactModelControlReadsV1(r.operation_kind,r.request_digest,b,bq,c,cq,body_versions,metadata,groups,classification)
    else:
        s.carrier=_ArtifactBorrowedWriteFrameReadsV3(_KEY,b,bq,c,cq,body_versions,metadata,s.artifact_phase_selector)
        _FRAME_READS[s.carrier]=(s,s.capability,s.plan)
    return s.carrier

def artifact_borrowed_control_body_atoms_v3(prepared):
    from .current_method_learning_read_v3 import method_graph_head_v3
    s=_require_artifact_prepared_v3(prepared);r=s.reader
    atoms=tuple(method_graph_head_v3(r.db,r.namespace,key)for key in sorted(s.control_body_keys,key=lambda key:key.token))
    for atom in atoms:
        if GraphVersion(atom.key,atom.revision)!=s.control_metadata[atom.key]:
            raise AuthorityUnavailable("Artifact qualified actual control Body differs from original current metadata")
    s.control_body=atoms;return atoms

def artifact_borrowed_control_originals_v3(prepared):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    s=_require_artifact_prepared_v3(prepared)
    if s.current is None:return ()
    current=s.current;q=s.qualification;p=current.policy_original
    originals=[ProductionOriginalRefV1("d10.habit_occurrence_qualification",q.original_ref,q.digest,q.read_versions),
        ProductionOriginalRefV1("d10.habit_standing_policy",p.original_ref,p.digest,p.source_closure_versions)]
    s.control_originals=tuple(originals);return s.control_originals

def _body_tokens_v3(state):
    r=state.reader;plan=r.selected_plan or state.preplan
    tokens={key.token for key in plan.exact_keys}|{key.token for key in state.support}|{key.token for key in state.control_body_keys}
    tokens.update(ref for ref in state.headers if AtomKey.from_token(ref).type_name in plan.fixed_type_ids)
    tokens.add(owner_grant_key(*r.namespace.as_tuple).token)
    locator=r.action_schema_locator
    if locator is not None and locator.complete:
        from .current_method_learning_read_v3 import _ACTION_LOCATORS
        if _ACTION_LOCATORS.get(locator)!=locator._identity_v3():raise AuthorityUnavailable("Artifact actual derived Action-schema locator changed")
        tokens.add(locator.key.token)
    return tokens

def _actual_original_keys_v3(state):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2,artifact_draft_file_ids_v2
    r=state.reader;selector=state.artifact_phase_selector
    phase=type(selector)is ArtifactDraftPhaseSelectorV2;task=selector.task if phase else selector
    model=artifact_draft_model_ids_v2(selector)if phase else artifact_draft_model_ids_v1(selector)
    prefix="c4_phase_"if phase else"c4_"
    pairs={(prefix+part,model[name])for part,name in(
        ("prepared","job"),("frozen","frozen"),("request","request"),("call","call"),("paid","paid"),("result","result"),("adopted","adopt"))}
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    pairs.update((("artifact_task_scope",task_scope_ref_v1(task.root_registration_ref)),("draft_root_capability",task.root_registration_ref)))
    pairs.update(state.signed_pairs)
    operations={r.operation_id,task.c02_operation_id,*state.signed_operations}
    jobs={AtomKey.from_token(task.cycle_job_ref).name,model["job"]}
    for loc,value in state.metadata.items():
        if loc.family in{"life","life_header"}:
            pairs.add((loc.kind,loc.ref))
            if loc.family=="life_header"and value is not None:operations.add(value["operation_id"])
        elif loc.family=="domain"and value is not None:operations.add(value["receipt"].operation_id)
        elif loc.family=="history"and value is not None:operations.add(value["event_id"])
        elif loc.family=="job"and value is not None:jobs.add(loc.ref);operations.add(value["operation_id"])
    for loc,task_read in state.tasks.items():
        if type(loc)is ArtifactMetadataLocatorV3 and loc.family=="life"and task_read.header is not None:
            operations.add(task_read.header[0])
    scope=_needed_value_v3(state,"life","artifact_task_scope",task_scope_ref_v1(task.root_registration_ref))
    if scope is not None:
        from .ingress_artifact_task_scope_v1 import _decode,IngressArtifactTaskScopeOriginalV1
        from .artifact_original_child_locators_v3 import artifact_original_child_locators_v3
        value=_decode(scope,IngressArtifactTaskScopeOriginalV1)
        children=artifact_original_child_locators_v3(kind="artifact_task_scope",value=value)
        pairs.update(children.life_originals);operations.update(children.operation_ids)
    if phase:
        file=artifact_draft_file_ids_v2(selector)
        operations.update((file["action_operation"],"d02-life-body:"+file["action_operation"]))
        pairs.update((("draft_action","life-draft-root:"+file["action_operation"]),
            ("life_body_preparation","life-body:d02-life-body:"+file["action_operation"])))
        if selector.prev_phase_original_ref is not None:pairs.add(("c4_phase_verified",selector.prev_phase_original_ref))
    return pairs,operations,jobs

def require_artifact_borrowed_point_v3(reader,request):
    from ..runtime_contracts import NamespaceId
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False
    state.require_v3()
    table,columns,key_columns,key=request
    # The old Root grant metadata reader keeps its own exact signed parent binding.
    if table in{"runtime_budget_grants","runtime_budget_leases"}:
        if key[0]!=reader.parent_budget_lease_ref:raise AuthorityUnavailable("Artifact budget metadata changed original parent Root")
        return True
    if state.capability is None:raise AuthorityUnavailable("Artifact protected Body was requested before independent metadata/Owner/Source ALL")
    state.capability.require_v3();tokens=_body_tokens_v3(state)
    if table in{"graph_atoms","graph_history"}:
        atom_key=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom_key)!=reader.namespace or atom_key.token not in tokens:
            raise AuthorityUnavailable("Artifact Body point escaped actual fixed recipe and control partition")
        if atom_key.type_name=="memory.source":
            witness=reader.sources.get(atom_key.token)
            if atom_key.token not in state.qualified or witness is None:
                raise AuthorityUnavailable("Artifact Source Body has no complete independent ALL")
            _require_source_witness_v3(state,witness)
            if table=="graph_history"and key[1]!=witness.revision:
                raise AuthorityUnavailable("Artifact current Source permission cannot read another historical Source Body")
        return True
    pairs,operations,jobs=_actual_original_keys_v3(state)
    if table in{"graph_d10_production_inputs_v1","graph_d08_joint_node_originals_v1","graph_d08_joint_plan_intents_v1","graph_d08_party_consents_v1"}:
        if key_columns!=("bot","persona","original_ref")or tuple(key[:2])!=reader.namespace.as_tuple or(table,key[2])not in state.joint_pairs:
            raise AuthorityUnavailable("Artifact Joint Body escaped its actual signed fixed metadata locator")
        if state.joint_kinds[table,key[2]]=="external_observation"and key[2]not in state.preplan.required_original_refs:
            raise AuthorityUnavailable("Artifact unrelated external observation has metadata EOF but no business Body Source qualification")
        return True
    if table=="graph_d07_execution_originals_v1":
        if tuple(key[:2])!=reader.namespace.as_tuple or(key[2],key[3])not in state.d07_pairs:
            raise AuthorityUnavailable("Artifact D07 Body escaped actual signed Need preparation locator")
        return True
    if table=="runtime_jobs":
        if key_columns!=("job_id",)or key[0]not in jobs:raise AuthorityUnavailable("Artifact durable Body job crossed actual typed recipe")
        return True
    if table=="graph_d11_life_originals_v1":
        if tuple(key[:2])!=reader.namespace.as_tuple or(key[2],key[3])not in pairs:
            raise AuthorityUnavailable("Artifact signed Body Original escaped actual typed parent/child locator")
        return True
    if table in{"graph_domain_production_originals_v1","graph_bundle_operations"}:
        if tuple(key[:2])!=reader.namespace.as_tuple:raise AuthorityUnavailable("Artifact positive producer Body crossed namespace")
        operation=key[2]
        if operation not in operations:
            header=reader.db.execute("SELECT domain,operation_kind,original_digest FROM graph_domain_production_originals_v1 "
                "WHERE bot=? AND persona=? AND operation_id=?",(*reader.namespace.as_tuple,operation)).fetchone()
            from .domain_production_originals_v1 import _registered_domain_original_v1
            if(header is None or not _registered_domain_original_v1(*header[:2])
                    or header[0]+"-current:"+header[2][:48]not in state.preplan.required_original_refs):
                raise AuthorityUnavailable("Artifact producer Body has no actual positive metadata parent or exact recipe Original reference")
        return True
    if table=="graph_events":
        values=dict(zip(key_columns,key))
        if(values.get("bot"),values.get("persona"))!=reader.namespace.as_tuple or values["event_id"]not in operations:
            raise AuthorityUnavailable("Artifact event Body escaped exact authenticated producing lineage")
        return True
    if table=="graph_d05_production_policies_v1":
        from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
        loc=ArtifactMetadataLocatorV3("relationship_policy","current",key[2]);task=state.tasks.get(loc)
        if tuple(key[:2])!=reader.namespace.as_tuple or task is None or not task.complete or task.header[0]!=key[3]:
            raise AuthorityUnavailable("Artifact relationship Body policy escaped actual complete signed current metadata")
        return True
    if table=="graph_d04_root_originals_v3":
        policy=reader.graph._GraphCoordinator__life_d04_before_capture_policy
        if policy is None or tuple(key)!=(*reader.namespace.as_tuple,policy.root_operation_id):
            raise AuthorityUnavailable("Artifact D04 Body root escaped actual installed before-capture selection")
        return True
    if table in{"runtime_budget_reservations","runtime_budget_operations"}:
        values=dict(zip(key_columns,key))
        if values["operation_id"]not in operations or values.get("lease_id",reader.parent_budget_lease_ref)!=reader.parent_budget_lease_ref:
            raise AuthorityUnavailable("Artifact reservation metadata escaped actual original producer/Root")
        return True
    raise AuthorityUnavailable("Artifact Body has no actual fixed recipe point family")

def require_artifact_borrowed_body_column_v3(reader,table,key):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False
    state.require_v3()
    if table in{"runtime_budget_grants","runtime_budget_leases"}:
        if key[0]!=reader.parent_budget_lease_ref:raise AuthorityUnavailable("Artifact signed Root column changed actual parent")
        return True
    if state.capability is None:raise AuthorityUnavailable("Artifact Body column precedes independent Source ALL")
    key_columns={
        "graph_atoms":("token","bot","persona")if len(key)==3 else("token",),
        "graph_history":("token","revision"),
        "graph_d11_life_originals_v1":("bot","persona","kind","original_ref"),
        "graph_d07_execution_originals_v1":("bot","persona","kind","original_ref"),
        "graph_d10_production_inputs_v1":("bot","persona","original_ref"),
        "graph_d08_joint_node_originals_v1":("bot","persona","original_ref"),
        "graph_d08_joint_plan_intents_v1":("bot","persona","original_ref"),
        "graph_d08_party_consents_v1":("bot","persona","original_ref"),
        "graph_domain_production_originals_v1":("bot","persona","operation_id"),
        "graph_bundle_operations":("bot","persona","operation_id"),
        "runtime_jobs":("job_id",),"graph_d05_production_policies_v1":("bot","persona","policy_ref","revision"),
        "graph_d04_root_originals_v3":("bot","persona","operation_id"),
        "graph_events":("bot","persona","session","event_id"),
        "runtime_budget_reservations":("lease_id","operation_id"),
        "runtime_budget_operations":("bot_id","persona_id","operation_id","phase"),
    }.get(table)
    if key_columns is None:raise AuthorityUnavailable("Artifact Body column has no fixed actual recipe table")
    return require_artifact_borrowed_point_v3(reader,(table,(),key_columns,key))

@dataclass(frozen=True,slots=True,eq=False)
class _ArtifactBorrowedFrameFactsV3:
    execution_current:object
    occurrence_qualification:object
    read_frame:object
    artifact_phase_selector:object

def require_artifact_borrowed_frame_facts_v3(db,*,frame,selector,issuer):
    from .current_method_learning_read_v3 import _method_active
    from .artifact_frame_control_reads_v3 import _record_v3
    r=_method_active(db);state=_STATES.get(r)
    if(state is None or state.active is not True or db is not r.db or not db.in_transaction
            or issuer is not r.graph._GraphCoordinator__d11_issuer or selector!=state.artifact_phase_selector
            or not r.business_started or r.business_completed):
        raise AuthorityUnavailable("Artifact current classification needs its actual same-W01 private Source frame")
    record=_record_v3(frame,current=True)
    if record is None or record[1]is not r:raise AuthorityUnavailable("Artifact frame has no actual complete Rfull/Body Source record")
    state.capability.require_v3()
    from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
    require_borrowed_habit_metadata_eof_v3(r).require_current_v3(r)
    if state.classification_kind=="ordinary":return None
    port=r.graph._GraphCoordinator__habit_occurrence_port_v1
    if r.operation_kind in _MODEL_V2:port.require_issued_artifact_model_read_v3(scope=r.issued.scope,request=state.restriction_selector,evidence=state.current)
    else:port.require_issued_artifact_restriction_v1(scope=r.issued.scope,request=state.restriction_selector,evidence=state.current)
    if not set(state.current.read_versions)<=set(record[8]):
        raise AuthorityUnavailable("Artifact actual current Core restriction is outside this frame's exact full CAS read set")
    facts=_ArtifactBorrowedFrameFactsV3(state.current,state.qualification,frame,state.artifact_phase_selector)
    _FRAME_FACTS[id(frame)]=(facts,frame,state,state.capability)
    return facts

def require_artifact_borrowed_life_facts_v3(db,*,frame,prepared,job,issuer):
    from .current_method_learning_read_v3 import _method_active
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from ..domains.d01.production_operations_v1 import plain_v1
    r=_method_active(db);state=_STATES.get(r)
    if(state is None or r.operation_kind!="prepare_life"or type(prepared.plan)is not RegisteredDraftFilePlanV3
            or plain_v1(prepared.plan)!=_needed_value_v3(state,"life","plan",r.request.plan_original_ref)
            or job.job_id!=prepared.binding.job_id or job.activity_id!=prepared.plan.activity_id
            or(job.bot_id,job.persona_id)!=r.namespace.as_tuple):
        raise AuthorityUnavailable("Artifact Life restriction changed actual original registered plan/job")
    return require_artifact_borrowed_frame_facts_v3(db,frame=frame,selector=state.artifact_phase_selector,issuer=issuer)

def artifact_borrowed_frame_deadline_v3(prepared,deadline):
    state=_require_artifact_prepared_v3(prepared)
    return deadline if state.current is None else min(deadline,state.current.valid_until_utc,state.qualification.original_deadline_utc)

def _advance_joint_artifact_metadata_v3(task,meter):
    from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3
    from .artifact_joint_recipe_metadata_v3 import (artifact_joint_registered_metadata_profile_v3,
        artifact_joint_registration_request_frame_v3,artifact_joint_registration_request_digest_v3)
    state=task.state;r=state.require_v3().reader;loc=task.locator;ns=r.namespace
    if loc.family=="joint_registered_index":
        if(loc.kind,loc.ref)!=("external_observations","all"):
            raise AuthorityUnavailable("Artifact Joint metadata index is not the existing fixed external-observation recipe")
        if task.header is None:task.header="";task.rows=[];task.child=None
        if task.child is not None:
            task.child.advance_v3(meter)
            if not task.child.complete:return
            if task.child.value is None:raise AuthorityUnavailable("Artifact Joint metadata index member disappeared")
            task.rows.append((task.child.locator.ref,task.child.value["payload"]));task.child=None;return
        table,kinds,_,_,_=artifact_joint_registered_metadata_profile_v3("external_observation")
        row=meter.read_fixed_row(r.db,table,("original_ref",),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",(*ns.as_tuple,kinds[0],task.header))
        if row is None:task.value=tuple(task.rows);task.complete=True;return
        if len(task.rows)>=128:raise AuthorityUnavailable("Artifact actual external-observation metadata exceeds the formal recipe bound")
        task.header=row[0];task.child=_ArtifactBorrowedLocatorTaskV3(state,ArtifactMetadataLocatorV3("joint_registered","external_observation",row[0]));return
    table,kinds,sign_kind,domain,operation=artifact_joint_registered_metadata_profile_v3(loc.kind)
    if task.header is None:
        columns=("producing_operation_id","payload_digest","signature")+(("kind",)if kinds else())
        task.header=meter.read_fixed_row(r.db,table,columns,"bot=? AND persona=? AND original_ref=?",(*ns.as_tuple,loc.ref))
        if task.header is None:
            state.joint_pairs.add((table,loc.ref));state.joint_kinds[table,loc.ref]=loc.kind
            task.complete=True;return
        if kinds and task.header[3]not in kinds:raise AuthorityUnavailable("Artifact Joint metadata has another actual fixed Original kind")
        task.column=task._column_v3(table,"payload_json",("bot","persona","original_ref"),(*ns.as_tuple,loc.ref))
        task.column.sign_stream_v3(r.graph._GraphCoordinator__d11_issuer._signer,sign_kind,task.header[2])
        task.request_frame=artifact_joint_registration_request_frame_v3(loc.kind,loc.ref)
        if task.request_frame is not None:
            import hashlib
            task.column.request_payload_hash=hashlib.sha256(task.request_frame[0])
        return
    if not task.column.advance(meter):return
    if task.column.sha256!=task.header[1]:raise AuthorityUnavailable("Artifact Joint signed Original lacks its actual whole canonical EOF")
    header=meter.read_fixed_row(r.db,"graph_domain_production_originals_v1",("domain","operation_kind","request_digest","bundle_digest"),
        "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,task.header[0]))
    bundle=meter.read_fixed_row(r.db,"graph_bundle_operations",("digest","commit_seq"),
        "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,task.header[0]))
    if(header is None or header[:2]!=(domain,operation)or bundle is None or bundle[0]!=header[3]
            or type(bundle[1])is not int or bundle[1]<1):
        raise AuthorityUnavailable("Artifact Joint signed metadata lost its exact actual registered W01 COMMIT")
    value=task.column.require_v3(r)
    if"namespace"in value and value["namespace"]!={"bot_id":ns.bot_id,"persona_id":ns.persona_id}:
        raise AuthorityUnavailable("Artifact Joint signed metadata crossed namespace")
    if task.request_frame is None:request_digest=artifact_joint_registration_request_digest_v3(loc.kind,value)
    else:
        task.column.request_payload_hash.update(task.request_frame[1]);request_digest=task.column.request_payload_hash.hexdigest()
    if request_digest!=header[2]:raise AuthorityUnavailable("Artifact signed Joint metadata differs from its exact actual producer request")
    prefixes={"binding":"joint-node-binding:","external_contract":"joint-external-contract:","compensation":"joint-node-compensation:"}
    if loc.kind in prefixes and loc.ref!=prefixes[loc.kind]+task.header[1]:
        raise AuthorityUnavailable("Artifact signed Joint metadata lost its exact content-derived Original reference")
    if loc.kind=="external_observation"and value["producing_operation_id"]!=task.header[0]:
        raise AuthorityUnavailable("Artifact external observation differs from its exact signed producer")
    state.joint_pairs.add((table,loc.ref));state.joint_kinds[table,loc.ref]=loc.kind;state.signed_operations.add(task.header[0])
    task.value={"payload":value,"payload_digest":task.header[1],"operation_id":task.header[0],"request_digest":header[2]}
    task.complete=True

def artifact_borrowed_inventory_types_v3(reader):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return frozenset()
    state.capability.require_v3()
    return frozenset(state.preplan.fixed_type_ids)

def artifact_borrowed_joint_original_keys_v3(reader,*,table,namespace,kind):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return False,None
    state.capability.require_v3()
    if(table,namespace,kind)!=("graph_d08_joint_node_originals_v1",reader.namespace,"external_node_observation_v1"):
        raise AuthorityUnavailable("Artifact Joint key census has another fixed actual recipe family")
    rows=_needed_value_v3(state,"joint_registered_index","external_observations","all")
    return True,tuple((ref,)for ref,_ in rows)

class _ArtifactBorrowedDependencyRowsV3:
    def __init__(self,state,request):
        self.state,self.request=state,request
        self.cursor="";self.rows=[];self.complete=False
    def advance(self,meter):
        s=self.state;s.capability.require_v3();r=s.reader
        table,columns,key_columns,key,order_column=self.request
        row=meter.read_fixed_row(r.db,table,columns,"dependent_token=? AND dependency_token>? ORDER BY dependency_token",(key[0],self.cursor))
        if row is None:self.complete=True;return
        self.cursor=row[0];self.rows.append(row);r.operation.retain(len(row[0].encode("utf-8"))+64)

def read_bound_artifact_borrowed_dependencies_v3(db,*,table,columns,key_columns,key,order_column):
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    r=_method_active(db);state=_STATES.get(r)
    if state is None or state.active is not True:return False,None
    state.capability.require_v3()
    request=(table,tuple(columns),tuple(key_columns),tuple(key),order_column)
    if(request[:3]!=("graph_dependencies",("dependency_token","dependency_revision"),("dependent_token",))
            or order_column!="dependency_token"or len(key)!=1 or key[0]not in _body_tokens_v3(state)):
        raise AuthorityUnavailable("Artifact dependency metadata scan escaped its actual qualified dependent head")
    task=state.tasks.get(("body_dependencies",request))
    if task is None or not task.complete:_need_method_input(r,("artifact_body_dependencies",request))
    return True,tuple(task.rows)

def start_artifact_borrowed_dependencies_v3(reader,request):
    state=_STATES.get(reader)
    if state is None or state.active is not True:raise AuthorityUnavailable("Actual Artifact private dependency Source required")
    state.capability.require_v3()
    table,columns,key_columns,key,order_column=request
    if(table,columns,key_columns,order_column)!=("graph_dependencies",("dependency_token","dependency_revision"),("dependent_token",),"dependency_token")or len(key)!=1 or key[0]not in _body_tokens_v3(state):
        raise AuthorityUnavailable("Artifact dependency metadata task changed its exact registered recipe")
    index=("body_dependencies",request);task=state.tasks.get(index)
    if task is None:task=_ArtifactBorrowedDependencyRowsV3(state,request);state.tasks[index]=task
    return task

def artifact_borrowed_recipe_index_v3(db,*,namespace,family,kind,ref):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db);state=_STATES.get(r)
    if state is None or state.active is not True:return False,None
    state.capability.require_v3()
    if namespace!=r.namespace or(family,kind)not in{
            ("history_index","valid_cycle_events"),("life_index","prepared_by_action"),("life_index","adopted_by_marker")}:
        raise AuthorityUnavailable("Artifact recipe index changed its exact metadata-only family")
    return True,_needed_value_v3(state,family,kind,ref)

def artifact_borrowed_frame_monotonic_deadline_v3(prepared,deadline):
    state=_require_artifact_prepared_v3(prepared)
    return min(deadline,state.initial_monotonic_deadline,state.current_monotonic_deadline)

def require_artifact_borrowed_source_family_v3(reader,frame,db,roots,*,purpose=None,audience=None):
    state=_STATES.get(reader)
    if state is None or state.active is not True or db is not reader.db:
        raise AuthorityUnavailable("Artifact Source family requires its actual registered frame Work")
    state.capability.require_v3()
    actual_purpose=purpose or frame.envelope.authority.purpose
    audiences=(audience,)if audience is not None else frame.envelope.authority.audience
    if type(roots)is not tuple or not roots:
        raise AuthorityUnavailable("Artifact Source family needs its actual bounded roots")
    for ref in roots:
        for target in audiences:
            if not any((name,ref,actual_purpose,target)in state.checked for name,_,_,_ in state.groups):
                raise AuthorityUnavailable("Artifact Source family purpose/audience has no independent same-Work ALL")
    return True

def read_bound_artifact_borrowed_joint_observation_keys_v3(db,*,namespace,node_id):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db);state=_STATES.get(r)
    if state is None or state.active is not True:return False,None
    state.capability.require_v3()
    if namespace!=r.namespace:raise AuthorityUnavailable("Artifact external-node selector crossed actual Work namespace")
    rows=_needed_value_v3(state,"joint_registered_index","external_observations","all")
    return True,tuple((ref,)for ref,value in rows if value["node_id"]==node_id)

def artifact_borrowed_action_schema_complete_v3(reader):
    state=_STATES.get(reader)
    if state is None or state.active is not True:return
    from .current_method_learning_read_v3 import _ACTION_LOCATORS,ACTION_SCHEMA_LOCATOR_OPERATIONS_V3
    from dataclasses import replace
    state.capability.require_v3();locator=reader.action_schema_locator
    if(reader.operation_kind not in ACTION_SCHEMA_LOCATOR_OPERATIONS_V3 or locator is None or not locator.complete
            or _ACTION_LOCATORS.get(locator)!=locator._identity_v3()
            or reader.selected_plan!=replace(state.plan,exact_keys=tuple(sorted(set((*state.plan.exact_keys,locator.key)),key=lambda key:key.token)))):
        raise AuthorityUnavailable("Artifact schema extension lost its actual same-Work parameter/derived-key EOF")
    if type(state.carrier)is _ArtifactBorrowedWriteFrameReadsV3:_FRAME_READS.pop(state.carrier,None)
    elif state.carrier is not None:
        raise AuthorityUnavailable("Artifact model carrier cannot acquire an Action-schema extension")
    state.carrier=None
