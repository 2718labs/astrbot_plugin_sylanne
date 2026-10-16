"""Habit-owned Authority READ preparation on the same original Core permit."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
import json,time,codecs
from hashlib import sha256
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_KEY=object()
_WORKS=WeakKeyDictionary()
_SELECTIONS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class HabitStandingDefinitionInputV1:
    definition:object
    operation_id:str

class _HabitSelectionV3:
    def __init__(self,key,work,roots,audience,purpose="context"):
        if key is not _KEY:raise TypeError("Habit Source selection requires its actual factory")
        self.work,self.roots,self.audience=work,roots,audience
        self.root=roots[0]
        self.purpose=purpose;self.attention=None;self.maximum_ancestors=256
        _SELECTIONS[self]=(work,roots,audience,purpose,work.operation,work.scope)
    def require_v3(self,work):
        state=require_habit_authority_work_v3(work)
        if(_SELECTIONS.get(self)!=(work,self.roots,self.audience,self.purpose,work.operation,work.scope)
                or self.work is not work or (self.roots,self.purpose)not in habit_authority_source_groups_v1(state)
                or self.audience not in state.definition.audience):
            raise AuthorityUnavailable("Habit Source selection escaped its fixed actual roots/audience")
        return self

# These are identifiers/permission metadata; selected body values are read later.
_POLICY_FIELDS=frozenset(("namespace","policy_id","revision","project_ref","recipe_ref","recipe_revision",
    "executor_kind","parent_root_grant_ref","parent_root_grant_id","parent_root_grant_version","parent_root_grant_digest",
    "window_anchor_utc","window_seconds","execution_seconds","minimum_interval_seconds","maximum_occurrences_per_window",
    "original_valid_until_utc","miss_policy","state","cancellation_generation","purpose","audience","target_ref","source_refs"))
_REF_FIELDS=frozenset(("source_refs","source_ref","input_source_ref","body_source_ref","project_ref","recipe_ref",
    "namespace","revision","state","reality","creation_evidence_refs","reason_refs","plan_ref","plan_revision","goal_ref","goal_revision"))
_CENSUS_FIELDS=frozenset(("policy_ref","policy_revision","window_id","state","admitted_at_utc","actual_started_at_utc","effect_id"))
_OCCURRENCE_FIELDS=frozenset(("namespace","occurrence_id","policy_ref","policy_revision","policy_digest","window_id",
    "window_start_utc","window_end_utc","cue_original_ref","cue_original_digest","cue_stable_key","occurrence_operation_id",
    "activity_id","effect_id","attempt_id","recipe_ref","recipe_revision","executor_kind","parent_root_grant_ref",
    "parent_root_grant_digest","original_deadline_utc","cancellation_generation","state","action_intent_ref",
    "life_plan_original_ref","qualification_original_ref","outcome_original_ref","source_refs","admitted_at_utc","actual_started_at_utc",
    "goal_ref","plan_ref","context_original_ref","context_original_digest","schema"))


_RECIPE_METADATA_FIELDS_V1={
    'd03.role_binding':frozenset(('status','subject_persona_ref','target_entity_ref','group_ref','scene_ref','effective_from','effective_until','source_refs')),
    'd05.boundary_rule':frozenset(('status','subject_persona_ref','target_entity_ref','action_kind','audience_scope','scene_ref','valid_from','valid_until','source_refs')),
    'd07.focus.v1':frozenset(('persona_id','focus_epoch','primary_ticket_ref')),
    'd07.attention_ticket.v1':frozenset(('ticket_id','concern_ref','causal_root','source_refs','valid_until','eligible','resources_available','cancel_refs')),
    'd03.entity_anchor':frozenset(('entity_id','source_refs','creation_evidence_refs','reason_refs')),
}


def _habit_recipe_metadata_selected_v1(state,type_name,key):
    if state.definition.executor_kind!='source_note':return False
    if type_name=='d03.entity_anchor':return key.token==state.definition.target_ref
    from .d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_execution_purpose_v1
    from .habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
    request=state.work.request
    return type_name in _RECIPE_METADATA_FIELDS_V1 and(type(request)is HabitStandingDefinitionInputV1
        or (type(request)is HabitBodyPreparationSelectorV3 or type(request)is HabitOccurrenceExecutionSelectorV1 and habit_execution_purpose_v1(request)=='consolidation'))

def _retain_v3(type_name,path,locator,census):
    if not path:return True
    if type_name=="d10.habit_occurrence.v1":return path[0]in(_CENSUS_FIELDS|{"qualification_original_ref","action_intent_ref","outcome_original_ref"}if locator or census else _OCCURRENCE_FIELDS)
    if type_name=="d10.habit_policy.v1":
        if path[0]!="definition":return path[0]in{"core_namespace","installation_id","core_policy_revision","core_original_ref","core_original_digest","adoption_operation_id","schema"}
        return len(path)==1 or path[1]in _POLICY_FIELDS
    if type_name in{"memory.access","d06.source_correction_head.v1"}:return True
    from .habit_maintenance_source_read_v3 import MAINTENANCE_METADATA_TYPES_V1
    if type_name in MAINTENANCE_METADATA_TYPES_V1:return True
    if type_name in {'d02.body_profile.v1','d02.body_state.v1','d02.reservation.v1'}:return path[0]in {'profile_id','source_refs'}
    if type_name in _RECIPE_METADATA_FIELDS_V1:return path[0]in _RECIPE_METADATA_FIELDS_V1[type_name]
    return path[0]in _REF_FIELDS

class _HabitMetadataStreamV3:
    def __init__(self,column,ascii_codec):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.column=column;self.parser=C09CanonicalJSONStreamV2(ensure_ascii=ascii_codec)
        self.decoder=codecs.getincrementaldecoder("utf8")("strict");self.semantic=sha256()
    def feed(self,fragment,emit):
        text=self.decoder.decode(fragment)
        self.column._reserve(8*len(text)+8192)
        encoded=[]
        for char in text:
            point=ord(char)
            if point<127:encoded.append(char)
            elif point<=65535:encoded.append("\\u"+format(point,"04x"))
            else:
                point-=65536;encoded.append("\\u"+format(55296+(point>>10),"04x")+"\\u"+format(56320+(point&1023),"04x"))
        self.semantic.update("".join(encoded).encode("ascii"));self.parser.feed(fragment,emit)
    def finish(self):
        self.decoder.decode(b"",final=True)
        return self.parser.finish()

class _HabitMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,key,revision,valid,cell,*,locator,census=False,selected=True,history=False):
        self.state,self.graph_key,self.revision,self.valid,self.cell_id,self.locator=state,key,revision,valid,cell,locator
        self.census,self.selected=census,selected
        self.policy_locator=key.type_name=="d10.habit_policy.v1"and key not in state.service.selected_keys_v1(state.work.request,state.definition)
        super().__init__(state.work,table="graph_history"if history else"graph_atoms",column="value",
            key_columns=("token","revision")if history else("token",),key=(key.token,revision)if history else(key.token,),cell_id=cell)
        if self.cell.header[0]not in("canonical-json.ascii.v1","canonical-json.utf8.v1"):raise AuthorityUnavailable("Habit metadata codec differs")
        self.metadata_stream=_HabitMetadataStreamV3(self,self.cell.header[0]=="canonical-json.ascii.v1")
        self.parser=self.metadata_stream
    def _emit(self,event):
        if self.policy_locator:
            path=event.path
            keep=not path or path[0]=="definition"and(len(path)==1 or path[1]in{"namespace","policy_id","revision","project_ref","target_ref"})
        else:keep=not event.path or self.selected and _retain_v3(self.graph_key.type_name,event.path,self.locator,self.census)
        if keep:super()._emit(event)
    def finish_metadata_v3(self):
        w=self.state.work;require_habit_authority_work_v3(w)
        raw=self.require_v3(w)
        if not self.valid or not self.selected:return None
        if self.graph_key.type_name=="d10.habit_policy.v1":
            definition=raw["definition"]
            if NamespaceId(**definition["namespace"])!=w.namespace or definition["policy_id"]!=self.graph_key.name:
                raise AuthorityUnavailable("Habit policy target census metadata crossed its actual namespace/key")
            self.state.policy_targets[self.graph_key.token]=(self.revision,definition["target_ref"],definition["project_ref"],definition["revision"])
            if self.policy_locator:return None
        if self.graph_key.type_name=="d10.habit_occurrence.v1":
            self.state.occurrence_policies[self.graph_key]=raw
        if self.locator:return None
        if self.census:
            self.state.census[self.graph_key]=(self.revision,self.metadata_stream.semantic.hexdigest(),raw)
            return None
        if _habit_recipe_metadata_selected_v1(self.state,self.graph_key.type_name,self.graph_key):
            self.state.recipe_metadata[self.graph_key]=(self.revision,self.cell_id,self.sha256,raw)
            if self.graph_key not in self.state.service.selected_keys_v1(w.request,self.state.definition):return None
        self.state.metadata[self.graph_key]=(self.revision,self.cell_id,self.sha256,raw)
        if self.graph_key.type_name=="d10.habit_occurrence.v1"and raw.get("policy_ref")==self.state.policy_ref:
            self.state.census[self.graph_key]=(self.revision,self.metadata_stream.semantic.hexdigest(),{key:value for key,value in raw.items()if key in _CENSUS_FIELDS})
        if self.graph_key.type_name in{"memory.access","d06.source_correction_head.v1"}:
            w.members[self.graph_key]=GraphAtom(self.graph_key,self.revision,raw,True)
        return None

class HabitAuthorityInputsV3:
    def __init__(self,key,work,service,definition,current_self):
        if key is not _KEY:raise TypeError("Habit inputs require its actual independent Core Work")
        self.work,self.service,self.definition,self.current_self=work,service,definition,current_self
        self.policy_ref=service.policy_ref_v1(definition.policy_id)
        self.metadata={};self.recipe_metadata={};self.recipe_source_roots=();self.policy_targets={};self.occurrence_policies={};self.census_keys=set();self.census={};self.bodies={};self.roots=();self.materials=[]
        self.owner_entry=None;self.root_lease=self.root_grant=None;self.root_lease_id=definition.parent_root_grant_ref;self.read_versions=()
        self.complete=False;self.closed=False;self.owner_attempt=None
        self.initial_monotonic_deadline=None;self.recipe_valid_until_utc=None;self.extra_keys=set();self.obligations=();self.foreground_source_roots=()
        _WORKS[work]=self
    def require_for_v3(self,*,service,permit):
        if(self.closed or not self.complete or self.service is not service or self.work.permit!=permit
                or require_habit_authority_work_v3(self.work)is not self):
            raise AuthorityUnavailable("Habit prepared inputs changed actual Core/permit/EOF")
        if self.recipe_valid_until_utc is not None:
            reading=self.service.clock()
            if reading.utc_seconds+reading.utc_error_seconds>=self.recipe_valid_until_utc:
                raise AuthorityUnavailable("Habit exact metadata selection reached its current temporal boundary")
        for material in self.materials:
            material.selection.require_v3(self.work)
            if material.work is not self.work or material.phase!="cell"or material.pending:
                raise AuthorityUnavailable("Habit actual Source rights phase or sameWork identity changed")
            for witness in material.witnesses.values():witness.require_current_v3()
        self.work._check_permission_v3()
        if type(self.work.request)is HabitStandingDefinitionInputV1:require_habit_owner_policy_attempt_v3(self)
        with self.work.quantum_v3()as meter:self.work.require_current(meter=meter)
        return self
    def release_v3(self):
        if self.closed:return
        from .habit_finished_producer_v3 import release_habit_finished_reads_v3
        release_habit_finished_reads_v3(self.work)
        self.work.release_v3();self.closed=True;_WORKS.pop(self.work,None)
        for material in self.materials:_SELECTIONS.pop(material.selection,None)
        self.metadata.clear();self.recipe_metadata.clear();self.policy_targets.clear();self.occurrence_policies.clear();self.census.clear();self.bodies.clear();self.materials.clear()

def habit_authority_work_v3(work):return _WORKS.get(work)
def require_habit_authority_work_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
    state=_WORKS.get(work)
    if(type(work)is not AuthorityGraphReadWorkV3 or state is None or state.work is not work
            or type(state.service)is not InstalledCurrentHabitOccurrenceV1 or work.service is not state.service
            or work.controller.kind!="habit"or work.controller.verifier is not state.service or state.closed
            or state.initial_monotonic_deadline is not None and time.monotonic()>=state.initial_monotonic_deadline):
        raise AuthorityUnavailable("Habit cannot borrow another Authority Source Work")
    work._actual();return state

def habit_namespace_metadata_column_v3(work,key,revision,valid,cell):
    state=require_habit_authority_work_v3(work)
    selected=key in state.service.selected_keys_v1(work.request,state.definition)or key in state.extra_keys
    rights=key.type_name in{"memory.access","d06.source_correction_head.v1"}
    occurrence=key.type_name=="d10.habit_occurrence.v1"
    return _HabitMetadataColumnV3(state,key,revision,valid,cell,locator=occurrence and not selected,
        selected=selected or rights or occurrence or key.type_name=="d10.habit_policy.v1"or _habit_recipe_metadata_selected_v1(state,key.type_name,key))

def _run_column_v3(work,column):
    while not column.complete:
        with work.quantum_v3()as meter:column.advance(meter)
    return column.require_v3(work)

def _fixed_row_v3(work,table,columns,where,parameters):
    with work.quantum_v3()as meter:
        row=meter.read_fixed_row(work.db,table,columns,where,parameters)
        work.operation.retain(4096)
        return row

def _source_refs_v3(value):
    refs=set()
    if type(value)is dict:
        for key,item in value.items():
            if key in{"source_refs","source_ref","input_source_ref","body_source_ref","creation_evidence_refs","reason_refs"}:
                candidates=item if type(item)is list else(item,)
                for ref in candidates:
                    if type(ref)is not str:continue
                    try:source_key=AtomKey.from_token(ref)
                    except ValueError:
                        if key not in{"creation_evidence_refs","reason_refs"}:raise
                        continue
                    if source_key.type_name=="memory.source":refs.add(ref)
            elif type(item)in(dict,list):refs.update(_source_refs_v3(item))
    elif type(value)is list:
        for item in value:refs.update(_source_refs_v3(item))
    return refs

def prepare_habit_authority_inputs_v3(service,*,credential,subject,permit,request,definition,current_self):
    from .current_authority_graph_read_v3 import (begin_authority_graph_read_work_v3,_AuthorityNamespaceReadV3,
        AuthorityGraphProjectionV3,_AuthoritySourceMaterialReadV3,_ISSUER)
    reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
    deadline=min(definition.original_valid_until_utc,service.installed_bundle.installation_policy.root_grant.valid_until_utc)
    work=begin_authority_graph_read_work_v3(service,credential=credential,subject=subject,permit=permit,
        namespace=definition.namespace,request=request,parent_original_id=definition.parent_root_grant_ref,
        now_utc=now,deadline_utc=deadline)
    state=HabitAuthorityInputsV3(_KEY,work,service,definition,current_self)
    state.read_now_utc=now
    from .current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3,require_habit_foreground_observation_v1
    if type(request)in{HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}:
        upstream=require_habit_foreground_observation_v1(service,permit,request)
        state.foreground_source_roots=tuple(sorted(v.key.token for v in upstream.read_versions if v.key.type_name=="memory.source"))
    state.initial_monotonic_deadline=reading.monotonic_seconds+deadline-now
    try:
        from .owner_location_read_v3 import prepare_owner_location_for_habit_graph_work_v3
        state.owner_entry=prepare_owner_location_for_habit_graph_work_v3(work)
        if type(request)is HabitStandingDefinitionInputV1:require_habit_owner_policy_attempt_v3(state)
        grant=state.owner_entry.grant
        if("workbench.create"not in grant["capabilities"]or "context"not in grant["purposes"]
                or not set(definition.audience)<=set(grant["audiences"])):
            raise AuthorityUnavailable("Habit current Owner lacks original capability/purpose/audiences")
        while not work.catalogue_reader.complete:
            with work.quantum_v3()as meter:work.catalogue_reader.advance_v3(meter)
        work.namespace_reader=_AuthorityNamespaceReadV3(work,catalogue=work.catalogue_reader.rows,
            catalogue_hash=work.catalogue_reader.catalogue_hash)
        while not work.namespace_reader.graph_eof:
            with work.quantum_v3()as meter:work.namespace_reader.advance_v3(meter)
        # Resolve only actual target/project relationships after complete policy metadata EOF.
        prepare_habit_opaque_obligations_v1(state)
        for key,locator in state.occurrence_policies.items():
            policy_ref=locator["policy_ref"];relation=state.policy_targets.get(policy_ref)
            if policy_ref==state.policy_ref or relation is not None and relation[3]==locator["policy_revision"]and(relation[1]==definition.target_ref or relation[2]==definition.project_ref):
                state.census_keys.add(key)
        for key in sorted(state.census_keys,key=lambda key:key.token):
            revision,valid,cell=work.heads[key.token]
            column=_HabitMetadataColumnV3(state,key,revision,valid,cell,locator=False,census=True)
            _run_column_v3(work,column);column.finish_metadata_v3()
        prepare_habit_project_context_metadata_v1(state)
        from ..runtime.habit_body_cpu_source_v3 import select_core_body_metadata_v3
        select_core_body_metadata_v3(state)
        work.projection=AuthorityGraphProjectionV3(_ISSUER,work)
        from ..domains.d10.habit_policy_v1 import habit_policy_dependency_refs_v1
        roots={ref for ref in habit_policy_dependency_refs_v1(definition)if AtomKey.from_token(ref).type_name=="memory.source"}
        for _,_,_,metadata in state.metadata.values():roots.update(_source_refs_v3(metadata))
        state.recipe_source_roots=habit_source_note_recipe_source_roots_v1(state)
        roots.update(state.recipe_source_roots)
        roots.update(state.foreground_source_roots)
        state.roots=tuple(sorted(roots))
        if not state.roots:raise AuthorityUnavailable("Habit actual Source locator roots absent")
        for ref in state.roots:
            if NamespaceId.from_key(AtomKey.from_token(ref))!=work.namespace:raise AuthorityUnavailable("Habit Source locator crossed namespace")
        # Every audience and every ancestor qualifies before any selected Source/body.
        for audience in definition.audience:
            for roots,purpose in habit_authority_source_groups_v1(state):
                if purpose not in grant["purposes"]:raise AuthorityUnavailable("Habit phase exceeds current actual Owner Source purpose")
                material=_AuthoritySourceMaterialReadV3(work,_HabitSelectionV3(_KEY,work,roots,audience,purpose))
                state.materials.append(material)
                while material.phase=="rights":
                    with work.quantum_v3()as meter:material.advance_v3(meter)
        # Habit consumes Source identifiers and recorded times, never Source text.
        # Every actual kernel reader is at its completed-rights boundary; no generic body proof is minted.
        for material in state.materials:
            if material.phase!="cell"or material.pending:raise AuthorityUnavailable("Habit Source ancestry rights EOF absent")
        policy=service.installed_bundle.installation_policy
        lease_id=definition.parent_root_grant_ref
        if lease_id!=policy.root_lease.lease_id:raise AuthorityUnavailable("Habit Definition selected a different installed original Root")
        from ..runtime.budget import _lease_from_row
        row=_fixed_row_v3(work,"runtime_budget_leases",("lease_id","parent_id","bot_id","persona_id","currency","limits_json","used_json","reserved_json","unconfirmed_json","version","state"),"lease_id=?",(lease_id,))
        state.root_lease=_lease_from_row(row)
        if state.root_lease.parent_id is not None or state.root_lease.state!="active"or any(state.root_lease.unconfirmed.values()):
            raise AuthorityUnavailable("Habit original Root is not current/admissible")
        if any(state.root_lease.used.get(k,0)+state.root_lease.reserved.get(k,0)+state.root_lease.unconfirmed.get(k,0)>limit for k,limit in state.root_lease.limits.items()):
            raise AuthorityUnavailable("Habit original Root family has debt")
        signed=_fixed_row_v3(work,"runtime_budget_grants",("version","signature","status"),"lease_id=? ORDER BY version DESC",(lease_id,))
        if signed is None or signed[2]!="active"or signed[0]!=definition.parent_root_grant_version:
            raise AuthorityUnavailable("Habit actual Root signed grant revision changed")
        column=DispatchOriginalJSONReadV3(work,table="runtime_budget_grants",column="grant_json",key_columns=("lease_id","version"),key=(lease_id,signed[0]))
        raw=_run_column_v3(work,column);payload=canonical_serialize(raw)
        service.issuer._signer.verify("budget-grant.v1",payload,signed[1])
        from ..runtime.issuers import _decode_grant
        state.root_grant=_decode_grant(payload)
        if(state.root_grant!=policy.root_grant or canonical_digest(state.root_grant)!=definition.parent_root_grant_digest
                or state.root_grant.grant_id!=definition.parent_root_grant_id
                or "habit_subscription_v1"not in state.root_grant.allowed_work_kinds):
            raise AuthorityUnavailable("Habit installed Root grant lacks exact explicit standing subscription scope")
        # Protected values are now bounded to this recipe's actual selected locators.
        keys=set(service.selected_keys_v1(request,definition))|state.extra_keys
        for key in sorted(keys,key=lambda key:key.token):
            head=work.heads.get(key.token)
            if head is None or head[1]!=1:raise AuthorityUnavailable("Habit current selected required member absent")
            column=DispatchOriginalJSONReadV3(work,table="graph_atoms",column="value",key_columns=("token",),key=(key.token,),cell_id=head[2])
            from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            column.parser=C09CanonicalJSONStreamV2(ensure_ascii=column.cell.header[0]=="canonical-json.ascii.v1")
            raw=_run_column_v3(work,column)
            if key in state.metadata and(column.sha256!=state.metadata[key][2]or head[0]!=state.metadata[key][0]):
                raise AuthorityUnavailable("Habit selected body differs from its actual metadata EOF")
            if not _source_refs_v3(raw)<=set(state.roots):raise AuthorityUnavailable("Habit selected body introduced an unqualified Source locator")
            state.bodies[key]=GraphAtom(key,head[0],raw,True)
        versions={v.key:v.revision for material in state.materials for v in material.versions}
        versions.update((key,atom.revision)for key,atom in state.bodies.items())
        versions.update((key,entry[0])for key,entry in state.census.items())
        versions.update((key,entry[0])for key,entry in state.recipe_metadata.items())
        versions.update((AtomKey.from_token(ref),relation[0])for ref,relation in state.policy_targets.items())
        state.read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda x:x[0].token))
        state.complete=True
        return state.require_for_v3(service=service,permit=permit)
    except BaseException:
        state.release_v3();raise


def read_habit_subscription_job_v3(inputs,job_ref):
    state=require_habit_authority_work_v3(inputs.work);w=state.work
    if job_ref!=w.request.subscription_job_ref or not state.complete:raise AuthorityUnavailable("Habit job read escaped fixed subscription locator")
    key=AtomKey.from_token(job_ref)
    columns=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref","phase","work_kind",
        "deadline_utc","budget_ref","resource_ref","lease_holder","lease_expires_utc","fence","cancel_epoch","result_ref")
    row=_fixed_row_v3(w,"runtime_jobs",columns,"job_id=?",(key.name,))
    if row is None or tuple(row[4:6])!=w.namespace.as_tuple:raise AuthorityUnavailable("Habit actual durable subscription absent")
    data=dict(zip(columns,row))
    for column in("continuation_json","wake_condition_json","operator_versions_json","usage_json"):
        if column=="wake_condition_json":
            shape=_fixed_row_v3(w,"runtime_jobs",("wake_condition_json",),"job_id=?",(key.name,))
            if shape==(None,):data[column]=None;continue
        parsed=DispatchOriginalJSONReadV3(w,table="runtime_jobs",column=column,key_columns=("job_id",),key=(key.name,))
        data[column]=canonical_serialize(_run_column_v3(w,parsed))
    from ..runtime.jobs import _job_from_row
    return _job_from_row(tuple(data[x]for x in("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref","phase","work_kind",
        "continuation_json","wake_condition_json","deadline_utc","budget_ref","resource_ref","operator_versions_json",
        "lease_holder","lease_expires_utc","fence","cancel_epoch","usage_json","result_ref")))


def _read_habit_committed_original_v3(inputs,*,operation_id,expected_kind,member=None,expected_core_cue=None):
    state=require_habit_authority_work_v3(inputs.work);w=state.work
    if not state.complete:raise AuthorityUnavailable("Habit producer body requires completed Source EOF")
    row=_fixed_row_v3(w,"graph_domain_production_originals_v1",("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
        "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,operation_id))
    domain={"record_habit_window_cue_v1":"d11","instantiate_current_habit_source_note_context_v1":"d08",
        "prepare_current_habit_source_note_action_v1":"d08","prepare_source_note_body":"d02"}.get(expected_kind,"d10")
    if row is None or row[:2]!=(domain,expected_kind):
        raise AuthorityUnavailable("Habit actual fixed W01 producer original absent")
    payload=DispatchOriginalJSONReadV3(w,table="graph_domain_production_originals_v1",column="original_payload_json",
        key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,operation_id))
    raw=_run_column_v3(w,payload)
    if canonical_digest(raw)!=row[3]or raw["identity"]["operation_id"]!=operation_id or raw["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}:
        raise AuthorityUnavailable("Habit W01 original canonical/namespace/operation differs")
    if not _source_refs_v3(raw)<=set(state.roots):raise AuthorityUnavailable("Habit W01 body introduced an unqualified Source")
    receipt_column=DispatchOriginalJSONReadV3(w,table="graph_domain_production_originals_v1",column="receipt_json",
        key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,operation_id))
    receipt_raw=_run_column_v3(w,receipt_column)
    from ..runtime.domain_production_originals_v1 import _receipt
    receipt=_receipt(receipt_raw)
    bundle=_fixed_row_v3(w,"graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
        "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,operation_id))
    if(receipt.status!="committed"or canonical_digest(receipt)!=row[5]or receipt.operation_id!=operation_id or receipt.operation_digest!=row[4]
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)or receipt.commit_seq<1):
        raise AuthorityUnavailable("Habit W01 original lost its actual positive COMMIT/bundle")
    from .habit_finished_producer_v3 import require_habit_producer_finished_v3
    from ..runtime.habit_activity_history_v1 import HABIT_ACTIVITY_KINDS_V1
    if expected_kind in HABIT_ACTIVITY_KINDS_V1:
        require_habit_producer_finished_v3(inputs,operation_id=operation_id,expected_kind=expected_kind,
            original_digest=row[3],receipt_digest=row[5])
    elif expected_kind=="advance_life":
        from .habit_finished_producer_v3 import require_habit_life_progress_producer_finished_v3
        require_habit_life_progress_producer_finished_v3(inputs,operation_id=operation_id,
            original_digest=row[3],receipt_digest=row[5])
    if member is not None:
        history=_fixed_row_v3(w,"graph_history",("event_id","valid","value_cell_id"),"token=? AND revision=?",(member.key.token,member.revision))
        if history is None or history[:2]!=(operation_id,1):raise AuthorityUnavailable("Habit actual member did not originate in selected producer")
        body=DispatchOriginalJSONReadV3(w,table="graph_history",column="value",key_columns=("token","revision"),
            key=(member.key.token,member.revision),cell_id=history[2])
        if _run_column_v3(w,body)!=member.value:raise AuthorityUnavailable("Habit current member differs from actual producer history")
    if expected_core_cue is not None:
        from ..domains.d01.production_operations_v1 import plain_v1
        if raw["provenance"]["core_cue_original"]!=plain_v1(expected_core_cue):
            raise AuthorityUnavailable("Habit Graph wake did not persist actual immutable Core cue")
    return row[3],raw

def require_habit_committed_original_v3(inputs,*,operation_id,expected_kind,member=None,expected_core_cue=None):
    return _read_habit_committed_original_v3(inputs,operation_id=operation_id,expected_kind=expected_kind,
        member=member,expected_core_cue=expected_core_cue)[0]

def require_habit_current_adoption_v3(inputs,atom):
    state=require_habit_authority_work_v3(inputs.work);w=state.work
    if not state.complete or atom.key not in state.bodies:raise AuthorityUnavailable("Habit adoption outside exact Source-qualified body recipe")
    history=_fixed_row_v3(w,"graph_history",("event_id","valid","value_cell_id"),"token=? AND revision=?",(atom.key.token,atom.revision))
    if history is None or history[1]!=1:raise AuthorityUnavailable("Habit current semantic adoption absent")
    body=DispatchOriginalJSONReadV3(w,table="graph_history",column="value",key_columns=("token","revision"),key=(atom.key.token,atom.revision),cell_id=history[2])
    if _run_column_v3(w,body)!=atom.value:raise AuthorityUnavailable("Habit semantic current/history values differ")
    row=_fixed_row_v3(w,"graph_bundle_operations",("digest","commit_seq"),"bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,history[0]))
    if row is None or row[1]<1:raise AuthorityUnavailable("Habit semantic producer did not commit")
    column=DispatchOriginalJSONReadV3(w,table="graph_bundle_operations",column="receipt_json",key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,history[0]))
    receipt=_run_column_v3(w,column)
    if receipt["operation_id"]!=history[0]or receipt["commit_seq"]!=row[1]or receipt["operation_digest"]!=row[0]:
        raise AuthorityUnavailable("Habit semantic producer actual receipt differs")


def habit_standing_source_closure_versions_v1(inputs):
    inputs.require_for_v3(service=inputs.service,permit=inputs.work.permit)
    versions={}
    for material in inputs.materials:
        if material.phase!="cell"or material.pending:
            raise AuthorityUnavailable("Habit standing closure requires all audience Source rights EOF")
        for version in material.versions:
            if version.key.type_name!="memory.source":continue
            prior=versions.get(version.key)
            if prior is not None and prior!=version.revision:
                raise AuthorityUnavailable("Habit standing Source changed revision between actual audiences")
            versions[version.key]=version.revision
    captured=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
    projection=tuple(v for v in inputs.read_versions if v.key.type_name=="memory.source")
    if captured!=projection or not set(inputs.roots)<=set(v.key.token for v in captured):
        raise AuthorityUnavailable("Habit standing closure differs from its actual selected roots and sameWork read versions")
    return captured


def habit_authority_source_groups_v1(state):
    if getattr(state,'maintenance',False):
        from .habit_maintenance_source_read_v3 import habit_maintenance_source_groups_v1
        return habit_maintenance_source_groups_v1(state)
    groups=((state.roots,'context'),)
    from .d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_execution_purpose_v1
    from .habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
    request=state.work.request
    if(type(request)is HabitBodyPreparationSelectorV3 or type(request)is HabitOccurrenceExecutionSelectorV1
            and habit_execution_purpose_v1(request)=='consolidation'):
        groups+=((state.roots,'consolidation'),)
    elif state.recipe_source_roots:groups+=((state.recipe_source_roots,'consolidation'),)
    if state.foreground_source_roots:
        from .current_habit_artifact_restriction_v1 import require_habit_foreground_observation_v1
        upstream=require_habit_foreground_observation_v1(state.service,state.work.permit,state.work.request)
        groups+=((state.foreground_source_roots,upstream.request.purpose),)
    return groups


def habit_owner_policy_business_operation_id_v1(operation_id):
    if type(operation_id)is not str or not operation_id.startswith('habit-policy:')or not operation_id.removeprefix('habit-policy:'):
        raise AuthorityUnavailable('Habit standing requires its fixed Owner business operation identity')
    return operation_id.removeprefix('habit-policy:')


def require_habit_owner_policy_attempt_v3(inputs):
    state=require_habit_authority_work_v3(inputs.work);w=state.work
    if type(w.request)is not HabitStandingDefinitionInputV1:
        raise AuthorityUnavailable('Habit Owner attempt metadata belongs only to its standing Definition Work')
    from dataclasses import asdict,fields
    from .v2_contract import to_wire
    from ..contracts import canonical_json
    from ..runtime_contracts import SnapshotRequirementsV2
    business=habit_owner_policy_business_operation_id_v1(w.request.operation_id)
    key=(*w.namespace.as_tuple,business)
    expected_anchor=canonical_json(asdict(w.permit.pinned_anchor))
    expected_permit=canonical_json(to_wire(w.permit))
    where='bot=? AND persona=? AND operation_id=? AND receipt_json IS NULL AND anchor_json=? AND permit_json=?'
    row=_fixed_row_v3(w,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_revision','graph_epoch'),where,(*key,expected_anchor,expected_permit))
    recovery=_fixed_row_v3(w,'graph_recovery_metadata_v2',('schema','graph_revision'),'bot=? AND persona=?',w.namespace.as_tuple)
    if(row is None or type(row[0])is not str or not row[0]or row[1]!=w.permit.operation_id
            or recovery!=('sylanne3.authority.v2',row[2])or row[3]!=w.graph_stamp[0]
            or(state.current_self.graph_revision,state.current_self.graph_epoch)!=(row[2],row[3])):
        raise AuthorityUnavailable('Habit Owner business row differs from actual current WRITE attempt and Graph stamp')
    if state.owner_attempt is None:
        for column,expected in(('anchor_json',expected_anchor),('permit_json',expected_permit)):
            reader=DispatchOriginalJSONReadV3(w,table='graph_owner_domain_attempts_v3',column=column,
                key_columns=('bot','persona','operation_id'),key=key)
            value=_run_column_v3(w,reader)
            if(canonical_json(value)!=expected or reader.sha256!=sha256(expected.encode('utf8')).hexdigest()
                    or reader.byte_count!=len(expected.encode('utf8'))):
                raise AuthorityUnavailable('Habit Owner attempt canonical original differs from actual permit/anchor EOF')
        reader=DispatchOriginalJSONReadV3(w,table='graph_recovery_metadata_v2',column='requirements_json',
            key_columns=('bot','persona'),key=w.namespace.as_tuple)
        raw=_run_column_v3(w,reader)
        if type(raw)is not dict or set(raw)!={f.name for f in fields(SnapshotRequirementsV2)}:
            raise AuthorityUnavailable('Habit actual Graph recovery requirements closed fields differ')
        requirements=SnapshotRequirementsV2(**{**raw,'namespace':NamespaceId(**raw['namespace'])})
        anchor=w.permit.pinned_anchor
        if(requirements.namespace!=w.namespace or requirements.authority_namespace!=anchor.namespace
                or any(getattr(requirements,name)!=getattr(anchor,name)for name in(
                    'authority_id','activation_generation','deletion_journal_id','deletion_seq','deletion_digest',
                    'execution_journal_id','execution_seq','execution_digest','revocation_epoch'))):
            raise AuthorityUnavailable('Habit current Graph recovery identity differs from actual pinned Core anchor')
        state.owner_attempt=(business,row,canonical_json(raw))
    if state.owner_attempt[:2]!=(business,row):
        raise AuthorityUnavailable('Habit original Owner business/attempt metadata changed during actual Source work')
    current=_fixed_row_v3(w,'graph_recovery_metadata_v2',('graph_revision',),
        'bot=? AND persona=? AND schema=? AND requirements_json=?',
        (*w.namespace.as_tuple,'sylanne3.authority.v2',state.owner_attempt[2]))
    if current!=(row[2],):raise AuthorityUnavailable('Habit actual recovery original changed during its Owner Definition Work')
    return state.owner_attempt


def habit_source_note_recipe_source_roots_v1(state):
    from .d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_execution_purpose_v1
    from .habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
    from ..graph_types import Owner
    request=state.work.request;definition=state.definition
    if definition.executor_kind!='source_note' or not(type(request)is HabitStandingDefinitionInputV1
            or (type(request)is HabitBodyPreparationSelectorV3 or type(request)is HabitOccurrenceExecutionSelectorV1 and habit_execution_purpose_v1(request)=='consolidation')):
        return ()
    if not state.work.namespace_reader.graph_eof:
        raise AuthorityUnavailable('Habit recipe groups require actual complete sameWork metadata inventory EOF')
    target_key=AtomKey.from_token(definition.target_ref)
    target=state.recipe_metadata.get(target_key)
    if target is None or type(target[3]['entity_id'])is not str:
        raise AuthorityUnavailable('Habit recipe target lacks its actual Entity identity metadata')
    # The actual selected token/header and its complete JSON SHA bind this Entity ID;
    # Graph key names are not assumed to equal domain entity IDs.
    entity_id=target[3]['entity_id'];subject='persona:'+definition.namespace.persona_id
    now=state.read_now_utc;roots={definition.source_note_input.source_ref};bounds=[]
    for key,entry in state.recipe_metadata.items():
        value=entry[3]
        if key.type_name=='d03.role_binding':
            scoped=(value['status']=='active'and value['subject_persona_ref']==subject
                and value['target_entity_ref']in(None,entity_id)and value['group_ref']is None and value['scene_ref']is None)
            start,end=value['effective_from'],value['effective_until']
        elif key.type_name=='d05.boundary_rule':
            scoped=(value['status']=='active'and value['subject_persona_ref']==subject
                and value['target_entity_ref']==entity_id and value['action_kind']=='source_note'
                and value['audience_scope']in definition.audience and value['scene_ref']is None)
            start,end=value['valid_from'],value['valid_until']
        else:continue
        if not scoped:continue
        if start>now:bounds.append(start);continue
        if end is not None and now>end:continue
        if end is not None:bounds.append(end)
        roots.update(_source_refs_v3({'source_refs':value['source_refs']}))
    focus_key=AtomKey(Owner('persona',*definition.namespace.as_tuple),'d07.focus.v1',definition.namespace.persona_id)
    focus=state.recipe_metadata.get(focus_key)
    if focus is not None:
        focus=focus[3];ref=focus['primary_ticket_ref']
        if focus['persona_id']!=definition.namespace.persona_id:raise AuthorityUnavailable('Habit actual focus crossed persona')
        if ref is not None:
            ticket_key=AtomKey.from_token(ref)
            if(ticket_key.type_name!='d07.attention_ticket.v1'or ticket_key.owner!=focus_key.owner):
                raise AuthorityUnavailable('Habit actual primary focus crossed ticket namespace/type')
            selected=state.recipe_metadata.get(ticket_key)
            if selected is not None:
                ticket=selected[3]
                if(ticket['ticket_id']==ticket_key.name and ticket['concern_ref']==definition.project_ref
                        and definition.source_note_input.source_ref in ticket['source_refs']and ticket['valid_until']>now
                        and ticket['eligible']is True and ticket['resources_available']is True and not ticket['cancel_refs']
                        and ticket['causal_root']in ticket['source_refs']):
                    roots.update(_source_refs_v3({'source_refs':ticket['source_refs']}));bounds.append(ticket['valid_until'])
    roots.update(_source_refs_v3(target[3]))
    # Goal Source commitments have named semantic fields; Goal.params is never searched.
    for key,entry in state.metadata.items():
        if key.type_name=='d08.goal.v1':
            roots.update(_source_refs_v3({name:entry[3].get(name,[])for name in('source_refs','creation_evidence_refs','reason_refs')}))
    state.recipe_valid_until_utc=min(bounds)if bounds else None
    return tuple(sorted(roots))


def prepare_habit_project_context_metadata_v1(state):
    from .d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    from .habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
    if state.definition.executor_kind!='source_note'or not(type(state.work.request)is HabitStandingDefinitionInputV1
            or type(state.work.request)in {HabitOccurrenceExecutionSelectorV1,HabitBodyPreparationSelectorV3}):return
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    w=state.work;checkpoint=project_checkpoint_key_v1(w.namespace,state.definition.project_ref)
    entry=state.metadata.get(checkpoint)
    if entry is None:raise AuthorityUnavailable('Habit original project context lacks its actual current checkpoint metadata')
    plan=AtomKey.from_token(entry[3]['plan_ref'])
    if NamespaceId.from_key(plan)!=w.namespace or plan.type_name!='d08.personal_plan.v1':
        raise AuthorityUnavailable('Habit original checkpoint selected a different namespace/type of PersonalPlan')
    head=w.heads.get(plan.token)
    if head is None or head[1]!=1:raise AuthorityUnavailable('Habit original checkpoint Plan is absent')
    state.extra_keys.add(plan)
    column=_HabitMetadataColumnV3(state,plan,head[0],head[1],head[2],locator=False,selected=True)
    _run_column_v3(w,column);column.finish_metadata_v3()
    goal=AtomKey.from_token(state.metadata[plan][3]['goal_ref'])
    if NamespaceId.from_key(goal)!=w.namespace or goal.type_name!='d08.goal.v1':
        raise AuthorityUnavailable('Habit original project Plan selected a different namespace/type of Goal')
    head=w.heads.get(goal.token)
    if head is None or head[1]!=1:raise AuthorityUnavailable('Habit original project Plan Goal is absent')
    state.extra_keys.add(goal)
    column=_HabitMetadataColumnV3(state,goal,head[0],head[1],head[2],locator=False,selected=True)
    _run_column_v3(w,column);column.finish_metadata_v3()


def prepare_habit_opaque_obligations_v1(state):
    from .d10_habit_ledger_v1 import (OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,HabitRetirementV1,
        habit_scope_identity_commitment_v1,habit_identity_commitment_v1,habit_ledger_decode_v1)
    from .d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
    service=state.service;p=service.policy_service;w=state.work;definition=state.definition
    target=habit_scope_identity_commitment_v1(service._key,'target',w.namespace,p.installation_id,definition.target_ref)
    project=habit_scope_identity_commitment_v1(service._key,'project',w.namespace,p.installation_id,definition.project_ref)
    locators={}
    for key,raw in state.occurrence_policies.items():
        effect=raw['effect_id'];ref=raw.get('qualification_original_ref')
        if effect is None or ref is None:continue
        pair=(habit_scope_identity_commitment_v1(service._key,'effect',w.namespace,p.installation_id,effect),
            habit_identity_commitment_v1(service._key,'original',ref))
        if pair in locators:raise AuthorityUnavailable('Habit actual occurrence inventory has conflicting effect/original identity')
        locators[pair]=key
    obligations=[]
    with p.fences._frozen()as(db,deletion,execution,_):
        anchor=p.fences._current_locked(db,deletion,execution)
        p.fences.fences.validate_fence_locked(db,w.permit,subject=w.subject,current_anchor=anchor)
        cursor=db.execute('SELECT * FROM '+OCCURRENCE_TABLE+' WHERE authority_namespace=? AND installation_id=? '
            'AND effect_commitment IS NOT NULL AND(target_commitment=? OR project_commitment=?) ORDER BY operation_commitment',
            (p.fences.namespace,p.installation_id,target,project))
        while True:
            row=cursor.fetchone()
            if row is None:break
            original=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,row,key=service._key,
                authority_namespace=p.fences.namespace,authority_id=p.core._id(db),installation_id=p.installation_id)
            if type(original)not in{HabitOccurrenceQualificationOriginalV1,HabitRetirementV1}:
                raise AuthorityUnavailable('Habit opaque effect row is not its actual signed original or accepted retirement')
            original_commitment=row[OCCURRENCE_COLUMNS.index('original_commitment')]
            selected=locators.get((original.effect_commitment,original_commitment))
            if selected is not None:state.census_keys.add(selected)
            w.operation.retain(2048)
            obligations.append((selected,original.target_commitment==target,original.project_commitment==project,
                original.effect_commitment,original_commitment,original.digest))
    state.obligations=tuple(obligations)
    with w.quantum_v3()as meter:w.require_current(meter=meter)


def require_habit_actual_terminal_census_v1(inputs,key):
    state=require_habit_authority_work_v3(inputs.work);w=state.work
    revision,semantic,metadata=state.census[key]
    if metadata['state']not in{'completed_verified','failed_verified'}or not metadata.get('outcome_original_ref'):
        raise AuthorityUnavailable('Habit prior matched effect has no actual verified terminal occurrence')
    history=_fixed_row_v3(w,'graph_history',('event_id','valid','value_cell_id'),'token=? AND revision=?',(key.token,revision))
    if history is None or history[1]!=1:raise AuthorityUnavailable('Habit actual terminal occurrence history is absent')
    column=_HabitMetadataColumnV3(state,key,revision,True,history[2],locator=False,census=True,history=True)
    actual=_run_column_v3(w,column)
    if actual!=metadata or column.metadata_stream.semantic.hexdigest()!=semantic:
        raise AuthorityUnavailable('Habit terminal current metadata differs from actual same-version history EOF')
    operation=history[0]
    producer=_fixed_row_v3(w,'graph_domain_production_originals_v1',('domain','operation_kind','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*w.namespace.as_tuple,operation))
    if producer is None or producer[:2]!=('d10','adopt_habit_outcome_v1'):
        raise AuthorityUnavailable('Habit terminal occurrence has no actual named verified-outcome producer')
    reader=DispatchOriginalJSONReadV3(w,table='graph_domain_production_originals_v1',column='receipt_json',
        key_columns=('bot','persona','operation_id'),key=(*w.namespace.as_tuple,operation))
    from ..runtime.domain_production_originals_v1 import _receipt
    receipt=_receipt(_run_column_v3(w,reader))
    bundle=_fixed_row_v3(w,'graph_bundle_operations',('digest','commit_seq'),'bot=? AND persona=? AND operation_id=?',(*w.namespace.as_tuple,operation))
    if(receipt.status!='committed'or receipt.operation_id!=operation or receipt.operation_digest!=producer[2]
            or canonical_digest(receipt)!=producer[3]or bundle!=(receipt.operation_digest,receipt.commit_seq)
            or receipt.commit_seq<1 or GraphVersion(key,revision)not in receipt.write_versions):
        raise AuthorityUnavailable('Habit terminal occurrence lost its actual positive COMMIT/member receipt')


def require_habit_no_other_obligation_v1(inputs,*,occurrence_key,context):
    state=require_habit_authority_work_v3(inputs.work)
    for key,same_target,same_project,effect,original,digest in state.obligations:
        if key is None:
            if same_target or context and same_project:
                raise AuthorityUnavailable('Habit matched opaque prior effect lacks current authenticated obligation/settlement binding')
            continue
        if key==occurrence_key:continue
        metadata=state.census[key][2];status=metadata['state']
        if same_target and status in{'active','unknown'}or context and same_project and status in{'qualified','active','unknown'}:
            raise AuthorityUnavailable('Habit other actual same-target/project responsibility remains unresolved')
        if status in{'completed_verified','failed_verified'}:require_habit_actual_terminal_census_v1(state,key)
        elif status not in{'registered','waiting','qualified','cancelled'}or status=='cancelled'and metadata['actual_started_at_utc']is not None:
            raise AuthorityUnavailable('Habit prior matched effect has no authenticated no-start or verified terminal state')
    # Current Graph metadata also blocks malformed/unadopted active heads; a ledger
    # signature is never used to clear an actual visible responsibility.
    for key,(_,_,metadata)in state.census.items():
        if key==occurrence_key:continue
        relation=state.policy_targets.get(metadata['policy_ref'])
        if relation is None or relation[3]!=metadata["policy_revision"]:continue
        if(relation[1]==state.definition.target_ref and metadata['state']in{'active','unknown'}
                or context and relation[2]==state.definition.project_ref and metadata['state']in{'qualified','active','unknown'}):
            raise AuthorityUnavailable('Habit current target/project metadata retains another unresolved responsibility')
