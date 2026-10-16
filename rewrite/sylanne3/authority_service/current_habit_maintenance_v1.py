"""Closed current control observations of actual Habit miss and completed Life originals."""
from dataclasses import dataclass,fields
from .contract import AuthorityUnavailable
from .d10_habit_contract_v1 import _sha_v1,HabitStandingPolicyOriginalV1,HabitOccurrenceQualificationOriginalV1
from .v2_contract import FencePermitV2
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_value_from_wire_v1
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,QueryEpoch,canonical_digest
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..runtime.d10_habit_v1 import RecordHabitMissRequestV1,AdoptHabitOutcomeRequestV1

@dataclass(frozen=True,slots=True)
class HabitOriginalMaintenanceSelectorV1:
    namespace:NamespaceId
    installation_id:str
    policy_ref:str
    operation_kind:str
    operation_id:str
    request_digest:str
    occurrence_ref:str
    expected_revision:int
    policy_original_ref:str
    policy_original_digest:str
    standing_original_ref:str
    standing_original_digest:str
    standing_operation_id:str
    registration_original_ref:str
    registration_original_digest:str
    cue_original_ref:str
    cue_original_digest:str
    command:RecordHabitMissRequestV1|AdoptHabitOutcomeRequestV1
    qualification_selector:HabitOccurrenceSelectorV1|None=None
    qualification_original_ref:str|None=None
    qualification_original_digest:str|None=None
    schema:str='d10.habit-original-maintenance-selector.v1'
    def __post_init__(self):
        cls={'record_habit_miss_v1':RecordHabitMissRequestV1,'adopt_habit_outcome_v1':AdoptHabitOutcomeRequestV1}.get(self.operation_kind)
        if(self.schema!='d10.habit-original-maintenance-selector.v1'or type(self.namespace)is not NamespaceId
                or cls is None or type(self.command)is not cls or type(self.expected_revision)is not int or self.expected_revision<1
                or(self.command.occurrence_ref,self.command.expected_revision)!=(self.occurrence_ref,self.expected_revision)
                or any(type(v)is not str or not v for v in(self.installation_id,self.operation_id,self.policy_original_ref,
                    self.standing_original_ref,self.standing_operation_id,self.registration_original_ref,self.cue_original_ref))):
            raise ValueError('Habit maintenance requires its exact existing occurrence and closed actual typed command')
        for ref,kind in((self.occurrence_ref,'d10.habit_occurrence.v1'),(self.policy_ref,'d10.habit_policy.v1')):
            key=AtomKey.from_token(ref)
            if key.type_name!=kind or NamespaceId.from_key(key)!=self.namespace:raise ValueError('Habit maintenance locator crossed actual namespace/type')
        for value in(self.request_digest,self.policy_original_digest,self.standing_original_digest,self.registration_original_digest,self.cue_original_digest):_sha_v1(value)
        from ..runtime.habit_maintenance_issuance_v1 import habit_maintenance_typed_command_digest_v1
        from ..runtime.domain_production_registry_v1 import installed_operation_v1
        if self.request_digest!=habit_maintenance_typed_command_digest_v1(installed_operation_v1(self.operation_kind),self.command):raise ValueError('Habit maintenance actual typed command digest differs')
        if self.qualification_selector is None:
            if self.operation_kind!='record_habit_miss_v1'or self.qualification_original_ref is not None or self.qualification_original_digest is not None:
                raise ValueError('Only an actually unqualified registered occurrence can use a registration-only miss')
        else:
            q=self.qualification_selector
            if(type(q)is not HabitOccurrenceSelectorV1 or q.namespace!=self.namespace or q.policy_ref!=self.policy_ref
                    or type(self.qualification_original_ref)is not str or not self.qualification_original_ref):
                raise ValueError('Habit maintenance historical qualification differs')
            _sha_v1(self.qualification_original_digest)

@dataclass(frozen=True,slots=True)
class HabitOriginalMaintenanceCurrentV1:
    request:HabitOriginalMaintenanceSelectorV1
    permit:FencePermitV2
    current_self:AuthorityCurrentSelfIdentityV1
    owner_guard:ProductionOwnerGuardV1
    policy_original:HabitStandingPolicyOriginalV1
    standing_original:HabitStandingPolicyOriginalV1
    qualification_original:HabitOccurrenceQualificationOriginalV1|None
    occurrence_head:GraphVersion
    occurrence_digest:str
    original_root_ref:str
    original_root_digest:str
    original_deadline_utc:float
    read_versions:tuple[GraphVersion,...]
    query_epoch:QueryEpoch
    access_epoch:int
    delete_epoch:int
    observed_at_utc:float
    schema:str='d10.current-habit-original-maintenance.v1'
    def __post_init__(self):
        if(self.schema!='d10.current-habit-original-maintenance.v1'or type(self.request)is not HabitOriginalMaintenanceSelectorV1
                or type(self.permit)is not FencePermitV2 or self.permit.operation!='write'or self.permit.operation_id!=self.request.operation_id
                or type(self.current_self)is not AuthorityCurrentSelfIdentityV1 or self.current_self.permit!=self.permit
                or type(self.owner_guard)is not ProductionOwnerGuardV1 or type(self.query_epoch)is not QueryEpoch
                or self.occurrence_head.key.token!=self.request.occurrence_ref or self.occurrence_head.revision!=self.request.expected_revision
                or type(self.policy_original)is not HabitStandingPolicyOriginalV1 or type(self.standing_original)is not HabitStandingPolicyOriginalV1
                or self.standing_original.definition.parent_root_grant_ref!=self.original_root_ref
                or self.standing_original.definition.parent_root_grant_digest!=self.original_root_digest):
            raise ValueError('Habit maintenance observation changed its actual control permit/history/occurrence')
        _sha_v1(self.occurrence_digest);_sha_v1(self.original_root_digest)
    def require_for_v3(self,*,request,permit,installation_id,authority_namespace):
        if(self.request!=request or self.permit!=permit or self.current_self.installation_id!=installation_id
                or self.current_self.authority_namespace!=authority_namespace):raise AuthorityUnavailable('Habit maintenance paired current Scope differs')
        return self

def habit_maintenance_selector_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitOriginalMaintenanceSelectorV1:raise TypeError('exact Habit maintenance selector required')
    return plain_v1(value)

def habit_maintenance_selector_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitOriginalMaintenanceSelectorV1)}:raise ValueError('Habit maintenance selector fields differ')
    cls={'record_habit_miss_v1':RecordHabitMissRequestV1,'adopt_habit_outcome_v1':AdoptHabitOutcomeRequestV1}.get(raw['operation_kind'])
    if cls is None:raise ValueError('unknown Habit maintenance command')
    value=HabitOriginalMaintenanceSelectorV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'command':decode_typed_production_value_v1(raw['command'],cls),
        'qualification_selector':None if raw['qualification_selector']is None else habit_value_from_wire_v1('d10.habit-occurrence-selector.v1',raw['qualification_selector'])})
    if habit_maintenance_selector_to_wire_v1(value)!=raw:raise ValueError('Habit maintenance canonical selector differs')
    return value

def habit_maintenance_current_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitOriginalMaintenanceCurrentV1:raise TypeError('exact Habit maintenance current required')
    return plain_v1(value)

def habit_maintenance_current_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitOriginalMaintenanceCurrentV1)}:raise ValueError('Habit maintenance current fields differ')
    # This decoder preserves the normal fixed production value types, with the closed request decoded explicitly.
    value=decode_typed_production_value_v1({**raw,'request':habit_maintenance_selector_to_wire_v1(habit_maintenance_selector_from_wire_v1(raw['request']))},HabitOriginalMaintenanceCurrentV1)
    if habit_maintenance_current_to_wire_v1(value)!=raw:raise ValueError('Habit maintenance current canonical shape differs')
    return value


def _historical_original_v1(service,permit,subject,ref,*,policy=False,operation_id=None):
    from .d10_habit_ledger_v1 import (POLICY_TABLE,POLICY_COLUMNS,OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,
        habit_identity_commitment_v1,habit_ledger_decode_v1,HabitRetirementV1)
    p=service.policy_service;table,columns=(POLICY_TABLE,POLICY_COLUMNS)if policy else(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS)
    with p.fences._frozen()as(db,deletion,execution,_):
        anchor=p.fences._current_locked(db,deletion,execution)
        p.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        column='operation_commitment'if policy else'original_commitment'
        selected=habit_identity_commitment_v1(service._key,'operation',operation_id)if policy else habit_identity_commitment_v1(service._key,'original',ref)
        row=db.execute('SELECT * FROM '+table+' WHERE authority_namespace=? AND installation_id=? AND '+column+'=?',
            (p.fences.namespace,p.installation_id,selected)).fetchone()
        if row is None:raise AuthorityUnavailable('Habit maintenance actual historical Core original is absent')
        original=habit_ledger_decode_v1(table,columns,row,key=service._key,authority_namespace=p.fences.namespace,
            authority_id=p.core._id(db),installation_id=p.installation_id)
        if type(original)is HabitRetirementV1:raise AuthorityUnavailable('Habit maintenance cannot reconstruct an erased historical original')
        if original.original_ref!=ref:raise AuthorityUnavailable('Habit maintenance historical original locator differs')
        return original

def current_habit_maintenance_v1(service,*,credential,subject,permit,request):
    from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
    from .habit_maintenance_source_read_v3 import prepare_habit_maintenance_inputs_v3,require_habit_maintenance_life_v1
    from .habit_authority_source_read_v3 import _read_habit_committed_original_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
    from ..graph_types import owner_grant_key
    if(type(service)is not InstalledCurrentHabitOccurrenceV1 or type(request)is not HabitOriginalMaintenanceSelectorV1
            or type(permit)is not FencePermitV2 or permit.operation!='write'or permit.operation_id!=request.operation_id
            or request.installation_id!=service.policy_service.installation_id or request.namespace!=service.self_identity._namespace_id):
        raise AuthorityUnavailable('Habit maintenance needs its actual installed fresh control WRITE')
    current=service._self_v1(credential,subject,permit,request.operation_id)
    p=service.policy_service
    with p.fences._frozen()as(db,deletion,execution,_):
        anchor=p.fences._current_locked(db,deletion,execution)
        p.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        policy=p._head_v1(db,AtomKey.from_token(request.policy_ref).name)
    if(policy is None or(policy.original_ref,policy.digest)!=(request.policy_original_ref,request.policy_original_digest)):
        raise AuthorityUnavailable('Habit maintenance changed the actual highest current policy head')
    q=None
    if request.qualification_selector is not None:
        q=_historical_original_v1(service,permit,subject,request.qualification_original_ref)
        if(type(q)is not HabitOccurrenceQualificationOriginalV1 or q.selector!=request.qualification_selector
                or q.digest!=request.qualification_original_digest):raise AuthorityUnavailable('Habit maintenance historical qualification differs')
        old=q.selector
        standing=_historical_original_v1(service,permit,subject,old.standing_authorization_original_ref,policy=True,operation_id=request.standing_operation_id)
        if standing.digest!=old.standing_authorization_original_digest:raise AuthorityUnavailable('Habit maintenance historical standing digest differs')
    else:
        standing=_historical_original_v1(service,permit,subject,request.standing_original_ref,policy=True,operation_id=request.standing_operation_id)
    if(standing.original_ref,standing.digest)!=(request.standing_original_ref,request.standing_original_digest):
        raise AuthorityUnavailable('Habit maintenance actual old signed standing locator/digest differs')
    inputs=prepare_habit_maintenance_inputs_v3(service,credential=credential,subject=subject,permit=permit,
        request=request,definition=standing.definition,current_self=current,current_policy=policy)
    try:
        key=AtomKey.from_token(request.occurrence_ref);atom=inputs.bodies[key]
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
        if(atom.revision!=request.expected_revision or occurrence.policy_ref!=request.policy_ref
                or occurrence.cue_original_ref!=request.cue_original_ref or occurrence.cue_original_digest!=request.cue_original_digest
                or occurrence.namespace!=request.namespace or occurrence.parent_root_grant_ref!=standing.root_lease_id
                or occurrence.parent_root_grant_digest!=canonical_digest(standing.root_grant)
                or occurrence.policy_revision!=standing.definition.revision):
            raise AuthorityUnavailable('Habit maintenance changed actual original occurrence/standing/Root lineage')
        mirror=graph_adopted_habit_policy_from_wire_v1(inputs.bodies[AtomKey.from_token(request.policy_ref)].value)
        if mirror.definition!=policy.definition or(mirror.core_original_ref,mirror.core_original_digest)!=(policy.original_ref,policy.digest):
            raise AuthorityUnavailable('Habit maintenance actual Graph policy mirror differs from current signed Core head')
        from .habit_authority_source_read_v3 import _fixed_row_v3
        born=_fixed_row_v3(inputs.work,'graph_history',('event_id','valid'),'token=? AND revision=?',(key.token,1))
        if born is None or born[1]!=1:raise AuthorityUnavailable('Habit maintenance actual occurrence registration history absent')
        digest,registration=_read_habit_committed_original_v3(inputs,operation_id=born[0],expected_kind='register_habit_occurrence_v1')
        if('d10-current:'+digest[:48],digest)!=(request.registration_original_ref,request.registration_original_digest):
            raise AuthorityUnavailable('Habit maintenance actual registration positive COMMIT differs')
        registered=registration['provenance']['occurrence'];cue=registration['provenance']['actual_cue']
        if(registered['occurrence_id'],registered['policy_ref'],registered['policy_revision'],registered['parent_root_grant_ref'],
                registered['parent_root_grant_digest'],registered['original_deadline_utc'],cue['cue_original_ref'],cue['cue_original_digest'])!=(
                occurrence.occurrence_id,occurrence.policy_ref,occurrence.policy_revision,occurrence.parent_root_grant_ref,
                occurrence.parent_root_grant_digest,occurrence.original_deadline_utc,request.cue_original_ref,request.cue_original_digest):
            raise AuthorityUnavailable('Habit maintenance actual registration/cue historical lineage differs')
        if q is not None:
            if occurrence.qualification_original_ref!=q.original_ref:raise AuthorityUnavailable('Habit maintenance occurrence lost actual historical qualification')
            _,qualified=_read_habit_committed_original_v3(inputs,operation_id=q.selector.operation_id,expected_kind='qualify_habit_occurrence_v1')
            if qualified['provenance']['core_qualification']!=plain_v1(q):raise AuthorityUnavailable('Habit maintenance qualification has no actual positive W01')
            if(occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.occurrence_operation_id,
                    occurrence.original_deadline_utc)!=(q.selector.activity_id,q.selector.effect_id,q.selector.attempt_id,
                    q.selector.execution_operation_id,q.selector.original_deadline_utc):raise AuthorityUnavailable('Habit maintenance historical effect/deadline changed')
        elif occurrence.qualification_original_ref is not None:raise AuthorityUnavailable('Habit maintenance omitted an existing actual qualification')
        reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
        if request.operation_kind=='record_habit_miss_v1':
            if(occurrence.state not in{'registered','waiting'}or occurrence.actual_started_at_utc is not None
                    or occurrence.action_intent_ref is not None or occurrence.life_plan_original_ref is not None
                    or now<occurrence.original_deadline_utc):
                raise AuthorityUnavailable('Habit miss requires an actual expired, never-started registered occurrence')
        else:
            if q is None or occurrence.state not in{'qualified','active','unknown'}:raise AuthorityUnavailable('Habit outcome maintenance requires its actual unresolved effect')
            require_habit_maintenance_life_v1(service,inputs,occurrence,request.command)
        inputs.require_for_v3(service=service,permit=permit)
        owner_key=owner_grant_key(*request.namespace.as_tuple);entry=inputs.owner_entry
        guard=ProductionOwnerGuardV1(owner_key.token,inputs.work.heads[owner_key.token][0],canonical_digest(entry.grant),
            entry.head.guard.authorization_head.removeprefix('sha256:'))
        evidence=HabitOriginalMaintenanceCurrentV1(request,permit,current,guard,policy,standing,q,
            GraphVersion(key,atom.revision),canonical_digest(atom.value),occurrence.parent_root_grant_ref,
            occurrence.parent_root_grant_digest,occurrence.original_deadline_utc,inputs.read_versions,
            QueryEpoch(request.namespace,'all',inputs.work.graph_stamp[0]),inputs.work.graph_stamp[1],inputs.work.graph_stamp[2],now)
        return evidence,permit
    finally:inputs.release_v3()
