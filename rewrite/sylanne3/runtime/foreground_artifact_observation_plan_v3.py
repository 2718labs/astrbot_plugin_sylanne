"""Explicit Artifact V3 call contract with independent, phase-bound D07 attempts.

The old V2 contract is validated unchanged after removing only the new typed
observation attempts. The same original six calls and token totals still apply.
"""
from dataclasses import dataclass,fields,replace
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
from .foreground_call_plan_v1 import (ForegroundCallPlanV1,ForegroundCallPlanV2,ForegroundModelAttemptV1,
    ForegroundModelAttemptV2,ForegroundArtifactPhaseGroupV2,foreground_artifact_phase_group_identity_v2,
    foreground_call_plan_from_wire_v2,require_foreground_phase_checkpoint_v2)

SCHEMA='d11.foreground-call-plan.v3'


def artifact_observation_ids_v1(selector,condition_id):
    if (type(selector)is not ArtifactDraftPhaseSelectorV2 or selector.generation
            or(condition_id,selector.phase_kind)not in{('tone','sample_check'),('task_semantics','check')}):
        raise ValueError('independent observation must name its actual semantic check condition')
    marker=canonical_digest((selector,condition_id))[:48]
    operation='artifact-phase-observe:'+marker
    from .d07_execution_v1 import d07_execution_ids_v1
    return {**d07_execution_ids_v1(selector.task.namespace,operation,'concern'),'operation':operation,
        'basis':'artifact-phase-observation-basis:'+marker,'prepare':'artifact-phase-observation-basis:'+marker+':prepare',
        'question':'artifact-phase-observation-question:'+marker,'ticket':'attention:artifact-observation:'+marker}


@dataclass(frozen=True,slots=True,kw_only=True)
class ForegroundArtifactObservationAttemptV3(ForegroundModelAttemptV1):
    phase_selector:ArtifactDraftPhaseSelectorV2
    condition_id:str
    observation_basis_ref:str
    observation_basis_digest:str

    def __post_init__(self):
        ForegroundModelAttemptV1.__post_init__(self)
        ids=artifact_observation_ids_v1(self.phase_selector,self.condition_id)
        digest=self.observation_basis_digest
        if (self.slot!='C3' or self.call_id!=ids['call'] or self.reservation_operation_id!=ids['operation']
                or self.observation_basis_ref!=ids['basis'] or self.original_call_id is not None
                or self.terminal_ref is not None and self.terminal_ref!='d07-terminal:'+ids['call']
                or type(digest)is not str or len(digest)!=64 or any(c not in '0123456789abcdef'for c in digest)):
            raise ValueError('independent observation attempt crossed its actual phase/basis/once identity')


@dataclass(frozen=True,slots=True,kw_only=True)
class ForegroundCallPlanV3(ForegroundCallPlanV2):
    observer_policy_ref:str
    observer_policy_digest:str
    schema:str=SCHEMA

    def __post_init__(self):
        if (self.schema!=SCHEMA or type(self.observer_policy_ref)is not str or not self.observer_policy_ref
                or type(self.observer_policy_digest)is not str or len(self.observer_policy_digest)!=64
                or any(c not in '0123456789abcdef'for c in self.observer_policy_digest)
                or type(self.attempts)is not tuple or len(self.attempts)>6
                or any(type(row)not in{ForegroundModelAttemptV1,ForegroundModelAttemptV2,
                    ForegroundArtifactObservationAttemptV3}for row in self.attempts)
                or len({row.call_id for row in self.attempts})!=len(self.attempts)
                or any(row.slot in {'C5','C6'} for row in self.attempts)
                or sum(row.input_ceiling for row in self.attempts)>48000
                or sum(row.output_ceiling for row in self.attempts)>8000):
            raise ValueError('independent Artifact calls exceed their unchanged whole-episode limits')
        ordinary=tuple(row for row in self.attempts if type(row)is not ForegroundArtifactObservationAttemptV3)
        inherited={f.name:getattr(self,f.name)for f in fields(ForegroundCallPlanV2)}
        ForegroundCallPlanV2(**{**inherited,'schema':'d11.foreground-call-plan.v2','attempts':ordinary})
        observed=set()
        for row in self.attempts:
            if type(row)is not ForegroundArtifactObservationAttemptV3:continue
            selector=row.phase_selector
            if (foreground_artifact_phase_group_identity_v2(selector)!=foreground_artifact_phase_group_identity_v2(self.phase_group.selector)
                    or selector.phase_index>self.phase_group.selector.phase_index or selector.phase_index in observed
                    or row.budget_lease_ref!=self.parent_budget_lease_ref):
                raise ValueError('observation attempt cannot cross or duplicate an actual ordered check phase')
            observed.add(selector.phase_index)
            previous=self.phase_group.completed_phase_originals[selector.phase_index-1]if selector.phase_index else(None,None)
            if (selector.prev_phase_original_ref,selector.prev_phase_original_digest)!=previous:
                raise ValueError('observation lost its immediately preceding verified generation')
            if not any(type(generation)is ForegroundModelAttemptV2
                    and generation.phase_selector.phase_index==selector.phase_index-1
                    and generation.state=='completed'for generation in ordinary):
                raise ValueError('observation requires its actual completed generation call')
        for index in range(len(self.phase_group.completed_phase_originals)):
            from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
            phase=artifact_draft_phase_sequence_v2(self.phase_group.selector.method_ref)[index]
            if phase in{'sample_check','check'}and not any(type(row)is ForegroundArtifactObservationAttemptV3
                    and row.phase_selector.phase_index==index and row.state=='completed'for row in self.attempts):
                raise ValueError('verified semantic check cannot hide its actual completed independent call')
        if len(observed)>2 or len(canonical_serialize(self).encode())>65536:
            raise ValueError('independent observation exceeds the fixed method or continuation bound')


def foreground_call_plan_from_wire_v3(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not dict or set(value)!={f.name for f in fields(ForegroundCallPlanV3)}:
        raise ValueError('V3 independent Artifact call plan fields differ')
    raw=dict(value);observations=[];ordinary=[]
    for encoded in raw['attempts']:
        if 'observation_basis_ref'in encoded:
            if set(encoded)!={f.name for f in fields(ForegroundArtifactObservationAttemptV3)}:
                raise ValueError('V3 observation attempt fields differ')
            row={**encoded,'phase_selector':artifact_draft_from_wire_v2(encoded['phase_selector'],ArtifactDraftPhaseSelectorV2)}
            observations.append(ForegroundArtifactObservationAttemptV3(**row))
        else:ordinary.append(encoded)
    base=foreground_call_plan_from_wire_v2({name:('d11.foreground-call-plan.v2'if name=='schema'else ordinary if name=='attempts'else raw[name])
        for name in ForegroundCallPlanV2.__dataclass_fields__})
    by_call={row.call_id:row for row in (*base.attempts,*observations)}
    result=ForegroundCallPlanV3(**{**{f.name:getattr(base,f.name)for f in fields(ForegroundCallPlanV2)},
        'schema':SCHEMA,'attempts':tuple(by_call[row['call_id']]for row in raw['attempts']),
        'observer_policy_ref':raw['observer_policy_ref'],'observer_policy_digest':raw['observer_policy_digest']})
    if plain_v1(result)!=value:raise ValueError('independent call plan is noncanonical')
    return result


def require_artifact_observation_checkpoint_v3(before,after):
    if type(after)is not ForegroundCallPlanV3:
        if type(before)is ForegroundCallPlanV3:raise ValueError('checkpoint cannot erase its independent observation contract')
        return False
    if type(before)is ForegroundCallPlanV2:
        raise ValueError('old V2 Artifact groups cannot automatically upgrade to V3')
    def base(plan):
        return ForegroundCallPlanV2(**{**{f.name:getattr(plan,f.name)for f in fields(ForegroundCallPlanV2)},
            'schema':'d11.foreground-call-plan.v2',
            'attempts':tuple(row for row in plan.attempts if type(row)is not ForegroundArtifactObservationAttemptV3)})
    if type(before)is ForegroundCallPlanV1:
        require_foreground_phase_checkpoint_v2(before,base(after));return True
    if type(before)is not ForegroundCallPlanV3:
        raise TypeError('unregistered independent observation checkpoint')
    if (before.observer_policy_ref,before.observer_policy_digest)!=(after.observer_policy_ref,after.observer_policy_digest):
        raise ValueError('checkpoint cannot replace its original independent observer policy')
    require_foreground_phase_checkpoint_v2(base(before),base(after))
    by_call={row.call_id:row for row in after.attempts}
    for row in before.attempts:
        if type(row)is ForegroundArtifactObservationAttemptV3:
            current=by_call.get(row.call_id)
            if (type(current)is not ForegroundArtifactObservationAttemptV3 or current.phase_selector!=row.phase_selector
                    or(current.observation_basis_ref,current.observation_basis_digest)!=(row.observation_basis_ref,row.observation_basis_digest)):
                raise ValueError('checkpoint cannot replace an existing observation identity')
    return True


def derive_initial_artifact_observation_plan_v3(db,*,namespace,continuation,selector,issuer,
        installed_bundle,owner_guard,now_utc):
    """Read a selected real D08 first phase against its original message allocation.

    This returns checkpoint metadata only. The existing current W01 checkpoint
    must still verify and commit it before any C4 or D07 job can be prepared.
    """
    from .artifact_receipt_allocation_v3 import read_actual_artifact_receipt_allocation_v3
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    if (type(continuation.call_plan)is not ForegroundCallPlanV1
            or type(selector)is not ArtifactDraftPhaseSelectorV2 or selector.phase_index!=0 or not selector.generation
            or selector.task.namespace!=namespace or selector.task.c02_operation_id!=continuation.c02_operation_id
            or any(row.slot not in {'C1','C2'}for row in continuation.call_plan.attempts)):
        raise ValueError('only an original unstarted Artifact cycle can begin its explicit selected V3 method')
    job,allocation,child,grant=read_actual_artifact_receipt_allocation_v3(db,namespace=namespace,
        c02_operation_id=continuation.c02_operation_id,source_ref=continuation.source_ref,issuer=issuer)
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    responsibility=read_original_foreground_responsibility_for_c09_v1(db,namespace=namespace,job=job,issuer=issuer)
    if (responsibility is None or responsibility.root_registration_ref!=selector.task.root_registration_ref
            or responsibility.owner_guard!=owner_guard or allocation.responsibility_digest!=responsibility.digest):
        raise ValueError('initial method group changed its actual original Root or Owner responsibility')
    observer=require_current_artifact_phase_observer_v2(installed_bundle)
    if (continuation.call_plan.protected_reply_lease_ref!=child.lease_id
            or continuation.call_plan.parent_budget_lease_ref!=allocation.parent_lease_ref
            or child.state!='active' or grant.allowed_work_kinds!=('message',)
            or (allocation.observer_policy_ref,allocation.observer_policy_digest)!=(observer.asset_ref,observer.asset_digest)
            or (allocation.installation_id,allocation.manifest_digest)!=
                (installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest)
            or not now_utc<allocation.valid_until_utc):
        raise ValueError('initial Artifact group lost its actual original allocation and installed observer')
    group=ForegroundArtifactPhaseGroupV2(selector)
    actual=require_current_artifact_phase_group_v2(db,namespace=namespace,group=group,issuer=issuer,
        installed_bundle=installed_bundle,owner_guard=owner_guard)
    if actual!=group:raise ValueError('initial group differs from the actual adopted D08 Decision and Plan')
    result=ForegroundCallPlanV3(continuation.call_plan.parent_budget_lease_ref,
        continuation.call_plan.protected_reply_lease_ref,continuation.call_plan.attempts,phase_group=group,
        observer_policy_ref=observer.asset_ref,observer_policy_digest=observer.asset_digest)
    require_artifact_observation_checkpoint_v3(continuation.call_plan,result)
    return result
