"""Permanent pure contract boundaries for explicit independent Artifact observation.

These do not certify installed execution, paid originals or Sender acceptance.
"""
from dataclasses import replace,fields
from hashlib import sha256
import pytest
from sylanne3.domains.d01 import TONE_SAMPLE_METHOD_V1
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_types import AtomKey,Owner
from sylanne3.runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from sylanne3.model_broker.artifact_draft_v1 import (
    artifact_draft_task_selector_v1,ArtifactDraftPhaseSelectorV2,
    artifact_draft_phase_original_ref_v2,artifact_draft_model_ids_v2)
from sylanne3.runtime.foreground_call_plan_v1 import (
    ForegroundModelAttemptV1,ForegroundModelAttemptV2,ForegroundCallPlanV1,
    ForegroundCallPlanV2,ForegroundArtifactPhaseGroupV2)
from sylanne3.runtime.foreground_artifact_observation_plan_v3 import (
    ForegroundCallPlanV3,ForegroundArtifactObservationAttemptV3,
    artifact_observation_ids_v1,foreground_call_plan_from_wire_v3,
    require_artifact_observation_checkpoint_v3)
from sylanne3.runtime.artifact_phase_observation_v1 import semantic_observation_status_v1
from sylanne3.host.artifact_phase_observer_policy_v2 import (
    ArtifactPhaseObserverPolicyV2,artifact_phase_observer_from_asset_v2)


def _method():
    task=artifact_draft_task_selector_v1(NamespaceId('bot','persona'),c02_operation_id='c02:test',root_registration_ref='root:test')
    owner=AtomKey.from_token(task.cycle_job_ref).owner
    decision=AtomKey(owner,'d08.decision_record.v2','decision:test').token
    plan=AtomKey(owner,'d08.personal_plan.v1','plan:test').token
    selectors=[];completed=[];attempts=[]
    for index,phase in enumerate(('tone_sample','sample_check','full','check')):
        previous=completed[-1] if completed else (None,None)
        selector=ArtifactDraftPhaseSelectorV2(task,decision,1,'1'*64,plan,1,'2'*64,
            TONE_SAMPLE_METHOD_V1,index,phase,*previous)
        selectors.append(selector)
        if selector.generation:
            ids=artifact_draft_model_ids_v2(selector)
            attempts.append(ForegroundModelAttemptV2('C4',ids['call'],None,ids['prepare'],'3'*64,
                'lease:root',6000,1000,'completed',ids['result'],phase_selector=selector))
        else:
            condition='tone' if phase=='sample_check' else 'task_semantics'
            ids=artifact_observation_ids_v1(selector,condition)
            attempts.append(ForegroundArtifactObservationAttemptV3('C3',ids['call'],None,ids['operation'],
                '4'*64,'lease:root',6000,1000,'completed','d07-terminal:'+ids['call'],
                phase_selector=selector,condition_id=condition,observation_basis_ref=ids['basis'],observation_basis_digest='5'*64))
        completed.append((artifact_draft_phase_original_ref_v2(selector)+':verified',str(index+1)*64))
    front=tuple(ForegroundModelAttemptV1(slot,'call:'+slot,None,'reserve:'+slot,'6'*64,
        'lease:root',6000,800,'completed','terminal:'+slot) for slot in ('C1','C2'))
    group=ForegroundArtifactPhaseGroupV2(selectors[-1],tuple(completed))
    return ForegroundCallPlanV3('lease:root','lease:receipt',(*front,*attempts),phase_group=group,
        observer_policy_ref='/installed/observer.json',observer_policy_digest='7'*64)


def test_tone_sample_two_generations_two_observations_remain_six_and_roundtrip():
    plan=_method()
    assert len(plan.attempts)==6
    assert [a.slot for a in plan.attempts]==['C1','C2','C4','C3','C4','C3']
    assert foreground_call_plan_from_wire_v3(plain_v1(plan))==plan


def test_old_v2_is_not_upgraded_by_a_checkpoint():
    plan=_method()
    ordinary=tuple(a for a in plan.attempts if type(a)is not ForegroundArtifactObservationAttemptV3)
    before=ForegroundCallPlanV2(plan.parent_budget_lease_ref,plan.protected_reply_lease_ref,ordinary,phase_group=plan.phase_group)
    with pytest.raises(ValueError,match='old V2'):
        require_artifact_observation_checkpoint_v3(before,plan)


@pytest.mark.parametrize('slot',['C5','C6'])
def test_receipt_only_plan_cannot_add_natural_model_calls(slot):
    plan=_method()
    attempt=ForegroundModelAttemptV1(slot,'new:'+slot,None,'reserve:new','8'*64,'lease:receipt',100,100,'reserved')
    with pytest.raises(ValueError,match='unchanged whole-episode'):
        replace(plan,attempts=(*plan.attempts[1:],attempt))


def test_completed_check_cannot_omit_or_borrow_its_actual_observation():
    plan=_method()
    with pytest.raises(ValueError,match='completed independent call'):
        replace(plan,attempts=tuple(a for a in plan.attempts if type(a)is not ForegroundArtifactObservationAttemptV3))
    observation=plan.attempts[-1]
    foreign=replace(observation,budget_lease_ref='lease:other')
    with pytest.raises(ValueError,match='cross or duplicate'):
        replace(plan,attempts=(*plan.attempts[:-1],foreign))
    with pytest.raises(ValueError,match='once identity'):
        replace(observation,original_call_id='call:old')


def _finding(stance='support',status='supported',unknowns=()):
    return {'proposition':'condition_satisfied','current':True,'stance':stance,
        'evidence_status':status,'meaningful_unknowns':unknowns}


@pytest.mark.parametrize('rows,expected',[
    ((),'unknown'),((_finding(),),'satisfied'),
    ((_finding('oppose','refuted'),),'violated'),
    ((_finding(),_finding('oppose','refuted')),'conflicting'),
    ((_finding(),_finding('suspend','insufficient')),'unknown'),
    ((_finding(),_finding(unknowns=('missing source',))),'unknown'),
    ((_finding(),_finding(status='conflicted')),'conflicting')])
def test_consumer_combines_every_actual_finding(rows,expected):
    assert semantic_observation_status_v1(rows)==expected


def test_installed_rubric_asset_contains_no_per_content_answers(tmp_path):
    spec=ArtifactPhaseObserverPolicyV2('observer:test',1,str(tmp_path.resolve()/'observer.json'),'a'*64,'b'*64)
    raw={k:v for k,v in plain_v1(spec).items() if k not in {'asset_ref','asset_digest'}}
    encoded=canonical_serialize(raw).encode()
    actual=artifact_phase_observer_from_asset_v2(asset_ref=spec.asset_ref,asset_bytes=encoded,expected_digest=sha256(encoded).hexdigest())
    assert actual.workflow_digest==spec.workflow_digest and actual.completion_mode=='artifact_receipt_only'
    tampered={**raw,'cases':[{'status':'satisfied'}]};encoded=canonical_serialize(tampered).encode()
    with pytest.raises(ValueError,match='closed rubric'):
        artifact_phase_observer_from_asset_v2(asset_ref=spec.asset_ref,asset_bytes=encoded,expected_digest=sha256(encoded).hexdigest())
