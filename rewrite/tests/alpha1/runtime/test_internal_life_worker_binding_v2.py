"""Dual-role codec/transition and real SQLite schema; no worker permission.

The Owner, installation and occurrence are unissued DTOs here. Recomputed
commitments must still pass closed shape checks. Public shape cannot issue a
worker; actual installation/current Owner is exercised by the installed node.
"""
from dataclasses import replace
import sqlite3

import pytest

from test_internal_life_content_acquisition_v1 import acquired_input, transition_fixture, D
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.runtime_contracts import canonical_digest,canonical_serialize
from sylanne3.runtime.internal_life_worker_binding_v2 import (
    InternalLifeWorkerBindingV2,InternalLifeWorkerFrameV2,decode_internal_life_worker_binding_v2,
    require_installed_life_worker_v2)
from sylanne3.runtime.internal_life_content_worker_v2 import (
    OPERATION,PROPOSAL_SCHEMA,PROPOSAL_HASH,TABLE,COLUMNS,
    validate_internal_life_acquisition_proposal_v2,validate_life_worker_inventory_row_v2,
    install_life_worker_schema_v2,require_life_worker_schema_v2,_model,
    require_exact_internal_life_acquisition_issuance_v2)
from sylanne3.host.authority_profile import AdminModelWorkflowV2,installed_model_config_ref
from sylanne3.model_broker.internal_life_content_v1 import WORK_KIND,TEMPLATE_VERSION,thaw_internal_life_content_request_v1
import json


def fixture():
    prepared,frame,_,_=acquired_input()
    frame=replace(frame,envelope=replace(frame.envelope,identity=replace(frame.envelope.identity,phase=OPERATION)))
    b=InternalLifeWorkerBindingV2(prepared.namespace,prepared.installation_id,D,'tls-worker',D,
        OwnerPrincipalV1('owner-idp','account','incarnation'),'owner',D,frame.owner_guard,D,D,
        prepared.digest,prepared.occurrence_digest,prepared.episode_ref,prepared.job_id,
        prepared.prepare_operation_id,prepared.acquire_operation_id,prepared.call_id,
        prepared.quote_digest,prepared.reservation_digest,D,D,12,7,1,prepared.graph_incarnation,30.)
    worker_frame=InternalLifeWorkerFrameV2(frame,b)
    proposal,snapshot=transition_fixture()
    write=proposal.typed_writes[0]
    from sylanne3.graph_types import GraphWrite
    write=GraphWrite(write.key,{**write.value,'lease_holder':b.worker_subject})
    proposal=replace(proposal,envelope=frame.envelope,proposal_schema=PROPOSAL_SCHEMA,
        proposal_schema_hash=PROPOSAL_HASH,typed_writes=(write,))
    return prepared,worker_frame,proposal,snapshot


def test_closed_binding_preserves_separate_roles_and_cross_version_once_ids():
    p,f,proposal,snapshot=fixture();raw=plain_v1(f.binding)
    assert decode_internal_life_worker_binding_v2(raw)==f.binding
    assert f.binding.owner_actor!=f.binding.worker_subject
    assert f.owner_frame.envelope.authority.actor==f.binding.owner_actor
    assert validate_internal_life_acquisition_proposal_v2(proposal,snapshot,f.binding) is proposal
    assert (f.binding.job_id,f.binding.call_id,f.binding.acquire_operation_id)==(p.job_id,p.call_id,p.acquire_operation_id)
    row=(*p.namespace.as_tuple,'binding',p.job_id,canonical_serialize(raw),canonical_digest(raw),D)
    assert validate_life_worker_inventory_row_v2(COLUMNS,row)==raw
    with pytest.raises(ValueError,match='active installed'):
        require_exact_internal_life_acquisition_issuance_v2(None,object(),object())
    with pytest.raises(ValueError,match='active installed'):
        require_installed_life_worker_v2(f.binding,object())


@pytest.mark.parametrize('field,value',[
    ('activation_generation',True),('graph_epoch',0),('graph_revision',False),
    ('job_id','life-content-job:new'),('acquire_operation_id','new-caller-op'),
    ('purpose','expression'),('schema','d06.internal-life-worker-binding.v1'),
    ('deadline_utc',True),('manifest_digest','invalid'),('episode_ref','not-a-token')])
def test_rehashed_binding_rejects_closed_field_drift(field,value):
    _,f,_,_=fixture();raw=plain_v1(f.binding);raw[field]=value
    with pytest.raises((ValueError,TypeError)):
        decode_internal_life_worker_binding_v2(raw)


@pytest.mark.parametrize('change',['owner','worker','job','nontransition','schema'])
def test_transition_refuses_role_swap_and_unrelated_mutation(change):
    _,f,p,snapshot=fixture()
    if change=='owner':p=replace(p,envelope=replace(p.envelope,authority=replace(p.envelope.authority,actor=f.binding.worker_subject)))
    elif change=='schema':p=replace(p,proposal_schema='d11.internal-life-content-acquisition.proposal.v1')
    else:
        from sylanne3.graph_types import GraphWrite
        w=p.typed_writes[0];v=dict(w.value)
        if change=='worker':v['lease_holder']=f.binding.owner_actor
        elif change=='job':v['operation_id']=f.binding.acquire_operation_id
        else:v['cancel_epoch']=True
        p=replace(p,typed_writes=(GraphWrite(w.key,v),))
    with pytest.raises(ValueError):validate_internal_life_acquisition_proposal_v2(p,snapshot,f.binding)


def test_worker_frame_rejects_owner_namespace_and_original_deadline_drift():
    _,f,_,_=fixture()
    with pytest.raises(ValueError):replace(f,binding=replace(f.binding,owner_actor='another-owner'))
    with pytest.raises(ValueError):replace(f,binding=replace(f.binding,deadline_utc=41.))
    with pytest.raises(ValueError):replace(f,binding=replace(f.binding,activation_generation=2))


def test_actual_sql_schema_and_transaction_rollback_keep_no_partial_inventory():
    with sqlite3.connect(':memory:') as db:
        db.execute('BEGIN');install_life_worker_schema_v2(db)
        require_life_worker_schema_v2(db)
        db.rollback()
        assert db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TABLE,)).fetchone() is None
        install_life_worker_schema_v2(db)
        db.execute(f'DROP TRIGGER {TABLE}_no_delete')
        with pytest.raises(ValueError,match='exact DDL'):require_life_worker_schema_v2(db)


def test_model_request_is_worker_held_but_original_owner_envelope_is_unchanged():
    from sylanne3.runtime.jobs import PersistentJob
    p,f,proposal,_=fixture();v=proposal.typed_writes[0].value
    job=PersistentJob(p.job_id,p.prepare_operation_id,p.activity_id,None,*p.namespace.as_tuple,
        'snapshot','running',WORK_KIND,{},None,'2026-10-02T00:00:00Z','lease','provider:installed',{},
        f.binding.worker_subject,'2026-10-02T00:00:00Z',1,0,{},None)
    workflow=AdminModelWorkflowV2(WORK_KIND,'provider','model',installed_model_config_ref('provider','model',D),
        D,'consolidation',('owner',),'private',TEMPLATE_VERSION,('text',),20.,1024,{'output_tokens':1024})
    frozen=thaw_internal_life_content_request_v1(json.loads(p.frozen_json))
    model=_model(f,p,frozen,workflow,job)
    assert model.envelope.authority.actor==job.lease_holder=='tls-worker'
    assert f.owner_frame.envelope.authority.actor=='owner'
    assert model.identity.phase=='internal_life_content_v2'
    assert model.call_id==p.call_id and model.envelope.deadline_utc==30.
    assert model.envelope.authority.capability_ref=='life-worker-binding:'+f.binding.digest
