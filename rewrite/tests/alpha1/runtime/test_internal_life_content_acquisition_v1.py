"""Closed acquired-input codec and deadline cases; no installed permission.

The occurrence, frame and workflow here are unissued typed fixtures. Real
Owner/Source/GCP acquisition is covered by the installed integration node.
"""
from dataclasses import replace
import json

import pytest

from test_internal_life_content_v1 import frozen_fixture, prepared_fixture, D
from sylanne3.host.authority_profile import AdminModelWorkflowV2, installed_model_config_ref
from sylanne3.runtime_contracts import AuthorityContext, CommandEnvelope, OperationIdentity, RUNTIME_SCHEMA, SourceQualification, VersionGuard, QueryEpoch, canonical_digest, canonical_serialize
from sylanne3.runtime.domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOwnerGuardV1
from sylanne3.graph_types import GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.internal_life_content_worker_v1 import _acquired_model_request
from sylanne3.runtime.reply_model_job import reply_request_wire_v1
from sylanne3.runtime.c09_internal_life_content_v1 import COLUMNS, validate_internal_life_content_inventory_row_v1
from sylanne3.model_broker.internal_life_content_v1 import WORK_KIND, TEMPLATE_VERSION


def acquired_input():
    frozen=frozen_fixture(); prepared=prepared_fixture(frozen);ns=prepared.namespace
    workflow=AdminModelWorkflowV2(WORK_KIND,'provider','model',installed_model_config_ref('provider','model',D),
        D,'consolidation',('owner',),'private',TEMPLATE_VERSION,('text',),20.,1024,{'output_tokens':1024})
    job=PersistentJob(prepared.job_id,prepared.prepare_operation_id,prepared.activity_id,None,*ns.as_tuple,
        'snapshot','running',WORK_KIND,{},None,'2026-10-02T00:00:00Z','lease','provider:installed',{},
        'owner','2026-10-02T00:00:00Z',1,0,{},None)
    key=job_graph_write(job).key
    envelope=CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity(prepared.activity_id,None,prepared.acquire_operation_id,'acquire_internal_life_content',
            prepared.acquire_operation_id,canonical_digest({'input_refs':[]})),
        AuthorityContext('owner','d11','unissued',ns,('activity',),'consolidation',('owner',),'policy',1),
        VersionGuard((GraphVersion(key,1),),(QueryEpoch(ns,'namespace',7),),0,0,'catalogue','scheme','operator','policy',(),(),()),
        SourceQualification((),'derived',None,3.,'inference','ineligible',None,'not_applicable'),
        (),'lease',40.,400.,'interval',())
    frame=CurrentOperationFrameV1(envelope,GraphSnapshot((GraphAtom(key,1,{},True),),(NamespaceEpoch(*ns.as_tuple,7),)),
        3.,ProductionOwnerGuardV1(owner_grant_key(*ns.as_tuple).token,1,D,D),1,(),(),())
    model=_acquired_model_request(frame,prepared,frozen,workflow,job)
    raw={'schema':'d06.internal-life-content-request.v1','prepared_digest':prepared.digest,
        'request_digest':model.digest,'worker_fence':1,'wire':canonical_serialize(reply_request_wire_v1(model.envelope,model))}
    return prepared,frame,model,raw


def validate(prepared,raw):
    return validate_internal_life_content_inventory_row_v1(COLUMNS,
        (*prepared.namespace.as_tuple,'request',prepared.job_id,canonical_serialize(raw),canonical_digest(raw),D))


def test_complete_acquired_input_roundtrip_preserves_typed_reads_and_shrinks_deadline():
    prepared,frame,model,raw=acquired_input()
    assert validate(prepared,raw)==raw
    assert model.identity.phase=='internal_life_content'
    assert model.envelope.version_guard.read_versions[0].revision==2
    assert model.envelope.version_guard.query_epochs[0].revision==8
    assert model.envelope.deadline_utc==30.
    assert model.envelope.monotonic_deadline==390.<frame.envelope.monotonic_deadline
    assert 'historical_reads' not in canonical_serialize(model.payload)


@pytest.mark.parametrize('change',('bool_fence','unknown','wrong_digest','phase'))
def test_rehashed_acquired_input_still_rejects_closed_field_drift(change):
    prepared,_,model,raw=acquired_input()
    if change=='bool_fence':raw['worker_fence']=True
    elif change=='unknown':raw['grant_current']=True
    elif change=='wrong_digest':raw['request_digest']='b'*64
    else:
        changed=replace(model,envelope=replace(model.envelope,identity=replace(model.identity,phase='first_ingress_c02')))
        raw['request_digest']=changed.digest
        raw['wire']=canonical_serialize(reply_request_wire_v1(changed.envelope,changed))
    with pytest.raises(ValueError):validate(prepared,raw)


def transition_fixture():
    from sylanne3.runtime_contracts import DomainProposal, DependencySet
    from sylanne3.graph_types import GraphWrite
    from sylanne3.runtime.internal_life_content_worker_v1 import PROPOSAL_SCHEMA,PROPOSAL_HASH
    prepared,frame,model,_=acquired_input()
    job=PersistentJob(prepared.job_id,prepared.prepare_operation_id,prepared.activity_id,None,*prepared.namespace.as_tuple,
        'snapshot','queued',WORK_KIND,{},None,'2026-10-02T00:00:00Z','lease','provider:installed',{},
        None,None,0,0,{},None)
    before=job_graph_write(job)
    running=job_graph_write(replace(job,phase='running',lease_holder='owner',lease_expires_utc='2026-10-02T00:00:00Z',fence=1))
    snapshot=GraphSnapshot((GraphAtom(before.key,1,before.value,True),),frame.snapshot.epochs)
    proposal=DomainProposal('d11',PROPOSAL_SCHEMA,PROPOSAL_HASH,frame.envelope,(running,),DependencySet(),(),())
    return proposal,snapshot


def test_transition_retains_prepare_identity_and_public_shape_never_issues_witness():
    from sylanne3.runtime.internal_life_content_worker_v1 import validate_internal_life_acquisition_proposal_v1,require_exact_internal_life_acquisition_issuance_v1
    proposal,snapshot=transition_fixture()
    assert validate_internal_life_acquisition_proposal_v1(proposal,snapshot) is proposal
    assert proposal.typed_writes[0].value['operation_id']!=proposal.envelope.identity.operation_id
    with pytest.raises(ValueError,match='active installed'):
        require_exact_internal_life_acquisition_issuance_v1(None,object(),object())


@pytest.mark.parametrize('field',('operation_id','parent_budget_lease_ref','usage_digest','fence'))
def test_transition_rejects_other_charge_or_nontransition_job_fields(field):
    from sylanne3.graph_types import GraphWrite
    from sylanne3.runtime.internal_life_content_worker_v1 import validate_internal_life_acquisition_proposal_v1
    proposal,snapshot=transition_fixture()
    write=proposal.typed_writes[0];value=dict(write.value)
    value[field]={'operation_id':proposal.envelope.identity.operation_id,'parent_budget_lease_ref':'another-lease',
        'usage_digest':'b'*64,'fence':True}[field]
    changed=replace(proposal,typed_writes=(GraphWrite(write.key,value),))
    with pytest.raises(ValueError):validate_internal_life_acquisition_proposal_v1(changed,snapshot)


def test_transition_rejects_a_missing_current_queued_head():
    from sylanne3.runtime.internal_life_content_worker_v1 import validate_internal_life_acquisition_proposal_v1
    proposal,snapshot=transition_fixture()
    with pytest.raises(ValueError):
        validate_internal_life_acquisition_proposal_v1(proposal,GraphSnapshot((),snapshot.epochs))


def test_existing_job_registration_cannot_be_issued_by_public_shape():
    from sylanne3.runtime.internal_life_content_worker_v1 import require_internal_life_acquisition_job_registration_v1
    with pytest.raises(ValueError,match='actual installed witness'):
        require_internal_life_acquisition_job_registration_v1(None,None)
