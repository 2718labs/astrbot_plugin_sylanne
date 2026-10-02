"""Permanent installed source-note identity issuance and D08 wire contract.

The freeze seam observes the real runtime's outgoing typed envelope; its
SQL/provider qualification is stubbed here and exercised by installed Life.
"""
from dataclasses import replace
from types import SimpleNamespace as S

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.domains.d08.execution import ActionOutcome
from sylanne3.runtime.d08_source_note_action_v1 import (
    PrepareSourceNoteActionRequestV1, source_note_attempt_id_v1,
)
from sylanne3.runtime import domain_production_runtime_v1 as runtime
from sylanne3.runtime import domain_production_read_plans_v1 as plans
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
)


NS=NamespaceId('bot','persona')


def request():
    def ref(kind,name):return AtomKey(Owner('persona',*NS.as_tuple),kind,name).token
    return PrepareSourceNoteActionRequestV1(*(ref(kind,name) for kind,name in (
        ('d10.life_project.v1','project'),('d10.activity_recipe.v1','recipe'),
        ('memory.source','source'),('d08.goal.v1','goal'),('d03.entity_anchor','target'),('d03.role_binding','role'))))


@pytest.mark.parametrize('kind',['prepare_source_note_action','recheck_action'])
def test_real_runtime_derives_only_source_note_attempt_before_freezing(monkeypatch,kind):
    operation_id='f9ea99d7-4fd9-4909-a1a2-06ef0334577e';req=request()
    envelope=CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity('activity:one','effect:before',operation_id,kind,operation_id,canonical_digest({'input_refs':[]})),
        AuthorityContext('owner','d11','capability',NS,('persona',),'context',('audience',),'policy',1),
        VersionGuard((),(),0,0,'catalogue','scheme','operator','policy',(),(),()),
        SourceQualification((),'reported',0.,0.,'external_report','qualified',None,'not_applicable'),
        (),'lease',100.,100.,'interval',())
    instance=object.__new__(runtime.InstalledDomainOperationRuntimeV1);instance.graph=object()
    monkeypatch.setattr(runtime.InstalledDomainOperationRuntimeV1,'_current',lambda self:None)
    monkeypatch.setattr(runtime,'installed_readers_for_operation_v1',lambda *a,**kw:S())
    monkeypatch.setattr(plans,'read_current_domain_command_identity_v1',lambda *a,**kw:S(effect_id='effect:actual',purpose='consolidation',audience_ref='audience'))
    monkeypatch.setattr(plans,'read_plan_current_domain_operation_v1',lambda *a,**kw:object())
    monkeypatch.setattr(plans,'read_current_domain_original_refs_v1',lambda *a,**kw:())
    monkeypatch.setattr(plans,'read_current_domain_policy_refs_v1',lambda *a,**kw:())
    seen=[]
    class FreezeObserved(Exception):pass
    def freeze(*a,**kw):seen.append(kw['envelope']);raise FreezeObserved()
    monkeypatch.setattr(runtime,'freeze_domain_production_frame_v1',freeze)
    with pytest.raises(FreezeObserved):instance.compile_in_transaction(object(),operation=S(operation_kind=kind,domain='d08'),
        request=req,envelope=envelope,scope=object(),owner=object(),guard=object(),now_utc=0.)
    actual=seen[0].identity
    assert actual.operation_id==operation_id and actual.activity_id==envelope.identity.activity_id
    assert actual.effect_id=='effect:actual'
    if kind=='recheck_action':assert actual.attempt_id==operation_id
    else:
        assert actual.attempt_id==source_note_attempt_id_v1(NS,req.project_ref,operation_id)
        outcome=ActionOutcome('outcome:actual','action:actual',actual.effect_id,actual.attempt_id,
            'completed_verified','verified',('terminal',),(actual.effect_id,),(),'settlement',0.)
        assert outcome.attempt_id==actual.attempt_id


@pytest.mark.parametrize('field',['namespace','project','operation'])
def test_source_note_attempt_is_bound_to_its_actual_root_scope(field):
    req=request();base=source_note_attempt_id_v1(NS,req.project_ref,'operation:one')
    key=AtomKey.from_token(req.project_ref)
    if field=='namespace':
        with pytest.raises(ValueError):source_note_attempt_id_v1(NamespaceId('other','persona'),key.token,'operation:one')
    elif field=='project':assert source_note_attempt_id_v1(NS,replace(key,name='other').token,'operation:one')!=base
    else:assert source_note_attempt_id_v1(NS,key.token,'operation:other')!=base


@pytest.mark.parametrize('attempt',['f9ea99d7-4fd9-4909-a1a2-06ef0334577e','attempt:caller-chosen'])
def test_legacy_or_unbound_plan_attempt_is_rejected_before_current_execution(attempt):
    from sylanne3.runtime.d11_life_preparation_v1 import _plan_current
    class Read:
        frame=S(envelope=S(authority=S(namespace=NS)))
        def head(self,*a,**kw):raise AssertionError('legacy attempt entered current execution reads')
    plan=S(project=S(ref=request().project_ref),operation_id='operation:one',attempt_id=attempt)
    with pytest.raises(ValueError,match='typed source-note attempt'):_plan_current(object(),Read(),plan)


def test_terminal_bundle_keeps_input_provenance_out_of_same_transaction_experience_outputs():
    from sylanne3.runtime.d11_life_adoption_v1 import _bundle
    from sylanne3.runtime_contracts import DomainProposal, DependencySet
    from sylanne3.graph_types import GraphWrite
    from test_d11_life_job_result_binding_v1 import _binding
    b=_binding();input_ref=request().source_ref
    envelope=CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity(b.activity_id,b.effect_id,b.attempt_id,'adopt_life','adopt-operation',canonical_digest({'input_refs':[input_ref]})),
        AuthorityContext('owner','d11','capability',NS,('activity',),'consolidation',('audience',),'policy',1),
        VersionGuard((),(),0,0,'catalogue','scheme','operator','policy',(),(),()),
        SourceQualification((input_ref,),'reported',0.,0.,'external_report','qualified',None,'not_applicable'),
        (input_ref,),'lease',100.,100.,'interval',())
    owner=Owner('activity',*NS.as_tuple,b.activity_id)
    writes=tuple(GraphWrite(AtomKey(owner,kind,name),{}) for kind,name in (
        ('runtime.job',b.job_id),('runtime.cost_settlement','cost'),('d11.life_artifact.v1','artifact')))
    proposal=DomainProposal('d11','fixture.bundle','a'*64,envelope,writes,DependencySet(),(),())
    staged=S(prepared=S(binding=b),envelope=envelope,memory_stage=S(proposals=()),
        runtime_stage=S(proposals=(proposal,)),source_refs=(input_ref,))
    bundle=_bundle(staged)
    assert bundle.experience_refs==()
    assert staged.source_refs==bundle.envelope.source_qualification.source_refs==(input_ref,)
    assert bundle.d11_cost_settlement_refs==(writes[1].key.token,)
    assert bundle.persistent_job_refs==(writes[0].key.token,)
    output_refs=(*bundle.experience_refs,*bundle.choice_refs,*bundle.d02_settlement_refs,
        *bundle.d11_cost_settlement_refs,*bundle.persistent_job_refs,*bundle.outbox_refs)
    assert set(output_refs)<={write.key.token for write in writes}
