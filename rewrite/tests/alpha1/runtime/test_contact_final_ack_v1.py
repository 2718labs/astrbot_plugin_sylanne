"""Permanent Contact COMMIT/ACK control-flow seam with real Owner SQL helper.

The actual ProductionGraphStore, Owner attempt DDL, transaction, private call,
stage issuance and before-finish/ACK functions run. Authority authentication,
Owner grants and the comprehensive qualification SQL decoder are bounded local
fixture seams (the latter has its separate permanent regressions). This is not
installed adoption acceptance or proof of the blocked immutable batch route.
There are no HTTP/model/platform clients, credentials or external calls.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import time
from types import SimpleNamespace as S

import pytest

from test_contact_qualification_evidence_v1 import qualification_fixture_values
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime import contact_final_ack_v1 as ack
from sylanne3.runtime import contact_final_stage_v1 as stage
from sylanne3.runtime.domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
from sylanne3.runtime_contracts import AuthorityContext, SnapshotRequirementsV2, canonical_serialize


class LocalAuthority:
    def __init__(self, store, evidence):
        self.store=store;self.evidence=evidence;self.permit=None;self.state='active'
        self.events=[];self.ack=True;self.drift=None

    def _outside(self):
        assert not self.store._lock._is_owned() and not self.store._db.in_transaction

    def current_anchor(self, **kwargs):
        self._outside();return self.evidence.effect_snapshot.anchor

    def begin_fence(self, **kwargs):
        self._outside();self.events.append('begin')
        assert self.permit is None
        self.permit=FencePermitV2('authority','authority:fixture','subject',kwargs['holder'],1,
            'write',kwargs['operation_id'],'1'*64,1,0,kwargs['expected_anchor'])
        return self.permit

    def get_fence_operation(self, **kwargs):
        self._outside();self.events.append('get:'+self.state)
        return self.permit,self.state

    def validate_fence(self, scope):
        self._outside();return self.permit

    def read_ingress_clock(self, policy):
        self._outside();return S(utc_upper_bound_seconds=1.,monotonic_after_seconds=time.monotonic())

    def read_current_effect(self, **kwargs):
        self._outside();self.events.append('effect')
        return replace(self.evidence.current_effect,effect_id='wrong-effect') if self.drift=='effect' else self.evidence.current_effect

    def read_current_effect_snapshot_for_write_fence(self, **kwargs):
        self._outside();self.events.append('snapshot')
        return replace(self.evidence.effect_snapshot,permit_digest='sha256:'+'b'*64) if self.drift=='snapshot' else self.evidence.effect_snapshot

    def finish_fence(self, scope, **kwargs):
        self._outside();assert scope.permit==self.permit
        self.events.append('finish')
        if self.ack:self.state='finished'


@pytest.fixture
def owner_call(tmp_path,monkeypatch):
    evidence,_=qualification_fixture_values();ns=evidence.namespace
    store=ProductionGraphStore(tmp_path/'owner.sqlite',TypeRegistry())
    port=LocalAuthority(store,evidence);bootstrap=object()
    graph=GraphCoordinator(store,bootstrap,holder='holder',content_fence_v2=port)
    a=evidence.effect_snapshot.anchor
    target=SnapshotRequirementsV2(ns,a.authority_id,a.namespace,a.activation_generation,
        a.deletion_journal_id,a.deletion_seq,a.deletion_digest,a.execution_journal_id,
        a.execution_seq,a.execution_digest,a.revocation_epoch,'fixture-incarnation')
    store.install_graph_recovery_genesis(target,_capability=store._coordinator_capability)
    store._db.execute('CREATE TABLE fixture_contact_commit(value TEXT NOT NULL)')
    authority=AuthorityContext('owner','d08','fixture-grant',ns,('activity',),'expression',('user',),'policy',1)
    owner=S(capabilities=('fixture-contact',),principal='owner',target_admission=None,storage_admission=None)
    graph._GraphCoordinator__owner_leases['lease']=owner
    graph._GraphCoordinator__owner_session_proofs['lease']=object()
    monkeypatch.setattr(GraphCoordinator,'_authorize',lambda *args,**kwargs:None)
    monkeypatch.setattr(GraphCoordinator,'_owner_binding_in_fence',lambda *args,**kwargs:(object(),owner))
    monkeypatch.setattr(GraphCoordinator,'_owner_graph_binding_locked',lambda *args,**kwargs:owner)
    runtime=object.__new__(InstalledDomainOperationRuntimeV1);runtime.graph=graph
    graph._GraphCoordinator__domain_production_runtime_v1=runtime
    request=stage.PrepareCurrentContactDispatchRequestV1('contact:fixture')
    call=ack.issue_contact_owner_call_v1(runtime,authority=authority,lease='lease',request=request,
        operation_id='operation',request_digest='a'*64)
    result=dict(schema='sylanne.domain-production-receipt.v1',operation_kind='prepare_contact_dispatch',
        operation_id='operation',fixture='durable')
    state=S(evidence=evidence,proof_drift=False,stage=True,sql_drift=False)

    # Keep a real independent read-only SQL snapshot around the actual saved
    # attempt and business rows. Comprehensive typed joins run in the separate
    # qualification evidence tests, not in this bounded control-flow fixture.
    def readonly(actual,result_value):
        if actual is not call or result_value!=result:
            raise ValueError('fixture independent committed result identity differs')
        with store._lock:
            assert not store._db.in_transaction
            store._db.execute('BEGIN')
            try:
                row=store._db.execute('SELECT request_digest,receipt_json FROM graph_owner_domain_attempts_v3').fetchone()
                assert row==(call.request_digest,canonical_serialize(result))
                assert store._db.execute('SELECT value FROM fixture_contact_commit').fetchall()==[('committed',)]
                port.events.append('readback')
                if state.sql_drift:raise ValueError('fixture independent SQL drift')
                return evidence
            finally:store._db.rollback()
    monkeypatch.setattr(ack,'_readonly',readonly)

    @contextmanager
    def context(scope,guard,current_owner):
        runtime._active_contact_final_command_v1=(request,'operation')
        runtime._active_contact_final_scope_v1=scope
        runtime._active_contact_final_stage_call_v1=object()
        runtime._active_contact_final_effect_v1=evidence.current_effect
        current_policy=(replace(evidence.owner_policy,owner_head_digest='sha256:'+'b'*64)
            if state.proof_drift else evidence.owner_policy)
        runtime._active_current_contact_policy_v1=S(scope=scope,original=current_policy)
        runtime._active_contact_final_stage_v1=None
        if state.stage:
            frame=S(envelope=S(identity=S(operation_id='operation')))
            bundle=object();clock=port.read_ingress_clock(None)
            material=stage._ContactFinalMaterialV1(runtime,object(),request,frame,scope,current_owner,guard,
                object(),runtime._active_current_contact_policy_v1,evidence.current_effect,evidence.effect_snapshot,
                clock,object(),object(),object(),object(),runtime._active_contact_final_stage_call_v1,(),bundle)
            for field,value in (('owner',current_owner),('guard',guard),('clock',clock),('effect_snapshot',evidence.effect_snapshot)):
                setattr(runtime,'_active_contact_final_'+field+'_v1',value)
            stage._publish_material(material);stage._QUALIFIED[id(material)]=evidence
            runtime._active_contact_final_stage_v1=stage.ContactFinalStageV1(material,object(),evidence.qualification,bundle,object())
        try:yield
        finally:
            stage.revoke_contact_final_material_v1(runtime)
            runtime._active_contact_final_stage_v1=None
            runtime._active_contact_final_scope_v1=None

    def commit(db,*args):
        assert db.in_transaction;port.events.append('commit')
        db.execute("INSERT INTO fixture_contact_commit VALUES('committed')")
        return result

    def invoke():
        return graph._owner_domain_write_v3(authority,'lease',operation_id=call.operation_id,
            request_digest=call.request_digest,domains=('d08',),capability='fixture-contact',
            commit=commit,fence_context=context)

    # Read fence authenticity is another explicit fixture seam; the actual
    # recovery observer and repeated SQL read still run and must see true ACK.
    def current_read(self,reader,**kwargs):
        assert port.state=='finished'
        scope=S(permit=port.permit,pinned_anchor=a,generation=1,namespace=ns,authority_namespace=a.namespace)
        kwargs['fence_observer'](scope)
        return reader()
    monkeypatch.setattr(GraphCoordinator,'_read_v2',lambda self,actual,reader,**kwargs:current_read(self,reader,**kwargs))
    graph._GraphCoordinator__c04_authority_port_v3=S(contact_policy=lambda *args,**kwargs:evidence.owner_policy)
    try:yield S(store=store,graph=graph,runtime=runtime,call=call,result=result,state=state,port=port,invoke=invoke)
    finally:
        stage.revoke_contact_final_material_v1(runtime)
        runtime._active_contact_owner_call_v1=call
        ack.revoke_contact_owner_call_v1(runtime);store.close()


def _durable(c):
    assert not c.store._db.in_transaction
    assert c.store._db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3').fetchone()==(canonical_serialize(c.result),)
    assert c.store._db.execute('SELECT value FROM fixture_contact_commit').fetchall()==[('committed',)]


@pytest.mark.parametrize('failure',('sql','owner','effect','snapshot','missing_stage'))
def test_actual_commit_readback_failure_keeps_receipt_and_does_not_finish(owner_call,failure):
    c=owner_call
    if failure=='sql':c.state.sql_drift=True
    if failure=='owner':c.state.proof_drift=True
    if failure in ('effect','snapshot'):c.port.drift=failure
    if failure=='missing_stage':c.state.stage=False
    with pytest.raises(ValueError):c.invoke()
    _durable(c);assert 'finish' not in c.port.events and c.port.state=='active'
    assert c.port.events.count('commit')==1


def test_actual_commit_independent_readback_precedes_true_finish_and_return(owner_call):
    c=owner_call;assert c.invoke()==c.result;_durable(c)
    assert c.port.events.index('commit')<c.port.events.index('readback')<c.port.events.index('finish')
    assert c.port.events[-1]=='get:finished'


def test_finish_without_authenticated_ack_keeps_commit_and_does_not_return(owner_call):
    c=owner_call;c.port.ack=False
    with pytest.raises(ValueError,match='authenticated Authority finish ACK'):c.invoke()
    _durable(c);assert c.port.events.count('finish')==1 and c.port.state=='active'


def test_saved_pending_retry_only_reads_same_commit_and_finishes_original(owner_call):
    c=owner_call;c.state.sql_drift=True
    with pytest.raises(ValueError):c.invoke()
    _durable(c);c.state.sql_drift=False;c.state.stage=False
    assert c.invoke()==c.result;_durable(c)
    assert c.port.events.count('begin')==1 and c.port.events.count('commit')==1
    assert c.port.events.count('finish')==1 and c.port.state=='finished'


def test_saved_finished_retry_has_no_new_begin_commit_or_finish(owner_call):
    c=owner_call;assert c.invoke()==c.result;before=tuple(c.port.events)
    assert c.invoke()==c.result;_durable(c)
    for event in ('begin','commit','finish'):assert c.port.events.count(event)==before.count(event)


@pytest.mark.parametrize('tamper',('request','result','permit','unissued_call'))
def test_saved_recovery_refuses_durable_identity_or_unissued_invocation(owner_call,tamper):
    c=owner_call;c.state.sql_drift=True
    with pytest.raises(ValueError):c.invoke()
    c.state.sql_drift=False;c.state.stage=False
    if tamper=='request':c.store._db.execute("UPDATE graph_owner_domain_attempts_v3 SET request_digest='changed'")
    if tamper=='result':
        c.store._db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=?',(canonical_serialize(dict(c.result,fixture='changed')),))
    if tamper=='permit':
        raw=json.loads(c.store._db.execute('SELECT permit_json FROM graph_owner_domain_attempts_v3').fetchone()[0]);raw['holder']='changed'
        c.store._db.execute('UPDATE graph_owner_domain_attempts_v3 SET permit_json=?',(canonical_serialize(raw),))
    if tamper=='unissued_call':
        c.runtime._active_contact_owner_call_v1=replace(c.call)
    with pytest.raises((ValueError,RuntimeError)):c.invoke()
    assert c.port.events.count('finish')==0 and c.port.events.count('commit')==1
