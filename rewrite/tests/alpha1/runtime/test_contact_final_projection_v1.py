"""Permanent Contact private lifecycle and closed C09 evidence refusals.

The SQL lifecycle seam uses a real GraphStore/SAVEPOINT with a fixture mutable
atom and exact concrete runtime classes. Paired-clock/anchor and frame content
are bounded local fixture values; this does not authenticate Authority or prove
six-provider/full installed adoption, whose immutable batch conflict is HOLD.
No provider HTTP client, model, platform sender or Authority RPC is constructed.
"""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace as S
import time

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, NamespaceEpoch, Owner, TypeRegistry, TypeSpec
from sylanne3.runtime import contact_final_projection_v1 as projection
from sylanne3.runtime import contact_final_stage_v1 as stage
from sylanne3.runtime.domain_production_erasure_v1 import DomainProductionErasureHold, validate_domain_stage_provenance_v1
from sylanne3.runtime.domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import FenceScope, NamespaceId, canonical_digest

NS = NamespaceId('bot','persona')

@pytest.fixture
def sql_stage(tmp_path, monkeypatch):
    registry = TypeRegistry()
    registry.register(TypeSpec('fixture.contact.sql',('activity',),'state',lambda value: value))
    store = GraphStore(tmp_path/'fixture.sqlite', registry)
    capability = object();store._coordinator_capability = capability
    graph = object.__new__(GraphCoordinator)
    graph._GraphCoordinator__store = store
    graph._GraphCoordinator__graph_capability = capability
    runtime = object.__new__(InstalledDomainOperationRuntimeV1);runtime.graph = graph
    graph._GraphCoordinator__domain_production_runtime_v1 = runtime
    anchor = RestoreAnchor('authority','authority:fixture',1,'deletion',0,'genesis','execution',0,'genesis',0,'fixture-proof')
    permit = FencePermitV2('authority','authority:fixture','subject','holder',1,'write','attempt', '1'*64,1,0,anchor)
    epoch = NamespaceEpoch(*NS.as_tuple,0)
    scope = FenceScope(NS,'authority:fixture',1,'write','attempt',permit,anchor,epoch,4)
    key = AtomKey(Owner('activity',*NS.as_tuple,'activity'),'fixture.contact.sql','member')
    write = GraphWrite(key,{'generation':1})
    envelope = S(authority=S(namespace=NS,activation_generation=1),identity=S(operation_id='operation',effect_id='effect',activity_id='activity'),
        deadline_utc=10000.,local_monotonic_deadline=time.monotonic()+100,version_guard=S(read_versions=(GraphVersion(key,0),)))
    frame = S(envelope=envelope,activation_generation=1,snapshot=GraphSnapshot((GraphAtom(key,0,{},False),),(epoch,)),now_utc=1.)
    content = S(activity_id='activity',segments=(S(operation_id='operation',segment=S(effect_id='effect')),),digest='c'*64)
    material = stage._ContactFinalMaterialV1(runtime,S(operation_kind='prepare_contact_dispatch'),stage.PrepareCurrentContactDispatchRequestV1('contact:fixture'),
        frame,scope,object(),object(),content,object(),object(),object(),S(utc_upper_bound_seconds=1.,monotonic_after_seconds=time.monotonic()),
        object(),object(),object(),object(),object(),(('fixture',write),))
    runtime._active_contact_final_stage_call_v1=material.stage_call
    runtime._active_contact_final_command_v1=(material.request,'operation')
    runtime._active_contact_final_scope_v1=scope
    for field, value in [('owner',material.owner),('guard',material.owner_guard),('clock',material.clock_reading),('effect',material.current_effect),('effect_snapshot',material.effect_snapshot)]:
        setattr(runtime,'_active_contact_final_'+field+'_v1',value)
    stage._publish_material(material)
    # Only the anchor comparison and metadata R are fixture seals. E and all
    # event/member history are read from actual SQLite rows at every check.
    monkeypatch.setattr(GraphCoordinator,'_anchor_matches',staticmethod(lambda requirements, actual: actual == anchor))
    def stamp(self, namespace):
        row = store._db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',namespace.as_tuple).fetchone()
        return S(graph_revision=4,requirements=object()),NamespaceEpoch(*namespace.as_tuple,row[0] if row else 0)
    monkeypatch.setattr(GraphCoordinator,'_v2_graph_stamp',stamp)
    try:yield material,store,write
    finally:
        stage.revoke_contact_final_material_v1(runtime)
        store._db.close()


def _witness(material,store,phase,receipt=None):
    witness=projection._ContactProjectionWitnessV1(material.runtime,material.runtime.graph,store._db,material.scope,material,phase,receipt,None)
    projection._ACTIVE[id(witness)]=witness
    return witness


def test_actual_savepoint_phase_history_and_rollback(sql_stage):
    m,store,write=sql_stage
    with store._lock:
        store._db.execute('BEGIN')
        before=_witness(m,store,'pre_e')
        try:
            projection._require(before,store._db)
            with stage._provisional(m,store._db,m.provisional_writes) as receipt:
                projected=_witness(m,store,'provisional_e_plus_1',receipt)
                try:
                    projection._require(projected,store._db)
                    assert store._db.execute('SELECT revision FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone()==(1,)
                finally:projection._ACTIVE.pop(id(projected))
            projection._require(before,store._db)
            for table in ('graph_atoms','graph_history','graph_events'):
                assert store._db.execute('SELECT count(*) FROM '+table).fetchone()==(0,)
            assert not stage._RECEIPTS
        finally:
            projection._ACTIVE.pop(id(before));store._db.rollback()


@pytest.mark.parametrize('tamper',['history_bool','history_event','receipt_clone','receipt_duplicate','wrong_phase'])
def test_projected_receipt_requires_actual_event_exact_member_and_phase(sql_stage,tamper):
    m,store,_=sql_stage
    with store._lock:
        store._db.execute('BEGIN')
        try:
            with stage._provisional(m,store._db,m.provisional_writes) as receipt:
                if tamper=='history_bool':store._db.execute('UPDATE graph_history SET value=?',('{"generation":true}',))
                if tamper=='history_event':store._db.execute('UPDATE graph_history SET event_id=?',('foreign-operation',))
                actual=replace(receipt) if tamper=='receipt_clone' else receipt
                if tamper=='receipt_duplicate':actual=replace(receipt,revisions=receipt.revisions*2)
                witness=_witness(m,store,'post_cas_e_plus_1' if tamper=='wrong_phase' else 'provisional_e_plus_1',actual)
                try:
                    with pytest.raises(ValueError):projection._require(witness,store._db)
                finally:projection._ACTIVE.pop(id(witness))
        finally:store._db.rollback()


@pytest.mark.parametrize('boundary',['unissued_clone','revoke','missing_transaction','missing_lock','changed_stage_call','wrong_bundle','expired_local'])
def test_private_reader_cannot_escape_its_current_installed_sql_stage(sql_stage,boundary):
    m,store,_=sql_stage
    with store._lock:
        store._db.execute('BEGIN')
        witness=_witness(m,store,'pre_e')
        if boundary=='unissued_clone':witness=replace(witness,material=replace(m));projection._ACTIVE[id(witness)]=witness
        if boundary=='revoke':stage.revoke_contact_final_material_v1(m.runtime)
        if boundary=='changed_stage_call':m.runtime._active_contact_final_stage_call_v1=object()
        if boundary=='wrong_bundle':witness=replace(witness,bundle=object());projection._ACTIVE[id(witness)]=witness
        if boundary=='expired_local':m.frame.envelope.local_monotonic_deadline=time.monotonic()-1
        if boundary=='missing_transaction':store._db.rollback()
        try:
            if boundary!='missing_lock':
                with pytest.raises(ValueError):projection._require(witness,store._db)
        finally:
            if boundary!='missing_lock':projection._ACTIVE.clear();store._db.rollback()
    if boundary=='missing_lock':
        try:
            with pytest.raises(ValueError):projection._require(witness,store._db)
        finally:projection._ACTIVE.clear();store._db.rollback()


def _provenance():
    from test_contact_qualification_evidence_v1 import qualification_fixture_values
    return qualification_fixture_values()[1]


def test_c09_decodes_exact_finite_contact_first_inventory():
    proof=_provenance()
    expected=tuple(sorted(row['ref'] for row in proof['qualification_evidence']['members']))
    assert validate_domain_stage_provenance_v1('d08','prepare_contact_dispatch',proof)==expected
    assert stage.validate_contact_final_provenance_v1(proof)==expected


@pytest.mark.parametrize('change',['extra','missing','bool_revision','duplicate','foreign_namespace','foreign_activity','wrong_job','bad_digest','partial'])
def test_c09_rejects_contact_provenance_scope_or_inventory_tampering(change):
    proof=deepcopy(_provenance());members=proof['write_commitments']
    if change=='extra':proof['approved']=True
    if change=='missing':del proof['qualification_digest']
    if change=='bool_revision':members[0]['revision']=True
    if change=='duplicate':members[1]=deepcopy(members[0])
    if change=='foreign_namespace':
        key=AtomKey.from_token(members[0]['ref']);members[0]['ref']=AtomKey(Owner('activity','other','persona','activity'),key.type_name,key.name).token
    if change=='foreign_activity':
        key=AtomKey.from_token(members[0]['ref']);members[0]['ref']=AtomKey(Owner('activity',*NS.as_tuple,'other'),key.type_name,key.name).token
    if change=='wrong_job':proof['job_ref']=proof['outbox_ref']
    if change=='bad_digest':members[0]['digest']='z'*64
    if change=='partial':members.pop()
    with pytest.raises(DomainProductionErasureHold):validate_domain_stage_provenance_v1('d08','prepare_contact_dispatch',proof)


@pytest.mark.parametrize('position',[True,-1,1,3,'0'])
def test_final_command_never_accepts_later_or_untyped_segment(position):
    with pytest.raises(ValueError):stage.PrepareCurrentContactDispatchRequestV1('contact:fixture',position)


def test_current_generic_reader_cannot_issue_contact_provider_checks():
    from sylanne3.runtime.contact_qualification_v1 import issue_contact_checks_locked_v1
    with pytest.raises(ValueError,match='private installed'):
        issue_contact_checks_locked_v1(None,None,None,None,current_read=object(),stage=None,route=None,context=None,
            d02_issuer=None,d11_issuer=None,quote=None,grant=None,current_policy=None,current_effect=None,effect_snapshot=None,
            now_utc=1.,valid_until_utc=2.)


def _expression_seam():
    """Real Source-family SQL checks, bounded frame/paid-reader fixture seam."""
    from dataclasses import dataclass
    import json, sqlite3
    from sylanne3.domains.d09 import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate
    from sylanne3.domains.d09.contact_batch_v1 import ContactReviewedContentV1, ContactReviewedSegmentV1
    from sylanne3.memory_types import SourceRecord, source_key, access_key
    from sylanne3.domains.d06 import source_correction_head_key
    from sylanne3.runtime_contracts import SourceQualification
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOperationLimitsV1
    from sylanne3.runtime.d01_production_operations_v1 import CurrentDomainReadV1
    @dataclass(frozen=True)
    class Envelope:
        source_qualification:object
        input_refs:tuple
        identity:object
        authority:object
    @dataclass(frozen=True)
    class Frame:
        snapshot:object
        envelope:object
        limits:object
    class FamilySqlRead(CurrentDomainReadV1):
        def __init__(self,frame):self.frame=frame
    atoms=[]
    for source_id,purposes,audiences in [('claim',('expression',),('user:one',)),('route',('context',),('user:one',)),('structural',('context',),('owner',))]:
        record=SourceRecord(source_id,'fixture text','user:one','reported','reported',None,1.,source_id,audiences,purposes)
        atoms.extend((GraphAtom(source_key(*NS.as_tuple,source_id),1,record.to_dict()),
            GraphAtom(access_key(*NS.as_tuple,source_id),1,dict(source_id=source_id,audiences=list(audiences),purposes=list(purposes),status='active',recorded_at=1.)),
            GraphAtom(source_correction_head_key(NS,source_id),0,{},False)))
    snapshot=GraphSnapshot(tuple(atoms),(NamespaceEpoch(*NS.as_tuple,0),))
    roots=tuple(source_key(*NS.as_tuple,x).token for x in ('claim','route','structural'))
    env=Envelope(SourceQualification(roots,'derived',None,1.,'inference','ineligible',None,'not_applicable'),roots,
        S(canonical_input_digest=canonical_digest(roots)),S(namespace=NS,purpose='expression',audience=('user:one',)))
    frame=Frame(snapshot,env,ProductionOperationLimitsV1())
    claim=ExpressionClaim('claim:one','fixture text',ClaimKind.REPORTED_CLAIM,(roots[0],),('user:one',),('expression',),'fixture-disclosure')
    segment=SegmentCandidate('segment:one','effect:one','fixture text',(ClaimUse(claim.claim_id,0,12,claim.kind),),(),(),0.)
    reviewed=ContactReviewedSegmentV1(0,'operation:one',segment,'a'*64,None,(claim,))
    content=ContactReviewedContentV1(NS,'contact:one','activity',GraphVersion(AtomKey(Owner('activity',*NS.as_tuple,'activity'),'d08.contact_expression_plan.v1','plan'),1),
        'a'*64,'b'*64,'c'*64,(),'d'*64,'user:one','scene:one',(),snapshot.versions,None,None,(reviewed,),100.,0)
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE graph_atoms(token TEXT PRIMARY KEY,bot TEXT,persona TEXT,revision INTEGER,value TEXT,valid INTEGER)')
    for atom in atoms:
        if atom.revision:db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)',(atom.key.token,*NS.as_tuple,atom.revision,json.dumps(atom.value),1))
    return frame,content,db,roots,FamilySqlRead


def test_expression_claim_roots_preserve_context_only_route_and_structural_closure():
    from sylanne3.runtime.structural_source_closure_v1 import read_current_structural_source_closure_v1
    frame,content,db,roots,reader=_expression_seam()
    try:
        narrowed=stage._contact_expression_frame_v1(frame,content)
        assert narrowed.snapshot is frame.snapshot and narrowed.envelope.input_refs==roots
        assert narrowed.envelope.identity.canonical_input_digest==frame.envelope.identity.canonical_input_digest
        assert narrowed.envelope.source_qualification.source_refs==(roots[0],)
        read=reader(narrowed)
        assert set(read.source_family(db,narrowed.envelope.source_qualification.source_refs,purpose='expression',audience='user:one'))=={roots[0]}
        assert set(read.source_family(db,(roots[1],),purpose='context',audience='user:one'))=={roots[1]}
        structural,heads=read_current_structural_source_closure_v1(db,narrowed.snapshot,NS,(roots[2],))
        assert len(structural)==2 and len(heads)==1
    finally:db.close()


def test_expression_claim_still_requires_actual_source_permission():
    import json
    from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
    frame,content,db,roots,reader=_expression_seam()
    try:
        atoms=[]
        for atom in frame.snapshot.atoms:
            value=dict(atom.value)
            if atom.key.owner.subject=='claim' and atom.revision:value['purposes']=['context']
            updated=replace(atom,value=value);atoms.append(updated)
            db.execute('UPDATE graph_atoms SET value=? WHERE token=?',(json.dumps(value),atom.key.token))
        frame=replace(frame,snapshot=replace(frame.snapshot,atoms=tuple(atoms)))
        narrowed=stage._contact_expression_frame_v1(frame,content)
        with pytest.raises(MissingProductionOriginalV1,match='permission'):
            reader(narrowed).source_family(db,narrowed.envelope.source_qualification.source_refs,purpose='expression',audience='user:one')
    finally:db.close()


def test_expression_roots_cannot_be_substituted_by_caller_frame_or_unsigned_claim():
    frame,content,db,roots,_=_expression_seam()
    try:
        caller=replace(frame,envelope=replace(frame.envelope,source_qualification=replace(frame.envelope.source_qualification,source_refs=(roots[1],))))
        assert stage._contact_expression_frame_v1(caller,content).envelope.source_qualification.source_refs==(roots[0],)
        fake_claim=replace(content.segments[0].claims[0],source_refs=(roots[1],))
        fake=replace(content,segments=(replace(content.segments[0],claims=(fake_claim,)),),read_versions=tuple(v for v in content.read_versions if v.key.token!=roots[1]))
        with pytest.raises(ValueError,match='signed/current source binding'):stage._contact_expression_frame_v1(frame,fake)
    finally:db.close()


def test_c09_empty_contact_final_provenance_is_not_a_legacy_empty_variant():
    with pytest.raises(DomainProductionErasureHold):validate_domain_stage_provenance_v1('d08','prepare_contact_dispatch',{})
