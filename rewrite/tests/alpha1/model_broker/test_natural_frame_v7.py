"""V7 pure semantic/codec boundaries over the existing declared software seam.

No installed Source, Owner, Corecounter, Native CPU or paid permission is claimed.
Root runs these necessary permanent cases only after the whole source compiles.
"""
from dataclasses import asdict,fields,replace
import json
import pytest

from test_natural_frame_v6 import materials,collect_software_pages
from sylanne3.runtime.installed_d13_natural_frame_v6 import build_natural_frame_v6
from sylanne3.runtime.installed_d13_natural_frame_v7 import build_natural_frame_v7
from sylanne3.model_broker import natural_reply_history_v6 as v6,natural_reply_history_v7 as v7
from sylanne3.runtime_contracts import canonical_serialize


def test_v7_full_provenance_semantics_and_strict_crossparse(monkeypatch):
    base,plan,question,window=materials(65)
    collection,_=collect_software_pages(monkeypatch,window)
    args=dict(collection=collection,plan=plan,question=question,installation=base.installation,
        frozen_at_utc=100.0,expires_at_utc=130.0,policy_digest='9'*64)
    old,_=build_natural_frame_v6(**args);new,_=build_natural_frame_v7(**args)
    assert new.input.history_selection.read_set==old.input.history_selection.read_set
    assert new.input.history_selection.source_dependencies==old.input.history_selection.source_dependencies
    assert len(new.input.recent_history)==65 and len(collection.pages)==2
    stable,dynamic=(json.loads(message.content) for message in new.messages[1:])
    assert 'read_set' not in dynamic['history_selection'] and 'source_dependencies' not in dynamic['history_selection']
    assert set(dynamic['history_selection'])=={'order_watermark','coverage','gaps'}
    assert len(dynamic['speaker_dictionary'])==1 and dynamic['speaker_dictionary'][0]['speaker_ref']=='software-speaker'
    assert all(row['speaker_key']=='s0' for row in dynamic['recent_history'])
    unit=dynamic['qualified_units'][0]
    for name in ('polarity_status','uncertainty','source_excerpt','semantic_constraints','speaker_id'):
        assert unit[name]==json.loads(canonical_serialize(asdict(new.input.plan.units[0])))[name]
    assert set(unit)==set(v7.UNIT_SEMANTIC_FIELDS_V7)
    assert v7.thaw_natural_reply_request_v7(json.loads(canonical_serialize(asdict(new))))==new
    for parser,frozen in ((v6.parse_natural_reply_output_v6,new),(v7.parse_natural_reply_output_v7,old)):
        with pytest.raises(ValueError):parser('{}',frozen)
    with pytest.raises(ValueError):v6.thaw_natural_reply_request_v6(json.loads(canonical_serialize(asdict(new))))
    with pytest.raises(ValueError):v7.thaw_natural_reply_request_v7(json.loads(canonical_serialize(asdict(old))))
    changed_unit=replace(new.input.plan.units[0],qualification_digest='8'*64)
    changed=v7.freeze_natural_reply_request_v7(replace(new.input,plan=replace(new.input.plan,units=(changed_unit,))),new.installation)
    assert changed.frozen_input_digest!=new.frozen_input_digest and changed.model_request_digest!=new.model_request_digest
    assert json.loads(changed.messages[-1].content)['qualified_units']==dynamic['qualified_units']


def test_v7_template_container_rejects_registered_other_version():
    from sylanne3.host.authority_profile import AdminModelWorkflowV2,installed_model_config_ref
    from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
    from sylanne3.host.model_workflows_v7 import AdminModelWorkflowsV7
    from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
    from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
    from sylanne3.runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2
    def workflow(kind,purpose,template):
        return AdminModelWorkflowV2(kind,'provider','model',installed_model_config_ref('provider','model','a'*64),
            'a'*64,purpose,('owner','conversation'),'private',template,('text',),120.0,1024,
            {'input_tokens':6000,'output_tokens':1024,'model_tokens':7024,'model_microusd':100})
    values=dict(encode=workflow('d06.encode_source','consolidation',FIRST_INGRESS_ENCODING_TEMPLATE_VERSION),
        reply=workflow('reply','proposal',REPLY_TEMPLATE_VERSION),natural_generation=workflow('natural_generation','proposal',v7.TEMPLATE_VERSION),
        natural_review=workflow('natural_review','proposal',NATURAL_REPLY_REVIEW_WORKFLOW_V2),artifact_draft=None,
        d07_relationship_cognition=None,growth_cognition=None)
    new=AdminModelWorkflowsV7(7,**values)
    with pytest.raises(ValueError):AdminModelWorkflowsV6(6,**values)
    with pytest.raises(ValueError):replace(new,natural_generation=replace(new.natural_generation,template_version=v6.TEMPLATE_VERSION))
    with pytest.raises(ValueError):replace(new,version=6)


def test_v7_http_template_counts_actual_httpx_bytes_and_only_one_late_slot(monkeypatch):
    import httpx
    from sylanne3.model_broker.d13_provider_http_template_v1 import (
        provider_http_template_v1,provider_http_body_v1,serialize_provider_http_v1,SERIALIZER_FINGERPRINT)
    base,plan,question,window=materials(2)
    collection,_=collect_software_pages(monkeypatch,window)
    frozen,_=build_natural_frame_v7(collection=collection,plan=plan,question=question,installation=base.installation,
        frozen_at_utc=100.0,expires_at_utc=130.0,policy_digest='9'*64)
    template=provider_http_template_v1(frozen,generation_call_id='actual-software-call',
        billing_contract_digest='b'*64,serializer_pin=SERIALIZER_FINGERPRINT)
    first=provider_http_body_v1(template,request_digest='a'*64)
    actual=httpx.Request('POST','https://fixture.invalid/v1/chat/completions',json=first).content
    assert actual==serialize_provider_http_v1(template,request_digest='a'*64)
    assert len(actual)==template.byte_count
    second=provider_http_body_v1(template,request_digest='f'*64)
    other=httpx.Request('POST','https://fixture.invalid/v1/chat/completions',json=second).content
    assert len(other)==len(actual) and other!=actual
    assert set(first)=={'model','messages','stream','max_completion_tokens','metadata'}
    assert first['metadata']['sylanne_call_id']=='actual-software-call'
    assert first['metadata']['sylanne_billing_contract']=='b'*64
    for bad in ('a'*63,'A'*64,'z'*64):
        with pytest.raises(ValueError):provider_http_body_v1(template,request_digest=bad)
    with pytest.raises(ValueError):replace(template,late_path=('model','id'))
    with pytest.raises(ValueError):provider_http_template_v1(frozen,generation_call_id='actual-software-call',
        billing_contract_digest='b'*64,serializer_pin='0'*64)
    changed=replace(template,billing_contract_digest='c'*64)
    assert changed.template_digest!=template.template_digest


@pytest.mark.asyncio
async def test_v7_actual_openai_sdk_transport_checks_late_bytes_before_send(monkeypatch):
    """Actual SDK serialization and MockTransport; no installed/paid qualification."""
    import httpx
    from openai import AsyncOpenAI
    from test_broker import request as model_request
    from sylanne3.host.astrbot_model_call import _checked_d13_http_client_v1,_D13ProviderHTTPRejectedV1
    from sylanne3.model_broker.d13_provider_http_template_v1 import provider_http_template_v1,SERIALIZER_FINGERPRINT
    base,plan,question,window=materials(2)
    collection,_=collect_software_pages(monkeypatch,window)
    frozen,_=build_natural_frame_v7(collection=collection,plan=plan,question=question,installation=base.installation,
        frozen_at_utc=100.0,expires_at_utc=130.0,policy_digest='9'*64)
    payload={'provider_id':frozen.installation.provider_id,'model':frozen.installation.model_id,
        'messages':[{'role':m.role,'content':m.content} for m in frozen.messages],
        'max_output_tokens':frozen.installation.max_output_tokens}
    request=model_request(call_id='actual-sdk-call',provider_id=frozen.installation.provider_id,
        model_id=frozen.installation.model_id,payload=payload,max_output_tokens=frozen.installation.max_output_tokens,
        prompt_template_digest=v7.TEMPLATE_DIGEST)
    template=provider_http_template_v1(frozen,generation_call_id=request.call_id,
        billing_contract_digest='b'*64,serializer_pin=SERIALIZER_FINGERPRINT)
    sent=[];order=[]
    async def transport(actual):
        order.append("transport")
        sent.append(actual.content)
        return httpx.Response(200,json={'id':'mock-only','object':'chat.completion','created':1,
            'model':request.model_id,'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}})
    actual_client=httpx.AsyncClient(transport=httpx.MockTransport(transport))
    sdk=AsyncOpenAI(api_key='local-fixture-only',base_url='https://fixture.invalid/v1',http_client=actual_client,max_retries=0)
    captures=[]
    async def core_capture(content):
        assert len(captures)==1 and sent==[]
        order.append("core_capture")
    checked=_checked_d13_http_client_v1(actual_client,template=template,model_request=request,
        current_binding=lambda:True,observations=captures,core_binding=core_capture)
    call=sdk.with_options(http_client=checked,max_retries=0)
    kwargs={'model':request.model_id,'messages':payload['messages'],'stream':False,
        'max_completion_tokens':request.max_output_tokens,'metadata':{'sylanne_call_id':request.call_id,
            'sylanne_request_digest':request.digest,'sylanne_billing_contract':'b'*64}}
    try:
        result=await call.chat.completions.create(**kwargs)
        assert result.id=='mock-only' and len(sent)==1 and len(captures)==1
        assert order==["core_capture","transport"]
        import hashlib
        assert captures[0]==(request.call_id,request.digest,template.template_digest,hashlib.sha256(sent[0]).hexdigest(),len(sent[0]))
        for current,changed in [(True,True),(False,False)]:
            negative=[]
            wrapper=_checked_d13_http_client_v1(actual_client,template=template,model_request=request,
                current_binding=lambda current=current:current,observations=negative)
            try:
                args=dict(kwargs)
                if changed:args['metadata']={**args['metadata'],'sylanne_request_digest':'c'*64}
                reason='actual SDK wire differs' if changed else 'current provider changed'
                with pytest.raises(_D13ProviderHTTPRejectedV1,match=reason) as failure:
                    await sdk.with_options(http_client=wrapper,max_retries=0).chat.completions.create(**args)
                if changed:assert isinstance(failure.value.__cause__,ValueError)
                assert len(sent)==1 and negative==[]
            finally:await wrapper.aclose()
        refusal=[]
        async def core_refuse(content):
            raise ValueError('software Core binding refused')
        refused=_checked_d13_http_client_v1(actual_client,template=template,model_request=request,
            current_binding=lambda:True,observations=refusal,core_binding=core_refuse)
        try:
            with pytest.raises(ValueError,match='software Core binding refused'):
                await sdk.with_options(http_client=refused,max_retries=0).chat.completions.create(**kwargs)
            assert len(refusal)==1 and len(sent)==1
        finally:await refused.aclose()
        with pytest.raises(_D13ProviderHTTPRejectedV1,match='original SDK wire already consumed'):
            await call.chat.completions.create(**kwargs)
        assert len(sent)==1
    finally:
        await checked.aclose()
        assert not actual_client.is_closed
        await sdk.close()



def _signed_v7_counter_originals():
    """Actual Ed25519 software originals and controlled boundary times only."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from sylanne3.runtime_contracts import canonical_digest,NamespaceId,VersionedRef
    from sylanne3.authority_service.d13_core_counter_contract_v1 import (
        InstalledD13WirePolicyV7,D13CoreFrameIntentHeaderV7,D13CurrentWireCountSelectorV1,
        D13CoreFullWireEvidenceV1,D13CoreFullWireEnvelopeV1,SIGNING_DOMAIN)
    from sylanne3.graph_types import AtomKey,Owner
    from sylanne3.graph_coordinator import namespace_ref
    base,_,_,_=materials(2)
    private=Ed25519PrivateKey.generate()
    policy=InstalledD13WirePolicyV7(base.installation,
        private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
        'software-counter-key','software-policy',1,*(['1'*64]*5),7024,0,1,1,1,0)
    frame=D13CoreFrameIntentHeaderV7(
        install_id=base.installation.installation_id,authority_id='software-authority',
        authority_namespace=namespace_ref(NamespaceId('bot','persona')),namespace=NamespaceId('bot','persona'),
        frame_intent_id='software-frame',frame_intent_digest='2'*64,counter_operation_id='software-counter',
        counter_nonce='software-nonce',c02_operation_id='software-c02',plan_ref=VersionedRef(AtomKey(Owner('activity','bot','persona','software-activity'),
            'd08.natural_expression_plan.v2','software-plan').token,1),
        job_id='software-job',step_index=0,generation_call_id='software-call',activation_generation=1,
        storage_generation=0,selected_manifest_digest='3'*64,selected_pointer_version=0,
        owner_responsibility_digest='4'*64,owner_grant_digest='5'*64,source_scope_digest='6'*64,
        parent_budget_lease_ref='software-lease',budget_grant_digest='7'*64,cpu_reservation_ref='software-reservation',
        cpu_reservation_digest='8'*64,policy_digest=policy.policy_digest,template_digest=policy.template_digest,
        collection_digest='9'*64,collection_snapshot_commitment='a'*64,
        blockset_digest=canonical_digest({'schema':'sylanne3.d13.core-paid-blockset.v7','bindings':[]}),
        billing_contract_digest='b'*64,frozen_at_utc=100.0,expires_at_utc=130.0,
        prospective_plan_deadline_utc=130.0,raw_authority_digest='c'*64,compressed_authority_digest=None,
        raw_http_template_digest='d'*64,compressed_http_template_digest=None)
    selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,frame.frame_intent_id,
        frame.frame_intent_digest,frame.counter_operation_id,frame.raw_authority_digest,None,
        frame.raw_http_template_digest,None)
    payload=D13CoreFullWireEvidenceV1(frame,selector.selector_digest,frame.raw_authority_digest,None,
        'e'*64,None,frame.raw_http_template_digest,None,256,None,'bounded_full_wire',64,64,None,None,
        *(['1'*64]*5),'software-execution','2'*64,'3'*64,'4'*64,'5'*64,1000,
        'software-settlement','6'*64,'7'*64,'8'*64)
    signature=base64.b64encode(private.sign(SIGNING_DOMAIN+canonical_serialize(asdict(payload)).encode('utf-8'))).decode('ascii')
    envelope=D13CoreFullWireEnvelopeV1(payload,policy.counter_key_id,signature)
    return policy,frame,selector,envelope


def test_v7_historical_counter_signature_does_not_revive_current_lifetime():
    from cryptography.exceptions import InvalidSignature
    from sylanne3.authority_service.d13_core_counter_contract_v1 import (
        verify_signed_d13_core_wire_evidence_v1,verify_historical_d13_core_wire_origin_v1)
    policy,frame,selector,envelope=_signed_v7_counter_originals()
    payload=envelope.payload
    assert verify_signed_d13_core_wire_evidence_v1(policy,envelope,selector=selector,frame=frame,now_utc=100.0)==payload
    assert verify_historical_d13_core_wire_origin_v1(policy,envelope,selector=selector,frame=frame)==payload
    # All identities, signatures and pair commitments remain valid in these negatives.
    for now in (99.999,130.0,131.0):
        with pytest.raises(ValueError,match='original lifetime'):
            verify_signed_d13_core_wire_evidence_v1(policy,envelope,selector=selector,frame=frame,now_utc=now)
    with pytest.raises(ValueError,match='another scope'):
        verify_historical_d13_core_wire_origin_v1(replace(policy,installation=replace(policy.installation,
            installation_id='other-installation')),envelope,selector=selector,frame=frame)
    with pytest.raises(ValueError,match='another scope'):
        verify_historical_d13_core_wire_origin_v1(policy,envelope,
            selector=replace(selector,counter_operation_id='other-counter'),frame=frame)
    altered=replace(envelope,payload=replace(payload,raw_upper_tokens=65))
    with pytest.raises(InvalidSignature):
        verify_historical_d13_core_wire_origin_v1(policy,altered,selector=selector,frame=frame)



def test_v7_imported_core_evidence_has_real_schema_inventory_and_exact_identity(tmp_path):
    """A signed software original exercises the real installer and migration codec."""
    import sqlite3
    from cryptography.exceptions import InvalidSignature
    from sylanne3.graph_store import GraphStore
    from sylanne3.graph_types import TypeRegistry
    from sylanne3.authority_service.d13_wire_evidence_v7 import (
        TABLE, install_d13_core_wire_evidence_schema_v1, record_signed_d13_core_wire_evidence_v1)
    from sylanne3.runtime.graph_migration_snapshot_v1 import _inventory
    from sylanne3.runtime.domain_production_erasure_v1 import (
        TABLE_COLUMNS, DomainProductionErasureHold, _validate_derived_store_row_v6,
        _derived_wire_metadata_members_v6, _derived_fact_primary_key_v6,
        validate_domain_production_schema_v1)
    policy,frame,selector,envelope=_signed_v7_counter_originals()
    store=GraphStore(tmp_path/'v7-original.db',TypeRegistry())
    try:
        db=store._db
        install_d13_core_wire_evidence_schema_v1(db)
        db.execute('BEGIN IMMEDIATE')
        assert record_signed_d13_core_wire_evidence_v1(db,policy=policy,selector=selector,
            frame=frame,envelope=envelope,now_utc=100.0)==envelope.evidence_digest
        db.commit()
        row=db.execute('SELECT * FROM '+TABLE).fetchone()
        result=_validate_derived_store_row_v6(TABLE,TABLE_COLUMNS[TABLE],row)
        assert result[:2]==('derived_core_wire_evidence',frame.frame_intent_id)
        assert _derived_wire_metadata_members_v6(TABLE,result[2])==()
        assert _derived_fact_primary_key_v6(TABLE)==('bot','persona','frame_intent_id')
        entries={name:(columns,rows)for name,columns,rows in _inventory(db,frame.namespace)}
        assert entries[TABLE]==(TABLE_COLUMNS[TABLE],(row,))
        for index,value in ((0,'other-bot'),(2,'other-frame'),(3,'0'*64),
                (4,'0'*64),(5,'other-c02')):
            changed=list(row);changed[index]=value
            with pytest.raises(DomainProductionErasureHold,match='V7 imported counter'):
                _validate_derived_store_row_v6(TABLE,TABLE_COLUMNS[TABLE],tuple(changed))
        db.execute('BEGIN IMMEDIATE')
        altered=replace(envelope,payload=replace(envelope.payload,raw_upper_tokens=65))
        with pytest.raises(InvalidSignature):
            record_signed_d13_core_wire_evidence_v1(db,policy=policy,selector=selector,
                frame=frame,envelope=altered,now_utc=100.0)
        db.rollback()
        assert db.execute('SELECT * FROM '+TABLE).fetchall()==[row]
        for statement in ('UPDATE '+TABLE+' SET policy_digest=policy_digest','DELETE FROM '+TABLE):
            with pytest.raises(sqlite3.IntegrityError,match='immutable Core V7 full-wire original'):
                db.execute(statement)
        db.rollback()
        assert validate_domain_production_schema_v1(db)
        db.execute('CREATE INDEX unregistered_v7 ON '+TABLE+'(frame_intent_id)')
        with pytest.raises(DomainProductionErasureHold,match='production index/trigger definitions differ'):
            validate_domain_production_schema_v1(db)
    finally:
        store.close()



@pytest.mark.parametrize('version', [6, 7])
def test_current_output_dispatch_keeps_semantic_version_and_frozen_identity(monkeypatch, version):
    from test_natural_reply import output
    from sylanne3.model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1
    from sylanne3.domains.d09.natural_reply import NATURAL_REPLY_OUTPUT_SCHEMA_V3
    base, plan, question, window = materials(2)
    collection, _ = collect_software_pages(monkeypatch, window)
    builder = build_natural_frame_v6 if version == 6 else build_natural_frame_v7
    frozen, _ = builder(collection=collection, plan=plan, question=question,
        installation=base.installation, frozen_at_utc=100.0, expires_at_utc=130.0, policy_digest='9'*64)
    body = output()
    body.update(schema=NATURAL_REPLY_OUTPUT_SCHEMA_V3,
                semantic_segments=[{'start': 0, 'end': len(body['body'])}])
    text = json.dumps(body)
    parsed = parse_natural_reply_output_current_v1(text, frozen)
    assert parsed.status == 'untrusted_content_candidate'
    assert parsed.frozen_input_digest == frozen.frozen_input_digest
    assert parsed.d09_payload() == body
    with pytest.raises(ValueError, match='shape'):
        parse_natural_reply_output_current_v1(json.dumps(output()), frozen)
    with pytest.raises(ValueError, match='frozen original differs'):
        parse_natural_reply_output_current_v1(text, replace(frozen, frozen_input_digest='f'*64))
    class UnknownFrozen(type(frozen)):
        pass
    values = {field.name: getattr(frozen, field.name) for field in fields(frozen)}
    with pytest.raises(TypeError, match='unknown natural generation original version'):
        parse_natural_reply_output_current_v1(text, UnknownFrozen(**values))
