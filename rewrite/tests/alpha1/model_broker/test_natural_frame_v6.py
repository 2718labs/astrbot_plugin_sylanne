"""V6 pagination/frame software boundaries; source inventory is a declared typed seam.



The actual collector, strict snapshot/cursor logic, producer, freeze/thaw and full

JSON writer run here. No current Owner/Source/paid/tokenizer installation claim

is made. Signed counter numbers below are codec vectors only; no paid verifier,

installed tokenizer result, selected model permission or budget is substituted.

"""

from dataclasses import asdict, replace

import json

import sqlite3

import pytest



from test_natural_reply import frozen

from sylanne3.graph_types import AtomKey, Owner

from sylanne3.memory_types import source_key, access_key

from sylanne3.runtime_contracts import CompletedTurnV1, ConversationWindowProjectionV1, VersionedRef, canonical_serialize

from sylanne3.runtime import d13_current_collection_v6 as collector

from sylanne3.runtime.installed_d13_natural_frame_v6 import build_natural_frame_v6, NaturalHistoryPairV6

from sylanne3.model_broker.natural_reply_history_v6 import thaw_natural_reply_request_v6, TEMPLATE_VERSION

from sylanne3.authority_service.d13_wire_evidence_v6 import InstalledD13WirePolicyV6, d13_full_wire_count_request_v6





def materials(total):

    base=frozen()

    scene=VersionedRef(AtomKey(Owner('scene','bot','persona',base.input.plan.scene_id),'scene.test','binding').token,1)

    audience=VersionedRef(AtomKey(Owner('scene','bot','persona',base.input.plan.audience_id),'audience.test','account').token,1)

    plan=replace(base.input.plan,scene_ref=scene,audience_ref=audience)

    question=replace(base.input.question,audience_ref=audience)

    turns=tuple(CompletedTurnV1(plan.audience_id,audience,i,

        VersionedRef(AtomKey(Owner('scene','bot','persona',plan.scene_id),'d13.turn_completion.v2',str(i)).token,1),

        VersionedRef(source_key('bot','persona','software-turn-'+str(i)).token,1),

        VersionedRef(access_key('bot','persona','software-turn-'+str(i)).token,1),

        'software-speaker','Quote \"Chinese中文\\n\\t😀\" '+str(i),80.0+i/1000,'confirmed','not_applicable')

        for i in range(total))

    deps=tuple(ref for turn in turns for ref in (turn.raw_ref,turn.source_ref,turn.access_ref))

    window=ConversationWindowProjectionV1(plan.namespace,'software-owner',plan.audience_id,scene,audience,

        turns,total-1,100.0,deps,(scene,audience,*deps),0,0,1)

    return base,plan,question,window





def collect_software_pages(monkeypatch,window,*,change_snapshot=False):

    db=sqlite3.connect(':memory:')

    db.execute('CREATE TABLE graph_recovery_metadata_v2(bot,persona,schema,requirements_json,graph_revision)')

    db.execute('INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)',(*window.namespace.as_tuple,'software-snapshot','{}',1))

    db.execute('CREATE TABLE graph_epochs(bot,persona,revision)')

    db.execute('INSERT INTO graph_epochs VALUES(?,?,1)',window.namespace.as_tuple)

    db.execute('CREATE TABLE graph_atoms(token,revision,valid)')

    db.execute('INSERT INTO graph_atoms VALUES(?,?,1)',(window.audience_ref.ref,window.audience_ref.version))

    db.commit();db.execute('BEGIN')

    calls=[]

    def source_inventory(read_db,namespace,scene_ref,conversation_ref,max_slots,now,*,before_sequence=None,

                         expected_activation_generation=None,expected_owner_authorization_head=None,

                         _page_observation=None,_collector_context=None):

        assert read_db is db and db.in_transaction and namespace==window.namespace

        if change_snapshot and calls:

            db.execute('UPDATE graph_epochs SET revision=2')

        if _collector_context is not None:

            _collector_context.require_current(db,namespace,scene_ref,conversation_ref)

        end=window.order_watermark if before_sequence is None else before_sequence-1

        start=max(0,end-max_slots+1)

        selected=tuple(turn for turn in window.turns if start<=turn.sequence<=end)

        deps=tuple(ref for turn in selected for ref in (turn.raw_ref,turn.source_ref,turn.access_ref))

        calls.append((before_sequence,max_slots,start,end))

        return replace(window,turns=selected,source_dependencies=deps,read_set=(window.scene_ref,window.audience_ref,*deps))

    monkeypatch.setattr(collector,'_read_current_d13_window_for_authority_v1',source_inventory)

    try:

        result=collector.read_current_d13_collection_v6(db,window.namespace,

            AtomKey.from_token(window.scene_ref.ref).owner.subject,window.conversation_ref,window.trusted_utc,

            expected_activation_generation=window.activation_epoch,max_slots=256)

        return result,calls

    finally:

        db.rollback();db.close()





@pytest.mark.parametrize('total',[64,65,128,256])

def test_v6_same_snapshot_pages_feed_real_raw_wire_and_reject_unpaid_count_pair(monkeypatch,record_property,total):

    base,plan,question,window=materials(total)

    collection,calls=collect_software_pages(monkeypatch,window)

    assert len(collection.pages)==(total+63)//64

    assert all(page.max_slots<=64 for page in collection.pages)

    assert [turn.sequence for turn in collection.window.turns]==list(range(total))

    assert len({turn.source_ref.ref for turn in collection.window.turns})==total

    assert collection.window.missing_ranges==()

    assert calls==[(page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence) for page in collection.pages]

    result,selected=build_natural_frame_v6(collection=collection,plan=plan,question=question,

        installation=base.installation,frozen_at_utc=100.0,expires_at_utc=130.0,policy_digest='9'*64)

    assert selected==() and len(result.input.recent_history)==total

    assert result.input.history_selection.coverage==((0,total-1),)

    assert result.input.history_selection.gaps==()

    assert thaw_natural_reply_request_v6(json.loads(canonical_serialize(asdict(result))))==result

    assert result.input.schema==TEMPLATE_VERSION

    actual_wire_bytes=len(result.canonical_wire.encode('utf-8'))

    record_property('actual_raw_wire_utf8_bytes',actual_wire_bytes)

    record_property('original_counter_stdin_cap_bytes',16*1024*1024)

    record_property('scope','software typed inventory seam; no installed Source/paid/count/budget permission')

    policy=InstalledD13WirePolicyV6(base.installation,'1'*64,'software-policy',1,'2'*64,'3'*64,'4'*64,

        2048,0,100,100,100,0)

    # Raw bytes alone are not a paid compressed candidate or count authority.

    pair=NaturalHistoryPairV6(result,None,collection,(),(),())

    with pytest.raises(ValueError,match='complete exact same-model wire pair'):

        d13_full_wire_count_request_v6(policy=policy,pair=pair)





def test_v6_page_collection_refuses_changed_snapshot_before_second_page(monkeypatch):

    _,_,_,window=materials(65)

    with pytest.raises(ValueError,match='snapshot/collector identity'):

        collect_software_pages(monkeypatch,window,change_snapshot=True)





def test_v6_signed_counter_codec_binds_four_ordered_blocks_and_a_separate_signature_domain(record_property):

    """Protocol vector only; these integers are not an installed tokenizer result."""

    import base64

    from copy import deepcopy

    from cryptography.exceptions import InvalidSignature

    from cryptography.hazmat.primitives import serialization

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from sylanne3.runtime_contracts import canonical_digest,canonical_serialize

    from sylanne3.authority_service.d13_wire_evidence_v6 import (

        EVIDENCE_SCHEMA,SIGNING_DOMAIN,verify_signed_d13_wire_envelope_v6)

    from sylanne3.authority_service.d13_wire_evidence_v1 import SIGNING_DOMAIN as OLD_DOMAIN

    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()

    policy=InstalledD13WirePolicyV6(frozen().installation,public,'software-codec-vector',1,

        '2'*64,'3'*64,'4'*64,2048,0,100,100,100,0)

    bindings=[{'metadata_ref':AtomKey(Owner('persona','bot','persona'),'d13.derived_block_metadata.v2','software-block-'+str(i)).token,

        'metadata_revision':1,'metadata_digest':str(i+1)*64,'payload_digest':'5'*64,'plan_ref':'software-plan-'+str(i),

        'plan_digest':'6'*64,'paid_original_ref':'software-paid-'+str(i),'paid_original_digest':'7'*64,

        'expires_at_utc':130.0,'turn_first':i*64,'turn_last':i*64+63} for i in range(4)]

    payload={'schema':EVIDENCE_SCHEMA,'namespace':{'bot_id':'bot','persona_id':'persona'},

        'policy_digest':policy.policy_digest,'raw_request_digest':'8'*64,'compressed_request_digest':'9'*64,

        'raw_frozen_digest':'a'*64,'compressed_frozen_digest':'b'*64,'collection_digest':'c'*64,

        'block_bindings':bindings,'blockset_digest':canonical_digest(bindings),'frozen_at_utc':100.0,'expires_at_utc':130.0,

        'token_evidence':'bounded_full_wire','raw_lower_tokens':100,'raw_upper_tokens':110,

        'compressed_lower_tokens':80,'compressed_upper_tokens':90}

    def signed(value,domain=SIGNING_DOMAIN):

        return {'payload':value,'signature':base64.b64encode(key.sign(domain+canonical_serialize(value).encode())).decode()}

    envelope=signed(payload)

    assert verify_signed_d13_wire_envelope_v6(policy,envelope)==payload

    record_property('actual_counter_response_utf8_bytes_plus_lf',len(canonical_serialize(envelope).encode('utf-8'))+1)

    record_property('signed_codec_scope','software envelope vector; not actual tokenizer/count/paid/Owner permission')

    with pytest.raises(InvalidSignature):

        verify_signed_d13_wire_envelope_v6(policy,signed(payload,OLD_DOMAIN))

    overlap=deepcopy(payload);overlap['block_bindings'][1]['turn_first']=63

    overlap['block_bindings'][1]['turn_last']=126

    overlap['blockset_digest']=canonical_digest(overlap['block_bindings'])

    with pytest.raises(ValueError,match='overlap'):

        verify_signed_d13_wire_envelope_v6(policy,signed(overlap))

    crossed=deepcopy(payload)

    crossed['block_bindings'][0]['metadata_ref']=AtomKey(Owner('persona','other-bot','persona'),

        'd13.derived_block_metadata.v2','software-block-0').token

    crossed['blockset_digest']=canonical_digest(crossed['block_bindings'])

    with pytest.raises(ValueError,match='another namespace/type'):

        verify_signed_d13_wire_envelope_v6(policy,signed(crossed))
