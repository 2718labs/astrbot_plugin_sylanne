"""V5 closed codec and actual SQL pin roundtrips, without signed freeze claims.

The nonempty original uses real Core finish and business SQL joins from the
permanent seam fixture. Inventory construction here remains unissued.
"""
from dataclasses import asdict, fields, replace
from copy import deepcopy
import json

import pytest

from test_c09_contact_finish_original_v1 import finished, capture
from test_contact_final_c09_joins_v1 import history_join
from test_contact_qualification_evidence_v1 import sql_evidence
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_recovery_frame_v4 import make_fact_frame_v4, make_source_pin_v4
from sylanne3.authority_service.c09_source_prepare_v4 import persist_execution_source_bundle_in_tx_v4
from sylanne3.authority_service.c09_contact_finish_original_v1 import contact_graph_fact_v1
from sylanne3.authority_service.c09_recovery_frame_v5 import (
    SCHEMA, PIN_SCHEMA, INVENTORY_SCHEMA, ContactFinishInventoryMemberV5, ContactFinishInventoryV5,
    C09RecoveryFactFrameV5, C09ExecutionSourcePinV5, decode_c09_frame_v5, decode_c09_pin_v5,
    _make_issued_frame_v5,
    _durable_contact_batch_operations_v5, _require_durable_contact_finishes_v5,
)
from sylanne3.authority_service.erasure_recovery_pin_v4 import (
    read_execution_recovery_facts_v4_locked, read_execution_recovery_facts_pin_v4_locked,
)


def values(case, *, empty=False):
    core, _store, ns, seal, _fact, _permit = case
    original = capture(case)[0]
    anchor = core.current_anchor('fixture', 'authority:fixture')
    members = () if empty else (ContactFinishInventoryMemberV5(original, None),)
    body = dict(authority_id=seal.authority_id, installation_id=seal.installation_id, namespace=seal.namespace,
        operation_id=seal.operation_id, source_seal_digest=seal.seal_digest, observed_core_anchor=anchor,
        verifier_commitment=original.verifier_commitment, business_namespace_digest=canonical_digest(ns),
        members=members, schema=INVENTORY_SCHEMA)
    inventory = ContactFinishInventoryV5(**body, inventory_digest=canonical_digest(tuple(
        body[field.name] for field in fields(ContactFinishInventoryV5) if field.name != 'inventory_digest')))
    base = make_fact_frame_v4(authority_id=seal.authority_id, installation_id=seal.installation_id,
        namespace=seal.namespace, operation_id=seal.operation_id, old_journal_id=seal.execution_journal_id,
        old_seq=seal.execution_seq, old_chain_head_digest=seal.execution_digest, prior_fact_frame_digests=(),
        verifier_commitment=inventory.verifier_commitment, executions=(), d02_facts=(), d11_facts=(), unknown_facts=(),
        graph_facts=() if empty else (contact_graph_fact_v1(original),))
    frame = C09RecoveryFactFrameV5(base, inventory, canonical_digest((base,inventory,SCHEMA)))
    pin4 = make_source_pin_v4(seal=seal, facts=frame)
    pin = C09ExecutionSourcePinV5(pin4,inventory.inventory_digest,anchor,
        canonical_digest((pin4,inventory.inventory_digest,anchor,PIN_SCHEMA)))
    return frame, pin


def wire(value):
    return json.loads(canonical_serialize(asdict(value)))


@pytest.mark.parametrize('empty', [False,True])
def test_closed_v5_preserves_complete_empty_and_nonempty_inventory(finished, empty):
    facts, pin = values(finished,empty=empty)
    assert decode_c09_frame_v5(wire(facts)) == facts
    assert decode_c09_pin_v5(wire(pin)) == pin
    assert len(facts.contact_finish_inventory.members) == (0 if empty else 1)
    assert facts.facts_digest != facts.ordinary_facts.facts_digest
    assert pin.pin_digest != pin.source_pin.pin_digest


def test_unissued_empty_dto_cannot_issue_authenticated_v5_frame(finished):
    facts,_pin = values(finished,empty=True)
    with pytest.raises(AuthorityUnavailable,match='installed private freeze'):
        _make_issued_frame_v5(object(),ordinary_facts=facts.ordinary_facts,
            inventory=facts.contact_finish_inventory,seal=finished[3])


@pytest.mark.parametrize('path', [('contact_finish_inventory',), ('schema',),
    ('contact_finish_inventory','members'), ('contact_finish_inventory','observed_core_anchor','activation_generation')])
def test_v5_rejects_missing_closed_fields(finished,path):
    facts,_pin = values(finished); raw=wire(facts); target=raw
    for key in path[:-1]:target=target[key]
    del target[path[-1]]
    with pytest.raises((ValueError,TypeError,AuthorityUnavailable)):decode_c09_frame_v5(raw)


def test_v5_rejects_bool_generation_unknown_fields_and_duplicate_members(finished):
    facts,_pin=values(finished)
    raw=wire(facts);raw['contact_finish_inventory']['observed_core_anchor']['activation_generation']=True
    with pytest.raises((ValueError,TypeError,AuthorityUnavailable)):decode_c09_frame_v5(raw)
    raw=wire(facts);raw['ordinary_facts']['extra']='caller'
    with pytest.raises((ValueError,TypeError,AuthorityUnavailable)):decode_c09_frame_v5(raw)
    with pytest.raises(AuthorityUnavailable):replace(facts.contact_finish_inventory,
        members=facts.contact_finish_inventory.members*2)


def test_v5_actual_core_sql_roundtrip_dispatch_keeps_exact_frame_and_pin(finished):
    facts,pin=values(finished);core,_store,ns,seal,_fact,_permit=finished
    with core._tx() as db:
        persist_execution_source_bundle_in_tx_v4(db,seal=seal,pin=pin,facts=facts)
        assert read_execution_recovery_facts_v4_locked(db,seal.namespace,operation_id=seal.operation_id)==facts
        assert read_execution_recovery_facts_pin_v4_locked(db,seal.namespace,operation_id=seal.operation_id)==pin
        assert db.execute('SELECT facts_json FROM authority_c09_recovery_fact_frames_v4 WHERE namespace=? AND operation_id=?',
            (seal.namespace,seal.operation_id)).fetchone()==(canonical_serialize(asdict(facts)),)


@pytest.fixture
def durable_graph(tmp_path):
    from sylanne3.graph_store import GraphStore
    from sylanne3.graph_types import TypeRegistry
    from sylanne3.runtime_contracts import NamespaceId
    store=GraphStore(tmp_path/'durable.db',TypeRegistry())
    store._db.execute('BEGIN')
    yield store._db,NamespaceId('bot','persona')
    store._db.rollback();store.close()


def insert_durable(db,ns,kind,token,revision=1):
    if kind=='event':
        db.execute('INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)',
            (*ns.as_tuple,'fixture','orphan','digest','[]','[]',json.dumps([[token,revision]]),'[]',1))
    else:
        # Matches the real GCP ledger_refs envelope; no assumed universal
        # write_versions field. All Graph body/history/archive rows are absent.
        db.execute('INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)',
            (*ns.as_tuple,'orphan','digest','activity',None,1,json.dumps({'commit_seq':1,'ledger_refs':[token],'outbox_refs':[]})))


@pytest.mark.parametrize('kind',['event','receipt'])
def test_orphan_durable_batch_prevents_false_empty_without_any_body_or_archive(durable_graph,kind):
    from sylanne3.domains.d09.contact_batch_v1 import contact_batch_key_v1
    db,ns=durable_graph;key=contact_batch_key_v1(ns,'activity','contact:fixture')
    insert_durable(db,ns,kind,key.token)
    assert db.execute('SELECT count(*) FROM graph_atoms').fetchone()==(0,)
    assert db.execute('SELECT count(*) FROM graph_history').fetchone()==(0,)
    operations=_durable_contact_batch_operations_v5(db,ns)
    assert operations=={'orphan'}
    with pytest.raises(AuthorityUnavailable,match='complete authenticated finished original'):
        _require_durable_contact_finishes_v5(operations,())


@pytest.mark.parametrize('kind',['event','receipt'])
def test_durable_inventory_rejects_cross_namespace_typed_batch(durable_graph,kind):
    from sylanne3.domains.d09.contact_batch_v1 import contact_batch_key_v1
    from sylanne3.runtime_contracts import NamespaceId
    db,ns=durable_graph;key=contact_batch_key_v1(NamespaceId('other','persona'),'activity','contact:fixture')
    insert_durable(db,ns,kind,key.token)
    with pytest.raises(AuthorityUnavailable,match='crosses namespace'):
        _durable_contact_batch_operations_v5(db,ns)


def test_durable_event_rejects_bool_write_revision(durable_graph):
    from sylanne3.domains.d09.contact_batch_v1 import contact_batch_key_v1
    db,ns=durable_graph
    insert_durable(db,ns,'event',contact_batch_key_v1(ns,'activity','contact:fixture').token,True)
    with pytest.raises(AuthorityUnavailable,match='changes revision'):
        _durable_contact_batch_operations_v5(db,ns)


def test_real_empty_durable_sql_inventory_and_missing_table_refusal(durable_graph):
    db,ns=durable_graph
    assert _durable_contact_batch_operations_v5(db,ns)==set()
    db.execute('DROP TABLE graph_bundle_operations')
    with pytest.raises(AuthorityUnavailable,match='inventory table is missing'):
        _durable_contact_batch_operations_v5(db,ns)


@pytest.mark.parametrize('kind',['event','receipt'])
@pytest.mark.parametrize('version',[2,3])
def test_every_versioned_contact_member_is_in_complete_durable_inventory(durable_graph,kind,version):
    from sylanne3.domains.d09.contact_batch_v1 import contact_batch_key_v1
    from sylanne3.domains.d09.contact_batch_v2 import KINDS as V2
    from sylanne3.domains.d09.contact_batch_v3 import KINDS as V3
    from sylanne3.graph_types import AtomKey
    db,ns=durable_graph;base=contact_batch_key_v1(ns,'activity','contact:fixture')
    for type_name in sorted(V2 if version==2 else V3):
        insert_durable(db,ns,kind,AtomKey(base.owner,type_name,base.name).token)
        assert _durable_contact_batch_operations_v5(db,ns)=={'orphan'}
        db.execute('DELETE FROM graph_events' if kind=='event' else 'DELETE FROM graph_bundle_operations')


@pytest.fixture
def v5_consumed(finished,tmp_path):
    """Real Core consumption/SQL, signed-original transport fixture seam.

    The control pointer/manifest transport is bounded fixture input. This is
    not an installed freeze or a genuine business Contact GCP acceptance.
    """
    import sqlite3
    from contextlib import contextmanager
    from types import SimpleNamespace
    from sylanne3.authority_service.c09_storage_control_v1 import InstalledC09StorageReaderV1
    from sylanne3.authority_service.c09_authority_storage_rebase import _CoreTransform,_LEDGER_DDL
    core,store,ns,seal,_fact,_permit=finished
    facts,pin=values(finished);original=facts.contact_finish_inventory.members[0].original
    prepared=dict(namespace=seal.namespace,operation_id=seal.operation_id,facts_digest=facts.facts_digest,
        facts_pin_original=asdict(pin),old_core_anchor_original=asdict(original.observed_core_anchor),
        new_core_anchor_original=asdict(replace(original.observed_core_anchor,activation_generation=2)),
        anchor_transition_original={'before_anchor':asdict(original.observed_core_anchor),
            'after_anchor':asdict(replace(original.observed_core_anchor,activation_generation=2))},
        recovery_bindings_digest='e'*64)
    reader=object.__new__(InstalledC09StorageReaderV1)
    reader._key=b'isolated fixture signing transport key';reader.key_id='fixture';reader.installation_id='installation'
    prepared=reader.sign_original_v1('fixture.prepared.transport.v1',
        {'schema':'fixture.prepared.transport.v1',**prepared},'prepared_digest')
    control_path=tmp_path/'protected-fixture.db'
    with sqlite3.connect(control_path) as db:
        db.execute('CREATE TABLE c09_storage_operations_v1(installation_id,generation,prepared_original_json)')
        db.execute('INSERT INTO c09_storage_operations_v1 VALUES(?,?,?)',('installation',1,canonical_serialize(prepared)))
    @contextmanager
    def protected():
        with sqlite3.connect(control_path) as db:yield db
    reader._db=protected
    reader._current=lambda db:{'pointer_version':1,'current_manifest_digest':'f'*64,'stage':'RELEASED'}
    reader.read_verified_current_storage_v1=lambda **kw:SimpleNamespace(pointer_version=1,manifest_digest='f'*64,
        stage='RELEASED',storage_generation=1,manifest={'members':[{'role':'core','resolved_path':core.path}]})
    transform=_CoreTransform(namespace=seal.namespace,operation_id=seal.operation_id,authority_id=seal.authority_id,
        pin_digest=pin.pin_digest,new_journal_id='next-execution',old_journal_id='execution',
        new_anchor_nonce='e'*64,continuation_permit_token='f'*64,old_seq=0,old_digest='genesis',facts=facts,execution_rows=())
    with core._tx() as db:
        persist_execution_source_bundle_in_tx_v4(db,seal=seal,pin=pin,facts=facts)
        columns=tuple(r[1] for r in db.execute('PRAGMA table_info(authority_v2_fences)'))
        output,_changes=transform('authority_v2_fences',columns,tuple(db.execute('SELECT * FROM authority_v2_fences')))
        assert output==()
        db.execute(_LEDGER_DDL)
        db.execute('INSERT INTO authority_c09_consumed_execution_v1 VALUES(?,?,?,?,?,?)',
            (seal.namespace,'fence',original.owner_attempt_id,original.owner_attempt_id,original.fence_row_commitment,pin.pin_digest))
        db.execute('DELETE FROM authority_v2_fences')
    return finished,facts,pin,prepared,reader


def verify_consumed(case):
    from sylanne3.authority_service.c09_recovery_frame_v5 import verify_contact_finish_inventory_restore_v5
    finished,facts,pin,prepared,_reader=case
    with finished[0]._tx() as db:
        return verify_contact_finish_inventory_restore_v5(db,facts=facts,pin=pin,prepared=prepared,verified_prior=())


def test_v5_nonempty_actual_consumed_sql_restores(v5_consumed):
    case,facts,_pin,_prepared,reader=v5_consumed;core,store,ns,seal,fact,_permit=case
    original=facts.contact_finish_inventory.members[0].original
    assert verify_consumed(v5_consumed)==facts.contact_finish_inventory
    assert core._db.execute('SELECT count(*) FROM authority_v2_fences').fetchone()==(0,)


@pytest.mark.parametrize('change',['consumed','transition','all_archive','pin'])
def test_v5_nonempty_cold_original_drift_refuses(v5_consumed,change):
    from sylanne3.authority_service.c09_contact_finish_original_v1 import TABLE
    case,facts,pin,prepared,reader=v5_consumed;core=case[0]
    if change=='consumed':core._db.execute('UPDATE authority_c09_consumed_execution_v1 SET original_commitment=?',('f'*64,))
    elif change=='transition':prepared['anchor_transition_original']['after_anchor']['activation_generation']=3
    elif change=='pin':prepared['facts_pin_original']['pin_digest']='f'*64
    else:
        # Model physical loss, not a product bypass of immutable triggers.
        core._db.execute('DROP TRIGGER '+TABLE+'_no_delete');core._db.execute('DELETE FROM '+TABLE)
    with pytest.raises(AuthorityUnavailable):verify_consumed(v5_consumed)


@pytest.mark.parametrize('legacy',['none','empty','opaque'])
def test_v5_actual_capture_after_consumption_uses_versioned_historical_inventory(v5_consumed,monkeypatch,legacy):
    from types import SimpleNamespace
    from sylanne3.authority_service.c09_contact_finish_original_v1 import capture_contact_finish_originals_v1
    case,facts,_pin,prepared,reader=v5_consumed;core,store,ns,seal,fact,_permit=case
    original=facts.contact_finish_inventory.members[0].original
    # Honest binding transport seam: the fully signed installed four-store
    # empty inventory cases exercise actual bindings/selected-path context.
    prior_digest=None
    if legacy!='none':
        from sylanne3.authority_service.c09_recovery_frame_v4 import make_source_seal_v4
        from sylanne3.runtime.c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
        oldseal=make_source_seal_v4(authority_id=seal.authority_id,installation_id=seal.installation_id,
            namespace=seal.namespace,operation_id='delete:legacy',execution_journal_id=seal.execution_journal_id,
            execution_seq=0,execution_digest='genesis',prior_prefix_digest=None,suffix_row_commitments=(),accepted_receipt_digest='a'*64)
        oldfacts=make_fact_frame_v4(authority_id=seal.authority_id,installation_id=seal.installation_id,
            namespace=seal.namespace,operation_id=oldseal.operation_id,old_journal_id=seal.execution_journal_id,
            old_seq=0,old_chain_head_digest='genesis',prior_fact_frame_digests=(),verifier_commitment='d'*64,
            executions=(),d02_facts=(),d11_facts=(),unknown_facts=(),
            graph_facts=() if legacy=='empty' else (SanitizedGraphFactV4('opaque','a'*64,'b'*64,None),))
        oldpin=make_source_pin_v4(seal=oldseal,facts=oldfacts)
        oldprepared=reader.sign_original_v1('fixture.prepared.transport.v1',dict(schema='fixture.prepared.transport.v1',
            namespace=oldseal.namespace,operation_id=oldseal.operation_id,facts_digest=oldfacts.facts_digest,
            facts_pin_original=asdict(oldpin),recovery_bindings_digest='e'*64),'prepared_digest')
        prior_digest=oldprepared['prepared_digest']
        with core._tx() as db:persist_execution_source_bundle_in_tx_v4(db,seal=oldseal,pin=oldpin,facts=oldfacts)
        with reader._db() as protected:
            protected.execute('INSERT INTO c09_storage_operations_v1 VALUES(?,?,?)',
                ('installation',0,canonical_serialize(oldprepared)))
    monkeypatch.setattr('sylanne3.authority_service.c09_recovery_resolver_v4.read_recovery_bindings_v1_locked',
        lambda *args,**kw:SimpleNamespace(bindings_digest='e'*64,
            prior_transition_digest_or_none=prior_digest if kw['operation_id']==seal.operation_id else None))
    # Recompute the genuine closed seal rather than changing its digest alone.
    from sylanne3.authority_service.c09_recovery_frame_v4 import make_source_seal_v4
    next_seal=make_source_seal_v4(authority_id=seal.authority_id,installation_id=seal.installation_id,
        namespace=seal.namespace,operation_id='delete:next',execution_journal_id=seal.execution_journal_id,
        execution_seq=0,execution_digest='genesis',prior_prefix_digest=None,suffix_row_commitments=(),accepted_receipt_digest='a'*64)
    with core._tx() as db:
        store._db.execute('BEGIN')
        try:
            arguments=dict(core_db=db,business=store._db,namespace_id=ns,seal=next_seal,
                verifier_commitment='f'*64,registry=store._registry,graph_facts=(fact,),require_existing=True,storage_reader=reader)
            if legacy=='opaque':
                with pytest.raises(AuthorityUnavailable,match='legacy V4'):
                    capture_contact_finish_originals_v1(**arguments)
                return
            saved=capture_contact_finish_originals_v1(**arguments)
            assert saved==(original,)
            assert saved[0].operation_id==seal.operation_id and saved[0].source_seal_digest==seal.seal_digest
        finally:store._db.rollback()


def test_v5_carry_keeps_old_original_and_authenticates_consumed_prior_chain(v5_consumed):
    from sylanne3.authority_service.c09_recovery_frame_v5 import ContactFinishCarryV5,verify_contact_finish_inventory_restore_v5
    from sylanne3.authority_service.c09_recovery_frame_v4 import make_source_seal_v4
    case,prior,pin,prepared,_reader=v5_consumed;core=case[0]
    original=prior.contact_finish_inventory.members[0].original
    carry=ContactFinishCarryV5(prior.operation_id,prior.facts_digest,prior.contact_finish_inventory.inventory_digest,
        pin.pin_digest,prepared['prepared_digest'],original.fence_row_commitment)
    anchor=replace(original.observed_core_anchor,activation_generation=2,execution_journal_id='next-execution')
    seal=make_source_seal_v4(authority_id=prior.authority_id,installation_id=prior.installation_id,
        namespace=prior.namespace,operation_id='delete:next',execution_journal_id=anchor.execution_journal_id,
        execution_seq=0,execution_digest='genesis',prior_prefix_digest=None,suffix_row_commitments=(),accepted_receipt_digest='a'*64)
    inventory=prior.contact_finish_inventory
    body={f.name:getattr(inventory,f.name) for f in fields(type(inventory)) if f.name!='inventory_digest'}
    body.update(operation_id=seal.operation_id,source_seal_digest=seal.seal_digest,observed_core_anchor=anchor,
        members=(ContactFinishInventoryMemberV5(original,carry),))
    inventory=ContactFinishInventoryV5(**body,inventory_digest=canonical_digest(tuple(
        body[f.name] for f in fields(ContactFinishInventoryV5) if f.name!='inventory_digest')))
    ordinary=make_fact_frame_v4(authority_id=prior.authority_id,installation_id=prior.installation_id,
        namespace=prior.namespace,operation_id=seal.operation_id,old_journal_id=anchor.execution_journal_id,
        old_seq=0,old_chain_head_digest='genesis',prior_fact_frame_digests=(prior.facts_digest,),
        verifier_commitment=inventory.verifier_commitment,executions=(),d02_facts=(),d11_facts=(),unknown_facts=(),
        graph_facts=prior.graph_facts)
    frame=C09RecoveryFactFrameV5(ordinary,inventory,canonical_digest((ordinary,inventory,SCHEMA)))
    pin4=make_source_pin_v4(seal=seal,facts=frame)
    next_pin=C09ExecutionSourcePinV5(pin4,inventory.inventory_digest,anchor,
        canonical_digest((pin4,inventory.inventory_digest,anchor,PIN_SCHEMA)))
    after=replace(anchor,activation_generation=3)
    next_prepared={'namespace':frame.namespace,'operation_id':frame.operation_id,'facts_digest':frame.facts_digest,
        'facts_pin_original':asdict(next_pin),'old_core_anchor_original':asdict(anchor),
        'new_core_anchor_original':asdict(after),'anchor_transition_original':{'before_anchor':asdict(anchor),'after_anchor':asdict(after)}}
    with core._tx() as db:
        verified=((prepared,prior,None),)
        assert verify_contact_finish_inventory_restore_v5(db,facts=frame,pin=next_pin,prepared=next_prepared,
            verified_prior=verified)==inventory
        assert inventory.members[0].original==original
        assert original.operation_id!=frame.operation_id and original.observed_core_anchor!=anchor
        with pytest.raises(AuthorityUnavailable,match='historical frame missing'):
            verify_contact_finish_inventory_restore_v5(db,facts=frame,pin=next_pin,prepared=next_prepared,verified_prior=())
        db.execute('UPDATE authority_c09_consumed_execution_v1 SET original_commitment=?',('f'*64,))
        with pytest.raises(AuthorityUnavailable,match='once-only fence'):
            verify_contact_finish_inventory_restore_v5(db,facts=frame,pin=next_pin,prepared=next_prepared,verified_prior=verified)
