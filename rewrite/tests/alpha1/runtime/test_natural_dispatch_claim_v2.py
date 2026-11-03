"""The natural P2 helper cannot mint a claim outside a real graph transaction."""

from pathlib import Path

import pytest

from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.natural_dispatch_claim_v2 import (
    NaturalDispatchClaimHold, prepare_natural_dispatch_claim_v2,
)


def test_natural_p2_requires_real_graph_transaction_and_typed_evidence(tmp_path: Path):
    store = GraphStore(tmp_path / "natural-p2.db", TypeRegistry())
    arguments = dict(
        namespace=None, admission_receipt=None, request=None,
        evidence=None, operation=None, batch={}, original_scope_proof=None,
        current_route=None, context=None, binding=None, claimed=None,
        witness=None, authority_snapshot=None, now_utc=1.0,
    )
    try:
        with pytest.raises(NaturalDispatchClaimHold, match="typed final natural"):
            prepare_natural_dispatch_claim_v2(db=store._db, **arguments)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(NaturalDispatchClaimHold,
                                   match="typed final natural"):
                    prepare_natural_dispatch_claim_v2(db=store._db, **arguments)
                assert store._db.execute(
                    "SELECT COUNT(*) FROM graph_events").fetchone()[0] == 0
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()


def _canonical_evidence_codec_case(monkeypatch,*,admission_padding=0):
    """Isolate canonical bytes, not Graph/Source or sender authorization."""
    from contextlib import contextmanager
    from types import SimpleNamespace
    from sylanne3.graph_types import AtomKey,GraphVersion,Owner
    from sylanne3.runtime_contracts import canonical_serialize,meter_canonical_outputs
    from sylanne3.runtime.c09_paged_sql_v2 import C09BatchBudgetV2,C09SqlByteMeterV2
    from sylanne3.runtime.natural_dispatch_claim_v2 import _NaturalEvidenceCanonicalReadV3,_STATIC_EVIDENCE_KEYS_V3
    from rewrite.tests.alpha1.dispatch.test_authority_budget_snapshot import _case
    import sylanne3.runtime_storage_v3 as storage

    namespace,_context,witness,snapshot,footprint=_case()
    budget=C09BatchBudgetV2(100,262144,25000000,250000000,8388608)
    @contextmanager
    def codec_quantum(_db):
        meter=C09SqlByteMeterV2(budget)
        with meter_canonical_outputs(meter):yield meter
    monkeypatch.setattr(storage,'runtime_storage_quantum_v3',codec_quantum)
    class Retention:
        closed=False
        retained=0
        def retain(self,size):
            self.retained+=size
            assert self.retained<=8388608
    owner=Owner('persona',*namespace.as_tuple)
    reads=tuple(GraphVersion(AtomKey(owner,'d09.topic.v1','topic:'+str(i)),1)for i in range(250))
    values={'admission':{'unicode':'中文😀','escape':'\\"\n'},'batch_digest':'a'*64,
        'candidate':{'epoch':1,'reads':reads},'natural_v2':True,'operation':reads,
        'paid_review':{'call_id':'call:real','receipt_digest':'b'*64},
        'route':namespace,'scoped_proof':{'reads':reads},'footprint':footprint}
    if admission_padding:values['admission']['padding']='x'*admission_padding
    inventory=SimpleNamespace(db=None,namespace=namespace,query=None,
        operation=Retention(),request=SimpleNamespace(effect_id=snapshot.unresolved_effects[0].effect_id),
        require_current=lambda *_:None)
    # Skip the business reader constructor intentionally; only this codec's
    # own resumable stages and private completed-result issuer are exercised.
    reader=object.__new__(_NaturalEvidenceCanonicalReadV3)
    reader.owner=SimpleNamespace(db=None,namespace=namespace,operation=inventory.operation)
    reader.inventory=inventory;reader.values=values
    reader.keys=(*_STATIC_EVIDENCE_KEYS_V3,'footprint');reader.index=0
    reader.stream=None;reader.parts={};reader.complete=False;reader.result=None
    for _ in range(500):
        meter=C09SqlByteMeterV2(budget)
        with meter_canonical_outputs(meter):done=reader.advance(meter)
        assert meter.consumed_bytes<=262144
        if done:break
    else:pytest.fail('actual canonical codec did not reach EOF')
    for key,parts in reader.parts.items():
        assert b''.join(parts)==canonical_serialize(values[key]).encode('ascii')
    return inventory,reader.result,{key:values[key]for key in _STATIC_EVIDENCE_KEYS_V3},snapshot,witness


def test_natural_retained_canonical_matches_exact_legacy_digest_and_live_shell(monkeypatch):
    from dataclasses import replace
    from sylanne3.runtime_contracts import canonical_digest
    inventory,proof,values,snapshot,witness=_canonical_evidence_codec_case(monkeypatch)
    try:
        expected='sha256:'+canonical_digest(dict(values,authority_snapshot=snapshot,owner_witness=witness))
        assert proof.digest_v3(inventory,values,snapshot,witness)==expected
        current=replace(snapshot,admission_epoch=snapshot.admission_epoch+1)
        current_witness=replace(witness,grant_id='grant:changed')
        changed=proof.digest_v3(inventory,values,current,current_witness)
        assert changed=='sha256:'+canonical_digest(dict(values,authority_snapshot=current,owner_witness=current_witness))
        assert changed!=expected
    finally:proof.release_payload_v3()


def test_natural_retained_canonical_rejects_changed_original_footprint_and_release(monkeypatch):
    from dataclasses import replace
    inventory,proof,values,snapshot,witness=_canonical_evidence_codec_case(monkeypatch)
    with pytest.raises(NaturalDispatchClaimHold,match='differs from its actual canonical originals'):
        proof.digest_v3(inventory,dict(values,batch_digest='changed'),snapshot,witness)
    changed_footprint=replace(snapshot.unresolved_effects[0].footprint,conflict_keys=('different',))
    changed=replace(snapshot,unresolved_effects=(replace(snapshot.unresolved_effects[0],footprint=changed_footprint),))
    with pytest.raises(NaturalDispatchClaimHold,match='actual admitted footprint'):
        proof.digest_v3(inventory,values,changed,witness)
    proof.release_payload_v3()
    with pytest.raises(NaturalDispatchClaimHold,match='actual canonical originals'):
        proof.digest_v3(inventory,values,snapshot,witness)


@pytest.mark.parametrize('incoming_error',[None,RuntimeError('earlier failure')])
def test_natural_inventory_fence_finish_failure_releases_result_once(monkeypatch,incoming_error):
    from types import SimpleNamespace
    import sylanne3.runtime.dispatch_current_inventory_v3 as module
    releases=[];closed=[]
    def finish_fence(_fence):raise OSError('actual fence finish failed')
    result=SimpleNamespace(release_payload_v3=lambda:releases.append('result'))
    admission=SimpleNamespace(release_payload_v3=lambda:releases.append('admission'))
    reader=SimpleNamespace(fence=object(),result=result,auxiliary=None,admission_originals=admission)
    operation=object();work=SimpleNamespace(state=reader,operation=operation,result_lease=None)
    monkeypatch.setattr(module,'finish_runtime_storage_operation_v3',lambda op:closed.append(op))
    with pytest.raises(OSError,match='actual fence finish failed'):
        module.finish_current_dispatch_inventory_v3(SimpleNamespace(_finish_read_fence_v3=finish_fence),work,incoming_error)
    assert releases==['result'] and closed==[operation]
    assert reader.result is reader.admission_originals is reader.evidence_task is None
    assert work.result_lease is None


def test_natural_runtime_canonical_stream_preserves_enum_and_rejects_cycle():
    from enum import Enum
    from types import SimpleNamespace
    from sylanne3.runtime.runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
    from sylanne3.runtime.c09_paged_sql_v2 import C09BatchBudgetV2,C09SqlByteMeterV2
    from sylanne3.runtime_contracts import canonical_serialize,meter_canonical_outputs
    class Mode(Enum):ACTIVE='active'
    operation=SimpleNamespace(retain=lambda count:None)
    budget=C09BatchBudgetV2(100,262144,25000000,250000000,8388608)
    value={'enum':Mode.ACTIVE,'numbers':(None,True,2,1.5),'unicode':'😀中文'}
    stream=RuntimeCanonicalStreamV3(value,operation);parts=[]
    while not stream.complete:
        meter=C09SqlByteMeterV2(budget)
        with meter_canonical_outputs(meter):part=stream.read_fragment(meter)
        if part:parts.append(part)
    assert b''.join(parts)==canonical_serialize(value).encode('ascii')
    cyclic=[];cyclic.append(cyclic)
    stream=RuntimeCanonicalStreamV3(cyclic,operation)
    with pytest.raises(ValueError,match='cyclic canonical value'):
        stream.read_fragment(C09SqlByteMeterV2(budget))


def test_natural_final_canonical_refuses_original_local_time_boundary(monkeypatch):
    import sylanne3.runtime.natural_dispatch_claim_v2 as module
    inventory,proof,values,snapshot,witness=_canonical_evidence_codec_case(monkeypatch)
    monkeypatch.setattr(module,'monotonic_ns',lambda:10**30)
    try:
        with pytest.raises(NaturalDispatchClaimHold,match='original local quantum'):
            proof.digest_v3(inventory,values,snapshot,witness)
    finally:proof.release_payload_v3()


def test_natural_final_canonical_preserves_synchronous_byte_ceiling(monkeypatch):
    from sylanne3.runtime.c09_paged_sql_v2 import C09PagedCaptureHold
    inventory,proof,values,snapshot,witness=_canonical_evidence_codec_case(monkeypatch,admission_padding=300000)
    try:
        # Preparation legitimately used separate original quanta. The exact
        # final hash still has one synchronous boundary; it must HOLD here.
        with pytest.raises(C09PagedCaptureHold,match='codec quantum needs continuation'):
            proof.digest_v3(inventory,values,snapshot,witness)
    finally:proof.release_payload_v3()


def test_natural_runtime_canonical_reuses_sibling_frame_retention():
    """Real canonical bytes and actual original 8MiB retained-operation pool."""
    from types import SimpleNamespace
    from sylanne3.graph_types import AtomKey, GraphVersion, Owner
    from sylanne3.runtime.runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
    from sylanne3.runtime.c09_paged_sql_v2 import C09BatchBudgetV2, C09SqlByteMeterV2
    from sylanne3.runtime_contracts import canonical_serialize, meter_canonical_outputs
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED
    pool = _RuntimeResourcePoolV3()
    baseline = pool.used
    operation = RuntimeStorageOperationV3(_INSTALLED,
        SimpleNamespace(pool=pool, selection_digest="natural-canonical-codec"),
        "natural-canonical-codec", 100.0)
    owner = Owner("persona", "bot", "persona")
    value = tuple(GraphVersion(AtomKey(owner, "d09.topic.v1", "topic:" + str(i)), 1) for i in range(2048))
    stream = RuntimeCanonicalStreamV3(value, operation)
    parts = []
    budget = C09BatchBudgetV2(100, 262144, 25000000, 250000000, 8388608)
    try:
        while not stream.complete:
            meter = C09SqlByteMeterV2(budget)
            with meter_canonical_outputs(meter):
                part = stream.read_fragment(meter)
            if part:
                parts.append(part)
        assert b"".join(parts) == canonical_serialize(value).encode("ascii")
        assert stream.live_bytes == 0 and stream._active == set()
        assert pool.used - baseline == stream.peak_bytes
        assert stream.peak_bytes < 262144
    finally:
        operation.release()
    assert pool.used == baseline
