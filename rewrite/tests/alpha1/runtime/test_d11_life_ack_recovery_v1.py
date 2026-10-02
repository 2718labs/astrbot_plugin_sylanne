"""Permanent readonly Life ACK recovery and RPC-race regressions.

The SQL artifact/member/Jobs seam uses the real isolated fixture and readers.
The control-flow race fixture stubs bridge authentication and the paired RPCs;
it verifies no new Graph/budget work, not installed Authority acceptance.
"""
from dataclasses import replace
import json
import sqlite3
from types import SimpleNamespace as S

import pytest

from test_d11_life_job_result_binding_v1 import case, _adopt_sql, _read, D
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_types import AtomKey
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.runtime import d11_life_adoption_v1 as adoption
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.d11_life_preparation_v1 import TABLE
from sylanne3.runtime_contracts import SnapshotRequirementsV2, canonical_serialize


def _insert_head(db,ref,revision,value,valid):
    key=AtomKey.from_token(ref)
    db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
        (ref,key.owner.bot,key.owner.persona,key.owner.kind,key.owner.subject,key.type_name,key.name,revision,value,int(valid)))


@pytest.fixture
def recovery(case):
    db=case.db;b=case.binding
    db.execute('BEGIN');_adopt_sql(case)
    adopted=_read(case)
    for ref,revision,value,valid in db.execute('SELECT token,revision,value,valid FROM graph_history').fetchall():
        _insert_head(db,ref,revision,value,valid)
    source_ref=case.prepared.plan.input_source.ref
    requirements=SnapshotRequirementsV2(b.namespace,b.authority_id,b.authority_namespace,1,
        'deletion',0,'genesis','execution',0,'genesis',0,'fixture-incarnation')
    db.execute('INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)',
        (*b.namespace.as_tuple,requirements.schema,canonical_serialize(plain_v1(requirements)),100))
    prepared=case.prepared
    for ref,dependencies in db.execute('SELECT token,dependencies FROM graph_history').fetchall():
        for dependency,revision in json.loads(dependencies):
            db.execute('INSERT INTO graph_dependencies VALUES(?,?,?)',(ref,dependency,revision))
    db.commit()
    return case,prepared,adopted,requirements


def _validate(db,recovery):
    case,prepared,adopted,_=recovery
    return adoption.validate_life_recovery_heads_v1(db,binding=case.binding,prepared_digest=prepared.digest,prepared=prepared,adopted=adopted)


def test_cold_repeat_is_readonly_and_allows_unrelated_same_generation_revision(recovery):
    case,_,adopted,_=recovery
    case.db.execute('UPDATE graph_recovery_metadata_v2 SET graph_revision=999');case.db.commit()
    counts={table:case.db.execute('SELECT count(*) FROM '+table).fetchone() for table in ('graph_events','runtime_budget_operations','graph_d11_life_originals_v1')}
    with sqlite3.connect(case.path.as_uri()+'?mode=ro',uri=True) as cold:
        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
        assert _validate(cold,recovery)==adopted
        assert _validate(cold,recovery)==adopted
        assert cold.total_changes==0
    assert counts=={table:case.db.execute('SELECT count(*) FROM '+table).fetchone() for table in counts}


@pytest.mark.parametrize('change',('generation','metadata_namespace','deleted_source','source_body','source_revision',
    'artifact_revision','artifact_digest','artifact_bytes','artifact_adopter','terminal_member','missing_job','job_operation','job_continuation'))
def test_recovery_refuses_changed_deleted_or_cross_scope_actual_heads(recovery,change):
    case,prepared,_,requirements=recovery;db=case.db;b=case.binding
    if change in ('generation','metadata_namespace'):
        value=replace(requirements,activation_generation=2) if change=='generation' else replace(requirements,namespace=type(b.namespace)('other','persona'))
        db.execute('UPDATE graph_recovery_metadata_v2 SET requirements_json=?',(canonical_serialize(plain_v1(value)),))
    if change=='deleted_source':db.execute('DELETE FROM graph_atoms WHERE token=?',(prepared.read_rows[0].ref,))
    if change=='source_body':db.execute('UPDATE graph_atoms SET value=? WHERE token=?',('{}',prepared.read_rows[0].ref))
    if change=='source_revision':db.execute('UPDATE graph_atoms SET revision=2 WHERE token=?',(prepared.read_rows[0].ref,))
    if change=='artifact_revision':db.execute('UPDATE graph_atoms SET revision=2 WHERE token=?',(b.artifact_ref,))
    if change=='artifact_digest':db.execute('UPDATE graph_atoms SET value=? WHERE token=?',('{}',b.artifact_ref))
    if change=='artifact_bytes':db.execute('UPDATE graph_d11_life_artifact_stage_v1 SET artifact_bytes=?',(b'changed',))
    if change=='artifact_adopter':db.execute("UPDATE graph_d11_life_artifact_stage_v1 SET adopted_operation_id='another-adoption'")
    if change=='terminal_member':
        ref=next(row[0] for row in db.execute('SELECT token FROM graph_atoms') if AtomKey.from_token(row[0]).type_name=='d11.role_segment_end.v1')
        db.execute('UPDATE graph_atoms SET value=? WHERE token=?',('{}',ref))
    if change=='missing_job':db.execute('DELETE FROM runtime_jobs')
    if change=='job_operation':db.execute("UPDATE runtime_jobs SET operation_id='another-root'")
    if change=='job_continuation':db.execute('UPDATE runtime_jobs SET continuation_json=?',(canonical_serialize({'changed':True}),))
    db.commit();db.execute('BEGIN')
    with pytest.raises(ValueError):_validate(db,recovery)
    db.rollback()


@pytest.mark.parametrize('race',('none','deleted_source','source_body','generation','owner_pairing','terminal_receipt','claim_receipt','saved_receipt','false_ack'))
def test_saved_ack_rechecks_after_terminal_rpc_and_never_begins_or_charges(recovery,monkeypatch,race):
    case,prepared,adopted,requirements=recovery;db=case.db;b=case.binding
    gate=S(binding=b,terminal=case.terminal,owner_actor_id='owner',prepared_digest=prepared.digest)
    payload=canonical_serialize({'binding':{'prepared_original_ref':b.prepared_original_ref}})
    db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?)',
        (*b.namespace.as_tuple,'adoption_bridge',b.execution_id,'fixture-adoption',payload,D,D));db.commit()
    graph=object.__new__(GraphCoordinator);graph._GraphCoordinator__store=case.store
    port=object.__new__(V2FencePort);port._transport=object.__new__(MtlsAuthorityTransport)
    graph._GraphCoordinator__content_fence_v2=port
    graph._GraphCoordinator__d11_issuer=case.issuer;graph._GraphCoordinator__d02_issuer=case.issuer._d02
    monkeypatch.setattr(GraphCoordinator,'_admin',lambda self,bootstrap:None)
    monkeypatch.setattr(adoption,'_read_signed',lambda *args,**kwargs:('fixture-adoption',{}))
    monkeypatch.setattr(adoption,'life_bridge_from_wire_v1',lambda raw:gate)
    receipt={'schema':'fixture-durable-receipt','identity':b.digest}
    reads=[]
    def read_receipt(*args,**kwargs):
        reads.append(True)
        return {'changed':True} if race=='saved_receipt' and len(reads)>1 else receipt
    monkeypatch.setattr(adoption,'verify_life_adoption_commit_v1',read_receipt)
    monkeypatch.setattr(adoption,'validate_life_ack_recovery_v1',lambda connection,**kwargs:_validate(connection,recovery))
    pairing=S(installation_id=b.installation_id);calls=[]
    def paired(self,**kwargs):
        calls.append('pairing')
        return S(installation_id='changed') if race=='owner_pairing' and calls.count('pairing')>1 else pairing
    monkeypatch.setattr(V2FencePort,'current_owner_actor_binding',paired)
    def terminal(self,**kwargs):
        calls.append('terminal')
        if race=='deleted_source':db.execute('DELETE FROM graph_atoms WHERE token=?',(prepared.read_rows[0].ref,))
        if race=='source_body':db.execute('UPDATE graph_atoms SET value=? WHERE token=?',('{}',prepared.read_rows[0].ref))
        if race=='generation':db.execute('UPDATE graph_recovery_metadata_v2 SET requirements_json=?',
            (canonical_serialize(plain_v1(replace(requirements,activation_generation=2))),))
        db.commit()
        return (None if race=='claim_receipt' else case.terminal.claim,
            None if race=='terminal_receipt' else case.terminal)
    monkeypatch.setattr(InstalledD11LifePortV1,'read_d11_life_original_v1',terminal)
    # Exercise the real installed method/channel parser for finish ACK. Only
    # the bridge's authenticated contents/encoding are bounded fixture stubs.
    import asyncio
    import sylanne3.authority_service.d11_life_bridge_v1 as bridge
    monkeypatch.setattr(bridge,'life_bridge_to_wire_v1',lambda value:{'fixture':'gate'})
    port._request=object();channel='fixture-local-channel'
    monkeypatch.setattr(V2FencePort,'_identity',lambda self:(S(channel_binding_sha256=channel),
        S(authority_id=b.authority_id,installation_id=b.installation_id,channel_binding_sha256=channel)))
    async def repaired(self,callback):return await callback()
    monkeypatch.setattr(V2FencePort,'_with_session_repair',repaired)
    monkeypatch.setattr(V2FencePort,'_submit',lambda self,coro:asyncio.run(coro))
    async def rpc(self,request,handshake,method,command,**kwargs):
        calls.append(command['action'])
        return {'result':False if race=='false_ack' else True,'channel_binding_sha256':channel}
    monkeypatch.setattr(MtlsAuthorityTransport,'_content_rpc',rpc)
    before=db.execute('SELECT count(*) FROM runtime_budget_operations').fetchone()
    if race=='none':assert adoption.adopt_current_life_v1(graph,object(),namespace=b.namespace,prepared_original_ref=b.prepared_original_ref)==receipt
    else:
        with pytest.raises((ValueError,RuntimeError)):adoption.adopt_current_life_v1(graph,object(),namespace=b.namespace,prepared_original_ref=b.prepared_original_ref)
    assert calls.count('finish')==(1 if race in ('none','false_ack') else 0)
    assert 'begin' not in calls and db.execute('SELECT count(*) FROM runtime_budget_operations').fetchone()==before
