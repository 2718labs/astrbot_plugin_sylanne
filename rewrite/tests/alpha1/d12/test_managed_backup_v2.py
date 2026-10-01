"""Real SQLite recovery/ledger components, not privileged supervisor acceptance."""
import sqlite3
from pathlib import Path
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_sqlite_backup_v2 import snapshot_sqlite_file_v2
from sylanne3.authority_service.d12_managed_backup_v2 import reread_sqlite_backup_v2
from sylanne3.authority_service.d12_managed_backup_cleanup_v2 import _budget_coverage
from sylanne3.runtime.budget import BudgetLease,install_schema,create_budget_lease,reserve_budget,settle_budget
from sylanne3.runtime_contracts import NamespaceId


def test_same_original_copy_ack_loss_reread_never_overwrites_changed_source(tmp_path):
    source=tmp_path/'source.db';target=tmp_path/'backup.db'
    db=sqlite3.connect(source)
    db.execute('CREATE TABLE originals(id INTEGER PRIMARY KEY,payload BLOB NOT NULL) STRICT')
    db.execute('INSERT INTO originals VALUES(1,?)',(b'actual-original\x00',));db.commit()
    first=snapshot_sqlite_file_v2(source,target,maximum_bytes=1024*1024)
    before=target.read_bytes();identity=first['backup_observation']
    replay=reread_sqlite_backup_v2(source,target,first['logical_inventory'],maximum_file_bytes=1024*1024)
    assert replay==first and replay['backup_observation']==identity
    db.execute('INSERT INTO originals VALUES(2,?)',(b'later-terminal',));db.commit()
    with pytest.raises(AuthorityUnavailable,match='originals changed'):
        reread_sqlite_backup_v2(source,target,first['logical_inventory'],maximum_file_bytes=1024*1024)
    assert target.read_bytes()==before
    db.close()


def test_backup_coverage_preserves_all_units_unknown_and_immutable_actual_receipts(tmp_path):
    ns=NamespaceId('bot','persona');source=sqlite3.connect(tmp_path/'old.db')
    install_schema(source)
    create_budget_lease(source,BudgetLease('budget',None,*ns.as_tuple,'USD',{'cpu_ms':100,'model_tokens':200,'model_microusd':300},{},{},{},1,'active'),'create','a'*64)
    reserve_budget(source,'budget','unknown','b'*64,{'model_tokens':20,'model_microusd':30})
    settle_budget(source,'budget','unknown','b'*64,None)
    reserve_budget(source,'budget','cpu','c'*64,{'cpu_ms':10})
    settle_budget(source,'budget','cpu','c'*64,{'cpu_ms':13})
    source.commit();current=sqlite3.connect(tmp_path/'current.db');source.backup(current)
    try:
        result=_budget_coverage(source,current,ns,{})
        assert any(r[0]=='budget_reservation' and r[2]=='unknown' for r in result)
        assert any(r[0]=='budget_receipt' and r[2]=='cpu:settle' for r in result)
        current.execute("UPDATE runtime_budget_leases SET unconfirmed_json='{}' WHERE lease_id='budget'")
        with pytest.raises(AuthorityUnavailable,match='per-unit'):_budget_coverage(source,current,ns,{})
        current.rollback()
        current.execute("DELETE FROM runtime_budget_operations WHERE operation_id='cpu' AND phase='settle'")
        with pytest.raises(AuthorityUnavailable,match='immutable'):_budget_coverage(source,current,ns,{})
        current.rollback()
        current.execute("UPDATE runtime_budget_leases SET used_json='{}' WHERE lease_id='budget'")
        with pytest.raises(AuthorityUnavailable,match='actual spent'):_budget_coverage(source,current,ns,{})
    finally:source.close();current.close()


def test_reconciliation_codec_preserves_original_typed_namespace_commitment():
    from dataclasses import asdict
    from sylanne3.authority_service.installed_migration_reconciliation_v1 import NamespaceExecutionReconciliationV1,_digest
    from sylanne3.authority_service.d12_managed_backup_v2 import _reconciliation
    # A codec-only commitment roundtrip; this DTO does not authorize backup.
    material=dict(namespace=NamespaceId('bot','persona'),authority_namespace='namespace',
        retained_graph_digest='a'*64,deletion_head_digest='sha256:'+'b'*64,
        execution_head_digest='sha256:'+'c'*64,authority_originals_digest='sha256:'+'d'*64,constraints=())
    original=NamespaceExecutionReconciliationV1(**material,original_digest=_digest(material))
    assert _reconciliation(asdict(original),'namespace')==original
    changed=asdict(original);changed['namespace']['persona_id']='other'
    with pytest.raises(AuthorityUnavailable,match='commitment'):_reconciliation(changed,'namespace')
