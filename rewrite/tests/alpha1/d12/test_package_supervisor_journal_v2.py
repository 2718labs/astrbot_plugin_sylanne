"""Durable signed data-layer acceptance; no process or Owner authority invented."""
from dataclasses import asdict
import sqlite3
from uuid import uuid4
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_package_maintenance_contract_v2 import build_d12_package_intent_v2,D12PackageStageReceiptV2
from sylanne3.authority_service.d12_package_supervisor_journal_v2 import _install_schema,_SupervisorJournalKernelV2
from sylanne3.runtime_contracts import canonical_digest


def intent():
    return build_d12_package_intent_v2(operation_id=str(uuid4()),request_digest='a'*64,authority_id='authority:test',installation_id='installation:test',
        namespace_cohort=('namespace:test',),current_storage_identity_digest='b'*64,current_owner_heads_digest='c'*64,
        lifecycle_operation_id=str(uuid4()),lifecycle_epoch=2,old_package_id='old',old_manifest_sha256='d'*64,
        old_cohort_ref='cohort:old',old_cohort_digest='e'*64,expected_selection_revision=0,expected_selection_digest='f'*64,
        expected_package_epoch=0,candidate_package_id='new',candidate_manifest_sha256='1'*64,candidate_cohort_ref='cohort:new',
        candidate_cohort_digest='2'*64,compatibility_plan_digest='3'*64,managed_backup_ref='backup:test',supervisor_policy_digest='4'*64)


def receipt(value,pending,stage=None):
    body=dict(operation_id=value.operation_id,accepted_original_digest=value.accepted_original_digest,
        stage=stage or pending['stage'],stage_sequence=pending['stage_sequence'],prior_receipt_digest=pending['prior_receipt_digest'],
        observation_refs=((value.accepted_original_ref,value.accepted_original_digest),),schema='d12.compatible-package-stage.v2')
    return D12PackageStageReceiptV2(**body,receipt_digest=canonical_digest(body))


def test_actual_journal_cold_replay_pending_intent_and_signature(tmp_path):
    path=tmp_path/'journal.db';db=sqlite3.connect(path);_install_schema(db)
    value=intent();key=b'K'*32
    store=_SupervisorJournalKernelV2(db,key,'4'*64)
    store._register_observed_acceptance(value)
    assert store._register_observed_acceptance(value)==value
    with pytest.raises(AuthorityUnavailable,match='skips'):
        store._prepare_stage(value.operation_id,'active')
    pending=store._prepare_stage(value.operation_id,'accepted')
    assert store._prepare_stage(value.operation_id,'accepted')==pending
    first=receipt(value,pending);store._record_observed_stage(first);db.close()
    db=sqlite3.connect(path);store=_SupervisorJournalKernelV2(db,key,'4'*64)
    try:
        assert store.read_intent(value.operation_id)==value
        assert store.read_receipts(value.operation_id)==(first,)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public=Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        verifier=_SupervisorJournalKernelV2(db,None,'4'*64,verification_key=public)
        assert verifier.read_receipts(value.operation_id)==(first,)
        with pytest.raises(AuthorityUnavailable,match='cannot sign'):
            verifier._register_observed_acceptance(intent())
        assert store._record_observed_stage(first)==first
        pending=store._prepare_stage(value.operation_id,'packages_verified')
        # Crash/lost acknowledgement before recording observation preserves one
        # exact stage intent, not an inferred successful package verification.
        assert store.read_receipts(value.operation_id)==(first,)
        assert store._prepare_stage(value.operation_id,'packages_verified')==pending
        with pytest.raises(AuthorityUnavailable,match='skips'):
            store._prepare_stage(value.operation_id,'quiescing')
        with pytest.raises(AuthorityUnavailable,match='signature'):
            _SupervisorJournalKernelV2(db,b'X'*32,'4'*64).read_intent(value.operation_id)
        with pytest.raises(AuthorityUnavailable,match='policy'):
            _SupervisorJournalKernelV2(db,key,'0'*64).read_intent(value.operation_id)
        unknown=receipt(value,pending,'unknown');store._record_observed_stage(unknown)
        assert store.read_receipts(value.operation_id)==(first,unknown)
        with pytest.raises(AuthorityUnavailable,match='unknown side effect'):
            store._prepare_stage(value.operation_id,'quiescing')
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            db.execute('DELETE FROM package_stage_receipts_v2')
        db.rollback()
    finally:db.close()
