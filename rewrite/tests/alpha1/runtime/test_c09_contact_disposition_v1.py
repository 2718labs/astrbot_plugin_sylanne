"""Closed disposal contracts and bounded real SQL, not a signed deletion.

No fixture DTO issues an attestation or authorizes physical disposal/restore.
The real installed freeze is checked separately by the four-store acceptance.
"""
from dataclasses import asdict, fields
import json
import sqlite3

import pytest

from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_originals_archive_v1 import install_c09_archive_schema_v1
from sylanne3.authority_service.c09_contact_disposition_v1 import (
    CARRIER_FAMILIES, MAX_CARRIER_ROWS, ContactCarrierInventoryV1, ContactCarrierFamilyV1,
    ContactCarrierRowV1, ContactErasedMemberAttestationV1, SanitizedContactHistoricalCarrierV1,
    decode_contact_disposition_v1, _carrier_family_in_tx_v1,
    _capture_issued_contact_carriers_v1, require_issued_contact_carriers_v1,
)


def committed(kind, digest_field, values):
    values = dict(values)
    values[digest_field] = canonical_digest(tuple(values[f.name] if f.name in values else f.default
        for f in fields(kind) if f.name != digest_field))
    return kind(**values)


def wire(value):
    return json.loads(canonical_serialize(asdict(value)))


@pytest.fixture
def carrier():
    families = tuple(ContactCarrierFamilyV1(role, table, False,
        canonical_digest((role, table, 'absent')), ()) for role, table in CARRIER_FAMILIES)
    return committed(ContactCarrierInventoryV1, 'inventory_digest', dict(
        namespace_commitment='a'*64, operation_commitment='b'*64, source_seal_digest='c'*64,
        current_manifest_digest='d'*64, source_files_commitment='e'*64,
        observed_generation=1, observed_execution_seq=7, families=families))


@pytest.fixture
def sanitized(carrier):
    erased = committed(ContactErasedMemberAttestationV1, 'attestation_digest', dict(
        namespace_commitment='a'*64, business_operation_commitment='b'*64, original_digest='c'*64,
        old_frame_digest='d'*64, old_prepared_digest='e'*64, old_signature_commitment='f'*64,
        old_member_commitment='1'*64, coverage_commitment='2'*64, consumed_fence_commitment='3'*64,
        carrier_inventory_digest=carrier.inventory_digest, disposal_manifest_digest='4'*64,
        disposition_transaction_commitment='5'*64, new_generation=2, observation_seq=8))
    return committed(SanitizedContactHistoricalCarrierV1, 'carrier_digest', dict(
        old_frame_digest=erased.old_frame_digest, old_prepared_digest=erased.old_prepared_digest,
        old_signature_commitment=erased.old_signature_commitment, old_inventory_digest='6'*64,
        old_member_commitments=('1'*64,'7'*64), retained_member_commitments=('7'*64,),
        erased_members=(erased,), carrier_inventory_digest=carrier.inventory_digest,
        new_generation=2, observation_seq=8))


def test_closed_opaque_carriers_roundtrip_without_old_body(carrier, sanitized):
    for value in (carrier, sanitized, sanitized.erased_members[0]):
        assert decode_contact_disposition_v1(wire(value)) == value
    assert set(wire(sanitized)) == {f.name for f in fields(SanitizedContactHistoricalCarrierV1)}
    assert not {'facts_json','prepared_original_json','original_json','resolved_path','namespace','operation_id'} & set(wire(sanitized))


@pytest.mark.parametrize('change', ['omit','replace','overlap','duplicate'])
def test_recomputed_carrier_rejects_incomplete_member_partition(sanitized, change):
    values=asdict(sanitized)
    values['erased_members']=sanitized.erased_members
    values['old_member_commitments']=sanitized.old_member_commitments
    values['retained_member_commitments']=sanitized.retained_member_commitments
    if change=='omit':values['retained_member_commitments']=()
    elif change=='replace':values['retained_member_commitments']=('8'*64,)
    elif change=='overlap':values['retained_member_commitments']=('1'*64,'7'*64)
    else:values['erased_members']=sanitized.erased_members*2
    with pytest.raises(AuthorityUnavailable):committed(SanitizedContactHistoricalCarrierV1,'carrier_digest',values)


@pytest.mark.parametrize('field', ['new_generation','observation_seq'])
def test_recomputed_attestation_rejects_bool_numeric_identity(sanitized, field):
    values=asdict(sanitized.erased_members[0]);values[field]=True
    with pytest.raises(AuthorityUnavailable):committed(ContactErasedMemberAttestationV1,'attestation_digest',values)


@pytest.mark.parametrize('change',['missing_family','duplicate_family','unknown_payload','wrong_old_frame'])
def test_closed_codec_rejects_carrier_or_auth_chain_drift(carrier,sanitized,change):
    if change=='missing_family':
        values=asdict(carrier);values['families']=carrier.families[:-1]
        with pytest.raises(AuthorityUnavailable):committed(ContactCarrierInventoryV1,'inventory_digest',values)
    elif change=='duplicate_family':
        values=asdict(carrier);values['families']=carrier.families+(carrier.families[0],)
        with pytest.raises(AuthorityUnavailable):committed(ContactCarrierInventoryV1,'inventory_digest',values)
    elif change=='unknown_payload':
        raw=wire(sanitized);raw['original_json']='fixture body'
        with pytest.raises(AuthorityUnavailable):decode_contact_disposition_v1(raw)
    else:
        values=asdict(sanitized);values['erased_members']=sanitized.erased_members
        values['old_member_commitments']=sanitized.old_member_commitments
        values['retained_member_commitments']=sanitized.retained_member_commitments
        values['old_frame_digest']='9'*64
        with pytest.raises(AuthorityUnavailable):committed(SanitizedContactHistoricalCarrierV1,'carrier_digest',values)


def test_dto_cannot_issue_or_restore_disposal(carrier):
    with pytest.raises(AuthorityUnavailable,match='actual freeze'):
        _capture_issued_contact_carriers_v1(object(),inventory=carrier)
    with pytest.raises(AuthorityUnavailable,match='active issued'):
        require_issued_contact_carriers_v1(object(),carrier)


@pytest.fixture
def sql_carrier():
    db=sqlite3.connect(':memory:')
    install_c09_archive_schema_v1(db)
    db.execute('BEGIN')
    try:yield db
    finally:db.close()


def test_real_sql_carriers_include_duplicate_body_locations_and_negative_table(sql_carrier):
    db=sql_carrier
    for operation in ('old-a','old-b'):
        db.execute('INSERT INTO authority_c09_recovery_fact_frames_v4 VALUES(?,?,?,?)',
            ('fixture',operation,'same covered fixture body','a'*64))
    family=_carrier_family_in_tx_v1(db,role='core',table='authority_c09_recovery_fact_frames_v4',
        namespace='fixture',installation_id='installation')
    assert family.present and len(family.rows)==2
    assert len({r.locator_commitment for r in family.rows})==2
    assert 'same covered fixture body' not in canonical_serialize(asdict(family))
    absent=_carrier_family_in_tx_v1(db,role='core',table='authority_c09_contact_finish_originals_v1',
        namespace='fixture',installation_id='installation')
    assert not absent.present and absent.rows==()


def test_real_sql_overlimit_holds_before_partial_inventory(sql_carrier):
    db=sql_carrier
    db.executemany('INSERT INTO authority_c09_recovery_fact_frames_v4 VALUES(?,?,?,?)',
        (('fixture',str(i),'fixture','a'*64) for i in range(MAX_CARRIER_ROWS+1)))
    with pytest.raises(AuthorityUnavailable,match='exceeds finite limit'):
        _carrier_family_in_tx_v1(db,role='core',table='authority_c09_recovery_fact_frames_v4',
            namespace='fixture',installation_id='installation')


def test_real_sql_inventory_requires_pinned_snapshot(sql_carrier):
    sql_carrier.rollback()
    with pytest.raises(AuthorityUnavailable,match='pinned known SQL family'):
        _carrier_family_in_tx_v1(sql_carrier,role='core',table='authority_c09_recovery_fact_frames_v4',
            namespace='fixture',installation_id='installation')


def test_surface_carrier_uses_real_operation_installation_join():
    from sylanne3.authority_service.c09_storage_control_v1 import _DDL
    with sqlite3.connect(':memory:') as db:
        db.execute(_DDL['c09_storage_operations_v1'])
        db.execute(_DDL['c09_storage_surface_evidence_v1'])
        for operation, installation in (('one','installed'),('two','other')):
            db.execute('INSERT INTO c09_storage_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                (operation,installation,'fixture',1,0,'a'*64,'b'*64,'covered fixture body',
                 canonical_digest(operation),'key','signature'))
            db.execute('INSERT INTO c09_storage_surface_evidence_v1 VALUES(?,?,?,?,?,?,?)',
                (operation,'controlled_backups','covered fixture body',canonical_digest((operation,'surface')),
                 'issuer','key','signature'))
        result=_carrier_family_in_tx_v1(db,role='control',table='c09_storage_surface_evidence_v1',
            namespace='fixture',installation_id='installed')
        assert result.present and len(result.rows)==1
        assert 'covered fixture body' not in canonical_serialize(asdict(result))


def test_surface_orphan_cannot_disappear_through_installation_join():
    from sylanne3.authority_service.c09_storage_control_v1 import _DDL
    with sqlite3.connect(':memory:') as db:
        # Model an offline damaged database. Enabling FK on open cannot
        # retroactively authenticate or remove its pre-existing orphan.
        db.execute(_DDL['c09_storage_operations_v1'])
        db.execute(_DDL['c09_storage_surface_evidence_v1'])
        db.execute('INSERT INTO c09_storage_surface_evidence_v1 VALUES(?,?,?,?,?,?,?)',
            ('missing','controlled_backups','fixture body','a'*64,'issuer','key','signature'))
        with pytest.raises(AuthorityUnavailable,match='orphan surface'):
            _carrier_family_in_tx_v1(db,role='control',table='c09_storage_surface_evidence_v1',
                namespace='fixture',installation_id='installed')


@pytest.mark.parametrize('field', ['old_member_commitments','erased_members'])
def test_closed_array_bound_checked_before_member_decode(sanitized,field):
    raw=wire(sanitized)
    raw[field]=[None]*1025
    with pytest.raises(AuthorityUnavailable,match='closed and bounded'):
        decode_contact_disposition_v1(raw)
