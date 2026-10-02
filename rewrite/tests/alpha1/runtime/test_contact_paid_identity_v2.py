"""Paid V2 identity/schema boundaries, not installed model acceptance."""
from dataclasses import replace
import sqlite3

import pytest

from test_contact_plan_v2 import proof
from sylanne3.runtime.contact_model_job_v2 import contact_model_ids_v2
from sylanne3.runtime.contact_model_job_v1 import contact_model_ids_v1
from sylanne3.runtime.contact_product_adapter_v2 import PrepareCurrentContactModelRequestV2
from sylanne3.runtime.contact_paid_original_v2 import (
    TABLE, TRIGGERS, install_contact_original_schema_v2, require_contact_original_schema_v2,
    record_contact_original_v2, read_contact_original_v2,
)
from sylanne3.authority_service.contact_model_result_contract_v2 import (
    ContactModelResultReadRequestV2, contact_result_from_wire_v2,
)
from sylanne3.domains.d01.production_operations_v1 import plain_v1


def test_paid_v2_once_ids_consume_frozen_reservation_and_distinct_calls(proof):
    plan = proof.plan
    gen = contact_model_ids_v2(plan, 'contact_generation')
    review = contact_model_ids_v2(plan, 'contact_review')
    assert gen['prepare'] == plan.generation_reservation_id
    assert review['prepare'] == plan.review_reservation_id
    assert gen['prepare'] == contact_model_ids_v1(plan, 'contact_generation')['prepare']
    assert set(gen.values()).isdisjoint(set(review.values()))
    assert gen == contact_model_ids_v2(plan, 'contact_generation')
    assert gen['call'] != contact_model_ids_v1(plan, 'contact_generation')['call']
    # Public command operation IDs are not inputs to this once identity.
    with pytest.raises(TypeError):
        contact_model_ids_v2(plan, 'contact_generation', operation_id='fresh-charge')


@pytest.mark.parametrize('change', ('columns', 'trigger', 'pk'))
def test_actual_sql_schema_drift_refuses_original_access(change):
    with sqlite3.connect(':memory:') as db:
        install_contact_original_schema_v2(db)
        if change == 'trigger':
            db.execute(f'DROP TRIGGER {TABLE}_no_delete')
        elif change == 'columns':
            db.execute(f'ALTER TABLE {TABLE} ADD COLUMN unexplained TEXT')
        else:
            db.execute(f'DROP TABLE {TABLE}')
            db.execute(f'CREATE TABLE {TABLE}(bot,persona,kind,original_ref,payload_json,payload_digest,signature)')
        with pytest.raises(ValueError, match='exact columns'):
            require_contact_original_schema_v2(db)
        with pytest.raises(ValueError, match='exact columns'):
            read_contact_original_v2(db, object(), proof_namespace(), 'prepared', 'missing')
        db.execute('BEGIN') if not db.in_transaction else None
        with pytest.raises(ValueError, match='exact columns'):
            record_contact_original_v2(db, object(), proof_namespace(), 'prepared', 'missing', {})


def proof_namespace():
    from sylanne3.runtime_contracts import NamespaceId
    return NamespaceId('bot', 'persona')


@pytest.mark.parametrize('contact', (True, 'contact:' + 'a'*300, 'arbitrary'))
def test_request_v2_is_a_closed_bounded_locator(contact):
    with pytest.raises((TypeError, ValueError)):
        PrepareCurrentContactModelRequestV2(contact, 'contact_generation')


def test_v2_original_table_is_not_a_legacy_plan_carrier():
    with sqlite3.connect(':memory:') as db:
        install_contact_original_schema_v2(db)
        db.execute('BEGIN')
        with pytest.raises(ValueError, match='closed kind'):
            record_contact_original_v2(db, object(), proof_namespace(), 'plan', 'legacy', {})


def test_result_request_v2_roundtrip_and_legacy_purpose_refusal(proof):
    plan = proof.plan
    ids = contact_model_ids_v2(plan, 'contact_generation')
    request = ContactModelResultReadRequestV2('authority', 'bot/persona', plan.namespace,
        'installation', plan.contact_id, 'contact_generation', ids['job'], ids['acquire'],
        ids['prepare'], ids['call'], 'a'*64, 'b'*64, 'consumer', 'read-attempt')
    assert contact_result_from_wire_v2(plain_v1(request), ContactModelResultReadRequestV2) == request
    with pytest.raises(ValueError, match='scope differs'):
        replace(request, purpose='contact_paid_expression')
    with pytest.raises(ValueError, match='scope differs'):
        replace(request, schema='d10.contact-model-result-read.v1')
    raw = plain_v1(request); raw['extra'] = True
    with pytest.raises(ValueError, match='exact fields'):
        contact_result_from_wire_v2(raw, ContactModelResultReadRequestV2)
