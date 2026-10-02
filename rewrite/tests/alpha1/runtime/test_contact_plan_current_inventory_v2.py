"""Actual finite SQLite inventory checks; Owner/expression bodies are seams.

The real closed original decoder is exercised. These public fixture values
do not issue a production stage or grant current Contact permission.
"""
from dataclasses import replace
import json

import pytest

from test_contact_plan_v2 import proof, graph, NS, D
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d08.contact_plan_v2 import contact_plan_keys_v2
from sylanne3.domains.d09.natural_reply import NaturalExpressionPlanV2
from sylanne3.graph_types import AtomKey, GraphAtom, Owner
from sylanne3.runtime.contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
from sylanne3.runtime.contact_plan_adoption_v2 import SIGN_KIND, require_contact_inventory_current_v2
from sylanne3.runtime_contracts import VersionedRef, canonical_digest, canonical_serialize


def original(proof):
    proof=replace(proof,plan=replace(proof.plan,qualified_units_digest=canonical_digest(())))
    plan=proof.plan
    expression=NaturalExpressionPlanV2(NS,VersionedRef(contact_plan_keys_v2(plan)[0].token,1),
        plan.source_ref,plan.source_ref,(),('paraphrase',),(),(),10.,plan.activity_id,
        'final-operation','final-effect','scene','user')
    inventories={kind:[plain_v1(GraphAtom(AtomKey.from_token(row.ref),row.revision,
        json.loads(row.value_json),row.valid)) for row in proof.historical_reads
        if row.revision and AtomKey.from_token(row.ref).type_name==kind]
        for kind in CONTACT_CURRENT_TYPES}
    return {'schema':SIGN_KIND,'plan':plain_v1(plan),'expression':plain_v1(expression),
        'proof':plain_v1(proof),'producing_operation_id':proof.producing_operation_id,
        'receipt_digest':D,'policy_ref':next(row.ref for row in proof.historical_reads
            if AtomKey.from_token(row.ref).type_name=='d10.contact_policy.v1'),
        'opportunity_ref':plan.opportunity_ref.ref,'route_ref':plan.route_account_ref.ref,
        'current_inventories':inventories}


def test_actual_current_inventory_requires_transaction_and_complete_rows(proof,graph):
    raw=original(proof)
    with pytest.raises(ValueError,match='transaction'):
        require_contact_inventory_current_v2(graph._db,NS,raw)
    graph._db.execute('BEGIN')
    try:
        assert require_contact_inventory_current_v2(graph._db,NS,raw)
    finally:graph._db.rollback()


@pytest.mark.parametrize('change',['new_claim','changed_policy','invalid_policy','deleted_policy'])
def test_actual_current_inventory_rejects_new_and_changed_heads(proof,graph,change):
    raw=original(proof);db=graph._db;db.execute('BEGIN')
    try:
        policy=next(row.ref for row in proof.historical_reads
            if AtomKey.from_token(row.ref).type_name=='d10.contact_policy.v1')
        if change=='new_claim':
            key=AtomKey(Owner('persona',*NS.as_tuple),'d10.contact_claim.v2','new-claim')
            db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
                (key.token,*NS.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,
                 1,canonical_serialize({'fixture':'new claim'}),1))
        elif change=='changed_policy':db.execute('UPDATE graph_atoms SET revision=2 WHERE token=?',(policy,))
        elif change=='invalid_policy':db.execute('UPDATE graph_atoms SET valid=0 WHERE token=?',(policy,))
        else:db.execute('DELETE FROM graph_atoms WHERE token=?',(policy,))
        with pytest.raises(ValueError,match='inventory changed'):
            require_contact_inventory_current_v2(db,NS,raw)
    finally:db.rollback()
