"""Closed Plan B original inventory and actual historical Graph joins."""
import json
import sqlite3

from .contact_plan_adoption_v2 import (
    TABLE,COLUMNS,SIGN_KIND,install_contact_plan_original_schema_v2,
    validate_contact_plan_original_payload_v2,validate_contact_plan_history_v2,
)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey


def validate_contact_plan_original_schema_v2(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute('BEGIN');install_contact_plan_original_schema_v2(expected)
        sql="SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name"
        if tuple(db.execute(sql,(TABLE,)))!=tuple(expected.execute(sql,(TABLE,))):
            raise ValueError('Contact Plan v2 actual original DDL/triggers differ')


def read_contact_plan_inventory_row_v2(columns,row,*,issuer=None):
    if tuple(columns)!=COLUMNS or len(row)!=len(COLUMNS):
        raise ValueError('Contact Plan v2 exact original row columns differ')
    namespace=NamespaceId(row[0],row[1]);raw=json.loads(row[3])
    plan,expression,proof=validate_contact_plan_original_payload_v2(raw)
    if (namespace!=plan.namespace or row[2]!=plan.contact_id or canonical_serialize(raw)!=row[3]
            or canonical_digest(raw)!=row[4] or type(row[5]) is not str
            or len(row[5])!=64 or any(c not in '0123456789abcdef' for c in row[5])):
        raise ValueError('Contact Plan v2 actual original SQL locator/digest/signature shape differs')
    if issuer is not None:
        issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,plan.contact_id,row[4])),row[5])
    return namespace,plan,expression,proof,raw


def validate_contact_plan_original_history_row_v2(db,columns,row):
    namespace,_plan,_expression,proof,raw=read_contact_plan_inventory_row_v2(columns,row)
    actual=read_adopted_domain_operation_v1(db,namespace,proof.producing_operation_id)
    if actual is None or canonical_digest(actual['receipt'])!=raw['receipt_digest']:
        raise ValueError('Contact Plan v2 actual producing COMMIT missing')
    validate_contact_plan_history_v2(db,proof=proof,actual=actual)
    return proof


def contact_plan_original_dispositions_v2(db,columns,rows,*,affected,affected_operations):
    result=[]
    for row in rows:
        proof=validate_contact_plan_original_history_row_v2(db,columns,row)
        references={read.ref for read in proof.historical_reads}
        if references & set(affected) or proof.producing_operation_id in affected_operations:
            result.append('derived_removed')
        else:result.append('preserved_exact')
    return tuple(result)
