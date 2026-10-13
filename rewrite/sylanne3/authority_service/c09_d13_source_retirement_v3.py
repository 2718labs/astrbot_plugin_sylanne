"""Bodyless D13 Source retirement originals; these records confer no execution right."""
from __future__ import annotations
import json
import sqlite3
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize

TABLE='authority_c09_d13_source_retirements_v3'
SCHEMA='sylanne3.c09.d13-source-retirement.v3'
COLUMNS=('namespace','kind','item_id','phase','counter_operation_id','generation_call_id','retirement_digest','retirement_json','key_id','signature')
DDL="""CREATE TABLE authority_c09_d13_source_retirements_v3(
 namespace TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('counter','http')),item_id TEXT NOT NULL,
 phase TEXT NOT NULL,counter_operation_id TEXT NOT NULL,generation_call_id TEXT NOT NULL,
 retirement_digest TEXT NOT NULL UNIQUE,retirement_json TEXT NOT NULL,key_id TEXT NOT NULL,signature TEXT NOT NULL,
 PRIMARY KEY(namespace,kind,item_id,phase)) STRICT"""
TRIGGERS={TABLE+'_no_'+op.lower()+'_v3':'CREATE TRIGGER '+TABLE+'_no_'+op.lower()+'_v3 BEFORE '+op+' ON '+TABLE+
    " BEGIN SELECT RAISE(ABORT,'D13 Source retirement original is immutable'); END" for op in ('UPDATE','DELETE')}
FIELDS=frozenset(('schema','authority_id','installation_id','namespace','maintenance_operation_id','scope_digest',
    'source_role_digest','source_table','source_primary_key','physical_schema_digest','logical_shape_digest',
    'source_descriptor_digest','source_physical_row_commitment','source_logical_row_commitment','source_payload_digest',
    'source_payload_origin_scope_digest','source_cell_header','source_member',
    'kind','item_id','phase','counter_operation_id','frame_intent_digest','generation_call_id','execution_id',
    'graph_disposition_root','graph_disposition_count','facts_pin_digest','actual_facts','pending_obligations','retirement_reason',
    'retirement_digest','key_id','signature'))


def require_retirement_schema_v3(db,*,meter=None):
    row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    if row is None:return False
    if meter is not None:meter.charge_read(len(row[0].encode('utf8')))
    if row!=(DDL,):raise AuthorityUnavailable('actual D13 retirement metadata schema differs')
    for name,ddl in TRIGGERS.items():
        row=db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name,)).fetchone()
        if meter is not None:meter.charge_read(0 if row is None else len(row[0].encode('utf8')))
        if row!=(ddl,):raise AuthorityUnavailable('actual D13 retirement immutable trigger differs')
    return True


def validate_retirement_original_v3(control,original):
    if type(original) is not dict or set(original)!=FIELDS or original['schema']!=SCHEMA:
        raise AuthorityUnavailable('exact bodyless D13 retirement original required')
    control.verify_original_v1(original,'retirement_digest')
    kind=original['kind'];phases={'draft','header','evidence'} if kind=='counter' else {'expected','observed_before_send'}
    expected_table='authority_d13_counter_originals_v1' if kind=='counter' else 'authority_d13_provider_http_bindings_v1'
    if (kind not in {'counter','http'} or original['phase'] not in phases or original['source_table']!=expected_table
            or original['authority_id']!=control.authority_id or original['installation_id']!=control.installation_id
            or original['source_primary_key']!=[original['namespace'],original['item_id'],original['phase']]
            or original['item_id']!=(original['counter_operation_id'] if kind=='counter' else original['generation_call_id'])
            or original['retirement_reason'] not in {'source_revoked_never_started','source_revoked_terminal','source_revoked_unknown_obligation'}
            or type(original['actual_facts']) is not dict or type(original['graph_disposition_count']) is not int
            or original['graph_disposition_count']<1):
        raise AuthorityUnavailable('actual D13 retirement identity/source/facts disposition differs')
    for field in ('scope_digest','source_role_digest','physical_schema_digest','source_descriptor_digest',
        'source_physical_row_commitment','source_payload_digest','frame_intent_digest','graph_disposition_root','facts_pin_digest'):
        value=original[field]
        if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
            raise AuthorityUnavailable('actual D13 retirement complete commitment differs: '+field)
    pending=original['pending_obligations']
    if type(pending) is not list or len(pending) not in {0,3} or (pending and {item['kind'] for item in pending}!={'job','budget','body'}):
        raise AuthorityUnavailable('actual D13 pending obligations inventory differs from its three original accounting families')
    source=original['source_member'];origin=original['source_payload_origin_scope_digest'];header=original['source_cell_header']
    if original['logical_shape_digest'] is None:
        if source is not None or origin is not None or header is not None or original['source_logical_row_commitment'] is not None:
            raise AuthorityUnavailable('legacy D13 Source cannot borrow a mapped origin/cutoff member')
    else:
        if (type(source) is not dict or set(source)!={'stream_id','record_ordinal','table_name','primary_key','descriptor_digest'}
                or source['table_name']!=original['source_table'] or source['primary_key']!=original['source_primary_key']
                or source['descriptor_digest']!=original['source_descriptor_digest']
                or type(source['record_ordinal']) is not int or source['record_ordinal']<1):
            raise AuthorityUnavailable('mapped D13 retirement lacks its actual captured Source member locator')
        if (type(header) is not list or len(header)!=9 or header[1]!='canonical-json.ascii.v1'
                or header[6]!=original['source_payload_digest'] or header[8]!=origin
                or type(header[4]) is not int or header[4]<1 or type(header[5]) is not int or header[5]<1):
            raise AuthorityUnavailable('mapped D13 retirement full original cell header differs from its Source payload/scope')
        for value in (origin,header[0],header[6],header[7],original['logical_shape_digest'],original['source_logical_row_commitment'],source['stream_id']):
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise AuthorityUnavailable('mapped D13 retirement origin/shape/member commitment differs')
    return original


def require_not_retired_d13_source_v3(db,*,control,namespace,kind,item_id):
    """Actual business point gate; absence cannot revive a retired frame/call."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise AuthorityUnavailable('D13 retirement point gate requires actual Core transaction')
    if not require_retirement_schema_v3(db):return
    rows=db.execute('SELECT '+','.join(COLUMNS)+' FROM '+TABLE+
        ' WHERE namespace=? AND kind=? AND item_id=? ORDER BY phase LIMIT 4',(namespace,kind,item_id)).fetchall()
    if not rows:return
    if control is None:raise AuthorityUnavailable('actual installed Control must verify D13 Source retirement')
    for row in rows:
        raw=row[COLUMNS.index('retirement_json')]
        if len(raw.encode('utf8'))>65536:raise AuthorityUnavailable('actual bodyless D13 retirement exceeds fixed metadata bound')
        original=validate_retirement_original_v3(control,json.loads(raw))
        if (row[:6]!=(original['namespace'],original['kind'],original['item_id'],original['phase'],
                original['counter_operation_id'],original['generation_call_id']) or row[6]!=original['retirement_digest']
                or row[8:]!=(original['key_id'],original['signature'])):
            raise AuthorityUnavailable('actual D13 Source retirement SQL row/original binding differs')
    raise AuthorityUnavailable('D13 Source execution right was retired by actual C09 content disposition')


def issue_d13_source_retirement_v3(builder,qualified,*,meter):
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2,_D13CoreDispositionReadV3
    if type(builder) is not _InstalledAuthorityRoleBuilderV2 or type(qualified) is not _D13CoreDispositionReadV3:
        raise AuthorityUnavailable('actual private D13 Source disposition producer required')
    body=qualified.require_retirement_body(builder,meter=meter)
    control=builder.session._control.maintenance.control
    original=control.sign_original_v1(SCHEMA,body,'retirement_digest')
    validate_retirement_original_v3(control,original)
    raw=canonical_serialize(original)
    if len(raw.encode('utf8'))>65536:raise AuthorityUnavailable('actual D13 bodyless retirement needs its fixed metadata profile')
    return original
