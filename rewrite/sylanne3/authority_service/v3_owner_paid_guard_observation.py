"""Actual immutable Owner guard observations for fenced paid D13 originals."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .contract import AuthorityUnavailable, identifier
from .v2_owner_contract import OwnerAuthorizationGuardV1, to_wire as owner_to_wire, from_wire as owner_from_wire
from .v2_contract import FencePermitV2, to_wire as fence_to_wire, from_wire as fence_from_wire
from ..runtime_contracts import NamespaceId, namespace_ref, canonical_digest, canonical_serialize
from ..runtime.c09_paged_sql_v2 import peek_current_c09_sql_meter_v3

SCHEMA='sylanne3.owner.paid-guard-observation.v3'
TABLE='authority_owner_paid_guard_observations_v3'
COLUMNS=('authority_namespace','business_operation_id','phase','fence_operation_id','payload_json','payload_digest')
DDL="""CREATE TABLE authority_owner_paid_guard_observations_v3 (
    authority_namespace TEXT NOT NULL,
    business_operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('schedule','acquire')),
    fence_operation_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    PRIMARY KEY(authority_namespace,business_operation_id,phase,fence_operation_id)
) STRICT"""
TRIGGERS={TABLE+'_no_'+operation.lower(): 'CREATE TRIGGER '+TABLE+'_no_'+operation.lower()+
    ' BEFORE '+operation+' ON '+TABLE+" BEGIN SELECT RAISE(ABORT,'paid Owner guard observation is immutable'); END"
    for operation in ('UPDATE','DELETE')}
DDL_MAP={TABLE:DDL,**TRIGGERS}

GRAPH_TABLE='graph_d13_paid_owner_guard_links_v3'
GRAPH_COLUMNS=('bot','persona','business_operation_id','phase','fence_operation_id',
    'request_digest','observation_digest','receipt_digest')
GRAPH_DDL="""CREATE TABLE graph_d13_paid_owner_guard_links_v3 (
    bot TEXT NOT NULL,
    persona TEXT NOT NULL,
    business_operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('schedule','acquire')),
    fence_operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    observation_digest TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    PRIMARY KEY(bot,persona,business_operation_id,phase)
) STRICT"""
GRAPH_TRIGGERS={GRAPH_TABLE+'_no_'+operation.lower(): 'CREATE TRIGGER '+GRAPH_TABLE+'_no_'+operation.lower()+
    ' BEFORE '+operation+' ON '+GRAPH_TABLE+" BEGIN SELECT RAISE(ABORT,'paid Owner guard business link is immutable'); END"
    for operation in ('UPDATE','DELETE')}
GRAPH_DDL_MAP={GRAPH_TABLE:GRAPH_DDL,**GRAPH_TRIGGERS}


def _hex(value,name):
    if type(value) is not str or len(value)!=64 or any(char not in '0123456789abcdef' for char in value):
        raise ValueError('invalid '+name)


def _wire_bytes(value):
    text=canonical_serialize(value)
    raw=text.encode('ascii')
    meter=peek_current_c09_sql_meter_v3()
    if meter is not None:meter.charge_encode(len(raw))
    return raw


def _root_db(db):
    from .c09_graph_application_v1 import c09_actual_root_read_v3
    return c09_actual_root_read_v3(db)


def _write(db,sql,parameters):
    meter=peek_current_c09_sql_meter_v3()
    if meter is None:return db.execute(sql,parameters)
    from ..runtime.c09_paged_sql_v2 import _capture_write_v2
    return _capture_write_v2(db,sql,parameters)


def _require_schema(db,table,catalogue):
    db=_root_db(db)
    for name,ddl in catalogue.items():
        kind='table' if name==table else 'trigger'
        if db.execute("SELECT tbl_name,sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()!=(table,ddl):
            raise AuthorityUnavailable('actual immutable paid Owner original schema differs')


def require_owner_paid_guard_observation_schema_v3(db):
    _require_schema(db,TABLE,DDL_MAP)


def require_paid_owner_guard_link_schema_v3(db):
    _require_schema(db,GRAPH_TABLE,GRAPH_DDL_MAP)


def _install(db,table,catalogue):
    bounded=_root_db(db)
    for name,ddl in catalogue.items():
        kind='table' if name==table else 'trigger'
        row=bounded.execute("SELECT tbl_name,sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
        if row is None:
            meter=peek_current_c09_sql_meter_v3()
            if meter is not None:
                encoded=ddl.encode('utf8');meter.charge_encode(len(encoded));meter.charge_write(len(encoded))
            _write(db,ddl,())
        elif row!=(table,ddl):raise AuthorityUnavailable('paid Owner original installation schema differs')
    _require_schema(db,table,catalogue)


def install_owner_paid_guard_observations_v3(db):
    _install(db,TABLE,DDL_MAP)


def install_paid_owner_guard_links_v3(db):
    _install(db,GRAPH_TABLE,GRAPH_DDL_MAP)


@dataclass(frozen=True,slots=True)
class OwnerPaidGuardObservationV3:
    authority_namespace:str
    business_operation_id:str
    request_digest:str
    phase:str
    issue_operation_id:str
    head_commitment:str
    guard:OwnerAuthorizationGuardV1
    permit:FencePermitV2
    schema:str=SCHEMA

    def __post_init__(self):
        for name in ('authority_namespace','business_operation_id','issue_operation_id'):
            identifier(getattr(self,name),name)
        _hex(self.request_digest,'paid original request digest')
        _hex(self.head_commitment,'actual Owner head commitment')
        if (self.schema!=SCHEMA or self.phase not in {'schedule','acquire'}
                or type(self.guard) is not OwnerAuthorizationGuardV1 or type(self.permit) is not FencePermitV2
                or self.permit.operation!='write' or self.permit.namespace!=self.authority_namespace
                or namespace_ref(self.guard.namespace)!=self.authority_namespace
                or self.guard.authority_id!=self.permit.authority_id
                or self.guard.authorization_revision!=1 or self.guard.pending_revoke_operation_id is not None
                or self.guard.minimum_revocation_revision!=0 or self.guard.minimum_revocation_epoch!=0):
            raise ValueError('exact active original paid Owner guard/write permit required')

    @property
    def digest(self):
        return sha256(_wire_bytes(owner_paid_guard_observation_to_wire_v3(self))).hexdigest()


def owner_paid_guard_observation_to_wire_v3(value):
    if type(value) is not OwnerPaidGuardObservationV3:
        raise TypeError('typed actual Owner paid guard observation required')
    return {'schema':value.schema,'authority_namespace':value.authority_namespace,
        'business_operation_id':value.business_operation_id,'request_digest':value.request_digest,
        'phase':value.phase,'issue_operation_id':value.issue_operation_id,
        'head_commitment':value.head_commitment,
        'guard':owner_to_wire(value.guard),'permit':fence_to_wire(value.permit)}


def owner_paid_guard_observation_from_wire_v3(raw):
    fields={'schema','authority_namespace','business_operation_id','request_digest','phase',
        'issue_operation_id','head_commitment','guard','permit'}
    if type(raw) is not dict or set(raw)!=fields:
        raise ValueError('paid Owner observation exact fields required')
    value=dict(raw)
    value['guard']=owner_from_wire(value['guard'])
    value['permit']=fence_from_wire(value['permit'])
    return OwnerPaidGuardObservationV3(**value)


def validate_owner_paid_guard_observation_row_v3(row):
    if type(row) is not tuple or len(row)!=len(COLUMNS):
        raise ValueError('actual paid Owner observation row shape differs')
    value=owner_paid_guard_observation_from_wire_v3(json.loads(row[4]))
    payload=_wire_bytes(owner_paid_guard_observation_to_wire_v3(value))
    if (row[:4]!=(value.authority_namespace,value.business_operation_id,value.phase,value.permit.operation_id)
            or row[4].encode('ascii')!=payload or row[5]!=sha256(payload).hexdigest()):
        raise ValueError('actual paid Owner observation row identity or bytes differ')
    return value


def _record_owner_paid_guard_observation_v3(db,*,authority_namespace,business_operation_id,
        request_digest,phase,guard,permit,head):
    if not db.in_transaction:
        raise AuthorityUnavailable('paid Owner observation needs the real Core guard transaction')
    require_owner_paid_guard_observation_schema_v3(db)
    if (type(head) is not tuple or len(head)!=6
            or head[:5]!=(authority_namespace,head[1],head[1],1,'active')):
        raise AuthorityUnavailable('paid Owner observation lacks exact active original issue head')
    from .v2_owner_contract import canonical_bytes as owner_bytes
    if head[5]!=owner_bytes(guard):
        raise AuthorityUnavailable('paid Owner observation head/guard bytes differ')
    commitment=canonical_digest(tuple({'blob_sha256':sha256(item).hexdigest(),'size':len(item)}
        if type(item) is bytes else item for item in head))
    value=OwnerPaidGuardObservationV3(authority_namespace,business_operation_id,request_digest,phase,head[1],commitment,guard,permit)
    payload=_wire_bytes(owner_paid_guard_observation_to_wire_v3(value))
    expected=(authority_namespace,business_operation_id,phase,permit.operation_id,payload.decode('ascii'),sha256(payload).hexdigest())
    bounded=_root_db(db)
    prior=bounded.execute('SELECT '+','.join(COLUMNS)+' FROM '+TABLE+
        ' WHERE authority_namespace=? AND business_operation_id=? AND phase=? AND fence_operation_id=?',expected[:4]).fetchone()
    if prior is not None:
        if prior!=expected:raise AuthorityUnavailable('paid Owner observation immutable replay differs')
        return validate_owner_paid_guard_observation_row_v3(prior)
    _write(db,'INSERT INTO '+TABLE+'('+','.join(COLUMNS)+') VALUES(?,?,?,?,?,?)',expected)
    return value


def validate_paid_owner_guard_link_row_v3(row):
    if type(row) is not tuple or len(row)!=len(GRAPH_COLUMNS):
        raise ValueError('actual paid Owner business link row shape differs')
    namespace=NamespaceId(row[0],row[1])
    for index in (2,4):identifier(row[index],GRAPH_COLUMNS[index])
    for index in (5,6,7):_hex(row[index],GRAPH_COLUMNS[index])
    if row[3] not in {'schedule','acquire'}:
        raise ValueError('actual named paid Owner phase required')
    return namespace


def record_paid_owner_guard_link_v3(db,*,namespace,business_operation_id,request_digest,phase,
        permit,observation,receipt_json):
    """Only the existing real business transaction seals this association."""
    if not db.in_transaction:
        raise AuthorityUnavailable('paid Owner business association needs its actual Graph transaction')
    require_paid_owner_guard_link_schema_v3(db)
    if (type(observation) is not OwnerPaidGuardObservationV3 or type(namespace) is not NamespaceId
            or observation.guard.namespace!=namespace or observation.permit!=permit
            or observation.business_operation_id!=business_operation_id or observation.request_digest!=request_digest
            or observation.phase!=phase or type(receipt_json) is not str):
        raise AuthorityUnavailable('actual paid Owner observation crossed its business receipt')
    encoded=receipt_json.encode('utf8')
    meter=peek_current_c09_sql_meter_v3()
    if meter is not None:meter.charge_encode(len(encoded))
    expected=(*namespace.as_tuple,business_operation_id,phase,permit.operation_id,request_digest,
        observation.digest,sha256(encoded).hexdigest())
    validate_paid_owner_guard_link_row_v3(expected)
    bounded=_root_db(db)
    prior=bounded.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
        ' WHERE bot=? AND persona=? AND business_operation_id=? AND phase=?',expected[:4]).fetchone()
    if prior is not None:
        if prior!=expected:raise AuthorityUnavailable('paid Owner business association immutable replay differs')
        return prior
    _write(db,'INSERT INTO '+GRAPH_TABLE+'('+','.join(GRAPH_COLUMNS)+') VALUES(?,?,?,?,?,?,?,?)',expected)
    return expected


def require_committed_paid_owner_guard_link_v3(db,*,namespace,business_operation_id,request_digest,phase):
    from .v2_contract import from_wire
    require_paid_owner_guard_link_schema_v3(db)
    reader=_root_db(db)
    worker=reader.execute('SELECT request_digest,attempt_id,permit_json,receipt_json FROM graph_d13_worker_attempts_v2 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,business_operation_id)).fetchone()
    if worker is None or worker[3] is None:
        return None
    link=reader.execute('SELECT '+','.join(GRAPH_COLUMNS)+' FROM '+GRAPH_TABLE+
        ' WHERE bot=? AND persona=? AND business_operation_id=? AND phase=?',
        (*namespace.as_tuple,business_operation_id,phase)).fetchone()
    if link is None:
        raise AuthorityUnavailable('committed paid original lacks authenticated Owner guard business association')
    validate_paid_owner_guard_link_row_v3(tuple(link))
    permit=from_wire(json.loads(worker[2]))
    raw=worker[3].encode('utf8');meter=peek_current_c09_sql_meter_v3()
    if meter is not None:meter.charge_encode(len(raw))
    if (worker[0]!=request_digest or link[:6]!=(*namespace.as_tuple,business_operation_id,phase,worker[1],request_digest)
            or permit.operation_id!=worker[1] or link[7]!=sha256(raw).hexdigest()):
        raise AuthorityUnavailable('committed paid Owner association/permit/receipt original differs')
    return link
