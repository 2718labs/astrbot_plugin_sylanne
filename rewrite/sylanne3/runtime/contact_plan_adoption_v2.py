"""Installed external Contact Plan B with explicit historical/current version.

The same-transaction original is provisional until a separate SQLite reader
observes the committed row. Neither a public plan nor a committed-shaped
GraphReceipt is a substitute for durable COMMIT.
"""
from .contact_original_read_v3 import contact_original_point_v3
from dataclasses import asdict, dataclass, replace, fields
import json
from contextlib import closing
from pathlib import Path
import sqlite3

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.contact_plan_v1 import contact_ids_v1
from ..domains.d08.contact_plan_v2 import (
    PLAN, PROVENANCE, ELIGIBILITY, KINDS, PROPOSAL_SCHEMA, PROPOSAL_HASH,
    AdoptedContactExpressionPlanV2, ContactExpressionPlanProvenanceV2,
    contact_plan_keys_v2, contact_plan_writes_v2, decode_contact_plan_member_v2,
)
from ..domains.d09.natural_reply import NaturalExpressionPlanV2
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .contact_plan_adoption_v1 import (
    AdoptCurrentContactExpressionPlanRequestV1,
    contact_inventory_from_frame_v1,
)
from .d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from .d01_production_operations_v1 import MissingProductionOriginalV1

OPERATION = 'adopt_contact_expression_plan_v2'
TABLE = 'graph_contact_expression_plan_originals_v2'
SIGN_KIND = 'd10.contact-expression-plan-original.v2'
COLUMNS=('bot','persona','contact_id','payload_json','payload_digest','signature')
DDL=f'CREATE TABLE {TABLE}(bot TEXT NOT NULL,persona TEXT NOT NULL,contact_id TEXT NOT NULL,'\
    'payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,'\
    'PRIMARY KEY(bot,persona,contact_id)) STRICT'


@dataclass(frozen=True,slots=True)
class AdoptCurrentContactExpressionPlanRequestV2:
    opportunity_ref: str
    contact_policy_ref: str
    target_route_ref: str

    def __post_init__(self):
        keys=tuple(AtomKey.from_token(getattr(self,name)) for name in ('opportunity_ref','contact_policy_ref','target_route_ref'))
        if tuple(k.type_name for k in keys)!=('d10.proactive_opportunity.v1','d10.contact_policy.v1','d03.account_binding'):
            raise ValueError('Contact Plan v2 requires exact opportunity/policy/private route locators')
        if len({NamespaceId.from_key(k) for k in keys})!=1:
            raise ValueError('Contact Plan v2 request crosses namespaces')


@dataclass(frozen=True,slots=True)
class ContactPlanStageV2:
    frame: object
    request: AdoptCurrentContactExpressionPlanRequestV2
    plan: AdoptedContactExpressionPlanV2
    expression: NaturalExpressionPlanV2
    proof: ContactExpressionPlanProvenanceV2
    writes: tuple
    stage: object


def read_plan_contact_expression_v2(db,*,namespace,activity_id,operation_kind,request):
    from .contact_product_adapter_v1 import read_plan_contact_expression_v1
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    if type(request) is not AdoptCurrentContactExpressionPlanRequestV2 or operation_kind!=OPERATION:
        raise TypeError('Contact Plan v2 exact registered request required')
    legacy=AdoptCurrentContactExpressionPlanRequestV1(**asdict(request))
    old=read_plan_contact_expression_v1(db,namespace=namespace,activity_id=activity_id,
        operation_kind='adopt_contact_expression_plan',request=legacy)
    keys=list(old.exact_keys)
    from ..domains.d08.contact_plan_v3 import PROVENANCE as PROVENANCE3,ELIGIBILITY as ELIGIBILITY3
    # The old planner authenticates the stable contact cause/recipient. Keep
    # its complete Source/negative inventories and add every absent new member.
    for key in old.exact_keys:
        if key.type_name=='d08.contact_expression_plan.v1':
            keys.extend(AtomKey(key.owner,kind,key.name) for kind in (PLAN,PROVENANCE,ELIGIBILITY,PROVENANCE3,ELIGIBILITY3))
    return ProductionReadPlanV1(old.fixed_type_ids,tuple(sorted(set(keys),key=lambda k:k.token)),
        old.source_roots,old.required_original_refs)


def stage_adopt_current_contact_expression_plan_in_transaction_v2(db,*,frame,request,installed_readers):
    from .domain_background_read_v3 import _active_v3
    if _active_v3(db) is not None:
        raise ValueError('Contact Plan3 background adoption requires its actual retained streamed WRITE producer')
    if type(request) is not AdoptCurrentContactExpressionPlanRequestV2:
        raise TypeError('Contact Plan v2 exact request required')
    graph=installed_readers.role_clock_reader.graph
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:raise MissingProductionOriginalV1('actual_installed_contact_bundle')
    from .contact_plan_preparation_v2 import prepare_contact_plan_in_transaction_v2
    # The versioned producer performs the actual Owner/current budget/route/
    # D06 checks and consumes their closed original_ref/original_digest wire.
    plan,expression=prepare_contact_plan_in_transaction_v2(db,frame=frame,request=request,
        installed_readers=installed_readers,installed_bundle=assembly.admin_bundle,issuer=installed_readers.issuer)
    if frame.envelope.identity.activity_id!=plan.activity_id:
        raise ValueError('Contact Plan v2 command has the wrong actual cause activity')
    rows=tuple(sorted((OfflineTickGraphReadV1(a.key.token,a.revision,canonical_serialize(a.value),a.valid)
        for a in frame.snapshot.atoms),key=lambda row:row.ref))
    from ..domains.d08.contact_plan_v2 import CURRENT_TYPES
    metadata,_=graph._v2_graph_stamp(plan.namespace)
    if metadata.requirements.activation_generation!=frame.envelope.authority.activation_generation:
        raise ValueError('Contact Plan v2 actual activation generation drifted')
    proof=ContactExpressionPlanProvenanceV2(plan,frame.envelope.identity.operation_id,
        frame.envelope.authority.activation_generation,metadata.requirements.graph_incarnation,
        frame.owner_guard,rows,tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES),
        frame.query_coverage)
    writes=contact_plan_writes_v2(proof)
    stage=stage_result_v1(frame,'d08',OPERATION,request,writes=writes,
        provenance={'schema':SIGN_KIND,'contact_plan':plain_v1(plan),'expression':plain_v1(expression),
            'proof':plain_v1(proof)},proposal_schema=PROPOSAL_SCHEMA,proposal_hash=PROPOSAL_HASH)
    result=ContactPlanStageV2(frame,request,plan,expression,proof,writes,stage)
    return verify_contact_plan_stage_v2(result)


def verify_contact_plan_stage_v2(value):
    if type(value) is not ContactPlanStageV2 or value.stage.operation_kind!=OPERATION:
        raise TypeError('Contact Plan v2 exact installed stage required')
    p=value.stage.proposals
    if (len(p)!=1 or p[0].domain!='d08' or (p[0].proposal_schema,p[0].proposal_schema_hash)!=(PROPOSAL_SCHEMA,PROPOSAL_HASH)
            or canonical_serialize(p[0].typed_writes)!=canonical_serialize(contact_plan_writes_v2(value.proof))
            or value.plan!=value.proof.plan or value.proof.producing_operation_id!=value.frame.envelope.identity.operation_id
            or value.expression.plan_ref!=VersionedRef(contact_plan_keys_v2(value.plan)[0].token,1)
            or canonical_digest(value.expression.units)!=value.plan.qualified_units_digest
            or value.stage.jobs or value.stage.outbox or value.stage.coverage!='complete'):
        raise ValueError('Contact Plan v2 complete stage/proof/producer membership differs')
    return value


def require_exact_contact_plan_issuance_v2(witness,graph,bundle):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph or witness.bundle is not bundle
            or type(witness.stage) is not ContactPlanStageV2 or witness.operation.operation_kind!=OPERATION):
        raise ValueError('Contact Plan v2 public DTO has no exact active installed issuance')
    return verify_contact_plan_stage_v2(witness.stage)


def install_contact_plan_original_schema_v2(db):
    if not db.in_transaction:raise ValueError('Contact Plan v2 original requires the actual SQL transaction')
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()!=(DDL,):
        raise ValueError('Contact Plan v2 exact original SQL schema differs')
    for action in ('UPDATE','DELETE'):
        ddl=f'CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,\'Contact plan original immutable\'); END'
        existing=db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(TABLE+'_no_'+action.lower(),)).fetchone()
        if existing is None:db.execute(ddl)
        elif existing!=(ddl,):raise ValueError('Contact Plan v2 original SQL trigger differs')


def record_contact_plan_after_cas_v2(db,*,stage,issuer,receipt):
    verify_contact_plan_stage_v2(stage)
    if (not db.in_transaction or receipt.status!='committed'
            or receipt.operation_id!=stage.proof.producing_operation_id
            or {(v.key,v.revision) for v in receipt.write_versions}!={(w.key,1) for w in stage.writes}):
        raise ValueError('Contact Plan v2 requires its provisional same-transaction complete receipt')
    for write in stage.writes:
        if contact_original_point_v3(db,table='graph_history',columns=('event_id', 'value', 'valid'),key_columns=('token', 'revision'),key=(lambda _contact_values: (_contact_values[0],1))((write.key.token,)),legacy_reader=lambda: db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',
            (write.key.token,)).fetchone())!=(receipt.operation_id,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan v2 original member/history was not actually written')
    payload={'schema':SIGN_KIND,'plan':plain_v1(stage.plan),'expression':plain_v1(stage.expression),
        'proof':plain_v1(stage.proof),'producing_operation_id':receipt.operation_id,
        'receipt_digest':canonical_digest(receipt),'policy_ref':stage.request.contact_policy_ref,
        'opportunity_ref':stage.request.opportunity_ref,'route_ref':stage.request.target_route_ref,
        'current_inventories':contact_inventory_from_frame_v1(stage.frame)}
    validate_contact_plan_original_payload_v2(payload)
    wire=canonical_serialize(payload);digest=canonical_digest(payload)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((stage.plan.namespace,stage.plan.contact_id,digest)))
    install_contact_plan_original_schema_v2(db)
    row=(*stage.plan.namespace.as_tuple,stage.plan.contact_id,wire,digest,signature)
    existing=contact_original_point_v3(db,table='graph_contact_expression_plan_originals_v2',columns=('bot', 'persona', 'contact_id', 'payload_json', 'payload_digest', 'signature'),key_columns=('bot', 'persona', 'contact_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))(row[:3]),legacy_reader=lambda: db.execute(f'SELECT * FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',row[:3]).fetchone())
    if existing is None:db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?)',row)
    elif existing!=row:raise ValueError('Contact Plan v2 retry cannot replace its original')
    return digest


def _require_durable_contact_plan_row_v2(db,row):
    from .contact_original_read_v3 import contact_original_durable_connection_v3
    if contact_original_durable_connection_v3(db,row):
        return
    path=db.execute('PRAGMA database_list').fetchone()[2]
    if not path:raise ValueError('Contact Plan v2 installed durable database required')
    with closing(sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,isolation_level=None)) as committed:
        committed.execute('PRAGMA query_only=ON');committed.execute('BEGIN')
        try:
            actual=committed.execute(f'SELECT * FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',row[:3]).fetchone()
            if actual!=row:raise ValueError('Contact Plan v2 same-transaction original is not durably committed')
        except sqlite3.OperationalError as error:
            raise ValueError('Contact Plan v2 original is not durably committed') from error
        finally:committed.execute('ROLLBACK')


def read_adopted_contact_plan_v2(db,*,namespace,contact_id,issuer):
    from ..authority_service.named_joint_contact_plan_v1 import read_bound_named_joint_contact_plan_v1
    named=read_bound_named_joint_contact_plan_v1(db,namespace=namespace,contact_id=contact_id)
    if named is not None:return named
    from .contact_plan_adoption_v3 import TABLE as TABLE3,read_adopted_contact_plan_v3
    found3 = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE3,)).fetchone()
    if found3 and db.execute('SELECT 1 FROM '+TABLE3+' WHERE bot=? AND persona=? AND contact_id=?',(*namespace.as_tuple,contact_id)).fetchone():
        return read_adopted_contact_plan_v3(db,namespace=namespace,contact_id=contact_id,issuer=issuer)
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError('Contact Plan v2 reader requires its actual current SQL snapshot')
    found=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    row=contact_original_point_v3(db,table='graph_contact_expression_plan_originals_v2',columns=('bot', 'persona', 'contact_id', 'payload_json', 'payload_digest', 'signature'),key_columns=('bot', 'persona', 'contact_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((*namespace.as_tuple,contact_id)),legacy_reader=lambda: db.execute(f'SELECT * FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',
        (*namespace.as_tuple,contact_id)).fetchone()) if found else None
    if row is None:raise MissingProductionOriginalV1('durable_contact_plan_v2_original')
    _require_durable_contact_plan_row_v2(db,row)
    raw=json.loads(row[3])
    if canonical_serialize(raw)!=row[3] or canonical_digest(raw)!=row[4]:
        raise ValueError('Contact Plan v2 original canonical SQL changed')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,contact_id,row[4])),row[5])
    plan,expression,proof=validate_contact_plan_original_payload_v2(raw)
    if (plan.namespace!=namespace or plan.contact_id!=contact_id or raw['plan']!=plain_v1(plan)
            or raw['producing_operation_id']!=proof.producing_operation_id):
        raise ValueError('Contact Plan v2 original locator/producer scope differs')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    actual=read_adopted_domain_operation_v1(db,namespace,proof.producing_operation_id)
    if actual is None or actual['operation_kind']!=OPERATION or canonical_digest(actual['receipt'])!=raw['receipt_digest']:
        raise ValueError('Contact Plan v2 actual durable production COMMIT is missing')
    validate_contact_plan_history_v2(db,proof=proof,actual=actual)
    require_current_contact_plan_members_v2(db,proof=proof,receipt=actual['receipt'])
    return plan,expression,raw,row[4]


def require_current_contact_plan_members_v2(db,*,proof,receipt):
    if not db.in_transaction or type(proof) is not ContactExpressionPlanProvenanceV2:
        raise ValueError('Contact Plan v2 actual current snapshot/proof required')
    from ..graph_store import GraphStore
    ns=proof.plan.namespace
    metadata=db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
    if metadata is None:raise ValueError('Contact Plan v2 actual recovery scope absent')
    requirements=GraphStore._decode_recovery(metadata,ns).requirements
    if (requirements.namespace,requirements.activation_generation,requirements.graph_incarnation)!=(ns,proof.activation_generation,proof.graph_incarnation):
        raise ValueError('Contact Plan v2 current namespace/generation/incarnation drifted')
    expected=contact_plan_writes_v2(proof)
    revisions={row.ref:row.revision for row in proof.current_reads}
    revisions.update({w.key.token:1 for w in expected})
    if {(v.key,v.revision) for v in receipt.write_versions}!={(w.key,1) for w in expected}:
        raise ValueError('Contact Plan v2 complete actual receipt members differ')
    for write in expected:
        if contact_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((write.key.token,)),legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone())!=(1,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan v2 current fact/proof/eligibility invalidated or changed')
        if contact_original_point_v3(db,table='graph_history',columns=('event_id', 'value', 'valid'),key_columns=('token', 'revision'),key=(lambda _contact_values: (_contact_values[0],1))((write.key.token,)),legacy_reader=lambda: db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',(write.key.token,)).fetchone())!=(proof.producing_operation_id,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan v2 actual historical member changed')
        from .contact_original_read_v3 import contact_dependency_rows_v3
        edges=contact_dependency_rows_v3(db,dependent_token=write.key.token)
        if edges is None:
            edges=tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',(write.key.token,)))
        wanted={(dep.token,revisions[dep.token]) for dep in write.dependencies}
        if len(edges)!=len(wanted) or set(edges)!=wanted:raise ValueError('Contact Plan v2 actual eligibility edges changed')
    for read in proof.current_reads:
        row=contact_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((read.ref,)),legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(read.ref,)).fetchone())
        if row!=((read.revision,read.value_json,int(read.valid)) if read.revision else None):
            raise ValueError('Contact Plan v2 Source/Access/Correction/Owner/plan current head drifted')
    return proof


def require_contact_inventory_current_v2(db, namespace, raw):
    from .contact_plan_adoption_v3 import SIGN_KIND as SIGN_KIND3,require_contact_inventory_current_v3
    if type(raw) is dict and raw.get('schema') == SIGN_KIND3:
        return require_contact_inventory_current_v3(db,namespace,raw)
    """Fresh bounded full provider inventory; the eligibility bit is insufficient."""
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError('Contact Plan v2 actual current inventory transaction required')
    validate_contact_plan_original_payload_v2(raw)
    inventories = raw['current_inventories']
    for kind in CONTACT_CURRENT_TYPES:
        from .contact_original_read_v3 import contact_current_inventory_v3
        rows = contact_current_inventory_v3(db,namespace=namespace,kind=kind)
        if rows is None:
            rows = db.execute('SELECT token,revision,value,valid FROM graph_atoms '
                'WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129',
                (*namespace.as_tuple, kind)).fetchall()
        if len(rows) > 128:
            raise ValueError('Contact Plan v2 current full inventory exceeds bound; HOLD')
        observed = []
        for token, revision, value, valid in rows:
            atom = _decode_contact_plan_inventory_atom_v2(
                {'key': token, 'revision': revision, 'value': json.loads(value),
                 'valid': bool(valid)}, kind=kind, namespace=namespace)
            observed.append(plain_v1(atom))
        if canonical_serialize(observed) != canonical_serialize(inventories[kind]):
            raise ValueError('Contact Plan v2 fresh full provider inventory changed: ' + kind)
    return True


def _decode_contact_plan_inventory_atom_v2(raw,*,kind,namespace):
    """Finite GraphAtom wire, with its family's body bound to actual reads.

    GraphAtom.value is deliberately an unparameterized JSON object. It is
    not a generic typed dataclass decoder target or a new permission issuer.
    The enclosing codec authenticates the exact frozen read bytes, followed
    by the history/current SQL joins in their respective installed readers.
    """
    from ..graph_types import GraphAtom
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    if (kind not in CONTACT_CURRENT_TYPES or type(raw) is not dict
            or set(raw)!={'key','revision','value','valid'}
            or type(raw['key']) is not str or type(raw['revision']) is not int
            or raw['revision']<1 or type(raw['valid']) is not bool
            or type(raw['value']) is not dict):
        raise ValueError('Contact Plan v2 exact finite inventory atom required')
    key=AtomKey.from_token(raw['key'])
    if key.type_name!=kind or NamespaceId.from_key(key)!=namespace:
        raise ValueError('Contact Plan v2 inventory atom crossed family/namespace')
    atom=GraphAtom(key,raw['revision'],raw['value'],raw['valid'])
    if canonical_serialize(plain_v1(atom))!=canonical_serialize(raw):
        raise ValueError('Contact Plan v2 inventory atom wire is noncanonical')
    return atom


def validate_contact_plan_original_payload_v2(raw):
    from .contact_plan_adoption_v3 import SIGN_KIND as SIGN_KIND3,validate_contact_plan_original_payload_v3
    if type(raw) is dict and raw.get('schema') == SIGN_KIND3:
        return validate_contact_plan_original_payload_v3(raw)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    from ..graph_types import GraphAtom
    names={'schema','plan','expression','proof','producing_operation_id','receipt_digest',
        'policy_ref','opportunity_ref','route_ref','current_inventories'}
    if type(raw) is not dict or set(raw)!=names or raw['schema']!=SIGN_KIND:
        raise ValueError('Contact Plan v2 closed signed payload differs')
    proof=decode_contact_plan_member_v2(PROVENANCE,raw['proof']);plan=proof.plan
    expression=decode_typed_production_value_v1(raw['expression'],NaturalExpressionPlanV2)
    if (canonical_serialize(raw['plan'])!=canonical_serialize(plain_v1(plan))
            or raw['producing_operation_id']!=proof.producing_operation_id
            or expression.namespace!=plan.namespace or expression.plan_ref!=VersionedRef(contact_plan_keys_v2(plan)[0].token,1)
            or canonical_digest(expression.units)!=plan.qualified_units_digest
            or raw['opportunity_ref']!=plan.opportunity_ref.ref or raw['route_ref']!=plan.route_account_ref.ref):
        raise ValueError('Contact Plan v2 original expression/provenance/producer binding differs')
    from ..domains.d08.contact_plan_v2 import _digest
    _digest(raw['receipt_digest'])
    policy=AtomKey.from_token(raw['policy_ref'])
    if policy.type_name!='d10.contact_policy.v1' or NamespaceId.from_key(policy)!=plan.namespace:
        raise ValueError('Contact Plan v2 signed policy locator differs')
    inventories=raw['current_inventories']
    if type(inventories) is not dict or set(inventories)!=set(CONTACT_CURRENT_TYPES):
        raise ValueError('Contact Plan v2 complete provider inventory differs')
    for kind,rows in inventories.items():
        if type(rows) is not list or len(rows)>128:
            raise ValueError('Contact Plan v2 complete provider inventory exceeds bound; HOLD')
        atoms=tuple(_decode_contact_plan_inventory_atom_v2(row,kind=kind,namespace=plan.namespace) for row in rows)
        if (any(atom.key.type_name!=kind or NamespaceId.from_key(atom.key)!=plan.namespace for atom in atoms)
                or len({atom.key for atom in atoms})!=len(atoms)):
            raise ValueError('Contact Plan v2 actual provider inventory scope/duplicates differ')
        expected=tuple((row.ref,row.revision,row.value_json,row.valid) for row in proof.historical_reads
            if AtomKey.from_token(row.ref).type_name==kind and row.revision>0)
        observed=tuple((atom.key.token,atom.revision,canonical_serialize(atom.value),atom.valid) for atom in atoms)
        if canonical_serialize(observed)!=canonical_serialize(expected):
            raise ValueError('Contact Plan v2 provider inventory differs from complete frozen read bytes')
    return plan,expression,proof


def validate_contact_plan_history_v2(db,*,proof,actual):
    """Historical full E inventory and actual COMMIT; grants no current right."""
    if not db.in_transaction or type(proof) is not ContactExpressionPlanProvenanceV2:
        raise ValueError('Contact Plan v2 actual historical SQL snapshot required')
    ns=proof.plan.namespace;receipt=actual['receipt']
    expected=contact_plan_writes_v2(proof)
    if (actual['operation_kind']!=OPERATION or receipt.operation_id!=proof.producing_operation_id
            or {(v.key,v.revision) for v in receipt.write_versions}!={(w.key,1) for w in expected}
            or {(row.ref,row.revision) for row in proof.historical_reads}!=
                {(v.key.token,v.revision) for v in receipt.read_versions}
            or canonical_serialize(actual['payload']['provenance']['proof'])!=canonical_serialize(plain_v1(proof))):
        raise ValueError('Contact Plan v2 historical producer/readset/complete write membership differs')
    epochs={q.epoch.revision for q in proof.query_coverage}
    if len(epochs)!=1:raise ValueError('Contact Plan v2 historical snapshot epoch differs')
    refs=tuple(row.ref for row in proof.historical_reads)
    kinds=tuple(sorted({q.type_id for q in proof.query_coverage}))
    from .contact_original_read_v3 import contact_historical_inventory_v3
    rows=contact_historical_inventory_v3(db,namespace=ns,epoch=next(iter(epochs)),refs=refs,kinds=kinds)
    if rows is None:
        rows=db.execute('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h '
            'JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)='
            '(e.bot,e.persona,e.session,e.event_id) WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? '
            f"AND (h.token IN ({','.join('?' for _ in refs)}) OR json_extract(h.token,'$[4]') IN ({','.join('?' for _ in kinds)})) "
            'GROUP BY h.token) SELECT h.token,h.revision,h.value,h.valid FROM latest l JOIN graph_history h '
            'ON h.token=l.token AND h.revision=l.revision ORDER BY h.token LIMIT 1025',
            (*ns.as_tuple,next(iter(epochs)),*refs,*kinds)).fetchall()
    if len(rows)>1024:raise ValueError('Contact Plan v2 historical complete inventory exceeds bound; HOLD')
    heads={ref:(revision,value,valid) for ref,revision,value,valid in rows}
    for read in proof.historical_reads:
        if heads.get(read.ref)!=((read.revision,read.value_json,int(read.valid)) if read.revision else None):
            raise ValueError('Contact Plan v2 frozen historical read changed or omitted')
    for query in proof.query_coverage:
        observed=tuple((ref,value[0]) for ref,value in sorted(heads.items()) if AtomKey.from_token(ref).type_name==query.type_id)
        if observed!=tuple((v.key.token,v.revision) for v in query.row_versions):
            raise ValueError('Contact Plan v2 historical negative query inventory incomplete')
    revisions={row.ref:row.revision for row in proof.current_reads}
    revisions.update({w.key.token:1 for w in expected})
    for write in expected:
        row=contact_original_point_v3(db,table='graph_history',columns=('event_id', 'value', 'valid', 'dependencies'),key_columns=('token', 'revision'),key=(lambda _contact_values: (_contact_values[0],1))((write.key.token,)),legacy_reader=lambda: db.execute('SELECT event_id,value,valid,dependencies FROM graph_history WHERE token=? AND revision=1',
            (write.key.token,)).fetchone())
        if row is None or row[:3]!=(receipt.operation_id,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan v2 actual historical immutable member changed')
        edges=json.loads(row[3])
        wanted={(dep.token,revisions[dep.token]) for dep in write.dependencies}
        if (type(edges) is not list or any(type(edge) is not list or len(edge)!=2
                or type(edge[0]) is not str or type(edge[1]) is not int or edge[1]<0 for edge in edges)
                or len(edges)!=len(wanted) or {tuple(edge) for edge in edges}!=wanted):
            raise ValueError('Contact Plan v2 historical provenance/projection edges differ')
    return proof
