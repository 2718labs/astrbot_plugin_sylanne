"""Installed Plan3 producer and immutable metadata-only birth provenance."""
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.contact_plan_v2 import PLAN,AdoptedContactExpressionPlanV2
from ..domains.d08.contact_plan_v3 import (PROVENANCE,ELIGIBILITY,PROPOSAL_SCHEMA,PROPOSAL_HASH,CURRENT_TYPES,
    ContactReadCommitmentV3,ContactExpressionPlanProvenanceV3,contact_plan_writes_v3,contact_plan_keys_v3,
    decode_contact_plan_member_v3)
from ..domains.d09.natural_reply import NaturalExpressionPlanV2
from ..runtime_contracts import NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..graph_types import AtomKey
from .contact_original_read_v3 import contact_original_point_v3
from .contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2,OPERATION

TABLE = 'graph_contact_expression_plan_originals_v3'
LOGICAL_KIND = 'd10.contact-expression-plan-payload.v3'
SIGN_KIND = 'd10.contact-expression-plan-physical-original.v3'
COLUMNS = ('bot','persona','contact_id','producing_operation_id','payload_cell_id','codec','byte_count',
    'payload_sha256','payload_digest','source_selection_cell_id','source_selection_bytes','source_selection_sha256',
    'receipt_digest','signature')
DDL = ('CREATE TABLE '+TABLE+'(bot TEXT NOT NULL,persona TEXT NOT NULL,contact_id TEXT NOT NULL,'
    'producing_operation_id TEXT NOT NULL,payload_cell_id TEXT NOT NULL,codec TEXT NOT NULL,byte_count INTEGER NOT NULL,'
    'payload_sha256 TEXT NOT NULL,payload_digest TEXT NOT NULL,source_selection_cell_id TEXT NOT NULL,'
    'source_selection_bytes INTEGER NOT NULL,source_selection_sha256 TEXT NOT NULL,receipt_digest TEXT NOT NULL,'
    'signature TEXT NOT NULL,PRIMARY KEY(bot,persona,contact_id)) STRICT')

DDL_MAP = {TABLE:DDL,**{TABLE+'_no_'+action.lower():
    f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'Contact plan original immutable'); END"
    for action in ('UPDATE','DELETE')}}


def _producer_read_commitment_v3(db,frame,atom):
    from .domain_background_read_v3 import _active_v3,background_graph_head_v3,BackgroundJSONColumnV3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if atom.revision == 0:
        return ContactReadCommitmentV3(atom.key.token,0,False,'absent',None,0,None,None,None)
    from .contact_initial_plan_source_v3 import initial_contact_source_commitment_v3
    source_commitment=initial_contact_source_commitment_v3(db,frame,atom)
    if source_commitment is not None:return source_commitment
    owner = _active_v3(db)
    if owner is None or owner.namespace != frame.envelope.authority.namespace:
        raise ValueError('Contact Plan3 requires its actual installed background producer EOF Work')
    row = background_graph_head_v3(db,owner.namespace,atom.key)
    if row is None or (row[0],bool(row[2])) != (atom.revision,atom.valid):
        raise ValueError('Contact Plan3 producer changed its physical current read')
    column = row[1]
    if type(column) is not BackgroundJSONColumnV3 or column.cell is None:
        raise ValueError('Contact Plan3 physical commitment has no actual segmented JSON EOF')
    column._actual_v3()
    with runtime_storage_quantum_v3(db) as meter:
        owner.require_data_current_v3(meter)
    codec,_,_,count,*_ = column.cell.header
    if (not column.complete or column.byte_count != count or column.sha256 != column.cell.header[5]
            or column.table != 'graph_atoms' or column.key != (atom.key.token,*owner.namespace.as_tuple)):
        raise ValueError('Contact Plan3 physical header and actual complete EOF differ')
    source = atom.key.type_name == 'memory.source'
    if not source and not column.matches_v3(atom.value):
        raise ValueError('Contact Plan3 nonSource body differs from its actual canonical JSON EOF')
    return ContactReadCommitmentV3(atom.key.token,atom.revision,atom.valid,'graph_atoms',codec,column.byte_count,column.sha256,
        None if source else 'canonical-json.ascii.v1',None if source else canonical_digest(atom.value))


def prepare_contact_plan_physical_in_transaction_v3(db,*,runtime,parent,frame,request,installed_readers,scope,owner,guard,metadata,epoch):
    from .contact_plan_preparation_v2 import prepare_contact_plan_in_transaction_v2
    from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
    if type(request) is not AdoptCurrentContactExpressionPlanRequestV2:
        raise TypeError('Contact Plan3 retains its exact approved locator request')
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise MissingProductionOriginalV1('actual_installed_contact_bundle')
    CurrentDomainReadV1(frame).check(db)
    plan,expression = prepare_contact_plan_in_transaction_v2(db,frame=frame,request=request,
        installed_readers=installed_readers,installed_bundle=assembly.admin_bundle,issuer=installed_readers.issuer)
    rows = tuple(_producer_read_commitment_v3(db,frame,atom) for atom in sorted(frame.snapshot.atoms,key=lambda atom:atom.key.token))
    metadata,_ = graph._v2_graph_stamp(plan.namespace)
    proof = ContactExpressionPlanProvenanceV3(plan,frame.envelope.identity.operation_id,
        frame.activation_generation,metadata.requirements.graph_incarnation,frame.owner_guard,rows,
        tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES),frame.query_coverage)
    from .contact_plan_physical_write_v3 import _ISSUER,PreparedContactPlanPhysicalV3
    return PreparedContactPlanPhysicalV3(_ISSUER,parent,runtime,frame,request,installed_readers,scope,owner,guard,
        metadata,epoch,plan,expression,proof)


def install_contact_plan_original_schema_v3(db):
    if not db.in_transaction:
        raise ValueError('Contact Plan3 schema requires its actual migration transaction')
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() != (DDL,):
        raise ValueError('Contact Plan3 original SQL schema differs')
    for action in ('UPDATE','DELETE'):
        ddl = f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'Contact plan original immutable'); END"
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(TABLE+'_no_'+action.lower(),)).fetchone()
        if row is None:
            db.execute(ddl)
        elif row != (ddl,):
            raise ValueError('Contact Plan3 immutable original trigger differs')


def validate_contact_plan_original_payload_v3(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    names = {'schema','plan','expression','proof','producing_operation_id','receipt_digest','policy_ref','opportunity_ref','route_ref','current_inventories','birth_bundle','business_deadline'}
    if type(raw) is not dict or set(raw)!=names or raw['schema']!=LOGICAL_KIND:
        raise ValueError('Contact Plan3 exact signed payload schema differs')
    from ..runtime_contracts import DomainBundle
    if (type(raw['birth_bundle']) is not dict or raw['birth_bundle'].get('$type')!=DomainBundle.__module__+'.'+DomainBundle.__qualname__
            or raw['birth_bundle'].get('envelope',{}).get('identity',{}).get('operation_id')!=raw['producing_operation_id']):
        raise ValueError('Contact Plan3 original lost its complete typed birth bundle')
    plan = decode_contact_plan_v2(raw['plan'])
    validate_contact_business_deadline_v3(raw['business_deadline'],plan)
    expression = decode_typed_production_value_v1(raw['expression'],NaturalExpressionPlanV2)
    proof = decode_contact_plan_member_v3(PROVENANCE,raw['proof'])
    if (proof.plan!=plan or raw['producing_operation_id']!=proof.producing_operation_id
            or expression.namespace!=plan.namespace or expression.plan_ref!=VersionedRef(contact_plan_keys_v3(plan)[0].token,1)
            or canonical_digest(expression.units)!=plan.qualified_units_digest
            or raw['opportunity_ref']!=plan.opportunity_ref.ref or raw['route_ref']!=plan.route_account_ref.ref
            or type(raw['current_inventories']) is not dict or set(raw['current_inventories'])!=set(CONTACT_CURRENT_TYPES)):
        raise ValueError('Contact Plan3 original expression and metadata lineage differ')
    for kind,rows in raw['current_inventories'].items():
        decoded = tuple(decode_typed_production_value_v1(row,ContactReadCommitmentV3) for row in rows)
        if (tuple(sorted(row.ref for row in decoded))!=tuple(row.ref for row in decoded)
                or any(AtomKey.from_token(row.ref).type_name!=kind or row.revision<1 for row in decoded)):
            raise ValueError('Contact Plan3 exact metadata inventory differs')
    return plan,expression,proof


def _read_row_v3(db,namespace,contact_id):
    from .contact_original_read_v3 import require_contact_source_db_v3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    work = require_contact_source_db_v3(db)
    if work is None or work.namespace!=namespace or contact_id!=work.contact_selector.contact_id:
        raise ValueError('Contact Plan3 row requires its actual finite Source Work selector')
    with runtime_storage_quantum_v3(db) as meter:
        work.require_current(meter=meter)
        return _runtime_bounded_fixed_row_v3(db,meter,TABLE,COLUMNS,
            'bot=? AND persona=? AND contact_id=?',(*namespace.as_tuple,contact_id))


def read_adopted_contact_plan_v3(db,*,namespace,contact_id,issuer):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .contact_original_read_v3 import (require_contact_source_db_v3,contact_plan_physical_payload_v3,
        contact_plan_physical_adoption_v3)
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError('Contact Plan3 requires its actual current SQL snapshot')
    work = require_contact_source_db_v3(db)
    if work is None:
        raise ValueError('Contact Plan3 original consumer requires its actual installed Source Work')
    row = _read_row_v3(db,namespace,contact_id)
    if row is None:
        raise MissingProductionOriginalV1('durable_contact_plan_v3_original')
    if row[8]!=work.contact_locator.digest:
        raise ValueError('Contact Plan3 signed locator and physical original differ')
    issuer._signer.verify(SIGN_KIND,canonical_serialize(contact_plan_logical_descriptor_v3(row)),row[13])
    raw = contact_plan_physical_payload_v3(db,namespace,contact_id)
    plan,expression,proof = validate_contact_plan_original_payload_v3(raw)
    if (plan.namespace,plan.contact_id,proof.producing_operation_id)!=(namespace,contact_id,row[3]):
        raise ValueError('Contact Plan3 actual protected original lineage differs from its metadata')
    actual = contact_plan_physical_adoption_v3(db,namespace,contact_id)
    if row[12]!=raw['receipt_digest']:
        raise ValueError('Contact Plan3 immutable physical record and payload receipt differ')
    validate_contact_plan_history_v3(db,proof=proof,actual=actual)
    require_current_contact_plan_members_v3(db,proof=proof,receipt=actual['receipt'])
    return plan,expression,raw,row[8]


def _require_read_commitment_v3(db,read,*,historical):
    from .contact_original_read_v3 import contact_payload_commitment_v3
    if read.revision == 0:
        if not historical:
            row = db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(read.ref,)).fetchone()
            if row is not None:
                raise ValueError('Contact Plan3 negative dependency appeared')
        return
    commitment = contact_payload_commitment_v3(db,read.ref,read.revision,historical=historical)
    if commitment!=(read.codec,read.byte_count,read.payload_sha256):
        raise ValueError('Contact Plan3 actual full physical EOF differs from its signed birth commitment')
    if AtomKey.from_token(read.ref).type_name != 'memory.source':
        table = 'graph_history' if historical else 'graph_atoms'
        key_columns = ('token','revision') if historical else ('token',)
        key = (read.ref,read.revision) if historical else (read.ref,)
        row = contact_original_point_v3(db,table=table,columns=('value','valid'),key_columns=key_columns,key=key,legacy_reader=lambda:None)
        if row is None or bool(row[1])!=read.valid or canonical_digest(json.loads(row[0]))!=read.semantic_sha256:
            raise ValueError('Contact Plan3 actual nonSource semantic canonical EOF differs')


def require_current_contact_plan_members_v3(db,*,proof,receipt):
    from ..graph_store import GraphStore
    from .contact_original_read_v3 import contact_dependency_rows_v3
    if type(proof) is not ContactExpressionPlanProvenanceV3 or not db.in_transaction:
        raise ValueError('Contact Plan3 requires exact current metadata provenance')
    ns = proof.plan.namespace
    metadata = db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
    requirements = GraphStore._decode_recovery(metadata,ns).requirements
    if (requirements.namespace,requirements.activation_generation,requirements.graph_incarnation)!=(ns,proof.activation_generation,proof.graph_incarnation):
        raise ValueError('Contact Plan3 current namespace/generation/incarnation changed')
    writes = contact_plan_writes_v3(proof)
    if {(v.key,v.revision) for v in receipt.write_versions}!={(w.key,1) for w in writes}:
        raise ValueError('Contact Plan3 current receipt lost a member')
    revisions = {row.ref:row.revision for row in proof.current_reads}
    revisions.update({write.key.token:1 for write in writes})
    for write in writes:
        row = contact_original_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token',),
            key=(write.key.token,),legacy_reader=lambda:None)
        if row != (1,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan3 fact/provenance/current eligibility changed')
        edges = contact_dependency_rows_v3(db,dependent_token=write.key.token)
        wanted = {(dep.token,revisions[dep.token]) for dep in write.dependencies}
        if edges is None or len(edges)!=len(wanted) or set(edges)!=wanted:
            raise ValueError('Contact Plan3 actual current eligibility dependencies differ')
    for read in proof.current_reads:
        current = db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(read.ref,)).fetchone()
        if current != ((read.revision,int(read.valid)) if read.revision else None):
            raise ValueError('Contact Plan3 current dependency head changed')
        _require_read_commitment_v3(db,read,historical=False)
    return proof


def validate_contact_plan_history_v3(db,*,proof,actual):
    from .contact_original_read_v3 import contact_historical_metadata_inventory_v3
    if type(proof) is not ContactExpressionPlanProvenanceV3 or not db.in_transaction:
        raise ValueError('Contact Plan3 history requires its actual immutable metadata proof')
    receipt,writes = actual['receipt'],contact_plan_writes_v3(proof)
    if (actual['operation_kind']!=OPERATION or receipt.operation_id!=proof.producing_operation_id
            or {(v.key,v.revision) for v in receipt.write_versions}!={(w.key,1) for w in writes}
            or {(row.ref,row.revision) for row in proof.historical_reads}!={(v.key.token,v.revision) for v in receipt.read_versions}
            or canonical_serialize(actual['payload']['provenance']['proof'])!=canonical_serialize(plain_v1(proof))):
        raise ValueError('Contact Plan3 original COMMIT read/write/producer membership differs')
    epochs = {query.epoch.revision for query in proof.query_coverage}
    if len(epochs)!=1:
        raise ValueError('Contact Plan3 original query epoch differs')
    rows = contact_historical_metadata_inventory_v3(db,namespace=proof.plan.namespace,epoch=next(iter(epochs)),
        refs=tuple(row.ref for row in proof.historical_reads),kinds=tuple(sorted(query.type_id for query in proof.query_coverage)))
    heads = {ref:(revision,bool(valid)) for ref,revision,valid in rows}
    for read in proof.historical_reads:
        if heads.get(read.ref)!=((read.revision,read.valid) if read.revision else None):
            raise ValueError('Contact Plan3 historical metadata selected a changed or omitted member')
        _require_read_commitment_v3(db,read,historical=True)
    for query in proof.query_coverage:
        observed = tuple((ref,revision) for ref,(revision,_) in sorted(heads.items()) if AtomKey.from_token(ref).type_name==query.type_id)
        if observed!=tuple((version.key.token,version.revision) for version in query.row_versions):
            raise ValueError('Contact Plan3 historical negative query coverage is incomplete')
    revisions = {read.ref:read.revision for read in proof.current_reads}
    revisions.update({write.key.token:1 for write in writes})
    for write in writes:
        row = contact_original_point_v3(db,table='graph_history',columns=('event_id','value','valid','dependencies'),
            key_columns=('token','revision'),key=(write.key.token,1),legacy_reader=lambda:None)
        if row is None or row[:3]!=(receipt.operation_id,canonical_serialize(write.value),1):
            raise ValueError('Contact Plan3 actual historical member changed')
        edges = json.loads(row[3])
        wanted = {(dep.token,revisions[dep.token]) for dep in write.dependencies}
        if len(edges)!=len(wanted) or {tuple(edge) for edge in edges}!=wanted:
            raise ValueError('Contact Plan3 historical dependencies differ')
    return proof


def require_contact_inventory_current_v3(db,namespace,raw):
    from .contact_original_read_v3 import contact_host_work_for_db_v3,contact_authority_work_v3
    from .contact_domain_source_v3 import contact_domain_work_for_db_v3
    plan,_,proof = validate_contact_plan_original_payload_v3(raw)
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None or namespace!=plan.namespace or namespace!=work.namespace:
        raise ValueError('Contact Plan3 current inventory requires its actual selected Work')
    for kind,inventory in raw['current_inventories'].items():
        expected = tuple((row['ref'],row['revision'],row['valid']) for row in inventory)
        current = tuple((ref,head[0],bool(head[1])) for ref,head in sorted(work.heads.items()) if AtomKey.from_token(ref).type_name==kind)
        if current != expected:
            raise ValueError('Contact Plan3 positive/negative current inventory changed')
        for row in inventory:
            _require_read_commitment_v3(db,next(read for read in proof.historical_reads if read.ref==row['ref']),historical=False)
    return True


def contact_plan_logical_descriptor_v3(row):
    if (len(row)!=len(COLUMNS) or row[5]!='canonical-json.ascii.v1' or row[6]<1 or row[10]<1
            or row[7]!=row[8]):
        raise ValueError('Contact Plan3 exact logical physical commitment differs')
    return {'schema':SIGN_KIND,'namespace':{'bot_id':row[0],'persona_id':row[1]},'contact_id':row[2],
        'producing_operation_id':row[3],'payload':{'codec':row[5],'byte_count':row[6],'payload_sha256':row[7],
            'logical_algorithm':'canonical-json.ascii.v1','logical_digest':row[8]},
        'source_selection':{'codec':'canonical-json.ascii.v1','byte_count':row[10],'payload_sha256':row[11]},
        'receipt_digest':row[12]}


def record_contact_plan_physical_after_cas_v3(db,*,prepared,receipt):
    from .contact_plan_physical_write_v3 import require_contact_plan_physical_v3
    from .domain_production_originals_v1 import PHYSICAL_TABLE,PHYSICAL_DDL,_receipt_wire
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    prepared = require_contact_plan_physical_v3(prepared)
    if (db is not prepared.db or not db.in_transaction or prepared.phase!='publishing'
            or receipt!=prepared.predicted_receipt):
        raise ValueError('Contact physical original needs its actual same-COMMIT three-member receipt')
    with runtime_storage_quantum_v3(db) as meter:
        for name in ('plan_original','source_selection','domain_original'):
            prepared.cells[name].publish_in_transaction(prepared,meter)
        payload,selection,domain = (prepared.cells[name] for name in ('plan_original','source_selection','domain_original'))
        receipt_digest = prepared.receipt_stream.hash.hexdigest()
        row = (*prepared.namespace.as_tuple,prepared.plan.contact_id,prepared.operation_id,payload.cell_id,
            payload.header[1],payload.byte_count,payload.raw_sha,payload.raw_sha,selection.cell_id,selection.byte_count,
            selection.raw_sha,receipt_digest,None)
        descriptor = contact_plan_logical_descriptor_v3(row)
        signature = prepared.readers.issuer._signer.sign(SIGN_KIND,canonical_serialize(descriptor))
        row = (*row[:-1],signature)
        install_contact_plan_original_schema_v3(db)
        old = db.execute('SELECT * FROM '+TABLE+' WHERE bot=? AND persona=? AND contact_id=?',row[:3]).fetchone()
        if old is None:
            meter.charge_write(sum(len(str(value).encode()) for value in row)+512)
            db.execute('INSERT INTO '+TABLE+' VALUES('+','.join('?' for _ in row)+')',row)
        elif old!=row:
            raise ValueError('Contact physical immutable original retry differs')
        db.execute(PHYSICAL_DDL)
        reads = canonical_serialize([[version.key.token,version.revision] for version in prepared.frame.snapshot.versions])
        content = (*prepared.namespace.as_tuple,prepared.operation_id,'d08','adopt_contact_expression_plan_v2',
            canonical_digest({'request':plain_v1(prepared.request)}),domain.raw_sha,domain.cell_id,
            prepared.stream_ref,reads,prepared.bundle_digest,canonical_serialize(_receipt_wire(receipt)),receipt_digest)
        prior = db.execute('SELECT * FROM '+PHYSICAL_TABLE+' WHERE bot=? AND persona=? AND operation_id=?',content[:3]).fetchone()
        if prior is None:
            meter.charge_write(sum(len(str(value).encode()) for value in content)+512)
            db.execute('INSERT INTO '+PHYSICAL_TABLE+' VALUES('+','.join('?' for _ in content)+')',content)
        elif prior!=content:
            raise ValueError('Contact physical domain original retry differs')
    original = ProductionOriginalRefV1('d08.current-adopt_contact_expression_plan_v2',
        'd08-current:'+domain.raw_sha[:48],domain.raw_sha,prepared.frame.snapshot.versions)
    return payload.raw_sha,original


def verify_selected_contact_plan_cell_origin_v3(db,*,basis,cell_id,header,original,meter):
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from ..runtime_contracts import namespace_ref
    from .domain_production_originals_v1 import PHYSICAL_TABLE
    ns = NamespaceId(*original['namespace'])
    operation,locator,proof = original['operation_id'],original['locator'],original['read_proof']
    if (namespace_ref(ns)!=basis.prepared['namespace'] or header[2]!=operation
            or set(proof)!={'schema','stream_ref','request_digest','permit_digest','readset_digest',
                'namespace_epoch','source_selection_digest'}):
        raise ValueError('Contact Plan3 selected producer scope/closed origin proof differs')
    physical = _runtime_bounded_fixed_row_v3(db,meter,PHYSICAL_TABLE,
        ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation))
    bundle = _runtime_bounded_fixed_row_v3(db,meter,'graph_bundle_operations',
        ('digest','activity_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation))
    attempt = _runtime_bounded_fixed_row_v3(db,meter,'graph_owner_domain_attempts_v3',
        ('request_digest','attempt_id','graph_epoch','permit_json','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation))
    if (physical is None or physical[:2]!=('d08','adopt_contact_expression_plan_v2')
            or physical[4]!=proof['stream_ref'] or bundle is None or bundle[0]!=physical[5]
            or attempt is None or attempt[0]!=proof['request_digest'] or attempt[2]!=proof['namespace_epoch']
            or attempt[3] is None or attempt[4] is None
            or canonical_digest(json.loads(attempt[3]))!=proof['permit_digest']):
        raise ValueError('Contact Plan3 actual birth COMMIT/attempt/permit producer is absent or differs')
    event = _runtime_bounded_fixed_row_v3(db,meter,'graph_events',('digest','reads','epoch_reads'),
        'bot=? AND persona=? AND session=? AND event_id=?',(*ns.as_tuple,bundle[1],operation))
    if (event is None or event[0]!=original['event_digest']
            or canonical_digest(json.loads(event[1]))!=proof['readset_digest'] or event[2]!='[]'):
        raise ValueError('Contact Plan3 born Graph event/readset original differs')
    if locator['table']=='graph_atoms':
        key = AtomKey.from_token(locator['token'])
        actual = _runtime_bounded_fixed_row_v3(db,meter,'graph_history',
            ('value_cell_id','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=?',(key.token,locator['revision']))
        if (set(locator)!={'table','token','revision'} or key.type_name not in (PLAN,PROVENANCE,ELIGIBILITY)
                or NamespaceId.from_key(key)!=ns or locator['revision']!=1 or header[1]!=key.token
                or actual!=(cell_id,*ns.as_tuple,bundle[1],operation)):
            raise ValueError('Contact Plan3 exact born three-member physical history differs')
    elif locator['table']==TABLE:
        if tuple(locator['key'])[:2]!=ns.as_tuple:
            raise ValueError('Contact Plan3 original physical namespace differs')
        plan = _runtime_bounded_fixed_row_v3(db,meter,TABLE,COLUMNS,
            'bot=? AND persona=? AND contact_id=?',tuple(locator['key']))
        if plan is None or plan[3]!=operation or plan[12]!=physical[6]:
            raise ValueError('Contact Plan3 actual signed physical record is absent or differs')
        field = locator.get('field')
        expected = (plan[9],plan[10],plan[11]) if field=='source_selection_cell_id' else (plan[4],plan[6],plan[7])
        if (set(locator)!=({'table','key','field'} if field is not None else {'table','key'})
                or field not in (None,'source_selection_cell_id') or expected!=(cell_id,header[3],header[5])):
            raise ValueError('Contact Plan3 exact sealed logical payload/selection descriptor differs')
    elif locator['table']==PHYSICAL_TABLE:
        if set(locator)!={'table','key'} or tuple(locator['key'])!=(*ns.as_tuple,operation) or physical[2:4]!=(header[5],cell_id):
            raise ValueError('Contact Plan3 exact immutable domain payload differs')
    else:
        raise ValueError('Contact Plan3 producer has no other physical family')
    return original


def validate_contact_business_deadline_v3(terms,plan):
    from ..domains.d01.production_operations_v1 import plain_v1
    names={'schema','namespace','deadline_utc','policy_original_ref','policy_original_digest','policy_window_id',
        'policy_window_end_utc','opportunity_ref','opportunity_revision','opportunity_digest','opportunity_expires_at_utc',
        'raw_check_digest','raw_check_valid_until_utc','parent_budget_lease_ref','root_grant_version','root_grant_digest','root_grant_valid_until_utc'}
    if (type(terms)is not dict or set(terms)!=names or terms['schema']!='d10.contact-business-deadline.v3'
            or terms['namespace']!=plain_v1(plan.namespace) or terms['deadline_utc']!=plan.valid_until_utc
            or (terms['policy_original_ref'],terms['policy_original_digest'])!=(plan.policy_original_ref,plan.policy_original_digest)
            or (terms['opportunity_ref'],terms['opportunity_revision'])!=(plan.opportunity_ref.ref,plan.opportunity_ref.revision)
            or (terms['parent_budget_lease_ref'],terms['root_grant_version'],terms['root_grant_digest'])!=
                (plan.parent_budget_lease_id,plan.budget_grant_version,plan.budget_grant_digest)
            or terms['deadline_utc']!=min(terms['policy_window_end_utc'],terms['opportunity_expires_at_utc'],
                terms['raw_check_valid_until_utc'],terms['root_grant_valid_until_utc'])):
        raise ValueError('Contact immutable business deadline lost its actual standing policy/opportunity/raw check/original Root terms')
    for name in ('policy_original_digest','opportunity_digest','raw_check_digest','root_grant_digest'):
        value=terms[name]
        if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
            raise ValueError('Contact business deadline actual original digest differs')
    return terms
