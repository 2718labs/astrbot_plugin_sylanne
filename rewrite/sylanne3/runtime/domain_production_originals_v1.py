"""Shared W01 originals for concrete registered domain production operations."""

from dataclasses import asdict
import json

from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import StagedDomainOperationV1, ProductionOriginalRefV1

TABLE = "graph_domain_production_originals_v1"
SCHEMA = "sylanne.domain-production-original.v1"
PHYSICAL_TABLE = "graph_domain_production_originals_v3"
PHYSICAL_DDL = """CREATE TABLE IF NOT EXISTS graph_domain_production_originals_v3 (
    bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,
    domain TEXT NOT NULL,operation_kind TEXT NOT NULL,request_digest TEXT NOT NULL,
    original_digest TEXT NOT NULL,original_payload_cell_id TEXT NOT NULL,
    prepared_digest TEXT NOT NULL,read_versions_json TEXT NOT NULL,bundle_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL,receipt_digest TEXT NOT NULL,
    PRIMARY KEY(bot,persona,operation_id)) STRICT"""


DOMAINS = frozenset({"d01", "d02", "d03", "d05", "d06", "d07", "d08", "d09", "d10", "d11"})


def install_domain_production_originals_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        domain TEXT NOT NULL, operation_kind TEXT NOT NULL,
        request_digest TEXT NOT NULL, original_digest TEXT NOT NULL,
        original_payload_json TEXT NOT NULL, read_versions_json TEXT NOT NULL,
        bundle_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, receipt_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    db.execute(f"CREATE INDEX IF NOT EXISTS graph_domain_production_lookup_v1 "
        f"ON {TABLE}(bot,persona,domain,operation_kind,operation_id)")


def _receipt_wire(receipt):
    return {"status": receipt.status, "operation_id": receipt.operation_id,
        "operation_digest": receipt.operation_digest, "activity_id": receipt.activity_id, "effect_id": receipt.effect_id,
        "commit_seq": receipt.commit_seq,
        "read_versions": [[v.key.token, v.revision] for v in receipt.read_versions],
        "write_versions": [[v.key.token, v.revision] for v in receipt.write_versions],
        "invalidated_epochs": [asdict(e) for e in receipt.invalidated_epochs],
        "ledger_refs": list(receipt.ledger_refs), "outbox_refs": list(receipt.outbox_refs)}


def _receipt(raw):
    if type(raw) is not dict or set(raw) != set(CommitReceipt.__dataclass_fields__):
        raise ValueError("domain operation receipt fields differ")
    value = dict(raw)
    for key in ("read_versions", "write_versions"):
        value[key] = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in raw[key])
    value["invalidated_epochs"] = tuple(NamespaceEpoch(**item) for item in raw["invalidated_epochs"])
    for key in ("ledger_refs", "outbox_refs"):
        value[key] = tuple(raw[key])
    result = CommitReceipt(**value)
    if _receipt_wire(result) != raw:
        raise ValueError("domain operation receipt wire differs")
    return result


def _registered_domain_original_v1(domain, operation_kind):
    return domain in DOMAINS or (domain, operation_kind) in {('d04', 'adopt_internal_life_numeric'), ('d04', 'prepare_internal_life_numeric_drive')}


def record_adopted_domain_operation_v1(db, stage, receipt):
    from .owner_material_source_storage_v3 import StagedDomainOperationV3
    if type(stage) is StagedDomainOperationV3:
        return record_adopted_physical_domain_operation_v3(db, stage, receipt)
    if (not db.in_transaction or type(stage) is not StagedDomainOperationV1
            or type(receipt) is not CommitReceipt or not _registered_domain_original_v1(stage.domain, stage.operation_kind)
            or receipt.status != "committed" or receipt.operation_id != stage.operation_id
            or receipt.activity_id != stage.activity_id):
        raise ValueError("domain original needs its actual same-transaction W01 receipt")
    bundle = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*stage.namespace.as_tuple, stage.operation_id)).fetchone()
    if bundle != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
        raise ValueError("domain original was not adopted by the actual shared bundle ledger")
    wire = canonical_serialize(_receipt_wire(receipt))
    reads = canonical_serialize([[v.key.token, v.revision] for v in stage.read_versions])
    content = (stage.domain, stage.operation_kind, stage.request_digest, stage.original_digest,
        stage.original_payload_json, reads, receipt.operation_digest, wire, canonical_digest(receipt))
    old = db.execute(f"SELECT domain,operation_kind,request_digest,original_digest,original_payload_json,"
        f"read_versions_json,bundle_digest,receipt_json,receipt_digest FROM {TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?", (*stage.namespace.as_tuple, stage.operation_id)).fetchone()
    if old is not None and old != content:
        raise ValueError("domain operation changed its adopted original")
    if old is None:
        db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (*stage.namespace.as_tuple, stage.operation_id, *content))
    return ProductionOriginalRefV1(stage.domain + ".current-" + stage.operation_kind,
        stage.domain + "-current:" + stage.original_digest[:48], stage.original_digest, stage.read_versions)


def read_adopted_domain_operation_v1(db, namespace, operation_id):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from ..authority_service.named_joint_binding_body_v1 import named_joint_adopted_operation_v1
    named,value=named_joint_adopted_operation_v1(db,namespace,operation_id)
    if named:return value
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import (read_bound_background_graph_attachment_v3,
        background_physical_payload_v3, background_json_loads_v3, background_json_matches_v3,
        background_json_digest_v3, background_typed_original_digest_v3)
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("domain adopted original needs the current W01 snapshot")
    background,row=read_bound_background_graph_attachment_v3(db,table=TABLE,columns=('domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest'),
        key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,operation_id))
    if not background:
        row = _producer_original_point_v3(db, table='graph_domain_production_originals_v1', columns=('domain', 'operation_kind', 'request_digest', 'original_digest', 'original_payload_json', 'read_versions_json', 'bundle_digest', 'receipt_json', 'receipt_digest'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((*namespace.as_tuple, operation_id)), legacy_reader=lambda: _artifact_receipt_sql_v1(db,f"SELECT domain,operation_kind,request_digest,original_digest,original_payload_json,"
        f"read_versions_json,bundle_digest,receipt_json,receipt_digest FROM {TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone())
    if row is None:
        if background:
            _,physical=read_bound_background_graph_attachment_v3(db,table=PHYSICAL_TABLE,
                columns=('domain','operation_kind','request_digest','original_digest','original_payload_cell_id',
                    'prepared_digest','read_versions_json','bundle_digest','receipt_json','receipt_digest'),
                key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,operation_id))
            if physical is None:return None
            if physical[:2]!=('d06','admit_owner_material_source_v1'):
                raise ValueError('unregistered physical domain original kind')
            payload=background_physical_payload_v3(db,namespace,operation_id,physical)
            row=(*physical[:4],payload,*physical[6:])
        else:
            from ..runtime_storage_v3 import runtime_storage_v3
            if runtime_storage_v3(db) is None:return None
            return read_adopted_physical_domain_operation_v3(db, namespace, operation_id)
    domain, kind, request, original_digest, encoded, reads_json, digest, receipt_json, receipt_digest = row
    payload, read_rows, raw_receipt = background_json_loads_v3(encoded), background_json_loads_v3(reads_json), background_json_loads_v3(receipt_json)
    receipt = _receipt(raw_receipt)
    reads = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in read_rows)
    if (not _registered_domain_original_v1(domain, kind) or not background_json_matches_v3(encoded,payload)
            or background_json_digest_v3(encoded,payload) != original_digest or not background_json_matches_v3(reads_json,read_rows)
            or len(reads) > 1024 or any(NamespaceId.from_key(v.key) != namespace for v in reads)
            or not background_json_matches_v3(receipt_json,raw_receipt) or background_typed_original_digest_v3(db,receipt_json,receipt) != receipt_digest
            or receipt.operation_id != operation_id or receipt.operation_digest != digest
            or payload.get("namespace") != asdict(namespace)
            or payload.get("identity", {}).get("operation_id") != operation_id):
        raise ValueError("domain adopted original identity or exact bytes differ")
    background_actual,actual=read_bound_background_graph_attachment_v3(db,table='graph_bundle_operations',
        columns=('digest','activity_id','effect_id','commit_seq'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,operation_id))
    if not background_actual:
        actual = _producer_original_point_v3(db, table='graph_bundle_operations', columns=('digest', 'activity_id', 'effect_id', 'commit_seq'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((*namespace.as_tuple, operation_id)), legacy_reader=lambda: _artifact_receipt_sql_v1(db,"SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone())
    if actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
        raise ValueError("domain adopted original lost its actual W01 commit")
    original={"domain": domain, "operation_kind": kind, "request_digest": request,
        "original_digest": original_digest, "payload": payload, "read_versions": reads, "receipt": receipt}
    from .habit_census_provenance_v1 import validate_habit_census_original_v1
    validate_habit_census_original_v1(original)
    from ..authority_service.artifact_model_original_family_v3 import register_artifact_model_positive_parent_v3
    register_artifact_model_positive_parent_v3(db,original)
    return original


def record_adopted_physical_domain_operation_v3(db, stage, receipt):
    from .owner_material_source_storage_v3 import StagedDomainOperationV3, _PREPARATIONS
    from ..runtime_storage_v3 import runtime_storage_v3, _operation
    if (not db.in_transaction or type(stage) is not StagedDomainOperationV3
            or stage.prepared not in _PREPARATIONS or type(receipt) is not CommitReceipt
            or stage.operation_kind != 'admit_owner_material_source_v1' or stage.domain != 'd06'
            or receipt.status != 'committed' or receipt.operation_id != stage.operation_id
            or receipt.activity_id != stage.activity_id):
        raise ValueError('physical domain original needs its actual issued same-W01 receipt')
    prepared=stage.prepared
    prepared.require_current()
    if db is not prepared.db or _operation(runtime_storage_v3(db)) is not prepared.operation:
        raise ValueError('physical domain original crossed its actual retained operation/store')
    actual=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*stage.namespace.as_tuple,stage.operation_id)).fetchone()
    if actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError('physical domain original lost its actual shared W01 commit')
    seal=prepared.seals['original'].require_current(prepared,'original')
    if receipt.operation_digest!=prepared.expected['bundle'][0] or stage.original_digest!=seal.header[6]:
        raise ValueError('physical domain original/bundle sealed canonical digests differ')
    wire=canonical_serialize(_receipt_wire(receipt))
    reads=canonical_serialize([[v.key.token,v.revision] for v in stage.read_versions])
    content=(stage.domain,stage.operation_kind,stage.request_digest,stage.original_digest,
        seal.cell_id,prepared.prepared_digest,reads,receipt.operation_digest,wire,canonical_digest(receipt))
    old=db.execute('SELECT domain,operation_kind,request_digest,original_digest,original_payload_cell_id,'
        'prepared_digest,read_versions_json,bundle_digest,receipt_json,receipt_digest FROM '+PHYSICAL_TABLE+
        ' WHERE bot=? AND persona=? AND operation_id=?',(*stage.namespace.as_tuple,stage.operation_id)).fetchone()
    if old is None:
        db.execute('INSERT INTO '+PHYSICAL_TABLE+' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (*stage.namespace.as_tuple,stage.operation_id,*content))
    elif old!=content:raise ValueError('physical domain adopted original changed its exact identity')
    return ProductionOriginalRefV1(stage.domain+'.current-'+stage.operation_kind,
        stage.domain+'-current:'+stage.original_digest[:48],stage.original_digest,stage.read_versions)


class DomainOriginalPayloadReadV3:
    """Complete v1 logical payload, decoded over actual bounded worker quanta."""
    def __init__(self,db,namespace,operation_id,row):
        from ..runtime_storage_v3 import runtime_storage_v3,_operation,RuntimeCellReadV3,runtime_storage_quantum_v3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.db,self.namespace,self.operation_id,self.row=db,namespace,operation_id,row
        self.handle=runtime_storage_v3(db);self.operation=_operation(self.handle)
        self.operation.retain(131072)
        with runtime_storage_quantum_v3(db) as meter:
            self.cell=RuntimeCellReadV3(self.handle,row[4],meter=meter)
            self.receipt,self.reads=_validate_physical_original_metadata_v3(db,namespace,operation_id,row)
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.nodes={};self.scalar=bytearray();self.value=None
        self.fragment=b'';self.fragment_offset=0;self.complete=False

    def _put(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent) is list:
                if path[-1]!=len(parent):raise ValueError('physical original array cursor differs')
                parent.append(value)
            else:parent[path[-1]]=value

    def _emit(self,event):
        if event.kind in ('object_start','array_start'):
            value={} if event.kind=='object_start' else []
            self.nodes[event.path]=value;self._put(event.path,value)
        elif event.kind=='scalar_start':self.scalar=bytearray()
        elif event.kind=='scalar_chunk':
            # Reserve actual retained wire and decoded temporary copies before growth.
            self.operation.retain(len(event.raw)*4+128)
            self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            value=json.loads(self.scalar);self.scalar=bytearray();self._put(event.path,value)

    def _current(self):
        from ..runtime_storage_v3 import _operation
        if _operation(self.handle) is not self.operation:
            raise ValueError('domain original read crossed its actual retained operation')
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter=current_c09_sql_meter_v2()
        actual=meter.read_fixed_row(self.db,PHYSICAL_TABLE,
            ('original_digest','original_payload_cell_id','prepared_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
        if actual!=(self.row[3],self.row[4],self.row[5],self.row[7],self.row[9]):
            raise ValueError('physical adopted original changed during complete read')
        bundle=meter.read_fixed_row(self.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
        receipt=self.receipt
        if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise ValueError('physical domain original lost actual W01 metadata during continuation')

    def advance(self):
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(self.db) as meter:
            self._current()
            if self.complete:return {'status':'complete','value':self.result}
            if self.fragment_offset<len(self.fragment):
                end=min(self.fragment_offset+1024,len(self.fragment))
                self.parser.feed(self.fragment[self.fragment_offset:end],self._emit)
                self.fragment_offset=end
            else:
                chunk=self.cell.read_fragment(meter=meter)
                if chunk is not None:self.fragment,self.fragment_offset=chunk,0
                else:
                    parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
                    if (parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]) or digest!=self.row[3]:
                        raise ValueError('physical domain original complete canonical bytes/EOF differ')
                    if (self.value.get('namespace')!=asdict(self.namespace)
                            or self.value.get('identity',{}).get('operation_id')!=self.operation_id
                            or self.value.get('schema')!='d06.current-admit_owner_material_source_v1.v1'):
                        raise ValueError('physical domain original logical v1 identity differs')
                    receipt,reads=self.receipt,self.reads
                    self.result={'domain':self.row[0],'operation_kind':self.row[1],'request_digest':self.row[2],
                        'original_digest':self.row[3],'payload':self.value,'read_versions':reads,'receipt':receipt}
                    self.complete=True;self._current()
        return {'status':'complete','value':self.result} if self.complete else {'status':'progress'}


def _physical_original_row_v3(db,namespace,operation_id):
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    return _runtime_bounded_fixed_row_v3(db,current_c09_sql_meter_v2(),PHYSICAL_TABLE,
        ('domain','operation_kind','request_digest','original_digest','original_payload_cell_id',
         'prepared_digest','read_versions_json','bundle_digest','receipt_json','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id))


def _validate_physical_original_metadata_v3(db,namespace,operation_id,row):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    domain,kind,request,digest,cell,prepared,reads_json,bundle_digest,receipt_json,receipt_digest=row
    if (domain,kind)!=('d06','admit_owner_material_source_v1'):
        raise ValueError('unregistered physical domain original kind')
    read_rows=background_json_loads_v3(reads_json);raw_receipt=background_json_loads_v3(receipt_json);receipt=_receipt(raw_receipt)
    reads=tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in read_rows)
    if (canonical_serialize(read_rows)!=reads_json or len(reads)>1024
            or any(NamespaceId.from_key(value.key)!=namespace for value in reads)
            or canonical_serialize(raw_receipt)!=receipt_json or canonical_digest(receipt)!=receipt_digest
            or receipt.operation_id!=operation_id or receipt.operation_digest!=bundle_digest):
        raise ValueError('physical domain original receipt/readset exact v1 wire differs')
    actual=_artifact_receipt_sql_v1(db,'SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if actual!=(bundle_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError('physical domain original lost its actual W01 bundle')
    return receipt,reads


def read_adopted_physical_domain_operation_v3(db,namespace,operation_id):
    from ..runtime_storage_v3 import RuntimeStorageNeedsContinuationV3,RuntimeStorageProgressV3,runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db):
        row=_physical_original_row_v3(db,namespace,operation_id)
        if row is None:return None
        _validate_physical_original_metadata_v3(db,namespace,operation_id,row)
        reader=DomainOriginalPayloadReadV3(db,namespace,operation_id,row)
    raise RuntimeStorageNeedsContinuationV3(RuntimeStorageProgressV3(reader.handle.selection_digest,row[4],0,0,
        row[3],reader.operation.operation_id,reader.operation.deadline_utc),continuation=reader)


def reconstruct_graph_bundle_commit_receipt_v1(namespace, operation_id, bundle_row, event_row):
    """Decode the original bundle/event metadata without changing its historical wire."""
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .domain_background_read_v3 import background_json_loads_v3
    from ..graph_store import GraphStore
    if type(namespace) is not NamespaceId or type(operation_id) is not str or not operation_id:
        raise ValueError("committed receipt requires its exact namespace and operation")
    if bundle_row is None or event_row is None:
        raise MissingProductionOriginalV1("actual_committed_graph_bundle_event_metadata")
    if len(bundle_row) != 5 or len(event_row) != 3:
        raise ValueError("committed bundle/event metadata fields differ")
    operation_digest, activity_id, effect_id, commit_seq, encoded = bundle_row
    raw = background_json_loads_v3(encoded)
    if (type(raw) is not dict or type(commit_seq) is not int or commit_seq < 1
            or raw["commit_seq"] != commit_seq):
        raise ValueError("committed bundle sequence differs from its original metadata")
    receipt = CommitReceipt("committed", operation_id, operation_digest, activity_id, effect_id, commit_seq,
        GraphStore._version_rows(event_row[0]), GraphStore._version_rows(event_row[1]),
        (NamespaceEpoch(namespace.bot_id, namespace.persona_id, event_row[2]),),
        tuple(raw["ledger_refs"]), tuple(raw["outbox_refs"]))
    return _receipt(_receipt_wire(receipt))
