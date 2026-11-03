"""Core originals joining the counted template to one actual pre-send SDK capture.

Expected bytes are reconstructed at model admission. The observed phase is an
assertion by the designated mTLS adapter before send, not a provider completion,
remote execution proof or charge. Existing model fences and Source gates apply.
"""
from dataclasses import asdict
from hashlib import sha256
import base64
import json
import sqlite3
import math
from .contract import AuthorityUnavailable
from .d13_core_counter_contract_v1 import (D13CoreFrameIntentHeaderV7,D13CoreFullWireEnvelopeV1,
    D13CurrentWireCountSelectorV1,d13_core_counter_from_wire_v1,verify_signed_d13_core_wire_evidence_v1,
    verify_historical_d13_core_wire_origin_v1)
from ..model_broker.d13_provider_http_template_v1 import D13ProviderHTTPTemplateV1,serialize_provider_http_v1
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import (read_core_payload_row_v3, insert_core_payload_row_v3,
    reserve_runtime_payload_v3)

TABLE='authority_d13_provider_http_bindings_v1'
SCHEMA="""CREATE TABLE authority_d13_provider_http_bindings_v1 (
    namespace TEXT NOT NULL, call_id TEXT NOT NULL, phase TEXT NOT NULL,
    payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,call_id,phase)) STRICT"""
DOMAIN=b'sylanne3.d13.provider-http-binding.v1\0'


def install_initial_provider_http_binding_schema_v1(db):
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise AuthorityUnavailable('initial provider HTTP store requires actual installer transaction')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone():
        raise AuthorityUnavailable('fresh provider HTTP store refuses overwrite')
    db.execute(SCHEMA)
    for operation in ('UPDATE','DELETE'):
        db.execute(f"CREATE TRIGGER d13_provider_http_no_{operation.lower()}_v1 BEFORE {operation} ON {TABLE} BEGIN SELECT RAISE(ABORT,'provider HTTP binding original is immutable'); END")


def _read_counter_phase(db,counter,operation,phase):
    from .c09_d13_source_retirement_v3 import require_not_retired_d13_source_v3
    require_not_retired_d13_source_v3(db,control=getattr(counter.core,'_c09_storage_reader_v1',None),
        namespace=counter.bridge.namespace,kind='counter',item_id=operation)
    row=read_core_payload_row_v3(db,'authority_d13_counter_originals_v1',
        (counter.bridge.namespace,operation,phase))
    if row is None or sha256(row[0].encode('utf-8')).hexdigest()!=row[1]:
        raise AuthorityUnavailable('provider HTTP admission lacks its actual immutable counter original')
    value=json.loads(row[0])
    if canonical_serialize(value)!=row[0]:raise AuthorityUnavailable('counter original encoding differs')
    return value


def _record(db,counter,payload):
    if db is not counter.core._db or not db.in_transaction:
        raise AuthorityUnavailable('provider HTTP original needs actual Core transaction')
    from .c09_d13_source_retirement_v3 import require_not_retired_d13_source_v3
    require_not_retired_d13_source_v3(db,control=getattr(counter.core,'_c09_storage_reader_v1',None),
        namespace=payload['authority_namespace'],kind='http',item_id=payload['call_id'])
    signature=base64.b64encode(counter._key.sign(DOMAIN+canonical_serialize(payload).encode('utf-8'))).decode('ascii')
    value={'payload':payload,'signature':signature}
    reserve_runtime_payload_v3(db,value)
    encoded=canonical_serialize(value)
    if len(encoded.encode('utf-8'))>65536:raise AuthorityUnavailable('provider HTTP original exceeds fixed bound')
    digest=sha256(encoded.encode('utf-8')).hexdigest()
    key=(payload['authority_namespace'],payload['call_id'],payload['phase'])
    prior=read_core_payload_row_v3(db,TABLE,key)
    if prior is not None:
        if prior!=(encoded,digest):raise AuthorityUnavailable('provider HTTP original replay differs')
    else:insert_core_payload_row_v3(db,TABLE,key,encoded,digest,
        read_proof={'admission_id':payload['admission_id'],'request_digest':payload['request_digest'],
            'counter_operation_id':payload['counter_operation_id'],
            'frame_intent_digest':payload['frame_intent_digest'],
            'counter_evidence_digest':payload['counter_evidence_digest']})
    return {'original_digest':digest,'payload':payload,'signature':signature}


def stage_expected_provider_http_v1(db,*,counter,intent,request,admission,now_utc):
    """Called only inside the successful existing model-admission transaction."""
    if (db is not counter.core._db or not db.in_transaction or admission is None
            or intent.namespace!=counter.bridge.namespace
            or admission.installation_id!=counter.policy.installation.installation_id
            or request.digest!=intent.request_digest or request.call_id!=intent.call_id
            or admission.request_digest!=request.digest or admission.call_id!=request.call_id):
        raise AuthorityUnavailable('provider HTTP admission crosses actual model/Core installation')
    rows=read_runtime_counter_operations_for_call_v3(db,counter=counter,
        namespace=intent.namespace,call_id=intent.call_id)
    if len(rows)!=1:raise AuthorityUnavailable('model call lacks its one actual Core counted frame')
    operation=rows[0][0]
    frame=d13_core_counter_from_wire_v1(_read_counter_phase(db,counter,operation,'header'),D13CoreFrameIntentHeaderV7)
    evidence=d13_core_counter_from_wire_v1(_read_counter_phase(db,counter,operation,'evidence'),D13CoreFullWireEnvelopeV1)
    selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,frame.frame_intent_id,
        frame.frame_intent_digest,frame.counter_operation_id,frame.raw_authority_digest,frame.compressed_authority_digest,
        frame.raw_http_template_digest,frame.compressed_http_template_digest)
    verify_signed_d13_core_wire_evidence_v1(counter.policy,evidence,selector=selector,frame=frame,now_utc=now_utc)
    template=D13ProviderHTTPTemplateV1(request.model_id,tuple((item['role'],item['content']) for item in request.payload['messages']),
        request.max_output_tokens,request.call_id,counter.billing_contract_digest,counter.policy.serializer_fingerprint)
    if template.template_digest not in (frame.raw_http_template_digest,frame.compressed_http_template_digest):
        raise AuthorityUnavailable('actual admitted model body differs from independently counted template')
    content=serialize_provider_http_v1(template,request_digest=request.digest)
    expected_bytes=evidence.payload.raw_http_bytes if template.template_digest==frame.raw_http_template_digest else evidence.payload.compressed_http_bytes
    if len(content)!=expected_bytes:raise AuthorityUnavailable('model HTTP byte bound differs from its actual counter original')
    payload={'schema':'sylanne3.d13.provider-http-binding.v1','phase':'expected',
        'authority_namespace':intent.namespace,'installation_id':admission.installation_id,'authority_id':intent.authority_id,
        'call_id':intent.call_id,'admission_id':admission.admission_id,'request_digest':request.digest,
        'provider_config_digest':intent.provider_config_digest,'template_digest':template.template_digest,
        'http_digest':sha256(content).hexdigest(),'http_bytes':len(content),'counter_operation_id':operation,
        'frame_intent_digest':frame.frame_intent_digest,'counter_evidence_digest':canonical_digest(evidence),
        'expires_at_utc':frame.expires_at_utc,'model_intent_digest':canonical_digest(intent)}
    return _record(db,counter,payload)


def record_observed_provider_http_v1(db,*,counter,intent,admission,actual_content,now_utc):
    """One designated pre-send capture, still inside the current model fence."""
    if type(actual_content) is not bytes or not 0<len(actual_content)<=65536:
        raise AuthorityUnavailable('bounded actual provider HTTP bytes required')
    row=read_core_payload_row_v3(db,TABLE,(intent.namespace,intent.call_id,'expected'))
    if row is None or sha256(row[0].encode('utf-8')).hexdigest()!=row[1]:
        raise AuthorityUnavailable('actual provider capture lacks its original expected admission')
    value=json.loads(row[0]);expected=value['payload']
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(counter.policy.counter_public_key_hex)).verify(
        base64.b64decode(value['signature'],validate=True),DOMAIN+canonical_serialize(expected).encode('utf-8'))
    if (expected['phase']!='expected' or expected['authority_namespace']!=intent.namespace
            or expected['call_id']!=intent.call_id or expected['admission_id']!=admission.admission_id
            or expected['installation_id']!=admission.installation_id or expected['request_digest']!=intent.request_digest
            or expected['provider_config_digest']!=intent.provider_config_digest
            or expected['model_intent_digest']!=canonical_digest(intent)
            or now_utc>=expected['expires_at_utc'] or expected['http_bytes']!=len(actual_content)
            or expected['http_digest']!=sha256(actual_content).hexdigest()):
        raise AuthorityUnavailable('actual provider HTTP capture differs from current same-admission original')
    return _record(db,counter,{**expected,'phase':'observed_before_send','observed_at_utc':now_utc})




def verify_historical_provider_http_phase_v1(counter,value,*,phase,intent,admission):
    """Authenticate one actual historical pre-send phase; no present dispatch."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if phase not in {'expected','observed_before_send'}:
        raise AuthorityUnavailable('unknown registered historical provider HTTP phase')
    fields={'schema','phase','authority_namespace','installation_id','authority_id','call_id','admission_id',
        'request_digest','provider_config_digest','template_digest','http_digest','http_bytes','counter_operation_id',
        'frame_intent_digest','counter_evidence_digest','expires_at_utc','model_intent_digest'}
    if phase=='observed_before_send':fields.add('observed_at_utc')
    if type(value) is not dict or set(value)!={'payload','signature'} or type(value['payload']) is not dict:
        raise AuthorityUnavailable('provider HTTP historical original fields differ')
    payload=value['payload']
    if set(payload)!=fields or payload['schema']!='sylanne3.d13.provider-http-binding.v1' or payload['phase']!=phase:
        raise AuthorityUnavailable('provider HTTP historical payload schema or phase differs')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(counter.policy.counter_public_key_hex)).verify(
        base64.b64decode(value['signature'],validate=True),DOMAIN+canonical_serialize(payload).encode('utf-8'))
    if (payload['authority_namespace']!=intent.namespace or payload['call_id']!=intent.call_id
            or payload['installation_id']!=admission.installation_id or payload['admission_id']!=admission.admission_id
            or payload['authority_id']!=intent.authority_id or payload['request_digest']!=intent.request_digest
            or payload['model_intent_digest']!=canonical_digest(intent)
            or payload['provider_config_digest']!=intent.provider_config_digest):
        raise AuthorityUnavailable('provider HTTP historical phase crossed actual installation/model admission')
    return payload


def require_recorded_provider_http_binding_v1(db,*,counter,intent,admission):
    """Authenticate historical pre-send originals; grants no fresh dispatch."""
    values=[]
    for phase in ('expected','observed_before_send'):
        row=read_core_payload_row_v3(db,TABLE,(intent.namespace,intent.call_id,phase))
        if row is None or sha256(row[0].encode('utf-8')).hexdigest()!=row[1]:
            raise AuthorityUnavailable('V7 completion lacks actual immutable provider HTTP binding')
        value=json.loads(row[0])
        if canonical_serialize(value)!=row[0]:raise AuthorityUnavailable('provider HTTP historical original encoding differs')
        payload=verify_historical_provider_http_phase_v1(counter,value,phase=phase,intent=intent,admission=admission)
        values.append(payload)
    expected,observed=values
    observed_at=observed.pop('observed_at_utc')
    if ({**observed,'phase':'expected'}!=expected or type(observed_at) not in (int,float)
            or not math.isfinite(observed_at)):
        raise AuthorityUnavailable('V7 actual provider capture differs from its original expected bytes')
    operation=expected['counter_operation_id']
    frame=d13_core_counter_from_wire_v1(_read_counter_phase(db,counter,operation,'header'),D13CoreFrameIntentHeaderV7)
    evidence=d13_core_counter_from_wire_v1(_read_counter_phase(db,counter,operation,'evidence'),D13CoreFullWireEnvelopeV1)
    selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,frame.frame_intent_id,
        frame.frame_intent_digest,frame.counter_operation_id,frame.raw_authority_digest,frame.compressed_authority_digest,
        frame.raw_http_template_digest,frame.compressed_http_template_digest)
    verify_historical_d13_core_wire_origin_v1(counter.policy,evidence,selector=selector,frame=frame)
    counted=evidence.payload
    template=expected['template_digest']
    if template==frame.raw_http_template_digest:counted_bytes=counted.raw_http_bytes
    elif template==frame.compressed_http_template_digest:counted_bytes=counted.compressed_http_bytes
    else:raise AuthorityUnavailable('historical provider HTTP template differs from its original counter pair')
    if (expected['counter_evidence_digest']!=canonical_digest(evidence)
            or expected['frame_intent_digest']!=frame.frame_intent_digest
            or expected['authority_id']!=frame.authority_id or expected['call_id']!=frame.generation_call_id
            or expected['expires_at_utc']!=frame.expires_at_utc
            or expected['http_bytes']!=counted_bytes
            or not frame.frozen_at_utc<=observed_at<frame.expires_at_utc):
        raise AuthorityUnavailable('historical provider HTTP original crosses counter evidence, frame or original lifetime')
    return expected

_INDEX_DDL = """CREATE TABLE IF NOT EXISTS runtime_d13_counter_calls_v3 (
    selection_digest TEXT NOT NULL,namespace TEXT NOT NULL,counter_operation_id TEXT NOT NULL,
    generation_call_id TEXT NOT NULL,header_digest TEXT NOT NULL,classification TEXT NOT NULL,cutoff_scope_digest TEXT,
    PRIMARY KEY(selection_digest,namespace,counter_operation_id)) STRICT"""
_CURSOR_DDL = """CREATE TABLE IF NOT EXISTS runtime_d13_counter_index_cursor_v3 (
    selection_digest TEXT PRIMARY KEY,cutoff_scope_digest TEXT NOT NULL,storage_instance_id TEXT NOT NULL,
    namespace TEXT NOT NULL,last_operation_id TEXT NOT NULL,record_count INTEGER NOT NULL,
    prefix_root TEXT NOT NULL,phase TEXT NOT NULL,cursor_revision INTEGER NOT NULL) STRICT"""
_SEAL_DDL = """CREATE TABLE IF NOT EXISTS runtime_d13_counter_index_seals_v3 (
    selection_digest TEXT PRIMARY KEY,cutoff_scope_digest TEXT NOT NULL,storage_instance_id TEXT NOT NULL,
    namespace TEXT NOT NULL,record_count INTEGER NOT NULL,ordered_root TEXT NOT NULL,
    eof_digest TEXT NOT NULL) STRICT"""


def _require_index_schema(db):
    for table in ('runtime_d13_counter_calls_v3','runtime_d13_counter_index_cursor_v3','runtime_d13_counter_index_seals_v3'):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:
            raise AuthorityUnavailable('actual counter derived index schema was not registered at bootstrap')



def _initial_runtime_counter_index_material_v4(counter,db,meter):
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_source_identity_v4
    if (type(counter)is not InstalledD13CoreCounterServiceV1 or db is not counter.core._db
            or not db.in_transaction or not counter.core._lock._is_owned()):
        raise AuthorityUnavailable('actual same-Core Counter initialization transaction required')
    handle=runtime_storage_v3(db)
    identity=runtime_source_identity_v4(handle,meter=meter)
    if (identity.origin_kind!='initial_segmented_v4' or identity.role!='core'
            or identity.namespace!=counter.namespace or identity.authority_namespace!=counter.bridge.namespace):
        raise AuthorityUnavailable('actual signed initial Core Counter scope required')
    return _initial_runtime_counter_prefix_material_v4(db,identity,handle.initial.original,meter)


def _initial_runtime_counter_prefix_material_v4(db,identity,original,meter):
    empty=original['core_counter_empty_eof']
    fields={'schema','core_storage_instance_id','namespace','header_table','header_count','header_schema_digest',
        'index_table','index_count','index_schema_digest','empty_root'}
    if (type(empty)is not dict or set(empty)!=fields or empty['schema']!='sylanne3.c09.initial-counter-empty-eof.v4'
            or empty['core_storage_instance_id']!=identity.instance or empty['namespace']!=identity.authority_namespace
            or empty['header_table']!='authority_d13_counter_originals_v1'
            or empty['index_table']!='runtime_d13_counter_calls_v3'
            or type(empty['header_count'])is not int or empty['header_count']!=0
            or type(empty['index_count'])is not int or empty['index_count']!=0):
        raise AuthorityUnavailable('initial Counter prefix lacks its actual signed zero-history EOF')
    for table,digest in ((empty['header_table'],empty['header_schema_digest']),
            (empty['index_table'],empty['index_schema_digest'])):
        row=meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",(table,))
        if row is None or canonical_digest(row[0])!=digest:
            raise AuthorityUnavailable('initial Counter empty EOF differs from its actual installed schema')
    if empty['empty_root']!=canonical_digest((empty['header_table'],empty['header_schema_digest'],0,
            empty['index_table'],empty['index_schema_digest'],0)):
        raise AuthorityUnavailable('initial Counter signed zero-history root differs')
    marker=canonical_digest(('sylanne3.d13.initial-counter-empty-prefix.v4',identity.genesis_digest,
        identity.selection_digest,identity.instance,identity.authority_namespace))
    root=canonical_digest(('sylanne3.d13.initial-counter-index-empty-root.v4',identity.genesis_digest,
        marker,empty['empty_root']))
    eof=canonical_digest(('sylanne3.d13.initial-counter-index-eof.v4',identity.selection_digest,
        marker,identity.instance,identity.authority_namespace,0,root))
    cursor=(identity.selection_digest,marker,identity.instance,identity.authority_namespace,'',0,root,'sealed',1)
    seal=(identity.selection_digest,marker,identity.instance,identity.authority_namespace,0,root,eof)
    return cursor,seal


def _read_initial_runtime_counter_index_v4(db,meter,selection):
    cursor=meter.read_fixed_row(db,'runtime_d13_counter_index_cursor_v3',
        ('selection_digest','cutoff_scope_digest','storage_instance_id','namespace','last_operation_id',
            'record_count','prefix_root','phase','cursor_revision'),'selection_digest=?',(selection,))
    seal=meter.read_fixed_row(db,'runtime_d13_counter_index_seals_v3',
        ('selection_digest','cutoff_scope_digest','storage_instance_id','namespace','record_count',
            'ordered_root','eof_digest'),'selection_digest=?',(selection,))
    return cursor,seal


def install_actual_initial_runtime_counter_index_v4(counter,*,db):
    """Record only the actual initial empty prefix; later runtime headers are delta rows."""
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        cursor,seal=_initial_runtime_counter_index_material_v4(counter,db,meter)
        actual=_read_initial_runtime_counter_index_v4(db,meter,seal[0])
        if actual==(cursor,seal):return seal
        if actual!=(None,None):
            raise AuthorityUnavailable('initial Counter prefix has a partial or different immutable seal')
        header=meter.read_fixed_row(db,'authority_d13_counter_originals_v1',
            ('namespace','counter_operation_id','phase'),'1=1',())
        indexed=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',
            ('selection_digest','namespace','counter_operation_id'),'1=1',())
        if header is not None or indexed is not None:
            raise AuthorityUnavailable('initial Counter prefix cannot be backfilled after actual Counter production')
        meter.charge_write(sum(len(str(value).encode('utf8'))for value in cursor+seal))
        meter.count_mutation()
        db.execute('INSERT INTO runtime_d13_counter_index_cursor_v3 VALUES(?,?,?,?,?,?,?,?,?)',cursor)
        meter.count_mutation()
        db.execute('INSERT INTO runtime_d13_counter_index_seals_v3 VALUES(?,?,?,?,?,?,?)',seal)
        return seal


def require_actual_initial_runtime_counter_index_v4(counter,*,db):
    """Verify the signed genesis prefix and its actual durable seal without replaying it."""
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        cursor,seal=_initial_runtime_counter_index_material_v4(counter,db,meter)
        if _read_initial_runtime_counter_index_v4(db,meter,seal[0])!=(cursor,seal):
            raise AuthorityUnavailable('actual initial Counter zero-history prefix seal required')
        return seal


def _index_header(db,counter,operation,payload,digest,classification):
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_source_identity_v4
    handle=runtime_storage_v3(db)
    identity=runtime_source_identity_v4(handle)
    frame=d13_core_counter_from_wire_v1(payload,D13CoreFrameIntentHeaderV7)
    if (frame.counter_operation_id!=operation or frame.authority_namespace!=counter.bridge.namespace
            or frame.install_id!=counter.policy.installation.installation_id
            or frame.authority_id!=identity.control.authority_id):
        raise AuthorityUnavailable('counter index header crosses its actual installed producer')
    actual=db.execute("SELECT c.origin_scope_digest FROM authority_d13_counter_originals_v1 o JOIN segmented_cells_v1 c "
        "ON c.cell_id=o.payload_cell_id WHERE o.namespace=? AND o.counter_operation_id=? AND o.phase='header'",
        (counter.bridge.namespace,operation)).fetchone()
    if actual is None:raise AuthorityUnavailable('counter index needs its actual immutable header producer')
    if identity.origin_kind=='initial_segmented_v4':
        require_actual_initial_runtime_counter_index_v4(counter,db=db)
        from ..runtime_storage_v3 import read_runtime_cell_origin_v3,runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(db)as meter:
            cell=meter.read_fixed_row(db,'authority_d13_counter_originals_v1',('payload_cell_id','payload_digest'),
                "namespace=? AND counter_operation_id=? AND phase='header'",(counter.bridge.namespace,operation))
            if cell is None or cell[1]!=digest:
                raise AuthorityUnavailable('initial Counter delta differs from its actual immutable header')
            origin=read_runtime_cell_origin_v3(db,cell[0],meter=meter)
            if origin is None or origin['operation_id']!=operation:
                raise AuthorityUnavailable('initial Counter delta lacks its actual runtime header producer')
        cutoff=None
    else:
        cutoff=actual[0]if actual[0]==identity.capture_scope_digest else None
    row=(handle.selection_digest,counter.bridge.namespace,operation,frame.generation_call_id,digest,classification,cutoff)
    prior=db.execute('SELECT selection_digest,namespace,counter_operation_id,generation_call_id,header_digest,classification,cutoff_scope_digest '
        'FROM runtime_d13_counter_calls_v3 WHERE selection_digest=? AND namespace=? AND counter_operation_id=?',
        row[:3]).fetchone()
    if prior is None:
        db.execute('INSERT INTO runtime_d13_counter_calls_v3 VALUES(?,?,?,?,?,?,?)',row)
    elif prior!=row:
        # A header-only index remains a locator. Full evidence is rechecked at
        # use, so later evidence does not mutate the original classification.
        if prior[:5]!=row[:5] or prior[6]!=row[6] or prior[5] not in ('header_only','signed_full_wire'):
            raise AuthorityUnavailable('counter derived index attempted to replace its immutable header')
    return row


def register_runtime_counter_header_index_v3(db,*,counter,operation,payload,digest):
    """Same true counter header transaction; no new claim, fee or call admission."""
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(db) is None:
        return
    if db is not counter.core._db or not db.in_transaction:
        raise AuthorityUnavailable('counter index requires its actual immutable header transaction')
    _require_index_schema(db)
    _index_header(db,counter,operation,payload,digest,'header_only')


class RuntimeCounterCallIndexBuilderV3:
    """Bounded actual old-cutoff scan and cold prefix verification before use."""
    def __init__(self,counter):
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        from ..runtime_storage_v3 import runtime_storage_v3
        if type(counter) is not InstalledD13CoreCounterServiceV1:
            raise AuthorityUnavailable('actual installed counter actor required for derived bootstrap')
        self.counter,self.db=counter,counter.core._db
        self.handle=runtime_storage_v3(self.db)
        if self.handle is None or self.handle.role!='core':
            raise AuthorityUnavailable('counter bootstrap requires its actual selected Core')
        from ..runtime_storage_v3 import runtime_source_identity_v4
        identity=runtime_source_identity_v4(self.handle)
        self.selection=identity.selection_digest
        if identity.origin_kind=='initial_segmented_v4':
            self.scope=self.genesis=self.root=None
            self.after,self.count='',0
            self.complete=False;self.saved=None;self.phase='initial_zero'
            return
        self.scope=identity.capture_scope_digest
        self.genesis=canonical_digest(('sylanne3.d13.counter-index-genesis.v3',self.selection,self.scope,
            self.handle.instance,counter.bridge.namespace))
        self.after,self.count,self.root='',0,self.genesis
        self.complete=False
        self.saved=None
        self.phase='initialize'

    def _next(self,after):
        return self.db.execute("SELECT o.counter_operation_id,o.payload_cell_id,o.payload_digest "
            "FROM authority_d13_counter_originals_v1 o JOIN segmented_cells_v1 c ON c.cell_id=o.payload_cell_id "
            "WHERE o.namespace=? AND o.phase='header' AND c.origin_scope_digest=? "
            "AND o.counter_operation_id COLLATE BINARY>? ORDER BY o.counter_operation_id COLLATE BINARY LIMIT 1",
            (self.counter.bridge.namespace,self.scope,after)).fetchone()

    def _qualified(self,row):
        payload,digest=read_core_payload_row_v3(self.db,'authority_d13_counter_originals_v1',
            (self.counter.bridge.namespace,row[0],'header'))
        if digest!=row[2]:
            raise AuthorityUnavailable('counter bootstrap header digest changed')
        frame=d13_core_counter_from_wire_v1(json.loads(payload),D13CoreFrameIntentHeaderV7)
        evidence=read_core_payload_row_v3(self.db,'authority_d13_counter_originals_v1',
            (self.counter.bridge.namespace,row[0],'evidence'))
        classification='header_only'
        if evidence is not None:
            envelope=d13_core_counter_from_wire_v1(json.loads(evidence[0]),D13CoreFullWireEnvelopeV1)
            selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,
                frame.frame_intent_id,frame.frame_intent_digest,frame.counter_operation_id,
                frame.raw_authority_digest,frame.compressed_authority_digest,
                frame.raw_http_template_digest,frame.compressed_http_template_digest)
            verify_historical_d13_core_wire_origin_v1(self.counter.policy,envelope,selector=selector,frame=frame)
            classification='signed_full_wire'
        return json.loads(payload),digest,classification

    def advance(self):
        from ..runtime_storage_v3 import runtime_storage_operation_v3,runtime_storage_quantum_v3
        if self.complete:
            return dict(status='complete',selection_digest=self.selection,record_count=self.count,ordered_root=self.root)
        with runtime_storage_operation_v3(self.db,operation_id='d13-index:'+self.selection),runtime_storage_quantum_v3(self.db):
            if self.phase=='initial_zero':
                with self.counter.core._tx()as db:
                    seal=require_actual_initial_runtime_counter_index_v4(self.counter,db=db)
                self.scope,self.root=seal[1],seal[5]
                self.complete=True
                return dict(status='complete',selection_digest=self.selection,record_count=0,ordered_root=self.root)
            if self.phase=='initialize':
                with self.counter.core._tx() as db:
                    _require_index_schema(db)
                    prior=db.execute('SELECT selection_digest,cutoff_scope_digest,storage_instance_id,namespace,'
                        'last_operation_id,record_count,prefix_root,phase,cursor_revision '
                        'FROM runtime_d13_counter_index_cursor_v3 WHERE selection_digest=?',(self.selection,)).fetchone()
                    if prior is None:
                        initial=(self.selection,self.scope,self.handle.instance,self.counter.bridge.namespace,
                            '',0,self.genesis,'scan',0)
                        db.execute('INSERT INTO runtime_d13_counter_index_cursor_v3 VALUES(?,?,?,?,?,?,?,?,?)',initial)
                        prior=initial
                    if prior[:4]!=(self.selection,self.scope,self.handle.instance,self.counter.bridge.namespace):
                        raise AuthorityUnavailable('counter bootstrap cursor crossed its actual selected cutoff')
                    self.saved=prior
                self.phase='replay_prefix'
                return dict(status='progress',phase=self.phase)
            if self.phase=='replay_prefix' and self.count==self.saved[5]:
                if self.after!=self.saved[4] or self.root!=self.saved[6]:
                    raise AuthorityUnavailable('counter bootstrap cold actual prefix differs from its cursor')
                self.phase='scan'
                return dict(status='progress',phase=self.phase)
            row=self._next(self.after)
            if row is None:
                if self.phase=='replay_prefix':
                    raise AuthorityUnavailable('counter bootstrap saved prefix lacks actual header EOF')
                eof=canonical_digest(('sylanne3.d13.counter-index-eof.v3',self.selection,self.scope,self.after,self.count,self.root))
                seal=(self.selection,self.scope,self.handle.instance,self.counter.bridge.namespace,self.count,self.root,eof)
                with self.counter.core._tx() as db:
                    actual=db.execute('SELECT * FROM runtime_d13_counter_index_cursor_v3 WHERE selection_digest=?',
                        (self.selection,)).fetchone()
                    if actual!=self.saved:
                        raise AuthorityUnavailable('counter bootstrap final cursor CAS changed')
                    prior=db.execute('SELECT * FROM runtime_d13_counter_index_seals_v3 WHERE selection_digest=?',
                        (self.selection,)).fetchone()
                    if prior is None:db.execute('INSERT INTO runtime_d13_counter_index_seals_v3 VALUES(?,?,?,?,?,?,?)',seal)
                    elif prior!=seal:raise AuthorityUnavailable('counter bootstrap immutable EOF seal differs')
                    db.execute("UPDATE runtime_d13_counter_index_cursor_v3 SET phase='sealed',cursor_revision=cursor_revision+1 "
                        'WHERE selection_digest=? AND cursor_revision=?',(self.selection,self.saved[-1]))
                self.complete=True
                return dict(status='complete',selection_digest=self.selection,record_count=self.count,ordered_root=self.root)
            payload,digest,classification=self._qualified(row)
            next_root=canonical_digest(('sylanne3.d13.counter-index-link.v3',self.root,self.count,row[0],digest,
                payload['generation_call_id'],classification))
            if self.phase=='replay_prefix':
                index=self.db.execute('SELECT generation_call_id,header_digest,classification,cutoff_scope_digest FROM runtime_d13_counter_calls_v3 '
                    'WHERE selection_digest=? AND namespace=? AND counter_operation_id=?',
                    (self.selection,self.counter.bridge.namespace,row[0])).fetchone()
                if index!=(payload['generation_call_id'],digest,classification,self.scope):
                    raise AuthorityUnavailable('counter bootstrap cold prefix differs from its actual classified cutoff member')
                next_root=canonical_digest(('sylanne3.d13.counter-index-link.v3',self.root,self.count,row[0],digest,
                    payload['generation_call_id'],index[2]))
            else:
                with self.counter.core._tx() as db:
                    actual=db.execute('SELECT * FROM runtime_d13_counter_index_cursor_v3 WHERE selection_digest=?',
                        (self.selection,)).fetchone()
                    if actual!=self.saved:raise AuthorityUnavailable('counter bootstrap cursor CAS changed')
                    index=_index_header(db,self.counter,row[0],payload,digest,classification)
                    next_root=canonical_digest(('sylanne3.d13.counter-index-link.v3',self.root,self.count,row[0],digest,
                        payload['generation_call_id'],index[5]))
                    changed=db.execute('UPDATE runtime_d13_counter_index_cursor_v3 SET last_operation_id=?,record_count=?,'
                        'prefix_root=?,cursor_revision=cursor_revision+1 WHERE selection_digest=? AND cursor_revision=?',
                        (row[0],self.count+1,next_root,self.selection,self.saved[-1]))
                    if changed.rowcount!=1:raise AuthorityUnavailable('counter bootstrap progress CAS changed')
                    self.saved=(*self.saved[:4],row[0],self.count+1,next_root,'scan',self.saved[-1]+1)
            self.after,self.count,self.root=row[0],self.count+1,next_root
            return dict(status='progress',phase=self.phase,record_count=self.count)


def read_runtime_counter_operations_for_call_v3(db,*,counter,namespace,call_id):
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_source_identity_v4
    handle=runtime_storage_v3(db)
    if handle is None:
        return db.execute('SELECT counter_operation_id FROM authority_d13_counter_originals_v1 '
            "WHERE namespace=? AND phase='header' AND json_extract(payload_json,'$.generation_call_id')=? LIMIT 2",
            (namespace,call_id)).fetchall()
    identity=runtime_source_identity_v4(handle)
    initial=identity.origin_kind=='initial_segmented_v4'
    if initial:
        require_actual_initial_runtime_counter_index_v4(counter,db=db)
        if namespace!=identity.authority_namespace:
            raise AuthorityUnavailable('initial Counter call lookup crossed its actual namespace')
    else:
        seal=db.execute('SELECT cutoff_scope_digest,storage_instance_id,namespace FROM runtime_d13_counter_index_seals_v3 '
            'WHERE selection_digest=?',(handle.selection_digest,)).fetchone()
        if seal!=(identity.capture_scope_digest,identity.instance,namespace):
            raise AuthorityUnavailable('counter call lookup requires the actual complete selected cutoff index')
    rows=db.execute('SELECT counter_operation_id,header_digest,classification,cutoff_scope_digest FROM runtime_d13_counter_calls_v3 '
        'WHERE selection_digest=? AND namespace=? AND generation_call_id=? ORDER BY counter_operation_id LIMIT 2',
        (handle.selection_digest,namespace,call_id)).fetchall()
    for operation,digest,classification,cutoff in rows:
        actual=read_core_payload_row_v3(db,'authority_d13_counter_originals_v1',(namespace,operation,'header'))
        if actual is None or actual[1]!=digest:
            raise AuthorityUnavailable('counter call derived index no longer matches its actual header')
        frame=d13_core_counter_from_wire_v1(json.loads(actual[0]),D13CoreFrameIntentHeaderV7)
        if (frame.generation_call_id!=call_id or frame.counter_operation_id!=operation
                or frame.authority_namespace!=namespace or frame.authority_id!=identity.control.authority_id
                or frame.install_id!=counter.policy.installation.installation_id
                or initial and (cutoff is not None or classification not in ('header_only','signed_full_wire'))):
            raise AuthorityUnavailable('counter call derived index differs from its actual typed runtime producer')
    return [(operation,)for operation,digest,classification,cutoff in rows]


_SELECTED_INDEX_ISSUER_V3 = object()
_SELECTED_INDEX_READS_V3 = __import__('weakref').WeakSet()


class SelectedRuntimeCounterIndexReadV3:
    """Actual selected immutable header/index provenance; no current call right."""
    def __init__(self,issuer,db,basis,row,header_ref,policy):
        if issuer is not _SELECTED_INDEX_ISSUER_V3:
            raise AuthorityUnavailable('actual selected derived index reader issuer required')
        self.basis,self.row,self.header_ref,self.policy=basis,row,header_ref,policy
        _SELECTED_INDEX_READS_V3.add(self)
        self.header=None;self.ordinal=self.offset=0;self.root=None;self.hash=sha256()
        self.encoded=bytearray();self.phase='header';self.frame=None;self.complete=False

    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self) is not SelectedRuntimeCounterIndexReadV3 or self not in _SELECTED_INDEX_READS_V3
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual private counter original progress and Root quantum required')
        self.basis.require_current(meter=meter)
        self.basis.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=len(self.encoded)+4096)
        meter.charge_encode(len(self.encoded))
        result=copy(self);result.hash=self.hash.copy();result.encoded=bytearray(self.encoded)
        _SELECTED_INDEX_READS_V3.add(result)
        return result

    def _begin(self,db,meter,cell_id,digest):
        _begin_runtime_counter_cell_v4(self,db,meter,cell_id,digest)

    def advance(self,*,db,meter):
        from pathlib import Path
        from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if self not in _SELECTED_INDEX_READS_V3 or type(self.basis) is not _InstalledSelectedStorageBasisV3 or type(db) is not sqlite3.Connection:
            raise AuthorityUnavailable('actual private selected derived-index Core snapshot required')
        self.basis.require_current(meter=meter)
        database=db.execute('PRAGMA database_list').fetchall()
        if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(self.basis.member('core')['resolved_path']).resolve(strict=True):
            raise AuthorityUnavailable('counter index continuation crossed actual selected Core')
        row=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',
            ('selection_digest','namespace','counter_operation_id','generation_call_id','header_digest','classification','cutoff_scope_digest'),
            'selection_digest=? AND namespace=? AND counter_operation_id=?',self.row[:3])
        if row!=self.row:raise AuthorityUnavailable('actual derived index immutable row changed')
        return _advance_runtime_counter_original_v4(self,db=db,meter=meter,control=self.basis.control)


def _begin_runtime_counter_cell_v4(self,db,meter,cell_id,digest):
    from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
    header=meter.read_fixed_row(db,'segmented_cells_v1',
        ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
         'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
    if header is None or header[5]!=digest or header[0]!='canonical-json.ascii.v1':
        raise AuthorityUnavailable('selected derived counter index actual immutable cell differs')
    if header[3]*8+131072>meter.budget.reserved_arena_bytes:
        raise AuthorityUnavailable('counter header/evidence typed decode exceeds actual reserved arena')
    if type(self)is SelectedRuntimeCounterIndexReadV3:
        read_selected_runtime_cell_origin_v3(db,selected_basis=self.basis,role='core',cell_id=cell_id,header=header,meter=meter)
    elif type(self)is InitialRuntimeCounterIndexReadV4:
        from ..runtime_storage_v3 import read_initial_runtime_cell_origin_v4
        origin=read_initial_runtime_cell_origin_v4(db,initial=self.view,role='core',cell_id=cell_id,header=header,meter=meter)
        if origin is None:raise AuthorityUnavailable('initial Counter cell requires its actual runtime producer')
    else:raise AuthorityUnavailable('actual private Counter cell decoder required')
    self.header,self.cell_id=header,cell_id;self.ordinal=self.offset=0;self.hash=sha256()
    self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id));self.encoded=bytearray()



def _advance_runtime_counter_original_v4(self,*,db,meter,control):
    if self.complete:return {'status':'complete','row':self.row,'classification':self.row[5]}
    if self.header is None:
        self._begin(db,meter,*self.header_ref)
        return {'status':'progress'}
    if self.ordinal<self.header[4]:
        lengths=db.execute('SELECT length(payload) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?',
            (self.cell_id,self.ordinal)).fetchone()
        if lengths is None or not 0<lengths[0]<=16384:
            raise AuthorityUnavailable('counter index actual segment byte bound differs')
        segment=meter.read_fixed_row(db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
            'cell_id=? AND ordinal=?',(self.cell_id,self.ordinal))
        if segment[0]!=self.offset or sha256(segment[1]).hexdigest()!=segment[2]:
            raise AuthorityUnavailable('counter index actual segment offset/SHA differs')
        self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,
            self.ordinal,self.offset,len(segment[1]),segment[2]))
        self.hash.update(segment[1]);self.encoded.extend(segment[1]);self.ordinal+=1;self.offset+=len(segment[1])
        return {'status':'progress'}
    extra=db.execute('SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
        (self.cell_id,self.ordinal)).fetchone();meter.charge_read(8 if extra else 0)
    if (extra is not None or self.offset!=self.header[3] or self.hash.hexdigest()!=self.header[5]
            or self.root!=self.header[6]):
        raise AuthorityUnavailable('counter index complete original cell SHA/root/count/EOF differs')
    raw=json.loads(self.encoded)
    encoded=canonical_serialize(raw).encode('ascii');meter.charge_encode(len(encoded))
    if encoded!=self.encoded:
        raise AuthorityUnavailable('counter index original canonical bytes differ')
    if self.phase=='header':
        if self.row[6] is not None and self.header[7]!=self.row[6]:
            raise AuthorityUnavailable('derived cutoff membership differs from actual captured header origin')
        self.frame=d13_core_counter_from_wire_v1(raw,D13CoreFrameIntentHeaderV7)
        if (self.frame.authority_id!=control.authority_id
                or self.frame.install_id!=control.installation_id
                or self.frame.authority_namespace!=self.row[1]
                or self.frame.counter_operation_id!=self.row[2] or self.frame.generation_call_id!=self.row[3]
                or self.row[4]!=self.header[5]):
            raise AuthorityUnavailable('counter derived index changed actual typed V7 header identity')
        if self.row[5]=='signed_full_wire':
            evidence=meter.read_fixed_row(db,'authority_d13_counter_originals_v1',('payload_cell_id','payload_digest'),
                "namespace=? AND counter_operation_id=? AND phase='evidence'",self.row[1:3])
            if evidence is None or self.policy is None:
                raise AuthorityUnavailable('signed counter index needs actual installed public wire policy and evidence')
            self.phase='evidence';self._begin(db,meter,*evidence);return {'status':'progress'}
        if self.row[5]!='header_only':raise AuthorityUnavailable('unregistered counter index classification')
    else:
        envelope=d13_core_counter_from_wire_v1(raw,D13CoreFullWireEnvelopeV1)
        selector=D13CurrentWireCountSelectorV1(self.frame.install_id,self.frame.authority_namespace,
            self.frame.frame_intent_id,self.frame.frame_intent_digest,self.frame.counter_operation_id,
            self.frame.raw_authority_digest,self.frame.compressed_authority_digest,
            self.frame.raw_http_template_digest,self.frame.compressed_http_template_digest)
        verify_historical_d13_core_wire_origin_v1(self.policy,envelope,selector=selector,frame=self.frame)
    self.complete=True;self.encoded=bytearray()
    return {'status':'complete','row':self.row,'classification':self.row[5]}


def read_selected_runtime_counter_index_v3(db,*,basis,selection_digest,namespace,counter_operation_id,meter,policy=None):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from .c09_d13_source_retirement_v3 import TABLE,COLUMNS,validate_retirement_original_v3
    from pathlib import Path
    if type(basis) is not _InstalledSelectedStorageBasisV3 or type(db) is not sqlite3.Connection or namespace!=basis.prepared['namespace']:
        raise AuthorityUnavailable('actual selected counter derived-index namespace required')
    basis.require_current(meter=meter)
    database=db.execute('PRAGMA database_list').fetchall()
    if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(basis.member('core')['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('counter index point read crossed actual selected Core')
    row=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',
        ('selection_digest','namespace','counter_operation_id','generation_call_id','header_digest','classification','cutoff_scope_digest'),
        'selection_digest=? AND namespace=? AND counter_operation_id=?',(selection_digest,namespace,counter_operation_id))
    if row is None:return None
    header=meter.read_fixed_row(db,'authority_d13_counter_originals_v1',('payload_cell_id','payload_digest'),
        "namespace=? AND counter_operation_id=? AND phase='header'",(namespace,counter_operation_id))
    if header is None:
        retired=_runtime_bounded_fixed_row_v3(db,meter,TABLE,COLUMNS,
            "namespace=? AND kind='counter' AND item_id=? AND phase='header'",(namespace,counter_operation_id))
        if retired is None:raise AuthorityUnavailable('derived counter index has neither actual header nor signed retirement')
        original=validate_retirement_original_v3(basis.control,json.loads(retired[7]))
        if (original['counter_operation_id']!=row[2] or original['generation_call_id']!=row[3]
                or original['source_payload_digest']!=row[4] or retired[6]!=original['retirement_digest']):
            raise AuthorityUnavailable('bodyless counter retirement and derived index exact identity differ')
        if row[6] is not None:
            member=original['source_member']
            if (original['source_payload_origin_scope_digest']!=row[6] or type(member) is not dict
                    or member.get('table_name')!='authority_d13_counter_originals_v1'
                    or member.get('primary_key')!=[namespace,counter_operation_id,'header']
                    or member.get('descriptor_digest')!=original['source_descriptor_digest']):
                raise AuthorityUnavailable('retired captured counter lacks actual signed Source member/origin cutoff qualification')
        return {'status':'complete','row':row,'classification':'retired_metadata_only','retirement_original':original}
    actual_policy=basis.control.read_selected_installed_d13_policy_v3(namespace,meter=meter)
    if policy is not None and policy is not actual_policy:
        raise AuthorityUnavailable('caller policy cannot replace actual bound selected producer configuration')
    return SelectedRuntimeCounterIndexReadV3(_SELECTED_INDEX_ISSUER_V3,db,basis,row,header,actual_policy)


class SelectedRuntimeCounterCutoffReadV3:
    """Complete immutable cutoff prefix; runtime delta rows are qualified separately."""
    def __init__(self,issuer,basis,cursor,seal):
        if issuer is not _SELECTED_INDEX_ISSUER_V3:
            raise AuthorityUnavailable('actual selected derived cutoff issuer required')
        self.basis,self.cursor,self.seal=basis,cursor,seal
        self.after='';self.count=0;self.reader=None;self.pending=None;self.complete=False
        self.root=canonical_digest(('sylanne3.d13.counter-index-genesis.v3',cursor[0],cursor[1],cursor[2],cursor[3]))
        _SELECTED_INDEX_READS_V3.add(self)

    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self) is not SelectedRuntimeCounterCutoffReadV3 or self not in _SELECTED_INDEX_READS_V3
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual private counter cutoff progress and Root quantum required')
        self.basis.require_current(meter=meter)
        result=copy(self)
        if self.reader is not None:result.reader=self.reader.copy_for_c09_quantum_v3(meter=meter)
        _SELECTED_INDEX_READS_V3.add(result)
        return result

    def advance(self,*,db,meter):
        from pathlib import Path
        if self not in _SELECTED_INDEX_READS_V3 or type(db) is not sqlite3.Connection:
            raise AuthorityUnavailable('actual selected cutoff reader/SQLite required')
        self.basis.require_current(meter=meter)
        database=db.execute('PRAGMA database_list').fetchall()
        if len(database)!=1 or Path(database[0][2]).resolve(strict=True)!=Path(self.basis.member('core')['resolved_path']).resolve(strict=True):
            raise AuthorityUnavailable('counter cutoff continuation crossed actual selected Core')
        actual=meter.read_fixed_row(db,'runtime_d13_counter_index_cursor_v3',
            ('selection_digest','cutoff_scope_digest','storage_instance_id','namespace','last_operation_id',
             'record_count','prefix_root','phase','cursor_revision'),'selection_digest=?',(self.cursor[0],))
        if actual!=self.cursor:raise AuthorityUnavailable('actual counter cutoff cursor changed during prefix proof')
        if self.complete:return {'status':'complete','record_count':self.count,'ordered_root':self.root}
        if self.reader is not None:
            result=self.reader.advance(db=db,meter=meter)
            if result['status']=='complete':
                row=result['row']
                self.root=canonical_digest(('sylanne3.d13.counter-index-link.v3',self.root,self.count,
                    row[2],row[4],row[3],row[5]))
                self.after=row[2];self.count+=1;self.reader=None
            return {'status':'progress'}
        if self.count<self.cursor[5]:
            # Bound the saved prefix by its actual immutable last key. Every row
            # is independently joined to a typed complete header or signed retirement.
            row=db.execute('SELECT counter_operation_id FROM runtime_d13_counter_calls_v3 '
                'WHERE selection_digest=? AND namespace=? AND cutoff_scope_digest=? AND counter_operation_id COLLATE BINARY>? '
                'ORDER BY counter_operation_id COLLATE BINARY LIMIT 1',
                (self.cursor[0],self.cursor[3],self.cursor[1],self.after)).fetchone()
            meter.charge_read(0 if row is None else len(row[0].encode('utf8')))
            if row is None:raise AuthorityUnavailable('actual saved counter cutoff prefix is incomplete')
            reader=read_selected_runtime_counter_index_v3(db,basis=self.basis,selection_digest=self.cursor[0],
                namespace=self.cursor[3],counter_operation_id=row[0],meter=meter)
            if type(reader) is dict:
                from .c09_selected_core_source_v3 import (
                    require_selected_retired_counter_source_v3,VerifiedSelectedRetiredCounterSourceV3)
                original=reader['retirement_original']
                proof=require_selected_retired_counter_source_v3(self.basis,
                    retirement_original=original,meter=meter)
                if (type(proof) is not VerifiedSelectedRetiredCounterSourceV3 or proof.basis is not self.basis
                        or proof.original['retirement_digest']!=original['retirement_digest']):
                    raise AuthorityUnavailable('actual retired counter complete Source member chain required')
                proof.require_current(meter=meter)
                row=reader['row'];self.root=canonical_digest(('sylanne3.d13.counter-index-link.v3',
                    self.root,self.count,row[2],row[4],row[3],row[5]));self.after=row[2];self.count+=1
            else:self.reader=reader
            return {'status':'progress'}
        if self.after!=self.cursor[4] or self.root!=self.cursor[6]:
            raise AuthorityUnavailable('counter cutoff actual prefix count/last key/root differs')
        if self.seal is not None:
            eof=canonical_digest(('sylanne3.d13.counter-index-eof.v3',self.cursor[0],self.cursor[1],
                self.after,self.count,self.root))
            if self.seal!=(self.cursor[0],self.cursor[1],self.cursor[2],self.cursor[3],self.count,self.root,eof):
                raise AuthorityUnavailable('counter cutoff immutable full EOF seal differs')
            extra_index=db.execute('SELECT counter_operation_id FROM runtime_d13_counter_calls_v3 '
                'WHERE selection_digest=? AND namespace=? AND cutoff_scope_digest=? AND counter_operation_id COLLATE BINARY>? LIMIT 1',
                (self.cursor[0],self.cursor[3],self.cursor[1],self.after)).fetchone()
            meter.charge_read(0 if extra_index is None else len(extra_index[0].encode('utf8')))
            if extra_index is not None:raise AuthorityUnavailable('counter cutoff seal omitted an actual immutable captured member')
            extra=db.execute("SELECT counter_operation_id FROM authority_d13_counter_originals_v1 o JOIN segmented_cells_v1 c "
                "ON c.cell_id=o.payload_cell_id WHERE o.namespace=? AND o.phase='header' AND c.origin_scope_digest=? "
                "AND o.counter_operation_id COLLATE BINARY>? LIMIT 1",(self.cursor[3],self.cursor[1],self.after)).fetchone()
            meter.charge_read(0 if extra is None else len(extra[0].encode('utf8')))
            if extra is not None:raise AuthorityUnavailable('counter cutoff claimed EOF before actual captured header EOF')
        elif self.cursor[7]=='sealed':raise AuthorityUnavailable('counter cutoff sealed cursor lacks its actual immutable seal')
        self.complete=True
        return {'status':'complete','record_count':self.count,'ordered_root':self.root}


def begin_selected_runtime_counter_cutoff_read_v3(db,*,basis,selection_digest,meter):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    if type(basis) is not _InstalledSelectedStorageBasisV3:
        raise AuthorityUnavailable('actual private selected counter cutoff basis required')
    cursor=meter.read_fixed_row(db,'runtime_d13_counter_index_cursor_v3',
        ('selection_digest','cutoff_scope_digest','storage_instance_id','namespace','last_operation_id',
         'record_count','prefix_root','phase','cursor_revision'),'selection_digest=?',(selection_digest,))
    seal=meter.read_fixed_row(db,'runtime_d13_counter_index_seals_v3',
        ('selection_digest','cutoff_scope_digest','storage_instance_id','namespace','record_count','ordered_root','eof_digest'),
        'selection_digest=?',(selection_digest,))
    if cursor is None:
        if seal is not None:raise AuthorityUnavailable('counter cutoff seal lacks its actual original cursor')
        return None
    if cursor[0]!=selection_digest or cursor[3]!=basis.prepared['namespace'] or cursor[5]<0 or cursor[8]<0 or cursor[7] not in ('scan','sealed'):
        raise AuthorityUnavailable('counter cutoff actual namespace/progress identity differs')
    return SelectedRuntimeCounterCutoffReadV3(_SELECTED_INDEX_ISSUER_V3,basis,cursor,seal)


_INITIAL_INDEX_ISSUER_V4=object()
_INITIAL_INDEX_READS_V4=__import__('weakref').WeakSet()


def _initial_counter_source_material_v4(db,qualification,selection_digest,meter,view):
    from .c09_source_physical_read_v3 import InitialPhysicalSourceReadQualificationV3
    from ..runtime_storage_v3 import runtime_storage_basis_identity_v4
    if (type(qualification)is not InitialPhysicalSourceReadQualificationV3 or qualification.role!='core'
            or view.qualification is not qualification):
        raise AuthorityUnavailable('actual initial Core physical Source qualification required')
    view.require_current(db=db,meter=meter)
    identity=runtime_storage_basis_identity_v4(view,role='core',meter=meter)
    if (identity.origin_kind!='initial_segmented_v4' or identity.selection_digest!=selection_digest
            or identity.authority_namespace!=qualification.scope.session.scope.authority_namespace):
        raise AuthorityUnavailable('initial Counter Source differs from its actual signed genesis selection')
    cursor,seal=_initial_runtime_counter_prefix_material_v4(db,identity,view.original,meter)
    if _read_initial_runtime_counter_index_v4(db,meter,selection_digest)!=(cursor,seal):
        raise AuthorityUnavailable('initial physical Source lacks its actual immutable zero-history prefix seal')
    return view,identity,cursor,seal


class InitialRuntimeCounterIndexReadV4(SelectedRuntimeCounterIndexReadV3):
    """The shared cell decoder under an actual INTENT Source qualification."""
    def __init__(self,key,qualification,view,row,header_ref,policy):
        if key is not _INITIAL_INDEX_ISSUER_V4:
            raise AuthorityUnavailable('actual initial Counter Source reader issuer required')
        self.qualification,self.view=qualification,view
        self.row,self.header_ref,self.policy=row,header_ref,policy
        self.header=None;self.ordinal=self.offset=0;self.root=None;self.hash=sha256()
        self.encoded=bytearray();self.phase='header';self.frame=None;self.complete=False
        _INITIAL_INDEX_READS_V4.add(self)
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self)is not InitialRuntimeCounterIndexReadV4 or self not in _INITIAL_INDEX_READS_V4
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual initial Counter Source continuation/Root quantum required')
        self.qualification.require_current(meter=meter)
        self.view.control.require_c09_retained_arena_v3(meter=meter,additional_bytes=len(self.encoded)+4096)
        meter.charge_encode(len(self.encoded))
        result=copy(self);result.hash=self.hash.copy();result.encoded=bytearray(self.encoded)
        _INITIAL_INDEX_READS_V4.add(result)
        return result
    def advance(self,*,db,meter):
        if type(self)is not InitialRuntimeCounterIndexReadV4 or self not in _INITIAL_INDEX_READS_V4:
            raise AuthorityUnavailable('actual private initial Counter Source reader required')
        self.view.require_current(db=db,meter=meter)
        view,identity,cursor,seal=_initial_counter_source_material_v4(db,self.qualification,self.row[0],meter,self.view)
        if view.original!=self.view.original or view.db is not self.view.db:
            raise AuthorityUnavailable('initial Counter Source changed its actual genesis/connection')
        row=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',
            ('selection_digest','namespace','counter_operation_id','generation_call_id','header_digest',
                'classification','cutoff_scope_digest'),'selection_digest=? AND namespace=? AND counter_operation_id=?',self.row[:3])
        if row!=self.row or row[6]is not None:
            raise AuthorityUnavailable('initial Counter delta changed its actual immutable locator')
        return _advance_runtime_counter_original_v4(self,db=db,meter=meter,control=self.view.control)


def read_initial_runtime_counter_index_v4(db,*,qualification,selection_digest,namespace,counter_operation_id,meter):
    from .c09_initial_segmented_genesis_v4 import require_initial_segmented_physical_metadata_v4
    view=require_initial_segmented_physical_metadata_v4(qualification,db=db,meter=meter)
    view,identity,cursor,seal=_initial_counter_source_material_v4(db,qualification,selection_digest,meter,view)
    if namespace!=identity.authority_namespace:
        raise AuthorityUnavailable('initial Counter index crossed its actual Source namespace')
    row=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',
        ('selection_digest','namespace','counter_operation_id','generation_call_id','header_digest',
            'classification','cutoff_scope_digest'),'selection_digest=? AND namespace=? AND counter_operation_id=?',
        (selection_digest,namespace,counter_operation_id))
    if row is None:return None
    if row[6]is not None or row[5]not in ('header_only','signed_full_wire'):
        raise AuthorityUnavailable('initial Counter runtime delta cannot claim a captured cutoff')
    header=meter.read_fixed_row(db,'authority_d13_counter_originals_v1',('payload_cell_id','payload_digest'),
        "namespace=? AND counter_operation_id=? AND phase='header'",(namespace,counter_operation_id))
    if header is None:
        raise AuthorityUnavailable('initial Counter delta has no actual header; an independently qualified retirement original is required')
    if header[1]!=row[4]:
        raise AuthorityUnavailable('initial Counter delta differs from its actual immutable header digest')
    policy=view.control.read_selected_installed_d13_policy_v3(namespace,meter=meter)
    return InitialRuntimeCounterIndexReadV4(_INITIAL_INDEX_ISSUER_V4,qualification,view,row,header,policy)


class InitialRuntimeCounterEmptyPrefixReadV4:
    def __init__(self,key,qualification,view,cursor,seal):
        if key is not _INITIAL_INDEX_ISSUER_V4:
            raise AuthorityUnavailable('actual initial zero-history prefix issuer required')
        self.qualification,self.view,self.cursor,self.seal=qualification,view,cursor,seal
        self.root=seal[5];self.complete=False
        _INITIAL_INDEX_READS_V4.add(self)
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
        if (type(self)is not InitialRuntimeCounterEmptyPrefixReadV4 or self not in _INITIAL_INDEX_READS_V4
                or meter is not require_c09_reserved_meter_v3(meter.budget)):
            raise AuthorityUnavailable('actual initial prefix continuation/Root quantum required')
        self.qualification.require_current(meter=meter)
        result=copy(self);_INITIAL_INDEX_READS_V4.add(result)
        return result
    def advance(self,*,db,meter):
        if type(self)is not InitialRuntimeCounterEmptyPrefixReadV4 or self not in _INITIAL_INDEX_READS_V4:
            raise AuthorityUnavailable('actual private initial zero-history prefix required')
        self.view.require_current(db=db,meter=meter)
        view,identity,cursor,seal=_initial_counter_source_material_v4(db,self.qualification,self.cursor[0],meter,self.view)
        if (view.original!=self.view.original or view.db is not self.view.db
                or (cursor,seal)!=(self.cursor,self.seal)or self.root!=seal[5]):
            raise AuthorityUnavailable('initial Counter prefix changed its actual signed zero-history commitment')
        extra=meter.read_fixed_row(db,'runtime_d13_counter_calls_v3',('counter_operation_id',),
            'selection_digest=? AND namespace=? AND cutoff_scope_digest IS NOT NULL',(seal[0],seal[3]))
        if extra is not None:
            raise AuthorityUnavailable('initial Counter delta contains a falsely captured prefix member')
        self.complete=True
        return {'status':'complete','record_count':0,'ordered_root':self.root}


def begin_initial_runtime_counter_empty_prefix_read_v4(db,*,qualification,selection_digest,meter):
    from .c09_initial_segmented_genesis_v4 import require_initial_segmented_physical_metadata_v4
    view=require_initial_segmented_physical_metadata_v4(qualification,db=db,meter=meter)
    view,identity,cursor,seal=_initial_counter_source_material_v4(db,qualification,selection_digest,meter,view)
    return InitialRuntimeCounterEmptyPrefixReadV4(_INITIAL_INDEX_ISSUER_V4,qualification,view,cursor,seal)
