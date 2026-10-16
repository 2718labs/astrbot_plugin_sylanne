"""D11 transaction-owned deletable derived body, separate from immutable originals/history."""
from dataclasses import dataclass, replace
from ..graph_types import AtomKey,GraphReceipt,GraphVersion
import hashlib
import json

from ..domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2, DerivedTurnExpiryV1, derived_block_metadata_key_v2
from ..domains.d13.provider import _block_from_graph_value, block_graph_value
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .d13_paid_coordinator_v1 import D13PaidStandbyPreparationV1

TABLE = 'graph_d11_derived_cache_payloads_v1'

@dataclass(frozen=True, slots=True)
class DerivedPayloadStageV1:
    metadata: DerivedBlockMetadataV2
    payload_bytes: bytes

@dataclass(frozen=True, slots=True)
class DerivedPayloadReclaimReceiptV1:
    namespace: NamespaceId
    block_ref: str
    payload_digest: str
    rows_deleted: int
    payload_absent: bool
    derived_cache_payload_reclaimed: bool
    scope: str = 'named_derived_store_logical_payload_only'
    schema: str = 'd11.derived-cache-reclaim-receipt.v1'


def install_derived_payload_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, block_ref TEXT NOT NULL,
        payload_digest TEXT NOT NULL, payload_bytes BLOB NOT NULL,
        PRIMARY KEY(bot,persona,block_ref), CHECK(length(payload_bytes) BETWEEN 1 AND 524288))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_derived_activations_v6 (
        bot TEXT NOT NULL,persona TEXT NOT NULL,block_ref TEXT NOT NULL,before_revision INTEGER NOT NULL,
        after_revision INTEGER NOT NULL,before_digest TEXT NOT NULL,after_digest TEXT NOT NULL,
        payload_digest TEXT NOT NULL,operation_id TEXT NOT NULL,receipt_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,block_ref,before_revision))""")
    for action in ('UPDATE','DELETE'):
        db.execute(f"CREATE TRIGGER IF NOT EXISTS graph_d13_derived_activation_no_{action.lower()} BEFORE {action} ON graph_d13_derived_activations_v6 BEGIN SELECT RAISE(ABORT,'derived activation original is immutable'); END")


def prepare_derived_payload_v1(preparation, *, scene_ref):
    """Staging only; W01 must revalidate the actual paid preparation in its transaction."""
    if type(preparation) is not D13PaidStandbyPreparationV1 or preparation.block is None or preparation.reason is not None:
        raise ValueError('derived cache needs the actual successful paid standby preparation')
    block = preparation.block
    if block.status != 'standby' or len(block.turns) > 64:
        raise ValueError('one derived payload is a bounded original standby block')
    payload = canonical_serialize(block_graph_value(block)).encode('utf-8')
    metadata = DerivedBlockMetadataV2(preparation.original.namespace, block.block_ref, block.conversation_ref,
        scene_ref, block.audience_ref, hashlib.sha256(payload).hexdigest(), len(payload), block.source_dependencies,
        tuple(DerivedTurnExpiryV1(turn.sequence, turn.source_ref, turn.trusted_utc + 72*3600) for turn in block.turns),
        block.job_ref, block.candidate_ref, block.compiler_version, preparation.original.binding.original_operation_id,
        preparation.original.original_digest, preparation.evidence_digest, canonical_digest(preparation.settlement),
        min(block.expires_at_utc, preparation.original.binding.expires_at_utc,
            *(turn.trusted_utc+72*3600 for turn in block.turns)), 'standby')
    return DerivedPayloadStageV1(metadata, payload)


def _transaction(db):
    if not db.in_transaction:
        raise ValueError('derived payload changes belong to the caller-owned W01 transaction')


def _require_metadata_head(db, metadata):
    key = derived_block_metadata_key_v2(metadata)
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    handled,row=read_bound_authority_graph_attachment_v3(db,table='graph_atoms',columns=('value','valid'),
        key_columns=('bot','persona','token'),key=(*metadata.namespace.as_tuple,key.token))
    if not handled:
        from ..runtime_storage_v3 import read_graph_row_v3
        row=read_graph_row_v3(db,columns=('value','valid'),where='bot=? AND persona=? AND token=?',
            parameters=(*metadata.namespace.as_tuple,key.token))
    if row != (canonical_serialize(metadata), 1):
        raise ValueError('derived payload requires its exact currently adopted Graph metadata')


def insert_derived_payload_v1(db, stage):
    _transaction(db)
    if type(stage) is not DerivedPayloadStageV1 or type(stage.metadata) is not DerivedBlockMetadataV2:
        raise TypeError('actual bounded derived stage required')
    metadata, payload = stage.metadata, stage.payload_bytes
    _require_metadata_head(db, metadata)
    if (type(payload) is not bytes or len(payload) != metadata.payload_length_bytes
            or hashlib.sha256(payload).hexdigest() != metadata.payload_digest):
        raise ValueError('derived body differs from the metadata commitment')
    block = _block_from_graph_value(json.loads(payload.decode('utf-8')))
    if (block.status != 'standby' or block.block_ref != metadata.block_ref
            or block.source_dependencies != metadata.source_dependencies or metadata.expires_at_utc > block.expires_at_utc):
        raise ValueError('derived payload is not its actual prepared cache member')
    prior = db.execute(f'SELECT payload_digest,payload_bytes FROM {TABLE} WHERE bot=? AND persona=? AND block_ref=?',
        (*metadata.namespace.as_tuple, metadata.block_ref)).fetchone()
    if prior is not None:
        if prior != (metadata.payload_digest, payload):
            raise ValueError('derived block identity was reused for different body bytes')
        return False
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?)',
        (*metadata.namespace.as_tuple, metadata.block_ref, metadata.payload_digest, payload))
    return True


def read_derived_payload_v1(db, metadata, *, now_utc):
    _transaction(db)
    if type(metadata) is not DerivedBlockMetadataV2 or metadata.status == 'retired' or now_utc >= metadata.expires_at_utc:
        raise ValueError('retired or expired derived payload is synchronously unreadable')
    _require_metadata_head(db, metadata)
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is not None:
        if work.namespace!=metadata.namespace:raise ValueError('current derived payload crossed Authority namespace')
        from .installed_d13_natural_frame_v6 import require_authority_derived_blocks_reader_v6
        return require_authority_derived_blocks_reader_v6(work).require_body_v6(metadata)
    row = db.execute(f'SELECT payload_digest,payload_bytes FROM {TABLE} WHERE bot=? AND persona=? AND block_ref=?',
        (*metadata.namespace.as_tuple, metadata.block_ref)).fetchone()
    if (row is None or row[0]!=metadata.payload_digest or len(row[1])!=metadata.payload_length_bytes
            or hashlib.sha256(row[1]).hexdigest()!=metadata.payload_digest):
        raise ValueError('current derived payload is missing or altered; no legacy/cache fallback')
    return _qualify_derived_payload_value_v1(metadata,json.loads(row[1].decode('utf-8')),
        payload_digest=row[0],payload_length=len(row[1]))


def _qualify_derived_payload_value_v1(metadata,raw,*,payload_digest,payload_length):
    if payload_digest!=metadata.payload_digest or payload_length!=metadata.payload_length_bytes:
        raise ValueError('current derived payload is missing or altered; no legacy/cache fallback')
    block = _block_from_graph_value(raw)
    if (block.block_ref != metadata.block_ref or block.status != 'standby'
            or block.source_dependencies != metadata.source_dependencies or metadata.expires_at_utc > block.expires_at_utc
            or tuple(DerivedTurnExpiryV1(turn.sequence, turn.source_ref, turn.trusted_utc+72*3600) for turn in block.turns) != metadata.turn_expiries):
        raise ValueError('derived body identity/source/original expiry differs')
    return replace(block, status=metadata.status)


def reclaim_derived_payload_v1(db, metadata):
    """Only after W01's actual retired metadata CAS, within that same transaction."""
    _transaction(db)
    if type(metadata) is not DerivedBlockMetadataV2 or metadata.status != 'retired':
        raise ValueError('reclamation needs the actual adopted retired metadata')
    _require_metadata_head(db, metadata)
    row = db.execute(f'SELECT payload_digest FROM {TABLE} WHERE bot=? AND persona=? AND block_ref=?',
        (*metadata.namespace.as_tuple, metadata.block_ref)).fetchone()
    if row is not None and row[0] != metadata.payload_digest:
        raise ValueError('retirement selector differs from the stored derived body')
    cursor = db.execute(f'DELETE FROM {TABLE} WHERE bot=? AND persona=? AND block_ref=? AND payload_digest=?',
        (*metadata.namespace.as_tuple, metadata.block_ref, metadata.payload_digest))
    absent = db.execute(f'SELECT 1 FROM {TABLE} WHERE bot=? AND persona=? AND block_ref=?',
        (*metadata.namespace.as_tuple, metadata.block_ref)).fetchone() is None
    return DerivedPayloadReclaimReceiptV1(metadata.namespace, metadata.block_ref, metadata.payload_digest,
        cursor.rowcount, absent, absent)


def record_derived_activations_v6(db,pair,*,graph_receipt,operation_id):
    """W01's actual receipt hook, after the exact same-payload standby-to-active CAS."""
    _transaction(db)
    if type(graph_receipt) is not GraphReceipt or graph_receipt.status!='committed':
        raise ValueError('derived activation must bind the actual committed W01 receipt')
    for item in pair.projected_blocks:
        if item.metadata.status!='standby':
            continue
        key=AtomKey.from_token(item.ref.ref)
        target=replace(item.metadata,status='active')
        if GraphVersion(key,item.ref.version+1) not in graph_receipt.revisions:
            raise ValueError('derived activation is absent from this actual W01 receipt')
        _require_metadata_head(db,target)
        history=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
            (key.token,item.ref.version+1)).fetchone()
        if history!=(canonical_serialize(target),1,operation_id):
            raise ValueError('derived activation event is another actual operation')
        previous=db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
            (key.token,item.ref.version)).fetchone()
        if previous!=(canonical_serialize(item.metadata),1):
            raise ValueError('derived activation before member differs from its paid standby')
        values=(*item.metadata.namespace.as_tuple,item.metadata.block_ref,item.ref.version,item.ref.version+1,
            canonical_digest(item.metadata),canonical_digest(target),item.metadata.payload_digest,operation_id,canonical_digest(graph_receipt))
        prior=db.execute('SELECT before_revision,after_revision,before_digest,after_digest,payload_digest,operation_id,receipt_digest '
            'FROM graph_d13_derived_activations_v6 WHERE bot=? AND persona=? AND block_ref=? AND before_revision=?',
            (*item.metadata.namespace.as_tuple,item.metadata.block_ref,item.ref.version)).fetchone()
        if prior is not None:
            if prior!=values[3:]:
                raise ValueError('derived activation original changed')
        else:
            db.execute('INSERT INTO graph_d13_derived_activations_v6 VALUES(?,?,?,?,?,?,?,?,?,?)',values)


def require_actual_derived_metadata_activation_v6(db,before,before_ref,after,after_ref):
    """Bind an exact historical metadata revision to its one actual W01 activation."""
    _transaction(db)
    if (type(before) is not DerivedBlockMetadataV2 or type(after) is not DerivedBlockMetadataV2
            or type(before_ref) is not VersionedRef or type(after_ref) is not VersionedRef
            or before.status!='standby' or after!=replace(before,status='active')
            or after_ref.version!=before_ref.version+1 or after_ref.ref!=before_ref.ref):
        raise ValueError('current derived metadata differs beyond one actual activation')
    row=db.execute('SELECT after_revision,before_digest,after_digest,payload_digest,operation_id,receipt_digest '
        'FROM graph_d13_derived_activations_v6 WHERE bot=? AND persona=? AND block_ref=? AND before_revision=?',
        (*before.namespace.as_tuple,before.block_ref,before_ref.version)).fetchone()
    if row is None or row[:4]!=(after_ref.version,canonical_digest(before),canonical_digest(after),before.payload_digest):
        raise ValueError('derived activation has no actual immutable W01 before/after receipt')
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    handled,history=read_bound_authority_graph_attachment_v3(db,table='graph_history',columns=('value','valid','event_id'),
        key_columns=('token','revision'),key=(after_ref.ref,after_ref.version))
    if not handled:
        history=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
            (after_ref.ref,after_ref.version)).fetchone()
    if history!=(canonical_serialize(after),1,row[4]):
        raise ValueError('derived activation history changed')
    _require_metadata_head(db,after)


def require_actual_derived_activation_v6(db,original,current):
    if (current.block!=replace(original.block,status='active')
            or current.compression_plan!=original.compression_plan):
        raise ValueError('current derived paid payload/plan changed at activation')
    require_actual_derived_metadata_activation_v6(db,original.metadata,original.ref,current.metadata,current.ref)
