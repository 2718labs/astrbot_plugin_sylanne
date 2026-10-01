"""Fixed canonical source-note generation and durable readback postcondition."""
import hashlib
import json

from ..runtime_contracts import canonical_serialize
from ..memory_types import SourceRecord
from ..domains.d01.production_operations_v1 import plain_v1
from .d11_life_contract_v1 import ARTIFACT_SCHEMA, RECIPE_ID, POSTCONDITION_ID

STAGE_TABLE = "graph_d11_life_artifact_stage_v1"
STAGE_DDL = "CREATE TABLE graph_d11_life_artifact_stage_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,execution_id TEXT NOT NULL,binding_digest TEXT NOT NULL,artifact_ref TEXT NOT NULL,artifact_bytes BLOB NOT NULL,artifact_digest TEXT NOT NULL,artifact_length INTEGER NOT NULL,adopted_operation_id TEXT,PRIMARY KEY(bot,persona,execution_id),UNIQUE(bot,persona,artifact_ref))"


def artifact_value_v1(prepared):
    b, plan = prepared.binding, prepared.plan
    source = json.loads(prepared.source_record_json)
    SourceRecord.from_dict(source)
    if len(source["text"].encode("utf-8")) > 65536 or len(prepared.source_record_json.encode("utf-8")) > 131072:
        raise ValueError("source-note input exceeds the fixed complete-input bound")
    return {"schema": ARTIFACT_SCHEMA, "recipe_id": RECIPE_ID, "recipe_version": 1,
        "activity_id": b.activity_id, "effect_id": b.effect_id, "attempt_id": b.attempt_id,
        "source_ref": plan.input_source.ref, "source_revision": plan.input_source.revision,
        "source_digest": plan.input_source.digest, "source_record": source}


def generate_source_note_bytes_v1(prepared):
    data = canonical_serialize(artifact_value_v1(prepared)).encode("utf-8")
    if len(data) > 262144:
        raise ValueError("source-note complete artifact exceeds installed bound")
    return data


def install_life_artifact_stage_schema_v1(db):
    if db.in_transaction:
        raise ValueError("Life stage schema installation precedes business transactions")
    db.execute(STAGE_DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))


def write_life_artifact_stage_v1(db, prepared, data):
    if not db.in_transaction or type(data) is not bytes:
        raise ValueError("Life stage needs actual SQLite write transaction and produced bytes")
    expected_data = generate_source_note_bytes_v1(prepared)
    if data != expected_data:
        raise ValueError("Life executor produced another fixed artifact")
    b = prepared.binding
    expected = (b.digest, b.artifact_ref, data, hashlib.sha256(data).hexdigest(), len(data))
    old = db.execute("SELECT binding_digest,artifact_ref,artifact_bytes,artifact_digest,artifact_length FROM " + STAGE_TABLE +
        " WHERE bot=? AND persona=? AND execution_id=?", (*b.namespace.as_tuple, b.execution_id)).fetchone()
    if old is not None:
        if old != expected:
            raise ValueError("Life stage identity cannot overwrite an earlier produced artifact")
    else:
        db.execute("INSERT INTO " + STAGE_TABLE + " VALUES(?,?,?,?,?,?,?,?,NULL)", (*b.namespace.as_tuple, b.execution_id, *expected))
    return expected[3], expected[4]


def verify_durable_life_artifact_v1(db, prepared, *, digest=None, length=None):
    if not db.in_transaction:
        raise ValueError("Life postcondition requires a new pinned durable read")
    b = prepared.binding
    row = db.execute("SELECT binding_digest,artifact_ref,artifact_bytes,artifact_digest,artifact_length FROM " + STAGE_TABLE +
        " WHERE bot=? AND persona=? AND execution_id=?", (*b.namespace.as_tuple, b.execution_id)).fetchone()
    if row is None or row[:2] != (b.digest, b.artifact_ref):
        raise ValueError("Life durable artifact stage is absent or crossed binding")
    data = row[2]
    if (type(data) is not bytes or not 1 <= len(data) <= 262144 or row[3:] != (hashlib.sha256(data).hexdigest(), len(data))
            or digest is not None and row[3] != digest or length is not None and row[4] != length):
        raise ValueError("Life durable artifact length/hash differs")
    value = json.loads(data)
    if canonical_serialize(value).encode("utf-8") != data or value != artifact_value_v1(prepared):
        raise ValueError("Life fixed postcondition rejects changed canonical source facts")
    return data, row[3], row[4]


def mark_life_artifact_adopted_v1(db, binding, operation_id):
    row = db.execute("SELECT adopted_operation_id FROM " + STAGE_TABLE + " WHERE bot=? AND persona=? AND execution_id=? AND binding_digest=?",
        (*binding.namespace.as_tuple, binding.execution_id, binding.digest)).fetchone()
    if row is None or row[0] not in {None, operation_id}:
        raise ValueError("Life stage adoption identity differs")
    db.execute("UPDATE " + STAGE_TABLE + " SET adopted_operation_id=? WHERE bot=? AND persona=? AND execution_id=? AND binding_digest=?",
        (operation_id, *binding.namespace.as_tuple, binding.execution_id, binding.digest))
