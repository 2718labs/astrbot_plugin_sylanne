"""Append-only contact originals in the installed Graph business database."""
from .contact_original_read_v3 import contact_original_point_v3
import json
import sqlite3
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1

TABLE = "graph_contact_model_originals_v2"
SIGN_KIND = "d10.contact-model-original.v2"
KINDS = frozenset({"prepared", "accounting_prepared", "prepare_commit", "request", "call", "read_attempt", "result", "terminal", "paid_cost", "stage_attempt", "stage_permit", "stage_receipt"})
DDL = f"""CREATE TABLE {TABLE} (
    bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
    original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))"""
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'contact model original is immutable'); END" for action in ("UPDATE", "DELETE"))


def install_contact_original_schema_v2(db):
    db.execute(DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    for ddl in TRIGGERS:
        db.execute(ddl.replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1))
    require_contact_original_schema_v2(db)


def require_contact_original_schema_v2(db):
    """Authenticate the installed DDL on every original read/write boundary."""
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for ddl in TRIGGERS:
            expected.execute(ddl)
        query = 'SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(query, (TABLE,))) != tuple(expected.execute(query, (TABLE,))):
            raise ValueError('Contact V2 original exact columns/PK/index/immutable triggers differ')
    return True


def record_contact_original_v2(db, issuer, namespace, kind, ref, payload):
    if not db.in_transaction or kind not in KINDS:
        raise ValueError("contact original requires its actual W01 transaction and closed kind")
    require_contact_original_schema_v2(db)
    wire = canonical_serialize(plain_v1(payload))
    from .c09_contact_originals_v2 import validate_contact_payload_v2
    validate_contact_payload_v2(kind, json.loads(wire))
    digest = canonical_digest(json.loads(wire))
    previous = read_contact_original_v2(db, issuer, namespace, kind, ref)
    if previous is not None:
        if previous != (json.loads(wire), digest):
            raise ValueError("contact original cannot be replaced by a retry")
        return digest
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, wire, digest, signature))
    return digest


def read_contact_original_v2(db, issuer, namespace, kind, ref):
    if kind not in KINDS:
        raise ValueError("unregistered contact original kind")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return None
    require_contact_original_schema_v2(db)
    row = contact_original_point_v3(db,table='graph_contact_model_originals_v2',columns=('payload_json', 'payload_digest', 'signature'),key_columns=('bot', 'persona', 'kind', 'original_ref'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],_contact_values[3]))((*namespace.as_tuple, kind, ref)),legacy_reader=lambda: db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} "
        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone())
    if row is None:
        return None
    raw = json.loads(row[0])
    if canonical_serialize(raw) != row[0] or canonical_digest(raw) != row[1]:
        raise ValueError("contact original canonical bytes differ")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[1])), row[2])
    from .c09_contact_originals_v2 import validate_contact_payload_v2
    validate_contact_payload_v2(kind, raw)
    return raw, row[1]


def require_contact_original_v2(db, issuer, namespace, kind, ref):
    value = read_contact_original_v2(db, issuer, namespace, kind, ref)
    if value is None:
        raise ValueError("actual contact original absent: " + kind)
    return value
