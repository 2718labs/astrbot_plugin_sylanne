"""Append-only contact originals in the installed Graph business database."""
import json
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1

TABLE = "graph_contact_model_originals_v1"
SIGN_KIND = "d10.contact-model-original.v1"
KINDS = frozenset({"plan", "prepared", "accounting_prepared", "prepare_commit", "request", "call", "read_attempt", "result", "terminal", "paid_cost", "stage_attempt", "stage_permit", "stage_receipt"})
DDL = f"""CREATE TABLE {TABLE} (
    bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
    original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))"""
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'contact model original is immutable'); END" for action in ("UPDATE", "DELETE"))


def install_contact_original_schema_v1(db):
    db.execute(DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    for ddl in TRIGGERS:
        db.execute(ddl.replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1))


def record_contact_original_v1(db, issuer, namespace, kind, ref, payload):
    if not db.in_transaction or kind not in KINDS:
        raise ValueError("contact original requires its actual W01 transaction and closed kind")
    wire = canonical_serialize(plain_v1(payload))
    from .c09_contact_originals_v1 import validate_contact_payload_v1
    validate_contact_payload_v1(kind, json.loads(wire))
    digest = canonical_digest(json.loads(wire))
    previous = read_contact_original_v1(db, issuer, namespace, kind, ref)
    if previous is not None:
        if previous != (json.loads(wire), digest):
            raise ValueError("contact original cannot be replaced by a retry")
        return digest
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, wire, digest, signature))
    return digest


def read_contact_original_v1(db, issuer, namespace, kind, ref):
    if kind not in KINDS:
        raise ValueError("unregistered contact original kind")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return None
    row = db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} "
        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if canonical_serialize(raw) != row[0] or canonical_digest(raw) != row[1]:
        raise ValueError("contact original canonical bytes differ")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[1])), row[2])
    from .c09_contact_originals_v1 import validate_contact_payload_v1
    validate_contact_payload_v1(kind, raw)
    return raw, row[1]


def require_contact_original_v1(db, issuer, namespace, kind, ref):
    value = read_contact_original_v1(db, issuer, namespace, kind, ref)
    if value is None:
        raise ValueError("actual contact original absent: " + kind)
    return value
