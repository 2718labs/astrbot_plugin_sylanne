"""Shared W01 originals for concrete registered domain production operations."""
from dataclasses import asdict
import json

from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import StagedDomainOperationV1, ProductionOriginalRefV1

TABLE = "graph_domain_production_originals_v1"
SCHEMA = "sylanne.domain-production-original.v1"
DOMAINS = frozenset({"d01", "d02", "d03", "d05", "d06", "d07", "d08", "d10", "d11"})


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


def record_adopted_domain_operation_v1(db, stage, receipt):
    if (not db.in_transaction or type(stage) is not StagedDomainOperationV1
            or type(receipt) is not CommitReceipt or stage.domain not in DOMAINS
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
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("domain adopted original needs the current W01 snapshot")
    row = db.execute(f"SELECT domain,operation_kind,request_digest,original_digest,original_payload_json,"
        f"read_versions_json,bundle_digest,receipt_json,receipt_digest FROM {TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
    if row is None:
        return None
    domain, kind, request, original_digest, encoded, reads_json, digest, receipt_json, receipt_digest = row
    payload, read_rows, raw_receipt = json.loads(encoded), json.loads(reads_json), json.loads(receipt_json)
    receipt = _receipt(raw_receipt)
    reads = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in read_rows)
    if (domain not in DOMAINS or canonical_serialize(payload) != encoded
            or canonical_digest(payload) != original_digest or canonical_serialize(read_rows) != reads_json
            or len(reads) > 1024 or any(NamespaceId.from_key(v.key) != namespace for v in reads)
            or canonical_serialize(raw_receipt) != receipt_json or canonical_digest(receipt) != receipt_digest
            or receipt.operation_id != operation_id or receipt.operation_digest != digest
            or payload.get("namespace") != asdict(namespace)
            or payload.get("identity", {}).get("operation_id") != operation_id):
        raise ValueError("domain adopted original identity or exact bytes differ")
    actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
    if actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
        raise ValueError("domain adopted original lost its actual W01 commit")
    return {"domain": domain, "operation_kind": kind, "request_digest": request,
        "original_digest": original_digest, "payload": payload, "read_versions": reads, "receipt": receipt}
