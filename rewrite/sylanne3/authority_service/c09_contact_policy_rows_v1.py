"""Closed C09 inventory of the installed Owner contact policy originals."""
from dataclasses import asdict
import hashlib
import hmac
import json

from .contract import AuthorityUnavailable
from .d10_contact_policy_service_v1 import TABLE, DDL, TRIGGERS, contact_policy_original_from_wire_v1
from ..runtime_contracts import canonical_serialize

COLUMNS = ("authority_namespace", "installation_id", "policy_id", "policy_version",
           "operation_id", "action", "payload_json", "payload_digest", "signature")


def require_contact_policy_schema_v1(db):
    if (db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() != (DDL,)
            or any(db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone() != (sql,)
                   for name, sql in TRIGGERS)):
        raise AuthorityUnavailable("C09 contact policy immutable installed schema differs")


def validate_contact_policy_core_row_v1(columns, row):
    if tuple(columns) != COLUMNS:
        raise AuthorityUnavailable("C09 contact policy original columns differ")
    original = contact_policy_original_from_wire_v1(json.loads(row[6]))
    if row != (original.authority_namespace, original.installation_id, original.policy.policy_id,
            original.policy.version, original.operation_id, original.action,
            canonical_serialize(original), original.digest, original.signature):
        raise AuthorityUnavailable("C09 contact policy original row differs")
    return original


def verify_contact_policy_source_in_tx_v1(db, *, config, control, namespace):
    actual = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if actual is None:
        return
    require_contact_policy_schema_v1(db)
    installation = (config.natural_model_authorities_v2 or {}).get(namespace)
    if actual != (DDL,) or installation is None or installation.installation_bundle is None:
        raise AuthorityUnavailable("C09 installed contact policy verifier absent")
    key = hmac.new(installation.installation_bundle.d11_signing_key,
        b"sylanne.authority.d10-contact-policy-signing.v1", hashlib.sha256).digest()
    for row in db.execute("SELECT * FROM " + TABLE):
        original = validate_contact_policy_core_row_v1(COLUMNS, row)
        material = asdict(original); material.pop("signature")
        expected = hmac.new(key, canonical_serialize(material).encode("utf-8"), hashlib.sha256).hexdigest()
        if (original.authority_namespace != namespace or original.authority_id != control.authority_id
                or original.installation_id != control.installation_id
                or not hmac.compare_digest(original.signature, expected)):
            raise AuthorityUnavailable("C09 contact policy installed signature differs")
