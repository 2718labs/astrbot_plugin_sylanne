"""Immutable W01 product requests for resuming the original C04 operation.

The envelope is the actual prepare request, including its original deadlines.
This store authenticates neither Owner nor execution: callers must use W01's
current fenced transaction and the independently recorded prepared binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..runtime_contracts import CommandEnvelope, NamespaceId, canonical_digest, canonical_serialize
from .c02_bundle_codec import _decode
from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1, read_c04_internal_work_prepared_v1


class C04ProductOriginalHold(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class C04ProductRequestOriginalV3:
    envelope: CommandEnvelope
    prepared_digest: str
    binding_digest: str
    request_digest: str

    @property
    def original_digest(self) -> str:
        return canonical_digest(self)


def install_c04_product_original_v3(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise C04ProductOriginalHold("provision product requests outside transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_c04_product_requests_v3 (
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            envelope_json TEXT NOT NULL, prepared_digest TEXT NOT NULL,
            binding_digest TEXT NOT NULL, request_digest TEXT NOT NULL,
            original_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
                REFERENCES graph_c04_internal_work_prepared_v1(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_c04_product_requests_no_update_v3
            BEFORE UPDATE ON graph_c04_product_requests_v3
            BEGIN SELECT RAISE(ABORT, 'C04 product request is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_c04_product_requests_no_delete_v3
            BEFORE DELETE ON graph_c04_product_requests_v3
            BEGIN SELECT RAISE(ABORT, 'C04 product request is immutable'); END;
    """)


def read_c04_product_request_v3(db: sqlite3.Connection, namespace: NamespaceId,
                              operation_id: str) -> C04ProductRequestOriginalV3 | None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise C04ProductOriginalHold("W01 original read transaction required")
    row = db.execute("SELECT envelope_json,prepared_digest,binding_digest,request_digest,"
                     "original_digest FROM graph_c04_product_requests_v3 "
                     "WHERE bot=? AND persona=? AND operation_id=?",
                     (*namespace.as_tuple, operation_id)).fetchone()
    if row is None:
        return None
    envelope = _decode(json.loads(row[0]), CommandEnvelope)
    original = C04ProductRequestOriginalV3(envelope, *row[1:4])
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if (canonical_serialize(envelope) != row[0]
            or original.original_digest != row[4]
            or envelope.authority.namespace != namespace
            or envelope.identity.operation_id != operation_id
            or prepared is None or prepared.prepared_digest != original.prepared_digest
            or prepared.binding.binding_digest != original.binding_digest
            or (envelope.identity.activity_id, envelope.parent_budget_lease_ref,
                envelope.authority.activation_generation) !=
               (prepared.binding.activity_id, prepared.binding.parent_budget_lease_ref,
                prepared.binding.activation_generation)):
        raise C04ProductOriginalHold("immutable C04 product request differs from preparation")
    return original


def record_c04_product_request_v3(db: sqlite3.Connection, *, envelope: CommandEnvelope,
                                 prepared: C04InternalWorkPreparedV1,
                                 request_digest: str) -> C04ProductRequestOriginalV3:
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(envelope) is not CommandEnvelope
            or type(prepared) is not C04InternalWorkPreparedV1
            or type(request_digest) is not str or len(request_digest) != 64
            or any(char not in "0123456789abcdef" for char in request_digest)):
        raise C04ProductOriginalHold("typed W01 prepare originals required")
    namespace, operation = envelope.authority.namespace, envelope.identity.operation_id
    adopted = read_c04_internal_work_prepared_v1(db, namespace, operation)
    if adopted != prepared or envelope.version_guard.resource_lease_versions:
        raise C04ProductOriginalHold("record the exact pre-quote envelope after prepare CAS")
    original = C04ProductRequestOriginalV3(envelope, prepared.prepared_digest,
                                         prepared.binding.binding_digest, request_digest)
    prior = read_c04_product_request_v3(db, namespace, operation)
    if prior is not None:
        if prior != original:
            raise C04ProductOriginalHold("same operation changed C04 product request")
        return prior
    db.execute("INSERT INTO graph_c04_product_requests_v3 VALUES(?,?,?,?,?,?,?,?)",
               (*namespace.as_tuple, operation, canonical_serialize(envelope),
                original.prepared_digest, original.binding_digest,
                request_digest, original.original_digest))
    return read_c04_product_request_v3(db, namespace, operation)


__all__ = ["C04ProductOriginalHold", "C04ProductRequestOriginalV3",
           "install_c04_product_original_v3", "read_c04_product_request_v3",
           "record_c04_product_request_v3"]
