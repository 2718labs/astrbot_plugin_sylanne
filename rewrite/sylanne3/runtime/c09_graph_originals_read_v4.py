"""Cold Graph originals used by C09 recovery and by a switched generation.

The caller owns the installed, frozen SQLite connection.  No caller supplied
Graph fact is accepted here: facts are reconstructed from durable graph rows.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict

from ..graph_types import AtomKey, GraphReceipt, GraphVersion, NamespaceEpoch
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1
from .c09_erasure_plan_original_v1 import read_c09_erasure_plan_original_v1
from .c09_storage_rebase_contract_v1 import (
    GraphErasureRebaseCertificateV1, SanitizedGraphFactV4, SanitizedGraphReadV1,
)


def read_current_graph_originals_v4(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> tuple[SanitizedGraphFactV4, ...]:
    """Read every committed event of a frozen namespace, including C09.

    A missing plan, barrier, event, or an unresolved output row without an
    event makes this read incomplete.  The Authority service must compare its
    current accepted head independently before consuming the result.
    """
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(operation_id) is not str or not operation_id):
        raise ValueError("frozen Graph transaction and C09 identity required")
    plan = read_c09_erasure_plan_original_v1(db, namespace, operation_id)
    barrier = read_c09_erasure_barrier_v1(db, namespace, operation_id)
    if (plan is None or barrier is None
            or plan.operation_id != barrier.operation_id
            or plan.graph_incarnation != barrier.graph_incarnation
            or plan.source_ref not in barrier.affected_source_refs):
        raise ValueError("C09 Graph plan/barrier original differs")
    rows = db.execute(
        "SELECT session,event_id,digest,reads,epoch_reads,revisions,"
        "invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? "
        "ORDER BY event_id,session", namespace.as_tuple,
    ).fetchall()
    if not rows:
        raise ValueError("Graph event originals are absent")
    by_operation = {}
    for session, event_id, digest, reads, epoch_reads, revisions, invalidated, epoch in rows:
        try:
            written = tuple(GraphVersion(AtomKey.from_token(token), revision)
                            for token, revision in json.loads(revisions))
            invalid = tuple(GraphVersion(AtomKey.from_token(token), revision)
                            for token, revision in json.loads(invalidated))
            for payload in (reads, epoch_reads):
                json.loads(payload)
            receipt = GraphReceipt("committed", written, invalid,
                                   NamespaceEpoch(*namespace.as_tuple, epoch))
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError(f"Graph event original unreadable: {event_id}") from exc
        if event_id == operation_id and (
                session != barrier.event_session or digest != barrier.graph_event_digest
                or epoch != barrier.graph_epoch_after
                or canonical_digest(receipt) != barrier.graph_receipt_digest):
            raise ValueError("C09 event differs from immutable barrier")
        obligations = []
        for table in ("graph_bundle_outbox", "graph_outbox_jobs"):
            columns = tuple(item[1] for item in db.execute(f"PRAGMA table_info({table})"))
            if "operation_id" not in columns:
                raise ValueError(f"Graph obligation table unavailable: {table}")
            obligations.extend((table, tuple(row)) for row in db.execute(
                f"SELECT * FROM {table} WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, event_id),
            ))
        fact = SanitizedGraphFactV4(
            event_id, canonical_digest(receipt),
            canonical_digest((digest, reads, epoch_reads, revisions, invalidated)),
            canonical_digest(tuple(obligations)) if obligations else None,
        )
        by_operation.setdefault(event_id, []).append((session, fact))
    facts = []
    for event_id, parts in by_operation.items():
        if len(parts) == 1:
            # Preserve all previously issued single-event fact bytes exactly.
            facts.append(parts[0][1])
            continue
        if len(parts) != 2 or {session for session, _ in parts} != {"d12.scheme_adoption.v1", "d04.authored_root.v3"}:
            raise ValueError("Graph operation has ambiguous event originals")
        from .d04_appraisal_driver_v3 import read_d04_original_v3
        from .c09_d04_originals_v3 import validate_d04_original_payload_v3
        original = read_d04_original_v3(db, namespace, "root_execution_link", event_id)
        if original is None:
            raise ValueError("compound root operation lacks its actual execution link")
        link = validate_d04_original_payload_v3("root_execution_link", original[0])
        receipts = {session: fact.receipt_commitment for session, fact in parts}
        if (link["operation_id"] != event_id or link["head_receipt_digest"] != receipts["d12.scheme_adoption.v1"]
                or link["root_receipt_digest"] != receipts["d04.authored_root.v3"]):
            raise ValueError("compound root operation actual receipt commitments differ")
        ordered = tuple(sorted(parts, key=lambda item: item[0]))
        facts.append(SanitizedGraphFactV4(event_id,
            canonical_digest(tuple((session, fact.receipt_commitment) for session, fact in ordered)),
            canonical_digest(tuple((session, fact.write_set_commitment) for session, fact in ordered)),
            canonical_digest(tuple((session, fact.unresolved_obligation_commitment) for session, fact in ordered))
                if any(fact.unresolved_obligation_commitment is not None for _, fact in ordered) else None))
    ids = [item.operation_id for item in facts]
    if len(ids) != len(set(ids)) or operation_id not in ids:
        raise ValueError("Graph operation is missing or has ambiguous event originals")
    durable_ids = set()
    for table in ("graph_bundle_operations", "graph_bundle_outbox",
                  "graph_outbox_jobs"):
        durable_ids.update(row[0] for row in db.execute(
            f"SELECT DISTINCT operation_id FROM {table} "
            "WHERE bot=? AND persona=?", namespace.as_tuple))
    if durable_ids - set(ids):
        raise ValueError("Graph operation or outbox lacks committed event original")
    return tuple(sorted(facts, key=lambda item: item.operation_id))


def read_graph_rebase_certificate_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> GraphErasureRebaseCertificateV1 | None:
    """Read the certificate mirrored into the switched Graph generation."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("frozen switched Graph transaction required")
    row = db.execute("SELECT certificate_json FROM graph_c09_rebase_certificates_v1 "
                     "WHERE bot=? AND persona=? AND operation_id=?",
                     (*namespace.as_tuple, operation_id)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if type(raw) is not dict:
        raise ValueError("Graph rebase certificate malformed")
    from .c09_storage_rebase_contract_v1 import (
        GraphRowDispositionV1, GraphTableDispositionManifestV1,
    )
    raw["table_manifests"] = tuple(GraphTableDispositionManifestV1(
        item["table_name"], tuple(GraphRowDispositionV1(**entry)
                                  for entry in item["rows"]),
        item["manifest_digest"], item["schema"])
        for item in raw["table_manifests"])
    for key in ("prior_erased_key_digests", "newly_erased_key_digests",
                "cumulative_erased_key_digests"):
        raw[key] = tuple(raw[key])
    raw["component_hashes"] = tuple(tuple(item) for item in raw["component_hashes"])
    certificate = GraphErasureRebaseCertificateV1(**raw)
    recovery = db.execute(
        "SELECT requirements_json FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if recovery is None:
        raise ValueError("Graph recovery identity is absent")
    authority_namespace = json.loads(recovery[0])["authority_namespace"]
    if (certificate.namespace != authority_namespace
            or certificate.operation_id != operation_id
            or canonical_serialize(asdict(certificate)) != row[0]):
        raise ValueError("Graph rebase certificate bytes or identity differ")
    return certificate


def read_sanitized_graph_atom_v1(
    db: sqlite3.Connection, namespace: NamespaceId, key: AtomKey,
) -> SanitizedGraphReadV1:
    """Return an explicit erased result for every cumulative tombstone."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(key) is not AtomKey or NamespaceId.from_key(key) != namespace):
        raise ValueError("frozen same-namespace Graph read required")
    key_digest = canonical_digest(key.token)
    erased = db.execute(
        "SELECT operation_id FROM graph_c09_erased_keys_v1 "
        "WHERE bot=? AND persona=? AND key_digest=?",
        (*namespace.as_tuple, key_digest),
    ).fetchone()
    if erased is not None:
        certificate = read_graph_rebase_certificate_v1(
            db, namespace, erased[0])
        if certificate is None or key_digest not in certificate.cumulative_erased_key_digests:
            raise ValueError("Graph erased key lacks certified transition")
        return SanitizedGraphReadV1(
            key_digest, "erased", None, certificate.certificate_digest)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? "
                     "AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone()
    if row is None:
        raise KeyError("Graph original is absent")
    try:
        value = json.loads(row[1])
    except (TypeError, ValueError) as exc:
        raise ValueError("Graph original value is unreadable") from exc
    if type(value) is dict and value.get("schema") == "sylanne3.graph.erased_value.v1":
        raise ValueError("Graph erased marker lacks tombstone")
    return SanitizedGraphReadV1(
        key_digest, "original", canonical_digest((key.token, *row)), None)


__all__ = ["read_current_graph_originals_v4", "read_graph_rebase_certificate_v1",
           "read_sanitized_graph_atom_v1"]
