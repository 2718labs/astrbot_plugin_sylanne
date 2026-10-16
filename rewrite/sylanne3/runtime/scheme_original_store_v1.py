"""D12 immutable originals on W01's graph SQLite transaction.

W01 authenticates the current Owner lease and graph fence before calling this
module. Recording and reading here never grants adoption or advances a head.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3
from uuid import UUID

from ..domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, D12IsolatedPreviewV1,
    D12PreviewCertificateV1, compiled_scheme_digest_v1,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .scheme_port_v1 import (
    install_scheme_originals_schema_v1, record_compilation_original_v1,
    record_preview_original_v1,
)


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class CompilationOriginalV1:
    operation_id: str
    compiled: D12CompiledSchemeV1
    source_input_digest: str
    budget_receipt_digest: str


@dataclass(frozen=True, slots=True)
class PreviewOriginalV1:
    operation_id: str
    certificate: D12PreviewCertificateV1
    isolated_result: D12IsolatedPreviewV1
    source_input_digest: str
    budget_receipt_digest: str
    isolation_result_digest: str


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("W01 must hold BEGIN IMMEDIATE graph transaction")


def _operation(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("operation_id must be canonical UUID4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("operation_id must be canonical UUID4")
    return value


def _digest(value: str, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def install_scheme_original_store_v1(db: sqlite3.Connection) -> None:
    """Install in W01's existing graph database, inside its migration transaction."""
    _transaction(db)
    install_scheme_originals_schema_v1(db)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_compilation_operations_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        compiled_digest TEXT NOT NULL, source_input_digest TEXT NOT NULL,
        budget_receipt_digest TEXT NOT NULL, binding_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        FOREIGN KEY(bot,persona,compiled_digest)
          REFERENCES graph_d12_compilation_originals_v1(bot,persona,compiled_digest))""")
    db.execute("""CREATE INDEX IF NOT EXISTS graph_d12_compilation_op_digest_v1
        ON graph_d12_compilation_operations_v1(bot,persona,compiled_digest)""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_preview_operations_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        preview_seal TEXT NOT NULL, compiled_digest TEXT NOT NULL,
        source_input_digest TEXT NOT NULL, budget_receipt_digest TEXT NOT NULL,
        isolation_result_digest TEXT NOT NULL, binding_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        FOREIGN KEY(bot,persona,preview_seal)
          REFERENCES graph_d12_preview_originals_v1(bot,persona,preview_seal))""")
    db.execute("""CREATE INDEX IF NOT EXISTS graph_d12_preview_op_seal_v1
        ON graph_d12_preview_operations_v1(bot,persona,preview_seal)""")


def _compilation_binding(original: CompilationOriginalV1) -> str:
    return canonical_digest((
        original.operation_id, original.compiled.namespace,
        original.compiled.compiled_digest, original.source_input_digest,
        original.budget_receipt_digest, canonical_serialize(original.compiled),
    ))


def _preview_binding(original: PreviewOriginalV1) -> str:
    return canonical_digest((
        original.operation_id, original.certificate.compiled_digest,
        original.certificate.issuer_seal, original.source_input_digest,
        original.budget_receipt_digest, original.isolation_result_digest,
        canonical_serialize(original.certificate),
        canonical_serialize(original.isolated_result),
    ))


def record_compilation_original_for_operation_v1(
        db: sqlite3.Connection, original: CompilationOriginalV1) -> None:
    """Persist one trusted compilation; same operation is idempotent exactly."""
    _transaction(db)
    if type(original) is not CompilationOriginalV1:
        raise TypeError("typed compilation original is required")
    _operation(original.operation_id)
    _digest(original.source_input_digest, "source_input_digest")
    _digest(original.budget_receipt_digest, "budget_receipt_digest")
    compiled = original.compiled
    if (type(compiled) is not D12CompiledSchemeV1
            or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest):
        raise ValueError("compiled original basis differs")
    binding = _compilation_binding(original)
    identity = (*compiled.namespace.as_tuple, original.operation_id)
    row = db.execute(
        "SELECT compiled_digest,source_input_digest,budget_receipt_digest,binding_digest "
        "FROM graph_d12_compilation_operations_v1 WHERE bot=? AND persona=? AND operation_id=?",
        identity,
    ).fetchone()
    expected = (compiled.compiled_digest, original.source_input_digest,
                original.budget_receipt_digest, binding)
    if row is not None and row != expected:
        raise ValueError("compilation operation changed its immutable original")
    record_compilation_original_v1(db, compiled)
    if row is None:
        db.execute("INSERT INTO graph_d12_compilation_operations_v1 VALUES (?,?,?,?,?,?,?)",
                   (*identity, *expected))


def record_preview_original_for_operation_v1(
        db: sqlite3.Connection, compiled: D12CompiledSchemeV1,
        original: PreviewOriginalV1) -> None:
    """Persist isolated result and certificate, bound to one operation."""
    _transaction(db)
    if type(original) is not PreviewOriginalV1:
        raise TypeError("typed preview original is required")
    _operation(original.operation_id)
    _digest(original.source_input_digest, "source_input_digest")
    _digest(original.budget_receipt_digest, "budget_receipt_digest")
    _digest(original.isolation_result_digest, "isolation_result_digest")
    if original.isolation_result_digest != canonical_digest(original.isolated_result):
        raise ValueError("isolation result digest differs")
    if (type(compiled) is not D12CompiledSchemeV1
            or original.certificate.compiled_digest != compiled.compiled_digest):
        raise ValueError("preview compilation differs")
    identity = (*compiled.namespace.as_tuple, original.operation_id)
    binding = _preview_binding(original)
    expected = (original.certificate.issuer_seal, compiled.compiled_digest,
                original.source_input_digest, original.budget_receipt_digest,
                original.isolation_result_digest, binding)
    row = db.execute(
        "SELECT preview_seal,compiled_digest,source_input_digest,budget_receipt_digest,"
        "isolation_result_digest,binding_digest FROM graph_d12_preview_operations_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?", identity,
    ).fetchone()
    if row is not None and row != expected:
        raise ValueError("preview operation changed its immutable original")
    record_preview_original_v1(db, compiled, original.isolated_result,
                               original.certificate)
    if row is None:
        db.execute("INSERT INTO graph_d12_preview_operations_v1 VALUES (?,?,?,?,?,?,?,?,?)",
                   (*identity, *expected))


def _namespace(value: dict) -> NamespaceId:
    if type(value) is not dict or set(value) != {"$type", "bot_id", "persona_id"}:
        raise ValueError("original namespace shape differs")
    if value["$type"] != "sylanne3.runtime_contracts.NamespaceId":
        raise ValueError("original namespace type differs")
    return NamespaceId(value["bot_id"], value["persona_id"])


def _compiled(encoded: str) -> D12CompiledSchemeV1:
    value = json.loads(encoded)
    receipts = tuple(D12DomainCompileReceiptV1(
        item["domain"], tuple(item["field_names"]), item["field_input_digest"],
        item["candidate_ref"], item["proposal_schema_hash"], item["status"])
        for item in value["domain_receipts"])
    compiled = D12CompiledSchemeV1(
        _namespace(value["namespace"]), value["draft_ref"],
        value["draft_revision"], value["draft_digest"],
        value["active_head_ref"], value["active_head_revision"],
        value["graph_revision"], value["access_epoch"], value["delete_epoch"],
        receipts, value["compiled_digest"], value["issuer_seal"], value["status"])
    if (canonical_serialize(compiled) != encoded
            or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest):
        raise ValueError("compilation original bytes differ")
    return compiled


def _preview(encoded: str, result_encoded: str) -> tuple[D12PreviewCertificateV1, D12IsolatedPreviewV1]:
    value, source = json.loads(encoded), json.loads(result_encoded)
    certificate = D12PreviewCertificateV1(
        value["compiled_digest"], _namespace(value["sandbox_namespace"]),
        value["actual_cost_receipt_ref"], value["issuer_seal"], value["status"])
    result = D12IsolatedPreviewV1(
        source["compiled_digest"], _namespace(source["sandbox_namespace"]),
        source["source_snapshot_digest"], source["production_revision_before"],
        source["production_revision_after"], tuple(source["external_effect_refs"]),
        tuple(source["formal_contribution_refs"]),
        tuple(source["production_write_refs"]),
        source["actual_cost_receipt_ref"], source["status"])
    if (canonical_serialize(certificate) != encoded
            or canonical_serialize(result) != result_encoded):
        raise ValueError("preview original bytes differ")
    return certificate, result


def read_compilation_original_for_operation_v1(
        db: sqlite3.Connection, namespace: NamespaceId, *,
        compiled_digest: str) -> CompilationOriginalV1 | None:
    """Exact read for W01's authenticated original callback."""
    from ..authority_service.named_joint_binding_body_v1 import named_joint_compilation_original_v1
    named,value=named_joint_compilation_original_v1(db,namespace,compiled_digest)
    if named:return value
    from .frozen_joint_command_source_v3 import read_frozen_joint_compilation_v3
    frozen,value=read_frozen_joint_compilation_v3(db,namespace,compiled_digest)
    if frozen:return value
    _transaction(db)
    _digest(compiled_digest, "compiled_digest")
    row = db.execute(
        "SELECT o.operation_id,o.source_input_digest,o.budget_receipt_digest,o.binding_digest,"
        "c.original_json,c.original_sha256 FROM graph_d12_compilation_operations_v1 o "
        "JOIN graph_d12_compilation_originals_v1 c ON c.bot=o.bot AND c.persona=o.persona "
        "AND c.compiled_digest=o.compiled_digest WHERE o.bot=? AND o.persona=? "
        "AND o.compiled_digest=? ORDER BY o.operation_id LIMIT 1",
        (*namespace.as_tuple, compiled_digest),
    ).fetchone()
    if row is None:
        return None
    operation, input_digest, budget_digest, binding, encoded, raw_sha = row
    if _sha(encoded) != raw_sha:
        raise ValueError("compilation original was changed")
    original = CompilationOriginalV1(operation, _compiled(encoded), input_digest, budget_digest)
    if (original.compiled.namespace != namespace
            or _compilation_binding(original) != binding):
        raise ValueError("compilation operation binding was changed")
    return original


def read_preview_original_for_operation_v1(
        db: sqlite3.Connection, namespace: NamespaceId, *,
        preview_seal: str) -> PreviewOriginalV1 | None:
    """Exact preview read; W01 still validates current Owner and graph heads."""
    _transaction(db)
    if type(preview_seal) is not str or not preview_seal:
        raise ValueError("preview seal is required")
    row = db.execute(
        "SELECT o.operation_id,o.source_input_digest,o.budget_receipt_digest,"
        "o.isolation_result_digest,o.binding_digest,p.compiled_digest,"
        "p.certificate_json,p.result_json,p.original_sha256 "
        "FROM graph_d12_preview_operations_v1 o JOIN graph_d12_preview_originals_v1 p "
        "ON p.bot=o.bot AND p.persona=o.persona AND p.preview_seal=o.preview_seal "
        "WHERE o.bot=? AND o.persona=? AND o.preview_seal=? "
        "ORDER BY o.operation_id LIMIT 1",
        (*namespace.as_tuple, preview_seal),
    ).fetchone()
    if row is None:
        return None
    operation, input_digest, budget_digest, isolation_digest, binding, compiled_digest, cert_json, result_json, raw_sha = row
    if _sha(cert_json + "\n" + result_json) != raw_sha:
        raise ValueError("preview original was changed")
    certificate, result = _preview(cert_json, result_json)
    original = PreviewOriginalV1(operation, certificate, result, input_digest,
                                 budget_digest, isolation_digest)
    if (certificate.issuer_seal != preview_seal
            or certificate.compiled_digest != compiled_digest
            or certificate.sandbox_namespace == namespace
            or certificate.sandbox_namespace != result.sandbox_namespace
            or certificate.actual_cost_receipt_ref != result.actual_cost_receipt_ref
            or isolation_digest != canonical_digest(result)
            or _preview_binding(original) != binding):
        raise ValueError("preview operation binding was changed")
    return original


__all__ = (
    "CompilationOriginalV1", "PreviewOriginalV1",
    "install_scheme_original_store_v1",
    "record_compilation_original_for_operation_v1",
    "record_preview_original_for_operation_v1",
    "read_compilation_original_for_operation_v1",
    "read_preview_original_for_operation_v1",
)
