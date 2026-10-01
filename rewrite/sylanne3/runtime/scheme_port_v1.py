"""Immutable D12 issuer originals and read-only adoption transaction fence.

W01 alone calls the record functions from its trusted issuer path. These SQL
helpers confer no creator Authority and never advance the active head.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from typing import Any
from uuid import UUID

from ..domains.d12.scheme_command import (
    D12CompiledSchemeV1,
    D12IsolatedPreviewV1,
    D12PreviewCertificateV1,
    D12SchemeAdoptionIntentV1,
    compiled_scheme_digest_v1,
)
from ..domains.d12.types import (
    ActiveSchemeHeadV1,
    CharacterDraft,
    active_scheme_head_key,
    character_draft_key,
)
from ..graph_types import GraphVersion, NamespaceEpoch
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


@dataclass(frozen=True, slots=True)
class D12SchemeAdoptionPreflightV1:
    namespace: NamespaceId
    status: str
    hold_reason: str
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    draft_digest: str | None
    active_head_digest: str | None
    read_versions: tuple[GraphVersion, ...]
    query_epoch: NamespaceEpoch
    writes: tuple[()] = ()


@dataclass(frozen=True, slots=True)
class D12SchemeAdoptionCandidateV1:
    namespace: NamespaceId
    operation_id: str
    compiled_digest: str
    previous_head: ActiveSchemeHeadV1
    compiled: D12CompiledSchemeV1
    preview: D12PreviewCertificateV1
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    read_versions: tuple[GraphVersion, ...]
    query_epoch: NamespaceEpoch


def _require_transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("caller must hold BEGIN IMMEDIATE transaction")


def install_scheme_originals_schema_v1(db: sqlite3.Connection) -> None:
    """W01 schema hook; caller owns installation transaction."""
    _require_transaction(db)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_compilation_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, compiled_digest TEXT NOT NULL,
        original_json TEXT NOT NULL, original_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,compiled_digest))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_preview_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, preview_seal TEXT NOT NULL,
        compiled_digest TEXT NOT NULL, certificate_json TEXT NOT NULL,
        result_json TEXT NOT NULL, original_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,preview_seal),
        FOREIGN KEY(bot,persona,compiled_digest)
            REFERENCES graph_d12_compilation_originals_v1(bot,persona,compiled_digest))""")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def record_compilation_original_v1(db: sqlite3.Connection,
                                   compiled: D12CompiledSchemeV1) -> None:
    """W01 only: persist a trusted compiler result once, without replacement."""
    _require_transaction(db)
    if (type(compiled) is not D12CompiledSchemeV1
            or type(compiled.namespace) is not NamespaceId
            or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest
            or compiled.draft_ref != character_draft_key(compiled.namespace).token
            or compiled.active_head_ref != active_scheme_head_key(compiled.namespace).token
            or not compiled.issuer_seal):
        raise ValueError("invalid compilation original")
    encoded = canonical_serialize(compiled)
    identity = (*compiled.namespace.as_tuple, compiled.compiled_digest)
    row = db.execute("SELECT original_json,original_sha256 FROM graph_d12_compilation_originals_v1 "
                     "WHERE bot=? AND persona=? AND compiled_digest=?", identity).fetchone()
    if row is not None:
        if row != (encoded, _sha(encoded)):
            raise ValueError("compilation original identity conflict")
        return
    db.execute("INSERT INTO graph_d12_compilation_originals_v1 VALUES (?,?,?,?,?)",
               (*identity, encoded, _sha(encoded)))


def record_preview_original_v1(db: sqlite3.Connection,
                               compiled: D12CompiledSchemeV1,
                               result: D12IsolatedPreviewV1,
                               certificate: D12PreviewCertificateV1) -> None:
    """W01 only: persist its trusted isolated run and D12 certificate once."""
    _require_transaction(db)
    if (type(result) is not D12IsolatedPreviewV1
            or type(certificate) is not D12PreviewCertificateV1
            or result.status != "isolated_preview_only"
            or certificate.status != "preview_candidate_no_adoption_authority"
            or certificate.compiled_digest != compiled.compiled_digest
            or result.compiled_digest != compiled.compiled_digest
            or certificate.sandbox_namespace != result.sandbox_namespace
            or certificate.actual_cost_receipt_ref != result.actual_cost_receipt_ref
            or result.sandbox_namespace == compiled.namespace
            or result.source_snapshot_digest != compiled.draft_digest
            or result.production_revision_before != compiled.graph_revision
            or result.production_revision_after != compiled.graph_revision
            or result.external_effect_refs or result.formal_contribution_refs
            or result.production_write_refs or not certificate.issuer_seal
            or not result.actual_cost_receipt_ref):
        raise ValueError("invalid preview original")
    comp_json = canonical_serialize(compiled)
    comp_row = db.execute(
        "SELECT original_json,original_sha256 FROM graph_d12_compilation_originals_v1 "
        "WHERE bot=? AND persona=? AND compiled_digest=?",
        (*compiled.namespace.as_tuple, compiled.compiled_digest),
    ).fetchone()
    if comp_row != (comp_json, _sha(comp_json)):
        raise ValueError("trusted compilation original is absent or changed")
    cert_json, result_json = canonical_serialize(certificate), canonical_serialize(result)
    original_sha = _sha(cert_json + "\n" + result_json)
    identity = (*compiled.namespace.as_tuple, certificate.issuer_seal)
    row = db.execute(
        "SELECT compiled_digest,certificate_json,result_json,original_sha256 "
        "FROM graph_d12_preview_originals_v1 WHERE bot=? AND persona=? AND preview_seal=?",
        identity,
    ).fetchone()
    expected = (compiled.compiled_digest, cert_json, result_json, original_sha)
    if row is not None:
        if row != expected:
            raise ValueError("preview original identity conflict")
        return
    db.execute("INSERT INTO graph_d12_preview_originals_v1 VALUES (?,?,?,?,?,?,?)",
               (*identity, *expected))


def _exact_nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative exact integer")
    return value


def _candidate_matches(compiled: D12CompiledSchemeV1,
                       intent: D12SchemeAdoptionIntentV1,
                       namespace: NamespaceId) -> None:
    if (type(compiled) is not D12CompiledSchemeV1
            or type(intent) is not D12SchemeAdoptionIntentV1
            or compiled.namespace != namespace or intent.namespace != namespace
            or compiled_scheme_digest_v1(compiled) != compiled.compiled_digest):
        raise ValueError("D12 compiled/adoption candidate is malformed")
    try:
        operation = UUID(intent.operation_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("adoption operation must be canonical UUID4") from exc
    if operation.version != 4 or str(operation) != intent.operation_id:
        raise ValueError("adoption operation must be canonical UUID4")
    if (intent.compiled_digest != compiled.compiled_digest
            or intent.expected_draft_ref != compiled.draft_ref
            or intent.expected_draft_revision != compiled.draft_revision
            or intent.expected_active_head_ref != compiled.active_head_ref
            or intent.expected_active_head_revision != compiled.active_head_revision
            or intent.expected_graph_revision != compiled.graph_revision
            or intent.expected_access_epoch != compiled.access_epoch
            or intent.expected_delete_epoch != compiled.delete_epoch
            or not intent.preview_seal or not intent.issuer_seal):
        raise ValueError("D12 adoption intent does not match its compiled basis")


def _read_current_value(db: sqlite3.Connection, key, value_type: type
                        ) -> tuple[int, Any] | None:
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (key.token,),
    ).fetchone()
    if row is None:
        return None
    revision, encoded, valid = row
    if type(revision) is not int or revision < 1 or valid != 1:
        raise ValueError("current D12 scheme graph atom is invalid")
    try:
        value = json.loads(encoded)
        if (type(value) is not dict or value.pop("schema", None) != key.type_name):
            raise ValueError("D12 graph atom schema differs")
        decoded = value_type(**value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("current D12 scheme graph atom is malformed") from exc
    return revision, decoded


def read_current_scheme_adoption_candidate_v1(
        db: sqlite3.Connection, namespace: NamespaceId,
        compiled: D12CompiledSchemeV1,
        intent: D12SchemeAdoptionIntentV1, *,
        expected_graph_epoch: int,
        expected_access_epoch: int,
        expected_delete_epoch: int,
) -> D12SchemeAdoptionPreflightV1 | D12SchemeAdoptionCandidateV1:
    """Read issuer originals and current heads inside W01's adoption transaction.

    A candidate is evidence for W01's owner/lease/CAS decision, never a write
    permit. Only W01's trusted issuer path may have recorded the originals.
    """
    _require_transaction(db)
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace is required")
    graph_expected = _exact_nonnegative(expected_graph_epoch, "expected_graph_epoch")
    access_expected = _exact_nonnegative(expected_access_epoch, "expected_access_epoch")
    delete_expected = _exact_nonnegative(expected_delete_epoch, "expected_delete_epoch")
    _candidate_matches(compiled, intent, namespace)

    draft_key = character_draft_key(namespace)
    head_key = active_scheme_head_key(namespace)
    draft_row = _read_current_value(db, draft_key, CharacterDraft)
    head_row = _read_current_value(db, head_key, ActiveSchemeHeadV1)
    graph_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    access_row = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    graph_epoch = graph_row[0] if graph_row is not None else 0
    access_epoch, delete_epoch = access_row if access_row is not None else (0, 0)
    _exact_nonnegative(graph_epoch, "current graph epoch")
    _exact_nonnegative(access_epoch, "current access epoch")
    _exact_nonnegative(delete_epoch, "current delete epoch")

    draft_revision = draft_row[0] if draft_row is not None else 0
    head_revision = head_row[0] if head_row is not None else 0
    versions = tuple(sorted((
        GraphVersion(draft_key, draft_revision),
        GraphVersion(head_key, head_revision),
    ), key=lambda item: item.key.token))
    draft_digest = canonical_digest(draft_row[1]) if draft_row is not None else None
    head_digest = canonical_digest(head_row[1]) if head_row is not None else None
    query_epoch = NamespaceEpoch(namespace.bot_id, namespace.persona_id, graph_epoch)

    stale = (
        graph_epoch != graph_expected
        or access_epoch != access_expected
        or delete_epoch != delete_expected
        or draft_row is None or head_row is None
        or draft_revision != compiled.draft_revision
        or draft_digest != compiled.draft_digest
        or head_revision != compiled.active_head_revision
        or compiled.draft_ref != draft_key.token
        or compiled.active_head_ref != head_key.token
        or graph_epoch != compiled.graph_revision
        or access_epoch != compiled.access_epoch
        or delete_epoch != compiled.delete_epoch
    )
    if stale:
        return D12SchemeAdoptionPreflightV1(
            namespace, "hold_stale_scheme_read_set", "current_scheme_read_set_changed",
            graph_epoch, access_epoch, delete_epoch, draft_digest, head_digest,
            versions, query_epoch,
        )
    try:
        comp_row = db.execute(
            "SELECT original_json,original_sha256 FROM graph_d12_compilation_originals_v1 "
            "WHERE bot=? AND persona=? AND compiled_digest=?",
            (*namespace.as_tuple, compiled.compiled_digest),
        ).fetchone()
        preview_row = db.execute(
            "SELECT compiled_digest,certificate_json,result_json,original_sha256 "
            "FROM graph_d12_preview_originals_v1 "
            "WHERE bot=? AND persona=? AND preview_seal=?",
            (*namespace.as_tuple, intent.preview_seal),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise
        comp_row = preview_row = None
    if comp_row is None or preview_row is None:
        return D12SchemeAdoptionPreflightV1(
            namespace, "hold_missing_durable_scheme_original",
            "compiled_and_preview_original_rows_unavailable",
            graph_epoch, access_epoch, delete_epoch, draft_digest, head_digest,
            versions, query_epoch,
        )
    comp_json = canonical_serialize(compiled)
    preview_digest, cert_json, result_json, original_sha = preview_row
    if (comp_row != (comp_json, _sha(comp_json))
            or preview_digest != compiled.compiled_digest
            or original_sha != _sha(cert_json + "\n" + result_json)):
        return D12SchemeAdoptionPreflightV1(
            namespace, "hold_tampered_scheme_original", "issuer_original_changed",
            graph_epoch, access_epoch, delete_epoch, draft_digest, head_digest,
            versions, query_epoch,
        )
    try:
        cert = json.loads(cert_json)
        result = json.loads(result_json)
        sandbox = cert["sandbox_namespace"]
        preview = D12PreviewCertificateV1(
            cert["compiled_digest"],
            NamespaceId(sandbox["bot_id"], sandbox["persona_id"]),
            cert["actual_cost_receipt_ref"], cert["issuer_seal"], cert["status"],
        )
        isolated = D12IsolatedPreviewV1(
            result["compiled_digest"],
            NamespaceId(result["sandbox_namespace"]["bot_id"],
                        result["sandbox_namespace"]["persona_id"]),
            result["source_snapshot_digest"],
            result["production_revision_before"],
            result["production_revision_after"],
            tuple(result["external_effect_refs"]),
            tuple(result["formal_contribution_refs"]),
            tuple(result["production_write_refs"]),
            result["actual_cost_receipt_ref"], result["status"],
        )
        valid_preview = (
            canonical_serialize(preview) == cert_json
            and canonical_serialize(isolated) == result_json
            and preview.issuer_seal == intent.preview_seal
            and preview.compiled_digest == compiled.compiled_digest
            and preview.status == "preview_candidate_no_adoption_authority"
            and result["compiled_digest"] == compiled.compiled_digest
            and result["sandbox_namespace"] == sandbox
            and result["source_snapshot_digest"] == compiled.draft_digest
            and result["production_revision_before"] == compiled.graph_revision
            and result["production_revision_after"] == compiled.graph_revision
            and result["actual_cost_receipt_ref"] == preview.actual_cost_receipt_ref
            and result["status"] == "isolated_preview_only"
            and not result["external_effect_refs"]
            and not result["formal_contribution_refs"]
            and not result["production_write_refs"]
            and sandbox != json.loads(canonical_serialize(namespace))
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        valid_preview = False
    if not valid_preview:
        return D12SchemeAdoptionPreflightV1(
            namespace, "hold_tampered_scheme_original", "issuer_original_changed",
            graph_epoch, access_epoch, delete_epoch, draft_digest, head_digest,
            versions, query_epoch,
        )
    return D12SchemeAdoptionCandidateV1(
        namespace, intent.operation_id, compiled.compiled_digest, head_row[1],
        compiled, preview, graph_epoch, access_epoch, delete_epoch,
        versions, query_epoch,
    )


__all__ = (
    "D12SchemeAdoptionPreflightV1",
    "D12SchemeAdoptionCandidateV1",
    "install_scheme_originals_schema_v1",
    "record_compilation_original_v1",
    "record_preview_original_v1",
    "read_current_scheme_adoption_candidate_v1",
)
