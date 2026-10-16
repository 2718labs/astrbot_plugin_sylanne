"""Immutable, typed D12 domain compiler originals in W01's graph database."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from ..domains.d12.scheme_command import D12DomainCompileReceiptV1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d12_domain_scheme_compile_v1 import (
    AUTHORED_ROOT_FIELD, D12ActivityRecipeCandidateV1, D12AffectSchemeCandidateV1,
    D12AuthoredRootSelectionCandidateV1,
    D12AttentionPolicyCandidateV1, D12BodyProfileCandidateV1,
    D12ContextSchemeCandidateV1, D12PersonaPlanCandidateV1,
    D12RelationshipSchemeCandidateV1,
    D12ActionSchemasCandidateV1, D12EncodingProjectionPolicyCandidateV1,
    D12ExpressionPolicyCandidateV1,
    compile_d12_domain_scheme_candidate_v1,
)


_CANDIDATES = (
    D12ActivityRecipeCandidateV1, D12BodyProfileCandidateV1,
    D12ContextSchemeCandidateV1, D12PersonaPlanCandidateV1,
    D12RelationshipSchemeCandidateV1, D12AffectSchemeCandidateV1,
    D12ActionSchemasCandidateV1, D12EncodingProjectionPolicyCandidateV1,
    D12AttentionPolicyCandidateV1,
    D12ExpressionPolicyCandidateV1, D12AuthoredRootSelectionCandidateV1,
)


def install_d12_compiled_candidate_store_v1(db: sqlite3.Connection) -> None:
    if not db.in_transaction:
        raise RuntimeError("W01 graph transaction required")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_domain_candidates_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, candidate_ref TEXT NOT NULL,
        domain TEXT NOT NULL, field_input_digest TEXT NOT NULL,
        proposal_schema_hash TEXT NOT NULL, candidate_digest TEXT NOT NULL,
        candidate_json TEXT NOT NULL, candidate_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,candidate_ref))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_domain_candidate_no_update_v1
        BEFORE UPDATE ON graph_d12_domain_candidates_v1
        BEGIN SELECT RAISE(ABORT, 'D12 candidate original is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_domain_candidate_no_delete_v1
        BEFORE DELETE ON graph_d12_domain_candidates_v1
        BEGIN SELECT RAISE(ABORT, 'D12 candidate original is immutable'); END""")


def record_d12_domain_candidate_v1(
        db: sqlite3.Connection, namespace: NamespaceId, candidate,
) -> D12DomainCompileReceiptV1:
    """Record one compiler result; its ref names this exact durable row."""
    if not db.in_transaction or type(candidate) not in _CANDIDATES:
        raise ValueError("typed D12 candidate requires W01 graph transaction")
    if (candidate.status != "typed_candidate_not_persisted"
            or getattr(candidate, "namespace", namespace) != namespace):
        raise ValueError("candidate namespace or status differs")
    encoded = canonical_serialize(candidate)
    ref = "d12-domain-candidate:" + candidate.candidate_digest
    row = (candidate.domain, candidate.field_input_digest,
           candidate.proposal_schema_hash, candidate.candidate_digest, encoded,
           hashlib.sha256(encoded.encode("utf-8")).hexdigest())
    identity = (*namespace.as_tuple, ref)
    previous = db.execute(
        "SELECT domain,field_input_digest,proposal_schema_hash,candidate_digest,"
        "candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 "
        "WHERE bot=? AND persona=? AND candidate_ref=?", identity,
    ).fetchone()
    if previous is not None and previous != row:
        raise ValueError("D12 candidate original changed")
    if previous is None:
        db.execute(
            "INSERT INTO graph_d12_domain_candidates_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            (*identity, *row),
        )
    return D12DomainCompileReceiptV1(
        candidate.domain, candidate.field_names, candidate.field_input_digest,
        ref, candidate.proposal_schema_hash,
    )


def verify_d12_domain_candidate_v1(
        db: sqlite3.Connection, namespace: NamespaceId, candidate,
        receipt: D12DomainCompileReceiptV1,
) -> bool:
    """Recheck a candidate against its persisted bytes, not a caller ref."""
    if not db.in_transaction or type(candidate) not in _CANDIDATES:
        raise ValueError("typed D12 candidate requires W01 graph transaction")
    expected = D12DomainCompileReceiptV1(
        candidate.domain, candidate.field_names, candidate.field_input_digest,
        "d12-domain-candidate:" + candidate.candidate_digest,
        candidate.proposal_schema_hash,
    )
    if receipt != expected:
        return False
    encoded = canonical_serialize(candidate)
    from .domain_background_read_v3 import background_point_v3
    row=background_point_v3(db,table='graph_d12_domain_candidates_v1',columns=('domain','field_input_digest','proposal_schema_hash','candidate_digest','candidate_json','candidate_sha256'),
        key_columns=('bot','persona','candidate_ref'),key=(*namespace.as_tuple,receipt.candidate_ref),
        legacy_reader=lambda:db.execute('SELECT domain,field_input_digest,proposal_schema_hash,candidate_digest,candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 WHERE bot=? AND persona=? AND candidate_ref=?',(*namespace.as_tuple,receipt.candidate_ref)).fetchone())
    return row == (
        candidate.domain, candidate.field_input_digest,
        candidate.proposal_schema_hash, candidate.candidate_digest, encoded,
        hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    )


def read_current_compiled_authored_root_selection_v1(
        db: sqlite3.Connection, namespace: NamespaceId,
        draft_digest: str, field_input_digest: str,
) -> D12AuthoredRootSelectionCandidateV1:
    """Replay a persisted D12 V3 root selection inside W01's graph transaction.

    The caller must additionally bind the candidate ref to the current active
    scheme's compilation original and compare its field with the current draft.
    """
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(draft_digest) is not str or len(draft_digest) != 64
            or type(field_input_digest) is not str or len(field_input_digest) != 64):
        raise ValueError("current D12 root selection requires graph transaction and digests")
    rows = db.execute(
        "SELECT candidate_ref,proposal_schema_hash,candidate_digest,"
        "candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 "
        "WHERE bot=? AND persona=? AND domain='d04' AND field_input_digest=?",
        (*namespace.as_tuple, field_input_digest),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("unique compiled D04 authored root selection is unavailable")
    ref, proposal_hash, candidate_digest, encoded, encoded_sha = rows[0]
    if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != encoded_sha:
        raise ValueError("compiled D04 authored root original bytes changed")
    try:
        raw = json.loads(encoded)
        expected_type = D12AuthoredRootSelectionCandidateV1.__module__ + "." + D12AuthoredRootSelectionCandidateV1.__qualname__
        if (type(raw) is not dict or raw.get("$type") != expected_type
                or set(raw) != set(D12AuthoredRootSelectionCandidateV1.__dataclass_fields__) | {"$type"}):
            raise ValueError("compiled D04 root candidate fields differ")
        value = json.loads(raw["field_value_json"])
        fields = ((AUTHORED_ROOT_FIELD, value, raw["field_source"]),)
        if (raw["namespace"] != {"$type": NamespaceId.__module__ + "." + NamespaceId.__qualname__,
                                 "bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
                or raw["draft_digest"] != draft_digest
                or canonical_digest((draft_digest, "d04", fields)) != field_input_digest):
            raise ValueError("compiled D04 root draft binding differs")
        candidate = compile_d12_domain_scheme_candidate_v1(
            namespace=namespace, draft_digest=draft_digest, domain="d04",
            fields=fields, field_input_digest=field_input_digest,
        )
        if (type(candidate) is not D12AuthoredRootSelectionCandidateV1
                or candidate.candidate_digest != candidate_digest
                or ref != "d12-domain-candidate:" + candidate_digest
                or candidate.proposal_schema_hash != proposal_hash
                or canonical_serialize(candidate) != encoded):
            raise ValueError("compiled D04 authored root replay differs")
        return candidate
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("compiled D04 authored root selection is invalid") from exc
