"""Restricted D12 adoption evidence reader for W01's existing graph transaction.

W01 must hold its signed Owner write fence and BEGIN IMMEDIATE before calling.
The callbacks must read current source/asset inputs and schema from trusted
server state in that same transaction. This helper never writes a graph atom.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
from typing import Callable

from ..domains.d12.scheme_command import D12SchemeAdoptionIntentV1
from ..runtime_contracts import AuthorityContext, NamespaceId
from .scheme_original_store_v1 import (
    read_compilation_original_for_operation_v1,
    read_preview_original_for_operation_v1,
)
from .scheme_port_v1 import (
    D12SchemeAdoptionCandidateV1, D12SchemeAdoptionPreflightV1,
    read_current_scheme_adoption_candidate_v1,
)


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class CurrentSchemeInputsV1:
    """W01's current, trusted inputs; both input digests include asset identity.

    W01 recomputes these using the same canonical input rules used when the
    operation originals were recorded. The separate asset digest makes an
    absent asset snapshot explicit; it is not a substitute for that binding.
    """

    compilation_source_input_digest: str
    preview_source_input_digest: str
    asset_snapshot_digest: str
    proposal_schema_hashes: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class SchemeAdoptionHoldV1:
    code: str
    detail: str
    status: str = "hold"


def read_current_scheme_adoption_for_w01_v1(
        db: sqlite3.Connection, authority: AuthorityContext, lease: object,
        intent: D12SchemeAdoptionIntentV1, *,
        authorize_owner: Callable[[AuthorityContext, object], bool] | None,
        read_current_inputs: Callable[[AuthorityContext], CurrentSchemeInputsV1] | None,
) -> D12SchemeAdoptionCandidateV1 | SchemeAdoptionHoldV1:
    """Return a CAS candidate only after all current and durable checks pass.

    The caller owns transaction/fence lifetime and must commit through W01's
    normal graph coordinator. Neither a callback nor this candidate is a
    standalone permission to advance the active head.
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("W01 must hold BEGIN IMMEDIATE graph transaction")
    if (type(authority) is not AuthorityContext
            or authority.issuer_domain != "d12"
            or "persona" not in authority.owner_scope
            or type(intent) is not D12SchemeAdoptionIntentV1
            or intent.namespace != authority.namespace):
        return SchemeAdoptionHoldV1("authority_or_intent_invalid", "D12 Owner scope differs")
    if not callable(authorize_owner) or not callable(read_current_inputs):
        return SchemeAdoptionHoldV1("trusted_current_checks_missing", "Owner or input reader absent")
    try:
        if authorize_owner(authority, lease) is not True:
            return SchemeAdoptionHoldV1("owner_lease_not_current", "current Owner lease denied")
        inputs = read_current_inputs(authority)
    except (PermissionError, LookupError, ValueError, sqlite3.Error):
        return SchemeAdoptionHoldV1("trusted_current_checks_failed", "Owner or input read failed")
    if (type(inputs) is not CurrentSchemeInputsV1
            or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                   for value in (inputs.compilation_source_input_digest,
                                 inputs.preview_source_input_digest,
                                 inputs.asset_snapshot_digest))
            or type(inputs.proposal_schema_hashes) is not tuple
            or not inputs.proposal_schema_hashes
            or any(type(item) is not tuple or len(item) != 2
                   or type(item[0]) is not str or not item[0]
                   or type(item[1]) is not str or _DIGEST.fullmatch(item[1]) is None
                   for item in inputs.proposal_schema_hashes)):
        return SchemeAdoptionHoldV1("current_source_asset_schema_missing", "current input proof incomplete")
    namespace: NamespaceId = authority.namespace
    try:
        compilation = read_compilation_original_for_operation_v1(
            db, namespace, compiled_digest=intent.compiled_digest)
        preview = read_preview_original_for_operation_v1(
            db, namespace, preview_seal=intent.preview_seal)
    except (ValueError, sqlite3.Error):
        return SchemeAdoptionHoldV1("scheme_original_invalid", "durable original could not be verified")
    if compilation is None or preview is None:
        return SchemeAdoptionHoldV1("scheme_original_missing", "operation originals absent")
    compiled = compilation.compiled
    if (preview.certificate.compiled_digest != compiled.compiled_digest
            or compilation.source_input_digest != inputs.compilation_source_input_digest
            or preview.source_input_digest != inputs.preview_source_input_digest):
        return SchemeAdoptionHoldV1("current_source_asset_changed", "current input binding differs")
    expected_schema = tuple(sorted((receipt.domain, receipt.proposal_schema_hash)
                                   for receipt in compiled.domain_receipts))
    if (len(set(domain for domain, _ in inputs.proposal_schema_hashes))
            != len(inputs.proposal_schema_hashes)
            or tuple(sorted(inputs.proposal_schema_hashes)) != expected_schema):
        return SchemeAdoptionHoldV1("current_schema_changed", "domain proposal schema differs")
    try:
        candidate = read_current_scheme_adoption_candidate_v1(
            db, namespace, compiled, intent,
            expected_graph_epoch=intent.expected_graph_revision,
            expected_access_epoch=intent.expected_access_epoch,
            expected_delete_epoch=intent.expected_delete_epoch,
        )
    except (ValueError, sqlite3.Error):
        return SchemeAdoptionHoldV1("scheme_candidate_invalid", "current graph candidate invalid")
    if type(candidate) is D12SchemeAdoptionPreflightV1:
        return SchemeAdoptionHoldV1(candidate.status, candidate.hold_reason)
    if (type(candidate) is not D12SchemeAdoptionCandidateV1
            or candidate.preview != preview.certificate):
        return SchemeAdoptionHoldV1("scheme_candidate_invalid", "preview candidate differs")
    return candidate


__all__ = (
    "CurrentSchemeInputsV1", "SchemeAdoptionHoldV1",
    "read_current_scheme_adoption_for_w01_v1",
)
