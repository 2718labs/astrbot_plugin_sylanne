"""Distinct D11 originals on the existing mixed independent execution chain."""
from __future__ import annotations

import hashlib
import json
import threading

from .contract import AuthorityUnavailable, JournalHead
from .d11_offline_tick_contract_v1 import (
    D11OfflineTickBindingV1, D11OfflineTickClaimPayloadV1, D11OfflineTickClaimV1,
    D11OfflineTickTerminalPayloadV1, D11OfflineTickTerminalV1,
    offline_tick_from_wire_v1, offline_tick_to_wire_v1, offline_tick_mutation_id_v1,
)
from ..runtime_contracts import canonical_digest, canonical_serialize


ENTRY_PREFIX = b'{"d11_offline_tick_original":'
ENTRY_SCHEMA = "sylanne.authority.d11-offline-tick-entry.v1"


def _encoded(journal, binding, payload, sequence, previous_digest):
    phase = "claim" if type(payload) is D11OfflineTickClaimPayloadV1 else "terminal"
    return canonical_serialize({"d11_offline_tick_original": {
        "schema": ENTRY_SCHEMA, "phase": phase, "journal_id": journal.journal_id,
        "sequence": sequence, "previous_digest": previous_digest,
        "binding": offline_tick_to_wire_v1(binding),
        "payload": offline_tick_to_wire_v1(payload),
    }}).encode("utf-8")


def _claim_original(journal, binding, payload, row):
    return D11OfflineTickClaimV1(binding, payload, journal.journal_id, row[6], row[1])


def decode_offline_tick_row_v1(journal, row):
    """Closed structural decoder. Service verification also checks signatures."""
    try:
        envelope = json.loads(row[4])
        if type(envelope) is not dict or set(envelope) != {"d11_offline_tick_original"}:
            raise ValueError("offline entry envelope differs")
        body = envelope["d11_offline_tick_original"]
        if type(body) is not dict or set(body) != {
                "schema", "phase", "journal_id", "sequence", "previous_digest", "binding", "payload"}:
            raise ValueError("offline entry shape differs")
        phase = body["phase"]
        kind = {"claim": D11OfflineTickClaimPayloadV1,
                "terminal": D11OfflineTickTerminalPayloadV1}.get(phase)
        binding = offline_tick_from_wire_v1(body["binding"], D11OfflineTickBindingV1)
        payload = offline_tick_from_wire_v1(body["payload"], kind)
        if (body["schema"] != ENTRY_SCHEMA or body["journal_id"] != journal.journal_id
                or body["sequence"] != row[0] or body["previous_digest"] != row[5]
                or binding.authority_namespace != journal.namespace
                or payload.binding_digest != binding.digest
                or payload.execution_id != binding.execution_id):
            raise ValueError("offline journal identity differs")
        encoded = _encoded(journal, binding, payload, row[0], row[5])
        mutation = offline_tick_mutation_id_v1(binding, phase)
        if (row[1], row[2], row[3], row[4], row[6]) != (
                mutation, canonical_digest(offline_tick_to_wire_v1(payload)), mutation,
                encoded, "sha256:" + hashlib.sha256(encoded).hexdigest()):
            raise ValueError("offline journal commitment differs")
        if phase == "claim":
            if (payload.claim_sequence != row[0] or payload.claim_id != mutation
                    or payload.executor_installation_id != binding.installation_id):
                raise ValueError("offline claim sequence/installation differs")
            return binding, payload, None
        # Verify the exact prior claim, allowing unrelated valid entries between
        # claim and terminal. Sequence adjacency is deliberately not required.
        prior = journal._db.execute(
            "SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest "
            "FROM authority_v2_execution_entries WHERE mutation_id=?",
            (offline_tick_mutation_id_v1(binding, "claim"),)).fetchone()
        if prior is None or prior[0] >= row[0]:
            raise ValueError("offline terminal lacks an earlier durable claim")
        old_binding, claim_payload, old_terminal = decode_offline_tick_row_v1(journal, prior)
        if old_binding != binding or old_terminal is not None:
            raise ValueError("offline terminal crossed its original binding")
        claim = _claim_original(journal, binding, claim_payload, prior)
        D11OfflineTickTerminalV1(binding, claim, payload, journal.journal_id,
                                row[0], row[6], row[1])
        return binding, claim_payload, payload
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("malformed D11 offline execution original") from exc


def read_offline_tick_rows_locked_v1(journal, binding):
    if (type(binding) is not D11OfflineTickBindingV1
            or binding.authority_namespace != journal.namespace
            or journal._guard_owner != threading.get_ident()):
        raise AuthorityUnavailable("offline originals need the actual frozen paired journal")
    head, rows = journal._scan_locked()
    claim = terminal = claim_row = terminal_row = None
    expected = {offline_tick_mutation_id_v1(binding, phase) for phase in ("claim", "terminal")}
    for row in rows:
        if row[1] not in expected:
            continue
        actual_binding, claim_payload, terminal_payload = decode_offline_tick_row_v1(journal, row)
        if actual_binding != binding:
            raise AuthorityUnavailable("offline execution identity was reused")
        if terminal_payload is None:
            if claim is not None:
                raise AuthorityUnavailable("offline claim duplicated")
            claim_row = row
            claim = _claim_original(journal, binding, claim_payload, row)
        else:
            if claim is None or terminal is not None or claim.payload != claim_payload:
                raise AuthorityUnavailable("offline terminal has no unique preceding original")
            terminal_row = row
            terminal = D11OfflineTickTerminalV1(binding, claim, terminal_payload,
                journal.journal_id, row[0], row[6], row[1])
    return head, claim, terminal, claim_row, terminal_row


def append_offline_tick_entry_locked_v1(journal, *, binding, payload, before_head):
    """Private installed-service append, following actual final Core admission."""
    if (journal._guard_owner != threading.get_ident()
            or type(binding) is not D11OfflineTickBindingV1
            or type(payload) not in {D11OfflineTickClaimPayloadV1, D11OfflineTickTerminalPayloadV1}
            or type(before_head) is not JournalHead
            or before_head.journal_id != journal.journal_id
            or binding.authority_namespace != journal.namespace):
        raise AuthorityUnavailable("offline append requires exact paired locked inputs")
    journal._check_schema()
    if journal._schema_version not in {"2", "4"}:
        raise AuthorityUnavailable("offline originals require the mixed execution chain")
    is_claim = type(payload) is D11OfflineTickClaimPayloadV1
    if journal._installed_storage_reader is not None:
        journal._require_current_storage_v1(action="business" if is_claim else "recovery")
        if is_claim:
            journal._installed_storage_reader.require_unconsumed_identity_v1(
                namespace=journal.namespace,
                identities=(("execution_id", binding.execution_id),
                            ("internal_operation", binding.operation_id)))
    head, claim, terminal, claim_row, terminal_row = read_offline_tick_rows_locked_v1(journal, binding)
    existing = claim_row if is_claim else terminal_row
    if existing is not None:
        if (_encoded(journal, binding, payload, existing[0], existing[5]) != existing[4]
                or before_head != JournalHead(journal.journal_id, existing[0] - 1, existing[5])):
            raise AuthorityUnavailable("offline append retry differs from immutable original")
        return existing
    if head != before_head:
        raise AuthorityUnavailable("offline append head changed")
    if is_claim:
        if claim is not None or payload.claim_sequence != head.seq + 1:
            raise AuthorityUnavailable("offline execution right already consumed")
    elif claim is None or terminal is not None:
        raise AuthorityUnavailable("offline terminal lacks its consumed claim")
    phase = "claim" if is_claim else "terminal"
    encoded = _encoded(journal, binding, payload, head.seq + 1, head.digest)
    mutation = offline_tick_mutation_id_v1(binding, phase)
    row = (head.seq + 1, mutation, canonical_digest(offline_tick_to_wire_v1(payload)),
           mutation, encoded, head.digest, "sha256:" + hashlib.sha256(encoded).hexdigest())
    decode_offline_tick_row_v1(journal, row)
    journal._db.execute("INSERT INTO authority_v2_execution_entries VALUES(?,?,?,?,?,?,?)", row)
    return row
