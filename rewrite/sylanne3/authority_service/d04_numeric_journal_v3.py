"""D04 numeric originals in the installed mixed execution append chain.

This module owns no second journal or activation state. The installed service
holds the existing deletion/execution locks, verifies authority, appends here,
and reconciles the exact resulting head into Core before admitting execution.
"""
from __future__ import annotations

import hashlib
import json
import threading

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable, JournalHead
from .d04_numeric_contract_v3 import (
    D04NumericBindingV3, D04NumericClaimV3, D04NumericMeasurementV3,
    from_wire, to_wire,
)


ENTRY_PREFIX = b'{"d04_numeric_original":'
ENTRY_SCHEMA = "sylanne.authority.d04-numeric-entry.v3"


def numeric_mutation_id_v3(binding: D04NumericBindingV3, phase: str) -> str:
    if type(binding) is not D04NumericBindingV3 or phase not in {"claim", "terminal"}:
        raise AuthorityUnavailable("typed numeric mutation identity required")
    return "d04-numeric:" + phase + ":" + canonical_digest(
        (binding.authority_namespace, binding.installation_id, binding.execution_id))


def _encoded(journal, binding, claim, measurement, sequence, previous_digest, cost_closure_basis=None):
    return canonical_serialize({"d04_numeric_original": {
        "schema": ENTRY_SCHEMA,
        "phase": "claim" if measurement is None else "terminal" if cost_closure_basis is None else "cost_only",
        "journal_id": journal.journal_id,
        "sequence": sequence,
        "previous_digest": previous_digest,
        "binding": to_wire(binding),
        "claim": to_wire(claim),
        "measurement": None if measurement is None else to_wire(measurement),
        **({} if cost_closure_basis is None else {"cost_closure_basis":cost_closure_basis}),
    }}).encode("utf-8")


def decode_numeric_row_v3(journal, row):
    """Strict structural decode for the ordinary full-chain verifier."""
    try:
        envelope = json.loads(row[4])
        if type(envelope) is not dict or set(envelope) != {"d04_numeric_original"}:
            raise ValueError("numeric entry envelope differs")
        body = envelope["d04_numeric_original"]
        if type(body) is not dict or set(body) != ({
                "schema", "phase", "journal_id", "sequence", "previous_digest",
                "binding", "claim", "measurement"} | ({"cost_closure_basis"} if body.get("phase")=="cost_only" else set())):
            raise ValueError("numeric entry shape differs")
        binding = from_wire(body["binding"], D04NumericBindingV3)
        claim = from_wire(body["claim"], D04NumericClaimV3)
        measurement = (None if body["measurement"] is None else
                       from_wire(body["measurement"], D04NumericMeasurementV3))
        basis=body.get("cost_closure_basis")
        if basis is not None:
            from ..runtime.restore_anchor import RestoreAnchor
            if (type(basis) is not dict or set(basis)!={"artifact_disposition","barrier_basis_digest","current_anchor"}
                    or measurement is None or measurement.status!="completed"
                    or basis["artifact_disposition"] not in {"withheld_by_current_barrier","missing_after_crash"}
                    or type(basis["barrier_basis_digest"]) is not str or len(basis["barrier_basis_digest"])!=64
                    or any(c not in "0123456789abcdef" for c in basis["barrier_basis_digest"])):
                raise ValueError("numeric cost-only closure basis differs")
            anchor=RestoreAnchor(**basis["current_anchor"])
            if (anchor.namespace!=binding.authority_namespace or anchor.authority_id!=binding.authority_id
                    or anchor.execution_journal_id!=journal.journal_id
                    or (anchor.execution_seq,anchor.execution_digest)!=(row[0]-1,row[5])):
                raise ValueError("numeric measured-cost closure current heads differ")
        phase = "claim" if measurement is None else "terminal" if basis is None else "cost_only"
        if (body["schema"] != ENTRY_SCHEMA or body["phase"] != phase
                or body["journal_id"] != journal.journal_id
                or binding.authority_namespace != journal.namespace
                or body["sequence"] != row[0] or body["previous_digest"] != row[5]
                or claim.binding_digest != binding.digest
                or claim.execution_id != binding.execution_id
                or claim.executor_installation_id != binding.installation_id
                or claim.claim_id != numeric_mutation_id_v3(binding, "claim")):
            raise ValueError("numeric entry original identity differs")
        if measurement is None:
            if claim.claim_sequence != row[0]:
                raise ValueError("numeric claim sequence differs")
        elif (measurement.binding_digest != binding.digest
              or measurement.claim_id != claim.claim_id or claim.claim_sequence >= row[0]
              or (measurement.status == "completed" and
                  tuple(f for f, _ in measurement.family_loo_transcripts) != binding.family_roots)):
            raise ValueError("numeric measured original differs")
        encoded = _encoded(journal, binding, claim, measurement, row[0], row[5], basis)
        content_digest = canonical_digest(to_wire(claim if measurement is None else measurement) if basis is None
            else (to_wire(measurement),basis))
        chain_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        mutation_id = numeric_mutation_id_v3(binding, "terminal" if phase=="cost_only" else phase)
        if ((row[1], row[2], row[3], row[4], row[6]) !=
                (mutation_id, content_digest, mutation_id, encoded, chain_digest)):
            raise ValueError("numeric entry commitment differs")
        return binding, claim, measurement
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("malformed D04 numeric execution entry") from exc


def read_numeric_rows_locked_v3(journal, binding):
    if type(binding) is not D04NumericBindingV3 or binding.authority_namespace != journal.namespace:
        raise AuthorityUnavailable("numeric read installation differs")
    if journal._guard_owner != threading.get_ident():
        raise AuthorityUnavailable("numeric originals require the frozen execution writer")
    head, rows = journal._scan_locked()
    claim = measurement = claim_row = terminal_row = None
    expected = {numeric_mutation_id_v3(binding, "claim"), numeric_mutation_id_v3(binding, "terminal")}
    for row in rows:
        if row[1] not in expected:
            continue
        observed_binding, observed_claim, observed_measurement = decode_numeric_row_v3(journal, row)
        if observed_binding != binding:
            raise AuthorityUnavailable("numeric execution identity was reused")
        if observed_measurement is None:
            if claim is not None:
                raise AuthorityUnavailable("numeric claim is duplicated")
            claim, claim_row = observed_claim, row
        else:
            if measurement is not None:
                raise AuthorityUnavailable("numeric terminal is duplicated")
            measurement, terminal_row = observed_measurement, row
            if claim is None or observed_claim != claim:
                raise AuthorityUnavailable("numeric terminal lacks its preceding claim")
    return head, claim, measurement, claim_row, terminal_row


def append_numeric_entry_locked_v3(journal, *, binding, claim,
                                   measurement, before_head, cost_closure_basis=None):
    """Called only by the installed service after its current Core checks."""
    if journal._guard_owner != threading.get_ident():
        raise AuthorityUnavailable("numeric append requires the frozen execution writer")
    journal._check_schema()
    if journal._schema_version not in {"2", "4"}:
        raise AuthorityUnavailable("numeric append requires a mixed execution chain")
    if (type(binding) is not D04NumericBindingV3 or type(claim) is not D04NumericClaimV3
            or (measurement is not None and type(measurement) is not D04NumericMeasurementV3)
            or type(before_head) is not JournalHead or before_head.journal_id != journal.journal_id
            or binding.authority_namespace != journal.namespace):
        raise AuthorityUnavailable("numeric append inputs differ")
    if journal._installed_storage_reader is not None:
        journal._require_current_storage_v1(action="business" if measurement is None else "recovery")
        if measurement is None:
            journal._installed_storage_reader.require_unconsumed_identity_v1(
                namespace=journal.namespace, identities=(("execution_id", binding.execution_id),
                    ("internal_operation", binding.operation_id)))
    head, old_claim, old_measurement, claim_row, terminal_row = read_numeric_rows_locked_v3(journal, binding)
    existing = claim_row if measurement is None else terminal_row
    if existing is not None:
        if (_encoded(journal, binding, claim, measurement, existing[0], existing[5], cost_closure_basis) != existing[4]
                or before_head != JournalHead(journal.journal_id, existing[0] - 1, existing[5])):
            raise AuthorityUnavailable("numeric mutation replay bytes differ")
        return existing
    if head != before_head:
        raise AuthorityUnavailable("numeric append before-head changed")
    if measurement is None:
        if old_claim is not None or claim.claim_sequence != head.seq + 1:
            raise AuthorityUnavailable("numeric execution right was already consumed")
    elif old_claim != claim or old_measurement is not None:
        raise AuthorityUnavailable("numeric terminal lacks its original claim")
    phase = "claim" if measurement is None else "terminal"
    encoded = _encoded(journal, binding, claim, measurement, head.seq + 1, head.digest, cost_closure_basis)
    mutation_id = numeric_mutation_id_v3(binding, phase)
    row = (head.seq + 1, mutation_id,
           canonical_digest(to_wire(claim if measurement is None else measurement) if cost_closure_basis is None
               else (to_wire(measurement),cost_closure_basis)),
           mutation_id, encoded, head.digest, "sha256:" + hashlib.sha256(encoded).hexdigest())
    # Validate the exact persisted representation before the append-only insert.
    decode_numeric_row_v3(journal, row)
    journal._db.execute("INSERT INTO authority_v2_execution_entries VALUES(?,?,?,?,?,?,?)", row)
    return row


def numeric_cost_closure_basis_v3(row):
    body=json.loads(row[4])["d04_numeric_original"]
    return body.get("cost_closure_basis")
