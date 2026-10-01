"""Series claim/terminal rows on the existing independent execution chain."""
import hashlib
import json
import threading

from .contract import AuthorityUnavailable, JournalHead
from .d04_series_contract_v1 import (D04SeriesChunkBindingV1, D04SeriesClaimV1,
    D04SeriesMeasurementV1, from_wire, to_wire, mutation_id)
from ..runtime_contracts import canonical_digest, canonical_serialize

ENTRY_PREFIX = b'{"d04_series_original":'
ENTRY_SCHEMA = "sylanne.authority.d04-series-entry.v1"


def _encoded(journal, binding, claim, measurement, sequence, previous):
    return canonical_serialize({"d04_series_original": {"schema": ENTRY_SCHEMA,
        "phase": "claim" if measurement is None else "terminal", "journal_id": journal.journal_id,
        "sequence": sequence, "previous_digest": previous, "binding": to_wire(binding),
        "claim": to_wire(claim), "measurement": None if measurement is None else to_wire(measurement)}}).encode()


def decode_series_row_v1(journal, row):
    try:
        raw = json.loads(row[4])
        if set(raw) != {"d04_series_original"}:
            raise ValueError("series envelope differs")
        body = raw["d04_series_original"]
        if set(body) != {"schema", "phase", "journal_id", "sequence", "previous_digest", "binding", "claim", "measurement"}:
            raise ValueError("series entry fields differ")
        binding = from_wire(body["binding"], D04SeriesChunkBindingV1)
        claim = from_wire(body["claim"], D04SeriesClaimV1)
        measurement = None if body["measurement"] is None else from_wire(body["measurement"], D04SeriesMeasurementV1)
        phase = "claim" if measurement is None else "terminal"
        if (body["schema"] != ENTRY_SCHEMA or body["phase"] != phase or body["journal_id"] != journal.journal_id
                or binding.numeric.authority_namespace != journal.namespace or body["sequence"] != row[0]
                or body["previous_digest"] != row[5] or claim.binding_digest != binding.digest
                or claim.execution_id != binding.numeric.execution_id
                or claim.executor_installation_id != binding.numeric.installation_id
                or claim.claim_id != mutation_id(binding, "claim")
                or (measurement is None and claim.claim_sequence != row[0])
                or (measurement is not None and (measurement.binding_digest != binding.digest
                    or measurement.claim_id != claim.claim_id or claim.claim_sequence + 1 != row[0]))):
            raise ValueError("series original identity differs")
        encoded = _encoded(journal, binding, claim, measurement, row[0], row[5])
        identity = mutation_id(binding, phase)
        if (row[1], row[2], row[3], row[4], row[6]) != (identity,
                canonical_digest(to_wire(claim if measurement is None else measurement)), identity,
                encoded, "sha256:" + hashlib.sha256(encoded).hexdigest()):
            raise ValueError("series original commitment differs")
        return binding, claim, measurement
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("malformed D04 series execution row") from exc


def read_series_rows_locked_v1(journal, binding):
    if journal._guard_owner != threading.get_ident() or binding.numeric.authority_namespace != journal.namespace:
        raise AuthorityUnavailable("series originals require the current frozen execution writer")
    head, rows = journal._scan_locked()
    claim = measurement = claim_row = terminal_row = None
    expected = {mutation_id(binding, "claim"), mutation_id(binding, "terminal")}
    for row in rows:
        if row[1] not in expected:
            continue
        observed, original, measured = decode_series_row_v1(journal, row)
        if observed != binding:
            raise AuthorityUnavailable("series execution identity reused")
        if measured is None:
            if claim is not None:
                raise AuthorityUnavailable("duplicate series claim")
            claim, claim_row = original, row
        else:
            if claim != original or measurement is not None:
                raise AuthorityUnavailable("series terminal lacks one exact original claim")
            measurement, terminal_row = measured, row
    return head, claim, measurement, claim_row, terminal_row


def append_series_entry_locked_v1(journal, *, binding, claim, measurement, before_head):
    journal._check_schema()
    if journal._schema_version not in {"2", "4"} or journal._guard_owner != threading.get_ident():
        raise AuthorityUnavailable("series append requires the installed mixed frozen chain")
    head, old_claim, old_measurement, claim_row, terminal_row = read_series_rows_locked_v1(journal, binding)
    existing = claim_row if measurement is None else terminal_row
    if existing is not None:
        if (_encoded(journal, binding, claim, measurement, existing[0], existing[5]) != existing[4]
                or before_head != JournalHead(journal.journal_id, existing[0] - 1, existing[5])):
            raise AuthorityUnavailable("series append replay bytes changed")
        return existing
    if head != before_head or (measurement is None and old_claim is not None) or (measurement is not None and old_claim != claim):
        raise AuthorityUnavailable("series execution right or append head changed")
    if journal._installed_storage_reader is not None:
        journal._require_current_storage_v1(action="business" if measurement is None else "recovery")
        if measurement is None:
            journal._installed_storage_reader.require_unconsumed_identity_v1(namespace=journal.namespace,
                identities=(("execution_id", binding.numeric.execution_id), ("internal_operation", binding.numeric.operation_id)))
    phase = "claim" if measurement is None else "terminal"
    encoded = _encoded(journal, binding, claim, measurement, head.seq + 1, head.digest)
    identity = mutation_id(binding, phase)
    row = (head.seq + 1, identity, canonical_digest(to_wire(claim if measurement is None else measurement)),
        identity, encoded, head.digest, "sha256:" + hashlib.sha256(encoded).hexdigest())
    decode_series_row_v1(journal, row)
    journal._db.execute("INSERT INTO authority_v2_execution_entries VALUES(?,?,?,?,?,?,?)", row)
    return row
