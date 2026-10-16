"""Exact C09/cold codecs for bodyless original Contact accounting metadata."""
import json
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_effect_accounting_contract_v1 import (
    SignedContactEffectBudgetOriginV1, ContactEffectAccountingRequestV1, ContactEffectCostFactV1,
    ContactEffectMeasurementReceiptV1, ORIGIN_SIGN, SETTLEMENT_SIGN, from_wire, encoded_v1,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contact_effect_accounting_v1 import (ORIGINAL_TABLE, ORIGINAL_COLUMNS, ORIGINAL_DDL,
    ORIGINAL_TRIGGER_DDLS, ATTEMPT_TABLE, ATTEMPT_COLUMNS, ATTEMPT_DDL, ContactEffectSettlementResultV1, restore_stored_fact_v1)

GRAPH_TABLES = frozenset({ORIGINAL_TABLE, ATTEMPT_TABLE})


def require_financial_schema_v1(db, table):
    from ..authority_service.contact_effect_accounting_v1 import (
        MEASUREMENT_TABLE, MEASUREMENT_DDL, MEASUREMENT_TRIGGER_DDLS)
    definitions = {ORIGINAL_TABLE:(ORIGINAL_DDL, ORIGINAL_TRIGGER_DDLS),
        ATTEMPT_TABLE:(ATTEMPT_DDL, ()), MEASUREMENT_TABLE:(MEASUREMENT_DDL, MEASUREMENT_TRIGGER_DDLS)}
    if table not in definitions: raise AuthorityUnavailable("unregistered Contact financial schema")
    ddl, triggers = definitions[table]
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() != (ddl.replace(" IF NOT EXISTS", ""),):
        raise AuthorityUnavailable("Contact financial table schema differs")
    actual = tuple(row[0] for row in db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name=? ORDER BY name", (table,)))
    if actual != tuple(sorted((value.replace(" IF NOT EXISTS", "") for value in triggers), key=lambda value:value.split()[2])):
        raise AuthorityUnavailable("Contact financial immutable trigger inventory differs")


def validate_graph_financial_row_v1(table, columns, row, *, issuer=None):
    expected = ORIGINAL_COLUMNS if table == ORIGINAL_TABLE else ATTEMPT_COLUMNS if table == ATTEMPT_TABLE else None
    if expected is None or tuple(columns) != expected or len(row) != len(expected):
        raise AuthorityUnavailable("Contact financial exact row columns differ")
    ns = NamespaceId(row[0], row[1])
    if table == ATTEMPT_TABLE:
        request = from_wire(json.loads(row[5]), ContactEffectAccountingRequestV1)
        if (encoded_v1(request) != row[5] or request.origin.origin.namespace != ns
                or request.origin.origin.digest != row[3] or row[6] not in {"open", "committed", "closed"}
                or type(row[4]) is not str or len(row[4]) != 64):
            raise AuthorityUnavailable("Contact financial saved maintenance attempt differs")
        if issuer is not None:
            issuer._signer.verify(ORIGIN_SIGN, encoded_v1(request.origin.origin), request.origin.signature)
        return "attempt", row[2], json.loads(row[5]), canonical_digest(tuple(row))
    kind, ref, wire, digest, signature = row[2:]
    if len(wire.encode("utf-8")) > 65536:
        raise AuthorityUnavailable("Contact financial row exceeds its closed metadata bound")
    raw = json.loads(wire)
    if canonical_serialize(raw) != wire or canonical_digest(raw) != digest:
        raise AuthorityUnavailable("Contact financial canonical EOF/digest differs")
    if kind == "origin":
        signed = from_wire(raw, SignedContactEffectBudgetOriginV1)
        if signed.origin.namespace != ns or signed.origin.operation_id != ref or signed.signature != signature:
            raise AuthorityUnavailable("Contact financial birth row identity differs")
        if issuer is not None: issuer._signer.verify(ORIGIN_SIGN, encoded_v1(signed.origin), signature)
    elif kind == "settlement":
        if set(raw) != {"schema", "result", "fact", "origin_ref", "request_ref", "budget_receipt", "commit_seq", "epoch_revision"} or raw["schema"] != "d11.contact-effect-settlement-original.v1":
            raise AuthorityUnavailable("Contact financial receipt exact fields differ")
        result = ContactEffectSettlementResultV1(**raw["result"])
        from dataclasses import fields
        expected = {field.name for field in fields(ContactEffectCostFactV1)} - {"origin"}
        if type(raw["fact"]) is not dict or set(raw["fact"]) != expected:
            raise AuthorityUnavailable("Contact financial fact metadata fields differ")
        from ..graph_types import AtomKey
        key = AtomKey.from_token(result.cost_ref)
        if (result.operation_id != ref or result.accounting_finished
                or result.budget_receipt_digest != canonical_digest(raw["budget_receipt"])
                or result.budget_status != raw["budget_receipt"]["status"]
                or key.type_name != "runtime.cost_settlement"
                or (key.owner.bot, key.owner.persona) != ns.as_tuple
                or type(raw["origin_ref"]) is not str or not 1 <= len(raw["origin_ref"]) <= 128
                or type(raw["request_ref"]) is not str or not 1 <= len(raw["request_ref"]) <= 128
                or type(raw["commit_seq"]) is not int or raw["commit_seq"] < 1
                or type(raw["epoch_revision"]) is not int or raw["epoch_revision"] < 1):
            raise AuthorityUnavailable("Contact financial receipt original/measurement/budget linkage differs")
        if issuer is not None:
            issuer._signer.verify(SETTLEMENT_SIGN, canonical_serialize(raw), signature)
        if raw["fact"]["measurement"] is not None:
            receipt = from_wire(raw["fact"]["measurement"], ContactEffectMeasurementReceiptV1)
            if receipt.measurement.namespace != ns:
                raise AuthorityUnavailable("Contact financial measured namespace differs")
            if issuer is not None:
                from ..authority_service.contact_effect_accounting_v1 import verify_measurement_receipt_v1
                verify_measurement_receipt_v1(receipt, issuer._d02)
    else: raise AuthorityUnavailable("unknown Contact financial original kind")
    return kind, ref, raw, digest


def verify_financial_original_join_v1(original, *, read_original):
    if original.family != ORIGINAL_TABLE or original.kind == "origin": return
    birth = read_original("origin", original.payload["origin_ref"])
    if birth is None:
        raise AuthorityUnavailable("Contact actual settlement lacks its original signed budget birth")
    signed = from_wire(birth.payload, SignedContactEffectBudgetOriginV1)
    fact = restore_stored_fact_v1(original.payload, signed)
    if fact.origin.origin.digest != original.payload["result"]["origin_digest"]:
        raise AuthorityUnavailable("Contact actual settlement changed its original budget birth")


def validate_measurement_row_v1(columns, row, *, resource_issuer=None):
    from ..authority_service.contact_effect_accounting_v1 import MEASUREMENT_COLUMNS, verify_measurement_receipt_v1
    if tuple(columns) != MEASUREMENT_COLUMNS or len(row) != len(MEASUREMENT_COLUMNS):
        raise AuthorityUnavailable("Contact Core measurement exact columns differ")
    receipt = from_wire(json.loads(row[5]), ContactEffectMeasurementReceiptV1)
    m = receipt.measurement
    if (encoded_v1(receipt) != row[5] or (receipt.authority_namespace, m.installation_id, m.effect_id,
            m.measurement_id, m.digest, receipt.receipt_digest, receipt.signature) != (*row[:5], *row[6:])
            or canonical_digest(receipt.material()) != receipt.receipt_digest):
        raise AuthorityUnavailable("Contact Core measurement original row differs")
    if resource_issuer is not None: verify_measurement_receipt_v1(receipt, resource_issuer)
    return receipt


def require_financial_schema_object_v1(original):
    if original.table_name not in GRAPH_TABLES: return
    ddl = ORIGINAL_DDL if original.table_name == ORIGINAL_TABLE else ATTEMPT_DDL
    expected = {("table", original.table_name):ddl.replace(" IF NOT EXISTS", "")}
    if original.table_name == ORIGINAL_TABLE:
        for trigger in ORIGINAL_TRIGGER_DDLS:
            normalized = trigger.replace(" IF NOT EXISTS", "")
            expected[("trigger", normalized.split()[2])] = normalized
    if expected.get((original.object_type, original.name)) != original.sql:
        raise AuthorityUnavailable("Contact financial exact installed schema object differs")
