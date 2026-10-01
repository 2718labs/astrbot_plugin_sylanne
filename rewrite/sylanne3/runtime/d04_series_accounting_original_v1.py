"""Content-free signed series CPU originals shared by C09 and migration."""
from types import SimpleNamespace
import json

from ..authority_service.d04_series_contract_v1 import D04SeriesChunkBindingV1, from_wire
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d04_appraisal_driver_v3 import read_d04_original_v3


def read_series_accounting_original_v1(db, namespace, operation_id, *, issuer):
    from .c09_d04_series_originals_v1 import validate_d04_series_original_payload_v1
    saved = read_d04_original_v3(db, namespace, "series_chunk_accounting", operation_id)
    if saved is None:
        return None
    raw, digest = saved
    validate_d04_series_original_payload_v1("series_chunk_accounting", raw)
    binding = from_wire(raw["binding"], D04SeriesChunkBindingV1)
    numeric = binding.numeric
    quote = issuer.original_signed_quote(db, numeric.quote_id, numeric.quote_version)
    reserve = db.execute("SELECT receipt_json,digest,lease_id FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, numeric.reservation_operation_id)).fetchone()
    if (numeric.namespace != namespace or numeric.operation_id != operation_id
            or canonical_digest(quote) != numeric.quote_digest
            or canonical_serialize(quote) != raw["quote_payload_json"]
            or dict(quote.ceiling) != {"cpu_ms": numeric.cpu_ceiling_ms}
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.parent_budget_lease_ref != numeric.parent_budget_lease_ref
            or reserve != (raw["reserve_receipt_json"], numeric.reservation_digest, numeric.parent_budget_lease_ref)):
        raise ValueError("series signed CPU accounting identity differs")
    body = read_d04_original_v3(db, namespace, "series_chunk_prepared", operation_id)
    if body is not None and any(body[0][key] != raw[key] for key in
            ("binding", "quote_payload_json", "reserve_receipt_json")):
        raise ValueError("series body/accounting originals differ")
    return SimpleNamespace(binding=binding, digest=digest,
        quote_payload_json=raw["quote_payload_json"], reserve_receipt_json=raw["reserve_receipt_json"],
        job_identity_json=raw["job_identity_json"])


def read_series_cpu_cost_original_v1(db, namespace, binding, terminal):
    from .c09_d04_series_originals_v1 import validate_d04_series_original_payload_v1
    numeric = binding.numeric
    committed = read_d04_original_v3(db, namespace, "series_chunk_cost_commit", numeric.operation_id)
    acknowledged = read_d04_original_v3(db, namespace, "series_chunk_cost", numeric.operation_id)
    if committed is None:
        if acknowledged is not None:
            raise ValueError("series CPU ACK lacks its committed cost original")
        return None
    raw = validate_d04_series_original_payload_v1("series_chunk_cost_commit", committed[0])
    if (terminal is None or raw["binding_digest"] != binding.digest
            or raw["terminal_digest"] != terminal.digest
            or raw["root_digest"] != binding.root_digest
            or (raw["actual_cpu_ns"], raw["actual_cpu_ms"], raw["status"], raw["math_digest"]) !=
                (terminal.measurement.actual_cpu_ns, terminal.measurement.actual_cpu_ms,
                 terminal.measurement.status, terminal.measurement.chunk_math_digest)):
        raise ValueError("series committed CPU differs from genuine terminal")
    if acknowledged is not None:
        validate_d04_series_original_payload_v1("series_chunk_cost", acknowledged[0])
        if acknowledged[0] != {**raw, "authority_ack": True}:
            raise ValueError("series CPU ACK changes its committed cost original")
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt, NamespaceEpoch
    from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write
    event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, numeric.activity_id, raw["event_id"])).fetchone()
    operation = db.execute("SELECT receipt_json,activity_id FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, raw["event_id"])).fetchone()
    if event is None or operation is None or operation[1] != numeric.activity_id:
        raise ValueError("series CPU original lacks its actual committed Graph event")
    receipt = GraphReceipt("committed", GraphStore._version_rows(event[0]),
        GraphStore._version_rows(event[1]), NamespaceEpoch(*namespace.as_tuple, event[2]))
    if (canonical_digest(receipt) != raw["graph_receipt_digest"]
            or json.loads(operation[0])["graph_receipt_digest"] != raw["graph_receipt_digest"]):
        raise ValueError("series CPU committed Graph receipt differs")
    cost_id = "d04-series-cost:" + canonical_digest((binding.root_digest, binding.start_step_index))[:48]
    write = cost_settlement_graph_write(cost_settlement_from_runtime(db,
        bot_id=numeric.namespace.bot_id, persona_id=numeric.namespace.persona_id, activity_id=numeric.activity_id,
        bundle_operation_id=numeric.operation_id, effect_id=None, settlement_id=cost_id,
        lease_id=numeric.parent_budget_lease_ref, cost_operation_id=numeric.reservation_operation_id,
        budget_operation_id=numeric.reservation_operation_id, budget_phase="settle",
        prior_unknown_ref=None, execution_revoked=True))
    revision = next((version.revision for version in receipt.revisions if version.key == write.key), None)
    history = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
        "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
        (write.key.token, revision, *namespace.as_tuple, numeric.activity_id, raw["event_id"])).fetchone()
    if history is None or history[1] != 1 or json.loads(history[0]) != write.value:
        raise ValueError("series CPU Graph event did not write the exact actual budget settlement")
    return raw
