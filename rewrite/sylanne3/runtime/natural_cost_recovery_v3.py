"""Content-free recovery of actual natural-generation/review expenses.

Only original identities and signed resource quotes are read here. Frozen
prompts and model output are deliberately never selected from the database.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest
from .c02_cost_settlement import C02OriginalIntentLookupV1
from .jobs import get_job
from .natural_reply_job_v2 import _seal, natural_job_ids_v2


@dataclass(frozen=True, slots=True)
class NaturalCostRecoveryOriginalV3:
    cursor: str
    stage: str
    parent_original_id: str
    lookup: C02OriginalIntentLookupV1
    quote_id: str
    quote_version: int


def read_natural_cost_recovery_page_v3(db, *, namespace, authority_id,
        authority_namespace, installation_id, after=None, limit=32):
    if not db.in_transaction or type(limit) is not int or not 1 <= limit <= 64:
        raise ValueError("natural accounting scan needs a bounded current transaction")
    rows = []
    for stage in ("generation", "review"):
        table = f"graph_natural_{stage}_preparations_v2"
        if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone() is None:
            continue
        rows.extend((stage + ":" + row[0], stage, *row) for row in db.execute(
            f"SELECT parent_original_id,seal_json,typed_request_digest,worker_fence "
            f"FROM {table} WHERE bot=? AND persona=? AND state IN ('acquired','terminal') "
            "AND (? IS NULL OR ? || ':' || parent_original_id > ?) "
            "ORDER BY parent_original_id LIMIT ?",
            (*namespace.as_tuple, after, stage, after, limit + 1)))
    rows.sort()
    more = len(rows) > limit
    result = []
    for cursor, stage, parent, wire, request_digest, worker_fence in rows[:limit]:
        raw = json.loads(wire)
        if canonical_json(raw) != wire:
            raise ValueError("noncanonical natural accounting seal")
        seal = _seal(stage, raw)
        ids = natural_job_ids_v2(namespace, parent, stage)
        job = get_job(db, seal.job_id)
        if (seal.namespace != namespace or seal.installation_id != installation_id
                or (seal.job_id, seal.original_operation_id, seal.acquire_operation_id,
                    seal.call_id, seal.reservation_operation_id) != ids
                or job is None or job.operation_id != seal.original_operation_id
                or job.budget_ref != seal.parent_budget_lease_id
                or job.work_kind != "natural_" + stage
                or type(request_digest) is not str or len(request_digest) != 64
                or type(worker_fence) is not int or worker_fence < 1):
            raise ValueError("natural accounting original identity differs")
        quote_id, version = job.operator_versions["resource_quote"].rsplit(":", 1)
        binding = canonical_digest({"original_seal_digest": canonical_digest(asdict(seal)),
            "model_call_request_digest": request_digest, "worker_fence": worker_fence})
        lookup = C02OriginalIntentLookupV1(namespace, authority_id, authority_namespace,
            installation_id, seal.job_id, seal.reservation_operation_id,
            seal.acquire_operation_id, seal.call_id, binding, request_digest,
            "natural-cost-recovery:" + canonical_digest((namespace, seal.call_id))[:48])
        result.append(NaturalCostRecoveryOriginalV3(cursor, stage, parent, lookup, quote_id, int(version)))
    return tuple(result), result[-1].cursor if more and result else None


def reconcile_natural_cost_page_v3(graph, bootstrap, *, namespace, installation_id,
                                  after=None, limit=32):
    """Read authenticated terminal facts outside SQL, then use D11 accounting."""
    graph._admin(bootstrap)
    store = graph._GraphCoordinator__store
    lookup_port = graph._GraphCoordinator__original_c02_cost_intent_port
    if lookup_port is None:
        raise RuntimeError("installed original model accounting observer unavailable")
    with store._lock:
        metadata, _ = graph._v2_graph_stamp(namespace)
        db = store._db
        db.execute("BEGIN")
        try:
            originals, continuation = read_natural_cost_recovery_page_v3(db,
                namespace=namespace, authority_id=metadata.requirements.authority_id,
                authority_namespace=metadata.requirements.authority_namespace,
                installation_id=installation_id, after=after, limit=limit)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    results = []
    for original in originals:
        try:
            intent = lookup_port.read_historical_accounting_v1(original.lookup)
            receipt = graph._commit_original_model_cost_v1(bootstrap, namespace, intent,
                quote_id=original.quote_id, quote_version=original.quote_version,
                work_kind="natural_" + original.stage)
            status = "accounting_recorded" if receipt.status in {"committed", "duplicate"} else "accounting_hold"
            results.append({"cursor": original.cursor, "status": status,
                "call_id": original.lookup.call_id, "receipt": receipt})
        except Exception as exc:
            # No fact means unknown, never zero, cancellation or a new paid call.
            results.append({"cursor": original.cursor, "status": "original_fact_unresolved",
                "call_id": original.lookup.call_id, "reason": type(exc).__name__})
    return {"schema": "sylanne.natural_cost_recovery_page.v3",
        "items": tuple(results), "next_after": continuation}
