"""Historical D07 cost closure under genuine Authority accounting permits."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import time

from ..authority_service.v2_accounting_contract import AccountingMaintenanceRequestV1, AccountingMaintenanceGrantV1
from ..authority_service.v2_contract import to_wire as permit_wire
from ..runtime_contracts import canonical_digest, canonical_serialize
from .restore_anchor import RestoreAnchor
from .d07_execution_v1 import (read_d07_accounting_prepared_v1, read_d07_original_v1,
    settle_d07_original_model_cost_in_transaction_v1, stage_d07_body_cost_in_transaction_v1,
    record_d07_body_cost_after_cas_v1)
from .d07_graph_stages_v1 import _service, _commit_graph_stage
from ..graph_types import GraphVersion

TABLE = "graph_d07_accounting_attempts_v1"


def install_d07_accounting_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, call_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL, attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        grant_json TEXT, result_json TEXT, PRIMARY KEY(bot,persona,call_id))""")


def read_current_d07_accounting_request_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    with service._store._lock:
        prepared = read_d07_accounting_prepared_v1(service._db, service.d11_issuer, bundle.installation_policy.namespace, job_id)
        if prepared is None:
            raise ValueError("D07 preserved accounting identity absent")
        row = service._db.execute(f"SELECT intent_digest,attempt_id,anchor_json,state,result_json FROM {TABLE} WHERE bot=? AND persona=? AND call_id=?",
            (*prepared.namespace.as_tuple, prepared.call_id)).fetchone()
        if row is None:
            return None
        fact = service.pre_read_cost_fact_v1(job_id)
        if row[0] != canonical_digest(asdict(fact.intent)):
            raise ValueError("D07 historical accounting call identity changed")
        request = AccountingMaintenanceRequestV1(row[1], fact.intent, RestoreAnchor(**json.loads(row[2])))
        return request, row[3], None if row[4] is None else json.loads(row[4])


def close_current_d07_accounting_request_v1(graph, bootstrap, bundle, *, job_id, request):
    service = _service(graph, bootstrap, bundle)
    if service._closed_accounting_requests.get(job_id) != request:
        raise ValueError("D07 accounting attempt lacks actual independent finish confirmation")
    with service._store._lock:
        service._db.execute(f"UPDATE {TABLE} SET state='closed' WHERE bot=? AND persona=? AND call_id=? AND attempt_id=? AND state='open'",
            (*bundle.installation_policy.namespace.as_tuple, request.intent.call_id, request.operation_id))


def prepare_current_d07_accounting_request_v1(graph, bootstrap, bundle, *, job_id, anchor):
    service = _service(graph, bootstrap, bundle)
    fact = service.pre_read_cost_fact_v1(job_id)
    ns = bundle.installation_policy.namespace
    with service._store._lock:
        metadata, _epoch = graph._v2_graph_stamp(ns)
        prepared = read_d07_accounting_prepared_v1(service._db, service.d11_issuer, ns, job_id)
        if prepared is None or not graph._accounting_anchor_covers(metadata.requirements, anchor):
            raise ValueError("D07 accounting current Authority anchor does not cover graph history")
        if (anchor.authority_id, anchor.namespace) != (fact.intent.authority_id, fact.intent.namespace):
            raise ValueError("D07 accounting original Authority identity differs")
        attempt = "d07-accounting:" + canonical_digest((ns, prepared.call_id, anchor, fact.receipt))[:48]
        request = AccountingMaintenanceRequestV1(attempt, fact.intent, anchor)
        row = service._db.execute(f"SELECT state FROM {TABLE} WHERE bot=? AND persona=? AND call_id=?",
            (*ns.as_tuple, prepared.call_id)).fetchone()
        if row is not None and row[0] != "closed":
            raise ValueError("D07 original accounting attempt remains open or committed")
        service._db.execute("BEGIN IMMEDIATE")
        try:
            if graph._v2_graph_stamp(ns)[0] != metadata:
                raise ValueError("D07 accounting graph changed before durable attempt")
            service._db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,'open',NULL,NULL) ON CONFLICT(bot,persona,call_id) "
                "DO UPDATE SET intent_digest=excluded.intent_digest,attempt_id=excluded.attempt_id,anchor_json=excluded.anchor_json,state='open',grant_json=NULL,result_json=NULL",
                (*ns.as_tuple, prepared.call_id, canonical_digest(asdict(fact.intent)), attempt, canonical_serialize(asdict(anchor))))
            service._db.commit()
        except BaseException:
            service._db.rollback()
            raise
        return request


def reconcile_current_d07_cost_under_accounting_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    fact = service.pre_read_cost_fact_v1(job_id)
    request, grant = service.pre_read_accounting_grant_v1(job_id)
    if (type(request) is not AccountingMaintenanceRequestV1 or type(grant) is not AccountingMaintenanceGrantV1
            or request.intent != fact.intent or grant.call_id != fact.intent.call_id
            or grant.admission_id != fact.admission.admission_id
            or grant.reservation_digest != fact.intent.budget_reservation_digest
            or grant.observation_digest != fact.recovery.observation_digest
            or grant.terminal_receipt_digest != canonical_digest(asdict(fact.receipt))
            or grant.permit.pinned_anchor != request.expected_anchor or grant.permit.operation_id != request.operation_id):
        raise ValueError("D07 actual pre-read accounting permit differs from independent terminal")
    ns, store = bundle.installation_policy.namespace, service._store
    with store._lock:
        db = service._db
        metadata, epoch = graph._v2_graph_stamp(ns)
        if not graph._accounting_anchor_covers(metadata.requirements, request.expected_anchor):
            raise ValueError("D07 actual accounting permit no longer covers current graph")
        row = db.execute(f"SELECT intent_digest,attempt_id,anchor_json,state,result_json FROM {TABLE} WHERE bot=? AND persona=? AND call_id=?",
            (*ns.as_tuple, fact.intent.call_id)).fetchone()
        if row is None or row[:3] != (canonical_digest(asdict(fact.intent)), request.operation_id, canonical_serialize(asdict(request.expected_anchor))):
            raise ValueError("D07 actual durable accounting attempt differs")
        if row[3] == "committed":
            if row[4] is None:
                raise ValueError("D07 committed accounting receipt absent")
            return json.loads(row[4])
        if row[3] != "open":
            raise ValueError("D07 accounting attempt is closed")
        db.execute("BEGIN IMMEDIATE")
        try:
            prepared = read_d07_accounting_prepared_v1(db, service.d11_issuer, ns, job_id)
            value, writes = settle_d07_original_model_cost_in_transaction_v1(db, prepared=prepared, fact=fact,
                issuer=service.d11_issuer, resource_issuer=service.resource_issuer)
            if writes:
                from .model_cost_settlement import original_model_cost_operation_id_v1
                reads = []
                for write in writes:
                    existing = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
                    reads.append(GraphVersion(write.key, existing[0] if existing else 0))
                _commit_graph_stage(graph, db, metadata, epoch, prepared,
                    original_model_cost_operation_id_v1(ns, prepared.call_id), "actual_model_cost", time.time(), writes, reads,
                    extra={"terminal_receipt_digest": value["terminal_digest"], "paid": value["paid"]})
                metadata, epoch = graph._v2_graph_stamp(ns)
            if value["paid"]:
                body_writes, body_reads, body_original = stage_d07_body_cost_in_transaction_v1(db, prepared=prepared,
                    issuer=service.d11_issuer, resource_issuer=service.resource_issuer, body_authority=service.body_authority)
                if body_writes:
                    _commit_graph_stage(graph, db, metadata, epoch, prepared,
                        "d07-body-cost:" + canonical_digest((ns, prepared.call_id))[:48], "actual_body_cost", time.time(), body_writes, body_reads)
                    record_d07_body_cost_after_cas_v1(db, prepared=prepared, issuer=service.d11_issuer,
                        writes=body_writes, original=body_original)
                    metadata, _ = graph._v2_graph_stamp(ns)
            anchor = request.expected_anchor
            replacement = replace(metadata.requirements, deletion_seq=anchor.deletion_seq, deletion_digest=anchor.deletion_digest,
                execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
            store.cas_graph_recovery_metadata(metadata, replacement, _capability=graph._GraphCoordinator__graph_capability)
            db.execute(f"UPDATE {TABLE} SET state='committed',grant_json=?,result_json=? WHERE bot=? AND persona=? AND call_id=? AND attempt_id=? AND state='open'",
                (canonical_serialize(asdict(grant)), canonical_serialize(_json_cost(value)), *ns.as_tuple, prepared.call_id, request.operation_id))
            if db.execute("SELECT changes()").fetchone() != (1,):
                raise ValueError("D07 accounting actual receipt CAS changed")
            db.commit()
            return value
        except BaseException:
            db.rollback()
            raise


def _json_cost(value):
    from .d07_current_behavior_v1 import _json
    return _json(value)
