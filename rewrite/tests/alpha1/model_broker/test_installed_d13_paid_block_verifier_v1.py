"""D13 settled-original consumption using real lifecycle stores, no model call.

Only the current-window inventory is synthetic. The original job/call, signed
D02/D11 quotes/grants, persisted result, settlement and cache rows are real.
"""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import os
import sqlite3

import pytest

from sylanne3.authority_service.d13_paid_block_verifier_v1 import build_installed_d13_paid_block_verifier_v1
from sylanne3.authority_service.d13_source_identity_v1 import d13_original_source_identity_v1
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressObservationV1,
    ModelEgressRecoveryV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1, d13_paid_read_attempt_id_v1,
)
from sylanne3.graph_types import AtomKey, Owner, GraphVersion
from sylanne3.memory_types import source_key, access_key
from sylanne3.model_broker.d13_precompression import D13PrecompressionInstallationV1, issue_unadmitted_d13_model_request_v1
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, install_schema as budget_schema
from sylanne3.runtime.issuers import BudgetLeaseGrant, D02ResourceIssuer, D11BudgetGrantIssuer, install_schema as issuer_schema
from sylanne3.runtime.jobs import install_schema as job_schema
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.d13_paid_intent_original_v1 import install_d13_paid_intent_original_v1, record_d13_paid_call_original_v1
from sylanne3.runtime.d13_paid_coordinator_v1 import (
    install_d13_paid_coordinator_schema_v1, schedule_paid_d13_in_transaction_v1,
    acquire_paid_d13_in_transaction_v1, record_paid_d13_result_read_in_transaction_v1,
    settle_paid_d13_in_transaction_v1, prepare_paid_d13_standby_in_transaction_v1,
    finalize_paid_d13_in_transaction_v1,
)
from sylanne3.runtime.d13_precompression_job import prepare_paid_precompression_intent_v1
from sylanne3.runtime.model_cost_settlement import OriginalModelCostFactV1
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity, SourceQualification,
    VersionGuard, VersionedRef, NamespaceId, CompletedTurnV1, ConversationWindowProjectionV1,
    canonical_digest, canonical_serialize,
)


def fixture(monkeypatch):
    ns = NamespaceId("bot", "persona")
    def ref(key):
        return VersionedRef(key.token, 1)
    scene = ref(AtomKey(Owner("scene", *ns.as_tuple, "scene:test"), "scene.test", "current"))
    audience = ref(AtomKey(Owner("scene", *ns.as_tuple, "conversation"), "audience.test", "current"))
    turns = tuple(CompletedTurnV1("conversation", audience, i,
        ref(AtomKey(Owner("event", *ns.as_tuple, "turn:" + str(i)), "raw.test", "current")),
        ref(source_key(*ns.as_tuple, "source:" + str(i))), ref(access_key(*ns.as_tuple, "source:" + str(i))),
        "speaker:" + str(i % 2), "Keep this exact detail. Another useful sentence. " + "x" * 180,
        80.0 + i, "confirmed", "not_applicable") for i in range(6))
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    window = ConversationWindowProjectionV1(ns, "owner", "conversation", scene, audience,
        turns, 5, 100.0, deps, (scene, audience, *deps), 0, 0, 1)
    state = {"window": window}
    import sylanne3.runtime.d13_current_window as window_reader
    monkeypatch.setattr(window_reader, "read_current_d13_window_for_authority_v1",
        lambda *a, **kw: replace(state["window"], trusted_utc=a[5]))
    db = sqlite3.connect(":memory:")
    budget_schema(db); issuer_schema(db); job_schema(db)
    install_d13_paid_intent_original_v1(db); install_d13_paid_coordinator_schema_v1(db)
    db.execute("CREATE TABLE graph_atoms(token TEXT PRIMARY KEY,revision INTEGER,value TEXT,valid INTEGER,bot TEXT,persona TEXT,type_name TEXT,owner_kind TEXT)")
    db.execute("CREATE TABLE graph_d13_retirements_v1(bot TEXT,persona TEXT,block_token TEXT)")
    db.execute("CREATE TABLE graph_authority_epochs(bot TEXT,persona TEXT,access_epoch INTEGER,delete_epoch INTEGER)")
    db.execute("CREATE TABLE graph_bundle_operations(bot TEXT,persona TEXT,operation_id TEXT,activity_id TEXT)")
    db.commit(); db.execute("BEGIN")
    db.execute("INSERT INTO graph_authority_epochs VALUES('bot','persona',0,0)")
    d02, d11 = D02ResourceIssuer(os.urandom(32)), D11BudgetGrantIssuer(os.urandom(32))
    ceiling = {"input_tokens": 4000, "output_tokens": 256, "model_microusd": 10000}
    create_budget_lease(db, BudgetLease("paid-lease", None, *ns.as_tuple, "USD", ceiling,
        {}, {}, {}, 1, "active"), "create-paid", "1" * 64)
    d11.issue_budget_grant(db, BudgetLeaseGrant("paid-grant", 1, *ns.as_tuple, "paid-lease", "USD",
        ceiling, ("d13.precompress.paid.v1",), 200.0, "paid-policy"))
    installed = D13PrecompressionInstallationV1("installed-main", "provider", "model", "a" * 64, 256)
    intent = prepare_paid_precompression_intent_v1(window, installed, history_token_budget=2000,
        background_capacity=True, outstanding_candidate=False, attempted_input_digests=frozenset(),
        parent_budget_lease_ref="paid-lease", resource_ref="provider-main", ceiling=ceiling, deadline_utc=150.0)
    scheduled = schedule_paid_d13_in_transaction_v1(db, intent, window,
        resource_issuer=d02, budget_issuer=d11, valid_until_utc=160.0)
    original = scheduled.original
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?)", ns.as_tuple +
        (intent.job.operation_id, intent.job.activity_id))
    running = acquire_paid_d13_in_transaction_v1(db, ns, intent.job.job_id, "worker", now_utc=
        datetime.fromtimestamp(100, timezone.utc).isoformat(), lease_seconds=50)
    inputs = tuple(r.ref for r in intent.plan.source_dependencies)
    envelope = CommandEnvelope("sylanne.runtime.v1", OperationIdentity(running.activity_id, None,
        "attempt", "d13.precompress", running.operation_id, canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("worker", "d13", "cap", ns, ("persona",), "context", ("conversation",), "policy", 1, running.fence),
        VersionGuard(tuple(GraphVersion(AtomKey.from_token(r.ref), r.version) for r in window.read_set),
            (), 0, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((), "reported", None, 1.0, "external_report", "qualified", None, "actual"),
        inputs, "paid-lease", 150.0, 1.0, "clock", ())
    request = issue_unadmitted_d13_model_request_v1(envelope, intent.frozen,
        call_id=intent.binding.call_id, timeout_seconds=10.0, privacy_tier="private")
    call = record_d13_paid_call_original_v1(db, original, intent.frozen, window, request,
        resource_issuer=d02, budget_issuer=d11)
    source_ids, source_revisions, access_revisions = d13_original_source_identity_v1(intent.frozen)
    from sylanne3.runtime.restore_anchor import RestoreAnchor
    anchor = RestoreAnchor("authority", "authority-ns", 1, "deletion", 0, "genesis", "execution", 0, "genesis", 0, "proof")
    egress = ModelEgressIntentV1("authority", "authority-ns", "worker", running.operation_id,
        request.call_id, request.digest, running.job_id, running.fence, "f" * 32, 1, 0, canonical_digest(asdict(anchor)),
        source_ids, source_revisions, access_revisions, 0, 0, 1, 1, 1, 0, 0, 0,
        "paid-lease", original.budget_operation_id, original.budget_reservation_digest,
        tuple(sorted(ceiling.items())), "provider", "model", "a" * 64, 256,
        running.operation_id, intent.binding.binding_digest)
    model_text = json.dumps({"schema": "d13.extractive_model_output.v1", "turns": [
        {"sequence": t.sequence, "beat": "Keep this exact detail.", "details": []} for t in intent.frozen.turns]})
    observation = ModelEgressObservationV1("authority", "authority-ns", "worker", running.operation_id,
        request.call_id, request.digest, "completed", canonical_serialize({"text": model_text}),
        (("input_tokens", 100), ("output_tokens", 20)), (("model_microusd", 10),), None)
    admission = ModelAdmissionV2("b" * 64, "authority", "authority-ns", "worker", running.operation_id,
        request.call_id, request.digest, "a" * 64, "installed-main", "c" * 64, "profile", "d" * 64, "e" * 64)
    terminal = ModelTerminalReceiptV2(admission.admission_id, request.call_id, request.digest, "1" * 64,
        observation.digest, "sha256:" + observation.digest, "installed-main", admission.host_incarnation)
    fact = OriginalModelCostFactV1(egress, ModelEgressRecoveryV1(egress, "observed", observation.digest,
        observation.usage, observation.cost), admission, terminal)
    consumer = "d13-adopt:" + intent.binding.binding_digest
    read_request = WorkerModelResultReadRequestV1("authority", "authority-ns", ns, "installed-main",
        running.job_id, running.operation_id, original.budget_operation_id, request.call_id,
        intent.binding.binding_digest, request.digest, consumer, d13_paid_read_attempt_id_v1(consumer, 1),
        "d13_precompress_paid")
    read = WorkerModelResultReadV1(read_request, observation, terminal)
    record_paid_d13_result_read_in_transaction_v1(db, original, call, fact, read,
        holder="worker", fence=running.fence, now_utc=100.0)
    settlement = settle_paid_d13_in_transaction_v1(db, original, call, resource_issuer=d02)
    def write(item):
        db.execute("INSERT OR REPLACE INTO graph_atoms VALUES(?,1,?,1,?,?,?,?)",
            (item.key.token, canonical_serialize(item.value), *ns.as_tuple, item.key.type_name, item.key.owner.kind))
    write(settlement.cost_write)
    preparation = prepare_paid_d13_standby_in_transaction_v1(db, original, call, intent.frozen, window,
        installed, resource_issuer=d02, budget_issuer=d11, holder="worker", fence=running.fence, now_utc=100.0)
    assert preparation.block is not None, preparation.reason
    completed, writes = finalize_paid_d13_in_transaction_v1(db, preparation, holder="worker", fence=running.fence)
    for item in writes:
        write(item)
    candidate = replace(preparation.block, status="candidate")
    verifier = build_installed_d13_paid_block_verifier_v1(db, installation=installed,
        resource_issuer=d02, budget_issuer=d11)
    return locals()


def test_reopens_actual_settled_result_and_recompiles_at_later_time(monkeypatch):
    c = fixture(monkeypatch)
    assert c["verifier"].verify_current_paid_model_block_v2(c["candidate"], plan=c["intent"].plan,
        window=replace(c["window"], trusted_utc=101.0))
    before = c["db"].total_changes
    assert c["verifier"].verify_current_paid_model_block_v2(c["candidate"], plan=c["intent"].plan,
        window=replace(c["window"], trusted_utc=102.0))
    assert c["db"].total_changes == before


@pytest.mark.parametrize("mutation", ["text", "source", "access", "delete", "generation", "expired", "retired", "cost", "job", "installation", "quote_signature"])
def test_paid_original_consumption_rejects_changed_current_proof(monkeypatch, mutation):
    c = fixture(monkeypatch)
    candidate, window = c["candidate"], c["window"]
    if mutation == "text":
        candidate = replace(candidate, timeline=(replace(candidate.timeline[0], text="Another useful sentence."), *candidate.timeline[1:]))
    elif mutation == "source":
        window = replace(window, turns=(replace(window.turns[0], text="Changed original"), *window.turns[1:]))
    elif mutation in {"access", "delete", "generation"}:
        field = {"access": "access_epoch", "delete": "delete_epoch", "generation": "activation_epoch"}[mutation]
        window = replace(window, **{field: getattr(window, field) + 1})
    elif mutation == "expired":
        window = replace(window, trusted_utc=candidate.expires_at_utc)
    elif mutation == "retired":
        block_key = next(w.key for w in c["writes"] if w.key.type_name == "d13.compressed_turn_block.v2")
        c["db"].execute("INSERT INTO graph_d13_retirements_v1 VALUES(?,?,?)", c["ns"].as_tuple + (block_key.token,))
    elif mutation == "cost":
        c["db"].execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (c["settlement"].cost_write.key.token,))
    elif mutation == "job":
        c["db"].execute("UPDATE runtime_jobs SET cancel_epoch=1")
    elif mutation == "quote_signature":
        c["db"].execute("UPDATE runtime_resource_quotes SET signature='forged'")
    else:
        c["verifier"] = build_installed_d13_paid_block_verifier_v1(c["db"],
            installation=replace(c["installed"], model_id="other"), resource_issuer=c["d02"], budget_issuer=c["d11"])
    c["state"]["window"] = window
    assert not c["verifier"].verify_current_paid_model_block_v2(candidate, plan=c["intent"].plan, window=window)


def test_authority_reopens_its_independent_ledger_and_finished_fence(monkeypatch, tmp_path):
    from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
    from sylanne3.authority_service.v2_fence_store import _FENCE_DDL
    from sylanne3.authority_service.v2_contract import FencePermitV2
    from sylanne3.authority_service.v2_contract import canonical_bytes
    c = fixture(monkeypatch)
    authority_db = sqlite3.connect(tmp_path / "authority.sqlite", isolation_level=None)
    authority_db.execute("PRAGMA synchronous=FULL")
    store = AuthorityV2ModelEgressStore(authority_db, create=True)
    verifier = build_installed_d13_paid_block_verifier_v1(c["db"], installation=c["installed"],
        resource_issuer=c["d02"], budget_issuer=c["d11"], authority_store=store)
    args = dict(plan=c["intent"].plan, window=c["window"])
    assert not verifier.verify_current_paid_model_block_v2(c["candidate"], **args)
    # Offline fixture construction of the independent journal; no actual
    # provider or platform is invoked and no admission is claimed by this test.
    authority_db.execute(_FENCE_DDL)
    authority_db.execute("BEGIN")
    egress = c["egress"]
    permit = FencePermitV2("authority", "authority-ns", "worker", "holder", 1,
        "model_egress", egress.operation_id, egress.fence_token, 1, 0, c["anchor"])
    store.prepare_locked(authority_db, egress)
    store.bind_fence_locked(authority_db, egress)
    store.bind_original_identity_locked(authority_db, egress, "installed-main")
    authority_db.execute("INSERT INTO authority_v2_fences VALUES(?,?,?,?,?,?,'active',?,NULL,NULL,NULL)",
        (egress.operation_id, egress.namespace, egress.subject, egress.fence_token, 1, 0, canonical_bytes(permit)))
    store._transition_locked(authority_db, ModelEgressRecoveryV1(egress, "dispatch_started"))
    store.record_admission_locked(authority_db, egress, c["admission"])
    store._record_observation_locked(authority_db, c["observation"])
    store.record_terminal_receipt_locked(authority_db, c["admission"], c["terminal"])
    authority_db.execute("UPDATE authority_v2_fences SET state='finished',finish_request_id=?,finish_request_digest=?",
        (egress.call_id, c["terminal"].finish_digest))
    authority_db.execute("COMMIT")
    assert verifier.verify_current_paid_model_block_v2(c["candidate"], **args)
    authority_db.execute("UPDATE authority_v2_fences SET finish_request_digest='sha256:" + "f" * 64 + "'")
    assert not verifier.verify_current_paid_model_block_v2(c["candidate"], **args)
    authority_db.execute("UPDATE authority_v2_fences SET finish_request_digest=?", (c["terminal"].finish_digest,))
    authority_db.execute("UPDATE authority_model_egress_observations_v1 SET observation_json='{}'")
    assert not verifier.verify_current_paid_model_block_v2(c["candidate"], **args)
    authority_db.close()
