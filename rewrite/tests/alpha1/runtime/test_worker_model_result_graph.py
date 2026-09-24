"""Terminal worker reads qualify current graph facts after cost settlement."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import sqlite3
import time
from types import SimpleNamespace

from sylanne3.authority_service.current_worker_model_result_graph_verifier import (
    PinnedCurrentWorkerModelResultGraphVerifier,
)
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.authority_service.v2_worker_model_result_contract import WorkerModelResultReadRequestV1
from sylanne3.contracts import canonical_json
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.d11_types import RuntimeOutboxValue, job_graph_write, runtime_job_key, runtime_outbox_key
from sylanne3.runtime.encoding_call_binding import (
    binding_to_json, insert_binding, install_schema as install_binding_schema, prepare_binding,
)
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote,
)
from sylanne3.runtime.jobs import PersistentJob, install_schema as install_job_schema
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import SnapshotRequirementsV2, SourceQualification, canonical_digest, canonical_serialize

from test_encoding_call_binding import NAMESPACE, SOURCE, _request
from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_ENCODING_TEMPLATE_VERSION


def _case(tmp_path):
    source = SOURCE
    namespace = NAMESPACE
    _, activity, original_id, job_id, outbox_id, idempotency = ingress_ids(source.source_id)
    acquire_id = "acquire-1"
    now = datetime.now(timezone.utc)
    lease = (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    deadline = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    job = PersistentJob(
        job_id, original_id, activity, None, *namespace.as_tuple,
        "snapshot-1", "running", "d06.encode_source", {}, None,
        deadline, "budget-1", "resource-1", {"resource_quote": "quote-1:1"},
        "worker", lease, 1, 0, {}, None)
    original_request = _request(source=source)
    envelope = original_request.envelope
    envelope = replace(
        envelope,
        identity=replace(envelope.identity, activity_id=activity,
                         operation_id=acquire_id),
        authority=replace(envelope.authority, issuer_domain="d11"),
    )
    model_request = replace(original_request, envelope=envelope)
    context = SimpleNamespace(
        acquire_operation_id=acquire_id, job=job,
        monotonic_deadline=envelope.monotonic_deadline,
        character_interval_ref=envelope.character_interval_ref,
        deadline_utc=envelope.deadline_utc, clock_epoch="clock-1")
    binding = prepare_binding(
        namespace, job_id, source, 1, 1, job.budget_ref, job.operation_id,
        model_request,
        prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        provider_config_ref="admin-config-1", provider_config_digest="b" * 64,
        production_context=context)
    anchor = RestoreAnchor(
        "authority", "bot:persona", 1, "deletion-journal", 0, "genesis",
        "execution-journal", 0, "genesis", 0, "proof-1")
    requirements = SnapshotRequirementsV2(
        namespace, anchor.authority_id, anchor.namespace,
        anchor.activation_generation, anchor.deletion_journal_id,
        anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, "incarnation-1")
    path = tmp_path / "graph.db"
    db = sqlite3.connect(path, isolation_level=None)
    install_job_schema(db)
    install_binding_schema(db)
    db.executescript("""
        CREATE TABLE graph_atoms(token TEXT PRIMARY KEY,bot TEXT,persona TEXT,
            owner_kind TEXT,subject TEXT,type_name TEXT,name TEXT,
            revision INTEGER,value TEXT,valid INTEGER);
        CREATE TABLE graph_dependencies(dependent_token TEXT,dependency_token TEXT,
            dependency_revision INTEGER);
        CREATE TABLE graph_recovery_metadata_v2(bot TEXT,persona TEXT,schema TEXT,
            requirements_json TEXT,graph_revision INTEGER);
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_authority_epochs(bot TEXT,persona TEXT,
            access_epoch INTEGER,delete_epoch INTEGER);
        CREATE TABLE graph_job_acquire_intents_v2(bot TEXT,persona TEXT,
            acquire_operation_id TEXT,job_id TEXT,original_operation_id TEXT,
            actor TEXT,encoding_binding_json TEXT,requirements_json TEXT);
        CREATE TABLE graph_job_acquire_receipts_v2(bot TEXT,persona TEXT,
            acquire_operation_id TEXT,job_json TEXT);
        CREATE TABLE graph_bundle_operations(bot TEXT,persona TEXT,
            operation_id TEXT,activity_id TEXT,effect_id TEXT,receipt_json TEXT);
        CREATE TABLE graph_history(token TEXT, value TEXT, valid INTEGER,
            event_bot TEXT,event_persona TEXT,event_session TEXT,event_id TEXT);
        CREATE TABLE graph_namespace_provisioning_v2(bot TEXT,persona TEXT,
            operation_id TEXT,digest TEXT,receipt_json TEXT);
        CREATE TABLE runtime_ingress_issuance(bot TEXT,persona TEXT,operation_id TEXT,
            activation_generation INTEGER,quote_id TEXT,grant_id TEXT,
            source_qualification_json TEXT);
        CREATE TABLE runtime_budget_reservations(lease_id TEXT,operation_id TEXT,
            digest TEXT,ceiling_json TEXT,state TEXT);
        CREATE TABLE runtime_budget_operations(bot_id TEXT,persona_id TEXT,
            operation_id TEXT,phase TEXT,digest TEXT);
        CREATE TABLE runtime_resource_quotes(quote_id TEXT,version INTEGER,
            quote_json TEXT,signature TEXT,status TEXT);
        CREATE TABLE runtime_budget_grants(lease_id TEXT,version INTEGER,
            grant_json TEXT,signature TEXT,status TEXT);
    """)
    db.execute("INSERT INTO runtime_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (job.job_id, job.operation_id, job.activity_id, job.effect_id,
                job.bot_id, job.persona_id, job.snapshot_ref, job.phase, job.work_kind,
                canonical_json(job.continuation), None, job.deadline_utc,
                job.budget_ref, job.resource_ref, canonical_json(job.operator_versions),
                job.lease_holder, job.lease_expires_utc, job.fence, job.cancel_epoch,
                canonical_json(job.usage), job.result_ref))
    insert_binding(db, binding)
    job_atom = runtime_job_key(*namespace.as_tuple, activity, job_id)
    outbox_atom = runtime_outbox_key(*namespace.as_tuple, activity, outbox_id)
    outbox = RuntimeOutboxValue(
        *namespace.as_tuple, activity, original_id, None, outbox_id,
        job_id, job_atom.token, source.source_id, idempotency, "delivered", 1)
    source_atom = source_key(*namespace.as_tuple, source.source_id)
    access_atom = access_key(*namespace.as_tuple, source.source_id)
    access = {"source_id": source.source_id, "audiences": ["internal"],
              "purposes": ["consolidation"], "status": "active", "recorded_at": 1.0}
    for key, value in ((job_atom, job_graph_write(job).value),
                       (outbox_atom, asdict(outbox)),
                       (source_atom, source.to_dict()), (access_atom, access)):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (key.token, *namespace.as_tuple, key.owner.kind,
                    key.owner.subject, key.type_name, key.name, 1,
                    canonical_json(value)))
    db.execute("INSERT INTO graph_dependencies VALUES(?,?,1)",
               (access_atom.token, source_atom.token))
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,1)",
               (*namespace.as_tuple, "sylanne3.authority.v2",
                canonical_json(asdict(requirements))))
    db.execute("INSERT INTO graph_epochs VALUES(?,?,1)", namespace.as_tuple)
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,0,0)", namespace.as_tuple)
    db.execute("INSERT INTO graph_job_acquire_intents_v2 VALUES(?,?,?,?,?,?,?,?)",
               (*namespace.as_tuple, acquire_id, job_id, original_id,
                job.lease_holder, binding_to_json(binding),
                canonical_json(asdict(requirements))))
    db.execute("INSERT INTO graph_job_acquire_receipts_v2 VALUES(?,?,?,?)",
               (*namespace.as_tuple, acquire_id, canonical_json(asdict(job))))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?)",
               (*namespace.as_tuple, original_id, activity, None,
                canonical_json({"ledger_refs": [job_atom.token],
                                "outbox_refs": [outbox_atom.token]})))
    historical = replace(outbox, phase="pending")
    db.execute("INSERT INTO graph_history VALUES(?,?,1,?,?,?,?)",
               (outbox_atom.token, canonical_json(asdict(historical)),
                *namespace.as_tuple, activity, original_id))
    d02 = D02ResourceIssuer(b"d" * 32)
    issuer = D11BudgetJobIssuer(d02, b"g" * 32)
    quote = ResourceQuote(
        "quote-1", 1, *namespace.as_tuple, activity, original_id, None,
        job.budget_ref, job.work_kind, job.snapshot_ref, time.time() + 600,
        job.resource_ref, job_atom.token, (outbox_atom.token,), (),
        {"output_tokens": 128}, job.fence, time.time() + 900)
    quote_json = canonical_serialize(asdict(quote))
    db.execute("INSERT INTO runtime_resource_quotes VALUES(?,?,?,?,?)",
               (quote.quote_id, quote.version, quote_json,
                d02._signer.sign("resource-quote.v1", quote_json), "revoked"))
    grant = BudgetLeaseGrant(
        "grant-1", 1, *namespace.as_tuple, job.budget_ref, "TOK",
        {"output_tokens": 128}, (job.work_kind,), time.time() + 900, "policy-1")
    grant_json = canonical_serialize(asdict(grant))
    grant_signature = issuer._signer.sign("budget-grant.v1", grant_json)
    db.execute("INSERT INTO runtime_budget_grants VALUES(?,?,?,?,?)",
               (job.budget_ref, 1, grant_json, grant_signature, "revoked"))
    provision = dict(
        namespace=asdict(namespace), operation_id="provision-1", input_digest="p"*64,
        installation_id="installation-1", manifest_digest="m"*64,
        authority_id=anchor.authority_id, authority_namespace=anchor.namespace,
        generation=anchor.activation_generation,
        graph_incarnation=requirements.graph_incarnation,
        graph_revision=1, graph_epoch=1, catalogue_hash="c"*64,
        scheme_version="1", operator_version="1", policy_version="1",
        root_lease_id=job.budget_ref, root_grant_id=grant.grant_id,
        root_grant_version=1, root_grant_signature=grant_signature,
        fence_attempt_id="provision-fence-1", finish_request_id="provision-finish-1",
        finish_request_digest="f"*64, permit_wire={})
    db.execute("INSERT INTO graph_namespace_provisioning_v2 VALUES(?,?,?,?,?)",
               (*namespace.as_tuple, provision["operation_id"],
                provision["input_digest"], canonical_json(provision)))
    qualification = model_request.envelope.source_qualification
    db.execute("INSERT INTO runtime_ingress_issuance VALUES(?,?,?,?,?,?,?)",
               (*namespace.as_tuple, original_id, 1, quote.quote_id, grant.grant_id,
                canonical_serialize(asdict(qualification))))
    db.execute("INSERT INTO runtime_budget_reservations VALUES(?,?,?,?,?)",
               (job.budget_ref, original_id, "c"*64,
                canonical_json({"output_tokens": 128}), "settled"))
    db.execute("INSERT INTO runtime_budget_operations VALUES(?,?,?,?,?)",
               (*namespace.as_tuple, original_id, "reserve", "c"*64))
    intent = ModelEgressIntentV1(
        anchor.authority_id, anchor.namespace, job.lease_holder,
        acquire_id, model_request.call_id, model_request.digest,
        job_id, job.fence, "m" * 32, 2, 0, canonical_digest(asdict(anchor)),
        (source.source_id,), ((source.source_id, 1),),
        ((source.source_id, 1),), 0, 0, 1, 1, 1, 0, 0, 0,
        job.budget_ref, original_id, "c" * 64, (("output_tokens", 128),),
        model_request.provider_id, model_request.model_id, "b" * 64, 128)
    request = WorkerModelResultReadRequestV1(
        anchor.authority_id, anchor.namespace, namespace, "installation-1",
        job_id, acquire_id, original_id, intent.call_id,
        binding.binding_digest, intent.request_digest,
        "c02-consumer-1", "worker-read-1")
    permit = FencePermitV2(
        anchor.authority_id, anchor.namespace, job.lease_holder,
        "administrator", 1, "read", request.read_attempt_id,
        "r" * 32, 100, 0, anchor)
    verifier = PinnedCurrentWorkerModelResultGraphVerifier(
        path, trusted_now_utc=time.time, d11_issuer=issuer)
    return db, job, intent, request, permit, verifier, access_atom, outbox_atom


def test_current_worker_graph_allows_settled_original_without_readmission(tmp_path):
    db, _, intent, request, permit, verifier, _, _ = _case(tmp_path)
    try:
        assert db.execute("SELECT state FROM runtime_budget_reservations").fetchone() == ("settled",)
        assert verifier.current(request, intent, permit) is True
    finally:
        db.close()


def test_current_worker_graph_rejects_revoked_access_cancel_and_expired_lease(tmp_path):
    db, job, intent, request, permit, verifier, access, _ = _case(tmp_path)
    try:
        assert verifier.current(request, intent, permit) is True
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access.token,))
        assert verifier.current(request, intent, permit) is False
        db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?", (access.token,))
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?", (job.job_id,))
        assert verifier.current(request, intent, permit) is False
        db.execute("UPDATE runtime_jobs SET cancel_epoch=0 WHERE job_id=?", (job.job_id,))
        verifier._clock = lambda: time.time() + 3600
        assert verifier.current(request, intent, permit) is False
        verifier._clock = time.time
        assert verifier.current(replace(request, call_id="other-call"), intent, permit) is False
    finally:
        db.close()


def test_original_ingress_receipt_is_required_after_settlement(tmp_path):
    db, job, intent, request, permit, verifier, _, outbox = _case(tmp_path)
    try:
        assert verifier.current(request, intent, permit) is True
        db.execute("DELETE FROM graph_bundle_operations WHERE operation_id=?",
                   (job.operation_id,))
        assert verifier.current(request, intent, permit) is False
        db.execute("DELETE FROM graph_history WHERE token=?", (outbox.token,))
        assert verifier.current(request, intent, permit) is False
    finally:
        db.close()


def test_historical_signed_bounds_and_provisioning_are_required(tmp_path):
    db, job, intent, request, permit, verifier, _, _ = _case(tmp_path)
    try:
        assert verifier.current(request, intent, permit) is True
        db.execute("UPDATE runtime_resource_quotes SET signature='0' WHERE quote_id='quote-1'")
        assert verifier.current(request, intent, permit) is False
        db.execute("UPDATE runtime_resource_quotes SET signature=? WHERE quote_id='quote-1'",
                   (verifier._issuer.resource_issuer._signer.sign(
                       "resource-quote.v1",
                       db.execute("SELECT quote_json FROM runtime_resource_quotes").fetchone()[0]),))
        db.execute("DELETE FROM graph_namespace_provisioning_v2")
        assert verifier.current(request, intent, permit) is False
    finally:
        db.close()


def test_original_reservation_receipt_and_qualification_are_required(tmp_path):
    db, job, intent, request, permit, verifier, _, _ = _case(tmp_path)
    try:
        assert verifier.current(request, intent, permit) is True
        db.execute("DELETE FROM runtime_budget_operations WHERE operation_id=?",
                   (job.operation_id,))
        assert verifier.current(request, intent, permit) is False
        db.execute("INSERT INTO runtime_budget_operations VALUES(?,?,?,?,?)",
                   (*request.namespace.as_tuple, job.operation_id, "reserve", "c" * 64))
        db.execute("UPDATE runtime_ingress_issuance SET source_qualification_json=NULL")
        assert verifier.current(request, intent, permit) is False
    finally:
        db.close()


def test_original_model_and_budget_operations_cannot_be_rebound(tmp_path):
    db, _, intent, request, permit, verifier, _, _ = _case(tmp_path)
    try:
        assert verifier.current(request, intent, permit) is True
        assert verifier.current(request, replace(intent, operation_id="other-model-op"), permit) is False
        assert verifier.current(
            request, replace(intent, budget_reservation_operation_id="other-budget-op"),
            permit) is False
        assert verifier.current(replace(request, acquire_operation_id="other-acquire"),
                                intent, permit) is False
    finally:
        db.close()
