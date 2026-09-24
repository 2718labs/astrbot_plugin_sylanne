"""Current ingress proof is useful, but cannot authorize an unbound model call."""

from dataclasses import asdict, replace
import json
import time

from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.v2_contract import from_wire
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.graph_coordinator import first_ingress_encoding_acquire_operation_id
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from sylanne3.runtime.encoding_call_binding import insert_binding, prepare_binding
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)

from test_first_ingress_v2 import ingress_system  # noqa: F401


def _case(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    db = store._db
    job_id, original_id = db.execute(
        "SELECT job_id,operation_id FROM runtime_jobs").fetchone()
    acquire_id = first_ingress_encoding_acquire_operation_id(
        policy.namespace, job_id, original_id, "encoding-worker", 1, "a" * 32)
    lease, capability = coordinator.grant(
        bootstrap, actor="encoding-worker", issuer_domain="d11",
        namespace=policy.namespace, domains=("d11",), activation_generation=1,
        operation_id=acquire_id)
    from sylanne3.runtime_contracts import AuthorityContext

    authority = AuthorityContext(
        "encoding-worker", "d11", capability, policy.namespace, ("activity",),
        "encode", ("internal",), "policy-1", 1)
    job = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, acquire_id, lease_seconds=30)
    source_ref = db.execute(
        "SELECT json_extract(value,'$.payload_ref') FROM graph_atoms "
        "WHERE type_name='runtime.outbox'").fetchone()[0]
    source = source_key(*policy.namespace.as_tuple, source_ref)
    access = access_key(*policy.namespace.as_tuple, source_ref)
    revisions = dict(db.execute(
        "SELECT token,revision FROM graph_atoms WHERE token IN (?,?)",
        (source.token, access.token)).fetchall())
    quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
    quote = json.loads(db.execute(
        "SELECT quote_json FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
        (quote_id, int(quote_version))).fetchone()[0])
    reservation = db.execute(
        "SELECT digest,ceiling_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (job.budget_ref, original_id)).fetchone()
    acquire_permit = from_wire(json.loads(db.execute(
        "SELECT permit_json FROM graph_job_acquire_receipts_v2 "
        "WHERE acquire_operation_id=?", (acquire_id,)).fetchone()[0]))
    requirements = json.loads(db.execute(
        "SELECT requirements_json FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", policy.namespace.as_tuple).fetchone()[0])
    graph_revision = db.execute(
        "SELECT graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", policy.namespace.as_tuple).fetchone()[0]
    graph_epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        policy.namespace.as_tuple).fetchone()[0]
    access_epoch, delete_epoch = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", policy.namespace.as_tuple).fetchone()
    intent = ModelEgressIntentV1(
        "authority", requirements["authority_namespace"], "encoding-worker",
        "model-operation", "model-call", "0" * 64, job_id, job.fence,
        "m" * 32, acquire_permit.fence_epoch + 1, 0,
        canonical_digest(asdict(acquire_permit.pinned_anchor)), (source_ref,),
        ((source_ref, revisions[source.token]),),
        ((source_ref, revisions[access.token]),), access_epoch, delete_epoch,
        graph_epoch, graph_revision, requirements["activation_generation"],
        requirements["revocation_epoch"], requirements["deletion_seq"],
        requirements["execution_seq"], job.budget_ref, original_id,
        reservation[0], tuple(sorted(json.loads(reservation[1]).items())),
        "provider", "model", "1" * 64, 100)
    path = db.execute("PRAGMA database_list").fetchone()[2]
    # The fixture installs a signing key shared by D02/D11 issuers.
    issuer = coordinator._GraphCoordinator__d11_issuer
    verifier = PinnedCurrentModelEgressGraphVerifier(
        path, d11_issuer=issuer, trusted_now_utc=time.time)
    assert quote["ceiling"] == dict(intent.budget_ceiling)
    assert intent.fence_token != acquire_permit.token
    return db, verifier, intent


def test_current_ingress_still_holds_unbound_model_request(ingress_system):
    db, verifier, intent = _case(ingress_system)
    changes = db.total_changes
    assert verifier.graph_facts_current(intent)
    assert verifier(intent) is False
    assert verifier(replace(intent, request_digest="f" * 64)) is False
    assert db.total_changes == changes


def test_access_epoch_or_original_ceiling_change_holds(ingress_system):
    db, verifier, intent = _case(ingress_system)
    assert not verifier.graph_facts_current(replace(intent, access_epoch=intent.access_epoch + 1))
    assert not verifier.graph_facts_current(replace(intent, budget_ceiling=(("cpu_ms", 1),)))
    assert not verifier.graph_facts_current(replace(
        intent, access_revisions=intent.access_revisions + (("other-source", 1),)))
    assert not verifier.graph_facts_current(replace(
        intent, source_revisions=intent.source_revisions + (("other-source", 1),)))
    access_token = access_key("bot", "persona", intent.source_refs[0]).token
    db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access_token,))
    assert not verifier.graph_facts_current(intent)


def test_complete_graph_facts_require_exact_durable_model_request(ingress_system):
    db, verifier, intent = _case(ingress_system)
    assert not verifier.complete_graph_current(intent)
    source_id = intent.source_refs[0]
    namespace = NamespaceId("bot", "persona")
    source_token = source_key(*namespace.as_tuple, source_id).token
    access_token = access_key(*namespace.as_tuple, source_id).token
    source = SourceRecord.from_dict(json.loads(db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (source_token,)).fetchone()[0]))
    job = get_job(db, intent.job_id)
    payload, template_digest = build_first_ingress_encoding_payload(source)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(job.activity_id, None, "model-attempt", "encode",
                          intent.operation_id,
                          canonical_digest({"input_refs": [source_token]})),
        AuthorityContext(intent.subject, "d06", "model-capability", namespace,
                         ("activity",), "consolidation", ("conversation",),
                         "model-policy", intent.authority_activation_generation,
                         worker_fence=job.fence),
        VersionGuard((GraphVersion(source_key(*namespace.as_tuple, source_id),
                                   intent.source_revisions[0][1]),
                      GraphVersion(access_key(*namespace.as_tuple, source_id),
                                   intent.access_revisions[0][1])),
                     (), intent.access_epoch, intent.delete_epoch,
                     "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((source_token,), "reported", source.occurred_at,
                            source.recorded_at, "external_report", "qualified",
                            None, "not_applicable"),
        (source_token,), job.budget_ref, 100.0, 100.0, "interval", (job.operation_id,),
    )
    request = ModelCallRequest(
        envelope, intent.call_id, intent.provider_id, intent.model_id,
        frozenset({"text"}), "private", template_digest, payload, 20.0,
        intent.max_output_tokens,
    )
    binding = prepare_binding(
        namespace, job.job_id, source, intent.source_revisions[0][1],
        intent.access_revisions[0][1], job.budget_ref, job.operation_id,
        request, prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        provider_config_ref="admin-config-1",
        provider_config_digest=intent.provider_config_digest,
    )
    insert_binding(db, binding)
    matching = replace(intent, request_digest=request.digest)
    assert verifier.complete_graph_current(matching)
    assert not verifier.complete_graph_current(intent)
    assert not verifier.complete_graph_current(replace(
        matching, provider_config_digest="2" * 64))
    assert verifier(matching) is False  # Authority fence and provider gate remain HOLD.
