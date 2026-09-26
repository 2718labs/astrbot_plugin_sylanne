"""One original V3 worker result is adopted by the fenced C02 graph path."""

from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressObservationV1,
    ModelEgressRecoveryV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_worker_model_result_contract import WorkerModelResultReadV1
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV2, WorkerResultReadFactV2,
)
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.contracts import EventConflict
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy, AdminD06FirstIngressC02Policy,
)
from sylanne3.host.worker_result_identity import first_ingress_worker_result_request_v1
from sylanne3.runtime.encoding_call_binding import load_binding
from sylanne3.runtime.graph_write_attempt import domain_bundle_write_attempt_id_v1
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

import test_graph_v2_provisioning
from test_d03_self_projection_commit import FixtureCurrentSelf
from test_first_encoding_cost_graph_commit import AccountingPort
from test_first_ingress_job_acquire_v2 import _op, _worker, FixedEncodingRequestIssuer
from test_first_ingress_v2 import _ingress_inputs
from test_scene_binding_v2 import _bind_scene, _scene_case


class FinishedReadFactPort:
    def __init__(self, graph_store, authority_port, intent, read, read_permit):
        self.graph_store = graph_store
        self.port = authority_port
        self.intent = intent
        self.read = read
        self.read_permit = read_permit
        self.calls = 0

    def current_worker_result_read_fact(self, request):
        assert not self.graph_store._lock._is_owned()
        self.calls += 1
        assert type(request) is WorkerResultReadFactRequestV2
        assert request.read_request == self.read.request
        namespace = self.read.request.namespace
        operation_id = request.write_permit.operation_id
        row = self.graph_store._db.execute(
            "SELECT operation_id,digest FROM graph_bundle_intents_v2 "
            "WHERE bot=? AND persona=? AND fence_attempt_id=?",
            namespace.as_tuple + (operation_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == self.read.request.consumer_operation_id
        assert request.bundle_digest == row[1]
        assert request.write_permit.operation_id == domain_bundle_write_attempt_id_v1(
            namespace, row[0], row[1])
        anchor = self.port.anchors[self.read.request.namespace]
        assert self.port.fences.validate_fence(
            request.write_permit, subject="subject", current_anchor=anchor)
        assert self.port.fences.get_operation(
            self.read.request.read_attempt_id, subject="subject",
            namespace=anchor.namespace)[1] == "finished"
        finish_id = "worker-result-finish:" + canonical_digest({
            "request": asdict(self.read.request),
            "permit": asdict(self.read_permit)})
        finish_digest = "sha256:" + canonical_digest({
            "action": "finish_worker_result_read",
            "request": asdict(self.read.request),
            "permit": asdict(self.read_permit)})
        return WorkerResultReadFactV2(
            read_request=self.read.request,
            read_request_digest=self.read.request.digest,
            read_permit=self.read_permit,
            read_permit_digest=canonical_digest(asdict(self.read_permit)),
            read_finish_request_id=finish_id,
            read_finish_request_digest=finish_digest,
            result_digest=canonical_digest(asdict(self.read)),
            original_intent_digest=canonical_digest(asdict(self.intent)),
            terminal_receipt=self.read.terminal_receipt,
            write_permit=request.write_permit,
            write_permit_digest=canonical_digest(asdict(request.write_permit)),
            bundle_digest=request.bundle_digest)


@pytest.fixture
def c02_case(tmp_path, monkeypatch):
    original_policy = test_graph_v2_provisioning.policy_for

    def token_policy(store):
        policy = original_policy(store)
        return replace(
            policy,
            root_lease=replace(policy.root_lease, limits={
                "cpu_ms": 200, "output_tokens": 512}),
            root_grant=replace(policy.root_grant, max_ceiling={
                "cpu_ms": 100, "output_tokens": 256}),
        )

    monkeypatch.setattr(test_graph_v2_provisioning, "policy_for", token_policy)
    d04 = AffectProvider(active_scheme=AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1",
        "parameter:fixture", "coupling:fixture",
        (AffectAxis("care", "normalized", "care"),), ()))
    case = _scene_case(
        tmp_path, enable_ingress=True, arrival_allowed=True,
        extra_specs=d04.type_specs(),
        extra_work_kinds=("d03.self_identity_projection",
                          "d04.encoding_baseline", "d06.first_ingress_c02"))
    store, authority_db, port, coordinator, namespace, _, _, policy, bootstrap = case
    coordinator.register_provider(
        bootstrap, "d04", d04, "d04.proposal.v1",
        d04.descriptor.request_schema_hash)
    _bind_scene(case)
    host, clock, encoding = _ingress_inputs(namespace)
    encoding = replace(encoding, quote_ceiling={"output_tokens": 128})
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    coordinator.commit_d03_message_arrival_v2(
        bootstrap, namespace, host.lineage.source_ref, policy,
        AdminD03ArrivalPolicy(30.0, {"cpu_ms": 3},
                              "arrival-snapshot", "arrival-resource"), clock)
    fixture_self = FixtureCurrentSelf(store, coordinator, port, policy)
    coordinator._GraphCoordinator__self_identity_port = fixture_self
    job_id, original_op = store._db.execute(
        "SELECT job_id,operation_id FROM runtime_jobs").fetchone()
    coordinator.commit_d03_self_identity_projection_v1(
        bootstrap, namespace, job_id, original_op, policy,
        AdminD03SelfIdentityProjectionPolicy(
            30.0, {"cpu_ms": 4}, "projection-snapshot", "projection-resource"),
        clock)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_op, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock)
    original_clock = port.read_ingress_clock

    def paired_clock(requested_policy):
        reading = original_clock(requested_policy)
        reading.sample = SimpleNamespace(
            epoch="fixture-clock-epoch", source_id=clock.source_id)
        return reading

    port.read_ingress_clock = paired_clock
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    acquire_id = _op(coordinator, job_id)
    authority, worker_lease = _worker(
        coordinator, bootstrap, namespace, operation_id=acquire_id)
    job = coordinator.acquire_first_ingress_encoding_job_v3(
        authority, worker_lease, job_id, acquire_id, lease_seconds=30)
    authority = replace(authority, worker_fence=job.fence)
    binding, draft, anchor = coordinator.read_first_ingress_model_egress_preparation_v2(
        authority, worker_lease, job_id, acquire_id)
    model_permit = FencePermitV2(
        anchor.authority_id, anchor.namespace, job.lease_holder,
        "administrator", 1, "model_egress", acquire_id,
        "m" * 32, 1, 0, anchor)
    intent = ModelEgressIntentV1(
        **asdict(draft), fence_token=model_permit.token,
        fence_epoch=model_permit.fence_epoch,
        fence_revision=model_permit.revision,
        anchor_digest=canonical_digest(asdict(anchor)))
    response = {"text": json.dumps({
        "event_summary": "hello", "quoted_details": [],
        "possible_meanings": ["greeting"], "possible_feelings": []},
        sort_keys=True, separators=(",", ":"))}
    observation = ModelEgressObservationV1(
        intent.authority_id, intent.namespace, intent.subject,
        intent.operation_id, intent.call_id, intent.request_digest,
        "completed", canonical_serialize(response),
        (("output_tokens", 10),), (), "provider-ref")
    admission = ModelAdmissionV2(
        "f" * 64, intent.authority_id, intent.namespace, intent.subject,
        intent.operation_id, intent.call_id, intent.request_digest,
        intent.provider_config_digest, policy.installation_id,
        "1" * 64, "observer", "2" * 64, "3" * 64)
    terminal = ModelTerminalReceiptV2(
        admission.admission_id, intent.call_id, intent.request_digest,
        "4" * 64, observation.digest, "sha256:" + "5" * 64,
        policy.installation_id, admission.host_incarnation)
    record = ModelEgressRecoveryV1(
        intent, "observed", observation.digest, observation.usage, ())
    original_fact = (record, model_permit, admission, terminal)
    coordinator._GraphCoordinator__model_terminal_cost_port = (
        lambda actual: original_fact if actual == intent else None)
    coordinator._GraphCoordinator__accounting_maintenance_port = AccountingPort(
        store, original_fact)
    store._db.execute("""
        CREATE TABLE graph_original_model_cost_attempts_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            call_id TEXT NOT NULL, intent_digest TEXT NOT NULL,
            attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
            PRIMARY KEY(bot, persona, call_id), UNIQUE(attempt_id))
    """)
    quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
    coordinator.commit_first_ingress_model_cost_v1(
        bootstrap, namespace, intent, quote_id=quote_id,
        quote_version=int(quote_version))
    context = coordinator.read_first_ingress_original_model_result_context_v1(
        authority, worker_lease, job_id, acquire_id)
    request = first_ingress_worker_result_request_v1(context)
    read = WorkerModelResultReadV1(request, observation, terminal)
    read_permit = port.begin_fence(
        namespace=namespace, authority_namespace=anchor.namespace,
        holder="administrator", generation=1, operation="read",
        operation_id=request.read_attempt_id, expected_anchor=anchor)
    port.fences.finish_fence(
        read_permit, subject="subject", current_anchor=anchor,
        request_id="worker-result-finish:" + canonical_digest({
            "request": asdict(request), "permit": asdict(read_permit)}),
        request_digest="sha256:" + canonical_digest({
            "action": "finish_worker_result_read",
            "request": asdict(request), "permit": asdict(read_permit)}))
    fact_port = FinishedReadFactPort(store, port, intent, read, read_permit)
    coordinator._GraphCoordinator__worker_result_fact_port = fact_port
    try:
        yield (store, coordinator, bootstrap, namespace, policy, clock,
               intent, read, fact_port)
    finally:
        store.close()
        authority_db.close()


def test_first_ingress_c02_adopts_one_original_worker_result(c02_case):
    store, coordinator, bootstrap, _, policy, clock, intent, read, fact_port = c02_case
    receipt = coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy,
        AdminD06FirstIngressC02Policy(
            30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
        clock)
    assert receipt.status == "committed"
    assert fact_port.calls == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
        "('memory.episode.v1','memory.subjective_trace.v2')"
    ).fetchone() == (2,)
    job_phase, holder, expiry, result_ref = store._db.execute(
        "SELECT phase,lease_holder,lease_expires_utc,result_ref "
        "FROM runtime_jobs WHERE job_id=?", (read.request.job_id,),
    ).fetchone()
    assert (job_phase, holder, expiry) == ("completed", None, None)
    episode = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE type_name='memory.episode.v1'"
    ).fetchone()[0])
    assert result_ref == episode["episode_id"]
    job_projection = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE type_name='runtime.job'"
    ).fetchone()[0])
    assert (job_projection["phase"], job_projection["lease_holder"],
            job_projection["lease_expires_utc"],
            job_projection["result_ref"]) == (
                "completed", None, None, result_ref)
    replay = coordinator.commit_first_ingress_c02_v1(
        bootstrap, intent, read, policy,
        AdminD06FirstIngressC02Policy(
            30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
        clock)
    assert replay.status == "duplicate"
    assert fact_port.calls == 1
    with pytest.raises((EventConflict, ValueError)):
        coordinator.commit_first_ingress_c02_v1(
            bootstrap, replace(intent, provider_config_digest="d" * 64),
            read, policy,
            AdminD06FirstIngressC02Policy(
                30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
            clock)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
        "('memory.episode.v1','memory.subjective_trace.v2')"
    ).fetchone() == (2,)


@pytest.mark.parametrize("mutation", (
    "cancel", "revoke_access", "tamper_fact", "tamper_bundle_fact"))
def test_first_ingress_c02_rejects_lost_adoption_proof(c02_case, mutation):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, fact_port = c02_case
    if mutation == "cancel":
        store._db.execute(
            "UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?",
            (read.request.job_id,))
    elif mutation == "revoke_access":
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE type_name='memory.access' "
            "AND bot=? AND persona=?", namespace.as_tuple)
    else:
        current = fact_port.current_worker_result_read_fact

        def tampered(request):
            fact = current(request)
            if mutation == "tamper_bundle_fact":
                return replace(fact, bundle_digest="0" * 64)
            return replace(fact, result_digest="0" * 64)

        fact_port.current_worker_result_read_fact = tampered
    with pytest.raises((UnavailableGuard, ValueError, PermissionError)):
        coordinator.commit_first_ingress_c02_v1(
            bootstrap, intent, read, policy,
            AdminD06FirstIngressC02Policy(
                30.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
            clock)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name IN "
        "('memory.episode.v1','memory.subjective_trace.v2')"
    ).fetchone() == (0,)
