"""A settled original model call remains readable only by its current worker."""

from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressRecoveryV1, ModelTerminalReceiptV2,
)
from sylanne3.graph_coordinator import AuthorityDenied, GraphCoordinator, UnavailableGuard
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import AuthorityContext, canonical_digest

from test_current_model_egress_graph_verifier import (
    _case as _egress_case, token_ingress_system,  # noqa: F401
)
from test_first_encoding_cost_graph_commit import AccountingPort


def _settled_case(token_ingress_system):
    store, old_coordinator, _bootstrap, port, policy, clock, _, _ = token_ingress_system
    db, _, intent = _egress_case(token_ingress_system, production=True)
    namespace = policy.namespace
    anchor = port.current_anchor(
        namespace=namespace, authority_namespace=intent.namespace)
    permit = FencePermitV2(
        intent.authority_id, intent.namespace, intent.subject, "administrator",
        intent.authority_activation_generation, "model_egress",
        intent.operation_id, intent.fence_token, intent.fence_epoch,
        intent.fence_revision, anchor)
    assert canonical_digest(asdict(anchor)) == intent.anchor_digest
    record = ModelEgressRecoveryV1(
        intent, "observed", "e" * 64, (("output_tokens", 150),), ())
    admission = ModelAdmissionV2(
        "f" * 64, intent.authority_id, intent.namespace, intent.subject,
        intent.operation_id, intent.call_id, intent.request_digest,
        intent.provider_config_digest, policy.installation_id, "1" * 64,
        "observer", "2" * 64, "3" * 64)
    receipt = ModelTerminalReceiptV2(
        admission.admission_id, intent.call_id, intent.request_digest,
        "4" * 64, record.observation_digest, "sha256:" + "5" * 64,
        policy.installation_id, admission.host_incarnation)
    fact = (record, permit, admission, receipt)
    accounting = AccountingPort(store, fact)

    # Compose a restarted W01 against the same committed business store.
    # The old process authority is no longer used by this test.
    store._coordinator_capability = None
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        scene_clock_policy=clock,
        d02_issuer=old_coordinator._GraphCoordinator__d02_issuer,
        d11_issuer=old_coordinator._GraphCoordinator__d11_issuer,
        model_terminal_cost_port=lambda got: fact if got == intent else None,
        accounting_maintenance_port=accounting)
    coordinator.register_provider(
        bootstrap, "d11", *old_coordinator._GraphCoordinator__providers["d11"])
    job = get_job(db, intent.job_id)
    quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
    cost = coordinator.commit_first_ingress_model_cost_v1(
        bootstrap, namespace, intent,
        quote_id=quote_id, quote_version=int(quote_version))
    assert cost.status == "committed"
    assert get_budget_lease(db, job.budget_ref).reserved == {}
    assert get_budget_lease(db, job.budget_ref).used["output_tokens"] == 150

    acquire_id = db.execute(
        "SELECT acquire_operation_id FROM graph_job_acquire_receipts_v2 "
        "WHERE job_json LIKE ?", (f'%"job_id":"{job.job_id}"%',)
    ).fetchone()[0]
    lease, capability = coordinator.grant(
        bootstrap, actor=job.lease_holder, issuer_domain="d11",
        namespace=namespace, domains=("d11",),
        activation_generation=1, operation_id=acquire_id)
    authority = AuthorityContext(
        job.lease_holder, "d11", capability, namespace, ("activity",),
        "consolidation", ("conversation",), "policy-1", 1,
        worker_fence=job.fence)
    return db, store, coordinator, authority, lease, job, acquire_id, intent, port


def test_settled_original_model_has_content_free_worker_result_context(
        token_ingress_system):
    db, _, coordinator, authority, lease, job, acquire, intent, _ = (
        _settled_case(token_ingress_system))
    graph_changes = db.total_changes
    context = coordinator.read_first_ingress_original_model_result_context_v1(
        authority, lease, job.job_id, acquire)
    assert db.total_changes == graph_changes
    assert (context.job_id, context.acquire_operation_id,
            context.original_operation_id, context.call_id) == (
                job.job_id, acquire, job.operation_id, intent.call_id)
    assert context.model_request_digest == intent.request_digest
    assert context.installation_id == "installation"
    assert context.worker_fence == job.fence
    assert "request_json" not in asdict(context)
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_model_egress_preparation_v2(
            authority, lease, job.job_id, acquire)
    assert db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='runtime.cost_settlement'"
    ).fetchone()[0] == 1


@pytest.mark.parametrize("mutation", ["job", "cancel", "source", "access"])
def test_current_worker_or_source_change_holds(token_ingress_system, mutation):
    db, _, coordinator, authority, lease, job, acquire, _, _ = (
        _settled_case(token_ingress_system))
    if mutation == "job":
        db.execute("UPDATE runtime_jobs SET lease_holder='other' WHERE job_id=?",
                   (job.job_id,))
    elif mutation == "cancel":
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?",
                   (job.job_id,))
    elif mutation == "source":
        db.execute("UPDATE graph_atoms SET valid=0 WHERE type_name='memory.source'")
    else:
        db.execute("UPDATE graph_atoms SET valid=0 WHERE type_name='memory.access'")
    db.commit()
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_original_model_result_context_v1(
            authority, lease, job.job_id, acquire)


def test_original_binding_or_graph_incarnation_change_holds(token_ingress_system):
    db, _, coordinator, authority, lease, job, acquire, _, _ = (
        _settled_case(token_ingress_system))
    original = db.execute(
        "SELECT requirements_json FROM graph_recovery_metadata_v2"
    ).fetchone()[0]
    changed = json.loads(original)
    changed["graph_incarnation"] = "another-incarnation"
    db.execute("UPDATE graph_recovery_metadata_v2 SET requirements_json=?",
               (json.dumps(changed, sort_keys=True, separators=(",", ":")),))
    db.commit()
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_original_model_result_context_v1(
            authority, lease, job.job_id, acquire)
    db.execute("UPDATE graph_recovery_metadata_v2 SET requirements_json=?",
               (original,))
    with pytest.raises(AuthorityDenied):
        coordinator.read_first_ingress_original_model_result_context_v1(
            authority, lease, job.job_id, acquire + "-wrong")
    db.execute("DELETE FROM runtime_resource_quotes")
    db.commit()
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_original_model_result_context_v1(
            authority, lease, job.job_id, acquire)


def test_current_authority_anchor_change_holds(token_ingress_system):
    _, _, coordinator, authority, lease, job, acquire, _, port = (
        _settled_case(token_ingress_system))
    old = port.anchors[authority.namespace]
    port.anchors[authority.namespace] = replace(
        old, deletion_seq=1, deletion_digest="sha256:" + "9" * 64,
        revocation_epoch=1)
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_original_model_result_context_v1(
            authority, lease, job.job_id, acquire)
