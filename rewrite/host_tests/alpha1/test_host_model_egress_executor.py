"""Executor control-flow fixture; the paired RPC has a separate real TLS test."""

import hashlib
import json
import sqlite3
import sys
from dataclasses import asdict, replace
from pathlib import Path
from types import MethodType
from uuid import uuid4

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.tests.alpha1.runtime.test_natural_reply_job_v2 import (
    _case as natural_case, _generation_call,
)
from sylanne3.authority_service.natural_original_binding_verifier import (
    PinnedNaturalOriginalCallIdentityVerifierV2,
)
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressDraftV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.model_egress_executor import (
    HostModelEgressExecutor, _bound_model_admission_v1,
)
from sylanne3.host import astrbot_model_call as model_call_module
from sylanne3.host.authority_profile import AdminModelWorkflowsV2
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.model_broker.natural_reply import (
    NaturalReplyInstallationV2, TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION,
    freeze_natural_reply_request_v2,
)
from sylanne3.model_broker.natural_review import (
    NaturalReviewInstallationV1, REVIEW_TEMPLATE_DIGEST,
    REVIEW_TEMPLATE_VERSION, freeze_natural_reply_review_v1,
)
from sylanne3.runtime.jobs import (
    acquire_job, create_job, install_schema as jobs_schema,
    transition_job,
)
from sylanne3.runtime.natural_reply_job_v2 import (
    bind_original_call, install_schema as natural_schema,
    natural_job_ids_v2, read_original_preparation, record_terminal,
    save_original_preparation,
)
from sylanne3.runtime_contracts import (
    NaturalReplyReviewOriginalSealV2,
)
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from sylanne3.runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
from sylanne3.runtime.original_model_result_context import OriginalModelResultContextV1
from sylanne3.runtime_contracts import InstallationGrantV2, canonical_digest


@pytest.fixture(autouse=True)
def isolated_model_capacity(monkeypatch):
    """Separate unit Hosts; keep unknown occupancy throughout each test."""
    monkeypatch.setattr(model_call_module, "_calls", {})
    monkeypatch.setattr(model_call_module, "_admissions", {})


def _numeric_installed_adapter(host):
    from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
    from sylanne3.model_broker.internal_life_numeric_v1 import WORK_KIND, TEMPLATE_VERSION
    bundle, encoder, replier = host.v2_adapters()
    numeric = replace(encoder._admin_model, work_kind=WORK_KIND, template_version=TEMPLATE_VERSION)
    policy = replace(bundle.installation_policy, root_grant=replace(bundle.installation_policy.root_grant,
        allowed_work_kinds=(*bundle.installation_policy.root_grant.allowed_work_kinds, WORK_KIND)))
    bundle = replace(bundle, installation_policy=policy,
        model_workflows=AdminModelWorkflowsV3(3, encoder._admin_model, replier._admin_model, life_numeric=numeric))
    adapter = AstrBotModelProvider(context=host.context, host_loop=host.adapter._host_loop,
        trusted_umo=model_fixture.UMO, descriptor=replace(host.descriptor, purposes=frozenset({'consolidation'})),
        admin_model=numeric, installation_bundle=bundle)
    return bundle, adapter


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ('installed', 'equal_copy', 'unknown', 'foreign_bundle', 'wrong_config'))
async def test_life_numeric_executor_requires_exact_installed_slot(mutation):
    host = model_fixture.AstrBotModelCallTests(methodName='test_one_http_request_on_host_loop_with_usage')
    await host.asyncSetUp()
    try:
        bundle, adapter = _numeric_installed_adapter(host)
        _intent, _anchor, _permit, _admission, grant, authority = fixture_values(
            host, model_fixture.call_request(), bundle=bundle, adapter=adapter)
        if mutation == 'equal_copy':
            adapter._admin_model = replace(adapter._admin_model)
        elif mutation == 'unknown':
            adapter._admin_model = replace(adapter._admin_model, work_kind='unknown.numeric')
        elif mutation == 'foreign_bundle':
            bundle = replace(bundle)
        elif mutation == 'wrong_config':
            from sylanne3.host.authority_profile import installed_model_config_ref
            model = adapter._admin_model
            adapter._admin_model = replace(model, provider_config_digest='f' * 64,
                provider_config_ref=installed_model_config_ref(model.provider_id, model.model_id, 'f' * 64))
        if mutation == 'installed':
            executor = HostModelEgressExecutor(authority=authority, bundle=bundle, grant=grant, adapter=adapter)
            assert executor._adapter._admin_model is bundle.model_workflows.life_numeric
            assert executor._bundle is adapter._installation_bundle
        else:
            with pytest.raises(ValueError):
                HostModelEgressExecutor(authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        assert host.requests == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ('installed', 'unknown_slot', 'wrong_kind', 'wrong_purpose', 'wrong_template', 'wrong_config'))
async def test_v3_numeric_profile_decodes_only_the_formal_contract(mutation):
    from dataclasses import fields
    from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3, model_workflows_v3_from_payload
    host = model_fixture.AstrBotModelCallTests(methodName='test_one_http_request_on_host_loop_with_usage')
    await host.asyncSetUp()
    try:
        bundle, _adapter = _numeric_installed_adapter(host)
        raw = {'version': 3}
        for name in ('encode', 'reply', 'life_numeric'):
            model = getattr(bundle.model_workflows, name)
            row = {field.name: getattr(model, field.name) for field in fields(model)}
            row.update(audiences=list(model.audiences), required_capabilities=list(model.required_capabilities),
                       quote_ceiling=dict(model.quote_ceiling))
            raw[name] = row
        if mutation == 'unknown_slot':
            raw['unknown_numeric'] = raw['life_numeric']
        elif mutation != 'installed':
            field = {'wrong_kind': 'work_kind', 'wrong_purpose': 'purpose', 'wrong_template': 'template_version',
                     'wrong_config': 'provider_config_ref'}[mutation]
            raw['life_numeric'][field] = 'wrong'
        if mutation == 'installed':
            decoded = model_workflows_v3_from_payload(raw)
            assert type(decoded) is AdminModelWorkflowsV3 and decoded == bundle.model_workflows
            assert decoded.life_numeric is not bundle.model_workflows.life_numeric
        else:
            with pytest.raises(ValueError):
                model_workflows_v3_from_payload(raw)
        assert host.requests == []
    finally:
        await host.asyncTearDown()


def fixture_values(host, request, *, bundle, adapter):
    policy = bundle.installation_policy
    model = adapter._admin_model
    # This control-flow fixture supplies RPC replies; TLS itself is tested separately.
    bundle.tls_profile.profile_id = "default"
    grant = InstallationGrantV2(
        policy.expected_authority_id, "mtls:sha256:" + "a" * 64,
        policy.administrator_holder, policy.installation_id,
        policy.manifest_digest, "policy", "v2", "b" * 64)
    anchor = RestoreAnchor(
        grant.authority_id, policy.authority_namespace, 1, "deletion", 0,
        "genesis", "execution", 0, "genesis", 0, "proof")
    original = model_intent(
        authority_id=grant.authority_id, namespace=policy.authority_namespace,
        subject=grant.subject,
        call_id=request.call_id, operation_id=request.identity.operation_id,
        request_digest=request.digest, anchor_digest=canonical_digest(asdict(anchor)),
        provider_id=model.provider_id, model_id=model.model_id,
        provider_config_digest=model.provider_config_digest,
        budget_lease_id=request.envelope.parent_budget_lease_ref,
        max_output_tokens=request.max_output_tokens,
        budget_ceiling=(("output_tokens", 128),))
    permit = FencePermitV2(
        original.authority_id, original.namespace, original.subject,
        grant.administrator_holder, original.authority_activation_generation,
        "model_egress", original.operation_id, original.fence_token,
        original.fence_epoch, original.fence_revision, anchor)
    admission = ModelAdmissionV2(
        hashlib.sha256(request.call_id.encode()).hexdigest(),
        original.authority_id, original.namespace, original.subject,
        original.operation_id, original.call_id, original.request_digest,
        original.provider_config_digest, grant.installation_id,
        grant.subject.removeprefix("mtls:sha256:"),
        bundle.tls_profile.profile_id, grant.manifest_digest,
        adapter.host_incarnation)
    authority = AuthorityClient(
        AuthoritySelection(), package_root=Path.cwd(), data_dir=Path.cwd())
    assert _bound_model_admission_v1(
        adapter, bundle, grant, original, permit, admission)
    return original, anchor, permit, admission, grant, authority

def _natural_originals(host, path):
    """Durable original rows only; this fixture supplies no current graph grant."""
    bundle, encoder, replier = host.v2_adapters()
    worker = "mtls:sha256:" + "a" * 64
    namespace, parent, generation_seal, sample, versions, queries, job = (
        natural_case())
    parent = "c02-original:" + uuid4().hex
    generation_ids = natural_job_ids_v2(namespace, parent, "generation")
    generation_seal = replace(
        generation_seal, c02_operation_id=parent,
        job_id=generation_ids[0], original_operation_id=generation_ids[1],
        acquire_operation_id=generation_ids[2], call_id=generation_ids[3],
        reservation_operation_id=generation_ids[4])
    job = replace(job, job_id=generation_ids[0],
                  operation_id=generation_ids[1])
    config = replier._admin_model
    audience = sample.input.plan.audience_ref.ref
    generation = replace(
        config, work_kind="natural_generation",
        template_version=NATURAL_TEMPLATE_VERSION, audiences=(audience,))
    review = replace(
        config, work_kind="natural_review",
        template_version=REVIEW_TEMPLATE_VERSION, audiences=(audience,))
    policy = replace(bundle.installation_policy, root_grant=replace(
        bundle.installation_policy.root_grant,
        allowed_work_kinds=("d06.encode_source", "reply",
                            "natural_generation", "natural_review")))
    bundle = replace(bundle, installation_policy=policy,
                     model_workflows=AdminModelWorkflowsV2(
                         2, encoder._admin_model, config,
                         natural_generation=generation, natural_review=review))
    frozen = freeze_natural_reply_request_v2(
        sample.input, NaturalReplyInstallationV2(
            "install", config.provider_config_digest,
            config.provider_id, config.model_id,
            generation.max_output_tokens))
    generation_seal = replace(
        generation_seal, installation_id="install",
        provider_config_digest=config.provider_config_digest,
        frozen_input_digest=frozen.frozen_input_digest,
        model_request_digest=frozen.model_request_digest)
    gen_call = _generation_call(
        namespace, generation_seal, frozen, versions, queries)
    gen_call = replace(
        gen_call,
        envelope=replace(gen_call.envelope, authority=replace(
            gen_call.envelope.authority,
            actor=worker,
            provider_policy_ref=config.provider_config_ref)),
        provider_id=config.provider_id, model_id=config.model_id,
        payload=json.loads(frozen.canonical_wire),
        timeout_seconds=config.timeout_seconds,
        max_output_tokens=config.max_output_tokens)
    output = {
        "schema": "sylanne.d09.context_reply_output.v2", "body": "Hello.",
        "units": [{"start": 0, "end": 6, "kind": "rhetoric",
                   "basis_ids": ["basis:greeting"], "speech_act": "rhetoric",
                   "promise_grant_id": None, "slot_ids": []}],
    }
    review_frozen = freeze_natural_reply_review_v1(
        generation_seal, output, sample.input.plan.units, (), "policy:review",
        NaturalReviewInstallationV1(
            "install", config.provider_id, config.provider_config_digest,
            config.model_id, review.max_output_tokens))
    review_ids = natural_job_ids_v2(namespace, parent, "review")
    review_seal = NaturalReplyReviewOriginalSealV2(
        namespace=namespace, installation_id="install",
        provider_config_digest=config.provider_config_digest,
        job_id=review_ids[0], original_operation_id=review_ids[1],
        acquire_operation_id=review_ids[2], call_id=review_ids[3],
        generation_original_operation_id=generation_seal.original_operation_id,
        generation_call_id=generation_seal.call_id,
        generation_frozen_input_digest=generation_seal.frozen_input_digest,
        generation_output_digest=review_frozen.generation_output_digest,
        qualified_units_digest=generation_seal.qualified_units_digest,
        review_frozen_input_digest=review_frozen.digest,
        model_request_digest=review_frozen.wire_digest,
        original_graph_guard_digest=generation_seal.original_graph_guard_digest,
        parent_budget_lease_id=generation_seal.parent_budget_lease_id,
        reservation_operation_id=review_ids[4],
        review_policy_version="policy:review")
    review_call = replace(
        gen_call, envelope=replace(
            gen_call.envelope, identity=replace(
                gen_call.envelope.identity, phase="natural_review",
                operation_id=review_seal.acquire_operation_id)),
        call_id=review_seal.call_id,
        prompt_template_digest=REVIEW_TEMPLATE_DIGEST,
        payload=json.loads(review_frozen.canonical_wire))
    with sqlite3.connect(path) as db:
        jobs_schema(db)
        natural_schema(db)
        db.execute("BEGIN")
        create_job(db, job, "create:generation", "1" * 64)
        saved = save_original_preparation(
            db, stage="generation", namespace=namespace,
            parent_original_id=parent, seal=generation_seal, frozen=frozen,
            read_versions=versions, query_epochs=queries, graph_epoch=2,
            access_epoch=3, deletion_epoch=4, job=job)
        running = acquire_job(db, job.job_id, worker,
                              now_utc="2026-09-28T00:00:00Z", lease_seconds=30)
        bind_original_call(db, saved, running, gen_call)
        acquired = read_original_preparation(db, namespace, parent, "generation")
        completed = transition_job(db, job.job_id, worker,
                                   running.fence,
                                   target_phase="completed",
                                   result_ref="controlled-generation-result")
        record_terminal(
            db, acquired, completed, terminal_receipt_digest="2" * 64,
            output_digest=review_frozen.generation_output_digest)
        review_job = replace(
            job, job_id=review_seal.job_id,
            operation_id=review_seal.original_operation_id,
            work_kind="natural_review")
        create_job(db, review_job, "create:review", "3" * 64)
        saved_review = save_original_preparation(
            db, stage="review", namespace=namespace,
            parent_original_id=parent, seal=review_seal,
            frozen=review_frozen, read_versions=versions,
            query_epochs=queries, graph_epoch=2, access_epoch=3,
            deletion_epoch=4, job=review_job)
        running_review = acquire_job(
            db, review_job.job_id, worker,
            now_utc="2026-09-28T00:00:00Z", lease_seconds=30)
        bind_original_call(db, saved_review, running_review, review_call)
        db.commit()
    verifier = PinnedNaturalOriginalCallIdentityVerifierV2(
        path, installation_id="install", generation=generation, review=review)
    reads = {stage: verifier.read(namespace, parent, stage)
             for stage in ("generation", "review")}
    assert all(read is not None for read in reads.values())
    return bundle, reads


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ("generation", "review"))
@pytest.mark.parametrize("uncertain", (False, True))
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="natural original preparation requires the formal Linux fcntl package reader",
)
async def test_natural_executor_requires_original_binding_and_authority_admission(
        tmp_path, stage, uncertain):
    """A controlled Authority reply exercises host mechanics, not graph currentness."""
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, reads = _natural_originals(host, tmp_path / "natural-graph.db")
        original = reads[stage]
        workflow = (bundle.model_workflows.natural_generation
                    if stage == "generation" else bundle.model_workflows.natural_review)
        adapter = AstrBotModelProvider(
            context=host.context, host_loop=host.adapter._host_loop,
            trusted_umo=model_fixture.UMO, descriptor=host.descriptor,
            admin_model=workflow, installation_bundle=bundle)
        request = original.request
        intent, anchor, permit, admission, grant, authority = fixture_values(
            host, request, bundle=bundle, adapter=adapter)
        anchor = replace(
            anchor, namespace=bundle.installation_policy.authority_namespace)
        intent = replace(
            intent, namespace=anchor.namespace,
            anchor_digest=canonical_digest(asdict(anchor)),
            subject=request.envelope.authority.actor,
            operation_id=original.seal.acquire_operation_id,
            call_id=original.seal.call_id, request_digest=request.digest,
            job_id=original.seal.job_id, worker_fence=original.worker_fence,
            budget_lease_id=original.seal.parent_budget_lease_id,
            budget_reservation_operation_id=original.seal.reservation_operation_id,
            budget_ceiling=(("output_tokens", workflow.max_output_tokens),),
            provider_id=workflow.provider_id, model_id=workflow.model_id,
            provider_config_digest=workflow.provider_config_digest,
            max_output_tokens=workflow.max_output_tokens,
            acquire_operation_id=original.seal.acquire_operation_id,
            binding_digest=canonical_digest({
                "original_seal_digest": canonical_digest(asdict(original.seal)),
                "model_call_request_digest": request.digest,
                "worker_fence": original.worker_fence,
            }))
        permit = replace(
            permit, namespace=anchor.namespace, subject=intent.subject,
            operation_id=intent.operation_id, pinned_anchor=anchor)
        admission = replace(
            admission, namespace=anchor.namespace, subject=intent.subject,
            operation_id=intent.operation_id,
            call_id=intent.call_id, request_digest=intent.request_digest,
            provider_config_digest=intent.provider_config_digest)
        assert _bound_model_admission_v1(
            adapter, bundle, grant, intent, permit, admission)
        calls = []

        async def capacity(self, actual_bundle, actual_grant, *,
                           expected_anchor, draft, close_prepared=False):
            calls.append("capacity")
            assert actual_bundle is bundle and actual_grant is grant
            assert type(draft) is ModelEgressDraftV1
            assert draft == ModelEgressDraftV1.from_intent(intent)
            assert expected_anchor == anchor and close_prepared is False
            assert draft.subject == grant.subject
            pending = model_call_module._calls[request.call_id]
            assert pending.digest == request.digest and pending.stage == "prepare_reserved"
            assert model_call_module._admissions == {}
            return {
                "status": "absent", "global_count": 0, "namespace_count": 0,
                "background_count": 0, "namespace_background_count": 0,
                "capacity_available": True,
                "selected_admission_count": 0, "selected_observation_count": 0,
                "call_id": draft.call_id, "request_digest": draft.request_digest,
                "authority_id": grant.authority_id, "namespace": draft.namespace,
                "subject": grant.subject, "installation_id": grant.installation_id,
                "current_anchor_digest": canonical_digest(asdict(anchor)),
                "draft_digest": canonical_digest(asdict(draft)),
            }

        async def prepare(self, *args, **kwargs):
            calls.append("prepare")
            assert kwargs["draft"] == ModelEgressDraftV1.from_intent(intent)
            kwargs["_on_dispatch"]()
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        async def terminal_fact(self, *args, **kwargs):
            calls.append("terminal_fact")
            return ModelEgressRecoveryV1(intent, "prepared"), permit, admission, None

        async def recover(self, *args, **kwargs):
            calls.append("recover")
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        async def admit(self, *args, **kwargs):
            calls.append("admit")
            kwargs["_on_dispatch"]()
            assert kwargs["model_request"] == request
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def complete(self, *args, **kwargs):
            calls.append("complete")
            if uncertain:
                raise RuntimeError("terminal response lost")
            report = kwargs["report"]
            observed = report.observation_for(intent)
            receipt = ModelTerminalReceiptV2(
                admission.admission_id, intent.call_id, intent.request_digest,
                report.digest, observed.digest,
                AuthorityV2FenceStore.model_terminal_finish_digest(
                    intent, permit, "completed", observed.digest),
                admission.installation_id, admission.host_incarnation)
            return (ModelEgressRecoveryV1(
                intent, "observed", observed.digest, report.usage,
                report.cost), permit, receipt)

        authority.model_capacity_reconcile_v1 = MethodType(capacity, authority)
        authority.model_prepare_fenced_v1 = MethodType(prepare, authority)
        authority.model_terminal_fact_v2 = MethodType(terminal_fact, authority)
        authority.model_recover_fenced_v1 = MethodType(recover, authority)
        authority.model_admit_dispatch_once_v2 = MethodType(admit, authority)
        authority.model_complete_observed_v2 = MethodType(complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request,
            natural_original=reads["review" if stage == "generation" else
                                   "generation"]) is None
        other_workflow = (
            bundle.model_workflows.natural_review if stage == "generation"
            else bundle.model_workflows.natural_generation)
        wrong_adapter = AstrBotModelProvider(
            context=host.context, host_loop=host.adapter._host_loop,
            trusted_umo=model_fixture.UMO, descriptor=host.descriptor,
            admin_model=other_workflow, installation_bundle=bundle)
        wrong_executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant,
            adapter=wrong_adapter)
        assert await wrong_executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request,
            natural_original=original) is None
        assert calls == [] and host.requests == []
        assert await executor.execute_frozen_natural_once(
            original=original,
            draft=replace(ModelEgressDraftV1.from_intent(intent),
                          binding_digest="e" * 64),
            expected_anchor=anchor) is None
        assert calls == [] and host.requests == []
        result = await executor.execute_frozen_natural_once(
            original=original, draft=ModelEgressDraftV1.from_intent(intent),
            expected_anchor=anchor)
        assert result is not None
        assert (result.terminal is None) == uncertain
        assert result.intent == intent and result.original == original
        assert calls == (["capacity", "prepare", "terminal_fact", "recover", "admit",
                          "complete"] + (["terminal_fact"] if uncertain else []))
        sent = json.loads(host.requests[0][1].content)
        assert "provider_id" not in sent
        assert sent["messages"] == request.payload["messages"]
        assert len(host.requests) == 1
        assert await executor.execute_frozen_natural_once(
            original=original, draft=ModelEgressDraftV1.from_intent(intent),
            expected_anchor=anchor) is None
        assert len(host.requests) == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_executor_reports_only_actual_completed_response():
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(
            host, request, bundle=host.bundle, adapter=host.adapter)
        observed = []

        async def admit(self, *args, **kwargs):
            observed.append("admit")
            kwargs["_on_dispatch"]()
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def complete(self, *args, **kwargs):
            report = kwargs["report"]
            observed.append(report)
            observation = report.observation_for(intent)
            receipt = ModelTerminalReceiptV2(
                admission.admission_id, intent.call_id, intent.request_digest,
                report.digest, observation.digest,
                AuthorityV2FenceStore.model_terminal_finish_digest(
                    intent, permit, "completed", observation.digest),
                admission.installation_id, admission.host_incarnation)
            return (ModelEgressRecoveryV1(
                intent, "observed", observation.digest,
                report.usage, report.cost), permit, receipt)

        authority.model_admit_dispatch_once_v2 = MethodType(admit, authority)
        authority.model_complete_observed_v2 = MethodType(complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        receipt = await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request)
        assert receipt is not None and receipt.report_digest == observed[1].digest
        assert observed[0] == "admit"
        assert observed[1].result_json == '{"text":"hello"}'
        assert len(host.requests) == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_v2_executor_rejects_borrowed_workflow_quote_before_authority():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, encoder, replier = host.v2_adapters()
        request = model_fixture.call_request()
        request = replace(request, envelope=replace(
            request.envelope, authority=replace(
                request.envelope.authority, purpose="consolidation")),
            prompt_template_digest=FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST)
        intent, anchor, _permit, _admission, grant, authority = fixture_values(
            host, request, bundle=bundle, adapter=encoder)
        called = []

        async def forbidden_admit(self, *args, **kwargs):
            called.append(True)
            raise AssertionError("borrowed quote must not reach Authority")

        authority.model_admit_dispatch_once_v2 = MethodType(
            forbidden_admit, authority)
        encoder_executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=encoder)
        assert encoder._request_allowed(request)
        assert await encoder_executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert not called and not host.requests
        replier_executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=replier)
        assert await replier_executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert not called and not host.requests
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("admit", "http"))
async def test_executor_holds_on_uncertain_admit_or_incomplete_http(failure):
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(
            host, request, bundle=host.bundle, adapter=host.adapter)
        admits = 0

        async def admitted(self, *args, **kwargs):
            nonlocal admits
            admits += 1
            kwargs["_on_dispatch"]()
            if failure == "admit":
                raise RuntimeError("admit response lost after dispatch")
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def forbidden_complete(self, *args, **kwargs):
            raise AssertionError("incomplete response cannot be reported")

        authority.model_admit_dispatch_once_v2 = MethodType(admitted, authority)
        authority.model_complete_observed_v2 = MethodType(forbidden_complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        host.status = 500
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        expected_http_calls = 0 if failure == "admit" else 1
        assert len(host.requests) == expected_http_calls and admits == 1
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == expected_http_calls and admits == 1
    finally:
        await host.asyncTearDown()

@pytest.mark.asyncio
async def test_lost_terminal_reply_holds_without_second_http():
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(
            host, request, bundle=host.bundle, adapter=host.adapter)
        admits = 0
        reports = 0

        async def admit(self, *args, **kwargs):
            nonlocal admits
            admits += 1
            kwargs["_on_dispatch"]()
            if admits > 1:
                raise RuntimeError("admission already consumed")
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def lost_complete(self, *args, **kwargs):
            nonlocal reports
            reports += 1
            raise RuntimeError("terminal reply lost")

        authority.model_admit_dispatch_once_v2 = MethodType(admit, authority)
        authority.model_complete_observed_v2 = MethodType(lost_complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1 and reports == 1
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1 and reports == 1 and admits == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", [True, False])
async def test_acquired_recovery_reads_observed_terminal_without_model_admission(
        observed):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, encoder, _ = host.v2_adapters()
        request = model_fixture.call_request()
        original, anchor, permit, admission, grant, authority = fixture_values(
            host, request, bundle=bundle, adapter=encoder)
        anchor = replace(
            anchor, namespace=bundle.installation_policy.authority_namespace)
        original = replace(
            original, namespace=anchor.namespace, subject=grant.subject,
            anchor_digest=canonical_digest(asdict(anchor)),
            access_revisions=((original.source_refs[0], 3),),
            acquire_operation_id=original.operation_id,
            binding_digest="e" * 64)
        context = OriginalModelResultContextV1(
            bundle.installation_policy.namespace, original.authority_id,
            original.namespace, grant.installation_id, "incarnation-1",
            original.graph_revision + 7, original.graph_epoch + 2,
            original.access_epoch, original.delete_epoch,
            original.job_id, original.operation_id,
            original.budget_reservation_operation_id,
            original.call_id, original.binding_digest, original.request_digest,
            original.source_refs[0], original.source_revisions[0][1],
            original.access_revisions[0][1], original.subject,
            original.worker_fence, "2030-01-01T00:00:00Z", anchor)
        consumer_id = first_ingress_c02_consumer_operation_id_v1(
            namespace=context.namespace, authority_id=context.authority_id,
            authority_namespace=context.authority_namespace,
            installation_id=context.installation_id, job_id=context.job_id,
            acquire_operation_id=context.acquire_operation_id,
            original_operation_id=context.original_operation_id,
            call_id=context.call_id, binding_digest=context.binding_digest,
            model_request_digest=context.model_request_digest)
        item = FirstIngressRecoveryItemV1(
            bundle.installation_policy.namespace, grant.installation_id,
            original.job_id, original.operation_id,
            original.budget_reservation_operation_id, original.call_id,
            original.binding_digest, original.request_digest, consumer_id,
            "running", original.subject, original.worker_fence,
            "2030-01-01T00:00:00Z", "original_fence", None, None)
        terminal = ModelTerminalReceiptV2(
            admission.admission_id, original.call_id,
            original.request_digest, "a" * 64, "b" * 64,
            AuthorityV2FenceStore.model_terminal_finish_digest(
                original, permit, "completed", "b" * 64), grant.installation_id,
            admission.host_incarnation)
        assert _bound_model_admission_v1(
            encoder, bundle, grant, original, permit, admission)
        calls = []

        async def lookup(self, *args, **kwargs):
            calls.append("lookup")
            assert kwargs["lookup"].acquire_operation_id == item.acquire_operation_id
            return original

        async def terminal_fact(self, *args, **kwargs):
            calls.append("terminal")
            assert kwargs["intent"] == original
            if observed:
                return (ModelEgressRecoveryV1(original, "observed", "b" * 64),
                        permit, admission, terminal)
            return (ModelEgressRecoveryV1(original, "dispatch_started"),
                    permit, admission, None)

        async def forbidden_admit(self, *args, **kwargs):
            raise AssertionError("recovery must not admit a second model call")

        authority.model_original_intent_lookup_v1 = MethodType(lookup, authority)
        authority.model_terminal_fact_v2 = MethodType(terminal_fact, authority)
        authority.model_admit_dispatch_once_v2 = MethodType(
            forbidden_admit, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=encoder)
        result = await executor.recover_observed_frozen_encoding(
            context=context, original=item)
        assert calls == ["lookup", "terminal"]
        assert result is not None
        assert result.terminal == (terminal if observed else None)
        assert host.requests == []
    finally:
        await host.asyncTearDown()
