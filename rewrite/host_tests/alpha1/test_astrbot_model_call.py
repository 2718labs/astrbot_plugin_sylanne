"""Single-attempt AstrBot/OpenAI SDK calls through a local HTTP transport."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import threading
import unittest
from types import SimpleNamespace
from uuid import uuid4

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderType
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
import httpx
from openai import AsyncOpenAI

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.astrbot_model_call import AstrBotModelProvider, LocalModelAdmission
from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from sylanne3.host.authority_profile import (
    AdminIngressEncodingPolicy, AdminIngressModelPolicy,
    AdminModelWorkflowV2, AdminModelWorkflowsV2,
    AdminInstallationBundle, installed_model_config_ref,
)
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.model_broker.broker import ModelCallRequest, ModelProviderDescriptor
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from sylanne3.model_broker.reply_language import (
    REPLY_TEMPLATE_VERSION, ReplySourceSnapshot, freeze_installed_reply_request_v1,
    parse_reply_result_v1,
)
from sylanne3.model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_DIGEST, CONTEXT_REPLY_TEMPLATE_VERSION,
    ContextReplyInstallationV1, freeze_context_reply_request_v1,
)
from sylanne3.model_broker.d13_precompression import (
    freeze_d13_precompression_request_v1,
)
from sylanne3.model_broker.natural_reply import (
    NaturalReplyInstallationV2, TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION,
    freeze_natural_reply_request_v2,
)
from sylanne3.model_broker.natural_review import (
    NaturalReviewInstallationV1, REVIEW_TEMPLATE_DIGEST,
    REVIEW_TEMPLATE_VERSION, freeze_natural_reply_review_v1,
)
from sylanne3.model_broker.d04_appraisal import (
    AppraisalInstallationV1, TEMPLATE_DIGEST as APPRAISAL_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as APPRAISAL_TEMPLATE_VERSION,
    WORK_KIND as APPRAISAL_WORK_KIND, freeze_appraisal_request_v1,
)
from rewrite.tests.alpha1.model_broker.test_d04_appraisal import _frozen as appraisal_case
from rewrite.tests.alpha1.model_broker.test_d13_precompression import _planned as d13_plan_case
from rewrite.tests.alpha1.contracts.test_context_reply_contract import example_input
from rewrite.tests.alpha1.runtime.test_natural_reply_job_v2 import _case as natural_case
from sylanne3.memory_types import SourceRecord, source_key, access_key
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)


UMO = "platform-1:FriendMessage:123456"


class Manager:
    def __init__(self, provider):
        self.provider_insts = [provider]
        self.inst_map = {"provider-1": provider}
        self.selected = provider
        self.seen_umo = []
        self.on_selection = None

    def get_using_provider(self, *, provider_type, umo):
        assert provider_type is ProviderType.CHAT_COMPLETION
        self.seen_umo.append(umo)
        if self.on_selection is not None:
            self.on_selection(len(self.seen_umo))
        return self.selected

    async def get_using_provider_async(self, *, provider_type, umo):
        return self.get_using_provider(provider_type=provider_type, umo=umo)


def call_request():
    namespace = NamespaceId("bot", "persona")
    key = AtomKey(Owner("persona", "bot", "persona"), "state", "model")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity", None, "attempt", "propose", "operation",
                          canonical_digest({"input_refs": ["input"]})),
        AuthorityContext("actor", "d07", "cap", namespace, ("persona",),
                         "proposal", ("owner",), "policy", 1),
        VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "all", 0),),
                     0, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification(("source",), "reported", None, 1.0,
                            "external_report", "qualified", None, "actual"),
        ("input",), "budget", 2.0, 1.0, "clock", (),
    )
    return ModelCallRequest(
        envelope, uuid4().hex, "provider-1", "model-1", frozenset({"text"}),
        "private", "a" * 64, {"prompt": "say hello"}, 0.2, 64,
    )


def successful_completion():
    return {
        "id": "remote-1", "object": "chat.completion", "created": 1,
        "model": "model-1", "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "hello"},
        }],
        "usage": {
            "prompt_tokens": 3, "completion_tokens": 3, "total_tokens": 6,
            "prompt_tokens_details": {"cached_tokens": 1},
        },
    }


class AstrBotModelCallTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.host_thread = threading.get_ident()
        self.requests = []
        self.status = 200
        self.transport_error = None
        self.completion = successful_completion()
        self.request_started = asyncio.Event()
        self.response_gate = None

        async def respond(request):
            self.requests.append((threading.get_ident(), request))
            self.request_started.set()
            if self.response_gate is not None:
                await self.response_gate.wait()
            if self.transport_error is not None:
                raise self.transport_error
            if self.status != 200:
                return httpx.Response(self.status, json={"error": {"message": "test error"}})
            return httpx.Response(200, json=self.completion)

        self.http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        self.shared_client = AsyncOpenAI(
            api_key="test-only", base_url="https://mock.invalid/v1",
            http_client=self.http_client, max_retries=2,
        )
        self.provider = object.__new__(ProviderOpenAIOfficial)
        self.provider.provider_config = {
            "id": "provider-1", "type": "openai_chat_completion", "model": "model-1",
        }
        self.provider.model_name = "model-1"
        self.provider.client = self.shared_client
        self.manager = Manager(self.provider)
        self.context = Context(
            asyncio.Queue(), {}, None, self.manager, None, None,
            None, None, None, None, None,
        )
        self.descriptor = ModelProviderDescriptor(
            "provider-1", "astrbot-4.28.1", "model-1",
            frozenset({"text"}), frozenset({"proposal"}),
            frozenset({"private"}), "credential:astrbot-installed",
            "unknown", False, False,
        )
        config_digest = canonical_digest(self.provider.provider_config)
        self.admin_model = AdminIngressModelPolicy(
            "provider-1", "model-1",
            installed_model_config_ref("provider-1", "model-1", config_digest),
            config_digest, 0.2, 64, ("text",), "private",
            ("proposal",), ("owner",), ("private",),
        )
        namespace = NamespaceId("bot", "persona")
        lease = BudgetLease(
            "root-lease", None, "bot", "persona", "USD",
            {"output_tokens": 128}, {}, {}, {}, 1, "active")
        grant = BudgetLeaseGrant(
            "root-grant", 1, "bot", "persona", "root-lease", "USD",
            {"output_tokens": 128}, ("reply",), 4102444800,
            "budget-policy")
        policy = AdminInstallationPolicy(
            namespace, "bot/persona", "install", "a" * 64, "holder",
            "authority", "b" * 64, "scheme", "operator", "policy",
            lease, grant)
        encoding = AdminIngressEncodingPolicy(
            2, {"output_tokens": 128}, "snapshot", "resource", "interval")
        self.bundle = AdminInstallationBundle(
            SimpleNamespace(), policy, b"k" * 32, b"d" * 32,
            ingress_encoding=encoding, ingress_model=self.admin_model)
        self.adapter = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=self.descriptor,
            admin_model=self.admin_model,
            installation_bundle=self.bundle,
        )

    async def asyncTearDown(self):
        await self.shared_client.close()

    def v2_adapters(self):
        config = self.admin_model
        shared = dict(
            provider_id=config.provider_id, model_id=config.model_id,
            provider_config_ref=config.provider_config_ref,
            provider_config_digest=config.provider_config_digest,
            privacy_tier="private", required_capabilities=("text",),
            timeout_seconds=0.2, max_output_tokens=64,
        )
        encode = AdminModelWorkflowV2(
            work_kind="d06.encode_source", purpose="consolidation",
            audiences=("owner",),
            template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
            quote_ceiling={"output_tokens": 64}, **shared)
        reply = AdminModelWorkflowV2(
            work_kind="reply", purpose="proposal", audiences=("owner",),
            template_version=REPLY_TEMPLATE_VERSION,
            quote_ceiling={"output_tokens": 32},
            **{**shared, "max_output_tokens": 32})
        grant = replace(self.bundle.installation_policy.root_grant,
                        allowed_work_kinds=("d06.encode_source", "reply"))
        policy = replace(self.bundle.installation_policy, root_grant=grant)
        bundle = replace(
            self.bundle, installation_policy=policy, ingress_model=None,
            model_workflows=AdminModelWorkflowsV2(2, encode, reply))
        def adapter(workflow):
            descriptor = replace(
                self.descriptor, purposes=frozenset({workflow.purpose}))
            return AstrBotModelProvider(
                context=self.context, host_loop=asyncio.get_running_loop(),
                trusted_umo=UMO, descriptor=descriptor,
                admin_model=workflow, installation_bundle=bundle)
        return bundle, adapter(encode), adapter(reply)

    async def test_d13_main_model_requires_live_umo_selection(self):
        _, encoder, replier = self.v2_adapters()
        assert await encoder.selected_d13_main_installation_v1() is None
        selected = await replier.selected_d13_main_installation_v1()
        assert selected is not None
        assert (selected.provider_id, selected.model_id,
                selected.provider_config_digest) == (
                    replier._admin_model.provider_id,
                    replier._admin_model.model_id,
                    replier._admin_model.provider_config_digest)
        assert self.manager.seen_umo == [UMO]
        self.manager.selected = object()
        assert await replier.selected_d13_main_installation_v1() is None
        self.manager.selected = self.provider
        self.provider.provider_config["model"] = "changed"
        assert await replier.selected_d13_main_installation_v1() is None

    async def test_d13_preflight_matches_main_wire_but_holds_without_exact_counter(self):
        _, encoder, replier = self.v2_adapters()
        window, plan, _ = d13_plan_case()
        main = await replier.selected_d13_main_installation_v1()
        assert main is not None
        frozen = freeze_d13_precompression_request_v1(window, plan, main)

        selected = await replier.preflight_d13_precompression_v1(frozen)
        assert selected.status == "hold"
        assert selected.wire_digest == frozen.wire_digest
        assert selected.exact_input_tokens is None
        assert "exact installed-provider tokenizer unavailable" in selected.reason
        assert (await encoder.preflight_d13_precompression_v1(frozen)).status == "hold"

        changed = replace(frozen, wire_digest="0" * 64)
        assert "frozen D13 wire differs" in (
            await replier.preflight_d13_precompression_v1(changed)).reason
        self.manager.selected = object()
        assert "selected conversation model" in (
            await replier.preflight_d13_precompression_v1(frozen)).reason

    async def test_natural_stage_wire_strips_internal_provider_selector(self):
        bundle, encoder, replier = self.v2_adapters()
        config = replier._admin_model
        _, _, generation_seal, sample, _, _, _ = natural_case()
        audience = sample.input.plan.audience_ref.ref
        generation = replace(
            config, work_kind="natural_generation",
            template_version=NATURAL_TEMPLATE_VERSION,
            audiences=(audience,),
        )
        review = replace(
            config, work_kind="natural_review",
            template_version=REVIEW_TEMPLATE_VERSION,
            audiences=(audience,),
        )
        grant = replace(
            bundle.installation_policy.root_grant,
            allowed_work_kinds=("d06.encode_source", "reply",
                                "natural_generation", "natural_review"),
        )
        policy = replace(bundle.installation_policy, root_grant=grant)
        bundle = replace(bundle, installation_policy=policy,
                         model_workflows=AdminModelWorkflowsV2(
                             2, encoder._admin_model, config,
                             natural_generation=generation,
                             natural_review=review))
        generated = freeze_natural_reply_request_v2(
            sample.input, NaturalReplyInstallationV2(
                "install", config.provider_config_digest,
                config.provider_id, config.model_id,
                generation.max_output_tokens))
        review_frozen = freeze_natural_reply_review_v1(
            generation_seal,
            {"schema": "sylanne.d09.context_reply_output.v2",
             "body": "Hello.",
             "units": [{"start": 0, "end": 6, "kind": "rhetoric",
                        "basis_ids": ["basis:greeting"],
                        "speech_act": "rhetoric", "promise_grant_id": None,
                        "slot_ids": []}]},
            sample.input.plan.units, (), "policy:review",
            NaturalReviewInstallationV1(
                "install", config.provider_id, config.provider_config_digest,
                config.model_id, review.max_output_tokens))
        for stage, workflow, frozen, template in (
            ("natural_generation", generation, generated, NATURAL_TEMPLATE_DIGEST),
            ("natural_review", review, review_frozen, REVIEW_TEMPLATE_DIGEST),
        ):
            adapter = AstrBotModelProvider(
                context=self.context, host_loop=asyncio.get_running_loop(),
                trusted_umo=UMO, descriptor=self.descriptor,
                admin_model=workflow, installation_bundle=bundle)
            base = call_request()
            authority = replace(
                base.envelope.authority, audience=(audience,), worker_fence=1,
                provider_policy_ref=workflow.provider_config_ref)
            envelope = replace(
                base.envelope,
                identity=replace(base.envelope.identity, phase=stage),
                authority=authority)
            request = replace(
                base, envelope=envelope,
                prompt_template_digest=template,
                payload=json.loads(frozen.canonical_wire),
                timeout_seconds=workflow.timeout_seconds,
                max_output_tokens=workflow.max_output_tokens)
            admission = LocalModelAdmission(
                hashlib.sha256(stage.encode()).hexdigest(),
                adapter.host_incarnation, request.call_id, request.digest,
                workflow.provider_config_digest)
            response = await adapter.invoke_admitted(
                request, admission, asyncio.Event())
            assert response.status == "completed"
            sent = json.loads(self.requests[-1][1].content)
            assert "provider_id" not in sent
            assert sent["model"] == workflow.model_id
            assert sent["messages"] == request.payload["messages"]
            bad = replace(request, payload={**request.payload,
                                            "provider_id": "spoofed"})
            assert adapter._request_allowed(bad) is False

    async def test_d04_installed_appraisal_wire_uses_selected_provider_once(self):
        bundle, encoder, replier = self.v2_adapters()
        config = replier._admin_model
        workflow = replace(
            config, work_kind=APPRAISAL_WORK_KIND,
            template_version=APPRAISAL_TEMPLATE_VERSION)
        grant = replace(
            bundle.installation_policy.root_grant,
            allowed_work_kinds=("d06.encode_source", "reply", APPRAISAL_WORK_KIND))
        bundle = replace(
            bundle,
            installation_policy=replace(bundle.installation_policy,
                                        root_grant=grant),
            model_workflows=replace(bundle.model_workflows, appraisal=workflow))
        capability = InstalledModelCapabilityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            installed_namespace=bundle.installation_policy.namespace,
            installation_bundle=bundle)
        assert await asyncio.to_thread(
            capability.verify_admin_selection,
            bundle.installation_policy.namespace, workflow)
        assert not await asyncio.to_thread(
            capability.verify_admin_selection,
            bundle.installation_policy.namespace,
            replace(workflow, timeout_seconds=0.1))
        frozen = freeze_appraisal_request_v1(
            appraisal_case().input,
            AppraisalInstallationV1(
                "install", workflow.provider_id, workflow.model_id,
                workflow.provider_config_ref, workflow.provider_config_digest,
                workflow.max_output_tokens))
        adapter = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=self.descriptor,
            admin_model=workflow, installation_bundle=bundle)
        base = call_request()
        authority = replace(
            base.envelope.authority, worker_fence=1,
            provider_policy_ref=workflow.provider_config_ref)
        request = replace(
            base,
            envelope=replace(
                base.envelope,
                identity=replace(base.envelope.identity, phase=APPRAISAL_WORK_KIND),
                authority=authority),
            prompt_template_digest=APPRAISAL_TEMPLATE_DIGEST,
            payload=json.loads(frozen.canonical_wire),
            timeout_seconds=workflow.timeout_seconds,
            max_output_tokens=workflow.max_output_tokens)
        admission = LocalModelAdmission(
            hashlib.sha256(b"d04-appraisal").hexdigest(),
            adapter.host_incarnation, request.call_id, request.digest,
            workflow.provider_config_digest)
        assert adapter._request_allowed(request)
        response = await adapter.invoke_admitted(request, admission, asyncio.Event())
        assert response.status == "completed"
        assert (await adapter.invoke_admitted(
            request, admission, asyncio.Event())).status == "completed"
        assert len(self.requests) == 1
        sent = json.loads(self.requests[0][1].content)
        assert "provider_id" not in sent
        assert sent["messages"] == request.payload["messages"]
        assert not adapter._request_allowed(replace(
            request, payload={**request.payload, "provider_id": "another"}))
        assert not replier._request_allowed(request)

    async def test_v2_same_model_has_distinct_encoding_and_reply_scope(self):
        bundle, encoder, replier = self.v2_adapters()
        port = InstalledModelCapabilityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            installed_namespace=bundle.installation_policy.namespace,
            installation_bundle=bundle)
        assert await asyncio.to_thread(
            port.verify_admin_selection, bundle.installation_policy.namespace,
            bundle.model_workflows.encode)
        assert await asyncio.to_thread(
            port.verify_admin_selection, bundle.installation_policy.namespace,
            bundle.model_workflows.reply)
        request = call_request()
        encode_authority = replace(request.envelope.authority,
                                   purpose="consolidation")
        encode_request = replace(
            request, envelope=replace(request.envelope,
                                      authority=encode_authority),
            prompt_template_digest=FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST)
        assert encoder._request_allowed(encode_request)
        assert not encoder._request_allowed(request)
        assert not replier._request_allowed(encode_request)
        assert not replier._request_allowed(request)  # arbitrary prompt is refused
        narrow = replace(bundle.model_workflows.encode,
                         audiences=("private",))
        narrow_bundle = replace(bundle, model_workflows=AdminModelWorkflowsV2(
            2, narrow, bundle.model_workflows.reply))
        narrow_encoder = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=encoder.descriptor,
            admin_model=narrow, installation_bundle=narrow_bundle)
        assert not narrow_encoder._request_allowed(encode_request)
        reduced = replace(bundle.model_workflows.encode, max_output_tokens=32,
                          quote_ceiling={"output_tokens": 32})
        reduced_bundle = replace(bundle, model_workflows=AdminModelWorkflowsV2(
            2, reduced, bundle.model_workflows.reply))
        reduced_encoder = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=encoder.descriptor,
            admin_model=reduced, installation_bundle=reduced_bundle)
        assert not reduced_encoder._request_allowed(encode_request)

    async def test_context_reply_uses_exact_frozen_three_message_order(self):
        bundle, _, _ = self.v2_adapters()
        config = self.admin_model
        workflow = AdminModelWorkflowV2(
            work_kind="context_reply", purpose="proposal", audiences=("owner",),
            template_version=CONTEXT_REPLY_TEMPLATE_VERSION,
            quote_ceiling={"output_tokens": 32},
            provider_id=config.provider_id, model_id=config.model_id,
            provider_config_ref=config.provider_config_ref,
            provider_config_digest=config.provider_config_digest,
            privacy_tier="private", required_capabilities=("text",),
            timeout_seconds=0.2, max_output_tokens=32)
        grant = replace(bundle.installation_policy.root_grant,
                        allowed_work_kinds=(
                            "d06.encode_source", "reply", "context_reply"))
        bundle = replace(
            bundle,
            installation_policy=replace(bundle.installation_policy, root_grant=grant),
            model_workflows=replace(bundle.model_workflows, context_reply=workflow))
        adapter = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=self.descriptor,
            admin_model=workflow, installation_bundle=bundle)
        capability = InstalledModelCapabilityPort(
            context=self.context, host_loop=asyncio.get_running_loop(),
            installed_namespace=bundle.installation_policy.namespace,
            installation_bundle=bundle)
        assert await asyncio.to_thread(
            capability.verify_admin_selection,
            bundle.installation_policy.namespace, workflow)
        frozen = freeze_context_reply_request_v1(
            example_input(), ContextReplyInstallationV1(
                "install", config.provider_config_digest,
                "provider-1", "model-1", 32))
        base = call_request()
        envelope = replace(
            base.envelope,
            identity=replace(base.identity, phase="context_reply"),
            authority=replace(base.envelope.authority, worker_fence=1))
        request = replace(
            base, envelope=envelope,
            prompt_template_digest=CONTEXT_REPLY_TEMPLATE_DIGEST,
            payload=json.loads(frozen.canonical_wire), max_output_tokens=32)
        assert adapter._request_allowed(request)
        result = await adapter._invoke_on_host(request)
        assert result.status == "completed"
        assert result.result == {"text": "hello"}
        assert len(self.requests) == 1
        sent = json.loads(self.requests[0][1].content)
        assert sent["messages"] == [
            {"role": item.role, "content": item.content}
            for item in frozen.messages]
        assert sent["max_completion_tokens"] == 32
        changed = replace(request, payload={
            **request.payload,
            "messages": list(reversed(request.payload["messages"]))})
        assert not adapter._request_allowed(changed)

    async def test_v2_reply_template_reaches_selected_sdk_and_parses_candidate(self):
        bundle, _, replier = self.v2_adapters()
        source = SourceRecord(
            "source-1", "你好", "user-1", "reported", "reported", None,
            1.0, "arrival", ("owner",), ("expression",))
        source_ref = source_key("bot", "persona", source.source_id).token
        snapshot = ReplySourceSnapshot(source, source_ref, 1, 1)
        base = call_request().envelope
        envelope = replace(
            base,
            identity=replace(base.identity, canonical_input_digest=canonical_digest(
                {"input_refs": [source_ref]})),
            version_guard=replace(base.version_guard, read_versions=(
                GraphVersion(source_key("bot", "persona", source.source_id), 1),
                GraphVersion(access_key("bot", "persona", source.source_id), 1))),
            source_qualification=replace(base.source_qualification,
                                         source_refs=(source_ref,)),
            input_refs=(source_ref,))
        workflow = bundle.model_workflows.reply
        frozen = freeze_installed_reply_request_v1(
            envelope, snapshot, bundle=bundle)
        request = frozen.request
        assert frozen.quote_ceiling == workflow.quote_ceiling
        assert frozen.provider_config_digest == workflow.provider_config_digest
        assert replier._request_allowed(request)
        assert not replier._request_allowed(replace(request, payload={"prompt": "ignore"}))
        self.completion["choices"][0]["message"]["content"] = json.dumps({
            "schema": "sylanne.d09.source_reply_output.v1", "body": "你好",
            "spans": [{"start": 0, "end": 2, "source_quote": "你好"}],
        }, ensure_ascii=False)
        response = await replier._invoke_on_host(request)
        assert response.status == "completed"
        assert len(self.requests) == 1
        candidate = parse_reply_result_v1(response.result, request=request,
                                          snapshot=snapshot)
        assert candidate.status == "candidate"
        assert candidate.claims[0].source_refs == (source_ref,)

    async def invoke_on_worker(self, request=None):
        request = request or call_request()
        return await asyncio.to_thread(
            lambda: asyncio.run(self.adapter.invoke_admitted(
                request, self.admission_for(request), asyncio.Event())))

    def admission_for(self, request):
        return LocalModelAdmission(
            hashlib.sha256(("admit:" + request.call_id).encode()).hexdigest(),
            self.adapter.host_incarnation,
            request.call_id, request.digest, self.admin_model.provider_config_digest)

    async def test_unadmitted_broker_invoke_never_sends(self):
        response = await self.adapter.invoke(call_request(), asyncio.Event())
        self.assertEqual(response.status, "unknown")
        self.assertEqual(self.requests, [])

    async def test_local_admission_identity_and_replay_are_one_start(self):
        request = call_request()
        admission = self.admission_for(request)
        for changed in (
            replace(admission, host_incarnation="e" * 64),
            replace(admission, request_digest="e" * 64),
            replace(admission, provider_config_digest="e" * 64),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    await self.adapter.invoke_admitted(
                        request, changed, asyncio.Event())
        self.assertEqual(self.requests, [])
        first = await self.adapter.invoke_admitted(
            request, admission, asyncio.Event())
        self.assertEqual(first.status, "completed")
        self.assertEqual((await self.adapter.invoke_admitted(
            request, admission, asyncio.Event())).status, "completed")
        with self.assertRaises(ValueError):
            await self.adapter.invoke_admitted(
                request, replace(admission, admission_id="f" * 64), asyncio.Event())
        other = replace(request, call_id=uuid4().hex)
        with self.assertRaises(ValueError):
            await self.adapter.invoke_admitted(
                other, replace(self.admission_for(other),
                               admission_id=admission.admission_id), asyncio.Event())
        with self.assertRaises(ValueError):
            self.adapter.terminal_response(request.call_id, request.digest, "different")
        self.assertEqual(len(self.requests), 1)

    async def test_cancel_after_http_start_cannot_prove_unsent(self):
        from sylanne3.host.astrbot_model_call import _calls, _call_lock
        request = call_request()
        admission = self.admission_for(request)
        self.response_gate = asyncio.Event()
        waiter = asyncio.create_task(self.adapter.invoke_admitted(
            request, admission, asyncio.Event()))
        await asyncio.wait_for(self.request_started.wait(), 1)
        with _call_lock:
            task = _calls[request.call_id].task
        self.assertIsNotNone(task)
        task.cancel()
        response = await asyncio.wait_for(waiter, 1)
        self.assertEqual(response.status, "unknown")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, admission.admission_id), response)

    async def test_host_shutdown_aborts_local_task_but_keeps_unknown(self):
        from sylanne3.host.astrbot_model_call import _calls, _call_lock
        request = call_request()
        admission = self.admission_for(request)
        self.response_gate = asyncio.Event()
        waiter = asyncio.create_task(self.adapter.invoke_admitted(
            request, admission, asyncio.Event()))
        await asyncio.wait_for(self.request_started.wait(), 1)
        await self.adapter.abort_local_dispatches()
        response = await asyncio.wait_for(waiter, 1)
        await asyncio.sleep(0)
        with _call_lock:
            task = _calls[request.call_id].task
        self.assertTrue(task is None or task.done())
        self.assertEqual(response.status, "unknown")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, admission.admission_id), response)

    async def test_one_http_request_on_host_loop_with_usage(self):
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "completed")
        self.assertEqual(response.result, {"text": "hello"})
        self.assertEqual(response.usage, {
            "input_tokens": 3, "cached_input_tokens": 1, "output_tokens": 3,
        })
        self.assertEqual(response.provider_call_ref, "remote-1")
        self.assertEqual(self.manager.seen_umo, [UMO, UMO])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0][0], self.host_thread)
        self.assertIn(b'"max_completion_tokens":64', self.requests[0][1].content)
        self.assertEqual(self.shared_client.max_retries, 2)

    async def test_cached_usage_cannot_exceed_prompt_tokens(self):
        self.completion["usage"]["prompt_tokens_details"]["cached_tokens"] = 4
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "unknown")
        self.assertIsNone(response.result)
        self.assertEqual(response.usage, {})
        self.assertEqual(len(self.requests), 1)

    async def test_500_429_and_timeout_each_make_one_request(self):
        for status in (500, 429):
            with self.subTest(status=status):
                self.requests.clear()
                self.status = status
                response = await self.invoke_on_worker()
                self.assertEqual(response.status, "unknown")
                self.assertEqual(len(self.requests), 1)
        self.requests.clear()
        self.status = 200
        self.transport_error = httpx.ReadTimeout("lost response")
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "unknown")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.shared_client.max_retries, 2)

    async def test_selection_change_and_unsupported_provider_never_request(self):
        self.provider.model_name = "model-2"
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.provider.model_name = "model-1"
        self.manager.selected = None
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.manager.selected = self.provider
        self.provider.provider_config["api_version"] = "2025-01-01"
        self.assertEqual((await self.invoke_on_worker()).status, "not_dispatched")
        self.provider.provider_config.pop("api_version")
        self.assertEqual((await self.invoke_on_worker(
            replace(call_request(), payload={"prompt": "hello", "unexpected": True})
        )).status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_installed_config_drift_has_no_network_dispatch(self):
        self.provider.provider_config["temperature"] = 0.25
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.requests, [])
        self.provider.provider_config.pop("temperature")
        self.assertEqual((await self.invoke_on_worker()).status, "completed")
        self.assertEqual(len(self.requests), 1)

    async def test_config_drift_after_first_selection_still_has_no_dispatch(self):
        def change_on_second_selection(number):
            if number == 2:
                self.provider.provider_config["temperature"] = 0.25

        self.manager.on_selection = change_on_second_selection
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.manager.seen_umo, [UMO, UMO])
        self.assertEqual(self.requests, [])

    async def test_client_replacement_after_first_selection_has_no_dispatch(self):
        def replace_on_second_selection(number):
            if number == 2:
                self.provider.client = object.__new__(AsyncOpenAI)

        self.manager.on_selection = replace_on_second_selection
        response = await self.invoke_on_worker()
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_host_cancellation_during_final_preflight_has_no_dispatch(self):
        request = call_request()

        def cancel_on_second_selection(number):
            if number == 2:
                asyncio.current_task().cancel()

        self.manager.on_selection = cancel_on_second_selection
        response = await asyncio.wait_for(self.invoke_on_worker(request), 1)
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, self.admission_for(request).admission_id),
                         response)
        self.assertEqual(self.requests, [])

    async def test_admin_timeout_and_token_ceilings_hold_before_dispatch(self):
        for request in (
            replace(call_request(), timeout_seconds=0.3),
            replace(call_request(), max_output_tokens=65),
        ):
            with self.subTest(request=request):
                self.assertEqual((await self.invoke_on_worker(request)).status,
                                 "not_dispatched")
        self.assertEqual(self.manager.seen_umo, [])
        self.assertEqual(self.requests, [])

    async def test_request_purpose_audience_and_privacy_are_checked_before_http(self):
        adapter = AstrBotModelProvider(
            context=self.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=UMO, descriptor=self.descriptor,
            admin_model=self.admin_model, installation_bundle=self.bundle,
        )
        baseline = call_request()
        wrong_purpose = replace(
            baseline, call_id=uuid4().hex,
            envelope=replace(baseline.envelope, authority=replace(
                baseline.envelope.authority, purpose="unrelated")))
        wrong_audience = replace(
            baseline, call_id=uuid4().hex,
            envelope=replace(baseline.envelope, authority=replace(
                baseline.envelope.authority, audience=("public",))))
        wrong_privacy = replace(baseline, call_id=uuid4().hex,
                                privacy_tier="public")
        for request in (wrong_purpose, wrong_audience, wrong_privacy):
            with self.subTest(call_id=request.call_id):
                response = await adapter.invoke_admitted(
                    request, self.admission_for(request), asyncio.Event())
                self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_unscoped_or_underfunded_installed_selection_never_dispatches(self):
        request = call_request()
        for model, encoding in (
            (replace(self.admin_model, allowed_purposes=(),
                     allowed_audiences=(), allowed_privacy_tiers=()),
             self.bundle.ingress_encoding),
            (self.admin_model, replace(
                self.bundle.ingress_encoding,
                quote_ceiling={"output_tokens": 63})),
        ):
            with self.subTest(model=model, encoding=encoding):
                bundle = replace(self.bundle, ingress_model=model,
                                 ingress_encoding=encoding)
                adapter = AstrBotModelProvider(
                    context=self.context, host_loop=asyncio.get_running_loop(),
                    trusted_umo=UMO, descriptor=self.descriptor,
                    admin_model=model, installation_bundle=bundle)
                candidate = replace(request, call_id=uuid4().hex)
                result = await adapter.invoke_admitted(
                    candidate, self.admission_for(candidate), asyncio.Event())
                self.assertEqual(result.status, "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_ambiguous_completion_is_unknown(self):
        self.completion["choices"] = [{
            "index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": []},
        }]
        self.assertEqual((await self.invoke_on_worker()).status, "unknown")
        self.assertEqual(len(self.requests), 1)

    async def test_cancelled_waiter_can_rejoin_same_call_and_read_terminal(self):
        request = call_request()
        self.response_gate = asyncio.Event()
        first = asyncio.create_task(self.adapter.invoke_admitted(
            request, self.admission_for(request), asyncio.Event()))
        await asyncio.wait_for(self.request_started.wait(), 1)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assertIsNone(self.adapter.terminal_response(
            request.call_id, request.digest, self.admission_for(request).admission_id))
        second = asyncio.create_task(self.invoke_on_worker(request))
        await asyncio.sleep(0)
        self.assertEqual(len(self.requests), 1)
        self.response_gate.set()
        response = await asyncio.wait_for(second, 1)
        self.assertEqual(response.status, "completed")
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, self.admission_for(request).admission_id),
                         response)
        self.assertEqual(len(self.requests), 1)

    async def test_conflicting_digest_reuse_rejected_without_dispatch(self):
        request = call_request()
        response = await self.invoke_on_worker(request)
        different = replace(request, payload={"prompt": "different"})
        with self.assertRaises(ValueError):
            await self.adapter.invoke_admitted(
                different, self.admission_for(different), asyncio.Event())
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, self.admission_for(request).admission_id),
                         response)
        self.assertEqual(len(self.requests), 1)

    async def test_preflight_rejection_is_terminal_and_never_retried(self):
        request = call_request()
        self.provider.provider_config["temperature"] = 0.25
        response = await self.adapter.invoke_admitted(
            request, self.admission_for(request), asyncio.Event())
        self.assertEqual(response.status, "not_dispatched")
        self.assertEqual(self.adapter.terminal_response(
            request.call_id, request.digest, self.admission_for(request).admission_id),
                         response)
        self.provider.provider_config.pop("temperature")
        self.assertEqual((await self.adapter.invoke_admitted(
            request, self.admission_for(request), asyncio.Event())).status,
                         "not_dispatched")
        self.assertEqual(self.requests, [])

    async def test_host_loop_stopping_before_launch_leaves_call_unresolved(self):
        host_loop = asyncio.new_event_loop()
        blocking = threading.Event()
        release = threading.Event()

        def stop_before_launch():
            blocking.set()
            release.wait(2)
            host_loop.stop()

        host_loop.call_soon(stop_before_launch)
        thread = threading.Thread(target=host_loop.run_forever)
        thread.start()
        try:
            self.assertTrue(await asyncio.to_thread(blocking.wait, 1))
            adapter = AstrBotModelProvider(
                context=self.context, host_loop=host_loop, trusted_umo=UMO,
                descriptor=self.descriptor, admin_model=self.admin_model,
                installation_bundle=self.bundle,
            )
            request = call_request()
            waiter = asyncio.create_task(adapter.invoke_admitted(
                request, self.admission_for(request), asyncio.Event()))
            await asyncio.sleep(0)
            self.assertFalse(waiter.done())
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            release.set()
            await asyncio.to_thread(thread.join, 1)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(adapter.terminal_response(
                request.call_id, request.digest, self.admission_for(request).admission_id))
            self.assertEqual(self.requests, [])
            restarted_loop = asyncio.new_event_loop()
            try:
                restarted = AstrBotModelProvider(
                    context=self.context, host_loop=restarted_loop, trusted_umo=UMO,
                    descriptor=self.descriptor, admin_model=self.admin_model,
                    installation_bundle=self.bundle,
                )
                with self.assertRaises(ValueError):
                    await restarted.invoke_admitted(
                        request, self.admission_for(request), asyncio.Event())
            finally:
                restarted_loop.close()
        finally:
            release.set()
            await asyncio.to_thread(thread.join, 1)
            host_loop.close()


if __name__ == "__main__":
    unittest.main()
