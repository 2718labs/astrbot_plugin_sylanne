"""Permanent first-install M1 configuration and actual-original assertions.

Configuration enters the existing real Owner fixture before any model service
or budget grant. The local provider is a MockTransport; unknown billing remains
unknown. No Source, current grant, paid receipt, claim or terminal is seeded.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import asyncio
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.host.authority_profile import (
    AdminArtifactDraftBodyPolicyV1, AdminArtifactDraftPolicyV1,
    AdminArtifactDraftToolScopeV1, AdminForegroundDeadlinePolicyV1,
    AdminForegroundNaturalDeadlinePolicyV1, AdminForegroundPolicyV1,
    AdminModelWorkflowV2, AdminPrivateReplyDispatchPolicy,
)
from sylanne3.host.model_workflows_v4 import AdminModelWorkflowsV4
from sylanne3.model_broker.artifact_draft_v1 import TEMPLATE_VERSION, WORK_KIND
from sylanne3.model_broker.provider_billing_receipt_v1 import (
    EXTENSION_KEY, ProviderBillingPolicyV1, ProviderBillingReceiptV1,
    provider_billing_receipt_signing_bytes_v1,
)
from sylanne3.runtime.foreground_call_plan_v1 import MODEL_DIMENSIONS, SCHEMA
from sylanne3.runtime.d11_artifact_draft_contract_v1 import WORK_KIND as FILE_WORK_KIND
from sylanne3.runtime_contracts import canonical_digest


M1_PHASE_TASK_TEXT_V2 = "请写一份初稿，全文100到120字，稍后我给修改意见。"
M1_METHOD_TASK_TEXT_V4 = "只依据本条消息写独立初稿，主题是本地文字初稿用于验证真实文件写入与读回，全文100到120字。"
M1_METHOD_ASSESSMENT_TEXT_V6 = "共同任务输入：主题是本地文字初稿用于验证真实文件写入与读回，全文1000到1200字，语气朴实或温暖均可。请先评估是否可以在限定任务里试用先检查语气样段、再完成全文的方法；现在只评估，不生成或修改作品。"
M1_METHOD_BASELINE_FILENAME_V6 = "m1-baseline.txt"
M1_METHOD_TREATMENT_FILENAME_V6 = "m1-treatment.txt"
M1_METHOD_BASELINE_TEXT_V6 = "只依据本条消息写m1-baseline.txt。结构明确为围绕主题的一段完整初稿，材料就是已完整给出的本地文字初稿用于验证真实文件写入与读回这一主题。全文1000到1200字，语气朴实或温暖均可，允许先试写并检查120到180字语气样段，不急于立即获得全文；本任务作为先完成全文再检查的基线。"
M1_METHOD_TREATMENT_TEXT_V6 = "只依据本条消息写m1-treatment.txt。结构明确为围绕主题的一段完整初稿，材料就是已完整给出的本地文字初稿用于验证真实文件写入与读回这一主题。全文1000到1200字，语气朴实或温暖均可，允许先试写并检查120到180字语气样段，不急于立即获得全文；本任务可以在获准范围内先检查语气样段再完成全文。"
M1_METHOD_FULL_TEXT_V6 = "本地文字初稿用于验证真实文件写入与读回。" * 50
M1_METHOD_SAMPLE_TEXT_V6 = "本地文字初稿用于验证真实文件写入与读回。" * 7
M1_PHASE_FULL_TEXT_V2 = "本地文字初稿用于验证真实文件写入与读回。" * 5
M1_PHASE_REVISION_TASK_TEXT_V2 = "请继续修改刚才的初稿，把本地文字初稿改为本地修订初稿，全文仍为100到120字。"
M1_PHASE_REVISED_FULL_TEXT_V2 = "本地修订初稿用于验证真实文件更新与读回。" * 5


def m1_phase_fixture_observer_asset_payload_v1(observer_id, observer_version=1, *, method_dependency=False, paired_method_targets=False):
    """Public finite fixture evidence; this payload grants no installation scope."""
    text_digest = hashlib.sha256(M1_PHASE_TASK_TEXT_V2.encode("utf-8")).hexdigest()
    amendment_text_digest = hashlib.sha256(M1_PHASE_REVISION_TASK_TEXT_V2.encode("utf-8")).hexdigest()
    content_digest = hashlib.sha256(M1_PHASE_FULL_TEXT_V2.encode("utf-8")).hexdigest()
    revised_digest = hashlib.sha256(M1_PHASE_REVISED_FULL_TEXT_V2.encode("utf-8")).hexdigest()
    cases = (
        (text_digest, content_digest, ["本地文字初稿", "真实文件写入与读回"]),
        (text_digest, revised_digest, ["本地修订初稿", "真实文件更新与读回"]),
        (amendment_text_digest, revised_digest, ["本地修订初稿", "真实文件更新与读回"]))
    if method_dependency:
        cases += ((hashlib.sha256(M1_METHOD_TASK_TEXT_V4.encode("utf-8")).hexdigest(), content_digest,
            ["本地文字初稿", "真实文件写入与读回"]),)
    paired_cases = []
    if paired_method_targets:
        for task_text in (M1_METHOD_BASELINE_TEXT_V6, M1_METHOD_TREATMENT_TEXT_V6):
            phases = ((M1_METHOD_FULL_TEXT_V6, "check"),)
            if task_text == M1_METHOD_TREATMENT_TEXT_V6:
                phases += ((M1_METHOD_SAMPLE_TEXT_V6, "sample_check"),)
            for content, kind in phases:
                for condition in ("task_semantics", "tone"):
                    paired_cases.append({"task_source_text_digest": hashlib.sha256(task_text.encode("utf-8")).hexdigest(),
                        "phase_kind": kind, "condition_id": condition,
                        "content_digest": hashlib.sha256(content.encode("utf-8")).hexdigest(), "status": "satisfied",
                        "evidence_literals": ["本地文字初稿", "真实文件写入与读回"]})
    return {"schema": "d11.artifact-phase-finite-observer-rules.v1",
        "observer_id": observer_id, "observer_version": observer_version, "source_scope": "LOCAL_FIXTURE",
        "cases": [{"task_source_text_digest": source_digest, "phase_kind": "check",
            "condition_id": condition, "content_digest": digest, "status": "satisfied",
            "evidence_literals": literals}
            # Preserve the initial Source cases; append the exact second observed Source.
            for source_digest, digest, literals in cases
            for condition in ("task_semantics", "tone")] + paired_cases}


def load_m1_phase_fixture_installation_v2(setup_file):
    """Read Root's existing protected assets; create no service or permission."""
    import os
    import sylanne3.host.authority_profile as profile
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from sylanne3.authority_service.linux_installation_security_v1 import opened_installed_file_v1
    from rewrite.host_tests.alpha1.artifact_phase_counter_fixture_v1 import RULE as FIXTURE_RULE
    from sylanne3.model_broker.artifact_phase_count_v1 import (
        artifact_phase_counter_policy_from_payload_v1, FIXTURE_PROVIDER, FIXTURE_MODEL,
    )
    from sylanne3.model_broker.first_ingress_encoding import (FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION,
        FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION)
    from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("phase fixture uses Root-prepared assets in an ordinary Linux process")
    with opened_installed_file_v1(Path(setup_file)) as descriptor:
        raw = profile._read_fd_bounded(descriptor, profile._MAX_PROFILE_BYTES)
    setup = json.loads(raw.decode("utf-8"))
    names = {"schema", "profile_id", "profile_root", "package_root", "data_dir", "authority_store",
        "server_certificate", "server_private_key", "administrator_certificate", "administrator_private_key",
        "billing_signing_key"}
    current=setup["schema"]=="sylanne.artifact-phase-fixture-setup.v3"
    if current:names.update(("c04_component_key","c09_installation_assets","c09_sdk_peer_cohort"))
    if type(setup) is not dict or set(setup)!=names or setup["schema"] not in {"sylanne.artifact-phase-fixture-setup.v2","sylanne.artifact-phase-fixture-setup.v3"}:
        raise ValueError("exact protected phase fixture setup descriptor required")
    profile._check_profile_id(setup["profile_id"])
    paths = {name: Path(setup[name]) for name in names - {"schema", "profile_id"}}
    if any(not path.is_absolute() or path.resolve(strict=True) != path for path in paths.values()):
        raise ValueError("phase fixture setup requires actual canonical installation paths")
    assert paths["authority_store"].parent == paths["data_dir"]
    directory = paths["profile_root"] / setup["profile_id"]
    with profile._opened_profile(directory, "Linux", signing_key=True) as files:
        payload = profile._read_profile_json(files["profile.json"])
        counter = artifact_phase_counter_policy_from_payload_v1(payload["artifact_phase_counter"], allow_local_fixture=True)
        initial = {key: value for key, value in payload.items()
            if key not in {"artifact_phase_counter", "artifact_phase_fixture_observer"}}
        policy = profile._policy_from_payload(initial)
        tls = profile._profile_from_payload(setup["profile_id"], directory, initial,
            profile._prepared_ssl_context(files, "Linux"))
        d11_key = profile._checked_signing_key(profile._read_fd_bounded(files["d11-signing.key"], 32), "D11")
        d02_key = profile._checked_signing_key(profile._read_fd_bounded(files["d02-signing.key"], 32), "D02")
    ordinary = {
        "ingress_clock": "_ingress_clock_from_payload", "ingress_encoding": "_ingress_encoding_from_payload",
        "model_workflows": "_model_workflows_from_payload", "foreground": "_foreground_from_payload",
        "artifact_draft": "_artifact_draft_from_payload", "private_reply_dispatch": "_private_reply_dispatch_from_payload",
        "provider_billing_policy_v1": "_provider_billing_policy_from_payload_v1",
        "d03_arrival": "_d03_arrival_from_payload", "d04_encoding_baseline": "_d04_baseline_from_payload",
        "d06_first_ingress_c02": "_d06_c02_from_payload", "d03_self_identity_projection": "_d03_projection_from_payload",
        "d06_private_reply_source": "_d06_private_reply_source_from_payload", "d07_attention": "_d07_attention_from_payload",
        "d06_recall": "_d06_recall_from_payload",
    }
    if initial.get("method_measurement_policy") is not None:
        ordinary["method_measurement_policy"] = "_method_measurement_policy_from_payload_v1"
    bundle = profile.AdminInstallationBundle(tls, policy, d11_key, d02_key,
        **{name: getattr(profile, parser)(initial) for name, parser in ordinary.items()},
        d13_paid_precompression=profile._d13_paid_precompression_from_payload(initial,policy),
        d04_semantic_drive=profile._d04_semantic_drive_from_payload(initial,policy),
        d04_joint_numeric=profile._d04_joint_numeric_from_payload(initial,policy),
        life_d04_before_capture_policy=profile._life_d04_before_capture_policy_from_payload_v1(initial,policy))
    with opened_installed_file_v1(paths["billing_signing_key"], private=True, allowed_gid=os.getegid()) as descriptor:
        key = Ed25519PrivateKey.from_private_bytes(profile._read_fd_bounded(descriptor, 32))
    for name in ("server_certificate", "server_private_key", "administrator_certificate", "administrator_private_key"):
        with opened_installed_file_v1(paths[name], private="private_key" in name, allowed_gid=os.getegid()):
            pass
    if current:
        with opened_installed_file_v1(paths["c04_component_key"],private=True,allowed_gid=os.getegid()) as descriptor:
            if len(profile._read_fd_bounded(descriptor,33))!=32:
                raise ValueError("actual Root-prepared C04 component key must contain 32 bytes")
    configuration = {"id": FIXTURE_PROVIDER, "type": "openai_chat_completion", "model": FIXTURE_MODEL}
    phase = bundle.artifact_draft.phase_model_workflow
    from sylanne3.host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    assert type(bundle.artifact_draft) in {profile.AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}
    assert type(bundle.artifact_draft.standing_scope) is profile.AdminArtifactStandingScopeV3
    assert counter.source_scope == "LOCAL_FIXTURE"
    assert (counter.namespace, counter.installation_id, counter.manifest_digest, counter.profile_id) == (
        policy.namespace, policy.installation_id, policy.manifest_digest, setup["profile_id"])
    assert (counter.provider_id, counter.model_id, counter.provider_config_digest) == (
        FIXTURE_PROVIDER, FIXTURE_MODEL, canonical_digest(configuration))
    assert (phase.provider_id, phase.model_id, phase.provider_config_digest, phase.template_version) == (
        counter.provider_id, counter.model_id, counter.provider_config_digest, counter.template_version)
    assert bundle.model_workflows.encode.template_version in {FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION,
        FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}
    assert bundle.d06_recall is not None and bundle.model_workflows.d07_cognition is not None
    assert bundle.model_workflows.d07_cognition.template_version == RECALL_TEMPLATE_VERSION_V1
    for workflow in (bundle.model_workflows.encode, bundle.model_workflows.d07_cognition,
            bundle.model_workflows.artifact_draft, bundle.model_workflows.natural_generation,
            bundle.model_workflows.natural_review, phase):
        assert workflow is not None and (workflow.provider_id, workflow.model_id, workflow.provider_config_digest) == (
            counter.provider_id, counter.model_id, counter.provider_config_digest)
    billing = bundle.provider_billing_policy_v1
    assert billing is not None and billing.evidence_kind == "fixture_simulated_charge"
    assert billing.provider_ed25519_public_key_hex == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    assert (billing.namespace, billing.installation_id, billing.manifest_digest,
        billing.provider_id, billing.model_id, billing.provider_config_digest) == (
        counter.namespace, counter.installation_id, counter.manifest_digest,
        counter.provider_id, counter.model_id, counter.provider_config_digest)
    assert hashlib.sha256((paths["package_root"] / "release-manifest.json").read_bytes()).hexdigest() == policy.manifest_digest
    return M1PhaseFixtureInstallationV2(setup["profile_id"], paths["profile_root"], paths["package_root"],
        paths["data_dir"], paths["authority_store"], paths["server_certificate"], paths["server_private_key"],
        paths["administrator_certificate"], paths["administrator_private_key"], bundle, counter, key,
        paths["c04_component_key"] if current else None,paths["c09_installation_assets"] if current else None,
        paths["c09_sdk_peer_cohort"] if current else None)


M1_WORK_KINDS = ("d11.foreground_cycle.v1", WORK_KIND, FILE_WORK_KIND)


@dataclass(frozen=True, slots=True)
class M1InitialInstallationFixtureV1:
    workflows: AdminModelWorkflowsV4
    foreground: AdminForegroundPolicyV1
    artifact_draft: AdminArtifactDraftPolicyV1
    private_reply_dispatch: AdminPrivateReplyDispatchPolicy
    root_model_limits: tuple[tuple[str, int], ...]
    root_model_max_ceiling: tuple[tuple[str, int], ...]
    provider_billing_policy: ProviderBillingPolicyV1 | None
    simulated_provider_key: Ed25519PrivateKey | None

    def __post_init__(self):
        assert type(self.workflows) is AdminModelWorkflowsV4
        assert type(self.foreground) is AdminForegroundPolicyV1
        assert type(self.artifact_draft) is AdminArtifactDraftPolicyV1
        assert type(self.private_reply_dispatch) is AdminPrivateReplyDispatchPolicy
        assert self.artifact_draft.model_workflow is self.workflows.artifact_draft
        if self.provider_billing_policy is None:
            assert self.simulated_provider_key is None
        else:
            assert type(self.provider_billing_policy) is ProviderBillingPolicyV1
            assert self.provider_billing_policy.evidence_kind == "fixture_simulated_charge"
            public = self.simulated_provider_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            assert public == self.provider_billing_policy.provider_ed25519_public_key_hex
        for values in (self.root_model_limits, self.root_model_max_ceiling):
            assert type(values) is tuple and values == tuple(sorted(values))
            assert set(dict(values)) == MODEL_DIMENSIONS
            assert all(type(amount) is int and amount > 0 for _, amount in values)
        quotes = tuple(dict(workflow.quote_ceiling) for workflow in (
            self.workflows.encode, self.workflows.appraisal,
            self.workflows.artifact_draft, self.workflows.natural_generation,
            self.workflows.natural_review))
        assert all(set(quote) == MODEL_DIMENSIONS for quote in quotes)
        message = dict(self.private_reply_dispatch.quote_ceiling)
        limits, maximum = map(dict, (self.root_model_limits, self.root_model_max_ceiling))
        for dimension in MODEL_DIMENSIONS:
            # One C1, one C2, one selected C4, and the complete protected child.
            assert limits[dimension] == sum(quote[dimension] for quote in quotes) + 4 * message.get(dimension, 0)
            assert maximum[dimension] == max(*(quote[dimension] for quote in quotes), message.get(dimension, 0))
        assert self.workflows.d07_cognition is None  # C3=0 for this one slice.


def initial_m1_configuration_builder_v1(namespace, authority_namespace,
        installation_id, model_shared, base_workflows, *, manifest_digest, simulated_billing=True):
    """Only initial finite policy inputs; no handles or authorization mutation."""
    from sylanne3.graph_coordinator import namespace_ref
    from sylanne3.model_broker.d04_appraisal import TEMPLATE_VERSION as APPRAISAL_TEMPLATE
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION_V5
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
    assert namespace_ref(namespace) == authority_namespace
    assert installation_id == "installation-reply"

    def workflow(kind, purpose, template, input_tokens):
        output_tokens = 128
        return AdminModelWorkflowV2(work_kind=kind, purpose=purpose,
            template_version=template, max_output_tokens=output_tokens,
            quote_ceiling={"input_tokens": input_tokens, "output_tokens": output_tokens,
                "model_tokens": input_tokens + output_tokens, "model_microusd": 100},
            **model_shared)

    # These are quote ceilings, not measured or asserted monetary costs.
    selected = AdminModelWorkflowsV4(4,
        encode=replace(base_workflows.encode, quote_ceiling={"input_tokens": 1024,
            "output_tokens": 128, "model_tokens": 1152, "model_microusd": 100}),
        reply=base_workflows.reply,
        appraisal=workflow("d04.appraisal", "proposal", APPRAISAL_TEMPLATE, 6000),
        natural_generation=workflow("natural_generation", "proposal", TEMPLATE_VERSION_V5, 2048),
        natural_review=workflow("natural_review", "proposal", REVIEW_TEMPLATE_VERSION_V2, 2048),
        artifact_draft=workflow(WORK_KIND, "consolidation", TEMPLATE_VERSION, 10000))
    dispatch = AdminPrivateReplyDispatchPolicy(300, {"cpu_ms": 1},
        "snapshot:m1-private-reply", "resource:m1-private-reply", 2048, 10)
    foreground = AdminForegroundPolicyV1("sylanne.foreground-policy.v1", 1, SCHEMA,
        6, 2, 1, "policy:m1-first-slice", 1,
        AdminForegroundDeadlinePolicyV1("sylanne.foreground-deadline-policy.v1",
            AdminForegroundNaturalDeadlinePolicyV1("bounded_causal_window_v1", 300,
                "original_post_c02_cause_v1"), "signed_scope_intersection_v1"))
    draft = AdminArtifactDraftPolicyV1(selected.artifact_draft,
        AdminArtifactDraftToolScopeV1("export", "m1-draft.txt", "create", 524288, 32768, 65536, 300),
        AdminArtifactDraftBodyPolicyV1("body-policy:m1-draft", 1, "body-effect:m1-draft", 1, 100, "export"), None)
    quotes = tuple(dict(item.quote_ceiling) for item in (selected.encode, selected.appraisal,
        selected.artifact_draft, selected.natural_generation, selected.natural_review))
    limits = tuple(sorted((dimension, sum(quote[dimension] for quote in quotes)) for dimension in MODEL_DIMENSIONS))
    maximum = tuple(sorted((dimension, max(quote[dimension] for quote in quotes)) for dimension in MODEL_DIMENSIONS))
    key = Ed25519PrivateKey.generate() if simulated_billing else None
    billing = None if key is None else ProviderBillingPolicyV1(namespace, installation_id,
        manifest_digest, model_shared["provider_id"], model_shared["model_id"],
        model_shared["provider_config_digest"], "fixture:m1-provider-final-charge", 1,
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        "fixture_simulated_charge")
    return M1InitialInstallationFixtureV1(selected, foreground, draft, dispatch, limits, maximum, billing, key)


_M1_PHASE_VERIFIER_ISSUER_V2 = object()


class _M1PhaseVerifierInvocationV2:
    """Task-local scope around one independently composed original verifier."""
    def __init__(self, token, *, verifier, service, server, namespace, qualification, graph_db_path, issuer):
        from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
        from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
        assert token is _M1_PHASE_VERIFIER_ISSUER_V2
        assert type(verifier) is PinnedCurrentModelEgressGraphVerifier
        assert type(service) is AuthorityV2ModelEgressService and service._graph_verifier is verifier
        original = verifier._current
        assert original.__self__ is verifier and original.__func__ is PinnedCurrentModelEgressGraphVerifier._current
        assert verifier._path == Path(graph_db_path).resolve(strict=True) and verifier._issuer is issuer
        assert verifier._artifact_draft_bundle is qualification.bundle
        self.verifier, self.service, self.server = verifier, service, server
        self.namespace, self.qualification, self.original = namespace, qualification, original
        self.path, self.issuer = verifier._path, issuer

    def __call__(self, intent, *, include_binding, source_location=None, location_observation=None,
            model_service=None, credential=None, subject=None, permit=None):
        from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
        from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from sylanne3.host.authority_profile import (
            require_artifact_phase_fixture_qualification_v1, artifact_phase_local_fixture_scope_v1,
        )
        q = self.qualification
        require_artifact_phase_fixture_qualification_v1(q.bundle, client_grant=q.client_grant)
        assert type(intent) is ModelEgressIntentV1
        assert self.verifier._current is self and self.original.__self__ is self.verifier
        assert self.original.__func__ is PinnedCurrentModelEgressGraphVerifier._current
        assert self.verifier._path == self.path and self.verifier._issuer is self.issuer
        assert self.verifier._artifact_draft_bundle is q.bundle
        assert self.service._graph_verifier is self.verifier
        assert self.server._v2_model_egress[self.namespace] is self.service
        assert self.service._store._db is self.server._core._db and self.service._store._lock is self.server._core._lock
        assert (intent.authority_id, intent.namespace, intent.subject) == (
            q.client_grant.authority_id, self.namespace, q.client_grant.subject)
        assert (intent.provider_id, intent.model_id, intent.provider_config_digest) == (
            q.counter.provider_id, q.counter.model_id, q.counter.provider_config_digest)
        with artifact_phase_local_fixture_scope_v1(q):
            return self.original(intent, include_binding=include_binding, source_location=source_location,
                location_observation=location_observation, model_service=model_service,
                credential=credential, subject=subject, permit=permit)


def _bind_m1_phase_verifier_scope_v2(*, verifier, service, server, namespace, qualification, graph_db_path, issuer):
    adapter = _M1PhaseVerifierInvocationV2(_M1_PHASE_VERIFIER_ISSUER_V2, verifier=verifier,
        service=service, server=server, namespace=namespace, qualification=qualification,
        graph_db_path=graph_db_path, issuer=issuer)
    verifier._current = adapter
    return adapter


def build_m1_phase_mock_client_v2(configuration,ingress_text,*,provider_cache=None,positive_recall=False):
    """Fix the finite response, billing and cache handlers before qualification."""
    import httpx
    from openai import AsyncOpenAI
    from sylanne3.model_broker.artifact_draft_v1 import INPUT_SCHEMA_V2, OUTPUT_SCHEMA_V2
    from sylanne3.model_broker.natural_reply_history_v4 import INPUT_SCHEMA_V5
    from sylanne3.model_broker.natural_review import INPUT_SCHEMA_V2 as REVIEW_INPUT_SCHEMA_V2
    from sylanne3.model_broker.d07_cognition_v1 import INPUT_SCHEMA as COGNITION_INPUT_SCHEMA, OUTPUT_SCHEMA as COGNITION_OUTPUT_SCHEMA
    calls = []
    initial = {"schema": "sylanne.d06.first_ingress_encoding_output.v2",
        "event_summary": "The owner requested a local draft with an explicit full text range.",
        "quoted_details": [{"quote": ingress_text, "salience": 0.5}],
        "possible_meanings": [], "possible_feelings": [],
        "task_intent": {"kind": "draft_then_corrected_revision",
            "filename": None, "source_quote": ingress_text}}
    mode = {"content": json.dumps(initial, ensure_ascii=False)}

    def actual_finite_response(request):
        body = json.loads(request.content)
        assert body["model"] == configuration.counter_policy.model_id
        messages = body["messages"]
        payload = json.loads(messages[-1]["content"])
        if payload.get('reality')=='internal_life':
            from sylanne3.model_broker.internal_life_content_v1 import OUTPUT_SCHEMA as LIFE_CONTENT_OUTPUT_SCHEMA
            assert positive_recall and configuration.workflows.life_content is not None
            assert set(payload)=={'occurrence_digest','reality','assertion_scope','activity_id','effect_id','execution_id',
                'started_at','completed_at','actual_cpu_ms','artifact_digest','context','before_state','comparison','affect'}
            assert payload['assertion_scope']=='activity_occurred_only'
            content=json.loads(mode['content'])
            assert content['schema']==LIFE_CONTENT_OUTPUT_SCHEMA and content['occurrence_digest']==payload['occurrence_digest']
            encoded=mode['content']
        elif payload["schema"] == INPUT_SCHEMA_V2:
            frozen = payload["input"]
            kind = frozen["selector"]["phase_kind"]
            paired = any(source["text"] in {M1_METHOD_BASELINE_TEXT_V6, M1_METHOD_TREATMENT_TEXT_V6}
                for source in frozen["sources"])
            if paired:
                assert kind in {"tone_sample", "full"}
                text = M1_METHOD_SAMPLE_TEXT_V6 if kind == "tone_sample" else M1_METHOD_FULL_TEXT_V6
            else:
                assert kind == "full"
                amended = any(source["text"] == M1_PHASE_REVISION_TASK_TEXT_V2 for source in frozen["sources"])
                text = M1_PHASE_REVISED_FULL_TEXT_V2 if amended else M1_PHASE_FULL_TEXT_V2
            content = {"schema": OUTPUT_SCHEMA_V2, "input_digest": payload["input_digest"],
                "draft_text": text, "source_refs": [source["ref"] for source in frozen["sources"]],
                "needs_clarification": False, "gaps": []}
            encoded = json.dumps(content, ensure_ascii=False)
        elif payload["schema"] == "sylanne.d07.ingress_recall_routing_input.v1":
            if positive_recall:
                known=[source for source in payload['known_sources'] if source['source_ref']['ref']!=payload['cue']['source_ref']['ref']]
                assert known,'C09 current C04 requires independently qualified actual historical Source'
                source=known[0]
                query=source['record']['text'][:256].strip()
                assert query
                encoded=json.dumps({'schema':'sylanne.d07.ingress_recall_routing_output.v1',
                    'input_digest':payload['input_digest'],'need_ref':payload['need_ref'],'mode':'normal',
                    'triggers':payload['triggers'] or ['time_or_activity_status'],'query_terms':[query],
                    'selected_source_refs':[source['source_ref']['ref']],'unknowns':[],'stop_reason':'search_required'},ensure_ascii=False)
            else:
                assert not payload["triggers"] and not payload["required_checks"] and not payload["missing_items"]
                encoded = json.dumps({"schema": "sylanne.d07.ingress_recall_routing_output.v1",
                    "input_digest": payload["input_digest"], "need_ref": payload["need_ref"], "mode": "normal",
                    "triggers": [], "query_terms": [], "selected_source_refs": [], "unknowns": [],
                    "stop_reason": "no_history_needed"}, ensure_ascii=False)
        elif payload["schema"] == COGNITION_INPUT_SCHEMA:
            assert payload["work_kind"] == "concern" and payload["target_original_kind"] == "graph_head"
            target = json.loads(payload["target_original_json"])
            if target.get("schema") == "d01.method_trial_proposal.v2":
                from sylanne3.runtime.d01_method_learning_v1 import trial_question_v2
                assert payload["question_key"] == trial_question_v2(payload["target_ref"], canonical_digest(target))
                proposition = "accepted"
            else:
                candidate = mode["relationship_candidate"]
                assert type(candidate) is dict
                proposition = json.dumps(candidate, ensure_ascii=False)
            encoded = json.dumps({"schema": COGNITION_OUTPUT_SCHEMA,
                "input_digest": payload["input_digest"], "question_key": payload["question_key"],
                "work_kind": payload["work_kind"], "resolved_slots": [], "discriminating_refs": [],
                "predictions": [], "findings": [{"proposition": proposition,
                    "source_refs": [source["source_ref"]["ref"] for source in payload["sources"]],
                    "qualification": "subjective", "stance": "support", "subjective_conviction": 0.5,
                    "evidence_status": "supported"}], "unknowns": [], "stop_reason": "bounded_segment_complete"},
                ensure_ascii=False)
        elif payload["schema"] == INPUT_SCHEMA_V5:
            plan = payload["expression_plan"]
            basis = payload["qualified_units"][0]
            assert "statement" in plan["allowed_speech_acts"]
            text = basis["qualified_text"]
            encoded = json.dumps({"schema": "sylanne.d09.context_reply_output.v3", "body": text,
                "units": [{"start": 0, "end": len(text), "kind": basis["kind"],
                    "basis_ids": [basis["basis_id"]], "speech_act": "statement", "promise_grant_id": None,
                    "slot_ids": plan["required_slots"]}], "semantic_segments": [{"start": 0, "end": len(text)}]},
                ensure_ascii=False)
        elif payload["schema"] == REVIEW_INPUT_SCHEMA_V2:
            encoded = json.dumps({"schema": "sylanne.d09.natural_review_output.v2",
                "verdict": "pass", "issues": [], "prefix_safe": True})
        else:
            assert payload["schema"] in {"sylanne.d06.first_ingress_encoding_input.v2", "sylanne.d06.first_ingress_encoding_input.v4"}
            current_text = payload["source"]["text"]
            assert current_text in {M1_PHASE_TASK_TEXT_V2, M1_PHASE_REVISION_TASK_TEXT_V2, M1_METHOD_TASK_TEXT_V4, M1_METHOD_ASSESSMENT_TEXT_V6,
                M1_METHOD_BASELINE_TEXT_V6, M1_METHOD_TREATMENT_TEXT_V6}
            current = {**initial, "quoted_details": [{"quote": current_text, "salience": 0.5}],
                "task_intent": {"kind": "continue" if current_text == M1_PHASE_REVISION_TASK_TEXT_V2
                    else "draft_then_corrected_revision", "filename": None, "source_quote": current_text}}
            if payload["schema"] == "sylanne.d06.first_ingress_encoding_input.v4" and current_text == M1_METHOD_ASSESSMENT_TEXT_V6:
                current.update(schema="sylanne.d06.first_ingress_encoding_output.v4",
                    event_summary="The actual Owner requested a separate bounded method assessment, without artifact generation.",
                    task_intent=None, method_context_candidate=None, historical_dependency_candidate=None)
            elif payload["schema"] == "sylanne.d06.first_ingress_encoding_input.v4" and current_text in {
                    M1_METHOD_BASELINE_TEXT_V6, M1_METHOD_TREATMENT_TEXT_V6}:
                filename = M1_METHOD_BASELINE_FILENAME_V6 if current_text == M1_METHOD_BASELINE_TEXT_V6 else M1_METHOD_TREATMENT_FILENAME_V6
                support = [{"start": 0, "end": len(current_text)}]
                conditions = [("structure_explicit", "true"), ("materials_complete", "true"),
                    ("long_draft", "true"), ("short_draft", "false"), ("tone_multiple_legal_readings", "true"),
                    ("local_sample_permitted", "true"), ("immediate_full_draft", "false")]
                current.update(schema="sylanne.d06.first_ingress_encoding_output.v4",
                    task_intent={"kind": "draft_then_corrected_revision", "filename": filename, "source_quote": current_text},
                    method_context_candidate={"intent_kind": "draft_then_corrected_revision", "task_source_quote": current_text,
                        "conditions": [{"condition_id": name, "proposed_value": value, "support_spans": support,
                            "counter_spans": [], "meaningful_unknowns": []} for name, value in conditions]},
                    historical_dependency_candidate={"intent_kind": "draft_then_corrected_revision", "task_source_quote": current_text,
                        "mode": "current_task_only", "support_spans": support, "counter_spans": [], "meaningful_unknowns": []})
            elif payload["schema"] == "sylanne.d06.first_ingress_encoding_input.v4":
                assert current_text == M1_METHOD_TASK_TEXT_V4
                support = [{"start": 0, "end": len(current_text)}]
                current.update(schema="sylanne.d06.first_ingress_encoding_output.v4",
                    method_context_candidate={"intent_kind": current["task_intent"]["kind"],
                        "task_source_quote": current_text, "conditions": [{"condition_id": "short_draft",
                            "proposed_value": "true", "support_spans": support,
                            "counter_spans": [], "meaningful_unknowns": []}]},
                    historical_dependency_candidate={"intent_kind": current["task_intent"]["kind"],
                        "task_source_quote": current_text, "mode": "current_task_only", "support_spans": support,
                        "counter_spans": [], "meaningful_unknowns": []})
            encoded = json.dumps(current, ensure_ascii=False)
        # Explicit finite local endpoint accounting, never a vendor token claim.
        prompt_tokens = sum(3 + len(message["content"]) for message in messages) + 3
        assert all(all(ord(char) in (9, 10, 13) or 32 <= ord(char) <= 126
            for char in message["content"]) for message in messages)
        completion_tokens = 5
        calls.append((body["metadata"]["sylanne_call_id"], body["metadata"]["sylanne_request_digest"]))
        response = httpx.Response(200, json={"id": "finite-phase-response:" + str(len(calls)),
            "object": "chat.completion", "created": 1, "model": configuration.counter_policy.model_id,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": encoded}}], "usage": {"prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens}})
        return simulated_provider_response_v1(configuration, request, response)

    handler = actual_finite_response if provider_cache is None else provider_cache.wrap(actual_finite_response)
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport)
    sdk = AsyncOpenAI(api_key="test-only", base_url="https://mock.invalid/v1", http_client=http_client)
    return sdk, http_client, mode, calls


def simulated_provider_response_v1(configuration, request, response):
    """Only the actual MockTransport endpoint supplies this signed final charge."""
    import httpx
    policy = configuration.provider_billing_policy
    if policy is None:
        return response
    sdk_request = json.loads(request.content)
    metadata = sdk_request["metadata"]
    assert set(metadata) == {"sylanne_call_id", "sylanne_request_digest", "sylanne_billing_contract"}
    assert metadata["sylanne_billing_contract"] == policy.contract_digest
    assert sdk_request["model"] == policy.model_id
    body = response.json()
    assert body["model"] == policy.model_id
    usage = body["usage"]
    details = usage.get("prompt_tokens_details")
    cached = None if details is None else details.get("cached_tokens")
    receipt = ProviderBillingReceiptV1(policy.contract_digest, "fixture_simulated_charge",
        policy.installation_id, policy.manifest_digest, policy.provider_id, body["model"],
        policy.provider_config_digest, metadata["sylanne_call_id"], metadata["sylanne_request_digest"],
        body["id"], "fixture-bill:" + canonical_digest((metadata, body["id"], usage))[:40],
        usage["prompt_tokens"], usage["completion_tokens"], cached, 7, "0" * 128)
    receipt = replace(receipt, signature_hex=configuration.simulated_provider_key.sign(
        provider_billing_receipt_signing_bytes_v1(receipt)).hex())
    body[EXTENSION_KEY] = receipt.to_wire()
    return httpx.Response(response.status_code, json=body, request=request)


@contextmanager
def cold_originals_v1(case):
    """Read only the actual selected Graph; a fresh connection is no authority."""
    control = case["graph"]._actual_d04_authority_acceptance_v3.storage_control
    current = control.read_verified_current_storage_v1()
    current.require_current("business")
    graph_member = next(member for member in current.manifest["members"] if member["role"] == "graph")
    path = Path(graph_member["resolved_path"])
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db
        assert db.total_changes == 0
        db.rollback()
    current.require_current("business")


def assert_prebusiness_model_family_v1(server, *, namespace, original, selected):
    """Only fixture initial assembly; no old call or cost can be exchanged."""
    store = original._store
    assert selected._store is store and selected._fences is original._fences
    assert selected._graph_verifier._path == original._graph_verifier._path
    assert selected._graph_verifier._issuer is original._graph_verifier._issuer
    with store._lock:
        for table in ("authority_model_egress_v1", "authority_model_egress_bindings_v1",
                "authority_model_egress_observations_v1", "authority_model_admissions_v2",
                "authority_model_original_identity_v2"):
            assert store._db.execute("SELECT count(*) FROM " + table).fetchone() == (0,)
    owner_result = server._v2_model_result_reads[namespace]
    worker_result = server._v2_worker_model_result_reads[namespace]
    context_result = server._v2_context_reply_result_reads[namespace]
    natural_result = server._v2_natural_generation_output_reads[namespace]
    for reader in (owner_result, worker_result, context_result, natural_result):
        assert reader._store is store and reader._fences is selected._fences
        assert reader._graph._path == selected._graph_verifier._path
    assert worker_result._graph._issuer is selected._graph_verifier._issuer
    assert worker_result._reply_graph._issuer is selected._graph_verifier._issuer


def compose_actual_m1_services_v1(case):
    """Install the real current C09/Owner/Self/Stop services on this fixture."""
    import hmac
    import time
    from d11_offline_authority_acceptance_support_v1 import install_actual_offline_authority_case_v1
    from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
    from sylanne3.authority_service.current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
    from sylanne3.authority_service.d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
    from sylanne3.authority_service.d11_life_service_v1 import AuthorityD11LifeServiceV1
    from sylanne3.authority_service.d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
    from sylanne3.authority_service.v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
    from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2

    graph, server, ns = case["graph"], case["server"], case["namespace"]
    _, owner, admission = install_actual_offline_authority_case_v1(case)
    control = graph._actual_d04_authority_acceptance_v3.storage_control
    current = control.read_verified_current_storage_v1()
    current.require_current("business")
    files = {member["role"]: Path(member["resolved_path"]) for member in current.manifest["members"]}
    directories = {kind: files["core"].parent / "offline-managed-artifacts" / kind
        for kind in ("controlled_backup", "export", "rebuild_temp", "cache")}
    original_inventory = build_initial_inventory_v1(authority_id=control.authority_id,
        installation_id=control.installation_id, namespace=case["authority_namespace"], files=files, directories=directories)
    resources = tuple(replace(resource, content_coverage=tuple(sorted({*resource.content_coverage,
        "jobs_drafts", "imports_exports"}))) if resource.kind == "export" else resource
        for resource in original_inventory.resources)
    inventory = InstallationFilesystemManifestV2(original_inventory.authority_id, original_inventory.installation_id,
        original_inventory.namespace, resources, canonical_digest((original_inventory.schema,
            original_inventory.authority_id, original_inventory.installation_id, original_inventory.namespace, resources)))
    # The initial producer already signed this exact registration. This only
    # reconstructs the typed installed value and verifies it against that pin.
    assert current.manifest["inventory_manifest_digest"] == inventory.manifest_digest
    fences = server._v2_fences[case["authority_namespace"]]
    daemon=case.get('c09_daemon')
    if daemon is not None:
        assert daemon.server is server and daemon.core is case['core']
        life=server._d11_life_services_v1[case['authority_namespace']]
        location=life.current_source_location
        foreground=server._v2_foreground_activity[case['authority_namespace']]
        model=server._v2_model_egress[case['authority_namespace']]
        result=server._artifact_draft_model_reads_v1[case['authority_namespace']]
        bundle=case['installed_bundle']
        assert life.bridge is server._v2_execution[case['authority_namespace']]
        assert life.issuer is case['d11_issuer'] and life.resource_issuer is case['d02_issuer']
        assert life.installed_bundle.installation_policy==bundle.installation_policy
        assert life.installed_bundle.model_workflows==bundle.model_workflows
        assert life.installed_bundle.d11_signing_key==bundle.d11_signing_key and life.installed_bundle.d02_signing_key==bundle.d02_signing_key
        assert life.draft_self_identity is server._v2_self_identity[case['authority_namespace']]
        assert model._source_location is location
        assert life.draft_inventory_manifest==inventory==daemon.config.c09_maintenance_factory.inventory
        assert location.core is daemon.core and location._control is control
        assert model is case['model_service'] and result._store is model._store
    else:
        location = InstalledCurrentSourceLocationQualifierV1(fences=fences, scoped=control._applied_reader.scoped,
            control=control, graph_db_path=files["graph"], namespace_id=ns,
            installation_id=case["policy"].installation_id)
        self_service = server._v2_self_identity[case["authority_namespace"]]
        self_service.install_current_source_location_v1(location, owner)
        model = case["model_service"]
        assert model is server._v2_model_egress[case["authority_namespace"]]
        model.install_current_source_location_v1(location)
        bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        foreground = InstalledCurrentForegroundActivityV1(self_identity_service=self_service,
            budget_issuer=case["d11_issuer"], clock_provider=case["m1_kernel_clock"],
            filesystem_manifest=inventory, installed_bundle=bundle)
        server.install_current_foreground_activity_v1(case["authority_namespace"], foreground)
        bridge = server._v2_execution[case["authority_namespace"]]
        life = AuthorityD11LifeServiceV1(bridge=bridge, owner_tickets=server._v2_owner_tickets,
            namespace=ns, installation_id=case["policy"].installation_id, manifest_digest=case["manifest_digest"],
            graph_db_path=files["graph"], issuer=case["d11_issuer"], resource_issuer=case["d02_issuer"],
            credential=case["peer"], signing_key=hmac.new(bundle.d11_signing_key,
                b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest(), trusted_now_utc=time.time,
            owner_service=owner, package_root=case["package_root"], body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            current_source_location=location, draft_inventory_manifest=inventory, draft_self_identity=self_service,
            draft_self_read_credential=case["peer"], installed_bundle=bundle)
        server._d11_life_services_v1[case["authority_namespace"]] = life
        case["core"].install_execution_redaction_d11_life_service_v1(case["authority_namespace"], life)
        attempts = AuthorityV2WorkerModelResultAttempts(case["core"]._db, create=False, lock=case["core"]._lock)
        result = AuthorityArtifactDraftModelResultServiceV1(store=model._store, fences=fences,
            graph_db_path=files["graph"], d11_issuer=case["d11_issuer"], installed_bundle=bundle,
            installation_id=case["policy"].installation_id, read_subject=case["client_grant"].subject,
            holder=case["policy"].administrator_holder, trusted_now_utc=time.time, read_attempts=attempts)
        server.install_artifact_draft_model_result_reader_v1(case["authority_namespace"], result)
    status = InstalledD12OperationStatusServiceV1(fences=fences, owner_tickets=server._v2_owner_tickets,
        source_graph_db=files["graph"], namespace_id=ns, installation_id=case["policy"].installation_id)
    status.install_schema(case["admin_peer"])
    status.install_owner_storage_reader_v1(owner)
    server._d12_operation_status_services_v1[(case["authority_namespace"], case["policy"].installation_id)] = status
    stop = server.compose_installed_owner_stop_reply_service_v1(status)
    assert model._graph_verifier._owner_stop_reply_service_v1 is stop
    assert life._owner_stop_reply_service_v1 is stop and result._owner_stop_reply_service_v1 is stop
    case.update(m1_foreground_service=foreground, m1_stop_service=stop, m1_life_service=life,
        m1_source_location=location, m1_inventory=inventory, m1_export_root=directories["export"],
        m1_storage_admission=admission)


class M1InstalledGraphWorkerV1:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, operation):
        return await asyncio.to_thread(operation, self.graph)


def install_actual_m1_model_runtime_v1(case):
    from sylanne3.runtime.d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    graph = case["graph"]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    runtime = InstalledArtifactDraftModelRuntimeV1(graph=graph, bootstrap=case["bootstrap"], bundle=bundle,
        worker=M1InstalledGraphWorkerV1(graph), authority_client=case["authority_client"],
        client_grant=case["client_grant"], context=case["model_context"], owner_loop=asyncio.get_running_loop())
    graph.install_artifact_draft_model_runtime_v1(case["bootstrap"], runtime)
    case["m1_model_runtime"] = runtime
    return runtime


def register_actual_m1_task_root_v1(case):
    from test_current_domain_production_v1 import command
    from sylanne3.authority_service.current_foreground_activity_v1 import DraftRootRegistrationRequestV1
    from sylanne3.runtime.d11_life_preparation_v1 import TABLE, _read
    from sylanne3.runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    bundle = case["graph"]._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    scope = bundle.artifact_draft.tool_scope
    reading = case["m1_kernel_clock"]()
    until = datetime.fromtimestamp(reading.utc_seconds + 300, timezone.utc).isoformat().replace("+00:00", "Z")
    operation_id = str(uuid4())
    request = DraftRootRegistrationRequestV1(case["namespace"], case["source_ref"], scope.resource_id,
        (scope.filename,), scope.max_file_bytes, until, operation_id, "consolidation", (case["ingress"].conversation_ref,))
    receipt = command(case, "register_artifact_draft_root", request, operation_id=operation_id,
        audience=case["ingress"].conversation_ref, activity_id="activity:m1-owner-root-setup")
    with cold_originals_v1(case) as db:
        rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind=? "
            "AND producing_operation_id=?", (*case["namespace"].as_tuple, "draft_root_capability", operation_id)).fetchall()
        assert len(rows) == 1
        raw, producer = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"],
            kind="draft_root_capability", ref=rows[0][0])
        root = draft_from_wire_v1(raw, DraftRootCapabilityV1)
        assert producer == operation_id and root.source_ref == case["source_ref"]
        assert root.filenames == (scope.filename,) and root.registration_ref == rows[0][0]
    case.update(m1_root=root, m1_root_receipt=receipt)
    return root


def install_m1_owner_body_and_catalogue_v1(case):
    """Explicit initial Owner inputs; no completed Body or role facts are seeded."""
    from test_current_domain_production_v1 import command, domain_owner
    from sylanne3.domains.d02 import BodyProfile, BodyState, WorkComponent
    from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
    from sylanne3.runtime.d02_production_operations_v1 import SettledBodyEffectPolicyV1
    from sylanne3.runtime.domain_production_inputs_v1 import InstallCurrentBodyInputRequestV1, InstallCurrentBodyEffectInputRequestV1
    bundle = case["graph"]._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    configured = bundle.artifact_draft.body_policy
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    phase_initial = type(case["m1_initial_configuration"]) is M1PhaseFixtureInstallationV2
    work_kinds = (FILE_WORK_KIND, "d07.cognition", "d06.c04_internal_cpu.v1") if phase_initial else (FILE_WORK_KIND,)
    from sylanne3.runtime.d11_life_contract_v1 import WORK_KIND as SOURCE_NOTE_WORK_KIND
    source_note_initial = phase_initial and SOURCE_NOTE_WORK_KIND in bundle.installation_policy.root_grant.allowed_work_kinds
    if source_note_initial:
        work_kinds += (SOURCE_NOTE_WORK_KIND,)
    profile = BodyProfile("body:m1-draft", case["namespace"], 1, ("energy", "fatigue", "load"), work_kinds)
    state = BodyState(profile.profile_id, 1, .8, {kind: .1 for kind in work_kinds}, .1, 0.0)
    component = WorkComponent("m1-draft-body", "body-energy", .02, 0.0)
    until = case["policy"].root_grant.valid_until_utc if phase_initial else case["m1_kernel_clock"]().utc_seconds + 300
    policy = FixedBodyPolicyV1(configured.policy_ref, configured.policy_version, profile, state,
        FILE_WORK_KIND, component, until)
    command(case, "initialize_body", InstallCurrentBodyInputRequestV1(policy), producer=True)
    effect = SettledBodyEffectPolicyV1(configured.effect_component_policy_ref,
        configured.effect_component_policy_version, case["namespace"], profile.profile_id,
        FILE_WORK_KIND, component.component_id, .01, .005)
    command(case, "install_body_effect_policy", InstallCurrentBodyEffectInputRequestV1(effect), producer=True)
    if source_note_initial:
        # Existing installed SourceNote donor, registered only in the explicit initial NOTE scope.
        note_profile = BodyProfile("body:source-note", case["namespace"], 1, ("energy", "fatigue", "load"), (SOURCE_NOTE_WORK_KIND,))
        note_state = BodyState(note_profile.profile_id, 1, .8, {SOURCE_NOTE_WORK_KIND: .1}, .1, 0.0)
        note_component = WorkComponent("source-note-body", "body-energy", .02, 0.0)
        note_policy = FixedBodyPolicyV1("body-policy:source-note", 1, note_profile, note_state,
            SOURCE_NOTE_WORK_KIND, note_component, until)
        note_body_receipt = command(case, "initialize_body", InstallCurrentBodyInputRequestV1(note_policy), producer=True)
        note_effect = SettledBodyEffectPolicyV1("body-effect:source-note", 1, case["namespace"], note_profile.profile_id,
            SOURCE_NOTE_WORK_KIND, note_component.component_id, .01, .005)
        note_effect_receipt = command(case, "install_body_effect_policy", InstallCurrentBodyEffectInputRequestV1(note_effect), producer=True)
        case.update(source_note_initial_body_policy=note_policy, source_note_initial_effect_policy=note_effect,
            source_note_initial_body_receipt=note_body_receipt, source_note_initial_effect_receipt=note_effect_receipt,
            source_note_initial_cpu_ceiling_ms=100)
    with case["store"]._lock:
        rows = case["store"]._db.execute("SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.role_binding' ORDER BY token LIMIT 129", case["namespace"].as_tuple).fetchall()
    assert len(rows) <= 128
    active = tuple(json.loads(value) for value, valid in rows if valid and json.loads(value)["status"] == "active")
    roles = tuple(sorted({"project_worker", *(binding["social_role"] for binding in active)}))
    norms = tuple(sorted({ref for binding in active for ref in binding["norm_refs"]}))
    with domain_owner(case) as (authority, lease):
        adopted = case["graph"].adopt_current_context_catalogue_v1(authority, lease,
            operation_id=str(uuid4()), roles=roles, norms=norms, budget_ref=case["policy"].root_grant.lease_id)
    assert adopted["graph_receipt"]["status"] == "committed"
    # The fixture Owner explicitly selects this named catalogue role and norms.
    case.update(m1_owner_social_role="project_worker", m1_owner_norm_refs=norms)


def adopt_m1_explicit_owner_project_role_v1(case):
    graph, ns = case["graph"], case["namespace"]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
        namespace=ns, domains=("d03",), purpose="consolidation", audience=case["ingress"].conversation_ref,
        activation_generation=1, owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"])
    try:
        result = graph.configure_current_owner_artifact_project_context_v1(case["bootstrap"], bundle, authority, lease,
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"],
            social_role=case["m1_owner_social_role"], norm_refs=case["m1_owner_norm_refs"], operation_id=str(uuid4()))
        assert result["receipt"]["status"] == "committed"
        return result
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)


async def run_installed_m1_case_v1(tmp_path, installed_root, *, after_c02, simulated_billing=True):
    """Reuse the actual Owner/C02 installation with one closed initial config."""
    from test_d04_owner_semantic_initialization_v3 import (
        real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
    )
    initialized = {}
    pin = hashlib.sha256((Path(installed_root) / "release-manifest.json").read_bytes()).hexdigest()
    builder = partial(initial_m1_configuration_builder_v1, manifest_digest=pin, simulated_billing=simulated_billing)

    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            mapping, clock = adopt_mapping_and_clock(case)
            for domain in ("d01", "d03", "d06", "d07", "d08", "d10"):
                registration = case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
            install_m1_owner_body_and_catalogue_v1(case)
            initialized.update(case, installed_mapping=mapping, installed_clock=clock)
        await asyncio.to_thread(initialize)

    async def actual_c02(case):
        from sylanne3.host.v2_installation import V2InstallationAssembly
        graph = case["graph"]
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        assert type(assembly) is V2InstallationAssembly
        # All policy, grant and workflow objects are the initial selected ones;
        # the later bundle adds the actual already-created ingress clock/input.
        assert assembly.admin_bundle.installation_policy is case["installed_bundle"].installation_policy
        assert assembly.admin_bundle.model_workflows is case["installed_bundle"].model_workflows
        assert assembly.admin_bundle.provider_billing_policy_v1 is case["installed_bundle"].provider_billing_policy_v1
        graph._GraphCoordinator__d04_installed_joint_assembly = replace(assembly,
            admin_bundle=case["installed_bundle"], ingress_clock=case["installed_bundle"].ingress_clock,
            ingress_encoding=case["installed_bundle"].ingress_encoding)
        actual = {**initialized, **case}
        await asyncio.to_thread(compose_actual_m1_services_v1, actual)
        install_actual_m1_model_runtime_v1(actual)
        await asyncio.to_thread(register_actual_m1_task_root_v1, actual)
        bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        created = await asyncio.to_thread(graph.prepare_post_c02_foreground_cycle_v1, case["bootstrap"], bundle, **args)
        acquired = await asyncio.to_thread(graph.acquire_post_c02_foreground_cycle_v1, case["bootstrap"], bundle, **args)
        assert created["receipt"]["status"] == acquired["receipt"]["status"] == "committed"
        actual.update(m1_cycle_creation=created, m1_cycle_acquisition=acquired)
        await after_c02(actual)

    await real_owner_case(tmp_path, "owned", installed_package_root=installed_root,
        initial_m1_configuration_builder=builder, after_role_initialization=after_role,
        continue_to_ingress=True, after_c02=actual_c02, enable_d09_workbench=True,
        enable_c04_body_work=True, register_c04_domains=True, enable_d04_root_cpu=True,
        enable_d10_offline_ticks=True, enable_d12_package_maintenance=True,
        enable_c09_maintenance=True, extra_owner_purposes=("context", "consolidation"),
        ingress_text="请把这条任务整理成一份本地文字草稿。")



def approve_m1_phase_standing_predecision_v3(case):
    """Genuine Owner W01 after the actual Self projection and before paid C1."""
    import time
    from test_current_domain_production_v1 import command
    from sylanne3.host.authority_profile import (
        AdminArtifactStandingScopeV3, artifact_candidate_preparation_dependency_contract_v1,
    )
    from sylanne3.runtime.artifact_phase_postconditions_v1 import (
        APPROVAL_KIND_V2, APPROVAL_OPERATION_V2, ApproveArtifactStandingPredecisionRequestV2,
        ArtifactStandingPredecisionApprovalOriginalV3,
        artifact_standing_predecision_approval_operation_id_v2,
        read_current_artifact_standing_predecision_approval_v2, _standing_approval_from_wire_v2,
    )
    from sylanne3.runtime.d11_life_preparation_v1 import _read
    graph, bundle = case["graph"], case["installed_bundle"]
    assert graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is bundle
    scope = bundle.artifact_draft.standing_scope
    assert type(scope) is AdminArtifactStandingScopeV3
    contract = artifact_candidate_preparation_dependency_contract_v1()
    assert not case["phase_provider_calls"]
    operation_id = artifact_standing_predecision_approval_operation_id_v2(scope.approval_original_ref)
    result = command(case, APPROVAL_OPERATION_V2,
        ApproveArtifactStandingPredecisionRequestV2(scope.approval_original_ref),
        operation_id=operation_id, activity_id="activity:m1-initial-standing-approval")
    with case["store"]._lock:
        db = case["store"]._db
        raw, producer = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"],
            kind=APPROVAL_KIND_V2, ref=scope.approval_original_ref)
        saved = _standing_approval_from_wire_v2(raw)
        approved = read_current_artifact_standing_predecision_approval_v2(db,
            namespace=case["namespace"], bundle=bundle, issuer=case["d11_issuer"],
            owner_guard=saved.owner_guard, now_utc=time.time())
    assert type(approved) is ArtifactStandingPredecisionApprovalOriginalV3
    assert (approved.preparation_dependency_contract_ref, approved.preparation_dependency_contract_digest) == (
        contract.original_ref, contract.digest)
    assert producer == approved.registration_operation_id == operation_id
    assert approved.approver_actor_ref == "owner-actor-reply"
    assert approved.self_actor_ref == scope.self_actor_ref == "entity:self-reply"
    assert approved.self_actor_ref != approved.approver_actor_ref
    assert approved.scope == scope and approved.root_budget_lease_ref == case["policy"].root_lease.lease_id
    assert approved.original_deadline_utc <= case["policy"].root_grant.valid_until_utc
    assert not case["phase_provider_calls"]
    case.update(phase_standing_approval=approved, phase_standing_approval_receipt=result)
    return approved


def adopt_m1_phase_owner_project_role_v2(case):
    """Actual Owner role W01 for the preregistered task Project, before C4."""
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
    from sylanne3.runtime.c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from sylanne3.runtime.artifact_continuation_originals_v1 import artifact_control_keys_for_task_v1
    from sylanne3.runtime.d03_life_project_context_v1 import AdoptOwnerArtifactProjectContextRequestV1
    from sylanne3.runtime.jobs import get_job
    graph, ns, bundle = case["graph"], case["namespace"], case["installed_bundle"]
    store = graph._GraphCoordinator__store
    with store._lock:
        cycle = get_job(store._db, foreground_cycle_ids_v1(ns, case["c02"].operation_id)[1])
        responsibility = read_original_foreground_responsibility_for_c09_v1(store._db,
            namespace=ns, job=cycle, issuer=case["d11_issuer"])
        keys = artifact_control_keys_for_task_v1(store._db, namespace=ns,
            c02_operation_id=case["c02"].operation_id, root_registration_ref=responsibility.root_registration_ref)
    request = AdoptOwnerArtifactProjectContextRequestV1(keys[2].token, keys[3].token,
        case["source_ref"], case["m1_owner_social_role"], case["m1_owner_norm_refs"])
    audience = case["ingress"].conversation_ref
    authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
        namespace=ns, domains=("d03",), purpose="consolidation", audience=audience,
        activation_generation=1, owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"])
    try:
        result = graph.run_current_domain_operation_v1(authority, lease,
            operation_kind="adopt_owner_artifact_project_context_v1", request=request,
            operation_id=str(uuid4()), activity_id=cycle.activity_id, audience_ref=audience,
            parent_budget_lease_ref=cycle.budget_ref)
        assert result["receipt"]["status"] == "committed", result
        return result
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)


async def install_actual_m1_c3_runtime_v2(case):
    """Install the one actual mTLS C3 consumer before any paid preparation."""
    from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    worker, graph, bootstrap, bundle = case["phase_worker"], case["graph"], case["bootstrap"], case["installed_bundle"]
    owner_loop = asyncio.get_running_loop()
    installation = graph._GraphCoordinator__d04_installed_joint_assembly
    def install(current_graph):
        service = InstalledD07ExecutionServiceV1(graph=current_graph, bootstrap=bootstrap, bundle=bundle,
            installation=installation, worker=worker, authority_client=case["authority_client"],
            client_grant=case["client_grant"], context=case["model_context"], owner_loop=owner_loop)
        current_graph._GraphCoordinator__d07_execution_service_v1 = service
        current_graph._GraphCoordinator__body_quote_authority = service.body_authority
        return service
    if "phase_c3_runtime" in case:
        service = case["phase_c3_runtime"]
        assert graph._GraphCoordinator__d07_execution_service_v1 is service
    else:
        service = await worker.call(install)
        case["phase_c3_runtime"] = service
    return service


async def commit_actual_m1_phase_event_v2(case, *, text, scope_only):
    """One new observed Owner event, never a renamed or cloned C02."""
    from sylanne3.runtime.c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    first, c02, ingress = await case["commit_second_c02"]("m1-event:" + uuid4().hex,
        text, commit_attention=True, return_envelope=True)
    attention_inputs = await case["phase_worker"].call(lambda graph:
        graph.read_post_c02_attention_inputs_v1(case["bootstrap"], case["namespace"],
            c02.operation_id, None, case["installed_bundle"]))
    assert attention_inputs[0] == c02 and len(attention_inputs[2].source_refs) == 1
    source_ref = attention_inputs[2].source_refs[0]
    assert source_ref != case["source_ref"]
    event_case = {**case, "c02": c02, "ingress": ingress, "source_ref": source_ref}
    with cold_originals_v1(event_case) as db:
        intent = read_c1_task_intent_original_v1(db, namespace=case["namespace"],
            c02_operation_id=c02.operation_id, issuer=case["d11_issuer"])
        source = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (source_ref,)).fetchone()
        assert source is not None and source[1] == 1 and json.loads(source[0])["text"] == text
    args = {"c02_operation_id": c02.operation_id, "source_ref": source_ref}
    if scope_only:
        assert intent is not None
        scope = await case["phase_worker"].call(lambda graph:
            graph.prepare_post_c02_artifact_task_scope_v1(case["bootstrap"], case["installed_bundle"], **args))
        assert scope is not None and scope["receipt"]["status"] == "committed", scope
        event_case["m1_task_scope_creation"] = scope
    else:
        assert text == M1_METHOD_ASSESSMENT_TEXT_V6 and intent is None
        created = await case["phase_worker"].call(lambda graph:
            graph.prepare_post_c02_foreground_cycle_v1(case["bootstrap"], case["installed_bundle"], **args))
        acquired = await case["phase_worker"].call(lambda graph:
            graph.acquire_post_c02_foreground_cycle_v1(case["bootstrap"], case["installed_bundle"], **args))
        assert created["receipt"]["status"] == acquired["receipt"]["status"] == "committed"
        event_case.update(m1_cycle_creation=created, m1_cycle_acquisition=acquired)
    event_case["actual_ingress_receipt"] = first
    return event_case


def run_actual_m1_owner_method_operation_v2(case, kind, request, *, producer, cycle_parent=False):
    """Exact current Owner W01; growth cognition pays its actual cause's lease."""
    from test_current_domain_production_v1 import domain_owner
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
    from sylanne3.runtime.jobs import get_job
    graph, ns = case["graph"], case["namespace"]
    if cycle_parent:
        with case["store"]._lock:
            job = get_job(case["store"]._db, foreground_cycle_ids_v1(ns, case["c02"].operation_id)[1])
        assert job.phase == "running" and job.cancel_epoch == 0
        parent, activity = job.budget_ref, job.activity_id
    else:
        parent, activity = case["policy"].root_grant.lease_id, "activity:m1-method-registration"
    with domain_owner(case) as (authority, lease):
        operation = graph.register_current_domain_input_v1 if producer else graph.run_current_domain_operation_v1
        result = operation(authority, lease, **{"producer_kind" if producer else "operation_kind": kind},
            request=request, operation_id=str(uuid4()), activity_id=activity,
            audience_ref="owner", parent_budget_lease_ref=parent)
    assert result["schema"] == "sylanne.domain-production-receipt.v1", repr(
        graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1)
    assert result["receipt"]["status"] == "committed", result
    return result


async def register_actual_m1_method_trial_v2(case, *, treatment_case):
    """Actual preregistered proposal → paid independent growth C3 → scoped ST1."""
    from sylanne3.domains.d01 import METHOD_POLICY_ID_V1, method_policy_state_v1, _activation_key
    from sylanne3.domains.d01.method_learning_v1 import (
        MethodEvaluationProtocolV1, MethodTrialProposalV2, PROTOCOL_TYPE, TRIAL_PROPOSAL_TYPE_V2,
        TRIAL_TYPE, method_learning_key_v1)
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.graph_types import AtomKey, GraphVersion, Owner
    from sylanne3.runtime_contracts import VersionedRef
    from sylanne3.runtime.d01_method_learning_v1 import (
        RegisterMethodEvaluationProtocolRequestV1, RegisterMethodTrialProposalRequestV2,
        RegisterScopedMethodTrialRequestV2, trial_question_v2)
    from sylanne3.runtime.d07_method_growth_semantic_v2 import (
        D07MethodGrowthSemanticQuestionV2, D07MethodGrowthPreparedV2)
    from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentSemanticQuestionInputRequestV1
    from sylanne3.runtime.d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1, read_observed_foreground_call_plan_v1, foreground_cycle_from_wire_v1
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.jobs import get_job, _utc
    from sylanne3.runtime.d11_life_preparation_v1 import TABLE, _read
    policy = case["installed_bundle"].method_measurement_policy
    assert policy is not None
    ns, worker = case["namespace"], case["phase_worker"]
    # This independent natural cause may require the ordinary routing C3.
    # It pays that actual original before growth; no NoSearch certificate is manufactured.
    await prepare_actual_m1_phase_recall_v2(case)
    def actual_heads(graph):
        with case["store"]._lock:
            db = case["store"]._db
            activation = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (_activation_key(ns).token,)).fetchone()
            assert activation is not None and activation[1] == 1
            active = json.loads(activation[0])
            plan = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",
                (AtomKey(Owner("persona", *ns.as_tuple), "d01.persona_plan.v1", active["plan_id"]).token,)).fetchone()[0])
            block = next(row for row in plan["blocks"] if row["block_id"] == METHOD_POLICY_ID_V1)
            assert block["kind"] == "strategy" and block["plasticity"] == "growth" and method_policy_state_v1(block["claim"]) == "ST0"
            authored = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' "
                "AND valid=1 AND json_extract(value,'$.source_kind')='authored' ORDER BY token LIMIT 1", ns.as_tuple).fetchone()
            assert authored is not None
            rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='artifact_task_objective' "
                "AND json_extract(payload_json,'$.initial_c02_operation_id')=? LIMIT 2", (*ns.as_tuple, treatment_case["c02"].operation_id)).fetchall()
            assert len(rows) == 1
            objective = _read(db, issuer=case["d11_issuer"], namespace=ns, kind="artifact_task_objective", ref=rows[0][0])[0]
            job = get_job(db, foreground_cycle_ids_v1(ns, case["c02"].operation_id)[1])
            cycle_key = job_graph_write(job).key
            revision, raw = db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1", (cycle_key.token,)).fetchone()
            source_revision, source_raw = db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1", (case["source_ref"],)).fetchone()
            grant = case["d11_issuer"].current_budget_grant(db, job.budget_ref)
            until = min(_utc(job.deadline_utc, "deadline_utc").timestamp(), grant.valid_until_utc)
            return active["head_id"], authored[0], objective["goal_ref"], job, GraphVersion(cycle_key, revision), canonical_digest(json.loads(raw)), GraphVersion(AtomKey.from_token(case["source_ref"]), source_revision), json.loads(source_raw), until
    base_head, authored_ref, goal_ref, cause_job, cycle_head, cycle_digest, source_head, source_value, until = await worker.call(actual_heads)
    protocol = MethodEvaluationProtocolV1(ns, "m1-protocol:" + uuid4().hex, METHOD_POLICY_ID_V1,
        2, 2, 100000, 100000, policy.policy_ref, policy.digest, (authored_ref,), float(source_value["recorded_at"]), until)
    await worker.call(lambda graph: run_actual_m1_owner_method_operation_v2(case,
        "register_method_evaluation_protocol_v1", RegisterMethodEvaluationProtocolRequestV1(protocol), producer=False))
    protocol_ref = method_learning_key_v1(ns, PROTOCOL_TYPE, protocol.protocol_id).token
    proposal = MethodTrialProposalV2(ns, "m1-trial:" + uuid4().hex, "m1-growth-proposal:" + uuid4().hex,
        base_head, METHOD_POLICY_ID_V1, protocol_ref, canonical_digest(plain_v1(protocol)), (goal_ref,),
        (case["source_ref"],), protocol.valid_from, until)
    await worker.call(lambda graph: run_actual_m1_owner_method_operation_v2(case,
        "register_method_trial_proposal_v2", RegisterMethodTrialProposalRequestV2(proposal), producer=False))
    proposal_ref = method_learning_key_v1(ns, TRIAL_PROPOSAL_TYPE_V2, proposal.trial_id).token
    # The two registration commits did not mutate the cause; authenticate the current head afresh.
    _, _, _, cause_job, cycle_head, cycle_digest, source_head, source_value, until = await worker.call(actual_heads)
    digest = canonical_digest(plain_v1(proposal))
    question = D07MethodGrowthSemanticQuestionV2(question_key=trial_question_v2(proposal_ref, digest),
        question="Evaluate the already registered bounded method trial proposal; return accepted only for this exact proposal.",
        target_ref=VersionedRef(proposal_ref, 1), source_refs=proposal.source_refs,
        cycle_ref=cycle_head, cycle_digest=cycle_digest,
        proposal_head=GraphVersion(AtomKey.from_token(proposal_ref), 1), proposal_digest=digest,
        c02_operation_id=case["c02"].operation_id, source_head=source_head, source_digest=canonical_digest(source_value),
        parent_budget_lease_ref=cause_job.budget_ref, original_deadline_utc=until)
    service = await install_actual_m1_c3_runtime_v2(case)
    question_ref = "m1-growth-question:" + uuid4().hex
    await worker.call(lambda graph: run_actual_m1_owner_method_operation_v2(case, "register_semantic_question",
        RegisterCurrentSemanticQuestionInputRequestV1(question_ref, question), producer=True, cycle_parent=True))
    receipt = await worker.call(lambda graph: run_actual_m1_owner_method_operation_v2(case, "serve_concern",
        ServeCurrentConcernRequestV1("interaction", question_ref), producer=False, cycle_parent=True))
    assert receipt["coverage"] == "deferred", receipt
    await asyncio.sleep(0)
    assert service._runner_task is not None
    await service._runner_task
    job_id = receipt["job_states"][0][0]
    with cold_originals_v1(case) as db:
        prepared = read_prepared_d07_execution_v1(db, case["d11_issuer"], ns, job_id)
        assert type(prepared) is D07MethodGrowthPreparedV2 and prepared.parent_budget_lease_ref == cause_job.budget_ref
        current = get_job(db, cause_job.job_id)
        plan = read_observed_foreground_call_plan_v1(db, namespace=ns,
            continuation=foreground_cycle_from_wire_v1(current.continuation), issuer=case["d11_issuer"], installed_bundle=case["installed_bundle"])
        assert len([row for row in plan.attempts if row.slot == "C3"]) == 2
        assert sum(row.slot == "C3" and row.call_id == prepared.call_id for row in plan.attempts) == 1
    adopted = service._last_progress[job_id]
    assert adopted["status"] == "adopted" and len(adopted["interpretation_refs"]) == 1, adopted
    gp1_ref = adopted["interpretation_refs"][0]
    trial_receipt = await worker.call(lambda graph: run_actual_m1_owner_method_operation_v2(case,
        "register_scoped_method_trial_v2", RegisterScopedMethodTrialRequestV2(proposal_ref, gp1_ref), producer=False))
    trial_ref = method_learning_key_v1(ns, TRIAL_TYPE, proposal.trial_id).token
    with cold_originals_v1(case) as db:
        trial = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1", (trial_ref,)).fetchone()[0])
        assert trial["status"] == "scoped_trial" and trial["gp1_interpretation_ref"] == gp1_ref
        assert trial["goal_refs"] == [goal_ref] and trial["base_persona_head"] == base_head
    case.update(method_protocol=protocol, method_protocol_ref=protocol_ref, method_trial_proposal=proposal,
        method_trial_proposal_ref=proposal_ref, method_growth_prepared=prepared, method_gp1_ref=gp1_ref,
        method_trial_ref=trial_ref, method_trial_receipt=trial_receipt)
    return trial_ref


async def prepare_actual_m1_phase_recall_v2(case):
    """Use the ordinary queue and the single actual installed C3 job consumer."""
    from sylanne3.runtime.d07_ingress_recall_preparation_v1 import OPERATION
    from sylanne3.runtime.d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1
    worker, bootstrap, bundle = case["phase_worker"], case["bootstrap"], case["installed_bundle"]
    service = await install_actual_m1_c3_runtime_v2(case)
    arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
    need = await worker.call(lambda current_graph:
        current_graph.prepare_current_post_c02_recall_need_v1(bootstrap, bundle, **arguments))
    assert need["receipt"]["receipt"]["status"] == "committed", need
    assert need["need"]["routing"] == "semantic_route_required", need
    prepared = await worker.call(lambda current_graph:
        current_graph.run_current_post_c02_ingress_recall_model_operation_v1(bootstrap, bundle,
            operation_kind=OPERATION, **arguments))
    assert prepared["receipt"]["status"] == "committed", prepared
    # The production notification owns the execution. Await that real job runner.
    await asyncio.sleep(0)
    assert service._runner_task is not None
    await service._runner_task
    def read(current_graph):
        store = current_graph._GraphCoordinator__store
        with store._lock:
            return read_adopted_ingress_recall_routing_v1(store._db, namespace=case["namespace"],
                c02_operation_id=case["c02"].operation_id, issuer=current_graph._GraphCoordinator__d11_issuer)
    routing = await worker.call(read)
    assert routing is not None and routing["stop_reason"] == "no_history_needed", routing
    acquired = await worker.call(lambda current_graph:
        current_graph.acquire_post_c02_foreground_cycle_v1(bootstrap, bundle, **arguments))
    assert acquired["receipt"]["status"] == "committed", acquired
    case.update(phase_actual_need=need, phase_actual_recall_preparation=prepared, phase_actual_recall_routing=routing)
    return routing



async def compose_actual_m1_phase_natural_runtime_v2(case):
    """Reuse the actual namespace and channels; no paid-stage readiness is seeded."""
    from sylanne3.runtime_context import RuntimeContext
    from sylanne3.host.v2_installation import V2InstallationAssembly
    from sylanne3.host.natural_generation_output_port import InstalledNaturalGenerationOutputPortV2
    from sylanne3.host.natural_generation_content_port import InstalledNaturalGenerationContentPortV2
    from sylanne3.host.natural_review_output_port import InstalledNaturalReviewOutputPortV2
    from sylanne3.host.natural_paid_review_port import InstalledNaturalPaidReviewPortV2
    from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
    from sylanne3.host.managed_data_layout_v1 import InstalledDataLayoutV1
    if "phase_natural_runtime" in case:
        return case["phase_natural_runtime"], case["phase_natural_installation"]
    graph, worker, bundle, port = case["graph"], case["phase_worker"], case["installed_bundle"], case["port"]
    policy, original_grant = bundle.installation_policy, case["grant"]
    configured = graph._GraphCoordinator__d04_installed_joint_assembly
    assert type(configured) is V2InstallationAssembly and configured.admin_bundle is bundle
    assert configured.installation_policy is policy
    admission = case["m1_storage_admission"]
    admission.require_current_process_v1()
    actual_data_root = case["m1_initial_configuration"].data_dir / "host-data"
    assert admission.graph_path == actual_data_root / "sylanne3.sqlite3"
    with case["store"]._lock:
        assert Path(case["store"]._db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True) == admission.graph_path
    layout = InstalledDataLayoutV1(actual_data_root, admission.graph_path, admission)
    assert same_installed_grant_identity_v2(original_grant, case["client_grant"])
    reverse_binding = configured.reverse_handoff
    from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
    if type(bundle.model_workflows) is AdminModelWorkflowsV6 and bundle.model_workflows.growth_cognition is not None:
        from sylanne3.host.final_handoff_pairing import TrustedFinalHandoffBindingV1
        from sylanne3.host.reverse_handoff import HostReverseGraphClaimServer
        from sylanne3.authority_service.reverse_handoff import ReverseGraphClaimClient
        assert type(case["reverse_server"]) is HostReverseGraphClaimServer
        assert type(case["reverse_client"]) is ReverseGraphClaimClient
        endpoint = case["reverse_client"].profile
        listening = case["reverse_listener"].sockets[0].getsockname()
        assert listening[1] == endpoint.port and case["reverse_listener"].is_serving()
        reverse_binding = TrustedFinalHandoffBindingV1(case["reverse_server"].profile,
            listening[0], endpoint.host, endpoint.port, endpoint.server_name)
        # This declared local endpoint is still unverified. Only the genuine
        # installed mTLS pairing reader/public handoff factory authenticates it.
    installation = V2InstallationAssembly(policy, original_grant,
        bundle.d11_signing_key, bundle.d02_signing_key, lambda: port,
        configured.package_root, actual_data_root,
        available_cpu_features=configured.available_cpu_features,
        ingress_clock=bundle.ingress_clock, ingress_encoding=bundle.ingress_encoding,
        workbench_origin=configured.workbench_origin, ingress_model=configured.ingress_model,
        admin_bundle=bundle, d03_arrival=bundle.d03_arrival,
        reverse_handoff=reverse_binding, storage_admission=admission,
        data_layout=layout)
    assert installation.graph_path == admission.graph_path
    runtime = RuntimeContext(installation.data_dir, package_root=installation.package_root, dependencies=None)
    runtime._worker, runtime._v2_bootstrap, runtime._v2_port = worker, case["bootstrap"], port
    runtime._v2_namespace, runtime._v2_policy = policy.namespace, policy
    runtime._v2_installation_grant, runtime._v2_model_bundle = original_grant, bundle
    runtime._v2_provision = lambda current_graph, operation_id: current_graph.provision_namespace_v2(
        case["bootstrap"], policy, operation_id=operation_id)
    # The public runtime method reconciles this exact already-committed initial
    # operation. It sets namespace state from the real factory; no new Root is issued.
    before_calls = tuple(case["phase_provider_calls"])
    created = await runtime.provision_installed_namespace(case["namespace_creation"].operation_id)
    assert created == case["namespace_creation"]
    assert tuple(case["phase_provider_calls"]) == before_calls
    loop = asyncio.get_running_loop()
    parameters = dict(client=case["authority_client"], bundle=bundle,
        grant=case["client_grant"], owner_loop=loop)
    generation = InstalledNaturalGenerationOutputPortV2(**parameters)
    content = InstalledNaturalGenerationContentPortV2(**parameters)
    review = InstalledNaturalReviewOutputPortV2(**parameters)
    paid = InstalledNaturalPaidReviewPortV2(**parameters)
    def bind(current_graph):
        assert current_graph is graph and current_graph._GraphCoordinator__content_fence_v2 is port
        current_graph._GraphCoordinator__natural_generation_output_port = generation.read_original_natural_generation_output_v2
        current_graph._GraphCoordinator__natural_generation_content_port = content.read_current_natural_generation_content_v2
        current_graph._GraphCoordinator__natural_review_output_port = review.read_original_natural_review_output_v2
        current_graph._GraphCoordinator__natural_paid_review_current_port = paid.read_current_natural_paid_review_v2
        return port.bind_natural_paid_consumers_v2(current_graph, bundle, original_grant)
    assert await worker.call(bind) is True
    # The production factory verifies its three real channels independently:
    # original installation grant, live FencePort grant, and these installed readers.
    case.update(phase_natural_runtime=runtime, phase_natural_installation=installation,
        phase_natural_ports=(generation, content, review, paid))
    return runtime, installation


async def run_actual_m1_phase_protected_reply_v2(case):
    """Actual C5/C6 provider terminals and once-only accounting on the same graph."""
    from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2, read_original_preparation
    from sylanne3.host.installed_natural_reply_driver import (
        InstalledNaturalGenerationProgressV2, run_installed_post_c02_natural_generation_v2,
    )
    from sylanne3.host.installed_natural_review_driver import (
        InstalledNaturalReviewProgressV2, run_installed_post_c02_natural_review_v2,
    )
    runtime, installation = await compose_actual_m1_phase_natural_runtime_v2(case)
    worker, bundle = case["phase_worker"], case["installed_bundle"]
    arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
    waiting = await worker.call(lambda graph: graph.checkpoint_post_c02_foreground_wait_v1(
        case["bootstrap"], bundle, **arguments))
    assert waiting["receipt"]["status"] == "committed", waiting
    saved = await worker.call(lambda graph: graph.prepare_post_c02_natural_generation_v2(
        case["bootstrap"], case["namespace"], case["c02"].operation_id, case["source_ref"], bundle))
    assert type(saved) is SavedNaturalPreparationV2 and saved.state == "queued"
    assert saved.seal.c02_operation_id == case["c02"].operation_id and saved.seal.source_ref == case["source_ref"]
    audience = json.loads(case["ingress"].conversation_ref)
    before_calls = len(case["phase_provider_calls"])
    generated = await run_installed_post_c02_natural_generation_v2(runtime, installation,
        context=case["model_context"], trusted_umo=audience[0], saved=saved)
    assert type(generated) is InstalledNaturalGenerationProgressV2
    assert generated.status == "review_content_hold", generated
    assert len(case["phase_provider_calls"]) == before_calls + 1
    with cold_originals_v1(case) as db:
        current_generation = read_original_preparation(db, case["namespace"], case["c02"].operation_id, "generation")
    assert current_generation.state == "terminal" and current_generation.seal == saved.seal
    review = await runtime._prepare_installed_natural_review_v2(installation, current_generation)
    assert type(review) is SavedNaturalPreparationV2 and review.state == "queued"
    assert review.seal.generation_original_operation_id == saved.seal.original_operation_id
    reviewed = await run_installed_post_c02_natural_review_v2(runtime, installation,
        context=case["model_context"], trusted_umo=audience[0],
        generation_saved=current_generation, review_saved=review)
    assert type(reviewed) is InstalledNaturalReviewProgressV2
    assert reviewed.status == "paid_review_current_hold", reviewed
    assert len(case["phase_provider_calls"]) == before_calls + 2
    assert generated.output.terminal_receipt_digest and reviewed.output.terminal_receipt_digest
    case.update(phase_natural_generation=generated, phase_natural_review=reviewed)
    return generated, reviewed


async def finish_actual_m1_method_assessment_reply_v2(case):
    """Scoped installed Graph/service chain, not a Main.start_v2 qualification.

    Every paid and final boundary is the production consumer. The genuine
    public handoff factory installs its writer; no readiness flag is supplied.
    """
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    from sylanne3.host.natural_reply_dispatch_driver import (
        InstalledNaturalReplyContinuationV2, NaturalReplyDispatchDriverV2)
    from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
    from sylanne3.runtime_contracts import AuthorityContext
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
    from sylanne3.runtime.jobs import get_job
    await run_actual_m1_phase_protected_reply_v2(case)
    runtime, installation = case["phase_natural_runtime"], case["phase_natural_installation"]
    worker, bootstrap, port = case["phase_worker"], case["bootstrap"], case["port"]
    policy, grant, bundle = installation.installation_policy, installation.installation_grant, installation.admin_bundle
    assert case["reverse_listener"].is_serving()
    verified, writer = await runtime.install_final_handoff_pairing_v1(installation, installation.reverse_handoff,
        host_context=case["host_context"], host_loop=asyncio.get_running_loop(), candidates=case["observed"])
    assert writer is runtime._final_claim_writer and verified.binding is installation.reverse_handoff
    with cold_originals_v1(case) as db:
        saved = read_original_preparation(db, case["namespace"], case["c02"].operation_id, "generation")
    identities = await runtime._read_installed_natural_batch_identity_v3(installation, saved)
    assert identities is not None and len(identities) == 1
    adapter, send_calls = case["adapter"], []
    previous_action = adapter.bot.call_action.side_effect
    async def actual_local_onebot(action, **kwargs):
        if action == "send_private_msg":
            send_calls.append((action, kwargs))
            assert len(send_calls) == 1
            return {"message_id": 97001}
        return {"user_id": "10001"}
    adapter.bot.call_action.side_effect = actual_local_onebot
    try:
        final = await runtime._commit_installed_natural_final_v2(installation, saved, segment_index=0)
        assert final is not None and (final.operation_id, final.effect_id) == identities[0]
        operation_id = final.operation_id
        # GraphWorker executes on its own thread, so retain the actual SDK owner loop.
        owner_loop = asyncio.get_running_loop()
        def factory(graph):
            anchor = port.current_anchor(namespace=policy.namespace, authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(bootstrap, actor=grant.administrator_holder,
                issuer_domain="d11", namespace=policy.namespace, domains=("d08", "d09", "d11"),
                activation_generation=anchor.activation_generation, operation_id=operation_id)
            try:
                authority = AuthorityContext(grant.administrator_holder, "d11", capability, policy.namespace,
                    ("activity",), "expression", ("internal",), policy.root_grant.policy_ref, anchor.activation_generation)
                route = InstalledDispatchRoutePort(context=case["host_context"], host_loop=owner_loop,
                    candidates=case["observed"], coordinator=graph, authority=authority, lease=lease, policy=policy, grant=grant)
                return authority, lease, graph.register_natural_dispatch_final_claim_writer_v2(
                    bootstrap, route_port=route, issuer_id=verified.issuer_id)
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise
        authority, lease, actual_writer = await worker.call(factory)
        try:
            continuation = InstalledNaturalReplyContinuationV2(worker=worker, authority=authority, lease=lease,
                local_module_admission=case["graph"].local_module_admission, fence_port=port, policy=policy, grant=grant,
                server=case["reverse_server"], natural_claim_writer=actual_writer, context=case["host_context"],
                candidates=case["observed"], clock_policy=bundle.ingress_clock, adapter_ref="astrbot:onebot:call_action")
            driver = NaturalReplyDispatchDriverV2(worker, authority, lease, continuation)
            witness = await worker.call(lambda graph: graph.read_natural_dispatch_resume_witness_v3(
                authority, lease, operation_id, bundle))
            assert witness.mode == "resume-original-child" and witness.child_identities[witness.segment_index][0] == operation_id
            dispatched = await driver.run_once(operation_id=operation_id, fresh_dispatch=True)
            assert dispatched.status == "accepted" and len(send_calls) == 1, dispatched
            await worker.call(lambda graph: graph.record_natural_outbound_observation_v1(bootstrap, policy.namespace, operation_id))
        finally:
            await worker.call(lambda graph: graph.release_authority_lease(bootstrap, lease))
        maintained = await worker.call(lambda graph: graph.maintain_natural_batch_disposition_v1(
            bootstrap, policy.namespace, case["c02"].operation_id))
        assert maintained["status"] in {"committed", "unchanged"}, maintained
        with cold_originals_v1(case) as db:
            cycle = get_job(db, foreground_cycle_ids_v1(case["namespace"], case["c02"].operation_id)[1])
            # Existing waiting checkpoint releases the real worker; report its actual state.
            assert cycle.phase != "running" and cycle.lease_holder is None
        case.update(method_assessment_reply=dispatched, method_assessment_disposition=maintained,
            method_assessment_cycle_phase=cycle.phase, method_assessment_send_calls=tuple(send_calls))
        return dispatched
    finally:
        adapter.bot.call_action.side_effect = previous_action
        await runtime.uninstall_final_handoff_pairing_v1()


async def run_installed_m1_phase_case_v2(installation, *, after_c02, owner_controls=False,
        before_source_note_initial_cycle=None, prepare_artifact_scope_only=False):
    """One actual initial phase installation, with no post-qualification patch."""
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from test_d04_owner_semantic_initialization_v3 import (
        real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
    )
    assert type(installation) is M1PhaseFixtureInstallationV2
    initialized = {}

    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            mapping, clock = adopt_mapping_and_clock(case)
            for domain in ("d01", "d03", "d06", "d07", "d08", "d10"):
                registration = case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
            install_m1_owner_body_and_catalogue_v1(case)
            from d11_offline_authority_acceptance_support_v1 import install_phase_fixture_recall_owner_policies_v1
            install_phase_fixture_recall_owner_policies_v1(case)
            initialized.update(case, installed_mapping=mapping, installed_clock=clock)
        await asyncio.to_thread(initialize)

    async def actual_c02(case):
        graph, bundle = case["graph"], case["installed_bundle"]
        qualification = case["phase_fixture_qualification"]
        assert graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is bundle
        assert qualification.bundle is bundle and qualification.client_grant is case["client_grant"]
        assert qualification.authority_client is case["authority_client"]
        actual = {**initialized, **case}
        from sylanne3.graph_worker import GraphWorker
        worker = await case["get_http_worker"]()
        assert type(worker) is GraphWorker and worker is qualification.worker
        runtime = case["phase_model_runtime"]
        assert runtime is qualification.model_runtime and runtime.worker is worker
        assert runtime.bundle is bundle and runtime.client_grant is qualification.client_grant
        actual.update(m1_model_runtime=runtime, phase_worker=worker)
        assert actual["phase_standing_approval"].scope == bundle.artifact_draft.standing_scope
        assert not actual["phase_standing_approval"].self_actor_ref == actual["phase_standing_approval"].approver_actor_ref
        await worker.call(lambda current_graph: compose_actual_m1_services_v1(actual))
        args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        # Each initial mode creates its own actual cycle from the original C02 authorization.
        if prepare_artifact_scope_only:
            assert before_source_note_initial_cycle is None
            from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
            assert type(bundle.model_workflows) is AdminModelWorkflowsV6 and bundle.model_workflows.growth_cognition is not None
            scope = await worker.call(lambda current_graph:
                current_graph.prepare_post_c02_artifact_task_scope_v1(case["bootstrap"], bundle, **args))
            assert scope is not None and scope["receipt"]["status"] == "committed", scope
            actual["m1_task_scope_creation"] = scope
        elif before_source_note_initial_cycle is not None:
            from sylanne3.runtime.d11_life_contract_v1 import WORK_KIND as SOURCE_NOTE_WORK_KIND
            assert SOURCE_NOTE_WORK_KIND in bundle.installation_policy.root_grant.allowed_work_kinds
            await before_source_note_initial_cycle(actual)
            authorization_ref = actual["source_note_authorization_original_ref"]
            created = await worker.call(lambda current_graph:
                current_graph.prepare_source_note_foreground_cycle_v1(case["bootstrap"], bundle,
                    authorization_original_ref=authorization_ref, **args))
        else:
            created = await worker.call(lambda current_graph:
                current_graph.prepare_post_c02_foreground_cycle_v1(case["bootstrap"], bundle, **args))
        if not prepare_artifact_scope_only:
            acquired = await worker.call(lambda current_graph:
                current_graph.acquire_post_c02_foreground_cycle_v1(case["bootstrap"], bundle, **args))
            assert created["receipt"]["status"] == acquired["receipt"]["status"] == "committed"
            actual.update(m1_cycle_creation=created, m1_cycle_acquisition=acquired)
        try:
            await after_c02(actual)
        finally:
            if actual.get("phase_c3_runtime") is not None:
                await actual["phase_c3_runtime"].close_v1()

    await real_owner_case(installation.data_dir, "owned", installed_package_root=installation.package_root,
        initial_phase_fixture_installation=installation, after_role_initialization=after_role,
        continue_to_ingress=True, after_c02=actual_c02, enable_d09_workbench=True,
        enable_c04_body_work=True, register_c04_domains=True, enable_d04_root_cpu=True,
        enable_d10_offline_ticks=True, enable_d12_package_maintenance=True,
        enable_c09_maintenance=True,
        extra_owner_capabilities=("workbench.control", "workbench.correct") if owner_controls else (),
        extra_owner_purposes=("context", "consolidation", "audit") if owner_controls else ("context", "consolidation"),
        ingress_text=M1_METHOD_BASELINE_TEXT_V6 if installation.artifact_draft.schema == "sylanne.artifact-draft-policy.v4" else
            M1_METHOD_TASK_TEXT_V4 if installation.workflows.encode.template_version ==
                "sylanne.d06.first_ingress_encoding.v4" else M1_PHASE_TASK_TEXT_V2)


def assert_original_file_witness_v1(root, prepared, terminal):
    """Metadata and real isolated bytes must agree with the original terminal."""
    from sylanne3.runtime.d11_life_contract_v1 import D11DraftTerminalV1
    assert type(terminal) is D11DraftTerminalV1 and terminal.binding == prepared.binding
    assert terminal.status == "completed" and terminal.payload.handoff_started is True
    witness = terminal.payload.readback
    assert witness is not None
    target = prepared.plan.target
    root_stat = Path(root).stat()
    assert (root_stat.st_dev, root_stat.st_ino) == (target.root_identity.device, target.root_identity.file_id)
    path = Path(root) / target.filename
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size)
    assert (after.st_dev, after.st_ino) == (witness.file_identity.device, witness.file_identity.file_id)
    assert witness.version == target.expected_prior_version + 1
    assert witness.effect_id == prepared.binding.effect_id and witness.execution_call_id == prepared.binding.execution_call_id
    assert len(data) == witness.content_length == prepared.plan.content.content_length
    assert hashlib.sha256(data).hexdigest() == witness.content_digest == prepared.plan.content.content_digest
    return path, data


def prepare_protected_phase_fixture_v2(*, installed_root, frozen_rewrite_root,
        setup_root, recall_payload, runner_user="ubuntu", relationship_cognition=False, method_measurement=False, method_dependency=False, growth_cognition=False,
        source_note_initial=False,paired_method_targets=False,completed_life_content=False,sdk_root=None,
        beta1_node_template=None,beta1_profile_policies=None):
    import ast, hashlib, json, os, pwd, socket, sys, time
    from dataclasses import replace
    from pathlib import Path
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    assert os.geteuid() == 0
    ordinary = pwd.getpwnam(runner_user)
    assert (ordinary.pw_uid, ordinary.pw_gid) == (1000, 1000)
    package = Path(installed_root)
    engineering = Path(frozen_rewrite_root)
    sdk_asset_root=Path(sdk_root if sdk_root is not None else os.environ['SYLANNE_QUAL_SDK_ROOT']).resolve(strict=True)
    assert sdk_asset_root.is_dir()
    root = Path(setup_root)
    assert package.is_absolute() and package.resolve(strict=True) == package
    assert engineering.is_absolute() and engineering.resolve(strict=True) == engineering
    assert root.is_absolute() and not root.exists()
    for parent in (root.parent, *root.parent.parents):
        stat = parent.lstat()
        assert parent.is_dir() and not parent.is_symlink()
        assert stat.st_uid == 0 and stat.st_mode & 0o022 == 0
    root.mkdir(mode=0o755)
    os.chown(root, 0, 0)
    root.chmod(0o755)
    profiles = root / "profiles"
    profiles.mkdir(mode=0o755)
    profiles.chmod(0o755)
    directory = profiles / "reply"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    business = root / "business"
    business.mkdir(mode=0o700)
    os.chown(business, ordinary.pw_uid, ordinary.pw_gid)
    host_data = business / "host-data"
    host_data.mkdir(mode=0o700)
    os.chown(host_data, ordinary.pw_uid, ordinary.pw_gid)

    sdk_root = sdk_asset_root
    sys.path[:0] = [str(package), str(package / "rewrite"), str(sdk_root),
        str(engineering / "tests/alpha1/integration")]
    from sylanne3.host import authority_profile as profile
    from sylanne3.host.identity import astrbot_namespace
    from sylanne3.graph_coordinator import namespace_ref
    from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.authority_service import AuthorityServiceCore
    from rewrite.host_tests.alpha1.artifact_phase_counter_fixture_v1 import RULE as FIXTURE_RULE
    from sylanne3.model_broker.artifact_phase_count_v1 import (
        ArtifactPhaseCountPolicyV1, FIXTURE_PROVIDER, FIXTURE_MODEL,
        FIXTURE_RULE_ID, FIXTURE_RULE_DIGEST)
    from sylanne3.authority_service.artifact_phase_counter_v1 import artifact_phase_applicability_wire_v1
    from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION
    from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
    from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
    from sylanne3.model_broker.artifact_draft_v1 import TEMPLATE_VERSION_V2
    from m1_artifact_draft_acceptance_support_v1 import (
        initial_m1_configuration_builder_v1, m1_phase_fixture_observer_asset_payload_v1,
        M1_PHASE_TASK_TEXT_V2, M1_PHASE_FULL_TEXT_V2)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert Path(profile.__file__).resolve().is_relative_to(package)
    manifest_bytes = (package / "release-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if beta1_node_template is None:
        assert beta1_profile_policies is None
        assert manifest["backend_qualification"]["runtime_scope"]=="backend-local-alpha2-acceptance"
    else:
        if type(beta1_node_template)is not Beta1ProtectedNodeTemplateV3 or type(beta1_profile_policies)is not dict:
            raise ValueError("typed Root Beta1 original node template required")
        if (manifest["package_version"],manifest["build_mode"],manifest["backend_qualification"]["runtime_scope"])!=(
                "3.0.0-beta1","beta1-candidate","backend-beta1-server-test"):
            raise ValueError("Root Beta1 setup requires its actual Beta1 manifest scope")
        if beta1_node_template.setup_root!=root:
            raise ValueError("original Root node template changed its fresh setup path")

    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    catalogue = json.loads((package / "resources/catalogue/current.json").read_bytes())
    scheme = json.loads((package / "resources/catalogue/d04-affect-scheme.json").read_bytes())

    # Execute only the existing pure payload functions; no test node or SDK client.
    builders = {"authority_profile": profile}
    source = engineering / "host_tests/alpha1/test_authority_profile.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names = {"_schema2_payload", "_model_workflow_payload", "_artifact_draft_v3_payload"}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == len(names)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), builders)
    tls_source = engineering / "host_tests/alpha1/test_authority_mtls_loopback.py"
    tls_tree = ast.parse(tls_source.read_text(encoding="utf-8"))
    tls_class = next(node for node in tls_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AuthorityMtlsLoopbackTests")
    certificate_function = next(node for node in tls_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "_certificates")
    tls_globals = {"x509": x509, "rsa": rsa, "hashes": hashes, "serialization": serialization,
        "ExtendedKeyUsageOID": ExtendedKeyUsageOID, "NameOID": NameOID, "Path": Path}
    exec(compile(ast.Module(body=[certificate_function], type_ignores=[]), str(tls_source), "exec"), tls_globals)
    tls_helper = type("ExistingCertificateFixture", (), {"_certificates": tls_globals["_certificates"]})
    tls_files = tls_helper._certificates(directory)
    needed = {"ca.pem", "client.pem", "client.key", "server.pem", "server.key", "second.pem", "second.key"}
    for name, path in tls_files.items():
        if name not in needed:
            path.unlink()
        else:
            os.chown(path, 0, ordinary.pw_gid)
            path.chmod(0o640 if name.endswith(".key") else 0o644)
    for old, new in (("ca.pem", "trust-root.pem"), ("client.pem", "client-cert.pem"),
            ("client.key", "client-key.pem")):
        (directory / old).rename(directory / new)
    directory.chmod(0o755)

    def protected(path, data, mode=0o644):
        assert not path.exists()
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as stream:
            os.fchown(stream.fileno(), 0, ordinary.pw_gid if mode == 0o640 else 0)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return hashlib.sha256(data).hexdigest()

    authority_store = business / "authority.db"
    deny = lambda *args: False
    core = AuthorityServiceCore(authority_store, authorizer=deny,
        deletion_verifier=deny, execution_verifier=deny,
        effect_verifier=deny, dispatch_verifier=deny, create=True)
    try:
        authority_id = core._db.execute(
            "SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()[0]
    finally:
        core.close()
    for path in business.iterdir():
        if path == host_data:
            assert path.is_dir() and not path.is_symlink()
            continue
        assert path.is_file() and not path.is_symlink()
        os.chown(path, ordinary.pw_uid, ordinary.pw_gid)
        path.chmod(0o600)
    prepared_at = time.time()
    valid_until=(prepared_at+3600 if beta1_node_template is None else
        beta1_node_template.original_budget.absolute_valid_until_utc)
    if valid_until<=prepared_at:raise ValueError("original Root setup deadline already ended; HOLD_PREPARATION")
    namespace = astrbot_namespace("platform-1", "10001", "persona-reply")
    authority_namespace = namespace_ref(namespace)
    installation_id = "installation-reply"
    configuration = {"id": FIXTURE_PROVIDER, "type": "openai_chat_completion", "model": FIXTURE_MODEL}
    config_digest = canonical_digest(configuration)
    audience = '["platform-1:FriendMessage:123456","conversation-1"]'
    shared = dict(provider_id=FIXTURE_PROVIDER, model_id=FIXTURE_MODEL,
        provider_config_ref=profile.installed_model_config_ref(FIXTURE_PROVIDER, FIXTURE_MODEL, config_digest),
        provider_config_digest=config_digest, audiences=(audience,),
        privacy_tier="private", required_capabilities=("text",), timeout_seconds=10.0)
    base = profile.AdminModelWorkflowsV2(2,
        profile.AdminModelWorkflowV2(work_kind="d06.encode_source", purpose="consolidation",
            template_version=FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION,
            max_output_tokens=128, quote_ceiling={"output_tokens": 128}, **shared),
        profile.AdminModelWorkflowV2(work_kind="reply", purpose="proposal",
            template_version=REPLY_TEMPLATE_VERSION,
            max_output_tokens=32, quote_ceiling={"output_tokens": 32}, **shared))
    initial = initial_m1_configuration_builder_v1(namespace, authority_namespace,
        installation_id, shared, base, manifest_digest=manifest_digest)
    workflows = plain_v1(initial.workflows)
    if method_dependency:
        from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
        workflows["encode"]["template_version"] = FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    main = workflows["artifact_draft"]
    main["max_output_tokens"] = 2000
    main["quote_ceiling"] = {"input_tokens":10000,"output_tokens":2000,
        "model_tokens":12000,"model_microusd":100}
    c3 = builders["_model_workflow_payload"]("d07.cognition", "proposal", RECALL_TEMPLATE_VERSION_V1)
    c3.update(plain_v1(shared))
    c3.update(max_output_tokens=128, quote_ceiling={
        "input_tokens":2048,"output_tokens":128,"model_tokens":2176,"model_microusd":100})
    workflows["d07_cognition"] = c3
    if completed_life_content:
        assert source_note_initial
        from sylanne3.model_broker.internal_life_content_v1 import WORK_KIND as CONTENT_WORK_KIND,TEMPLATE_VERSION as CONTENT_TEMPLATE
        content=profile.AdminModelWorkflowV2(work_kind=CONTENT_WORK_KIND,purpose='consolidation',template_version=CONTENT_TEMPLATE,
            max_output_tokens=128,quote_ceiling={'output_tokens':128},**shared)
        workflows['life_content']=plain_v1(content)

    sample = {"input_tokens":6000,"output_tokens":1000,"model_tokens":7000,"model_microusd":100}
    if relationship_cognition:
        # Explicit new ordinary producer quote; the existing sample ceiling already bounds it.
        from sylanne3.host.model_workflows_v5 import model_workflows_v5_from_payload
        from sylanne3.model_broker.d07_cognition_v1 import TEMPLATE_VERSION as ORDINARY_D07_TEMPLATE
        ordinary = profile.AdminModelWorkflowV2(work_kind="d07.cognition", purpose="proposal",
            template_version=ORDINARY_D07_TEMPLATE, max_output_tokens=1000,
            quote_ceiling=dict(sample), **shared)
        assert dict(ordinary.quote_ceiling) == sample
        workflows["version"] = 5
        workflows["d07_relationship_cognition"] = plain_v1(ordinary)
        model_workflows_v5_from_payload(workflows)
    if growth_cognition:
        assert method_dependency and method_measurement
        from sylanne3.host.model_workflows_v6 import model_workflows_v6_from_payload
        from sylanne3.model_broker.d07_cognition_v1 import TEMPLATE_VERSION as GROWTH_D07_TEMPLATE
        growth = profile.AdminModelWorkflowV2(work_kind="d07.cognition", purpose="proposal",
            template_version=GROWTH_D07_TEMPLATE, max_output_tokens=1000,
            quote_ceiling=dict(sample), **shared)
        workflows["version"] = 6
        workflows.setdefault("d07_relationship_cognition", None)
        workflows["growth_cognition"] = plain_v1(growth)
        model_workflows_v6_from_payload(workflows)
    artifact = builders["_artifact_draft_v3_payload"]()
    artifact.update(model_workflow=main, phase_model_workflow={
        **main, "template_version":TEMPLATE_VERSION_V2, "quote_ceiling":dict(main["quote_ceiling"])},
        body_policy=plain_v1(initial.artifact_draft.body_policy))
    original_tool = initial.artifact_draft.tool_scope
    artifact["tool_scope"] = plain_v1(profile.AdminArtifactDraftToolScopeV2(
        original_tool.resource_id, original_tool.filename, original_tool.max_file_bytes,
        original_tool.generated_text_bytes, original_tool.readback_chunk_bytes,
        original_tool.execution_timeout_seconds, 2, ("create", "replace_verified_predecessor")))
    if paired_method_targets:
        assert growth_cognition and method_dependency and method_measurement
        from sylanne3.host.artifact_draft_paired_policy_v4 import POLICY_SCHEMA, TOOL_SCHEMA
        paired_scope = dict(artifact["tool_scope"])
        paired_scope.pop("filename")
        paired_scope.update(schema=TOOL_SCHEMA, filenames=[M1_METHOD_BASELINE_FILENAME_V6, M1_METHOD_TREATMENT_FILENAME_V6])
        artifact.update(schema=POLICY_SCHEMA, tool_scope=paired_scope)
    # Fresh V3 declares the approved D01 preparation contract before any task exists.
    from sylanne3.domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
    standing_fields = dict(artifact["standing_scope"])
    standing_fields.pop("schema")
    standing_fields.update(platform_ref='["platform-1","aiocqhttp","10001"]',
        allowed_sender_refs=('["platform-1","123456"]',), valid_until_utc=valid_until,
        norm_refs=tuple(standing_fields["norm_refs"]))
    if paired_method_targets:
        standing_fields["maximum_active_tasks"] = 2
    dependency = profile.artifact_candidate_preparation_dependency_contract_v1()
    standing = profile.AdminArtifactStandingScopeV3(**standing_fields,
        preparation_dependency_contract_ref=dependency.original_ref,
        preparation_dependency_contract_digest=dependency.digest,
        predecision_operations=profile.STANDING_PREDECISION_OPERATIONS_V2,
        method_refs=(FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1)
            if paired_method_targets else (FULL_DRAFT_METHOD_V1,),
        rubric_scope=("length", "tone", "task_semantics"),
        observer_scope=(profile.STANDING_OBJECTIVE_OBSERVER_V2, str(root / "observer.json")),
        self_actor_ref="entity:self-reply",
        approval_original_ref="artifact-standing-approval:initial-declaration")
    standing = replace(standing, approval_original_ref=profile.artifact_standing_scope_approval_ref_v2(
        standing, namespace=namespace, installation_id=installation_id,
        manifest_digest=manifest_digest, profile_id="reply"))
    artifact["standing_scope"] = plain_v1(standing)

    # Six physical calls; at most two configured auxiliary calls still share this physical maximum.
    dims = ("input_tokens","output_tokens","model_tokens","model_microusd")
    quotes = [workflows["encode"]["quote_ceiling"], c3["quote_ceiling"], sample,
        main["quote_ceiling"], workflows["natural_generation"]["quote_ceiling"],
        workflows["natural_review"]["quote_ceiling"]]
    auxiliary = workflows["appraisal"]["quote_ceiling"]
    bounded_family = [*quotes, auxiliary, auxiliary]
    physical_max = initial.foreground.max_calls
    assert physical_max == 6 and initial.foreground.max_auxiliary_calls == 2
    model_limits = {d:sum(sorted((q[d] for q in bounded_family), reverse=True)[:physical_max]) for d in dims}
    model_max = {d:max(q[d] for q in bounded_family) for d in dims}
    assert model_limits["input_tokens"] <= 48000 and model_limits["output_tokens"] <= 8000
    if completed_life_content:
        assert all(value<=model_max[name] for name,value in workflows['life_content']['quote_ceiling'].items())


    payload = builders["_schema2_payload"]()
    with socket.socket() as port_probe:
        port_probe.bind(("127.0.0.1",0))
        port = port_probe.getsockname()[1]
    payload.update(host="127.0.0.1", port=port, server_name="localhost", expected_authority_id=authority_id)
    policy = payload["installation_policy"]
    lease_id = "lease-" + namespace.persona_id
    policy.update(namespace=plain_v1(namespace), authority_namespace=authority_namespace,
        installation_id=installation_id, manifest_digest=manifest_digest,
        administrator_holder="host:reply", expected_authority_id=authority_id,
        catalogue_hash=catalogue["catalogue_hash"], scheme_version=scheme["scheme_version"],
        operator_version=scheme["operator_version"], policy_version="policy-1")
    policy["root_lease"].update(lease_id=lease_id, bot_id=namespace.bot_id, persona_id=namespace.persona_id,
        limits={"cpu_ms":200,"thread_cpu_ms":61000,**model_limits})
    kinds = ["encode","d06.encode_source","d03.message_received","d03.self_identity_projection",
        "d04.encoding_baseline","d06.first_ingress_c02","d07.attention","message","reply",
        "scheme_compile","scheme_preview",C04_INTERNAL_CPU_WORK_KIND,"d10.offline_observed_tick.v1",
        "d11.foreground_cycle.v1","d10.life.artifact_draft.v1"]
    if source_note_initial:
        from sylanne3.runtime.d11_life_contract_v1 import WORK_KIND as SOURCE_NOTE_WORK_KIND
        kinds.append(SOURCE_NOTE_WORK_KIND)
    kinds.extend(value["work_kind"] for value in workflows.values() if isinstance(value,dict))
    policy["root_grant"].update(grant_id="grant-reply", bot_id=namespace.bot_id, persona_id=namespace.persona_id,
        lease_id=lease_id, max_ceiling={"cpu_ms":100,"thread_cpu_ms":61000,**model_max},
        allowed_work_kinds=list(dict.fromkeys(kinds)), valid_until_utc=valid_until, policy_ref="d11-policy")
    if beta1_node_template is not None:
        budget=beta1_node_template.original_budget
        policy["root_lease"].update(currency=budget.currency,limits=dict(budget.limits))
        policy["root_grant"].update(currency=budget.currency,max_ceiling=dict(budget.max_ceiling),
            allowed_work_kinds=list(budget.allowed_work_kinds),valid_until_utc=budget.absolute_valid_until_utc)
        model_limits=dict(budget.limits);model_max=dict(budget.max_ceiling)
    payload.update(model_workflows=workflows, foreground=plain_v1(initial.foreground),
        artifact_draft=artifact, private_reply_dispatch=plain_v1(initial.private_reply_dispatch),
        provider_billing_policy_v1=plain_v1(initial.provider_billing_policy))
    payload.update(
        ingress_clock=plain_v1(profile.AdminIngressClockPolicy("clock:reply",0.5,2.0)),
        ingress_encoding=plain_v1(profile.AdminIngressEncodingPolicy(120.0,
            workflows["encode"]["quote_ceiling"],"snapshot:reply-ingress","resource:reply-ingress","character:reply")),
        d03_arrival=plain_v1(profile.AdminD03ArrivalPolicy(30.0,{"cpu_ms":3},"snapshot:reply-arrival","resource:reply-arrival")),
        d03_self_identity_projection=plain_v1(profile.AdminD03SelfIdentityProjectionPolicy(
            30.0,{"cpu_ms":4},"snapshot:reply-projection","resource:reply-projection")),
        d04_encoding_baseline=plain_v1(profile.AdminD04EncodingBaselinePolicy(
            30.0,{"cpu_ms":2},"snapshot:reply-baseline","resource:reply-baseline")),
        d06_first_ingress_c02=plain_v1(profile.AdminD06FirstIngressC02Policy(
            30.0,{"cpu_ms":2},"snapshot:reply-c02","resource:reply-c02")),
        d06_private_reply_source=plain_v1(profile.AdminD06PrivateReplySourcePolicy(1,"private_conversation",True)),
        d07_attention=plain_v1(profile.AdminD07AttentionPolicy(
            30.0,{"cpu_ms":1},"snapshot:reply-attention","resource:reply-attention")))
    # This must be the actual bounded recall configuration supplied by Root, never a fabricated grant.
    recall = profile.d06_recall_policy_from_payload_v1(json.loads(canonical_serialize(recall_payload)))
    payload["d06_recall"] = plain_v1(recall)
    if method_measurement:
        from sylanne3.runtime.d11_method_observation_v1 import MethodMeasurementPolicyV1
        measured = MethodMeasurementPolicyV1("fixture:m1-method-measurement", 1,
            canonical_digest(plain_v1(initial.provider_billing_policy)))
        payload["method_measurement_policy"] = plain_v1(measured)
        assert profile._method_measurement_policy_from_payload_v1(payload) == measured
    for name in ("d11-signing.key","d02-signing.key"):
        protected(directory/name, os.urandom(32),0o640)
    billing_key = root/"billing-signing.key"
    protected(billing_key, initial.simulated_provider_key.private_bytes(
        serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()),0o640)
    counter_key = Ed25519PrivateKey.generate()
    counter_key_path = root/"counter-signing.key"
    protected(counter_key_path,counter_key.private_bytes(
        serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()),0o640)
    source = engineering/"host_tests/alpha1/artifact_phase_counter_fixture_v1.py"
    program_text = source.read_text(encoding="utf-8")
    old = 'PRIVATE_KEY = hashlib.sha256(b"sylanne.LOCAL_FIXTURE.phase-count-only.v1").digest()'
    assert program_text.count(old) == 1
    program_text = "#!"+sys.executable+"\n"+program_text.split("\n",1)[1]
    program_text = program_text.replace(old,
        "PRIVATE_KEY = __import__('pathlib').Path("+repr(str(counter_key_path))+").read_bytes()",1)
    program = root/"counter"
    program_digest = protected(program,program_text.encode("utf-8"),0o755)
    tokenizer = root/"tokenizer.json"
    tokenizer_digest = protected(tokenizer,canonical_serialize(FIXTURE_RULE).encode("utf-8"))
    applicability = root/"applicability.json"
    counter = ArtifactPhaseCountPolicyV1("LOCAL_FIXTURE",namespace,installation_id,manifest_digest,
        "reply",FIXTURE_PROVIDER,FIXTURE_MODEL,"1",config_digest,TEMPLATE_VERSION_V2,
        "fixture:m1-phase-counter",1,str(program),program_digest,
        counter_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),
        str(tokenizer),tokenizer_digest,str(applicability),"0"*64,FIXTURE_RULE_ID,FIXTURE_RULE_DIGEST,10)
    applicability_digest = protected(applicability,
        canonical_serialize(artifact_phase_applicability_wire_v1(counter)).encode("utf-8"))
    counter = replace(counter,applicability_sha256=applicability_digest)
    payload["artifact_phase_counter"] = plain_v1(counter)
    observer_id = "fixture:m1-phase-observer"
    observer = root/"observer.json"
    observer_digest = protected(observer,canonical_serialize(
        m1_phase_fixture_observer_asset_payload_v1(observer_id, method_dependency=method_dependency, paired_method_targets=paired_method_targets)).encode("utf-8"))
    payload["artifact_phase_fixture_observer"] = {
        "schema":"sylanne.artifact-phase-fixture-observer-installation.v1","source_scope":"LOCAL_FIXTURE",
        "observer_id":observer_id,"observer_version":1,"asset_ref":str(observer),"asset_sha256":observer_digest}
    if beta1_node_template is not None:
        payload.update(beta1_profile_policies)
        payload["life_d04_before_capture_policy"]=dict(namespace=plain_v1(namespace),
            installation_id=installation_id,manifest_digest=manifest_digest,
            root_operation_id=beta1_node_template.before_root_uuid)if beta1_node_template.fixture_kind=="numeric"else None
        if payload["life_d04_before_capture_policy"]is None:payload.pop("life_d04_before_capture_policy")
        # Invoke the original pure installation/policy parsers before any business issuance.
        installed_policy=profile._policy_from_payload(payload)
        _validate_beta1_profile_policy_sections_v3(payload,installed_policy)
        if (installed_policy.root_lease.currency!=budget.currency
                or dict(installed_policy.root_lease.limits)!=dict(budget.limits)
                or installed_policy.root_grant.currency!=budget.currency
                or dict(installed_policy.root_grant.max_ceiling)!=dict(budget.max_ceiling)
                or installed_policy.root_grant.allowed_work_kinds!=budget.allowed_work_kinds
                or installed_policy.root_grant.valid_until_utc!=budget.absolute_valid_until_utc
                or installed_policy.root_grant.grant_id!=beta1_node_template.root_grant_id
                or installed_policy.root_lease.lease_id!=beta1_node_template.root_lease_id):
            raise ValueError("post-create actual Root policy changed the original template; HOLD_PREPARATION")
        if any(canonical_serialize(payload[name])!=canonical_serialize(value)
                for name,value in beta1_profile_policies.items()):
            raise ValueError("post-create original Beta1 policy template commitment changed")
    profile_digest = protected(directory/"profile.json",canonical_serialize(payload).encode("utf-8"))
    setup = {"schema":"sylanne.artifact-phase-fixture-setup.v2","profile_id":"reply",
        "profile_root":str(profiles),"package_root":str(package),"data_dir":str(business),
        "authority_store":str(authority_store),"server_certificate":str(directory/"server.pem"),
        "server_private_key":str(directory/"server.key"),"administrator_certificate":str(directory/"second.pem"),
        "administrator_private_key":str(directory/"second.key"),"billing_signing_key":str(billing_key)}
    if completed_life_content or beta1_node_template is not None:
        component_key=root/"c04-component.key"
        protected(component_key,os.urandom(32),mode=0o640)
        setup["schema"]="sylanne.artifact-phase-fixture-setup.v3"
        setup["c04_component_key"]=str(component_key)
        from uuid import uuid4
        from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1
        from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        from sylanne3.host.c09_controlled_sdk_bootstrap_v3 import write_controlled_sdk_root_descriptor_from_assets_v3
        sdk_assets_root=root/"c09-sdk"
        sdk_assets_root.mkdir(mode=0o750);os.chown(sdk_assets_root,0,ordinary.pw_gid);sdk_assets_root.chmod(0o750)
        control_key=sdk_assets_root/"control.key";protected(control_key,os.urandom(32),mode=0o640)
        managed=business/"offline-managed-artifacts"
        managed.mkdir(mode=0o700);os.chown(managed,ordinary.pw_uid,ordinary.pw_gid)
        directories={name:managed/name for name in ("controlled_backup","export","rebuild_temp","cache")}
        for path in directories.values():
            path.mkdir(mode=0o700);os.chown(path,ordinary.pw_uid,ordinary.pw_gid)
        role_files={"core":authority_store,"deletion":business/"deletion.db","execution":business/"execution.db",
            "graph":host_data/"sylanne3.sqlite3"}
        inventory=build_initial_inventory_v1(authority_id=authority_id,installation_id=installation_id,
            namespace=authority_namespace,files=role_files,directories=directories)
        resource_id=initial.artifact_draft.tool_scope.resource_id
        resources=tuple(replace(resource,content_coverage=tuple(sorted({*resource.content_coverage,"jobs_drafts","imports_exports"})))
            if resource.resource_id==resource_id and resource.kind=="export" else resource for resource in inventory.resources)
        inventory=InstallationFilesystemManifestV2(inventory.authority_id,inventory.installation_id,inventory.namespace,resources,
            canonical_digest((inventory.schema,inventory.authority_id,inventory.installation_id,inventory.namespace,resources)))
        peer_cert=x509.load_pem_x509_certificate((directory/"client-cert.pem").read_bytes())
        peer_digest=hashlib.sha256(peer_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assets=dict(schema="sylanne3.c09.controlled-sdk-installation-assets.v3",authority_id=authority_id,
            installation_id=installation_id,control_store_id="controlled-sdk-control:"+uuid4().hex,
            key_id="controlled-sdk-key:"+uuid4().hex,namespace=authority_namespace,sdk_peer_descriptor=[peer_digest,"reply"],
            manifest_digest=manifest_digest,inventory_manifest_digest=inventory.manifest_digest,
            control_path=str(business/"c09-control.db"),key_path=str(control_key),instance_lock=str(business/"c09-instance.lock"))
        assets_path=sdk_assets_root/"installation-assets.json";protected(assets_path,canonical_serialize(assets).encode("utf8"),mode=0o640)
        cohort_path=sdk_assets_root/"peer-cohort.json"
        write_controlled_sdk_root_descriptor_from_assets_v3(cohort_path,installation_assets_path=assets_path)
        setup["c09_installation_assets"]=str(assets_path);setup["c09_sdk_peer_cohort"]=str(cohort_path)
    descriptor = root/"setup.json"
    setup_digest = protected(descriptor,canonical_serialize(setup).encode("utf-8"))
    if beta1_node_template is not None:
        # Actual Authority/TLS/key binding validation follows creation; it issues no fixture qualification.
        with profile._opened_profile(directory,"Linux",signing_key=True) as files:
            bound_payload=profile._read_profile_json(files["profile.json"])
            bound_policy=profile._policy_from_payload(bound_payload)
            sections=_validate_beta1_profile_policy_sections_v3(bound_payload,bound_policy)
            tls=profile._profile_from_payload("reply",directory,bound_payload,
                profile._prepared_ssl_context(files,"Linux"))
            d11_key=profile._checked_signing_key(profile._read_fd_bounded(files["d11-signing.key"],32),"D11")
            d02_key=profile._checked_signing_key(profile._read_fd_bounded(files["d02-signing.key"],32),"D02")
        bound_bundle=profile.AdminInstallationBundle(tls,bound_policy,d11_key,d02_key,
            **sections,ingress_clock=profile._ingress_clock_from_payload(bound_payload),
            provider_billing_policy_v1=profile._provider_billing_policy_from_payload_v1(bound_payload),
            method_measurement_policy=profile._method_measurement_policy_from_payload_v1(bound_payload),
            life_d04_before_capture_policy=profile._life_d04_before_capture_policy_from_payload_v1(bound_payload,bound_policy))
        if bound_policy!=installed_policy or tls.expected_authority_id!=authority_id:
            raise ValueError("post-create complete profile changed its actual Authority/Root binding")
        if any(canonical_serialize(bound_payload[name])!=canonical_serialize(value)
                for name,value in beta1_profile_policies.items()):
            raise ValueError("post-create protected profile changed an original policy commitment")
        from sylanne3.model_broker.artifact_phase_count_v1 import artifact_phase_counter_policy_from_payload_v1
        bound_counter=artifact_phase_counter_policy_from_payload_v1(bound_payload["artifact_phase_counter"],allow_local_fixture=True)
        if bound_counter!=counter:raise ValueError("post-create protected counter commitment changed")
        phase=bound_bundle.artifact_draft.phase_model_workflow
        if (counter.namespace,counter.installation_id,counter.manifest_digest,counter.profile_id,
                counter.provider_id,counter.model_id,counter.provider_config_digest,counter.template_version)!=(
                bound_policy.namespace,bound_policy.installation_id,bound_policy.manifest_digest,tls.profile_id,
                phase.provider_id,phase.model_id,phase.provider_config_digest,phase.template_version):
            raise ValueError("post-create counter metadata differs from the actual installed phase")
        if bound_bundle.provider_billing_policy_v1.provider_ed25519_public_key_hex!=initial.simulated_provider_key.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex():
            raise ValueError("post-create provider billing key differs from the actual protected producer")
    return {"setup_file":str(descriptor),"setup_sha256":setup_digest,"profile_sha256":profile_digest,
        "manifest_sha256":manifest_digest,"namespace":plain_v1(namespace),"authority_id":authority_id,
        "model_limits":model_limits,"model_max_ceiling":model_max,
        "task_utf8_sha256":hashlib.sha256((M1_METHOD_BASELINE_TEXT_V6 if paired_method_targets else M1_METHOD_TASK_TEXT_V4 if method_dependency else M1_PHASE_TASK_TEXT_V2).encode("utf-8")).hexdigest(),
        "full_utf8_sha256":hashlib.sha256(M1_PHASE_FULL_TEXT_V2.encode("utf-8")).hexdigest(),
        "relationship_cognition_initial_v5":relationship_cognition,
        "relationship_initial_quote":None if not relationship_cognition else dict(sample),
        "ingress_recall_original_quote":dict(c3["quote_ceiling"])}



@dataclass(frozen=True,slots=True)
class Beta1OriginalRootBudgetTemplateV3:
    """Root's original initial policy inputs; this object issues no authority."""
    currency:str
    limits:tuple
    max_ceiling:tuple
    allowed_work_kinds:tuple
    absolute_valid_until_utc:float

    def __post_init__(self):
        import math
        if (type(self.currency)is not str or not self.currency
                or type(self.limits)is not tuple or type(self.max_ceiling)is not tuple
                or type(self.allowed_work_kinds)is not tuple or not self.allowed_work_kinds
                or len(set(self.allowed_work_kinds))!=len(self.allowed_work_kinds)
                or any(type(v)is not str or not v for v in self.allowed_work_kinds)
                or type(self.absolute_valid_until_utc)not in(int,float)
                or not math.isfinite(self.absolute_valid_until_utc)):
            raise ValueError("exact original Root budget template required")
        for values in (self.limits,self.max_ceiling):
            if (tuple(sorted(values))!=values or len(dict(values))!=len(values)
                    or any(type(k)is not str or not k or type(v)is not int or v<=0 for k,v in values)):
                raise ValueError("original Root budget dimensions must be exact positive ordered integers")
        if any(value>dict(self.limits).get(name,0)for name,value in self.max_ceiling):
            raise ValueError("original Root quote ceiling exceeds its original total budget")


@dataclass(frozen=True,slots=True)
class Beta1ProtectedNodeTemplateV3:
    fixture_kind:str
    node:str
    scenario:str
    setup_root:Path
    before_root_uuid:str
    original_budget:Beta1OriginalRootBudgetTemplateV3
    profile_policies:dict
    namespace:object
    installation_id:str
    root_lease_id:str
    root_grant_id:str
    root_grant_version:int

    def __post_init__(self):
        from uuid import UUID
        from sylanne3.runtime_contracts import NamespaceId
        if (type(self.namespace)is not NamespaceId
                or any(type(v)is not str or not v for v in (self.installation_id,self.root_lease_id,self.root_grant_id))
                or type(self.root_grant_version)is not int or self.root_grant_version!=1
                or not isinstance(self.setup_root,Path) or not self.setup_root.is_absolute()
                or type(self.original_budget)is not Beta1OriginalRootBudgetTemplateV3
                or type(self.profile_policies)is not dict
                or str(UUID(self.before_root_uuid))!=self.before_root_uuid or UUID(self.before_root_uuid).version!=4):
            raise ValueError("exact fresh Root node template/path/UUID required")



@dataclass(frozen=True,slots=True)
class _Beta1RootGrantTemplateContextV3:
    grant_id:str
    version:int
    allowed_work_kinds:tuple
    max_ceiling:object


@dataclass(frozen=True,slots=True)
class _Beta1RootLeaseTemplateContextV3:
    lease_id:str
    limits:object


@dataclass(frozen=True,slots=True)
class _Beta1PolicyTemplateContextV3:
    namespace:object
    installation_id:str
    root_grant:_Beta1RootGrantTemplateContextV3
    root_lease:_Beta1RootLeaseTemplateContextV3

def _validate_beta1_original_node_template_v3(template,*,expected,now_utc,suite_root):
    from sylanne3.host import authority_profile as profile
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime_contracts import canonical_serialize
    family,node,scenario=expected
    if type(template)is not Beta1ProtectedNodeTemplateV3 or (template.fixture_kind,template.node,template.scenario)!=expected:
        raise ValueError("Root Beta1 node selection differs from the fixed full15 order")
    if template.original_budget.absolute_valid_until_utc<=now_utc:
        raise ValueError("original Root absolute deadline is already expired; HOLD_PREPARATION")
    from sylanne3.host.identity import astrbot_namespace
    if (template.namespace!=astrbot_namespace("platform-1","10001","persona-reply")
            or template.installation_id!="installation-reply"or template.root_lease_id!="lease-"+template.namespace.persona_id
            or template.root_grant_id!="grant-reply"):
        raise ValueError("original template identity differs from the actual permanent Owner fixture")
    root=template.setup_root
    if root.exists():
        raise ValueError("Root Beta1 setup must be fresh; existing original is preserved")
    if root.parent!=suite_root:
        raise ValueError("fixed node setup must be a direct child of the fresh suite")
    for path in (suite_root.parent,*suite_root.parent.parents):
        info=path.lstat()
        if not path.is_dir()or path.is_symlink()or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError("fresh Beta1 setup ancestry is not Root protected")
    allowed={"model_workflows","d04_semantic_drive","d04_joint_numeric","d13_paid_precompression",
        "d13_wire_policy","d13_wire_counter","foreground","artifact_draft","d06_recall","private_reply_dispatch",
        "d06_private_reply_source","ingress_encoding","d03_arrival","d03_self_identity_projection",
        "d04_encoding_baseline","d06_first_ingress_c02","d07_attention"}
    policies=json.loads(canonical_serialize(template.profile_policies))
    if not {"model_workflows","foreground","artifact_draft"}<=set(policies)or set(policies)-allowed:
        raise ValueError("fixed Beta1 policy template has missing workflow or unknown policy sections")
    workflows=profile._model_workflows_from_payload({"schema":2,**policies})
    if family=="numeric":
        if workflows.version<3 or workflows.life_numeric is None:
            raise ValueError("original Numeric workflow template is missing; HOLD_PREPARATION")
        if scenario=="numeric-positive"or scenario.startswith("numeric-authorization-"):
            if any(name not in policies for name in("d04_semantic_drive","d04_joint_numeric")):
                raise ValueError("original semantic/native policies missing for the fixed Numeric node")
        if scenario=="numeric-authorization-reservation"and workflows.life_content is None:
            raise ValueError("original normal Content donor workflow missing; HOLD_PREPARATION")
        if scenario=="numeric-authorization-lease":
            if workflows.version<4 or any(getattr(workflows,name,None)is None for name in("natural_generation","natural_review")):
                raise ValueError("original normal Foreground donor workflows missing; HOLD_PREPARATION")
    elif "d13_paid_precompression"not in policies:
        raise ValueError("original paid D13 policy template missing; HOLD_PREPARATION")
    budget=template.original_budget
    maximum=dict(budget.max_ceiling);total=dict(budget.limits);kinds=set(budget.allowed_work_kinds)
    for name,workflow in plain_v1(workflows).items():
        if name=="version"or workflow is None:continue
        if type(workflow)is not dict or "work_kind"not in workflow:continue
        if workflow["work_kind"]not in kinds or any(
                amount>maximum.get(dimension,0)or amount>total.get(dimension,0)
                for dimension,amount in workflow["quote_ceiling"].items()):
            raise ValueError("original Root kind/quote budget does not cover "+name+"; HOLD_PREPARATION")
    from types import MappingProxyType
    context=_Beta1PolicyTemplateContextV3(template.namespace,template.installation_id,
        _Beta1RootGrantTemplateContextV3(template.root_grant_id,template.root_grant_version,
            budget.allowed_work_kinds,MappingProxyType(maximum)),
        _Beta1RootLeaseTemplateContextV3(template.root_lease_id,MappingProxyType(total)))
    # Pure source input validation. Returned values never become installed/qualified or runtime authority.
    checked_payload={"schema":2,**policies}
    _validate_beta1_profile_policy_sections_v3(checked_payload,context)
    return policies


def prepare_protected_beta1_fixture_suite_v3(*,installed_root,frozen_rewrite_root,setup_root,
        sdk_root,recall_payload,runner_user,suite_id,package_archive,package_sha256,manifest_sha256,
        engineering_inventory_sha256,node_templates,expected_runtime_scope):
    """SOURCE-only Root entry; execution creates fifteen independent original setups."""
    import os,stat,time
    from uuid import UUID
    from sylanne3.runtime_contracts import canonical_serialize
    if os.geteuid()!=0 or str(UUID(suite_id))!=suite_id or UUID(suite_id).version!=4:
        raise ValueError("Root and one fresh fixed Beta1 suite UUID required")
    package=Path(installed_root).resolve(strict=True)
    engineering=Path(frozen_rewrite_root).resolve(strict=True)
    root=Path(setup_root)
    if not root.is_absolute()or root.exists():
        raise ValueError("fresh protected full15 suite directory required")
    manifest_raw=(package/"release-manifest.json").read_bytes()
    manifest=json.loads(manifest_raw)
    qualification=manifest["backend_qualification"]
    if expected_runtime_scope!="backend-beta1-server-test":
        raise ValueError("only the exact Beta1 setup SOURCE scope is supported")
    if (hashlib.sha256(manifest_raw).hexdigest()!=manifest_sha256
            or hashlib.sha256(Path(package_archive).read_bytes()).hexdigest()!=package_sha256
            or (manifest["package_version"],manifest["build_mode"],qualification["runtime_scope"])!=
                ("3.0.0-beta1","beta1-candidate","backend-beta1-server-test")):
        raise ValueError("exact runtime-only Beta1 package/manifest scope required")
    inventory_path=engineering.parent.parent/"frozen-engineering-inventory.json"
    inventory=json.loads(inventory_path.read_bytes())
    inventory_digest=hashlib.sha256(json.dumps(inventory["files"],sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode()).hexdigest()
    if inventory["schema"]!="sylanne.engineering-source-inventory.v1"or inventory["sha256"]!=inventory_digest or inventory_digest!=engineering_inventory_sha256:
        raise ValueError("actual frozen Root engineering source inventory differs")
    for row in inventory["files"]:
        path=engineering.parent/row["path"]
        data=path.read_bytes()
        if path.is_symlink()or hashlib.sha256(data).hexdigest()!=row["sha256"]or len(data)!=row["bytes"]:
            raise ValueError("frozen Root engineering source differs before setup")
    for path in (inventory_path,*inventory_path.parents,root.parent,*root.parent.parents):
        info=path.lstat()
        if path.is_symlink()or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError("Root full15/inventory ancestry differs")
    import sys
    sys.path.append(str(engineering/"host_tests/alpha1"))
    from c09_root_phase_harness_v3 import _BETA1_NUMERIC_SCENARIOS,_BETA1_D13_SCENARIOS
    from owned_resource_profile_v1 import FIXTURE_NODES
    expected=tuple(zip(("numeric",)*10+("d13_full",)*5,
        (*FIXTURE_NODES["numeric"],*FIXTURE_NODES["d13_full"]),
        (*_BETA1_NUMERIC_SCENARIOS,*_BETA1_D13_SCENARIOS),strict=True))
    if type(node_templates)is not tuple or len(node_templates)!=15:
        raise ValueError("all fifteen original Root node templates required before creating any setup")
    # Validate the complete input family before creating a single Authority or credential.
    policies=tuple(_validate_beta1_original_node_template_v3(item,expected=selected,now_utc=time.time(),suite_root=root)
        for item,selected in zip(node_templates,expected,strict=True))
    if (len({item.setup_root for item in node_templates})!=15
            or len({item.before_root_uuid for item in node_templates})!=15
            or any(item.setup_root.parent!=root for item in node_templates)):
        raise ValueError("all15 setup roots and original Root UUIDs must be distinct direct children")
    root.mkdir(mode=0o750);os.chown(root,0,1000);root.chmod(0o750)
    nodes=[];created=[]
    for template,policy in zip(node_templates,policies,strict=True):
        produced=prepare_protected_phase_fixture_v2(installed_root=package,frozen_rewrite_root=engineering,
            setup_root=template.setup_root,sdk_root=sdk_root,recall_payload=recall_payload,runner_user=runner_user,
            source_note_initial=template.fixture_kind=="numeric",completed_life_content=template.fixture_kind=="numeric",
            beta1_node_template=template,beta1_profile_policies=policy)
        created.append(produced)
        nodes.append(dict(fixture_kind=template.fixture_kind,node=template.node,scenario=template.scenario,
            setup_file=produced["setup_file"],setup_sha256=produced["setup_sha256"]))
    if len({v["setup_file"]for v in nodes})!=15 or len({v["setup_sha256"]for v in nodes})!=15 or len({v["authority_id"]for v in created})!=15:
        raise ValueError("actual full15 independently created original descriptors are not unique")
    descriptor=dict(schema="sylanne.beta1.protected-fixture-suite.v3",fixture_kind="beta1_full_15",
        package_sha256=package_sha256,manifest_sha256=manifest_sha256,nodes=nodes)
    data=canonical_serialize(descriptor).encode("utf8");path=root/"suite.json"
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640),"wb")as stream:
        os.fchown(stream.fileno(),0,1000);os.fchmod(stream.fileno(),0o640)
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    return dict(schema="sylanne.beta1.protected-fixture-preparation.v3",suite_id=suite_id,
        suite_file=str(path),suite_sha256=hashlib.sha256(data).hexdigest(),
        descriptor_count=15,node_observation_status="NOT_RUN",nodes=nodes,
        original_root_templates=tuple(dict(node=v.node,before_root_uuid=v.before_root_uuid,
            original_absolute_valid_until_utc=v.original_budget.absolute_valid_until_utc,
            original_limits=dict(v.original_budget.limits),original_max_ceiling=dict(v.original_budget.max_ceiling),
            original_allowed_work_kinds=v.original_budget.allowed_work_kinds)for v in node_templates))


def _validate_beta1_profile_policy_sections_v3(payload,context):
    """Use every original pure parser; return only unregistered configuration values."""
    from sylanne3.host import authority_profile as profile
    from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
    simple={
        "model_workflows":profile._model_workflows_from_payload,
        "d13_wire_counter":profile._d13_wire_counter_from_payload,
        "d06_recall":profile._d06_recall_from_payload,
        "private_reply_dispatch":profile._private_reply_dispatch_from_payload,
        "d06_private_reply_source":profile._d06_private_reply_source_from_payload,
        "ingress_encoding":profile._ingress_encoding_from_payload,
        "d03_arrival":profile._d03_arrival_from_payload,
        "d03_self_identity_projection":profile._d03_projection_from_payload,
        "d04_encoding_baseline":profile._d04_baseline_from_payload,
        "d06_first_ingress_c02":profile._d06_c02_from_payload,
        "d07_attention":profile._d07_attention_from_payload,
    }
    bound={
        "d04_semantic_drive":profile._d04_semantic_drive_from_payload,
        "d04_joint_numeric":profile._d04_joint_numeric_from_payload,
        "d13_paid_precompression":profile._d13_paid_precompression_from_payload,
        "d13_wire_policy":profile._d13_wire_policy_from_payload,
        "foreground":profile._foreground_for_policy_from_payload_v1,
        "artifact_draft":profile._artifact_draft_for_policy_from_payload_v1,
    }
    values={name:parser(payload)for name,parser in simple.items()if name in payload}
    values.update({name:parser(payload,context)for name,parser in bound.items()if name in payload})
    workflows=values["model_workflows"]
    if values.get("d06_recall")is not None:
        workflow=workflows.d07_cognition
        if (type(values.get("foreground"))is not profile.AdminForegroundPolicyV1
                or type(workflow)is not profile.AdminModelWorkflowV2
                or(workflow.work_kind,workflow.purpose,workflow.template_version)!=
                    ("d07.cognition","proposal",RECALL_TEMPLATE_VERSION_V1)):
            raise ValueError("original recall/foreground/C3 workflow relationship differs")
    artifact=values.get("artifact_draft")
    if artifact is not None:
        phase=artifact.phase_model_workflow
        if any(amount>context.root_grant.max_ceiling.get(name,0)
                or amount>context.root_lease.limits.get(name,0)for name,amount in phase.quote_ceiling.items()):
            raise ValueError("original phase workflow exceeds Root quote/total budget")
    from sylanne3.model_broker.artifact_phase_count_v1 import FIXTURE_PROVIDER,FIXTURE_MODEL
    configuration={"id":FIXTURE_PROVIDER,"type":"openai_chat_completion","model":FIXTURE_MODEL}
    expected_model=(FIXTURE_PROVIDER,FIXTURE_MODEL,canonical_digest(configuration))
    required=(workflows.encode,workflows.d07_cognition,workflows.artifact_draft,
        workflows.natural_generation,workflows.natural_review,
        None if artifact is None else artifact.phase_model_workflow)
    if values.get("d06_recall")is None or any(workflow is None or
            (workflow.provider_id,workflow.model_id,workflow.provider_config_digest)!=expected_model
            for workflow in required):
        raise ValueError("original protected fixture routing differs from its actual paired model/counter")
    return values

