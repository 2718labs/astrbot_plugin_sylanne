"""Current SDK LLM observation and setup permission semantics; zero model calls."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import secrets
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from astrbot.api.star import Context
from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.db.sqlite import SQLiteDatabase
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from astrbot.dashboard.api import auth as dashboard_auth, plugins as dashboard_plugins
from astrbot.dashboard.password_state import set_dashboard_password_hashes
from astrbot.dashboard.responses import ApiError
from fastapi.responses import JSONResponse

from rewrite.host_tests.alpha1 import test_authority_profile as profile_cases
from rewrite.host_tests.alpha1 import test_runtime_bootstrap as host_cases
from sylanne3.host.authority_profile import AdminInstallationBundle, installed_model_config_ref
from sylanne3.host.model_selection import (
    HostModelSelectionV1, observe_host_model_selection_v1, parse_host_model_selection_v1,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.runtime_context import RuntimeHealth
from sylanne3.runtime_contracts import InstallationGrantV2, canonical_digest


CANARY = "model-selector-secret-canary-not-a-real-key"
ORIGIN = "https://localhost:6238"
BASE = "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1"


@pytest.fixture
def sdk_models():
    providers, calls = [], []
    def create(provider_id, model):
        config = {"id": provider_id, "type": "openai_chat_completion", "model": model,
                  "key": [CANARY], "api_base": "https://example.invalid/v1", "enable": True}
        provider = ProviderOpenAIOfficial(config, {})
        async def forbidden(*_args, **_kwargs):
            calls.append("provider_call")
            raise AssertionError("configuration observation must never call a provider")
        provider.get_models = forbidden
        provider.text_chat = forbidden
        provider.client.chat.completions.create = forbidden
        providers.append(provider)
        return provider
    primary = create("main-provider", "main-model")
    other = create("other-provider", "main-model")
    manager = SimpleNamespace(provider_insts=providers, inst_map={p.meta().id: p for p in providers})
    context = Context(asyncio.Queue(), {}, None, manager, None, None, None, None, None, None, None)
    try:
        yield context, primary, other, calls
    finally:
        for provider in providers:
            asyncio.run(provider.client.close())
        assert calls == []


def bundle_for(provider, tmp_path, *, version=2):
    raw = profile_cases._workflow_profile_payload()
    raw["model_workflows"]["version"] = version
    for workflow in raw["model_workflows"].values():
        if type(workflow) is dict:
            workflow.update(provider_id=provider.meta().id, model_id=provider.get_model(),
                            provider_config_digest=canonical_digest(provider.provider_config))
            workflow["provider_config_ref"] = installed_model_config_ref(
                workflow["provider_id"], workflow["model_id"], workflow["provider_config_digest"])
    policy = profile_cases.authority_profile._policy_from_payload(raw)
    workflows = profile_cases.authority_profile._model_workflows_from_payload(raw)
    tls = AuthorityTlsProfile("ui25", "127.0.0.1", 19453, "localhost", policy.expected_authority_id,
                              tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "client.key")
    return AdminInstallationBundle(tls, policy, b"j" * 32, b"k" * 32,
        model_workflows=workflows, workbench_origin=ORIGIN)


def observe(context, provider_id, bundle=None, baseline=None):
    return observe_host_model_selection_v1(context=context, authority_profile="ui25", provider_id=provider_id,
        installation_bundle=bundle, authorized_baseline=baseline)


def test_current_main_model_identity_v2_v3_and_exact_safe_plan(sdk_models, tmp_path):
    context, provider, _, calls = sdk_models
    for version in (2, 3):
        bundle = bundle_for(provider, tmp_path, version=version)
        selected = observe(context, "main-provider", bundle)
        assert selected.state == "authorized" and selected.reason_code == "none"
        assert parse_host_model_selection_v1(selected.plan.to_dict()) == selected.plan
        assert set(selected.plan.to_dict()) == {"schema", "authority_profile", "provider_id", "model_id", "provider_config_digest"}
        assert CANARY not in json.dumps(selected.plan.to_dict())
        # Independent optional slots are never rewritten to the reply model.
        optional = replace(bundle.model_workflows.encode, work_kind="natural_generation", purpose="proposal",
            provider_id="independent-generation", model_id="independent-model",
            provider_config_ref=installed_model_config_ref("independent-generation", "independent-model", "d" * 64),
            provider_config_digest="d" * 64,
            template_version=profile_cases.authority_profile.NATURAL_GENERATION_TEMPLATE_VERSION)
        updated = replace(bundle.model_workflows, natural_generation=optional)
        independent = replace(bundle, model_workflows=updated)
        assert observe(context, "main-provider", independent).state == "authorized"
    plan = selected.plan.to_dict()
    for bad in ({**plan, "extra": CANARY}, {**plan, "schema": "future.v2"},
                {**plan, "provider_config_digest": "sha256:" + plan["provider_config_digest"]}):
        with pytest.raises(ValueError):
            parse_host_model_selection_v1(bad)
    assert calls == []


def test_each_nonmatching_main_condition_refuses_with_other_conditions_valid(sdk_models, tmp_path):
    context, provider, _, calls = sdk_models
    bundle = bundle_for(provider, tmp_path)
    valid = observe(context, "main-provider", bundle)
    assert valid.state == "authorized"
    assert observe(context, "", bundle).state == "unselected"
    assert observe(context, "missing-provider", bundle).state == "unavailable"
    assert observe(context, "main-provider").state == "awaiting_installation"
    wrong_provider = observe(context, "other-provider", bundle)
    assert (wrong_provider.state, wrong_provider.reason_code) == ("awaiting_installation", "model_provider_mismatch")
    provider.set_model("different-model")
    wrong_model = observe(context, "main-provider", bundle)
    assert wrong_model.reason_code == "model_id_mismatch"
    drift = observe(context, "main-provider", bundle, valid.plan)
    assert drift.state == "changed"
    provider.set_model("main-model")
    original = deepcopy(provider.provider_config)
    provider.provider_config["config_revision"] = 2
    wrong_config = observe(context, "main-provider", bundle)
    assert wrong_config.reason_code == "model_config_mismatch"
    provider.provider_config.clear()
    provider.provider_config.update(original)
    assert observe(context, "main-provider", bundle).state == "authorized"
    original_client = provider.client
    provider.client = object()
    assert observe(context, "main-provider", bundle).reason_code == "model_client_unsupported"
    provider.client = original_client
    assert calls == []


def actual_plugin(context, *, enabled, provider_id):
    return host_cases.load_plugin_module().Sylanne3Plugin(context, {
        "enabled": enabled, "authority_profile": "ui25", "llm_provider_id": provider_id})


def test_setup_read_preserves_startup_enabled_and_runtime_health(sdk_models, tmp_path):
    context, provider, _, calls = sdk_models
    plugin = actual_plugin(context, enabled=True, provider_id="main-provider")
    bundle = bundle_for(provider, tmp_path)
    policy = bundle.installation_policy
    grant = InstallationGrantV2(policy.expected_authority_id, "fixture:peer", policy.administrator_holder,
        policy.installation_id, policy.manifest_digest, "fixture:publisher", "2", "f" * 64)
    installation = V2InstallationAssembly(policy, grant, b"j" * 32, b"k" * 32,
        lambda: (_ for _ in ()).throw(AssertionError("GET must not create a port")), tmp_path, tmp_path,
        admin_bundle=bundle, workbench_origin=ORIGIN)
    plugin._setup_installation = installation
    plugin._authority_enabled = True
    plugin._enabled = True
    saved = RuntimeHealth("blocked", ("runtime_bootstrap",))
    plugin.runtime_health = saved
    def no_read(**_kwargs):
        raise AssertionError("GET must not apply a saved next_restart target")
    plugin._management_port = SimpleNamespace(installation_management_startup_v1=no_read)
    first = asyncio.run(plugin._setup_status())
    provider.set_model("changed-after-startup")
    second = asyncio.run(plugin._setup_status())
    assert first["model_selection"]["state"] == "authorized"
    assert second["model_selection"]["state"] == "awaiting_installation"
    assert first["authority_enabled"] is True and second["effective_enabled"] is True
    assert plugin._authority_enabled is True and plugin._enabled is True and plugin.runtime_health is saved
    provider.set_model("main-model")
    inactive = actual_plugin(context, enabled=False, provider_id="")
    inactive.runtime_health = RuntimeHealth("enrollment_required", ("authority_profile",))
    status = asyncio.run(inactive._setup_status())
    assert status["runtime"]["stage"] == "enrollment_required"
    assert status["runtime"]["reason_codes"] == ["authority_profile", "host_disabled", "model_unselected"]
    assert inactive._authority_enabled is None and inactive._enabled is False
    assert calls == []


def test_dashboard_only_setup_http_uses_real_auth_and_safe_observation(sdk_models, tmp_path):
    context, _, _, calls = sdk_models
    plugin = actual_plugin(context, enabled=False, provider_id="main-provider")
    plugin.runtime_health = RuntimeHealth("enrollment_required", ("authority_profile",))
    password = "SdkSetup9!" + secrets.token_hex(16)
    defaults = {"dashboard": {"username": "sdk-host-admin", "jwt_secret": secrets.token_hex(32),
                              "password_change_required": False}}
    set_dashboard_password_hashes(defaults, password)
    config = AstrBotConfig(str(tmp_path / "dashboard.json"), default_config=defaults)
    db = SQLiteDatabase(str(tmp_path / "dashboard.db"))
    from astrbot.dashboard.services.auth_service import AuthService
    app = FastAPI()
    app.state.jwt_secret = config["dashboard"]["jwt_secret"]
    app.state.services = SimpleNamespace(auth=AuthService(db, config))
    app.state.core_lifecycle = SimpleNamespace(star_context=context)
    app.include_router(dashboard_auth.router, prefix="/api/v1")
    app.include_router(dashboard_plugins.router, prefix="/api/v1")
    @app.exception_handler(ApiError)
    async def error(_request, problem):
        return JSONResponse({"status": "error", "message": problem.message}, status_code=problem.status_code)
    try:
        with TestClient(app, base_url=ORIGIN) as client:
            path = BASE + "/setup/v1/status"
            headers = {"sec-fetch-site": "same-origin"}
            assert client.get(path, headers=headers).status_code == 401
            logged = client.post("/api/v1/auth/login", json={"username": "sdk-host-admin", "password": password})
            assert logged.status_code == 200 and logged.json()["status"] == "ok"
            response = client.get(path, headers=headers)
            assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
            value = response.json()
            assert set(value) == {"schema_version", "profile_id", "host_enabled", "authority_enabled", "effective_enabled",
                                  "model_selection", "runtime", "installer", "model_plan"}
            assert value["authority_enabled"] is None and value["effective_enabled"] is False
            assert value["model_selection"]["state"] == "awaiting_installation"
            assert value["runtime"]["stage"] == "enrollment_required"
            assert CANARY.encode() not in response.content and b"api_base" not in response.content
            assert client.get(path, headers={"origin": "https://another.invalid", "sec-fetch-site": "cross-site"}).status_code == 403
            assert calls == []
    finally:
        plugin._workbench.close()
        asyncio.run(db.engine.dispose())


def test_v4_main_selection_keeps_exact_installation_identity_and_zero_provider_calls(sdk_models, tmp_path):
    from dataclasses import fields
    from sylanne3.host.model_workflows_v4 import AdminModelWorkflowsV4
    context, provider, _, calls = sdk_models
    base = bundle_for(provider, tmp_path, version=3)
    workflows = AdminModelWorkflowsV4(4, **{field.name:getattr(base.model_workflows,field.name)
        for field in fields(base.model_workflows) if field.name != 'version'})
    bundle = replace(base, model_workflows=workflows)
    valid = observe(context, 'main-provider', bundle)
    assert valid.state == 'authorized' and valid.reason_code == 'none'
    assert workflows.artifact_draft is None  # Main selection installs no additional work rights.
    assert observe(context, 'other-provider', bundle).reason_code == 'model_provider_mismatch'
    assert observe(context, 'main-provider', bundle).state == 'authorized'
    provider.set_model('different-model')
    assert observe(context, 'main-provider', bundle).reason_code == 'model_id_mismatch'
    provider.set_model('main-model')
    assert observe(context, 'main-provider', bundle).state == 'authorized'
    original = deepcopy(provider.provider_config)
    provider.provider_config['config_revision'] = 2
    assert observe(context, 'main-provider', bundle).reason_code == 'model_config_mismatch'
    provider.provider_config.clear(); provider.provider_config.update(original)
    assert observe(context, 'main-provider', bundle).state == 'authorized'
    wrong_profile = replace(bundle, tls_profile=replace(bundle.tls_profile,profile_id='other-profile'))
    assert observe(context, 'main-provider', wrong_profile).reason_code == 'model_awaiting_installation'
    with pytest.raises(ValueError, match='explicit model workflow version 4 required'):
        replace(workflows, version=5)
    assert calls == []
