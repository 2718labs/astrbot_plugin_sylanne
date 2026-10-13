"""Permanent acceptance of explicit Linux config and stopped-Host CLI inputs.

No system paths, credentials, model endpoints or systemd units are mutated.
"""
from __future__ import annotations
import base64
import importlib.util
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import zipfile
import pytest

ROOT = Path(__file__).resolve().parents[4]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / 'alpha1' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


INSTALL = module('install_linux')
CONTROL = module('authority_linux_control')


def request(tmp_path):
    value = INSTALL.request_template_v2()
    config = tmp_path / 'provider.json'
    config.write_text(json.dumps({'provider': 'controlled-test-provider'}))
    value.update(profile_id='installed', bot_id='testbot', persona_id='testpersona', host_uid=1234, host_gid=1234,
        currency='USD', budget_valid_until_utc=4102444800.0, provider_config_path=str(config),
        provider_id='controlled-provider', model_id='controlled-model', workbench_origin='https://localhost:6185',
        model_quote={'output_tokens':128}, local_quote={'cpu_ms':100,'thread_cpu_ms':100},
        budget_limits={'output_tokens':10000,'cpu_ms':10000,'thread_cpu_ms':10000},
        budget_max_ceiling={'output_tokens':1000,'cpu_ms':1000,'thread_cpu_ms':1000})
    value['d04_joint_numeric'].update(cpu_ceiling_ms=100, max_iterations=128, tolerance=1e-8, job_lifetime_seconds=300)
    value['provider_cache']['provider_id'] = value['provider_id']
    value['onebot_account'] = ['configuration-test', 'aiocqhttp', '100000001']
    return value


def test_template_never_silently_chooses_paid_limits():
    with pytest.raises(ValueError): INSTALL.check_request(INSTALL.request_template_v2())


def test_installer_preserves_explicit_full_policies_and_work_kinds(tmp_path):
    req = request(tmp_path)
    assert INSTALL.check_request(req) is req
    profile = INSTALL.make_profile(req, manifest_pin='a'*64, authority_id='authority:configuration-test',
        installation_id='installation:configuration-test', registry=SimpleNamespace(catalogue_hash='c'*64),
        scheme=SimpleNamespace(scheme_version='scheme:configuration-test',operator_version='operator:configuration-test'))
    kinds = profile['installation_policy']['root_grant']['allowed_work_kinds']
    assert {'d04.joint_numeric_cpu.v3','d04.authored_root_adoption.v3','d04.semantic_drive.adopt','d06.c04_internal_cpu.v1'} <= set(kinds)
    assert profile['d04_joint_numeric'] == req['d04_joint_numeric']
    assert profile['d04_semantic_drive'] == req['d04_semantic_drive']
    assert 'd13_wire_policy' not in profile and 'd13_wire_counter' not in profile
    assert profile['installation_policy']['root_lease']['limits'] == req['budget_limits']


def test_quotes_are_checked_separately_and_numeric_ceiling_cannot_exceed_root(tmp_path):
    req = request(tmp_path)
    req['local_quote']['output_tokens'] = 1001
    with pytest.raises(ValueError, match='per-call quote'): INSTALL.check_request(req)
    req = request(tmp_path)
    req['d04_joint_numeric']['cpu_ceiling_ms'] = 1001
    with pytest.raises(ValueError, match='root CPU'):
        INSTALL.make_profile(req,manifest_pin='a'*64,authority_id='authority:test',installation_id='installation:test',
            registry=SimpleNamespace(catalogue_hash='c'*64),scheme=SimpleNamespace(scheme_version='scheme:test',operator_version='operator:test'))


def test_independent_management_is_closed_and_never_accepts_private_key():
    fields = {'owner_actor_id':'actor','owner_session_request':{},'owner_session_token':'test-token'}
    method, command = CONTROL.command_for('resume', {**fields,'pause_operation_id':'pause','operation_id':'resume','expected_lifecycle_epoch':2}, 'namespace:test')
    assert method == 'd12_installation_control_v1'
    assert command['action'] == 'resume' and command['namespace'] == 'namespace:test'
    with pytest.raises(ValueError): CONTROL.command_for('resume',{**fields,'private_key':'never-accepted'},'namespace:test')
    with pytest.raises(ValueError): CONTROL.command_for('arbitrary-execution',fields,'namespace:test')
    method, command = CONTROL.command_for('accept',{'challenge':{},'signature_base64':base64.b64encode(bytes(64)).decode()},'namespace:test')
    assert method == 'accept_owner_session_v1' and command['signature'] == '00'*64
    with pytest.raises(ValueError): CONTROL.command_for('accept',{'challenge':{},'signature_base64':'bad'},'namespace:test')


def test_cache_provider_covers_every_configured_workflow(tmp_path):
    from sylanne3.authority_service.linux_deployment_v1 import require_complete_provider_cache_binding_v1
    from sylanne3.authority_service.contract import AuthorityUnavailable
    req = request(tmp_path)
    req['provider_cache']['provider_id'] = 'unrelated-provider'
    with pytest.raises(ValueError, match='cache adapter'):
        INSTALL.check_request(req)
    names = ('encode', 'reply', 'context_reply', 'natural_generation', 'natural_review', 'appraisal',
             'd07_cognition', 'contact_generation', 'contact_review', 'life_content', 'life_numeric')
    workflows = SimpleNamespace(**{name: SimpleNamespace(provider_id='provider-a') for name in names})
    bundle = SimpleNamespace(model_workflows=workflows, d13_paid_precompression=None)
    require_complete_provider_cache_binding_v1(bundle, 'provider-a')
    for name in names:
        getattr(workflows, name).provider_id = 'provider-b'
        with pytest.raises(AuthorityUnavailable, match='every installed model provider'):
            require_complete_provider_cache_binding_v1(bundle, 'provider-a')
        getattr(workflows, name).provider_id = 'provider-a'
    bundle.d13_paid_precompression = SimpleNamespace(selected_main=SimpleNamespace(provider_id='provider-b'))
    with pytest.raises(AuthorityUnavailable, match='every installed model provider'):
        require_complete_provider_cache_binding_v1(bundle, 'provider-a')


def test_real_package_plan_validates_full_policy_without_install(tmp_path):
    package_path = os.environ.get('SYLANNE_ALPHA1_PACKAGE')
    if not package_path:
        pytest.skip('actual candidate package not supplied')
    package = Path(package_path)
    with zipfile.ZipFile(package) as archive:
        pin = hashlib.sha256(archive.read('release-manifest.json')).hexdigest()
    args = SimpleNamespace(package=package, package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(), manifest_sha256=pin)
    req = request(tmp_path)
    INSTALL.preflight_profile(args, req)
    req['d04_joint_numeric']['cpu_ceiling_ms'] = 1001
    with pytest.raises(ValueError, match='root CPU'):
        INSTALL.preflight_profile(args, req)


def test_optional_d13_grants_follow_explicit_policies_and_budgets(tmp_path):
    req = request(tmp_path)
    common = dict(history_token_budget=1024, deadline_after_seconds=300, max_slots=3, resource_ref='installed:d13:test')
    req['d13_precompression'] = dict(common, quote_ceiling={'d13_compute_units':1})
    req['d13_paid_precompression'] = dict(common, quote_ceiling={'input_tokens':512, 'output_tokens':128})
    req['model_quote']['input_tokens'] = 512
    req['budget_limits']['input_tokens'] = 10000
    req['budget_max_ceiling']['input_tokens'] = 1000
    args = dict(manifest_pin='a'*64, authority_id='authority:test', installation_id='installation:test',
        registry=SimpleNamespace(catalogue_hash='c'*64), scheme=SimpleNamespace(scheme_version='scheme:test', operator_version='operator:test'))
    with pytest.raises(ValueError, match='D13 precompression quote exceeds'):
        INSTALL.make_profile(req, **args)
    req['budget_limits']['d13_compute_units'] = 10
    req['budget_max_ceiling']['d13_compute_units'] = 1
    profile = INSTALL.make_profile(req, **args)
    assert {'d13.precompress', 'd13.precompress.paid.v1'} <= set(profile['installation_policy']['root_grant']['allowed_work_kinds'])
    assert profile['d13_precompression'] == req['d13_precompression']
    assert profile['d13_paid_precompression'] == req['d13_paid_precompression']


def selected_request(tmp_path):
    from sylanne3.runtime_contracts import canonical_digest
    req = request(tmp_path)
    config = {'id': 'selected-provider', 'type': 'openai_chat_completion',
              'model': 'selected-model', 'api_key': 'MODEL_PLAN_SECRET_CANARY'}
    Path(req['provider_config_path']).write_text(json.dumps(config))
    selection = {'schema': 'sylanne.host-model-selection.v1',
                 'authority_profile': req['profile_id'],
                 'provider_id': config['id'], 'model_id': config['model'],
                 'provider_config_digest': canonical_digest(config)}
    return req, config, selection


def test_selected_llm_enters_formal_profile_without_changing_budget_or_exporting_config(tmp_path):
    req, _config, selection = selected_request(tmp_path)
    updated = INSTALL.selected_model_request_v1(req, selection)
    assert updated['provider_id'] == 'selected-provider'
    assert updated['model_id'] == 'selected-model'
    assert updated['provider_cache']['provider_id'] == 'selected-provider'
    changed = {key for key in req if req[key] != updated[key]}
    assert changed == {'provider_id', 'model_id', 'provider_cache'}
    assert req['provider_id'] == 'controlled-provider'
    profile = INSTALL.make_profile(updated, manifest_pin='a'*64, authority_id='authority:selection-test',
        installation_id='installation:selection-test', registry=SimpleNamespace(catalogue_hash='c'*64),
        scheme=SimpleNamespace(scheme_version='scheme:selection-test', operator_version='operator:selection-test'))
    reply = profile['model_workflows']['reply']
    assert reply['provider_id'] == selection['provider_id']
    assert reply['model_id'] == selection['model_id']
    assert reply['provider_config_digest'] == selection['provider_config_digest']
    assert profile['installation_policy']['root_lease']['limits'] == req['budget_limits']
    assert profile['installation_policy']['root_grant']['valid_until_utc'] == req['budget_valid_until_utc']
    assert 'MODEL_PLAN_SECRET_CANARY' not in json.dumps(profile)


def test_model_plan_rejects_wrong_profile_stale_config_and_same_digest_with_wrong_model(tmp_path):
    req, config, selection = selected_request(tmp_path)
    INSTALL.selected_model_request_v1(req, selection)
    with pytest.raises(ValueError, match='different Authority profile'):
        INSTALL.selected_model_request_v1(req, {**selection, 'authority_profile': 'different'})
    with pytest.raises(ValueError, match='provider or model differs'):
        INSTALL.selected_model_request_v1(req, {**selection, 'model_id': 'different-model'})
    Path(req['provider_config_path']).write_text(json.dumps({**config, 'model': 'changed-model'}))
    with pytest.raises(ValueError, match='configuration changed'):
        INSTALL.selected_model_request_v1(req, selection)


def test_model_selection_cannot_supply_credentials_grants_or_extra_budget_fields(tmp_path):
    req, _config, selection = selected_request(tmp_path)
    INSTALL.selected_model_request_v1(req, selection)
    for field in ('api_key', 'private_key', 'grant', 'budget_limits'):
        with pytest.raises((TypeError, ValueError)):
            INSTALL.selected_model_request_v1(req, {**selection, field: 'never-accepted'})


def test_initial_natural_template_pair_preserves_legacy_and_exact_profile_binding(tmp_path):
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION, TEMPLATE_VERSION_V5
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2

    req = request(tmp_path)
    template = INSTALL.request_template_v4()
    req.update(schema=template["schema"], foreground=template["foreground"],
               artifact_draft=None, host_process_command=template["host_process_command"],
               host_lifecycle=template["host_lifecycle"])
    req.pop("host_systemd_unit")
    args = dict(manifest_pin="a" * 64, authority_id="authority:template-test",
                installation_id="installation:template-test",
                registry=SimpleNamespace(catalogue_hash="c" * 64),
                scheme=SimpleNamespace(scheme_version="scheme:test", operator_version="operator:test"))
    INSTALL.check_request(req)
    legacy = INSTALL.make_profile(req, **args)
    omitted = INSTALL.make_profile({**req, "natural_template_pair_v1": None}, **args)
    assert INSTALL.canonical(omitted) == INSTALL.canonical(legacy)
    assert (legacy["model_workflows"]["natural_generation"]["template_version"],
            legacy["model_workflows"]["natural_review"]["template_version"]) == (
                TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION)
    selected = {"schema": "sylanne3.initial-natural-template-pair.v1",
                "generation": TEMPLATE_VERSION_V5, "review": REVIEW_TEMPLATE_VERSION_V2}
    configured = {**req, "natural_template_pair_v1": selected}
    INSTALL.check_request(configured)
    updated = INSTALL.make_profile(configured, **args)
    expected = json.loads(json.dumps(legacy))
    expected["model_workflows"]["natural_generation"]["template_version"] = TEMPLATE_VERSION_V5
    expected["model_workflows"]["natural_review"]["template_version"] = REVIEW_TEMPLATE_VERSION_V2
    assert INSTALL.canonical(updated) == INSTALL.canonical(expected)
    assert INSTALL.configuration_plan_v4(configured)["natural_template_pair_v1"] == selected


def test_initial_natural_template_pair_refuses_mixed_unknown_and_wrong_request_version():
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION_V5
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2

    pair = {"schema": "sylanne3.initial-natural-template-pair.v1",
            "generation": TEMPLATE_VERSION_V5, "review": REVIEW_TEMPLATE_VERSION_V2}
    for bad in ({**pair, "review": REVIEW_TEMPLATE_VERSION},
                {**pair, "generation": "unregistered"},
                {**pair, "scope": "owner"}):
        with pytest.raises(ValueError):
            INSTALL.natural_template_pair_v1({"schema": "sylanne3.linux-install-request.v4",
                                             "natural_template_pair_v1": bad})
    with pytest.raises(ValueError):
        INSTALL.natural_template_pair_v1({"schema": "sylanne3.linux-install-request.v3",
                                         "natural_template_pair_v1": pair})


def _astrbot_request_v4(tmp_path):
    from sylanne3.host.identity import astrbot_namespace_from_configuration_v1
    value = INSTALL.request_template_v4()
    common = request(tmp_path)
    value.update({name: data for name, data in common.items() if name in value and name not in {"schema", "host_lifecycle"}})
    declared = {"schema": "sylanne.astrbot.installed-namespace.v1",
        "platform_id": "configuration-test", "self_id": "100000001", "selected_persona_id": "fixture-persona"}
    namespace = astrbot_namespace_from_configuration_v1(declared)
    value.update(bot_id=namespace.bot_id, persona_id=namespace.persona_id, astrbot_namespace_v1=declared)
    return value


def test_initial_natural_v6_pair_builds_exact_typed_workflows_and_refuses_mixed_pair(tmp_path):
    from sylanne3.host.authority_profile import _model_workflows_from_payload, _policy_from_payload
    from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
    from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2

    req = _astrbot_request_v4(tmp_path)
    pair = {"schema": "sylanne3.initial-natural-template-pair.v1",
            "generation": TEMPLATE_VERSION, "review": REVIEW_TEMPLATE_VERSION_V2}
    req["natural_template_pair_v1"] = pair
    INSTALL.check_request(req)
    profile = INSTALL.make_profile(req, manifest_pin="a" * 64,
        authority_id="authority:natural-v6-install", installation_id="installation:natural-v6-install",
        registry=SimpleNamespace(catalogue_hash="c" * 64),
        scheme=SimpleNamespace(scheme_version="scheme:test", operator_version="operator:test"))
    policy = _policy_from_payload(profile)
    workflows = _model_workflows_from_payload(profile)
    assert policy.namespace.bot_id == req["bot_id"]
    assert type(workflows) is AdminModelWorkflowsV6
    assert workflows.natural_generation.template_version == TEMPLATE_VERSION
    assert workflows.natural_review.template_version == REVIEW_TEMPLATE_VERSION_V2
    assert workflows.natural_generation.provider_id == req["provider_id"]
    from sylanne3.runtime_contracts import canonical_digest
    assert workflows.natural_generation.provider_config_digest == canonical_digest(
        json.loads(Path(req["provider_config_path"]).read_bytes()))
    assert workflows.d07_relationship_cognition is None
    assert workflows.growth_cognition is None
    assert profile["model_workflows"]["version"] == 6
    assert profile["model_workflows"]["d07_relationship_cognition"] is None
    assert profile["model_workflows"]["growth_cognition"] is None
    assert INSTALL.configuration_plan_v4(req)["natural_template_pair_v1"] == pair
    for bad in ({**pair, "review": REVIEW_TEMPLATE_VERSION},
                {**pair, "generation": "sylanne.unregistered-natural-template.v6"}):
        with pytest.raises(ValueError):
            INSTALL.check_request({**req, "natural_template_pair_v1": bad})


def test_installer_binds_exact_derived_sdk_namespace_before_any_grant(tmp_path):
    req = _astrbot_request_v4(tmp_path)
    assert INSTALL.check_request(req) is req
    profile = INSTALL.make_profile(req, manifest_pin="a" * 64, authority_id="authority:configuration-test",
        installation_id="installation:configuration-test", registry=SimpleNamespace(catalogue_hash="c" * 64),
        scheme=SimpleNamespace(scheme_version="scheme:configuration-test", operator_version="operator:configuration-test"))
    assert profile["astrbot_namespace_v1"] == req["astrbot_namespace_v1"]
    assert profile["installation_policy"]["namespace"] == {"bot_id": req["bot_id"], "persona_id": req["persona_id"]}
    from sylanne3.host.authority_profile import _policy_from_payload
    profile["astrbot_namespace_v1"] = {**profile["astrbot_namespace_v1"], "selected_persona_id": "other-persona"}
    with pytest.raises(ValueError, match="configured AstrBot namespace identity"):
        _policy_from_payload(profile)


@pytest.mark.parametrize("changed", ["bot_id", "self_id", "account", "undeclared"])
def test_installer_rejects_mismatched_or_undeclared_sdk_namespace(tmp_path, changed):
    req = _astrbot_request_v4(tmp_path)
    if changed == "bot_id":
        req["bot_id"] = "astrbot-bot:" + "f" * 64
    elif changed == "self_id":
        req["astrbot_namespace_v1"] = {**req["astrbot_namespace_v1"], "self_id": "100000002"}
    elif changed == "account":
        req["onebot_account"] = ["other-platform", "aiocqhttp", "100000001"]
    else:
        req.pop("astrbot_namespace_v1")
    with pytest.raises(ValueError, match="configured AstrBot namespace differs|bot_id is invalid"):
        INSTALL.check_request(req)


def test_installer_and_authority_use_same_canonical_onebot_account_contract(tmp_path):
    from sylanne3.authority_service.installed_platform_observation import parse_installed_onebot_account_v2
    req = request(tmp_path)
    wire = json.dumps(req["onebot_account"], separators=(",", ":"))
    assert parse_installed_onebot_account_v2(wire) == tuple(req["onebot_account"])
    req["onebot_account"] = {"self_id": "100000001"}
    with pytest.raises(ValueError, match="installed OneBot account"):
        INSTALL.check_request(req)
    with pytest.raises(ValueError, match="installed OneBot account"):
        parse_installed_onebot_account_v2('["configuration-test", "aiocqhttp", "0100000001"]')
