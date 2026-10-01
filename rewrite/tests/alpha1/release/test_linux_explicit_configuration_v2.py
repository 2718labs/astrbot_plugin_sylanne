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
    names = ('encode', 'reply', 'context_reply', 'natural_generation', 'natural_review', 'appraisal')
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
