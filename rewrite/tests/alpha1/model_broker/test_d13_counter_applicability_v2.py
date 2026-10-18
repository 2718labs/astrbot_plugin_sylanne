"""Real protected D13 counter contracts; no kernel, SDK or provider execution."""
from dataclasses import replace
from pathlib import Path
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d13_core_counter_contract_v1 import InstalledD13WirePolicyV7
from sylanne3.authority_service.d13_counter_applicability_v2 import require_d13_counter_applicability_v2
from sylanne3.authority_service.d13_installed_counter_factory_v1 import validate_d13_counter_initial_spec_v1
from sylanne3.authority_service.d13_counter_kernel_worker_v1 import _validate_manifest_bytes_v1,D13CounterKernelHold
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST
from sylanne3.runtime_contracts import canonical_digest,canonical_serialize


def installed_contract():
    descriptor={'schema':'sylanne3.d13.counter-applicability.v2','execution_abi':'python-isolated-self-contained.v1',
        'measurement':'provider-metered-input-for-complete-http-request','metric_id':'test:administrator-counter',
        'metric_source_sha256':'a'*64,'program_sha256':'b'*64,'interpreter_sha256':'c'*64,
        'provider_id':'test-provider','model_id':'test-model','provider_config_digest':'d'*64,
        'template_digest':TEMPLATE_DIGEST,'serializer_fingerprint':'e'*64,'tokenizer_fingerprint':'f'*64,
        'wire_policy_fingerprint':'1'*64,
        'late_slot':{'path':['metadata','sylanne_request_digest'],'alphabet':'0123456789abcdef','characters':64,
            'coverage':'all-allowed-values','bound_evidence_sha256':'a'*64}}
    policy=InstalledD13WirePolicyV7(NaturalReplyInstallationV2('test-installation','d'*64,'test-provider','test-model',1024),
        '2'*64,'test-key','test-counter',1,'b'*64,'f'*64,'1'*64,'e'*64,canonical_digest(descriptor),7024,0,1,1,1,0)
    args=dict(metric_id=descriptor['metric_id'],metric_source_sha256='a'*64,program_sha256='b'*64,interpreter_sha256='c'*64)
    return descriptor,policy,args


def test_administrator_counter_binding_accepts_actual_pins_without_mock_metric_default():
    descriptor,policy,args=installed_contract()
    assert require_d13_counter_applicability_v2(canonical_serialize(descriptor).encode(),policy=policy,**args)==descriptor
    assert policy.max_input_tokens==6000 and policy.installation.max_output_tokens==1024


@pytest.mark.parametrize('field', ['program_sha256','interpreter_sha256','metric_source_sha256','provider_id',
    'model_id','provider_config_digest','tokenizer_fingerprint','serializer_fingerprint','wire_policy_fingerprint','template_digest'])
def test_repinning_descriptor_does_not_erase_cross_installation_asset_mismatch(field):
    descriptor,policy,args=installed_contract()
    descriptor[field]='foreign' if field in {'provider_id','model_id'} else '3'*64
    policy=replace(policy,applicability_fingerprint=canonical_digest(descriptor))
    with pytest.raises(AuthorityUnavailable,match='exact installed provider/program/evidence'):
        require_d13_counter_applicability_v2(canonical_serialize(descriptor).encode(),policy=policy,**args)


@pytest.mark.parametrize('change', ['late-value','missing-proof','extra-field'])
def test_count_only_exemplar_cannot_claim_complete_late_slot_coverage(change):
    descriptor,policy,args=installed_contract()
    if change=='late-value':descriptor['late_slot']['coverage']='zero-exemplar-only'
    elif change=='missing-proof':descriptor['late_slot'].pop('bound_evidence_sha256')
    else:descriptor['production_tokenizer_supported']=True
    policy=replace(policy,applicability_fingerprint=canonical_digest(descriptor))
    with pytest.raises(AuthorityUnavailable):
        require_d13_counter_applicability_v2(canonical_serialize(descriptor).encode(),policy=policy,**args)


def test_kernel_manifest_uses_exact_installed_applicability_and_retains_resource_caps():
    descriptor,policy,args=installed_contract()
    pins={k:descriptor[k] for k in ('metric_id','metric_source_sha256','provider_id','model_id','provider_config_digest',
        'template_digest','tokenizer_fingerprint','wire_policy_fingerprint','serializer_fingerprint')}
    pins.update(applicability_fingerprint=policy.applicability_fingerprint,counter_policy_fingerprint='b'*64)
    manifest={**pins,'schema':'sylanne3.d13.counter-kernel-manifest.v2','algorithm_id':'d13.full_http_counter.v1',
        'program_sha256':'b'*64,'interpreter_sha256':'c'*64,'input_schema':'sylanne3.d13.counter-kernel-input.v1',
        'output_schema':'sylanne3.d13.counter-kernel-output.v1','max_input_bytes':16*1024*1024,'max_stdout_bytes':65536,
        'max_stderr_bytes':65536,'cpu_ms_ceiling':1000,'memory_max_bytes':64*1024*1024,'pids_max':4}
    def validate(value):
        return _validate_manifest_bytes_v1(canonical_serialize(value).encode(),'b'*64,'c'*64,64*1024*1024,4,pins)
    assert validate(manifest)==manifest
    with pytest.raises(D13CounterKernelHold,match='fingerprint differs'):
        validate({**manifest,'applicability_fingerprint':'4'*64})
    with pytest.raises(D13CounterKernelHold,match='resource or ABI pin differs'):
        validate({**manifest,'cpu_ms_ceiling':1001})


def test_initial_spec_requires_external_program_interpreter_and_applicability():
    absolute=str(Path(__file__).resolve())
    spec={'schema':'sylanne3.d13.initial-counter.v2','metric_id':'test:administrator-counter',
        **{k:absolute for k in ('signing_key_path','metric_source_path','delegated_cgroup_path','program_path','interpreter_path','applicability_path')},
        **{k:'a'*64 for k in ('metric_source_sha256','program_sha256','interpreter_sha256','applicability_sha256')},
        'memory_max_bytes':64*1024*1024,'pids_max':4,'cpu_policy_id':'test-cpu','cpu_policy_version':1,
        'body_policy_id':'test-body','body_policy_version':1}
    assert validate_d13_counter_initial_spec_v1(spec) is spec
    with pytest.raises(AuthorityUnavailable,match='V2 specification'):
        validate_d13_counter_initial_spec_v1({**spec,'schema':'sylanne3.d13.initial-local-mock-counter.v1'})
    with pytest.raises(AuthorityUnavailable,match='absolute protected'):
        validate_d13_counter_initial_spec_v1({**spec,'program_path':'host-selected-program.py'})
