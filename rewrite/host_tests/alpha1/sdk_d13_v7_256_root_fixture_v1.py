"""Fresh-only approved V7 256 SDK Root; original single-call limits remain fixed."""
SCENARIO='sdk_d13_v7_256_current_v1'
PROFILE_ID='sdk-d13-v7-256'
EXPECTED_INITIAL_PERSONA_ID='sdk-d13-v7-256-persona'
EPISODE_COUNT=256
MAX_EPISODE_CALLS=6
MAX_AUXILIARY_CALLS=2
MAX_TOTAL_MODEL_CALLS=1536
PER_EPISODE_MODEL_LIMITS={'input_tokens':48000,'output_tokens':8000,'model_tokens':56000,'model_microusd':1200}
INITIAL_MODEL_LIMITS={name:amount*EPISODE_COUNT for name,amount in PER_EPISODE_MODEL_LIMITS.items()}


def approved_sdk_d13_v7_256_initial_request_v1(*,executable_sha256,valid_until_utc):
    from rewrite.host_tests.alpha1.sdk_m1_fixture_contract_v1 import approved_initial_request_v1
    from scripts.alpha1.install_linux import check_request
    value=approved_initial_request_v1(executable_sha256=executable_sha256,valid_until_utc=valid_until_utc)
    maximum=dict(value['budget_max_ceiling']);quote=dict(value['model_quote']);cpu=value['budget_limits']['cpu_ms']
    value.update(profile_id=PROFILE_ID,persona_id=EXPECTED_INITIAL_PERSONA_ID)
    value['budget_limits'].update(INITIAL_MODEL_LIMITS)
    assert value['budget_max_ceiling']==maximum and value['model_quote']==quote
    assert value['budget_limits']['cpu_ms']==cpu and value['budget_valid_until_utc']==valid_until_utc
    return check_request(value)


def configure_initial_v7_counter_v1(value,*,metric_source_path):
    """Actual protected fresh fixture assets, before any installation signing."""
    from pathlib import Path
    from dataclasses import asdict
    import hashlib,json,os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
    from sylanne3.authority_service.d13_core_counter_contract_v1 import InstalledD13WirePolicyV7
    from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
    from sylanne3.model_broker.d13_provider_http_template_v1 import SERIALIZER_FINGERPRINT
    from sylanne3.native_runtime import d13_local_mock_counter_v1 as counter
    from sylanne3.runtime_contracts import canonical_digest
    from scripts.alpha1.install_linux import write
    program_sha=hashlib.sha256(Path(counter.__file__).read_bytes()).hexdigest()
    metric_path=Path(metric_source_path)
    metric_sha=hashlib.sha256(metric_path.read_bytes()).hexdigest()
    config=json.loads(Path(value['provider_config_path']).read_bytes())
    config_digest=canonical_digest(config)
    tokenizer=canonical_digest({'metric_id':counter.METRIC_ID,'metric_source_sha256':metric_sha})
    wire=canonical_digest({'schema':'sylanne3.d13.local-mock-wire.v7','serializer':SERIALIZER_FINGERPRINT,
        'input_limit':6000,'output_limit':1024,'context_limit':7024,'tools':False})
    private=Ed25519PrivateKey.generate()
    key_path=Path('/etc/sylanne-b04-fixture/d13-v7-counter-private.key')
    write(key_path,private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()),mode=0o600)
    descriptor=counter.local_mock_applicability_descriptor_v1(metric_source_sha256=metric_sha,
        provider_id=value['provider_id'],model_id=value['model_id'],provider_config_digest=config_digest,
        template_digest=__import__('sylanne3.model_broker.natural_reply_history_v7',fromlist=['TEMPLATE_DIGEST']).TEMPLATE_DIGEST,
        serializer_fingerprint=SERIALIZER_FINGERPRINT,tokenizer_fingerprint=tokenizer,wire_policy_fingerprint=wire)
    policy=InstalledD13WirePolicyV7(
        installation=NaturalReplyInstallationV2('installation:initial-v7-placeholder',config_digest,
            value['provider_id'],value['model_id'],value['model_quote']['output_tokens']),
        counter_public_key_hex=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
        counter_key_id='fixture:sdk-d13-v7-core-key',counter_policy_id='fixture:sdk-d13-v7-http-byte-count',
        counter_policy_version=1,counter_policy_fingerprint=program_sha,tokenizer_fingerprint=tokenizer,
        wire_policy_fingerprint=wire,serializer_fingerprint=SERIALIZER_FINGERPRINT,
        applicability_fingerprint=canonical_digest(descriptor),context_limit_tokens=value['model_quote']['model_tokens'],
        tool_reserve_tokens=0,uncached_input_microusd_per_million=1,cache_write_input_microusd_per_million=1,
        output_microusd_per_million=1,storage_microusd_upper=0,allow_conservative_switch=True)
    raw_policy=asdict(policy);raw_policy['installation']='$current_installation'
    cgroup_lines=Path('/proc/self/cgroup').read_text().splitlines()
    unified=[line[3:] for line in cgroup_lines if line.startswith('0::')]
    if len(unified)!=1 or Path(unified[0]).name!='app':
        raise ValueError('fresh V7 fixture must run in its actual owned app resource group')
    delegated=Path('/sys/fs/cgroup')/str(Path(unified[0]).parent).lstrip('/')
    if delegated.name.startswith('sylanne-owned-') is False:
        raise ValueError('V7 counter delegation is outside the actual owned run subtree')
    value.update(d13_wire_policy=raw_policy,d13_wire_counter=None,
        d13_counter_installation_v1={'schema':'sylanne3.d13.initial-local-mock-counter.v1',
            'signing_key_path':str(key_path),'metric_source_path':str(metric_path),'metric_source_sha256':metric_sha,
            'delegated_cgroup_path':str(delegated),'memory_max_bytes':64*1024*1024,'pids_max':4,
            'cpu_policy_id':'cpu-policy:sdk-d13-v7-counter','cpu_policy_version':1,
            'body_policy_id':'body-policy:sdk-d13-v7-counter','body_policy_version':1})
    return value
