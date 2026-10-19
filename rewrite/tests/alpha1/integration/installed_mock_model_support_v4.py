"""Package-external Mock endpoint binding; grants no product execution permission."""
from dataclasses import dataclass
from pathlib import Path
from weakref import WeakKeyDictionary
import asyncio

from rewrite.host_tests.alpha1.artifact_phase_counter_fixture_v1 import (
    MOCK_V3_PROVIDER as PROVIDER, MOCK_V3_MODEL as MODEL, MOCK_V3_RULE as RULE,
    MOCK_V3_RULE_ID as RULE_ID, digest)

_BINDINGS = WeakKeyDictionary()

@dataclass(eq=False)
class InstalledMockTransportBindingV4:
    bundle: object
    client_grant: object
    authority_client: object
    counter: object
    provider_client: object
    mock_transport: object
    package_root: Path

async def load_installed_mock_bundle_v4(profile_id, *, profile_root, package_root,
        data_dir, provider_client, mock_transport):
    import httpx
    from openai import AsyncOpenAI
    from sylanne3.host.authority_profile import _load_installation_bundle_from_root
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    from sylanne3.runtime_contracts import canonical_digest
    if (type(provider_client) is not AsyncOpenAI or type(mock_transport) is not httpx.MockTransport
            or provider_client._client._transport is not mock_transport):
        raise ValueError("actual finite SDK MockTransport endpoint required")
    root=Path(package_root).resolve(strict=True)
    bundle=await asyncio.to_thread(_load_installation_bundle_from_root,profile_id,Path(profile_root),"Linux")
    policy=bundle.installation_policy
    verified=await asyncio.to_thread(verify_installed_backend_runtime_v1,root,policy.manifest_digest)
    if not verified.verified or verified.runtime_scope!="backend-beta1-server-test":
        raise ValueError("same installed Beta1 package required for the external Mock endpoint")
    counter=bundle.artifact_phase_counter
    configuration={"id":PROVIDER,"type":"openai_chat_completion","model":MODEL}
    if (counter is None or counter.source_scope!="production"
            or (counter.provider_id,counter.model_id,counter.provider_config_digest)!=(PROVIDER,MODEL,canonical_digest(configuration))
            or counter.encoding_rule_id!=RULE_ID or counter.encoding_rule_sha256!=digest(RULE)):
        raise ValueError("formal installed counter must declare this exact Mock-only model/rule")
    transport=MtlsAuthorityTransport({profile_id:bundle.tls_profile})
    client=AuthorityClient(AuthoritySelection(profile_id),package_root=root,data_dir=Path(data_dir),transport=transport)
    try:
        if (await client.status_v2()).state!="paired":
            raise ValueError("actual independent installed channel is not paired")
        grant=await client.installation_grant_v2()
        if (grant.authority_id!=policy.expected_authority_id
                or grant.administrator_holder!=policy.administrator_holder
                or grant.installation_id!=policy.installation_id
                or grant.manifest_digest!=policy.manifest_digest):
            raise ValueError("actual mTLS installation grant differs from the protected Root")
        binding=InstalledMockTransportBindingV4(bundle,grant,client,counter,provider_client,mock_transport,root)
        _BINDINGS[binding]=binding_identity_v4(binding)
        return bundle,binding
    except BaseException:
        await transport.close()
        raise

def binding_identity_v4(binding):
    return (binding.bundle,binding.client_grant,binding.authority_client,binding.counter,
        binding.provider_client,binding.mock_transport,binding.package_root)

def require_installed_mock_binding_v4(bundle, *, client_grant):
    matches=[b for b in _BINDINGS if b.bundle is bundle and b.client_grant is client_grant]
    if len(matches)!=1:
        raise ValueError("actual external Mock binding is absent or closed")
    b=matches[0]
    if _BINDINGS[b]!=binding_identity_v4(b) or b.provider_client._client._transport is not b.mock_transport:
        raise ValueError("external Mock endpoint changed")
    return b

def revoke_installed_mock_binding_v4(binding):
    _BINDINGS.pop(binding,None)

async def check_installed_mock_components_v4(binding, *, graph, bootstrap, model_runtime):
    require_installed_mock_binding_v4(binding.bundle,client_grant=binding.client_grant)
    graph._admin(bootstrap)
    if (graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not binding.bundle
            or model_runtime.graph is not graph or model_runtime.bundle is not binding.bundle):
        raise ValueError("actual installed Mock components differ")
    # No registration, permission, Work kind, production verifier patch or context override.
