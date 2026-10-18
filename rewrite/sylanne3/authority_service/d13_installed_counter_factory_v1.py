"""Protected composer for an administrator-pinned D13 Core counter.

Assets are fixed by Root's namespace installation. RPCs accept selectors and
actual authenticated peers; program paths, key bytes and resource policy never
come from a Host request. This factory does not install or renew budget grants.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path

from .contract import AuthorityUnavailable
from .d13_core_counter_contract_v1 import InstalledD13WirePolicyV7
from .d13_core_counter_source_v1 import InstalledD13CounterSourceV1
from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
from .d13_counter_kernel_worker_v1 import InstalledD13CounterKernelWorkerV1
from .d13_derived_paid_block_verifier_v2 import InstalledD13DerivedPaidBlockVerifierV2
from .linux_installation_security_v1 import opened_installed_file_v1,read_installed_bytes_v1
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..domains.d03.context import ContextProvider
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..host.context_scheme_asset import load_verified_context_scheme
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
from .d13_counter_applicability_v2 import require_d13_counter_applicability_v2
from ..runtime.d13_counter_cpu_quote_policy_v1 import D13CounterCpuQuotePolicyAuthorityV1
from ..runtime.issuers import D02ResourceIssuer,D11BudgetGrantIssuer
from ..runtime_contracts import NamespaceId,canonical_digest


@dataclass(frozen=True,slots=True)
class InstalledD13CounterAssetsV2:
    namespace: NamespaceId
    installation_id: str
    namespace_root: str
    package_root: str
    package_manifest_sha256: str
    program_path: str
    program_sha256: str
    program_manifest_path: str
    program_manifest_sha256: str
    interpreter_path: str
    interpreter_sha256: str
    metric_source_path: str
    metric_source_sha256: str
    delegated_cgroup_path: str
    memory_max_bytes: int
    pids_max: int
    signing_key_path: str
    component_signing_key_path: str
    cpu_policy_id: str
    cpu_policy_version: int
    body_policy_id: str
    body_policy_version: int
    metric_id: str
    applicability_path: str
    applicability_sha256: str
    schema: str='sylanne3.d13.installed-counter-assets.v2'

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.metric_id)is not str or not self.metric_id or len(self.metric_id)>4096
                or self.schema!='sylanne3.d13.installed-counter-assets.v2'):
            raise AuthorityUnavailable('exact administrator-installed counter metric and V2 asset identity required')
        for name in ('installation_id','cpu_policy_id','body_policy_id'):
            value=getattr(self,name)
            if type(value) is not str or not value:raise ValueError('counter asset identifier required: '+name)
        for name in ('package_manifest_sha256','program_sha256','program_manifest_sha256','interpreter_sha256','metric_source_sha256','applicability_sha256'):
            value=getattr(self,name)
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('counter asset digest required: '+name)
        for name in ('memory_max_bytes','pids_max','cpu_policy_version','body_policy_version'):
            if type(getattr(self,name)) is not int or getattr(self,name)<1:raise ValueError('positive installed counter limit/version required: '+name)
        for name in ('namespace_root','package_root','program_path','program_manifest_path','interpreter_path','metric_source_path','delegated_cgroup_path','signing_key_path','component_signing_key_path','applicability_path'):
            value=getattr(self,name)
            if type(value) is not str or not Path(value).is_absolute() or '..' in Path(value).parts:
                raise ValueError('absolute installed counter asset path required: '+name)
        root=Path(self.namespace_root)
        for name in ('program_path','program_manifest_path','metric_source_path','signing_key_path','component_signing_key_path','applicability_path'):
            if not Path(getattr(self,name)).is_relative_to(root):raise AuthorityUnavailable('counter namespace assets cross their protected Root directory')


class InstalledD13CounterPaidVerifierFactoryV1:
    """Create one exact verifier in the current Source reader's actual DB/scene."""
    __slots__=('installation','resource_issuer','budget_issuer','authority_store')
    def __init__(self,*,installation,resource_issuer,budget_issuer,authority_store):
        if (type(installation) is not D13PrecompressionInstallationV1
                or type(resource_issuer) is not D02ResourceIssuer
                or not isinstance(budget_issuer,D11BudgetGrantIssuer)
                or type(authority_store) is not AuthorityV2ModelEgressStore
                or budget_issuer.resource_issuer is not resource_issuer):
            raise AuthorityUnavailable('actual installed paid block authority objects required')
        self.installation=installation;self.resource_issuer=resource_issuer
        self.budget_issuer=budget_issuer;self.authority_store=authority_store

    def for_current_read(self,db,*,namespace,scene_ref,conversation_ref,now_utc,activation_generation,max_slots):
        return InstalledD13DerivedPaidBlockVerifierV2(db,installation=self.installation,
            resource_issuer=self.resource_issuer,budget_issuer=self.budget_issuer,
            namespace=namespace,scene_ref=scene_ref,conversation_ref=conversation_ref,now_utc=now_utc,
            activation_generation=activation_generation,authority_store=self.authority_store,max_slots=max_slots)


def _hash_protected_file_v1(path):
    digest=sha256()
    with opened_installed_file_v1(path) as fd:
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            digest.update(chunk)
    return digest.hexdigest()


def validate_installed_d13_counter_assets_v1(*,assets,foreground_observer,bridge,cpu_quote_authority,body_quote_authority,authority_store):
    """Validate fixed installation inputs without a fake worker or a signature."""
    from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
    from .v2_execution_bridge import AuthorityV2ExecutionBridge
    if (type(assets) is not InstalledD13CounterAssetsV2
            or type(foreground_observer) is not InstalledCurrentForegroundActivityV1
            or type(bridge) is not AuthorityV2ExecutionBridge
            or type(cpu_quote_authority) is not D13CounterCpuQuotePolicyAuthorityV1
            or type(body_quote_authority) is not D02BodyQuoteAuthority
            or type(authority_store) is not AuthorityV2ModelEgressStore):
        raise AuthorityUnavailable('actual protected Counter installation objects required')
    bundle=foreground_observer.installed_bundle;identity=foreground_observer.self_identity
    if (bundle is None or identity._core is not bridge.core or bridge.namespace!=identity._fences.namespace
            or assets.namespace!=identity._namespace_id or assets.installation_id!=identity._installation_id
            or bundle.installation_policy.namespace!=assets.namespace
            or bundle.installation_policy.installation_id!=assets.installation_id):
        raise AuthorityUnavailable('counter assets cross actual Core/Self/bundle installation')
    policy=bundle.d13_wire_policy
    workflow=bundle.model_workflows.natural_generation
    if type(policy) is not InstalledD13WirePolicyV7 or workflow is None or workflow.template_version!=TEMPLATE_VERSION:
        raise AuthorityUnavailable('actual installed V7 natural workflow and Core counter policy required')
    installation=NaturalReplyInstallationV2(assets.installation_id,workflow.provider_config_digest,
        workflow.provider_id,workflow.model_id,workflow.max_output_tokens)
    if policy.installation!=installation:raise AuthorityUnavailable('V7 counter policy differs from actual natural workflow')
    if bundle.d13_paid_precompression is None:raise AuthorityUnavailable('actual installed paid D13 policy required')
    main=bundle.d13_paid_precompression.selected_main
    if (main.provider_id,main.model_id,main.provider_config_digest)!=(workflow.provider_id,workflow.model_id,workflow.provider_config_digest):
        raise AuthorityUnavailable('counter paid D13 and natural provider/config differ')
    descriptor_raw=read_installed_bytes_v1(assets.applicability_path,limit=8192)
    if sha256(descriptor_raw).hexdigest()!=assets.applicability_sha256:
        raise AuthorityUnavailable('protected applicability original differs from its installed SHA256')
    require_d13_counter_applicability_v2(descriptor_raw,policy=policy,metric_id=assets.metric_id,
        metric_source_sha256=assets.metric_source_sha256,program_sha256=assets.program_sha256,
        interpreter_sha256=assets.interpreter_sha256)
    for path,digest in ((assets.program_path,assets.program_sha256),(assets.program_manifest_path,assets.program_manifest_sha256),
            (assets.interpreter_path,assets.interpreter_sha256),(assets.metric_source_path,assets.metric_source_sha256)):
        if _hash_protected_file_v1(path)!=digest:raise AuthorityUnavailable('actual protected counter asset bytes differ')
    scheme=load_verified_context_scheme(assets.package_root,assets.package_manifest_sha256)
    context=ContextProvider();context.compile_scheme(scheme.draft(),None)
    return policy,context,main


def install_d13_core_counter_v1(*,foreground_observer,bridge,execute_credential,assets,
        cpu_quote_authority,body_quote_authority,authority_store,create=False):
    policy,context,main=validate_installed_d13_counter_assets_v1(assets=assets,foreground_observer=foreground_observer,
        bridge=bridge,cpu_quote_authority=cpu_quote_authority,body_quote_authority=body_quote_authority,authority_store=authority_store)
    paid=InstalledD13CounterPaidVerifierFactoryV1(installation=main,
        resource_issuer=foreground_observer.issuer.resource_issuer,budget_issuer=foreground_observer.issuer,authority_store=authority_store)
    source=InstalledD13CounterSourceV1(foreground_observer=foreground_observer,context_provider=context,
        policy=policy,paid_verifier_factory=paid)
    worker=InstalledD13CounterKernelWorkerV1(program_path=assets.program_path,program_sha256=assets.program_sha256,
        manifest_path=assets.program_manifest_path,manifest_sha256=assets.program_manifest_sha256,
        delegated_cgroup_path=assets.delegated_cgroup_path,installation_id=assets.installation_id,
        memory_max_bytes=assets.memory_max_bytes,pids_max=assets.pids_max,
        interpreter_path=assets.interpreter_path,interpreter_sha256=assets.interpreter_sha256,
        metric_id=assets.metric_id,applicability_fingerprint=policy.applicability_fingerprint,
        metric_source_sha256=assets.metric_source_sha256,
        provider_id=policy.installation.provider_id,model_id=policy.installation.model_id,
        provider_config_digest=policy.installation.provider_config_digest,
        template_digest=policy.template_digest,serializer_fingerprint=policy.serializer_fingerprint,
        tokenizer_fingerprint=policy.tokenizer_fingerprint,wire_policy_fingerprint=policy.wire_policy_fingerprint,
        counter_policy_fingerprint=policy.counter_policy_fingerprint)
    signing_key=read_installed_bytes_v1(assets.signing_key_path,limit=32,private=True)
    component_key=read_installed_bytes_v1(assets.component_signing_key_path,limit=128,private=True)
    if len(signing_key)!=32 or len(component_key)<32:raise AuthorityUnavailable('actual protected counter signing keys have wrong lengths')
    return InstalledD13CoreCounterServiceV1(source=source,bridge=bridge,worker=worker,execute_credential=execute_credential,
        signing_key=signing_key,component_signing_key=component_key,cpu_quote_authority=cpu_quote_authority,
        body_quote_authority=body_quote_authority,cpu_policy_id=assets.cpu_policy_id,cpu_policy_version=assets.cpu_policy_version,
        body_policy_id=assets.body_policy_id,body_policy_version=assets.body_policy_version,
        billing_contract_digest=foreground_observer.installed_bundle.provider_billing_policy_v1.contract_digest,create=create)


def validate_d13_counter_initial_spec_v1(spec):
    """Explicit fresh Root input; program paths never come from a Host RPC."""
    paths=('signing_key_path','metric_source_path','delegated_cgroup_path','program_path','interpreter_path','applicability_path')
    hashes=('metric_source_sha256','program_sha256','interpreter_sha256','applicability_sha256')
    required={'schema','metric_id',*paths,*hashes,'memory_max_bytes','pids_max',
        'cpu_policy_id','cpu_policy_version','body_policy_id','body_policy_version'}
    if type(spec)is not dict or set(spec)!=required or spec['schema']!='sylanne3.d13.initial-counter.v2':
        raise AuthorityUnavailable('explicit administrator-reviewed self-contained counter V2 specification required')
    for name in paths:
        path=spec[name]
        if type(path)is not str or not Path(path).is_absolute()or '..'in Path(path).parts:
            raise AuthorityUnavailable('absolute protected counter installation locator required')
    for name in hashes:
        value=spec[name]
        if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
            raise AuthorityUnavailable('actual protected counter asset SHA256 required')
    for name in ('memory_max_bytes','pids_max','cpu_policy_version','body_policy_version'):
        if type(spec[name])is not int or spec[name]<1:
            raise AuthorityUnavailable('positive explicit counter cap and policy version required')
    for name in ('metric_id','cpu_policy_id','body_policy_id'):
        if type(spec[name])is not str or not spec[name]or len(spec[name])>4096:
            raise AuthorityUnavailable('explicit installed counter metric/policy identifier required')
    return spec


def stage_initial_d13_counter_assets_v1(*,spec,profile,package_root,namespace_root,writer):
    """Fresh Root creates fixed assets before the initial durable store snapshot."""
    from dataclasses import asdict
    import secrets
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from ..host.authority_profile import _policy_from_payload,_d13_wire_policy_from_payload
    from .linux_installation_security_v1 import require_linux_administrator_v1
    require_linux_administrator_v1()
    validate_d13_counter_initial_spec_v1(spec)
    installation=_policy_from_payload(profile)
    policy=_d13_wire_policy_from_payload(profile,installation)
    if type(policy) is not InstalledD13WirePolicyV7 or profile.get('d13_wire_counter') is not None:
        raise AuthorityUnavailable('initial counter assets require their exact V7 policy and no Host executable')
    root=Path(namespace_root)
    if root.exists():raise FileExistsError('fresh counter namespace assets refuse overwrite')
    program=read_installed_bytes_v1(spec['program_path'])
    if sha256(program).hexdigest()!=spec['program_sha256']:
        raise AuthorityUnavailable('initial protected counter program differs from its explicit pin')
    metric=read_installed_bytes_v1(spec['metric_source_path'])
    if sha256(metric).hexdigest()!=spec['metric_source_sha256']:
        raise AuthorityUnavailable('initial protected provider metric evidence differs from its explicit pin')
    signing_key=read_installed_bytes_v1(spec['signing_key_path'],limit=32,private=True,allowed_gid=0)
    if len(signing_key)!=32 or Ed25519PrivateKey.from_private_bytes(signing_key).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()!=policy.counter_public_key_hex:
        raise AuthorityUnavailable('initial protected signing key differs from V7 public policy')
    interpreter=Path(spec['interpreter_path']).resolve(strict=True)
    interpreter_sha=_hash_protected_file_v1(interpreter)
    if interpreter_sha!=spec['interpreter_sha256']:
        raise AuthorityUnavailable('initial protected Python interpreter differs from its explicit pin')
    program_sha=sha256(program).hexdigest()
    descriptor_raw=read_installed_bytes_v1(spec['applicability_path'],limit=8192)
    if sha256(descriptor_raw).hexdigest()!=spec['applicability_sha256']:
        raise AuthorityUnavailable('initial protected applicability original differs')
    require_d13_counter_applicability_v2(descriptor_raw,policy=policy,metric_id=spec['metric_id'],
        metric_source_sha256=spec['metric_source_sha256'],program_sha256=program_sha,
        interpreter_sha256=interpreter_sha)
    if policy.counter_policy_fingerprint!=program_sha:
        raise AuthorityUnavailable('initial counter program differs from its actual installed policy')
    manifest={'schema':'sylanne3.d13.counter-kernel-manifest.v2','algorithm_id':'d13.full_http_counter.v1',
        'program_sha256':program_sha,'interpreter_sha256':interpreter_sha,
        'input_schema':'sylanne3.d13.counter-kernel-input.v1','output_schema':'sylanne3.d13.counter-kernel-output.v1',
        'serializer_fingerprint':policy.serializer_fingerprint,'applicability_fingerprint':policy.applicability_fingerprint,
        'counter_policy_fingerprint':policy.counter_policy_fingerprint,'tokenizer_fingerprint':policy.tokenizer_fingerprint,
        'wire_policy_fingerprint':policy.wire_policy_fingerprint,'template_digest':policy.template_digest,
        'metric_id':spec['metric_id'],'metric_source_sha256':spec['metric_source_sha256'],
        'provider_id':policy.installation.provider_id,'model_id':policy.installation.model_id,
        'provider_config_digest':policy.installation.provider_config_digest,
        'max_input_bytes':16*1024*1024,'max_stdout_bytes':65536,'max_stderr_bytes':65536,
        'cpu_ms_ceiling':1000,'memory_max_bytes':spec['memory_max_bytes'],'pids_max':spec['pids_max']}
    from ..runtime_contracts import canonical_serialize
    manifest_bytes=canonical_serialize(manifest).encode('utf-8')
    root.mkdir(mode=0o700)
    for name,data in [('counter.py',program),('manifest.json',manifest_bytes),('metric-source.py',metric),
            ('applicability.json',descriptor_raw),('counter-signing.key',signing_key),('component-signing.key',secrets.token_bytes(32))]:
        writer(root/name,data,mode=0o600)
    assets=InstalledD13CounterAssetsV2(namespace=installation.namespace,installation_id=installation.installation_id,
        namespace_root=str(root),package_root=str(package_root),package_manifest_sha256=installation.manifest_digest,
        program_path=str(root/'counter.py'),program_sha256=program_sha,program_manifest_path=str(root/'manifest.json'),
        program_manifest_sha256=sha256(manifest_bytes).hexdigest(),interpreter_path=str(interpreter),interpreter_sha256=interpreter_sha,
        metric_source_path=str(root/'metric-source.py'),metric_source_sha256=spec['metric_source_sha256'],
        delegated_cgroup_path=spec['delegated_cgroup_path'],memory_max_bytes=spec['memory_max_bytes'],pids_max=spec['pids_max'],
        signing_key_path=str(root/'counter-signing.key'),component_signing_key_path=str(root/'component-signing.key'),
        cpu_policy_id=spec['cpu_policy_id'],cpu_policy_version=spec['cpu_policy_version'],
        body_policy_id=spec['body_policy_id'],body_policy_version=spec['body_policy_version'],
        metric_id=spec['metric_id'],applicability_path=str(root/'applicability.json'),
        applicability_sha256=spec['applicability_sha256'])
    return {'authority_namespace':installation.authority_namespace,**asdict(assets)}
