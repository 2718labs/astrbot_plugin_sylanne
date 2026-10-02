"""Fresh Host graph/TLS/runtime around the original synthetic installation.

The parent keeps Authority/Core/D11 instances. This context creates only Host
objects from the initial fixture configuration. It performs a fresh actual
Owner login; no stored lease/session dictionaries or inherited DBs are used.
"""
from contextlib import asynccontextmanager
import asyncio
import hmac
from pathlib import Path

from c09_life_host_process_support_v1 import (
    _validate_installation, _require_product_origins, _write_host_import_evidence_v1,
)

_FIELDS = {'schema', 'runtime_issuer_signing_key', 'ingress_clock', 'provider_domains',
    'owner_session_request', 'provider_cache', 'enable_c04_body_work'}
_CACHE_FIELDS = {'root', 'authority_id', 'installation_id', 'namespace', 'provider_id',
    'config_digest', 'executable_sha256', 'public_key_sha256'}


@asynccontextmanager
async def open_life_host_bootstrap_v1(material):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sylanne3.graph_store import ProductionGraphStore
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.host.v2_fence_port import V2FencePort
    from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    from sylanne3.host.v2_installation import V2InstallationAssembly
    from sylanne3.host.reverse_handoff import HostReverseGraphClaimServer
    from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
    from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
    from sylanne3.host.reply_suppression import HostReplySuppressionRegistryV1
    from sylanne3.host.installed_d04_output_policy import load_installed_d04_output_policy_v1
    from sylanne3.host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
    from sylanne3.runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyAuthorityV1
    from sylanne3.runtime.d04_semantic_installation_original_v3 import install_d04_semantic_installation_schema_v3
    from sylanne3.runtime.issuers import build_runtime_issuers
    from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1

    _validate_installation(material)
    _require_product_origins(material.package_root)
    config = material.host_driver_configuration.get('bootstrap')
    if (type(config) is not dict or set(config) != _FIELDS
            or config['schema'] != 'sylanne.c09.life-host-bootstrap.v1'
            or type(config['runtime_issuer_signing_key']) is not bytes
            or len(config['runtime_issuer_signing_key']) < 32
            or type(config['enable_c04_body_work']) is not bool
            or type(config['provider_domains']) is not tuple
            or len(set(config['provider_domains'])) != len(config['provider_domains'])
            or any(type(value) is not str for value in config['provider_domains'])
            or type(config['provider_cache']) is not dict or set(config['provider_cache']) != _CACHE_FIELDS):
        raise ValueError('closed original Host bootstrap material required')
    bundle = material.bundle
    policy = bundle.installation_policy
    if (policy.namespace != material.namespace or policy.authority_namespace != material.authority_namespace
            or bundle.tls_profile.profile_id != material.request.profile_id
            or material.reverse_profile.installation_id != policy.installation_id
            or material.reverse_profile.namespace != material.authority_namespace
            or material.reverse_profile.profile_id != material.request.profile_id):
        raise ValueError('original installed Host identity differs')
    # Load providers and math assets from the actual installed package. No
    # object registry, provider callback, or parent Graph capability crosses.
    assets = load_verified_affect_scheme(Path(material.package_root), policy.manifest_digest)
    registry = assets.registry
    if (registry.type_registry.catalogue_hash != policy.catalogue_hash
            or any(domain not in registry.registrations for domain in config['provider_domains'])):
        raise ValueError('installed provider catalogue differs')
    cache = config['provider_cache']
    if (cache['authority_id'] != material.grant.authority_id
            or cache['installation_id'] != policy.installation_id
            or cache['namespace'] != material.authority_namespace
            or cache['provider_id'] != material.provider_config['id']):
        raise ValueError('original installed provider cache differs')
    provider_cache = ControlledLifeProviderCacheV1.attach_installed(cache['root'], material.provider_config,
        authority_id=cache['authority_id'], installation_id=cache['installation_id'], namespace=cache['namespace'],
        executable_sha256=cache['executable_sha256'], public_key_sha256=cache['public_key_sha256'])
    if provider_cache.config_digest != cache['config_digest']:
        raise ValueError('installed provider configuration commitment differs')
    store = port = transport = listener = None
    try:
        profile = bundle.tls_profile
        port = await asyncio.to_thread(V2FencePort, material.request, {profile.profile_id: profile}, material.grant)
        transport = MtlsAuthorityTransport({profile.profile_id: profile})
        client = AuthorityClient(AuthoritySelection(profile.profile_id), package_root=material.package_root,
            data_dir=material.data_dir, transport=transport)
        assert (await client.status_v2()).state == 'paired'
        grant = await client.installation_grant_v2()
        assert grant is not None
        assert (grant.authority_id, grant.installation_id, grant.manifest_digest, grant.subject) == (
            material.grant.authority_id, material.grant.installation_id, material.grant.manifest_digest, material.grant.subject)
        # These are the Host side of the original fixture key configuration.
        # Parent Authority retains its original issuer instances throughout.
        d02, d11 = build_runtime_issuers(config['runtime_issuer_signing_key'])
        assert d11.resource_issuer is d02
        body = cpu = None
        if config['enable_c04_body_work']:
            body = D02BodyQuoteAuthority(hmac.digest(bundle.d02_signing_key,
                b'sylanne3.d02.body_quote_original.v1\0' + policy.installation_id.encode(), 'sha256'))
            cpu = C04InternalCpuQuotePolicyAuthorityV1(hmac.digest(bundle.d11_signing_key,
                b'sylanne3.c04.internal_cpu_quote_policy.v1\0' + policy.installation_id.encode(), 'sha256'))
        assembly = V2InstallationAssembly(policy, grant, config['runtime_issuer_signing_key'],
            config['runtime_issuer_signing_key'], lambda: port, Path(material.package_root), Path(material.data_dir),
            ingress_clock=config['ingress_clock'], admin_bundle=bundle)
        c04 = InstalledC04AuthorityPortV3(client=client, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop())
        suppression = HostReplySuppressionRegistryV1()

        def principal(actor, namespace):
            binding = port.current_owner_actor_binding(namespace=namespace,
                authority_namespace=material.authority_namespace, actor_id=actor)
            return None if binding is None or binding.namespace != namespace else binding.principal

        store = ProductionGraphStore(material.graph_path, registry.type_registry)
        bootstrap = object()
        graph = GraphCoordinator(store, bootstrap, holder=policy.administrator_holder,
            content_fence_v2=port, d02_issuer=d02, d11_issuer=d11,
            body_quote_authority=body, c04_cpu_quote_authority=cpu,
            owner_principal_resolver=principal, scene_clock_policy=config['ingress_clock'],
            reply_suppression_ack_verifier=suppression.verify_and_consume,
            accounting_maintenance_port=InstalledAccountingMaintenancePort(client=client, bundle=bundle,
                grant=grant, owner_loop=asyncio.get_running_loop()),
            c04_authority_port_v3=c04, d04_installed_joint_assembly=assembly,
            d04_installed_joint_output_policy=load_installed_d04_output_policy_v1(material.package_root,
                policy.manifest_digest, require_formal=False, require_backend_runtime=True),
            d13_paid_precompression_policy=bundle.d13_paid_precompression)
        for domain in config['provider_domains']:
            registration = registry.registrations[domain]
            graph.register_provider(bootstrap, domain, registration.provider,
                registration.proposal_schema, registration.proposal_schema_hash)
        with store._lock:
            install_d04_semantic_installation_schema_v3(store._db)
        mapping = InstalledD04SemanticMappingReaderV3(graph, material.package_root, policy.manifest_digest)
        graph._GraphCoordinator__d04_semantic_mapping_reader = mapping
        graph._GraphCoordinator__model_terminal_cost_port = InstalledModelTerminalCostPort(
            client=client, bundle=bundle, grant=grant, owner_loop=asyncio.get_running_loop())
        assert not graph._GraphCoordinator__owner_leases
        assert not graph._GraphCoordinator__owner_session_proofs
        reverse_server = HostReverseGraphClaimServer(material.reverse_profile)
        listener = await reverse_server.start(material.reverse_bind_host, material.reverse_bind_port)
        assert listener.sockets[0].getsockname()[1] == material.reverse_bind_port
        owner_key = Ed25519PrivateKey.from_private_bytes(material.owner_fixture_private_key)
        request = config['owner_session_request']
        challenge = await asyncio.to_thread(port.begin_owner_session, namespace=material.namespace,
            authority_namespace=material.authority_namespace, request=request)
        token = await asyncio.to_thread(port.accept_owner_session, namespace=material.namespace,
            authority_namespace=material.authority_namespace, challenge=challenge,
            signature=owner_key.sign(challenge.signed_bytes()))
        case = dict(graph=graph, store=store, bootstrap=bootstrap, namespace=material.namespace,
            authority_namespace=material.authority_namespace, port=port, authority_client=client,
            client_grant=grant, grant=grant, installed_bundle=bundle, policy=policy,
            domain_registry=registry, package_root=Path(material.package_root), manifest_digest=policy.manifest_digest,
            d02_issuer=d02, d11_issuer=d11, owner_key=owner_key, owner_session_token=token,
            owner_session_request=request, owner_loop=asyncio.get_running_loop(),
            ingress_clock=config['ingress_clock'], mapping_reader=mapping,
            reverse_server=reverse_server, reverse_listener=listener,
            c09_provider_cache=provider_cache, peer=material.peer, suppression_registry=suppression)
        assert not any(name in case for name in ('core', 'server', 'model_store', 'owner_sessions', 'protected'))
        _write_host_import_evidence_v1(material.package_root, 'host-bootstrap-open')
        yield case
        _require_product_origins(material.package_root)
    finally:
        # Listener and all Host-owned clients/Graph handles close before this
        # context returns and the actor reports completion to the parent.
        try:
            if listener is not None:
                listener.close()
                await listener.wait_closed()
        finally:
            try:
                if transport is not None:
                    await transport.close()
            finally:
                try:
                    if port is not None:
                        await asyncio.to_thread(port.close)
                finally:
                    try:
                        if store is not None:
                            store.close()
                    finally:
                        _write_host_import_evidence_v1(material.package_root, 'host-bootstrap-final')
