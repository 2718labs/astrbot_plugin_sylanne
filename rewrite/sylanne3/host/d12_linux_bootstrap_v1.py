"""Qualify one supervised resumed Host before any ordinary Graph admission."""
from __future__ import annotations

import asyncio
import os
import time

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d12_installation_lifecycle_rpc_v1 import BOOTSTRAP_METHOD
from ..authority_service.v2_contract import SCHEMA
from ..domain_registry import DomainRegistry
from ..native_runtime.loader import load_production_native
from .v2_installation import V2InstallationAssembly


def complete_linux_lifecycle_bootstrap_v1(installation, domains, *, timeout_seconds=60):
    """Blocking helper, called on a bootstrap thread with no Graph worker/fence.

    Returns a live native handle and the exact independent readiness original.
    The host retains the handle; no initial-value solve or model call occurs.
    """
    if type(installation) is not V2InstallationAssembly:
        raise TypeError("actual installation and registered domains required")
    admission = installation.storage_admission
    bootstrap = getattr(admission, "lifecycle_bootstrap", None)
    package_bootstrap = getattr(admission, 'package_bootstrap', None)
    if bootstrap is None and package_bootstrap is None:
        return None
    if bootstrap is not None and package_bootstrap is not None:
        raise AuthorityUnavailable('ambiguous Host lifecycle/package bootstrap')
    admission.require_current_process_v1()
    policy = installation.installation_policy
    if (type(domains) is not DomainRegistry or not domains.complete or tuple(sorted(domains.registrations)) != tuple(f"d{i:02}" for i in range(1, 14))
            or domains.type_registry.catalogue_hash != policy.catalogue_hash
            or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300):
        raise AuthorityUnavailable("resume bootstrap requires the real complete installed catalogue")
    native = load_production_native(installation.package_root, trusted_manifest_sha256=policy.manifest_digest)
    if package_bootstrap is not None:
        bootstrap = package_bootstrap
        method = 'd12_package_maintenance_v2'
        command = {'namespace':policy.authority_namespace,'action':'register_host_ready',
            'operation_id':bootstrap['operation_id'],'process_id':os.getpid(),'invocation_id':bootstrap['invocation_id'],
            'selection_revision':bootstrap['selection_revision'],'cohort_digest':bootstrap['cohort_digest'],
            'catalogue_hash':domains.type_registry.catalogue_hash,'ready_domains':list(sorted(domains.registrations))}
        expected_epoch = bootstrap['lifecycle_epoch']
    else:
        method = BOOTSTRAP_METHOD
        command = {'namespace':policy.authority_namespace,'operation_id':bootstrap['operation_id'],
            'expected_epoch':bootstrap['expected_epoch'],'process_id':os.getpid(),
            'invocation_id':bootstrap['invocation_id'],'catalogue_hash':domains.type_registry.catalogue_hash,
            'ready_domains':list(sorted(domains.registrations))}
        expected_epoch = bootstrap['expected_epoch']
    port = installation.fence_port_factory()
    try:
        async def wait_ready():
            deadline = time.monotonic() + timeout_seconds
            original = None
            while time.monotonic() < deadline:
                async def call():
                    handshake, _ = port._identity()
                    return await port._transport._content_rpc(port._request, handshake, method, command, protocol=SCHEMA)
                reply = await port._with_session_repair(call)
                if package_bootstrap is not None:
                    from ..authority_service.d12_package_bootstrap_v2 import decode_package_bootstrap_original_v2
                    if set(reply)!={'bootstrap_original','lifecycle_state','lifecycle_epoch','channel_binding_sha256'}:
                        raise AuthorityUnavailable('independent package readiness response fields differ')
                    actual=decode_package_bootstrap_original_v2(reply['bootstrap_original'])
                    if (actual['service_role']!='host' or actual['operation_id']!=bootstrap['operation_id']
                            or actual['maintenance_phase']!=bootstrap['maintenance_phase']
                            or actual['process_original']!=admission.process_original or actual['invocation_id']!=bootstrap['invocation_id']
                            or actual['selection_digest']!=bootstrap['selection_digest'] or actual['package_epoch']!=bootstrap['package_epoch']
                            or actual['cohort_digest']!=bootstrap['cohort_digest'] or actual['manifest_sha256']!=policy.manifest_digest
                            or actual['catalogue_hash']!=domains.type_registry.catalogue_hash
                            or actual['lifecycle_epoch']!=expected_epoch):
                        raise AuthorityUnavailable('actual Host package bootstrap original differs')
                    reference=actual['original_ref']
                else:
                    if (set(reply)!={'bootstrap_original_ref','lifecycle_state','lifecycle_epoch','channel_binding_sha256'}
                            or type(reply['bootstrap_original_ref']) is not str or not reply['bootstrap_original_ref'].startswith('d12bootstrap:')):
                        raise AuthorityUnavailable('independent bootstrap readiness response differs')
                    reference=reply['bootstrap_original_ref']
                if reply['lifecycle_epoch']!=expected_epoch or reply['lifecycle_state'] not in {'resuming','active'}:
                    raise AuthorityUnavailable('independent bootstrap readiness epoch/state differs')
                if original is not None and reference != original:
                    raise AuthorityUnavailable("resume bootstrap original changed during readiness")
                original = reference
                if reply["lifecycle_state"] == "active":
                    return original
                await asyncio.sleep(0.25)
            raise AuthorityUnavailable("original resume remains unfinished; no new Host start is permitted")
        ref = port._submit(wait_ready())
        return native, ref
    finally:
        port.close()
