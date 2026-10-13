"""Paired C04 V3 RPCs for the graph worker, outside graph locks."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..host.authority_client import AuthorityClient
from ..host.authority_profile import AdminInstallationBundle
from ..host.mtls_transport import MtlsAuthorityTransport
from ..runtime_contracts import InstallationGrantV2


class InstalledC04AuthorityPortV3:
    """Use the installed mTLS client and its owning event loop for originals."""

    def __init__(self, *, client: AuthorityClient, bundle: AdminInstallationBundle,
                 grant: InstallationGrantV2, owner_loop: asyncio.AbstractEventLoop):
        if (type(client) is not AuthorityClient
                or type(client._transport) is not MtlsAuthorityTransport
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or not isinstance(owner_loop, asyncio.AbstractEventLoop)
                or not owner_loop.is_running()
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest) !=
                   (bundle.installation_policy.expected_authority_id,
                    bundle.installation_policy.installation_id,
                    bundle.installation_policy.administrator_holder,
                    bundle.installation_policy.manifest_digest)):
            raise ValueError("paired C04 V3 installation is required")
        self._client, self._bundle, self._grant = client, bundle, grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def _run(self, coroutine, *, timeout_seconds=None):
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop or not self._loop.is_running():
            coroutine.close()
            raise RuntimeError("C04 synchronous RPC requires the active graph worker")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(self._timeout if timeout_seconds is None else timeout_seconds)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("original C04 Authority operation unresolved; inspect only") from exc

    def _binding_methods(self, binding):
        from ..authority_service.internal_work_contract import InternalWorkBindingV1
        if type(binding) is not InternalWorkBindingV1:
            raise TypeError("actual C04 installed binding required")
        if binding.algorithm_ref == "d06.association_activation.v3":
            return self._client.c04_execute_v3, self._client.c04_inspect_v3
        if binding.algorithm_ref == "d06.association_activation.direct_seed.v4":
            return self._client.c04_execute_v4, self._client.c04_inspect_v4
        raise ValueError("C04 binding has no installed execution route")

    def execute(self, binding):
        execute, _ = self._binding_methods(binding)
        return self._run(execute(self._bundle, self._grant, binding=binding))

    def inspect(self, binding):
        _, inspect = self._binding_methods(binding)
        return self._run(inspect(self._bundle, self._grant, binding=binding))

    def verify_terminal(self, proof):
        return self._run(self._client.c04_terminal_verify_v1(
            self._bundle, self._grant, proof=proof))

    def internal_accounting(self, request, action, grant=None):
        return self._run(self._client.internal_accounting_v1(
            self._bundle, self._grant, accounting_request=request,
            action=action, accounting_grant=grant))

    def root_inspect(self,binding):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_inspect_v3"))

    def root_claim(self,binding,executor_incarnation):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_claim_v3",executor_incarnation=executor_incarnation))

    def root_terminal(self,binding,claim,measurement):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_terminal_v3",claim=claim,measurement=measurement))

    def root_original_append(self,binding,claim):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_original_append_v3",claim=claim))

    def root_adoption_bridge(self,binding):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_adoption_bridge_v3"))

    def root_validate_gate(self,binding,gate):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_validate_gate_v3",gate=gate))

    def root_finish_gate(self,binding,gate,*,outcome):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_finish_adoption_v3",gate=gate,outcome=outcome))

    def root_gate_status(self,binding,gate):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_gate_status_v3",gate=gate))

    def root_restore_original(self,binding):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_restore_original_v3"),timeout_seconds=max(self._timeout,180.0))

    def root_cost_only(self,binding,claim,measurement):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_cost_only_v3",claim=claim,measurement=measurement))

    def root_cost_inspect(self,binding):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_cost_inspect_v3"))

    def root_accounting(self,binding,action,gate=None):
        return self._run(self._client.d04_root_v3(self._bundle,self._grant,binding=binding,method="d04_root_accounting_v3",action=action,gate=gate))

    def numeric_original_append(self,binding,claim):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_original_append_v3",claim=claim))

    def numeric_adoption_bridge(self,binding):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_adoption_bridge_v3"))

    def numeric_validate_gate(self,binding,gate):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_validate_gate_v3",gate=gate))

    def numeric_finish_gate(self,binding,gate,*,outcome):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_finish_adoption_v3",gate=gate,outcome=outcome))

    def numeric_restore_original(self,binding):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_restore_original_v3"),timeout_seconds=max(self._timeout,180.0))

    def numeric_cost_only(self,binding,claim,measurement):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_cost_only_v3",claim=claim,measurement=measurement))

    def numeric_cost_inspect(self,binding):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_cost_inspect_v3"))

    def numeric_gate_status(self,binding,gate):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_gate_status_v3",gate=gate))

    def numeric_accounting(self,binding,action,gate=None):
        return self._run(self._client.d04_numeric_bridge_v3(self._bundle,self._grant,binding=binding,
            method="d04_numeric_accounting_v3",action=action,gate=gate))

    def numeric_inspect(self, binding):
        return self._run(self._client.read_d04_numeric_originals_v3(
            self._bundle, self._grant, binding=binding))

    def series(self, binding, method, **values):
        return self._run(self._client.d04_series_v1(self._bundle, self._grant,
            binding=binding, method="d04_series_" + method + "_v1", **values),
            timeout_seconds=max(self._timeout, 180.0) if method in {"restore", "prefix_manifest"} else None)

    def contact_policy(self, permit, method, **values):
        return self._run(self._client.d10_contact_policy_v1(self._bundle, self._grant,
            permit=permit, method="d10_contact_policy_" + method + "_v1", **values))

    def numeric_claim(self, binding, executor_incarnation):
        return self._run(self._client.claim_d04_numeric_v3(
            self._bundle, self._grant, binding=binding, executor_incarnation=executor_incarnation))

    def numeric_terminal(self, binding, claim, measurement):
        return self._run(self._client.record_d04_numeric_terminal_v3(
            self._bundle, self._grant, binding=binding, claim=claim, measurement=measurement))


__all__ = ["InstalledC04AuthorityPortV3"]
