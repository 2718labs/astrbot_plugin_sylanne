"""One Authority-admitted local model attempt and designated host observation.

This is an independent host slice. No Broker or plugin route calls it yet.
Only the paired Authority v2 response may supply the local start identity.
"""

from __future__ import annotations

import asyncio

from ..authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2, ModelEgressIntentV1, ModelTerminalReceiptV2,
)
from ..model_broker.broker import ModelCallRequest, ProviderResponse
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import InstallationGrantV2, canonical_serialize
from .astrbot_model_call import AstrBotModelProvider, LocalModelAdmission
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class HostModelEgressExecutor:
    """A short-lived executor for one installed adapter and paired Authority client."""

    def __init__(self, *, authority: AuthorityClient, bundle: AdminInstallationBundle,
                 grant: InstallationGrantV2, adapter: AstrBotModelProvider) -> None:
        if (type(authority) is not AuthorityClient
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or type(adapter) is not AstrBotModelProvider
                or adapter._installation_bundle is not bundle
                or adapter._admin_model is not bundle.ingress_model):
            raise ValueError("trusted installed model executor binding is required")
        self._authority = authority
        self._bundle = bundle
        self._grant = grant
        self._adapter = adapter

    async def execute_once(
        self, *, intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        request: ModelCallRequest,
    ) -> ModelTerminalReceiptV2 | None:
        """Return a durable content-free receipt, or HOLD without another send.

        An uncertain admit reply, non-completed local result, cancelled waiter,
        changed installation or uncertain completion reply has no retry path.
        """
        if (type(intent) is not ModelEgressIntentV1
                or type(expected_anchor) is not RestoreAnchor
                or type(request) is not ModelCallRequest):
            return None
        try:
            record, permit, admission = await self._authority.model_admit_dispatch_once_v2(
                self._bundle, self._grant, intent=intent,
                expected_anchor=expected_anchor, model_request=request,
                host_incarnation=self._adapter.host_incarnation)
        except Exception:
            return None
        if (record.state != "dispatch_started" or record.intent != intent
                or permit.operation != "model_egress"
                or permit.pinned_anchor != expected_anchor
                or admission.host_incarnation != self._adapter.host_incarnation
                or admission.request_digest != request.digest
                or admission.provider_config_digest !=
                   self._adapter._admin_model.provider_config_digest):
            return None
        # LocalModelAdmission is not itself an Authority credential. Its values
        # are minted here only after the paired v2 client verified the reply.
        try:
            local = LocalModelAdmission(
                admission.admission_id, admission.host_incarnation,
                admission.call_id, admission.request_digest,
                admission.provider_config_digest)
            response = await self._adapter.invoke_admitted(
                request, local, asyncio.Event())
        except Exception:
            return None
        if (type(response) is not ProviderResponse
                or response.status != "completed" or response.result is None):
            return None
        try:
            report = HostObservedModelCompletionV2(
                admission.admission_id, admission.host_incarnation,
                intent.call_id, intent.request_digest, intent.provider_id,
                intent.model_id, intent.provider_config_digest,
                canonical_serialize(dict(response.result)),
                tuple(sorted(response.usage.items())),
                tuple(sorted(response.cost.items())), response.provider_call_ref)
            completed, terminal_permit, receipt = (
                await self._authority.model_complete_observed_v2(
                    self._bundle, self._grant, intent=intent,
                    expected_anchor=expected_anchor, admission=admission,
                    report=report))
        except Exception:
            return None
        if (completed.state != "observed" or completed.intent != intent
                or terminal_permit != permit
                or receipt.report_digest != report.digest):
            return None
        return receipt


__all__ = ("HostModelEgressExecutor",)
