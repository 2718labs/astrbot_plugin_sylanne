"""Installed Authority reads and observation writes for one V2 send window.

The paired V2FencePort owns the authenticated transport. This adapter never
constructs a permit, a clock reading, or a graph claim from caller facts.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from ..authority_service.v2_contract import (
    ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PlatformObservationV2, canonical_digest as authority_digest,
)
from ..authority_service.v2_execution_bridge import (
    CurrentEffectReadV2, HandoffStartV2, handoff_start_digest_v2,
)
from ..runtime_contracts import namespace_ref
from ..installation_policy import AdminInstallationPolicy
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import InstallationGrantV2, NamespaceId
from .astrbot_dispatch import CurrentDispatchHandoffReadV1
from .authority_profile import AdminIngressClockPolicy
from .v2_fence_port import V2FencePort, VerifiedIngressClockV2


class InstalledCurrentDispatchHandoffPort:
    """Bind the exact Authority P2 read and observation RPC to one installation."""

    def __init__(self, *, fence_port: V2FencePort,
                 policy: AdminInstallationPolicy,
                 grant: InstallationGrantV2,
                 claimed_receipt: MutationReceiptV2) -> None:
        if (type(fence_port) is not V2FencePort
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or type(claimed_receipt) is not MutationReceiptV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV2
                or claimed_receipt.durable_state != "committed"
                or claimed_receipt.pending.phase != "claimed"
                or not callable(getattr(fence_port, "execution_read_current_dispatch_handoff", None))
                or not callable(getattr(fence_port, "execution_observe_v2", None))
                or not callable(getattr(fence_port, "read_ingress_clock", None))):
            raise ValueError("installed V2 dispatch Authority ports are unavailable")
        current_grant = fence_port.installation_grant
        if (current_grant != grant
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest) != (
                    policy.expected_authority_id, policy.installation_id,
                    policy.administrator_holder, policy.manifest_digest)
                or claimed_receipt.pending.binding.graph_namespace
                   != "/".join(policy.namespace.as_tuple)
                or claimed_receipt.pending.permit.namespace
                   != namespace_ref(policy.namespace)
                or claimed_receipt.pending.permit.authority_id != grant.authority_id):
            raise ValueError("installed dispatch Authority identity differs")
        self._port = fence_port
        self._policy = policy
        self._grant = grant
        self._claimed = claimed_receipt

    def read_current_dispatch_handoff(
        self, start: HandoffStartV2, claimed_receipt: MutationReceiptV2,
    ) -> CurrentDispatchHandoffReadV1:
        if (type(start) is not HandoffStartV2 or start.replay
                or claimed_receipt != self._claimed
                or start.namespace != namespace_ref(self._policy.namespace)
                or start.claim_digest != authority_digest(self._claimed)
                or start.binding_digest != authority_digest(
                    self._claimed.pending.binding)
                or start.operation_id != self._claimed.pending.permit.operation_id
                or start.effect_id != self._claimed.pending.permit.effect_id):
            raise RuntimeError("current dispatch handoff identity differs")
        result = self._port.execution_read_current_dispatch_handoff(
            namespace=self._policy.namespace,
            authority_namespace=start.namespace,
            start=start, claimed_receipt=claimed_receipt)
        if (type(result) is not tuple or len(result) != 3
                or type(result[0]) is not FencePermitV2
                or type(result[1]) is not RestoreAnchor
                or type(result[2]) is not CurrentEffectReadV2):
            raise RuntimeError("current dispatch Authority read is unavailable")
        permit, anchor, effect = result
        if (permit != start.permit or anchor != permit.pinned_anchor
                or permit.authority_id != self._grant.authority_id
                or effect.authority_id != self._grant.authority_id
                or effect.namespace != start.namespace
                or effect.effect_id != start.effect_id):
            raise RuntimeError("current dispatch Authority read differs")
        return CurrentDispatchHandoffReadV1(permit, anchor, effect)

    def read_ingress_clock(
        self, policy: AdminIngressClockPolicy,
    ) -> VerifiedIngressClockV2:
        if type(policy) is not AdminIngressClockPolicy:
            raise TypeError("installed dispatch clock policy required")
        reading = self._port.read_ingress_clock(policy)
        if (type(reading) is not VerifiedIngressClockV2
                or reading.sample.authority_id != self._grant.authority_id
                or reading.sample.installation_id != self._grant.installation_id
                or reading.sample.source_id != policy.source_id):
            raise RuntimeError("current dispatch clock installation differs")
        return reading

    async def record_observation(
        self, start: HandoffStartV2, observation: PlatformObservationV2,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        """Persist a report; an accepted ACK still does not prove delivery."""
        if (type(start) is not HandoffStartV2
                or type(observation) is not PlatformObservationV2
                or start.replay or observation.binding != self._claimed.pending.binding
                or start.namespace != namespace_ref(self._policy.namespace)
                or start.claim_digest != authority_digest(self._claimed)
                or start.binding_digest != authority_digest(
                    self._claimed.pending.binding)
                or observation.handoff_id != start.handoff_id
                or observation.start_digest != handoff_start_digest_v2(start)):
            raise RuntimeError("V2 observation differs from the fresh handoff")
        result = await asyncio.to_thread(
            self._port.execution_observe_v2,
            namespace=self._policy.namespace,
            authority_namespace=start.namespace,
            claimed_receipt=self._claimed,
            observation=observation)
        if (type(result) is not tuple or len(result) != 2
                or type(result[0]) is not MutationReceiptV2
                or type(result[1]) is not FencePermitV2
                or result[0].durable_state != "committed"
                or result[0].pending.phase != "observed"
                or result[0].pending.claimed_receipt != self._claimed
                or result[0].pending.platform_observation != observation
                or result[0].pending.permit.operation_id != start.operation_id
                or result[1] != replace(
                    result[0].pending.permit,
                    revision=result[0].updated_revision,
                    pinned_anchor=result[0].after_anchor)):
            raise RuntimeError("V2 observation Authority receipt differs")
        return result


__all__ = ("InstalledCurrentDispatchHandoffPort",)
