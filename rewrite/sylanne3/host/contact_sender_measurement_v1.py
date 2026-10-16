"""Private one-shot measurement at the installed Sender's actual SDK boundary."""
import asyncio
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_effect_accounting_contract_v1 import (
    SignedContactEffectBudgetOriginV1, ContactSenderMeasurementV1,
)
from ..authority_service.v2_contract import canonical_digest as authority_digest
from ..runtime_contracts import canonical_digest
from .contact_effect_accounting_port_v1 import InstalledContactEffectAccountingPortV1

_KEY = object()


class InstalledContactSenderMeasurementV1:
    def __init__(self, key, port, origin):
        if (key is not _KEY or type(port) is not InstalledContactEffectAccountingPortV1
                or type(origin) is not SignedContactEffectBudgetOriginV1
                or origin.origin.pricing_policy is None
                or origin.origin.namespace != port.namespace
                or origin.origin.installation_id != port.bundle.installation_policy.installation_id):
            raise AuthorityUnavailable("configured original Contact Sender measurement required")
        self.port, self.origin, self._started = port, origin, None

    def start_invocation(self, binding, start, claimed, now_utc):
        o = self.origin.origin
        policy = o.pricing_policy
        if (self._started is not None or start.replay
                or not policy.valid_from_utc <= now_utc < policy.valid_until_utc
                or (binding.operation_id, binding.origin.effect_id, binding.origin.admission_ref,
                    binding.admission_receipt_digest) != (o.operation_id, o.effect_id, o.admission_ref,
                    "sha256:" + o.admission_receipt_digest)
                or start.binding_digest != authority_digest(binding)
                or start.claim_digest != authority_digest(claimed)):
            raise AuthorityUnavailable("Contact measurement cannot replay or substitute an SDK call")
        self._started = (binding, start, claimed)

    async def complete_invocation(self, observation):
        if self._started is None:
            raise AuthorityUnavailable("Contact SDK invocation was not measured")
        binding, start, claimed = self._started
        if observation.binding != binding or observation.handoff_id != start.handoff_id:
            raise AuthorityUnavailable("Contact measurement observation changed its real SDK call")
        o, policy = self.origin.origin, self.origin.origin.pricing_policy
        measurement = ContactSenderMeasurementV1(o.namespace, o.installation_id, o.operation_id,
            o.activity_id, o.effect_id, o.attempt_id, start.handoff_id, o.admission_ref,
            authority_digest(binding).removeprefix("sha256:"),
            authority_digest(claimed).removeprefix("sha256:"),
            observation.start_digest.removeprefix("sha256:"), policy.adapter_ref, policy.digest,
            "contact-measurement:" + canonical_digest((o.namespace, o.effect_id, start.handoff_id)),
            1, observation.observation_id, observation.outcome, observation.observed_at_utc)
        # Accounting may finish after the send deadline, but cannot start any execution.
        task = asyncio.create_task(asyncio.to_thread(self.port.record_measurement,
            self.origin, measurement, observation, claimed))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try: await asyncio.shield(task)
                except asyncio.CancelledError: continue
                except Exception: break
            if task.done() and not task.cancelled():
                task.exception()
            raise


def issue_contact_sender_measurement_v1(port, signed_origin):
    return InstalledContactSenderMeasurementV1(_KEY, port, signed_origin)
