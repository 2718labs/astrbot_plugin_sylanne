"""Content-free Authority facts for independent first-encoding cost accounting.

The installed port must perform the designated-observer mTLS terminal query.
These value checks bind its answer to the original call; constructing a value
here never authenticates an arbitrary caller or grants a graph write.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable

from ..authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_contract import FencePermitV2
from ..runtime_contracts import canonical_digest
from .issuers import ResourceOutcome, ResourceQuote


class ModelCostUnavailable(RuntimeError):
    """The original Authority terminal or its cost dimensions are unavailable."""


@dataclass(frozen=True, slots=True)
class OriginalModelCostFactV1:
    intent: ModelEgressIntentV1
    recovery: ModelEgressRecoveryV1
    admission: ModelAdmissionV2
    receipt: ModelTerminalReceiptV2

    def __post_init__(self) -> None:
        intent, record, admission, receipt = (
            self.intent, self.recovery, self.admission, self.receipt)
        if (type(intent) is not ModelEgressIntentV1
                or type(record) is not ModelEgressRecoveryV1
                or type(admission) is not ModelAdmissionV2
                or type(receipt) is not ModelTerminalReceiptV2
                or record.intent != intent
                or record.state not in {"observed", "unknown"}
                or (admission.authority_id, admission.namespace,
                    admission.subject, admission.operation_id,
                    admission.call_id, admission.request_digest,
                    admission.provider_config_digest) != (
                    intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id, intent.request_digest,
                    intent.provider_config_digest)
                or (receipt.admission_id, receipt.call_id,
                    receipt.request_digest, receipt.observation_digest,
                    receipt.installation_id, receipt.host_incarnation) != (
                    admission.admission_id, intent.call_id,
                    intent.request_digest, record.observation_digest,
                    admission.installation_id, admission.host_incarnation)):
            raise ModelCostUnavailable("original model terminal identity differs")


def read_original_model_cost(
    port: Callable[[ModelEgressIntentV1], tuple],
    intent: ModelEgressIntentV1,
) -> OriginalModelCostFactV1:
    """Ask the installed, credential-owning port; never accept a caller fact."""
    if type(intent) is not ModelEgressIntentV1 or not callable(port):
        raise ModelCostUnavailable("trusted original model terminal port is absent")
    record, permit, admission, receipt = port(intent)
    if (type(permit) is not FencePermitV2
            or (permit.authority_id, permit.namespace, permit.subject,
                permit.operation_id, permit.operation,
                permit.token, permit.fence_epoch, permit.revision,
                permit.generation, canonical_digest(asdict(permit.pinned_anchor)))
            != (intent.authority_id, intent.namespace, intent.subject,
                intent.operation_id, "model_egress",
                intent.fence_token, intent.fence_epoch,
                intent.fence_revision, intent.authority_activation_generation,
                intent.anchor_digest)):
        raise ModelCostUnavailable("original model fence proof differs")
    return OriginalModelCostFactV1(intent, record, admission, receipt)


def original_model_budget_actual(
    fact: OriginalModelCostFactV1, quote: ResourceQuote,
) -> dict[str, int] | None:
    """Map only declared D11 units. Missing prices keep the whole upper bound.

    Provider token and currency counters are never D02 body energy. Cached
    input tokens are already included in input_tokens and are not added twice.
    """
    if type(fact) is not OriginalModelCostFactV1 or type(quote) is not ResourceQuote:
        raise TypeError("typed original cost and signed resource quote required")
    intent = fact.intent
    # The business namespace is checked by the coordinator against the signed
    # quote. Authority's namespace has a separate installation identity.
    if (quote.operation_id != intent.budget_reservation_operation_id
            or quote.parent_budget_lease_ref != intent.budget_lease_id
            or quote.work_kind != "d06.encode_source"):
        raise ModelCostUnavailable("original cost differs from D02 quote")
    if dict(intent.budget_ceiling) != dict(quote.ceiling):
        raise ModelCostUnavailable("Authority ceiling differs from original quote")
    if fact.recovery.state != "observed":
        return None
    usage, money = dict(fact.recovery.usage), dict(fact.recovery.cost)
    actual: dict[str, int] = {}
    for dimension in quote.ceiling:
        if dimension in {"input_tokens", "output_tokens"}:
            if dimension not in usage:
                return None
            actual[dimension] = usage[dimension]
        elif dimension == "model_tokens":
            if not {"input_tokens", "output_tokens"} <= usage.keys():
                return None
            actual[dimension] = usage["input_tokens"] + usage["output_tokens"]
        elif dimension == "model_microusd":
            if dimension not in money:
                return None
            actual[dimension] = money[dimension]
        else:
            return None
    if any(name not in {"input_tokens", "output_tokens", "cached_input_tokens"}
           for name in usage) or any(name not in quote.ceiling for name in money):
        return None
    return actual


def outcome_from_original_model_cost(
    fact: OriginalModelCostFactV1, quote: ResourceQuote,
) -> ResourceOutcome:
    """Candidate D02 outcome; D02 issuer must still verify its trusted origin."""
    actual = original_model_budget_actual(fact, quote)
    return ResourceOutcome(
        outcome_id="model-cost:" + fact.intent.call_id,
        version=1, quote_id=quote.quote_id,
        bot_id=quote.bot_id, persona_id=quote.persona_id,
        activity_id=quote.activity_id, operation_id=quote.operation_id,
        actual=actual, execution_revoked=True,
        provider_receipt_ref=fact.intent.call_id,
    )


__all__ = (
    "ModelCostUnavailable", "OriginalModelCostFactV1",
    "original_model_budget_actual", "outcome_from_original_model_cost",
    "read_original_model_cost",
)
