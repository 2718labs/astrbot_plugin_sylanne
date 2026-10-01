"""Versioned natural originals; V4 binds the actual complete history wire."""
from __future__ import annotations
from dataclasses import dataclass
from ..runtime_contracts import NamespaceId, NATURAL_REPLY_REVIEW_WORKFLOW_V1, _digest, _nonempty
from ..model_broker.natural_reply_history_v4 import TEMPLATE_VERSION

@dataclass(frozen=True, slots=True)
class NaturalReplyGenerationOriginalSealV4:
    """Pre-call generation identity; model_request_digest is frozen wire SHA-256.

    The acquired typed ModelCallRequest has its own digest and must be bound
    by the graph coordinator before an Authority-paid terminal can be read.
    """

    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    installation_id: str
    provider_config_digest: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    frozen_input_digest: str
    qualified_units_digest: str
    model_request_digest: str
    original_graph_guard_digest: str
    parent_budget_lease_id: str
    reservation_operation_id: str
    template_version: str = TEMPLATE_VERSION
    schema: str = "sylanne.d09.natural_generation_seal.v4"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or (
                self.schema != "sylanne.d09.natural_generation_seal.v4"
                or self.template_version != TEMPLATE_VERSION):
            raise ValueError("unknown natural generation original identity")
        for name in (
            "c02_operation_id", "source_ref", "installation_id", "job_id",
            "original_operation_id", "acquire_operation_id", "call_id",
            "parent_budget_lease_id", "reservation_operation_id",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "provider_config_digest", "frozen_input_digest",
            "qualified_units_digest", "model_request_digest",
            "original_graph_guard_digest",
        ):
            _digest(getattr(self, name), name)
        if len({self.job_id, self.original_operation_id,
                self.acquire_operation_id, self.call_id}) != 4:
            raise ValueError("natural generation identities must be distinct")

@dataclass(frozen=True, slots=True)
class NaturalReplyReviewOriginalSealV4:
    """Separate review identity bound to one observed generation output.

    model_request_digest is the frozen provider wire digest; the acquired
    typed ModelCallRequest digest is a distinct paid-call binding.
    """

    namespace: NamespaceId
    installation_id: str
    provider_config_digest: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    generation_original_operation_id: str
    generation_call_id: str
    generation_frozen_input_digest: str
    generation_output_digest: str
    qualified_units_digest: str
    review_frozen_input_digest: str
    model_request_digest: str
    original_graph_guard_digest: str
    parent_budget_lease_id: str
    reservation_operation_id: str
    review_policy_version: str
    template_version: str = NATURAL_REPLY_REVIEW_WORKFLOW_V1
    schema: str = "sylanne.d09.natural_review_seal.v4"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or (
                self.schema != "sylanne.d09.natural_review_seal.v4"
                or self.template_version != NATURAL_REPLY_REVIEW_WORKFLOW_V1):
            raise ValueError("unknown natural review original identity")
        for name in (
            "installation_id", "job_id", "original_operation_id",
            "acquire_operation_id", "call_id",
            "generation_original_operation_id", "generation_call_id",
            "parent_budget_lease_id", "reservation_operation_id",
            "review_policy_version",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "provider_config_digest", "generation_frozen_input_digest",
            "generation_output_digest", "qualified_units_digest",
            "review_frozen_input_digest", "model_request_digest",
            "original_graph_guard_digest",
        ):
            _digest(getattr(self, name), name)
        if (len({self.job_id, self.original_operation_id,
                 self.acquire_operation_id, self.call_id}) != 4
                or self.original_operation_id == self.generation_original_operation_id
                or self.call_id == self.generation_call_id):
            raise ValueError("natural review and generation identities must differ")
