"""Named growth cognition values; only actual producers can authenticate these selectors."""
from dataclasses import dataclass
import math

from .d07_execution_v1 import D07SemanticQuestionV1, D07PreparedExecutionV1
from ..graph_types import GraphVersion
from ..runtime_contracts import NamespaceId, VersionedRef
from ..domains.d01.method_learning_v1 import TRIAL_PROPOSAL_TYPE_V2


QUESTION_SCHEMA = "d07.method-growth-semantic-question.v2"
PREPARED_SCHEMA = "d07.method-growth-prepared.v2"


def _head(value, kind, namespace):
    if (type(value) is not GraphVersion or value.revision < 1 or value.key.type_name != kind
            or NamespaceId.from_key(value.key) != namespace):
        raise ValueError("growth cognition requires its exact actual positive head")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("growth cognition requires original SHA256 commitments")


def _deadline(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("growth cognition retains its actual finite original deadline")


@dataclass(frozen=True, slots=True, kw_only=True)
class D07MethodGrowthSemanticQuestionV2(D07SemanticQuestionV1):
    cycle_ref: GraphVersion
    cycle_digest: str
    proposal_head: GraphVersion
    proposal_digest: str
    c02_operation_id: str
    source_head: GraphVersion
    source_digest: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    schema: str = QUESTION_SCHEMA

    def __post_init__(self):
        from .d01_method_learning_v1 import trial_question_v2
        D07SemanticQuestionV1(self.question_key, self.question, self.target_ref, self.source_refs)
        if type(self.proposal_head) is not GraphVersion:
            raise TypeError("growth question requires the actual registered proposal head")
        namespace = NamespaceId.from_key(self.proposal_head.key)
        _head(self.proposal_head, TRIAL_PROPOSAL_TYPE_V2, namespace)
        _head(self.cycle_ref, "runtime.job", namespace)
        _head(self.source_head, "memory.source", namespace)
        for digest in (self.proposal_digest, self.cycle_digest, self.source_digest):
            _digest(digest)
        _deadline(self.original_deadline_utc)
        if (self.schema != QUESTION_SCHEMA or self.target_ref != VersionedRef(self.proposal_head.key.token, self.proposal_head.revision)
                or self.source_head.key.token not in self.source_refs
                or self.question_key != trial_question_v2(self.proposal_head.key.token, self.proposal_digest)
                or any(type(ref) is not str or not 1 <= len(ref) <= 4096
                    for ref in (self.c02_operation_id, self.parent_budget_lease_ref))):
            raise ValueError("growth question binds one registered proposal and an actual independent Owner cause")


@dataclass(frozen=True, slots=True, kw_only=True)
class D07MethodGrowthPreparedV2(D07PreparedExecutionV1):
    semantic_question_ref: str
    semantic_question_digest: str
    cycle_ref: GraphVersion
    cycle_digest: str
    call_plan_digest: str
    proposal_head: GraphVersion
    proposal_digest: str
    c02_operation_id: str
    source_head: GraphVersion
    source_digest: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    cancel_generation: int
    schema: str = PREPARED_SCHEMA

    def __post_init__(self):
        _head(self.cycle_ref, "runtime.job", self.namespace)
        _head(self.proposal_head, TRIAL_PROPOSAL_TYPE_V2, self.namespace)
        _head(self.source_head, "memory.source", self.namespace)
        for digest in (self.semantic_question_digest, self.cycle_digest, self.call_plan_digest,
                self.proposal_digest, self.source_digest):
            _digest(digest)
        _deadline(self.original_deadline_utc)
        if (self.schema != PREPARED_SCHEMA or self.work_kind != "concern"
                or type(self.cancel_generation) is not int or self.cancel_generation < 0
                or any(type(ref) is not str or not 1 <= len(ref) <= 4096 for ref in (
                    self.semantic_question_ref, self.c02_operation_id, self.parent_budget_lease_ref))):
            raise ValueError("growth C3 prepared values retain the original cause, paying lease and counted CallPlan")


def method_growth_value_from_wire_v2(raw, cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if cls not in {D07MethodGrowthSemanticQuestionV2, D07MethodGrowthPreparedV2}:
        raise TypeError("only named growth question/prepared variants are decoded")
    from .d07_execution_v1 import decode_native_named_d07_value_v2
    return decode_native_named_d07_value_v2(raw, cls)
