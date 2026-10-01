"""C09 typed lineage. V4 historical facts retain their original bytes/digests."""
from __future__ import annotations

from dataclasses import dataclass, fields
from .c09_storage_rebase_contract_v1 import _id, _digest, _number, _ordered, _committed
from ..runtime_contracts import canonical_digest

C09_EXECUTION_KINDS_V1 = frozenset({"dispatch", "internal", "numeric", "series", "authored_root", "model", "offline_tick", "life"})
C09_EXECUTION_KIND_CAPABILITY_DIGEST_V1 = canonical_digest((
    "sylanne3.c09.fixed-execution-kinds.v1", tuple(sorted(C09_EXECUTION_KINDS_V1))))


@dataclass(frozen=True, slots=True)
class C09ExecutionBindingV1:
    execution_id: str
    business_operation_id: str
    execution_kind: str
    input_commitment: str
    first_consuming_operation_id: str
    originating_journal_id: str
    source_row_commitments: tuple[str, ...]
    d02_quote_ids: tuple[str, ...]
    d02_component_ids: tuple[str, ...]
    d11_settlement_ids: tuple[str, ...]
    dispatch_generation: int
    prior_fact_frame_digest_or_none: str | None

    def __post_init__(self):
        for name in ("execution_id", "business_operation_id", "first_consuming_operation_id", "originating_journal_id"):
            _id(getattr(self, name), name)
        if self.execution_kind not in C09_EXECUTION_KINDS_V1:
            raise ValueError("unknown C09 execution kind")
        _digest(self.input_commitment, "input_commitment")
        _number(self.dispatch_generation, "dispatch_generation")
        if self.dispatch_generation < 1:
            raise ValueError("C09 dispatch generation absent")
        for name in ("source_row_commitments", "d02_quote_ids", "d02_component_ids", "d11_settlement_ids"):
            values = getattr(self, name)
            if type(values) is not tuple or values != tuple(sorted(set(values))):
                raise ValueError("unordered C09 binding " + name)
            for value in values:
                (_digest if name == "source_row_commitments" else _id)(value, name)
        if self.prior_fact_frame_digest_or_none is not None:
            _digest(self.prior_fact_frame_digest_or_none, "prior frame")


@dataclass(frozen=True, slots=True)
class C09RecoveryBindingsV1:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    prior_transition_digest_or_none: str | None
    prior_fact_frame_digests: tuple[str, ...]
    execution_bindings: tuple[C09ExecutionBindingV1, ...]
    facts_digest: str
    bindings_digest: str

    def __post_init__(self):
        for name in ("authority_id", "installation_id", "namespace", "operation_id"):
            _id(getattr(self, name), name)
        if self.prior_transition_digest_or_none is not None:
            _digest(self.prior_transition_digest_or_none, "prior transition")
        for value in self.prior_fact_frame_digests:
            _digest(value, "prior frame")
        _ordered(self.execution_bindings, C09ExecutionBindingV1, "execution bindings", lambda x:x.execution_id)
        _digest(self.facts_digest, "facts_digest")
        _committed(self, "bindings_digest")


@dataclass(frozen=True, slots=True)
class VerifiedSanitizedExecutionReadV4:
    execution_id: str
    business_operation_id: str
    status: str
    input_commitment: str
    result_commitment: str | None
    terminal_commitment: str | None
    consumed: bool
    d02_facts: tuple
    d11_facts: tuple
    unknown_footprint: object | None
    originating_journal_id: str
    proof_chain: tuple[str, ...]

    def __post_init__(self):
        for name in ("execution_id", "business_operation_id", "originating_journal_id"):
            _id(getattr(self, name), name)
        if self.status not in {"pending", "completed", "failed", "unknown"}:
            raise ValueError("sanitized status differs")
        _digest(self.input_commitment, "input_commitment")
        if self.status == "unknown" and self.unknown_footprint is None:
            raise ValueError("sanitized unknown footprint absent")
        if not self.proof_chain:
            raise ValueError("sanitized proof chain absent")
        for value in self.proof_chain:
            _digest(value, "proof chain")
