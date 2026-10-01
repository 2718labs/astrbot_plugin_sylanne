"""Versioned identities for one C04 internal CPU work original.

These immutable shapes do not authorize execution or prove a journal append.
Only the independently installed Authority may issue and reread durable claim
and terminal receipts. They contain no platform dispatch identities.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .internal_work_service import AuthorityInternalWorkVerifiedReceiptV1

from ..runtime_contracts import canonical_digest
from ..contracts import canonical_json
from ..graph_types import AtomKey
from .contract import JournalHead, identifier


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BINDING_SCHEMA = "sylanne3.internal_work.binding.v1"
_CLAIM_SCHEMA = "sylanne3.internal_work.claim.v1"
_TERMINAL_SCHEMA = "sylanne3.internal_work.terminal.v1"
_TERMINAL_V2_SCHEMA = "sylanne3.internal_work.terminal.v2"
_PROOF_SCHEMA = "sylanne3.internal_work.terminal_proof.v1"


def _digest(value: str, name: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return value


def _phase_id(binding_digest: str, phase: str) -> str:
    return "internal-work:" + canonical_digest({
        "schema": "sylanne3.internal_work.mutation.v1",
        "binding_digest": binding_digest, "phase": phase,
    })


def _reservation_key(token: str, namespace: str, activity_id: str) -> None:
    """Bind the exact D02 activity AtomKey to W01's opaque namespace."""
    try:
        key = AtomKey.from_token(token)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid body_reservation_ref AtomKey") from exc
    owner = key.owner
    owner_namespace = "ns:sha256:" + hashlib.sha256(
        canonical_json([owner.bot, owner.persona]).encode("utf-8")
    ).hexdigest()
    if (owner.kind != "activity" or owner.subject != activity_id or
            key.type_name != "d02.reservation.v1" or owner_namespace != namespace):
        raise ValueError("body_reservation_ref owner, type or namespace differs")


@dataclass(frozen=True, slots=True)
class InternalWorkBindingV1:
    namespace: str
    activity_id: str
    operation_id: str
    execution_id: str
    input_digest: str
    resource_quote_ref: str
    resource_quote_version: int
    resource_quote_digest: str
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    body_reservation_ref: str
    component_id: str
    parent_budget_lease_ref: str
    activation_generation: int
    algorithm_ref: str
    policy_ref: str
    algorithm_build_digest: str | None = None
    schema: str = _BINDING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _BINDING_SCHEMA:
            raise ValueError("unknown internal work binding schema")
        for name in (
            "namespace", "activity_id", "operation_id", "execution_id",
            "resource_quote_ref", "body_quote_ref",
            "component_id", "parent_budget_lease_ref", "algorithm_ref",
            "policy_ref",
        ):
            identifier(getattr(self, name), name)
        _reservation_key(self.body_reservation_ref, self.namespace, self.activity_id)
        for name in ("input_digest", "resource_quote_digest", "body_quote_digest"):
            _digest(getattr(self, name), name)
        if self.algorithm_build_digest is not None:
            _digest(self.algorithm_build_digest, "algorithm_build_digest")
        for name in ("resource_quote_version", "body_quote_version",
                     "activation_generation"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative exact integer")

    @property
    def binding_digest(self) -> str:
        if self.algorithm_build_digest is not None:
            return canonical_digest(self)
        value = {"$type": f"{type(self).__module__}.{type(self).__qualname__}",
                 **asdict(self)}
        value.pop("algorithm_build_digest")  # Historical V1 digest stays valid.
        return canonical_digest(value)


@dataclass(frozen=True, slots=True)
class InternalWorkClaimV1:
    binding_digest: str
    mutation_id: str
    schema: str = _CLAIM_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != _CLAIM_SCHEMA or
                _digest(self.binding_digest, "binding_digest") != self.binding_digest or
                self.mutation_id != _phase_id(self.binding_digest, "claim")):
            raise ValueError("internal work claim identity differs")


def claim_internal_work_v1(binding: InternalWorkBindingV1) -> InternalWorkClaimV1:
    if type(binding) is not InternalWorkBindingV1:
        raise TypeError("typed internal work binding required")
    digest = binding.binding_digest
    return InternalWorkClaimV1(digest, _phase_id(digest, "claim"))


@dataclass(frozen=True, slots=True)
class InternalWorkTerminalV1:
    binding_digest: str
    claim_mutation_id: str
    mutation_id: str
    status: str
    actual_cpu_ms: int | None
    result_digest: str | None
    component_receipt_ref: str | None
    component_receipt_digest: str | None
    schema: str = _TERMINAL_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != _TERMINAL_SCHEMA or
                _digest(self.binding_digest, "binding_digest") != self.binding_digest or
                self.claim_mutation_id != _phase_id(self.binding_digest, "claim") or
                self.mutation_id != _phase_id(self.binding_digest, "terminal") or
                self.status not in {"completed", "failed", "unknown"}):
            raise ValueError("internal work terminal identity or status differs")
        if self.status == "unknown":
            if (self.actual_cpu_ms is not None or self.result_digest is not None or
                    self.component_receipt_ref is not None or
                    self.component_receipt_digest is not None):
                raise ValueError("unknown work cannot assert zero cost or completion")
            return
        if type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0:
            raise ValueError("observed work requires exact nonnegative CPU milliseconds")
        if self.status == "completed":
            _digest(self.result_digest, "result_digest")
        elif self.result_digest is not None:
            _digest(self.result_digest, "result_digest")
        if (self.component_receipt_ref is None) != (self.component_receipt_digest is None):
            raise ValueError("component receipt reference and digest must travel together")
        if self.component_receipt_ref is not None:
            identifier(self.component_receipt_ref, "component_receipt_ref")
            _digest(self.component_receipt_digest, "component_receipt_digest")

    @property
    def terminal_digest(self) -> str:
        return canonical_digest(self)

    @property
    def component_completed(self) -> bool:
        """Legacy caller-provided references never prove installed completion."""
        return False


@dataclass(frozen=True, slots=True)
class InternalWorkTerminalV2:
    """Bounded installed execution result; signature is verified on reread."""

    binding_digest: str
    claim_mutation_id: str
    mutation_id: str
    status: str
    actual_cpu_ms: int | None
    algorithm_id: str
    build_fingerprint: str
    input_digest: str
    result_digest: str | None
    output_json: str | None
    component_receipt_ref: str | None
    component_receipt_digest: str | None
    component_receipt_signature: str | None
    execution_signature: str | None
    schema: str = _TERMINAL_V2_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != _TERMINAL_V2_SCHEMA or
                _digest(self.binding_digest, "binding_digest") != self.binding_digest or
                self.claim_mutation_id != _phase_id(self.binding_digest, "claim") or
                self.mutation_id != _phase_id(self.binding_digest, "terminal") or
                self.status not in {"completed", "failed", "unknown"}):
            raise ValueError("internal work v2 terminal identity or status differs")
        identifier(self.algorithm_id, "algorithm_id")
        _digest(self.build_fingerprint, "build_fingerprint")
        _digest(self.input_digest, "input_digest")
        if self.status == "unknown":
            if any(value is not None for value in (
                    self.actual_cpu_ms, self.result_digest, self.output_json,
                    self.component_receipt_ref, self.component_receipt_digest,
                    self.component_receipt_signature, self.execution_signature)):
                raise ValueError("unknown work cannot assert cost, output or completion")
            return
        if type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0:
            raise ValueError("observed work needs measured CPU milliseconds")
        _digest(self.execution_signature, "execution_signature")
        if self.status == "failed":
            if any(value is not None for value in (
                    self.result_digest, self.output_json, self.component_receipt_ref,
                    self.component_receipt_digest, self.component_receipt_signature)):
                raise ValueError("failed work cannot assert component completion")
            return
        _digest(self.result_digest, "result_digest")
        if (type(self.output_json) is not str or
                len(self.output_json.encode("utf-8")) > 65536):
            raise ValueError("completed work needs bounded output")
        try:
            parsed = json.loads(self.output_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("completed work output is invalid") from exc
        if (type(parsed) is not dict or canonical_json(parsed) != self.output_json or
                parsed.get("input_digest") != "sha256:" + self.input_digest or
                parsed.get("result_digest") != "sha256:" + self.result_digest):
            raise ValueError("completed work output digest or canonical bytes differ")
        identifier(self.component_receipt_ref, "component_receipt_ref")
        _digest(self.component_receipt_digest, "component_receipt_digest")
        _digest(self.component_receipt_signature, "component_receipt_signature")

    @property
    def terminal_digest(self) -> str:
        return canonical_digest(self)

    @property
    def component_completed(self) -> bool:
        """A structural claim only; installed verifier must authenticate it."""
        return False


def terminal_internal_work_v1(
    binding: InternalWorkBindingV1, claim: InternalWorkClaimV1, *,
    status: str, actual_cpu_ms: int | None = None,
    result_digest: str | None = None,
    component_receipt_ref: str | None = None,
    component_receipt_digest: str | None = None,
) -> InternalWorkTerminalV1:
    if (type(binding) is not InternalWorkBindingV1 or
            claim != claim_internal_work_v1(binding)):
        raise ValueError("terminal requires original internal work claim")
    return InternalWorkTerminalV1(
        binding.binding_digest, claim.mutation_id,
        _phase_id(binding.binding_digest, "terminal"), status, actual_cpu_ms,
        result_digest, component_receipt_ref, component_receipt_digest,
    )


@dataclass(frozen=True, slots=True)
class InternalWorkTerminalProofV1:
    """Reread locator, not an authentication token or a cost receipt by itself."""

    binding: InternalWorkBindingV1
    claim: InternalWorkClaimV1
    terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2
    claim_receipt_ref: str
    claim_receipt_digest: str
    terminal_receipt_ref: str
    terminal_receipt_digest: str
    journal_head: JournalHead
    schema: str = _PROOF_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != _PROOF_SCHEMA or
                type(self.binding) is not InternalWorkBindingV1 or
                self.claim != claim_internal_work_v1(self.binding) or
                type(self.terminal) not in (InternalWorkTerminalV1,
                                            InternalWorkTerminalV2) or
                self.terminal.binding_digest != self.binding.binding_digest or
                self.terminal.claim_mutation_id != self.claim.mutation_id or
                type(self.journal_head) is not JournalHead or
                self.journal_head.seq < 2):
            raise ValueError("internal work terminal proof identity differs")
        for name in ("claim_receipt_ref", "terminal_receipt_ref"):
            identifier(getattr(self, name), name)
        for name in ("claim_receipt_digest", "terminal_receipt_digest"):
            _digest(getattr(self, name), name)


def validate_internal_work_terminal_proof_v1(
    proof: InternalWorkTerminalProofV1, *, expected_binding: InternalWorkBindingV1,
) -> None:
    """Check immutable identity before an installed independent reread port."""
    if (type(proof) is not InternalWorkTerminalProofV1 or
            type(expected_binding) is not InternalWorkBindingV1 or
            proof.binding != expected_binding):
        raise ValueError("original internal work binding differs")
    proof.__post_init__()


class InternalWorkOriginalTerminalVerifierV1(Protocol):
    """Installed Authority port; D02 must independently reread both records."""

    def verify_original_internal_work_terminal(
        self, proof: InternalWorkTerminalProofV1,
    ) -> AuthorityInternalWorkVerifiedReceiptV1: ...


__all__ = [
    "InternalWorkBindingV1", "InternalWorkClaimV1",
    "InternalWorkTerminalV1", "InternalWorkTerminalV2",
    "InternalWorkTerminalProofV1",
    "InternalWorkOriginalTerminalVerifierV1",
    "claim_internal_work_v1", "terminal_internal_work_v1",
    "validate_internal_work_terminal_proof_v1",
]
