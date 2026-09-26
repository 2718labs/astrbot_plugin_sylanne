"""Content-free original result identity for terminal C02 recovery.

These values are evidence, never a permission to read a provider body or
commit C02. A separate current graph verifier and durable read attempt must
authorize any later content handoff.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re
from typing import Protocol

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1


SCHEMA = "sylanne3.authority.terminal-c02-recovery.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class OriginalC02ResultKeyV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    original_model_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    original_intent_digest: str
    observation_digest: str
    terminal_receipt_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("terminal C02 key schema or namespace differs")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "job_id", "original_operation_id", "acquire_operation_id",
                     "original_model_operation_id", "call_id"):
            identifier(getattr(self, name), name)
        if self.acquire_operation_id != self.original_model_operation_id:
            raise ValueError("original acquire and model operation differ")
        for name in ("binding_digest", "model_request_digest",
                     "original_intent_digest", "observation_digest",
                     "terminal_receipt_digest"):
            value = getattr(self, name)
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"invalid {name}")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @property
    def stable_result_digest(self) -> str:
        """Original terminal identity only; excludes any read attempt."""
        return canonical_digest({
            "authority_id": self.authority_id,
            "authority_namespace": self.authority_namespace,
            "call_id": self.call_id,
            "model_request_digest": self.model_request_digest,
            "observation_digest": self.observation_digest,
            "terminal_receipt_digest": self.terminal_receipt_digest,
        })


@dataclass(frozen=True, slots=True)
class TerminalRecoveryReadRequestV1:
    original_key: OriginalC02ResultKeyV1
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = "first_ingress_c02_terminal_recovery"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or self.purpose != "first_ingress_c02_terminal_recovery"
                or type(self.original_key) is not OriginalC02ResultKeyV1):
            raise ValueError("terminal C02 read request scope differs")
        identifier(self.consumer_operation_id, "consumer_operation_id")
        identifier(self.read_attempt_id, "read_attempt_id")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class TerminalRecoveryReadAttemptV1:
    """Content-free durable attempt; this record grants no body read."""

    request: TerminalRecoveryReadRequestV1
    permit_digest: str
    state: str  # active | finished
    result_digest: str | None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.request) is not TerminalRecoveryReadRequestV1
                or self.state not in {"active", "finished"}
                or type(self.permit_digest) is not str
                or _DIGEST.fullmatch(self.permit_digest) is None):
            raise ValueError("invalid terminal C02 read attempt")
        if self.state == "active":
            if self.result_digest is not None:
                raise ValueError("active terminal C02 read has no result")
        elif self.result_digest != self.request.original_key.stable_result_digest:
            raise ValueError("finished terminal C02 result differs from original")


@dataclass(frozen=True, slots=True)
class TerminalRecoveryReadFactV1:
    """A finished attempt record, never a C02 write or body release permit.

    A future trusted transport must supply handoff_digest only after the
    original response has been drained. The ledger cannot prove that event.
    """

    request: TerminalRecoveryReadRequestV1
    permit_digest: str
    result_digest: str
    handoff_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.request) is not TerminalRecoveryReadRequestV1:
            raise ValueError("terminal C02 read fact scope differs")
        for name in ("permit_digest", "result_digest", "handoff_digest"):
            value = getattr(self, name)
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"invalid {name}")
        if self.result_digest != self.request.original_key.stable_result_digest:
            raise ValueError("terminal C02 fact differs from original result")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class TerminalRecoveryGraphVerifierV1(Protocol):
    """Future pinned read-only Graph check; old worker lease is historical.

    An implementation must verify the original V3 acquire and binding, job
    cancellation/fence/holder and expired lease with live business deadline,
    current source/access/D04 baseline/incarnation/activation, and signed quote
    and budget. The permit subject is the current installed recovery observer.
    """

    def current(self, request: TerminalRecoveryReadRequestV1,
                intent: ModelEgressIntentV1, permit: FencePermitV2) -> bool: ...


def to_wire(value: OriginalC02ResultKeyV1 | TerminalRecoveryReadRequestV1 |
            TerminalRecoveryReadAttemptV1 | TerminalRecoveryReadFactV1) -> dict:
    if type(value) not in {OriginalC02ResultKeyV1, TerminalRecoveryReadRequestV1,
                           TerminalRecoveryReadAttemptV1, TerminalRecoveryReadFactV1}:
        raise TypeError("typed terminal C02 recovery value required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if kind not in {OriginalC02ResultKeyV1, TerminalRecoveryReadRequestV1,
                    TerminalRecoveryReadAttemptV1, TerminalRecoveryReadFactV1}:
        raise TypeError("terminal C02 recovery wire type differs")
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("terminal C02 recovery wire fields differ")
    data = dict(raw)
    if kind is OriginalC02ResultKeyV1:
        namespace = data["namespace"]
        if type(namespace) is not dict or set(namespace) != {
                field.name for field in fields(NamespaceId)}:
            raise ValueError("terminal C02 namespace fields differ")
        data["namespace"] = NamespaceId(**namespace)
    elif kind is TerminalRecoveryReadRequestV1:
        data["original_key"] = from_wire(data["original_key"], OriginalC02ResultKeyV1)
    else:
        data["request"] = from_wire(data["request"], TerminalRecoveryReadRequestV1)
    value = kind(**data)
    if to_wire(value) != raw:
        raise ValueError("noncanonical terminal C02 recovery wire")
    return value


__all__ = ("SCHEMA", "OriginalC02ResultKeyV1", "TerminalRecoveryReadRequestV1",
           "TerminalRecoveryReadAttemptV1", "TerminalRecoveryReadFactV1",
           "TerminalRecoveryGraphVerifierV1", "from_wire", "to_wire")
