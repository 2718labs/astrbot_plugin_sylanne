"""Closed offline clock-tick originals; parsing is never execution authority."""
from __future__ import annotations

from dataclasses import dataclass, fields
import re

from ..runtime.d11_offline_originals_v1 import (
    D11OfflineTickBindingV1, D11OfflineTickResultV1, _utc,
)
from ..runtime_contracts import NamespaceId, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1


def _hex(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("exact content digest required")


def _chain(value):
    if type(value) is not str or not value.startswith("sha256:"):
        raise ValueError("prefixed journal digest required")
    _hex(value[7:])


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("bounded original identity required")


def _positive(value):
    if type(value) is not int or value < 1:
        raise ValueError("positive journal sequence required")


def offline_tick_mutation_id_v1(binding, phase):
    if type(binding) is not D11OfflineTickBindingV1 or phase not in {"claim", "terminal"}:
        raise ValueError("exact offline binding and finite phase required")
    return "d11-offline:" + phase + ":" + canonical_digest(
        (binding.authority_namespace, binding.installation_id, binding.execution_id))


@dataclass(frozen=True, slots=True)
class D11OfflineTickClaimPayloadV1:
    binding_digest: str
    prepared_digest: str
    execution_id: str
    claim_id: str
    claim_sequence: int
    executor_installation_id: str
    executor_incarnation: str
    claimed_at_utc: str
    signature: str
    schema: str = "d11.offline-tick-claim-payload.v1"

    def __post_init__(self):
        if self.schema != "d11.offline-tick-claim-payload.v1":
            raise ValueError("offline claim schema differs")
        for value in (self.binding_digest, self.prepared_digest, self.signature):
            _hex(value)
        for value in (self.execution_id, self.claim_id, self.executor_installation_id,
                      self.executor_incarnation):
            _text(value)
        _positive(self.claim_sequence)
        _utc(self.claimed_at_utc)


@dataclass(frozen=True, slots=True)
class D11OfflineTickClaimV1:
    binding: D11OfflineTickBindingV1
    payload: D11OfflineTickClaimPayloadV1
    journal_id: str
    claim_digest: str
    original_ref: str
    schema: str = "d11.offline-tick-claim-original.v1"

    def __post_init__(self):
        if (self.schema != "d11.offline-tick-claim-original.v1"
                or type(self.binding) is not D11OfflineTickBindingV1
                or type(self.payload) is not D11OfflineTickClaimPayloadV1
                or self.payload.binding_digest != self.binding.digest
                or self.payload.execution_id != self.binding.execution_id
                or self.payload.executor_installation_id != self.binding.installation_id
                or self.payload.claim_id != offline_tick_mutation_id_v1(self.binding, "claim")
                or self.original_ref != self.payload.claim_id):
            raise ValueError("offline claim original differs")
        _text(self.journal_id)
        _chain(self.claim_digest)

    @property
    def claim_sequence(self):
        return self.payload.claim_sequence


_FAILURES = frozenset({"computation_failed", "cpu_ceiling_exceeded", "deadline_expired",
                       "job_lease_expired", "clock_sample_inconsistent"})
_UNKNOWNS = frozenset({"executor_quiesced_measurement_lost"})


@dataclass(frozen=True, slots=True)
class D11OfflineTickTerminalPayloadV1:
    binding_digest: str
    prepared_digest: str
    execution_id: str
    claim_sequence: int
    claim_digest: str
    status: str
    actual_cpu_ms: int | None
    result: D11OfflineTickResultV1 | None
    reason_code: str | None
    completed_at_utc: str
    signature: str
    schema: str = "d11.offline-tick-terminal-payload.v1"

    def __post_init__(self):
        if self.schema != "d11.offline-tick-terminal-payload.v1":
            raise ValueError("offline terminal schema differs")
        for value in (self.binding_digest, self.prepared_digest, self.signature):
            _hex(value)
        _text(self.execution_id)
        _positive(self.claim_sequence)
        _chain(self.claim_digest)
        _utc(self.completed_at_utc)
        if self.status == "completed":
            valid = (type(self.actual_cpu_ms) is int and self.actual_cpu_ms >= 0
                     and type(self.result) is D11OfflineTickResultV1
                     and self.reason_code is None
                     and _utc(self.result.computed_at_utc) <= _utc(self.completed_at_utc))
        elif self.status == "failed":
            valid = (type(self.actual_cpu_ms) is int and self.actual_cpu_ms >= 0
                     and self.result is None and self.reason_code in _FAILURES)
        elif self.status == "unknown":
            valid = (self.actual_cpu_ms is None and self.result is None
                     and self.reason_code in _UNKNOWNS)
        else:
            valid = False
        if not valid:
            raise ValueError("offline outcome cannot invent result or measured CPU")


@dataclass(frozen=True, slots=True)
class D11OfflineTickTerminalV1:
    binding: D11OfflineTickBindingV1
    claim: D11OfflineTickClaimV1
    payload: D11OfflineTickTerminalPayloadV1
    journal_id: str
    terminal_sequence: int
    terminal_digest: str
    original_ref: str
    schema: str = "d11.offline-tick-terminal-original.v1"

    def __post_init__(self):
        if (self.schema != "d11.offline-tick-terminal-original.v1"
                or type(self.binding) is not D11OfflineTickBindingV1
                or type(self.claim) is not D11OfflineTickClaimV1
                or type(self.payload) is not D11OfflineTickTerminalPayloadV1
                or self.claim.binding != self.binding
                or self.payload.binding_digest != self.binding.digest
                or self.payload.prepared_digest != self.claim.payload.prepared_digest
                or self.payload.execution_id != self.binding.execution_id
                or self.payload.claim_sequence != self.claim.claim_sequence
                or self.payload.claim_digest != self.claim.claim_digest
                or self.journal_id != self.claim.journal_id
                or self.original_ref != offline_tick_mutation_id_v1(self.binding, "terminal")):
            raise ValueError("offline terminal does not join its exact earlier claim")
        _positive(self.terminal_sequence)
        _chain(self.terminal_digest)
        if self.terminal_sequence <= self.claim.claim_sequence:
            raise ValueError("offline terminal must follow its actual claim")
        if self.payload.result is not None:
            if (self.payload.result.scheduled_at_utc != self.binding.scheduled_at_utc
                    or self.payload.actual_cpu_ms > self.binding.cpu_ceiling_ms
                    or _utc(self.payload.completed_at_utc) >= min(
                        _utc(self.binding.deadline_utc), _utc(self.binding.job_lease_expires_utc))):
                raise ValueError("completed clock tick exceeded its frozen time/CPU bounds")

    @property
    def status(self):
        return self.payload.status

    @property
    def actual_cpu_ms(self):
        return self.payload.actual_cpu_ms

    @property
    def result(self):
        return self.payload.result


_TYPES = {D11OfflineTickBindingV1, D11OfflineTickResultV1,
          D11OfflineTickClaimPayloadV1, D11OfflineTickClaimV1,
          D11OfflineTickTerminalPayloadV1, D11OfflineTickTerminalV1}


def offline_tick_to_wire_v1(value):
    if type(value) not in _TYPES:
        raise TypeError("exact offline original type required")
    return plain_v1(value)


def offline_tick_from_wire_v1(raw, kind):
    if kind not in _TYPES or type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("offline original wire fields differ")
    value = dict(raw)
    if kind is D11OfflineTickBindingV1:
        value["namespace"] = NamespaceId(**value["namespace"])
    if kind in {D11OfflineTickClaimV1, D11OfflineTickTerminalV1}:
        value["binding"] = offline_tick_from_wire_v1(value["binding"], D11OfflineTickBindingV1)
        payload_kind = D11OfflineTickClaimPayloadV1 if kind is D11OfflineTickClaimV1 else D11OfflineTickTerminalPayloadV1
        value["payload"] = offline_tick_from_wire_v1(value["payload"], payload_kind)
    if kind is D11OfflineTickTerminalV1:
        value["claim"] = offline_tick_from_wire_v1(value["claim"], D11OfflineTickClaimV1)
    if kind is D11OfflineTickTerminalPayloadV1 and value["result"] is not None:
        value["result"] = offline_tick_from_wire_v1(value["result"], D11OfflineTickResultV1)
    result = kind(**value)
    if offline_tick_to_wire_v1(result) != raw:
        raise ValueError("offline original wire is not canonical")
    return result
