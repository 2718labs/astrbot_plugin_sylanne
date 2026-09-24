"""Content-free C02 adoption fact shape; only Authority may issue one.

Parsing this DTO does not prove a finished handoff or a live write fence.  The
issuer must derive every digest from its durable ledgers in one Authority
transaction after an independent current graph check.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import re

from ..runtime_contracts import canonical_digest
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from .v2_model_egress_contract import ModelTerminalReceiptV2
from .v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, from_wire as read_from_wire,
    to_wire as read_to_wire,
)


SCHEMA = "sylanne3.authority.worker-result-read-fact.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class WorkerResultReadFactRequestV1:
    """An installed C02 committer asks about one prior worker handoff."""

    read_request: WorkerModelResultReadRequestV1
    write_permit: FencePermitV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.read_request) is not WorkerModelResultReadRequestV1
                or type(self.write_permit) is not FencePermitV2
                or self.write_permit.operation != "write"
                or (self.write_permit.authority_id, self.write_permit.namespace) !=
                   (self.read_request.authority_id,
                    self.read_request.authority_namespace)):
            raise ValueError("C02 fact request requires matching graph write fence")


@dataclass(frozen=True, slots=True)
class WorkerResultReadFactV1:
    """Authority-derived finished handoff and original terminal identities.

    The final Graph transaction must revalidate the write permit, graph state,
    baseline and cost.  This fact contains no model observation or result body.
    """

    read_request: WorkerModelResultReadRequestV1
    read_request_digest: str
    read_permit: FencePermitV2
    read_permit_digest: str
    read_finish_request_id: str
    read_finish_request_digest: str
    result_digest: str
    original_intent_digest: str
    terminal_receipt: ModelTerminalReceiptV2
    write_permit: FencePermitV2
    write_permit_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.read_request) is not WorkerModelResultReadRequestV1
                or type(self.read_permit) is not FencePermitV2
                or type(self.write_permit) is not FencePermitV2
                or type(self.terminal_receipt) is not ModelTerminalReceiptV2):
            raise ValueError("typed Authority worker read fact required")
        request = self.read_request
        if (self.read_permit.operation != "read"
                or self.write_permit.operation != "write"
                or (self.read_permit.authority_id, self.read_permit.namespace,
                    self.read_permit.operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.read_attempt_id)
                or (self.write_permit.authority_id, self.write_permit.namespace) !=
                   (request.authority_id, request.authority_namespace)
                or self.read_permit.pinned_anchor != self.write_permit.pinned_anchor
                or (self.terminal_receipt.call_id,
                    self.terminal_receipt.request_digest,
                    self.terminal_receipt.installation_id) !=
                   (request.call_id, request.model_request_digest,
                    request.installation_id)):
            raise ValueError("worker read fact identities differ")
        for name in ("read_request_digest", "read_permit_digest", "result_digest",
                     "original_intent_digest", "write_permit_digest"):
            _digest(getattr(self, name), name)
        if (self.read_request_digest != request.digest
                or self.read_permit_digest != canonical_digest(asdict(self.read_permit))
                or self.write_permit_digest != canonical_digest(asdict(self.write_permit))
                or type(self.read_finish_request_id) is not str
                or not self.read_finish_request_id.startswith("worker-result-finish:")
                or self.read_finish_request_id.removeprefix("worker-result-finish:") !=
                   canonical_digest({"request": asdict(request),
                                     "permit": asdict(self.read_permit)})
                or self.read_finish_request_digest != "sha256:" + canonical_digest({
                    "action": "finish_worker_result_read",
                    "request": asdict(request), "permit": asdict(self.read_permit)})):
            raise ValueError("worker read fact digest or finish identity differs")


def to_wire(value: WorkerResultReadFactRequestV1 | WorkerResultReadFactV1) -> dict:
    if type(value) not in {WorkerResultReadFactRequestV1, WorkerResultReadFactV1}:
        raise TypeError("typed worker read fact required")
    result = asdict(value)
    result["read_request"] = read_to_wire(value.read_request)
    result["write_permit"] = fence_to_wire(value.write_permit)
    if type(value) is WorkerResultReadFactV1:
        result["read_permit"] = fence_to_wire(value.read_permit)
    return result


def from_wire(raw: object, kind: type):
    if kind not in {WorkerResultReadFactRequestV1, WorkerResultReadFactV1}:
        raise TypeError("typed worker read fact kind required")
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("worker read fact wire fields differ")
    data = dict(raw)
    data["read_request"] = read_from_wire(
        data["read_request"], WorkerModelResultReadRequestV1)
    data["write_permit"] = fence_from_wire(data["write_permit"])
    if kind is WorkerResultReadFactV1:
        data["read_permit"] = fence_from_wire(data["read_permit"])
        receipt = data["terminal_receipt"]
        if (type(receipt) is not dict
                or set(receipt) != {field.name for field in fields(ModelTerminalReceiptV2)}):
            raise ValueError("terminal receipt wire fields differ")
        data["terminal_receipt"] = ModelTerminalReceiptV2(**receipt)
    value = kind(**data)
    if to_wire(value) != raw:
        raise ValueError("noncanonical worker read fact wire value")
    return value


__all__ = (
    "SCHEMA", "WorkerResultReadFactRequestV1", "WorkerResultReadFactV1",
    "to_wire", "from_wire",
)
