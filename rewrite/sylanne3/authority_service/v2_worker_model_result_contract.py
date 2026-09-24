"""Identity-only worker read contract for the original first-ingress model call.

The request grants no access. Authority derives actor and transport credentials,
then verifies current job, acquire, call binding, graph and terminal state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_model_egress_contract import ModelEgressObservationV1, ModelTerminalReceiptV2


SCHEMA = "sylanne3.authority.worker_model_result_read.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class WorkerModelResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = "first_ingress_c02"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.purpose != "first_ingress_c02":
            raise ValueError("unknown worker model result read scope")
        for name in ("authority_id", "authority_namespace", "installation_id", "job_id",
                     "acquire_operation_id", "original_operation_id", "call_id",
                     "consumer_operation_id", "read_attempt_id"):
            identifier(getattr(self, name), name)
        if type(self.namespace) is not NamespaceId:
            raise TypeError("typed business namespace required")
        for name in ("binding_digest", "model_request_digest"):
            value = getattr(self, name)
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise ValueError(f"invalid {name}")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class WorkerModelResultReadV1:
    request: WorkerModelResultReadRequestV1
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or type(self.request) is not WorkerModelResultReadRequestV1
                or type(self.observation) is not ModelEgressObservationV1
                or type(self.terminal_receipt) is not ModelTerminalReceiptV2
                or self.observation.status != "completed"
                or (self.observation.authority_id, self.observation.namespace,
                    self.observation.call_id, self.observation.request_digest) !=
                   (self.request.authority_id, self.request.authority_namespace,
                    self.request.call_id, self.request.model_request_digest)
                or (self.terminal_receipt.call_id, self.terminal_receipt.request_digest,
                    self.terminal_receipt.observation_digest,
                    self.terminal_receipt.installation_id) !=
                   (self.request.call_id, self.request.model_request_digest,
                    self.observation.digest, self.request.installation_id)):
            raise ValueError("original completed worker result required")


def _shape(raw: object, kind: type) -> dict:
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("worker model result read wire fields differ")
    return dict(raw)


def to_wire(value: WorkerModelResultReadRequestV1 | WorkerModelResultReadV1) -> dict:
    if type(value) not in {WorkerModelResultReadRequestV1, WorkerModelResultReadV1}:
        raise TypeError("typed worker model result read required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if kind is WorkerModelResultReadRequestV1:
        data = _shape(raw, kind)
        data["namespace"] = NamespaceId(**_shape(data["namespace"], NamespaceId))
        value = WorkerModelResultReadRequestV1(**data)
    elif kind is WorkerModelResultReadV1:
        data = _shape(raw, kind)
        data["request"] = from_wire(data["request"], WorkerModelResultReadRequestV1)
        observation = _shape(data["observation"], ModelEgressObservationV1)
        for name in ("usage", "cost"):
            amounts = observation[name]
            if type(amounts) is not list or any(type(pair) is not list for pair in amounts):
                raise ValueError("worker result amount pairs differ")
            observation[name] = tuple(tuple(pair) for pair in amounts)
        data["observation"] = ModelEgressObservationV1(**observation)
        data["terminal_receipt"] = ModelTerminalReceiptV2(
            **_shape(data["terminal_receipt"], ModelTerminalReceiptV2))
        value = WorkerModelResultReadV1(**data)
    else:
        raise ValueError("unsupported worker result read wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical worker model result read wire value")
    return value


__all__ = ("SCHEMA", "WorkerModelResultReadRequestV1", "WorkerModelResultReadV1",
           "from_wire", "to_wire")
