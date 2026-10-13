"""Identity-only worker read contract for original worker model calls.

The request grants no access. Authority derives actor and transport credentials,
then verifies current job, acquire, call binding, graph and terminal state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_model_egress_contract import (
    ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2,
)


SCHEMA = "sylanne3.authority.worker_model_result_read.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def first_ingress_read_attempt_id_v1(
    consumer_operation_id: str, attempt: int,
) -> str:
    """Stable identity for one content read; this is not a read permit."""
    identifier(consumer_operation_id, "consumer_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("worker read attempt is outside the bounded sequence")
    return "first-ingress-worker-read-" + canonical_digest({
        "schema": "sylanne3.first-ingress-worker-read-attempt.v1",
        "consumer_operation_id": consumer_operation_id,
        "attempt": attempt,
    })[:48]


def d13_paid_read_attempt_id_v1(
    consumer_operation_id: str, attempt: int,
) -> str:
    """Stable D13 read identity, separate from the first-ingress scope."""
    identifier(consumer_operation_id, "consumer_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("D13 worker read attempt is outside the bounded sequence")
    return "d13-worker-read-" + canonical_digest({
        "schema": "sylanne3.d13-paid-worker-read-attempt.v1",
        "consumer_operation_id": consumer_operation_id,
        "attempt": attempt,
    })[:48]


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
        if self.schema != SCHEMA or self.purpose not in {
                "first_ingress_c02", "d13_precompress_paid"}:
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
    """Response shape only; Authority must check the original intent and current graph.

    The request does not contain the model fence operation or server-derived
    worker subject. The service must obtain those from its durable original
    egress ledger, call ``require_original_intent``, and verify that ledger's
    terminal fence, binding, and current worker qualification before release.
    This structural check never grants access by itself.
    """

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
            raise ValueError("consistent completed worker result fields required")

    def require_original_intent(self, intent: ModelEgressIntentV1) -> None:
        """Compare to an Authority-loaded original intent, without authorizing read."""
        if (type(intent) is not ModelEgressIntentV1
                or (intent.authority_id, intent.namespace, intent.job_id,
                    intent.call_id, intent.request_digest) !=
                   (self.request.authority_id, self.request.authority_namespace,
                    self.request.job_id, self.request.call_id,
                    self.request.model_request_digest)
                or (self.observation.authority_id, self.observation.namespace,
                    self.observation.subject, self.observation.operation_id,
                    self.observation.call_id, self.observation.request_digest) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id, intent.request_digest)):
            raise ValueError("worker result differs from original Authority model intent")


def _shape(raw: object, kind: type) -> dict:
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("worker model result read wire fields differ")
    return dict(raw)


def to_wire(value: WorkerModelResultReadRequestV1 | WorkerModelResultReadV1) -> dict:
    if type(value) not in {WorkerModelResultReadRequestV1, WorkerModelResultReadV1}:
        raise TypeError("typed worker model result read required")
    data = json.loads(canonical_serialize(asdict(value)))
    if type(value) is WorkerModelResultReadV1:
        from .v2_model_egress_contract import model_observation_to_wire_v1
        data["observation"] = model_observation_to_wire_v1(value.observation)
    return data


def from_wire(raw: object, kind: type):
    if kind is WorkerModelResultReadRequestV1:
        data = _shape(raw, kind)
        data["namespace"] = NamespaceId(**_shape(data["namespace"], NamespaceId))
        value = WorkerModelResultReadRequestV1(**data)
    elif kind is WorkerModelResultReadV1:
        data = _shape(raw, kind)
        data["request"] = from_wire(data["request"], WorkerModelResultReadRequestV1)
        from .v2_model_egress_contract import model_observation_from_wire_v1
        data["observation"] = model_observation_from_wire_v1(data["observation"])
        data["terminal_receipt"] = ModelTerminalReceiptV2(
            **_shape(data["terminal_receipt"], ModelTerminalReceiptV2))
        value = WorkerModelResultReadV1(**data)
    else:
        raise ValueError("unsupported worker result read wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical worker model result read wire value")
    return value


__all__ = (
    "SCHEMA", "WorkerModelResultReadRequestV1", "WorkerModelResultReadV1",
    "first_ingress_read_attempt_id_v1", "d13_paid_read_attempt_id_v1",
    "from_wire", "to_wire",
)
