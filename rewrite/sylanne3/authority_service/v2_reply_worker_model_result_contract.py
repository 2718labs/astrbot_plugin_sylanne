"""Identity-only request for a post-C02 reply model result read.

This DTO grants no access. The Authority must re-read its original completed
model call and current graph facts before releasing any result body.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_model_egress_contract import (
    ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2,
)


SCHEMA = "sylanne3.authority.reply-worker-model-result-read.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def reply_worker_read_attempt_id_v1(consumer_operation_id: str, attempt: int) -> str:
    identifier(consumer_operation_id, "consumer_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("reply worker read attempt outside bounded sequence")
    return "post-c02-reply-worker-read-" + canonical_digest({
        "schema": SCHEMA, "consumer_operation_id": consumer_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class ReplyWorkerModelResultReadRequestV1:
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
    c02_operation_id: str
    source_ref: str
    source_revision: int
    access_revision: int
    attention_ticket_id: str
    focus_revision: int
    audience: tuple[str, ...]
    purpose: str = "post_c02_reply"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.purpose != "post_c02_reply":
            raise ValueError("unknown reply worker model result scope")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("typed business namespace required")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "job_id", "acquire_operation_id", "original_operation_id",
                     "call_id", "consumer_operation_id", "read_attempt_id",
                     "c02_operation_id", "attention_ticket_id"):
            identifier(getattr(self, name), name)
        for name in ("binding_digest", "model_request_digest"):
            if type(getattr(self, name)) is not str or not _SHA256.fullmatch(
                    getattr(self, name)):
                raise ValueError(f"invalid {name}")
        source = AtomKey.from_token(self.source_ref)
        if (source.type_name != "memory.source" or source.owner.kind != "event"
                or (source.owner.bot, source.owner.persona) != self.namespace.as_tuple
                or type(self.source_revision) is not int or self.source_revision < 1
                or type(self.access_revision) is not int or self.access_revision < 1
                or type(self.focus_revision) is not int or self.focus_revision < 1):
            raise ValueError("reply source or current revision identity differs")
        if (type(self.audience) is not tuple or not self.audience
                or any(type(item) is not str or not item for item in self.audience)
                or len(set(self.audience)) != len(self.audience)):
            raise ValueError("reply audience must be a nonempty unique tuple")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ReplyWorkerModelResultReadV1:
    request: ReplyWorkerModelResultReadRequestV1
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.request) is not ReplyWorkerModelResultReadRequestV1
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
            raise ValueError("completed original reply result identity differs")

    def require_original_intent(self, intent: ModelEgressIntentV1) -> None:
        request = self.request
        if (type(intent) is not ModelEgressIntentV1
                or (intent.authority_id, intent.namespace, intent.job_id,
                    intent.operation_id, intent.budget_reservation_operation_id,
                    intent.call_id, intent.request_digest) !=
                   (request.authority_id, request.authority_namespace,
                    request.job_id, request.acquire_operation_id,
                    request.original_operation_id, request.call_id,
                    request.model_request_digest)
                or (self.observation.subject, self.observation.operation_id) !=
                   (intent.subject, intent.operation_id)
                or intent.binding_digest != request.binding_digest
                or intent.source_refs != (AtomKey.from_token(request.source_ref).owner.subject,)
                or intent.source_revisions != ((intent.source_refs[0], request.source_revision),)
                or intent.access_revisions != ((intent.source_refs[0], request.access_revision),)):
            raise ValueError("reply result differs from original Authority intent")


def to_wire(value: ReplyWorkerModelResultReadRequestV1 |
            ReplyWorkerModelResultReadV1) -> dict[str, object]:
    if type(value) not in {ReplyWorkerModelResultReadRequestV1,
                           ReplyWorkerModelResultReadV1}:
        raise TypeError("typed reply worker result required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if kind not in {ReplyWorkerModelResultReadRequestV1,
                    ReplyWorkerModelResultReadV1}:
        raise TypeError("typed reply worker result kind required")
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("reply worker result wire fields differ")
    data = dict(raw)
    if kind is ReplyWorkerModelResultReadRequestV1:
        namespace = data["namespace"]
        if type(namespace) is not dict or set(namespace) != {
                field.name for field in fields(NamespaceId)}:
            raise ValueError("reply namespace wire fields differ")
        data["namespace"] = NamespaceId(**namespace)
        if type(data["audience"]) is not list:
            raise ValueError("reply audience wire differs")
        data["audience"] = tuple(data["audience"])
    else:
        data["request"] = from_wire(data["request"], ReplyWorkerModelResultReadRequestV1)
        observation = data["observation"]
        if type(observation) is not dict or set(observation) != {
                field.name for field in fields(ModelEgressObservationV1)}:
            raise ValueError("reply observation wire fields differ")
        observation = dict(observation)
        for name in ("usage", "cost"):
            amounts = observation[name]
            if type(amounts) is not list or any(type(pair) is not list for pair in amounts):
                raise ValueError("reply observation amount pairs differ")
            observation[name] = tuple(tuple(pair) for pair in amounts)
        data["observation"] = ModelEgressObservationV1(**observation)
        terminal = data["terminal_receipt"]
        if type(terminal) is not dict or set(terminal) != {
                field.name for field in fields(ModelTerminalReceiptV2)}:
            raise ValueError("reply terminal wire fields differ")
        data["terminal_receipt"] = ModelTerminalReceiptV2(**terminal)
    result = kind(**data)
    if to_wire(result) != raw:
        raise ValueError("noncanonical reply worker result wire")
    return result


__all__ = ["SCHEMA", "ReplyWorkerModelResultReadRequestV1",
           "ReplyWorkerModelResultReadV1", "reply_worker_read_attempt_id_v1",
           "to_wire", "from_wire"]
