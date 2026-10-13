"""Identity-only V2 context reply result request; never a content grant.

The Authority must load the original paid job, acquire, intent, terminal and
frozen input from its durable stores. Caller fields only identify that record.
The old single-source reply-worker request remains a separate V1 contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..graph_types import AtomKey, GraphVersion, Owner
from ..model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_VERSION, FrozenContextReplyRequestV1,
    parse_context_reply_output_v1,
)
from ..runtime_contracts import (
    ContextReplyOriginalSealV2, NamespaceId, canonical_digest,
    canonical_serialize,
)
from .contract import identifier
from .v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)


SCHEMA = "sylanne3.authority.context-reply-result-read.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def context_reply_read_attempt_id_v1(original_operation_id: str,
                                     attempt: int) -> str:
    identifier(original_operation_id, "original_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("context reply read attempt outside bounded sequence")
    return "context-reply-result-read-" + canonical_digest({
        "schema": SCHEMA, "original_operation_id": original_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class ContextReplyResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    installation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    model_request_digest: str
    frozen_input_digest: str
    read_attempt_id: str
    template_version: str = CONTEXT_REPLY_TEMPLATE_VERSION
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or self.template_version != CONTEXT_REPLY_TEMPLATE_VERSION
                or type(self.namespace) is not NamespaceId):
            raise ValueError("unknown context reply result workflow")
        for name in (
            "authority_id", "authority_namespace", "installation_id",
            "c02_operation_id", "job_id", "acquire_operation_id", "original_operation_id",
            "call_id", "read_attempt_id",
        ):
            identifier(getattr(self, name), name)
        source = AtomKey.from_token(self.source_ref)
        if (source.type_name != "memory.source" or source.owner.kind != "event"
                or (source.owner.bot, source.owner.persona)
                   != self.namespace.as_tuple):
            raise ValueError("original C02 source crosses namespace")
        for name in ("model_request_digest", "frozen_input_digest"):
            value = getattr(self, name)
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class ContextReplyPaidResultReadV2:
    """Validated shape for a future Authority-issued paid, current result.

    Constructibility never authenticates this DTO. Only the pinned Authority
    result service may release one after its original terminal and current
    graph/Owner/D13 read fences all pass.
    """

    original_seal: ContextReplyOriginalSealV2
    frozen_request: FrozenContextReplyRequestV1
    read_attempt_id: str
    read_attempt_ordinal: int
    read_fence_operation_id: str
    read_fence_digest: str
    model_call_request_digest: str
    terminal_receipt: ModelTerminalReceiptV2
    provider_observation: ModelEgressObservationV1
    current_read_versions: tuple[GraphVersion, ...]
    current_guard_digest: str
    canonical_output: str
    output_digest: str
    status: str  # paid_current_source_verified_hold | no_reply_hold

    def __post_init__(self) -> None:
        seal = self.original_seal
        frozen = self.frozen_request
        receipt = self.terminal_receipt
        observed = self.provider_observation
        if (type(seal) is not ContextReplyOriginalSealV2
                or type(frozen) is not FrozenContextReplyRequestV1
                or type(receipt) is not ModelTerminalReceiptV2
                or type(observed) is not ModelEgressObservationV1
                or self.read_attempt_id != context_reply_read_attempt_id_v1(
                    seal.original_operation_id, self.read_attempt_ordinal)
                or self.read_fence_operation_id != self.read_attempt_id
                or not _SHA256.fullmatch(self.read_fence_digest)
                or not _SHA256.fullmatch(self.model_call_request_digest)
                or not _SHA256.fullmatch(self.current_guard_digest)
                or not _SHA256.fullmatch(self.output_digest)
                or type(self.current_read_versions) is not tuple
                or not self.current_read_versions
                or any(type(item) is not GraphVersion
                       for item in self.current_read_versions)
                or seal.template_version != CONTEXT_REPLY_TEMPLATE_VERSION
                or seal.installation_id != frozen.installation.installation_id
                or seal.provider_config_digest != frozen.installation.provider_config_digest
                or seal.frozen_input_digest != canonical_digest(asdict(frozen.input))
                or seal.model_request_digest != frozen.digest
                or (receipt.call_id, receipt.request_digest,
                    receipt.observation_digest, receipt.installation_id) !=
                   (seal.call_id, self.model_call_request_digest,
                    observed.digest, seal.installation_id)
                or (observed.call_id, observed.request_digest, observed.status) !=
                   (seal.call_id, self.model_call_request_digest, "completed")):
            raise ValueError("context reply paid/current identity differs")
        # The installed AstrBot adapter seals {"text": provider_message} in
        # the Authority observation. Parse only that exact field; its inner
        # JSON may have arbitrary whitespace or field order.
        result = json.loads(observed.result_json)
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise ValueError("context reply provider result shape differs")
        parsed = parse_context_reply_output_v1(result["text"], frozen)
        expected_status = ("no_reply_hold" if parsed.status == "no_reply_hold"
                           else "paid_current_source_verified_hold")
        if (self.status != expected_status
                or parsed.canonical_output != self.canonical_output
                or parsed.output_digest != self.output_digest):
            raise ValueError("context reply output state or digest differs")

    @property
    def body(self) -> str:
        """Content for D09 only after an actual Authority service read."""
        return json.loads(self.canonical_output)["body"]

    @property
    def provider_cost(self) -> tuple[tuple[str, int], ...]:
        return self.provider_observation.cost

    @property
    def provider_usage(self) -> tuple[tuple[str, int], ...]:
        return self.provider_observation.usage

    @property
    def original_seal_digest(self) -> str:
        return canonical_digest(asdict(self.original_seal))

    @property
    def provider_response_digest(self) -> str:
        return self.provider_observation.digest


def to_wire(value: ContextReplyResultReadRequestV1 |
            ContextReplyPaidResultReadV2) -> dict[str, object]:
    if type(value) not in {ContextReplyResultReadRequestV1,
                           ContextReplyPaidResultReadV2}:
        raise TypeError("typed context reply read wire required")
    data = json.loads(canonical_serialize(asdict(value)))
    if type(value) is ContextReplyPaidResultReadV2:
        from .v2_model_egress_contract import model_observation_to_wire_v1
        data["provider_observation"] = model_observation_to_wire_v1(value.provider_observation)
    return data


def from_wire(raw: object, kind: type):
    if kind not in {ContextReplyResultReadRequestV1,
                    ContextReplyPaidResultReadV2}:
        raise TypeError("typed context reply read kind required")
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("context reply read wire fields differ")
    data = dict(raw)
    if kind is ContextReplyResultReadRequestV1:
        data["namespace"] = NamespaceId(**data["namespace"])
    else:
        from ..runtime.context_reply_job_v2 import _frozen

        seal = dict(data["original_seal"])
        seal["namespace"] = NamespaceId(**seal["namespace"])
        data["original_seal"] = ContextReplyOriginalSealV2(**seal)
        data["frozen_request"] = _frozen(data["frozen_request"])
        data["terminal_receipt"] = ModelTerminalReceiptV2(**data["terminal_receipt"])
        from .v2_model_egress_contract import model_observation_from_wire_v1
        data["provider_observation"] = model_observation_from_wire_v1(data["provider_observation"])
        data["current_read_versions"] = tuple(GraphVersion(
            AtomKey(Owner(**item["key"]["owner"]),
                    item["key"]["type_name"], item["key"]["name"]),
            item["revision"]) for item in data["current_read_versions"])
    result = kind(**data)
    if to_wire(result) != raw:
        raise ValueError("context reply read wire is noncanonical")
    return result


__all__ = [
    "SCHEMA", "ContextReplyResultReadRequestV1", "ContextReplyPaidResultReadV2",
    "context_reply_read_attempt_id_v1",
    "to_wire", "from_wire",
]
