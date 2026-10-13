"""Frozen D13 asynchronous extractive-compression model boundary.

This module freezes a source window and provider wire, then parses provider text
as an untrusted candidate. ``compile_untrusted_d13_candidate_v1`` hands that
exact text to D13/W14's ``compile_extractive_model_output`` for source checking.
Neither operation proves that a model call happened, that a job is settled, that
a current graph fence is valid, or that a block is active/cache-hit/token-budgeted.
The supplied read set and epochs are frozen, but the public D13 projection does
not itself establish complete correction ancestry. W01 must recompute and
authenticate the current source, correction, access, audience, and deletion fence;
the broker never treats a read-set digest as that proof.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from ..runtime_contracts import (
    CommandEnvelope, CompressedTurnBlockV2,
    ConversationWindowProjectionV1,
    VersionedRef,
    canonical_digest,
    canonical_serialize,
)
from ..domains.d13.precompression import (
    EXTRACTIVE_OUTPUT_SCHEMA,
    PrecompressionPlan,
    _fingerprint,
    compile_extractive_model_output,
)
from .broker import ModelCallRequest
INPUT_SCHEMA = "d13.precompression_model_input.v1"
TEMPLATE_VERSION = "d13.precompression_model_workflow.v1"
MAX_OUTPUT_BYTES = 65_536
MAX_TURNS = 64
MAX_DETAILS_PER_TURN = 4
_TTL_SECONDS = 72 * 3600

SYSTEM_MESSAGE = (
    "Compress only the supplied closed raw turns into one short chronological beat "
    "per turn and up to four exact detail excerpts per turn. Return only JSON with "
    "exactly schema and turns; schema is d13.extractive_model_output.v1; each turn "
    "has exactly sequence, beat, details. Preserve order, speakers, negation, "
    "corrections, conditions, and unknown/failure states. If a turn contains a "
    "qualifier such as negation, correction, condition, failure, timeout, or unknown, "
    "its beat must reproduce the full original turn exactly. Every beat and detail "
    "must be an exact substring of its own source turn. Omitted text remains omitted, "
    "not disproven. Do not add identity, source, access, deletion, job, activation, "
    "cost, token-count, cache-hit, or permission claims."
)
TEMPLATE_DIGEST = canonical_digest({
    "version": TEMPLATE_VERSION, "input_schema": INPUT_SCHEMA,
    "output_schema": EXTRACTIVE_OUTPUT_SCHEMA, "system_prompt": SYSTEM_MESSAGE,
})


@dataclass(frozen=True, slots=True)
class D13ModelMessageV1:
    role: str
    content: str


@dataclass(frozen=True, slots=True)
class D13PrecompressionInstallationV1:
    """Neutral D13 copy of the host-selected conversation-model identity.

    W09 must build this from the actual conversation main workflow, never from
    optional natural-generation or natural-review workflow installations.
    Authority validates the selected identity against the live main workflow.
    """

    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    max_output_tokens: int

    def __post_init__(self) -> None:
        for name in ("installation_id", "provider_id", "model_id"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"{name} must be nonempty")
        digest = self.provider_config_digest
        if (type(digest) is not str or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("provider_config_digest must be lowercase SHA-256")
        if type(self.max_output_tokens) is not int or self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")


@dataclass(frozen=True, slots=True)
class FrozenD13PrecompressionRequestV1:
    window: ConversationWindowProjectionV1
    plan: PrecompressionPlan
    turns: tuple
    installation: D13PrecompressionInstallationV1
    canonical_input: str
    messages: tuple[D13ModelMessageV1, D13ModelMessageV1]
    messages_wire: str
    canonical_wire: str
    digest: str
    wire_digest: str
    read_closure_digest: str
    output_schema: str = EXTRACTIVE_OUTPUT_SCHEMA
    template_version: str = TEMPLATE_VERSION


@dataclass(frozen=True, slots=True)
class UntrustedD13PrecompressionOutputV1:
    frozen_input_digest: str
    wire_digest: str
    plan_input_digest: str
    output_digest: str
    model_text: str
    status: str = "untrusted_extractive_candidate"


@dataclass(frozen=True, slots=True)
class D13ExactTokenCountV1:
    """Host tokenizer result bound to the exact main-model request messages."""

    provider_id: str
    model_id: str
    provider_config_digest: str
    messages_digest: str
    wire_digest: str
    input_tokens: int
    tokenizer_fingerprint: str
    quality: str = "exact"

    def __post_init__(self) -> None:
        if any(type(getattr(self, name)) is not str or not getattr(self, name).strip()
               for name in ("provider_id", "model_id", "tokenizer_fingerprint")):
            raise ValueError("token count must identify the installed tokenizer/model")
        for name in ("provider_config_digest", "messages_digest", "wire_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"{name} must be lowercase SHA-256")
        if type(self.input_tokens) is not int or self.input_tokens <= 0:
            raise ValueError("exact input token count must be positive")


@dataclass(frozen=True, slots=True)
class D13PrecompressionCallGateV1:
    status: str
    frozen_input_digest: str
    wire_digest: str
    exact_input_tokens: int | None
    reason: str | None

    def __post_init__(self) -> None:
        if self.status not in {"ready", "hold"}:
            raise ValueError("unknown D13 call gate status")
        if ((self.status == "ready") != (self.reason is None)
                or (self.exact_input_tokens is not None
                    and (type(self.exact_input_tokens) is not int
                         or self.exact_input_tokens <= 0))):
            raise ValueError("D13 gate status and token evidence differ")


def _planned_turns_shape_v1(
    window: ConversationWindowProjectionV1, plan: PrecompressionPlan,
) -> tuple:
    if (type(window) is not ConversationWindowProjectionV1
            or type(plan) is not PrecompressionPlan):
        raise TypeError("typed D13 window and precompression plan required")
    if (type(plan.first_sequence) is not int or type(plan.last_sequence) is not int
            or plan.first_sequence < 0 or plan.last_sequence < plan.first_sequence
            or plan.last_sequence - plan.first_sequence + 1 > MAX_TURNS):
        raise ValueError("planned source window is outside turn bounds")
    turns = tuple(turn for turn in window.turns
                  if plan.first_sequence <= turn.sequence <= plan.last_sequence)
    if (len(turns) != plan.last_sequence - plan.first_sequence + 1
            or not turns or turns[0].sequence != plan.first_sequence
            or turns[-1].sequence != plan.last_sequence
            or any(right.sequence != left.sequence + 1
                   for left, right in zip(turns, turns[1:]))
            or window.scene_ref != plan.scene_ref
            or window.audience_ref != plan.audience_ref
            or (window.access_epoch, window.delete_epoch, window.activation_epoch)
               != (plan.access_epoch, plan.delete_epoch, plan.activation_epoch)
            or window.trusted_utc >= plan.expires_at_utc
            or plan.expires_at_utc > turns[0].trusted_utc + _TTL_SECONDS
            or any(start <= plan.last_sequence and end >= plan.first_sequence
                   for start, end in window.missing_ranges)):
        raise ValueError("stale, incomplete, or out-of-lifetime source window")
    expected_dependencies = tuple(dict.fromkeys(
        ref for turn in turns for ref in (turn.raw_ref, turn.source_ref, turn.access_ref)
    ))
    if (type(plan.source_dependencies) is not tuple
            or set(plan.source_dependencies) != set(expected_dependencies)
            or len(plan.source_dependencies) != len(expected_dependencies)
            or not {plan.scene_ref, plan.audience_ref, *expected_dependencies}
               .issubset(set(window.read_set))):
        raise ValueError("source/access/read closure differs from frozen window")
    if any(turn.audience_ref != window.audience_ref
           or turn.conversation_ref != window.conversation_ref for turn in turns):
        raise ValueError("planned turns cross conversation or audience")
    return turns



def _planned_turns(window,plan):
    turns=_planned_turns_shape_v1(window,plan)
    if _fingerprint(window,turns)!=plan.input_digest:
        raise ValueError("stale, incomplete, or out-of-lifetime source window")
    return turns

def _d13_read_closure_value_v1(window):
    return {
        "read_set": window.read_set,
        "source_dependencies": window.source_dependencies,
        "access_epoch": window.access_epoch,
        "delete_epoch": window.delete_epoch,
        "activation_epoch": window.activation_epoch,
    }


def _d13_frozen_payload_value_v1(window,plan,turns,read_closure_digest):
    return {
        "schema": INPUT_SCHEMA,
        "template_version": TEMPLATE_VERSION,
        "output_schema": EXTRACTIVE_OUTPUT_SCHEMA,
        "scope": {
            "namespace": asdict(window.namespace),
            "owner_ref": window.owner_ref,
            "conversation_ref": window.conversation_ref,
            "scene_ref": asdict(window.scene_ref),
            "audience_ref": asdict(window.audience_ref),
            "access_epoch": window.access_epoch,
            "delete_epoch": window.delete_epoch,
            "activation_epoch": window.activation_epoch,
            "order_watermark": window.order_watermark,
            "trusted_utc": window.trusted_utc,
            "expires_at_utc": plan.expires_at_utc,
            "read_closure_digest": read_closure_digest,
            "missing_ranges": [list(item) for item in window.missing_ranges],
        },
        "plan": {
            "input_digest": plan.input_digest,
            "first_sequence": plan.first_sequence,
            "last_sequence": plan.last_sequence,
            "scene_ref": asdict(plan.scene_ref),
            "audience_ref": asdict(plan.audience_ref),
            "access_epoch": plan.access_epoch,
            "delete_epoch": plan.delete_epoch,
            "activation_epoch": plan.activation_epoch,
        },
        "turns": [{
            "sequence": turn.sequence,
            "speaker_ref": turn.speaker_ref,
            "trusted_utc": turn.trusted_utc,
            "text": turn.text,
            "delivery_state": turn.delivery_state,
            "tool_state": turn.tool_state,
        } for turn in turns],
    }


def _d13_frozen_wire_value_v1(installation,messages):
    return {
        "installation_id": installation.installation_id,
        "provider_id": installation.provider_id,
        "model_id": installation.model_id,
        "provider_config_digest": installation.provider_config_digest,
        "messages": [asdict(message) for message in messages],
        "max_output_tokens": installation.max_output_tokens,
    }


def freeze_d13_precompression_request_v1(
    window: ConversationWindowProjectionV1,
    plan: PrecompressionPlan,
    installation: D13PrecompressionInstallationV1,
) -> FrozenD13PrecompressionRequestV1:
    """Freeze exact turns using a host-selected conversation model identity.

    W09 must construct this from the actual conversation main workflow. D13
    does not infer main-model identity from optional natural workflows.
    """
    if type(installation) is not D13PrecompressionInstallationV1:
        raise TypeError("installed main-conversation model workflow is required")
    turns = _planned_turns(window, plan)
    read_closure_digest=canonical_digest(_d13_read_closure_value_v1(window))
    payload=_d13_frozen_payload_value_v1(window,plan,turns,read_closure_digest)
    canonical_input = canonical_serialize(payload)
    messages = (
        D13ModelMessageV1("system", SYSTEM_MESSAGE),
        D13ModelMessageV1("user", canonical_input),
    )
    messages_wire = canonical_serialize([asdict(message) for message in messages])
    wire=canonical_serialize(_d13_frozen_wire_value_v1(installation,messages))
    return FrozenD13PrecompressionRequestV1(
        window, plan, turns, installation, canonical_input, messages,
        messages_wire, wire, canonical_digest(payload),
        sha256(wire.encode("utf-8")).hexdigest(), read_closure_digest,
    )


def _d13_typed_window_plan_v1(data):
    from ..runtime_contracts import CompletedTurnV1,NamespaceId,VersionedRef
    window_data = data["window"]
    window = ConversationWindowProjectionV1(**{
        **window_data, "namespace": NamespaceId(**window_data["namespace"]),
        "scene_ref": VersionedRef(**window_data["scene_ref"]),
        "audience_ref": VersionedRef(**window_data["audience_ref"]),
        "turns": tuple(CompletedTurnV1(**{
            **turn, **{name: VersionedRef(**turn[name]) for name in
                       ("audience_ref", "raw_ref", "source_ref", "access_ref")},
        }) for turn in window_data["turns"]),
        "source_dependencies": tuple(VersionedRef(**ref)
                                     for ref in window_data["source_dependencies"]),
        "read_set": tuple(VersionedRef(**ref) for ref in window_data["read_set"]),
        "missing_ranges": tuple(tuple(pair) for pair in window_data["missing_ranges"]),
    })
    plan_data = data["plan"]
    plan = PrecompressionPlan(**{
        **plan_data, "scene_ref": VersionedRef(**plan_data["scene_ref"]),
        "audience_ref": VersionedRef(**plan_data["audience_ref"]),
        "source_dependencies": tuple(VersionedRef(**ref)
                                     for ref in plan_data["source_dependencies"]),
    })
    return window,plan


def thaw_d13_precompression_request_v1(raw: str) -> FrozenD13PrecompressionRequestV1:
    """Restore the saved frozen wire and reject every noncanonical variation."""
    from ..runtime_contracts import CompletedTurnV1, NamespaceId, VersionedRef

    data = json.loads(raw)
    window,plan=_d13_typed_window_plan_v1(data)
    frozen = freeze_d13_precompression_request_v1(
        window, plan, D13PrecompressionInstallationV1(**data["installation"]))
    if canonical_serialize(asdict(frozen)) != raw:
        raise ValueError("saved D13 frozen wire changed")
    return frozen


def gate_d13_exact_token_count_v1(
    frozen: FrozenD13PrecompressionRequestV1,
    count: D13ExactTokenCountV1 | None,
    *,_prepared_paid_eof_v3=None,
) -> D13PrecompressionCallGateV1:
    """Check optional exact evidence for a frozen wire.

    An unavailable tokenizer leaves ``exact_input_tokens`` unknown. Paid
    dispatch then requires a separately authenticated signed D11 quote,
    reserved upper bound and Authority admission; this gate grants none of
    those. Never turn byte/character estimates into an exact token claim.
    """
    if type(frozen) is not FrozenD13PrecompressionRequestV1:
        raise TypeError("frozen D13 request required")
    messages_digest=None
    if _prepared_paid_eof_v3 is not None:
        from ..authority_service.d13_paid_block_verifier_v1 import PreparedD13PaidRequestEOFV3
        if type(_prepared_paid_eof_v3)is not PreparedD13PaidRequestEOFV3:
            raise ValueError('actual D13 Paid frozen EOF required')
        messages_digest=_prepared_paid_eof_v3.require_frozen_v3(frozen)['messages_wire']
    reason = None
    if count is not None and type(count) is not D13ExactTokenCountV1:
        reason = "token evidence has an unsupported type"
    elif count is not None and (count.quality != "exact"
          or count.provider_id != frozen.installation.provider_id
          or count.model_id != frozen.installation.model_id
          or count.provider_config_digest != frozen.installation.provider_config_digest
          or count.messages_digest != (sha256(frozen.messages_wire.encode('utf-8')).hexdigest() if _prepared_paid_eof_v3 is None else messages_digest)
          or count.wire_digest != frozen.wire_digest):
        reason = "token count is estimated or bound to another provider/model/config/wire"
    return D13PrecompressionCallGateV1(
        "hold" if reason else "ready", frozen.digest, frozen.wire_digest,
        count.input_tokens if reason is None and count is not None else None,
        reason,
    )


def _d13_model_request_fields_v1(envelope,frozen,*,call_id,timeout_seconds,privacy_tier):
    if type(envelope)is not CommandEnvelope or type(frozen)is not FrozenD13PrecompressionRequestV1:
        raise TypeError('typed D13 envelope and frozen request required')
    if (envelope.identity.phase!='d13.precompress' or envelope.authority.issuer_domain!='d13'
            or envelope.authority.namespace!=frozen.window.namespace
            or envelope.identity.operation_id!=frozen.plan.job_ref
            or type(envelope.authority.worker_fence)is not int or envelope.authority.worker_fence<1):
        raise ValueError('D13 model request differs from original job scope')
    return dict(envelope=envelope,call_id=call_id,provider_id=frozen.installation.provider_id,
        model_id=frozen.installation.model_id,required_capabilities=frozenset({'text'}),privacy_tier=privacy_tier,
        prompt_template_digest=TEMPLATE_DIGEST,payload={'system_prompt':SYSTEM_MESSAGE,'prompt':frozen.canonical_input},
        timeout_seconds=timeout_seconds,max_output_tokens=frozen.installation.max_output_tokens)


def issue_unadmitted_d13_model_request_v1(
    envelope: CommandEnvelope,
    frozen: FrozenD13PrecompressionRequestV1,
    *,
    call_id: str,
    timeout_seconds: float,
    privacy_tier: str,
) -> ModelCallRequest:
    """Shape a call from a frozen D13 source; this does not admit paid egress.

    W01 must authenticate the durable job, current read fence and D11 originals;
    W09 must recheck the selected main workflow before dispatch. An exact
    pre-call count is optional; W01 must reserve the signed upper bound.
    """
    request=ModelCallRequest(**_d13_model_request_fields_v1(envelope,frozen,call_id=call_id,
        timeout_seconds=timeout_seconds,privacy_tier=privacy_tier))
    if not d13_model_request_shape_valid_v1(request, frozen):
        raise ValueError("D13 model request differs from frozen wire")
    return request


def d13_model_request_shape_valid_v1(
    request: ModelCallRequest,
    frozen: FrozenD13PrecompressionRequestV1,
) -> bool:
    """Check the fixed chat payload against the complete frozen wire identity."""
    if type(request) is not ModelCallRequest or type(frozen) is not FrozenD13PrecompressionRequestV1:
        return False
    try:
        expected = freeze_d13_precompression_request_v1(
            frozen.window, frozen.plan, frozen.installation)
    except (TypeError, ValueError):
        return False
    installation = frozen.installation
    return (
        frozen == expected
        and request.identity.phase == "d13.precompress"
        and request.envelope.authority.issuer_domain == "d13"
        and request.envelope.authority.namespace == frozen.window.namespace
        and request.identity.operation_id == frozen.plan.job_ref
        and type(request.envelope.authority.worker_fence) is int
        and request.envelope.authority.worker_fence >= 1
        and request.provider_id == installation.provider_id
        and request.model_id == installation.model_id
        and request.required_capabilities == frozenset({"text"})
        and request.max_output_tokens == installation.max_output_tokens
        and request.prompt_template_digest == TEMPLATE_DIGEST
        and set(request.payload) == {"system_prompt", "prompt"}
        and request.payload["system_prompt"] == SYSTEM_MESSAGE
        and request.payload["prompt"] == frozen.canonical_input
    )


def parse_d13_precompression_output_v1(
    model_text: str, frozen: FrozenD13PrecompressionRequestV1,
) -> UntrustedD13PrecompressionOutputV1:
    """Parse bounded JSON shape; W14 must still validate every source excerpt."""
    if (type(model_text) is not str or not 0 < len(model_text.encode("utf-8")) <= MAX_OUTPUT_BYTES
            or type(frozen) is not FrozenD13PrecompressionRequestV1):
        raise ValueError("bounded model text and frozen D13 request required")

    def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("D13 model output repeats a field")
            result[key] = value
        return result

    try:
        data = json.loads(model_text, object_pairs_hook=unique_fields)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("D13 model output is not valid JSON") from exc
    if (type(data) is not dict or set(data) != {"schema", "turns"}
            or data["schema"] != EXTRACTIVE_OUTPUT_SCHEMA
            or type(data["turns"]) is not list
            or len(data["turns"]) != len(frozen.turns)):
        raise ValueError("D13 model output shape or planned coverage differs")
    for source, item in zip(frozen.turns, data["turns"]):
        if (type(item) is not dict or set(item) != {"sequence", "beat", "details"}
                or type(item["sequence"]) is not int
                or item["sequence"] != source.sequence
                or type(item["beat"]) is not str or not item["beat"]
                or len(item["beat"]) > len(source.text)
                or type(item["details"]) is not list
                or len(item["details"]) > MAX_DETAILS_PER_TURN
                or any(type(detail) is not str or not detail
                       or len(detail) > len(source.text) for detail in item["details"])):
            raise ValueError("D13 model output turn shape or order differs")
    return UntrustedD13PrecompressionOutputV1(
        frozen.digest, frozen.wire_digest, frozen.plan.input_digest,
        sha256(model_text.encode("utf-8")).hexdigest(), model_text,
    )


def compile_untrusted_d13_candidate_v1(
    frozen: FrozenD13PrecompressionRequestV1,
    candidate: UntrustedD13PrecompressionOutputV1,
) -> CompressedTurnBlockV2:
    """Submit the same frozen source and exact model bytes to W14's compiler.

    This returns an unadopted ``status='candidate'`` block only. Callers must
    independently authenticate the original async paid call and ask W01 to
    verify the current source/read fence before any durable acceptance.
    """
    if (type(frozen) is not FrozenD13PrecompressionRequestV1
            or type(candidate) is not UntrustedD13PrecompressionOutputV1
            or candidate.frozen_input_digest != frozen.digest
            or candidate.wire_digest != frozen.wire_digest
            or candidate.plan_input_digest != frozen.plan.input_digest
            or candidate.output_digest != sha256(candidate.model_text.encode("utf-8")).hexdigest()):
        raise ValueError("untrusted D13 candidate is not bound to this frozen input")
    block = compile_extractive_model_output(frozen.window, frozen.plan, candidate.model_text)
    if block.status != "candidate":
        raise ValueError("W14 returned a non-candidate block")
    return block


__all__ = [
    "INPUT_SCHEMA", "TEMPLATE_VERSION", "TEMPLATE_DIGEST", "D13PrecompressionInstallationV1",
    "D13ExactTokenCountV1",
    "D13PrecompressionCallGateV1", "gate_d13_exact_token_count_v1",
    "D13ModelMessageV1", "FrozenD13PrecompressionRequestV1",
    "UntrustedD13PrecompressionOutputV1", "freeze_d13_precompression_request_v1",
    "thaw_d13_precompression_request_v1",
    "issue_unadmitted_d13_model_request_v1", "d13_model_request_shape_valid_v1",
    "parse_d13_precompression_output_v1", "compile_untrusted_d13_candidate_v1",
]
