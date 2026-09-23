"""D09 dialogue and expression candidates for the Sylanne 3 alpha1 runtime.

D09 never authorizes an action and never sends to a platform.  It consumes a
frozen D08 grant view, verifies claim-qualified finite segments, and prepares
references that D11 may independently admit.  Transport observations remain
external facts owned by D11.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Callable

from ..d08 import CommunicationIntentGrant, SegmentGrant
from ...graph_types import TypeSpec
from ...runtime_contracts import (
    DomainProposal,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    canonical_digest,
    schema_hash,
)


_D09_PROPOSAL_SCHEMA = "d09.proposal.v1"
_D09_PROPOSAL_SCHEMA_HASH = schema_hash({"domain": "d09", "proposal": 1})


def _nonempty(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _names(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    for item in value:
        _nonempty(item, f"{label} item")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must contain unique values")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _finite(value: object, label: str, *, minimum: float = 0.0, maximum: float | None = None) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    result = float(value)
    if result < minimum or (maximum is not None and result > maximum):
        raise ValueError(f"{label} is outside its allowed range")
    return result


class ClaimKind(Enum):
    EXTERNAL_FACT = "external_fact"
    REPORTED_CLAIM = "reported_claim"
    SUBJECTIVE_JUDGMENT = "subjective_judgment"
    SELF_UNDERSTANDING = "self_understanding"
    INTERNAL_ACTIVITY = "internal_activity"
    SIMULATED = "simulated"
    RHETORIC = "rhetoric"


@dataclass(frozen=True)
class ExpressionClaim:
    claim_id: str
    text: str
    kind: ClaimKind
    source_refs: tuple[str, ...]
    allowed_audiences: tuple[str, ...]
    eligibility: tuple[str, ...]
    disclosure_ref: str

    def __post_init__(self) -> None:
        _nonempty(self.claim_id, "claim_id")
        _nonempty(self.text, "text")
        if not isinstance(self.kind, ClaimKind):
            raise TypeError("kind must be ClaimKind")
        _names(self.source_refs, "source_refs", allow_empty=self.kind is ClaimKind.RHETORIC)
        _names(self.allowed_audiences, "allowed_audiences", allow_empty=False)
        eligibility = _names(self.eligibility, "eligibility", allow_empty=False)
        if "expression" not in eligibility:
            raise ValueError("claim is not eligible for expression")
        _nonempty(self.disclosure_ref, "disclosure_ref")


@dataclass(frozen=True)
class ExpressionBlueprint:
    intent_ref: str
    action_id: str
    intent_revision: int
    target_ref: str
    audiences: tuple[str, ...]
    scene_ref: str
    conversation_epoch: int
    required_slots: tuple[str, ...]
    claims: tuple[ExpressionClaim, ...]
    segment_grants: tuple[SegmentGrant, ...]
    valid_until: float
    cancellation_epoch: int


@dataclass(frozen=True)
class BlueprintResult:
    status: str
    blueprint: ExpressionBlueprint | None
    missing: tuple[str, ...]


@dataclass(frozen=True)
class ClaimUse:
    claim_ref: str
    start: int
    end: int
    asserted_as: ClaimKind

    def __post_init__(self) -> None:
        _nonempty(self.claim_ref, "claim_ref")
        _nonnegative_int(self.start, "start")
        _nonnegative_int(self.end, "end")
        if self.end <= self.start:
            raise ValueError("claim span must be nonempty")
        if not isinstance(self.asserted_as, ClaimKind):
            raise TypeError("asserted_as must be ClaimKind")


def segment_payload_digest(
    body: str,
    media_refs: tuple[str, ...],
    claim_uses: tuple[ClaimUse, ...],
) -> str:
    """Digest the complete immutable visible segment payload."""

    _nonempty(body, "body")
    _names(media_refs, "media_refs")
    if type(claim_uses) is not tuple or any(not isinstance(item, ClaimUse) for item in claim_uses):
        raise TypeError("claim_uses must be a tuple of ClaimUse")
    uses = tuple(sorted(claim_uses, key=lambda item: (item.start, item.end)))
    return canonical_digest({
        "body": body,
        "media_refs": list(media_refs),
        "claim_uses": [
            {"claim_ref": use.claim_ref, "start": use.start, "end": use.end,
             "asserted_as": use.asserted_as.value}
            for use in uses
        ],
    })


@dataclass(frozen=True)
class SegmentCandidate:
    segment_id: str
    effect_id: str
    body: str
    claim_uses: tuple[ClaimUse, ...]
    covered_slots: tuple[str, ...]
    media_refs: tuple[str, ...]
    delay_seconds: float

    def __post_init__(self) -> None:
        _nonempty(self.segment_id, "segment_id")
        _nonempty(self.effect_id, "effect_id")
        _nonempty(self.body, "body")
        if type(self.claim_uses) is not tuple or any(not isinstance(item, ClaimUse) for item in self.claim_uses):
            raise TypeError("claim_uses must be a tuple of ClaimUse")
        _names(self.covered_slots, "covered_slots")
        _names(self.media_refs, "media_refs")
        object.__setattr__(self, "delay_seconds", _finite(self.delay_seconds, "delay_seconds"))


@dataclass(frozen=True)
class VerifiedSegment:
    intent_ref: str
    action_id: str
    segment_id: str
    effect_id: str
    position: int
    payload_digest: str
    body: str
    claim_uses: tuple[ClaimUse, ...]
    covered_slots: tuple[str, ...]
    media_refs: tuple[str, ...]
    prerequisite_segment_ref: str | None
    audiences: tuple[str, ...]


@dataclass(frozen=True)
class StagingResult:
    status: str
    segments: tuple[VerifiedSegment, ...]
    failures: tuple[str, ...]
    missing_slots: tuple[str, ...]


@dataclass(frozen=True)
class AdmissionReceipt:
    admission_ref: str
    segment_id: str
    effect_id: str
    payload_digest: str
    status: str

    def __post_init__(self) -> None:
        for name in ("admission_ref", "segment_id", "effect_id", "payload_digest"):
            _nonempty(getattr(self, name), name)
        if self.status not in {"admitted", "handed_off", "accepted", "unknown", "rejected"}:
            raise ValueError("unknown D11 admission status")


@dataclass(frozen=True)
class DeliveryPreparation:
    status: str
    admitted_segment_refs: tuple[str, ...]
    blocked_segment_refs: tuple[str, ...]
    missing: tuple[str, ...]


@dataclass(frozen=True)
class DeliveryObservation:
    segment_id: str
    effect_id: str
    transport_status: str
    provider_receipt_ref: str
    read_proof_ref: str | None

    def __post_init__(self) -> None:
        for name in ("segment_id", "effect_id", "provider_receipt_ref"):
            _nonempty(getattr(self, name), name)
        if self.transport_status not in {"known_not_accepted", "handed_off", "accepted", "unknown", "rejected"}:
            raise ValueError("unknown transport status")
        if self.read_proof_ref is not None:
            _nonempty(self.read_proof_ref, "read_proof_ref")


@dataclass(frozen=True)
class DialogueProgress:
    segment_id: str
    effect_id: str
    delivery_state: str
    read_state: str
    agreement_state: str
    receipt_refs: tuple[str, ...]


@dataclass(frozen=True)
class TopicThread:
    thread_id: str
    topic: str
    question_slots: tuple[str, ...]
    answered_slots: tuple[str, ...]
    return_condition: str
    state: str

    def __post_init__(self) -> None:
        for name in ("thread_id", "topic", "return_condition"):
            _nonempty(getattr(self, name), name)
        _names(self.question_slots, "question_slots")
        _names(self.answered_slots, "answered_slots")
        if not set(self.answered_slots).issubset(set(self.question_slots)):
            raise ValueError("answered_slots must be question slots")
        if self.state not in {"open", "waiting", "closed", "superseded"}:
            raise ValueError("unknown topic state")

    @property
    def unanswered_slots(self) -> tuple[str, ...]:
        return tuple(item for item in self.question_slots if item not in self.answered_slots)


@dataclass(frozen=True)
class ConversationTrack:
    track_id: str
    scene_ref: str
    conversation_epoch: int
    threads: tuple[TopicThread, ...]
    exposed_segment_refs: tuple[str, ...]
    unknown_segment_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _nonempty(self.track_id, "track_id")
        _nonempty(self.scene_ref, "scene_ref")
        _nonnegative_int(self.conversation_epoch, "conversation_epoch")
        if type(self.threads) is not tuple or any(not isinstance(item, TopicThread) for item in self.threads):
            raise TypeError("threads must be a tuple of TopicThread")
        if len({item.thread_id for item in self.threads}) != len(self.threads):
            raise ValueError("thread IDs must be unique")
        _names(self.exposed_segment_refs, "exposed_segment_refs")
        _names(self.unknown_segment_refs, "unknown_segment_refs")
        if self.status not in {"active", "interrupted", "waiting", "closed"}:
            raise ValueError("unknown conversation status")

    @property
    def unanswered_slots(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(slot for thread in self.threads for slot in thread.unanswered_slots))


def _strict_graph_validator(
    expected_schema: str,
    field_types: tuple[tuple[str, str], ...],
) -> Callable[[dict], None]:
    allowed = {"schema", *(name for name, _ in field_types)}

    def validate(value: dict) -> None:
        if type(value) is not dict:
            raise TypeError("graph value must be a dict")
        if set(value) != allowed:
            missing = sorted(allowed - set(value))
            unknown = sorted(set(value) - allowed)
            raise ValueError(f"graph schema fields mismatch: missing={missing}, unknown={unknown}")
        if value.get("schema") != expected_schema:
            raise ValueError(f"graph value schema must be {expected_schema}")
        for name, kind in field_types:
            item = value[name]
            if kind == "str":
                _nonempty(item, name)
            elif kind == "int":
                _nonnegative_int(item, name)
            elif kind == "positive_int":
                _nonnegative_int(item, name)
                if item < 1:
                    raise ValueError(f"{name} must be positive")
            elif kind == "digest":
                _nonempty(item, name)
                if len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item):
                    raise ValueError(f"{name} must be a lowercase SHA-256 digest")
            elif kind == "str_list":
                if type(item) is not list or any(type(part) is not str or not part for part in item):
                    raise ValueError(f"{name} must be a string list")
                if len(set(item)) != len(item):
                    raise ValueError(f"{name} must contain unique values")
            elif kind.startswith("enum:"):
                allowed_values = frozenset(kind.removeprefix("enum:").split("|"))
                if item not in allowed_values:
                    raise ValueError(f"{name} has an unknown status")
            else:
                raise RuntimeError(f"unsupported validator kind: {kind}")

    return validate


class D09ExpressionProvider:
    """Pure expression verifier.  It intentionally has no platform-send API."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            "d09.expression", RUNTIME_SCHEMA,
            _D09_PROPOSAL_SCHEMA_HASH,
            schema_hash({"domain": "d09", "response": 1}),
            ("persona", "activity"), ("structured_text", "media_refs"),
            ("expression", "audit"), ("runtime",), "bounded", "cooperative",
            "operation_and_segment_effect", "runtime_receipt", ("verify", "stage"),
            ("resume_from_receipts",),
        )

    @staticmethod
    def register_types() -> tuple[TypeSpec, ...]:
        definitions = (
            ("d09.conversation_track.v1", ("persona",), "state", False, (
                ("track_id", "str"), ("scene_ref", "str"), ("conversation_epoch", "int"),
                ("thread_refs", "str_list"), ("exposed_segment_refs", "str_list"),
                ("unknown_segment_refs", "str_list"),
                ("status", "enum:active|interrupted|waiting|closed"), ("version", "positive_int"),
            )),
            ("d09.topic_thread.v1", ("scene",), "state", False, (
                ("thread_id", "str"), ("topic", "str"), ("question_slots", "str_list"),
                ("answered_slots", "str_list"),
                ("state", "enum:open|waiting|closed|superseded"), ("version", "positive_int"),
            )),
            ("d09.expression_blueprint.v1", ("activity",), "state", True, (
                ("blueprint_id", "str"), ("intent_ref", "str"), ("claim_refs", "str_list"),
                ("segment_refs", "str_list"), ("version", "positive_int"),
            )),
            ("d09.utterance_draft.v1", ("activity",), "cache", False, (
                ("draft_id", "str"), ("blueprint_ref", "str"), ("segment_refs", "str_list"),
                ("version", "positive_int"),
            )),
            ("d09.segment_plan.v1", ("activity",), "state", True, (
                ("segment_id", "str"), ("effect_id", "str"), ("payload_digest", "digest"),
                ("claim_refs", "str_list"), ("version", "positive_int"),
            )),
            ("d09.dialogue_progress.v1", ("activity",), "projection", False, (
                ("progress_id", "str"), ("segment_id", "str"),
                ("delivery_state", "enum:prepared|verified|admitted|handed_off|accepted|unknown|rejected|superseded"),
                ("receipt_refs", "str_list"), ("version", "positive_int"),
            )),
        )
        return tuple(TypeSpec(
            name=name,
            owner_kinds=owners,
            storage_role=role,
            validator=_strict_graph_validator(name, fields),
            immutable=immutable,
            schema_version=1,
            writer_domain="d09",
            schema_hash=schema_hash({
                "domain": "d09", "type": name, "owners": owners, "role": role,
                "immutable": immutable, "fields": fields, "version": 1,
            }),
        ) for name, owners, role, immutable, fields in definitions)

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d09" or proposal.proposal_schema != _D09_PROPOSAL_SCHEMA:
            raise ValueError("proposal is not a D09 expression proposal")
        if proposal.proposal_schema_hash != _D09_PROPOSAL_SCHEMA_HASH:
            raise ValueError("D09 proposal schema hash is not recognized")
        specs = {spec.name: spec for spec in self.register_types()}
        for write in proposal.typed_writes:
            spec = specs.get(write.key.type_name)
            if (
                spec is None
                or spec.writer_domain != "d09"
                or write.key.owner.kind not in spec.owner_kinds
            ):
                raise ValueError("D09 proposal contains an unauthorized graph type or owner")
            spec.validator(write.value)
        return proposal

    @staticmethod
    def prepare_blueprint(
        intent: CommunicationIntentGrant | None,
        scene_ref: str,
        conversation_epoch: int,
        claims: tuple[ExpressionClaim, ...],
        *,
        now: float,
    ) -> BlueprintResult:
        _nonempty(scene_ref, "scene_ref")
        _nonnegative_int(conversation_epoch, "conversation_epoch")
        _finite(now, "now")
        if intent is None:
            return BlueprintResult("unavailable", None, ("d08_intent",))
        if not isinstance(intent, CommunicationIntentGrant):
            raise TypeError("intent must be CommunicationIntentGrant or None")
        if type(claims) is not tuple or any(not isinstance(item, ExpressionClaim) for item in claims):
            raise TypeError("claims must be a tuple of ExpressionClaim")
        if intent.valid_until < now:
            return BlueprintResult("stale", None, ("d08_intent_expired",))
        if len({item.claim_id for item in claims}) != len(claims):
            raise ValueError("claim IDs must be unique")
        missing = []
        for item in claims:
            if item.kind.value not in intent.allowed_claim_kinds:
                missing.append(f"claim_kind:{item.claim_id}")
            if not set(intent.audiences).issubset(set(item.allowed_audiences)):
                missing.append(f"audience:{item.claim_id}")
        if missing:
            return BlueprintResult("unavailable", None, tuple(missing))
        return BlueprintResult("complete", ExpressionBlueprint(
            intent.intent_ref, intent.action_id, intent.intent_revision, intent.target_ref,
            intent.audiences, scene_ref, conversation_epoch, intent.required_slots,
            claims, intent.segment_grants, intent.valid_until, intent.cancellation_epoch,
        ), ())

    @staticmethod
    def verify_and_stage(
        blueprint: ExpressionBlueprint,
        candidates: tuple[SegmentCandidate, ...],
    ) -> StagingResult:
        if not isinstance(blueprint, ExpressionBlueprint):
            raise TypeError("blueprint must be ExpressionBlueprint")
        if type(candidates) is not tuple or any(not isinstance(item, SegmentCandidate) for item in candidates):
            raise TypeError("candidates must be a tuple of SegmentCandidate")
        if not candidates or len(candidates) > 3:
            return StagingResult("rejected", (), ("segment_count",), blueprint.required_slots)
        claims = {item.claim_id: item for item in blueprint.claims}
        grants = {item.segment_id: item for item in blueprint.segment_grants}
        failures: list[str] = []
        verified: list[VerifiedSegment] = []
        covered: list[str] = []
        seen_segments = set()
        for candidate in candidates:
            grant = grants.get(candidate.segment_id)
            if grant is None or grant.effect_id != candidate.effect_id:
                failures.append("ungranted_segment")
                continue
            if candidate.segment_id in seen_segments:
                failures.append("duplicate_segment")
                continue
            seen_segments.add(candidate.segment_id)
            if len(candidate.body) > grant.max_chars:
                failures.append("segment_length")
            if candidate.delay_seconds > 2.0:
                failures.append("segment_delay")
            if not set(candidate.media_refs).issubset(set(grant.allowed_media)):
                failures.append("media_scope")
            uses = tuple(sorted(candidate.claim_uses, key=lambda item: (item.start, item.end)))
            cursor = 0
            for use in uses:
                mapped = claims.get(use.claim_ref)
                if mapped is None:
                    failures.append("unknown_claim")
                    continue
                if use.start < cursor or use.end > len(candidate.body):
                    failures.append("claim_span")
                    continue
                if any(ch.isalnum() for ch in candidate.body[cursor:use.start]):
                    failures.append("unmapped_content")
                if candidate.body[use.start:use.end] != mapped.text:
                    failures.append("claim_text_mismatch")
                if use.asserted_as is not mapped.kind:
                    failures.append("eligibility_upgrade")
                cursor = use.end
            if any(ch.isalnum() for ch in candidate.body[cursor:]):
                failures.append("unmapped_content")
            covered.extend(candidate.covered_slots)
            payload_digest = segment_payload_digest(candidate.body, candidate.media_refs, uses)
            if payload_digest != grant.payload_digest:
                failures.append("payload_digest_mismatch")
            verified.append(VerifiedSegment(
                blueprint.intent_ref, blueprint.action_id, candidate.segment_id,
                candidate.effect_id, grant.position, payload_digest, candidate.body, uses,
                candidate.covered_slots, candidate.media_refs, grant.prerequisite_segment_ref,
                blueprint.audiences,
            ))
        if failures:
            return StagingResult("rejected", (), tuple(dict.fromkeys(failures)), ())
        missing = tuple(slot for slot in blueprint.required_slots if slot not in covered)
        if missing:
            return StagingResult("unavailable", (), (), missing)
        return StagingResult("complete", tuple(sorted(verified, key=lambda item: item.position)), (), ())

    @staticmethod
    def prepare_delivery(
        staged: StagingResult,
        intent: CommunicationIntentGrant | None,
        admissions: tuple[AdmissionReceipt, ...],
    ) -> DeliveryPreparation:
        if not isinstance(staged, StagingResult):
            raise TypeError("staged must be StagingResult")
        if intent is None:
            return DeliveryPreparation("unavailable", (), (), ("d08_intent",))
        if not isinstance(intent, CommunicationIntentGrant):
            raise TypeError("intent must be CommunicationIntentGrant or None")
        if staged.status != "complete":
            return DeliveryPreparation("unavailable", (), (), ("verified_segments",))
        if type(admissions) is not tuple or any(not isinstance(item, AdmissionReceipt) for item in admissions):
            raise TypeError("admissions must be a tuple of AdmissionReceipt")
        grants = {item.segment_id: item for item in intent.segment_grants}
        if any(
            segment.intent_ref != intent.intent_ref
            or segment.action_id != intent.action_id
            or segment.segment_id not in grants
            or grants[segment.segment_id].effect_id != segment.effect_id
            for segment in staged.segments
        ):
            return DeliveryPreparation("rejected", (), (), ("intent_mismatch",))
        admission_ids = tuple(item.segment_id for item in admissions)
        if len(set(admission_ids)) != len(admission_ids):
            return DeliveryPreparation("rejected", (), (), ("duplicate_admission",))
        by_segment = {item.segment_id: item for item in admissions}
        admitted: list[str] = []
        blocked: list[str] = []
        missing: list[str] = []
        status = "complete"
        terminal_by_segment: dict[str, str] = {}
        for segment in staged.segments:
            if segment.prerequisite_segment_ref is not None:
                preceding = terminal_by_segment.get(segment.prerequisite_segment_ref)
                if preceding != "accepted":
                    blocked.append(segment.segment_id)
                    if preceding == "unknown":
                        status = "pending_confirmation"
                    else:
                        status = "unavailable"
                    continue
            receipt = by_segment.get(segment.segment_id)
            if receipt is None:
                missing.append(f"d11_admission:{segment.segment_id}")
                status = "unavailable"
                continue
            if receipt.effect_id != segment.effect_id or receipt.payload_digest != segment.payload_digest:
                return DeliveryPreparation("rejected", tuple(admitted), tuple(blocked), ("admission_mismatch",))
            terminal_by_segment[segment.segment_id] = receipt.status
            if receipt.status == "unknown":
                status = "pending_confirmation"
            elif receipt.status == "rejected":
                status = "rejected"
                blocked.append(segment.segment_id)
            else:
                admitted.append(segment.segment_id)
        return DeliveryPreparation(status, tuple(admitted), tuple(blocked), tuple(missing))

    @staticmethod
    def settle_progress(observation: DeliveryObservation) -> DialogueProgress:
        if not isinstance(observation, DeliveryObservation):
            raise TypeError("observation must be DeliveryObservation")
        if observation.read_proof_ref is not None and observation.transport_status != "accepted":
            raise ValueError("read proof requires an accepted transport observation")
        read_state = "confirmed" if observation.read_proof_ref is not None else "unknown"
        refs = (observation.provider_receipt_ref,) + (
            (observation.read_proof_ref,) if observation.read_proof_ref is not None else ()
        )
        return DialogueProgress(
            observation.segment_id,
            observation.effect_id,
            observation.transport_status,
            read_state,
            "unknown",
            refs,
        )

    @staticmethod
    def update_dialogue_track(
        track: ConversationTrack,
        incoming: TopicThread,
        *,
        explicit_stop: bool,
    ) -> ConversationTrack:
        if not isinstance(track, ConversationTrack) or not isinstance(incoming, TopicThread):
            raise TypeError("track and incoming must be D09 dialogue values")
        threads = tuple(item for item in track.threads if item.thread_id != incoming.thread_id) + (incoming,)
        return ConversationTrack(
            track.track_id,
            track.scene_ref,
            track.conversation_epoch + 1,
            threads,
            track.exposed_segment_refs,
            track.unknown_segment_refs,
            "interrupted" if explicit_stop else "active",
        )


__all__ = [
    "AdmissionReceipt", "BlueprintResult", "ClaimKind", "ClaimUse", "CommunicationIntentGrant",
    "ConversationTrack", "D09ExpressionProvider", "DeliveryObservation", "DeliveryPreparation",
    "DialogueProgress", "ExpressionBlueprint", "ExpressionClaim", "SegmentCandidate", "SegmentGrant",
    "StagingResult", "TopicThread", "VerifiedSegment", "segment_payload_digest",
]
