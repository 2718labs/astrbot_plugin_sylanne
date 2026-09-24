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


_VERIFIED_BATCH_SCHEMA = "d09.verified_segment_batch.v1"
_VERIFIED_BATCH_FIELDS = frozenset({
    "schema", "batch_id", "batch_digest", "qualification", "grant_id",
    "grant_digest", "grant_manifest_digest", "blueprint_digest", "candidate_digest",
    "communication_action_id", "contact_id", "batch_revision", "intent_ref",
    "action_id", "intent_revision", "target_ref", "purpose", "audiences",
    "scene_ref", "conversation_epoch", "valid_until", "cancellation_epoch",
    "required_slots", "required_check_refs", "claims", "segments", "version",
})


def _verified_batch_digest(value: dict) -> str:
    return canonical_digest({key: item for key, item in value.items() if key != "batch_digest"})


def _validate_verified_batch_value_v1(value: dict) -> None:
    """Validate the frozen candidate's exact shape and content digest.

    This structural check alone does not qualify D08 authorization or sources.
    The graph coordinator must also call recompute_verified_batch_v1 with its
    independently read current inputs before committing the value.
    """

    if type(value) is not dict or set(value) != _VERIFIED_BATCH_FIELDS:
        raise ValueError("verified batch fields differ from v1 schema")
    if (value["schema"] != _VERIFIED_BATCH_SCHEMA
            or type(value["version"]) is not int or value["version"] != 1):
        raise ValueError("verified batch schema/version mismatch")
    if value["qualification"] != "content_verified_source_hold":
        raise ValueError("verified batch cannot self-assert source qualification")
    for name in (
        "batch_id", "grant_id", "communication_action_id", "contact_id",
        "intent_ref", "action_id", "target_ref", "purpose", "scene_ref",
    ):
        _nonempty(value[name], name)
    if value["purpose"] != "expression":
        raise ValueError("verified batch purpose must be expression")
    for name in ("batch_revision", "intent_revision", "conversation_epoch", "cancellation_epoch"):
        _nonnegative_int(value[name], name)
    if value["batch_revision"] < 1 or value["intent_revision"] < 1:
        raise ValueError("verified batch revisions must be positive")
    _finite(value["valid_until"], "valid_until")
    for name in ("audiences", "required_slots", "required_check_refs"):
        if type(value[name]) is not list or any(type(item) is not str or not item for item in value[name]):
            raise ValueError(f"{name} must be a string list")
        if len(set(value[name])) != len(value[name]):
            raise ValueError(f"{name} must contain unique values")
    for name in ("grant_digest", "grant_manifest_digest", "blueprint_digest", "candidate_digest", "batch_digest"):
        item = value[name]
        if type(item) is not str or len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item):
            raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    if type(value["claims"]) is not list or type(value["segments"]) is not list or not value["segments"]:
        raise ValueError("verified batch requires frozen claims and finite segments")
    if len(value["segments"]) > 3:
        raise ValueError("verified batch exceeds the finite segment limit")
    claim_fields = {
        "claim_id", "text", "kind", "source_refs", "allowed_audiences",
        "eligibility", "disclosure_ref",
    }
    claims: dict[str, dict] = {}
    for claim in value["claims"]:
        if type(claim) is not dict or set(claim) != claim_fields:
            raise ValueError("verified claim fields differ from v1 schema")
        for name in ("claim_id", "text", "disclosure_ref"):
            _nonempty(claim[name], name)
        if claim["kind"] not in {kind.value for kind in ClaimKind}:
            raise ValueError("verified claim kind is unknown")
        for name in ("source_refs", "allowed_audiences", "eligibility"):
            parts = claim[name]
            if type(parts) is not list or any(type(part) is not str or not part for part in parts):
                raise ValueError(f"verified claim {name} must be a string list")
            if len(set(parts)) != len(parts):
                raise ValueError(f"verified claim {name} must be unique")
        if claim["kind"] != ClaimKind.RHETORIC.value and not claim["source_refs"]:
            raise ValueError("non-rhetorical claim requires source refs")
        if not claim["allowed_audiences"] or "expression" not in claim["eligibility"]:
            raise ValueError("verified claim lacks expression scope")
        if claim["claim_id"] in claims:
            raise ValueError("verified claim IDs must be unique")
        claims[claim["claim_id"]] = claim
    segment_fields = {
        "segment_id", "effect_id", "position", "body", "payload_digest",
        "segment_authorization_ref", "max_chars", "allowed_media",
        "claim_uses", "source_refs", "covered_slots", "media_refs",
        "prerequisite_segment_ref", "audiences", "required_check_refs",
        "valid_until", "cancellation_epoch",
    }
    seen_segments: set[str] = set()
    seen_effects: set[str] = set()
    covered_slots: set[str] = set()
    for position, segment in enumerate(value["segments"]):
        if type(segment) is not dict or set(segment) != segment_fields:
            raise ValueError("verified segment fields differ from v1 schema")
        for name in ("segment_id", "effect_id", "body"):
            _nonempty(segment[name], name)
        if segment["position"] != position or type(segment["position"]) is not int:
            raise ValueError("verified segments must be contiguous and ordered")
        if segment["segment_id"] in seen_segments or segment["effect_id"] in seen_effects:
            raise ValueError("verified segment identities must be unique")
        _nonempty(segment["segment_authorization_ref"], "segment_authorization_ref")
        _nonnegative_int(segment["max_chars"], "max_chars")
        if len(segment["body"]) > segment["max_chars"]:
            raise ValueError("verified segment exceeds its granted length")
        if segment["prerequisite_segment_ref"] is not None and segment["prerequisite_segment_ref"] not in seen_segments:
            raise ValueError("verified prerequisite must refer to an earlier segment")
        if segment["valid_until"] != value["valid_until"] or segment["cancellation_epoch"] != value["cancellation_epoch"]:
            raise ValueError("verified segment validity differs from its batch")
        if segment["audiences"] != value["audiences"] or segment["required_check_refs"] != value["required_check_refs"]:
            raise ValueError("verified segment scope differs from its batch")
        if type(segment["claim_uses"]) is not list:
            raise ValueError("verified claim uses must be a list")
        uses: list[ClaimUse] = []
        source_refs: set[str] = set()
        cursor = 0
        for use in segment["claim_uses"]:
            if type(use) is not dict or set(use) != {"claim_ref", "start", "end", "asserted_as"}:
                raise ValueError("verified claim use fields differ from v1 schema")
            mapped = claims.get(use["claim_ref"])
            if mapped is None or use["asserted_as"] != mapped["kind"]:
                raise ValueError("verified claim use is not eligible")
            claim_use = ClaimUse(use["claim_ref"], use["start"], use["end"], ClaimKind(use["asserted_as"]))
            if claim_use.start < cursor or claim_use.end > len(segment["body"]):
                raise ValueError("verified claim spans overlap or exceed the body")
            if any(char.isalnum() for char in segment["body"][cursor:claim_use.start]):
                raise ValueError("verified segment contains unmapped content")
            if segment["body"][claim_use.start:claim_use.end] != mapped["text"]:
                raise ValueError("verified claim span differs from frozen text")
            uses.append(claim_use)
            source_refs.update(mapped["source_refs"])
            cursor = claim_use.end
        if any(char.isalnum() for char in segment["body"][cursor:]):
            raise ValueError("verified segment contains unmapped content")
        for name in ("source_refs", "covered_slots", "media_refs", "allowed_media"):
            parts = segment[name]
            if type(parts) is not list or any(type(part) is not str or not part for part in parts):
                raise ValueError(f"verified segment {name} must be a string list")
            if len(set(parts)) != len(parts):
                raise ValueError(f"verified segment {name} must be unique")
        if segment["source_refs"] != sorted(source_refs):
            raise ValueError("verified segment source closure differs from claims")
        if not set(segment["media_refs"]).issubset(set(segment["allowed_media"])):
            raise ValueError("verified segment media exceeds its granted scope")
        if segment["payload_digest"] != segment_payload_digest(
            segment["body"], tuple(segment["media_refs"]), tuple(uses),
        ):
            raise ValueError("verified segment payload digest mismatch")
        covered_slots.update(segment["covered_slots"])
        seen_segments.add(segment["segment_id"])
        seen_effects.add(segment["effect_id"])
    if not set(value["required_slots"]).issubset(covered_slots):
        raise ValueError("verified batch does not cover required slots")
    if value["batch_digest"] != _verified_batch_digest(value):
        raise ValueError("verified batch content digest mismatch")


@dataclass(frozen=True)
class VerifiedBatchRecheckV1:
    status: str
    value: dict | None
    missing: tuple[str, ...]


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
            ("d09.verified_segment_batch.v1", ("activity",), "state", True, ()),
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
            validator=(
                _validate_verified_batch_value_v1 if name == _VERIFIED_BATCH_SCHEMA
                else _strict_graph_validator(name, fields)
            ),
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
        if set(seen_segments) != set(grants):
            failures.append("segment_manifest")
        if failures:
            return StagingResult("rejected", (), tuple(dict.fromkeys(failures)), ())
        missing = tuple(slot for slot in blueprint.required_slots if slot not in covered)
        if missing:
            return StagingResult("unavailable", (), (), missing)
        return StagingResult("complete", tuple(sorted(verified, key=lambda item: item.position)), (), ())

    @staticmethod
    def build_verified_batch_v1(
        intent: CommunicationIntentGrant,
        blueprint: ExpressionBlueprint,
        candidates: tuple[SegmentCandidate, ...],
        *,
        now: float,
    ) -> dict:
        """Freeze a complete content-verified batch candidate, not a send grant.

        The caller must obtain the D08 grant and all source qualifications from
        their authoritative current reads. An in-memory grant object alone does
        not establish that provenance, so the stored qualification remains HOLD.
        """

        if not isinstance(intent, CommunicationIntentGrant):
            raise TypeError("intent must be CommunicationIntentGrant")
        if not isinstance(blueprint, ExpressionBlueprint):
            raise TypeError("blueprint must be ExpressionBlueprint")
        _finite(now, "now")
        prepared = D09ExpressionProvider.prepare_blueprint(
            intent, blueprint.scene_ref, blueprint.conversation_epoch,
            blueprint.claims, now=now,
        )
        if prepared.status != "complete" or prepared.blueprint != blueprint:
            raise ValueError("blueprint differs from the current D08 intent or has expired")
        staged = D09ExpressionProvider.verify_and_stage(blueprint, candidates)
        if staged.status != "complete":
            raise ValueError(f"finite segment verification failed: {staged.status}: {staged.failures or staged.missing_slots}")
        claims = {claim.claim_id: claim for claim in blueprint.claims}
        grants = {grant.segment_id: grant for grant in intent.segment_grants}
        claim_values = [{
            "claim_id": claim.claim_id,
            "text": claim.text,
            "kind": claim.kind.value,
            "source_refs": list(claim.source_refs),
            "allowed_audiences": list(claim.allowed_audiences),
            "eligibility": list(claim.eligibility),
            "disclosure_ref": claim.disclosure_ref,
        } for claim in blueprint.claims]
        segment_values = []
        for segment in staged.segments:
            grant = grants[segment.segment_id]
            segment_values.append({
                "segment_id": segment.segment_id,
                "effect_id": segment.effect_id,
                "position": segment.position,
                "body": segment.body,
                "payload_digest": segment.payload_digest,
                "segment_authorization_ref": intent.segment_authorization_ref(segment.segment_id),
                "max_chars": grant.max_chars,
                "allowed_media": list(grant.allowed_media),
                "claim_uses": [{
                    "claim_ref": use.claim_ref,
                    "start": use.start,
                    "end": use.end,
                    "asserted_as": use.asserted_as.value,
                } for use in segment.claim_uses],
                "source_refs": sorted({
                    ref for use in segment.claim_uses
                    for ref in claims[use.claim_ref].source_refs
                }),
                "covered_slots": list(segment.covered_slots),
                "media_refs": list(segment.media_refs),
                "prerequisite_segment_ref": segment.prerequisite_segment_ref,
                "audiences": list(segment.audiences),
                "required_check_refs": list(grant.required_check_refs),
                "valid_until": grant.valid_until,
                "cancellation_epoch": grant.cancellation_epoch,
            })
        grant_digest = canonical_digest(intent)
        blueprint_digest = canonical_digest(blueprint)
        candidate_digest = canonical_digest(candidates)
        batch_id = "verified-batch:" + canonical_digest({
            "grant_id": intent.grant_id,
            "grant_digest": grant_digest,
            "blueprint_digest": blueprint_digest,
            "candidate_digest": candidate_digest,
        })
        value = {
            "schema": _VERIFIED_BATCH_SCHEMA,
            "batch_id": batch_id,
            "qualification": "content_verified_source_hold",
            "grant_id": intent.grant_id,
            "grant_digest": grant_digest,
            "grant_manifest_digest": intent.segment_manifest_digest,
            "blueprint_digest": blueprint_digest,
            "candidate_digest": candidate_digest,
            "communication_action_id": intent.communication_action_id,
            "contact_id": intent.contact_id,
            "batch_revision": intent.batch_revision,
            "intent_ref": intent.intent_ref,
            "action_id": intent.action_id,
            "intent_revision": intent.intent_revision,
            "target_ref": intent.target_ref,
            "purpose": intent.purpose,
            "audiences": list(intent.audiences),
            "scene_ref": blueprint.scene_ref,
            "conversation_epoch": blueprint.conversation_epoch,
            "valid_until": intent.valid_until,
            "cancellation_epoch": intent.cancellation_epoch,
            "required_slots": list(intent.required_slots),
            "required_check_refs": list(intent.required_check_refs),
            "claims": claim_values,
            "segments": segment_values,
            "version": 1,
        }
        value["batch_digest"] = _verified_batch_digest(value)
        return value

    @staticmethod
    def recompute_verified_batch_v1(
        value: dict,
        *,
        intent: CommunicationIntentGrant | None,
        blueprint: ExpressionBlueprint,
        candidates: tuple[SegmentCandidate, ...],
        now: float,
    ) -> VerifiedBatchRecheckV1:
        """Graph pre-commit check against independently read D08/D09 inputs.

        Exact equality includes the full segment manifest, body, claim spans,
        sources, scene, audience, validity and dependency chain. Source-access
        and current D08 provenance remain separate graph/Authority checks.
        """

        _validate_verified_batch_value_v1(value)
        if intent is None:
            return VerifiedBatchRecheckV1("hold", None, ("current_d08_grant",))
        expected = D09ExpressionProvider.build_verified_batch_v1(
            intent, blueprint, candidates, now=now,
        )
        if value != expected:
            raise ValueError("verified batch differs from recomputed finite source inputs")
        return VerifiedBatchRecheckV1(
            "content_verified_source_hold", value,
            ("current_d08_grant_provenance", "current_source_reads"),
        )

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
        if (
            len(staged.segments) != len(grants)
            or tuple(segment.segment_id for segment in staged.segments)
            != tuple(item.segment_id for item in intent.segment_grants)
            or any(
                segment.intent_ref != intent.intent_ref
                or segment.action_id != intent.action_id
                or segment.effect_id != grants[segment.segment_id].effect_id
                or segment.position != grants[segment.segment_id].position
                or segment.payload_digest != grants[segment.segment_id].payload_digest
                or segment.payload_digest != segment_payload_digest(
                    segment.body, segment.media_refs, segment.claim_uses,
                )
                or segment.prerequisite_segment_ref
                != grants[segment.segment_id].prerequisite_segment_ref
                or segment.audiences != intent.audiences
                for segment in staged.segments
            )
        ):
            return DeliveryPreparation("rejected", (), (), ("intent_mismatch",))
        admission_ids = tuple(item.segment_id for item in admissions)
        if len(set(admission_ids)) != len(admission_ids):
            return DeliveryPreparation("rejected", (), (), ("duplicate_admission",))
        if any(
            item.segment_id not in grants
            or item.effect_id != grants[item.segment_id].effect_id
            or item.payload_digest != grants[item.segment_id].payload_digest
            for item in admissions
        ):
            return DeliveryPreparation("rejected", (), (), ("admission_mismatch",))
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
    "StagingResult", "TopicThread", "VerifiedBatchRecheckV1", "VerifiedSegment",
    "segment_payload_digest",
]
