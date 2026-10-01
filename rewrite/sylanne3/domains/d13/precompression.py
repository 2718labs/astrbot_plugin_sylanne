"""Pure D13 precompression decisions. D11 owns jobs, budgets and persistence."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
from typing import TYPE_CHECKING, Protocol

from ...runtime_contracts import (
    CompressedTurnBlockV2, ConversationWindowProjectionV1, TurnAnchorV1,
    TurnDetailSlotV1, TurnTimelineItemV1, VersionedRef, canonical_digest,
)

if TYPE_CHECKING:
    from .paid_lifecycle import (
        D13ExactActivationEvidenceV1, D13ExactActivationVerifierV1,
    )

_TTL = 72 * 3600
_SPAN = 24 * 3600
COMPILER_VERSION = "d13.deterministic.v1"
EXTRACTIVE_MODEL_VERSION = "d13.model.extractive.v1"
_QUALIFIER = re.compile(r"不|没|无|未|未知|失败|超时|更正|改到|如果|除非|\b(?:not|never|unknown|fail(?:ed|ure)?|timeout|correct(?:ed|ion)?|if|unless)\b", re.I)
_CLAUSE = re.compile(r"[^。！？.!?\n]+[。！？.!?]?")
_LATIN_TERM = re.compile(r"[a-z0-9_]{3,}", re.I)
_CJK_RUN = re.compile(r"[\u3400-\u9fff]{2,}")
EXTRACTIVE_OUTPUT_SCHEMA = "d13.extractive_model_output.v1"


def _size(text: str) -> int:
    return len(text.encode("utf-8"))


def _fingerprint(window: ConversationWindowProjectionV1, turns: tuple) -> str:
    first, last = turns[0].sequence, turns[-1].sequence
    return canonical_digest({
        "namespace": window.namespace, "owner": window.owner_ref,
        "conversation": window.conversation_ref, "scene": window.scene_ref,
        "audience": window.audience_ref, "access_epoch": window.access_epoch,
        "delete_epoch": window.delete_epoch, "activation_epoch": window.activation_epoch,
        "missing_ranges": tuple((max(start, first), min(end, last))
                                for start, end in window.missing_ranges
                                if start <= last and end >= first),
        "turns": turns,
    })


@dataclass(frozen=True, slots=True)
class PrecompressionPlan:
    """One immutable intent; D11 must reserve and enqueue it exactly once."""

    job_ref: str
    candidate_ref: str
    input_digest: str
    first_sequence: int
    last_sequence: int
    source_dependencies: tuple[VersionedRef, ...]
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    access_epoch: int
    delete_epoch: int
    activation_epoch: int
    expires_at_utc: float


def plan_precompression(
    window: ConversationWindowProjectionV1,
    history_token_budget: int,
    *,
    background_capacity: bool,
    outstanding_candidate: bool,
    attempted_input_digests: frozenset[str] = frozenset(),
) -> PrecompressionPlan | None:
    """Plan the oldest complete prefix after the 60% line, without dispatching.

    Bytes are a conservative local proxy; D11 freezes actual token and cost
    budgets. The attempted set must come from D11's persistent job ledger.
    """
    if type(history_token_budget) is not int or history_token_budget <= 0:
        raise ValueError("history_token_budget must be positive")
    recent = tuple(t for t in window.turns if 0 <= window.trusted_utc - t.trusted_utc < _TTL)
    total = sum(_size(f"{t.speaker_ref}: {t.text}") for t in recent)
    return _plan_prefix(window, history_token_budget,
                        background_capacity=background_capacity,
                        outstanding_candidate=outstanding_candidate,
                        attempted_input_digests=attempted_input_digests,
                        pressure_reached=total >= history_token_budget * 0.6)


def _plan_prefix(
    window: ConversationWindowProjectionV1, history_token_budget: int, *,
    background_capacity: bool, outstanding_candidate: bool,
    attempted_input_digests: frozenset[str], pressure_reached: bool,
) -> PrecompressionPlan | None:
    if not background_capacity or outstanding_candidate:
        return None
    recent = tuple(t for t in window.turns if 0 <= window.trusted_utc - t.trusted_utc < _TTL)
    if len(recent) < 3:
        return None
    if not pressure_reached:
        return None
    limit = history_token_budget * 0.3
    prefix = []
    used = 0
    for turn in recent[:-1]:  # preserve at least one raw tail turn
        if prefix and (turn.sequence != prefix[-1].sequence + 1 or
                       turn.trusted_utc - prefix[0].trusted_utc > _SPAN):
            break
        size = _size(f"{turn.speaker_ref}: {turn.text}")
        if prefix and used + size > limit:
            break
        prefix.append(turn)
        used += size
    if len(prefix) < 2:
        return None
    prefix = tuple(prefix)
    if len({turn.raw_ref for turn in prefix}) != len(prefix):
        # The same raw ref is a retransmission/duplicate projection, not an
        # independent user emphasis. D11 must normalize it before planning.
        return None
    if any(start <= prefix[-1].sequence and end >= prefix[0].sequence
           for start, end in window.missing_ranges):
        return None
    digest = _fingerprint(window, prefix)
    if digest in attempted_input_digests:
        return None
    deps = tuple(dict.fromkeys(r for t in prefix for r in (t.raw_ref, t.source_ref, t.access_ref)))
    return PrecompressionPlan(
        job_ref=f"d13:precompress:{digest}", candidate_ref=f"d13:candidate:{digest}",
        input_digest=digest, first_sequence=prefix[0].sequence,
        last_sequence=prefix[-1].sequence, source_dependencies=deps,
        scene_ref=window.scene_ref, audience_ref=window.audience_ref,
        access_epoch=window.access_epoch, delete_epoch=window.delete_epoch,
        activation_epoch=window.activation_epoch,
        expires_at_utc=prefix[0].trusted_utc + _TTL,
    )


@dataclass(frozen=True, slots=True)
class D13CurrentMainPressureV2:
    """Exact foreground count candidate, bound to one current D11 window.

    W09 must authenticate the tokenizer and actual current main-model wire;
    constructing this value in a domain caller confers no egress authority.
    """

    window_digest: str
    main_messages_digest: str
    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    input_tokens: int
    tokenizer_fingerprint: str
    quality: str = "exact"

    def __post_init__(self) -> None:
        for value in (self.window_digest, self.main_messages_digest,
                      self.provider_config_digest):
            if (type(value) is not str or len(value) != 64 or
                    any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("D13 exact pressure needs SHA-256 bindings")
        if (any(type(value) is not str or not value.strip() for value in (
                self.installation_id, self.provider_id, self.model_id,
                self.tokenizer_fingerprint)) or
                type(self.input_tokens) is not int or self.input_tokens <= 0 or
                self.quality != "exact"):
            raise ValueError("D13 main pressure needs a verified exact count")


def plan_paid_precompression_v2(
    window: ConversationWindowProjectionV1,
    pressure: D13CurrentMainPressureV2 | None,
    selected_main_model: object, history_token_budget: int, *,
    background_capacity: bool, outstanding_candidate: bool,
    attempted_input_digests: frozenset[str],
) -> PrecompressionPlan | None:
    """Plan only after 60% exact main-model pressure and one pending guard.

    This is a pure candidate. W09 must authenticate ``pressure`` against the
    original foreground wire, while W01 owns the persisted pending/attempt
    inventory and D11 reservation. The later compression wire still needs its
    own exact pre-call token count and paid Authority grant.
    """
    from ...model_broker.d13_precompression import D13PrecompressionInstallationV1

    if (type(window) is not ConversationWindowProjectionV1 or
            type(history_token_budget) is not int or history_token_budget <= 0 or
            type(background_capacity) is not bool or
            type(outstanding_candidate) is not bool or
            type(attempted_input_digests) is not frozenset or
            any(type(item) is not str for item in attempted_input_digests)):
        raise TypeError("typed current D13 window, budget and inventory required")
    if (type(pressure) is not D13CurrentMainPressureV2 or
            type(selected_main_model) is not D13PrecompressionInstallationV1 or
            pressure.window_digest != canonical_digest(window) or
            (pressure.installation_id, pressure.provider_id, pressure.model_id,
             pressure.provider_config_digest) !=
            (selected_main_model.installation_id, selected_main_model.provider_id,
             selected_main_model.model_id, selected_main_model.provider_config_digest)):
        return None
    return _plan_prefix(
        window, history_token_budget,
        background_capacity=background_capacity,
        outstanding_candidate=outstanding_candidate,
        attempted_input_digests=attempted_input_digests,
        pressure_reached=pressure.input_tokens * 10 >= history_token_budget * 6,
    )


def _source_clauses(text: str) -> tuple[str, ...]:
    """Extract exact bounded source fragments; never rewrite a claim."""
    result = tuple(match.group().strip() for match in _CLAUSE.finditer(text)
                   if match.group().strip())
    return result or (text,)


def _structural_fragments(text: str) -> tuple[str, tuple[str, ...], bool]:
    """Keep a chronological beat and qualified excerpts from one raw turn.

    A qualified clause that cannot fit in a bounded excerpt makes the entire
    deterministic fold ineligible. Dropped text is surfaced as an omission.
    """
    clauses = _source_clauses(text)
    required = tuple(clause for clause in clauses if _QUALIFIER.search(clause))
    if any(_size(clause) > 160 for clause in required):
        raise ValueError("qualified source clause cannot be folded safely")
    first = clauses[0]
    beat = " ".join(required) if required else (
        first if _size(first) <= 160 else "已提交发言；详情须回查原文")
    if _size(beat) > 160:
        raise ValueError("qualified source clauses cannot fit a stable beat")
    details = tuple(clause for clause in clauses if clause not in required and
                    clause != beat and _size(clause) <= 160 and
                    len(set(clause)) > 2)[:1]
    if not details and required:
        # A requested qualifier can still carry the precise source/time label
        # that the compact chronological beat intentionally omits.
        details = (required[-1],)
    represented = beat == text or text in details
    return beat, details, not represented


def compile_deterministic_candidate(
    window: ConversationWindowProjectionV1, plan: PrecompressionPlan,
) -> CompressedTurnBlockV2:
    """Fold raw turns to anchored beats, without interpreting their claims."""
    turns = tuple(t for t in window.turns
                  if plan.first_sequence <= t.sequence <= plan.last_sequence)
    if (len(turns) != plan.last_sequence - plan.first_sequence + 1 or
            not turns or turns[0].sequence != plan.first_sequence or
            turns[-1].sequence != plan.last_sequence or
            _fingerprint(window, turns) != plan.input_digest or
            window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref or
            (window.access_epoch, window.delete_epoch, window.activation_epoch) !=
            (plan.access_epoch, plan.delete_epoch, plan.activation_epoch) or
            window.trusted_utc >= plan.expires_at_utc or
            len({t.raw_ref for t in turns}) != len(turns)):
        raise ValueError("stale or incomplete precompression plan")
    anchors = tuple(TurnAnchorV1.from_turn(t) for t in turns)
    fragments = tuple(_structural_fragments(t.text) for t in turns)
    timeline = tuple(TurnTimelineItemV1(t.sequence, t.source_ref, t.speaker_ref,
                                        fragment[0])
                     for t, fragment in zip(turns, fragments))
    details = tuple(TurnDetailSlotV1(
        f"turn:{t.sequence}" if index == 0 else f"turn:{t.sequence}:detail:{index}",
        t.sequence, t.source_ref, clause)
        for t, fragment in zip(turns, fragments)
        for index, clause in enumerate(fragment[1]))
    omitted = [t.sequence for t, fragment in zip(turns, fragments) if fragment[2]]
    candidate = CompressedTurnBlockV2(
        block_ref=f"d13:block:{plan.input_digest}",
        conversation_ref=window.conversation_ref, audience_ref=window.audience_ref,
        turns=anchors, source_dependencies=plan.source_dependencies,
        timeline=timeline, detail_slots=details,
        omitted_ranges=_omission_ranges(omitted),
        compiler_version=COMPILER_VERSION, job_ref=plan.job_ref,
        candidate_ref=plan.candidate_ref, expires_at_utc=plan.expires_at_utc,
        status="candidate",
    )
    if _size(candidate.rendered_text) >= sum(_size(t.text) for t in turns):
        raise ValueError("deterministic fold does not reduce this prefix")
    return candidate


def _validate_extractive_candidate(
    candidate: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1,
) -> None:
    """Check content and frozen source identity without claiming job settlement."""
    if (candidate.status != "candidate" or candidate.compiler_version != EXTRACTIVE_MODEL_VERSION
            or candidate.job_ref != plan.job_ref or candidate.candidate_ref != plan.candidate_ref
            or candidate.block_ref != f"d13:block:{plan.input_digest}"
            or candidate.conversation_ref != window.conversation_ref
            or candidate.audience_ref != plan.audience_ref
            or candidate.expires_at_utc != plan.expires_at_utc):
        raise ValueError("model candidate identity mismatch")
    turns = tuple(t for t in window.turns
                  if plan.first_sequence <= t.sequence <= plan.last_sequence)
    if (len(turns) != plan.last_sequence - plan.first_sequence + 1
            or not turns or turns[0].sequence != plan.first_sequence
            or turns[-1].sequence != plan.last_sequence
            or _fingerprint(window, turns) != plan.input_digest
            or window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref
            or (window.access_epoch, window.delete_epoch, window.activation_epoch) !=
            (plan.access_epoch, plan.delete_epoch, plan.activation_epoch)
            or window.trusted_utc >= plan.expires_at_utc
            or len({t.raw_ref for t in turns}) != len(turns)):
        raise ValueError("model candidate original turns are stale or incomplete")
    expected_anchors = tuple(TurnAnchorV1.from_turn(t) for t in turns)
    if candidate.turns != expected_anchors or candidate.source_dependencies != plan.source_dependencies:
        raise ValueError("model candidate source closure differs from original turns")
    if tuple(item.sequence for item in candidate.timeline) != tuple(t.sequence for t in turns):
        raise ValueError("model candidate must retain one ordered beat per turn")
    details_by_sequence: dict[int, list[str]] = {}
    for slot in candidate.detail_slots:
        details_by_sequence.setdefault(slot.sequence, []).append(slot.text)
    omitted = {sequence for start, end in candidate.omitted_ranges for sequence in range(start, end + 1)}
    expected_omitted = set()
    for turn, beat in zip(turns, candidate.timeline):
        if (beat.source_ref != turn.source_ref or beat.speaker_ref != turn.speaker_ref
                or beat.text not in turn.text):
            raise ValueError("model beat changes speaker, source, or original wording")
        details = details_by_sequence.get(turn.sequence, ())
        if any(text not in turn.text for text in details):
            raise ValueError("model detail lacks an exact original source fragment")
        if _QUALIFIER.search(turn.text) and beat.text != turn.text:
            raise ValueError("negation, correction, condition or unknown requires exact stable beat")
        if beat.text != turn.text and turn.text not in details:
            expected_omitted.add(turn.sequence)
    if omitted != expected_omitted:
        raise ValueError("model candidate omission ranges do not match represented turns")


def _omission_ranges(sequences: list[int]) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for sequence in sequences:
        if ranges and sequence == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], sequence)
        else:
            ranges.append((sequence, sequence))
    return tuple(ranges)


def compile_extractive_model_output(
    window: ConversationWindowProjectionV1, plan: PrecompressionPlan,
    model_text: str,
) -> CompressedTurnBlockV2:
    """Compile one bounded JSON model result into an unadopted candidate.

    The model supplies only sequence, exact beat and exact detail strings. All
    identity, speaker, source, omission, and lifetime fields come from the
    frozen original window and plan. D11 must still prove the original paid
    call, settlement, current job fence and source read set before adoption.
    """
    if type(model_text) is not str or not 0 < _size(model_text) <= 65_536:
        raise ValueError("extractive model output must be bounded JSON text")

    def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError("extractive model output repeats a field")
            fields[key] = value
        return fields

    try:
        data = json.loads(model_text, object_pairs_hook=unique_fields)
    except json.JSONDecodeError as exc:
        raise ValueError("extractive model output is not JSON") from exc
    if (type(data) is not dict or set(data) != {"schema", "turns"} or
            data["schema"] != EXTRACTIVE_OUTPUT_SCHEMA or
            type(data["turns"]) is not list):
        raise ValueError("extractive model output shape differs")
    turns = tuple(t for t in window.turns
                  if plan.first_sequence <= t.sequence <= plan.last_sequence)
    if len(data["turns"]) != len(turns) or not turns:
        raise ValueError("extractive output must cover each planned turn")
    timeline = []
    details = []
    omitted = []
    for turn, item in zip(turns, data["turns"]):
        if (type(item) is not dict or set(item) != {"sequence", "beat", "details"} or
                type(item["sequence"]) is not int or item["sequence"] != turn.sequence or
                type(item["beat"]) is not str or not item["beat"] or
                type(item["details"]) is not list or len(item["details"]) > 4 or
                any(type(part) is not str or not part for part in item["details"])):
            raise ValueError("extractive output turn shape or order differs")
        beat = item["beat"]
        excerpts = item["details"]
        if beat not in turn.text or any(part not in turn.text for part in excerpts):
            raise ValueError("extractive output contains text outside original turn")
        if len(set(excerpts)) != len(excerpts):
            raise ValueError("extractive output repeats a detail")
        timeline.append(TurnTimelineItemV1(
            turn.sequence, turn.source_ref, turn.speaker_ref, beat))
        details.extend(TurnDetailSlotV1(
            f"turn:{turn.sequence}:detail:{index}", turn.sequence,
            turn.source_ref, part) for index, part in enumerate(excerpts))
        if beat != turn.text and turn.text not in excerpts:
            omitted.append(turn.sequence)
    candidate = CompressedTurnBlockV2(
        block_ref=f"d13:block:{plan.input_digest}",
        conversation_ref=window.conversation_ref, audience_ref=window.audience_ref,
        turns=tuple(TurnAnchorV1.from_turn(t) for t in turns),
        source_dependencies=plan.source_dependencies,
        timeline=tuple(timeline), detail_slots=tuple(details),
        omitted_ranges=_omission_ranges(omitted),
        compiler_version=EXTRACTIVE_MODEL_VERSION, job_ref=plan.job_ref,
        candidate_ref=plan.candidate_ref, expires_at_utc=plan.expires_at_utc,
        status="candidate",
    )
    _validate_extractive_candidate(candidate, plan, window)
    if _size(candidate.rendered_text) >= sum(_size(t.text) for t in turns):
        raise ValueError("extractive model output does not reduce original text")
    return candidate


def accept_model_candidate(
    candidate: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *, settled_job_ref: str,
    job_fence_valid: bool,
) -> CompressedTurnBlockV2:
    """Accept only source-extractive output from the settled original job.

    D11 supplies the verified settlement and fence, then atomically checks the
    current source read set before storing this derived cache.
    """
    if not job_fence_valid or settled_job_ref != plan.job_ref:
        raise ValueError("original precompression job is not settled and current")
    _validate_extractive_candidate(candidate, plan, window)
    return replace(candidate, status="standby")


class D13CurrentPaidModelVerifierV2(Protocol):
    """W01-installed original paid result and current source closure port."""

    def verify_current_paid_model_block_v2(
        self, candidate: CompressedTurnBlockV2, *,
        plan: PrecompressionPlan, window: ConversationWindowProjectionV1,
    ) -> bool: ...


def _model_candidate_current(
    block: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None,
) -> bool:
    if paid_verifier is None or block.compiler_version != EXTRACTIVE_MODEL_VERSION:
        return False
    candidate = replace(block, status="candidate")
    try:
        _validate_extractive_candidate(candidate, plan, window)
        turns = tuple(t for t in window.turns
                      if plan.first_sequence <= t.sequence <= plan.last_sequence)
        if _size(candidate.rendered_text) >= sum(_size(t.text) for t in turns):
            return False
        return paid_verifier.verify_current_paid_model_block_v2(
            candidate, plan=plan, window=window) is True
    except Exception:
        return False


def accept_verified_model_candidate_v2(
    candidate: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None,
) -> CompressedTurnBlockV2:
    """Produce standby material only from current extractive paid evidence.

    W01 must supply its installed verifier and atomically CAS this candidate
    with the original D11 job and cache absence. A returned value is not a
    committed graph block or an activated cache.
    """
    if candidate.status != "candidate" or not _model_candidate_current(
            candidate, plan, window, paid_verifier):
        raise ValueError("current original paid model proof and source required")
    return replace(candidate, status="standby")


def accept_model_or_deterministic(
    candidate: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *, settled_job_ref: str,
    job_fence_valid: bool,
) -> CompressedTurnBlockV2:
    """Use the current deterministic excerpt when model content is rejected."""
    if not job_fence_valid or settled_job_ref != plan.job_ref:
        raise ValueError("original precompression job is not settled and current")
    try:
        return accept_model_candidate(candidate, plan, window,
                                      settled_job_ref=settled_job_ref,
                                      job_fence_valid=job_fence_valid)
    except ValueError:
        # Rebuild from current raw turns; this also rejects stale or revoked input.
        return replace(compile_deterministic_candidate(window, plan), status="standby")


def select_detail_slots(
    block: CompressedTurnBlockV2, *, query_keys: tuple[str, ...],
    detail_byte_budget: int,
    query_text: str = "",
    rementioned_sources: tuple[VersionedRef, ...] = (),
    evidence_sources: tuple[VersionedRef, ...] = (),
) -> tuple[TurnDetailSlotV1, ...]:
    """Choose anchored values for this query, without a selection-history score.

    ``rementioned_sources`` is a D09/D06-observed *new user turn*, not the
    number of times D13 put a slot in a prompt. D11 authenticates that input.
    ``evidence_sources`` suppresses details already present as current D06
    evidence or a raw tail source.
    """
    if type(block) is not CompressedTurnBlockV2:
        raise TypeError("block must be CompressedTurnBlockV2")
    if type(detail_byte_budget) is not int or detail_byte_budget < 0:
        raise ValueError("detail_byte_budget must be nonnegative")
    if type(query_keys) is not tuple or any(type(key) is not str or not key for key in query_keys):
        raise ValueError("query_keys must be a tuple of nonempty strings")
    if type(query_text) is not str or _size(query_text) > 4096:
        raise ValueError("query_text must be bounded text")
    for name, refs in (("rementioned_sources", rementioned_sources),
                       ("evidence_sources", evidence_sources)):
        if type(refs) is not tuple or any(type(ref) is not VersionedRef for ref in refs):
            raise TypeError(f"{name} must be versioned source references")
    keys = set(query_keys)
    mentioned = set(rementioned_sources)
    already_evidenced = set(evidence_sources)
    terms = _lexical_terms(query_text)
    ranked = []
    for slot in block.detail_slots:
        if slot.source_ref in already_evidenced:
            continue
        overlap = len(terms & _lexical_terms(slot.text))
        score = (100 if slot.key in keys else 0) + (20 if slot.source_ref in mentioned else 0)
        score += min(overlap, 5) * 10
        if score:
            score += 2 if _QUALIFIER.search(slot.text) else 0
            ranked.append((-score, slot.sequence, slot.key, slot))
    chosen = []
    used = 0
    for _, _, _, slot in sorted(ranked):
        line_size = _size(render_detail_slot(block, slot)) + (1 if chosen else 0)
        if used + line_size <= detail_byte_budget:
            chosen.append(slot)
            used += line_size
    return tuple(sorted(chosen, key=lambda slot: (slot.sequence, slot.key)))


def _lexical_terms(text: str) -> frozenset[str]:
    """Small deterministic lexical proxy, never a semantic evidence claim."""
    lowered = text.casefold()
    terms = set(_LATIN_TERM.findall(lowered))
    for run in _CJK_RUN.findall(lowered):
        terms.update(run[index:index + 2] for index in range(len(run) - 1))
    return frozenset(terms)


def render_detail_slot(block: CompressedTurnBlockV2, slot: TurnDetailSlotV1) -> str:
    """Render a selected value with its original anchor, never its lookup key."""
    anchor = next((turn for turn in block.turns if turn.sequence == slot.sequence), None)
    if anchor is None or anchor.source_ref != slot.source_ref:
        raise ValueError("detail slot has no matching original turn anchor")
    return (f"[detail {slot.sequence} {anchor.trusted_utc} {anchor.speaker_ref} "
            f"{slot.source_ref.ref}@{slot.source_ref.version}] {slot.text}")


def adopt_candidate(
    candidate: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *, job_fence_valid: bool,
) -> CompressedTurnBlockV2:
    """Validate a late result against current source revisions before CAS save."""
    if not job_fence_valid or candidate.status != "candidate":
        raise ValueError("candidate job is not adoptable")
    if (candidate.job_ref != plan.job_ref or candidate.candidate_ref != plan.candidate_ref or
            candidate.compiler_version != COMPILER_VERSION or
            candidate.block_ref != f"d13:block:{plan.input_digest}"):
        raise ValueError("candidate identity mismatch")
    expected = compile_deterministic_candidate(window, plan)
    if candidate != expected:
        raise ValueError("candidate content or source closure changed")
    return replace(candidate, status="standby")


def decide_activation(
    standby: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1,
    *, raw_window_fits: bool, proven_future_saving: bool,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
    exact_activation_evidence: D13ExactActivationEvidenceV1 | None = None,
    exact_activation_verifier: D13ExactActivationVerifierV1 | None = None,
) -> str:
    """Return activate, keep_raw, hold, or invalid; D11 performs the atomic CAS.

    The legacy fit/savings booleans may control deterministic candidates. Paid
    model candidates require the typed W09 same-main-model exact-wire proof;
    their paid-result verifier alone proves neither exact token fit nor cache
    economics. The proof is optional so an unavailable provider remains HOLD.
    """
    if (standby.status != "standby" or window.trusted_utc >= standby.expires_at_utc or
            standby.job_ref != plan.job_ref or standby.candidate_ref != plan.candidate_ref or
            standby.block_ref != f"d13:block:{plan.input_digest}" or
            window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref or
            (window.access_epoch, window.delete_epoch, window.activation_epoch) !=
            (plan.access_epoch, plan.delete_epoch, plan.activation_epoch)):
        return "invalid"
    by_sequence = {t.sequence: t for t in window.turns}
    covered = tuple(by_sequence.get(s) for s in range(plan.first_sequence, plan.last_sequence + 1))
    if (standby.conversation_ref != window.conversation_ref or
            standby.audience_ref != window.audience_ref or
            any(t is None for t in covered) or
            _fingerprint(window, covered) != plan.input_digest or
            not set(standby.source_dependencies).issubset(window.source_dependencies)):
        return "invalid"
    if standby.compiler_version == EXTRACTIVE_MODEL_VERSION:
        if not _model_candidate_current(standby, plan, window, paid_verifier):
            return "invalid"
        # Local import avoids making the pure source compiler depend on the
        # paid lifecycle module at import time (that module uses this module).
        from .paid_lifecycle import (
            D13ExactActivationEvidenceV1, decide_exact_activation_v1,
        )

        if (type(exact_activation_evidence) is not D13ExactActivationEvidenceV1 or
                exact_activation_verifier is None):
            return "hold"

        return decide_exact_activation_v1(
            standby, plan, window, exact_activation_evidence,
            verifier=exact_activation_verifier, paid_verifier=paid_verifier,
        )
    else:
        try:
            expected = compile_deterministic_candidate(window, plan)
        except ValueError:
            return "invalid"
        if standby != replace(expected, status="standby"):
            return "invalid"
    return "activate" if not raw_window_fits or proven_future_saving else "keep_raw"
