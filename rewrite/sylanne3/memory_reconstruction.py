"""Candidate D06 reconstruction of a selected, qualified recollection.

Source excerpts stay separate from the subject's recall. D07 owns inferred
interpretations; D04 owns the current feeling. This operator does not commit a
C04 experience or grant C06 expression/delivery admission.
"""

from dataclasses import dataclass
import math

from .domains.d06 import RecollectionProposal
from .graph_types import AtomKey, GraphVersion, NamespaceEpoch
from .memory_recollection_view import AffectiveRecollectionView


_RETRIEVED_AT = 0.65
_BLURRED_AT = 0.20
_MOOD_ACCESS_GAIN = 0.25


def _unit(value: float, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{label} must be finite and within [0, 1]")
    return float(value)


def _midpoint(interval: tuple[float, float]) -> float:
    return (interval[0] + interval[1]) / 2


def _clamp(value: float, lower: float, upper: float) -> float:
    return min(upper, max(lower, value))


@dataclass(frozen=True)
class DetailCue:
    """A source-bounded detail or a D07-owned interpretation reference."""

    detail_id: str
    source_span: tuple[int, int] | None = None
    accessibility: float | None = None
    interpretation_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.detail_id:
            raise ValueError("detail_id is required")
        if self.interpretation_ref is not None:
            if not self.interpretation_ref or self.source_span is not None or self.accessibility is not None:
                raise ValueError("inferred detail may only carry a D07 interpretation reference")
        else:
            if self.source_span is None or type(self.source_span) is not tuple or len(self.source_span) != 2:
                raise ValueError("source detail requires an exact source span")
            start, end = self.source_span
            if type(start) is not int or type(end) is not int or start < 0 or end <= start:
                raise ValueError("source span must be a nonempty half-open range")
            _unit(self.accessibility, "accessibility")


@dataclass(frozen=True)
class SourceField:
    """What the stored source literally says, without asserting it happened."""

    detail_id: str
    source_ref: str
    source_span: tuple[int, int]
    literal_text: str
    source_kind: str
    assertion_status: str


@dataclass(frozen=True)
class ReconstructedDetail:
    detail_id: str
    state: str  # retrieved / blurred / inferred / unavailable
    recalled_text: str | None
    source_ref: str | None
    source_span: tuple[int, int] | None
    interpretation_ref: str | None
    subjective_salience: tuple[float, float]


@dataclass(frozen=True)
class RecollectionReconstruction:
    recollection_id: str
    activity_id: str
    source_ref: str
    source_fields: tuple[SourceField, ...]
    subjective_details: tuple[ReconstructedDetail, ...]
    then_meaning_refs: tuple[str, ...]
    now_interpretation_refs: tuple[str, ...]
    feeling_experience_refs: tuple[str, ...]
    self_understanding_refs: tuple[str, ...]
    subjective_weight: tuple[float, float]
    subjective_tone: tuple[float, float]
    subjective_duration_delta: float | None
    mood_ref: str
    coupling_version: str
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate_hold"
    encoding_trace_ref: str | None = None
    then_feeling_refs: tuple[str, ...] = ()
    then_feeling_versions: tuple[GraphVersion, ...] = ()
    then_feeling_status: str = "not_read"


def reconstruct_recollection_candidate(
    *,
    proposal: RecollectionProposal,
    view: AffectiveRecollectionView,
    detail_cues: tuple[DetailCue, ...],
    then_meaning_refs: tuple[str, ...] = (),
    temporal_focus: bool = False,
) -> RecollectionReconstruction:
    """Project one source into a version-bound, non-authoritative experience.

    The duration delta is a dimensionless impression, not elapsed seconds.
    Positive means the remembered passage feels longer. The initial bounded
    heuristic is deliberately version-local to this candidate slice.
    """
    if not isinstance(proposal, RecollectionProposal) or proposal.status != "proposal":
        raise ValueError("a D06 recollection proposal is required")
    if not isinstance(view, AffectiveRecollectionView) or view.status != "candidate":
        raise ValueError("a qualified affective recollection candidate is required")
    source_key = AtomKey.from_token(view.source_ref)
    if source_key.type_name != "memory.source" or source_key.owner.subject not in proposal.content_refs:
        raise ValueError("recollection proposal does not select this source")
    if not any(version.key == source_key and version.revision > 0 for version in view.read_versions):
        raise ValueError("source read version is missing")
    if type(detail_cues) is not tuple or any(not isinstance(cue, DetailCue) for cue in detail_cues):
        raise TypeError("detail_cues must be a tuple of DetailCue")
    if len({cue.detail_id for cue in detail_cues}) != len(detail_cues):
        raise ValueError("detail IDs must be unique")
    if type(then_meaning_refs) is not tuple or any(type(ref) is not str or not ref for ref in then_meaning_refs):
        raise ValueError("then_meaning_refs must be nonempty references")
    if type(temporal_focus) is not bool:
        raise TypeError("temporal_focus must be bool")

    salience_shift = _midpoint(view.subjective_salience) - _midpoint(view.base_salience)
    source_fields: list[SourceField] = []
    details: list[ReconstructedDetail] = []
    for cue in detail_cues:
        if cue.interpretation_ref is not None:
            if cue.interpretation_ref not in proposal.now_interpretation_refs:
                raise ValueError("inferred detail lacks a D07 interpretation reference")
            details.append(ReconstructedDetail(
                cue.detail_id, "inferred", None, None, None,
                cue.interpretation_ref, view.subjective_salience,
            ))
            continue
        assert cue.source_span is not None and cue.accessibility is not None
        start, end = cue.source_span
        if end > len(view.source_text):
            raise ValueError("detail span exceeds the qualified source")
        literal = view.source_text[start:end]
        source_fields.append(SourceField(
            cue.detail_id, view.source_ref, cue.source_span, literal,
            view.source_kind, view.assertion_status,
        ))
        accessibility = _clamp(cue.accessibility + _MOOD_ACCESS_GAIN * salience_shift, 0, 1)
        state = ("retrieved" if accessibility >= _RETRIEVED_AT else
                 "blurred" if accessibility >= _BLURRED_AT else "unavailable")
        details.append(ReconstructedDetail(
            cue.detail_id, state, literal if state == "retrieved" else None,
            view.source_ref, cue.source_span, None, view.subjective_salience,
        ))

    tone = _midpoint(view.subjective_tone)
    weight = _midpoint(view.subjective_salience)
    duration_delta = _clamp(-tone * weight, -1, 1) if temporal_focus else None
    return RecollectionReconstruction(
        recollection_id=proposal.recollection_id,
        activity_id=proposal.activity_id,
        source_ref=view.source_ref,
        source_fields=tuple(source_fields),
        subjective_details=tuple(details),
        then_meaning_refs=then_meaning_refs,
        now_interpretation_refs=proposal.now_interpretation_refs,
        feeling_experience_refs=proposal.feeling_experience_refs,
        self_understanding_refs=proposal.self_understanding_refs,
        subjective_weight=view.subjective_salience,
        subjective_tone=view.subjective_tone,
        subjective_duration_delta=duration_delta,
        mood_ref=view.mood_ref,
        coupling_version=view.coupling_version,
        read_versions=view.read_versions,
        epoch=view.epoch,
    )
