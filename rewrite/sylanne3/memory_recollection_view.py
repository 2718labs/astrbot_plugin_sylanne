"""Source-preserving, read-only projection of one selected recollection.

This is a candidate view. D07 selects the source; D04 supplies the mood
transform. D11 must revalidate the returned versions before any C04 commit.
"""

from dataclasses import dataclass

from .domains.d04 import AffectCoupling, AffectProvider, AffectScheme, MoodField
from .domains.d06 import CandidateSet, SelectionTicket
from .graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from .memory_retrieval import MemoryHit
from .memory_types import SourceRecord, source_key
from .runtime_contracts import SourceQualification


@dataclass(frozen=True)
class AffectiveRecollectionView:
    source_ref: str
    source_text: str
    source_kind: str
    assertion_status: str
    subjective_salience: tuple[float, float]
    subjective_tone: tuple[float, float]
    mood_ref: str
    coupling_version: str
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    status: str = "candidate"


def prepare_affective_recollection_view(
    *,
    ticket: SelectionTicket,
    candidates: CandidateSet,
    hit: MemoryHit,
    mood_snapshot: GraphSnapshot,
    mood_key: AtomKey,
    scheme: AffectScheme,
    coupling: AffectCoupling,
    source_qualification: SourceQualification,
    base_salience: tuple[float, float],
    base_tone: tuple[float, float],
    purpose: str,
) -> AffectiveRecollectionView:
    """Color a qualified source without changing its bytes or evidence weight."""
    if not isinstance(ticket, SelectionTicket) or not isinstance(candidates, CandidateSet):
        raise TypeError("D07 selection and D06 candidate set are required")
    if not isinstance(hit, MemoryHit) or not isinstance(hit.record, SourceRecord):
        raise TypeError("a source retrieval hit is required")
    if not isinstance(mood_snapshot, GraphSnapshot) or not isinstance(mood_key, AtomKey):
        raise TypeError("a D04 graph snapshot and mood key are required")
    if not isinstance(scheme, AffectScheme) or not isinstance(coupling, AffectCoupling):
        raise TypeError("active D04 scheme and coupling are required")
    if not isinstance(source_qualification, SourceQualification):
        raise TypeError("classified source qualification is required")
    if ticket.candidate_set_id != candidates.candidate_set_id or len(ticket.selected_candidate_ids) != 1:
        raise ValueError("view requires exactly one selected candidate from this set")
    selected = next((item for item in candidates.items
                     if item.candidate_id == ticket.selected_candidate_ids[0]), None)
    if selected is None or selected.content_ref != hit.record.source_id:
        raise ValueError("retrieval hit does not match the selected source")
    if purpose not in selected.allowed_purposes:
        raise PermissionError("candidate is unavailable for this purpose")
    if hit.key != source_key(hit.key.owner.bot, hit.key.owner.persona, hit.record.source_id):
        raise ValueError("retrieval hit is not the selected source atom")
    if mood_key.type_name != "d04.mood_field.v1" or mood_key.owner.kind != "persona":
        raise ValueError("mood key must be the D04 persona mood")
    namespace = (hit.key.owner.bot, hit.key.owner.persona)
    if (mood_key.owner.bot, mood_key.owner.persona) != namespace:
        raise ValueError("mood and source cross namespaces")
    if len(mood_snapshot.epochs) != 1 or (
        mood_snapshot.epochs[0].bot, mood_snapshot.epochs[0].persona
    ) != namespace:
        raise ValueError("mood snapshot does not cover the selected namespace")
    source_version = GraphVersion(hit.key, next(
        (version.revision for version in hit.proof_versions if version.key == hit.key), 0
    ))
    if source_version.revision == 0:
        raise ValueError("retrieval hit lacks a positive source read proof")
    mood_atom = mood_snapshot.get(mood_key)
    if mood_atom is None or not mood_atom.valid:
        raise ValueError("committed D04 mood is unavailable")
    mood_spec = next(spec for spec in AffectProvider(active_scheme=scheme).type_specs()
                     if spec.name == mood_key.type_name)
    mood = mood_spec.validator(mood_atom.value)
    if not isinstance(mood, MoodField) or (
        mood.basis_version, mood.parameter_version, mood.coupling_version
    ) != (scheme.scheme_version, scheme.parameter_version, scheme.coupling_version):
        raise ValueError("mood is outside the active affect scheme")
    if coupling.version != scheme.coupling_version:
        raise ValueError("coupling is outside the active affect scheme")
    qualified = set(source_qualification.source_refs)
    if hit.key.token not in qualified or not set(mood.source_refs) <= qualified:
        raise ValueError("selected source or mood basis lacks qualification")
    influence = AffectProvider(active_scheme=scheme).condition_recollection(
        memory_ref=hit.key.token,
        memory_source_refs=(hit.key.token,),
        base_salience_interval=base_salience,
        base_tone_interval=base_tone,
        mood=mood,
        coupling=coupling,
    )
    if influence.evidence_weight_delta != 0:
        raise ValueError("mood must not change source evidence weight")
    return AffectiveRecollectionView(
        hit.key.token, hit.record.text, hit.record.source_kind,
        hit.record.assertion_status, influence.salience_interval,
        influence.tone_interval, mood_key.token, coupling.version,
        tuple(dict.fromkeys((*hit.proof_versions, GraphVersion(mood_key, mood_atom.revision)))),
        mood_snapshot.epochs[0],
    )
