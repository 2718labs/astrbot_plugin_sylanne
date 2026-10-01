"""D04's fail-closed C04 salience compiler over one W01 graph read.

The installed encoding baseline records unknown numeric projections.  This
compiler does not replace its absent verified projection issuer with a caller
supplied interval.
"""

from __future__ import annotations

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, source_key
from ...runtime_contracts import NamespaceId, SourceQualification
from ..d06.c04_work_input_v2 import D04SalienceOriginalV2
from .affect import AffectCoupling, AffectProvider, AffectScheme, MoodField
from .encoding_baseline import decode_encoding_baseline


class C04SalienceUnavailable(ValueError):
    """No qualified D04 salience original can be compiled from these heads."""

    def __init__(self, reason: str, dependencies: tuple[GraphVersion, ...] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.dependencies = dependencies


def compile_c04_salience_original_v2(
    snapshot: GraphSnapshot,
    *,
    namespace: NamespaceId,
    source_ref: str,
    mood_ref: str,
    baseline_ref: str,
    source_qualification: SourceQualification,
    scheme: AffectScheme,
    coupling: AffectCoupling,
    read_versions: tuple[GraphVersion, ...],
) -> tuple[D04SalienceOriginalV2, tuple[GraphVersion, ...]]:
    """Compile only a committed, version-closed D04 projection, or HOLD.

    W01 must still prove the snapshot's live fence and access/deletion barrier.
    The current ``d04.encoding_baseline.v1`` forbids known intervals, so the
    installed code always holds at ``verified_projection_issuer_missing``
    after validating the supplied graph originals.
    """
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(source_qualification) is not SourceQualification
            or type(scheme) is not AffectScheme or type(coupling) is not AffectCoupling
            or type(read_versions) is not tuple
            or any(type(item) is not GraphVersion for item in read_versions)):
        raise TypeError("C04 salience requires typed D04 originals and graph read versions")
    try:
        source, mood, baseline = (AtomKey.from_token(ref)
                                  for ref in (source_ref, mood_ref, baseline_ref))
    except (TypeError, ValueError) as exc:
        raise C04SalienceUnavailable("invalid_original_ref") from exc
    if (source != source_key(*namespace.as_tuple, source.owner.subject or "")
            or mood.type_name != "d04.mood_field.v1" or mood.owner.kind != "persona"
            or baseline.type_name != "d04.encoding_baseline.v1"
            or baseline.owner != source.owner
            or any((key.owner.bot, key.owner.persona) != namespace.as_tuple
                   for key in (source, mood, baseline))):
        raise C04SalienceUnavailable("original_namespace_or_type_mismatch")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        raise C04SalienceUnavailable("snapshot_namespace_or_epoch_mismatch")
    guarded = {item.key: item for item in read_versions}
    if len(guarded) != len(read_versions):
        raise C04SalienceUnavailable("duplicate_read_version")
    atoms = (snapshot.get(source), snapshot.get(mood), snapshot.get(baseline))
    if any(atom is None or not atom.valid or atom.revision < 1
           or guarded.get(atom.key) != GraphVersion(atom.key, atom.revision)
           for atom in atoms):
        raise C04SalienceUnavailable("original_absent_or_stale")
    source_atom, mood_atom, baseline_atom = atoms
    dependencies = tuple(GraphVersion(atom.key, atom.revision) for atom in atoms)
    try:
        record = SourceRecord.from_dict(source_atom.value)
        mood_spec = next(spec for spec in AffectProvider(active_scheme=scheme).type_specs()
                         if spec.name == "d04.mood_field.v1")
        mood_value = mood_spec.validator(mood_atom.value)
        baseline_value = decode_encoding_baseline(baseline_atom.value)
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        raise C04SalienceUnavailable("invalid_original_payload", dependencies) from exc
    if (record.source_id != source.owner.subject
            or baseline_value.baseline_id != baseline.name
            or baseline_value.source_refs != (source_ref,)
            or mood_value.mood_id != mood_ref
            or not isinstance(mood_value, MoodField)
            or (mood_value.basis_version, mood_value.parameter_version,
                mood_value.coupling_version)
            != (scheme.scheme_version, scheme.parameter_version,
                scheme.coupling_version)
            or (baseline_value.basis_version, baseline_value.parameter_version)
            != (scheme.scheme_version, scheme.parameter_version)
            or coupling.version != scheme.coupling_version):
        raise C04SalienceUnavailable("original_identity_or_scheme_mismatch", dependencies)
    if (source_ref not in source_qualification.source_refs
            or not set(mood_value.source_refs) <= set(source_qualification.source_refs)):
        raise C04SalienceUnavailable("source_unqualified", dependencies)
    family = {"observed": "observed", "reported": "reported",
              "authored": "authored", "simulated": "simulated",
              "internal": "derived"}[record.source_kind]
    reality = {"observed": "external_observation",
               "reported": "external_report", "authored": "authored_content",
               "simulated": "simulation", "internal": "inference"}[record.source_kind]
    if (source_qualification.source_family != family
            or source_qualification.content_reality != reality
            or source_qualification.occurred_at != record.occurred_at
            or source_qualification.learned_at != record.recorded_at
            or (source_qualification.evidence_eligibility == "eligible"
                and (record.source_kind != "observed"
                     or record.assertion_status != "confirmed"))):
        raise C04SalienceUnavailable("source_unqualified", dependencies)
    try:
        baseline_value.verify_committed_refs(snapshot)
    except (TypeError, ValueError) as exc:
        raise C04SalienceUnavailable("baseline_dependency_absent_or_stale", dependencies) from exc
    baseline_refs = (baseline_value.source_refs
                     + (baseline_value.perspective_ref,)
                     + baseline_value.perspective_dependency_refs(snapshot)
                     + tuple(item.ref for item in baseline_value.then_feeling_versions)
                     + tuple(item.ref for item in baseline_value.interpretation_versions))
    for ref in baseline_refs:
        key = AtomKey.from_token(ref)
        atom = snapshot.get(key)
        if guarded.get(key) != GraphVersion(key, atom.revision):
            raise C04SalienceUnavailable("baseline_dependency_read_unfenced", dependencies)
    dependencies = tuple(sorted(
        {GraphVersion(snapshot.get(AtomKey.from_token(ref)).key,
                      snapshot.get(AtomKey.from_token(ref)).revision)
         for ref in (*baseline_refs, mood_ref, baseline_ref)},
        key=lambda item: item.key.token,
    ))
    if baseline_value.salience_interval is None or baseline_value.tone_interval is None:
        raise C04SalienceUnavailable("verified_projection_issuer_missing", dependencies)
    influence = AffectProvider(active_scheme=scheme).condition_recollection(
        memory_ref=source_ref, memory_source_refs=(source_ref,),
        base_salience_interval=baseline_value.salience_interval,
        base_tone_interval=baseline_value.tone_interval,
        mood=mood_value, coupling=coupling,
    )
    return D04SalienceOriginalV2(
        source_ref, mood_ref, baseline_value.salience_interval,
        influence.salience_interval, coupling.version,
    ), dependencies


__all__ = ["C04SalienceUnavailable", "compile_c04_salience_original_v2"]
