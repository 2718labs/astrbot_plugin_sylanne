"""The current D04 encoding contract cannot certify C04 salience numbers."""

from dataclasses import asdict

import pytest

from sylanne3.domains.d04.affect import AffectAxis, AffectCoupling, AffectScheme, MoodField
from sylanne3.domains.d04.c04_salience_original import (
    C04SalienceUnavailable, compile_c04_salience_original_v2,
)
from sylanne3.domains.d04.encoding_baseline import EncodingBaseline
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord
from sylanne3.runtime_contracts import NamespaceId, SourceQualification


def _case():
    namespace = NamespaceId("bot", "persona")
    source = AtomKey(Owner("event", "bot", "persona", "event:1"), "memory.source", "record")
    mood = AtomKey(Owner("persona", "bot", "persona"), "d04.mood_field.v1", "mood:1")
    perspective = AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "self:1")
    baseline = AtomKey(source.owner, "d04.encoding_baseline.v1", "baseline:1")
    record = SourceRecord("event:1", "hello", "speaker:1", "observed", "confirmed",
                          1.0, 1.0, "root:1", ("user:1",), ("context",))
    mood_value = MoodField(mood.token, "scheme:1", (("care", 0.2),),
                           (source.token,), "parameter:1", "coupling:1", 1.0)
    baseline_value = EncodingBaseline(
        "baseline:1", (source.token,), perspective.token, (), (), 1.0,
        "policy:1", "policy:1", "scheme:1", "parameter:1", None, None,
        ("salience_interval:numeric_projection_uncertified",
         "tone_interval:numeric_projection_uncertified"),
    )
    atoms = (
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(mood, 2, {**asdict(mood_value), "coordinates": [["care", 0.2]],
                            "source_refs": [source.token]}),
        GraphAtom(perspective, 1, {}),
        GraphAtom(baseline, 1, {**asdict(baseline_value), "source_refs": [source.token],
                                 "then_feeling_versions": [], "interpretation_versions": [],
                                 "unknown_reasons": list(baseline_value.unknown_reasons)}),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 4),))
    qualification = SourceQualification(
        (source.token,), "observed", 1.0, 1.0, "external_observation", "eligible",
        0.7, "not_applicable",
    )
    scheme = AffectScheme("d04.affect.scheme.v1", "scheme:1", "operator:1",
                          "parameter:1", "coupling:1",
                          (AffectAxis("care", "normalized", "care"),), ())
    coupling = AffectCoupling("recall:1", "coupling:1", "care", "care", 0.0, 0.5, 0.0)
    kwargs = dict(namespace=namespace, source_ref=source.token, mood_ref=mood.token,
                  baseline_ref=baseline.token, source_qualification=qualification,
                  scheme=scheme, coupling=coupling,
                  read_versions=tuple(GraphVersion(atom.key, atom.revision) for atom in atoms))
    return snapshot, kwargs


def test_unknown_committed_baseline_holds_with_exact_dependencies():
    snapshot, kwargs = _case()
    with pytest.raises(C04SalienceUnavailable) as error:
        compile_c04_salience_original_v2(snapshot, **kwargs)
    assert error.value.reason == "verified_projection_issuer_missing"
    assert {item.key.token for item in error.value.dependencies} == {
        kwargs["source_ref"], kwargs["mood_ref"], kwargs["baseline_ref"],
        next(atom.key.token for atom in snapshot.atoms
             if atom.key.type_name == "d03.entity_anchor"),
    }


def test_cross_namespace_and_stale_head_hold_before_projection():
    snapshot, kwargs = _case()
    wrong = dict(kwargs, namespace=NamespaceId("bot", "other"))
    with pytest.raises(C04SalienceUnavailable, match="original_namespace_or_type_mismatch"):
        compile_c04_salience_original_v2(snapshot, **wrong)
    stale = dict(kwargs, read_versions=tuple(
        GraphVersion(item.key, 1) if item.key.token == kwargs["mood_ref"] else item
        for item in kwargs["read_versions"]
    ))
    with pytest.raises(C04SalienceUnavailable, match="original_absent_or_stale"):
        compile_c04_salience_original_v2(snapshot, **stale)
    unqualified = dict(kwargs, source_qualification=SourceQualification(
        ("other:source",), "observed", 1.0, 1.0, "external_observation",
        "eligible", 0.7, "not_applicable",
    ))
    with pytest.raises(C04SalienceUnavailable, match="source_unqualified"):
        compile_c04_salience_original_v2(snapshot, **unqualified)
