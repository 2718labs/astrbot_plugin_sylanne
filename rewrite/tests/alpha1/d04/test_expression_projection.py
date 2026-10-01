"""D04 expression sees qualified hypotheses, never complete affect diagnostics."""

from dataclasses import asdict, replace

from sylanne3.domains.d04.affect import FeelingState, SelfUnderstanding
from sylanne3.domains.d04.expression_projection import project_self_understanding_for_expression
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")


def _case():
    source = source_key(*NS.as_tuple, "evidence")
    record = SourceRecord("evidence", "private diagnostic text", "speaker", "reported",
                          "reported", 1.0, 2.0, "family", ("alice",), ("expression",))
    feeling = FeelingState("process", "object", "basis", "operator",
                           (("axis", 0.3),), ("meaning",), ("interpretation",), (),
                           (source.token,), "parameter", "coupling", 3.0)
    understanding = SelfUnderstanding("understanding", "process", ("I may feel uneasy",),
                                      ("perhaps because of uncertainty",), ("cause unknown",),
                                      0.4, (source.token,))
    ukey = AtomKey(Owner("persona", *NS.as_tuple), "d04.self_understanding.v1", "understanding")
    fkey = AtomKey(Owner("persona", *NS.as_tuple), "d04.feeling_state.v1", "process")
    access = access_key(*NS.as_tuple, "evidence")
    head = source_correction_head_key(NS, "evidence")
    understanding_value = asdict(understanding)
    for name in ("description_hypotheses", "reason_hypotheses", "unknown_parts",
                 "reflection_source_refs"):
        understanding_value[name] = list(understanding_value[name])
    feeling_value = asdict(feeling)
    for name in ("coordinates", "meaning_refs", "interpretation_refs",
                 "active_driver_refs", "historical_source_refs"):
        feeling_value[name] = list(feeling_value[name])
    feeling_value["coordinates"] = [list(item) for item in feeling_value["coordinates"]]
    atoms = (
        GraphAtom(ukey, 1, understanding_value), GraphAtom(fkey, 1, feeling_value),
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 1, {"source_id": "evidence", "audiences": ["alice"],
                              "purposes": ["expression"], "status": "active", "recorded_at": 2.0}),
        GraphAtom(head, 0, {}, False),
    )
    return GraphSnapshot(atoms, (NamespaceEpoch(*NS.as_tuple, 1),)), ukey, fkey, access, head


def _read(snapshot, ukey, fkey):
    return project_self_understanding_for_expression(
        snapshot, NS, understanding_ref=ukey.token, feeling_ref=fkey.token, audience="alice",
    )


def _change(snapshot, key, **changes):
    return replace(snapshot, atoms=tuple(
        replace(atom, **changes) if atom.key == key else atom for atom in snapshot.atoms
    ))


def test_narrow_hypothesis_projection_omits_diagnostic_and_guards_closure():
    snapshot, ukey, fkey, _, _ = _case()
    result = _read(snapshot, ukey, fkey)
    assert result is not None
    assert result.qualifier == "tentative_self_interpretation"
    assert result.description_hypotheses == ("I may feel uneasy",)
    assert result.unknown_parts == ("cause unknown",)
    assert len(result.read_versions) == 5
    assert "private diagnostic text" not in repr(result)
    assert "coordinates" not in repr(result)
    assert not hasattr(result, "send_authority")


def test_changed_understanding_or_source_access_holds():
    snapshot, ukey, fkey, access, head = _case()
    uatom = snapshot.get(ukey)
    assert _read(_change(snapshot, ukey, value={**uatom.value, "feeling_ref": "other"}), ukey, fkey) is None
    assert _read(_change(snapshot, access, value={**snapshot.get(access).value,
                                                 "status": "withdrawn"}), ukey, fkey) is None
    assert _read(_change(snapshot, head, valid=True, revision=1), ukey, fkey) is None
    assert _read(replace(snapshot, epochs=(NamespaceEpoch("bot", "other", 1),)), ukey, fkey) is None
