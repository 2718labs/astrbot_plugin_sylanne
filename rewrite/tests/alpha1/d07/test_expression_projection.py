"""D07 judgment expression preserves adopted stance and uncertainty."""

from dataclasses import asdict, replace

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d07 import BeliefRevision, EvidenceStatus, Stance
from sylanne3.domains.d07.expression_projection import project_adopted_judgment_for_expression
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")


def _case():
    source = source_key(*NS.as_tuple, "evidence")
    record = SourceRecord("evidence", "private transcript", "speaker", "reported",
                          "reported", 1.0, 2.0, "family", ("alice",), ("expression",))
    belief = BeliefRevision("belief", "question", "hypothesis", "person may be upset",
                            Stance.SUPPORT, 0.35, EvidenceStatus.INSUFFICIENT,
                            ("subjective_reaction",), (source.token,), ("family",))
    value = asdict(belief)
    value.update(schema="d07.belief_revision.v1", stance=belief.stance.value,
                 evidence_status=belief.evidence_status.value)
    for name in ("eligibility", "source_refs", "source_families", "invalidation_refs"):
        value[name] = list(value[name])
    key = AtomKey(Owner("persona", *NS.as_tuple), "d07.belief_revision.v1", "belief")
    access = access_key(*NS.as_tuple, "evidence")
    head = source_correction_head_key(NS, "evidence")
    snapshot = GraphSnapshot((
        GraphAtom(key, 1, value), GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 1, {"source_id": "evidence", "audiences": ["alice"],
                              "purposes": ["expression"], "status": "active", "recorded_at": 2.0}),
        GraphAtom(head, 0, {}, False),
    ), (NamespaceEpoch(*NS.as_tuple, 1),))
    return snapshot, key, access, head


def _read(snapshot, key):
    return project_adopted_judgment_for_expression(
        snapshot, NS, belief_ref=key.token, audience="alice",
    )


def _change(snapshot, key, **changes):
    return replace(snapshot, atoms=tuple(
        replace(atom, **changes) if atom.key == key else atom for atom in snapshot.atoms
    ))


def test_adopted_belief_projection_keeps_subjective_stance_and_omits_source_text():
    snapshot, key, _, _ = _case()
    result = _read(snapshot, key)
    assert result is not None
    assert result.stance == "support"
    assert result.uncertainty == "subjective_insufficient"
    assert result.proposition == "person may be upset"
    assert len(result.read_versions) == 4
    assert "private transcript" not in repr(result)
    assert not hasattr(result, "send_authority")


def test_unadopted_invalidated_or_revoked_judgment_holds():
    snapshot, key, access, head = _case()
    atom = snapshot.get(key)
    assert _read(_change(snapshot, key, value={**atom.value, "current": False,
                                               "invalidation_refs": ["correction"]}), key) is None
    assert _read(_change(snapshot, key, value={**atom.value, "stance": "suspend"}), key) is None
    assert _read(_change(snapshot, access, value={**snapshot.get(access).value,
                                                 "status": "withdrawn"}), key) is None
    assert _read(_change(snapshot, head, revision=1, valid=True), key) is None
