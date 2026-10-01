from dataclasses import asdict

from sylanne3.domains.d05 import RelationshipContribution
from sylanne3.domains.d05.audience import qualify_contribution_for_audience
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
RELATION = Owner("relation", "bot", "persona", "entity:friend")


def _source(source_id, audiences):
    record = SourceRecord(
        source_id, "observed interaction", "entity:friend", "reported", "reported",
        1.0, 1.0, f"family:{source_id}", tuple(audiences), ("expression",), (),
    )
    return (
        GraphAtom(source_key(*NS.as_tuple, source_id), 1, record.to_dict()),
        GraphAtom(access_key(*NS.as_tuple, source_id), 1, {
            "source_id": source_id, "audiences": list(audiences),
            "purposes": ["expression"], "status": "active", "recorded_at": 1.0,
        }),
    )


def _contribution(sources):
    item = RelationshipContribution(
        "persona:persona", "event:one", "entity:friend", "closeness",
        "external_observation", 1, tuple(
            source_key(*NS.as_tuple, source_id).token for source_id in sources
        ),
    )
    atom = GraphAtom(AtomKey(RELATION, "d05.contribution", item.key), 1,
                     asdict(item) | {"source_refs": list(item.source_refs)})
    return item, atom


def test_mixed_private_and_group_evidence_cannot_project_to_group():
    item, contribution = _contribution(("private", "public"))
    snapshot = GraphSnapshot((
        contribution, *_source("private", ("direct:friend",)),
        *_source("public", ("direct:friend", "group:project")),
    ), (NamespaceEpoch("bot", "persona", 6),))
    private = qualify_contribution_for_audience(
        snapshot, item.key, namespace=NS, audience="direct:friend",
        purpose="expression",
    )
    group = qualify_contribution_for_audience(
        snapshot, item.key, namespace=NS, audience="group:project",
        purpose="expression",
    )
    assert private.status == "eligible"
    assert len(private.read_versions) == 5
    assert group.status == "unavailable"
    assert group.contribution_key is None
    assert group.read_versions == ()


def test_revoked_access_or_wrong_owner_does_not_replay_relation_contribution():
    item, contribution = _contribution(("private",))
    source, access = _source("private", ("direct:friend",))
    revoked = GraphAtom(access.key, 2, {**access.value, "status": "revoked"})
    snapshot = GraphSnapshot((contribution, source, revoked),
                             (NamespaceEpoch("bot", "persona", 7),))
    result = qualify_contribution_for_audience(
        snapshot, item.key, namespace=NS, audience="direct:friend",
        purpose="expression",
    )
    assert result.status == "unavailable"
    foreign = GraphAtom(AtomKey(Owner("relation", "bot", "other", "entity:friend"),
                                "d05.contribution", item.key), 1, contribution.value)
    cross_role = GraphSnapshot((foreign, source, access),
                               (NamespaceEpoch("bot", "persona", 7),))
    assert qualify_contribution_for_audience(
        cross_role, item.key, namespace=NS, audience="direct:friend",
        purpose="expression",
    ).status == "unavailable"


def test_conflicting_access_revisions_cannot_replay_an_old_permission():
    item, contribution = _contribution(("private",))
    source, access = _source("private", ("direct:friend",))
    revoked = GraphAtom(access.key, 2, {**access.value, "status": "revoked"})
    conflicting = GraphSnapshot((contribution, source, access, revoked),
                                (NamespaceEpoch("bot", "persona", 8),))
    assert qualify_contribution_for_audience(
        conflicting, item.key, namespace=NS, audience="direct:friend",
        purpose="expression",
    ).status == "unavailable"


def test_graph_revision_and_semantic_contribution_revision_are_separate():
    item, contribution = _contribution(("private",))
    source, access = _source("private", ("direct:friend",))
    updated_graph = GraphAtom(contribution.key, 3, contribution.value)
    result = qualify_contribution_for_audience(
        GraphSnapshot((updated_graph, source, access),
                      (NamespaceEpoch("bot", "persona", 9),)),
        item.key, namespace=NS, audience="direct:friend", purpose="expression",
    )
    assert result.status == "eligible"
    assert result.read_versions[0].revision == 3
