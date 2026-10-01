from dataclasses import asdict

from sylanne3.domains.d03.context import AccountBinding, EntityAnchor, RoleBinding, WorldEvent
from sylanne3.domains.d03.cross_scene_social import project_cross_scene_social_v1
from sylanne3.domains.d05.relationship import RelationshipContribution
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


NS = NamespaceId("bot", "persona")
SOURCE = source_key(*NS.as_tuple, "private-one")
PRIVATE = "scene:private"
GROUP = "scene:group"
SPEAKER = "entity:sender"
DESTINATION = "group:project"
CONTRIBUTION = RelationshipContribution(
    "persona:persona", "family:one", SPEAKER, "closeness",
    "external_observation", 1, (SOURCE.token,))


def graph(*, source_audiences=("direct:sender",),
          access_audiences=("direct:sender",), access_status="active",
          group_revision=1, group_target=SPEAKER,
          group_role="collaborator", extra=()):
    source = SourceRecord(
        "private-one", "private message", "account:sender", "reported", "reported",
        1.0, 1.0, "family:one", tuple(source_audiences),
        ("context", "expression"), (),
    )
    anchor = EntityAnchor(SPEAKER, "account", "persona:persona", (SOURCE.token,), "active")
    evidence_key = AtomKey(Owner("event", *NS.as_tuple, "world:verified"),
                           "d03.world_event", "current")
    binding = AccountBinding("account:sender", "platform", "account:sender",
                             SPEAKER, evidence_key.token, 1.0, None)
    arrival = WorldEvent("world:arrival", "message_received", ((SPEAKER, "sender_account"),),
                         1.0, 1.0, 1.0, PRIVATE, (SOURCE.token,), "host_observed")
    verified = WorldEvent("world:verified", "message_received", ((SPEAKER, "sender_account"),),
                          1.0, 1.0, 1.0, PRIVATE,
                          (source_key(*NS.as_tuple, "account-proof").token,), "host_observed")
    roles = (
        RoleBinding("binding:private", "persona:persona", "friend", SPEAKER, None,
                    PRIVATE, "scene", "private", (), 1.0, None, 0,
                    (SOURCE.token,), 1, "active"),
        RoleBinding("binding:group", "persona:persona", group_role, group_target, None,
                    GROUP, "scene", "group", (), 1.0, None, 0,
                    (SOURCE.token,), 1, "active"),
    )
    atoms = (
        GraphAtom(SOURCE, 1, source.to_dict()),
        GraphAtom(access_key(*NS.as_tuple, "private-one"), 1, {
            "source_id": "private-one", "audiences": list(access_audiences),
            "purposes": ["context", "expression"], "status": access_status,
            "recorded_at": 1.0,
        }),
        GraphAtom(AtomKey(Owner("relation", *NS.as_tuple, SPEAKER),
                          "d05.contribution", CONTRIBUTION.key), 2,
                  asdict(CONTRIBUTION) | {"source_refs": [SOURCE.token]}),
        GraphAtom(AtomKey(Owner("event", *NS.as_tuple, "world:arrival"),
                          "d03.world_event", "current"), 1,
                  asdict(arrival) | {"participant_roles": [[SPEAKER, "sender_account"]],
                                     "source_refs": [SOURCE.token]}),
        GraphAtom(evidence_key, 1,
                  asdict(verified) | {"participant_roles": [[SPEAKER, "sender_account"]],
                                      "source_refs": list(verified.source_refs)}),
        GraphAtom(AtomKey(Owner("persona", *NS.as_tuple),
                          "d03.entity_anchor", SPEAKER), 1,
                  asdict(anchor) | {"creation_evidence_refs": [SOURCE.token]}),
        GraphAtom(AtomKey(Owner("persona", *NS.as_tuple),
                          "d03.account_binding", binding.account_id), 1, asdict(binding)),
        *(GraphAtom(AtomKey(Owner("scene", *NS.as_tuple, role.scene_ref),
                             "d03.role_binding", role.role_binding_id),
                     group_revision if role.scene_ref == GROUP else 1,
                     asdict(role) | {"norm_refs": [], "source_refs": [SOURCE.token]})
          for role in roles),
        *extra,
    )
    return GraphSnapshot(atoms, (NamespaceEpoch(*NS.as_tuple, 7),))


def project(snapshot):
    return project_cross_scene_social_v1(
        snapshot, QueryEpoch(NS, "all", 7), SOURCE.token, namespace=NS,
        target_scene_ref=GROUP, audience_scope=DESTINATION,
        relationship_contribution_key=CONTRIBUTION.key, now_utc=2.0,
    )


def test_private_source_remains_known_internally_but_cannot_be_expressed_to_group():
    candidate = project(graph())
    assert candidate.status == "hold"
    assert candidate.speaker_entity_ref == SPEAKER
    assert candidate.origin_scene_ref == PRIVATE
    assert candidate.audience_visibility == "group"
    assert (candidate.origin_social_role, candidate.target_social_role) == (
        "friend", "collaborator")
    assert candidate.disclosure_status == "restricted"
    assert candidate.reasons == ("source_not_disclosable_to_group",)
    assert {v.key.type_name for v in candidate.read_versions} >= {
        "memory.source", "memory.access", "d03.world_event", "d03.role_binding",
    }
    assert candidate.query_epoch == QueryEpoch(NS, "all", 7)


def test_access_expansion_alone_cannot_upgrade_private_source():
    assert project(graph(access_audiences=("direct:sender", DESTINATION))).status == "hold"
    assert project(graph(source_audiences=("direct:sender", DESTINATION))).status == "hold"
    assert project(graph(source_audiences=("direct:sender", DESTINATION),
                         access_audiences=("direct:sender", DESTINATION),
                         access_status="revoked")).status == "hold"


def test_explicit_dual_scope_candidate_carries_target_scene_version():
    result = project(graph(source_audiences=("direct:sender", DESTINATION),
                           access_audiences=("direct:sender", DESTINATION),
                           group_revision=3))
    assert result.status == "expression_candidate"
    assert result.disclosure_status == "eligible"
    assert result.relationship_disclosure_status == "eligible"
    assert (result.origin_social_role, result.target_social_role) == (
        "friend", "collaborator")
    assert any(v.key.type_name == "d05.contribution" and v.revision == 2
               for v in result.read_versions)
    assert any(v.key.type_name == "d03.role_binding" and v.key.owner.subject == GROUP
               and v.revision == 3 for v in result.read_versions)


def test_ambiguous_speaker_or_scene_does_not_choose_one():
    duplicate = GraphAtom(
        AtomKey(Owner("persona", *NS.as_tuple), "d03.account_binding", "account:other"),
        1, asdict(AccountBinding("account:other", "platform", "account:sender",
                                 SPEAKER, AtomKey(Owner("event", *NS.as_tuple, "world:verified"),
                                                  "d03.world_event", "current").token,
                                 1.0, None)),
    )
    assert project(graph(extra=(duplicate,))).status == "hold"
    additional_role = RoleBinding(
        "binding:group-two", "persona:persona", "companion", None, None,
        GROUP, "scene", "group", (), 1.0, None, 0, (SOURCE.token,), 1, "active")
    atom = GraphAtom(AtomKey(Owner("scene", *NS.as_tuple, GROUP),
                             "d03.role_binding", additional_role.role_binding_id),
                     1, asdict(additional_role) | {"norm_refs": [], "source_refs": [SOURCE.token]})
    assert project(graph(extra=(atom,))).status == "hold"


def test_group_role_for_another_person_cannot_relabel_private_relationship():
    result = project(graph(group_target="entity:other"))
    assert result.status == "hold"
    assert result.reasons == ("unique_current_scene_unavailable",)
    assert result.speaker_entity_ref == SPEAKER


def test_group_role_revision_changes_without_upgrading_relationship_disclosure():
    earlier_graph = graph(group_revision=1, group_role="collaborator")
    later_graph = graph(group_revision=2, group_role="observer")
    earlier = project(earlier_graph)
    later = project(later_graph)
    assert (earlier.status, later.status) == ("hold", "hold")
    assert earlier.target_social_role == "collaborator"
    assert later.target_social_role == "observer"
    assert earlier.relationship_disclosure_status == later.relationship_disclosure_status == "unavailable"
    assert earlier.disclosure_status == later.disclosure_status == "restricted"
    assert any(v.key.type_name == "d03.role_binding" and v.key.owner.subject == GROUP
               and v.revision == 2 for v in later.read_versions)
    relation_key = AtomKey(Owner("relation", *NS.as_tuple, SPEAKER),
                           "d05.contribution", CONTRIBUTION.key)
    assert earlier_graph.get(relation_key) == later_graph.get(relation_key)
