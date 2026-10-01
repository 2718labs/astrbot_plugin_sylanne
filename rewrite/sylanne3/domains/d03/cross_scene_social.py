"""Speaker and audience version closure for cross-scene expression candidates.

This is a read projection only. W01 must obtain a full current graph snapshot
under its fence and reissue the projection before D11 admission. D09 may use
the candidate to omit restricted content; it cannot treat it as send authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, source_key
from ...runtime_contracts import NamespaceId, QueryEpoch
from ..d05.audience import qualify_contribution_for_audience
from ..d05.disclosure import qualify_source_disclosure_v1
from ..d05.relationship import RelationshipContribution, _tuple_payload
from .context import AccountBinding, EntityAnchor, RoleBinding, WorldEvent


@dataclass(frozen=True, slots=True)
class CrossSceneSocialCandidateV1:
    status: str
    reasons: tuple[str, ...]
    source_ref: str
    origin_scene_ref: str | None
    target_scene_ref: str
    speaker_entity_ref: str | None
    origin_social_role: str | None
    target_social_role: str | None
    audience_scope: str
    audience_visibility: str | None
    disclosure_status: str
    relationship_contribution_key: str
    relationship_disclosure_status: str
    graph_epoch: int | None
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch | None
    negative_predicates: tuple[str, ...]


def project_cross_scene_social_v1(
    snapshot: GraphSnapshot, query: QueryEpoch, source_ref: str, *,
    namespace: NamespaceId, target_scene_ref: str, audience_scope: str,
    relationship_contribution_key: str, now_utc: float,
) -> CrossSceneSocialCandidateV1:
    """Read a host-observed speaker and current target scene without disclosure uplift.

    `audience_scope` is the exact destination used by D06, not a member name.
    Full-query coverage and host destination mapping remain W01 obligations.
    """
    if (type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(namespace) is not NamespaceId or type(source_ref) is not str
            or type(target_scene_ref) is not str or not target_scene_ref.startswith("scene:")
            or type(audience_scope) is not str or not audience_scope
            or type(relationship_contribution_key) is not str
            or not relationship_contribution_key.startswith("contribution:")
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise TypeError("typed current graph and target scope required")
    epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
    graph_epoch = epoch.revision if epoch is not None else None
    def hold(reason: str, *, speaker=None, origin=None, visibility=None,
             disclosure="unavailable", relationship_disclosure="unavailable",
             origin_role=None, target_role=None, reads=()):
        return CrossSceneSocialCandidateV1(
            "hold", (reason,), source_ref, origin, target_scene_ref, speaker,
            origin_role, target_role, audience_scope, visibility, disclosure,
            relationship_contribution_key,
            relationship_disclosure, graph_epoch,
            tuple(sorted(set(reads), key=lambda v: v.key.token)),
            query if graph_epoch == query.revision else None,
            ("d03.world_event:message_received:source:unique",
             "d03.account_binding:sender:unique_current",
             "d03.role_binding:origin_and_target:unique_active",
             "d05.contribution:relationship_key:unique"),
        )
    if (epoch is None or (epoch.bot, epoch.persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", epoch.revision)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        return hold("current_full_graph_query_unavailable")
    try:
        source_key_ref = AtomKey.from_token(source_ref)
        if source_key_ref != source_key(*namespace.as_tuple,
                                        source_key_ref.owner.subject or ""):
            return hold("canonical_source_unavailable")
        source_atom = snapshot.get(source_key_ref)
        if source_atom is None or not source_atom.valid or source_atom.revision < 1:
            return hold("source_unavailable")
        source = SourceRecord.from_dict(source_atom.value)
        if source.source_id != source_key_ref.owner.subject:
            return hold("source_unavailable")
        reads = [GraphVersion(source_atom.key, source_atom.revision)]
        arrivals = []
        for atom in snapshot.atoms:
            if (atom.key.type_name == "d03.world_event" and atom.valid
                    and atom.revision > 0 and atom.value.get("kind") == "message_received"
                    and source_ref in atom.value.get("source_refs", ())):
                arrivals.append(atom)
        if len(arrivals) != 1:
            return hold("unique_host_arrival_unavailable", reads=reads)
        arrival_atom = arrivals[0]
        arrival = WorldEvent(**{
            **arrival_atom.value,
            "participant_roles": tuple(tuple(pair) for pair in arrival_atom.value["participant_roles"]),
            "source_refs": tuple(arrival_atom.value["source_refs"]),
        })
        reads.append(GraphVersion(arrival_atom.key, arrival_atom.revision))
        if (arrival_atom.key.owner.kind != "event"
                or (arrival_atom.key.owner.bot, arrival_atom.key.owner.persona)
                   != namespace.as_tuple
                or arrival_atom.key.owner.subject != arrival.event_id
                or arrival_atom.key.name != "current"
                or arrival.reality != "host_observed"
                or arrival.source_refs != (source_ref,)
                or source.recorded_at != arrival.learned_at
                or len(arrival.participant_roles) != 1
                or arrival.participant_roles[0][1] != "sender_account"):
            return hold("host_speaker_unavailable", reads=reads)
        speaker = arrival.participant_roles[0][0]
        anchors = [atom for atom in snapshot.atoms
                   if atom.key.type_name == "d03.entity_anchor"
                   and atom.key.name == speaker and atom.valid and atom.revision > 0]
        bindings = [atom for atom in snapshot.atoms
                    if atom.key.type_name == "d03.account_binding"
                    and atom.valid and atom.revision > 0
                    and atom.value.get("entity_id") == speaker]
        if len(anchors) != 1 or len(bindings) != 1:
            return hold("unique_speaker_binding_unavailable", speaker=speaker,
                        origin=arrival.scene_ref, reads=reads)
        anchor_atom, binding_atom = anchors[0], bindings[0]
        anchor = EntityAnchor(**{
            **anchor_atom.value,
            "creation_evidence_refs": tuple(anchor_atom.value["creation_evidence_refs"]),
        })
        binding = AccountBinding(**binding_atom.value)
        reads.extend((GraphVersion(anchor_atom.key, anchor_atom.revision),
                      GraphVersion(binding_atom.key, binding_atom.revision)))
        evidence_key = AtomKey.from_token(binding.verification_ref)
        evidence_atom = snapshot.get(evidence_key)
        if (evidence_atom is None or not evidence_atom.valid
                or evidence_atom.revision < 1
                or evidence_key.type_name != "d03.world_event"
                or evidence_key.owner.kind != "event"
                or (evidence_key.owner.bot, evidence_key.owner.persona) != namespace.as_tuple
                or evidence_atom.value.get("kind") != "message_received"
                or evidence_atom.value.get("reality") != "host_observed"
                or evidence_atom.value.get("participant_roles")
                   != [[speaker, "sender_account"]]):
            return hold("speaker_evidence_unavailable", speaker=speaker,
                        origin=arrival.scene_ref, reads=reads)
        reads.append(GraphVersion(evidence_key, evidence_atom.revision))
        if (anchor_atom.key.owner.kind != "persona"
                or binding_atom.key.owner.kind != "persona"
                or anchor_atom.key.owner.bot != namespace.bot_id
                or anchor_atom.key.owner.persona != namespace.persona_id
                or binding_atom.key.owner.bot != namespace.bot_id
                or binding_atom.key.owner.persona != namespace.persona_id
                or anchor.entity_id != speaker
                or anchor.kind != "account" or anchor.status != "active"
                or anchor.owner_scope != f"persona:{namespace.persona_id}"
                or binding_atom.key.name != binding.account_id
                or binding.entity_id != speaker
                or binding.platform_identifier != source.speaker_id
                or binding.valid_from > now_utc
                or (binding.valid_until is not None and now_utc >= binding.valid_until)):
            return hold("current_speaker_binding_unavailable", speaker=speaker,
                        origin=arrival.scene_ref, reads=reads)
        scenes = {}
        for scene_ref in {arrival.scene_ref, target_scene_ref}:
            matches = []
            for atom in snapshot.atoms:
                if (atom.key.type_name != "d03.role_binding" or not atom.valid
                        or atom.revision < 1 or atom.key.owner.kind != "scene"
                        or atom.key.owner.subject != scene_ref
                        or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple):
                    continue
                role = RoleBinding(**{
                    **atom.value, "norm_refs": tuple(atom.value["norm_refs"]),
                    "source_refs": tuple(atom.value["source_refs"]),
                })
                if (role.scene_ref == scene_ref and role.scope_selector == "scene"
                        and role.subject_persona_ref == f"persona:{namespace.persona_id}"
                        and role.target_entity_ref in (None, speaker)
                        and role.status == "active" and role.effective_from <= now_utc
                        and (role.effective_until is None or now_utc <= role.effective_until)):
                    matches.append((atom, role))
            if len(matches) != 1:
                return hold("unique_current_scene_unavailable", speaker=speaker,
                            origin=arrival.scene_ref, reads=reads)
            scenes[scene_ref] = matches[0][1]
            reads.append(GraphVersion(matches[0][0].key, matches[0][0].revision))
        origin_role = scenes[arrival.scene_ref]
        target_role = scenes[target_scene_ref]
        if origin_role.visibility_scope != "private":
            return hold("origin_not_private", speaker=speaker,
                        origin=arrival.scene_ref, reads=reads)
        if target_role.visibility_scope != "group":
            return hold("target_not_group", speaker=speaker,
                        origin=arrival.scene_ref, reads=reads)
        disclosure = qualify_source_disclosure_v1(
            snapshot, source_ref, namespace=namespace,
            audience_scope=audience_scope, purpose="expression")
        reads.extend(disclosure.read_versions)
        relation = qualify_contribution_for_audience(
            snapshot, relationship_contribution_key, namespace=namespace,
            audience=audience_scope, purpose="expression")
        reads.extend(relation.read_versions)
        if disclosure.status != "eligible":
            return hold("source_not_disclosable_to_group", speaker=speaker,
                        origin=arrival.scene_ref, visibility="group",
                        disclosure=disclosure.status,
                        relationship_disclosure=relation.status,
                        origin_role=origin_role.social_role,
                        target_role=target_role.social_role, reads=reads)
        contributions = [atom for atom in snapshot.atoms
                         if atom.key.type_name == "d05.contribution"
                         and atom.key.name == relationship_contribution_key]
        if len(contributions) != 1:
            return hold("relationship_contribution_unavailable", speaker=speaker,
                        origin=arrival.scene_ref, visibility="group",
                        disclosure=disclosure.status,
                        origin_role=origin_role.social_role,
                        target_role=target_role.social_role, reads=reads)
        contribution = RelationshipContribution(**_tuple_payload(
            contributions[0].value, "source_refs"))
        if (relation.status != "eligible" or source_ref not in contribution.source_refs
                or contribution.subject_entity_ref != speaker):
            return hold("relationship_not_disclosable_to_group", speaker=speaker,
                        origin=arrival.scene_ref, visibility="group",
                        disclosure=disclosure.status,
                        relationship_disclosure=relation.status,
                        origin_role=origin_role.social_role,
                        target_role=target_role.social_role, reads=reads)
        return CrossSceneSocialCandidateV1(
            "expression_candidate", (), source_ref, arrival.scene_ref,
            target_scene_ref, speaker, origin_role.social_role,
            target_role.social_role, audience_scope, "group", "eligible",
            relationship_contribution_key, "eligible",
            graph_epoch, tuple(sorted(set(reads), key=lambda v: v.key.token)),
            query, ("d03.world_event:message_received:source:unique",
                    "d03.account_binding:sender:unique_current",
                    "d03.role_binding:origin_and_target:unique_active",
                    "d05.contribution:relationship_key:unique"),
        )
    except (TypeError, ValueError, KeyError):
        return hold("current_social_graph_unavailable")


__all__ = ["CrossSceneSocialCandidateV1", "project_cross_scene_social_v1"]
