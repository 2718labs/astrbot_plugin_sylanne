"""Pure D03 structure for a qualified host message arrival."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...graph_types import AtomKey, GraphVersion, Owner
from ...host.ingress import HostIngressEnvelope
from ...memory_types import SourceRecord, access_key, source_key
from ...runtime.first_ingress_v2 import scene_ref_for_conversation
from ...runtime_contracts import SourceQualification, canonical_digest
from .context import EntityAnchor, WorldEvent

if TYPE_CHECKING:
    from ...host.current_scene import CurrentHostScene


@dataclass(frozen=True)
class MessageArrivalCandidate:
    """A proposal with its source guards; it is neither a graph write nor authority."""

    sender_anchor: EntityAnchor
    sender_key: AtomKey
    event: WorldEvent
    event_key: AtomKey
    source_version: GraphVersion
    access_version: GraphVersion


def build_message_arrival_candidate(
    ingress: HostIngressEnvelope,
    current_scene: CurrentHostScene,
    source: SourceRecord,
    qualification: SourceQualification,
    *,
    source_version: GraphVersion,
    access_version: GraphVersion,
) -> MessageArrivalCandidate:
    """Describe the host-observed receipt, without endorsing the message text.

    The caller obtains ``current_scene`` through the host verifier and both
    graph versions through a current D06 read. A committing graph transaction
    must check those guards and the source's current access state again.
    """
    if not isinstance(ingress, HostIngressEnvelope):
        raise TypeError("host ingress is required")
    if not isinstance(source, SourceRecord) or not isinstance(qualification, SourceQualification):
        raise TypeError("qualified D06 source is required")
    namespace = ingress.namespace
    expected_scene = scene_ref_for_conversation(
        namespace, ingress.platform_ref, ingress.conversation_ref,
    )
    if (
        current_scene.namespace != namespace
        or current_scene.platform_ref != ingress.platform_ref
        or current_scene.conversation_ref != ingress.conversation_ref
        or current_scene.visibility != ingress.visibility
        or current_scene.scene_ref != expected_scene
    ):
        raise ValueError("current host scene differs from this ingress")
    source_atom = source_key(*namespace.as_tuple, ingress.lineage.source_ref)
    access_atom = access_key(*namespace.as_tuple, ingress.lineage.source_ref)
    if (
        source_version.key != source_atom or source_version.revision < 1
        or access_version.key != access_atom or access_version.revision < 1
        or qualification.source_refs != (source_atom.token,)
        or qualification.source_family != "reported"
        or qualification.content_reality != "external_report"
        or qualification.evidence_eligibility != "qualified"
        or qualification.occurred_at != ingress.occurred_at
        or qualification.learned_at != ingress.learned_at
        or source.source_id != ingress.lineage.source_ref
        or source.text != ingress.text
        or source.speaker_id != ingress.sender_ref
        or source.source_kind != "reported"
        or source.assertion_status != "reported"
        or source.occurred_at != ingress.occurred_at
        or source.recorded_at != ingress.learned_at
        or source.provenance_root != ingress.lineage.provenance_family
        or source.audiences != (ingress.conversation_ref,)
        or "context" not in source.purposes
    ):
        raise ValueError("current qualified source differs from host message")

    sender_id = "entity:account-v1:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": ingress.platform_ref,
        "sender_ref": ingress.sender_ref,
    })
    event_id = "world:message-arrival-v1:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": ingress.platform_ref,
        "conversation_ref": ingress.conversation_ref,
        "message_id": ingress.message_id,
        "source_id": source.source_id,
    })
    sender = EntityAnchor(
        sender_id, "account", f"persona:{namespace.persona_id}",
        (source_atom.token,), "active",
    )
    event = WorldEvent(
        event_id, "message_received", ((sender_id, "sender_account"),),
        source.recorded_at, source.recorded_at, source.recorded_at,
        expected_scene, (source_atom.token,), "host_observed",
    )
    return MessageArrivalCandidate(
        sender,
        AtomKey(Owner("persona", *namespace.as_tuple), "d03.entity_anchor", sender_id),
        event,
        AtomKey(Owner("event", *namespace.as_tuple, event_id), "d03.world_event", "current"),
        source_version, access_version,
    )


__all__ = ("MessageArrivalCandidate", "build_message_arrival_candidate")
