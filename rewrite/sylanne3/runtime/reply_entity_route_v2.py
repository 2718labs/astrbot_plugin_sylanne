"""Current original-ingress account entity for one private reply.

The reader runs only in the coordinator's held graph transaction.  Its value
is evidence for a later same-transaction check, never a dispatch grant.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..domains.d03.context import AccountBinding, EntityAnchor, WorldEvent
from ..graph_types import AtomKey, GraphVersion, Owner
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .first_ingress_v2 import scene_ref_for_conversation
from .ingress_observation import read_committed_ingress_identity
from .reply_model_job import CurrentReplyRouteManifestV2, source_key_from_ref


class ReplyEntityRouteHold(RuntimeError):
    """The current graph cannot certify this account-to-route identity."""


@dataclass(frozen=True, slots=True)
class CurrentReplyEntityRouteBindingV2:
    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    platform_ref: str
    sender_ref: str
    conversation_ref: str
    scene_ref: str
    target_entity_ref: str
    account_id: str
    anchor_version: GraphVersion
    binding_version: GraphVersion
    arrival_event_version: GraphVersion
    binding_evidence_event_version: GraphVersion
    source_version: GraphVersion
    access_version: GraphVersion
    binding_scan_versions: tuple[GraphVersion, ...]
    query: QueryEpoch
    valid_until_utc: float | None
    binding_digest: str


def _current_atom(db, key: AtomKey) -> tuple[GraphVersion, dict]:
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,),
    ).fetchone()
    if row is None or row[0] < 1 or row[2] != 1:
        raise ReplyEntityRouteHold("original reply account graph atom is absent")
    try:
        value = json.loads(row[1])
    except (TypeError, ValueError) as exc:
        raise ReplyEntityRouteHold("original reply account graph atom is invalid") from exc
    if type(value) is not dict:
        raise ReplyEntityRouteHold("original reply account graph atom is invalid")
    return GraphVersion(key, row[0]), value


def read_current_reply_entity_route_binding_v2(
    db, namespace: NamespaceId, route: CurrentReplyRouteManifestV2,
    query: QueryEpoch, *, now_utc: float,
) -> CurrentReplyEntityRouteBindingV2:
    """Join a settled C02 route to one current D03 account, with full scan."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(route) is not CurrentReplyRouteManifestV2
            or type(query) is not QueryEpoch or query.namespace != namespace
            or query.scope_ref != "all" or route.namespace != namespace
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ReplyEntityRouteHold("current transactional reply route is required")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch != (query.revision,):
        raise ReplyEntityRouteHold("reply account graph query epoch changed")
    try:
        source_id = source_key_from_ref(route.source_ref, namespace)
        original = read_committed_ingress_identity(db, namespace, source_id)
        if original is None:
            raise ReplyEntityRouteHold("original reply ingress identity is absent")
        identity = json.loads(original.identity_json)
        platform_ref = identity["platform_ref"]
        sender_ref = identity["sender_ref"]
        conversation_ref = identity["conversation_ref"]
        message_id = identity["message_id"]
        if (identity["visibility"] != "private"
                or identity["source_ref"] != source_id
                or platform_ref != route.platform_ref
                or conversation_ref != route.conversation_ref
                or scene_ref_for_conversation(namespace, platform_ref,
                                              conversation_ref) != route.scene_ref):
            raise ReplyEntityRouteHold("original reply ingress route changed")
        c02 = db.execute(
            "SELECT bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (route.c02_operation_id,),
        ).fetchone()
        c02_operation = db.execute(
            "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?", namespace.as_tuple + (route.c02_operation_id,),
        ).fetchone()
        if c02 is None or c02 != c02_operation:
            raise ReplyEntityRouteHold("original C02 seal is absent")
        arrival_operation_id = "d03-arrival-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "source_ref": source_id,
        })[:40]
        arrival = db.execute(
            "SELECT source_ref,bundle_digest FROM graph_d03_arrival_issuance_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (arrival_operation_id,),
        ).fetchone()
        arrival_operation = db.execute(
            "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND operation_id=?", namespace.as_tuple + (arrival_operation_id,),
        ).fetchone()
        if (arrival is None or arrival_operation is None
                or arrival != (source_id, arrival_operation[0])):
            raise ReplyEntityRouteHold("original D03 arrival seal is absent")
        source_version, source_value = _current_atom(
            db, source_key(*namespace.as_tuple, source_id))
        access_version, access_value = _current_atom(
            db, access_key(*namespace.as_tuple, source_id))
        source = SourceRecord.from_dict(source_value)
        validate_access(access_value)
        if (source.source_id != source_id or source.speaker_id != sender_ref
                or source.source_kind != "reported"
                or source.assertion_status != "reported"
                or source.audiences != (conversation_ref,)
                or access_value["source_id"] != source_id
                or access_value["status"] != "active"
                or conversation_ref not in access_value["audiences"]
                or "expression" not in access_value["purposes"]):
            raise ReplyEntityRouteHold("original reply source or access changed")
        account_identity = {
            "namespace": namespace.as_tuple,
            "platform_ref": platform_ref,
            "sender_ref": sender_ref,
        }
        suffix = canonical_digest(account_identity)
        target_entity_ref = "entity:account-v1:" + suffix
        account_id = "account:v1:" + suffix
        anchor_version, anchor_value = _current_atom(
            db, AtomKey(Owner("persona", *namespace.as_tuple),
                        "d03.entity_anchor", target_entity_ref))
        binding_version, binding_value = _current_atom(
            db, AtomKey(Owner("persona", *namespace.as_tuple),
                        "d03.account_binding", account_id))
        anchor = EntityAnchor(**{
            **anchor_value,
            "creation_evidence_refs": tuple(anchor_value["creation_evidence_refs"]),
        })
        binding = AccountBinding(**binding_value)
        if (anchor.entity_id != target_entity_ref or anchor.kind != "account"
                or anchor.owner_scope != f"persona:{namespace.persona_id}"
                or anchor.status != "active"
                or binding.account_id != account_id
                or binding.platform_namespace != platform_ref
                or binding.platform_identifier != sender_ref
                or binding.entity_id != target_entity_ref
                or binding.valid_from > now_utc
                or (binding.valid_until is not None
                    and now_utc >= binding.valid_until)):
            raise ReplyEntityRouteHold("current D03 account binding differs")
        event_id = "world:message-arrival-v1:" + canonical_digest({
            "namespace": namespace.as_tuple,
            "platform_ref": platform_ref,
            "conversation_ref": conversation_ref,
            "message_id": message_id,
            "source_id": source_id,
        })
        arrival_event_key = AtomKey(
            Owner("event", *namespace.as_tuple, event_id),
            "d03.world_event", "current",
        )
        arrival_event_version, arrival_event_value = _current_atom(
            db, arrival_event_key)
        arrival_event = WorldEvent(**{
            **arrival_event_value,
            "participant_roles": tuple(tuple(role) for role in
                                       arrival_event_value["participant_roles"]),
            "source_refs": tuple(arrival_event_value["source_refs"]),
        })
        if (arrival_event.event_id != event_id
                or arrival_event.kind != "message_received"
                or arrival_event.reality != "host_observed"
                or arrival_event.scene_ref != route.scene_ref
                or arrival_event.participant_roles != (
                    (target_entity_ref, "sender_account"),)
                or arrival_event.source_refs != (route.source_ref,)
                or arrival_event.learned_at != source.recorded_at):
            raise ReplyEntityRouteHold("original D03 arrival event differs")
        evidence_key = AtomKey.from_token(binding.verification_ref)
        if (evidence_key.type_name != "d03.world_event"
                or evidence_key.owner.kind != "event"
                or (evidence_key.owner.bot, evidence_key.owner.persona)
                   != namespace.as_tuple):
            raise ReplyEntityRouteHold("D03 binding evidence crosses namespace")
        evidence_version, evidence_value = _current_atom(db, evidence_key)
        evidence = WorldEvent(**{
            **evidence_value,
            "participant_roles": tuple(tuple(role) for role in
                                       evidence_value["participant_roles"]),
            "source_refs": tuple(evidence_value["source_refs"]),
        })
        if (evidence.kind != "message_received"
                or evidence.reality != "host_observed"
                or evidence.participant_roles != (
                    (target_entity_ref, "sender_account"),)
                or evidence.learned_at != binding.valid_from):
            raise ReplyEntityRouteHold("D03 binding verification event differs")
        rows = db.execute(
            "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.account_binding' AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
        scan = []
        matches = []
        for token, revision, raw in rows:
            key = AtomKey.from_token(token)
            value = AccountBinding(**json.loads(raw))
            scan.append(GraphVersion(key, revision))
            if (value.platform_namespace == platform_ref
                    and value.platform_identifier == sender_ref
                    and value.valid_from <= now_utc
                    and (value.valid_until is None
                         or now_utc < value.valid_until)):
                matches.append(key)
        if matches != [binding_version.key]:
            raise ReplyEntityRouteHold("reply sender has ambiguous account binding")
        versions = tuple(scan)
        proof = {
            "schema": "sylanne3.current-reply-entity-route-binding.v2",
            "namespace": list(namespace.as_tuple),
            "c02_operation_id": route.c02_operation_id,
            "source_ref": route.source_ref,
            "platform_ref": platform_ref,
            "sender_ref": sender_ref,
            "conversation_ref": conversation_ref,
            "scene_ref": route.scene_ref,
            "target_entity_ref": target_entity_ref,
            "account_id": account_id,
            "versions": [(v.key.token, v.revision) for v in (
                anchor_version, binding_version, arrival_event_version,
                evidence_version, source_version, access_version)],
            "binding_scan_versions": [(v.key.token, v.revision) for v in versions],
            "query": (query.namespace.as_tuple, query.scope_ref, query.revision),
            "valid_until_utc": binding.valid_until,
            "route_digest": route.route_digest,
            "ingress_identity_digest": canonical_digest(identity),
            "arrival_operation_digest": arrival_operation[0],
        }
        return CurrentReplyEntityRouteBindingV2(
            namespace, route.c02_operation_id, route.source_ref, platform_ref,
            sender_ref, conversation_ref, route.scene_ref,
            target_entity_ref, account_id, anchor_version, binding_version,
            arrival_event_version, evidence_version, source_version,
            access_version, versions, query, binding.valid_until,
            canonical_digest(proof),
        )
    except ReplyEntityRouteHold:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReplyEntityRouteHold("reply account route evidence is invalid") from exc
