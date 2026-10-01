"""Current entity-to-delivery binding required for a K03 private reply.

The route read originates in W01's held graph transaction. D08 checks its
current rows and freezes the entire read into the grant; W01 must repeat the
read at the final receipt hook before that candidate can authorize dispatch.
"""

from __future__ import annotations

import json
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ...memory_types import access_key, source_key
from ...runtime_contracts import FenceScope, QueryEpoch, canonical_digest
from .execution import ActionIntent, CommunicationGrantRequest, CommunicationIntentGrant


def _canonical_json_array(value: str, size: int) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("delivery route is not canonical JSON") from exc
    if (type(parsed) is not list or len(parsed) != size
            or any(type(item) is not str or not item for item in parsed)
            or json.dumps(parsed, ensure_ascii=True, separators=(",", ":")) != value):
        raise ValueError("delivery route is not canonical JSON")
    return tuple(parsed)


def _current_version(db, snapshot: GraphSnapshot, version: GraphVersion):
    if type(version) is not GraphVersion or version.revision < 1:
        raise ValueError("route binding graph version is missing")
    atom = snapshot.get(version.key)
    rows = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (version.key.token, version.key.owner.bot, version.key.owner.persona),
    ).fetchall()
    if (len(rows) != 1 or atom is None or not atom.valid
            or rows[0][2] != 1 or rows[0][0] != version.revision
            or atom.revision != version.revision or atom.value != json.loads(rows[0][1])):
        raise ValueError("route binding graph version is not current")
    return atom


def validate_communication_route_binding_v2(
    route_binding: object, intent: ActionIntent, audiences: tuple[str, ...],
    *, db: object, snapshot: GraphSnapshot, scope: FenceScope, now: float,
    expected_action_kind: str = "message",
) -> str:
    """Return a digest only for the current W01 route/entity SQL join.

    A typed read is necessary, but never by itself sufficient for dispatch:
    final W01 admission reissues the read and compares it to this frozen one.
    """
    # Lazy import avoids runtime -> D08 -> runtime import cycles.
    from ...runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2

    if (type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(intent) is not ActionIntent
            or type(audiences) is not tuple
            or type(snapshot) is not GraphSnapshot
            or type(scope) is not FenceScope
            or type(now) not in (int, float) or not math.isfinite(now)
            or not getattr(db, "in_transaction", False)):
        raise ValueError("current W01 entity route read and held graph transaction required")
    route = route_binding
    namespace = scope.namespace
    query = QueryEpoch(namespace, "all", scope.graph_epoch.revision + 1)
    if (scope.operation != "write" or scope.permit.operation != "write"
            or scope.operation_id != scope.permit.operation_id
            or scope.permit.pinned_anchor != scope.pinned_anchor
            or route.namespace != namespace or route.query != query
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona,
                snapshot.epochs[0].revision) != (*namespace.as_tuple, query.revision)
            or db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                          namespace.as_tuple).fetchone() != (query.revision,)
            or route.source_ref not in intent.source_refs
            or intent.source_refs != (route.source_ref,)
            or route.target_entity_ref != intent.target_ref
            or not intent.target_ref.startswith("entity:account-v1:")
            or audiences != (route.conversation_ref,)
            or intent.purpose != "expression"
            or type(expected_action_kind) is not str
            or expected_action_kind not in ("message", "communication")
            or intent.action_kind != expected_action_kind
            or not route.c02_operation_id or not route.scene_ref
            or (route.valid_until_utc is not None and now >= route.valid_until_utc)):
        raise ValueError("private reply entity, audience or graph epoch differs")
    platform = _canonical_json_array(route.platform_ref, 3)
    conversation = _canonical_json_array(route.conversation_ref, 2)
    # The platform tuple names the adapter/account; a private conversation
    # tuple starts with the trusted UMO. They identify different dimensions.
    identity_digest = canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": route.platform_ref,
        "sender_ref": route.sender_ref,
    })
    if (route.target_entity_ref != "entity:account-v1:" + identity_digest
            or route.account_id != "account:v1:" + identity_digest):
        raise ValueError("entity/account identity differs from original ingress")
    expected = (
        (route.anchor_version, AtomKey(Owner("persona", *namespace.as_tuple),
                                       "d03.entity_anchor", route.target_entity_ref)),
        (route.binding_version, AtomKey(Owner("persona", *namespace.as_tuple),
                                        "d03.account_binding", route.account_id)),
        (route.arrival_event_version, None),
        (route.binding_evidence_event_version, None),
        (route.source_version, AtomKey.from_token(route.source_ref)),
        (route.access_version, access_key(*namespace.as_tuple,
                                          route.source_version.key.owner.subject)),
    )
    atoms = []
    for version, key in expected:
        if (version.key.owner.bot, version.key.owner.persona) != namespace.as_tuple:
            raise ValueError("route binding graph namespace differs")
        if key is not None and version.key != key:
            raise ValueError("route binding graph key differs")
        atoms.append(_current_version(db, snapshot, version))
    anchor, binding, event, binding_event, source, access = atoms
    if (event.key.type_name != "d03.world_event"
            or event.key.owner.kind != "event" or event.key.name != "current"
            or binding_event.key.type_name != "d03.world_event"
            or binding_event.key.owner.kind != "event"
            or binding_event.key.name != "current"
            or source.key != source_key(*namespace.as_tuple,
                                        source.key.owner.subject or "")):
        raise ValueError("route binding event or source graph key differs")
    av, bv, ev = anchor.value, binding.value, event.value
    if (av.get("entity_id") != route.target_entity_ref
            or av.get("kind") != "account" or av.get("status") != "active"
            or bv.get("account_id") != route.account_id
            or bv.get("platform_namespace") != route.platform_ref
            or bv.get("platform_identifier") != route.sender_ref
            or bv.get("entity_id") != route.target_entity_ref
            or bv.get("verification_ref") != binding_event.key.token
            or not isinstance(bv.get("valid_from"), (int, float))
            or bv["valid_from"] > now
            or bv.get("valid_until") != route.valid_until_utc
            or ev.get("kind") != "message_received"
            or ev.get("reality") != "host_observed"
            or ev.get("scene_ref") != route.scene_ref
            or [route.target_entity_ref, "sender_account"] not in ev.get("participant_roles", [])
            or route.source_ref not in ev.get("source_refs", [])
            or binding_event.value.get("kind") != "message_received"
            or binding_event.value.get("reality") != "host_observed"
            or [route.target_entity_ref, "sender_account"] not in
               binding_event.value.get("participant_roles", [])
            or source.value.get("speaker_id") != route.sender_ref
            or route.conversation_ref not in source.value.get("audiences", [])
            or access.value.get("status") != "active"
            or route.conversation_ref not in access.value.get("audiences", [])
            or "expression" not in access.value.get("purposes", [])):
        raise ValueError("route binding current graph facts differ")
    binding_rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name='d03.account_binding' "
        "AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    scanned = tuple(GraphVersion(AtomKey.from_token(token), revision)
                    for token, revision, _, _ in binding_rows)
    if (type(route.binding_scan_versions) is not tuple
            or scanned != route.binding_scan_versions):
        raise ValueError("account-binding negative query closure is stale")
    active_matches = []
    for token, revision, encoded, valid in binding_rows:
        version = GraphVersion(AtomKey.from_token(token), revision)
        current = _current_version(db, snapshot, version) if valid == 1 else None
        if current is None:
            continue
        value = json.loads(encoded)
        expiry = value.get("valid_until")
        if (value.get("platform_namespace") == route.platform_ref
                and value.get("platform_identifier") == route.sender_ref
                and isinstance(value.get("valid_from"), (int, float))
                and value["valid_from"] <= now
                and (expiry is None or now < expiry)):
            active_matches.append(token)
    if active_matches != [route.binding_version.key.token]:
        raise ValueError("account binding is absent or non-unique")
    return canonical_digest(route)


def verify_route_bound_grant_v2(
    grant: CommunicationIntentGrant, intent: ActionIntent,
    request: CommunicationGrantRequest, route_binding: object,
) -> None:
    """Pure bundle consistency check; current-row validation stays with W01."""
    from ...runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2

    if (type(grant) is not CommunicationIntentGrant
            or type(intent) is not ActionIntent
            or type(request) is not CommunicationGrantRequest
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or grant.route_binding_digest != canonical_digest(route_binding)
            or grant.target_ref != intent.target_ref
            or grant.target_ref != route_binding.target_entity_ref
            or grant.audiences != request.audiences
            or grant.audiences != (route_binding.conversation_ref,)
            or grant.action_id != intent.action_id
            or grant.intent_revision != intent.revision
            or grant.purpose != intent.purpose):
        raise ValueError("communication grant is not bound to the current entity route")


__all__ = (
    "validate_communication_route_binding_v2", "verify_route_bound_grant_v2",
)
