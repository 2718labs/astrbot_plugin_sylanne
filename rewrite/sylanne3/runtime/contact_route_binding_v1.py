"""Current D03 contact route, independently qualified from message content."""
from dataclasses import dataclass
import json

from ..domains.d03.context import AccountBinding, EntityAnchor, WorldEvent
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .d01_production_operations_v1 import MissingProductionOriginalV1, raw_head_value_v1
from .first_ingress_v2 import scene_ref_for_conversation
from .ingress_observation import read_committed_ingress_identity


@dataclass(frozen=True, slots=True)
class CurrentContactRouteBindingV1:
    namespace: NamespaceId
    target_entity_ref: str
    platform_ref: str
    sender_ref: str
    conversation_ref: str
    scene_ref: str
    account_version: GraphVersion
    entity_version: GraphVersion
    evidence_version: GraphVersion
    source_ref: str
    ingress_digest: str
    query: QueryEpoch

    @property
    def digest(self):
        return canonical_digest(self)


def contact_route_semantic_digest_v1(route):
    """Bind actual route evidence independently of the current query epoch."""
    if type(route) is not CurrentContactRouteBindingV1:
        raise TypeError("actual current contact route binding required")
    return canonical_digest({
        "schema": "d03.contact-route-semantic.v1", "namespace": route.namespace,
        "target_entity_ref": route.target_entity_ref, "platform_ref": route.platform_ref,
        "sender_ref": route.sender_ref, "conversation_ref": route.conversation_ref,
        "scene_ref": route.scene_ref, "account_version": route.account_version,
        "entity_version": route.entity_version, "evidence_version": route.evidence_version,
        "source_ref": route.source_ref, "ingress_digest": route.ingress_digest,
    })


def contact_route_read_inputs_v1(db, namespace, account_ref):
    """Plan the original binding evidence; content sources remain separate."""
    account = raw_head_value_v1(db, namespace, AtomKey.from_token(account_ref))
    if account is None:
        return (), ()
    evidence_key = AtomKey.from_token(account["verification_ref"])
    evidence = raw_head_value_v1(db, namespace, evidence_key)
    return (evidence_key,), tuple(evidence["source_refs"]) if evidence is not None else ()


def contact_route_audience_v1(db, namespace, account_value):
    """Select only the private audience of the account's actual binding event."""
    evidence = raw_head_value_v1(db, namespace,
        AtomKey.from_token(account_value["verification_ref"]))
    if evidence is None or len(evidence["source_refs"]) != 1:
        raise MissingProductionOriginalV1("actual_contact_route_binding_evidence")
    source_id = AtomKey.from_token(evidence["source_refs"][0]).owner.subject
    original = read_committed_ingress_identity(db, namespace, source_id)
    if original is None:
        raise MissingProductionOriginalV1("actual_contact_route_private_ingress")
    identity = json.loads(original.identity_json)
    if ((identity["platform_ref"], identity["sender_ref"], identity["visibility"]) !=
            (account_value["platform_namespace"], account_value["platform_identifier"], "private")):
        raise ValueError("contact account's actual ingress is not the selected private route")
    return identity["conversation_ref"]


def read_current_contact_route_binding_v1(db, read, *, account_ref, target_entity_ref, audience):
    """Join the current account to its actual observed private conversation."""
    frame, namespace = read.frame, read.frame.envelope.authority.namespace
    read.check(db)
    account = read.head(db, account_ref, required=True)
    if account.key.type_name != "d03.account_binding":
        raise ValueError("contact route requires a current D03 account binding")
    binding = AccountBinding(**account.value)
    accounts = read.complete_inventory(db, "d03.account_binding")
    matches = tuple(atom for atom in accounts if atom.valid
        and (atom.value["platform_namespace"], atom.value["platform_identifier"]) ==
            (binding.platform_namespace, binding.platform_identifier)
        and atom.value["valid_from"] <= frame.now_utc
        and (atom.value["valid_until"] is None or frame.now_utc < atom.value["valid_until"]))
    if (matches != (account,) or binding.account_id != account.key.name
            or binding.entity_id != target_entity_ref):
        raise MissingProductionOriginalV1("unique_current_d03_contact_account")
    entities = tuple(atom for atom in read.complete_inventory(db, "d03.entity_anchor")
        if atom.valid and atom.value["entity_id"] == target_entity_ref)
    if len(entities) != 1:
        raise MissingProductionOriginalV1("unique_current_d03_contact_entity")
    entity = entities[0]
    anchor = EntityAnchor(**{**entity.value,
        "creation_evidence_refs": tuple(entity.value["creation_evidence_refs"])})
    if (anchor.kind != "account" or anchor.status != "active"
            or anchor.owner_scope != "persona:" + namespace.persona_id
            or anchor.entity_id != entity.key.name):
        raise MissingProductionOriginalV1("active_d03_contact_entity")
    evidence = read.head(db, binding.verification_ref, required=True)
    if evidence.key.type_name != "d03.world_event":
        raise ValueError("contact binding evidence is not a D03 world event")
    event = WorldEvent(**{**evidence.value,
        "participant_roles": tuple(tuple(row) for row in evidence.value["participant_roles"]),
        "source_refs": tuple(evidence.value["source_refs"])})
    if (event.event_id != evidence.key.owner.subject or event.kind != "message_received"
            or event.reality != "host_observed" or len(event.source_refs) != 1
            or event.participant_roles != ((target_entity_ref, "sender_account"),)
            or event.learned_at != binding.valid_from):
        raise ValueError("contact account has no exact observed binding evidence")
    read.source_family(db, event.source_refs, purpose="context", audience=audience)
    source_id = AtomKey.from_token(event.source_refs[0]).owner.subject
    ingress = read_committed_ingress_identity(db, namespace, source_id)
    if ingress is None:
        raise MissingProductionOriginalV1("original_contact_route_ingress")
    identity = json.loads(ingress.identity_json)
    if ((identity["platform_ref"], identity["sender_ref"], identity["conversation_ref"], identity["visibility"])
            != (binding.platform_namespace, binding.platform_identifier, audience, "private")
            or scene_ref_for_conversation(namespace, binding.platform_namespace, audience) != event.scene_ref):
        raise ValueError("contact route differs from its actual private ingress")
    return CurrentContactRouteBindingV1(namespace, target_entity_ref,
        binding.platform_namespace, binding.platform_identifier, audience, event.scene_ref,
        GraphVersion(account.key, account.revision), GraphVersion(entity.key, entity.revision),
        GraphVersion(evidence.key, evidence.revision), event.source_refs[0],
        canonical_digest(ingress), QueryEpoch(namespace, "all", frame.snapshot.epochs[0].revision))
