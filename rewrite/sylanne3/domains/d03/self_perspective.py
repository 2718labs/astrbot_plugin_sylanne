"""A post-arrival D03 self perspective, conditional on a certified mapping.

The current runtime has no issuer for the mapping.  In particular, a host
sender account and a persona namespace are not identity attestations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ...domains.d01 import ActiveRoleQualification
from ...graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, Owner, owner_grant_key,
)
from ...runtime_contracts import (
    CommandEnvelope, DependencySet, DomainBundle, DomainProposal, QueryEpoch, canonical_digest,
)
from .context import ContextProvider, WorldEvent


@dataclass(frozen=True)
class SelfIdentityMapping:
    mapping_id: str
    persona_ref: str
    self_entity_ref: str
    certification_ref: str
    role_head_id: str
    graph_incarnation: str
    status: str

    def __post_init__(self) -> None:
        if not self.mapping_id.startswith("self-map:"):
            raise ValueError("self mapping needs a stable identity")
        if (not self.persona_ref.startswith("persona:")
                or not self.self_entity_ref.startswith("entity:")
                or self.self_entity_ref.startswith("entity:account-v1:")):
            raise ValueError("self mapping needs persona and entity references")
        if not self.certification_ref.startswith("authority:self-identity:"):
            raise ValueError("self mapping needs an Authority current reference")
        if (not self.role_head_id or not self.graph_incarnation
                or self.status not in {"active", "revoked"}):
            raise ValueError("self mapping state is invalid")


@dataclass(frozen=True)
class SelfPerspective:
    perspective_id: str
    persona_ref: str
    self_entity_ref: str
    scene_ref: str
    identity_mapping_ref: str
    arrival_event_ref: str
    role_head_id: str

    def __post_init__(self) -> None:
        if not self.perspective_id.startswith("perspective:self-v1:"):
            raise ValueError("self perspective needs a stable identity")
        if not self.persona_ref.startswith("persona:") or not self.self_entity_ref.startswith("entity:"):
            raise ValueError("self perspective needs persona and entity references")
        if not self.scene_ref.startswith("scene:"):
            raise ValueError("self perspective scene is invalid")
        if (AtomKey.from_token(self.identity_mapping_ref).type_name != "d03.self_identity_mapping.v1"
                or AtomKey.from_token(self.arrival_event_ref).type_name != "d03.world_event"
                or not self.role_head_id):
            raise ValueError("self perspective lacks identity or arrival references")


def self_mapping_key(namespace) -> AtomKey:
    return AtomKey(Owner("persona", *namespace.as_tuple), "d03.self_identity_mapping.v1", "current")


def self_perspective_key(namespace, perspective_id: str) -> AtomKey:
    return AtomKey(Owner("persona", *namespace.as_tuple), "d03.self_perspective.v1", perspective_id)


def self_perspective_id(namespace, scene_ref: str, arrival_event_ref: str) -> str:
    return "perspective:self-v1:" + canonical_digest({
        "namespace": namespace.as_tuple, "scene_ref": scene_ref,
        "arrival_event_ref": arrival_event_ref,
    })


def build_self_perspective_proposal(
    envelope: CommandEnvelope, role: ActiveRoleQualification, mapping_atom: GraphAtom | None,
    arrival_atom: GraphAtom, *, perspective_revision: int = 0,
) -> DomainProposal:
    """Build a separate DomainBundle proposal after C01 has committed."""
    if mapping_atom is None:
        raise ValueError("certified self identity mapping is unavailable")
    if type(envelope) is not CommandEnvelope or type(role) is not ActiveRoleQualification:
        raise TypeError("command and qualified D01 role are required")
    namespace = envelope.authority.namespace
    mapping_key = self_mapping_key(namespace)
    if (role.namespace != namespace or role.plan.namespace != namespace
            or role.head_id != role.plan.head_id or role.graph_epoch < 1
            or envelope.authority.issuer_domain != "d11"
            or envelope.authority.purpose != "context"
            or "persona" not in envelope.authority.owner_scope
            or mapping_atom.key != mapping_key or not mapping_atom.valid
            or mapping_atom.revision < 1 or not arrival_atom.valid
            or arrival_atom.revision < 1):
        raise ValueError("self perspective lacks current role, identity, or arrival")
    mapping = SelfIdentityMapping(**mapping_atom.value)
    event = WorldEvent(**{
        **arrival_atom.value,
        "participant_roles": tuple(tuple(item) for item in arrival_atom.value["participant_roles"]),
        "source_refs": tuple(arrival_atom.value["source_refs"]),
    })
    if (mapping.status != "active" or mapping.persona_ref != f"persona:{namespace.persona_id}"
            or mapping.role_head_id != role.head_id
            or not mapping.graph_incarnation
            or arrival_atom.key != AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                                          "d03.world_event", "current")
            or event.kind != "message_received" or event.reality != "host_observed"
            or len(event.participant_roles) != 1
            or event.participant_roles[0][1] != "sender_account"
            or mapping.self_entity_ref == event.participant_roles[0][0]):
        raise ValueError("account arrival cannot establish the role's self identity")
    perspective = SelfPerspective(
        self_perspective_id(namespace, event.scene_ref, arrival_atom.key.token),
        mapping.persona_ref, mapping.self_entity_ref, event.scene_ref,
        mapping_key.token, arrival_atom.key.token, role.head_id,
    )
    target = self_perspective_key(namespace, perspective.perspective_id)
    versions = role.read_versions + (
        GraphVersion(mapping_key, mapping_atom.revision),
        GraphVersion(arrival_atom.key, arrival_atom.revision),
        GraphVersion(target, perspective_revision),
    )
    reads = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (perspective_revision != 0 or any(reads.get(item.key) != item.revision for item in versions)
            or not any(query == QueryEpoch(namespace, "all", role.graph_epoch)
                       for query in envelope.version_guard.query_epochs)
            or envelope.input_refs != event.source_refs
            or envelope.source_qualification.source_refs != event.source_refs):
        raise ValueError("self perspective lacks complete current graph guards")
    dependencies = versions[:-1]
    return DomainProposal(
        "d03", "d03.proposal.v1", ContextProvider().descriptor.request_schema_hash,
        envelope,
        (GraphWrite(target, asdict(perspective), tuple(item.key for item in dependencies)),),
        DependencySet(current_invalidation=dependencies), (), (),
    )


def build_self_perspective_bundle(
    envelope: CommandEnvelope, role: ActiveRoleQualification, mapping_atom: GraphAtom | None,
    arrival_atom: GraphAtom, *, perspective_revision: int = 0,
) -> DomainBundle:
    """Package the post-C01 proposal for a separate guarded coordinator commit."""
    proposal = build_self_perspective_proposal(
        envelope, role, mapping_atom, arrival_atom,
        perspective_revision=perspective_revision,
    )
    return DomainBundle(envelope, (proposal,), (), (), (), (), (), (), ())


def build_self_identity_projection_proposal(
    envelope: CommandEnvelope, role: ActiveRoleQualification,
    qualified_mapping: SelfIdentityMapping, mapping_atom: GraphAtom | None,
    arrival_atom: GraphAtom, *, perspective_revision: int = 0,
) -> DomainProposal:
    """Compile the Authority-qualified mapping and perspective in one D03 stage.

    The caller must qualify ``qualified_mapping`` against Authority current under
    the actual write fence. Construction alone is not an issuer. An unchanged
    mapping is read-guarded but not rewritten, preserving prior perspectives.
    """
    if (type(envelope) is not CommandEnvelope or type(role) is not ActiveRoleQualification
            or type(qualified_mapping) is not SelfIdentityMapping):
        raise TypeError("current command, role, and Authority mapping are required")
    namespace = envelope.authority.namespace
    mapping_key = self_mapping_key(namespace)
    if mapping_atom is not None and (type(mapping_atom) is not GraphAtom
                                     or mapping_atom.key != mapping_key):
        raise ValueError("self mapping read differs from namespace")
    prior_revision = 0 if mapping_atom is None else mapping_atom.revision
    if mapping_atom is not None and prior_revision > 0 and not mapping_atom.valid:
        raise ValueError("revoked graph mapping needs current Authority replacement")
    if mapping_atom is not None and prior_revision > 0:
        prior = SelfIdentityMapping(**mapping_atom.value)
        if prior == qualified_mapping:
            return build_self_perspective_proposal(
                envelope, role, mapping_atom, arrival_atom,
                perspective_revision=perspective_revision,
            )
    if (role.namespace != namespace or role.plan.namespace != namespace
            or role.head_id != role.plan.head_id or role.graph_epoch < 1
            or envelope.authority.issuer_domain != "d11"
            or envelope.authority.purpose != "context"
            or "persona" not in envelope.authority.owner_scope
            or qualified_mapping.status != "active"
            or qualified_mapping.persona_ref != f"persona:{namespace.persona_id}"
            or qualified_mapping.role_head_id != role.head_id
            or not arrival_atom.valid or arrival_atom.revision < 1):
        raise ValueError("self projection lacks current role, identity, or arrival")
    event = WorldEvent(**{
        **arrival_atom.value,
        "participant_roles": tuple(tuple(item) for item in arrival_atom.value["participant_roles"]),
        "source_refs": tuple(arrival_atom.value["source_refs"]),
    })
    if (arrival_atom.key != AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                                   "d03.world_event", "current")
            or event.kind != "message_received" or event.reality != "host_observed"
            or len(event.participant_roles) != 1
            or event.participant_roles[0][1] != "sender_account"
            or qualified_mapping.self_entity_ref == event.participant_roles[0][0]):
        raise ValueError("account arrival cannot establish the role's self identity")
    perspective = SelfPerspective(
        self_perspective_id(namespace, event.scene_ref, arrival_atom.key.token),
        qualified_mapping.persona_ref, qualified_mapping.self_entity_ref,
        event.scene_ref, mapping_key.token, arrival_atom.key.token, role.head_id,
    )
    target = self_perspective_key(namespace, perspective.perspective_id)
    dependencies = role.read_versions + (
        GraphVersion(mapping_key, prior_revision),
        GraphVersion(arrival_atom.key, arrival_atom.revision),
    )
    expected = dependencies + (GraphVersion(target, perspective_revision),)
    reads = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (perspective_revision != 0
            or any(reads.get(item.key) != item.revision for item in expected)
            or not any(query == QueryEpoch(namespace, "all", role.graph_epoch)
                       for query in envelope.version_guard.query_epochs)
            or envelope.input_refs != event.source_refs
            or envelope.source_qualification.source_refs != event.source_refs):
        raise ValueError("self projection lacks complete current graph guards")
    role_keys = tuple(item.key for item in role.read_versions)
    writes = (
        GraphWrite(mapping_key, asdict(qualified_mapping), role_keys),
        GraphWrite(target, asdict(perspective), tuple(item.key for item in dependencies)),
    )
    return DomainProposal(
        "d03", "d03.proposal.v1", ContextProvider().descriptor.request_schema_hash,
        envelope, writes, DependencySet(current_invalidation=dependencies), (), (),
    )


def build_self_identity_projection_bundle(
    envelope: CommandEnvelope, role: ActiveRoleQualification,
    qualified_mapping: SelfIdentityMapping, mapping_atom: GraphAtom | None,
    arrival_atom: GraphAtom, *, perspective_revision: int = 0,
) -> DomainBundle:
    proposal = build_self_identity_projection_proposal(
        envelope, role, qualified_mapping, mapping_atom, arrival_atom,
        perspective_revision=perspective_revision,
    )
    return DomainBundle(envelope, (proposal,), (), (), (), (), (), (), ())


def validate_self_identity_projection_snapshot(
    proposal: DomainProposal, snapshot: GraphSnapshot,
    role: ActiveRoleQualification, qualified_mapping: SelfIdentityMapping,
) -> None:
    """Check the dedicated D03 stage against a locked graph snapshot.

    W01 must additionally obtain the Authority current value and D11 quote
    under its actual fence. This graph check never authenticates the DTO.
    """
    if (type(proposal) is not DomainProposal or type(snapshot) is not GraphSnapshot
            or type(role) is not ActiveRoleQualification
            or type(qualified_mapping) is not SelfIdentityMapping):
        raise TypeError("self projection needs typed candidate and current proofs")
    namespace = proposal.envelope.authority.namespace
    mapping_key = self_mapping_key(namespace)
    mapping_atom = snapshot.get(mapping_key)
    if mapping_atom is None:
        raise ValueError("self projection needs a revision-0 mapping read")
    writes = proposal.typed_writes
    if len(writes) not in (1, 2):
        raise ValueError("self projection has an invalid write shape")
    perspective_value = SelfPerspective(**writes[-1].value)
    arrival_atom = snapshot.get(AtomKey.from_token(perspective_value.arrival_event_ref))
    target_atom = snapshot.get(writes[-1].key)
    if (arrival_atom is None or target_atom is None or target_atom.revision != 0
            or not arrival_atom.valid or arrival_atom.revision < 1
            or role.namespace != namespace):
        raise ValueError("self projection snapshot lacks current arrival or target")
    expected = build_self_identity_projection_proposal(
        proposal.envelope, role, qualified_mapping, mapping_atom, arrival_atom,
        perspective_revision=target_atom.revision,
    )
    if proposal != expected:
        raise ValueError("self projection differs from current Authority mapping or graph")
    activation_key = AtomKey(Owner("persona", *namespace.as_tuple),
                             "d01.persona_activation.v1", "current")
    activation = snapshot.get(activation_key)
    if activation is None or not activation.valid:
        raise ValueError("self projection lacks current D01 activation")
    plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
                       "d01.persona_plan.v1", activation.value.get("plan_id", ""))
    grant_key = owner_grant_key(*namespace.as_tuple)
    plan, grant = snapshot.get(plan_key), snapshot.get(grant_key)
    if (plan is None or grant is None or not plan.valid or not grant.valid
            or activation.value.get("head_id") != role.head_id
            or activation.value.get("graph_incarnation") != qualified_mapping.graph_incarnation
            or activation.value.get("owner_grant_id") != grant.value.get("grant_id")
            or activation.value.get("owner_grant_revision") != grant.revision
            or plan.value.get("version") != activation.value.get("plan_version")
            or plan.value.get("plan_id") != activation.value.get("plan_id")
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or snapshot.epochs[0].revision != role.graph_epoch):
        raise ValueError("self projection lacks current role and graph incarnation")
    for version in role.read_versions:
        atom = snapshot.get(version.key)
        if atom is None or not atom.valid or atom.revision != version.revision:
            raise ValueError("self projection role read changed")
    if len(writes) == 1:
        validate_self_perspective_snapshot(proposal, snapshot)


def validate_self_perspective_snapshot(proposal: DomainProposal, snapshot: GraphSnapshot) -> None:
    """Recheck a self write against the locked graph read set."""
    if type(snapshot) is not GraphSnapshot or len(proposal.typed_writes) != 1:
        raise ValueError("self perspective needs one current graph write")
    write = proposal.typed_writes[0]
    value = SelfPerspective(**write.value)
    namespace = proposal.envelope.authority.namespace
    mapping_key = self_mapping_key(namespace)
    event_key = AtomKey.from_token(value.arrival_event_ref)
    activation_key = AtomKey(Owner("persona", *namespace.as_tuple),
                             "d01.persona_activation.v1", "current")
    mapping = snapshot.get(mapping_key)
    event_atom = snapshot.get(event_key)
    activation = snapshot.get(activation_key)
    if (mapping is None or event_atom is None or activation is None
            or not all(atom.valid and atom.revision >= 1
                       for atom in (mapping, event_atom, activation))
            or value.identity_mapping_ref != mapping_key.token
            or write.key != self_perspective_key(namespace, value.perspective_id)
            or snapshot.get(write.key) is None
            or snapshot.get(write.key).revision != 0):
        raise ValueError("self perspective identity or arrival is not current")
    identity = SelfIdentityMapping(**mapping.value)
    event = WorldEvent(**{
        **event_atom.value,
        "participant_roles": tuple(tuple(item) for item in event_atom.value["participant_roles"]),
        "source_refs": tuple(event_atom.value["source_refs"]),
    })
    plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
                       "d01.persona_plan.v1", activation.value.get("plan_id", ""))
    grant_key = owner_grant_key(*namespace.as_tuple)
    grant = snapshot.get(grant_key)
    plan = snapshot.get(plan_key)
    if (grant is None or not grant.valid or grant.revision < 1
            or plan is None or not plan.valid or plan.revision < 1
            or identity.status != "active"
            or identity.persona_ref != value.persona_ref == f"persona:{namespace.persona_id}"
            or identity.self_entity_ref != value.self_entity_ref
            or identity.role_head_id != value.role_head_id
            or identity.graph_incarnation != activation.value.get("graph_incarnation")
            or activation.value.get("head_id") != value.role_head_id
            or activation.value.get("owner_grant_id") != grant.value.get("grant_id")
            or activation.value.get("owner_grant_revision") != grant.revision
            or plan.value.get("version") != activation.value.get("plan_version")
            or plan.value.get("plan_id") != activation.value.get("plan_id")
            or event_atom.key != AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                                         "d03.world_event", "current")
            or event.scene_ref != value.scene_ref or event.kind != "message_received"
            or event.reality != "host_observed"
            or len(event.participant_roles) != 1
            or event.participant_roles[0][1] != "sender_account"
            or event.participant_roles[0][0] == value.self_entity_ref):
        raise ValueError("self perspective lacks certified persona and scene identity")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or not any(query == QueryEpoch(namespace, "all", snapshot.epochs[0].revision)
                       for query in proposal.envelope.version_guard.query_epochs)):
        raise ValueError("self perspective lacks a current namespace query")
    expected_id = self_perspective_id(namespace, value.scene_ref, event_key.token)
    required = {mapping_key, event_key, activation_key, plan_key, grant_key}
    if (value.perspective_id != expected_id
            or set(write.dependencies) != required
            or {item.key for item in proposal.dependencies.current_invalidation} != required
            or proposal.envelope.input_refs != event.source_refs):
        raise ValueError("self perspective graph dependencies are incomplete")
