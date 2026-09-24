"""D03's conditional post-arrival self perspective contract."""

from dataclasses import asdict, replace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.domains.d03.context import ContextProvider, WorldEvent
from sylanne3.domains.d03.self_identity_qualification import (
    AuthorityCurrentSelfIdentityV1, qualify_authority_current_self_identity,
)
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, build_self_identity_projection_bundle,
    build_self_identity_projection_proposal, build_self_perspective_bundle,
    build_self_perspective_proposal, self_perspective_id, self_mapping_key,
    self_perspective_key,
    validate_self_identity_projection_snapshot,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
    owner_grant_key,
)
from sylanne3.memory_types import source_key
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, InstallationGrantV2, NamespaceId, OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
)


def _fixture():
    namespace = NamespaceId("bot", "persona")
    plan = PersonaPlan("plan", namespace, 1,
                       (PersonaBlock("identity", "semantic_identity", "self", "read_only"),),
                       (), True)
    plan_key = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_plan.v1", "plan")
    activation_key = AtomKey(Owner("persona", *namespace.as_tuple),
                             "d01.persona_activation.v1", "current")
    grant_key = owner_grant_key(*namespace.as_tuple)
    source = source_key(*namespace.as_tuple, "a" * 64)
    event = WorldEvent("world:arrival", "message_received",
                       (("entity:account-v1:sender", "sender_account"),),
                       10.0, 10.0, 10.0, "scene:one", (source.token,), "host_observed")
    event_key = AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                        "d03.world_event", "current")
    mapping = SelfIdentityMapping("self-map:one", "persona:persona", "entity:role-self",
                                  "authority:self-identity:certified", plan.head_id,
                                  "graph-incarnation", "active")
    mapping_key = self_mapping_key(namespace)
    role_versions = (GraphVersion(activation_key, 1), GraphVersion(plan_key, 1),
                     GraphVersion(grant_key, 1))
    role = ActiveRoleQualification(namespace, plan.head_id, plan, role_versions, 5, 1)
    perspective_id = self_perspective_id(namespace, event.scene_ref, event_key.token)
    reads = role_versions + (GraphVersion(mapping_key, 1), GraphVersion(event_key, 1),
                             GraphVersion(self_perspective_key(namespace, perspective_id), 0))
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("activity", None, "attempt", "self-perspective", "operation",
                          canonical_digest({"input_refs": [source.token]})),
        AuthorityContext("trusted-host", "d11", "lease", namespace, ("persona",),
                         "context", ("conversation",), "policy", 1),
        VersionGuard(reads, (QueryEpoch(namespace, "all", 5),), 0, 0,
                     "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((source.token,), "reported", 9.0, 10.0,
                            "external_report", "qualified", None, "not_applicable"),
        (source.token,), "budget", 30.0, 30.0, "interval", (),
    )
    atoms = (
        GraphAtom(activation_key, 1, {
            "plan_id": plan.plan_id, "plan_version": 1, "head_id": plan.head_id,
            "owner_grant_id": "grant", "owner_grant_revision": 1,
            "graph_incarnation": "graph-incarnation",
            "activation_generation": 1,
        }),
        GraphAtom(plan_key, 1, PersonaDomain.plan_write(plan).value),
        GraphAtom(grant_key, 1, {"grant_id": "grant"}),
        GraphAtom(mapping_key, 1, asdict(mapping)),
        GraphAtom(event_key, 1, {
            **asdict(event), "participant_roles": [list(item) for item in event.participant_roles],
            "source_refs": list(event.source_refs),
        }),
        GraphAtom(self_perspective_key(namespace, perspective_id), 0, {}, False),
    )
    return envelope, role, atoms


def test_self_perspective_requires_preexisting_certified_mapping():
    envelope, role, atoms = _fixture()
    with pytest.raises(ValueError, match="mapping is unavailable"):
        build_self_perspective_proposal(envelope, role, None, atoms[4])
    proposal = build_self_perspective_proposal(envelope, role, atoms[3], atoms[4])
    bundle = build_self_perspective_bundle(envelope, role, atoms[3], atoms[4])
    assert bundle.proposals == (proposal,)
    assert proposal.typed_writes[0].value["self_entity_ref"] == "entity:role-self"
    assert proposal.typed_writes[0].value["arrival_event_ref"] == atoms[4].key.token
    ContextProvider().validate(proposal, GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 5),)))


def test_sender_account_cannot_be_promoted_to_self_and_mapping_cannot_self_issue():
    envelope, role, atoms = _fixture()
    forged = replace(atoms[3], value={**atoms[3].value,
                                       "self_entity_ref": "entity:account-v1:sender"})
    with pytest.raises(ValueError, match="self mapping"):
        build_self_perspective_proposal(envelope, role, forged, atoms[4])
    proposal = build_self_perspective_proposal(envelope, role, atoms[3], atoms[4])
    mapping_write = replace(proposal.typed_writes[0], key=atoms[3].key, value=atoms[3].value)
    with pytest.raises(ValueError, match="mapping issuer is unavailable"):
        ContextProvider().validate(replace(proposal, typed_writes=(mapping_write,)),
                                   GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 5),)))


def test_self_perspective_rejects_revoked_or_changed_mapping_at_commit():
    envelope, role, atoms = _fixture()
    proposal = build_self_perspective_proposal(envelope, role, atoms[3], atoms[4])
    revoked = replace(atoms[3], value={**atoms[3].value, "status": "revoked"})
    snapshot = GraphSnapshot(atoms[:3] + (revoked,) + atoms[4:],
                             (NamespaceEpoch("bot", "persona", 5),))
    with pytest.raises(ValueError, match="certified persona"):
        ContextProvider().validate(proposal, snapshot)


def test_self_identity_projection_atomically_writes_new_mapping_and_perspective():
    envelope, role, atoms = _fixture()
    qualified = SelfIdentityMapping(**atoms[3].value)
    absent_mapping = replace(atoms[3], revision=0, value={}, valid=False)
    reads = tuple(
        replace(item, revision=0) if item.key == atoms[3].key else item
        for item in envelope.version_guard.read_versions
    )
    envelope = replace(envelope, version_guard=replace(
        envelope.version_guard, read_versions=reads,
    ))
    proposal = build_self_identity_projection_proposal(
        envelope, role, qualified, absent_mapping, atoms[4],
    )
    bundle = build_self_identity_projection_bundle(
        envelope, role, qualified, absent_mapping, atoms[4],
    )
    snapshot = GraphSnapshot(
        atoms[:3] + (absent_mapping,) + atoms[4:],
        (NamespaceEpoch("bot", "persona", 5),),
    )
    assert bundle.proposals == (proposal,)
    assert tuple(write.key.type_name for write in proposal.typed_writes) == (
        "d03.self_identity_mapping.v1", "d03.self_perspective.v1",
    )
    validate_self_identity_projection_snapshot(proposal, snapshot, role, qualified)
    with pytest.raises(ValueError, match="mapping issuer is unavailable"):
        ContextProvider().validate(proposal, snapshot)
    forged = replace(proposal.typed_writes[0], value={
        **proposal.typed_writes[0].value, "self_entity_ref": "entity:other",
    })
    with pytest.raises(ValueError, match="differs from current Authority mapping"):
        validate_self_identity_projection_snapshot(
            replace(proposal, typed_writes=(forged, proposal.typed_writes[1])),
            snapshot, role, qualified,
        )


def test_self_identity_projection_reuses_unchanged_mapping_and_cas_replacement():
    envelope, role, atoms = _fixture()
    qualified = SelfIdentityMapping(**atoms[3].value)
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 5),))
    unchanged = build_self_identity_projection_proposal(
        envelope, role, qualified, atoms[3], atoms[4],
    )
    assert len(unchanged.typed_writes) == 1
    validate_self_identity_projection_snapshot(unchanged, snapshot, role, qualified)

    replacement = replace(
        qualified, self_entity_ref="entity:new-role-self",
        certification_ref="authority:self-identity:replacement",
    )
    updated = build_self_identity_projection_proposal(
        envelope, role, replacement, atoms[3], atoms[4],
    )
    assert len(updated.typed_writes) == 2
    assert updated.typed_writes[1].value["self_entity_ref"] == "entity:new-role-self"
    validate_self_identity_projection_snapshot(updated, snapshot, role, replacement)
    with pytest.raises(ValueError, match="differs from current Authority mapping"):
        validate_self_identity_projection_snapshot(updated, snapshot, role, qualified)


def _admin_inputs():
    _, role, atoms = _fixture()
    namespace = role.namespace
    lease = BudgetLease("lease", None, *namespace.as_tuple, "USD",
                        {"cpu_ms": 200}, {}, {}, {}, 1, "active")
    grant_budget = BudgetLeaseGrant("budget-grant", 1, *namespace.as_tuple,
                                    "lease", "USD", {"cpu_ms": 100},
                                    ("d03.self_perspective",), 9999999999.0, "policy")
    policy = AdminInstallationPolicy(
        namespace, "authority-namespace", "installation", "a" * 64,
        "administrator", "authority", "b" * 64,
        "scheme", "operator", "policy", lease, grant_budget,
    )
    grant = InstallationGrantV2(
        "authority", "subject", "administrator", "installation",
        "a" * 64, "publisher-policy", "v2", "c" * 64,
    )
    guard = OwnerAuthorizationGuardV1(
        "authority", "installation", namespace, 1,
        "sha256:" + "d" * 64, 0, 0,
    )
    anchor = RestoreAnchor(
        "authority", "authority-namespace", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof",
    )
    permit = FencePermitV2(
        "authority", "authority-namespace", "subject", "holder", 1,
        "write", "fence-operation", "x" * 32, 1, 1, anchor,
    )
    current = AuthorityCurrentSelfIdentityV1(
        namespace, "authority-namespace", "authority", "installation", "a" * 64,
        1, "graph-incarnation", role.head_id, 1, role.graph_epoch,
        "persona:persona", "entity:role-self",
        "self-map:mapping", 1, 0, "registration-operation", "e" * 64,
        1, "sha256:" + "d" * 64, 0, 0, "mapping-operation", permit,
    )
    return role, atoms[0], policy, grant, guard, permit, current


def test_authority_self_identity_qualification_holds_without_current_port():
    role, activation, policy, grant, guard, permit, _ = _admin_inputs()
    with pytest.raises(ValueError, match="port is unavailable"):
        qualify_authority_current_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=grant, owner_guard=guard,
            request_operation_id="mapping-operation", permit=permit, port=None,
        )


def test_authority_self_identity_qualification_binds_exact_installed_role_and_fence():
    role, activation, policy, grant, guard, permit, current = _admin_inputs()

    class CurrentPort:
        def __init__(self, value):
            self.value = value

        def current_self_identity(self, *, namespace, authority_namespace,
                                  request_operation_id, permit):
            assert namespace == role.namespace
            assert authority_namespace == policy.authority_namespace
            assert request_operation_id == "mapping-operation"
            assert permit == current.permit
            return self.value

    def qualify(value=current, *, current_role=role, current_guard=guard,
                current_grant=grant, current_permit=permit, current_activation=activation):
        return qualify_authority_current_self_identity(
            role=current_role, activation_atom=current_activation, policy=policy,
            installation_grant=current_grant, owner_guard=current_guard,
            request_operation_id="mapping-operation", permit=current_permit,
            port=CurrentPort(value),
        )

    mapping = qualify()
    assert mapping.self_entity_ref == "entity:role-self"
    assert mapping.graph_incarnation == "graph-incarnation"
    assert mapping.certification_ref.startswith("authority:self-identity:")
    with pytest.raises(ValueError, match="differs from current role or fence"):
        qualify(replace(current, graph_incarnation="old-graph"))
    with pytest.raises(ValueError, match="differs from current role or fence"):
        qualify(replace(current, graph_epoch=role.graph_epoch - 1))
    with pytest.raises(ValueError, match="installed persona or Owner proof"):
        qualify(current_grant=replace(grant, installation_id="another-installation"))
    with pytest.raises(ValueError, match="installed persona or Owner proof"):
        qualify(current_guard=replace(guard, pending_revoke_operation_id="revoke"))
    with pytest.raises(ValueError, match="non-account entity reference"):
        replace(current, self_entity_ref="entity:account-v1:sender")
    with pytest.raises(ValueError, match="differs from current role or fence"):
        qualify(replace(current, request_operation_id="another-operation"))
    assert canonical_digest(current) != canonical_digest(
        replace(current, self_entity_ref="entity:another-role"))


def test_authority_self_identity_allows_current_reregistration_after_revocation():
    role, activation, policy, grant, guard, permit, current = _admin_inputs()
    renewed_guard = replace(
        guard, authorization_revision=2, authorization_head="sha256:" + "f" * 64,
        minimum_revocation_revision=1, minimum_revocation_epoch=1,
    )
    renewed_role = replace(role, authorization_revision=2)
    renewed_current = replace(
        current, mapping_revision=2, mapping_revocation_epoch=1,
        owner_authorization_revision=2,
        owner_authorization_head=renewed_guard.authorization_head,
        owner_minimum_revocation_revision=1, owner_revocation_epoch=1,
    )

    class CurrentPort:
        def current_self_identity(self, *, namespace, authority_namespace,
                                  request_operation_id, permit):
            return renewed_current

    mapping = qualify_authority_current_self_identity(
        role=renewed_role, activation_atom=activation, policy=policy,
        installation_grant=grant, owner_guard=renewed_guard,
        request_operation_id="mapping-operation", permit=permit, port=CurrentPort(),
    )
    assert mapping.self_entity_ref == "entity:role-self"


def test_authority_self_identity_projection_stable_across_current_permits():
    role, activation, policy, grant, guard, permit, current = _admin_inputs()

    class CurrentPort:
        def __init__(self, receipt):
            self.receipt = receipt

        def current_self_identity(self, *, namespace, authority_namespace,
                                  request_operation_id, permit):
            assert (namespace, authority_namespace, request_operation_id, permit) == (
                self.receipt.namespace, self.receipt.authority_namespace,
                self.receipt.request_operation_id, self.receipt.permit,
            )
            return self.receipt

    def qualify(receipt):
        return qualify_authority_current_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=grant, owner_guard=guard,
            request_operation_id=receipt.request_operation_id,
            permit=receipt.permit, port=CurrentPort(receipt),
        )

    first = qualify(current)
    next_permit = replace(permit, operation_id="fence-operation-2", token="y" * 32,
                          revision=2)
    next_request = replace(current, request_operation_id="mapping-operation-2",
                           permit=next_permit)
    assert canonical_digest(current) != canonical_digest(next_request)
    assert qualify(next_request) == first

    replacement = replace(next_request, mapping_revision=2,
                          registration_operation_id="registration-operation-2",
                          registration_digest="f" * 64)
    assert qualify(replacement).certification_ref != first.certification_ref
