"""D03's conditional post-arrival self perspective contract."""

import base64
from dataclasses import asdict, replace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.domains.d03.context import ContextProvider, WorldEvent
from sylanne3.domains.d03.self_identity_qualification import (
    AdminSelfIdentityAttestationV1, qualify_admin_self_identity,
)
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, build_self_perspective_bundle, build_self_perspective_proposal,
    self_perspective_id, self_mapping_key,
    self_perspective_key,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
    owner_grant_key,
)
from sylanne3.memory_types import source_key
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
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
                                  "d11:self-identity:certified", plan.head_id,
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
    attestation = AdminSelfIdentityAttestationV1(
        namespace, "authority", "installation", "a" * 64,
        "graph-incarnation", role.head_id, "persona:persona", "entity:role-self",
        "attestation", 1, 0, "2099-01-01T00:00:00Z",
        "admin-key", base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("="),
    )
    return role, atoms[0], policy, grant, guard, attestation


def test_admin_self_identity_qualification_holds_without_independent_port():
    role, activation, policy, grant, guard, _ = _admin_inputs()
    with pytest.raises(ValueError, match="port is unavailable"):
        qualify_admin_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=grant, owner_guard=guard, port=None,
        )


def test_admin_self_identity_qualification_binds_exact_installed_role():
    role, activation, policy, grant, guard, attestation = _admin_inputs()

    class CurrentPort:
        def __init__(self, value):
            self.value = value

        def current_attestation(self, namespace):
            assert namespace == role.namespace
            return self.value

    mapping = qualify_admin_self_identity(
        role=role, activation_atom=activation, policy=policy,
        installation_grant=grant, owner_guard=guard, port=CurrentPort(attestation),
    )
    assert mapping.self_entity_ref == "entity:role-self"
    assert mapping.graph_incarnation == "graph-incarnation"
    assert mapping.certification_ref.startswith("d11:self-identity:")
    with pytest.raises(ValueError, match="differs from current role"):
        qualify_admin_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=grant, owner_guard=guard,
            port=CurrentPort(replace(attestation, graph_incarnation="old-graph")),
        )
    with pytest.raises(ValueError, match="installed persona or Owner proof"):
        qualify_admin_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=replace(grant, installation_id="another-installation"),
            owner_guard=guard, port=CurrentPort(attestation),
        )
    with pytest.raises(ValueError, match="installed persona or Owner proof"):
        qualify_admin_self_identity(
            role=role, activation_atom=activation, policy=policy,
            installation_grant=grant,
            owner_guard=replace(guard, pending_revoke_operation_id="revoke"),
            port=CurrentPort(attestation),
        )
    with pytest.raises(ValueError, match="role entity, not an account"):
        replace(attestation, self_entity_ref="entity:account-v1:sender")
    with pytest.raises(ValueError, match="signature encoding"):
        replace(attestation, signature="unverified")
    assert canonical_digest(attestation.signing_payload) != canonical_digest(
        replace(attestation, self_entity_ref="entity:another-role").signing_payload)
