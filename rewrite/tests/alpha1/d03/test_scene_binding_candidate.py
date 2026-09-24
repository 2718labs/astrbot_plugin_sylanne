"""D03 prepares a guarded candidate; D11 remains the committing authority."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import (
    ActiveRoleQualification, PersonaBlock, PersonaPlan,
)
from sylanne3.domains.d03 import (
    ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)


def _candidate_inputs():
    namespace = NamespaceId("bot", "persona")
    plan = PersonaPlan(
        "plan:one", namespace, 1,
        (PersonaBlock("identity", "semantic_identity", "companion", "read_only"),),
        (), True,
    )
    role_reads = tuple(GraphVersion(
        AtomKey(Owner("persona", "bot", "persona"), type_name, name), 1,
    ) for type_name, name in (
        ("d01.persona_activation.v1", "current"),
        ("d01.persona_plan.v1", "plan:one"),
        ("d11.owner_grant.v1", "primary"),
    ))
    active = ActiveRoleQualification(namespace, plan.head_id, plan, role_reads, 0, 1)
    owner_guard = OwnerAuthorizationGuardV1(
        "authority", "installation", namespace, 1, "sha256:" + "a" * 64,
        0, 0,
    )
    binding = RoleBinding(
        "binding:project", "persona:persona", "collaborator", None, None,
        "scene:project", "scene", "private", ("norm:project",), 1.0,
        None, 10, ("source:one",), 1, "active",
    )
    key = AtomKey(
        Owner("scene", "bot", "persona", "scene:project"),
        "d03.role_binding", binding.role_binding_id,
    )
    query = QueryEpoch(namespace, "d03.role_binding", 0)
    request = RoleBindingRequest(
        "persona:persona", None, None, "scene:project", "bind_scene",
        "configure", 1.0, True,
    )
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (), query, None, request,
    )
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity:one", None, "attempt:one", "prepare", "operation:one",
            canonical_digest({"input_refs": ["source:one"]}),
        ),
        AuthorityContext(
            "host", "d11", "capability:one", namespace,
            ("persona", "scene"), "configure", ("internal",), "policy", 1,
        ),
        VersionGuard(
            role_reads + (GraphVersion(key, 0),), (query,), 0, 0,
            "catalogue", "scheme", "operator", "policy", (), (), (),
        ),
        SourceQualification(
            ("source:one",), "observed", 1.0, 1.0,
            "external_observation", "eligible", None, "not_applicable",
        ),
        ("source:one",), "budget:one", 10.0, 10.0, "interval:one", (),
    )
    provider = ContextProvider()
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("collaborator",), "norms": ("norm:project",),
    }, None)
    return provider, envelope, binding, active, owner_guard, prior, key


def test_first_scene_binding_candidate_carries_role_and_negative_query_guards():
    provider, envelope, binding, active, owner_guard, prior, key = _candidate_inputs()
    proposal = provider.build_scene_binding_proposal(
        envelope, binding, active, owner_guard, prior,
    )
    assert proposal.domain == "d03"
    assert proposal.typed_writes[0].key == key
    assert proposal.typed_writes[0].dependencies == tuple(
        item.key for item in active.read_versions
    )
    assert proposal.dependencies.current_invalidation == active.read_versions
    assert provider.validate(proposal, None) == proposal


def test_first_scene_binding_rejects_missing_cas_or_source():
    provider, envelope, binding, active, owner_guard, prior, key = _candidate_inputs()
    with pytest.raises(ValueError, match="CAS guards"):
        provider.build_scene_binding_proposal(
            replace(envelope, version_guard=replace(
                envelope.version_guard, query_epochs=(),
            )), binding, active, owner_guard, prior,
        )
    with pytest.raises(ValueError, match="source references"):
        provider.build_scene_binding_proposal(
            envelope, replace(binding, source_refs=("source:unverified",)),
            active, owner_guard, prior,
        )
    with pytest.raises(ValueError, match="negative query"):
        provider.build_scene_binding_proposal(
            envelope, binding, active, owner_guard,
            replace(prior, status="partial"),
        )
    with pytest.raises(ValueError, match="CAS guards"):
        provider.build_scene_binding_proposal(
            envelope, binding, active, owner_guard,
            replace(prior, read_versions=(GraphVersion(key, 1),)),
        )
    with pytest.raises(ValueError, match="active role"):
        provider.build_scene_binding_proposal(
            envelope, binding, active,
            replace(owner_guard, pending_revoke_operation_id="operation:revoke"),
            prior,
        )


def test_first_scene_binding_separates_owner_config_from_host_evidence():
    provider, envelope, binding, active, owner_guard, prior, _key = _candidate_inputs()
    namespace = envelope.authority.namespace
    owner = source_key(*namespace.as_tuple, "owner-config")
    host = source_key(*namespace.as_tuple, "host-identity")
    refs = (owner.token, host.token)
    binding = replace(binding, social_role="scene_participant", norm_refs=(),
                      source_refs=refs)
    provider.compile_scheme({"schema": "d03.context.scheme.v1",
                             "roles": ("scene_participant",), "norms": ()}, None)
    envelope = replace(
        envelope,
        identity=replace(envelope.identity, canonical_input_digest=canonical_digest({
            "input_refs": list(refs)})),
        input_refs=refs,
        source_qualification=SourceQualification(
            (host.token,), "observed", 1.0, 1.0,
            "external_observation", "eligible", None, "not_applicable"),
        version_guard=replace(envelope.version_guard, read_versions=(
            *envelope.version_guard.read_versions,
            GraphVersion(owner, 0), GraphVersion(access_key(*namespace.as_tuple, "owner-config"), 0),
            GraphVersion(host, 0), GraphVersion(access_key(*namespace.as_tuple, "host-identity"), 0),
        )),
    )
    proposal = provider.build_scene_binding_proposal(
        envelope, binding, active, owner_guard, prior,
        owner_config_source_ref=owner.token, host_identity_source_ref=host.token)
    assert provider.validate(proposal, None) == proposal
    assert proposal.typed_writes[0].value["norm_refs"] == []
    with pytest.raises(ValueError, match="distinct Owner and host"):
        provider.build_scene_binding_proposal(
            replace(envelope, source_qualification=replace(
                envelope.source_qualification, source_refs=refs)),
            binding, active, owner_guard, prior,
            owner_config_source_ref=owner.token, host_identity_source_ref=host.token)
    with pytest.raises(ValueError, match="revision-0 guards"):
        provider.build_scene_binding_proposal(
            replace(envelope, version_guard=replace(
                envelope.version_guard,
                read_versions=tuple(item for item in envelope.version_guard.read_versions
                                    if item.key != access_key(*namespace.as_tuple, "owner-config")))),
            binding, active, owner_guard, prior,
            owner_config_source_ref=owner.token, host_identity_source_ref=host.token)
    with pytest.raises(ValueError, match="distinct Owner and host"):
        provider.build_scene_binding_proposal(
            envelope, replace(binding, source_refs=(host.token, owner.token)),
            active, owner_guard, prior,
            owner_config_source_ref=owner.token, host_identity_source_ref=host.token)


def test_owner_first_scene_binding_write_has_frozen_sources_and_d01_dependencies():
    provider, _envelope, binding, active, owner_guard, prior, key = _candidate_inputs()
    owner = source_key(*active.namespace.as_tuple, "owner-config")
    host = source_key(*active.namespace.as_tuple, "host-identity")
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("scene_participant",), "norms": (),
    }, None)
    binding = replace(
        binding, social_role="scene_participant", norm_refs=(),
        source_refs=(owner.token, host.token),
    )

    write = provider.build_owner_scene_binding_write(
        binding, active, owner_guard, prior,
        owner_config_source_key=owner, host_identity_source_key=host,
    )
    assert write.key == key
    assert write.value["norm_refs"] == []
    assert write.value["source_refs"] == [owner.token, host.token]
    assert write.dependencies == tuple(item.key for item in active.read_versions)


def test_owner_first_scene_binding_write_rejects_invalid_route_or_role():
    provider, _envelope, binding, active, owner_guard, prior, key = _candidate_inputs()
    owner = source_key(*active.namespace.as_tuple, "owner-config")
    host = source_key(*active.namespace.as_tuple, "host-identity")
    binding = replace(binding, source_refs=(owner.token, host.token))
    kwargs = {"owner_config_source_key": owner, "host_identity_source_key": host}

    with pytest.raises(ValueError, match="negative query"):
        provider.build_owner_scene_binding_write(
            binding, active, owner_guard, replace(prior, status="partial"), **kwargs,
        )
    with pytest.raises(ValueError, match="negative query"):
        provider.build_owner_scene_binding_write(
            binding, active, owner_guard,
            replace(prior, read_versions=(GraphVersion(key, 1),)), **kwargs,
        )
    with pytest.raises(ValueError, match="source keys"):
        provider.build_owner_scene_binding_write(
            replace(binding, source_refs=(host.token, owner.token)),
            active, owner_guard, prior, **kwargs,
        )
    with pytest.raises(ValueError, match="source keys"):
        provider.build_owner_scene_binding_write(
            binding, active, owner_guard, prior,
            owner_config_source_key=source_key("other", "persona", "owner-config"),
            host_identity_source_key=host,
        )
    with pytest.raises(ValueError, match="active D03 scheme"):
        provider.build_owner_scene_binding_write(
            replace(binding, social_role="unregistered"),
            active, owner_guard, prior, **kwargs,
        )
    with pytest.raises(ValueError, match="Owner guard"):
        provider.build_owner_scene_binding_write(
            binding, active,
            replace(owner_guard, pending_revoke_operation_id="operation:revoke"),
            prior, **kwargs,
        )
