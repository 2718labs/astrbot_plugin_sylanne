"""Resolve a first D03 scene binding from host and graph facts.

The browser only selects a scene and acknowledges the proposed visibility.
The scene policy is host supplied; the D01 head and negative D03 query must
come from one current graph-worker proof.  This adapter owns no graph state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol
from uuid import UUID

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..domains.d01 import ActiveRoleQualification
from ..domains.d03 import ContextProvider, RoleBinding, RoleBindingResolution
from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import CommandEnvelope, NamespaceId
from .d01_onboarding import (
    CurrentOwnerIdentity, CurrentOwnerIdentityPort, InstalledNamespacePort,
)
from .onboarding import TrustedBindScene
from .service import AuthenticatedSession


@dataclass(frozen=True, slots=True)
class VerifiedHostScenePolicy:
    """Host-qualified scene identity, D03 policy and source-bearing command."""

    namespace: NamespaceId
    scene_ref: str
    visibility: str
    binding: RoleBinding
    envelope: CommandEnvelope


@dataclass(frozen=True, slots=True)
class CurrentGraphGuardMetadata:
    """VersionGuard inputs observed with the first-binding graph read."""

    namespace: NamespaceId
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    catalogue_version: str
    scheme_version: str
    operator_version: str
    policy_version: str

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("graph guard namespace is required")
        for name in ("graph_epoch", "access_epoch", "delete_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        for name in ("catalogue_version", "scheme_version",
                     "operator_version", "policy_version"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"{name} must be a current version")


@dataclass(frozen=True, slots=True)
class CurrentFirstBindingProof:
    """One fenced graph read of D01 and the complete D03 negative query."""

    active_role: ActiveRoleQualification
    prior: RoleBindingResolution
    owner_guard: OwnerAuthorizationGuardV1
    graph_guard: CurrentGraphGuardMetadata

    def __post_init__(self) -> None:
        if type(self.graph_guard) is not CurrentGraphGuardMetadata:
            raise TypeError("current graph guard metadata is required")
        if (self.graph_guard.namespace != self.active_role.namespace
                or self.graph_guard.namespace != self.owner_guard.namespace
                or self.prior.query_epoch is None
                or self.graph_guard.graph_epoch != self.active_role.graph_epoch
                or self.graph_guard.graph_epoch != self.prior.query_epoch.revision):
            raise ValueError("first binding graph guard differs from read epoch")


class HostScenePolicyPort(Protocol):
    def resolve_current_scene(
        self, *, namespace: NamespaceId, scene_ref: str, visibility: str,
        purpose: str, audience: str, operation_id: str,
        request_digest: str, proof: CurrentFirstBindingProof,
    ) -> VerifiedHostScenePolicy | None: ...


@dataclass(frozen=True, slots=True)
class SceneBindDecision:
    trusted: TrustedBindScene | None
    hold_reason: str | None


class CurrentD03OnboardingResolver:
    """Prepare a D03 candidate; W01 still owns admission and the final write."""

    def __init__(
        self, *, namespaces: InstalledNamespacePort | None = None,
        owners: CurrentOwnerIdentityPort | None = None,
        scenes: HostScenePolicyPort | None = None,
        provider: ContextProvider | None = None,
    ) -> None:
        self._namespaces = namespaces
        self._owners = owners
        self._scenes = scenes
        self._provider = provider

    def resolve_create_character(self, **_kwargs: object) -> None:
        """D01 onboarding has a separate resolver."""
        return None

    def resolve_bind_scene(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str, input_data: Mapping[str, object],
    ) -> TrustedBindScene | None:
        return self.resolve_bind_scene_decision(
            coordinator=coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=request_digest, input_data=input_data,
        ).trusted

    def resolve_bind_scene_decision(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str, input_data: Mapping[str, object],
    ) -> SceneBindDecision:
        def hold(reason: str) -> SceneBindDecision:
            return SceneBindDecision(None, reason)

        if (not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.bind_scene", purpose, audience)):
            return hold("session_capability_unavailable")
        if (type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1):
            return hold("signed_owner_session_unavailable")
        if (self._namespaces is None or self._owners is None
                or self._scenes is None or not isinstance(self._provider, ContextProvider)):
            return hold("trusted_scene_ports_uninstalled")
        try:
            UUID(operation_id)
        except (TypeError, ValueError, AttributeError):
            return hold("operation_identity_invalid")
        if (not isinstance(request_digest, str) or len(request_digest) != 71
                or not request_digest.startswith("sha256:")
                or any(ch not in "0123456789abcdef" for ch in request_digest[7:])):
            return hold("request_digest_invalid")
        if (set(input_data) != {"scene_ref", "visibility", "acknowledgement"}
                or not isinstance(input_data["scene_ref"], str)
                or not input_data["scene_ref"].startswith("scene:")
                or len(input_data["scene_ref"]) <= len("scene:")
                or not isinstance(input_data["visibility"], str)
                or input_data["visibility"] not in {"private", "group"}
                or input_data["acknowledgement"] is not True):
            return hold("scene_selection_or_acknowledgement_invalid")
        namespace = self._namespaces.resolve_installed_namespace(scope=scope)
        if (not isinstance(namespace, NamespaceId)
                or scope != f"{namespace.bot_id}/{namespace.persona_id}"):
            return hold("installed_namespace_unavailable")
        owner = self._owners.resolve_current_owner_identity(
            session=session, scope=scope, namespace=namespace)
        if (not isinstance(owner, CurrentOwnerIdentity)
                or owner.actor_id != session.actor_id
                or owner.session_id != session.session_id
                or owner.scope != scope or owner.namespace != namespace
                or not isinstance(owner.principal, OwnerPrincipalV1)
                or not isinstance(owner.guard, OwnerAuthorizationGuardV1)
                or owner.guard.namespace != namespace
                or owner.guard.pending_revoke_operation_id is not None
                or owner.guard.authorization_revision != 1
                or owner.guard.minimum_revocation_revision != 0
                or owner.guard.minimum_revocation_epoch != 0):
            return hold("current_owner_pairing_unavailable")
        scene_ref = input_data["scene_ref"]
        visibility = input_data["visibility"]
        read = getattr(coordinator, "read_first_scene_binding_proof_v2", None)
        if not callable(read):
            return hold("current_graph_negative_proof_uninstalled")
        try:
            proof = read(namespace=namespace, scene_ref=scene_ref,
                         purpose=purpose, principal=owner.principal,
                         actor_id=owner.actor_id,
                         owner_session_token=session.owner_session_token,
                         owner_session_request=session.owner_session_request)
        except (LookupError, PermissionError, RuntimeError, ValueError):
            return hold("current_graph_negative_proof_unavailable")
        if (not isinstance(proof, CurrentFirstBindingProof)
                or proof.owner_guard != owner.guard
                or proof.active_role.namespace != namespace
                or proof.active_role.authorization_revision != owner.guard.authorization_revision
                or proof.prior.status != "no_applicable_binding"
                or proof.prior.matched_bindings or proof.prior.missing_items
                or proof.prior.query_epoch is None
                or proof.prior.query_epoch.namespace != namespace
                or proof.prior.query_epoch.scope_ref != "d03.role_binding"
                or proof.prior.query_epoch.revision != proof.active_role.graph_epoch
                or proof.prior.request is None
                or not proof.prior.request.scope_complete
                or proof.prior.request.subject_persona_ref != f"persona:{namespace.persona_id}"
                or proof.prior.request.scene_ref != scene_ref
                or proof.prior.request.target_entity_ref is not None
                or proof.prior.request.group_ref is not None
                or proof.prior.request.requested_action_kind != "bind_scene"
                or proof.prior.request.purpose != purpose):
            return hold("current_graph_negative_proof_invalid")
        policy = self._scenes.resolve_current_scene(
            namespace=namespace, scene_ref=scene_ref, visibility=visibility,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=request_digest, proof=proof)
        if (not isinstance(policy, VerifiedHostScenePolicy)
                or policy.namespace != namespace
                or policy.scene_ref != scene_ref
                or policy.visibility != visibility
                or policy.binding.scene_ref != scene_ref
                or policy.binding.visibility_scope != visibility
                or policy.binding.subject_persona_ref != f"persona:{namespace.persona_id}"
                or policy.binding.scope_selector != "scene"
                or policy.binding.target_entity_ref is not None
                or policy.binding.group_ref is not None
                or policy.binding.status != "active"
                or policy.binding.binding_version != 1):
            return hold("host_scene_policy_unavailable")
        envelope = policy.envelope
        key = AtomKey(Owner("scene", *namespace.as_tuple, scene_ref),
                      "d03.role_binding", policy.binding.role_binding_id)
        expected_reads = (set(proof.active_role.read_versions)
                          | set(proof.prior.read_versions) | {GraphVersion(key, 0)})
        graph_guard = proof.graph_guard
        version_guard = envelope.version_guard
        if (envelope.authority.namespace != namespace
                or envelope.authority.actor != session.actor_id
                or envelope.authority.issuer_domain != "d11"
                or envelope.authority.purpose != purpose
                or audience not in envelope.authority.audience
                or envelope.identity.operation_id != operation_id
                or len(version_guard.read_versions) != len(expected_reads)
                or set(version_guard.read_versions) != expected_reads
                or version_guard.query_epochs != (proof.prior.query_epoch,)
                or version_guard.access_epoch != graph_guard.access_epoch
                or version_guard.delete_epoch != graph_guard.delete_epoch
                or version_guard.catalogue_version != graph_guard.catalogue_version
                or version_guard.scheme_version != graph_guard.scheme_version
                or version_guard.operator_version != graph_guard.operator_version
                or version_guard.policy_version != graph_guard.policy_version
                or envelope.source_qualification.evidence_eligibility != "qualified"
                or not set(policy.binding.source_refs).issubset(
                    envelope.source_qualification.source_refs)):
            return hold("scene_command_policy_unavailable")
        try:
            proposal = self._provider.build_scene_binding_proposal(
                envelope, policy.binding, proof.active_role,
                proof.owner_guard, proof.prior)
            self._provider.validate(proposal, None)
        except (TypeError, ValueError):
            return hold("d03_scene_proposal_unavailable")
        return SceneBindDecision(TrustedBindScene(
            session.actor_id, session.session_id, scope, operation_id,
            request_digest, policy.binding, proof.active_role,
            proposal, proof.prior, owner.principal), None)


__all__ = (
    "CurrentD03OnboardingResolver", "CurrentFirstBindingProof",
    "CurrentGraphGuardMetadata",
    "HostScenePolicyPort", "SceneBindDecision", "VerifiedHostScenePolicy",
)
