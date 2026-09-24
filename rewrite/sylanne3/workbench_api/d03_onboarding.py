"""Resolve Owner scene selection from current host identity and graph facts.

The browser selects a scene and acknowledges visibility. The D01 head and
negative D03 query come from one graph-worker proof. This adapter owns no graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Protocol
from uuid import UUID

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..domains.d01 import ActiveRoleQualification
from ..domains.d03 import RoleBindingResolution
from ..graph_coordinator import SceneBindingReceiptV1
from ..runtime_contracts import NamespaceId
from .d01_onboarding import (
    CurrentOwnerIdentity, CurrentOwnerIdentityPort, InstalledNamespacePort,
)
from .onboarding import TrustedBindScene
from .service import AuthenticatedSession

if TYPE_CHECKING:
    from ..host.current_scene import CurrentHostScene


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


class HostSceneIdentityPort(Protocol):
    def verify(self, namespace: NamespaceId, scene_ref: str,
               visibility: str) -> CurrentHostScene | None: ...


@dataclass(frozen=True, slots=True)
class SceneBindDecision:
    trusted: TrustedBindScene | None
    hold_reason: str | None


class CurrentD03OnboardingResolver:
    """Prepare typed Owner inputs; the graph worker owns the final write."""

    def __init__(
        self, *, namespaces: InstalledNamespacePort | None = None,
        owners: CurrentOwnerIdentityPort | None = None,
        scenes: HostSceneIdentityPort | None = None,
    ) -> None:
        self._namespaces = namespaces
        self._owners = owners
        self._scenes = scenes

    def replay_committed_bind_scene(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> SceneBindingReceiptV1 | None:
        """Replay a durable receipt before a now-stale negative query or host check."""
        if (not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.bind_scene", purpose, audience)
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or self._namespaces is None or self._owners is None):
            return None
        namespace = self._namespaces.resolve_installed_namespace(scope=scope)
        if not isinstance(namespace, NamespaceId) or scope != f"{namespace.bot_id}/{namespace.persona_id}":
            return None
        owner = self._owners.resolve_current_owner_identity(
            session=session, scope=scope, namespace=namespace)
        if (not isinstance(owner, CurrentOwnerIdentity)
                or owner.actor_id != session.actor_id
                or owner.session_id != session.session_id
                or owner.scope != scope or owner.namespace != namespace
                or not isinstance(owner.principal, OwnerPrincipalV1)
                or not isinstance(owner.guard, OwnerAuthorizationGuardV1)
                or owner.guard.namespace != namespace
                or owner.guard.pending_revoke_operation_id is not None):
            return None
        replay = getattr(coordinator, "replay_committed_scene_binding_v2", None)
        if not callable(replay):
            return None
        return replay(namespace=namespace, operation_id=operation_id,
                      request_digest=request_digest, principal=owner.principal,
                      actor_id=owner.actor_id,
                      owner_session_token=session.owner_session_token,
                      owner_session_request=session.owner_session_request)

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
        from ..host.current_scene import CurrentHostScene

        def hold(reason: str) -> SceneBindDecision:
            return SceneBindDecision(None, reason)

        if (not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.bind_scene", purpose, audience)):
            return hold("session_capability_unavailable")
        if (type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1):
            return hold("signed_owner_session_unavailable")
        if (self._namespaces is None or self._owners is None or self._scenes is None):
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
        scene = self._scenes.verify(namespace, scene_ref, visibility)
        if (type(scene) is not CurrentHostScene
                or scene.namespace != namespace or scene.scene_ref != scene_ref
                or scene.visibility != visibility):
            return hold("current_host_scene_unavailable")
        return SceneBindDecision(TrustedBindScene(
            session.actor_id, session.session_id, scope, operation_id,
            request_digest, scene, proof.active_role, proof.prior,
            owner.principal, proof.owner_guard.authorization_head), None)


__all__ = (
    "CurrentD03OnboardingResolver", "CurrentFirstBindingProof",
    "CurrentGraphGuardMetadata",
    "HostSceneIdentityPort", "SceneBindDecision",
)
