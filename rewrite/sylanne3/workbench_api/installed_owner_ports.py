"""Installed namespace and signed Owner identity for D01/D03 onboarding."""

from __future__ import annotations

from ..authority_service.v2_owner_contract import (
    OwnerActorBindingV1, OwnerAuthorizationGuardV1, OwnerPrincipalV1,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import (
    CreationBudgetProofV1, CurrentOwnerViewV1, GraphCoordinator, namespace_ref,
)
from ..installation_policy import AdminInstallationPolicy
from ..runtime_contracts import InstallationGrantV2, NamespaceId
from .d01_onboarding import CurrentOwnerIdentity, VerifiedBudgetLease
from .service import AuthenticatedSession


class InstalledOwnerOnboardingPorts:
    """Resolve onboarding identity using the installed Authority and graph fence."""

    def __init__(
        self, *, policy: AdminInstallationPolicy, authority: object,
        coordinator: GraphCoordinator, bootstrap: object,
    ) -> None:
        grant = getattr(authority, "installation_grant", None)
        if (type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or not isinstance(coordinator, GraphCoordinator)
                or policy.authority_namespace != namespace_ref(policy.namespace)
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest)
                != (policy.expected_authority_id, policy.installation_id,
                    policy.administrator_holder, policy.manifest_digest)
                or not callable(getattr(authority, "current_anchor", None))
                or not callable(getattr(authority, "current_owner_actor_binding", None))):
            raise TypeError("installed V2 Owner authority is required")
        self._policy = policy
        self._authority = authority
        self._coordinator = coordinator
        self._bootstrap = bootstrap

    def resolve_installed_namespace(self, *, scope: str) -> NamespaceId | None:
        policy = self._policy
        if scope != f"{policy.namespace.bot_id}/{policy.namespace.persona_id}":
            return None
        try:
            anchor = self._authority.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            if (anchor.authority_id == policy.expected_authority_id
                    and anchor.namespace == policy.authority_namespace
                    and anchor.activation_generation >= 1):
                return policy.namespace
        except (RuntimeError, TypeError, ValueError, OSError):
            pass
        return None

    def resolve_current_owner_identity(
        self, *, session: AuthenticatedSession, scope: str,
        namespace: NamespaceId,
    ) -> CurrentOwnerIdentity | None:
        policy = self._policy
        if (type(session) is not AuthenticatedSession
                or namespace != policy.namespace
                or scope != f"{namespace.bot_id}/{namespace.persona_id}"
                or not session.actor_id or not session.session_id
                or "owner" not in session.scope_audiences.get(scope, ())
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1):
            return None
        request = session.owner_session_request
        if (request.authority_id != policy.expected_authority_id
                or request.authority_namespace != policy.authority_namespace
                or request.installation_id != policy.installation_id
                or request.audience != "owner"):
            return None
        try:
            binding = self._authority.current_owner_actor_binding(
                namespace=namespace,
                authority_namespace=policy.authority_namespace,
                actor_id=session.actor_id)
            if (type(binding) is not OwnerActorBindingV1
                    or binding.authority_id != policy.expected_authority_id
                    or binding.installation_id != policy.installation_id
                    or binding.namespace != namespace
                    or binding.actor_id != session.actor_id
                    or binding.principal != request.principal):
                return None
            view = self._coordinator.read_current_owner_view(
                self._bootstrap, actor=session.actor_id, namespace=namespace,
                purpose="workbench_view", audience="owner",
                expected_principal=binding.principal,
                owner_session_token=session.owner_session_token,
                owner_session_request=request)
            if type(view) is not CurrentOwnerViewV1:
                return None
            guard = view.authority_guard
            if (type(guard) is not OwnerAuthorizationGuardV1
                    or guard.authority_id != policy.expected_authority_id
                    or guard.installation_id != policy.installation_id
                    or guard.namespace != namespace
                    or view.graph_binding.principal != binding.principal
                    or guard.authorization_revision != 1
                    or guard.minimum_revocation_revision != 0
                    or guard.minimum_revocation_epoch != 0
                    or guard.pending_revoke_operation_id is not None):
                return None
            return CurrentOwnerIdentity(
                session.actor_id, session.session_id, scope, namespace,
                binding.principal, guard)
        except (RuntimeError, TypeError, ValueError, OSError, PermissionError):
            return None

    def resolve_current_budget_lease(
        self, *, namespace: NamespaceId, budget_ref: str,
        session: AuthenticatedSession, principal: OwnerPrincipalV1,
    ) -> VerifiedBudgetLease | None:
        """Read an existing D11 lease under the signed current Owner fence."""
        policy = self._policy
        if (type(namespace) is not NamespaceId or namespace != policy.namespace
                or type(budget_ref) is not str or not budget_ref
                or type(session) is not AuthenticatedSession
                or type(principal) is not OwnerPrincipalV1
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or session.owner_session_request.principal != principal
                or session.owner_session_request.authority_id != policy.expected_authority_id
                or session.owner_session_request.installation_id != policy.installation_id
                or session.owner_session_request.authority_namespace != policy.authority_namespace
                or session.owner_session_request.audience != "owner"
                or "owner" not in session.scope_audiences.get(
                    f"{namespace.bot_id}/{namespace.persona_id}", ())):
            return None
        try:
            proof = self._coordinator.read_current_creation_budget_v2(
                namespace=namespace, budget_ref=budget_ref,
                actor_id=session.actor_id, principal=principal,
                owner_session_token=session.owner_session_token,
                owner_session_request=session.owner_session_request,
            )
        except (RuntimeError, TypeError, ValueError, OSError, PermissionError):
            return None
        if (type(proof) is not CreationBudgetProofV1
                or type(proof.budget) is not VerifiedBudgetLease
                or proof.budget.namespace != namespace
                or proof.budget.budget_ref != budget_ref):
            return None
        return proof.budget


__all__ = ("InstalledOwnerOnboardingPorts",)
