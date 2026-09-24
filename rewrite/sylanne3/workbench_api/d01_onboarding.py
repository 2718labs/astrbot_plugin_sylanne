"""Resolve D01 creation from current, host-verified installation resources.

This adapter owns no grant or catalogue. A host must install all three ports;
the browser's fields only select resources verified by those ports.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping, Protocol
from uuid import UUID

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..domains.d01 import PersonaBlock, PersonaPlan, ValueRule
from ..runtime_contracts import NamespaceId
from .onboarding import TrustedCreateCharacter
from .service import AuthenticatedSession


def _receipt_digest(value: str) -> bool:
    return (type(value) is str and len(value) == 71
            and value.startswith("sha256:")
            and all(char in "0123456789abcdef" for char in value[7:]))


@dataclass(frozen=True, slots=True)
class CurrentOwnerIdentity:
    """Pairing verified for this dashboard session and installation namespace."""

    actor_id: str
    session_id: str
    scope: str
    namespace: NamespaceId
    principal: OwnerPrincipalV1
    guard: OwnerAuthorizationGuardV1


@dataclass(frozen=True, slots=True)
class VerifiedCreationResources:
    """Current local catalogue resolution of all three user selections."""

    namespace: NamespaceId
    blueprint_ref: str
    model_capability_ref: str
    budget_ref: str
    blueprint_version: int
    blueprint_digest: str
    blocks: tuple[PersonaBlock, ...]
    values: tuple[ValueRule, ...]
    model: VerifiedModelCapability
    budget: VerifiedBudgetLease


@dataclass(frozen=True, slots=True)
class VerifiedModelCapability:
    namespace: NamespaceId
    capability_ref: str
    resource_ref: str
    revision: int
    digest: str

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.capability_ref) is not str or not self.capability_ref
                or type(self.resource_ref) is not str or not self.resource_ref
                or type(self.revision) is not int or self.revision < 1
                or not _receipt_digest(self.digest)):
            raise ValueError("host model capability receipt is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedBudgetLease:
    namespace: NamespaceId
    budget_ref: str
    lease_ref: str
    version: int
    digest: str

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.budget_ref) is not str or not self.budget_ref
                or type(self.lease_ref) is not str or not self.lease_ref
                or type(self.version) is not int or self.version < 1
                or not _receipt_digest(self.digest)):
            raise ValueError("current budget lease receipt is invalid")


class InstalledNamespacePort(Protocol):
    def resolve_installed_namespace(self, *, scope: str) -> NamespaceId | None: ...


class CurrentOwnerIdentityPort(Protocol):
    def resolve_current_owner_identity(
        self, *, session: AuthenticatedSession, scope: str,
        namespace: NamespaceId,
    ) -> CurrentOwnerIdentity | None: ...


class LocalCreationCataloguePort(Protocol):
    def resolve_current_resources(
        self, *, namespace: NamespaceId, blueprint_ref: str,
        model_capability_ref: str, budget_ref: str,
        session: AuthenticatedSession, principal: OwnerPrincipalV1,
    ) -> VerifiedCreationResources | None: ...


class CurrentD01OnboardingResolver:
    """Build a deterministic authored plan only from trusted current inputs.

    Missing ports or catalogue rows are an admission HOLD. The coordinator
    still performs the durable Owner grant and write-fence checks.
    """

    def __init__(
        self, *, namespaces: InstalledNamespacePort | None = None,
        owners: CurrentOwnerIdentityPort | None = None,
        catalogue: LocalCreationCataloguePort | None = None,
    ) -> None:
        self._namespaces = namespaces
        self._owners = owners
        self._catalogue = catalogue

    def replay_committed_create_character(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> object | None:
        """Ask the graph to replay an original commit under the current Owner."""
        replay = getattr(coordinator, "replay_committed_role_initialization_v2", None)
        if (not callable(replay) or not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.create", purpose, audience)
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or self._namespaces is None or self._owners is None
                or not _receipt_digest(request_digest)):
            return None
        try:
            UUID(operation_id)
        except (TypeError, ValueError, AttributeError):
            return None
        namespace = self._namespaces.resolve_installed_namespace(scope=scope)
        if (type(namespace) is not NamespaceId
                or scope != f"{namespace.bot_id}/{namespace.persona_id}"):
            return None
        owner = self._owners.resolve_current_owner_identity(
            session=session, scope=scope, namespace=namespace)
        if (type(owner) is not CurrentOwnerIdentity
                or owner.actor_id != session.actor_id
                or owner.session_id != session.session_id
                or owner.scope != scope or owner.namespace != namespace
                or type(owner.principal) is not OwnerPrincipalV1
                or type(owner.guard) is not OwnerAuthorizationGuardV1
                or owner.guard.namespace != namespace
                or owner.guard.authorization_revision != 1
                or owner.guard.pending_revoke_operation_id is not None
                or owner.guard.minimum_revocation_revision != 0
                or owner.guard.minimum_revocation_epoch != 0):
            return None
        return replay(
            namespace=namespace, operation_id=operation_id,
            request_digest=request_digest, principal=owner.principal,
            actor_id=owner.actor_id,
            owner_session_token=session.owner_session_token,
            owner_session_request=session.owner_session_request)

    def reject_unresolvable_create_character(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> bool:
        """Terminate a proven pending attempt when current selection vanished."""
        reject = getattr(coordinator, "reject_unresolvable_role_initialization_v2", None)
        if (not callable(reject) or not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.create", purpose, audience)
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or self._namespaces is None or self._owners is None
                or not _receipt_digest(request_digest)):
            return False
        try:
            UUID(operation_id)
        except (TypeError, ValueError, AttributeError):
            return False
        namespace = self._namespaces.resolve_installed_namespace(scope=scope)
        if (type(namespace) is not NamespaceId
                or scope != f"{namespace.bot_id}/{namespace.persona_id}"):
            return False
        owner = self._owners.resolve_current_owner_identity(
            session=session, scope=scope, namespace=namespace)
        if (type(owner) is not CurrentOwnerIdentity
                or owner.actor_id != session.actor_id
                or owner.session_id != session.session_id
                or owner.scope != scope or owner.namespace != namespace
                or type(owner.principal) is not OwnerPrincipalV1
                or type(owner.guard) is not OwnerAuthorizationGuardV1
                or owner.guard.namespace != namespace
                or owner.guard.authorization_revision != 1
                or owner.guard.pending_revoke_operation_id is not None
                or owner.guard.minimum_revocation_revision != 0
                or owner.guard.minimum_revocation_epoch != 0):
            return False
        return bool(reject(
            namespace=namespace, operation_id=operation_id,
            request_digest=request_digest, principal=owner.principal,
            actor_id=owner.actor_id,
            owner_session_token=session.owner_session_token,
            owner_session_request=session.owner_session_request))

    def resolve_create_character(
        self, *, session: AuthenticatedSession, scope: str, purpose: str,
        audience: str, operation_id: str, request_digest: str,
        input_data: Mapping[str, object],
    ) -> TrustedCreateCharacter | None:
        if (not isinstance(session, AuthenticatedSession)
                or not session.allows(scope, "workbench.create", purpose, audience)
                or type(session.owner_session_token) is not str
                or not session.owner_session_token
                or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
                or self._namespaces is None or self._owners is None
                or self._catalogue is None):
            return None
        try:
            UUID(operation_id)
        except (TypeError, ValueError, AttributeError):
            return None
        if (not isinstance(request_digest, str)
                or len(request_digest) != 71
                or not request_digest.startswith("sha256:")
                or any(char not in "0123456789abcdef" for char in request_digest[7:])):
            return None
        if set(input_data) != {"display_name", "blueprint", "model_capability_ref", "budget_ref"}:
            return None
        name = input_data["display_name"]
        blueprint_ref = input_data["blueprint"]
        model_ref = input_data["model_capability_ref"]
        budget_ref = input_data["budget_ref"]
        if (not isinstance(name, str) or not 1 <= len(name.strip()) <= 80
                or not all(isinstance(value, str) and value for value in (
                    blueprint_ref, model_ref, budget_ref))):
            return None
        namespace = self._namespaces.resolve_installed_namespace(scope=scope)
        if (not isinstance(namespace, NamespaceId)
                or scope != f"{namespace.bot_id}/{namespace.persona_id}"):
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
                or owner.guard.authorization_revision != 1
                or owner.guard.minimum_revocation_revision != 0
                or owner.guard.minimum_revocation_epoch != 0
                or owner.guard.pending_revoke_operation_id is not None):
            return None
        resources = self._catalogue.resolve_current_resources(
            namespace=namespace, blueprint_ref=blueprint_ref,
            model_capability_ref=model_ref, budget_ref=budget_ref,
            session=session, principal=owner.principal)
        if (not isinstance(resources, VerifiedCreationResources)
                or resources.namespace != namespace
                or resources.blueprint_ref != blueprint_ref
                or resources.model_capability_ref != model_ref
                or resources.budget_ref != budget_ref
                or type(resources.blueprint_version) is not int
                or resources.blueprint_version < 1
                or not _receipt_digest(resources.blueprint_digest)
                or not isinstance(resources.model, VerifiedModelCapability)
                or resources.model.namespace != namespace
                or resources.model.capability_ref != model_ref
                or not isinstance(resources.budget, VerifiedBudgetLease)
                or resources.budget.namespace != namespace
                or resources.budget.budget_ref != budget_ref
                or any(not isinstance(item, PersonaBlock) for item in resources.blocks)
                or any(not isinstance(item, ValueRule) for item in resources.values)
                or any(item.kind == "semantic_identity" for item in resources.blocks)):
            return None
        plan_id = "onboard-" + sha256(
            f"sylanne.d01.onboarding.v1\0{namespace.bot_id}\0{namespace.persona_id}"
            f"\0{operation_id}".encode("utf-8")
        ).hexdigest()
        plan = PersonaPlan(
            plan_id=plan_id, namespace=namespace,
            version=resources.blueprint_version,
            blocks=(PersonaBlock("identity", "semantic_identity", name.strip(), "read_only"),
                    *resources.blocks),
            values=resources.values, authored=True,
        )
        return TrustedCreateCharacter(
            actor_id=session.actor_id, session_id=session.session_id,
            scope=scope, operation_id=operation_id,
            request_digest=request_digest, plan=plan,
            principal=owner.principal, resources=resources,
        )

    def resolve_bind_scene(self, **_kwargs: object) -> None:
        """D03 scene admission has its own policy resolver."""
        return None


__all__ = (
    "CurrentD01OnboardingResolver", "CurrentOwnerIdentity", "VerifiedCreationResources",
    "InstalledNamespacePort", "CurrentOwnerIdentityPort", "LocalCreationCataloguePort",
    "VerifiedModelCapability", "VerifiedBudgetLease",
)
