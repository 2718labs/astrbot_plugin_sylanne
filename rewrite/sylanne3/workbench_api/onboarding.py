"""Server-side resolution of a user's onboarding intent.

The browser selects named resources. Only a trusted host resolver may turn
those names into a D01 plan and stable Owner principal. Neither an AstrBot
dashboard account nor this DTO is an Owner grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Protocol

from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..domains.d01 import ActiveRoleQualification, PersonaPlan
from ..domains.d03.context import RoleBindingResolution
from .service import AuthenticatedSession

if TYPE_CHECKING:
    from ..host.current_scene import CurrentHostScene
    from .d01_onboarding import VerifiedCreationResources


@dataclass(frozen=True, slots=True)
class TrustedCreateCharacter:
    actor_id: str
    session_id: str
    scope: str
    operation_id: str
    request_digest: str
    plan: PersonaPlan
    principal: OwnerPrincipalV1
    resources: VerifiedCreationResources


@dataclass(frozen=True, slots=True)
class TrustedBindScene:
    actor_id: str
    session_id: str
    scope: str
    operation_id: str
    request_digest: str
    scene: CurrentHostScene
    active_role: ActiveRoleQualification
    prior: RoleBindingResolution
    principal: OwnerPrincipalV1
    authorization_head: str


class OnboardingPolicyResolver(Protocol):
    """Host-installed resolver; never populated from workbench JSON."""

    def resolve_create_character(
        self, *, session: AuthenticatedSession, scope: str, purpose: str,
        audience: str, operation_id: str, request_digest: str,
        input_data: Mapping[str, object],
    ) -> TrustedCreateCharacter | None: ...

    def resolve_bind_scene(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str, input_data: Mapping[str, object],
    ) -> TrustedBindScene | None: ...


__all__ = ("TrustedCreateCharacter", "TrustedBindScene", "OnboardingPolicyResolver")
