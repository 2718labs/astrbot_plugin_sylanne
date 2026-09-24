"""Compose the independent D01 and D03 onboarding policy resolvers."""

from __future__ import annotations

from typing import Mapping

from .d01_onboarding import CurrentD01OnboardingResolver
from .d03_onboarding import CurrentD03OnboardingResolver
from .onboarding import TrustedBindScene, TrustedCreateCharacter
from .service import AuthenticatedSession


class CurrentOnboardingResolver:
    """Route each operation to its domain resolver; absent paths remain HOLD."""

    def __init__(
        self,
        *,
        d01: CurrentD01OnboardingResolver | None = None,
        d03: CurrentD03OnboardingResolver | None = None,
    ) -> None:
        self._d01 = d01
        self._d03 = d03

    def replay_committed_create_character(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> object | None:
        if self._d01 is None:
            return None
        return self._d01.replay_committed_create_character(
            coordinator=coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=request_digest)

    def reject_unresolvable_create_character(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> bool:
        if self._d01 is None:
            return False
        return self._d01.reject_unresolvable_create_character(
            coordinator=coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=request_digest)

    def replay_committed_bind_scene(
        self, *, coordinator: object, session: AuthenticatedSession,
        scope: str, purpose: str, audience: str, operation_id: str,
        request_digest: str,
    ) -> object | None:
        if self._d03 is None:
            return None
        return self._d03.replay_committed_bind_scene(
            coordinator=coordinator, session=session, scope=scope,
            purpose=purpose, audience=audience, operation_id=operation_id,
            request_digest=request_digest)

    def resolve_create_character(
        self,
        *,
        session: AuthenticatedSession,
        scope: str,
        purpose: str,
        audience: str,
        operation_id: str,
        request_digest: str,
        input_data: Mapping[str, object],
    ) -> TrustedCreateCharacter | None:
        if self._d01 is None:
            return None
        return self._d01.resolve_create_character(
            session=session,
            scope=scope,
            purpose=purpose,
            audience=audience,
            operation_id=operation_id,
            request_digest=request_digest,
            input_data=input_data,
        )

    def resolve_bind_scene(
        self,
        *,
        coordinator: object,
        session: AuthenticatedSession,
        scope: str,
        purpose: str,
        audience: str,
        operation_id: str,
        request_digest: str,
        input_data: Mapping[str, object],
    ) -> TrustedBindScene | None:
        if self._d03 is None:
            return None
        return self._d03.resolve_bind_scene(
            coordinator=coordinator,
            session=session,
            scope=scope,
            purpose=purpose,
            audience=audience,
            operation_id=operation_id,
            request_digest=request_digest,
            input_data=input_data,
        )


__all__ = ("CurrentOnboardingResolver",)
