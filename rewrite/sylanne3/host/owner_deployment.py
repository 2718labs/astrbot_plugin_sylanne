"""Authority-side deployment wiring for a first Owner.

The identity port is an installation-controlled, synchronous read of current
host facts. It must obtain these facts independently of the mTLS command and
must revoke them when the host login or administrator pairing is revoked.
No AstrBot plugin request, JSON field, or mTLS certificate is an Owner identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Mapping, Protocol

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.core import AuthorityServiceCore
from ..authority_service.local_composition import compose_local_owner_authority
from ..authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from ..authority_service.v2_clock import AuthorityClockReadingV2
from ..authority_service.v2_fence_service import AuthorityV2FenceService
from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerClaimTicketV1, OwnerPrincipalV1,
)
from ..authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    OwnerProofAcceptanceV1, OwnerProofRequestV1,
)
from ..authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class CurrentOwnerPairing:
    """Record read from the administrator's current Owner pairing authority."""

    registration: OwnerCredentialRegistrationV1
    client_certificate_sha256: str
    valid_until_utc: datetime


@dataclass(frozen=True, slots=True)
class CurrentCreationPairing:
    """W01 creation pairing, sourced independently from the proposed ticket."""

    ticket: OwnerClaimTicketV1
    client_certificate_sha256: str
    valid_until_utc: datetime


@dataclass(frozen=True, slots=True)
class CurrentDashboardLogin:
    """A live host login including its stable principal and current JWT digest."""

    principal: OwnerPrincipalV1
    installation_id: str
    authority_namespace: str
    host_username: str
    host_login_jwt_digest: str
    dashboard_origin: str
    client_certificate_sha256: str
    valid_until_utc: datetime


class OwnerIdentityPort(Protocol):
    """Deployment hook backed by trusted, revocation-aware host/admin state.

    The lookup arguments are selectors only. Implementations must not derive
    their returned records from the caller's proposed ticket, registration or
    proof request, and must perform a fresh read for every invocation.
    """

    def current_creation_pairing(self, authority_namespace: str
                                 ) -> CurrentCreationPairing | None: ...

    def current_owner_pairing(self, authority_namespace: str,
                              principal: OwnerPrincipalV1
                              ) -> CurrentOwnerPairing | None: ...

    def current_dashboard_login(self, host_login_jwt_digest: str
                                ) -> CurrentDashboardLogin | None: ...


class OwnerDeploymentVerifier:
    """Convert independent current identity records into exact Authority checks."""

    def __init__(self, identity: OwnerIdentityPort, utc_clock: Callable[[], datetime]) -> None:
        if identity is None or any(not callable(getattr(identity, name, None)) for name in (
                "current_creation_pairing", "current_owner_pairing",
                "current_dashboard_login")):
            raise AuthorityUnavailable("trusted Owner identity port is unavailable")
        if not callable(utc_clock):
            raise AuthorityUnavailable("trusted Owner UTC clock is unavailable")
        self._identity = identity
        self._clock = utc_clock

    def _current(self, expiry: datetime) -> bool:
        now = self._clock()
        if (type(now) is not datetime or now.tzinfo is None
                or now.utcoffset() != timedelta(0)
                or type(expiry) is not datetime or expiry.tzinfo is None
                or expiry.utcoffset() != timedelta(0)):
            return False
        return now < expiry

    @staticmethod
    def _peer(credential: object) -> str | None:
        return (credential.certificate_sha256
                if type(credential) is MtlsPeerCredential else None)

    def first_claim(self, credential: object, ticket: OwnerClaimTicketV1,
                    authority_namespace: str) -> bool:
        peer = self._peer(credential)
        if peer is None or type(ticket) is not OwnerClaimTicketV1:
            return False
        record = self._identity.current_creation_pairing(authority_namespace)
        return (type(record) is CurrentCreationPairing
                and record.ticket == ticket
                and record.client_certificate_sha256 == peer
                and self._current(record.valid_until_utc))

    def pair_credential(self, credential: object,
                        registration: OwnerCredentialRegistrationV1) -> bool:
        peer = self._peer(credential)
        if peer is None or type(registration) is not OwnerCredentialRegistrationV1:
            return False
        record = self._identity.current_owner_pairing(
            registration.authority_namespace, registration.principal)
        return (type(record) is CurrentOwnerPairing
                and record.registration == registration
                and record.client_certificate_sha256 == peer
                and self._current(record.valid_until_utc))

    def current_session(self, credential: object,
                        request: OwnerProofRequestV1) -> bool:
        peer = self._peer(credential)
        if peer is None or type(request) is not OwnerProofRequestV1:
            return False
        record = self._identity.current_dashboard_login(request.host_login_jwt_digest)
        return (type(record) is CurrentDashboardLogin
                and record.principal == request.principal
                and record.installation_id == request.installation_id
                and record.authority_namespace == request.authority_namespace
                and record.host_username == request.host_username
                and record.host_login_jwt_digest == request.host_login_jwt_digest
                and record.dashboard_origin == request.dashboard_origin
                and record.client_certificate_sha256 == peer
                and self._current(record.valid_until_utc))

    def current_claimant(self, credential: object,
                         operation: OwnerAuthorizationOperationV1,
                         acceptance: OwnerProofAcceptanceV1) -> bool:
        """Recheck pairing and login for every reserve/finalize, including replay."""
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(acceptance) is not OwnerProofAcceptanceV1
                or operation.action != "issue" or operation.ticket is None):
            return False
        request = acceptance.challenge.request
        try:
            request.assert_matches_operation(operation)
        except (TypeError, ValueError, AuthorityUnavailable):
            return False
        if (not self.first_claim(credential, operation.ticket, request.authority_namespace)
                or not self.current_session(credential, request)):
            return False
        peer = self._peer(credential)
        record = self._identity.current_owner_pairing(
            request.authority_namespace, request.principal)
        if type(record) is not CurrentOwnerPairing or peer is None:
            return False
        registration = record.registration
        return (type(registration) is OwnerCredentialRegistrationV1
                and registration.authority_id == request.authority_id
                and registration.authority_namespace == request.authority_namespace
                and registration.installation_id == request.installation_id
                and registration.principal == request.principal
                and registration.credential_id == request.credential_id
                and registration.credential_epoch == request.credential_epoch
                and record.client_certificate_sha256 == peer
                and self._current(record.valid_until_utc))


def compose_owner_deployment(
    *, core: AuthorityServiceCore,
    v2_fences: Mapping[str, AuthorityV2FenceService],
    graph_db_path: str | Path,
    utc_clock: Callable[[], datetime],
    identity: OwnerIdentityPort | None,
    administrator_authorizer: Callable[[object, str, str, str | None], bool],
    publisher_manifest_verifier: Callable[[str, str, str, str], bool],
    installations_v2: Mapping[tuple[str, str], AdministratorInstallationV2],
    namespace_bindings_v2: Mapping[tuple[str, str, NamespaceId], str],
    clock_provider: Callable[[], AuthorityClockReadingV2] | None = None,
    create_owner_schema: bool = False,
    owner_sessions: AuthorityV2OwnerSessionStore | None = None,
) -> AuthorityRpcServer:
    """Compose the existing graph verifier, proof store and mTLS RPC server.

    The caller installs the returned server and TLS configuration separately.
    Missing trusted host identity prevents construction before schema changes.
    Credential registration checks current pairing. With Owner sessions, key
    login and final issue use the revocable Authority session store. The older
    proof mode requires a separately verified current Dashboard login source.
    """
    verifier = OwnerDeploymentVerifier(identity, utc_clock)
    if (owner_sessions is not None
            and owner_sessions._current_pairing_source is not identity):
        raise AuthorityUnavailable(
            "Owner sessions require the current installation pairing source")
    proofs = AuthorityV2OwnerProofStore(
        core, utc_clock=utc_clock,
        pairing_verifier=verifier.pair_credential,
        session_verifier=verifier.current_session if owner_sessions is None else None,
        current_pairing_source=identity if owner_sessions is not None else None,
        create=create_owner_schema,
    )
    return compose_local_owner_authority(
        core=core, v2_fences=v2_fences, graph_db_path=graph_db_path,
        utc_clock=utc_clock, first_claim_verifier=verifier.first_claim,
        claimant_verifier=None, owner_proofs=proofs,
        current_claimant_verifier=(verifier.current_claimant
                                   if owner_sessions is None else None),
        owner_sessions=owner_sessions,
        creation_pairing_source=identity if owner_sessions is not None else None,
        administrator_authorizer=administrator_authorizer,
        publisher_manifest_verifier=publisher_manifest_verifier,
        installations_v2=installations_v2,
        namespace_bindings_v2=namespace_bindings_v2,
        clock_provider=clock_provider, create_owner_schema=create_owner_schema,
    )


__all__ = (
    "CurrentCreationPairing", "CurrentDashboardLogin", "CurrentOwnerPairing",
    "OwnerDeploymentVerifier", "OwnerIdentityPort", "compose_owner_deployment",
)
