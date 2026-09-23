"""Installer-owned Owner pairings in the separate Authority database.

This store runs inside the Authority process. Its write methods are installer
operations guarded by the Core's server-side administrator authorizer; they are
not RPC methods. The database and WAL must be inaccessible to the plugin OS
account. A Dashboard JWT is deliberately not a current Owner login source.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from typing import Callable

from ..authority_service.contract import AuthorityUnavailable, identifier
from ..authority_service.core import AuthorityServiceCore
from ..authority_service.v2_owner_contract import (
    OwnerClaimTicketV1, OwnerPrincipalV1, canonical_bytes,
    from_wire as owner_from_wire,
)
from ..authority_service.v2_owner_proof import (
    OwnerCredentialRegistrationV1, from_wire as proof_from_wire,
    to_wire as proof_to_wire,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import namespace_ref
from .owner_deployment import (
    CurrentCreationPairing, CurrentDashboardLogin, CurrentOwnerPairing,
)


_CREATION = """CREATE TABLE authority_owner_creation_pairings_v1 (
    authority_namespace TEXT PRIMARY KEY,
    ticket_bytes BLOB NOT NULL,
    client_certificate_sha256 TEXT NOT NULL,
    valid_until_utc TEXT NOT NULL
) STRICT"""
_CREDENTIAL = """CREATE TABLE authority_owner_credential_pairings_v1 (
    authority_namespace TEXT NOT NULL,
    principal_bytes BLOB NOT NULL,
    registration_bytes BLOB NOT NULL,
    client_certificate_sha256 TEXT NOT NULL,
    valid_until_utc TEXT NOT NULL,
    PRIMARY KEY(authority_namespace,principal_bytes)
) STRICT"""
_TABLES = {
    "authority_owner_creation_pairings_v1": _CREATION,
    "authority_owner_credential_pairings_v1": _CREDENTIAL,
}


def _stamp(value: datetime) -> str:
    if (type(value) is not datetime or value.tzinfo is None
            or value.utcoffset() != timedelta(0) or value.microsecond):
        raise ValueError("Owner pairing expiry must be UTC seconds")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _time(value: str) -> datetime:
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise AuthorityUnavailable("stored Owner pairing expiry differs") from exc
    if _stamp(result) != value:
        raise AuthorityUnavailable("stored Owner pairing expiry differs")
    return result


def _certificate(value: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError("Owner pairing requires a verified client certificate digest")
    return value


def _registration_bytes(registration: OwnerCredentialRegistrationV1) -> bytes:
    return json.dumps(proof_to_wire(registration), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class AuthorityOwnerPairingSource:
    """Fresh pairing reads and administrator-only changes on one Authority Core."""

    def __init__(self, core: AuthorityServiceCore, *,
                 utc_clock: Callable[[], datetime], create: bool = False) -> None:
        if type(core) is not AuthorityServiceCore or not callable(utc_clock):
            raise AuthorityUnavailable("independent Authority and UTC clock are required")
        self._core = core
        self._clock = utc_clock
        with core._tx() as db:
            self._require_mode(db)
            present = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?)",
                tuple(_TABLES),
            )}
            if not present and create:
                for ddl in _TABLES.values():
                    db.execute(ddl)
            elif present != set(_TABLES):
                raise AuthorityUnavailable("Owner pairing schema is absent or partial")
            for name, ddl in _TABLES.items():
                if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (ddl,):
                    raise AuthorityUnavailable("Owner pairing schema differs")

    @staticmethod
    def _require_mode(db: sqlite3.Connection) -> None:
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("Owner pairing requires v2-only Authority")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def _now(self) -> datetime:
        try:
            now = self._clock()
        except Exception as exc:
            raise AuthorityUnavailable("trusted Owner pairing clock failed") from exc
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise AuthorityUnavailable("trusted Owner pairing clock must provide UTC")
        return now

    def _scope(self, db: sqlite3.Connection, authority_namespace: str,
               authority_id: str) -> None:
        identifier(authority_namespace, "authority_namespace")
        if self._core._id(db) != authority_id:
            raise AuthorityUnavailable("Owner pairing Authority identity differs")
        self._core._row(db, authority_namespace)

    def pair_creation(self, *, administrator_credential: object,
                      authority_namespace: str, ticket: OwnerClaimTicketV1,
                      client_certificate_sha256: str,
                      valid_until_utc: datetime) -> None:
        """Record an independently verified W01 fact; no ticket is minted here."""
        if type(ticket) is not OwnerClaimTicketV1 or namespace_ref(ticket.namespace) != authority_namespace:
            raise ValueError("Owner creation pairing namespace differs")
        certificate = _certificate(client_certificate_sha256)
        expiry = _stamp(valid_until_utc)
        if valid_until_utc <= self._now():
            raise ValueError("Owner creation pairing is already expired")
        self._core._require(administrator_credential, "owner_identity_pair", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            self._scope(db, authority_namespace, ticket.authority_id)
            db.execute("INSERT INTO authority_owner_creation_pairings_v1 VALUES(?,?,?,?)",
                       (authority_namespace, canonical_bytes(ticket), certificate, expiry))

    def pair_credential(self, *, administrator_credential: object,
                        registration: OwnerCredentialRegistrationV1,
                        client_certificate_sha256: str,
                        valid_until_utc: datetime) -> None:
        """Record an installer-approved Owner public key and principal."""
        if type(registration) is not OwnerCredentialRegistrationV1:
            raise TypeError("Owner credential registration is required")
        certificate = _certificate(client_certificate_sha256)
        expiry = _stamp(valid_until_utc)
        if valid_until_utc <= self._now():
            raise ValueError("Owner credential pairing is already expired")
        namespace = registration.authority_namespace
        self._core._require(administrator_credential, "owner_identity_pair", namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            self._scope(db, namespace, registration.authority_id)
            db.execute("INSERT INTO authority_owner_credential_pairings_v1 VALUES(?,?,?,?,?)",
                       (namespace, canonical_bytes(registration.principal),
                        _registration_bytes(registration), certificate, expiry))

    def revoke_creation(self, *, administrator_credential: object,
                        authority_namespace: str) -> None:
        self._core._require(administrator_credential, "owner_identity_revoke", authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            self._core._row(db, authority_namespace)
            db.execute("DELETE FROM authority_owner_creation_pairings_v1 WHERE authority_namespace=?",
                       (authority_namespace,))

    def revoke_credential(self, *, administrator_credential: object,
                          authority_namespace: str,
                          principal: OwnerPrincipalV1) -> None:
        """Invalidate pairing, registered key and its live sessions atomically."""
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("stable Owner principal is required")
        self._core._require(administrator_credential, "owner_identity_revoke", authority_namespace)
        principal_bytes = canonical_bytes(principal)
        with self._core._tx() as db:
            self._require_mode(db)
            self._core._row(db, authority_namespace)
            row = db.execute(
                "SELECT registration_bytes FROM authority_owner_credential_pairings_v1 "
                "WHERE authority_namespace=? AND principal_bytes=?",
                (authority_namespace, principal_bytes),
            ).fetchone()
            if row is None:
                return
            registration = proof_from_wire(json.loads(row[0]))
            if (type(registration) is not OwnerCredentialRegistrationV1
                    or registration.authority_namespace != authority_namespace
                    or registration.principal != principal):
                raise AuthorityUnavailable("stored Owner credential pairing differs")
            # Existing Owner sessions check the current registered key in this
            # same Core transaction. Removing it invalidates all bearer tokens.
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_owner_credentials_v1'").fetchone():
                db.execute(
                    "DELETE FROM authority_owner_credentials_v1 WHERE authority_namespace=? "
                    "AND installation_id=? AND principal_json=?",
                    (authority_namespace, registration.installation_id,
                     _principal_bytes(principal)),
                )
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_owner_session_principals_v1'").fetchone():
                db.execute(
                    "INSERT INTO authority_owner_session_principals_v1 VALUES(?,?,?,1) "
                    "ON CONFLICT(authority_namespace,installation_id,principal_json) "
                    "DO UPDATE SET revocation_epoch=revocation_epoch+1",
                    (authority_namespace, registration.installation_id,
                     _principal_bytes(principal)),
                )
            db.execute(
                "DELETE FROM authority_owner_credential_pairings_v1 "
                "WHERE authority_namespace=? AND principal_bytes=?",
                (authority_namespace, principal_bytes),
            )

    def current_creation_pairing(self, authority_namespace: str) -> CurrentCreationPairing | None:
        identifier(authority_namespace, "authority_namespace")
        with self._core._lock:
            db = self._core._db
            if db is None:
                raise AuthorityUnavailable("Authority is unavailable")
            self._require_mode(db)
            row = db.execute(
                "SELECT ticket_bytes,client_certificate_sha256,valid_until_utc "
                "FROM authority_owner_creation_pairings_v1 WHERE authority_namespace=?",
                (authority_namespace,),
            ).fetchone()
            if row is None:
                return None
            ticket = owner_from_wire(json.loads(row[0]))
            if (type(ticket) is not OwnerClaimTicketV1
                    or namespace_ref(ticket.namespace) != authority_namespace):
                raise AuthorityUnavailable("stored Owner creation pairing differs")
            return CurrentCreationPairing(ticket, _certificate(row[1]), _time(row[2]))

    def current_owner_pairing(self, authority_namespace: str,
                              principal: OwnerPrincipalV1) -> CurrentOwnerPairing | None:
        identifier(authority_namespace, "authority_namespace")
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("stable Owner principal is required")
        with self._core._lock:
            db = self._core._db
            if db is None:
                raise AuthorityUnavailable("Authority is unavailable")
            self._require_mode(db)
            row = db.execute(
                "SELECT registration_bytes,client_certificate_sha256,valid_until_utc "
                "FROM authority_owner_credential_pairings_v1 "
                "WHERE authority_namespace=? AND principal_bytes=?",
                (authority_namespace, canonical_bytes(principal)),
            ).fetchone()
            if row is None:
                return None
            registration = proof_from_wire(json.loads(row[0]))
            if (type(registration) is not OwnerCredentialRegistrationV1
                    or registration.authority_namespace != authority_namespace
                    or registration.principal != principal):
                raise AuthorityUnavailable("stored Owner credential pairing differs")
            return CurrentOwnerPairing(registration, _certificate(row[1]), _time(row[2]))

    def current_dashboard_login(self, host_login_jwt_digest: str) -> CurrentDashboardLogin | None:
        # AstrBot Dashboard JWTs have no reliable server-side logout record.
        return None

    def require_current_creation_pairing_in_tx(
            self, db: sqlite3.Connection, *, authority_namespace: str,
            ticket: OwnerClaimTicketV1,
            client_certificate_sha256: str) -> None:
        """Check W01 pairing in the same transaction as ticket issue writes."""
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner creation check needs Authority transaction")
        if type(ticket) is not OwnerClaimTicketV1 or namespace_ref(ticket.namespace) != authority_namespace:
            raise AuthorityUnavailable("Owner creation pairing identity differs")
        self._require_mode(db)
        self._scope(db, authority_namespace, ticket.authority_id)
        row = db.execute(
            "SELECT ticket_bytes,client_certificate_sha256,valid_until_utc "
            "FROM authority_owner_creation_pairings_v1 WHERE authority_namespace=?",
            (authority_namespace,),
        ).fetchone()
        if (row is None or row[0] != canonical_bytes(ticket)
                or row[1] != _certificate(client_certificate_sha256)
                or self._now() >= _time(row[2])):
            raise AuthorityUnavailable("Owner creation pairing is not current")

    def require_current_owner_key_in_tx(
            self, db: sqlite3.Connection, request: OwnerSessionLoginRequestV1,
            public_key: bytes) -> None:
        """Reject a session when its installer pairing expires or is replaced."""
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner key check needs Authority transaction")
        if type(request) is not OwnerSessionLoginRequestV1 or type(public_key) is not bytes:
            raise AuthorityUnavailable("Owner key check identity differs")
        self._require_mode(db)
        self._scope(db, request.authority_namespace, request.authority_id)
        row = db.execute(
            "SELECT registration_bytes,valid_until_utc "
            "FROM authority_owner_credential_pairings_v1 "
            "WHERE authority_namespace=? AND principal_bytes=?",
            (request.authority_namespace, canonical_bytes(request.principal)),
        ).fetchone()
        if row is None or self._now() >= _time(row[1]):
            raise AuthorityUnavailable("Owner credential pairing is not current")
        registration = proof_from_wire(json.loads(row[0]))
        if (type(registration) is not OwnerCredentialRegistrationV1
                or registration.authority_id != request.authority_id
                or registration.authority_namespace != request.authority_namespace
                or registration.installation_id != request.installation_id
                or registration.principal != request.principal
                or registration.credential_id != request.credential_id
                or registration.credential_epoch != request.credential_epoch
                or registration.public_key != public_key):
            raise AuthorityUnavailable("Owner credential pairing differs from session key")

    def require_current_registration_in_tx(
            self, db: sqlite3.Connection,
            registration: OwnerCredentialRegistrationV1,
            client_certificate_sha256: str) -> None:
        """Recheck installer pairing at the final credential enrollment write."""
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner enrollment check needs Authority transaction")
        if type(registration) is not OwnerCredentialRegistrationV1:
            raise AuthorityUnavailable("Owner registration differs")
        self._require_mode(db)
        self._scope(db, registration.authority_namespace, registration.authority_id)
        row = db.execute(
            "SELECT registration_bytes,client_certificate_sha256,valid_until_utc "
            "FROM authority_owner_credential_pairings_v1 "
            "WHERE authority_namespace=? AND principal_bytes=?",
            (registration.authority_namespace, canonical_bytes(registration.principal)),
        ).fetchone()
        if (row is None or row[0] != _registration_bytes(registration)
                or row[1] != _certificate(client_certificate_sha256)
                or self._now() >= _time(row[2])):
            raise AuthorityUnavailable("Owner credential pairing is not current")


def _principal_bytes(principal: OwnerPrincipalV1) -> bytes:
    """Match the registered-key/session tables' canonical principal key."""
    from ..authority_service.v2_owner_proof import _principal

    return _principal(principal)


__all__ = ("AuthorityOwnerPairingSource",)
