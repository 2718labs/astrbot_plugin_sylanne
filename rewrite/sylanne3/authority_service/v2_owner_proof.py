"""Independent Owner key proof in Authority SQLite.

An installation transport credential only admits an RPC. Enrollment additionally
requires a trusted, independently paired Owner verifier. This store records proof
of key possession; it does not issue a graph grant or authorize a claim.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
import sqlite3
from typing import Callable
from urllib.parse import urlsplit

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerPrincipalV1, canonical_digest,
    from_wire as owner_from_wire, to_wire as owner_to_wire,
)
from ..graph_coordinator import namespace_ref


SCHEMA = "sylanne3.authority.owner-proof.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_CREDENTIALS = """CREATE TABLE authority_owner_credentials_v1 (
    authority_namespace TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    credential_epoch INTEGER NOT NULL CHECK(credential_epoch >= 1),
    credential_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    enrollment_operation_id TEXT NOT NULL UNIQUE,
    registration_json BLOB NOT NULL,
    PRIMARY KEY(authority_namespace,installation_id,principal_json)
) STRICT"""
_ENROLLMENTS = """CREATE TABLE authority_owner_enrollments_v1 (
    enrollment_operation_id TEXT PRIMARY KEY,
    registration_json BLOB NOT NULL
) STRICT"""
_CHALLENGES = """CREATE TABLE authority_owner_proof_challenges_v1 (
    operation_id TEXT PRIMARY KEY,
    authority_namespace TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    request_json BLOB NOT NULL,
    credential_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    signature BLOB,
    accepted_at_utc TEXT,
    receipt_json BLOB
) STRICT"""


def _canonical(value: object) -> bytes:
    def wire(item: object) -> object:
        if type(item) is bytes:
            return {"$bytes": item.hex()}
        if type(item) is dict:
            return {key: wire(part) for key, part in item.items()}
        return item

    return json.dumps(wire(asdict(value)), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _principal(value: OwnerPrincipalV1) -> bytes:
    if type(value) is not OwnerPrincipalV1:
        raise TypeError("stable Owner principal is required")
    return _canonical(value)


def _time(value: str) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise ValueError("time must be canonical UTC seconds")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(value: str, name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be SHA-256")


def _verify_signature(public_key: bytes, signature: bytes, payload: bytes,
                      denial: str) -> None:
    """Use the Authority-only crypto backend when a signature is verified."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityUnavailable(denial) from exc


@dataclass(frozen=True, slots=True)
class OwnerCredentialRegistrationV1:
    authority_id: str
    authority_namespace: str
    installation_id: str
    principal: OwnerPrincipalV1
    credential_id: str
    credential_epoch: int
    public_key: bytes
    enrollment_operation_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown Owner proof schema")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "credential_id", "enrollment_operation_id"):
            identifier(getattr(self, name), name)
        _principal(self.principal)
        if type(self.credential_epoch) is not int or self.credential_epoch < 1:
            raise ValueError("credential epoch must be positive")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise ValueError("Ed25519 public key must contain 32 bytes")

    def rotation_bytes(self) -> bytes:
        """Domain-separated bytes that the previous Owner key must sign."""
        return b"Sylanne3 Owner credential rotation v1\n" + _canonical(self)


@dataclass(frozen=True, slots=True)
class OwnerProofRequestV1:
    authority_id: str
    operation_id: str
    action: str
    authority_namespace: str
    installation_id: str
    principal: OwnerPrincipalV1
    credential_id: str
    credential_epoch: int
    authorization_request_digest: str
    ticket_digest: str
    host_login_jwt_digest: str
    host_username: str
    dashboard_origin: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown Owner proof schema")
        for name in ("authority_id", "operation_id", "authority_namespace",
                     "installation_id", "credential_id"):
            identifier(getattr(self, name), name)
        if self.action != "first_owner_claim":
            raise ValueError("unknown Owner proof action")
        _principal(self.principal)
        if type(self.credential_epoch) is not int or self.credential_epoch < 1:
            raise ValueError("credential epoch must be positive")
        for name in ("authorization_request_digest", "ticket_digest",
                     "host_login_jwt_digest"):
            _sha256(getattr(self, name), name)
        if (type(self.host_username) is not str or not 1 <= len(self.host_username) <= 256
                or self.host_username != self.host_username.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in self.host_username)):
            raise ValueError("invalid host username")
        if type(self.dashboard_origin) is not str:
            raise ValueError("invalid Dashboard Origin")
        origin = urlsplit(self.dashboard_origin)
        if (origin.scheme not in {"http", "https"} or not origin.hostname
                or origin.username is not None or origin.password is not None
                or origin.path or origin.query or origin.fragment
                or self.dashboard_origin != f"{origin.scheme}://{origin.netloc}"):
            raise ValueError("invalid Dashboard Origin")
        try:
            origin.port
        except ValueError as exc:
            raise ValueError("invalid Dashboard Origin port") from exc

    def assert_matches_operation(self, operation: OwnerAuthorizationOperationV1) -> None:
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != "issue":
            raise AuthorityUnavailable("first Owner claim operation is required")
        ticket = operation.ticket
        if (ticket is None or self.action != "first_owner_claim"
                or self.operation_id != operation.operation_id
                or self.authority_id != operation.authority_id
                or self.installation_id != operation.installation_id
                or self.authority_namespace != namespace_ref(operation.namespace)
                or self.principal != operation.principal
                or self.authorization_request_digest != operation.request_digest
                or self.ticket_digest != canonical_digest(ticket)):
            raise AuthorityUnavailable("Owner proof differs from authorization operation")


@dataclass(frozen=True, slots=True)
class OwnerProofChallengeV1:
    request: OwnerProofRequestV1
    nonce: str
    issued_at_utc: str
    expires_at_utc: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.request) is not OwnerProofRequestV1:
            raise ValueError("unknown Owner challenge schema")
        if type(self.nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.nonce):
            raise ValueError("invalid Owner challenge nonce")
        if _time(self.expires_at_utc) <= _time(self.issued_at_utc):
            raise ValueError("Owner challenge expiry must follow issue time")

    def signed_bytes(self) -> bytes:
        return _canonical(self)


@dataclass(frozen=True, slots=True)
class OwnerProofAcceptanceV1:
    challenge: OwnerProofChallengeV1
    signature_digest: str
    accepted_at_utc: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.challenge) is not OwnerProofChallengeV1:
            raise ValueError("unknown Owner proof acceptance schema")
        if type(self.signature_digest) is not str or _DIGEST.fullmatch(self.signature_digest) is None:
            raise ValueError("invalid signature digest")
        _time(self.accepted_at_utc)

    @property
    def receipt_digest(self) -> str:
        return "sha256:" + hashlib.sha256(_canonical(self)).hexdigest()


def to_wire(value: OwnerCredentialRegistrationV1 | OwnerProofRequestV1 |
            OwnerProofChallengeV1 | OwnerProofAcceptanceV1) -> dict[str, object]:
    """Exact, versioned RPC representation; signatures travel as lowercase hex."""
    if type(value) is OwnerCredentialRegistrationV1:
        return {"schema": SCHEMA, "kind": "owner_credential_registration_v1",
                "authority_id": value.authority_id,
                "authority_namespace": value.authority_namespace,
                "installation_id": value.installation_id,
                "principal": owner_to_wire(value.principal),
                "credential_id": value.credential_id,
                "credential_epoch": value.credential_epoch,
                "public_key": value.public_key.hex(),
                "enrollment_operation_id": value.enrollment_operation_id}
    if type(value) is OwnerProofRequestV1:
        return {"schema": SCHEMA, "kind": "owner_proof_request_v1",
                "authority_id": value.authority_id, "operation_id": value.operation_id,
                "action": value.action,
                "authority_namespace": value.authority_namespace,
                "installation_id": value.installation_id,
                "principal": owner_to_wire(value.principal),
                "credential_id": value.credential_id,
                "credential_epoch": value.credential_epoch,
                "authorization_request_digest": value.authorization_request_digest,
                "ticket_digest": value.ticket_digest,
                "host_login_jwt_digest": value.host_login_jwt_digest,
                "host_username": value.host_username,
                "dashboard_origin": value.dashboard_origin}
    if type(value) is OwnerProofChallengeV1:
        return {"schema": SCHEMA, "kind": "owner_proof_challenge_v1",
                "request": to_wire(value.request), "nonce": value.nonce,
                "issued_at_utc": value.issued_at_utc,
                "expires_at_utc": value.expires_at_utc}
    if type(value) is OwnerProofAcceptanceV1:
        return {"schema": SCHEMA, "kind": "owner_proof_acceptance_v1",
                "challenge": to_wire(value.challenge),
                "signature_digest": value.signature_digest,
                "accepted_at_utc": value.accepted_at_utc}
    raise TypeError("unsupported Owner proof wire value")


def from_wire(value: object) -> (OwnerCredentialRegistrationV1 | OwnerProofRequestV1 |
                                  OwnerProofChallengeV1 | OwnerProofAcceptanceV1):
    if type(value) is not dict or value.get("schema") != SCHEMA:
        raise ValueError("unknown Owner proof wire schema")
    kind = value.get("kind")
    common = {"schema", "kind"}
    if kind == "owner_credential_registration_v1":
        fields = common | {"authority_id", "authority_namespace", "installation_id",
                           "principal", "credential_id", "credential_epoch",
                           "public_key", "enrollment_operation_id"}
        expected = OwnerCredentialRegistrationV1
    elif kind == "owner_proof_request_v1":
        fields = common | {"authority_id", "operation_id", "action",
                           "authority_namespace", "installation_id", "principal",
                           "credential_id", "credential_epoch",
                           "authorization_request_digest", "ticket_digest",
                           "host_login_jwt_digest", "host_username", "dashboard_origin"}
        expected = OwnerProofRequestV1
    elif kind == "owner_proof_challenge_v1":
        fields = common | {"request", "nonce", "issued_at_utc", "expires_at_utc"}
        expected = OwnerProofChallengeV1
    elif kind == "owner_proof_acceptance_v1":
        fields = common | {"challenge", "signature_digest", "accepted_at_utc"}
        expected = OwnerProofAcceptanceV1
    else:
        raise ValueError("unknown Owner proof wire kind")
    if set(value) != fields:
        raise ValueError("invalid Owner proof wire fields")
    if expected in (OwnerCredentialRegistrationV1, OwnerProofRequestV1):
        principal = owner_from_wire(value["principal"])
        if type(principal) is not OwnerPrincipalV1:
            raise ValueError("invalid Owner proof principal")
        data = {key: item for key, item in value.items()
                if key not in {"kind", "principal", "public_key"}}
        data["principal"] = principal
        if expected is OwnerCredentialRegistrationV1:
            raw = value["public_key"]
            if (type(raw) is not str or len(raw) != 64
                    or any(char not in "0123456789abcdef" for char in raw)):
                raise ValueError("invalid Owner public key encoding")
            data["public_key"] = bytes.fromhex(raw)
        result = expected(**data)
    elif expected is OwnerProofChallengeV1:
        result = OwnerProofChallengeV1(from_wire(value["request"]), value["nonce"],
                                       value["issued_at_utc"], value["expires_at_utc"],
                                       value["schema"])
    else:
        result = OwnerProofAcceptanceV1(from_wire(value["challenge"]),
                                        value["signature_digest"],
                                        value["accepted_at_utc"], value["schema"])
    if type(result) is not expected or to_wire(result) != value:
        raise ValueError("noncanonical Owner proof wire value")
    return result


class AuthorityV2OwnerProofStore:
    """Versioned Owner public key and one-use signed challenge acceptance."""

    def __init__(self, core: AuthorityServiceCore, *,
                 utc_clock: Callable[[], datetime] | None = None,
                 pairing_verifier: Callable[[object, OwnerCredentialRegistrationV1], bool] | None = None,
                 session_verifier: Callable[[object, OwnerProofRequestV1], bool] | None = None,
                 recovery_verifier: Callable[[object, OwnerCredentialRegistrationV1,
                                              OwnerCredentialRegistrationV1], bool] | None = None,
                 create: bool = False) -> None:
        if type(core) is not AuthorityServiceCore:
            raise TypeError("Owner proof needs an independent Authority core")
        self._core = core
        self._utc_clock = utc_clock
        self._pairing_verifier = pairing_verifier
        self._session_verifier = session_verifier
        self._recovery_verifier = recovery_verifier
        with core._tx() as db:
            self._require_mode(db)
            present = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?,?)",
                ("authority_owner_credentials_v1", "authority_owner_enrollments_v1",
                 "authority_owner_proof_challenges_v1"))}
            if not present and create:
                db.execute(_CREDENTIALS)
                db.execute(_ENROLLMENTS)
                db.execute(_CHALLENGES)
            elif present != {"authority_owner_credentials_v1", "authority_owner_enrollments_v1",
                             "authority_owner_proof_challenges_v1"}:
                raise AuthorityUnavailable("Owner proof schema is absent or partial")
            for name, ddl in (("authority_owner_credentials_v1", _CREDENTIALS),
                              ("authority_owner_enrollments_v1", _ENROLLMENTS),
                              ("authority_owner_proof_challenges_v1", _CHALLENGES)):
                if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (ddl,):
                    raise AuthorityUnavailable("Owner proof schema differs")

    @staticmethod
    def _require_mode(db: sqlite3.Connection) -> None:
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("Owner proof requires v2-only Authority")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def _now(self) -> datetime:
        if not callable(self._utc_clock):
            raise AuthorityUnavailable("trusted Owner proof clock is unavailable")
        try:
            now = self._utc_clock()
        except Exception as exc:
            raise AuthorityUnavailable("trusted Owner proof clock failed") from exc
        if (type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0)):
            raise AuthorityUnavailable("Owner proof clock must provide UTC")
        return now

    def _verify_session(self, transport_credential: object, request: OwnerProofRequestV1) -> None:
        if not callable(self._session_verifier):
            raise AuthorityUnavailable("trusted host login verifier is unavailable")
        try:
            current = self._session_verifier(transport_credential, request)
        except Exception as exc:
            raise AuthorityUnavailable("host login verification failed") from exc
        if current is not True:
            raise AuthorityUnavailable("host login binding denied")

    def _scope(self, db: sqlite3.Connection, authority_id: str, namespace: str) -> None:
        if self._core._id(db) != authority_id:
            raise AuthorityUnavailable("Owner proof Authority identity differs")
        row = self._core._row(db, namespace)
        if row[0] is None or row[1] < 1 or row[2] != "active" or row[3] is not None or row[9] != "clear":
            raise AuthorityUnavailable("Owner proof namespace is not active")

    @staticmethod
    def _credential(db: sqlite3.Connection, namespace: str, installation: str,
                    principal: bytes) -> tuple | None:
        return db.execute(
            "SELECT credential_epoch,credential_id,public_key,enrollment_operation_id,registration_json "
            "FROM authority_owner_credentials_v1 WHERE authority_namespace=? "
            "AND installation_id=? AND principal_json=?",
            (namespace, installation, principal)).fetchone()

    def register_credential(self, *, transport_credential: object,
                            registration: OwnerCredentialRegistrationV1,
                            rotation_signature: bytes | None = None) -> OwnerCredentialRegistrationV1:
        """Pairing plus previous Owner signature or independent recovery rotates."""
        if type(registration) is not OwnerCredentialRegistrationV1:
            raise TypeError("Owner credential registration is required")
        self._core._require(transport_credential, "owner_pair", registration.authority_namespace)
        principal = _principal(registration.principal)
        encoded = _canonical(registration)
        with self._core._tx() as db:
            self._require_mode(db)
            self._scope(db, registration.authority_id, registration.authority_namespace)
            current = self._credential(db, registration.authority_namespace,
                                       registration.installation_id, principal)
            if current is not None and current[4] == encoded:
                return registration
        if current is not None:
            if rotation_signature is not None:
                if type(rotation_signature) is not bytes or len(rotation_signature) != 64:
                    raise ValueError("Owner rotation signature must contain 64 bytes")
                _verify_signature(current[2], rotation_signature,
                                  registration.rotation_bytes(),
                                  "previous Owner key denied rotation")
            else:
                if not callable(self._recovery_verifier):
                    raise AuthorityUnavailable("Owner rotation needs current key or recovery proof")
                previous_data = json.loads(current[4])
                previous_data["principal"] = registration.principal
                previous_data["public_key"] = current[2]
                previous = OwnerCredentialRegistrationV1(**previous_data)
                try:
                    recovered = self._recovery_verifier(
                        transport_credential, previous, registration)
                except Exception as exc:
                    raise AuthorityUnavailable("independent Owner recovery failed") from exc
                if recovered is not True:
                    raise AuthorityUnavailable("independent Owner recovery denied")
        if not callable(self._pairing_verifier):
            raise AuthorityUnavailable("independent Owner pairing verifier is unavailable")
        try:
            paired = self._pairing_verifier(transport_credential, registration)
        except Exception as exc:
            raise AuthorityUnavailable("independent Owner pairing verification failed") from exc
        if paired is not True:
            raise AuthorityUnavailable("independent Owner pairing denied")
        with self._core._tx() as db:
            self._require_mode(db)
            self._scope(db, registration.authority_id, registration.authority_namespace)
            current = self._credential(db, registration.authority_namespace,
                                       registration.installation_id, principal)
            if current is not None and current[4] == encoded:
                return registration
            if registration.credential_epoch != (current[0] + 1 if current else 1):
                raise AuthorityUnavailable("Owner credential epoch differs")
            if db.execute(
                "SELECT 1 FROM authority_owner_enrollments_v1 WHERE enrollment_operation_id=?",
                (registration.enrollment_operation_id,)).fetchone():
                raise AuthorityUnavailable("Owner enrollment operation replay differs")
            db.execute("INSERT INTO authority_owner_enrollments_v1 VALUES(?,?)",
                       (registration.enrollment_operation_id, encoded))
            if current is None:
                db.execute(
                    "INSERT INTO authority_owner_credentials_v1 VALUES(?,?,?,?,?,?,?,?)",
                    (registration.authority_namespace, registration.installation_id, principal,
                     registration.credential_epoch, registration.credential_id,
                     registration.public_key, registration.enrollment_operation_id, encoded))
            else:
                db.execute(
                    "UPDATE authority_owner_credentials_v1 SET credential_epoch=?,credential_id=?,"
                    "public_key=?,enrollment_operation_id=?,registration_json=? WHERE "
                    "authority_namespace=? AND installation_id=? AND principal_json=?",
                    (registration.credential_epoch, registration.credential_id,
                     registration.public_key, registration.enrollment_operation_id, encoded,
                     registration.authority_namespace, registration.installation_id, principal))
        return registration

    @staticmethod
    def _challenge(row: tuple, request: OwnerProofRequestV1) -> OwnerProofChallengeV1:
        return OwnerProofChallengeV1(request, row[7], row[8], row[9])

    @staticmethod
    def _row(db: sqlite3.Connection, operation_id: str) -> tuple | None:
        return db.execute(
            "SELECT operation_id,authority_namespace,installation_id,principal_json,request_json,"
            "credential_id,credential_epoch,nonce,issued_at_utc,expires_at_utc,"
            "signature,accepted_at_utc,receipt_json FROM authority_owner_proof_challenges_v1 "
            "WHERE operation_id=?", (operation_id,)).fetchone()

    def _current(self, db: sqlite3.Connection, request: OwnerProofRequestV1) -> bytes:
        self._scope(db, request.authority_id, request.authority_namespace)
        row = self._credential(db, request.authority_namespace,
                               request.installation_id, _principal(request.principal))
        if row is None or row[0:2] != (request.credential_epoch, request.credential_id):
            raise AuthorityUnavailable("Owner credential is not current")
        return row[2]

    def begin_challenge(self, *, transport_credential: object,
                        request: OwnerProofRequestV1,
                        operation: OwnerAuthorizationOperationV1,
                        ttl_seconds: int = 300) -> OwnerProofChallengeV1:
        if type(request) is not OwnerProofRequestV1:
            raise TypeError("Owner proof request is required")
        request.assert_matches_operation(operation)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ValueError("Owner challenge TTL must be 1..300 seconds")
        self._core._require(transport_credential, "owner_proof", request.authority_namespace)
        self._verify_session(transport_credential, request)
        now = self._now()
        with self._core._tx() as db:
            self._require_mode(db)
            self._current(db, request)
            prior = self._row(db, request.operation_id)
            if prior is not None:
                if prior[1:7] != (request.authority_namespace, request.installation_id,
                                 _principal(request.principal), _canonical(request),
                                 request.credential_id, request.credential_epoch):
                    raise AuthorityUnavailable("Owner challenge operation replay differs")
                challenge = self._challenge(prior, request)
                if prior[10] is None and now >= _time(challenge.expires_at_utc):
                    raise AuthorityUnavailable("Owner challenge expired; use a new operation")
                return challenge
            issued = _stamp(now)
            expires = _stamp(now + timedelta(seconds=ttl_seconds))
            challenge = OwnerProofChallengeV1(request, secrets.token_urlsafe(32), issued, expires)
            db.execute(
                "INSERT INTO authority_owner_proof_challenges_v1"
                "(operation_id,authority_namespace,installation_id,principal_json,request_json,"
                "credential_id,credential_epoch,nonce,issued_at_utc,expires_at_utc) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (request.operation_id, request.authority_namespace, request.installation_id,
                 _principal(request.principal), _canonical(request), request.credential_id,
                 request.credential_epoch, challenge.nonce, issued, expires))
            return challenge

    def accept_proof(self, *, transport_credential: object,
                     challenge: OwnerProofChallengeV1, signature: bytes) -> OwnerProofAcceptanceV1:
        if type(challenge) is not OwnerProofChallengeV1:
            raise TypeError("Owner challenge is required")
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("Ed25519 signature must contain 64 bytes")
        request = challenge.request
        self._core._require(transport_credential, "owner_proof", request.authority_namespace)
        self._verify_session(transport_credential, request)
        now = self._now()
        with self._core._tx() as db:
            self._require_mode(db)
            public_key = self._current(db, request)
            row = self._row(db, request.operation_id)
            if (row is None or row[1:7] != (request.authority_namespace,
                    request.installation_id, _principal(request.principal), _canonical(request),
                    request.credential_id, request.credential_epoch)
                    or self._challenge(row, request) != challenge):
                raise AuthorityUnavailable("Owner challenge binding differs")
            if row[10] is not None:
                if row[10] != signature or row[11] is None or row[12] is None:
                    raise AuthorityUnavailable("Owner proof replay differs")
                receipt = OwnerProofAcceptanceV1(
                    challenge, "sha256:" + hashlib.sha256(signature).hexdigest(), row[11])
                if row[12] != _canonical(receipt):
                    raise AuthorityUnavailable("stored Owner proof receipt differs")
                return receipt
            if now >= _time(challenge.expires_at_utc):
                raise AuthorityUnavailable("Owner challenge expired")
            _verify_signature(public_key, signature, challenge.signed_bytes(),
                              "Owner signature denied")
            receipt = OwnerProofAcceptanceV1(
                challenge, "sha256:" + hashlib.sha256(signature).hexdigest(), _stamp(now))
            db.execute(
                "UPDATE authority_owner_proof_challenges_v1 SET signature=?,accepted_at_utc=?,"
                "receipt_json=? WHERE operation_id=? AND signature IS NULL",
                (signature, receipt.accepted_at_utc, _canonical(receipt), request.operation_id))
            return receipt

    def get_current_acceptance(self, *, transport_credential: object,
                               request: OwnerProofRequestV1,
                               operation: OwnerAuthorizationOperationV1,
                               ) -> OwnerProofAcceptanceV1 | None:
        """Recover the exact accepted claim after login expiry while key epoch is current."""
        if type(request) is not OwnerProofRequestV1:
            raise TypeError("Owner proof request is required")
        request.assert_matches_operation(operation)
        self._core._require(transport_credential, "owner_proof", request.authority_namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            self._current(db, request)
            row = self._row(db, request.operation_id)
            if row is None:
                return None
            if row[4] != _canonical(request) or row[10] is None or row[11] is None:
                raise AuthorityUnavailable("Owner proof operation is not accepted")
            challenge = self._challenge(row, request)
            receipt = OwnerProofAcceptanceV1(
                challenge, "sha256:" + hashlib.sha256(row[10]).hexdigest(), row[11])
            if row[12] != _canonical(receipt):
                raise AuthorityUnavailable("stored Owner proof receipt differs")
            return receipt

    def get_accepted_for_operation(self, *, transport_credential: object,
                                   operation: OwnerAuthorizationOperationV1,
                                   ) -> OwnerProofAcceptanceV1 | None:
        """Recover only an Authority-stored proof bound to this exact operation."""
        if type(operation) is not OwnerAuthorizationOperationV1 or operation.action != "issue":
            raise TypeError("first Owner issue operation is required")
        namespace = namespace_ref(operation.namespace)
        self._core._require(transport_credential, "owner_proof", namespace)
        with self._core._tx() as db:
            self._require_mode(db)
            row = self._row(db, operation.operation_id)
            if row is None:
                return None
            raw = row[4]
            try:
                data = json.loads(raw)
                if type(data) is not dict or set(data) != {
                        "authority_id", "operation_id", "action", "authority_namespace",
                        "installation_id", "principal", "credential_id",
                        "credential_epoch", "authorization_request_digest",
                        "ticket_digest", "host_login_jwt_digest", "host_username",
                        "dashboard_origin", "schema"}:
                    raise ValueError("stored request fields differ")
                principal = data["principal"]
                if type(principal) is not dict or set(principal) != {
                        "identity_provider", "account_ref", "account_incarnation"}:
                    raise ValueError("stored principal fields differ")
                data["principal"] = OwnerPrincipalV1(**principal)
                request = OwnerProofRequestV1(**data)
                if _canonical(request) != raw:
                    raise ValueError("stored request is not canonical")
            except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                raise AuthorityUnavailable("stored Owner proof request differs") from exc
            request.assert_matches_operation(operation)
            public_key = self._current(db, request)
            if (row[1:7] != (request.authority_namespace, request.installation_id,
                              _principal(request.principal), raw,
                              request.credential_id, request.credential_epoch)
                    or row[10] is None or row[11] is None or row[12] is None):
                raise AuthorityUnavailable("Owner proof operation is not accepted")
            challenge = self._challenge(row, request)
            _verify_signature(public_key, row[10], challenge.signed_bytes(),
                              "stored Owner signature differs")
            receipt = OwnerProofAcceptanceV1(
                challenge, "sha256:" + hashlib.sha256(row[10]).hexdigest(), row[11])
            if row[12] != _canonical(receipt):
                raise AuthorityUnavailable("stored Owner proof receipt differs")
            return receipt


__all__ = (
    "AuthorityV2OwnerProofStore", "OwnerCredentialRegistrationV1",
    "OwnerProofAcceptanceV1", "OwnerProofChallengeV1", "OwnerProofRequestV1",
    "to_wire", "from_wire",
)
