"""Revocable, Authority-owned Owner login sessions.

The registered Owner Ed25519 key is the trust root. A host Dashboard JWT may be
recorded by a caller as provenance, but it is never an admission credential here.
Call ``require_current_in_tx`` inside the same ``core._tx()`` as the protected
Authority mutation, immediately before that mutation's final write.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
import secrets
import sqlite3
from typing import Callable
from urllib.parse import urlsplit

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_owner_contract import OwnerPrincipalV1
from .v2_owner_proof import _principal, _stamp, _time, _verify_signature


SCHEMA = "sylanne3.authority.owner-session.v1"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CHALLENGES = """CREATE TABLE authority_owner_login_challenges_v1 (
    nonce TEXT PRIMARY KEY,
    request_json BLOB NOT NULL,
    principal_epoch INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    consumed_at_utc TEXT
) STRICT"""
_SESSIONS = """CREATE TABLE authority_owner_sessions_v1 (
    verifier TEXT PRIMARY KEY,
    request_json BLOB NOT NULL,
    principal_epoch INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    revoked_at_utc TEXT
) STRICT"""
_PRINCIPALS = """CREATE TABLE authority_owner_session_principals_v1 (
    authority_namespace TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch >= 0),
    PRIMARY KEY(authority_namespace,installation_id,principal_json)
) STRICT"""
_REVOKED_KEYS = """CREATE TABLE authority_owner_session_revoked_keys_v1 (
    authority_namespace TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    credential_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    PRIMARY KEY(authority_namespace,installation_id,principal_json,credential_id,credential_epoch)
) STRICT"""
_TABLES = (
    ("authority_owner_login_challenges_v1", _CHALLENGES),
    ("authority_owner_sessions_v1", _SESSIONS),
    ("authority_owner_session_principals_v1", _PRINCIPALS),
    ("authority_owner_session_revoked_keys_v1", _REVOKED_KEYS),
)


def _canonical(value: object) -> bytes:
    return json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _verifier(token: str) -> str:
    if type(token) is not str or _TOKEN.fullmatch(token) is None:
        raise AuthorityUnavailable("invalid Owner session token")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class OwnerSessionLoginRequestV1:
    authority_id: str
    authority_namespace: str
    installation_id: str
    principal: OwnerPrincipalV1
    credential_id: str
    credential_epoch: int
    audience: str
    dashboard_origin: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown Owner session schema")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "credential_id", "audience"):
            identifier(getattr(self, name), name)
        _principal(self.principal)
        if type(self.credential_epoch) is not int or self.credential_epoch < 1:
            raise ValueError("Owner credential epoch must be positive")
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


@dataclass(frozen=True, slots=True)
class OwnerSessionLoginChallengeV1:
    request: OwnerSessionLoginRequestV1
    nonce: str
    principal_epoch: int
    boot_id: str
    issued_at_utc: str
    expires_at_utc: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.request) is not OwnerSessionLoginRequestV1:
            raise ValueError("unknown Owner login challenge schema")
        if type(self.nonce) is not str or _TOKEN.fullmatch(self.nonce) is None:
            raise ValueError("invalid Owner login nonce")
        if type(self.principal_epoch) is not int or self.principal_epoch < 0:
            raise ValueError("invalid Owner principal epoch")
        if type(self.boot_id) is not str or _TOKEN.fullmatch(self.boot_id) is None:
            raise ValueError("invalid Owner session boot identity")
        if _time(self.expires_at_utc) <= _time(self.issued_at_utc):
            raise ValueError("Owner login challenge expiry must follow issue time")

    def signed_bytes(self) -> bytes:
        return b"Sylanne3 Owner session login v1\n" + _canonical(self)


def to_wire(value: OwnerSessionLoginRequestV1 | OwnerSessionLoginChallengeV1) -> dict[str, object]:
    if type(value) is OwnerSessionLoginRequestV1:
        return {"kind": "owner_session_login_request_v1", **asdict(value)}
    if type(value) is OwnerSessionLoginChallengeV1:
        return {"kind": "owner_session_login_challenge_v1", "schema": SCHEMA,
                "request": to_wire(value.request), "nonce": value.nonce,
                "principal_epoch": value.principal_epoch, "boot_id": value.boot_id,
                "issued_at_utc": value.issued_at_utc,
                "expires_at_utc": value.expires_at_utc}
    raise TypeError("Owner session request or challenge is required")


def from_wire(raw: object) -> OwnerSessionLoginRequestV1 | OwnerSessionLoginChallengeV1:
    if type(raw) is not dict:
        raise TypeError("Owner session wire object is required")
    kind = raw.get("kind")
    if kind == "owner_session_login_request_v1":
        fields = set(OwnerSessionLoginRequestV1.__dataclass_fields__) | {"kind"}
        if set(raw) != fields or type(raw.get("principal")) is not dict:
            raise ValueError("Owner session request fields differ")
        principal_fields = set(OwnerPrincipalV1.__dataclass_fields__)
        if set(raw["principal"]) != principal_fields:
            raise ValueError("Owner principal fields differ")
        parts = {key: value for key, value in raw.items() if key != "kind"}
        parts["principal"] = OwnerPrincipalV1(**parts["principal"])
        value = OwnerSessionLoginRequestV1(**parts)
    elif kind == "owner_session_login_challenge_v1":
        fields = set(OwnerSessionLoginChallengeV1.__dataclass_fields__) | {"kind"}
        if set(raw) != fields:
            raise ValueError("Owner session challenge fields differ")
        request = from_wire(raw["request"])
        if type(request) is not OwnerSessionLoginRequestV1:
            raise ValueError("Owner session challenge request differs")
        value = OwnerSessionLoginChallengeV1(
            request, raw["nonce"], raw["principal_epoch"], raw["boot_id"],
            raw["issued_at_utc"], raw["expires_at_utc"], raw["schema"],
        )
    else:
        raise ValueError("unknown Owner session wire kind")
    if to_wire(value) != raw:
        raise ValueError("Owner session wire object is not canonical")
    return value


class AuthorityV2OwnerSessionStore:
    """One-use key login and revocable bearer sessions in independent Authority SQLite."""

    def __init__(self, core: AuthorityServiceCore, *,
                 utc_clock: Callable[[], datetime] | None = None,
                 create: bool = False) -> None:
        if type(core) is not AuthorityServiceCore:
            raise TypeError("Owner sessions need an independent Authority core")
        self._core = core
        self._utc_clock = utc_clock
        with core._tx() as db:
            self._require_mode(db)
            if db.execute("SELECT name FROM sqlite_master WHERE name='authority_owner_credentials_v1'").fetchone() is None:
                raise AuthorityUnavailable("registered Owner credential store is absent")
            present = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?,?,?)",
                tuple(name for name, _ in _TABLES),
            )}
            if not present and create:
                for _, ddl in _TABLES:
                    db.execute(ddl)
            elif present != {name for name, _ in _TABLES}:
                raise AuthorityUnavailable("Owner session schema is absent or partial")
            for name, ddl in _TABLES:
                if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (ddl,):
                    raise AuthorityUnavailable("Owner session schema differs")
            # One boot identity per live Core. A reopened Core rotates it and
            # makes old bearer tokens unusable even when the DB survives.
            boot_id = getattr(core, "_owner_session_boot_id", None)
            if boot_id is None:
                boot_id = secrets.token_urlsafe(32)
                db.execute("INSERT OR REPLACE INTO authority_meta(key,value) VALUES(?,?)",
                           ("owner_session_boot_id", boot_id))
                core._owner_session_boot_id = boot_id
            self._boot_id = boot_id

    @staticmethod
    def _require_mode(db: sqlite3.Connection) -> None:
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("Owner sessions require v2-only Authority")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def _now(self) -> datetime:
        if not callable(self._utc_clock):
            raise AuthorityUnavailable("trusted Owner session clock is unavailable")
        try:
            now = self._utc_clock()
        except Exception as exc:
            raise AuthorityUnavailable("trusted Owner session clock failed") from exc
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise AuthorityUnavailable("Owner session clock must provide UTC")
        return now

    def _current_key(self, db: sqlite3.Connection, request: OwnerSessionLoginRequestV1) -> bytes:
        self._require_mode(db)
        if self._core._id(db) != request.authority_id:
            raise AuthorityUnavailable("Owner session Authority identity differs")
        row = self._core._row(db, request.authority_namespace)
        if row[0] is None or row[1] < 1 or row[2] != "active" or row[3] is not None or row[9] != "clear":
            raise AuthorityUnavailable("Owner session namespace is not active")
        principal = _principal(request.principal)
        key = db.execute(
            "SELECT credential_id,credential_epoch,public_key FROM authority_owner_credentials_v1 "
            "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
            (request.authority_namespace, request.installation_id, principal),
        ).fetchone()
        if key is None or key[:2] != (request.credential_id, request.credential_epoch):
            raise AuthorityUnavailable("Owner credential is not current")
        if db.execute(
            "SELECT 1 FROM authority_owner_session_revoked_keys_v1 WHERE authority_namespace=? "
            "AND installation_id=? AND principal_json=? AND credential_id=? AND credential_epoch=?",
            (request.authority_namespace, request.installation_id, principal,
             request.credential_id, request.credential_epoch),
        ).fetchone() is not None:
            raise AuthorityUnavailable("Owner credential is revoked")
        return key[2]

    @staticmethod
    def _principal_epoch(db: sqlite3.Connection, request: OwnerSessionLoginRequestV1) -> int:
        row = db.execute(
            "SELECT revocation_epoch FROM authority_owner_session_principals_v1 "
            "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
            (request.authority_namespace, request.installation_id, _principal(request.principal)),
        ).fetchone()
        return row[0] if row is not None else 0

    def begin_login(self, *, transport_credential: object,
                    request: OwnerSessionLoginRequestV1,
                    ttl_seconds: int = 300) -> OwnerSessionLoginChallengeV1:
        if type(request) is not OwnerSessionLoginRequestV1:
            raise TypeError("Owner session login request is required")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ValueError("Owner login challenge TTL must be 1..300 seconds")
        self._core._require(transport_credential, "owner_session", request.authority_namespace)
        now = self._now()
        with self._core._tx() as db:
            self._current_key(db, request)
            challenge = OwnerSessionLoginChallengeV1(
                request, secrets.token_urlsafe(32), self._principal_epoch(db, request),
                self._boot_id, _stamp(now), _stamp(now + timedelta(seconds=ttl_seconds)),
            )
            db.execute("INSERT INTO authority_owner_login_challenges_v1 VALUES(?,?,?,?,?,?,NULL)",
                       (challenge.nonce, _canonical(request), challenge.principal_epoch,
                        challenge.boot_id, challenge.issued_at_utc, challenge.expires_at_utc))
        return challenge

    def accept_login(self, *, transport_credential: object,
                     challenge: OwnerSessionLoginChallengeV1,
                     signature: bytes, session_ttl_seconds: int = 3600) -> str:
        if type(challenge) is not OwnerSessionLoginChallengeV1:
            raise TypeError("Owner login challenge is required")
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("Ed25519 signature must contain 64 bytes")
        if type(session_ttl_seconds) is not int or not 1 <= session_ttl_seconds <= 86400:
            raise ValueError("Owner session TTL must be 1..86400 seconds")
        request = challenge.request
        self._core._require(transport_credential, "owner_session", request.authority_namespace)
        now = self._now()
        with self._core._tx() as db:
            public_key = self._current_key(db, request)
            row = db.execute(
                "SELECT request_json,principal_epoch,boot_id,issued_at_utc,expires_at_utc,consumed_at_utc "
                "FROM authority_owner_login_challenges_v1 WHERE nonce=?",
                (challenge.nonce,),
            ).fetchone()
            current_boot = db.execute(
                "SELECT value FROM authority_meta WHERE key='owner_session_boot_id'"
            ).fetchone()
            if (row != (_canonical(request), challenge.principal_epoch, challenge.boot_id,
                        challenge.issued_at_utc, challenge.expires_at_utc, None)
                    or challenge.principal_epoch != self._principal_epoch(db, request)
                    or challenge.boot_id != self._boot_id or current_boot != (self._boot_id,)):
                raise AuthorityUnavailable("Owner login challenge is absent or consumed")
            if now >= _time(challenge.expires_at_utc):
                raise AuthorityUnavailable("Owner login challenge expired")
            _verify_signature(public_key, signature, challenge.signed_bytes(),
                              "Owner login signature denied")
            token = secrets.token_urlsafe(32)
            db.execute("UPDATE authority_owner_login_challenges_v1 SET consumed_at_utc=? WHERE nonce=?",
                       (_stamp(now), challenge.nonce))
            db.execute("INSERT INTO authority_owner_sessions_v1 VALUES(?,?,?,?,?,?,NULL)",
                       (_verifier(token), _canonical(request), self._principal_epoch(db, request),
                        self._boot_id, _stamp(now),
                        _stamp(now + timedelta(seconds=session_ttl_seconds))))
        return token

    def require_current_in_tx(self, db: sqlite3.Connection, *, token: str,
                              request: OwnerSessionLoginRequestV1) -> OwnerSessionLoginRequestV1:
        """Final admission check inside caller's Authority write transaction.

        The caller must hold ``core._tx()`` through its protected write. This
        serializes the write with logout, revoke-all, key revocation and rotation.
        """
        if type(request) is not OwnerSessionLoginRequestV1:
            raise TypeError("Owner session login request is required")
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner session check needs current Authority transaction")
        now = self._now()
        self._current_key(db, request)
        row = db.execute(
            "SELECT request_json,principal_epoch,boot_id,expires_at_utc,revoked_at_utc "
            "FROM authority_owner_sessions_v1 WHERE verifier=?",
            (_verifier(token),),
        ).fetchone()
        current_boot = db.execute(
            "SELECT value FROM authority_meta WHERE key='owner_session_boot_id'"
        ).fetchone()
        if (row is None or row[0] != _canonical(request)
                or row[1] != self._principal_epoch(db, request)
                or row[2] != self._boot_id or current_boot != (self._boot_id,)
                or now >= _time(row[3]) or row[4] is not None):
            raise AuthorityUnavailable("Owner session is not current")
        return request

    def require_current(self, *, transport_credential: object, token: str,
                        request: OwnerSessionLoginRequestV1) -> OwnerSessionLoginRequestV1:
        self._core._require(transport_credential, "owner_session", request.authority_namespace)
        with self._core._tx() as db:
            return self.require_current_in_tx(db, token=token, request=request)

    def describe_current_in_tx(self, db: sqlite3.Connection, *, token: str,
                               namespace: str,
                               installation_id: str) -> OwnerSessionLoginRequestV1:
        """Resolve the persisted claim and recheck it in this Authority transaction."""
        identifier(namespace, "namespace")
        identifier(installation_id, "installation_id")
        if db is not self._core._db or not db.in_transaction:
            raise AuthorityUnavailable("Owner session description needs current Authority transaction")
        row = db.execute(
            "SELECT request_json FROM authority_owner_sessions_v1 WHERE verifier=?",
            (_verifier(token),),
        ).fetchone()
        if row is None:
            raise AuthorityUnavailable("Owner session is not current")
        try:
            stored = json.loads(row[0])
            if type(stored) is not dict:
                raise ValueError("stored request is not an object")
            request = from_wire({"kind": "owner_session_login_request_v1", **stored})
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise AuthorityUnavailable("stored Owner session request differs") from exc
        if (type(request) is not OwnerSessionLoginRequestV1
                or _canonical(request) != row[0]
                or request.authority_namespace != namespace
                or request.installation_id != installation_id):
            raise AuthorityUnavailable("Owner session description identity differs")
        return self.require_current_in_tx(db, token=token, request=request)

    def describe_current(self, *, transport_credential: object, token: str,
                         namespace: str,
                         installation_id: str) -> OwnerSessionLoginRequestV1:
        self._core._require(transport_credential, "owner_session", namespace)
        with self._core._tx() as db:
            return self.describe_current_in_tx(
                db, token=token, namespace=namespace,
                installation_id=installation_id)

    def logout(self, *, transport_credential: object, token: str,
               request: OwnerSessionLoginRequestV1) -> None:
        self._core._require(transport_credential, "owner_session", request.authority_namespace)
        with self._core._tx() as db:
            self.require_current_in_tx(db, token=token, request=request)
            db.execute("UPDATE authority_owner_sessions_v1 SET revoked_at_utc=? WHERE verifier=?",
                       (_stamp(self._now()), _verifier(token)))

    def revoke_all(self, *, transport_credential: object, token: str,
                   request: OwnerSessionLoginRequestV1) -> None:
        self._core._require(transport_credential, "owner_session_revoke", request.authority_namespace)
        with self._core._tx() as db:
            self.require_current_in_tx(db, token=token, request=request)
            db.execute(
                "INSERT INTO authority_owner_session_principals_v1 VALUES(?,?,?,1) "
                "ON CONFLICT(authority_namespace,installation_id,principal_json) "
                "DO UPDATE SET revocation_epoch=revocation_epoch+1",
                (request.authority_namespace, request.installation_id, _principal(request.principal)),
            )

    def revoke_credential(self, *, transport_credential: object, token: str,
                          request: OwnerSessionLoginRequestV1) -> None:
        self._core._require(transport_credential, "owner_session_revoke", request.authority_namespace)
        with self._core._tx() as db:
            self.require_current_in_tx(db, token=token, request=request)
            db.execute(
                "INSERT INTO authority_owner_session_revoked_keys_v1 VALUES(?,?,?,?,?)",
                (request.authority_namespace, request.installation_id, _principal(request.principal),
                 request.credential_id, request.credential_epoch),
            )


__all__ = (
    "AuthorityV2OwnerSessionStore", "OwnerSessionLoginChallengeV1",
    "OwnerSessionLoginRequestV1", "from_wire", "to_wire",
)
