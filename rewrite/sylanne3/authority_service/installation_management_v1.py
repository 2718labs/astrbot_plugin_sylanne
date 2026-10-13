"""Installation settings, finite Owner grants and safe audit projections.

This is an independent Authority service. The installed composition supplies
the installation/profile binding and OS administrator authorizer. Browser
claims never select an installation or create a grant. All protected work uses
the same Core transaction as current Owner admission, CAS and its receipt.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import uuid

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_owner_contract import OwnerPrincipalV1
from .v2_owner_proof import _principal
from .v2_owner_session import AuthorityV2OwnerSessionStore


REQUEST_SCHEMA = "sylanne.workbench-management.v1"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
PERMISSIONS = frozenset({"installation.logs.read", "installation.settings.read",
                         "installation.settings.enabled.write"})
EVENTS = {
    "management.initialized": ("INFO", "Installation management was initialized."),
    "management.granted": ("INFO", "Installation management access was granted."),
    "management.revoked": ("WARNING", "Installation management access was revoked."),
    "settings.enabled.updated": ("INFO", "Installation enabled setting was updated; restart required."),
    "management.logs.retained": ("INFO", "Installation management log retention was applied."),
}
TABLES = {
    "authority_installation_management_v1": """CREATE TABLE authority_installation_management_v1 (
    installation_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    authority_profile TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    revision TEXT NOT NULL,
    access_epoch INTEGER NOT NULL CHECK(access_epoch >= 1),
    retention_epoch INTEGER NOT NULL CHECK(retention_epoch >= 1),
    cursor_key BLOB NOT NULL,
    retained_after_utc TEXT
) STRICT""",
    "authority_installation_management_grants_v1": """CREATE TABLE authority_installation_management_grants_v1 (
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    credential_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    permissions_json TEXT NOT NULL,
    valid_until_utc TEXT NOT NULL,
    PRIMARY KEY(installation_id,principal_json),
    FOREIGN KEY(installation_id) REFERENCES authority_installation_management_v1(installation_id)
) STRICT""",
    "authority_installation_management_events_v1": """CREATE TABLE authority_installation_management_events_v1 (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at_utc TEXT NOT NULL,
    event_code TEXT NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES authority_installation_management_v1(installation_id)
) STRICT""",
    "authority_installation_management_receipts_v1": """CREATE TABLE authority_installation_management_receipts_v1 (
    installation_id TEXT NOT NULL,
    principal_json BLOB NOT NULL,
    operation_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY(installation_id,principal_json,operation_id),
    FOREIGN KEY(installation_id) REFERENCES authority_installation_management_v1(installation_id)
) STRICT""",
}
TRIGGERS = {
    "authority_installation_management_events_v1_no_update": """CREATE TRIGGER authority_installation_management_events_v1_no_update
BEFORE UPDATE ON authority_installation_management_events_v1
BEGIN SELECT RAISE(ABORT,'append-only'); END""",
    "authority_installation_management_events_v1_no_delete": """CREATE TRIGGER authority_installation_management_events_v1_no_delete
BEFORE DELETE ON authority_installation_management_events_v1
BEGIN SELECT RAISE(ABORT,'append-only'); END""",
}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _text(value, maximum, *, empty=False):
    return (type(value) is str and (0 if empty else 1) <= len(value) <= maximum
            and not any(0xD800 <= ord(char) <= 0xDFFF for char in value))


class ManagementProblem(Exception):
    """A fixed, safe public error; arbitrary server exception text is excluded."""
    def __init__(self, code, status, *, fields=None):
        super().__init__(code)
        self.code, self.status, self.fields = code, status, fields

    def json(self):
        problem = {"code": self.code, "retryable": self.status in {429, 503}}
        if self.fields is not None:
            problem["fields"] = self.fields
        return {"schema_version": "sylanne.workbench-error.v1", "problem": problem}


class InstallationManagementServiceV1:
    def __init__(self, core, owner_sessions, *, namespace, installation_id,
                 authority_profile, utc_clock, administrator_authorizer):
        if (type(core) is not AuthorityServiceCore
                or type(owner_sessions) is not AuthorityV2OwnerSessionStore
                or owner_sessions._core is not core
                or not callable(utc_clock) or not callable(administrator_authorizer)):
            raise AuthorityUnavailable("installed management composition is required")
        identifier(namespace, "namespace")
        identifier(installation_id, "installation_id")
        identifier(authority_profile, "authority_profile")
        if not _text(installation_id, 128) or not _text(authority_profile, 64):
            raise ValueError("installation management binding exceeds contract")
        self.core, self.owner_sessions = core, owner_sessions
        self.namespace, self.installation_id = namespace, installation_id
        self.authority_profile = authority_profile
        self._clock, self._administrator_authorizer = utc_clock, administrator_authorizer

    def _now(self):
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise AuthorityUnavailable("installation management requires trusted UTC")
        return now

    def _admin(self, credential, action):
        if self._administrator_authorizer(credential, action, self.namespace, None) is not True:
            raise AuthorityUnavailable("installation management administrator denied")

    def _state(self, db):
        AuthorityV2OwnerSessionStore._require_mode(db)
        row = db.execute("SELECT namespace,authority_profile,enabled,revision,access_epoch,"
                         "retention_epoch,cursor_key,retained_after_utc FROM authority_installation_management_v1 "
                         "WHERE installation_id=?", (self.installation_id,)).fetchone()
        if row is None or row[:2] != (self.namespace, self.authority_profile):
            raise AuthorityUnavailable("installation management binding is absent or differs")
        namespace = self.core._row(db, self.namespace)
        if namespace[0] is None or namespace[2:4] != ("active", None) or namespace[9] != "clear":
            raise AuthorityUnavailable("installation management namespace is not active")
        return row, namespace

    def initialize(self, credential, initial_enabled):
        """Explicit installer seed, once. Never treat a schema default as a read."""
        if type(initial_enabled) is not bool:
            raise ValueError("initial_enabled must be boolean")
        self._admin(credential, "installation_management_install")
        with self.core._tx() as db:
            AuthorityV2OwnerSessionStore._require_mode(db)
            self.core._row(db, self.namespace)
            schema = {**TABLES, **TRIGGERS}
            present = {name: db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
                       for name in schema}
            if any(present.values()) and not all(present.values()):
                raise AuthorityUnavailable("installation management schema is partial")
            for name, ddl in schema.items():
                if present[name] is None:
                    db.execute(ddl)
                elif present[name] != (ddl,):
                    raise AuthorityUnavailable("installation management schema differs")
            if db.execute("SELECT 1 FROM authority_installation_management_v1 WHERE installation_id=?",
                          (self.installation_id,)).fetchone():
                raise AuthorityUnavailable("installation management seed already exists")
            db.execute("INSERT INTO authority_installation_management_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                       (self.installation_id, self.namespace, self.authority_profile,
                        int(initial_enabled), str(uuid.uuid4()), 1, 1, secrets.token_bytes(32), None))
            self._state(db)
            self._event(db, "management.initialized")

    def grant_management(self, credential, principal, permissions, valid_until):
        """Finite installation grant pinned to the actual registered Owner key."""
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("Owner principal is required")
        if (type(permissions) not in {list, tuple, frozenset, set}
                or not permissions or any(type(p) is not str for p in permissions)
                or len(set(permissions)) != len(permissions) or not set(permissions) <= PERMISSIONS
                or ("installation.settings.enabled.write" in permissions
                    and "installation.settings.read" not in permissions)):
            raise ValueError("finite management permissions differ")
        if (type(valid_until) is not datetime or valid_until.tzinfo is None
                or valid_until.utcoffset() != timedelta(0) or valid_until <= self._now()):
            raise ValueError("management grant needs a future UTC expiry")
        self._admin(credential, "installation_management_grant")
        with self.core._tx() as db:
            self._state(db)
            identity = _principal(principal)
            key = db.execute("SELECT credential_id,credential_epoch FROM authority_owner_credentials_v1 "
                             "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
                             (self.namespace, self.installation_id, identity)).fetchone()
            if key is None or db.execute(
                    "SELECT 1 FROM authority_owner_session_revoked_keys_v1 WHERE authority_namespace=? "
                    "AND installation_id=? AND principal_json=? AND credential_id=? AND credential_epoch=?",
                    (self.namespace, self.installation_id, identity, *key)).fetchone():
                raise AuthorityUnavailable("management grant needs a current registered Owner key")
            db.execute("INSERT INTO authority_installation_management_grants_v1 VALUES(?,?,?,?,?,?) "
                       "ON CONFLICT(installation_id,principal_json) DO UPDATE SET "
                       "credential_id=excluded.credential_id,credential_epoch=excluded.credential_epoch,"
                       "permissions_json=excluded.permissions_json,valid_until_utc=excluded.valid_until_utc",
                       (self.installation_id, identity, *key, _json(sorted(permissions)), _stamp(valid_until)))
            db.execute("UPDATE authority_installation_management_v1 SET access_epoch=access_epoch+1 "
                       "WHERE installation_id=?", (self.installation_id,))
            self._event(db, "management.granted")

    def revoke_management(self, credential, principal):
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("Owner principal is required")
        self._admin(credential, "installation_management_revoke")
        with self.core._tx() as db:
            self._state(db)
            db.execute("DELETE FROM authority_installation_management_grants_v1 "
                       "WHERE installation_id=? AND principal_json=?",
                       (self.installation_id, _principal(principal)))
            db.execute("UPDATE authority_installation_management_v1 SET access_epoch=access_epoch+1 "
                       "WHERE installation_id=?", (self.installation_id,))
            self._event(db, "management.revoked")

    def startup_settings(self, credential):
        """Host startup admission; never uses a browser's management grant."""
        self.core._require(credential, "installation_management_startup", self.namespace)
        with self.core._tx() as db:
            state, _ = self._state(db)
            return {"installation_id": self.installation_id, "enabled": bool(state[2]),
                    "authority_profile": state[1], "revision": state[3]}

    def retain_logs(self, credential, before):
        """Advance the visible retention boundary; audit rows stay append-only.

        This local administrator action invalidates snapshots and narrows the
        safe projection. It does not erase historical Authority evidence.
        """
        if (type(before) is not datetime or before.tzinfo is None
                or before.utcoffset() != timedelta(0) or before > self._now()):
            raise ValueError("retention needs an elapsed UTC boundary")
        self._admin(credential, "installation_management_install")
        with self.core._tx() as db:
            state, _ = self._state(db)
            if state[7] is not None and _stamp(before) < state[7]:
                raise ValueError("retention boundary cannot move backwards")
            db.execute("UPDATE authority_installation_management_v1 SET retention_epoch=retention_epoch+1,"
                       "retained_after_utc=? WHERE installation_id=?", (_stamp(before), self.installation_id))
            self._event(db, "management.logs.retained")

    def _event(self, db, code):
        if code not in EVENTS:
            raise ValueError("unknown safe management event")
        db.execute("INSERT INTO authority_installation_management_events_v1 "
                   "(installation_id,event_id,occurred_at_utc,event_code) VALUES(?,?,?,?)",
                   (self.installation_id, str(uuid.uuid4()), _stamp(self._now()), code))

    @staticmethod
    def _request(operation, payload):
        fields = {"schema_version", "operation_id"}
        if operation != "capabilities":
            fields |= {"installation_id", "access_generation"}
        if operation == "logs/query":
            fields |= {"filter", "cursor", "limit"}
        elif operation == "settings/update":
            fields |= {"expected_revision", "patch"}
        elif operation not in {"capabilities", "settings/read"}:
            raise ManagementProblem("unsupported_operation", 404)
        if type(payload) is not dict or set(payload) != fields:
            raise ManagementProblem("invalid_request", 400)
        try:
            size = len(_json(payload).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError):
            raise ManagementProblem("invalid_request", 400) from None
        if size > MAX_REQUEST_BYTES:
            raise ManagementProblem("request_too_large", 413)
        if payload["schema_version"] != REQUEST_SCHEMA:
            raise ManagementProblem("unsupported_schema", 400)
        try:
            operation_id = uuid.UUID(payload["operation_id"])
            if operation_id.version != 4 or str(operation_id) != payload["operation_id"]:
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ManagementProblem("invalid_request", 400) from None
        if operation != "capabilities" and (
                not _text(payload["installation_id"], 128)
                or type(payload["access_generation"]) is not int
                or not 1 <= payload["access_generation"] <= 2**53 - 1):
            raise ManagementProblem("invalid_request", 400)
        if operation == "logs/query":
            filt = payload["filter"]
            if (type(filt) is not dict or set(filt) != {"level", "query"}
                    or type(filt["level"]) is not str
                    or filt["level"] not in {"ALL", "INFO", "WARNING", "ERROR"}
                    or not _text(filt["query"], 128, empty=True)
                    or type(payload["limit"]) is not int or payload["limit"] != 50
                    or (payload["cursor"] is not None and not _text(payload["cursor"], 2048))):
                raise ManagementProblem("invalid_request", 400)
        if operation == "settings/update":
            if not _text(payload["expected_revision"], 128):
                raise ManagementProblem("invalid_request", 400)
            patch = payload["patch"]
            if type(patch) is not dict or set(patch) != {"enabled"}:
                raise ManagementProblem("invalid_request", 400)
            if type(patch["enabled"]) is not bool:
                raise ManagementProblem("validation_failed", 422, fields=["enabled"])

    def _access(self, db, request, state):
        grant = db.execute("SELECT credential_id,credential_epoch,permissions_json,valid_until_utc "
                           "FROM authority_installation_management_grants_v1 "
                           "WHERE installation_id=? AND principal_json=?",
                           (self.installation_id, _principal(request.principal))).fetchone()
        expired = grant is not None and self._now() >= _time(grant[3])
        generation = state[4]
        if expired:
            # The service retires this finite grant exactly once, under the
            # same transaction as current Owner admission. No audit event is
            # fabricated by a read, and subsequent reads leave the epoch alone.
            db.execute("DELETE FROM authority_installation_management_grants_v1 "
                       "WHERE installation_id=? AND principal_json=?",
                       (self.installation_id, _principal(request.principal)))
            db.execute("UPDATE authority_installation_management_v1 SET access_epoch=access_epoch+1 "
                       "WHERE installation_id=?", (self.installation_id,))
            generation = db.execute("SELECT access_epoch FROM authority_installation_management_v1 "
                                    "WHERE installation_id=?", (self.installation_id,)).fetchone()[0]
        active = (grant is not None and not expired
                  and grant[:2] == (request.credential_id, request.credential_epoch))
        permissions = frozenset(json.loads(grant[2])) if active else frozenset()
        return permissions, generation, expired

    @staticmethod
    def _settings_capability(permissions):
        available = "installation.settings.read" in permissions
        writable = available and "installation.settings.enabled.write" in permissions
        return {"available": available, "reason_code": "available" if available else "permission_missing",
                "writable_fields": ["enabled"] if writable else [],
                "apply_semantics": "next_restart" if writable else "read_only"}

    def handle(self, credential, owner_token, operation, payload):
        self._request(operation, payload)
        self.core._require(credential, "installation_management", self.namespace)
        with self.core._tx() as db:
            try:
                request = self.owner_sessions.describe_current_in_tx(
                    db, token=owner_token, namespace=self.namespace, installation_id=self.installation_id)
            except AuthorityUnavailable:
                raise ManagementProblem("owner_session_invalid", 401) from None
            state, _ = self._state(db)
            permissions, generation, expired = self._access(db, request, state)
            try:
                result = self._response_in_tx(db, request, owner_token, state,
                                             permissions, generation, operation, payload)
            except ManagementProblem as problem:
                if not expired:
                    raise
                # An expired grant has no permissions, so no business write can
                # occur. Commit its retirement even when an old-generation call
                # must receive 409; raising inside Core._tx would roll it back.
                result = problem
        if isinstance(result, ManagementProblem):
            raise result
        return result

    def _response_in_tx(self, db, request, owner_token, state, permissions,
                        generation, operation, payload):
        if operation != "capabilities":
            if payload["installation_id"] != self.installation_id:
                raise ManagementProblem("installation_mismatch", 403)
            if payload["access_generation"] != generation:
                raise ManagementProblem("capabilities_changed", 409)
        settings = self._settings_capability(permissions)
        if operation == "capabilities":
            available = "installation.logs.read" in permissions
            result = {"schema_version": "sylanne.workbench-capabilities.v1",
                      "installation_id": self.installation_id, "access_generation": generation,
                      "capabilities": {"logs": {"available": available,
                          "reason_code": "available" if available else "permission_missing",
                          "max_page_size": 50, "redaction": "server_allowlist.v1"}, "settings": settings}}
        elif operation == "logs/query":
            self._permission(permissions, "installation.logs.read")
            result = self._logs(db, request, state, generation, payload)
        elif operation == "settings/read":
            self._permission(permissions, "installation.settings.read")
            result = {"schema_version": "sylanne.workbench-settings.v1",
                      "installation_id": self.installation_id, "access_generation": generation,
                      "revision": state[3], "values": {"enabled": bool(state[2]), "authority_profile": state[1]},
                      "writable_fields": settings["writable_fields"], "apply_semantics": settings["apply_semantics"]}
        else:
            self._permission(permissions, "installation.settings.enabled.write")
            result = self._update(db, request, owner_token, state, generation, payload)
        if len(_json(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
            raise ManagementProblem("response_too_large", 503)
        return {"http_status": 200, "json": result}

    @staticmethod
    def _permission(permissions, permission):
        if permission not in permissions:
            # A valid Owner lacking this capability remains logged in.
            raise ManagementProblem("capability_unavailable", 409)

    def _update(self, db, request, owner_token, state, generation, payload):
        principal = _principal(request.principal)
        digest = hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()
        previous = db.execute("SELECT payload_digest,receipt_json "
                              "FROM authority_installation_management_receipts_v1 "
                              "WHERE installation_id=? AND principal_json=? AND operation_id=?",
                              (self.installation_id, principal, payload["operation_id"])).fetchone()
        if previous:
            if previous[0] != digest:
                raise ManagementProblem("operation_conflict", 409)
            return json.loads(previous[1])
        if payload["expected_revision"] != state[3]:
            raise ManagementProblem("revision_conflict", 409)
        try:
            self.owner_sessions.require_current_in_tx(db, token=owner_token, request=request)
        except AuthorityUnavailable:
            raise ManagementProblem("owner_session_invalid", 401) from None
        revision = str(uuid.uuid4())
        changed = db.execute("UPDATE authority_installation_management_v1 SET enabled=?,revision=? "
                             "WHERE installation_id=? AND revision=?",
                             (int(payload["patch"]["enabled"]), revision, self.installation_id, state[3]))
        if changed.rowcount != 1:
            raise ManagementProblem("revision_conflict", 409)
        receipt = {"schema_version": "sylanne.workbench-settings-receipt.v1",
                   "installation_id": self.installation_id, "access_generation": generation,
                   "operation_id": payload["operation_id"], "revision": revision, "applied": "next_restart"}
        db.execute("INSERT INTO authority_installation_management_receipts_v1 VALUES(?,?,?,?,?)",
                   (self.installation_id, principal, payload["operation_id"], digest, _json(receipt)))
        self._event(db, "settings.enabled.updated")
        return receipt

    def _cursor(self, data, key):
        encoded = base64.urlsafe_b64encode(_json(data).encode()).rstrip(b"=")
        signature = hmac.new(key, encoded, hashlib.sha256).digest()
        return (encoded + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode("ascii")

    def _decode_cursor(self, cursor, key):
        try:
            encoded, signed = cursor.encode("ascii").split(b".")
            signature = base64.urlsafe_b64decode(signed + b"=" * (-len(signed) % 4))
            if not hmac.compare_digest(signature, hmac.new(key, encoded, hashlib.sha256).digest()):
                raise ValueError
            data = json.loads(base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4)))
            if type(data) is not dict or set(data) != {"i", "p", "g", "f", "s", "h", "e", "r", "a"}:
                raise ValueError
            if self._cursor(data, key) != cursor:
                raise ValueError
            return data
        except (ValueError, TypeError, UnicodeError):
            raise ManagementProblem("invalid_cursor", 400) from None

    def _logs(self, db, request, state, generation, payload):
        filt = payload["filter"]
        binding = {"i": hashlib.sha256(self.installation_id.encode()).hexdigest(),
                   "p": hashlib.sha256(_principal(request.principal)).hexdigest(),
                   "g": generation, "f": hashlib.sha256(_json(filt).encode()).hexdigest()}
        now = self._now()
        if payload["cursor"] is None:
            highwater = db.execute("SELECT COALESCE(MAX(seq),0) FROM authority_installation_management_events_v1 "
                                   "WHERE installation_id=?", (self.installation_id,)).fetchone()[0]
            snapshot = {**binding, "s": str(uuid.uuid4()), "h": highwater,
                        "e": _stamp(now + timedelta(minutes=10)), "r": state[5], "a": None}
        else:
            snapshot = self._decode_cursor(payload["cursor"], state[6])
            if any(snapshot[k] != value for k, value in binding.items()) or snapshot["r"] != state[5]:
                raise ManagementProblem("snapshot_changed", 409)
            if now >= _time(snapshot["e"]):
                raise ManagementProblem("cursor_expired", 410)
        codes = [code for code, (level, summary) in EVENTS.items()
                 if (filt["level"] == "ALL" or filt["level"] == level)
                 and (not filt["query"] or filt["query"].casefold() in (code + " " + summary).casefold())]
        entries = []
        more = False
        if codes:
            sql = ("SELECT event_id,occurred_at_utc,event_code FROM authority_installation_management_events_v1 "
                   "WHERE installation_id=? AND seq<=? AND event_code IN (" + ",".join("?" for _ in codes) + ")")
            args = [self.installation_id, snapshot["h"], *codes]
            if state[7] is not None:
                sql += " AND occurred_at_utc>=?"
                args.append(state[7])
            if snapshot["a"] is not None:
                sql += " AND (occurred_at_utc,event_id)<(?,?)"
                args += snapshot["a"]
            rows = db.execute(sql + " ORDER BY occurred_at_utc DESC,event_id DESC LIMIT 51", args).fetchall()
            more = len(rows) > 50
            for event_id, occurred, code in rows[:50]:
                level, summary = EVENTS[code]
                entries.append({"event_id": event_id, "occurred_at": occurred, "level": level,
                                "event_code": code, "summary": summary, "redacted": True})
        next_cursor = None
        if more:
            last = entries[-1]
            snapshot["a"] = [last["occurred_at"], last["event_id"]]
            next_cursor = self._cursor(snapshot, state[6])
        return {"schema_version": "sylanne.workbench-logs.v1", "installation_id": self.installation_id,
                "access_generation": generation, "entries": entries, "next_cursor": next_cursor,
                "snapshot_id": snapshot["s"], "redaction": "server_allowlist.v1"}
