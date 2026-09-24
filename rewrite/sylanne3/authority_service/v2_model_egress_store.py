"""Authority-local passive egress ledger; never executes or authorizes a send."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
import sqlite3
import threading

from .contract import AuthorityUnavailable, identifier
from .v2_contract import FencePermitV2
from ..runtime_contracts import canonical_digest, canonical_serialize
from .v2_model_egress_contract import (
    ModelEgressIntentV1, ModelEgressObservationV1, ModelEgressRecoveryV1,
)


_DDL = """CREATE TABLE authority_model_egress_v1(
    call_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, subject TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','dispatch_started','observed','unknown')),
    observation_digest TEXT,
    CHECK((state IN ('prepared','dispatch_started') AND observation_digest IS NULL)
       OR (state IN ('observed','unknown') AND observation_digest IS NOT NULL))
)"""
_JOB_INDEX_DDL = "CREATE UNIQUE INDEX authority_model_egress_one_job ON authority_model_egress_v1(namespace,json_extract(identity_json,'$.job_id'))"
_BINDING_DDL = """CREATE TABLE authority_model_egress_bindings_v1(
    call_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL UNIQUE,
    FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id)
)"""
_OBSERVATION_DDL = """CREATE TABLE authority_model_egress_observations_v1(
    call_id TEXT PRIMARY KEY, observation_json TEXT NOT NULL,
    observation_digest TEXT NOT NULL,
    FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id)
)"""


def _encoded(intent: ModelEgressIntentV1) -> str:
    return json.dumps(asdict(intent), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _decoded(value: str) -> ModelEgressIntentV1:
    data = json.loads(value)
    if type(data) is not dict or set(data) != set(ModelEgressIntentV1.__dataclass_fields__):
        raise ValueError("egress identity fields changed")
    data["source_refs"] = tuple(data["source_refs"])
    data["source_revisions"] = tuple(tuple(item) for item in data["source_revisions"])
    data["access_revisions"] = tuple(tuple(item) for item in data["access_revisions"])
    data["budget_ceiling"] = tuple(tuple(item) for item in data["budget_ceiling"])
    result = ModelEgressIntentV1(**data)
    if _encoded(result) != value:
        raise ValueError("noncanonical egress identity")
    return result


class AuthorityV2ModelEgressStore:
    """Transactionally records identity and a one-way send marker.

    `record_dispatch_started` is an internal persistence primitive for a future
    executor. It must be called only after independent current graph and fence
    checks. No production service currently exposes that executor.
    """

    def __init__(self, connection: sqlite3.Connection, *, create: bool = False,
                 lock: threading.RLock | None = None):
        if type(connection) is not sqlite3.Connection or connection.isolation_level is not None:
            raise AuthorityUnavailable("model egress needs an autocommit Authority SQLite connection")
        path = connection.execute("PRAGMA database_list").fetchone()[2]
        synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if not path or synchronous < 2 or journal.lower() in {"off", "memory"}:
            raise AuthorityUnavailable("model egress requires durable Authority SQLite settings")
        self._db = connection
        self._lock = lock if lock is not None else threading.RLock()
        with self._tx() as db:
            existing = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'"
            ).fetchone()
            if existing is None:
                if not create:
                    raise AuthorityUnavailable("model egress schema is absent")
                db.execute(_DDL)
            elif existing != (_DDL,):
                raise AuthorityUnavailable("unknown model egress schema")
            index = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='authority_model_egress_one_job'"
            ).fetchone()
            if index is None:
                # The original ledger had no job key. An ambiguous history must
                # fail migration rather than permit a second call after restart.
                for (raw,) in db.execute("SELECT identity_json FROM authority_model_egress_v1"):
                    _decoded(raw)
                db.execute(_JOB_INDEX_DDL)
            elif index != (_JOB_INDEX_DDL,):
                raise AuthorityUnavailable("unknown model egress job index")
            binding = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_egress_bindings_v1'"
            ).fetchone()
            if binding is None:
                db.execute(_BINDING_DDL)
            elif binding != (_BINDING_DDL,):
                raise AuthorityUnavailable("unknown model egress binding schema")
            observation = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_egress_observations_v1'"
            ).fetchone()
            if observation is None:
                # Older digest-only observations cannot be recovered safely.
                if db.execute("SELECT 1 FROM authority_model_egress_v1 WHERE state='observed' LIMIT 1").fetchone():
                    raise AuthorityUnavailable("legacy digest-only observation cannot be migrated")
                db.execute(_OBSERVATION_DDL)
            elif observation != (_OBSERVATION_DDL,):
                raise AuthorityUnavailable("unknown model egress observation schema")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db.in_transaction:
                raise AuthorityUnavailable("model egress connection already has a transaction")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield self._db
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("model egress SQLite transaction failed") from exc

    @staticmethod
    def _read(db, call_id: str) -> ModelEgressRecoveryV1 | None:
        row = db.execute(
            "SELECT call_id,operation_id,namespace,subject,identity_json,state,observation_digest "
            "FROM authority_model_egress_v1 WHERE call_id=?", (call_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            intent = _decoded(row[4])
            if row[:4] != (intent.call_id, intent.operation_id, intent.namespace, intent.subject):
                raise ValueError("persisted egress identity mismatch")
            observation_row = db.execute(
                "SELECT observation_json,observation_digest FROM authority_model_egress_observations_v1 WHERE call_id=?",
                (call_id,),
            ).fetchone()
            observation = None
            if observation_row is not None:
                data = json.loads(observation_row[0])
                if (type(data) is not dict
                        or set(data) != set(ModelEgressObservationV1.__dataclass_fields__)
                        or canonical_serialize(data) != observation_row[0]):
                    raise ValueError("noncanonical observation")
                data["usage"] = tuple(tuple(item) for item in data["usage"])
                data["cost"] = tuple(tuple(item) for item in data["cost"])
                observation = ModelEgressObservationV1(**data)
                if observation.digest != observation_row[1]:
                    raise ValueError("observation digest mismatch")
            if row[5] == "observed" and observation is None:
                raise ValueError("observed result body missing")
            if observation is not None and row[5] not in {"observed", "unknown"}:
                raise ValueError("unobserved egress has result body")
            return ModelEgressRecoveryV1(intent, row[5], row[6], observation)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted model egress record is invalid") from exc

    def prepare(self, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        if type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("typed model egress intent required")
        with self._tx() as db:
            return self.prepare_locked(db, intent)

    def prepare_locked(self, db: sqlite3.Connection,
                       intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        """Persist one call per job inside an Authority-owned immediate transaction."""
        if type(intent) is not ModelEgressIntentV1 or db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("typed model egress intent and Authority transaction required")
        old = self._read(db, intent.call_id)
        if old is not None:
            if old.intent != intent:
                raise AuthorityUnavailable("model call ID reused with different identity")
            return old
        row = db.execute(
            "SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? AND json_extract(identity_json,'$.job_id')=?",
            (intent.namespace, intent.job_id),
        ).fetchone()
        if row is not None:
            raise AuthorityUnavailable("model job already has a call identity")
        db.execute(
            "INSERT INTO authority_model_egress_v1 "
            "(call_id,operation_id,namespace,subject,identity_json,state) "
            "VALUES(?,?,?,?,?,'prepared')",
            (intent.call_id, intent.operation_id, intent.namespace,
             intent.subject, _encoded(intent)),
        )
        return ModelEgressRecoveryV1(intent, "prepared")

    def read_locked(self, db: sqlite3.Connection, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        if type(intent) is not ModelEgressIntentV1 or db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("typed model egress identity and Authority transaction required")
        record = self._read(db, intent.call_id)
        if record is None or record.intent != intent:
            raise AuthorityUnavailable("model egress identity changed or absent")
        return record

    @staticmethod
    def is_fence_bound_locked(db: sqlite3.Connection,
                              intent: ModelEgressIntentV1) -> bool:
        return db.execute(
            "SELECT operation_id,token FROM authority_model_egress_bindings_v1 WHERE call_id=?",
            (intent.call_id,),
        ).fetchone() == (intent.operation_id, intent.fence_token)

    def bind_fence_locked(self, db: sqlite3.Connection,
                          intent: ModelEgressIntentV1) -> None:
        self.read_locked(db, intent)
        if self.is_fence_bound_locked(db, intent):
            raise AuthorityUnavailable("model fence binding already exists")
        db.execute(
            "INSERT INTO authority_model_egress_bindings_v1(call_id,operation_id,token) "
            "VALUES(?,?,?)", (intent.call_id, intent.operation_id, intent.fence_token))

    def read(self, call_id: str, *, subject: str, namespace: str) -> ModelEgressRecoveryV1:
        identifier(call_id, "call_id")
        identifier(subject, "subject")
        identifier(namespace, "namespace")
        with self._tx() as db:
            record = self._read(db, call_id)
            if record is None or (record.intent.subject, record.intent.namespace) != (subject, namespace):
                raise AuthorityUnavailable("model egress unavailable for subject or namespace")
            return record

    def _transition(self, intent: ModelEgressIntentV1, state: str,
                    observation_digest: str | None = None) -> ModelEgressRecoveryV1:
        if state in {"observed", "unknown"}:
            raise AuthorityUnavailable("digest-only provider observation is forbidden")
        target = ModelEgressRecoveryV1(intent, state, observation_digest)
        with self._tx() as db:
            self._transition_locked(db, target)
        return target

    def _transition_locked(self, db: sqlite3.Connection,
                           target: ModelEgressRecoveryV1) -> None:
        intent = target.intent
        old = self.read_locked(db, intent)
        expected = "prepared" if target.state == "dispatch_started" else "dispatch_started"
        if old.state != expected:
            raise AuthorityUnavailable("model egress transition cannot repeat or reverse")
        updated = db.execute(
            "UPDATE authority_model_egress_v1 SET state=?,observation_digest=? "
            "WHERE call_id=? AND state=? AND identity_json=?",
            (target.state, target.observation_digest, intent.call_id,
             expected, _encoded(intent)),
        )
        if updated.rowcount != 1:
            raise AuthorityUnavailable("model egress transition lost its exact identity")

    def _record_dispatch_started_fenced_locked(self, db: sqlite3.Connection,
                                                intent: ModelEgressIntentV1,
                                                permit: FencePermitV2, fences,
                                                current_anchor) -> ModelEgressRecoveryV1:
        """Future executor primitive: exact live fence and single durable CAS.

        The service must first verify the complete graph request and executable
        provider limit. This primitive alone never grants a provider send.
        """
        if (type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2
                or permit.operation != "model_egress"
                or (permit.operation_id, permit.subject, permit.namespace,
                    permit.authority_id, permit.generation, permit.token,
                    permit.fence_epoch, permit.revision,
                    canonical_digest(asdict(permit.pinned_anchor))) !=
                   (intent.operation_id, intent.subject, intent.namespace,
                    intent.authority_id, intent.authority_activation_generation,
                    intent.fence_token, intent.fence_epoch, intent.fence_revision,
                    intent.anchor_digest)):
            raise AuthorityUnavailable("typed model fence and call identity mismatch")
        fences.validate_fence_locked(
            db, permit, subject=intent.subject, current_anchor=current_anchor)
        if not self.is_fence_bound_locked(db, intent):
            raise AuthorityUnavailable("model fence was not atomically bound")
        target = ModelEgressRecoveryV1(intent, "dispatch_started")
        self._transition_locked(db, target)
        return target

    def record_dispatch_started(self, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        """Commit before any future send; no second caller can cross this boundary."""
        return self._transition(intent, "dispatch_started")

    def record_observed(self, intent: ModelEgressIntentV1, *,
                        observation_digest: str) -> ModelEgressRecoveryV1:
        raise AuthorityUnavailable("digest-only provider observation is forbidden")

    def _record_observation_locked(self, db: sqlite3.Connection,
                                   observation: ModelEgressObservationV1) -> ModelEgressRecoveryV1:
        """Future executor only: commit the entire parsed response before any finish."""
        if db is not self._db or not db.in_transaction or type(observation) is not ModelEgressObservationV1:
            raise AuthorityUnavailable("Authority transaction and typed observation required")
        old = self._read(db, observation.call_id)
        if old is None or old.state != "dispatch_started":
            raise AuthorityUnavailable("original dispatch marker is absent or already resolved")
        if not self.is_fence_bound_locked(db, old.intent):
            raise AuthorityUnavailable("original dispatch lacks atomic fence binding")
        fence = db.execute(
            "SELECT state,token FROM authority_v2_fences WHERE operation_id=?",
            (old.intent.operation_id,),
        ).fetchone()
        if fence != ("active", old.intent.fence_token):
            raise AuthorityUnavailable("original model fence is not active")
        target_state = "observed" if observation.status == "completed" else "unknown"
        target = ModelEgressRecoveryV1(old.intent, target_state,
                                       observation.digest, observation)
        raw = canonical_serialize(asdict(observation))
        db.execute(
            "INSERT INTO authority_model_egress_observations_v1(call_id,observation_json,observation_digest) VALUES(?,?,?)",
            (observation.call_id, raw, observation.digest),
        )
        updated = db.execute(
            "UPDATE authority_model_egress_v1 SET state=?,observation_digest=? "
            "WHERE call_id=? AND state='dispatch_started' AND identity_json=?",
            (target_state, observation.digest, observation.call_id, _encoded(old.intent)),
        )
        if updated.rowcount != 1:
            raise AuthorityUnavailable("original dispatch identity changed")
        return target

    def record_unknown(self, intent: ModelEgressIntentV1, *,
                       observation_digest: str) -> ModelEgressRecoveryV1:
        raise AuthorityUnavailable("digest-only provider observation is forbidden")


__all__ = ["AuthorityV2ModelEgressStore"]
