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
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressObservationV1,
    ModelEgressRecoveryV1, ModelTerminalReceiptV2,
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
_OBSERVATION_STATUS_DDL = """CREATE TABLE authority_model_egress_observation_status_v1(
    call_id TEXT PRIMARY KEY, observation_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed','unknown')),
    usage_json TEXT NOT NULL, cost_json TEXT NOT NULL,
    content_erased INTEGER NOT NULL CHECK(content_erased IN (0,1)),
    FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id)
)"""
_ADMISSION_DDL = """CREATE TABLE authority_model_admissions_v2(
    call_id TEXT PRIMARY KEY, admission_id TEXT NOT NULL UNIQUE,
    admission_json TEXT NOT NULL,
    report_digest TEXT, receipt_json TEXT,
    CHECK((report_digest IS NULL AND receipt_json IS NULL)
       OR (report_digest IS NOT NULL AND receipt_json IS NOT NULL)),
    FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id)
)"""
_ORIGINAL_IDENTITY_DDL = """CREATE TABLE authority_model_original_identity_v2(
    call_id TEXT PRIMARY KEY, authority_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    namespace TEXT NOT NULL, job_id TEXT NOT NULL,
    acquire_operation_id TEXT NOT NULL, operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL, binding_digest TEXT NOT NULL,
    FOREIGN KEY(call_id) REFERENCES authority_model_egress_v1(call_id)
)"""


def _encoded(intent: ModelEgressIntentV1) -> str:
    return json.dumps(asdict(intent), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _decoded(value: str) -> ModelEgressIntentV1:
    data = json.loads(value)
    current = set(ModelEgressIntentV1.__dataclass_fields__)
    legacy = current - {"acquire_operation_id", "binding_digest"}
    if type(data) is not dict or set(data) not in (current, legacy):
        raise ValueError("egress identity fields changed")
    data["source_refs"] = tuple(data["source_refs"])
    data["source_revisions"] = tuple(tuple(item) for item in data["source_revisions"])
    data["access_revisions"] = tuple(tuple(item) for item in data["access_revisions"])
    data["budget_ceiling"] = tuple(tuple(item) for item in data["budget_ceiling"])
    result = ModelEgressIntentV1(**data)
    if ((json.dumps({key: item for key, item in asdict(result).items() if key in data},
                    sort_keys=True, separators=(",", ":"), ensure_ascii=True)) != value):
        raise ValueError("noncanonical egress identity")
    return result


def _decoded_observation(value: str) -> ModelEgressObservationV1:
    data = json.loads(value)
    if canonical_serialize(data) != value:
        raise ValueError("noncanonical observation")
    from .v2_model_egress_contract import model_observation_from_wire_v1
    return model_observation_from_wire_v1(data)


class AuthorityV2ModelEgressStore:
    """Transactionally records identity and a one-way send marker.

    Dispatch admission uses only the fenced locked primitive after independent
    current graph and policy checks. The public unfenced marker is disabled.
    No production service currently exposes a provider executor.
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
            status = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_egress_observation_status_v1'"
            ).fetchone()
            if status is None:
                # This unshipped schema can be upgraded without changing the
                # complete response bytes or any call identity.
                db.execute(_OBSERVATION_STATUS_DDL)
                for call_id, raw, digest in db.execute(
                        "SELECT call_id,observation_json,observation_digest "
                        "FROM authority_model_egress_observations_v1"):
                    try:
                        item = _decoded_observation(raw)
                        ledger = self._read_ledger(db, call_id)
                        if (item.call_id != call_id or item.digest != digest
                                or ledger is None or ledger[5:7] !=
                                (("observed" if item.status == "completed" else "unknown"), digest)):
                            raise ValueError("observation and ledger differ")
                    except (TypeError, ValueError, UnicodeError) as exc:
                        raise AuthorityUnavailable("legacy observation cannot be upgraded") from exc
                    db.execute(
                        "INSERT INTO authority_model_egress_observation_status_v1 "
                        "(call_id,observation_digest,status,usage_json,cost_json,content_erased) "
                        "VALUES(?,?,?,?,?,0)",
                        (call_id, digest, item.status,
                         canonical_serialize(item.usage), canonical_serialize(item.cost)))
                if db.execute(
                        "SELECT 1 FROM authority_model_egress_v1 l LEFT JOIN "
                        "authority_model_egress_observation_status_v1 s USING(call_id) "
                        "WHERE l.state IN ('observed','unknown') AND s.call_id IS NULL LIMIT 1"
                ).fetchone():
                    raise AuthorityUnavailable("digest-only model observation cannot be upgraded")
            elif status != (_OBSERVATION_STATUS_DDL,):
                raise AuthorityUnavailable("unknown model egress observation status schema")
            admission = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_model_admissions_v2'"
            ).fetchone()
            if admission is None:
                # Pre-v2 dispatches remain HOLD: no observer identity may be
                # manufactured retroactively from their passive records.
                db.execute(_ADMISSION_DDL)
            elif admission != (_ADMISSION_DDL,):
                raise AuthorityUnavailable("unknown model admission schema")
            original = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name='authority_model_original_identity_v2'"
            ).fetchone()
            if original is None:
                # Historical rows have no verifiable binding digest. They stay
                # ineligible; never backfill from a current graph snapshot.
                db.execute(_ORIGINAL_IDENTITY_DDL)
            elif original != (_ORIGINAL_IDENTITY_DDL,):
                raise AuthorityUnavailable("unknown original model identity schema")

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
    def _read_ledger(db, call_id: str):
        return db.execute(
            "SELECT call_id,operation_id,namespace,subject,identity_json,state,observation_digest "
            "FROM authority_model_egress_v1 WHERE call_id=?", (call_id,),
        ).fetchone()

    @staticmethod
    def _read(db, call_id: str) -> ModelEgressRecoveryV1 | None:
        row = AuthorityV2ModelEgressStore._read_ledger(db, call_id)
        if row is None:
            return None
        try:
            intent = _decoded(row[4])
            from .c09_model_budget_original_v1 import require_model_identities_unconsumed_in_tx_v1
            require_model_identities_unconsumed_in_tx_v1(db, namespace=intent.namespace,
                call_id=intent.call_id, operation_id=intent.operation_id, job_id=intent.job_id,
                acquire_operation_id=intent.acquire_operation_id)
            if row[:4] != (intent.call_id, intent.operation_id, intent.namespace, intent.subject):
                raise ValueError("persisted egress identity mismatch")
            status_row = db.execute(
                "SELECT observation_digest,status,usage_json,cost_json,content_erased "
                "FROM authority_model_egress_observation_status_v1 WHERE call_id=?",
                (call_id,),
            ).fetchone()
            if row[5] in {"observed", "unknown"}:
                if (status_row is None or status_row[:2] !=
                        (row[6], "completed" if row[5] == "observed" else "unknown")
                        or type(status_row[4]) is not int or status_row[4] not in (0, 1)):
                    raise ValueError("observation status differs from ledger")
                usage = json.loads(status_row[2])
                cost = json.loads(status_row[3])
                if (type(usage) is not list or type(cost) is not list
                        or canonical_serialize(usage) != status_row[2]
                        or canonical_serialize(cost) != status_row[3]):
                    raise ValueError("noncanonical observation amounts")
                result = ModelEgressRecoveryV1(
                    intent, row[5], row[6], tuple(tuple(item) for item in usage),
                    tuple(tuple(item) for item in cost), bool(status_row[4]))
                content_exists = db.execute(
                    "SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?",
                    (call_id,),
                ).fetchone() is not None
                if content_exists == result.content_erased:
                    raise ValueError("observation content and erasure marker differ")
                return result
            if status_row is not None:
                raise ValueError("unobserved egress has observation metadata")
            return ModelEgressRecoveryV1(intent, row[5], row[6])
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted model egress record is invalid") from exc

    @staticmethod
    def _read_observation_locked(db: sqlite3.Connection,
                                 intent: ModelEgressIntentV1) -> ModelEgressObservationV1:
        """Internal only; production reads require future graph and deletion proofs."""
        if type(intent) is not ModelEgressIntentV1 or not db.in_transaction:
            raise AuthorityUnavailable("typed original call and Authority transaction required")
        recovery = AuthorityV2ModelEgressStore._read(db, intent.call_id)
        if (recovery is None or recovery.intent != intent
                or recovery.state not in {"observed", "unknown"}
                or recovery.content_erased):
            raise AuthorityUnavailable("original provider content is unavailable")
        row = db.execute(
            "SELECT observation_json,observation_digest FROM authority_model_egress_observations_v1 WHERE call_id=?",
            (intent.call_id,),
        ).fetchone()
        try:
            if row is None:
                raise ValueError("observation body absent")
            observation = _decoded_observation(row[0])
            if (observation.digest != row[1] or row[1] != recovery.observation_digest
                    or observation.status != ("completed" if recovery.state == "observed" else "unknown")
                    or observation.usage != recovery.usage or observation.cost != recovery.cost
                    or (observation.authority_id, observation.namespace,
                        observation.subject, observation.operation_id,
                        observation.call_id, observation.request_digest) !=
                       (intent.authority_id, intent.namespace,
                        intent.subject, intent.operation_id,
                        intent.call_id, intent.request_digest)):
                raise ValueError("observation differs from original call")
            return observation
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted provider content is invalid") from exc

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
        from .c09_model_budget_original_v1 import require_model_identities_unconsumed_in_tx_v1
        require_model_identities_unconsumed_in_tx_v1(db, namespace=intent.namespace,
            call_id=intent.call_id, operation_id=intent.operation_id, job_id=intent.job_id,
            acquire_operation_id=intent.acquire_operation_id)
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

    def capacity_original_locked_v1(self, db, draft):
        """Read one bounded exact draft, without provider content or old permits."""
        from .model_capacity_v1 import ORIGINAL_IDENTITY_BYTES_V1
        from .v2_model_egress_contract import ModelEgressDraftV1
        if db is not self._db or not db.in_transaction or type(draft) is not ModelEgressDraftV1:
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
        row = db.execute(
            "SELECT call_id,operation_id,namespace,subject,"
            "CASE WHEN length(CAST(identity_json AS BLOB))<=? THEN identity_json END,state "
            "FROM authority_model_egress_v1 WHERE call_id=?",
            (ORIGINAL_IDENTITY_BYTES_V1,draft.call_id)).fetchone()
        if row is None:
            return None
        if row[4] is None:
            raise AuthorityUnavailable("MODEL_CAPACITY_CENSUS_OVERFLOW")
        try:
            intent = _decoded(row[4])
        except (TypeError,ValueError,UnicodeError) as exc:
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED") from exc
        if (row[:4] != (intent.call_id,intent.operation_id,intent.namespace,intent.subject)
                or ModelEgressDraftV1.from_intent(intent) != draft):
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
        return intent,row[5]

    def bind_original_identity_locked(self, db: sqlite3.Connection,
                                      intent: ModelEgressIntentV1,
                                      installation_id: str) -> None:
        """Persist the V2 original key in the same transaction as preparation."""
        if (db is not self._db or not db.in_transaction
                or type(intent) is not ModelEgressIntentV1
                or intent.acquire_operation_id is None
                or intent.binding_digest is None):
            raise AuthorityUnavailable("complete original model identity required")
        identifier(installation_id, "installation_id")
        self.read_locked(db, intent)
        identity = (intent.call_id, intent.authority_id, installation_id,
                    intent.namespace,
                    intent.job_id, intent.acquire_operation_id,
                    intent.operation_id, intent.request_digest,
                    intent.binding_digest)
        old = db.execute(
            "SELECT call_id,authority_id,installation_id,namespace,job_id,acquire_operation_id,"
            "operation_id,request_digest,binding_digest "
            "FROM authority_model_original_identity_v2 WHERE call_id=?",
            (intent.call_id,),
        ).fetchone()
        if old is None:
            db.execute(
                "INSERT INTO authority_model_original_identity_v2 "
                "(call_id,authority_id,installation_id,namespace,job_id,acquire_operation_id,"
                "operation_id,request_digest,binding_digest) VALUES(?,?,?,?,?,?,?,?,?)",
                identity,
            )
        elif old != identity:
            raise AuthorityUnavailable("original model identity changed")

    def lookup_original_locked(self, db: sqlite3.Connection, *, authority_id: str,
                               installation_id: str,
                               namespace: str, job_id: str,
                               acquire_operation_id: str, operation_id: str,
                               call_id: str, request_digest: str,
                               binding_digest: str) -> ModelEgressRecoveryV1 | None:
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("Authority original lookup transaction required")
        from .c09_model_budget_original_v1 import require_model_identities_unconsumed_in_tx_v1
        require_model_identities_unconsumed_in_tx_v1(db, namespace=namespace, call_id=call_id,
            operation_id=operation_id, job_id=job_id, acquire_operation_id=acquire_operation_id)
        row = db.execute(
            "SELECT call_id,authority_id,installation_id,namespace,job_id,acquire_operation_id,"
            "operation_id,request_digest,binding_digest "
            "FROM authority_model_original_identity_v2 WHERE call_id=?",
            (call_id,),
        ).fetchone()
        if row is None:
            return None
        if row != (call_id, authority_id, installation_id, namespace, job_id,
                   acquire_operation_id, operation_id, request_digest,
                   binding_digest):
            raise AuthorityUnavailable("original model lookup identity differs")
        record = self._read(db, call_id)
        if (record is None or (record.intent.call_id, record.intent.authority_id,
                record.intent.namespace, record.intent.job_id,
                record.intent.acquire_operation_id, record.intent.operation_id,
                record.intent.request_digest,
                record.intent.binding_digest) != (row[0], row[1], *row[3:])):
            raise AuthorityUnavailable("original model identity and ledger differ")
        return record

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

    def record_admission_locked(self, db: sqlite3.Connection,
                                intent: ModelEgressIntentV1,
                                admission: ModelAdmissionV2) -> None:
        """Bind the v2 observer in the same transaction as the one-way CAS."""
        from .c09_model_budget_original_v1 import require_model_identities_unconsumed_in_tx_v1
        require_model_identities_unconsumed_in_tx_v1(db, namespace=intent.namespace,
            call_id=intent.call_id, operation_id=intent.operation_id, job_id=intent.job_id,
            acquire_operation_id=intent.acquire_operation_id, admission_id=admission.admission_id)
        if (db is not self._db or not db.in_transaction
                or type(intent) is not ModelEgressIntentV1
                or type(admission) is not ModelAdmissionV2
                or (admission.authority_id, admission.namespace,
                    admission.subject, admission.operation_id,
                    admission.call_id, admission.request_digest,
                    admission.provider_config_digest) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id, intent.request_digest,
                    intent.provider_config_digest)
                or self.read_locked(db, intent).state != "dispatch_started"):
            raise AuthorityUnavailable("v2 admission lacks original dispatch identity")
        try:
            db.execute(
                "INSERT INTO authority_model_admissions_v2 "
                "(call_id,admission_id,admission_json) VALUES(?,?,?)",
                (intent.call_id, admission.admission_id,
                 canonical_serialize(asdict(admission))))
        except sqlite3.IntegrityError as exc:
            raise AuthorityUnavailable("model admission cannot repeat") from exc

    def read_admission_locked(self, db: sqlite3.Connection,
                              intent: ModelEgressIntentV1) -> tuple[ModelAdmissionV2, str | None, ModelTerminalReceiptV2 | None]:
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("Authority admission transaction required")
        self.read_locked(db, intent)
        row = db.execute(
            "SELECT admission_id,admission_json,report_digest,receipt_json "
            "FROM authority_model_admissions_v2 WHERE call_id=?",
            (intent.call_id,),
        ).fetchone()
        if row is None:
            raise AuthorityUnavailable("v2 admission is absent; legacy dispatch remains HOLD")
        try:
            admission = ModelAdmissionV2(**json.loads(row[1]))
            receipt = (None if row[3] is None else
                       ModelTerminalReceiptV2(**json.loads(row[3])))
            if (admission.admission_id != row[0]
                    or canonical_serialize(asdict(admission)) != row[1]
                    or (admission.authority_id, admission.namespace,
                        admission.subject, admission.operation_id,
                        admission.call_id, admission.request_digest,
                        admission.provider_config_digest) !=
                       (intent.authority_id, intent.namespace, intent.subject,
                        intent.operation_id, intent.call_id, intent.request_digest,
                        intent.provider_config_digest)
                    or (row[2] is None) != (receipt is None)
                    or (receipt is not None and (
                        canonical_serialize(asdict(receipt)) != row[3]
                        or receipt.report_digest != row[2]
                        or (receipt.admission_id, receipt.call_id,
                            receipt.request_digest, receipt.installation_id,
                            receipt.host_incarnation) !=
                           (admission.admission_id, admission.call_id,
                            admission.request_digest, admission.installation_id,
                            admission.host_incarnation)))):
                raise ValueError("admission or receipt identity differs")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("persisted model admission is invalid") from exc
        return admission, row[2], receipt

    def record_terminal_receipt_locked(
            self, db: sqlite3.Connection, admission: ModelAdmissionV2,
            receipt: ModelTerminalReceiptV2) -> None:
        if (db is not self._db or not db.in_transaction
                or type(admission) is not ModelAdmissionV2
                or type(receipt) is not ModelTerminalReceiptV2
                or (receipt.admission_id, receipt.call_id,
                    receipt.request_digest, receipt.installation_id,
                    receipt.host_incarnation) !=
                   (admission.admission_id, admission.call_id,
                    admission.request_digest, admission.installation_id,
                    admission.host_incarnation)):
            raise AuthorityUnavailable("terminal receipt differs from admission")
        changed = db.execute(
            "UPDATE authority_model_admissions_v2 SET report_digest=?,receipt_json=? "
            "WHERE call_id=? AND admission_id=? AND admission_json=? "
            "AND report_digest IS NULL AND receipt_json IS NULL",
            (receipt.report_digest, canonical_serialize(asdict(receipt)),
             admission.call_id, admission.admission_id,
             canonical_serialize(asdict(admission))),
        )
        if changed.rowcount != 1:
            raise AuthorityUnavailable("terminal receipt cannot repeat or change")

    def record_dispatch_started(self, intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        """Legacy unfenced entrypoint is forbidden; use Authority admission."""
        raise AuthorityUnavailable("unfenced model dispatch marker is forbidden")

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
        if (observation.authority_id, observation.namespace,
            observation.subject, observation.operation_id,
            observation.call_id, observation.request_digest) != (
            old.intent.authority_id, old.intent.namespace,
            old.intent.subject, old.intent.operation_id,
            old.intent.call_id, old.intent.request_digest):
            raise ValueError("observation differs from original call")
        from .v2_model_egress_contract import require_model_observation_billing_intent_v1
        require_model_observation_billing_intent_v1(observation, old.intent)
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
                                       observation.digest, observation.usage,
                                       observation.cost)
        from .v2_model_egress_contract import model_observation_to_wire_v1
        raw = canonical_serialize(model_observation_to_wire_v1(observation))
        db.execute(
            "INSERT INTO authority_model_egress_observations_v1(call_id,observation_json,observation_digest) VALUES(?,?,?)",
            (observation.call_id, raw, observation.digest),
        )
        db.execute(
            "INSERT INTO authority_model_egress_observation_status_v1 "
            "(call_id,observation_digest,status,usage_json,cost_json,content_erased) "
            "VALUES(?,?,?,?,?,0)",
            (observation.call_id, observation.digest, observation.status,
             canonical_serialize(observation.usage), canonical_serialize(observation.cost)),
        )
        updated = db.execute(
            "UPDATE authority_model_egress_v1 SET state=?,observation_digest=? "
            "WHERE call_id=? AND state='dispatch_started' AND identity_json=?",
            (target_state, observation.digest, observation.call_id, _encoded(old.intent)),
        )
        if updated.rowcount != 1:
            raise AuthorityUnavailable("original dispatch identity changed")
        return target

    def _finish_terminal_observation_fenced_locked(
            self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
            observation: ModelEgressObservationV1, permit: FencePermitV2,
            fences, current_anchor) -> ModelEgressRecoveryV1:
        """Executor-only storage step; caller must authenticate the response first.

        The caller holds the journal freezes and Authority transaction. This
        does not accept a host task or authorize a provider call.
        """
        if (db is not self._db or not db.in_transaction
                or type(intent) is not ModelEgressIntentV1
                or type(observation) is not ModelEgressObservationV1
                or type(permit) is not FencePermitV2):
            raise AuthorityUnavailable("typed executor observation and Authority transaction required")
        if (observation.authority_id, observation.namespace,
                observation.subject, observation.operation_id,
                observation.call_id, observation.request_digest) != (
                intent.authority_id, intent.namespace, intent.subject,
                intent.operation_id, intent.call_id, intent.request_digest):
            raise AuthorityUnavailable("executor observation differs from original call")
        record = self.read_locked(db, intent)
        if record.state == "dispatch_started":
            record = self._record_observation_locked(db, observation)
        elif record.state in {"observed", "unknown"}:
            if self._read_observation_locked(db, intent) != observation:
                raise AuthorityUnavailable("terminal observation identity conflict")
        else:
            raise AuthorityUnavailable("original dispatch marker is absent")
        fences.finish_terminal_model_egress_locked(
            db, permit, intent=intent, current_anchor=current_anchor,
            status=observation.status)
        return record

    def _finish_not_dispatched_fenced_locked(
            self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
            permit: FencePermitV2, fences, current_anchor) -> ModelEgressRecoveryV1:
        """Close an unsent prepared call; dispatch_started can never return here."""
        record = self.read_locked(db, intent)
        if record.state != "prepared":
            raise AuthorityUnavailable("model call was dispatched or already resolved")
        fences.finish_terminal_model_egress_locked(
            db, permit, intent=intent, current_anchor=current_anchor,
            status="not_dispatched")
        return record

    def _erase_observation_content_locked(self, db: sqlite3.Connection,
                                          intent: ModelEgressIntentV1) -> ModelEgressRecoveryV1:
        """Internal D12 cleanup primitive; caller must first prove barrier and closure.

        This method supplies no deletion admission or cleanup receipt. It only
        removes content inside an Authority transaction, preserving the original
        call, state, digest and accounting summary so a send cannot be retried.
        """
        if db is not self._db or not db.in_transaction or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("typed original call and Authority transaction required")
        recovery = self.read_locked(db, intent)
        if recovery.state not in {"observed", "unknown"}:
            raise AuthorityUnavailable("unobserved call has no content to erase")
        if recovery.content_erased:
            return recovery
        self._read_observation_locked(db, intent)
        removed = db.execute(
            "DELETE FROM authority_model_egress_observations_v1 WHERE call_id=?",
            (intent.call_id,),
        )
        marked = db.execute(
            "UPDATE authority_model_egress_observation_status_v1 SET content_erased=1 "
            "WHERE call_id=? AND content_erased=0 AND observation_digest=?",
            (intent.call_id, recovery.observation_digest),
        )
        if removed.rowcount != 1 or marked.rowcount != 1:
            raise AuthorityUnavailable("observation erasure lost exact identity")
        return ModelEgressRecoveryV1(
            intent, recovery.state, recovery.observation_digest,
            recovery.usage, recovery.cost, True)

    def record_unknown(self, intent: ModelEgressIntentV1, *,
                       observation_digest: str) -> ModelEgressRecoveryV1:
        raise AuthorityUnavailable("digest-only provider observation is forbidden")


__all__ = ["AuthorityV2ModelEgressStore"]
