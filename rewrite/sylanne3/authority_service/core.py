"""Durable, content-free authority kernel for a separate trusted service.

The SQLite path must be outside business backup and owned by a separately
installed service. A copied local DB, in-process plugin, or loopback socket is
not a trust root. All calls require server-side authentication and independent
journal verification supplied by the deployment. Open permits never expire:
an uncertain/crashed holder blocks transfer until independently recovered.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import uuid

from ..runtime.activation import ActivationProof, TransferPlan
from ..runtime.restore_anchor import RestoreAnchor
from .contract import (
    AuthorityUnavailable, CONTENT_OPERATIONS, ContentPermit, JournalHead,
    identifier,
)
from .erasure_closure_redaction_v3 import (
    ExecutionRedactionPreparedV3, ExecutionRedactionSwitchV3,
    execution_row_commitment_v3, install_execution_redaction_schema,
    read_execution_redaction_pin_locked, read_execution_redaction_seal_locked,
    read_execution_redaction_switch_locked,
    require_no_execution_redaction_locked,
)
from .erasure_recovery_pin_v4 import (
    ExecutionRecoveryFactsPinV4, install_execution_recovery_pin_schema_v4,
    make_execution_recovery_facts_pin_v4,
    read_consumed_execution_fact_v4_locked,
    read_execution_recovery_facts_v4_locked,
    read_execution_recovery_facts_pin_v4_locked,
)
from .c09_graph_rebase_issue_v1 import (
    AuthorityGraphRebaseIssuedV1, install_graph_rebase_issue_schema_v1,
    read_graph_rebase_issue_v1_locked, sign_graph_rebase_issue_v1,
    verify_graph_rebase_issue_signature_v1,
)
from dataclasses import asdict


class AuthorityServiceCore:
    """Transactional authority state; no role content and no network listener."""

    def __init__(self, path, *, authorizer, deletion_verifier,
                 execution_verifier, effect_verifier, dispatch_verifier,
                 create: bool = False, execution_redaction_c04_service=None):
        for name, value in (
            ("authorizer", authorizer), ("deletion_verifier", deletion_verifier),
            ("execution_verifier", execution_verifier),
            ("effect_verifier", effect_verifier),
            ("dispatch_verifier", dispatch_verifier),
        ):
            if not callable(value):
                raise AuthorityUnavailable(f"server-side {name} is required")
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise AuthorityUnavailable("independent authority store is absent")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._authorize_callback = authorizer
        self._deletion_verifier = deletion_verifier
        self._execution_verifier = execution_verifier
        self._effect_verifier = effect_verifier
        self._dispatch_verifier = dispatch_verifier
        # Installed service only. A request-supplied verifier cannot authorize
        # a one-way migration of measured C04 terminal facts.
        self._execution_redaction_c04_service = execution_redaction_c04_service
        self._execution_redaction_c04_services = {}
        self._execution_redaction_d04_numeric_services_v3 = {}
        self._execution_redaction_d04_series_services_v1 = {}
        self._execution_redaction_d04_root_services_v3 = {}
        self._execution_redaction_d11_offline_services_v1 = {}
        self._execution_redaction_d11_life_services_v1 = {}
        self._execution_recovery_facts_ports_v4 = {}
        self._c09_maintenance_authority_v1 = None
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, isolation_level=None,
                                   check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._install_schema()

    def _install_schema(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS authority_meta(
                key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_namespaces(
                namespace TEXT PRIMARY KEY, holder TEXT, generation INTEGER NOT NULL,
                phase TEXT NOT NULL, transfer_id TEXT, target TEXT,
                revocation_epoch INTEGER NOT NULL, deletion_journal_id TEXT NOT NULL,
                deletion_seq INTEGER NOT NULL, deletion_digest TEXT NOT NULL,
                deletion_phase TEXT NOT NULL, execution_journal_id TEXT NOT NULL,
                execution_seq INTEGER NOT NULL, execution_digest TEXT NOT NULL,
                anchor_nonce TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_transfers(
                operation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                source TEXT NOT NULL, target TEXT NOT NULL,
                base_generation INTEGER NOT NULL, phase TEXT NOT NULL,
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_permits(
                token TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                holder TEXT NOT NULL, generation INTEGER NOT NULL,
                operation TEXT NOT NULL,
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_effects(
                namespace TEXT NOT NULL, effect_id TEXT NOT NULL,
                state TEXT NOT NULL, conflict_keys_json TEXT NOT NULL,
                execution_seq INTEGER NOT NULL,
                PRIMARY KEY(namespace,effect_id),
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_events(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL, kind TEXT NOT NULL,
                generation INTEGER NOT NULL, detail_digest TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS authority_events_no_update
                BEFORE UPDATE ON authority_events
                BEGIN SELECT RAISE(ABORT,'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS authority_events_no_delete
                BEFORE DELETE ON authority_events
                BEGIN SELECT RAISE(ABORT,'append-only'); END;
        """)
        self._db.execute(
            "INSERT OR IGNORE INTO authority_meta(key,value) VALUES('authority_id',?)",
            (str(uuid.uuid4()),))
        install_execution_redaction_schema(self._db)
        install_execution_recovery_pin_schema_v4(self._db)
        install_graph_rebase_issue_schema_v1(self._db)
        from .c09_model_budget_original_v1 import install_c09_model_budget_schema_v1
        install_c09_model_budget_schema_v1(self._db)

    def _require(self, credential, action: str, namespace: str,
                 holder: str | None = None) -> None:
        identifier(namespace, "namespace")
        if holder is not None:
            identifier(holder, "holder")
        try:
            granted = self._authorize_callback(credential, action, namespace, holder)
        except Exception as exc:
            raise AuthorityUnavailable("server authentication failed") from exc
        if granted is not True:
            raise AuthorityUnavailable("server authentication denied")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db is None:
                raise AuthorityUnavailable("authority service is unavailable")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    @staticmethod
    def _require_legacy_mode(db) -> None:
        row = db.execute(
            "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone()
        if row is None:
            return
        if row == ("v2-only",):
            raise AuthorityUnavailable("legacy authority entry disabled by v2-only seal")
        raise AuthorityUnavailable("unknown authority service mode")

    @staticmethod
    def _require_no_deletion_migration(db) -> None:
        """All v2 entrances fail while the cross-file migration is incomplete."""
        require_no_execution_redaction_locked(db)
        row = db.execute(
            "SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone()
        if row is None:
            return  # Pre-migration service prototype; never a deployment claim.
        try:
            marker = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion migration blocker") from exc
        if (type(marker) is not dict
                or marker.get("schema") != "sylanne3.deletion-migration.v1"
                or marker.get("stage") != "complete"):
            raise AuthorityUnavailable("deletion migration blocks v2 service entry")

    @contextmanager
    def _legacy_tx(self):
        """Cross-process seal barrier before any legacy journal access."""
        with self._tx() as db:
            self._require_legacy_mode(db)
            yield db

    def seal_v2_only(self, credential) -> None:
        """Installer transition for this whole Authority DB; never clears state."""
        with self._lock:
            if self._db is None:
                raise AuthorityUnavailable("authority service is unavailable")
            namespaces = tuple(row[0] for row in self._db.execute(
                "SELECT namespace FROM authority_namespaces ORDER BY namespace"))
        if not namespaces:
            raise AuthorityUnavailable("cannot seal an uninstalled authority")
        for namespace in namespaces:
            self._require(credential, "seal_v2_only", namespace)
        with self._tx() as db:
            current = tuple(row[0] for row in db.execute(
                "SELECT namespace FROM authority_namespaces ORDER BY namespace"))
            if current != namespaces:
                raise AuthorityUnavailable("authority namespace set changed during seal")
            mode = db.execute(
                "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone()
            if mode == ("v2-only",):
                return
            if mode is not None:
                raise AuthorityUnavailable("unknown authority service mode")
            if db.execute("SELECT 1 FROM authority_permits LIMIT 1").fetchone():
                raise AuthorityUnavailable("legacy content permit blocks v2-only seal")
            if db.execute("SELECT 1 FROM authority_transfers LIMIT 1").fetchone():
                raise AuthorityUnavailable("legacy transfer history requires explicit migration")
            if db.execute("SELECT 1 FROM authority_effects WHERE state!='resolved' LIMIT 1").fetchone():
                raise AuthorityUnavailable("unresolved legacy effect blocks v2-only seal")
            if db.execute("SELECT 1 FROM authority_namespaces WHERE holder IS NULL OR phase!='active' OR transfer_id IS NOT NULL OR target IS NOT NULL OR deletion_phase!='clear' LIMIT 1").fetchone():
                raise AuthorityUnavailable("unsettled authority namespace blocks v2-only seal")
            for namespace in namespaces:
                self._verify_current_heads(namespace, self._row(db, namespace))
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_v2_fences'").fetchone()
            if table and db.execute("SELECT 1 FROM authority_v2_fences WHERE state='active' LIMIT 1").fetchone():
                raise AuthorityUnavailable("active v2 fence blocks mode transition")
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_v2_mutations'").fetchone()
            if table and db.execute("SELECT 1 FROM authority_v2_mutations WHERE state='pending' LIMIT 1").fetchone():
                raise AuthorityUnavailable("pending v2 mutation blocks mode transition")
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")

    def _row(self, db, namespace: str):
        row = db.execute(
            "SELECT holder,generation,phase,transfer_id,target,revocation_epoch,"
            "deletion_journal_id,deletion_seq,deletion_digest,deletion_phase,"
            "execution_journal_id,execution_seq,execution_digest,anchor_nonce "
            "FROM authority_namespaces WHERE namespace=?", (namespace,),
        ).fetchone()
        if row is None:
            raise AuthorityUnavailable("namespace is not registered")
        return row

    def _id(self, db) -> str:
        return db.execute(
            "SELECT value FROM authority_meta WHERE key='authority_id'"
        ).fetchone()[0]

    @staticmethod
    def _head(row, kind: str) -> JournalHead:
        index = 6 if kind == "deletion" else 10
        return JournalHead(row[index], row[index + 1], row[index + 2])

    def _proof(self, db, namespace: str, row) -> ActivationProof:
        return ActivationProof(self._id(db), namespace, row[0], row[1], row[2], row[3])

    def _anchor(self, db, namespace: str, row) -> RestoreAnchor:
        return RestoreAnchor(
            self._id(db), namespace, row[1], row[6], row[7], row[8],
            row[10], row[11], row[12], row[5], row[13],
        )

    @staticmethod
    def _event(db, namespace: str, kind: str, generation: int,
               detail: object) -> None:
        import hashlib
        payload = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        db.execute(
            "INSERT INTO authority_events(namespace,kind,generation,detail_digest) "
            "VALUES(?,?,?,?)", (namespace, kind, generation, digest),
        )

    @staticmethod
    def _new_nonce() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def _no_permits(db, namespace: str) -> None:
        if db.execute(
            "SELECT 1 FROM authority_permits WHERE namespace=? LIMIT 1",
            (namespace,),
        ).fetchone():
            raise AuthorityUnavailable("in-flight content permit blocks transfer or deletion")

    def _verify_head(self, kind: str, namespace: str,
                     previous: JournalHead | None, current: JournalHead,
                     phase: str | None) -> None:
        verifier = (self._deletion_verifier if kind == "deletion"
                    else self._execution_verifier)
        if not isinstance(current, JournalHead):
            raise TypeError("current journal head must be JournalHead")
        if previous is not None:
            if (current.journal_id != previous.journal_id
                    or current.seq <= previous.seq):
                raise AuthorityUnavailable("journal head must advance on one journal")
        try:
            verified = verifier(namespace, previous, current, phase)
        except Exception as exc:
            raise AuthorityUnavailable("independent journal verification failed") from exc
        if verified is not True:
            raise AuthorityUnavailable("independent journal head was not verified")

    def _verify_current_heads(self, namespace: str, row) -> None:
        """A journal append not yet reflected here closes every content path."""
        if getattr(self, "_c09_storage_reader_v1", None) is not None:
            self.require_current_storage_generation_locked(self._db, namespace=namespace,
                action="business" if row[9] == "clear" else "maintenance")
        else:
            require_no_execution_redaction_locked(self._db, namespace)
        for kind, phase in (("deletion", row[9]), ("execution", None)):
            head = self._head(row, kind)
            verifier = (self._deletion_verifier if kind == "deletion"
                        else self._execution_verifier)
            try:
                current = verifier(namespace, head, head, phase)
            except Exception as exc:
                raise AuthorityUnavailable("current independent journal is unavailable") from exc
            if current is not True:
                raise AuthorityUnavailable("authority head is behind independent journal")

    def begin_execution_redaction_v3(
            self, *, credential, closure, subject: str,
            operation_id: str) -> ExecutionRedactionPreparedV3:
        """Seal a nonempty old execution chain in Core before any redaction.

        Installer authentication and the original accepted CleanupRun are
        checked in Core. This does not change the execution head or any body.
        Lock order is deletion journal, execution journal, then Core.
        """
        from .erasure_closure_inventory import (
            AuthorityErasureClosureInventory, CleanupRunV2,
            ExecutionPayloadInventoryV1, _TABLES,
        )
        from ..runtime_contracts import canonical_digest, canonical_serialize

        if (type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not self
                or closure.scoped.core is not self
                or closure.execution is not closure.scoped.execution
                or closure.deletion is not closure.scoped.deletion):
            raise AuthorityUnavailable("paired C09 closure original service required")
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        namespace = closure.namespace
        self._require(credential, "execution_redaction_install", namespace)
        closure.qualify_current_registry_location_v1(
            credential=credential, subject=subject, operation_id=operation_id)

        # An exact retry reads the immutable Core original without reopening
        # the old journal, which is deliberately blocked after PREPARED.
        with self._tx() as db:
            prior = read_execution_redaction_seal_locked(db, namespace)
            if prior is not None:
                run = closure._read_record(
                    db, _TABLES[1], operation_id, CleanupRunV2)
                inventory = closure._read_record(
                    db, _TABLES[2], operation_id,
                    ExecutionPayloadInventoryV1)
                if (run is None or inventory is None
                        or prior.operation_id != operation_id
                        or run.operation_id != operation_id
                        or inventory.operation_id != operation_id
                        or prior.installation_id != closure.installation_id
                        or prior.authority_id != self._id(db)
                        or prior.cleanup_run_digest != run.run_digest
                        or prior.inventory_receipt_digest != inventory.receipt_digest
                        or self._head(self._row(db, namespace), "execution")
                           != JournalHead(prior.execution_journal_id,
                                          prior.execution_seq,
                                          prior.execution_digest)):
                    raise AuthorityUnavailable("execution redaction begin conflicts")
                closure._registry_locked(db)
                closure._accepted_locked(db, run, subject)
                return prior
            authority_id = self._id(db)

        # Persist the journal's Core source first. A crash here leaves an
        # ordinary journal; a crash after Core PREPARED leaves a blocking link.
        closure.execution.install_core_redaction_source(
            core_path=self.path, authority_id=authority_id)
        with closure.deletion.freeze_writes():
            with closure.execution.freeze_writes():
                with self._tx() as db:
                    if read_execution_redaction_seal_locked(db, namespace):
                        raise AuthorityUnavailable("execution redaction begin raced")
                    if db.execute(
                            "SELECT value FROM authority_meta WHERE key='service_mode'"
                    ).fetchone() != ("v2-only",):
                        raise AuthorityUnavailable("execution redaction needs v2-only Core")
                    self._require_no_deletion_migration(db)
                    registry = closure._registry_locked(db)
                    run = closure._read_record(
                        db, _TABLES[1], operation_id, CleanupRunV2)
                    inventory = closure._read_record(
                        db, _TABLES[2], operation_id,
                        ExecutionPayloadInventoryV1)
                    if (run is None or inventory is None
                            or run.operation_id != operation_id
                            or inventory.operation_id != operation_id):
                        raise AuthorityUnavailable("accepted cleanup originals absent")
                    closure._accepted_locked(db, run, subject)
                    if inventory != closure._inventory_locked(db, run, subject):
                        raise AuthorityUnavailable("execution inventory original differs")
                    current = self._row(db, namespace)
                    head, rows = closure.execution._scan_locked()
                    if (self._head(current, "execution") != head
                            or (run.execution_journal_id, run.execution_seq,
                                run.execution_digest) != (
                                    head.journal_id, head.seq, head.digest)
                            or not rows
                            or inventory.entry_count != len(rows)):
                        raise AuthorityUnavailable(
                            "nonempty current execution head required for redaction seal")
                    self._verify_execution_redaction_c04_rows(
                        closure.execution, rows, journal_id=head.journal_id)
                    closure.execution.require_core_redaction_source(
                        core_path=self.path, authority_id=authority_id)
                    commitments = tuple(execution_row_commitment_v3(
                        closure.execution, row) for row in rows)
                    shape = (
                        authority_id, namespace, closure.installation_id,
                        operation_id, run.accepted_receipt_digest,
                        run.run_digest, inventory.receipt_digest,
                        registry.registry_digest, head.journal_id,
                        head.seq, head.digest, commitments)
                    seal = ExecutionRedactionPreparedV3(
                        *shape, canonical_digest((
                            "sylanne3.authority.execution_redaction_seal.v3",
                            *shape, "prepared")))
                    db.execute(
                        "INSERT INTO authority_execution_redaction_seals_v3 "
                        "(namespace,operation_id,seal_json) VALUES(?,?,?)",
                        (namespace, operation_id,
                         canonical_serialize(asdict(seal))))
                    self._event(db, namespace, "execution-redaction-prepared",
                                current[1], (operation_id, seal.seal_digest))
                    return seal

    def install_execution_redaction_c04_services(self, namespace: str,
                                                 services: dict) -> None:
        """Installer-only, one-shot binding of formal V2/V3 terminal verifiers."""
        from .internal_work_service import AuthorityInternalWorkService

        identifier(namespace, "namespace")
        if (type(services) is not dict or not services
                or set(services) - {
                    "d06.association_activation.v2",
                    "d06.association_activation.v3"}):
            raise AuthorityUnavailable("installed C04 redaction versions differ")
        for algorithm, service in services.items():
            if (type(service) is not AuthorityInternalWorkService
                    or not service.installed_runtime_verified
                    or service._component_signing_key is None
                    or service.installed_algorithm_id != algorithm
                    or service.journal.namespace != namespace):
                raise AuthorityUnavailable("formal C04 redaction verifier required")
        with self._lock:
            if namespace in self._execution_redaction_c04_services:
                raise AuthorityUnavailable("C04 redaction verifier already installed")
            self._execution_redaction_c04_services[namespace] = dict(services)

    def install_execution_redaction_d04_numeric_service_v3(self, namespace, service):
        from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
        identifier(namespace, "namespace")
        if (type(service) is not AuthorityD04NumericServiceV3
                or service.bridge.core is not self or service.bridge.namespace != namespace):
            raise AuthorityUnavailable("D04 numeric recovery service installation differs")
        with self._lock:
            if namespace in self._execution_redaction_d04_numeric_services_v3:
                raise AuthorityUnavailable("D04 numeric recovery verifier already installed")
            self._execution_redaction_d04_numeric_services_v3[namespace] = service

    def install_execution_redaction_d04_series_service_v1(self, namespace, service):
        from .d04_series_service_v1 import AuthorityD04SeriesServiceV1
        if (type(service) is not AuthorityD04SeriesServiceV1
                or service.numeric is not self._execution_redaction_d04_numeric_services_v3.get(namespace)):
            raise AuthorityUnavailable("D04 series recovery must share the installed numeric authority")
        with self._lock:
            if namespace in self._execution_redaction_d04_series_services_v1:
                raise AuthorityUnavailable("D04 series recovery service already installed")
            self._execution_redaction_d04_series_services_v1[namespace] = service

    def install_execution_redaction_d04_root_service_v3(self, namespace, service):
        from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
        identifier(namespace, "namespace")
        if (type(service) is not AuthorityD04RootExecutionServiceV3
                or service.bridge.core is not self or service.bridge.namespace != namespace):
            raise AuthorityUnavailable("authored-root recovery service installation differs")
        with self._lock:
            if namespace in self._execution_redaction_d04_root_services_v3:
                raise AuthorityUnavailable("authored-root recovery verifier already installed")
            self._execution_redaction_d04_root_services_v3[namespace] = service

    def install_execution_redaction_d11_offline_service_v1(self, namespace, service):
        from .d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
        identifier(namespace, "namespace")
        if (type(service) is not AuthorityD11OfflineTickServiceV1
                or service.bridge.core is not self or service.bridge.namespace != namespace):
            raise AuthorityUnavailable("offline tick recovery service installation differs")
        with self._lock:
            if namespace in self._execution_redaction_d11_offline_services_v1:
                raise AuthorityUnavailable("offline tick recovery verifier already installed")
            self._execution_redaction_d11_offline_services_v1[namespace] = service

    def install_execution_redaction_d11_life_service_v1(self, namespace, service):
        from .d11_life_service_v1 import AuthorityD11LifeServiceV1
        identifier(namespace, "namespace")
        if (type(service) is not AuthorityD11LifeServiceV1 or service.bridge.core is not self
                or service.bridge.namespace != namespace):
            raise AuthorityUnavailable("Life recovery service differs from actual installed authority")
        with self._lock:
            if namespace in self._execution_redaction_d11_life_services_v1:
                raise AuthorityUnavailable("Life recovery verifier already installed")
            self._execution_redaction_d11_life_services_v1[namespace] = service

    def install_execution_recovery_facts_port_v4(
        self, namespace: str, port: object) -> None:
        """Installer-only hook; no RPC accepts a caller-provided facts port."""
        from .c09_current_recovery_originals_v4 import (
            InstalledC09RecoveryOriginalsV4,
        )

        identifier(namespace, "namespace")
        methods = (
            "read_current_anchor_v4", "read_current_execution_originals_v4",
            "read_current_d02_originals_v4", "read_current_d11_originals_v4",
            "read_current_unknown_originals_v4", "read_current_graph_originals_v4",
        )
        if (type(port) is not InstalledC09RecoveryOriginalsV4
                or port.core is not self
                or port.closure.namespace != namespace
                or any(not callable(getattr(port, name, None))
                                for name in methods)):
            raise AuthorityUnavailable("complete installed V4 facts reader required")
        with self._lock:
            if namespace in self._execution_recovery_facts_ports_v4:
                raise AuthorityUnavailable("V4 facts reader already installed")
            self._execution_recovery_facts_ports_v4[namespace] = port

    def install_current_c09_recovery_readers_v4(
            self, *, closure, graph, namespace_id, resource_issuer,
            body_authority, internal_services):
        """Bind live installed Authority/Graph/D02 readers to this Core."""
        from .c09_current_recovery_originals_v4 import (
            InstalledC09RecoveryOriginalsV4,
        )

        port = InstalledC09RecoveryOriginalsV4(
            core=self, closure=closure, graph=graph,
            namespace_id=namespace_id, resource_issuer=resource_issuer,
            body_authority=body_authority,
            internal_services=internal_services)
        self.install_execution_recovery_facts_port_v4(closure.namespace, port)
        return port

    def install_current_c09_storage_reader_v1(self, *, reader) -> None:
        from .c09_storage_control_v1 import InstalledC09StorageReaderV1
        if not isinstance(reader, InstalledC09StorageReaderV1):
            raise AuthorityUnavailable("installed C09 storage reader required")
        context = reader.read_verified_current_storage_v1()
        member = next(m for m in context.manifest["members"] if m["role"] == "core")
        if member["resolved_path"] != str(self.path.resolve()):
            raise AuthorityUnavailable("Core outside C09 current manifest")
        with self._lock:
            prior = getattr(self, "_c09_storage_reader_v1", None)
            if prior is not None and prior is not reader:
                raise AuthorityUnavailable("C09 storage reader already installed")
            self._c09_storage_reader_v1 = reader

    def require_current_content_ready_locked(self, db, *, namespace):
        """A current signed C09 RELEASED supersedes old history, never the history bytes."""
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("content readiness requires current Core transaction")
        context = self.require_current_storage_generation_locked(db, namespace=namespace, action="business")
        if context.stage != "RELEASED" or context.prepared_original is None:
            raise AuthorityUnavailable("historical deletion needs current authenticated C09 RELEASED")
        row = self._row(db, namespace)
        if row[9] != "clear" or row[2] != "active":
            raise AuthorityUnavailable("C09 current namespace is not content ready")
        return context

    def require_current_storage_generation_locked(self, db, *, namespace, action):
        """Current generation admission; old seal guards remain unchanged."""
        reader = getattr(self, "_c09_storage_reader_v1", None)
        if reader is None:
            raise AuthorityUnavailable("installed current C09 storage verifier unavailable")
        context = reader.read_verified_current_storage_v1(verify_files=False)
        context.require_current(action)
        member = next(m for m in context.manifest["members"] if m["role"] == "core")
        if member["resolved_path"] != str(self.path.resolve()) or member["namespace"] != namespace or context.manifest["authority_id"] != self._id(db):
            raise AuthorityUnavailable("Core current storage generation differs")
        return context

    def read_current_deletion_continuation_v1(
            self, *, credential, namespace, operation_id, db=None):
        """Close-only authenticated transition. With db supplied no nested tx."""
        self._require(credential, "delete", namespace)
        if db is None:
            with self._tx() as locked:
                return self.read_current_deletion_continuation_v1(
                    credential=credential, namespace=namespace, operation_id=operation_id, db=locked)
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("C09 continuation requires current Core transaction")
        from .c09_originals_archive_v1 import read_current_deletion_continuation_v1_locked
        transition = read_current_deletion_continuation_v1_locked(
            db, namespace=namespace, operation_id=operation_id)
        if transition is None:
            raise AuthorityUnavailable("current C09 deletion continuation absent")
        self.verify_c09_deletion_transition_v1(
            namespace=namespace, operation_id=operation_id, transition=transition, db=db)
        return transition

    def verify_c09_deletion_transition_v1(
            self, *, namespace, operation_id, transition, db=None):
        """Verify detached PREPARED coverage and live anchor, never caller bool."""
        if db is None:
            with self._tx() as locked:
                return self.verify_c09_deletion_transition_v1(
                    namespace=namespace, operation_id=operation_id, transition=transition, db=locked)
        if db is not self._db or not db.in_transaction:
            raise AuthorityUnavailable("C09 transition requires current Core transaction")
        from .c09_originals_archive_v1 import read_current_deletion_continuation_v1_locked
        from ..runtime.restore_anchor import RestoreAnchor
        from .v2_contract import FencePermitV2, canonical_bytes
        context = self.require_current_storage_generation_locked(db, namespace=namespace, action="maintenance")
        prepared = context.prepared_original
        if (prepared is None or context.stage not in {"SWITCHED", "CLEANED", "RELEASED"}
                or prepared["operation_id"] != operation_id
                or prepared["anchor_transition_original"] != transition
                or read_current_deletion_continuation_v1_locked(db, namespace=namespace, operation_id=operation_id) != transition
                or transition["authority_id"] != self._id(db)):
            raise AuthorityUnavailable("C09 transition detached authentication differs")
        after = RestoreAnchor(**transition["after_anchor"])
        permit_body = dict(transition["continuation_permit"])
        permit_body["pinned_anchor"] = RestoreAnchor(**permit_body["pinned_anchor"])
        permit = FencePermitV2(**permit_body)
        live = self._anchor(db, namespace, self._row(db, namespace))
        fence = db.execute("SELECT permit FROM authority_v2_fences WHERE operation_id=?", (permit.operation_id,)).fetchone()
        if live != after or permit.pinned_anchor != after or fence != (canonical_bytes(permit),):
            raise AuthorityUnavailable("C09 continuation no longer current")
        return transition

    def install_c09_maintenance_authority_v1(
            self, *, signing_key: bytes, inventory_manifest,
            writer_freeze_verifier) -> None:
        """Install the independent key, file inventory and real writer gate."""
        from ..runtime.c09_installation_inventory_v2 import (
            InstallationFilesystemManifestV2,
        )

        if (type(signing_key) is not bytes or len(signing_key) < 32
                or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or not callable(writer_freeze_verifier)):
            raise AuthorityUnavailable("installed C09 maintenance authority incomplete")
        with self._lock:
            if self._c09_maintenance_authority_v1 is not None:
                raise AuthorityUnavailable("C09 maintenance authority already installed")
            self._c09_maintenance_authority_v1 = (
                signing_key, inventory_manifest, writer_freeze_verifier)

    def prepare_c09_execution_source_v4(self, *, credential, closure, subject, operation_id):
        from .c09_source_prepare_v4 import prepare_installed_execution_source_v4
        return prepare_installed_execution_source_v4(core=self,credential=credential,
            closure=closure,subject=subject,operation_id=operation_id)

    def issue_graph_rebase_certificate_v1(
            self, *, credential, closure, subject: str,
            candidate) -> AuthorityGraphRebaseIssuedV1:
        """Sign a pinned Graph candidate after fresh installed facts and files."""
        import hashlib
        from pathlib import Path

        from ..runtime.c09_graph_rebase_candidate_v1 import (
            GraphRebaseCandidateV1, graph_source_files_fingerprint_v1,
        )
        from ..runtime_contracts import canonical_serialize
        from ..runtime.c09_installation_inventory_v2 import (
            scan_installed_filesystem_v2,
        )
        from .erasure_closure_inventory import (
            AuthorityErasureClosureInventory, CleanupRunV2, _TABLES,
        )

        if (type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not self
                or type(candidate) is not GraphRebaseCandidateV1
                or candidate.operation_id is None):
            raise AuthorityUnavailable("paired installed C09 candidate required")
        namespace, operation_id = closure.namespace, candidate.operation_id
        self._require(credential, "execution_redaction_install", namespace)
        closure.qualify_current_registry_location_v1(
            credential=credential, subject=subject, operation_id=operation_id)
        identifier(subject, "subject")
        installed = self._c09_maintenance_authority_v1
        if installed is None:
            raise AuthorityUnavailable("C09 maintenance signer not installed")
        key, manifest, freeze_verifier = installed
        certificate = candidate.certificate_draft
        reader = self._execution_recovery_facts_ports_v4.get(namespace)
        if (manifest.namespace != namespace
                or manifest.installation_id != closure.installation_id
                or candidate.frozen_inventory_digest != manifest.manifest_digest
                or certificate.namespace != namespace
                or certificate.installation_id != closure.installation_id
                or certificate.operation_id != operation_id
                or certificate.frozen_inventory_digest != manifest.manifest_digest
                or reader is None or reader.namespace_id != candidate.namespace
                or candidate.source_closure_digest != certificate.source_closure_digest):
            raise AuthorityUnavailable("C09 installed candidate identity differs")
        try:
            if freeze_verifier(candidate) is not True:
                raise AuthorityUnavailable("C09 writers are not frozen")
        except Exception as exc:
            raise AuthorityUnavailable("installed C09 writer freeze unavailable") from exc
        # Freshly reread every V4 family from the sealed old chain. A digest
        # pinned earlier alone is insufficient to authorize a file transition.
        from .c09_source_prepare_v4 import read_installed_source_bundle_v4
        pin = read_installed_source_bundle_v4(core=self,closure=closure,
            credential=credential,subject=subject,operation_id=operation_id)["pin"]
        # A successor generation preserves the installer manifest. Its exact
        # four selected paths come only from the independently issued lineage
        # view; the old paths are never re-registered or recreated.
        location = getattr(closure, "current_source_location", None)
        inventory_view = None
        observed_run = None
        if location is not None:
            from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
            if (type(location) is not InstalledCurrentSourceLocationQualifierV1
                    or location._fences.core is not self):
                raise AuthorityUnavailable("actual installed C09 inventory qualifier required")
            with self._tx() as db:
                observed_run = closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
            if observed_run is None:
                raise AuthorityUnavailable("accepted C09 cleanup run absent")
            inventory_view = location.observe_installation_inventory_v1(manifest,
                credential=credential, subject=subject,
                accepted_mutation_id=observed_run.accepted_mutation_id)
            location.scan_installation_inventory_v1(inventory_view)
            location.require_inventory_graph_source_v1(inventory_view, candidate.source_path)
        else:
            scan_installed_filesystem_v2(
                manifest, pinned_manifest_digest=manifest.manifest_digest)
        source, target = Path(candidate.source_path), Path(candidate.target_path)
        with reader.graph._lock:
            if reader.graph_path != source.resolve():
                raise AuthorityUnavailable("installed Graph source path differs")
        try:
            source_stat, target_stat = source.stat(), target.stat()
            identity = lambda info: (info.st_dev, info.st_ino,
                                     info.st_size, info.st_mtime_ns)
            hasher = hashlib.sha256()
            with target.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(block)
            file_hash = hasher.hexdigest()
            if (identity(source_stat) != candidate.source_identity
                    or identity(target_stat) != candidate.target_identity
                    or graph_source_files_fingerprint_v1(source) !=
                       candidate.source_files_fingerprint
                    or file_hash != candidate.new_file_sha256):
                raise AuthorityUnavailable("Graph candidate files changed")
        except OSError as exc:
            raise AuthorityUnavailable("Graph candidate file unavailable") from exc
        if inventory_view is None and not any(item.kind == "sqlite_db" and item.path == str(source)
                   for item in manifest.resources):
            raise AuthorityUnavailable("Graph source outside installed inventory")
        if not any(item.kind == "rebuild_temp" and item.path in
                   {str(parent) for parent in (target.parent, *target.parents)}
                   for item in manifest.resources):
            raise AuthorityUnavailable("Graph target outside installed inventory")
        with self._tx() as db:
            run = closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable("accepted C09 cleanup run absent")
            if inventory_view is not None:
                if run != observed_run:
                    raise AuthorityUnavailable("accepted C09 cleanup changed after inventory observation")
                location.require_current_in_tx_v1(db, inventory_view.location)
            closure._registry_locked(db)
            closure._accepted_locked(db, run, subject)
            if (run.accepted_receipt_digest !=
                    certificate.accepted_receipt_digest
                    or run.graph_barrier_receipt_digest !=
                       certificate.barrier_receipt_digest
                    or certificate.authority_id != self._id(db)
                    or read_execution_recovery_facts_pin_v4_locked(
                        db, namespace,operation_id=operation_id) != pin
                    or read_execution_recovery_facts_v4_locked(
                        db, namespace,operation_id=operation_id) is None):
                raise AuthorityUnavailable("C09 current signed originals differ")
            from .c09_graph_rebase_issue_v1 import issue_graph_rebase_in_tx_v1
            return issue_graph_rebase_in_tx_v1(db, key=key, manifest=manifest,
                candidate=candidate, run=run, pin=pin)

    def verify_current_graph_rebase_issue_v1(
            self, credential, issued: AuthorityGraphRebaseIssuedV1,
            certificate) -> bool:
        """Installer verifier used by Graph mirror and every cold recovery."""
        from ..runtime.c09_storage_rebase_contract_v1 import (
            GraphErasureRebaseCertificateV1,
        )

        if (type(issued) is not AuthorityGraphRebaseIssuedV1
                or type(certificate) is not GraphErasureRebaseCertificateV1
                or issued.certificate_digest != certificate.certificate_digest):
            raise AuthorityUnavailable("authenticated C09 Graph issue required")
        self._require(credential, "execution_redaction_install", issued.namespace)
        installed = self._c09_maintenance_authority_v1
        if installed is None:
            raise AuthorityUnavailable("cold C09 maintenance signer unavailable")
        key, manifest, _ = installed
        verify_graph_rebase_issue_signature_v1(issued, key)
        with self._tx() as db:
            from .c09_graph_rebase_issue_v1 import verify_graph_rebase_issue_in_tx_v1
            return verify_graph_rebase_issue_in_tx_v1(db, key=key, manifest=manifest,
                issued=issued, certificate=certificate)
        return True

    def _extract_execution_recovery_facts_v4(
            self, *, closure, seal, credential):
        """Reopen and verify the old chain before asking installed original readers."""
        from ..runtime.c09_sanitized_recovery_extractor_v4 import (
            C09RecoveryFactsHold, extract_sanitized_recovery_facts_v4,
        )
        from ..runtime_contracts import canonical_digest
        from .v2_execution_journal import AuthorityV2ExecutionJournal

        port = self._execution_recovery_facts_ports_v4.get(seal.namespace)
        if port is None:
            raise AuthorityUnavailable("trusted V4 recovery originals unavailable")
        old = AuthorityV2ExecutionJournal.open_prepared_redaction_v3(
            closure.execution.path, namespace=seal.namespace,
            journal_id=seal.execution_journal_id, core=self,
            credential=credential)
        try:
            with closure.deletion.freeze_writes():
                with old.freeze_prepared_redaction_v3() as raw:
                    signed = self._verify_execution_redaction_c04_rows(
                        old, raw, journal_id=seal.execution_journal_id)
                    versions = set()
                    for entry in raw:
                        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX, decode_series_row_v1
                        if entry[4].startswith(SERIES_PREFIX):
                            binding, _, _ = decode_series_row_v1(old, entry)
                            versions.add((binding.numeric.algorithm_id, binding.numeric.algorithm_build_digest))
                        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3, decode_root_execution_row_v3
                        if entry[4].startswith(ROOT_ENTRY_PREFIX_V3):
                            binding, _, _ = decode_root_execution_row_v3(old, entry)
                            versions.add((binding.algorithm_id, binding.algorithm_build_digest))
                        from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3
                        if entry[4].startswith(ENTRY_PREFIX):
                            binding, _, _ = decode_numeric_row_v3(old, entry)
                            versions.add((binding.algorithm_id, binding.algorithm_build_digest))
                        if entry[4].startswith(b'{"binding":'):
                            binding, _, _ = old._decode_internal_row(entry)
                            versions.add((binding.algorithm_ref,
                                          binding.algorithm_build_digest))
                    verifier_commitment = canonical_digest((
                        "sylanne3.authority.c09_v4_verifier.v1",
                        seal.seal_digest, tuple(sorted(versions)), signed))
                    try:
                        freeze = getattr(port, "freeze_verified_originals_v4", None)
                        if not callable(freeze):
                            raise C09RecoveryFactsHold(("installed_freeze",))
                        with freeze(seal=seal, old=old, rows=raw,
                                    verifier_commitment=verifier_commitment):
                            facts = extract_sanitized_recovery_facts_v4(
                                port=port, namespace=seal.namespace,
                                operation_id=seal.operation_id)
                    except C09RecoveryFactsHold as exc:
                        raise AuthorityUnavailable(
                            "V4 recovery originals unavailable: "
                            + ", ".join(exc.missing)) from exc
                    if ((facts.authority_id, facts.installation_id,
                         facts.namespace, facts.operation_id,
                         facts.old_chain_head_digest,
                         facts.verifier_commitment) !=
                        (seal.authority_id, seal.installation_id,
                         seal.namespace, seal.operation_id,
                         seal.execution_digest, verifier_commitment)):
                        raise AuthorityUnavailable("V4 recovery facts anchor differs")
                    return facts
        finally:
            old.close()

    def pin_execution_recovery_facts_v4(
            self, *, credential, closure, subject: str,
            operation_id: str) -> ExecutionRecoveryFactsPinV4:
        """Pin complete V4 facts while the old PREPARED chain is still active."""
        from .erasure_closure_inventory import (
            AuthorityErasureClosureInventory, CleanupRunV2, _TABLES,
        )
        from ..runtime_contracts import canonical_serialize

        if (type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not self
                or closure.execution is not closure.scoped.execution
                or closure.deletion is not closure.scoped.deletion):
            raise AuthorityUnavailable("paired C09 closure service required")
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        namespace = closure.namespace
        self._require(credential, "execution_redaction_install", namespace)
        closure.qualify_current_registry_location_v1(
            credential=credential, subject=subject, operation_id=operation_id)
        with self._tx() as db:
            seal = read_execution_redaction_seal_locked(db, namespace)
            if (seal is None or seal.operation_id != operation_id
                    or read_execution_redaction_switch_locked(db, namespace)
                       is not None
                    or self._head(self._row(db, namespace), "execution") !=
                       JournalHead(seal.execution_journal_id,
                                   seal.execution_seq, seal.execution_digest)):
                raise AuthorityUnavailable("active V3 PREPARED old head required")
        facts = self._extract_execution_recovery_facts_v4(
            closure=closure, seal=seal, credential=credential)
        candidate = make_execution_recovery_facts_pin_v4(seal=seal, facts=facts)
        with self._tx() as db:
            if (read_execution_redaction_seal_locked(db, namespace) != seal
                    or read_execution_redaction_switch_locked(db, namespace)
                       is not None
                    or self._head(self._row(db, namespace), "execution") !=
                       JournalHead(seal.execution_journal_id,
                                   seal.execution_seq, seal.execution_digest)):
                raise AuthorityUnavailable("V4 PREPARED head changed before pin")
            run = closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable("accepted cleanup run absent")
            closure._registry_locked(db)
            closure._accepted_locked(db, run, subject)
            prior = read_execution_recovery_facts_pin_v4_locked(db, namespace)
            if prior is not None:
                if (prior != candidate
                        or read_execution_recovery_facts_v4_locked(
                            db, namespace) != facts):
                    raise AuthorityUnavailable("V4 facts pin replay differs")
                return prior
            db.execute(
                "INSERT INTO authority_execution_recovery_facts_pins_v4 "
                "(namespace,operation_id,pin_json) VALUES(?,?,?)",
                (namespace, operation_id,
                 canonical_serialize(asdict(candidate))))
            db.execute(
                "INSERT INTO authority_execution_recovery_facts_v4 "
                "(namespace,operation_id,facts_json) VALUES(?,?,?)",
                (namespace, operation_id,
                 canonical_serialize(asdict(facts))))
            self._event(db, namespace, "execution-recovery-facts-v4-pinned",
                        self._row(db, namespace)[1],
                        (operation_id, candidate.pin_digest))
            return candidate

    def verify_execution_recovery_facts_v4_for_rebase(
            self, *, credential, closure, subject: str,
            operation_id: str) -> ExecutionRecoveryFactsPinV4:
        """Independent current reread required by a future physical switch."""
        from .erasure_closure_inventory import (
            AuthorityErasureClosureInventory, CleanupRunV2, _TABLES,
        )

        if (type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not self
                or closure.execution is not closure.scoped.execution
                or closure.deletion is not closure.scoped.deletion):
            raise AuthorityUnavailable("paired C09 closure service required")
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        namespace = closure.namespace
        self._require(credential, "execution_redaction_install", namespace)
        closure.qualify_current_registry_location_v1(
            credential=credential, subject=subject, operation_id=operation_id)
        with self._tx() as db:
            seal = read_execution_redaction_seal_locked(db, namespace)
            pin = read_execution_recovery_facts_pin_v4_locked(db, namespace)
            if (seal is None or pin is None
                    or seal.operation_id != operation_id
                    or pin.operation_id != operation_id
                    or pin.seal_digest != seal.seal_digest
                    or read_execution_redaction_switch_locked(db, namespace)
                       is not None):
                raise AuthorityUnavailable("V4 PREPARED facts pin required")
        facts = self._extract_execution_recovery_facts_v4(
            closure=closure, seal=seal, credential=credential)
        if make_execution_recovery_facts_pin_v4(seal=seal, facts=facts) != pin:
            raise AuthorityUnavailable("V4 recovery facts changed after pin")
        with self._tx() as db:
            if (read_execution_redaction_seal_locked(db, namespace) != seal
                    or read_execution_recovery_facts_pin_v4_locked(db, namespace)
                       != pin
                    or read_execution_recovery_facts_v4_locked(
                        db, namespace) != facts
                    or read_execution_redaction_switch_locked(db, namespace)
                       is not None
                    or self._head(self._row(db, namespace), "execution") !=
                       JournalHead(seal.execution_journal_id,
                                   seal.execution_seq, seal.execution_digest)):
                raise AuthorityUnavailable("V4 PREPARED state changed on reread")
            run = closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable("accepted cleanup run absent")
            closure._registry_locked(db)
            closure._accepted_locked(db, run, subject)
            return pin

    def read_pinned_execution_recovery_facts_v4(
            self, *, credential, namespace: str, operation_id: str):
        """Cold-read the exact authenticated V4 fact set after old bytes go."""
        identifier(namespace, "namespace")
        identifier(operation_id, "operation_id")
        self._require(credential, "execution_redaction_install", namespace)
        with self._tx() as db:
            pin = read_execution_recovery_facts_pin_v4_locked(db, namespace)
            facts = read_execution_recovery_facts_v4_locked(db, namespace)
            if (pin is None or facts is None
                    or pin.operation_id != operation_id
                    or facts.operation_id != operation_id
                    or pin.authority_id != self._id(db)):
                raise AuthorityUnavailable("current V4 recovery facts absent")
            return facts

    def read_current_consumed_execution_v4(
            self, *, credential, namespace: str, operation_id: str,
            execution_id: str):
        """Read one old execution right and unknown constraint from Core facts.

        The fact is a cold recovery observation. It cannot grant a new send,
        reissue an old permit, or manufacture an absent terminal original.
        """
        identifier(namespace, "namespace")
        identifier(operation_id, "operation_id")
        identifier(execution_id, "execution_id")
        self._require(credential, "execution_redaction_install", namespace)
        with self._tx() as db:
            pin = read_execution_recovery_facts_pin_v4_locked(db, namespace)
            if (pin is None or pin.authority_id != self._id(db)
                    or pin.operation_id != operation_id):
                raise AuthorityUnavailable("current V4 execution pin absent")
            found = read_consumed_execution_fact_v4_locked(
                db, namespace, execution_id)
            if found is None or not found[0].consumed:
                raise AuthorityUnavailable("consumed execution right absent")
            return found

    def _verify_execution_redaction_c04_rows(
            self, journal, rows, *, journal_id: str) -> tuple[str, ...]:
        """Check each old internal row against its installed version and key."""
        from .internal_work_service import AuthorityInternalWorkService

        signed = []
        for entry in rows:
            from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX
            if entry[4].startswith(SERIES_PREFIX):
                series = self._execution_redaction_d04_series_services_v1.get(journal.namespace)
                if series is None:
                    raise AuthorityUnavailable("installed D04 series recovery verifier required")
                _binding, _claim, terminal = series.verify_series_journal_row_v1(journal, entry)
                if terminal is not None:
                    signed.append(entry[2])
                continue
            from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_PREFIX
            if entry[4].startswith(LIFE_PREFIX):
                life = self._execution_redaction_d11_life_services_v1.get(journal.namespace)
                if life is None:
                    raise AuthorityUnavailable("installed Life recovery verifier required")
                _binding, _claim, terminal = life.verify_life_journal_row_v1(journal, entry)
                if terminal is not None:
                    signed.append(entry[2])
                continue
            from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_PREFIX
            if entry[4].startswith(OFFLINE_PREFIX):
                offline = self._execution_redaction_d11_offline_services_v1.get(journal.namespace)
                if offline is None:
                    raise AuthorityUnavailable("installed offline tick recovery verifier required")
                _binding, _claim, terminal = offline.verify_offline_tick_journal_row_v1(journal, entry)
                if terminal is not None:
                    signed.append(entry[2])
                continue
            from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3
            if entry[4].startswith(ROOT_ENTRY_PREFIX_V3):
                root_service = self._execution_redaction_d04_root_services_v3.get(journal.namespace)
                if root_service is None:
                    raise AuthorityUnavailable("installed authored-root recovery verifier required")
                _binding, _claim, terminal = root_service.verify_root_journal_row_v3(journal, entry)
                if terminal is not None:
                    signed.append(entry[2])
                continue
            from .d04_numeric_journal_v3 import ENTRY_PREFIX
            if entry[4].startswith(ENTRY_PREFIX):
                numeric = self._execution_redaction_d04_numeric_services_v3.get(journal.namespace)
                if numeric is None:
                    raise AuthorityUnavailable("installed D04 numeric recovery verifier required")
                _binding, _claim, terminal = numeric.verify_numeric_journal_row_v3(journal, entry)
                if terminal is not None:
                    signed.append(entry[2])
                continue
            if not entry[4].startswith(b'{"binding":'):
                continue
            binding, claim, terminal = journal._decode_internal_row(entry)
            verifier = self._execution_redaction_c04_services.get(
                journal.namespace, {}).get(binding.algorithm_ref)
            if verifier is None and binding.algorithm_ref == "d06.association_activation.v2":
                verifier = self._execution_redaction_c04_service
            if (type(verifier) is not AuthorityInternalWorkService
                    or not verifier.installed_runtime_verified
                    or verifier._component_signing_key is None
                    or verifier.installed_algorithm_id != binding.algorithm_ref
                    or verifier.installed_build_digest !=
                       binding.algorithm_build_digest
                    or verifier.journal.namespace != journal.namespace
                    or verifier.journal.journal_id != journal_id
                    or verifier.journal.path.resolve() != journal.path.resolve()):
                raise AuthorityUnavailable("installed C04 terminal verifier required")
            if terminal is None:
                continue  # Open claim retains its unresolved obligation.
            if terminal.status == "unknown":
                if (terminal.algorithm_id != binding.algorithm_ref
                        or terminal.build_fingerprint !=
                           binding.algorithm_build_digest
                        or terminal.input_digest != binding.input_digest):
                    raise AuthorityUnavailable("unknown C04 terminal identity differs")
                continue  # Unknown cost is never inferred to be zero.
            if type(verifier).verify_installed_terminal(
                    verifier, binding, claim, terminal) is not True:
                raise AuthorityUnavailable("C04 terminal signature differs")
            signed.append(entry[2])
        return tuple(signed)

    def switch_execution_redaction_v3(
            self, *, credential, closure, subject: str,
            operation_id: str) -> ExecutionRedactionSwitchV3:
        """Installer-only old-head CAS to the pinned sanitized V3 identity.

        The old journal bytes are unchanged. Its ordinary entry stays blocked
        by PREPARED, including after this Core transaction commits.
        """
        from .erasure_closure_inventory import (
            AuthorityErasureClosureInventory, CleanupRunV2, _TABLES,
        )
        from .erasure_closure_sidecar_v3 import (
            _read_sidecar, _sanitize, redaction_facts_digest_v3,
            read_execution_sidecar_recovery_v3, sidecar_path_v3,
        )
        from .v2_execution_journal import AuthorityV2ExecutionJournal
        from ..runtime_contracts import canonical_digest, canonical_serialize

        if (type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not self
                or closure.execution is not closure.scoped.execution
                or closure.deletion is not closure.scoped.deletion):
            raise AuthorityUnavailable("paired C09 closure service required")
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        namespace = closure.namespace
        self._require(credential, "execution_redaction_install", namespace)
        closure.qualify_current_registry_location_v1(
            credential=credential, subject=subject, operation_id=operation_id)
        with self._tx() as db:
            prior = read_execution_redaction_switch_locked(db, namespace)
            if prior is not None:
                if (prior.operation_id != operation_id or
                        self._head(self._row(db, namespace), "execution") !=
                        JournalHead(prior.new_journal_id, prior.new_seq,
                                    prior.new_digest)):
                    raise AuthorityUnavailable("execution redaction switch replay differs")
            else:
                seal = read_execution_redaction_seal_locked(db, namespace)
                pin = read_execution_redaction_pin_locked(db, namespace)
                if (seal is None or pin is None
                        or seal.operation_id != operation_id
                        or pin.operation_id != operation_id
                        or pin.seal_digest != seal.seal_digest):
                    raise AuthorityUnavailable("pinned PREPARED sidecar required")
        if prior is not None:
            recovered = read_execution_sidecar_recovery_v3(
                core=self, credential=credential, namespace=namespace,
                operation_id=operation_id,
                old_journal_path=closure.execution.path)
            if (recovered.stage != "identity_switched_hold"
                    or recovered.switch != prior):
                raise AuthorityUnavailable("execution redaction switch replay differs")
            return prior
        old = AuthorityV2ExecutionJournal.open_prepared_redaction_v3(
            closure.execution.path, namespace=namespace,
            journal_id=seal.execution_journal_id, core=self,
            credential=credential)
        try:
            with closure.deletion.freeze_writes():
                with old.freeze_prepared_redaction_v3() as raw:
                    rows = _sanitize(old, seal, raw)
                    path = sidecar_path_v3(old.path, seal)
                    stored_rows, certificate = _read_sidecar(path, seal)
                    if stored_rows != rows:
                        raise AuthorityUnavailable("pinned sidecar facts differ from old chain")
                    signed = self._verify_execution_redaction_c04_rows(
                        old, raw, journal_id=seal.execution_journal_id)
                    with self._tx() as db:
                        current_seal = read_execution_redaction_seal_locked(
                            db, namespace)
                        current_pin = read_execution_redaction_pin_locked(
                            db, namespace)
                        if current_seal != seal or current_pin != pin:
                            raise AuthorityUnavailable("redaction originals changed")
                        run = closure._read_record(
                            db, _TABLES[1], operation_id, CleanupRunV2)
                        if run is None:
                            raise AuthorityUnavailable("accepted cleanup run absent")
                        closure._registry_locked(db)
                        closure._accepted_locked(db, run, subject)
                        owner = self._row(db, namespace)
                        old_head = JournalHead(
                            seal.execution_journal_id, seal.execution_seq,
                            seal.execution_digest)
                        if self._head(owner, "execution") != old_head:
                            raise AuthorityUnavailable("execution redaction old-head CAS differs")
                        if ((pin.sidecar_path, pin.certificate_digest,
                             pin.sanitized_head_digest, pin.row_count) !=
                            (str(path.resolve()), certificate.certificate_digest,
                             certificate.sanitized_head_digest, len(rows))):
                            raise AuthorityUnavailable("Core sidecar pin differs")
                        effects = tuple(db.execute(
                            "SELECT effect_id,state,conflict_keys_json,execution_seq "
                            "FROM authority_effects WHERE namespace=? ORDER BY effect_id",
                            (namespace,)))
                        facts = redaction_facts_digest_v3(rows, effects)
                        before_anchor = canonical_digest(asdict(
                            self._anchor(db, namespace, owner)))
                        new_head = JournalHead(
                            "redacted-v3-" + seal.seal_digest[:32],
                            seal.execution_seq,
                            "sha256:" + certificate.sanitized_head_digest)
                        db.execute(
                            "UPDATE authority_namespaces SET execution_journal_id=?,"
                            "execution_seq=?,execution_digest=?,anchor_nonce=? "
                            "WHERE namespace=? AND execution_journal_id=? "
                            "AND execution_seq=? AND execution_digest=?",
                            (new_head.journal_id, new_head.seq,
                             new_head.digest, self._new_nonce(), namespace,
                             old_head.journal_id, old_head.seq, old_head.digest))
                        if db.execute("SELECT changes()").fetchone() != (1,):
                            raise AuthorityUnavailable("execution redaction CAS lost")
                        after_anchor = canonical_digest(asdict(
                            self._anchor(db, namespace,
                                         self._row(db, namespace))))
                        shape = (
                            self._id(db), namespace, operation_id,
                            seal.seal_digest, pin.pin_digest,
                            certificate.certificate_digest,
                            old_head.journal_id, old_head.seq, old_head.digest,
                            new_head.journal_id, new_head.seq, new_head.digest,
                            facts, signed, before_anchor, after_anchor)
                        switch = ExecutionRedactionSwitchV3(
                            *shape, canonical_digest((
                                "sylanne3.authority.execution_redaction_switch.v3",
                                *shape, "identity_switched_hold")))
                        db.execute(
                            "INSERT INTO authority_execution_redaction_switches_v3 "
                            "(namespace,operation_id,switch_json) VALUES(?,?,?)",
                            (namespace, operation_id,
                             canonical_serialize(asdict(switch))))
                        self._event(db, namespace, "execution-redaction-switch-v3",
                                    owner[1], (operation_id, switch.switch_digest))
                        return switch
        finally:
            old.close()

    def register_namespace(self, credential, namespace: str, holder: str,
                           deletion: JournalHead, execution: JournalHead) -> ActivationProof:
        """Installer-only genesis after both independent journals are verified."""
        self._require(credential, "install", namespace, holder)
        with self._legacy_tx() as db:
            return self._register_namespace_locked(db, namespace, holder,
                                                   deletion, execution)

    def _register_namespace_locked(self, db, namespace: str, holder: str,
                                   deletion: JournalHead,
                                   execution: JournalHead) -> ActivationProof:
        self._verify_head("deletion", namespace, None, deletion, "clear")
        self._verify_head("execution", namespace, None, execution, None)
        if db.execute("SELECT 1 FROM authority_namespaces WHERE namespace=?",
                      (namespace,)).fetchone():
            raise AuthorityUnavailable("namespace already registered")
        db.execute(
            "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (namespace, holder, 1, "active", None, None, 0,
             deletion.journal_id, deletion.seq, deletion.digest, "clear",
             execution.journal_id, execution.seq, execution.digest,
             self._new_nonce()),
        )
        self._event(db, namespace, "install", 1, (holder, deletion.seq, execution.seq))
        return self._proof(db, namespace, self._row(db, namespace))

    def current(self, credential, namespace: str) -> ActivationProof:
        self._require(credential, "current", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            return self._proof(db, namespace, row)

    def current_anchor(self, credential, namespace: str) -> RestoreAnchor:
        self._require(credential, "anchor", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            return self._anchor(db, namespace, row)

    def verify_current(self, credential, anchor: RestoreAnchor) -> bool:
        if not isinstance(anchor, RestoreAnchor):
            return False
        self._require(credential, "anchor", anchor.namespace)
        with self._legacy_tx() as db:
            try:
                row = self._row(db, anchor.namespace)
                self._verify_current_heads(anchor.namespace, row)
                return self._anchor(db, anchor.namespace, row) == anchor
            except AuthorityUnavailable:
                return False

    def check(self, credential, *, namespace: str, holder: str,
              generation: int, operation: str) -> ActivationProof:
        if operation not in CONTENT_OPERATIONS or type(generation) is not int:
            raise AuthorityUnavailable("invalid content operation or generation")
        self._require(credential, operation, namespace, holder)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if (row[0] != holder or row[1] != generation or row[2] != "active"
                    or row[9] != "clear"):
                raise AuthorityUnavailable("holder, generation or deletion barrier is stale")
            return self._proof(db, namespace, row)

    def begin_content_operation(self, credential, *, namespace: str, holder: str,
                                generation: int, operation: str) -> ContentPermit:
        if operation not in CONTENT_OPERATIONS or type(generation) is not int:
            raise AuthorityUnavailable("invalid content operation or generation")
        self._require(credential, operation, namespace, holder)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if (row[0] != holder or row[1] != generation or row[2] != "active"
                    or row[9] != "clear"):
                raise AuthorityUnavailable("holder, generation or deletion barrier is stale")
            permit = ContentPermit(secrets.token_hex(32), namespace, holder,
                                   generation, operation)
            db.execute("INSERT INTO authority_permits VALUES(?,?,?,?,?)",
                       (permit.token, namespace, holder, generation, operation))
            return permit

    def end_content_operation(self, credential, permit: ContentPermit) -> None:
        if not isinstance(permit, ContentPermit):
            raise TypeError("permit must be ContentPermit")
        self._require(credential, "release", permit.namespace, permit.holder)
        with self._legacy_tx() as db:
            changed = db.execute(
                "DELETE FROM authority_permits WHERE token=? AND namespace=? "
                "AND holder=? AND generation=? AND operation=?",
                (permit.token, permit.namespace, permit.holder,
                 permit.generation, permit.operation),
            ).rowcount
            if changed != 1:
                raise AuthorityUnavailable("permit is absent or already released")

    def observe_deletion_head(self, credential, namespace: str,
                              expected: JournalHead, current: JournalHead,
                              phase: str) -> RestoreAnchor:
        if phase not in {"pending", "accepted", "clear"}:
            raise ValueError("invalid deletion barrier phase")
        self._require(credential, "deletion", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            if self._head(row, "deletion") != expected:
                raise AuthorityUnavailable("deletion head CAS failed")
            self._no_permits(db, namespace)
            self._verify_head("deletion", namespace, expected, current, phase)
            db.execute(
                "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
                "deletion_phase=?,revocation_epoch=revocation_epoch+1,anchor_nonce=? "
                "WHERE namespace=?",
                (current.seq, current.digest, phase, self._new_nonce(), namespace),
            )
            self._event(db, namespace, "deletion", row[1],
                        (current.seq, current.digest, phase))
            return self._anchor(db, namespace, self._row(db, namespace))

    def observe_execution_head(self, credential, namespace: str,
                               expected: JournalHead, current: JournalHead,
                               *, effect_id: str, state: str,
                               conflict_keys: tuple[str, ...]) -> RestoreAnchor:
        """Advance only after verifying the journal and its exact effect footprint."""
        identifier(effect_id, "effect_id")
        if state not in {"unresolved", "resolved"}:
            raise ValueError("effect state must be unresolved or resolved")
        keys = self._keys(conflict_keys)
        self._require(credential, "execution", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            if self._head(row, "execution") != expected:
                raise AuthorityUnavailable("execution head CAS failed")
            self._verify_head("execution", namespace, expected, current, None)
            try:
                verified = self._effect_verifier(namespace, effect_id, state,
                                                 keys, current)
            except Exception as exc:
                raise AuthorityUnavailable("execution footprint verification failed") from exc
            if verified is not True:
                raise AuthorityUnavailable("execution footprint is not verified")
            prior = db.execute(
                "SELECT state,conflict_keys_json FROM authority_effects WHERE "
                "namespace=? AND effect_id=?", (namespace, effect_id),
            ).fetchone()
            if prior is None:
                if state != "unresolved":
                    raise AuthorityUnavailable("effect cannot begin resolved")
                db.execute(
                    "INSERT INTO authority_effects VALUES(?,?,?,?,?)",
                    (namespace, effect_id, state, json.dumps(keys), current.seq),
                )
            else:
                if tuple(json.loads(prior[1])) != keys or prior[0] == "resolved":
                    raise AuthorityUnavailable("effect footprint changed or was resolved")
                db.execute(
                    "UPDATE authority_effects SET state=?,execution_seq=? "
                    "WHERE namespace=? AND effect_id=?",
                    (state, current.seq, namespace, effect_id),
                )
            db.execute(
                "UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,"
                "anchor_nonce=? WHERE namespace=?",
                (current.seq, current.digest, self._new_nonce(), namespace),
            )
            self._event(db, namespace, "execution", row[1],
                        (effect_id, state, current.seq, current.digest))
            return self._anchor(db, namespace, self._row(db, namespace))

    @staticmethod
    def _keys(keys: tuple[str, ...]) -> tuple[str, ...]:
        if not isinstance(keys, tuple) or len(keys) > 64:
            raise ValueError("conflict keys must be a bounded tuple")
        for key in keys:
            identifier(key, "conflict key")
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate conflict keys")
        return tuple(sorted(keys))

    def admit_dispatch(self, credential, *, namespace: str, holder: str,
                       generation: int, effect_id: str,
                       conflict_keys: tuple[str, ...],
                       permit: ContentPermit) -> None:
        """Read-only eligibility under a durable dispatch permit.

        This is still not a send token: business claim, journal preparation,
        current policy and platform handoff require their own receipts.
        """
        with self._legacy_tx() as db:
            self._admit_dispatch_locked(
                db, credential, namespace=namespace, holder=holder,
                generation=generation, effect_id=effect_id,
                conflict_keys=conflict_keys, permit=permit)

    def _admit_dispatch_locked(self, db, credential, *, namespace: str,
                               holder: str, generation: int, effect_id: str,
                               conflict_keys: tuple[str, ...],
                               permit: ContentPermit) -> None:
        self._require(credential, "dispatch", namespace, holder)
        identifier(effect_id, "effect_id")
        keys = self._keys(conflict_keys)
        if (not isinstance(permit, ContentPermit)
                or (permit.namespace, permit.holder, permit.generation,
                    permit.operation) != (namespace, holder, generation, "dispatch")):
            raise AuthorityUnavailable("current dispatch permit required")
        try:
            verified = self._dispatch_verifier(namespace, effect_id, keys)
        except Exception as exc:
            raise AuthorityUnavailable("dispatch constraint verification failed") from exc
        if verified is not True:
            raise AuthorityUnavailable("dispatch constraint set is not verified")
        row = self._row(db, namespace)
        self._verify_current_heads(namespace, row)
        if (row[0] != holder or row[1] != generation or row[2] != "active"
                or row[9] != "clear"):
            raise AuthorityUnavailable("dispatch holder or deletion barrier is stale")
        if not db.execute(
            "SELECT 1 FROM authority_permits WHERE token=? AND namespace=? "
            "AND holder=? AND generation=? AND operation='dispatch'",
            (permit.token, namespace, holder, generation),
        ).fetchone():
            raise AuthorityUnavailable("dispatch permit is no longer current")
        if db.execute(
            "SELECT 1 FROM authority_effects WHERE namespace=? AND effect_id=?",
            (namespace, effect_id),
        ).fetchone():
            raise AuthorityUnavailable("effect already has execution history; query original")
        for state, encoded in db.execute(
            "SELECT state,conflict_keys_json FROM authority_effects WHERE namespace=?",
            (namespace,),
        ):
            if state == "unresolved":
                prior = set(json.loads(encoded))
                if not prior or not keys or prior.intersection(keys):
                    raise AuthorityUnavailable("unresolved execution constraint blocks dispatch")

    def begin_transfer(self, credential, plan: TransferPlan,
                       *, expected_generation: int) -> ActivationProof:
        if not isinstance(plan, TransferPlan) or type(expected_generation) is not int:
            raise TypeError("typed transfer plan and expected generation required")
        self._require(credential, "transfer", plan.namespace, plan.source)
        with self._legacy_tx() as db:
            row = self._row(db, plan.namespace)
            self._verify_current_heads(plan.namespace, row)
            prior = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (plan.operation_id,),
            ).fetchone()
            if prior is not None:
                if prior[:4] != (plan.namespace, plan.source, plan.target,
                                 expected_generation):
                    raise AuthorityUnavailable("transfer ID reused with different plan")
                return self._proof(db, plan.namespace, row)
            if (row[0] != plan.source or row[1] != expected_generation
                    or row[2] != "active" or row[3] is not None):
                raise AuthorityUnavailable("source is not uniquely active at expected generation")
            db.execute(
                "INSERT INTO authority_transfers VALUES(?,?,?,?,?,?)",
                (plan.operation_id, plan.namespace, plan.source, plan.target,
                 expected_generation, "planned"),
            )
            db.execute(
                "UPDATE authority_namespaces SET transfer_id=?,target=?,anchor_nonce=? "
                "WHERE namespace=?",
                (plan.operation_id, plan.target, self._new_nonce(), plan.namespace),
            )
            self._event(db, plan.namespace, "transfer_planned", row[1],
                        (plan.operation_id, plan.source, plan.target))
            return self._proof(db, plan.namespace, self._row(db, plan.namespace))

    def revoke_source(self, credential, operation_id: str,
                      *, expected_generation: int) -> ActivationProof:
        identifier(operation_id, "operation_id")
        if type(expected_generation) is not int:
            raise TypeError("expected generation must be exact integer")
        with self._legacy_tx() as db:
            transfer = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if transfer is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace, source, _, base, phase = transfer
            self._require(credential, "revoke", namespace, source)
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if phase == "revoked":
                if (base != expected_generation or row[0] is not None
                        or row[1] != expected_generation + 1
                        or row[2] != "revoked" or row[3] != operation_id):
                    raise AuthorityUnavailable("revoked transfer replay differs from current state")
                return self._proof(db, namespace, row)
            if (phase != "planned" or base != expected_generation
                    or row[1] != expected_generation or row[0] != source
                    or row[3] != operation_id or row[2] != "active"):
                raise AuthorityUnavailable("source transfer CAS failed")
            self._no_permits(db, namespace)
            db.execute(
                "UPDATE authority_namespaces SET holder=NULL,generation=generation+1,"
                "phase='revoked',revocation_epoch=revocation_epoch+1,anchor_nonce=? "
                "WHERE namespace=?", (self._new_nonce(), namespace),
            )
            db.execute(
                "UPDATE authority_transfers SET phase='revoked' WHERE operation_id=?",
                (operation_id,),
            )
            self._event(db, namespace, "source_revoked", row[1] + 1, operation_id)
            return self._proof(db, namespace, self._row(db, namespace))

    def activate_target(self, credential, operation_id: str, *,
                        expected_revoked_generation: int,
                        deletion: JournalHead, execution: JournalHead) -> ActivationProof:
        identifier(operation_id, "operation_id")
        if type(expected_revoked_generation) is not int:
            raise TypeError("expected revoked generation must be exact integer")
        with self._legacy_tx() as db:
            transfer = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if transfer is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace, _, target, _, phase = transfer
            self._require(credential, "activate", namespace, target)
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if phase == "activated":
                if (row[0] != target or row[1] != expected_revoked_generation + 1
                        or row[2] != "active"
                        or self._head(row, "deletion") != deletion
                        or self._head(row, "execution") != execution):
                    raise AuthorityUnavailable("activated transfer replay differs from current state")
                return self._proof(db, namespace, row)
            if (phase != "revoked" or row[2] != "revoked" or row[0] is not None
                    or row[1] != expected_revoked_generation
                    or row[3] != operation_id
                    or self._head(row, "deletion") != deletion
                    or self._head(row, "execution") != execution
                    or row[9] != "clear"):
                raise AuthorityUnavailable("target activation requires current revoked heads")
            self._no_permits(db, namespace)
            db.execute(
                "UPDATE authority_namespaces SET holder=?,generation=generation+1,"
                "phase='active',transfer_id=NULL,target=NULL,anchor_nonce=? "
                "WHERE namespace=?", (target, self._new_nonce(), namespace),
            )
            db.execute(
                "UPDATE authority_transfers SET phase='activated' WHERE operation_id=?",
                (operation_id,),
            )
            self._event(db, namespace, "target_activated", row[1] + 1,
                        (operation_id, target))
            return self._proof(db, namespace, self._row(db, namespace))

    def recover_transfer(self, credential, operation_id: str) -> ActivationProof:
        identifier(operation_id, "operation_id")
        with self._legacy_tx() as db:
            row = db.execute(
                "SELECT namespace FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace = row[0]
            self._require(credential, "recover", namespace)
            current = self._row(db, namespace)
            self._verify_current_heads(namespace, current)
            return self._proof(db, namespace, current)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = ["AuthorityServiceCore"]
