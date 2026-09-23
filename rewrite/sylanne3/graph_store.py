"""Transactional typed graph storage on the foundation SQLite connection."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields

from .contracts import Event, EventConflict, StaleRead, canonical_json, json_object, nonempty
from .graph_types import (
    AtomKey,
    GraphAtom,
    GraphPage,
    GraphCandidate,
    GraphReceipt,
    GraphSnapshot,
    GraphVersion,
    NamespaceEpoch,
    TypeRegistry,
)
from .store import Store
from .runtime import install_schema as install_runtime_schema
from .runtime_contracts import NamespaceId, SnapshotRequirementsV2


@dataclass(frozen=True, slots=True)
class GraphRecoveryMetadataV2:
    """Stored comparison target and namespace commit stamp, not an Authority permit.

    Every protected business commit must advance graph_revision when its writer
    is connected to this seam; this storage slice does not connect those writers.
    """

    requirements: SnapshotRequirementsV2
    graph_revision: int

    def __post_init__(self):
        if type(self.requirements) is not SnapshotRequirementsV2:
            raise TypeError("requirements must be SnapshotRequirementsV2")
        if type(self.graph_revision) is not int or self.graph_revision < 0:
            raise ValueError("graph_revision must be a nonnegative integer")


class GraphStore(Store):
    """Adds a typed, multi-owner graph to :class:`Store`'s database and lock."""

    def __init__(self, path, registry: TypeRegistry):
        if not isinstance(registry, TypeRegistry):
            raise TypeError("registry must be TypeRegistry")
        self._registry = registry.freeze()
        super().__init__(path)
        with self._lock:
            try:
                self._create_graph_schema()
                self._db.execute("BEGIN IMMEDIATE")
                install_runtime_schema(self._db)
                self._check_catalog()
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                super().close()
                raise

    def _create_graph_schema(self):
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS graph_type_catalog (
                name TEXT PRIMARY KEY,
                owner_kinds TEXT NOT NULL,
                storage_role TEXT NOT NULL,
                immutable INTEGER NOT NULL CHECK(immutable IN (0, 1)),
                schema_version INTEGER NOT NULL CHECK(schema_version > 0));
            CREATE TABLE IF NOT EXISTS graph_atoms (
                token TEXT PRIMARY KEY,
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                owner_kind TEXT NOT NULL,
                subject TEXT,
                type_name TEXT NOT NULL,
                name TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                value TEXT NOT NULL,
                valid INTEGER NOT NULL CHECK(valid IN (0, 1)));
            CREATE INDEX IF NOT EXISTS graph_atoms_namespace
                ON graph_atoms(bot, persona);
            CREATE INDEX IF NOT EXISTS graph_atoms_namespace_type_token
                ON graph_atoms(bot, persona, type_name, token);
            CREATE TABLE IF NOT EXISTS graph_dependencies (
                dependent_token TEXT NOT NULL,
                dependency_token TEXT NOT NULL,
                dependency_revision INTEGER NOT NULL CHECK(dependency_revision >= 0),
                PRIMARY KEY(dependent_token, dependency_token),
                FOREIGN KEY(dependent_token) REFERENCES graph_atoms(token));
            CREATE INDEX IF NOT EXISTS graph_dependencies_reverse
                ON graph_dependencies(dependency_token);
            CREATE TABLE IF NOT EXISTS graph_epochs (
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 0),
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_events (
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                session TEXT NOT NULL,
                event_id TEXT NOT NULL,
                digest TEXT NOT NULL,
                reads TEXT NOT NULL,
                epoch_reads TEXT NOT NULL,
                revisions TEXT NOT NULL,
                invalidated TEXT NOT NULL,
                epoch_revision INTEGER NOT NULL CHECK(epoch_revision >= 0),
                PRIMARY KEY(bot, persona, session, event_id));
            CREATE TABLE IF NOT EXISTS graph_history (
                token TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                value TEXT NOT NULL,
                valid INTEGER NOT NULL CHECK(valid IN (0, 1)),
                dependencies TEXT NOT NULL,
                event_bot TEXT NOT NULL,
                event_persona TEXT NOT NULL,
                event_session TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY(token, revision),
                FOREIGN KEY(event_bot, event_persona, event_session, event_id)
                    REFERENCES graph_events(bot, persona, session, event_id));
            CREATE TABLE IF NOT EXISTS graph_type_authority (
                name TEXT PRIMARY KEY,
                writer_domain TEXT NOT NULL,
                schema_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS graph_authority_epochs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                access_epoch INTEGER NOT NULL DEFAULT 0,
                delete_epoch INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_guard_versions (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                kind TEXT NOT NULL, ref TEXT NOT NULL, version TEXT NOT NULL,
                PRIMARY KEY(bot, persona, kind, ref));
            CREATE TABLE IF NOT EXISTS graph_bundle_operations (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                activity_id TEXT NOT NULL, effect_id TEXT,
                commit_seq INTEGER NOT NULL, receipt_json TEXT NOT NULL,
                PRIMARY KEY(bot, persona, operation_id));
            CREATE TABLE IF NOT EXISTS graph_bundle_sequence (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                last_seq INTEGER NOT NULL,
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_bundle_refs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, ref_kind TEXT NOT NULL,
                ref TEXT NOT NULL,
                PRIMARY KEY(bot, persona, ref_kind, ref),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_operations(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_bundle_outbox (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                outbox_ref TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending','claimed','cancelled')),
                PRIMARY KEY(bot,persona,outbox_ref),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_operations(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_outbox_jobs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                outbox_ref TEXT NOT NULL, job_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                PRIMARY KEY(bot,persona,outbox_ref),
                FOREIGN KEY(job_id) REFERENCES runtime_jobs(job_id));
            CREATE TABLE IF NOT EXISTS graph_dependency_edges (
                dependent_token TEXT NOT NULL, dependency_token TEXT NOT NULL,
                dependency_revision INTEGER NOT NULL,
                edge_kind TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                PRIMARY KEY(dependent_token,dependency_token,edge_kind,operation_id));
            CREATE TABLE IF NOT EXISTS graph_recovery_metadata_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                schema TEXT NOT NULL CHECK(schema='sylanne3.authority.v2'),
                requirements_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL CHECK(graph_revision >= 0),
                PRIMARY KEY(bot,persona));
        """)

    @staticmethod
    def _catalog_row(spec):
        return (
            spec.name,
            canonical_json(sorted(spec.owner_kinds)),
            spec.storage_role,
            int(spec.immutable),
            spec.schema_version,
        )

    def _check_catalog(self):
        expected = tuple(self._catalog_row(spec) for spec in self._registry.specs)
        actual = tuple(self._db.execute(
            "SELECT name,owner_kinds,storage_role,immutable,schema_version "
            "FROM graph_type_catalog ORDER BY name"
        ).fetchall())
        if actual and actual != expected:
            raise ValueError("graph type catalog does not match this registry")
        if not actual:
            self._db.executemany(
                "INSERT INTO graph_type_catalog(name,owner_kinds,storage_role,immutable,schema_version) "
                "VALUES(?,?,?,?,?)", expected
            )
        authority = tuple(self._db.execute(
            "SELECT name,writer_domain,schema_hash FROM graph_type_authority ORDER BY name"
        ).fetchall())
        expected_authority = tuple((spec.name, spec.writer_domain or "",
                                    spec.schema_hash or "") for spec in self._registry.specs)
        if authority and authority != expected_authority:
            raise ValueError("graph type authority catalogue does not match this registry; migration required")
        if not authority:
            # Existing nonempty graphs have no writer provenance. Only a separate
            # reviewed migration may grant their types production write authority.
            count = self._db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone()[0]
            if count and any(spec.writer_domain for spec in self._registry.specs):
                raise ValueError("legacy graph requires explicit writer-authority migration")
            self._db.executemany(
                "INSERT INTO graph_type_authority(name,writer_domain,schema_hash) VALUES(?,?,?)",
                expected_authority,
            )

    def _validate_key(self, key: AtomKey):
        if not isinstance(key, AtomKey):
            raise TypeError("graph key must be AtomKey")
        spec = self._registry.spec(key.type_name)
        if key.owner.kind not in spec.owner_kinds:
            raise ValueError(
                f"type {spec.name!r} does not support owner kind {key.owner.kind!r}"
            )
        return spec

    @staticmethod
    def _namespace(key: AtomKey):
        return key.owner.bot, key.owner.persona

    def _require_coordinator(self, capability):
        if isinstance(self, ProductionGraphStore) and (
                capability is None or capability is not getattr(self, "_coordinator_capability", None)):
            raise PermissionError("production graph access requires GraphCoordinator")

    def _require_recovery_capability(self, capability):
        if (capability is None or
                capability is not getattr(self, "_coordinator_capability", None)):
            raise PermissionError("graph recovery metadata requires GraphCoordinator")

    @staticmethod
    def _recovery_payload(requirements):
        if type(requirements) is not SnapshotRequirementsV2:
            raise TypeError("requirements must be SnapshotRequirementsV2")
        return canonical_json(asdict(requirements))

    @staticmethod
    def _decode_recovery(row, namespace):
        if row is None:
            return None
        schema, encoded, revision = row
        data = json.loads(encoded)
        expected = {field.name for field in fields(SnapshotRequirementsV2)}
        if (schema != "sylanne3.authority.v2" or not isinstance(data, dict)
                or set(data) != expected or not isinstance(data["namespace"], dict)
                or set(data["namespace"]) != {"bot_id", "persona_id"}):
            raise ValueError("incompatible graph recovery metadata")
        data["namespace"] = NamespaceId(**data["namespace"])
        result = GraphRecoveryMetadataV2(SnapshotRequirementsV2(**data), revision)
        if result.requirements.namespace != namespace:
            raise ValueError("graph recovery metadata crosses namespace")
        return result

    def _recovery_row(self, namespace):
        return self._db.execute(
            "SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()

    def _has_namespace_history(self, namespace):
        """Reject genesis for scoped rows or legacy clocks without ownership."""
        # Clock rows have no namespace columns yet. Until that schema carries
        # ownership, any old clock row makes every namespace genesis ambiguous.
        unscoped_clocks = {
            "runtime_character_clocks", "runtime_clock_operations",
            "runtime_deadlines", "runtime_deadline_operations",
        }
        for (table,) in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            if table in {"graph_recovery_metadata_v2", "graph_type_catalog",
                         "graph_type_authority"}:
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            if table in unscoped_clocks:
                if self._db.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                    return True
                continue
            columns = {row[1] for row in self._db.execute(
                f"PRAGMA table_info({quoted})")}
            if {"bot", "persona"}.issubset(columns):
                pair = ("bot", "persona")
            elif {"bot_id", "persona_id"}.issubset(columns):
                pair = ("bot_id", "persona_id")
            elif {"event_bot", "event_persona"}.issubset(columns):
                pair = ("event_bot", "event_persona")
            else:
                continue
            if self._db.execute(
                    f'SELECT 1 FROM {quoted} WHERE {pair[0]}=? AND {pair[1]}=? LIMIT 1',
                    namespace.as_tuple).fetchone():
                return True
        return False

    def graph_recovery_metadata(self, namespace, *, _capability=None):
        """Read stored v2 requirements, never derive them from a current anchor."""
        self._require_recovery_capability(_capability)
        if type(namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        with self._lock:
            self._ensure_open()
            row = self._recovery_row(namespace)
            if row is None and self._has_namespace_history(namespace):
                raise RuntimeError("namespace has unsealed business state")
            return self._decode_recovery(row, namespace)

    def _install_graph_recovery_genesis_locked(self, requirements, *, _capability=None):
        """Stage genesis in the caller's existing business SQL transaction."""
        self._require_recovery_capability(_capability)
        encoded = self._recovery_payload(requirements)
        if (requirements.activation_generation == 0 or requirements.revocation_epoch != 0
                or requirements.deletion_seq != 0 or requirements.execution_seq != 0):
            raise ValueError("graph genesis requires an active zero-head snapshot")
        with self._lock:
            self._ensure_open()
            if not self._db.in_transaction:
                raise RuntimeError("graph genesis requires an active SQL transaction")
            if self._recovery_row(requirements.namespace) is not None:
                raise StaleRead("graph recovery metadata already installed")
            if self._has_namespace_history(requirements.namespace):
                raise RuntimeError("namespace has unsealed business state")
            self._db.execute(
                "INSERT INTO graph_recovery_metadata_v2"
                "(bot,persona,schema,requirements_json,graph_revision) "
                "VALUES(?,?,?,?,0)",
                requirements.namespace.as_tuple + (requirements.schema, encoded),
            )
            return GraphRecoveryMetadataV2(requirements, 0)

    def install_graph_recovery_genesis(self, requirements, *, _capability=None):
        """Install explicit zero-head metadata only for an empty namespace."""
        self._require_recovery_capability(_capability)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = self._install_graph_recovery_genesis_locked(
                    requirements, _capability=_capability)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return result

    def cas_graph_recovery_metadata(self, expected, replacement, *, _capability=None):
        """Advance the namespace commit stamp inside the caller's SQL transaction."""
        self._require_recovery_capability(_capability)
        if type(expected) is not GraphRecoveryMetadataV2:
            raise TypeError("expected must be GraphRecoveryMetadataV2")
        encoded = self._recovery_payload(replacement)
        before = expected.requirements
        if (replacement.namespace != before.namespace
                or replacement.authority_id != before.authority_id
                or replacement.authority_namespace != before.authority_namespace
                or replacement.activation_generation != before.activation_generation
                or replacement.deletion_journal_id != before.deletion_journal_id
                or replacement.execution_journal_id != before.execution_journal_id
                or replacement.graph_incarnation != before.graph_incarnation):
            raise StaleRead("graph recovery identity changed")
        if (replacement.deletion_seq < before.deletion_seq
                or replacement.execution_seq < before.execution_seq
                or replacement.revocation_epoch < before.revocation_epoch):
            raise StaleRead("graph recovery watermark regressed")
        with self._lock:
            self._ensure_open()
            if not self._db.in_transaction:
                raise RuntimeError("graph recovery CAS requires an active SQL transaction")
            changed = self._db.execute(
                "UPDATE graph_recovery_metadata_v2 SET requirements_json=?,"
                "graph_revision=graph_revision+1 WHERE bot=? AND persona=? "
                "AND schema=? AND requirements_json=? AND graph_revision=?",
                (encoded, *before.namespace.as_tuple, before.schema,
                 self._recovery_payload(before), expected.graph_revision),
            ).rowcount
            if changed != 1:
                raise StaleRead("graph recovery metadata changed")
            return GraphRecoveryMetadataV2(replacement, expected.graph_revision + 1)

    def graph_epoch(self, bot, persona, *, _capability=None):
        self._require_coordinator(_capability)
        nonempty(bot, "bot")
        nonempty(persona, "persona")
        with self._lock:
            self._ensure_open()
            row = self._db.execute(
                "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", (bot, persona)
            ).fetchone()
            return NamespaceEpoch(bot, persona, row[0] if row else 0)

    def graph_snapshot(self, keys, *, _capability=None):
        self._require_coordinator(_capability)
        keys = tuple(keys)
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate graph snapshot keys")
        for key in keys:
            self._validate_key(key)
        namespaces = tuple(dict.fromkeys(self._namespace(key) for key in keys))
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN")
            try:
                atoms = []
                for key in keys:
                    row = self._db.execute(
                        "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)
                    ).fetchone()
                    atoms.append(
                        GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                        if row else GraphAtom(key, 0, {}, False)
                    )
                epochs = []
                for bot, persona in namespaces:
                    row = self._db.execute(
                        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                        (bot, persona),
                    ).fetchone()
                    epochs.append(NamespaceEpoch(bot, persona, row[0] if row else 0))
                self._db.execute("COMMIT")
                return GraphSnapshot(tuple(atoms), tuple(epochs))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise


    @staticmethod
    def _version_rows(encoded):
        return tuple(GraphVersion(AtomKey.from_token(token), revision)
                     for token, revision in json.loads(encoded))

    def graph_event_receipt(self, event, *, _capability=None):
        self._require_coordinator(_capability)
        if not isinstance(event, Event):
            raise TypeError('event must be Event')
        digest = event.digest
        scope = event.scope
        with self._lock:
            self._ensure_open()
            prior = self._db.execute(
                'SELECT digest,revisions,invalidated,epoch_revision FROM graph_events '
                'WHERE bot=? AND persona=? AND session=? AND event_id=?',
                (scope.bot, scope.persona, scope.session, event.event_id)).fetchone()
            if prior is None:
                return None
            if prior[0] != digest:
                raise EventConflict('event ID reused with different content')
            return GraphReceipt('duplicate', self._version_rows(prior[1]),
                self._version_rows(prior[2]), NamespaceEpoch(scope.bot, scope.persona, prior[3]))

    def graph_query(self, bot, persona, *, type_names=(), owner_kind=None,
                    subject=None, after=None, limit=100, expected_epoch=None,
                    include_invalid=False, _capability=None):
        self._require_coordinator(_capability)
        nonempty(bot, 'bot')
        nonempty(persona, 'persona')
        if type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError('limit must be an integer from 1 to 512')
        if type(include_invalid) is not bool:
            raise TypeError('include_invalid must be bool')
        if not isinstance(type_names, tuple) or len(set(type_names)) != len(type_names):
            raise ValueError('type_names must be a unique tuple')
        for name in type_names:
            self._registry.spec(name)
        if owner_kind is not None and owner_kind not in ('persona', 'relation', 'scene', 'event', 'activity'):
            raise ValueError('unknown owner kind')
        if subject is not None:
            nonempty(subject, 'subject')
        if after is not None:
            self._validate_key(after)
            if self._namespace(after) != (bot, persona):
                raise ValueError('cursor crosses namespace')
        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError('expected_epoch must be NamespaceEpoch')
            if (expected_epoch.bot, expected_epoch.persona) != (bot, persona):
                raise ValueError('epoch crosses namespace')
        clauses, args = ['bot=?', 'persona=?'], [bot, persona]
        if type_names:
            clauses.append('type_name IN (' + ','.join('?' for _ in type_names) + ')')
            args.extend(type_names)
        for column, value in (('owner_kind', owner_kind), ('subject', subject)):
            if value is not None:
                clauses.append(column + '=?')
                args.append(value)
        if not include_invalid:
            clauses.append('valid=1')
        if after is not None:
            clauses.append('token>?')
            args.append(after.token)
        args.append(limit + 1)
        with self._lock:
            self._ensure_open()
            self._db.execute('BEGIN')
            try:
                epoch = GraphStore.graph_epoch(self, bot, persona, _capability=_capability)
                if expected_epoch is not None and epoch != expected_epoch:
                    raise StaleRead('query namespace changed between pages')
                rows = self._db.execute(
                    'SELECT token,revision,value,valid FROM graph_atoms WHERE '
                    + ' AND '.join(clauses) + ' ORDER BY token LIMIT ?', args).fetchall()
                atoms = tuple(GraphAtom(AtomKey.from_token(row[0]), row[1],
                    json.loads(row[2]), bool(row[3])) for row in rows[:limit])
                next_after = atoms[-1].key if len(rows) > limit else None
                self._db.execute('COMMIT')
                return GraphPage(GraphSnapshot(atoms, (epoch,)), next_after)
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def _current_revision(self, token):
        row = self._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?", (token,)
        ).fetchone()
        return row[0] if row else 0

    def _reverse_closure(self, seeds):
        """Follow old reverse edges even through keys that will be rewritten."""
        seen = set(seeds)
        closure = set()
        pending = list(seeds)
        while pending:
            token = pending.pop()
            rows = self._db.execute(
                "SELECT dependent_token FROM graph_dependencies WHERE dependency_token=?",
                (token,),
            ).fetchall()
            for (dependent,) in rows:
                closure.add(dependent)
                if dependent not in seen:
                    seen.add(dependent)
                    pending.append(dependent)
        return closure

    def _assert_acyclic(self, namespace, replacements):
        bot, persona = namespace
        nodes = {
            row[0]: set() for row in self._db.execute(
                "SELECT token FROM graph_atoms WHERE bot=? AND persona=?", (bot, persona)
            )
        }
        for dependent, dependency in self._db.execute(
            "SELECT d.dependent_token,d.dependency_token FROM graph_dependencies d "
            "JOIN graph_atoms a ON a.token=d.dependent_token WHERE a.bot=? AND a.persona=?",
            (bot, persona),
        ):
            nodes.setdefault(dependent, set()).add(dependency)
            nodes.setdefault(dependency, set())
        for token, dependencies in replacements.items():
            nodes[token] = set(dependencies)
            for dependency in dependencies:
                nodes.setdefault(dependency, set())
        # Kahn's algorithm avoids Python's recursion ceiling for long memory chains.
        indegree = {token: 0 for token in nodes}
        for dependencies in nodes.values():
            for dependency in dependencies:
                indegree[dependency] += 1
        ready = [token for token, degree in indegree.items() if degree == 0]
        visited = 0
        while ready:
            token = ready.pop()
            visited += 1
            for dependency in nodes[token]:
                indegree[dependency] -= 1
                if indegree[dependency] == 0:
                    ready.append(dependency)
        if visited != len(nodes):
            raise ValueError("instantaneous dependency cycle")

    def graph_commit(self, candidate: GraphCandidate, *, _guard=None, _receipt_hook=None,
                     _capability=None):
        self._require_coordinator(_capability)
        if not isinstance(candidate, GraphCandidate):
            raise TypeError("candidate must be GraphCandidate")
        event = candidate.event
        namespace = (event.scope.bot, event.scope.persona)
        reads = tuple(candidate.reads)
        writes = tuple(candidate.writes)
        epochs = tuple(candidate.epochs)
        read_keys = [read.key for read in reads]
        write_keys = [write.key for write in writes]
        if len(set(read_keys)) != len(read_keys):
            raise ValueError("duplicate graph reads")
        if len(set(write_keys)) != len(write_keys):
            raise ValueError("duplicate graph writes")
        if len({(epoch.bot, epoch.persona) for epoch in epochs}) != len(epochs):
            raise ValueError("duplicate namespace epochs")
        if not set(write_keys).issubset(read_keys):
            raise ValueError("every graph write must have a read version")
        for read in reads:
            self._validate_key(read.key)
            if self._namespace(read.key) != namespace:
                raise ValueError("cross-namespace graph candidate")
        for epoch in epochs:
            if (epoch.bot, epoch.persona) != namespace:
                raise ValueError("cross-namespace epoch")
        read_set = set(read_keys)
        prepared = []
        for write in writes:
            spec = self._validate_key(write.key)
            if self._namespace(write.key) != namespace:
                raise ValueError("cross-namespace graph candidate")
            if any(self._namespace(key) != namespace for key in write.dependencies):
                raise ValueError("cross-namespace dependency")
            if not set(write.dependencies).issubset(read_set):
                raise ValueError("dependencies must belong to the complete read set")
            if spec.immutable and write.dependencies:
                raise ValueError("immutable graph atoms cannot have invalidating dependencies")
            prepared.append((write, spec, canonical_json(self._registry.validate(write.key, write.value))))
        # The Event is the idempotency unit. A retry may legitimately rebuild its
        # candidate from the now-current snapshot, so candidate CAS material is
        # retained for audit but is not part of the event conflict digest.
        digest = event.digest
        scope_key = (event.scope.bot, event.scope.persona, event.scope.session, event.event_id)

        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if _guard is not None:
                    _guard(self._db)
                prior = self._db.execute(
                    "SELECT digest,revisions,invalidated,epoch_revision FROM graph_events "
                    "WHERE bot=? AND persona=? AND session=? AND event_id=?", scope_key
                ).fetchone()
                if prior:
                    if prior[0] != digest:
                        raise EventConflict("event ID reused with different graph candidate")
                    receipt = GraphReceipt(
                        "duplicate", self._version_rows(prior[1]),
                        self._version_rows(prior[2]),
                        NamespaceEpoch(namespace[0], namespace[1], prior[3]),
                    )
                    if _receipt_hook is not None:
                        _receipt_hook(self._db, receipt)
                    self._db.execute("COMMIT")
                    return receipt

                for read in reads:
                    actual = self._current_revision(read.key.token)
                    if actual != read.revision:
                        raise StaleRead(
                            f"{read.key.token}: expected {read.revision}, observed {actual}"
                        )
                epoch_row = self._db.execute(
                    "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace
                ).fetchone()
                current_epoch = epoch_row[0] if epoch_row else 0
                for epoch in epochs:
                    if epoch.revision != current_epoch:
                        raise StaleRead(
                            f"namespace epoch: expected {epoch.revision}, observed {current_epoch}"
                        )
                for write, spec, _ in prepared:
                    if spec.immutable and self._current_revision(write.key.token) != 0:
                        raise ValueError(f"immutable graph atom already exists: {write.key.token}")

                write_tokens = {write.key.token for write in writes}
                closure = self._reverse_closure(write_tokens)
                to_invalidate = closure - write_tokens
                replacements = {
                    write.key.token: tuple(key.token for key in write.dependencies)
                    for write in writes
                }
                self._assert_acyclic(namespace, replacements)

                post_revisions = {read.key.token: read.revision for read in reads}
                for write in writes:
                    post_revisions[write.key.token] = post_revisions[write.key.token] + 1
                post_valid = {}
                for token in to_invalidate:
                    row = self._db.execute(
                        "SELECT valid FROM graph_atoms WHERE token=?", (token,)
                    ).fetchone()
                    post_valid[token] = False if row else False
                for write in writes:
                    post_valid[write.key.token] = True
                for write in writes:
                    for dependency in write.dependencies:
                        token = dependency.token
                        if token in post_valid:
                            valid = post_valid[token]
                        else:
                            row = self._db.execute(
                                "SELECT valid FROM graph_atoms WHERE token=?", (token,)
                            ).fetchone()
                            # Revision-zero dependencies are explicit observations of
                            # absence. They remain valid until that key first appears,
                            # at which point the reverse edge invalidates the dependent.
                            valid = bool(row[0]) if row else True
                        if not valid:
                            raise ValueError(
                                f"dependency is absent or invalid after transaction: {token}"
                            )

                invalidation_rows = []
                for token in sorted(to_invalidate):
                    row = self._db.execute(
                        "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (token,)
                    ).fetchone()
                    if row and row[2]:
                        invalidation_rows.append((token, row[0] + 1, row[1]))

                state_changed = bool(writes or invalidation_rows)
                new_epoch = current_epoch + int(state_changed)
                revisions = tuple(
                    GraphVersion(write.key, post_revisions[write.key.token]) for write in writes
                )
                invalidated = tuple(
                    GraphVersion(AtomKey.from_token(token), revision)
                    for token, revision, _ in invalidation_rows
                )
                reads_json = canonical_json([[r.key.token, r.revision] for r in reads])
                epoch_reads_json = canonical_json(
                    [[e.bot, e.persona, e.revision] for e in epochs]
                )
                revisions_json = canonical_json(
                    [[r.key.token, r.revision] for r in revisions]
                )
                invalidated_json = canonical_json(
                    [[r.key.token, r.revision] for r in invalidated]
                )
                self._db.execute(
                    "INSERT INTO graph_events(bot,persona,session,event_id,digest,reads,epoch_reads,"
                    "revisions,invalidated,epoch_revision) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    scope_key + (digest, reads_json, epoch_reads_json, revisions_json,
                                 invalidated_json, new_epoch),
                )

                for write, _, value_json in prepared:
                    token = write.key.token
                    revision = post_revisions[token]
                    owner = write.key.owner
                    self._db.execute(
                        "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,"
                        "revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1) "
                        "ON CONFLICT(token) DO UPDATE SET revision=excluded.revision,"
                        "value=excluded.value,valid=1",
                        (token, owner.bot, owner.persona, owner.kind, owner.subject,
                         write.key.type_name, write.key.name, revision, value_json),
                    )
                    self._db.execute(
                        "DELETE FROM graph_dependencies WHERE dependent_token=?", (token,)
                    )
                    dependency_rows = []
                    for dependency in write.dependencies:
                        dep_revision = post_revisions.get(dependency.token)
                        if dep_revision is None:
                            dep_revision = self._current_revision(dependency.token)
                        dependency_rows.append((token, dependency.token, dep_revision))
                    self._db.executemany(
                        "INSERT INTO graph_dependencies(dependent_token,dependency_token,"
                        "dependency_revision) VALUES(?,?,?)", dependency_rows
                    )
                    dependencies_json = canonical_json(
                        [[dependency, revision] for _, dependency, revision in dependency_rows]
                    )
                    self._db.execute(
                        "INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,"
                        "event_persona,event_session,event_id) VALUES(?,?,?,?,?,?,?,?,?)",
                        (token, revision, value_json, 1, dependencies_json) + scope_key,
                    )

                for token, revision, value_json in invalidation_rows:
                    self._db.execute(
                        "UPDATE graph_atoms SET revision=?,valid=0 WHERE token=?",
                        (revision, token),
                    )
                    dependencies = self._db.execute(
                        "SELECT dependency_token,dependency_revision FROM graph_dependencies "
                        "WHERE dependent_token=? ORDER BY dependency_token", (token,)
                    ).fetchall()
                    self._db.execute(
                        "INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,"
                        "event_persona,event_session,event_id) VALUES(?,?,?,?,?,?,?,?,?)",
                        (token, revision, value_json, 0,
                         canonical_json([list(row) for row in dependencies])) + scope_key,
                    )

                if state_changed:
                    self._db.execute(
                        "INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,?) "
                        "ON CONFLICT(bot,persona) DO UPDATE SET revision=excluded.revision",
                        namespace + (new_epoch,),
                    )
                receipt = GraphReceipt(
                    "committed", revisions, invalidated,
                    NamespaceEpoch(namespace[0], namespace[1], new_epoch),
                )
                if _receipt_hook is not None:
                    _receipt_hook(self._db, receipt)
                self._db.execute("COMMIT")
                return receipt
            except BaseException:
                self._db.execute("ROLLBACK")
                raise


class ProductionGraphStore(GraphStore):
    """Production-facing class that closes legacy untyped and direct graph APIs.

    Host setup keeps the store private and passes domain code a coordinator.
    Python module internals remain part of the trusted computing base.
    """

    @staticmethod
    def _deny():
        raise PermissionError("production graph access requires GraphCoordinator")

    def snapshot(self, *args, **kwargs):
        self._deny()

    def commit(self, *args, **kwargs):
        self._deny()

    def graph_snapshot(self, *args, **kwargs):
        self._deny()

    def graph_epoch(self, *args, **kwargs):
        self._deny()

    def graph_query(self, *args, **kwargs):
        self._deny()

    def graph_event_receipt(self, *args, **kwargs):
        self._deny()

    def graph_commit(self, *args, **kwargs):
        self._deny()
