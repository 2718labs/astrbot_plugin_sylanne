"""Scoped, transactional SQLite atom storage."""
import json
import sqlite3
import threading
from .contracts import (Scope, Atom, AtomVersion, Snapshot, CommitReceipt,
                        EventConflict, StaleRead, canonical_json, json_object, nonempty)

class Store:
    def __init__(self, path):
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute('PRAGMA busy_timeout=5000')
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA synchronous=FULL')
        self._db.executescript('''
            CREATE TABLE IF NOT EXISTS atoms (
                bot TEXT NOT NULL, persona TEXT NOT NULL, session TEXT NOT NULL,
                name TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), value TEXT NOT NULL,
                PRIMARY KEY(bot, persona, session, name));
            CREATE TABLE IF NOT EXISTS events (
                bot TEXT NOT NULL, persona TEXT NOT NULL, session TEXT NOT NULL,
                event_id TEXT NOT NULL, digest TEXT NOT NULL, revisions TEXT NOT NULL,
                PRIMARY KEY(bot, persona, session, event_id));
        ''')

    @staticmethod
    def _key(scope):
        if not isinstance(scope, Scope): raise TypeError('scope must be Scope')
        return scope.bot, scope.persona, scope.session

    def _ensure_open(self):
        if self._closed: raise RuntimeError('store is closed')

    def snapshot(self, scope, names):
        key = self._key(scope)
        names = tuple(names)
        for name in names: nonempty(name, 'atom name')
        if len(set(names)) != len(names): raise ValueError('duplicate snapshot names')
        with self._lock:
            self._ensure_open()
            self._db.execute('BEGIN')
            try:
                atoms = []
                for name in names:
                    row = self._db.execute('SELECT revision, value FROM atoms WHERE bot=? AND persona=? AND session=? AND name=?', key + (name,)).fetchone()
                    atoms.append(Atom(name, row[0], json.loads(row[1])) if row else Atom(name, 0, {}))
                self._db.execute('COMMIT')
                return Snapshot(scope, tuple(atoms))
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def commit(self, candidate):
        event = candidate.event
        key = self._key(event.scope)
        # Snapshot mutable write containers before acquiring the database transaction.
        digest = event.digest
        reads = tuple(candidate.reads)
        writes = tuple((write.name, canonical_json(json_object(write.value))) for write in candidate.writes)
        read_names = [read.name for read in reads]
        write_names = [name for name, _ in writes]
        for read in reads: AtomVersion(read.name, read.revision)
        for name in write_names: nonempty(name, 'atom name')
        if len(set(read_names)) != len(read_names) or len(set(write_names)) != len(write_names):
            raise ValueError('duplicate read or write names')
        if not set(write_names).issubset(read_names):
            raise ValueError('every write must have a read version')
        with self._lock:
            self._ensure_open()
            self._db.execute('BEGIN IMMEDIATE')
            try:
                prior = self._db.execute('SELECT digest, revisions FROM events WHERE bot=? AND persona=? AND session=? AND event_id=?', key + (event.event_id,)).fetchone()
                if prior:
                    if prior[0] != digest: raise EventConflict('event ID reused with different content')
                    result = CommitReceipt('duplicate', tuple(AtomVersion(*v) for v in json.loads(prior[1])))
                    self._db.execute('COMMIT')
                    return result
                for read in reads:
                    row = self._db.execute('SELECT revision FROM atoms WHERE bot=? AND persona=? AND session=? AND name=?', key + (read.name,)).fetchone()
                    actual = row[0] if row else 0
                    if actual != read.revision:
                        raise StaleRead(f'{read.name}: expected {read.revision}, observed {actual}')
                versions = {r.name: r.revision for r in reads}
                revisions = []
                for name, value in writes:
                    revision = versions[name] + 1
                    self._db.execute('''INSERT INTO atoms(bot,persona,session,name,revision,value) VALUES(?,?,?,?,?,?)
                        ON CONFLICT(bot,persona,session,name) DO UPDATE SET revision=excluded.revision,value=excluded.value''', key + (name, revision, value))
                    revisions.append(AtomVersion(name, revision))
                encoded = canonical_json([[r.name, r.revision] for r in revisions])
                self._db.execute('INSERT INTO events(bot,persona,session,event_id,digest,revisions) VALUES(?,?,?,?,?,?)', key + (event.event_id, digest, encoded))
                self._db.execute('COMMIT')
                return CommitReceipt('committed', tuple(revisions))
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def close(self):
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True
