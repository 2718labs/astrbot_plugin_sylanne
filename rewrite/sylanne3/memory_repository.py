"""Access-safe source and interpretation repository over :mod:`graph_store`."""

from __future__ import annotations

import json
import math

from .contracts import CapacityExceeded, Event, nonempty
from .graph_store import GraphStore
from .graph_types import (
    GraphAtom,
    GraphCandidate,
    GraphSnapshot,
    GraphVersion,
    GraphWrite,
    NamespaceEpoch,
)
from .memory_types import (
    InterpretationRecord,
    SourceRecord,
    access_key,
    interpretation_key,
    source_key,
    validate_access,
)


_MAX_MUTATION_ATOMS = 4096


def _time(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite nonnegative real number")


class MemoryRepository:
    """Stores immutable evidence and revisable interpretations in one namespace."""

    def __init__(self, store, bot, persona):
        if not isinstance(store, GraphStore):
            raise TypeError("store must be GraphStore")
        nonempty(bot, "bot")
        nonempty(persona, "persona")
        self.store = store
        self._store = store
        self.bot = bot
        self.persona = persona

    def _event(self, event, operation, arguments):
        if not isinstance(event, Event):
            raise TypeError("event must be Event")
        if (event.scope.bot, event.scope.persona) != (self.bot, self.persona):
            raise ValueError("event scope does not match repository namespace")
        payload = {
            "memory_repository": {
                "operation": operation,
                "arguments": arguments,
                "original_event_digest": event.digest,
            }
        }
        return Event(event.scope, event.event_id, event.occurred_at,
                     f"memory.repository.{operation}", payload)

    @staticmethod
    def _max_nodes(value):
        if type(value) is not int:
            raise TypeError("max_nodes must be an exact integer")
        if not 1 <= value <= 4096:
            raise ValueError("max_nodes must be from 1 to 4096")
        return value

    def _epoch_locked(self):
        row = self._store._db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            (self.bot, self.persona),
        ).fetchone()
        return NamespaceEpoch(self.bot, self.persona, row[0] if row else 0)

    def _atom_locked(self, key, atoms, max_nodes):
        prior = atoms.get(key)
        if prior is not None:
            return prior
        if len(atoms) >= max_nodes:
            raise CapacityExceeded("memory ancestry exceeds max_nodes")
        row = self._store._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (key.token,),
        ).fetchone()
        atom = (GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                if row else GraphAtom(key, 0, {}, False))
        atoms[key] = atom
        return atom

    @staticmethod
    def _source_from_atom(atom, expected_id):
        if atom.revision == 0 or not atom.valid:
            return None
        record = SourceRecord.from_dict(atom.value)
        if record.source_id != expected_id:
            raise ValueError("source payload identity does not match graph key")
        return record

    @staticmethod
    def _access_from_atom(atom, expected_id):
        if atom.revision == 0 or not atom.valid:
            return None
        validate_access(atom.value)
        if atom.value["source_id"] != expected_id:
            raise ValueError("access payload identity does not match graph key")
        return atom.value

    @staticmethod
    def _interpretation_from_atom(atom, expected_id):
        if atom.revision == 0:
            return None
        record = InterpretationRecord.from_dict(atom.value)
        if record.interpretation_id != expected_id:
            raise ValueError("interpretation payload identity does not match graph key")
        return record

    def _read_sources_locked(self, source_ids, atoms, max_nodes):
        """Return every unique source/access reachable from ``source_ids``."""
        records = {}
        accesses = {}
        pending = list(reversed(tuple(source_ids)))
        while pending:
            source_id = pending.pop()
            if source_id in records:
                continue
            source_atom = self._atom_locked(
                source_key(self.bot, self.persona, source_id), atoms, max_nodes)
            access_atom = self._atom_locked(
                access_key(self.bot, self.persona, source_id), atoms, max_nodes)
            source = self._source_from_atom(source_atom, source_id)
            access = self._access_from_atom(access_atom, source_id)
            records[source_id] = source
            accesses[source_id] = access
            if source is not None:
                pending.extend(reversed(source.parent_source_ids))
        return records, accesses

    def _coherent_sources(self, source_ids, max_nodes, bound_event=None):
        max_nodes = self._max_nodes(max_nodes)
        atoms = {}
        with self._store._lock:
            self._store._ensure_open()
            self._store._db.execute("BEGIN")
            try:
                duplicate = (self._store.graph_event_receipt(bound_event)
                             if bound_event is not None else None)
                if duplicate is not None:
                    self._store._db.execute("COMMIT")
                    return {}, {}, (), duplicate.epoch, duplicate
                records, accesses = self._read_sources_locked(
                    source_ids, atoms, max_nodes)
                epoch = self._epoch_locked()
                self._store._db.execute("COMMIT")
            except BaseException:
                self._store._db.execute("ROLLBACK")
                raise
        return records, accesses, tuple(atoms.values()), epoch, duplicate

    @staticmethod
    def _lineage_permits(root_ids, records, accesses, audience=None, purpose=None,
                         as_known_at=None):
        pending = list(root_ids)
        visited = set()
        while pending:
            source_id = pending.pop()
            if source_id in visited:
                continue
            visited.add(source_id)
            source = records.get(source_id)
            access = accesses.get(source_id)
            if source is None or access is None or access["status"] != "active":
                return False
            if audience is not None and audience not in access["audiences"]:
                return False
            if purpose is not None and purpose not in access["purposes"]:
                return False
            if as_known_at is not None and source.recorded_at > as_known_at:
                return False
            pending.extend(source.parent_source_ids)
        return True

    @staticmethod
    def _proof(atoms, epoch):
        return GraphSnapshot(
            tuple(GraphAtom(atom.key, atom.revision, {}, atom.valid) for atom in atoms),
            (epoch,),
        )

    def ingest(self, event, source):
        if not isinstance(source, SourceRecord):
            raise TypeError("source must be SourceRecord")
        bound = self._event(event, "ingest", {"source": source.to_dict()})
        records, accesses, atoms, epoch, duplicate = self._coherent_sources(
            (source.source_id,) + source.parent_source_ids,
            _MAX_MUTATION_ATOMS, bound)
        if duplicate is not None:
            return duplicate
        if records[source.source_id] is not None:
            raise ValueError("source ID already exists")
        for parent_id in source.parent_source_ids:
            if records.get(parent_id) is None or accesses.get(parent_id) is None:
                raise ValueError("parent source does not exist")
        if not self._lineage_permits(source.parent_source_ids, records, accesses):
            raise ValueError("parent source access is not active")

        for parent_id, parent_access in accesses.items():
            if parent_id == source.source_id:
                continue
            if not set(source.audiences).issubset(parent_access["audiences"]):
                raise ValueError("child source may not broaden parent audiences")
            if not set(source.purposes).issubset(parent_access["purposes"]):
                raise ValueError("child source may not broaden parent purposes")
        if source.source_kind != "simulated":
            if any(record is not None and record.source_kind == "simulated"
                   for record in records.values()):
                raise ValueError("simulated provenance cannot become non-simulated")

        source_k = source_key(self.bot, self.persona, source.source_id)
        access_k = access_key(self.bot, self.persona, source.source_id)
        initial_access = {
            "source_id": source.source_id,
            "audiences": list(source.audiences),
            "purposes": list(source.purposes),
            "status": "active",
            "recorded_at": source.recorded_at,
        }
        validate_access(initial_access)
        writes = (
            GraphWrite(source_k, source.to_dict()),
            GraphWrite(access_k, initial_access, (source_k,)),
        )
        return self._store.graph_commit(GraphCandidate(
            bound, tuple(_version(atom) for atom in atoms), writes, (epoch,)
        ))

    def interpret(self, event, record):
        if not isinstance(record, InterpretationRecord):
            raise TypeError("record must be InterpretationRecord")
        bound = self._event(event, "interpret", {"record": record.to_dict()})
        key = interpretation_key(self.bot, self.persona, record.interpretation_id)
        max_nodes = _MAX_MUTATION_ATOMS
        atoms = {}
        with self._store._lock:
            self._store._ensure_open()
            self._store._db.execute("BEGIN")
            try:
                duplicate = self._store.graph_event_receipt(bound)
                if duplicate is not None:
                    self._store._db.execute("COMMIT")
                    return duplicate
                current_atom = self._atom_locked(key, atoms, max_nodes)
                current = self._interpretation_from_atom(
                    current_atom, record.interpretation_id)
                records, accesses = self._read_sources_locked(
                    record.source_ids, atoms, max_nodes)
                epoch = self._epoch_locked()
                self._store._db.execute("COMMIT")
            except BaseException:
                self._store._db.execute("ROLLBACK")
                raise
        if current is not None and record.recorded_at <= current.recorded_at:
            raise ValueError("interpretation recorded_at must strictly advance")
        if not self._lineage_permits(record.source_ids, records, accesses):
            raise ValueError("interpretation sources require active access")
        if record.status == "confirmed" and not any(
            records[source_id].source_kind == "observed"
            and records[source_id].assertion_status == "confirmed"
            for source_id in record.source_ids
        ):
            raise ValueError("confirmed interpretation requires confirmed observed support")
        dependencies = tuple(atom.key for atom in atoms.values()
                             if atom.key != key)
        return self._store.graph_commit(GraphCandidate(
            bound, tuple(_version(atom) for atom in atoms.values()),
            (GraphWrite(key, record.to_dict(), dependencies),), (epoch,)
        ))

    def set_access(self, event, source_id, *, audiences, purposes, status, recorded_at):
        nonempty(source_id, "source_id")
        if not isinstance(audiences, tuple) or not isinstance(purposes, tuple):
            raise TypeError("audiences and purposes must be tuples")
        value = {"source_id": source_id, "audiences": list(audiences),
                 "purposes": list(purposes), "status": status,
                 "recorded_at": recorded_at}
        validate_access(value)
        bound = self._event(event, "set_access", value)
        records, accesses, atoms, epoch, duplicate = self._coherent_sources(
            (source_id,), _MAX_MUTATION_ATOMS, bound)
        if duplicate is not None:
            return duplicate
        source = records.get(source_id)
        prior = accesses.get(source_id)
        if source is None or prior is None:
            raise ValueError("source does not exist")
        if recorded_at <= prior["recorded_at"]:
            raise ValueError("access recorded_at must strictly advance")
        if status == "active":
            for parent_id, parent_access in accesses.items():
                if parent_id == source_id:
                    continue
                if parent_access is None or parent_access["status"] != "active":
                    raise ValueError("parent source access is not active")
                if not set(audiences).issubset(parent_access["audiences"]):
                    raise ValueError("access may not broaden ancestor audiences")
                if not set(purposes).issubset(parent_access["purposes"]):
                    raise ValueError("access may not broaden ancestor purposes")
        key = access_key(self.bot, self.persona, source_id)
        dependency = source_key(self.bot, self.persona, source_id)
        return self._store.graph_commit(GraphCandidate(
            bound, tuple(_version(atom) for atom in atoms),
            (GraphWrite(key, value, (dependency,)),), (epoch,)
        ))

    def read_source(self, source_id, *, audience, purpose, as_known_at=None):
        return self.read_source_evidence(
            source_id, audience=audience, purpose=purpose,
            as_known_at=as_known_at)[0]

    def read_source_evidence(self, source_id, *, audience, purpose,
                             as_known_at=None, max_nodes=512):
        nonempty(source_id, "source_id")
        nonempty(audience, "audience")
        nonempty(purpose, "purpose")
        if as_known_at is not None:
            _time(as_known_at, "as_known_at")
        records, accesses, atoms, epoch, _ = self._coherent_sources(
            (source_id,), max_nodes)
        record = records.get(source_id)
        if not self._lineage_permits(
                (source_id,), records, accesses, audience, purpose, as_known_at):
            record = None
        return record, self._proof(atoms, epoch)

    def read_interpretation(self, iid, *, audience, purpose,
                            as_known_at=None, valid_at=None):
        return self.read_interpretation_evidence(
            iid, audience=audience, purpose=purpose,
            as_known_at=as_known_at, valid_at=valid_at)[0]

    def read_interpretation_evidence(self, iid, *, audience, purpose,
                                     as_known_at=None, valid_at=None, max_nodes=512):
        nonempty(iid, "iid")
        nonempty(audience, "audience")
        nonempty(purpose, "purpose")
        if as_known_at is not None:
            _time(as_known_at, "as_known_at")
        if valid_at is not None:
            _time(valid_at, "valid_at")
        max_nodes = self._max_nodes(max_nodes)
        key = interpretation_key(self.bot, self.persona, iid)
        atoms = {}
        with self._store._lock:
            self._store._ensure_open()
            self._store._db.execute("BEGIN")
            try:
                atom = self._atom_locked(key, atoms, max_nodes)
                record = (self._interpretation_from_atom(atom, iid)
                          if atom.valid else None)
                records, accesses = ({}, {})
                if record is not None:
                    records, accesses = self._read_sources_locked(
                        record.source_ids, atoms, max_nodes)
                epoch = self._epoch_locked()
                self._store._db.execute("COMMIT")
            except BaseException:
                self._store._db.execute("ROLLBACK")
                raise

        allowed = record is not None and atom.valid and record.status != "retracted"
        if allowed and as_known_at is not None and record.recorded_at > as_known_at:
            allowed = False
        if allowed and valid_at is not None:
            allowed = record.valid_from <= valid_at and (
                record.valid_to is None or valid_at < record.valid_to)
        if allowed and not self._lineage_permits(
                record.source_ids, records, accesses, audience, purpose, as_known_at):
            allowed = False
        return (record if allowed else None), self._proof(tuple(atoms.values()), epoch)


def _version(atom):
    return GraphVersion(atom.key, atom.revision)
