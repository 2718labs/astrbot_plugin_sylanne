"""Immutable W01 preparation for one C04 internal-work operation.

This store records identities after W01 has verified the current Owner, D02,
D11 and graph originals.  A row is neither an Authority execution claim nor a
resource settlement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import sqlite3

from ..authority_service.internal_work_contract import InternalWorkBindingV1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class C04InternalWorkPreparedV1:
    binding: InternalWorkBindingV1
    body_profile_ref: str
    body_profile_revision: int
    body_state_ref: str
    body_state_revision: int
    body_reservation_revision: int
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    budget_reservation_operation_id: str
    budget_reservation_digest: str
    read_versions: tuple[tuple[str, int], ...]
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    schema: str = "sylanne3.c04.internal_work_prepared.v1"

    def __post_init__(self) -> None:
        if (self.schema != "sylanne3.c04.internal_work_prepared.v1"
                or type(self.binding) is not InternalWorkBindingV1):
            raise ValueError("typed C04 internal-work preparation required")
        for value in (self.body_profile_ref, self.body_state_ref,
                      self.owner_grant_ref,
                      self.budget_reservation_operation_id):
            if type(value) is not str or not value:
                raise ValueError("internal-work original reference is absent")
        for value in (self.owner_grant_digest, self.budget_reservation_digest):
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError("internal-work original digest differs")
        for value in (self.body_profile_revision, self.body_state_revision,
                      self.body_reservation_revision, self.owner_grant_revision,
                      self.graph_revision, self.access_epoch, self.delete_epoch):
            if type(value) is not int or value < 0:
                raise ValueError("internal-work original revision differs")
        reads = tuple((token, revision) for token, revision in self.read_versions)
        if (len({token for token, _ in reads}) != len(reads)
                or any(type(token) is not str or not token
                       or type(revision) is not int or revision < 0
                       for token, revision in reads)):
            raise ValueError("internal-work current read set differs")
        object.__setattr__(self, "read_versions", tuple(sorted(reads)))

    @property
    def prepared_digest(self) -> str:
        return canonical_digest(asdict(self))


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("W01 BEGIN IMMEDIATE transaction required")


def install_c04_internal_work_original_v1(db: sqlite3.Connection) -> None:
    _transaction(db)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c04_internal_work_prepared_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL, prepared_digest TEXT NOT NULL,
        prepared_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        UNIQUE(bot,persona,binding_digest))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_c04_internal_work_no_update_v1
        BEFORE UPDATE ON graph_c04_internal_work_prepared_v1
        BEGIN SELECT RAISE(ABORT, 'C04 internal-work original is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_c04_internal_work_no_delete_v1
        BEFORE DELETE ON graph_c04_internal_work_prepared_v1
        BEGIN SELECT RAISE(ABORT, 'C04 internal-work original is immutable'); END""")


def record_c04_internal_work_prepared_v1(
    db: sqlite3.Connection, namespace: NamespaceId,
    prepared: C04InternalWorkPreparedV1,
) -> C04InternalWorkPreparedV1:
    """Insert once; an operation replay must match every original byte."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(prepared) is not C04InternalWorkPreparedV1:
        raise TypeError("typed namespace and C04 preparation required")
    from ..graph_coordinator import namespace_ref

    if prepared.binding.namespace != namespace_ref(namespace):
        raise ValueError("internal-work binding namespace differs")
    encoded = canonical_serialize(asdict(prepared))
    expected = (prepared.binding.binding_digest, prepared.prepared_digest, encoded)
    key = (*namespace.as_tuple, prepared.binding.operation_id)
    previous = db.execute(
        "SELECT binding_digest,prepared_digest,prepared_json "
        "FROM graph_c04_internal_work_prepared_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?", key,
    ).fetchone()
    if previous is not None and previous != expected:
        raise ValueError("internal-work operation changed its immutable original")
    if previous is None:
        db.execute("INSERT INTO graph_c04_internal_work_prepared_v1 VALUES(?,?,?,?,?,?)",
                   (*key, *expected))
    return prepared


def read_c04_internal_work_prepared_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> C04InternalWorkPreparedV1 | None:
    """Reread exact typed bytes; W01 must separately check current heads."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(operation_id) is not str:
        raise TypeError("typed namespace and operation identity required")
    row = db.execute(
        "SELECT binding_digest,prepared_digest,prepared_json "
        "FROM graph_c04_internal_work_prepared_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    try:
        original = json.loads(row[2])
        raw = dict(original)
        binding_shape = raw.pop("binding")
        binding = InternalWorkBindingV1(**binding_shape)
        prepared = C04InternalWorkPreparedV1(
            binding=binding,
            **{**raw, "read_versions": tuple(tuple(item)
                                            for item in raw["read_versions"])},
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("internal-work prepared original is invalid") from exc
    from ..graph_coordinator import namespace_ref

    reconstructed = asdict(prepared)
    if "algorithm_build_digest" not in binding_shape:
        reconstructed["binding"].pop("algorithm_build_digest")
    if (binding.namespace != namespace_ref(namespace)
            or binding.operation_id != operation_id
            or canonical_serialize(reconstructed) != canonical_serialize(original)
            or row != (binding.binding_digest, canonical_digest(original),
                       canonical_serialize(original))):
        raise ValueError("internal-work prepared original changed")
    return prepared


__all__ = [
    "C04InternalWorkPreparedV1", "install_c04_internal_work_original_v1",
    "record_c04_internal_work_prepared_v1", "read_c04_internal_work_prepared_v1",
]
