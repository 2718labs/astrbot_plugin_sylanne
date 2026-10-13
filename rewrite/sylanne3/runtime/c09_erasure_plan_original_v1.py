"""Immutable, content-free basis for an initial one-source D06 erasure request.

The coordinator owns the Owner fence and current graph read. This v1 requires
active access for every ancestor; later overlapping scoped erasures need a
tombstone-aware closure contract. It does not attest an Authority phase.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


C09_SOURCE_ERASURE_POLICY_REF = "d06-deletion-closure-v1"


def authority_c09_plan_request_identity_v1(authority_namespace, plan):
    """Exact existing Authority request wire, shared with the Graph consumer."""
    if type(plan) is not C09ErasurePlanOriginalV1:
        raise TypeError("exact stored C09 plan required")
    return dict(schema="sylanne3.scoped-erasure-plan-request.v2",
        namespace=authority_namespace, operation_id=plan.operation_id,
        scope_kind="one_source", roots=plan.root_source_ids, epoch=plan.delete_epoch + 1,
        policy_ref=plan.policy_ref, policy_version=1,
        plan_request_digest=plan.request_digest, plan_content_digest=canonical_digest(plan.to_wire()),
        graph_namespace=plan.namespace.as_tuple, graph_incarnation=plan.graph_incarnation,
        graph_epoch=plan.graph_epoch, graph_access_epoch=plan.access_epoch,
        graph_delete_epoch=plan.delete_epoch, owner_grant_digest=plan.owner_grant_digest)


@dataclass(frozen=True, slots=True)
class C09ErasurePlanOriginalV1:
    namespace: NamespaceId
    operation_id: str
    scope_kind: str
    root_source_ids: tuple[str, ...]
    source_id: str
    source_ref: str
    policy_ref: str
    policy_version: int
    graph_incarnation: str
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    owner_grant_digest: str
    read_versions: tuple[GraphVersion, ...]
    request_digest: str
    schema: str = "sylanne3.graph.c09_erasure_plan_original.v1"

    def __post_init__(self) -> None:
        from ..memory_types import source_key

        if (type(self.namespace) is not NamespaceId
                or type(self.operation_id) is not str or not self.operation_id
                or self.scope_kind != "one_source"
                or self.root_source_ids != (self.source_id,)
                or type(self.source_id) is not str or not self.source_id
                or self.source_ref != source_key(
                    *self.namespace.as_tuple, self.source_id).token
                or self.policy_ref != C09_SOURCE_ERASURE_POLICY_REF
                or self.policy_version != 1
                or type(self.graph_incarnation) is not str
                or not self.graph_incarnation
                or self.schema != "sylanne3.graph.c09_erasure_plan_original.v1"
                or any(type(v) is not int or v < 0 for v in (
                    self.graph_epoch, self.access_epoch, self.delete_epoch))
                or type(self.owner_grant_digest) is not str
                or not self.owner_grant_digest.startswith("sha256:")
                or type(self.read_versions) is not tuple
                or not self.read_versions
                or tuple(sorted(self.read_versions,
                                key=lambda item: item.key.token)) != self.read_versions
                or len({version.key for version in self.read_versions})
                   != len(self.read_versions)
                or any(type(version) is not GraphVersion
                       or NamespaceId.from_key(version.key) != self.namespace
                       for version in self.read_versions)):
            raise ValueError("C09 erasure plan identity or read closure is invalid")
        if self.request_digest != canonical_digest(self._identity()):
            raise ValueError("C09 erasure plan request digest differs")

    def _identity(self) -> tuple:
        return (self.namespace, self.operation_id, self.scope_kind,
                self.root_source_ids, self.source_id, self.source_ref,
                self.policy_ref, self.policy_version, self.graph_incarnation,
                self.graph_epoch,
                self.access_epoch, self.delete_epoch,
                self.owner_grant_digest, self.read_versions)

    def to_wire(self) -> dict:
        return {
            "schema": self.schema,
            "namespace": {"bot_id": self.namespace.bot_id,
                          "persona_id": self.namespace.persona_id},
            "operation_id": self.operation_id,
            "scope_kind": self.scope_kind,
            "root_source_ids": list(self.root_source_ids),
            "source_id": self.source_id,
            "source_ref": self.source_ref,
            "policy_ref": self.policy_ref,
            "policy_version": self.policy_version,
            "graph_incarnation": self.graph_incarnation,
            "graph_epoch": self.graph_epoch,
            "access_epoch": self.access_epoch,
            "delete_epoch": self.delete_epoch,
            "owner_grant_digest": self.owner_grant_digest,
            "read_versions": [[item.key.token, item.revision]
                              for item in self.read_versions],
            "request_digest": self.request_digest,
        }

    @classmethod
    def from_wire(cls, raw: dict) -> "C09ErasurePlanOriginalV1":
        if type(raw) is not dict or set(raw) != {
                "schema", "namespace", "operation_id", "scope_kind",
                "root_source_ids", "source_id", "source_ref", "policy_ref",
                "policy_version", "graph_incarnation", "graph_epoch", "access_epoch",
                "delete_epoch", "owner_grant_digest", "read_versions",
                "request_digest"}:
            raise ValueError("C09 plan original wire differs")
        versions = tuple(GraphVersion(AtomKey.from_token(token), revision)
                         for token, revision in raw["read_versions"])
        return cls(
            NamespaceId(**raw["namespace"]), raw["operation_id"],
            raw["scope_kind"], tuple(raw["root_source_ids"]),
            raw["source_id"], raw["source_ref"], raw["policy_ref"],
            raw["policy_version"], raw["graph_incarnation"],
            raw["graph_epoch"], raw["access_epoch"], raw["delete_epoch"],
            raw["owner_grant_digest"], versions, raw["request_digest"],
            raw["schema"],
        )


def install_c09_erasure_plan_schema_v1(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c09_erasure_plans_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL,
        PRIMARY KEY (bot, persona, operation_id))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_c09_erasure_plans_v1_{action.lower()}_immutable
            BEFORE {action} ON graph_c09_erasure_plans_v1
            BEGIN SELECT RAISE(ABORT, 'C09 erasure plan is immutable'); END""")


def read_c09_erasure_plan_original_v1(
        db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> C09ErasurePlanOriginalV1 | None:
    row = db.execute(
        "SELECT original_json FROM graph_c09_erasure_plans_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    original = C09ErasurePlanOriginalV1.from_wire(json.loads(row[0]))
    if (original.namespace != namespace or original.operation_id != operation_id
            or canonical_serialize(original.to_wire()) != row[0]):
        raise ValueError("C09 erasure plan original bytes differ")
    return original


def record_c09_erasure_plan_original_v1(
        db: sqlite3.Connection, original: C09ErasurePlanOriginalV1,
) -> C09ErasurePlanOriginalV1:
    if not db.in_transaction:
        raise ValueError("C09 erasure plan requires caller transaction")
    prior = read_c09_erasure_plan_original_v1(
        db, original.namespace, original.operation_id)
    if prior is not None:
        if prior != original:
            raise ValueError("C09 erasure plan operation changed")
        return prior
    db.execute(
        "INSERT INTO graph_c09_erasure_plans_v1 VALUES(?,?,?,?)",
        (*original.namespace.as_tuple, original.operation_id,
         canonical_serialize(original.to_wire())),
    )
    return original


def current_c09_source_read_versions_v1(
        db: sqlite3.Connection, namespace: NamespaceId, source_id: str,
) -> tuple[GraphVersion, ...]:
    """Read one source's current ancestry, access and correction heads."""
    from ..domains.d06 import source_correction_head_key

    if not db.in_transaction:
        raise ValueError("C09 source closure requires caller transaction")
    pending = [source_id]
    seen: set[str] = set()
    versions: dict[AtomKey, GraphVersion] = {}
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if len(seen) > 256:
            raise ValueError("C09 source ancestry exceeds bound")
        source = source_key(*namespace.as_tuple, current)
        access = access_key(*namespace.as_tuple, current)
        correction = source_correction_head_key(namespace, current)
        rows = {}
        for key in (source, access, correction):
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms "
                "WHERE bot=? AND persona=? AND token=?",
                (*namespace.as_tuple, key.token),
            ).fetchone()
            rows[key] = row
            versions[key] = GraphVersion(key, row[0] if row else 0)
        source_row, access_row = rows[source], rows[access]
        if (source_row is None or access_row is None
                or source_row[2] != 1 or access_row[2] != 1):
            raise ValueError("C09 source or access is unavailable")
        record = SourceRecord.from_dict(json.loads(source_row[1]))
        access_value = json.loads(access_row[1])
        validate_access(access_value)
        if (record.source_id != current
                or access_value["source_id"] != current
                or access_value["status"] != "active"):
            raise ValueError("C09 source access differs")
        if rows[correction] is not None and rows[correction][2] != 1:
            raise ValueError("C09 correction head is invalid")
        pending.extend(record.parent_source_ids)
    return tuple(versions[key] for key in sorted(versions,
                                                key=lambda item: item.token))


__all__ = [
    "C09_SOURCE_ERASURE_POLICY_REF", "C09ErasurePlanOriginalV1",
    "install_c09_erasure_plan_schema_v1", "read_c09_erasure_plan_original_v1",
    "record_c09_erasure_plan_original_v1",
    "current_c09_source_read_versions_v1",
]



SOURCE_PLAN_ORIGINAL_DDL_V2 = 'CREATE TABLE graph_c09_erasure_plans_v2 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,original_json TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))'


def install_c09_erasure_plan_schema_v2(db):
    db.execute(SOURCE_PLAN_ORIGINAL_DDL_V2.replace("CREATE TABLE ","CREATE TABLE IF NOT EXISTS ",1))
    for action in ("UPDATE","DELETE"):
        db.execute("CREATE TRIGGER IF NOT EXISTS graph_c09_erasure_plans_v2_"+action.lower()+"_immutable BEFORE "+action+" ON graph_c09_erasure_plans_v2 BEGIN SELECT RAISE(ABORT,'C09 V2 Source plan immutable'); END")


def read_c09_erasure_plan_original_v2(db,namespace,operation_id):
    from .c09_source_plan_barrier_v2 import C09SourcePlanCaptureV2
    row=db.execute('SELECT original_json FROM graph_c09_erasure_plans_v2 WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if row is None:return None
    original=C09SourcePlanCaptureV2.from_wire(json.loads(row[0]))
    if original.namespace!=namespace or original.operation_id!=operation_id or canonical_serialize(original.to_wire())!=row[0]:
        raise ValueError('C09 V2 Source plan original canonical identity differs')
    return original


def record_c09_erasure_plan_original_v2(db,original):
    from .c09_source_plan_barrier_v2 import C09SourcePlanCaptureV2,seal_c09_source_plan_v2
    if not db.in_transaction or type(original) is not C09SourcePlanCaptureV2:
        raise ValueError('C09 V2 actual Source plan transaction required')
    if seal_c09_source_plan_v2(db,original.namespace,original.operation_id)!=original:
        raise ValueError('C09 V2 plan lacks actual captured Source EOF/count/seal')
    prior=read_c09_erasure_plan_original_v2(db,original.namespace,original.operation_id)
    if prior is not None:
        if prior!=original:raise ValueError('C09 V2 Source plan replay differs')
        return prior
    db.execute('INSERT INTO graph_c09_erasure_plans_v2 VALUES(?,?,?,?)',(*original.namespace.as_tuple,original.operation_id,canonical_serialize(original.to_wire())))
    return original


def read_c09_erasure_plan_original_versioned_v2(db,namespace,operation_id):
    """Explicit table/schema dispatch; no failed-V2 downgrade to V1."""
    new=read_c09_erasure_plan_original_v2(db,namespace,operation_id)
    old=read_c09_erasure_plan_original_v1(db,namespace,operation_id)
    if new is not None and old is not None:raise ValueError('C09 operation has two plan versions')
    return new if new is not None else old
