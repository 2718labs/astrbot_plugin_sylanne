"""Finite signed originals for actual Host lifecycle and role-clock schedules.

An original signature authenticates installed production, not execution. CPU
tick completion additionally requires the independent durable Authority chain.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10.offline_interval import OfflineTickRecipeV1
from .clock import CharacterClockMapping
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1
from .issuers import D11BudgetJobIssuer

TABLE = "graph_d11_offline_originals_v1"
SIGN_KIND = "d11.offline-original.v1"
WORK_KIND = "d10.offline_observed_tick.v1"
ALGORITHM_ID = "d11.signed_role_clock_tick.v1"


def _utc(value):
    if type(value) is not str:
        raise ValueError("explicit UTC timestamp required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError("explicit UTC timestamp required")
    if value != result.isoformat().replace("+00:00", "Z"):
        raise ValueError("canonical UTC spelling required (ISO T, optional nonzero microseconds, Z)")
    return result


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("bounded original locator required")


def _digest(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("exact original SHA-256 required")


@dataclass(frozen=True, slots=True)
class D11OfflineScheduleOriginalV1:
    namespace: NamespaceId
    schedule_ref: str
    schedule_id: str
    revision: int
    recipe_ref: str
    cadence_seconds: int
    max_ticks_per_slice: int
    cpu_ceiling_ms: int
    clock_mapping_ref: str
    clock_mapping_version: int
    clock_original_digest: str
    starts_at_utc: str
    valid_until_utc: str
    parent_budget_lease_ref: str
    audiences: tuple[str, ...]
    purposes: tuple[str, ...]
    work_kind: str = WORK_KIND
    world_kind: str = "role_simulation"
    schema: str = "d11.registered-offline-role-tick-schedule.v1"

    def __post_init__(self):
        if (self.schema != "d11.registered-offline-role-tick-schedule.v1" or type(self.namespace) is not NamespaceId
                or self.work_kind != WORK_KIND or self.world_kind != "role_simulation"
                or type(self.revision) is not int or self.revision < 1
                or type(self.clock_mapping_version) is not int or self.clock_mapping_version < 1
                or type(self.cadence_seconds) is not int or self.cadence_seconds < 60
                or type(self.max_ticks_per_slice) is not int or not 1 <= self.max_ticks_per_slice <= 32
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.audiences) is not tuple or not self.audiences
                or type(self.purposes) is not tuple or not self.purposes
                or not set(self.purposes) <= {"context", "consolidation", "audit"}
                or _utc(self.starts_at_utc) >= _utc(self.valid_until_utc)):
            raise ValueError("exact bounded role simulation schedule required")
        for value in (self.schedule_ref, self.schedule_id, self.recipe_ref, self.clock_mapping_ref, self.parent_budget_lease_ref, *self.audiences):
            _text(value)
        _digest(self.clock_original_digest)


@dataclass(frozen=True, slots=True)
class D11HostLifecycleOriginalV1:
    namespace: NamespaceId
    lifecycle_ref: str
    kind: str
    host_incarnation: str
    observed_at_utc: str
    trusted_clock_original_ref: str
    trusted_clock_digest: str
    source_ref: str
    source_revision: int
    boundary_state: str
    observation_scope: str = "sylanne_logical_runtime"
    schema: str = "d11.observed-host-lifecycle.v1"

    def __post_init__(self):
        if (self.schema != "d11.observed-host-lifecycle.v1" or type(self.namespace) is not NamespaceId
                or self.kind not in {"host_disconnect", "host_reconnect"} or type(self.source_revision) is not int
                or self.source_revision != 1 or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or self.observation_scope != "sylanne_logical_runtime"
                or self.boundary_state != ("quiesced_ingress_gated" if self.kind == "host_disconnect" else "paired_runtime_ready")):
            raise ValueError("exact actual host lifecycle original required")
        for value in (self.lifecycle_ref, self.host_incarnation, self.trusted_clock_original_ref):
            _text(value)
        _utc(self.observed_at_utc)
        _digest(self.trusted_clock_digest)


@dataclass(frozen=True, slots=True)
class D11OfflineTickBindingV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    activation_generation: int
    operation_id: str
    activity_id: str
    execution_id: str
    job_id: str
    job_holder: str
    job_fence: int
    job_lease_expires_utc: str
    job_cancel_epoch: int
    schedule_ref: str
    schedule_revision: int
    scheduled_at_utc: str
    prepared_original_ref: str
    input_digest: str
    clock_original_digest: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    parent_budget_lease_ref: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_operation_id: str
    reservation_digest: str
    cpu_ceiling_ms: int
    deadline_utc: str
    algorithm_id: str = ALGORITHM_ID
    schema: str = "d11.offline-role-clock-tick-binding.v1"

    def __post_init__(self):
        if (self.schema != "d11.offline-role-clock-tick-binding.v1" or self.algorithm_id != ALGORITHM_ID
                or type(self.namespace) is not NamespaceId
                or any(type(getattr(self, name)) is not int or getattr(self, name) < 1 for name in (
                    "activation_generation", "schedule_revision", "owner_grant_revision", "quote_version", "cpu_ceiling_ms"))
                or type(self.job_fence) is not int or self.job_fence < 1
                or type(self.job_cancel_epoch) is not int or self.job_cancel_epoch != 0
                or self.cpu_ceiling_ms > 60000
                or _utc(self.job_lease_expires_utc) > _utc(self.deadline_utc)
                or _utc(self.scheduled_at_utc) >= _utc(self.deadline_utc)):
            raise ValueError("exact installed bounded clock tick binding required")
        for name in ("authority_namespace", "authority_id", "installation_id", "operation_id", "activity_id", "execution_id",
                "job_id", "job_holder", "schedule_ref", "prepared_original_ref", "owner_grant_ref", "parent_budget_lease_ref", "quote_id",
                "reservation_operation_id"):
            _text(getattr(self, name))
        for name in ("manifest_digest", "input_digest", "clock_original_digest", "owner_grant_digest", "quote_digest", "reservation_digest"):
            _digest(getattr(self, name))

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class D11OfflineTickResultV1:
    scheduled_at_utc: str
    computed_at_utc: str
    clock_mapping_ref: str
    clock_mapping_version: int
    character_at: str
    world_kind: str = "role_simulation"
    actuality: str = "computed_at_recovery"
    schema: str = "d11.actual-offline-role-clock-tick-result.v1"

    def __post_init__(self):
        from decimal import Decimal
        if (self.schema != "d11.actual-offline-role-clock-tick-result.v1" or self.world_kind != "role_simulation"
                or self.actuality != "computed_at_recovery" or type(self.clock_mapping_version) is not int
                or self.clock_mapping_version < 1 or _utc(self.scheduled_at_utc) > _utc(self.computed_at_utc)
                or not Decimal(self.character_at).is_finite()):
            raise ValueError("clock tick result must preserve virtual time and actual computation time")
        _text(self.clock_mapping_ref)


def install_d11_offline_schema_v1(db):
    if db.in_transaction:
        raise ValueError("offline original schema must be installed before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d11_offline_originals_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,kind TEXT NOT NULL,original_ref TEXT NOT NULL,"
        "producing_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,kind,original_ref))")


_KINDS = {"registered_schedule": D11OfflineScheduleOriginalV1, "host_disconnect": D11HostLifecycleOriginalV1,
    "host_reconnect": D11HostLifecycleOriginalV1}


def record_d11_offline_original_in_transaction_v1(db, *, issuer, frame, kind, original_ref, value, producing_operation_id):
    if type(issuer) is not D11BudgetJobIssuer or kind not in _KINDS or type(value) is not _KINDS[kind]:
        raise TypeError("offline original needs its exact finite installed issuer/type")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    read.committed_operation(db, producing_operation_id)
    if value.namespace != frame.envelope.authority.namespace:
        raise ValueError("offline original crossed its actual producing namespace")
    if kind in {"host_disconnect", "host_reconnect"} and value.kind != kind:
        raise ValueError("lifecycle original kind differs")
    raw = plain_v1(value)
    wire, digest = canonical_serialize(raw), canonical_digest(raw)
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((value.namespace, kind, original_ref, digest)))
    expected = (producing_operation_id, wire, digest, signature)
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*value.namespace.as_tuple, kind, original_ref)).fetchone()
    if row is not None and row != expected:
        raise ValueError("offline original identity replay conflicts")
    if row is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*value.namespace.as_tuple, kind, original_ref, *expected))
    return ProductionOriginalRefV1("d11." + kind, original_ref, digest)


def read_current_d11_offline_value_v1(db, *, namespace, original_ref, issuer):
    if not table_exists_v1(db, TABLE):
        return None
    rows = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND original_ref=? LIMIT 2", (*namespace.as_tuple, original_ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1 or type(issuer) is not D11BudgetJobIssuer:
        raise ValueError("offline original locator collides or has another issuer")
    kind, operation, wire, digest, signature = rows[0]
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if kind not in _KINDS:
        raise ValueError("unregistered offline original kind")
    raw = json.loads(wire)
    value = decode_typed_production_value_v1(raw, _KINDS[kind])
    if canonical_serialize(raw) != wire or canonical_digest(raw) != digest or value.namespace != namespace:
        raise ValueError("offline signed original bytes/namespace changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, original_ref, digest)), signature)
    from .domain_production_read_plans_v1 import _committed
    _committed(db, namespace, operation)
    if kind in {"host_disconnect", "host_reconnect"}:
        row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (value.source_ref, value.source_revision)).fetchone()
        if row is None or row[0] != operation or row[2] != 1:
            raise ValueError("lifecycle signed original lost its actual admitted source history")
        from ..memory_types import SourceRecord
        source = SourceRecord.from_dict(json.loads(row[1]))
        if source.occurred_at != _utc(value.observed_at_utc).timestamp():
            raise ValueError("lifecycle original time differs from its actual source")
    return value


def read_current_d11_offline_original_ref_v1(db, *, namespace, original_ref, issuer):
    if not table_exists_v1(db, TABLE):
        return None
    rows = db.execute("SELECT kind,original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND "
        "(original_ref=? OR kind IN ('host_disconnect','host_reconnect') AND json_extract(payload_json,'$.source_ref')=?) LIMIT 2",
        (*namespace.as_tuple, original_ref, original_ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("offline original reference is ambiguous")
    kind, actual_ref = rows[0]
    if kind == "prepared_tick":
        from .d10_offline_tick_execution_v1 import read_prepared_offline_tick_v1
        value = read_prepared_offline_tick_v1(db, namespace=namespace, prepared_original_ref=actual_ref, issuer=issuer)
        return ProductionOriginalRefV1("d11.prepared_offline_tick", original_ref, value.digest)
    if kind == "adopted_tick":
        from .d10_offline_tick_terminal_v1 import read_adopted_offline_tick_original_v1
        value = read_adopted_offline_tick_original_v1(db, namespace=namespace, result_ref=actual_ref, issuer=issuer)
        return ProductionOriginalRefV1("d11.completed_offline_tick" if value.terminal.status == "completed" else "d11.offline_tick_accounting",
            original_ref, canonical_digest(plain_v1(value)))
    if kind == "accounting_prepared":
        from .d11_offline_accounting_v1 import D11OfflineAccountingPreparedV1, read_offline_accounting_prepared_v1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref=?",
            (*namespace.as_tuple, actual_ref)).fetchone()
        locator = decode_typed_production_value_v1(json.loads(row[0]), D11OfflineAccountingPreparedV1)
        value = read_offline_accounting_prepared_v1(db, binding=locator.binding, issuer=issuer, resource_issuer=issuer.resource_issuer)
        return ProductionOriginalRefV1("d11.offline_accounting_prepared", original_ref, canonical_digest(plain_v1(value)))
    value = read_current_d11_offline_value_v1(db, namespace=namespace, original_ref=actual_ref, issuer=issuer)
    versions = ((GraphVersion(AtomKey.from_token(value.source_ref), value.source_revision),)
        if kind in {"host_disconnect", "host_reconnect"} else ())
    return ProductionOriginalRefV1("d11." + kind, original_ref, canonical_digest(plain_v1(value)), versions)
