"""Explicit Owner schedule and actual lifecycle interval production.

All dates describing an observation are read from original signed Host events.
The only caller dates are the explicitly authorized schedule validity bound.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10.offline_interval import OfflineTickRecipeV1, offline_tick_recipe_to_wire_v1
from ..runtime_contracts import VersionedRef, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d10_offline_tick_execution_v1 import read_current_offline_clock_reference_v1
from .d10_production_operations_v1 import RegisteredOfflineIntervalV1
from .d11_offline_originals_v1 import (
    TABLE, WORK_KIND, D11OfflineScheduleOriginalV1, D11HostLifecycleOriginalV1,
    _utc, _text, read_current_d11_offline_value_v1, record_d11_offline_original_in_transaction_v1,
)
from .budget import get_budget_lease, require_budget_family_admissible
from .domain_production_contracts_v1 import ProductionPolicyRefV1


@dataclass(frozen=True, slots=True)
class RegisterCurrentOfflineScheduleInputRequestV1:
    schedule_id: str
    expected_revision: int
    cadence_seconds: int
    max_ticks_per_slice: int
    cpu_ceiling_ms: int
    valid_until_utc: str
    purposes: tuple[str, ...]

    def __post_init__(self):
        _text(self.schedule_id)
        _utc(self.valid_until_utc)
        if (type(self.expected_revision) is not int or self.expected_revision < 0
                or type(self.cadence_seconds) is not int or self.cadence_seconds < 60
                or type(self.max_ticks_per_slice) is not int or not 1 <= self.max_ticks_per_slice <= 16
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.purposes) is not tuple or not self.purposes
                or tuple(sorted(set(self.purposes))) != self.purposes
                or not set(self.purposes) <= {"context", "consolidation", "audit"}):
            raise ValueError("offline schedule needs explicit bounded cadence/CPU/permissions")


@dataclass(frozen=True, slots=True)
class RegisterCurrentOfflineIntervalInputRequestV1:
    schedule_ref: str
    disconnect_original_ref: str
    reconnect_original_ref: str

    def __post_init__(self):
        for ref in (self.schedule_ref, self.disconnect_original_ref, self.reconnect_original_ref):
            _text(ref)


def offline_schedule_refs_v1(namespace, schedule_id, revision):
    suffix = canonical_digest(("d11.explicit-offline-schedule.v1", namespace, schedule_id, revision))[:48]
    return "d11-offline-schedule:" + suffix, "d10-offline-recipe:" + suffix


def require_adjacent_host_lifecycle_pair_v1(db, *, namespace, disconnected, reconnected):
    """Bind one actual logical-runtime interval by committed lifecycle order."""
    if (type(disconnected) is not D11HostLifecycleOriginalV1 or type(reconnected) is not D11HostLifecycleOriginalV1
            or disconnected.namespace != namespace or reconnected.namespace != namespace
            or disconnected.kind != "host_disconnect" or reconnected.kind != "host_reconnect"
            or disconnected.observation_scope != reconnected.observation_scope):
        raise ValueError("offline interval requires a same-scope actual disconnect/reconnect pair")
    committed = db.execute("SELECT b.commit_seq FROM " + TABLE + " o "
        "JOIN graph_bundle_operations b ON b.bot=o.bot AND b.persona=o.persona AND b.operation_id=o.producing_operation_id "
        "WHERE o.bot=? AND o.persona=? AND o.kind='host_disconnect' AND o.original_ref=?",
        (*namespace.as_tuple, disconnected.lifecycle_ref)).fetchone()
    if committed is None:
        raise MissingProductionOriginalV1("actual_committed_adjacent_host_lifecycle_pair")
    next_boundary = db.execute("SELECT o.original_ref,o.kind FROM " + TABLE + " o "
        "JOIN graph_bundle_operations b ON b.bot=o.bot AND b.persona=o.persona AND b.operation_id=o.producing_operation_id "
        "WHERE o.bot=? AND o.persona=? AND o.kind IN ('host_disconnect','host_reconnect') "
        "AND b.commit_seq>? ORDER BY b.commit_seq,o.original_ref LIMIT 1",
        (*namespace.as_tuple, committed[0])).fetchone()
    if next_boundary != (reconnected.lifecycle_ref, "host_reconnect"):
        raise ValueError("offline interval crosses another registered Host boundary")


def derive_current_offline_schedule_v1(db, *, frame, request, issuer):
    if type(request) is not RegisterCurrentOfflineScheduleInputRequestV1:
        raise TypeError("exact registered offline schedule request required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' ORDER BY original_ref LIMIT 129",
        ns.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("complete_registered_offline_schedule_inventory")
    prior = [value for (ref,) in rows if (value := read_current_d11_offline_value_v1(db,
        namespace=ns, original_ref=ref, issuer=issuer)).schedule_id == request.schedule_id]
    revision = max((value.revision for value in prior), default=0)
    if revision != request.expected_revision:
        raise ValueError("explicit offline schedule expected revision changed")
    mapping, _ = read_current_offline_clock_reference_v1(db, namespace=ns, issuer=issuer)
    clock = read.original(mapping.mapping_id, kind="d11.role_clock")
    owner = read.head(db, frame.owner_guard.grant_ref, required=True)
    if (not set(request.purposes) <= set(owner.value["purposes"])
            or not set(frame.envelope.authority.audience) <= set(owner.value["audiences"])):
        raise ValueError("offline schedule exceeds actual Owner content permissions")
    parent = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    grant = issuer.current_budget_grant(db, parent.lease_id)
    require_budget_family_admissible(db, parent.lease_id)
    until = _utc(request.valid_until_utc).timestamp()
    if (parent.state != "active" or (parent.bot_id, parent.persona_id) != ns.as_tuple
            or WORK_KIND not in grant.allowed_work_kinds or request.cpu_ceiling_ms > grant.max_ceiling.get("thread_cpu_ms", 0)
            or not frame.now_utc < until <= grant.valid_until_utc
            or until > datetime.fromisoformat(mapping.valid_until_utc.replace("Z", "+00:00")).timestamp()):
        raise MissingProductionOriginalV1("actual_signed_offline_schedule_clock_and_cpu_budget")
    starts = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    mapping.character_at(starts)
    ref, recipe_ref = offline_schedule_refs_v1(ns, request.schedule_id, revision + 1)
    return D11OfflineScheduleOriginalV1(ns, ref, request.schedule_id, revision + 1, recipe_ref,
        request.cadence_seconds, request.max_ticks_per_slice, request.cpu_ceiling_ms, mapping.mapping_id, mapping.version,
        clock.original_digest, starts, request.valid_until_utc, parent.lease_id,
        frame.envelope.authority.audience, request.purposes)


def derive_current_offline_interval_v1(db, *, frame, request, readers):
    if type(request) is not RegisterCurrentOfflineIntervalInputRequestV1:
        raise TypeError("exact actual offline interval request required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    schedule = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=request.schedule_ref, issuer=readers.issuer)
    disconnected = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=request.disconnect_original_ref, issuer=readers.issuer)
    reconnected = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=request.reconnect_original_ref, issuer=readers.issuer)
    if schedule is None or disconnected is None or reconnected is None:
        raise MissingProductionOriginalV1("actual_signed_host_disconnect_reconnect_and_registered_schedule")
    if (type(schedule) is not D11OfflineScheduleOriginalV1 or type(disconnected) is not D11HostLifecycleOriginalV1
            or type(reconnected) is not D11HostLifecycleOriginalV1 or disconnected.kind != "host_disconnect"
            or reconnected.kind != "host_reconnect" or disconnected.host_incarnation == reconnected.host_incarnation
            or disconnected.namespace != ns or reconnected.namespace != ns
            or not _utc(schedule.starts_at_utc) <= _utc(disconnected.observed_at_utc) < _utc(reconnected.observed_at_utc) <= _utc(schedule.valid_until_utc)
            or _utc(reconnected.observed_at_utc).timestamp() > frame.now_utc):
        raise ValueError("offline recovery is not a genuine closed authorized Host lifecycle interval")
    require_adjacent_host_lifecycle_pair_v1(db, namespace=ns, disconnected=disconnected, reconnected=reconnected)
    mapping = readers._clock(db, read, schedule.clock_mapping_ref)
    if mapping.version != schedule.clock_mapping_version:
        raise MissingProductionOriginalV1("actual_offline_schedule_clock_continuity")
    read.source_family(db, (disconnected.source_ref, reconnected.source_ref))
    ref = "d10-offline-interval:" + canonical_digest((ns, schedule.schedule_ref, disconnected.lifecycle_ref, reconnected.lifecycle_ref))[:48]
    return RegisteredOfflineIntervalV1(ref, disconnected.source_ref, reconnected.source_ref,
        schedule.clock_mapping_ref, schedule.clock_mapping_version, schedule.recipe_ref,
        disconnected.observed_at_utc, reconnected.observed_at_utc, None)


def record_current_offline_schedule_after_commit_v1(db, *, frame, request, readers, operation_id):
    schedule = derive_current_offline_schedule_v1(db, frame=frame, request=request, issuer=readers.issuer)
    original = record_d11_offline_original_in_transaction_v1(db, issuer=readers.issuer, frame=frame,
        kind="registered_schedule", original_ref=schedule.schedule_ref, value=schedule, producing_operation_id=operation_id)
    recipe = OfflineTickRecipeV1(schedule.recipe_ref, schedule.revision, VersionedRef(schedule.schedule_ref, schedule.revision),
        schedule.cadence_seconds, schedule.max_ticks_per_slice, cadence_origin_utc=schedule.starts_at_utc)
    augmented = replace(frame, observed_originals=(*frame.observed_originals, original), installed_policy_refs=(
        *frame.installed_policy_refs, ProductionPolicyRefV1(schedule.recipe_ref, schedule.revision, canonical_digest(offline_tick_recipe_to_wire_v1(recipe)))))
    recipe_original = readers.record_offline_recipe_v1(db, frame=augmented, original_ref=schedule.recipe_ref,
        producing_operation_id=operation_id, recipe=recipe)
    return original, recipe_original
