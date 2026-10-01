"""Immutable W01 preparation for the independent once-only D11 clock worker.

This module does not run a callback or accept a caller's CPU/completion result.
The installed Authority executes only the fixed role-clock arithmetic and
persists its measured terminal before the current D06+D11 consumer runs.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, owner_grant_key
from ..memory_types import source_key
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, VersionedRef, canonical_digest, canonical_serialize
from .budget import BudgetLease, BudgetReceipt, get_budget_lease, require_budget_family_admissible, reserve_budget
from .clock import CharacterClockMapping
from .d11_offline_originals_v1 import (
    ALGORITHM_ID, TABLE, WORK_KIND, D11OfflineScheduleOriginalV1, D11OfflineTickBindingV1, D11OfflineTickResultV1,
    _utc, _text, _digest, read_current_d11_offline_original_ref_v1,
)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_types import RuntimeJobValue, job_graph_write
from .jobs import PersistentJob, get_job, create_job, acquire_job
from .issuers import BudgetLeaseGrant, D11BudgetJobIssuer, D02ResourceIssuer, ResourceQuote
from .domain_production_contracts_v1 import CurrentOperationFrameV1, StagedDomainOperationV1, ProductionOriginalRefV1, ProductionOwnerGuardV1


@dataclass(frozen=True, slots=True)
class PrepareCurrentOfflineTickRequestV1:
    schedule_ref: str
    scheduled_at_utc: str

    def __post_init__(self):
        _text(self.schedule_ref)
        _utc(self.scheduled_at_utc)


@dataclass(frozen=True, slots=True)
class OfflineTickGraphReadV1:
    ref: str
    revision: int
    value_json: str
    valid: bool

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool:
            raise ValueError("exact current tick graph read required")
        if canonical_serialize(json.loads(self.value_json)) != self.value_json:
            raise ValueError("tick original contains noncanonical current graph bytes")


@dataclass(frozen=True, slots=True)
class D10OfflineTickPreparedV1:
    binding: D11OfflineTickBindingV1
    prepare_operation_id: str
    schedule: D11OfflineScheduleOriginalV1
    clock_mapping_json: str
    clock_original_json: str
    quote_json: str
    signed_grant_json: str
    signed_grant_signature: str
    parent_budget_json: str
    reserve_receipt_json: str
    owner_guard_json: str
    owner_grant_json: str
    read_rows: tuple[OfflineTickGraphReadV1, ...]
    prepared_at_utc: str
    requirements_json: str | None = None
    graph_revision: int | None = None
    graph_epoch: int | None = None
    job_projection_json: str | None = None
    job_projection_revision: int | None = None
    schema: str = "d10.actual-offline-role-tick-preparation.v1"

    def __post_init__(self):
        if (self.schema != "d10.actual-offline-role-tick-preparation.v1" or type(self.binding) is not D11OfflineTickBindingV1
                or type(self.schedule) is not D11OfflineScheduleOriginalV1 or type(self.read_rows) is not tuple
                or any(type(row) is not OfflineTickGraphReadV1 for row in self.read_rows)
                or len(self.read_rows) > 1024 or self.schedule.namespace != self.binding.namespace
                or (self.schedule.schedule_ref, self.schedule.revision) != (self.binding.schedule_ref, self.binding.schedule_revision)):
            raise ValueError("actual immutable tick preparation has another identity/schema")
        _utc(self.prepared_at_utc)
        _digest(self.signed_grant_signature)
        validate_offline_tick_prepared_content_v1(self)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class D10OfflineTickPreparationStageV1:
    frame: CurrentOperationFrameV1
    stage: StagedDomainOperationV1
    prepared: D10OfflineTickPreparedV1
    job: PersistentJob
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]


def offline_tick_ids_v1(namespace, schedule_ref, scheduled_at_utc):
    _utc(scheduled_at_utc)
    suffix = canonical_digest(("d11.signed-offline-role-clock-tick.v1", namespace, schedule_ref, scheduled_at_utc))[:48]
    return {name: "d11-offline-" + name + ":" + suffix for name in (
        "operation", "activity", "job", "execution", "quote", "reservation", "prepared", "result", "source")}


def read_plan_current_offline_tick_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1, table_exists_v1
    if operation_kind != "prepare_offline_tick" or type(request) is not PrepareCurrentOfflineTickRequestV1:
        raise TypeError("exact registered offline preparation read request required")
    ids = offline_tick_ids_v1(namespace, request.schedule_ref, request.scheduled_at_utc)
    if activity_id != ids["activity"]:
        raise ValueError("offline preparation activity differs from stable schedule occurrence")
    keys = [owner_grant_key(*namespace.as_tuple), AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "runtime.job", ids["job"])]
    originals = [request.schedule_ref]
    if table_exists_v1(db, TABLE):
        row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' AND original_ref=?",
            (*namespace.as_tuple, request.schedule_ref)).fetchone()
        if row:
            originals.append(json.loads(row[0])["clock_mapping_ref"])
    return production_read_plan_v1(("d01.persona_activation.v1", "d03.role_binding"), keys, (), originals)


def stage_prepare_current_offline_tick_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d01_production_operations_v1 import waiting_stage_v1
    from .d11_offline_originals_v1 import read_current_d11_offline_value_v1
    try:
        schedule = read_current_d11_offline_value_v1(db, namespace=frame.envelope.authority.namespace,
            original_ref=request.schedule_ref, issuer=installed_readers.issuer)
        if type(schedule) is not D11OfflineScheduleOriginalV1:
            raise MissingProductionOriginalV1("actual_registered_offline_role_clock_schedule")
        graph = installed_readers.role_clock_reader.graph
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None or assembly.installation_policy.namespace != frame.envelope.authority.namespace:
            raise MissingProductionOriginalV1("actual_installed_offline_tick_identity")
        mapping = installed_readers._clock(db, CurrentDomainReadV1(frame), schedule.clock_mapping_ref)
        _, clock_json = read_current_offline_clock_reference_v1(db, namespace=frame.envelope.authority.namespace, issuer=installed_readers.issuer)
        policy = assembly.installation_policy
        return prepare_current_offline_tick_in_transaction_v1(db, frame=frame, request=request,
            issuer=installed_readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            schedule=schedule, clock_mapping=mapping, clock_original_json=clock_json,
            installation_id=policy.installation_id, authority_id=policy.expected_authority_id,
            authority_namespace=policy.authority_namespace, manifest_digest=policy.manifest_digest,
            job_holder=graph._GraphCoordinator__holder)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "prepare_offline_tick", request, missing)


def _decode_json(value, kind):
    from .domain_production_erasure_v1 import _json, decode_typed_production_value_v1
    return decode_typed_production_value_v1(_json(value), kind)


def validate_offline_tick_prepared_content_v1(prepared):
    """Closed original schemas and cross-bindings, never a current permit."""
    from ..graph_types import validate_owner_grant_v1
    from .domain_production_erasure_v1 import _json
    mapping = _decode_json(prepared.clock_mapping_json, CharacterClockMapping)
    quote = _decode_json(prepared.quote_json, ResourceQuote)
    grant = _decode_json(prepared.signed_grant_json, BudgetLeaseGrant)
    lease = _decode_json(prepared.parent_budget_json, BudgetLease)
    reserve = _decode_json(prepared.reserve_receipt_json, BudgetReceipt)
    owner_guard = _decode_json(prepared.owner_guard_json, ProductionOwnerGuardV1)
    owner = _json(prepared.owner_grant_json)
    validate_owner_grant_v1(owner)
    binding = prepared.binding
    identity = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    input_payload = {"schema": "d11.offline-role-clock-tick-input.v1", "namespace": plain_v1(binding.namespace),
        "schedule": plain_v1(prepared.schedule), "clock_mapping": plain_v1(mapping),
        "clock_original_digest": binding.clock_original_digest, "scheduled_at_utc": binding.scheduled_at_utc}
    due, origin = _utc(binding.scheduled_at_utc), _utc(prepared.schedule.starts_at_utc)
    from decimal import Decimal
    delta = due - origin
    seconds = Decimal(delta.days) * 86400 + Decimal(delta.seconds) + Decimal(delta.microseconds) / 1000000
    if ((mapping.mapping_id, mapping.version) != (prepared.schedule.clock_mapping_ref, prepared.schedule.clock_mapping_version)
            or binding.cpu_ceiling_ms != prepared.schedule.cpu_ceiling_ms
            or binding.input_digest != canonical_digest(input_payload)
            or not origin <= due < _utc(prepared.schedule.valid_until_utc)
            or seconds % Decimal(prepared.schedule.cadence_seconds) != 0
            or any(getattr(binding, field) != identity[name] for field, name in (("operation_id", "operation"),
                ("activity_id", "activity"), ("execution_id", "execution"), ("job_id", "job"),
                ("quote_id", "quote"), ("reservation_operation_id", "reservation"), ("prepared_original_ref", "prepared")))
            or prepared.prepare_operation_id != "d11-offline-tick-prepare:" + binding.operation_id
            or quote.snapshot_ref != "offline-tick-input:" + binding.input_digest[:48]
            or quote.graph_job_ref != AtomKey(Owner("activity", *binding.namespace.as_tuple, binding.activity_id), "runtime.job", binding.job_id).token
            or (quote.quote_id, quote.version, quote.operation_id, quote.activity_id, quote.effect_id) !=
                (binding.quote_id, binding.quote_version, binding.operation_id, binding.activity_id, None)
            or canonical_digest(quote) != binding.quote_digest or quote.work_kind != WORK_KIND
            or quote.resource_ref != ALGORITHM_ID or quote.ceiling != {"thread_cpu_ms": binding.cpu_ceiling_ms}
            or quote.d02_settlement_refs or quote.outbox_refs or quote.job_continuation is not None
            or quote.required_worker_fence != binding.job_fence
            or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency) !=
                (*binding.namespace.as_tuple, lease.lease_id, lease.currency)
            or lease.lease_id != binding.parent_budget_lease_ref or WORK_KIND not in grant.allowed_work_kinds
            or quote.parent_budget_lease_ref != lease.lease_id or quote.valid_until_utc > grant.valid_until_utc
            or binding.cpu_ceiling_ms > grant.max_ceiling.get("thread_cpu_ms", 0)
            or (reserve.operation_id, reserve.digest, reserve.lease_id, reserve.status) !=
                (binding.reservation_operation_id, binding.reservation_digest, lease.lease_id, "reserved")
            or (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest) !=
                (binding.owner_grant_ref, binding.owner_grant_revision, binding.owner_grant_digest)
            or canonical_digest(owner) != owner_guard.grant_digest
            or binding.reservation_digest != canonical_digest(("d11.offline-role-clock-reserve.v1", binding.namespace,
                binding.operation_id, binding.input_digest, canonical_digest(quote), owner_guard))
            or (owner["authority_id"], owner["installation_id"], owner["activation_generation"]) !=
                (binding.authority_id, binding.installation_id, binding.activation_generation)
            or not set(prepared.schedule.audiences) <= set(owner["audiences"])
            or not set(prepared.schedule.purposes) <= set(owner["purposes"])):
        raise ValueError("offline preparation original quote/budget/Owner/clock binding differs")
    clock = _json(prepared.clock_original_json)
    if type(clock) is not dict or set(clock) != {"schema", "namespace", "revision", "operation_id", "original_digest", "signature"}:
        raise ValueError("offline clock original reference envelope fields differ")
    if (clock["schema"] != "d11.owner-role-clock-signed-reference.v1" or clock["namespace"] != plain_v1(binding.namespace)
            or clock["revision"] != mapping.version or clock["original_digest"] != binding.clock_original_digest):
        raise ValueError("offline clock reference differs from actual registered mapping")
    _text(clock["operation_id"])
    _digest(clock["signature"])
    final = (prepared.requirements_json, prepared.graph_revision, prepared.graph_epoch, prepared.job_projection_json, prepared.job_projection_revision)
    if any(value is not None for value in final):
        if any(value is None for value in final) or any(type(value) is not int or value < 0 for value in (prepared.graph_revision, prepared.graph_epoch)):
            raise ValueError("offline preparation must carry one complete actual post-CAS stamp")
        requirements = _decode_json(prepared.requirements_json, SnapshotRequirementsV2)
        job = _decode_json(prepared.job_projection_json, RuntimeJobValue)
        if type(prepared.job_projection_revision) is not int or prepared.job_projection_revision < 1:
            raise ValueError("offline running job needs its actual adopted projection revision")
        if (requirements.namespace != binding.namespace or requirements.authority_id != binding.authority_id
                or requirements.authority_namespace != binding.authority_namespace
                or requirements.activation_generation != binding.activation_generation
                or (job.job_id, job.operation_id, job.activity_id, job.phase, job.work_kind, job.lease_holder,
                    job.fence, job.lease_expires_utc, job.cancel_epoch) !=
                    (binding.job_id, binding.operation_id, binding.activity_id, "running", WORK_KIND,
                    binding.job_holder, binding.job_fence, binding.job_lease_expires_utc, binding.job_cancel_epoch)):
            raise ValueError("offline actual post-CAS stamp/running job differs from frozen binding")
    if len({row.ref for row in prepared.read_rows}) != len(prepared.read_rows):
        raise ValueError("offline immutable input readset repeats a key")
    from ..domain_registry import discover_domain_registry
    registry = discover_domain_registry().type_registry
    for row in prepared.read_rows:
        key = AtomKey.from_token(row.ref)
        if NamespaceId.from_key(key) != binding.namespace:
            raise ValueError("offline frozen content read crossed namespace")
        raw = _json(row.value_json)
        if row.revision == 0:
            if row.valid or raw != {}:
                raise ValueError("offline absent content read has body content")
        else:
            registry.validate(key, raw)
    return prepared


def read_current_offline_clock_reference_v1(db, *, namespace, issuer):
    from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_KIND, _mapping_original
    from .d04_semantic_installation_original_v3 import _read_signed
    original = _read_signed(db, issuer, CLOCK_TABLE, CLOCK_KIND, namespace)
    if original is None:
        raise MissingProductionOriginalV1("actual_owner_registered_offline_role_clock")
    mapping = _mapping_original(db, namespace, original)
    body, digest = original
    row = db.execute("SELECT signature FROM " + CLOCK_TABLE + " WHERE bot=? AND persona=? AND revision=?",
        (*namespace.as_tuple, mapping.version)).fetchone()
    if row is None:
        raise ValueError("offline clock actual signed original disappeared")
    return mapping, canonical_serialize({"schema": "d11.owner-role-clock-signed-reference.v1",
        "namespace": plain_v1(namespace), "revision": mapping.version, "operation_id": body["operation_id"],
        "original_digest": digest, "signature": row[0]})


def prepare_current_offline_tick_in_transaction_v1(db, *, frame, request, issuer, resource_issuer,
        schedule, clock_mapping, clock_original_json, installation_id, authority_id, authority_namespace, manifest_digest, job_holder):
    if (type(frame) is not CurrentOperationFrameV1 or type(request) is not PrepareCurrentOfflineTickRequestV1
            or type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer
            or type(schedule) is not D11OfflineScheduleOriginalV1 or type(clock_mapping) is not CharacterClockMapping):
        raise TypeError("offline tick preparation requires exact installed current inputs")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    if (schedule.namespace != ns or request.schedule_ref != schedule.schedule_ref
            or (clock_mapping.mapping_id, clock_mapping.version) != (schedule.clock_mapping_ref, schedule.clock_mapping_version)
            or frame.envelope.parent_budget_lease_ref != schedule.parent_budget_lease_ref
            or tuple(frame.envelope.authority.audience) != schedule.audiences):
        raise ValueError("offline tick differs from its actual registered schedule/clock/budget/audience")
    clock = read.original(clock_mapping.mapping_id, kind="d11.role_clock", digest=schedule.clock_original_digest)
    actual_mapping, actual_clock_json = read_current_offline_clock_reference_v1(db, namespace=ns, issuer=issuer)
    if actual_mapping != clock_mapping or actual_clock_json != clock_original_json:
        raise ValueError("offline supplied clock bytes differ from independently read current original")
    actual_schedule = read.original(schedule.schedule_ref, kind="d11.registered_schedule", digest=canonical_digest(plain_v1(schedule)))
    due, origin, until = _utc(request.scheduled_at_utc), _utc(schedule.starts_at_utc), _utc(schedule.valid_until_utc)
    from decimal import Decimal
    delta = due - origin
    seconds = Decimal(delta.days) * 86400 + Decimal(delta.seconds) + Decimal(delta.microseconds) / 1000000
    if not origin <= due < until or seconds % Decimal(schedule.cadence_seconds) != 0:
        raise ValueError("offline tick is not an exact actually authorized schedule occurrence")
    now = datetime.fromtimestamp(frame.now_utc, timezone.utc)
    if due > now:
        raise MissingProductionOriginalV1("actual_trusted_due_clock_observation")
    identity = offline_tick_ids_v1(ns, request.schedule_ref, request.scheduled_at_utc)
    if (frame.envelope.identity.operation_id, frame.envelope.identity.activity_id) != (identity["operation"], identity["activity"]):
        raise ValueError("offline occurrence must preserve its stable original operation/activity identity")
    if read_prepared_offline_tick_v1(db, namespace=ns, prepared_original_ref=identity["prepared"], issuer=issuer) is not None:
        raise MissingProductionOriginalV1("resume_actual_original_offline_tick_preparation")
    job_key = AtomKey(Owner("activity", *ns.as_tuple, identity["activity"]), "runtime.job", identity["job"])
    if read.head(db, job_key).revision != 0:
        raise ValueError("offline tick already has an actual durable job")
    parent = get_budget_lease(db, schedule.parent_budget_lease_ref)
    grant = issuer.current_budget_grant(db, parent.lease_id)
    require_budget_family_admissible(db, parent.lease_id)
    if ((parent.bot_id, parent.persona_id) != ns.as_tuple or parent.state != "active" or grant.valid_until_utc <= frame.now_utc
            or WORK_KIND not in grant.allowed_work_kinds or grant.max_ceiling.get("thread_cpu_ms", 0) <= 0):
        raise MissingProductionOriginalV1("actual_signed_offline_tick_thread_cpu_budget_grant")
    ceiling = schedule.cpu_ceiling_ms
    if ceiling > grant.max_ceiling["thread_cpu_ms"]:
        raise ValueError("explicit offline CPU quote ceiling exceeds actual signed grant")
    deadline = min(frame.envelope.deadline_utc, grant.valid_until_utc)
    wire_clock = plain_v1(clock_mapping)
    input_payload = {"schema": "d11.offline-role-clock-tick-input.v1", "namespace": plain_v1(ns),
        "schedule": plain_v1(schedule), "clock_mapping": wire_clock, "clock_original_digest": clock.original_digest,
        "scheduled_at_utc": request.scheduled_at_utc}
    input_digest = canonical_digest(input_payload)
    quote = ResourceQuote(identity["quote"], 1, *ns.as_tuple, identity["activity"], identity["operation"], None,
        parent.lease_id, WORK_KIND, "offline-tick-input:" + input_digest[:48], deadline, ALGORITHM_ID, job_key.token,
        (), (), {"thread_cpu_ms": ceiling}, 1, deadline)
    resource_issuer.issue_quote(db, quote)
    if resource_issuer.original_signed_quote(db, quote.quote_id, 1) != quote:
        raise ValueError("offline actual signed resource quote did not round-trip")
    quoted_envelope = replace(frame.envelope, deadline_utc=deadline,
        authority=replace(frame.envelope.authority, worker_fence=1),
        version_guard=replace(frame.envelope.version_guard, resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
    if issuer._admission_state(quoted_envelope, db, now_utc=frame.now_utc)[0] != quote:
        raise ValueError("offline quote is outside actual installed budget admission")
    reserve_digest = canonical_digest(("d11.offline-role-clock-reserve.v1", ns, identity["operation"],
        input_digest, canonical_digest(quote), frame.owner_guard))
    reserve = reserve_budget(db, parent.lease_id, identity["reservation"], reserve_digest, quote.ceiling)
    if reserve.status != "reserved":
        raise MissingProductionOriginalV1("actual_offline_tick_reserved_thread_cpu")
    reserve_row = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*ns.as_tuple, identity["reservation"])).fetchone()
    grant_row = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?", (parent.lease_id, grant.version)).fetchone()
    if reserve_row is None or grant_row is None:
        raise ValueError("offline tick genuine reservation/signed grant original is absent")
    deadline_text = datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z")
    job = PersistentJob(identity["job"], identity["operation"], identity["activity"], None, *ns.as_tuple,
        quote.snapshot_ref, "queued", WORK_KIND,
        {"schema": "d11.actual-offline-tick-job.v1", "prepared_original_ref": identity["prepared"],
            "schedule_ref": schedule.schedule_ref, "scheduled_at_utc": request.scheduled_at_utc,
            "source_ref": source_key(*ns.as_tuple, identity["source"]).token,
            "input_digest": input_digest, "execution_id": identity["execution"]},
        None, deadline_text, parent.lease_id, quote.resource_ref,
        {"algorithm": ALGORITHM_ID, "resource_quote": quote.quote_id + ":" + str(quote.version)}, None, None, 0, 0, {}, None)
    create_job(db, job, "create:" + identity["operation"], canonical_digest(plain_v1(job)))
    lease_seconds = min(60, int(deadline - frame.now_utc))
    if lease_seconds < 1:
        raise MissingProductionOriginalV1("actual_offline_tick_worker_deadline")
    job = acquire_job(db, job.job_id, job_holder, now_utc=now.isoformat().replace("+00:00", "Z"), lease_seconds=lease_seconds)
    binding = D11OfflineTickBindingV1(ns, authority_namespace, authority_id, installation_id, manifest_digest,
        frame.activation_generation, identity["operation"], identity["activity"], identity["execution"], identity["job"],
        job.lease_holder, job.fence, job.lease_expires_utc, job.cancel_epoch,
        schedule.schedule_ref, schedule.revision, request.scheduled_at_utc, identity["prepared"], input_digest,
        clock.original_digest, frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest,
        parent.lease_id, quote.quote_id, quote.version, canonical_digest(quote), identity["reservation"], reserve_digest,
        ceiling, deadline_text)
    owner = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    prepared = D10OfflineTickPreparedV1(binding, "d11-offline-tick-prepare:" + binding.operation_id, schedule,
        canonical_serialize(wire_clock), clock_original_json, canonical_serialize(plain_v1(quote)), grant_row[0], grant_row[1],
        canonical_serialize(plain_v1(parent)), reserve_row[0], canonical_serialize(plain_v1(frame.owner_guard)),
        canonical_serialize(owner.value), tuple(OfflineTickGraphReadV1(atom.key.token, atom.revision,
            canonical_serialize(atom.value), atom.valid) for atom in frame.snapshot.atoms if atom.key != job_key), now.isoformat().replace("+00:00", "Z"))
    stage = stage_result_v1(frame, "d10", "prepare_offline_tick", request,
        provenance={"prepared_binding": binding, "actual_schedule_original": actual_schedule,
            "actual_clock_original": clock, "execution": "requires_independent_d11_once_claim_and_actual_terminal"})
    return D10OfflineTickPreparationStageV1(frame, stage, prepared, job, (job_graph_write(job),), frame.snapshot.versions)


def read_prepared_offline_tick_v1(db, *, namespace, prepared_original_ref, issuer):
    from .d01_production_operations_v1 import table_exists_v1
    if not table_exists_v1(db, TABLE):
        return None
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='prepared_tick' AND original_ref=?", (*namespace.as_tuple, prepared_original_ref)).fetchone()
    if row is None:
        return None
    from .d11_offline_originals_v1 import SIGN_KIND
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, "prepared_tick", prepared_original_ref, row[2])), row[3])
    raw = json.loads(row[1])
    value = decode_typed_production_value_v1(raw, D10OfflineTickPreparedV1)
    if canonical_serialize(raw) != row[1] or value.digest != row[2] or value.binding.namespace != namespace:
        raise ValueError("signed actual offline preparation bytes differ")
    from .domain_production_read_plans_v1 import _committed
    _committed(db, namespace, row[0])
    if value.prepare_operation_id != row[0] or value.binding.prepared_original_ref != prepared_original_ref:
        raise ValueError("offline preparation lost its actual producing operation")
    if value.requirements_json is None:
        raise ValueError("offline immutable prepared original lacks its actual post-CAS stamp")
    return value


def _verify_offline_original_inputs_v1(db, prepared, issuer, resource_issuer, now_utc, *, for_execution=True):
    """Read-only signature, reservation, clock and registered policy joins."""
    from .d11_offline_originals_v1 import read_current_d11_offline_value_v1
    from .d01_production_operations_v1 import table_exists_v1
    ns, binding = prepared.binding.namespace, prepared.binding
    schedule = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=binding.schedule_ref, issuer=issuer)
    if schedule != prepared.schedule:
        raise ValueError("offline original registered schedule differs from frozen content")
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' ORDER BY original_ref LIMIT 129", ns.as_tuple).fetchall()
    if len(rows) > 128:
        raise ValueError("offline current schedule inventory exceeds its bound")
    group = tuple(value for (ref,) in rows if (value := read_current_d11_offline_value_v1(db, namespace=ns,
        original_ref=ref, issuer=issuer)).schedule_id == schedule.schedule_id)
    if max(value.revision for value in group) != schedule.revision:
        raise ValueError("offline prepared schedule has been explicitly superseded")
    recipe_row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 "
        "WHERE bot=? AND persona=? AND kind='offline_recipe' AND original_ref=?", (*ns.as_tuple, schedule.recipe_ref)).fetchone()
    schedule_row = db.execute("SELECT producing_operation_id FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' AND original_ref=?",
        (*ns.as_tuple, schedule.schedule_ref)).fetchone()
    if recipe_row is None or schedule_row is None or recipe_row[0] != schedule_row[0]:
        raise ValueError("offline actual schedule/recipe producing operation differs")
    issuer._signer.verify("d11.d10-production-input.v1", recipe_row[1], recipe_row[3])
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, offline_tick_recipe_to_wire_v1
    recipe = _decode_json(recipe_row[1], OfflineTickRecipeV1)
    if (canonical_digest(offline_tick_recipe_to_wire_v1(recipe)) != recipe_row[2] or (recipe.recipe_id, recipe.version,
            recipe.schedule_ref, recipe.cadence_seconds, recipe.max_ticks_per_slice, recipe.cadence_origin_utc) != (schedule.recipe_ref, schedule.revision,
            VersionedRef(schedule.schedule_ref, schedule.revision), schedule.cadence_seconds, schedule.max_ticks_per_slice, schedule.starts_at_utc)):
        raise ValueError("offline original recipe does not bind its exact registered schedule")
    mapping, clock_json = read_current_offline_clock_reference_v1(db, namespace=ns, issuer=issuer)
    if prepared.clock_mapping_json != canonical_serialize(plain_v1(mapping)) or prepared.clock_original_json != clock_json:
        raise ValueError("offline current signed clock original/mapping changed")
    quote = resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    if prepared.quote_json != canonical_serialize(plain_v1(quote)):
        raise ValueError("offline signed original quote changed")
    grant = issuer.current_budget_grant(db, binding.parent_budget_lease_ref)
    grant_row = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",
        (grant.lease_id, grant.version)).fetchone()
    if grant_row != (prepared.signed_grant_json, prepared.signed_grant_signature):
        raise ValueError("offline original signed grant changed")
    current = get_budget_lease(db, binding.parent_budget_lease_ref)
    original = _decode_json(prepared.parent_budget_json, BudgetLease)
    if (current.state != "active" or (current.lease_id, current.parent_id, current.bot_id, current.persona_id, current.currency, current.limits) !=
            (original.lease_id, original.parent_id, original.bot_id, original.persona_id, original.currency, original.limits)
            or (for_execution and (grant.valid_until_utc <= now_utc or _utc(binding.deadline_utc).timestamp() <= now_utc
                or _utc(binding.job_lease_expires_utc).timestamp() <= now_utc))):
        raise ValueError("offline prepared budget or original worker deadline is no longer current")
    reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
    reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*ns.as_tuple, binding.reservation_operation_id)).fetchone()
    if (reservation != (binding.reservation_digest, canonical_serialize({"thread_cpu_ms": binding.cpu_ceiling_ms}), "reserved", None)
            or reserve != (prepared.reserve_receipt_json,)):
        raise ValueError("offline actual reserved CPU/receipt differs from original preparation")
    require_budget_family_admissible(db, binding.parent_budget_lease_ref)
    return prepared


def _verify_offline_content_rows_v1(db, prepared):
    for frozen in prepared.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (frozen.ref,)).fetchone()
        expected = (frozen.revision, frozen.value_json, int(frozen.valid))
        if frozen.revision == 0 and row is None:
            continue
        if row != expected:
            raise ValueError("offline frozen actual current input row changed")
    return prepared


def _verify_offline_running_job_v1(prepared, job):
    binding, schedule = prepared.binding, prepared.schedule
    ids = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    expected_continuation = {"schema": "d11.actual-offline-tick-job.v1", "prepared_original_ref": binding.prepared_original_ref,
        "schedule_ref": schedule.schedule_ref, "scheduled_at_utc": binding.scheduled_at_utc,
        "source_ref": source_key(*binding.namespace.as_tuple, ids["source"]).token,
        "input_digest": binding.input_digest, "execution_id": binding.execution_id}
    if ((job.job_id, job.operation_id, job.activity_id, job.effect_id, job.bot_id, job.persona_id, job.phase,
            job.work_kind, job.lease_holder, job.fence, job.lease_expires_utc, job.cancel_epoch,
            job.deadline_utc, job.budget_ref, job.resource_ref, job.snapshot_ref) !=
            (binding.job_id, binding.operation_id, binding.activity_id, None, *binding.namespace.as_tuple, "running",
            WORK_KIND, binding.job_holder, binding.job_fence, binding.job_lease_expires_utc, 0,
            binding.deadline_utc, binding.parent_budget_lease_ref, ALGORITHM_ID, "offline-tick-input:" + binding.input_digest[:48])
            or dict(job.continuation) != expected_continuation or job.wake_condition is not None or job.result_ref is not None
            or dict(job.usage) or dict(job.operator_versions) != {"algorithm": ALGORITHM_ID, "resource_quote": binding.quote_id + ":" + str(binding.quote_version)}):
        raise ValueError("offline actual acquired job content/continuation differs from exact preparation")
    return job


def verify_offline_preparation_in_transaction_v1(db, preparation, issuer, resource_issuer):
    if type(preparation) is not D10OfflineTickPreparationStageV1 or not db.in_transaction:
        raise TypeError("exact pending offline preparation under W01 transaction required")
    frame, prepared = preparation.frame, preparation.prepared
    CurrentDomainReadV1(frame).check(db)
    if prepared.requirements_json is not None or prepared.binding.namespace != frame.envelope.authority.namespace:
        raise ValueError("pending offline stage carries another/final preparation")
    validate_offline_tick_prepared_content_v1(prepared)
    _verify_offline_original_inputs_v1(db, prepared, issuer, resource_issuer, frame.now_utc)
    _verify_offline_content_rows_v1(db, prepared)
    if (get_job(db, prepared.binding.job_id) != preparation.job
            or preparation.writes != (job_graph_write(preparation.job),)
            or preparation.read_versions != frame.snapshot.versions):
        raise ValueError("pending offline actual acquired job/write/readset differs")
    _verify_offline_running_job_v1(prepared, preparation.job)
    job_key = job_graph_write(preparation.job).key
    if frame.snapshot.get(job_key).revision != 0 or db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (job_key.token,)).fetchone():
        raise ValueError("offline new acquired job projection lacks actual pre-CAS absence")
    return preparation


def read_current_prepared_offline_tick_v1(db, *, binding, issuer, resource_issuer, now_utc, for_execution=True):
    if type(binding) is not D11OfflineTickBindingV1 or type(for_execution) is not bool or not db.in_transaction:
        raise TypeError("actual current offline prepared read requires exact binding and pinned SQL")
    prepared = read_prepared_offline_tick_v1(db, namespace=binding.namespace, prepared_original_ref=binding.prepared_original_ref, issuer=issuer)
    if prepared is None or prepared.binding != binding:
        raise ValueError("actual signed offline preparation is missing or has another binding")
    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
    if metadata != (prepared.requirements_json, prepared.graph_revision) or epoch != (prepared.graph_epoch,):
        raise ValueError("offline first claim current full Graph stamp differs from actual post-CAS preparation")
    _verify_offline_original_inputs_v1(db, prepared, issuer, resource_issuer, now_utc, for_execution=for_execution)
    _verify_offline_content_rows_v1(db, prepared)
    job = get_job(db, binding.job_id)
    _verify_offline_running_job_v1(prepared, job)
    if (job.phase, job.lease_holder, job.fence, job.lease_expires_utc, job.cancel_epoch) != (
            "running", binding.job_holder, binding.job_fence, binding.job_lease_expires_utc, binding.job_cancel_epoch):
        raise ValueError("offline actual current acquired worker lease changed")
    write = job_graph_write(job)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (write.key.token, prepared.job_projection_revision)).fetchone()
    if (row != (prepared.job_projection_revision, prepared.job_projection_json, 1)
            or history != (prepared.prepare_operation_id, prepared.job_projection_json, 1)
            or canonical_serialize(write.value) != prepared.job_projection_json):
        raise ValueError("offline current running job is not its actual prepare-CAS member")
    return prepared


def record_offline_tick_preparation_after_cas_v1(db, *, issuer, preparation, graph_receipt):
    from ..runtime_contracts import CommitReceipt
    if (type(preparation) is not D10OfflineTickPreparationStageV1 or type(graph_receipt) is not CommitReceipt
            or graph_receipt.status != "committed" or graph_receipt.operation_id != preparation.prepared.prepare_operation_id):
        raise TypeError("offline preparation needs its exact actual same-transaction W01 CAS receipt")
    prepared = preparation.prepared
    actual = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*prepared.binding.namespace.as_tuple, prepared.prepare_operation_id)).fetchone()
    if actual != (graph_receipt.operation_digest, graph_receipt.commit_seq):
        raise ValueError("offline preparation was not committed by its actual bundle")
    adopted = {version.key: version.revision for version in graph_receipt.write_versions}
    for write in preparation.writes:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[2] != 1 or row[0] != adopted.get(write.key) or json.loads(row[1]) != write.value:
            raise ValueError("offline prepared job projection is not the actual adopted member")
    if get_job(db, prepared.binding.job_id) != preparation.job:
        raise ValueError("offline preparation job differs from its actual runtime original")
    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        prepared.binding.namespace.as_tuple).fetchone()
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", prepared.binding.namespace.as_tuple).fetchone()
    job_key = job_graph_write(preparation.job).key
    job_row = db.execute("SELECT value,revision FROM graph_atoms WHERE token=?", (job_key.token,)).fetchone()
    if metadata is None or epoch is None or job_row is None:
        raise ValueError("offline preparation actual post-CAS metadata/job is absent")
    prepared = replace(prepared, requirements_json=metadata[0], graph_revision=metadata[1], graph_epoch=epoch[0],
        job_projection_json=job_row[0], job_projection_revision=job_row[1])
    from .d11_offline_originals_v1 import SIGN_KIND
    wire, digest = canonical_serialize(plain_v1(prepared)), prepared.digest
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((prepared.binding.namespace, "prepared_tick",
        prepared.binding.prepared_original_ref, digest)))
    expected = (prepared.prepare_operation_id, wire, digest, signature)
    prior = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='prepared_tick' AND original_ref=?",
        (*prepared.binding.namespace.as_tuple, prepared.binding.prepared_original_ref)).fetchone()
    if prior is not None and prior != expected:
        raise ValueError("offline prepared identity replay changed its original")
    if prior is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*prepared.binding.namespace.as_tuple,
            "prepared_tick", prepared.binding.prepared_original_ref, *expected))
    from .d11_offline_accounting_v1 import record_offline_accounting_prepared_after_cas_v1
    record_offline_accounting_prepared_after_cas_v1(db, issuer=issuer, prepared=prepared)
    return ProductionOriginalRefV1("d11.prepared_offline_tick", prepared.binding.prepared_original_ref, digest)
