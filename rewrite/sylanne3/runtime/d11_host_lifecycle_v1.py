"""Installed Host observations captured at actual startup and drained shutdown.

This private seam accepts the bound RuntimeContext, not an Owner-supplied event
or timestamp. The paired trusted clock and W01 admission supply the fact time.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from uuid import uuid4

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d06 import SourceAdmission
from ..graph_types import GraphVersion, Owner, owner_grant_key
from ..memory_types import source_key, access_key
from ..runtime_contracts import DomainProposal, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d11_offline_originals_v1 import D11HostLifecycleOriginalV1, record_d11_offline_original_in_transaction_v1

_CAPTURE = object()


@dataclass(frozen=True, slots=True, init=False)
class _ActualHostLifecycleObservationV1:
    _service: object
    kind: str
    namespace: object
    host_incarnation: str
    observation_id: str

    def __init__(self, key, service, kind):
        if key is not _CAPTURE:
            raise TypeError("Host lifecycle observation must come from installed capture")
        for name, value in (("_service", service), ("kind", kind), ("namespace", service.context._v2_namespace),
                ("host_incarnation", service.host_incarnation), ("observation_id", str(uuid4()))):
            object.__setattr__(self, name, value)


class InstalledHostLifecycleObserverV1:
    def __init__(self, context):
        from ..runtime_context import RuntimeContext
        if type(context) is not RuntimeContext:
            raise TypeError("actual installed RuntimeContext required")
        self.context = context
        self.host_incarnation = "host-runtime:" + str(uuid4())
        self._observations = {}
        self._capture_fields = {}

    def _check(self, kind):
        ctx = self.context
        if (ctx._worker is None or ctx._v2_coordinator is None or ctx._v2_namespace is None
                or ctx._v2_bootstrap is None or ctx._v2_installation_grant is None
                or not ctx._v2_namespace_provisioned):
            raise MissingProductionOriginalV1("actual_running_paired_host_installation")
        if kind == "host_reconnect":
            if ctx.health.status not in {"ready", "limited"}:
                raise MissingProductionOriginalV1("actual_host_startup_ready_state")
        elif kind == "host_disconnect":
            tasks = tuple(ctx._d04_numeric_tasks.values()) + ((ctx._d04_numeric_scan_task,) if ctx._d04_numeric_scan_task is not None else ())
            if (ctx.health.status != "draining" or ctx.v2_ingress_qualified or not ctx._domain_followup_stopping or not ctx._d04_numeric_stopping
                    or ctx._v2_d07_execution_service is not None
                    or ctx._domain_followup_task is not None and not ctx._domain_followup_task.done()
                    or ctx._offline_recovery_task is not None and not ctx._offline_recovery_task.done()
                    or any(not task.done() for task in tasks)):
                raise MissingProductionOriginalV1("actual_host_domain_and_cognition_drain")
        else:
            raise ValueError("unregistered Host observation kind")

    def capture_startup_v1(self):
        return self._capture("host_reconnect")

    def capture_drained_shutdown_v1(self):
        return self._capture("host_disconnect")

    def _capture(self, kind):
        self._check(kind)
        if kind not in self._observations:
            self._observations[kind] = _ActualHostLifecycleObservationV1(_CAPTURE, self, kind)
            captured = self._observations[kind]
            self._capture_fields[kind] = (captured.namespace, captured.host_incarnation, captured.observation_id)
        return self._observations[kind]

    def verify_observation_v1(self, observation):
        if (type(observation) is not _ActualHostLifecycleObservationV1 or observation._service is not self
                or self._observations.get(observation.kind) is not observation):
            raise TypeError("genuine bound Host observation required")
        if ((observation.namespace, observation.host_incarnation, observation.observation_id) != self._capture_fields.get(observation.kind)
                or observation.namespace != self.context._v2_namespace or observation.host_incarnation != self.host_incarnation):
            raise ValueError("captured Host observation identity was altered")
        self._check(observation.kind)
        return observation


@dataclass(frozen=True, slots=True)
class HostLifecycleRequestV1:
    kind: str
    host_incarnation: str
    observation_id: str


@dataclass(frozen=True, slots=True)
class HostLifecycleStageV1:
    stage: object
    memory_proposal: DomainProposal
    original: D11HostLifecycleOriginalV1
    observer: InstalledHostLifecycleObserverV1
    observation: _ActualHostLifecycleObservationV1
    member_domains: tuple[str, ...] = ("d06", "d11")
    bundle_kind: str = "d11.actual-host-lifecycle-source.v1"


def read_current_host_lifecycle_scope_v1(db, *, namespace, issuer, now_utc):
    from .d11_offline_originals_v1 import TABLE, read_current_d11_offline_value_v1, read_current_d11_offline_original_ref_v1, _utc
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='registered_schedule' ORDER BY original_ref LIMIT 129", namespace.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("bounded_actual_offline_schedule_lifecycle_audience")
    latest = {}
    for (ref,) in rows:
        schedule = read_current_d11_offline_value_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if schedule.schedule_id not in latest or latest[schedule.schedule_id].revision < schedule.revision:
            latest[schedule.schedule_id] = schedule
    owner_row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (owner_grant_key(*namespace.as_tuple).token,)).fetchone()
    if owner_row is None or owner_row[1] != 1:
        raise MissingProductionOriginalV1("actual_current_owner_host_lifecycle_scope")
    owner = json.loads(owner_row[0])
    active = tuple(schedule for schedule in latest.values() if _utc(schedule.starts_at_utc).timestamp() <= now_utc < _utc(schedule.valid_until_utc).timestamp())
    audiences = set().union(*(set(schedule.audiences) for schedule in active)) if active else {"owner"}
    purposes = set().union(*(set(schedule.purposes) for schedule in active)) if active else {"context", "audit"}
    audiences &= set(owner["audiences"])
    purposes &= set(owner["purposes"])
    if not audiences or not purposes:
        raise MissingProductionOriginalV1("actual_owner_intersection_host_lifecycle_permissions")
    originals = tuple(read_current_d11_offline_original_ref_v1(db, namespace=namespace,
        original_ref=schedule.schedule_ref, issuer=issuer) for schedule in sorted(active, key=lambda item:item.schedule_ref))
    return tuple(sorted(audiences)), tuple(sorted(purposes)), originals


def read_plan_current_host_lifecycle_v1(db, *, namespace, observation, issuer, now_utc):
    observation._service.verify_observation_v1(observation)
    if namespace != observation.namespace:
        raise ValueError("Host lifecycle capture crossed installation namespace")
    source_id = "d11-host-lifecycle:" + canonical_digest((namespace, observation.host_incarnation, observation.kind, observation.observation_id))[:48]
    _, _, originals = read_current_host_lifecycle_scope_v1(db, namespace=namespace, issuer=issuer, now_utc=now_utc)
    return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple), source_key(*namespace.as_tuple, source_id),
        access_key(*namespace.as_tuple, source_id)), (), tuple(original.original_ref for original in originals))


def stage_current_host_lifecycle_in_transaction_v1(db, *, frame, observer, observation, issuer):
    observer.verify_observation_v1(observation)
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    if ns != observation.namespace:
        raise ValueError("actual Host observation differs from current Owner frame")
    ticks = tuple(original for original in frame.observed_originals if original.kind == "d11.trusted_tick")
    if len(ticks) != 1 or ticks[0].original_ref != "d11-tick:" + frame.envelope.identity.operation_id:
        raise MissingProductionOriginalV1("actual_paired_host_lifecycle_trusted_clock")
    request = HostLifecycleRequestV1(observation.kind, observation.host_incarnation, observation.observation_id)
    source_id = "d11-host-lifecycle:" + canonical_digest((ns, observation.host_incarnation, observation.kind, observation.observation_id))[:48]
    source_ref = source_key(*ns.as_tuple, source_id)
    access_ref = access_key(*ns.as_tuple, source_id)
    if read.head(db, source_ref).revision or read.head(db, access_ref).revision:
        raise ValueError("actual lifecycle observation was already adopted; read its producing receipt")
    owner = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    audiences, purposes, schedules = read_current_host_lifecycle_scope_v1(db, namespace=ns, issuer=issuer, now_utc=frame.now_utc)
    if frame.envelope.authority.audience != audiences:
        raise ValueError("Host lifecycle audience differs from actual current registered schedule/Owner intersection")
    for schedule in schedules:
        read.original(schedule.original_ref, kind=schedule.kind, digest=schedule.original_digest)
    timestamp = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    original_ref = "d11-host-observation:" + canonical_digest((ns, request))[:48]
    original = D11HostLifecycleOriginalV1(ns, original_ref, observation.kind, observation.host_incarnation,
        timestamp, ticks[0].original_ref, ticks[0].original_digest, source_ref.token, 1,
        "quiesced_ingress_gated" if observation.kind == "host_disconnect" else "paired_runtime_ready")
    text = canonical_serialize({"schema": "d11.actual-host-lifecycle-content.v1", "kind": observation.kind,
        "host_incarnation": observation.host_incarnation, "installation_id": owner.value["installation_id"],
        "observation_scope": original.observation_scope, "boundary_state": original.boundary_state})
    admission = SourceAdmission(source_id, text, "persona:" + ns.persona_id, "internal", "observed", "subjective_only",
        "committed", frame.now_utc, frame.now_utc, "host-runtime:" + observation.host_incarnation,
        frame.envelope.authority.audience, purposes)
    from .d10_production_operations_v1 import _memory_experience_proposal_v1
    proposal, _, _ = _memory_experience_proposal_v1(frame, (admission,))
    stage = stage_result_v1(frame, "d11", "record_host_lifecycle", request,
        provenance={"actual_lifecycle_original": original, "trusted_clock_original": ticks[0]})
    return HostLifecycleStageV1(stage, proposal, original, observer, observation)


def record_host_lifecycle_after_cas_v1(db, *, frame, staged, graph_receipt, issuer):
    if type(staged) is not HostLifecycleStageV1 or graph_receipt.operation_id != frame.envelope.identity.operation_id:
        raise TypeError("exact actual Host lifecycle composite receipt required")
    staged.observer.verify_observation_v1(staged.observation)
    original = staged.original
    versions = {version.key: version.revision for version in graph_receipt.write_versions}
    for write in staged.memory_proposal.typed_writes:
        row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (write.key.token, versions.get(write.key, 0))).fetchone()
        if row is None or row[0] != graph_receipt.operation_id or row[2] != 1 or json.loads(row[1]) != write.value:
            raise ValueError("Host source is not an actual adopted same-transaction composite member")
    from .domain_production_inputs_v1 import _post_commit_frame
    current = _post_commit_frame(db, frame, HostLifecycleRequestV1(original.kind, original.host_incarnation, staged.observation.observation_id))
    return record_d11_offline_original_in_transaction_v1(db, issuer=issuer, frame=current,
        kind=original.kind, original_ref=original.lifecycle_ref, value=original, producing_operation_id=graph_receipt.operation_id)
