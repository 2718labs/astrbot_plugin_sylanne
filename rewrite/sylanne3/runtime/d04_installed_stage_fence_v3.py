"""Installed post-C02 D04 stages under the current Owner/Authority write fence.

The callable here is a W01-owned implementation selected by a fixed stage, not
an executable field in any user or model request. No long work runs in SQL.
"""
from __future__ import annotations

from contextlib import nullcontext, contextmanager
from dataclasses import asdict
import json
import logging
import time

from ..authority_service.v2_contract import from_wire, to_wire
from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..contracts import StaleRead
from ..graph_types import NamespaceEpoch
from ..runtime_contracts import FenceScope, canonical_digest, canonical_serialize
from .first_ingress_v2 import trusted_upper
from .restore_anchor import RestoreAnchor

TABLE = "graph_d04_installed_stage_attempts_v3"
STAGES = frozenset({"interpretation", "prepare", "acquire", "seal_call", "settle", "adopt", "drive", "numeric_prepare", "numeric_adopt", "c04_encoding"})

_TIMING_PHASES = frozenset({"installed_stage_total", "authority_owner_clock", "sql_transaction", "stage_callback",
    "drive", "root_freeze", "prior_adoption", "prepare_inspect", "queue_wait", "terminal_persist", "cpu_settle",
    "hot_handoff", "cold_restore_decode_verify", "final_adoption", "post_encoding", "progress_scan",
    "prefix_collection", "prefix_manifest_rpc", "packet_hash", "packet_decode", "prefix_restore",
    "final_derive_numeric_verify", "installed_asset_verify", "authority_gate_validate", "business_transaction"})
_TIMING_LOG = logging.getLogger(__name__)


class _D04PhaseTimingsV1:
    """Finite diagnostic counters, never an authorization or CPU measurement.

    UTC is explicitly absent until an existing qualified paired clock is bound.
    Advancing that same upper bound uses local monotonic time; no extra RPC,
    body, permit token, unbounded trace list or persistent state is introduced.
    """
    def __init__(self, operation_id, *, deadline_utc=None):
        self.operation_id, self.deadline_utc = operation_id, deadline_utc
        self.seconds = dict.fromkeys(_TIMING_PHASES, 0.0)
        self.counts = dict.fromkeys(_TIMING_PHASES, 0)
        self.clock_reading = None

    def bind_clock(self, reading):
        self.clock_reading = reading

    def _upper(self):
        if self.clock_reading is None:
            return None
        # Diagnostics cannot replace/mask the actual stage's clock rejection.
        try:
            return trusted_upper(self.clock_reading)
        except (ValueError, TypeError, AttributeError):
            return None

    @contextmanager
    def measure(self, phase, *, chunk_start=None):
        if phase not in _TIMING_PHASES:
            raise ValueError("unknown finite D04 timing phase")
        started = time.monotonic()
        upper_start = self._upper()
        outcome = "completed"
        try:
            yield
        except BaseException as failure:
            outcome = type(failure).__name__
            raise
        finally:
            finished = time.monotonic()
            elapsed = finished - started
            self.seconds[phase] += elapsed
            self.counts[phase] += 1
            _TIMING_LOG.info("D04 phase timing schema=d04.phase-timing.v1 operation_id=%s phase=%s chunk_start=%s "
                "wall_seconds=%.9f monotonic_start=%.9f monotonic_end=%.9f trusted_utc_upper_start=%s "
                "trusted_utc_upper_end=%s fixed_deadline_utc=%s outcome=%s",
                self.operation_id, phase, chunk_start, elapsed, started, finished, upper_start,
                self._upper(), self.deadline_utc, outcome)


def install_schema(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        stage TEXT NOT NULL, c02_operation_id TEXT NOT NULL, source_ref TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL,
        anchor_json TEXT NOT NULL, pre_revision INTEGER NOT NULL, pre_epoch INTEGER NOT NULL,
        permit_json TEXT, receipt_json TEXT, PRIMARY KEY(bot,persona,operation_id))""")


def run_installed_d04_stage_v3(graph, bootstrap, bundle, *, c02_operation_id,
        source_ref, operation_id, stage, request_digest, commit, semantic=False, fence_observer=None):
    timings = _D04PhaseTimingsV1(operation_id)
    with timings.measure("installed_stage_total"):
        return _run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id,
            source_ref=source_ref, operation_id=operation_id, stage=stage, request_digest=request_digest,
            commit=commit, semantic=semantic, fence_observer=fence_observer, timings=timings)


def _run_installed_d04_stage_v3(graph, bootstrap, bundle, *, c02_operation_id,
        source_ref, operation_id, stage, request_digest, commit, semantic, fence_observer, timings):
    from ..host.authority_profile import AdminInstallationBundle
    from ..graph_coordinator import AuthorityDenied
    graph._admin(bootstrap)
    if type(bundle) is not AdminInstallationBundle or stage not in STAGES:
        raise ValueError("actual installed D04 stage required")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise ValueError("D04 installed stage differs from active assembly")
    policy, namespace = bundle.installation_policy, bundle.installation_policy.namespace
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    attempt = "d04-stage:" + canonical_digest((namespace, operation_id, stage, request_digest))[:48]
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        saved = store._db.execute(f"SELECT stage,c02_operation_id,source_ref,request_digest,attempt_id,anchor_json,"
            f"pre_revision,pre_epoch,permit_json,receipt_json FROM {TABLE} WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, operation_id)).fetchone()
    target = metadata.requirements
    anchor = port.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target, anchor):
        raise StaleRead("D04 installed stage Graph/Authority anchor differs")
    if saved is not None:
        if saved[:5] != (stage, c02_operation_id, source_ref, request_digest, attempt):
            raise ValueError("D04 installed stage original identity conflict")
        if saved[9] is None and (RestoreAnchor(**json.loads(saved[5])) != anchor
                or saved[6:8] != (metadata.graph_revision, epoch.revision)):
            raise StaleRead("D04 unresolved stage cannot change its original snapshot")
    else:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("D04 graph changed before durable stage intent")
                store._db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                    (*namespace.as_tuple, operation_id, stage, c02_operation_id, source_ref,
                     request_digest, attempt, canonical_serialize(asdict(anchor)), metadata.graph_revision, epoch.revision))
                store._db.commit()
            except BaseException:
                store._db.rollback()
                raise
    if saved is not None and saved[8] is not None:
        permit = from_wire(json.loads(saved[8]))
        actual, state = port.get_fence_operation(namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=attempt)
        if actual != permit or state not in {"active", "finished"}:
            raise ValueError("D04 original stage permit is unavailable")
    else:
        permit = port.begin_fence(namespace=namespace, authority_namespace=target.authority_namespace,
            holder=policy.administrator_holder, generation=target.activation_generation,
            operation="write", operation_id=attempt, expected_anchor=anchor, retain_on_unknown=True)
        state = "active"
    pre_revision, pre_epoch = saved[6:8] if saved else (metadata.graph_revision, epoch.revision)
    scope = FenceScope(namespace, target.authority_namespace, target.activation_generation, "write", attempt,
        permit, permit.pinned_anchor, NamespaceEpoch(*namespace.as_tuple, pre_epoch), pre_revision)
    finish = "sha256:" + canonical_digest(("d04.installed-stage.v3", operation_id, request_digest, permit.token))
    if saved is not None and saved[9] is not None:
        if state == "active":
            port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
        # A known local rejection is a durable, content-free terminal for this
        # exact stage request. It never authorizes a paid retry or a new result.
        restored = json.loads(saved[9])
        if restored.get("status") == "held":
            raise ValueError("D04 original stage held: " + restored["reason"])
        return restored
    if state != "active" or port.validate_fence(scope) != permit:
        raise ValueError("D04 current installed stage write unavailable")
    try:
        with timings.measure("authority_owner_clock"):
            from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
            guarded = port.get_current_background_owner_authority_for_fence_v1(namespace=namespace,
                authority_namespace=target.authority_namespace, permit=permit)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not D12CurrentOwnerAuthorityV1 or guarded[1] != permit
                    or type(guarded[0].guard) is not OwnerAuthorizationGuardV1):
                raise ValueError("D04 actual current Owner guard unavailable")
            current_owner, guard = guarded[0], guarded[0].guard
            clock_reading = port.read_ingress_clock(bundle.ingress_clock)
            timings.bind_clock(clock_reading)
            now = trusted_upper(clock_reading)
        semantic_reader = getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
        if semantic and semantic_reader is None:
            raise ValueError("current installed D04 semantic reader unavailable")
        if fence_observer is not None:
            fence_observer(scope)
        if (current_owner.target_admission is not None or current_owner.storage_admission is not None) and semantic_reader is None:
            raise ValueError("D04 migrated background work needs its actual installed location verifier")
        semantic_context = semantic_reader.current_fence(scope) if (semantic or current_owner.target_admission is not None or current_owner.storage_admission is not None) else nullcontext()
        with semantic_context, timings.measure("sql_transaction"):
            with store._lock:
                db = store._db
                db.execute(f"UPDATE {TABLE} SET permit_json=? WHERE bot=? AND persona=? AND operation_id=? AND permit_json IS NULL",
                    (canonical_serialize(to_wire(permit)), *namespace.as_tuple, operation_id))
                db.execute("BEGIN IMMEDIATE")
                try:
                    if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("D04 graph changed before stage adoption")
                    role, _bindings, role_epoch, _versions = graph._scene_binding_state_locked(namespace, guard)
                    if (role_epoch != epoch or current_owner.target_admission is None
                            and guard.installation_id != policy.installation_id):
                        raise StaleRead("D04 installed Owner scope changed")
                    if current_owner.target_admission is not None or current_owner.storage_admission is not None:
                        semantic_reader._require_current_location(db, namespace, scope)
                    if stage in {"drive", "numeric_prepare", "c04_encoding"}:
                        from .d04_current_source_context_v3 import read_current_d04_post_appraisal_context_v3
                        current = read_current_d04_post_appraisal_context_v3(graph, db, namespace,
                            c02_operation_id, source_ref, now, epoch)
                    else:
                        current = graph._current_natural_generation_inputs_locked(namespace, c02_operation_id, source_ref, now, epoch)
                    with timings.measure("stage_callback"):
                        result = commit(db, metadata, epoch, now, guard, role, current)
                    db.execute(f"UPDATE {TABLE} SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND receipt_json IS NULL",
                        (canonical_serialize(result), *namespace.as_tuple, operation_id))
                    if db.execute("SELECT changes()").fetchone() != (1,):
                        raise ValueError("D04 original stage receipt raced")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
    except (ValueError, TypeError, StaleRead, AuthorityDenied) as exc:
        # All callbacks are fixed W01 SQL-only stages. A deterministic local
        # rejection, with the original business stamp unchanged and no saved
        # result, can close this retained fence. A transport/SQL uncertainty is
        # deliberately outside this branch and remains recoverable unknown.
        from .d04_appraisal_driver_v3 import record_d04_original_in_transaction_v3
        with store._lock:
            db = store._db
            if db.in_transaction:
                raise RuntimeError("D04 rejected stage rollback is uncertain") from exc
            observed = db.execute(f"SELECT attempt_id,receipt_json FROM {TABLE} WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, operation_id)).fetchone()
            if observed != (attempt, None) or graph._v2_graph_stamp(namespace) != (metadata, epoch):
                raise
            refused = {"schema": "d04.installed-stage-refusal.v3", "status": "held",
                "operation_id": operation_id, "attempt_id": attempt, "stage": stage,
                "request_digest": request_digest, "reason": type(exc).__name__,
                "permit_digest": canonical_digest(to_wire(permit)),
                "anchor_digest": canonical_digest(asdict(anchor)),
                "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision}
            db.execute("BEGIN IMMEDIATE")
            try:
                record_d04_original_in_transaction_v3(db, namespace, "stage_refusal", attempt, refused)
                db.execute(f"UPDATE {TABLE} SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND attempt_id=? AND receipt_json IS NULL",
                    (canonical_serialize(refused), *namespace.as_tuple, operation_id, attempt))
                if db.execute("SELECT changes()").fetchone() != (1,):
                    raise ValueError("D04 rejected stage original raced")
                db.commit()
            except BaseException:
                db.rollback()
                raise
        port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
        raise
    port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
    return result
