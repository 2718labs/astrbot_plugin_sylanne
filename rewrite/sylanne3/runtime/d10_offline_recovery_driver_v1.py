"""Bounded installed recovery of actual logical-runtime offline intervals."""
from dataclasses import dataclass
import json

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..graph_types import owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest, canonical_serialize
from ..domains.d10.offline_interval import scheduled_offline_ticks_v1, decode_offline_tick_recipe_v1
from ..domains.d10.production_operations_v1 import AdvanceCurrentOfflineRequestV1
from .d10_offline_inputs_v1 import (
    RegisterCurrentOfflineIntervalInputRequestV1, require_adjacent_host_lifecycle_pair_v1,
)
from .d10_offline_tick_execution_v1 import (
    PrepareCurrentOfflineTickRequestV1, offline_tick_ids_v1, read_prepared_offline_tick_v1,
)
from .d11_offline_originals_v1 import TABLE, _utc, read_current_d11_offline_value_v1
from .d11_offline_adoption_v1 import _read_signed

_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _BackgroundOfflineCommandV1:
    context: object
    graph: object
    authority: AuthorityContext
    owner: object
    operation_id: str
    operation_kind: str
    request: object


def require_background_offline_command_v1(value, graph, authority, operation_id):
    from ..runtime_context import RuntimeContext
    if (type(value) is not _BackgroundOfflineCommandV1 or _ACTIVE.get(id(value)) is not value
            or type(value.context) is not RuntimeContext or value.context._v2_coordinator is not graph
            or value.graph is not graph or value.authority != authority or value.operation_id != operation_id
            or value.context._offline_recovery_stopping or value.context.health.status not in {"ready", "limited"}):
        raise ValueError("offline recovery requires its actual running installed Host command")
    exact = {"prepare_offline_tick": PrepareCurrentOfflineTickRequestV1,
        "input:register_offline_interval": RegisterCurrentOfflineIntervalInputRequestV1,
        "advance_offline": AdvanceCurrentOfflineRequestV1}
    if value.operation_kind not in exact or type(value.request) is not exact[value.operation_kind]:
        raise ValueError("offline background command cannot select another operation")
    return value.owner


def _command(context, graph, schedule, kind, request, operation_id, activity_id):
    from .domain_followup_consumer_v1 import _observe_owner
    from .domain_background_read_v3 import _active_v3, bind_background_reads_v3
    actual=_active_v3(graph._GraphCoordinator__store._db)
    if actual is not None:
        if actual.kind!='offline' or not actual.sealed or actual.context is not context:
            raise ValueError('offline child requires its independently completed actual background reader')
        from dataclasses import replace
        authority=replace(actual.authority,purpose=schedule.purposes[0],audience=schedule.audiences)
        issued=_BackgroundOfflineCommandV1(context,graph,authority,actual.owner,operation_id,kind,request)
        _ACTIVE[id(issued)]=issued
        try:
            with bind_background_reads_v3(actual,db=actual.db):
                return graph._GraphCoordinator__domain_production_runtime_v1.run_current(authority,None,
                    operation_kind=kind,request=request,operation_id=operation_id,activity_id=activity_id,
                    audience_ref=schedule.audiences[0],parent_budget_lease_ref=schedule.parent_budget_lease_ref,
                    _background_offline=issued)
        finally:_ACTIVE.pop(id(issued),None)
    ns, store, port = schedule.namespace, graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata, _ = graph._v2_graph_stamp(ns)
        row = store._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (owner_grant_key(*ns.as_tuple).token,)).fetchone()
        if row is None or row[1] != 1:
            raise ValueError("offline recovery awaits the actual current Owner")
        principal = OwnerPrincipalV1(**json.loads(row[0])["principal"])
    pairing = port.current_owner_principal_binding(namespace=ns,
        authority_namespace=metadata.requirements.authority_namespace, principal=principal)
    if pairing is None:
        raise ValueError("offline recovery current Owner is unpaired")
    authority = AuthorityContext(pairing.actor_id, "d10", "installed-offline:" + operation_id,
        ns, ("d02", "d06", "d10", "d11"), schedule.purposes[0], schedule.audiences,
        port.installation_grant.publisher_policy_ref, metadata.requirements.activation_generation)
    captured = []
    def observe(scope):
        result = _observe_owner(graph, authority, scope)
        captured[:] = [result]
        return result
    graph._read_v2(authority, lambda: None, fence_observer=observe)
    issued = _BackgroundOfflineCommandV1(context, graph, authority, captured[0][1], operation_id, kind, request)
    _ACTIVE[id(issued)] = issued
    try:
        return graph._GraphCoordinator__domain_production_runtime_v1.run_current(authority, None,
            operation_kind=kind, request=request, operation_id=operation_id, activity_id=activity_id,
            audience_ref=schedule.audiences[0], parent_budget_lease_ref=schedule.parent_budget_lease_ref,
            _background_offline=issued)
    finally:
        _ACTIVE.pop(id(issued), None)


def _intervals(context, graph):
    """Resume registered intervals, then the actual current Host boundary."""
    from .domain_background_read_v3 import (background_rows_v3,background_json_loads_v3,background_json_matches_v3,
        background_json_digest_v3,background_verify_signature_v3,background_offline_lifecycle_lookup_v3)
    ns, store, issuer = context._v2_namespace, graph._GraphCoordinator__store, graph._GraphCoordinator__d11_issuer
    with store._lock:
        db = store._db
        schedule_rows=background_rows_v3(db,table=TABLE,columns=('original_ref',),group_columns=('bot','persona','kind'),
            group=(*ns.as_tuple,'registered_schedule'),order_columns=('original_ref',),limit=129,
            legacy_reader=lambda:db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
                "AND kind='registered_schedule' ORDER BY original_ref LIMIT 129",ns.as_tuple).fetchall())
        if len(schedule_rows) > 128:
            raise ValueError("offline schedules exceed the installed finite inventory")
        schedules = [read_current_d11_offline_value_v1(db, namespace=ns, original_ref=row[0], issuer=issuer)
            for row in schedule_rows]
        by_recipe = {schedule.recipe_ref: schedule for schedule in schedules}
        registered=background_rows_v3(db,table='graph_d10_production_inputs_v1',
            columns=('original_ref','producing_operation_id','payload_json','payload_digest','signature'),
            group_columns=('bot','persona','kind'),group=(*ns.as_tuple,'offline_interval'),order_columns=('original_ref',),limit=129,
            legacy_reader=lambda:db.execute("SELECT original_ref,producing_operation_id,payload_json,payload_digest,signature "
                "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND kind='offline_interval' ORDER BY original_ref LIMIT 129",ns.as_tuple).fetchall())
        if len(registered) > 128:
            raise ValueError("offline intervals exceed the installed finite inventory")
        pairs = {}
        from .d10_production_operations_v1 import RegisteredOfflineIntervalV1
        from ..domains.d01.production_operations_v1 import plain_v1
        for ref, operation, encoded, digest, signature in registered:
            background_verify_signature_v3(issuer._signer,"d11.d10-production-input.v1",encoded,signature)
            raw = background_json_loads_v3(encoded)
            interval = RegisteredOfflineIntervalV1(**raw)
            if (interval.interval_ref != ref or not background_json_matches_v3(encoded,raw)
                    or background_json_digest_v3(encoded,plain_v1(interval)) != digest
                    or db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                        (*ns.as_tuple, operation)).fetchone() is None):
                raise ValueError("registered offline interval differs from its committed original")
            schedule = by_recipe[interval.recipe_original_ref]
            boundaries = []
            for source, kind in ((interval.start_source_ref, "host_disconnect"), (interval.end_source_ref, "host_reconnect")):
                boundary_rows=background_offline_lifecycle_lookup_v3(db,ns,kind=kind,field='source_ref',value=source,
                    legacy_reader=lambda:db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
                        "AND kind=? AND json_extract(payload_json,'$.source_ref')=? LIMIT 2",(*ns.as_tuple,kind,source)).fetchall())
                if len(boundary_rows) != 1:
                    raise ValueError("registered offline interval has no unique actual Host boundary")
                boundaries.append(read_current_d11_offline_value_v1(db, namespace=ns,
                    original_ref=boundary_rows[0][0], issuer=issuer))
            disconnected, reconnected = boundaries
            require_adjacent_host_lifecycle_pair_v1(db, namespace=ns, disconnected=disconnected, reconnected=reconnected)
            expected = "d10-offline-interval:" + canonical_digest((ns, schedule.schedule_ref,
                disconnected.lifecycle_ref, reconnected.lifecycle_ref))[:48]
            if (ref != expected or interval.checkpoint_start_utc != disconnected.observed_at_utc
                    or interval.requested_until_utc != reconnected.observed_at_utc
                    or (interval.clock_mapping_ref, interval.clock_mapping_version) !=
                        (schedule.clock_mapping_ref, schedule.clock_mapping_version)):
                raise ValueError("registered offline interval changed its actual schedule or lifecycle")
            pairs[ref] = (schedule, disconnected, reconnected)
        rows=background_offline_lifecycle_lookup_v3(db,ns,kind='host_reconnect',field='host_incarnation',
            value=context._host_lifecycle_observer.host_incarnation,legacy_reader=lambda:db.execute(
                "SELECT o.original_ref,b.commit_seq FROM " + TABLE + " o JOIN graph_bundle_operations b "
                "ON b.bot=o.bot AND b.persona=o.persona AND b.operation_id=o.producing_operation_id "
                "WHERE o.bot=? AND o.persona=? AND o.kind='host_reconnect' "
                "AND json_extract(o.payload_json,'$.host_incarnation')=? LIMIT 2",
                (*ns.as_tuple,context._host_lifecycle_observer.host_incarnation)).fetchall())
        if not rows:
            return tuple(pairs.values())
        if len(rows) != 1:
            raise ValueError("actual Host reconnect identity collides")
        reconnect = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=rows[0][0], issuer=issuer)
        prior = db.execute("SELECT o.original_ref,o.kind FROM " + TABLE + " o JOIN graph_bundle_operations b "
            "ON b.bot=o.bot AND b.persona=o.persona AND b.operation_id=o.producing_operation_id "
            "WHERE o.bot=? AND o.persona=? AND o.kind IN ('host_disconnect','host_reconnect') "
            "AND b.commit_seq<? ORDER BY b.commit_seq DESC LIMIT 1", (*ns.as_tuple, rows[0][1])).fetchone()
        if prior is None or prior[1] != "host_disconnect":
            return tuple(pairs.values())
        disconnect = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=prior[0], issuer=issuer)
        require_adjacent_host_lifecycle_pair_v1(db, namespace=ns, disconnected=disconnect, reconnected=reconnect)
        latest = {}
        for schedule in schedules:
            if schedule.schedule_id not in latest or latest[schedule.schedule_id].revision < schedule.revision:
                latest[schedule.schedule_id] = schedule
        for schedule in latest.values():
            if _utc(schedule.starts_at_utc) <= _utc(disconnect.observed_at_utc) < _utc(reconnect.observed_at_utc) <= _utc(schedule.valid_until_utc):
                ref = "d10-offline-interval:" + canonical_digest((ns, schedule.schedule_ref,
                    disconnect.lifecycle_ref, reconnect.lifecycle_ref))[:48]
                pairs.setdefault(ref, (schedule, disconnect, reconnect))
        return tuple(sorted(pairs.values(), key=lambda item:(_utc(item[1].observed_at_utc), item[0].schedule_ref)))


def _close_legacy_pre_reconnect_offline_page_v1(context, graph, *, after_ref=""):
    """Close old prepared work without issuing any first claim or Source write."""
    from ..runtime_context import RuntimeContext
    from .d11_offline_accounting_v1 import (
        D11OfflineAccountingPreparedV1, read_offline_accounting_prepared_v1,
    )
    from .d10_offline_tick_execution_v1 import _decode_json
    if (type(context) is not RuntimeContext or context._v2_coordinator is not graph
            or context._worker is None or context._host_lifecycle_startup_receipt is not None
            or context._offline_recovery_stopping):
        raise ValueError("pending offline closure belongs to the actual pre-reconnect Host")
    graph._admin(context._v2_bootstrap)
    ns, store = context._v2_namespace, graph._GraphCoordinator__store
    issuer, resources = graph._GraphCoordinator__d11_issuer, graph._GraphCoordinator__d02_issuer
    port, bootstrap = graph._GraphCoordinator__content_fence_v2, context._v2_bootstrap
    with store._lock:
        rows = store._db.execute("SELECT original_ref,payload_json FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref>? "
            "ORDER BY original_ref LIMIT 32", (*ns.as_tuple, after_ref)).fetchall()
    cursor = after_ref
    for ref, wire in rows:
        binding = _decode_json(wire, D11OfflineAccountingPreparedV1).binding
        with store._lock:
            prepared = read_offline_accounting_prepared_v1(store._db, binding=binding,
                issuer=issuer, resource_issuer=resources)
            if prepared is None or prepared.accounting_original_ref != ref:
                raise ValueError("offline startup inventory differs from its signed accounting original")
            saved = {kind: _read_signed(store._db, ns, kind, binding.execution_id, issuer)
                for kind in ("adoption_receipt", "historical_accounting_receipt", "cancellation_receipt")}
            reservation = store._db.execute("SELECT state FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (binding.parent_budget_lease_ref,
                    binding.reservation_operation_id)).fetchone()
        if sum(value is not None for value in saved.values()) > 1:
            raise ValueError("offline execution has conflicting terminal dispositions")
        if saved["adoption_receipt"] is not None:
            graph.adopt_current_offline_tick_v1(bootstrap, namespace=ns,
                prepared_original_ref=binding.prepared_original_ref)
        elif saved["historical_accounting_receipt"] is not None:
            graph.reconcile_historical_offline_tick_cost_v1(bootstrap, binding=binding)
        elif saved["cancellation_receipt"] is not None:
            graph.cancel_unstarted_offline_tick_v1(bootstrap, binding=binding)
        elif reservation == ("reserved",):
            claim, terminal = port.read_historical_d11_offline_tick_original_v1(binding=binding)
            if claim is None:
                graph.cancel_unstarted_offline_tick_v1(bootstrap, binding=binding)
            else:
                if terminal is None:
                    claim, terminal = port.recover_claimed_d11_offline_tick_v1(binding=binding)
                if terminal is None:
                    return {"status": "held", "reason": "offline_prior_claim_not_retired",
                        "execution_id": binding.execution_id, "after_ref": cursor}
                # Startup is a historical closure. Never turn a stale preparation
                # into new experience before observing this Host's reconnect.
                graph.reconcile_historical_offline_tick_cost_v1(bootstrap, binding=binding)
        elif reservation is None:
            raise ValueError("offline startup original lacks its actual reservation")
        cursor = ref
    return {"status": "progressed" if len(rows) == 32 else "closed", "after_ref": cursor}


def _recover_legacy_offline_tick_v1(context, graph):
    """At most one original tick and one prefix commit per installed invocation."""
    from ..runtime_context import RuntimeContext
    from ..graph_coordinator import UnavailableGuard
    from ..host.v2_fence_port import V2FenceOutcomeUnknown
    if (type(context) is not RuntimeContext or context._v2_coordinator is not graph
            or context._worker is None or context._offline_recovery_stopping
            or context._host_lifecycle_observer is None or context._host_lifecycle_startup_receipt is None):
        raise ValueError("actual running Host and committed reconnect are required")
    store, issuer, ns = graph._GraphCoordinator__store, graph._GraphCoordinator__d11_issuer, context._v2_namespace
    port, bootstrap = graph._GraphCoordinator__content_fence_v2, context._v2_bootstrap
    for schedule, disconnected, reconnected in _intervals(context, graph):
        interval_ref = "d10-offline-interval:" + canonical_digest((ns, schedule.schedule_ref,
            disconnected.lifecycle_ref, reconnected.lifecycle_ref))[:48]
        with store._lock:
            db = store._db
            recipe_row = db.execute("SELECT payload_json FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
                (*ns.as_tuple, schedule.recipe_ref)).fetchone()
            if recipe_row is None:
                raise ValueError("offline recovery has no registered recipe")
            recipe = decode_offline_tick_recipe_v1(json.loads(recipe_row[0]))
            checkpoint_name = "interval:" + canonical_digest(interval_ref)[:48]
            checkpoint = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d10.offline_checkpoint.v1' AND name=? AND valid=1",
                (*ns.as_tuple, checkpoint_name)).fetchone()
            start = json.loads(checkpoint[0])["processed_until_utc"] if checkpoint else disconnected.observed_at_utc
        due_page = scheduled_offline_ticks_v1(recipe, start_utc=start, until_utc=reconnected.observed_at_utc)
        if not due_page:
            continue
        due = due_page[0]
        ids = offline_tick_ids_v1(ns, schedule.schedule_ref, due)
        with store._lock:
            prepared = read_prepared_offline_tick_v1(store._db, namespace=ns, prepared_original_ref=ids["prepared"], issuer=issuer)
            historical = store._db.execute("SELECT kind FROM " + TABLE + " WHERE bot=? AND persona=? "
                "AND kind IN ('historical_accounting_receipt','cancellation_receipt') AND original_ref=?",
                (*ns.as_tuple, ids["execution"])).fetchone()
        if historical is not None:
            # The retained content-free identity survives a removed preparation.
            from .d11_offline_accounting_v1 import D11OfflineAccountingPreparedV1
            from .d10_offline_tick_execution_v1 import _decode_json
            with store._lock:
                row = store._db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? "
                    "AND kind='accounting_prepared' AND json_extract(payload_json,'$.binding.execution_id')=?",
                    (*ns.as_tuple, ids["execution"])).fetchone()
                binding = _decode_json(row[0], D11OfflineAccountingPreparedV1).binding
            receipt = (graph.cancel_unstarted_offline_tick_v1(bootstrap, binding=binding)
                if historical[0] == "cancellation_receipt"
                else graph.reconcile_historical_offline_tick_cost_v1(bootstrap, binding=binding))
            return {"status": "held", "reason": "not_adopted_offline_tick", "receipt": receipt}
        if prepared is None:
            receipt = _command(context, graph, schedule, "prepare_offline_tick",
                PrepareCurrentOfflineTickRequestV1(schedule.schedule_ref, due), ids["operation"], ids["activity"])
            if receipt.get("schema") != "sylanne.domain-production-receipt.v1":
                return {"status": "held", "reason": "offline_preparation_refused", "receipt": receipt}
            with store._lock:
                prepared = read_prepared_offline_tick_v1(store._db, namespace=ns, prepared_original_ref=ids["prepared"], issuer=issuer)
        if prepared is None:
            return {"status": "held", "reason": "offline_preparation_waiting"}
        with store._lock:
            adopted = _read_signed(store._db, ns, "adoption_receipt", ids["execution"], issuer)
        if adopted is None:
            claim, terminal = port.read_d11_offline_tick_original_v1(binding=prepared.binding)
            if terminal is None:
                try:
                    claim, terminal = port.execute_d11_offline_tick_v1(binding=prepared.binding)
                except V2FenceOutcomeUnknown:
                    claim, terminal = port.read_d11_offline_tick_original_v1(binding=prepared.binding)
            if terminal is None:
                return {"status": "held", "reason": "offline_claim_outcome_unconfirmed", "execution_id": ids["execution"]}
        if adopted is not None:
            adoption = graph.adopt_current_offline_tick_v1(bootstrap, namespace=ns, prepared_original_ref=ids["prepared"])
        else:
            try:
                adoption = graph.adopt_current_offline_tick_v1(bootstrap, namespace=ns, prepared_original_ref=ids["prepared"])
            except (AuthorityUnavailable, UnavailableGuard, ValueError, RuntimeError):
                receipt = graph.reconcile_historical_offline_tick_cost_v1(bootstrap, binding=prepared.binding)
                return {"status": "held", "reason": "not_adopted_offline_tick", "receipt": receipt}
        if adoption["status"] != "completed":
            return {"status": "held", "reason": "offline_tick_has_no_simulated_source", "receipt": adoption}
        # No Graph writes are allowed between preparation and its own adoption.
        # Register the actual interval and import its prefix only after closing.
        with store._lock:
            interval = store._db.execute("SELECT 1 FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
                (*ns.as_tuple, interval_ref)).fetchone()
        if interval is None:
            registered = _command(context, graph, schedule, "input:register_offline_interval",
                RegisterCurrentOfflineIntervalInputRequestV1(schedule.schedule_ref, disconnected.lifecycle_ref, reconnected.lifecycle_ref),
                "d10-register-offline:" + canonical_digest(interval_ref), "d10.offline-recovery.v1")
            if registered.get("coverage") != "complete":
                return {"status": "held", "reason": "offline_interval_registration_waiting", "receipt": registered}
        continuation = "d10-offline:" + canonical_digest((interval_ref, start))[:48] if checkpoint else None
        request = AdvanceCurrentOfflineRequestV1(interval_ref, schedule.clock_mapping_ref, continuation)
        with store._lock:
            epoch = graph._v2_graph_stamp(ns)[1].revision
        progress = _command(context, graph, schedule, "advance_offline", request,
            "d10-advance-offline:" + canonical_digest((interval_ref, start, epoch)), "d10.offline-recovery.v1")
        with store._lock:
            committed = store._db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d10.offline_checkpoint.v1' AND name=? AND valid=1",
                (*ns.as_tuple, checkpoint_name)).fetchone()
            advanced = committed is not None and _utc(json.loads(committed[0])["processed_until_utc"]) > _utc(start)
        return {"status": "progressed" if advanced else "held",
            "reason": "actual_offline_prefix", "receipt": progress, "execution_id": ids["execution"]}
    return {"status": "idle", "reason": "no_remaining_registered_offline_tick"}


def _offline_background_work_v3(context,graph,*,kind,after_ref=''):
    from .domain_background_read_v3 import prepare_domain_background_read_v3,raise_background_work_error_v3
    from .first_ingress_v2 import trusted_upper
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation='offline-reader:'+canonical_digest((context._v2_namespace,context._host_lifecycle_observer.host_incarnation,
        kind,after_ref,graph._v2_graph_stamp(context._v2_namespace)))[:48]
    work=prepare_domain_background_read_v3(graph,context._v2_bootstrap,context._v2_model_bundle,
        kind=kind,operation_id=operation,deadline_utc=now+60,context=context)
    work.state.after_ref=after_ref
    work.map_terminal_v3('issuer',lambda prepared:finish_background_offline_data_v3(graph,prepared),raise_background_work_error_v3)
    return work


def close_pre_reconnect_offline_page_v1(context,graph,*,after_ref=''):
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(graph._GraphCoordinator__store._db)is None:
        return _close_legacy_pre_reconnect_offline_page_v1(context,graph,after_ref=after_ref)
    return _offline_background_work_v3(context,graph,kind='offline_close',after_ref=after_ref)


def recover_current_offline_tick_v1(context,graph):
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(graph._GraphCoordinator__store._db)is None:
        return _recover_legacy_offline_tick_v1(context,graph)
    return _offline_background_work_v3(context,graph,kind='offline')


def _prepare_offline_command_v3(reader,schedule,kind,request,operation_id,activity_id):
    from dataclasses import replace
    from .domain_background_read_v3 import prepare_background_command_frame_v3
    authority=reader.authority
    reader.authority=replace(authority,purpose=schedule.purposes[0],audience=schedule.audiences)
    try:
        frame=prepare_background_command_frame_v3(reader,operation_kind=kind,request=request,operation_id=operation_id,
            activity_id=activity_id,audience_ref=schedule.audiences[0],parent_budget_lease_ref=schedule.parent_budget_lease_ref)
    finally:reader.authority=authority
    return 'command',schedule,kind,request,operation_id,activity_id,frame


def prepare_background_offline_data_v3(reader):
    from .domain_background_read_v3 import (background_point_v3,background_json_loads_v3,background_graph_head_v3,
        background_rows_v3,background_offline_lifecycle_lookup_v3,background_original_recipe_row_v3,
        background_verify_signature_v3,background_json_digest_v3)
    from .d11_offline_accounting_v1 import D11OfflineAccountingPreparedV1,read_offline_accounting_prepared_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_read_plans_v1 import _committed
    from ..graph_types import AtomKey,Owner
    graph,context,db,ns=reader.graph,reader.context,reader.db,reader.namespace
    issuer=graph._GraphCoordinator__d11_issuer
    if reader.kind=='offline_close':
        row=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='accounting_prepared' AND original_ref>? ORDER BY original_ref LIMIT 1",(*ns.as_tuple,reader.after_ref)).fetchone()
        if row is None:return ('closed',reader.after_ref)
        ref=row[0]
        payload=background_point_v3(db,table=TABLE,columns=('payload_json',),key_columns=('bot','persona','kind','original_ref'),
            key=(*ns.as_tuple,'accounting_prepared',ref),legacy_reader=lambda:None)
        locator=decode_typed_production_value_v1(background_json_loads_v3(payload[0]),D11OfflineAccountingPreparedV1)
        binding=locator.binding
        prepared=read_offline_accounting_prepared_v1(db,binding=binding,issuer=issuer,resource_issuer=graph._GraphCoordinator__d02_issuer)
        if prepared is None or prepared.accounting_original_ref!=ref:raise ValueError('offline startup inventory differs from its signed accounting original')
        saved={kind:_read_signed(db,ns,kind,binding.execution_id,issuer) for kind in
            ('adoption_receipt','historical_accounting_receipt','cancellation_receipt')}
        if sum(value is not None for value in saved.values())>1:raise ValueError('offline execution has conflicting terminal dispositions')
        reservation=background_point_v3(db,table='runtime_budget_reservations',columns=('state',),
            key_columns=('lease_id','operation_id'),key=(binding.parent_budget_lease_ref,binding.reservation_operation_id),legacy_reader=lambda:None)
        if reservation is None:raise ValueError('offline startup original lacks its actual reservation')
        if saved['adoption_receipt'] is not None:
            from .d11_offline_adoption_v1 import verify_offline_adoption_commit_v1
            from ..authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
            bridges=background_offline_lifecycle_lookup_v3(db,ns,kind='adoption_bridge',field='prepared_original_ref',value=binding.prepared_original_ref,legacy_reader=lambda:())
            if len(bridges)!=1:raise ValueError('offline committed receipt lacks its original bridge')
            original=_read_signed(db,ns,'adoption_bridge',bridges[0][0],issuer)
            verify_offline_adoption_commit_v1(db,gate=offline_bridge_from_wire_v1(original[1]),issuer=issuer,
                resource_issuer=graph._GraphCoordinator__d02_issuer,require_current_metadata=False)
        return 'close_item',binding,saved,reservation,ref,reader.after_ref
    for schedule,disconnected,reconnected in _intervals(context,graph):
        interval_ref='d10-offline-interval:'+canonical_digest((ns,schedule.schedule_ref,disconnected.lifecycle_ref,reconnected.lifecycle_ref))[:48]
        recipe_row=background_original_recipe_row_v3(db,ns,schedule.recipe_ref,legacy_reader=lambda:None)
        if recipe_row is None or recipe_row[0]!='offline_recipe':raise ValueError('offline recovery has no registered recipe')
        background_verify_signature_v3(issuer._signer,'d11.d10-production-input.v1',recipe_row[2],recipe_row[4])
        raw=background_json_loads_v3(recipe_row[2])
        if background_json_digest_v3(recipe_row[2],raw)!=recipe_row[3]:raise ValueError('offline registered recipe digest differs')
        _committed(db,ns,recipe_row[1]);recipe=decode_offline_tick_recipe_v1(raw)
        checkpoint_name='interval:'+canonical_digest(interval_ref)[:48]
        checkpoint_key=AtomKey(Owner('persona',*ns.as_tuple),'d10.offline_checkpoint.v1',checkpoint_name)
        checkpoint=background_graph_head_v3(db,ns,checkpoint_key)
        start=background_json_loads_v3(checkpoint[1])['processed_until_utc'] if checkpoint is not None and checkpoint[2]==1 else disconnected.observed_at_utc
        due_page=scheduled_offline_ticks_v1(recipe,start_utc=start,until_utc=reconnected.observed_at_utc)
        if not due_page:continue
        due=due_page[0];ids=offline_tick_ids_v1(ns,schedule.schedule_ref,due)
        prepared=read_prepared_offline_tick_v1(db,namespace=ns,prepared_original_ref=ids['prepared'],issuer=issuer)
        historical={kind:_read_signed(db,ns,kind,ids['execution'],issuer) for kind in ('historical_accounting_receipt','cancellation_receipt')}
        if any(value is not None for value in historical.values()):
            if prepared is not None:binding=prepared.binding
            else:
                refs=background_offline_lifecycle_lookup_v3(db,ns,kind='accounting_prepared',field='execution_id',value=ids['execution'],legacy_reader=lambda:())
                if len(refs)!=1:raise ValueError('offline terminal identity has no unique signed accounting preparation')
                payload=background_point_v3(db,table=TABLE,columns=('payload_json',),key_columns=('bot','persona','kind','original_ref'),
                    key=(*ns.as_tuple,'accounting_prepared',refs[0][0]),legacy_reader=lambda:None)
                binding=decode_typed_production_value_v1(background_json_loads_v3(payload[0]),D11OfflineAccountingPreparedV1).binding
            return 'historical',binding,historical
        if prepared is None:
            return _prepare_offline_command_v3(reader,schedule,'prepare_offline_tick',
                PrepareCurrentOfflineTickRequestV1(schedule.schedule_ref,due),ids['operation'],ids['activity'])
        adopted=_read_signed(db,ns,'adoption_receipt',ids['execution'],issuer)
        if adopted is None:
            from .d10_offline_tick_execution_v1 import _verify_offline_original_inputs_v1,_verify_offline_content_rows_v1
            from .d10_offline_tick_terminal_v1 import AdoptCurrentOfflineTickRequestV1,read_plan_current_offline_tick_terminal_v1
            _verify_offline_original_inputs_v1(db,prepared,issuer,graph._GraphCoordinator__d02_issuer,reader.now,for_execution=False)
            _verify_offline_content_rows_v1(db,prepared)
            plan=read_plan_current_offline_tick_terminal_v1(db,namespace=ns,activity_id=prepared.binding.activity_id,
                operation_kind='adopt_offline_tick',request=AdoptCurrentOfflineTickRequestV1(ids['prepared']))
            for key in plan.exact_keys:background_graph_head_v3(db,ns,key)
            background_offline_lifecycle_lookup_v3(db,ns,kind='adoption_bridge',field='prepared_original_ref',value=ids['prepared'],legacy_reader=lambda:())
            return 'execute_adopt',prepared,ids
        interval=background_original_recipe_row_v3(db,ns,interval_ref,legacy_reader=lambda:None)
        if interval is None:
            return _prepare_offline_command_v3(reader,schedule,'input:register_offline_interval',
                RegisterCurrentOfflineIntervalInputRequestV1(schedule.schedule_ref,disconnected.lifecycle_ref,reconnected.lifecycle_ref),
                'd10-register-offline:'+canonical_digest(interval_ref),'d10.offline-recovery.v1')
        continuation='d10-offline:'+canonical_digest((interval_ref,start))[:48] if checkpoint is not None and checkpoint[2]==1 else None
        return _prepare_offline_command_v3(reader,schedule,'advance_offline',
            AdvanceCurrentOfflineRequestV1(interval_ref,schedule.clock_mapping_ref,continuation),
            'd10-advance-offline:'+canonical_digest((interval_ref,start,reader.graph_stamp[1].revision)),'d10.offline-recovery.v1')
    return ('idle','no_remaining_registered_offline_tick')


def _finish_background_offline_data_bound_v3(graph,prepared):
    from .domain_background_read_v3 import PreparedBackgroundOperationV3,bind_background_reads_v3
    from ..host.v2_fence_port import V2FenceOutcomeUnknown
    from ..graph_coordinator import UnavailableGuard
    if type(prepared)is not PreparedBackgroundOperationV3:raise TypeError('actual offline background preparation required')
    prepared.require_v3(graph);reader=prepared.owner;decision=prepared.local_result
    context,bootstrap,port=reader.context,reader.bootstrap,graph._GraphCoordinator__content_fence_v2
    kind=decision[0]
    if kind=='closed':return {'status':'closed','after_ref':decision[1]}
    if kind=='idle':return {'status':'idle','reason':decision[1]}
    if kind=='close_item':
        _,binding,saved,reservation,ref,cursor=decision
        if saved['adoption_receipt'] is not None:
            graph.adopt_current_offline_tick_v1(bootstrap,namespace=reader.namespace,prepared_original_ref=binding.prepared_original_ref)
        elif saved['historical_accounting_receipt'] is not None:graph.reconcile_historical_offline_tick_cost_v1(bootstrap,binding=binding)
        elif saved['cancellation_receipt'] is not None:graph.cancel_unstarted_offline_tick_v1(bootstrap,binding=binding)
        elif reservation==('reserved',):
            claim,terminal=port.read_historical_d11_offline_tick_original_v1(binding=binding)
            if claim is None:graph.cancel_unstarted_offline_tick_v1(bootstrap,binding=binding)
            else:
                if terminal is None:claim,terminal=port.recover_claimed_d11_offline_tick_v1(binding=binding)
                if terminal is None:return {'status':'held','reason':'offline_prior_claim_not_retired','execution_id':binding.execution_id,'after_ref':cursor}
                graph.reconcile_historical_offline_tick_cost_v1(bootstrap,binding=binding)
        else:raise ValueError('offline startup reservation has no authenticated terminal closure')
        return {'status':'progressed','after_ref':ref}
    if kind=='historical':
        _,binding,saved=decision
        receipt=(graph.cancel_unstarted_offline_tick_v1(bootstrap,binding=binding) if saved['cancellation_receipt'] is not None
            else graph.reconcile_historical_offline_tick_cost_v1(bootstrap,binding=binding))
        return {'status':'held','reason':'not_adopted_offline_tick','receipt':receipt}
    if kind=='command':
        _,schedule,command,request,operation,activity,frame=decision
        with bind_background_reads_v3(reader,db=reader.db):receipt=_command(context,graph,schedule,command,request,operation,activity)
        complete=(receipt.get('schema')=='sylanne.domain-production-receipt.v1' if command=='prepare_offline_tick'
            else receipt.get('coverage')=='complete' if command=='input:register_offline_interval' else receipt.get('schema')=='sylanne.domain-production-receipt.v1')
        advanced=complete and graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp
        return {'status':'progressed' if advanced else 'held','reason':'actual_offline_'+command,'receipt':receipt}
    if kind=='execute_adopt':
        _,tick,ids=decision
        claim,terminal=port.read_d11_offline_tick_original_v1(binding=tick.binding)
        if terminal is None:
            try:claim,terminal=port.execute_d11_offline_tick_v1(binding=tick.binding)
            except V2FenceOutcomeUnknown:claim,terminal=port.read_d11_offline_tick_original_v1(binding=tick.binding)
        if terminal is None:return {'status':'held','reason':'offline_claim_outcome_unconfirmed','execution_id':ids['execution']}
        try:receipt=graph.adopt_current_offline_tick_v1(bootstrap,namespace=reader.namespace,prepared_original_ref=ids['prepared'])
        except (AuthorityUnavailable,UnavailableGuard,ValueError,RuntimeError):
            receipt=graph.reconcile_historical_offline_tick_cost_v1(bootstrap,binding=tick.binding)
            return {'status':'held','reason':'not_adopted_offline_tick','receipt':receipt}
        return {'status':'progressed' if receipt['status']=='completed' else 'held','reason':'actual_offline_adoption','receipt':receipt,'execution_id':ids['execution']}
    raise ValueError('unregistered actual offline decision')


def finish_background_offline_data_v3(graph,prepared):
    from .domain_background_read_v3 import PreparedBackgroundOperationV3,bind_background_reads_v3
    if type(prepared)is not PreparedBackgroundOperationV3:raise TypeError('actual offline background preparation required')
    prepared.require_v3(graph)
    with bind_background_reads_v3(prepared.owner,db=prepared.owner.db):
        return _finish_background_offline_data_bound_v3(graph,prepared)
