"""Durable Habit W01 execution under its independent current Core and Source permits."""
from dataclasses import asdict
import json
import time

from ..runtime_contracts import (AuthorityContext, CommandEnvelope, FenceScope, NamespaceEpoch,
    OperationIdentity, QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard,
    canonical_digest, canonical_json)


def run_current_habit_activity_v1(graph, context, *, selector, operation_kind, request, source_inputs):
    from .habit_activity_issuance_v1 import (habit_activity_operation_kind_v1,
        habit_activity_request_digest_v1,habit_typed_command_digest_v1,habit_activity_for_fence_v1,
        reobserve_habit_activity_v1,habit_activity_finish_digest_v1)
    habit_activity_operation_kind_v1(selector)
    protocol=(habit_activity_operation_kind_v1,habit_activity_request_digest_v1,habit_typed_command_digest_v1,
        habit_activity_for_fence_v1,reobserve_habit_activity_v1,habit_activity_finish_digest_v1,
        compile_and_commit_current_habit_v1,'w01.habit-domain-write.v1')
    return _run_current_habit_control_write_v1(graph,context,selector=selector,
        operation_kind=operation_kind,request=request,source_inputs=source_inputs,protocol=protocol)


def _run_current_habit_control_write_v1(graph, context, *, selector, operation_kind, request, source_inputs, protocol):
    from ..graph_coordinator import GraphCoordinator
    from ..graph_store import ProductionGraphStore
    from ..authority_service.v2_contract import FencePermitV2, from_wire, to_wire
    from .restore_anchor import RestoreAnchor
    from .domain_production_registry_v1 import installed_operation_v1
    (habit_activity_operation_kind_v1, habit_activity_request_digest_v1, habit_typed_command_digest_v1,
        habit_activity_for_fence_v1, reobserve_habit_activity_v1, habit_activity_finish_digest_v1,
        compile_current, finish_schema) = protocol
    from .current_habit_source_read_v3 import (require_habit_prepared_write_v3,
        bind_habit_prepared_write_v3, read_current_habit_receipt_v3)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .first_ingress_v2 import trusted_upper
    if type(graph) is not GraphCoordinator:
        raise TypeError('Habit W01 requires the actual installed Graph coordinator')
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    runtime._current()
    operation = installed_operation_v1(operation_kind)
    if (operation_kind != habit_activity_operation_kind_v1(selector)
            or type(request) is not operation.request_type
            or selector.request_digest != habit_typed_command_digest_v1(operation, request)):
        raise ValueError('Habit W01 changed its exact fixed phase command')
    require_habit_prepared_write_v3(source_inputs, graph, context, selector, operation, request)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    if type(store) is not ProductionGraphStore or port is None:
        raise ValueError('Habit installed production storage/fence is absent')
    namespace, operation_id = selector.namespace, selector.operation_id
    digest, attempt_id = habit_activity_request_digest_v1(selector), selector.operation_id
    key = (*namespace.as_tuple, operation_id)
    query = ('SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json,receipt_json '
        'FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?')
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        saved = store._db.execute(query, key).fetchone()
    target = metadata.requirements
    if saved is not None and saved[:2] != (digest, attempt_id):
        raise ValueError('Habit existing attempt belongs to another immutable selector')
    if saved is not None and saved[6] is not None:
        projection=read_current_habit_receipt_v3(graph,context,selector,source_inputs=source_inputs,
            saved_projection=json.loads(saved[6]))
        anchor = RestoreAnchor(**json.loads(saved[2]))
        observed, state = port.get_fence_operation(namespace=namespace,
            authority_namespace=anchor.namespace, operation_id=attempt_id)
        permit = None if saved[5] is None else from_wire(json.loads(saved[5]))
        if (type(permit) is not FencePermitV2 or observed != permit or state not in {'active', 'finished'}
                or permit.operation_id != attempt_id or permit.operation != 'write'
                or permit.holder != graph._GraphCoordinator__holder or permit.pinned_anchor != anchor):
            raise ValueError('Habit committed attempt has no confirmed original permit')
        scope = FenceScope(namespace, anchor.namespace, permit.generation, 'write', attempt_id,
            permit, anchor, NamespaceEpoch(*namespace.as_tuple, saved[4]), saved[3])
        if state == 'active':
            port.finish_fence(scope, request_id='finish:' + attempt_id,
                request_digest='sha256:' + canonical_digest({'schema': finish_schema,
                    'operation_id': operation_id, 'request_digest': saved[0], 'permit_token': permit.token}))
        return projection
    anchor = port.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target, anchor):
        raise ValueError('Habit current recovery anchor differs')
    if saved is not None:
        if RestoreAnchor(**json.loads(saved[2])) != anchor or saved[3:5] != (metadata.graph_revision, epoch.revision):
            raise ValueError('Habit unresolved original graph stamp changed')
    else:
        with store._lock:
            db = store._db
            db.execute('BEGIN IMMEDIATE')
            try:
                if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise ValueError('Habit Graph changed before its durable original intent')
                db.execute('INSERT INTO graph_owner_domain_attempts_v3(bot,persona,operation_id,request_digest,'
                    'attempt_id,anchor_json,graph_revision,graph_epoch) VALUES(?,?,?,?,?,?,?,?)',
                    (*key, digest, attempt_id, canonical_json(asdict(anchor)), metadata.graph_revision, epoch.revision))
                db.execute('COMMIT')
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise
    observed = port.observe_content_write_attempt_v1(namespace=namespace,
        authority_namespace=target.authority_namespace, operation_id=attempt_id, expected_anchor=anchor)
    permit, state = observed.permit, observed.state
    if saved is not None and saved[5] is not None:
        if permit != from_wire(json.loads(saved[5])) or state != 'active':
            raise ValueError('Habit saved original permit is not active')
    elif state == 'absent' and permit is None:
        permit = port.begin_fence(namespace=namespace, authority_namespace=target.authority_namespace,
            holder=graph._GraphCoordinator__holder, generation=target.activation_generation,
            operation='write', operation_id=attempt_id, expected_anchor=anchor, retain_on_unknown=True)
        state = 'active'
    if (type(permit) is not FencePermitV2 or state != 'active' or permit.operation_id != attempt_id
            or permit.operation != 'write' or permit.holder != graph._GraphCoordinator__holder
            or permit.pinned_anchor != anchor):
        raise ValueError('Habit write outcome is unconfirmed; retain the original attempt')
    scope = FenceScope(namespace, target.authority_namespace, target.activation_generation,
        'write', attempt_id, permit, anchor, epoch, metadata.graph_revision)
    if port.validate_fence(scope) != permit:
        raise ValueError('Habit original write permit changed')
    permit_json = canonical_json(to_wire(permit))
    with store._lock:
        store._db.execute('UPDATE graph_owner_domain_attempts_v3 SET permit_json=? WHERE bot=? AND persona=? '
            'AND operation_id=? AND attempt_id=? AND permit_json IS NULL', (permit_json, *key, attempt_id))
        persisted = store._db.execute(query, key).fetchone()
        expected = (digest, attempt_id, canonical_json(asdict(anchor)), metadata.graph_revision,
            epoch.revision, permit_json, None)
        if persisted != expected:
            raise ValueError('Habit actual durable permit differs before current qualification')
    with habit_activity_for_fence_v1(graph, scope=scope, request=selector,
            operation=operation, command=request) as issued:
        reobserve_habit_activity_v1(issued, graph, scope)
        with bind_habit_prepared_write_v3(source_inputs, graph=graph, scope=scope, issued=issued):
            from .domain_structured_self_observation_v1 import observe_structured_self_identity_v1
            external = (observe_structured_self_identity_v1(graph, namespace=namespace,
                operation_id=operation_id, scope=scope, owner_guard=issued.evidence.owner_guard),)
            life_inventory = None
            if operation_kind == 'prepare_life':
                from ..host.d11_life_port_v1 import InstalledD11LifePortV1
                life_inventory = InstalledD11LifePortV1(port).read_d11_life_execution_inventory_v1(
                    namespace=scope.authority_namespace, permit=scope.permit)
            now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            with store._lock:
                db = store._db
                db.execute('BEGIN IMMEDIATE')
                try:
                    if store._db.execute(query, key).fetchone() != expected or graph._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise ValueError('Habit durable intent or Graph changed before W01')
                    runtime._active_life_execution_inventory_v1 = life_inventory
                    try:
                        result = compile_current(runtime, db, selector=selector,
                            operation=operation, request=request, issued=issued, scope=scope,
                            metadata=metadata, epoch=epoch, now_utc=now, external_originals=external)
                    finally:
                        runtime._active_life_execution_inventory_v1 = None
                    db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=? WHERE bot=? AND persona=? '
                        'AND operation_id=? AND attempt_id=? AND receipt_json IS NULL',
                        (canonical_json(result), *key, attempt_id))
                    if db.execute('SELECT changes()').fetchone() != (1,):
                        raise ValueError('Habit original receipt raced')
                    db.execute('COMMIT')
                except BaseException:
                    if db.in_transaction:
                        db.rollback()
                    raise
            finish_digest = habit_activity_finish_digest_v1(issued, graph, scope)
            port.finish_fence(scope, request_id='finish:' + attempt_id, request_digest=finish_digest)
            return result


def compile_and_commit_current_habit_v1(runtime, db, *, selector, operation, request,
        issued, scope, metadata, epoch, now_utc, external_originals):
    from .habit_activity_issuance_v1 import (require_habit_activity_issuance_v1,
        habit_activity_domains_v1)
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1, HabitOccurrenceBirthSelectorV1
    from ..authority_service.d10_habit_execution_contract_v1 import (HabitOccurrenceExecutionSelectorV1,
        habit_execution_phase_identity_v1, habit_execution_purpose_v1)
    from .habit_schedule_driver_v1 import habit_subscription_activity_id_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    from .local_module_admission_v1 import required_operation_modules_v1
    from .current_habit_source_read_v3 import require_habit_compile_inputs_v3
    from .habit_activity_frame_v1 import freeze_habit_activity_frame_v1
    from .domain_production_registry_v1 import stage_installed_domain_operation_v1
    from .domain_production_commit_v1 import commit_installed_domain_operation_v1
    runtime._current()
    graph = runtime.graph
    evidence = require_habit_activity_issuance_v1(issued, graph, scope)
    if evidence.request != selector or issued.operation != operation or issued.command != request:
        raise ValueError('Habit compiler requires its actual privately issued command')
    graph.local_module_admission.require_v1(required_operation_modules_v1(operation.operation_kind), operation.operation_kind)
    policy = evidence.policy_original.definition
    issuer = graph._GraphCoordinator__d11_issuer
    grant = issuer.current_budget_grant(db, policy.parent_root_grant_ref)
    lease = get_budget_lease(db, grant.lease_id)
    require_budget_family_admissible(db, grant.lease_id)
    if (lease.state != 'active' or grant.valid_until_utc <= now_utc
            or (grant.bot_id, grant.persona_id) != selector.namespace.as_tuple
            or policy.original_valid_until_utc > grant.valid_until_utc):
        raise ValueError('Habit lost the original active Root and its unchanged lifetime')
    execution = type(selector) is HabitOccurrenceExecutionSelectorV1
    if execution:
        activity, effect, attempt = habit_execution_phase_identity_v1(selector)
        purpose = habit_execution_purpose_v1(selector)
    elif type(selector) in {HabitWindowCueSelectorV1, HabitOccurrenceBirthSelectorV1}:
        activity, effect, attempt = habit_subscription_activity_id_v1(selector.namespace, policy.policy_id), None, selector.operation_id
        purpose = 'context'
    else:
        activity, effect, attempt = selector.activity_id, None, selector.operation_id
        purpose = 'context'
    domains = habit_activity_domains_v1(operation.operation_kind)
    token, capability = graph.grant(runtime._bootstrap, actor=evidence.current_self.self_entity_ref,
        issuer_domain=operation.domain, namespace=selector.namespace, domains=domains,
        activation_generation=evidence.current_self.activation_generation, operation_id=selector.operation_id)
    runtime._active_habit_issuance_v1 = issued
    try:
        versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
            "AND kind IN ('scheme','operator','policy')", selector.namespace.as_tuple).fetchall())
        if set(versions) != {'scheme', 'operator', 'policy'}:
            raise ValueError('Habit requires actual installed scheme/operator/policy heads')
        deadline = min(selector.original_deadline_utc, grant.valid_until_utc, evidence.valid_until_utc)
        authority = AuthorityContext(evidence.current_self.self_entity_ref, operation.domain, capability,
            selector.namespace, tuple(sorted(graph._GraphCoordinator__leases[token][5])), purpose,
            policy.audience, grant.policy_ref, evidence.current_self.activation_generation)
        envelope = CommandEnvelope(RUNTIME_SCHEMA,
            OperationIdentity(activity, effect, attempt, operation.operation_kind, selector.operation_id,
                canonical_digest({'input_refs': []})), authority,
            VersionGuard((), (QueryEpoch(selector.namespace, 'namespace', epoch.revision),), evidence.access_epoch,
                evidence.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
                versions['scheme'], versions['operator'], versions['policy'], (), (), ()),
            SourceQualification((), 'derived', None, now_utc, 'inference', 'ineligible', None, 'not_applicable'),
            (), policy.parent_root_grant_ref, deadline, time.monotonic() + deadline - now_utc,
            'habit-current:' + selector.operation_id, ())
        plan, originals, policies, readers = require_habit_compile_inputs_v3(db, graph=graph,
            scope=scope, issued=issued, operation=operation, request=request, now_utc=now_utc)
        frame = freeze_habit_activity_frame_v1(graph, db, envelope=envelope, issued=issued,
            scope=scope, plan=plan, now_utc=now_utc, operation=operation, request=request,
            process_lease=token, observed_originals=(*originals, *external_originals), installed_policy_refs=policies)
        with bind_current_habit_frame_v1(frame, graph=graph, issued=issued, scope=scope):
            stage = stage_installed_domain_operation_v1(db, operation=operation,
                frame=frame, request=request, installed_readers=readers)
            require_current_habit_commit_v1(runtime, db, operation=operation, request=request,
                frame=frame, stage=stage, scope=scope)
            return commit_installed_domain_operation_v1(runtime, db, operation=operation, request=request,
                frame=frame, stage=stage, readers=readers, scope=scope, owner=None, guard=evidence.owner_guard,
                metadata=metadata, epoch=epoch, process_lease=token, external_originals=external_originals)
    finally:
        runtime._active_habit_issuance_v1 = None
        graph.release_authority_lease(runtime._bootstrap, token)


def require_current_habit_commit_v1(runtime, db, *, operation, request, frame, stage, scope):
    """Actual pre-CAS terminal shared by ordinary and specialized Habit commits."""
    from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    if type(runtime._active_habit_issuance_v1)is _IssuedHabitMaintenanceV1:
        from .habit_original_maintenance_runtime_v1 import require_current_habit_maintenance_commit_v1
        return require_current_habit_maintenance_commit_v1(runtime,db,operation=operation,request=request,
            frame=frame,stage=stage,scope=scope)
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1
    from ..authority_service.d10_habit_execution_contract_v1 import (HabitOccurrenceExecutionSelectorV1,
        habit_execution_write_domains_v1)
    from .domain_production_commit_v1 import _members
    issued = runtime._active_habit_issuance_v1
    evidence = require_habit_activity_issuance_v1(issued, runtime.graph, scope)
    selector = evidence.request
    if (db is not runtime.graph._GraphCoordinator__store._db or not db.in_transaction
            or not runtime.graph._GraphCoordinator__store._lock._is_owned()
            or issued.operation != operation or issued.command != request
            or frame.envelope.identity.operation_id != selector.operation_id
            or frame.owner_guard != evidence.owner_guard
            or frame.snapshot.epochs[0].revision != evidence.query_epoch.revision):
        raise ValueError('Habit commit changed its actual transaction, frame or private issuance')
    domains = (habit_execution_write_domains_v1(selector) if type(selector) is HabitOccurrenceExecutionSelectorV1
        else ('d10', 'd11'))
    primary, proposals, _, _, _ = _members(stage)
    from .habit_census_provenance_v1 import require_current_habit_census_payload_v1
    require_current_habit_census_payload_v1(frame,json.loads(primary.original_payload_json))
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(stage) is LifePreparationStageV1:
        from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
        proposals = life_preparation_bundle_v1(runtime.graph, stage).proposals
    if primary.operation_kind != operation.operation_kind:
        raise ValueError('Habit commit changed its registered phase')
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1, current_habit_activity_provenance_v1
    raw = json.loads(primary.original_payload_json)['provenance']
    from .habit_followup_source_v3 import require_body_w01_basis_v3
    require_body_w01_basis_v3(runtime,db,frame=frame,selector=selector,request=request,stage=stage,provenance=raw)
    if raw.get(HABIT_ACTIVITY_PROVENANCE_V1) != json.loads(canonical_json(
            current_habit_activity_provenance_v1(issued, runtime.graph, scope, frame=frame))):
        raise ValueError('Habit commit lost its actual signed full-selector/scope provenance')
    registry = runtime.graph._GraphCoordinator__store._registry
    for proposal in proposals:
        if proposal.domain not in domains:
            raise ValueError('Habit commit exceeds the fixed phase proposal domains')
        for write in proposal.typed_writes:
            if (registry.spec(write.key.type_name).writer_domain != proposal.domain
                    or (write.key.owner.bot, write.key.owner.persona) != selector.namespace.as_tuple):
                raise ValueError('Habit actual write has another registered domain or namespace')


from contextlib import contextmanager

_HABIT_FRAMES_V1 = {}


@contextmanager
def bind_current_habit_frame_v1(frame, *, graph, issued, scope):
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    evidence = require_habit_activity_issuance_v1(issued, graph, scope)
    if (frame.envelope.identity.operation_id != evidence.request.operation_id
            or frame.owner_guard != evidence.owner_guard or id(frame) in _HABIT_FRAMES_V1):
        raise ValueError('Habit signed payload requires its actual single privately qualified frame')
    _HABIT_FRAMES_V1[id(frame)] = (frame, graph, issued, scope)
    from .current_habit_source_read_v3 import _active
    from .habit_followup_source_v3 import bind_followup_frame_v3,release_followup_frame_v3
    reader=_active(graph._GraphCoordinator__store._db)
    bind_followup_frame_v3(frame,reader)
    try:
        yield
    finally:
        release_followup_frame_v3(frame)
        _HABIT_FRAMES_V1.pop(id(frame), None)


def append_current_habit_provenance_v1(frame, domain, operation_kind, request, provenance):
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1, current_habit_activity_provenance_v1
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    if provenance is not None and HABIT_ACTIVITY_PROVENANCE_V1 in provenance:
        raise ValueError('Habit execution provenance is reserved for its actual private current frame')
    state = _HABIT_FRAMES_V1.get(id(frame))
    if state is None:
        return provenance
    actual, graph, issued, scope = state
    evidence = require_habit_activity_issuance_v1(issued, graph, scope)
    if actual is not frame:
        raise ValueError('Habit current payload changed its actual frame identity')
    if operation_kind != issued.operation.operation_kind:
        return provenance
    if domain != issued.operation.domain or request != issued.command:
        raise ValueError('Habit signed payload changed its exact registered command')
    from .habit_followup_source_v3 import append_followup_provenance_v3
    provenance=append_followup_provenance_v3(frame,provenance)
    return {**(provenance or {}), HABIT_ACTIVITY_PROVENANCE_V1:
        current_habit_activity_provenance_v1(issued, graph, scope, frame=frame)}


def habit_activity_phase_identity_v1(selector):
    """The immutable business identity; storage READ identifiers remain independent."""
    from ..authority_service.d10_habit_execution_contract_v1 import (HabitOccurrenceExecutionSelectorV1,
        habit_execution_phase_identity_v1)
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1, HabitOccurrenceBirthSelectorV1
    from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
    from ..graph_types import AtomKey
    from .habit_schedule_driver_v1 import habit_subscription_activity_id_v1
    if type(selector) is HabitOccurrenceExecutionSelectorV1:
        return habit_execution_phase_identity_v1(selector)
    if type(selector) in {HabitWindowCueSelectorV1, HabitOccurrenceBirthSelectorV1}:
        policy_id = AtomKey.from_token(selector.policy_ref).name
        return habit_subscription_activity_id_v1(selector.namespace, policy_id), None, selector.operation_id
    if type(selector) is HabitOccurrenceSelectorV1:
        return selector.activity_id, None, selector.operation_id
    raise TypeError('one exact installed Habit phase selector required')
