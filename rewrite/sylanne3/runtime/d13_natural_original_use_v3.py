"""Actual retained Graph receivers for durable natural input originals."""
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest

_ISSUER = object()
_ADMISSIONS = WeakKeyDictionary()
_RELEASES = WeakKeyDictionary()
_BY_WORK = WeakKeyDictionary()
_RETAINED = {}
_PARENT_CLOSES = WeakKeyDictionary()
_REVIEW_WRITERS_V3 = WeakKeyDictionary()
_REVIEW_WRITER_OUTCOMES_V3 = WeakKeyDictionary()
_GENERATION_WRITERS_V3 = WeakKeyDictionary()
_GENERATION_WRITER_OUTCOMES_V3 = WeakKeyDictionary()


class D13NaturalOriginalAdmissionRequiredV3(Exception):
    def __init__(self, work):
        self.work = work
        super().__init__('actual natural original receiver awaits its original Core acknowledgement')


def _actual_work_v3(reader):
    from .current_graph_full_read_v3 import _OrdinaryFullReadV3
    from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
    from .natural_dispatch_initial_read_v1 import _NaturalInitialReadV1
    if type(reader) is _NaturalInitialReadV1:
        work = reader.bootstrap.work
    elif type(reader) in (_OrdinaryFullReadV3, _DispatchInventoryReadV3):
        work = reader.work
    else:
        raise AuthorityUnavailable('natural original receiver requires an actual registered Graph Source Work')
    if (work is None or work.state is not reader or work.coordinator is not reader.graph
            or work.operation is not reader.operation or reader.operation.closed
            or reader.fence.scope.permit is None):
        raise AuthorityUnavailable('natural original receiver lost its actual Work/retention/permit')
    work._require_invocation(reader.graph)
    return work


def _require_sources_v3(task, meter):
    reader=task.owner
    from .current_graph_full_read_v3 import _OrdinaryFullReadV3
    from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
    from .natural_dispatch_initial_read_v1 import _NaturalInitialReadV1
    if type(reader) is _NaturalInitialReadV1:
        reader.require_actual_v1()
    elif type(reader) is _DispatchInventoryReadV3:
        from .natural_dispatch_p2_read_v1 import require_natural_p2_source_all_v1
        require_natural_p2_source_all_v1(reader, reader.db)
    elif type(reader) is _OrdinaryFullReadV3:
        if not reader.graph_eof or reader.prefinal is None:
            raise AuthorityUnavailable('natural original receiver has no actual complete namespace/Source census')
        from .d13_natural_original_sources_v3 import require_host_natural_original_source_all_v3
        require_host_natural_original_source_all_v3(task, meter=meter)
    else:
        raise AuthorityUnavailable('unregistered natural original Source reader')


class D13GraphNaturalOriginalAdmissionProofV3:
    def __init__(self, issuer, reader, work, port, material, seal_column, *, review_writer_scope=None, generation_writer_scope=None):
        if issuer is not _ISSUER:
            raise TypeError('actual same-Work natural original producer required')
        self.reader, self.work, self.port = reader, work, port
        if review_writer_scope is not None and generation_writer_scope is not None:
            raise TypeError('one actual Natural writer stage required')
        self.review_writer_scope, self.generation_writer_scope = review_writer_scope, generation_writer_scope
        writer_scope = review_writer_scope if review_writer_scope is not None else generation_writer_scope
        self.operation, self.permit = reader.operation, (reader.fence.scope.permit if writer_scope is None else writer_scope.permit)
        stage = 'review_writer' if review_writer_scope is not None else 'generation_writer'
        self.entry_key = material['parent_original_id'] if writer_scope is None else (material['parent_original_id'],stage,self.permit.operation_id,self.permit.token)
        self.material, self.seal_column = material, seal_column
        self.registration = self.release_proof = None
        self.attempted = self.release_requested = False
        self.closed_receipt = None
        self.key = (work.operation_id, self.permit.token, material['parent_original_id'])
        _ADMISSIONS[self] = (reader, work, port, self.operation, self.permit, canonical_digest(material), seal_column)
        if self.key in _RETAINED:
            raise AuthorityUnavailable('natural original receiver already owns this exact Work/parent')
        _RETAINED[self.key] = self


def require_actual_graph_natural_owner_v3(proof, *, port, permit, action):
    if type(proof) is not D13GraphNaturalOriginalAdmissionProofV3:
        raise AuthorityUnavailable('actual private natural original receiver proof required')
    state = _ADMISSIONS.get(proof)
    if (state != (proof.reader, proof.work, port, proof.operation, permit,
                    canonical_digest(proof.material), proof.seal_column)
            or proof.port is not port or proof.permit is not permit
            or _RETAINED.get(proof.key) is not proof or action not in ('register', 'inspect')):
        raise AuthorityUnavailable('natural receiver changed its original Source Work/metadata/permit')
    if proof.review_writer_scope is not None:
        _require_actual_review_writer_identity_v3(proof, registering=action=='register')
    elif proof.generation_writer_scope is not None:
        _require_actual_generation_writer_identity_v3(proof, registering=action=='register')
    elif action == 'register':
        if proof.release_requested or proof.work.terminal or proof.operation.closed:
            raise AuthorityUnavailable('ended natural receiver cannot acquire a new execution-input use')
        _actual_work_v3(proof.reader)
    port._actual()
    return dict(proof.material)


def require_graph_natural_original_before_body_v3(task, *, meter):
    """Called before frozen_json is opened, after its real seal metadata EOF."""
    from .dispatch_initial_source_read_v3 import AuthorityNaturalSavedOriginalReadV3
    # Authority has its independent actual Core producer/receiver protocol.
    if type(task) is AuthorityNaturalSavedOriginalReadV3:
        return
    reader = task.owner
    from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
    if not _graph_use_enabled_v2(reader.graph):
        return
    work = _actual_work_v3(reader)
    _require_sources_v3(task, meter)
    column = task.natural_json['seal_json']
    seal = column.require_v3(reader)
    parent = task.natural_meta[0]
    if (seal['c02_operation_id'] != parent or seal['namespace'] != {
            'bot_id': reader.namespace.bot_id, 'persona_id': reader.namespace.persona_id}):
        raise AuthorityUnavailable('natural receiver actual seal metadata crosses its parent or namespace')
    port = reader.graph._GraphCoordinator__d13_cache_use_control_v2
    material = dict(parent_original_id=parent, generation_job_id=seal['job_id'],
        generation_original_id=seal['original_operation_id'], generation_call_id=seal['call_id'],
        generation_frozen_input_digest=seal['frozen_input_digest'], review_job_id=None, review_original_id=None,
        retention_instance_ref='d13-natural-reader-retention-v3:' + canonical_digest((
            reader.namespace, work.operation_id, reader.fence.scope.permit.token,
            reader.operation.selection_digest, parent, column.sha256)),
        selection_digest=reader.operation.selection_digest)
    entries = _BY_WORK.setdefault(work, {})
    proof = entries.get(parent)
    if proof is None:
        proof = D13GraphNaturalOriginalAdmissionProofV3(_ISSUER, reader, work, port, material, column)
        entries[parent] = proof
    elif proof.material != material or proof.seal_column is not column:
        raise AuthorityUnavailable('same natural reader cannot replace its original seal/selection')
    require_actual_graph_natural_owner_v3(proof, port=port, permit=proof.permit, action='register')
    if proof.registration is None:
        raise D13NaturalOriginalAdmissionRequiredV3(work)


def resolve_graph_natural_original_admission_v3(work):
    """The worker invokes this only after the actual Graph SQL quantum unwinds."""
    entries = _BY_WORK.get(work, {})
    for proof in entries.values():
        if proof.registration is not None:
            continue
        if proof.reader.db.in_transaction:
            raise AuthorityUnavailable('natural receiver acquisition cannot inherit Graph SQL')
        values = dict(namespace=proof.reader.namespace, authority_namespace=proof.permit.namespace,
            permit=proof.permit, natural_admission=proof)
        if proof.attempted:
            registration = proof.port.inspect_natural_original_for_fence_v3(**values)
        else:
            proof.attempted = True
            registration = proof.port.acquire_natural_original_for_fence_v3(**values)
        if registration is None:
            raise AuthorityUnavailable('natural receiver original acquisition is unknown; retain its original operation')
        proof.registration = registration
        return
    raise AuthorityUnavailable('natural receiver progress has no actual pending original admission')


class D13GraphNaturalOriginalReleaseProofV3:
    def __init__(self, issuer, admission):
        if issuer is not _ISSUER or not admission.release_requested or not admission.operation.closed:
            raise AuthorityUnavailable('natural receiver release requires its actual final retention')
        self.admission = admission
        self.original = None
        _RELEASES[self] = admission


def require_actual_graph_natural_release_v3(proof, *, port):
    from ..authority_service.d13_cache_use_contract_v2 import D13RetentionReleaseOriginalV3, owner_operation_id_v3
    if type(proof) is not D13GraphNaturalOriginalReleaseProofV3:
        raise AuthorityUnavailable('actual private natural receiver final release required')
    admission = _RELEASES.get(proof)
    if (admission is not proof.admission or admission is None or admission.port is not port
            or _RETAINED.get(admission.key) is not admission or not admission.release_requested
            or not admission.operation.closed or admission.registration is None):
        raise AuthorityUnavailable('natural receiver final retention lost its original acknowledged owner')
    registration = admission.registration
    if admission.review_writer_scope is not None and _REVIEW_WRITER_OUTCOMES_V3.get(admission)not in ('committed','rolled_back'):
        raise AuthorityUnavailable('Natural review writer awaits actual Graph COMMIT/ROLLBACK classification')
    if admission.generation_writer_scope is not None and _GENERATION_WRITER_OUTCOMES_V3.get(admission) not in ('committed','rolled_back'):
        raise AuthorityUnavailable('Natural generation writer awaits actual Graph COMMIT/ROLLBACK classification')
    if proof.original is None:
        values = dict(producer_kind_version=registration.producer_kind_version,
            owner_ref=registration.owner_ref, registration_digest=registration.registration_digest,
            payload_set_digest=registration.payload_digest, peer_admission_digest=registration.peer_admission_digest,
            process_incarnation=registration.process_incarnation, original_permit_digest=registration.permit_digest,
            retention_instance_ref=registration.retention_instance_ref,
            release_operation_id=owner_operation_id_v3(registration.namespace, registration.owner_ref, 'owner_close'))
        values['request_digest'] = canonical_digest(('d13.actual-natural-reader-final-retention.v3', values,
            admission.operation.operation_id, admission.operation.selection_digest))
        proof.original = D13RetentionReleaseOriginalV3(**values)
    return registration, admission.permit, proof.original


def request_graph_natural_original_release_v3(work):
    """Mark responsibility at actual final retention; the installed worker does RPC."""
    if not work.operation.closed:
        raise AuthorityUnavailable('natural input receiver is still retained by its actual result owner')
    from .d13_natural_original_sources_v3 import release_host_natural_original_source_all_v3
    release_host_natural_original_source_all_v3(work.state)
    entries = _BY_WORK.get(work)
    if not entries:
        return
    for proof in entries.values():
        proof.release_requested = True
    wake = work.coordinator._GraphCoordinator__d13_cache_use_release_wake_v3
    if wake is not None:
        wake()


def reconcile_graph_natural_original_cleanup_v3(graph):
    for proof in tuple(_RETAINED.values()):
        if proof.work.coordinator is not graph or not proof.release_requested:
            continue
        if proof.reader.db.in_transaction:
            raise AuthorityUnavailable('natural original cleanup cannot inherit Graph SQL')
        if proof.registration is None:
            if not proof.attempted:
                _RETAINED.pop(proof.key)
                _BY_WORK[proof.work].pop(proof.entry_key)
                _ADMISSIONS.pop(proof, None)
                _REVIEW_WRITERS_V3.pop(proof,None);_REVIEW_WRITER_OUTCOMES_V3.pop(proof,None)
                _GENERATION_WRITERS_V3.pop(proof,None);_GENERATION_WRITER_OUTCOMES_V3.pop(proof,None)
                continue
            proof.registration = proof.port.inspect_natural_original_for_fence_v3(
                namespace=proof.reader.namespace, authority_namespace=proof.permit.namespace,
                permit=proof.permit, natural_admission=proof)
            if proof.registration is None:
                raise AuthorityUnavailable('natural original receiver registration remains unknown; preserve original cleanup')
        if proof.release_proof is None:
            proof.release_proof = D13GraphNaturalOriginalReleaseProofV3(_ISSUER, proof)
        receipt = proof.port.close_original_owner_v3(proof.registration, close_admission=proof.release_proof)
        proof.closed_receipt = receipt
        _RETAINED.pop(proof.key)
        _BY_WORK[proof.work].pop(proof.entry_key)
        _ADMISSIONS.pop(proof, None)
        _RELEASES.pop(proof.release_proof, None)
        _REVIEW_WRITERS_V3.pop(proof,None);_REVIEW_WRITER_OUTCOMES_V3.pop(proof,None)
        _GENERATION_WRITERS_V3.pop(proof,None);_GENERATION_WRITER_OUTCOMES_V3.pop(proof,None)
        proof.release_proof = None
    _reconcile_parent_closures_v3(graph)


_ROSTER_OUTBOUND = WeakKeyDictionary()
_PARENT_CENSUSES = WeakKeyDictionary()
_PARENT_CENSUS_FIELDS = frozenset({'roster_head', 'admissions', 'outbounds',
    'graph_final_operation_ids', 'graph_snapshot_digest', 'graph_census_digest'})


def _require_actual_authority_parent_capsule_v3(maintenance, capsule):
    services = maintenance.owner.core._d13_cache_use_controls_v2
    service = services.get(maintenance.owner.namespace)
    if (service is None or service.namespace != maintenance.owner.namespace_id
            or service.installation_id != maintenance.owner.installation_id):
        raise AuthorityUnavailable('Natural parent has no actual paired Core owner control')
    with maintenance.owner.core._tx() as db:
        actual = service._owner_operation_v3(db, capsule.owner_ref, 'owner_parent_input')
        registration = service._owner_operation_v3(db, capsule.owner_ref, 'owner_register')
    if (actual != capsule or registration is None
            or registration.registration_digest != capsule.registration_digest
            or registration.original_locator.original_id != capsule.review_original_id):
        raise AuthorityUnavailable('Natural input capsule differs from its current actual immutable Core operation')
    return service


def _natural_metadata_column_v3(reader, table, column, key_columns, key):
    from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    original = DispatchOriginalJSONReadV3(reader, table=table, column=column,
        key_columns=key_columns, key=key)
    while not original.complete:
        with reader.quantum_v3() as meter:
            original.advance(meter)
    return original


def _natural_metadata_digest_v3(reader, value):
    from .owner_material_source_storage_v3 import CanonicalValueStreamV3
    from ..runtime_contracts import _canonical_value
    from .source_correction_read_v3 import _heap
    value = _canonical_value(value, set())
    reader.operation.retain(_heap(value))
    stream = CanonicalValueStreamV3(value)
    while not stream.complete:
        with reader.quantum_v3() as meter:
            stream.read_fragment(meter)
    return stream.hash.hexdigest()


def _natural_child_admission_metadata_v3(reader, child, locator):
    from dataclasses import asdict
    from .dispatch_admission import (_admission_value_from_parsed_v3,
        DispatchAdmissionReceiptV1, namespace_of)
    namespace, operation, effect = reader.namespace, child[1], child[2]
    args = (*namespace.as_tuple, operation)
    row = reader.fixed_v3('graph_dispatch_admissions', ('admission_ref',),
        'bot=? AND persona=? AND operation_id=?', args)
    if row is None:
        if locator is not None:
            raise AuthorityUnavailable('Natural final locator lost its actual child admission')
        return None
    other = reader.fixed_v3('graph_dispatch_admissions', ('admission_ref',),
        'bot=? AND persona=? AND operation_id=? AND admission_ref<>?', (*args, row[0]))
    if other is not None or locator is None or row[0] != locator['admission_ref']:
        raise AuthorityUnavailable('Natural child admission is ambiguous or outside its actual selected locator')
    key = (*namespace.as_tuple, row[0])
    header = reader.fixed_v3('graph_dispatch_admissions',
        ('operation_id', 'effect_id', 'admission_digest', 'graph_revision', 'graph_epoch', 'receipt_digest'),
        'bot=? AND persona=? AND admission_ref=?', key)
    column = _natural_metadata_column_v3(reader, 'graph_dispatch_admissions', 'admission_json',
        ('bot', 'persona', 'admission_ref'), key)
    with reader.quantum_v3() as meter:
        meter.require_available(column.byte_count * 16 + 4096)
        reader.operation.retain(column.byte_count * 8 + 4096)
        admission = _admission_value_from_parsed_v3(column.require_v3(reader))
    digest = _natural_metadata_digest_v3(reader, asdict(admission))
    if ((admission.operation_id, admission.effect_id) != (operation, effect)
            or namespace_of(admission) != namespace or admission.admission_ref != row[0]
            or header != (operation, effect, digest, locator['graph_revision'],
                          locator['graph_epoch'], locator['admission_receipt_digest'])
            or digest != locator['admission_digest']):
        raise AuthorityUnavailable('Natural child admission EOF differs from its exact locator/Graph commitment')
    with reader.quantum_v3() as meter:
        meter.require_available(column.byte_count * 16 + 4096)
        return DispatchAdmissionReceiptV1(admission, *header[3:])


def _natural_child_outbound_metadata_v3(reader, child, observation, admission):
    from ..authority_service.v2_contract import from_wire, MutationReceiptV2
    args = (*reader.namespace.as_tuple, child[1])
    if (type(observation) is not MutationReceiptV2
            or observation.durable_state != 'committed' or observation.pending.phase != 'observed'
            or observation.pending.platform_observation is None
            or observation.pending.platform_observation.outcome not in ('accepted', 'delivered')):
        history = reader.fixed_v3('graph_d13_outbound_observations_v1', ('observation_digest',),
            'bot=? AND persona=? AND final_operation_id=?', args)
        if history is not None:
            raise AuthorityUnavailable('Natural child outbound history has no qualified current observation')
        return None
    current_digest = _natural_metadata_digest_v3(reader, observation)
    key = (*args, current_digest)
    row = reader.fixed_v3('graph_d13_outbound_observations_v1', ('observation_digest', 'original_digest'),
        'bot=? AND persona=? AND final_operation_id=? AND observation_digest=?', key)
    if row is None:
        return None
    if admission is None:
        raise AuthorityUnavailable('Natural child outbound metadata has no actual child admission')
    columns = tuple(_natural_metadata_column_v3(reader, 'graph_d13_outbound_observations_v1', name,
        ('bot', 'persona', 'final_operation_id', 'observation_digest'), key)
        for name in ('observation_json', 'original_json'))
    with reader.quantum_v3() as meter:
        meter.require_available(sum(column.byte_count for column in columns) * 16 + 4096)
        reader.operation.retain(sum(column.byte_count for column in columns) * 8 + 4096)
        decoded = from_wire(columns[0].require_v3(reader))
        adoption = columns[1].require_v3(reader)
    if (type(decoded) is not MutationReceiptV2 or decoded != observation
            or current_digest != row[0]
            or _natural_metadata_digest_v3(reader, adoption) != row[1]
            or adoption.get('schema') != 'd13.outbound_adoption.v1'
            or adoption.get('observation_digest') != row[0]):
        raise AuthorityUnavailable('Natural outbound adoption differs from its actual complete metadata originals')
    binding = observation.pending.platform_observation.binding
    if ((binding.origin.operation_id, binding.origin.effect_id) != child[1:]
            or binding.admission_receipt_digest != admission.receipt_digest):
        raise AuthorityUnavailable('Natural outbound observation changed its actual child admission identity')
    return observation, adoption

class _ActualAuthorityNaturalRosterOutboundV3:
    def __init__(self, issuer, maintenance, head, values, context, selected, operation):
        if issuer is not _ISSUER:
            raise TypeError('actual installed natural roster metadata producer required')
        self.maintenance, self.head, self.values, self.context = maintenance, head, values, context
        self.selected, self.operation = selected, operation
        _ROSTER_OUTBOUND[self] = self._identity_v3()

    def _identity_v3(self):
        return (self.maintenance, self.head, canonical_digest(self.values), self.context,
                self.selected, self.operation)

    def release_v3(self):
        if _ROSTER_OUTBOUND.pop(self, None) is not None:
            try:
                self.selected.release_v3()
            finally:
                self.operation.release()


def prepare_actual_authority_natural_roster_outbound_v3(maintenance, head, *, credential, subject):
    """Actual selected roster plus complete child admissions and outbound metadata."""
    from contextlib import closing
    import sqlite3
    from pathlib import Path
    from ..authority_service.natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from ..authority_service.d13_original_owner_v3 import D13NaturalRosterNotTerminalV3
    from .natural_roster_metadata_read_v3 import (prepare_authority_natural_roster_metadata_v3,
        _RosterMetadataReadV3)
    from .natural_same_batch_history_v3 import read_natural_roster_head_v1
    from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,
        begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3)
    if type(maintenance) is not InstalledNaturalDispositionMaintenanceServiceV1:
        raise AuthorityUnavailable('actual installed natural disposition service required')
    maintenance._paired(credential, subject)
    selected = prepare_authority_natural_roster_metadata_v3(maintenance,
        parent_original_id=head[2].parent_original_id)
    operation = handle = None
    issued = False
    try:
        if selected.head != head:
            raise AuthorityUnavailable('Natural successful parent differs from its actual selected signed head')
        capsule, context = selected.capsule, selected.context
        _require_actual_authority_parent_capsule_v3(maintenance, capsule)
        effects = tuple(maintenance.execution.read_current_effect(credential=credential,
            subject=subject, effect_id=child[2]) for child in capsule.child_identities)
        if any(effect.state != 'observed' for effect in effects):
            raise D13NaturalRosterNotTerminalV3('natural parent still has an unobserved actual child effect')
        observed = tuple(maintenance.execution.read_current_observation_receipt_v1(
            credential=credential, subject=subject, effect_id=child[2]) for child in capsule.child_identities)
        with closing(sqlite3.connect(Path(selected.storage['graph_path']).as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            handle = bind_runtime_database_from_control_v3(db, control=maintenance.owner.control, role='graph')
            if handle is None:
                raise AuthorityUnavailable('Natural outbound census requires the actual selected Graph')
            operation = begin_runtime_storage_operation_v3(db, 'natural-roster-outbound:' + capsule.operation_id, None)
            if operation.selection_digest != selected.operation.selection_digest:
                raise AuthorityUnavailable('Natural outbound metadata changed its selected storage')
            reader = _RosterMetadataReadV3(maintenance, db, operation, capsule)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(operation, db), selected.bind_v3(db):
                if read_natural_roster_head_v1(db, capsule.namespace, capsule.parent_original_id) != head:
                    raise AuthorityUnavailable('Natural parent changed its exact selected roster head')
                admissions, outbounds = [], []
                for child, observation in zip(capsule.child_identities, observed):
                    locator = selected.read_child_locator_v3(db, child[1])
                    admission = _natural_child_admission_metadata_v3(reader, child, locator)
                    outbound = _natural_child_outbound_metadata_v3(reader, child, observation, admission)
                    if admission is None or outbound is None:
                        raise D13NaturalRosterNotTerminalV3('Natural child admission or outbound adoption is not complete')
                    admissions.append(admission)
                    outbounds.append(outbound)
            db.rollback()
            handle.close(); handle = None
        context.require_current('business')
        values = (tuple(admissions), observed, tuple(outbound[1] for outbound in outbounds))
        proof = _ActualAuthorityNaturalRosterOutboundV3(_ISSUER, maintenance, head, values,
            context, selected, operation)
        issued = True
        return proof
    finally:
        if handle is not None:
            handle.close()
        if not issued:
            if operation is not None:
                operation.release()
            selected.release_v3()


def require_actual_authority_natural_roster_outbound_v3(proof, maintenance, head):
    if (type(proof) is not _ActualAuthorityNaturalRosterOutboundV3
            or _ROSTER_OUTBOUND.get(proof) != proof._identity_v3()
            or proof.maintenance is not maintenance or proof.head != head or proof.operation.closed):
        raise AuthorityUnavailable('natural close requires the actual same-roster outbound metadata producer')
    proof.selected._actual_v3()
    proof.context.require_current('business')
    return (*proof.values, proof.context)


class _NaturalReceiptClassificationColumnV3:
    """Closed receipt metadata profile; never a whole-original/Body proof."""
    def __init__(self, reader, operation_id):
        from .natural_dispatch_locator_metadata_v1 import NaturalDispatchLocatorMetadataColumnV1
        from .c09_canonical_json_stream_v2 import _CanonicalJSONValueBuilderV3
        class Profile(NaturalDispatchLocatorMetadataColumnV1):
            def _emit(self, event):
                markers = {'natural_dispatch_candidate', 'dispatch_candidate',
                           'contact_dispatch_candidate', 'dispatch_admission'}
                path = event.path
                if path and path[0] in markers:
                    if len(path) == 1 and event.kind in {'object_start', 'object_end'}:
                        return _CanonicalJSONValueBuilderV3._emit(self, event)
                    names = {'schema', 'status', 'digest', 'ref'}
                    if len(path) == 2 and path[1] in names:
                        return _CanonicalJSONValueBuilderV3._emit(self, event)
                    return
                if path == ('commit_seq',):
                    return _CanonicalJSONValueBuilderV3._emit(self, event)
                return super()._emit(event)
        self.reader, self.operation_id = reader, operation_id
        self.column = Profile(reader, operation_id)
        self.complete = False

    def advance(self, meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2, legacy_cell_read_transaction_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        column = self.column
        if column.fragment_offset < len(column.fragment):
            end = min(column.fragment_offset + 1024, len(column.fragment))
            column._reserve(65536)
            column.parser.feed(column.fragment[column.fragment_offset:end], column._emit)
            column.fragment_offset = end
            return False
        key = (*self.reader.namespace.as_tuple, self.operation_id)
        with legacy_cell_read_transaction_v2(self.reader.db):
            if column.total is None:
                row = self.reader.db.execute('SELECT length(CAST(receipt_json AS BLOB)) FROM '
                    'graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?', key).fetchone()
                meter.charge_read(8)
                if row is None:
                    raise AuthorityUnavailable('Natural census actual Graph receipt metadata is absent')
                if type(row[0]) is not int or row[0] < 0:
                    raise AuthorityUnavailable('Natural census legacy_unknown: canonical receipt metadata is absent')
                column.total = row[0]
            if column.offset < column.total:
                fragment, total, kind = read_legacy_sql_cell_fragment_v2(self.reader.db,
                    table='graph_bundle_operations', column='receipt_json',
                    where='bot=? AND persona=? AND operation_id=?', parameters=key,
                    start=column.offset, length=min(16384, column.total-column.offset), meter=meter)
                if total != column.total or kind != 'text':
                    raise AuthorityUnavailable('Natural census Graph receipt metadata changed')
                column.offset += len(fragment)
                column.fragment, column.fragment_offset = fragment, 0
                return False
        parsed = column.parser.finish()
        if parsed.byte_count != column.total:
            raise AuthorityUnavailable('Natural census Graph receipt metadata lacks canonical EOF')
        column.operation.retain(column._detached_container_bytes + 1024)
        self.raw = _detach_value_v3(column.value)
        self.sha256, self.byte_count = parsed.sha256, parsed.byte_count
        column.nodes = {}; column.value = column.parser = None
        column.scalar = bytearray(); column.fragment = b''
        self.complete = True
        return True


def _natural_graph_parent_census_v3(reader, *, include_roster_versions=False, include_runtime_jobs=False):
    """Classify the complete actual bundle/event/admission metadata namespace."""
    from ..graph_types import AtomKey
    from ..domains.d09.natural_disposition_v1 import TYPE as roster_type
    from .natural_dispatch_locator_metadata_v1 import _FIELD_V1
    namespace = reader.namespace
    events, bundles, naturals, admissions = {}, {}, [], {}
    roster_versions = []
    runtime_jobs = []
    cursor = None
    while True:
        where, args = ('bot=? AND persona=? ORDER BY session,event_id', namespace.as_tuple) if cursor is None else (
            'bot=? AND persona=? AND (session>? OR (session=? AND event_id>?)) ORDER BY session,event_id',
            (*namespace.as_tuple, cursor[0], cursor[0], cursor[1]))
        row = reader.fixed_v3('graph_events', ('session', 'event_id', 'epoch_revision'), where, args)
        if row is None:
            break
        cursor = row[:2]
        column = _natural_metadata_column_v3(reader, 'graph_events', 'revisions',
            ('bot', 'persona', 'session', 'event_id'), (*namespace.as_tuple, *cursor))
        with reader.quantum_v3() as meter:
            meter.require_available(column.byte_count * 8 + 4096)
            versions = column.require_v3(reader)
        if (type(versions) is not list or any(type(v) is not list or len(v) != 2
                or type(v[1]) is not int or v[1] < 1 for v in versions)):
            raise AuthorityUnavailable('Natural census has unclassified legacy Graph event versions')
        batches = tuple((token, revision, AtomKey.from_token(token).type_name)
                        for token, revision in versions
                        if AtomKey.from_token(token).type_name.startswith('d09.')
                        and 'batch' in AtomKey.from_token(token).type_name
                        and AtomKey.from_token(token).type_name != roster_type)
        if include_runtime_jobs:
            runtime_jobs.extend((token,revision,*cursor)for token,revision in versions if AtomKey.from_token(token).type_name=='runtime.job')
        if include_roster_versions:
            roster_versions.extend((token,revision,*cursor)for token,revision in versions if AtomKey.from_token(token).type_name==roster_type)
        events[cursor] = (row[2], batches, column.sha256, column.byte_count)
    cursor = None
    while True:
        where, args = ('bot=? AND persona=? ORDER BY operation_id', namespace.as_tuple) if cursor is None else (
            'bot=? AND persona=? AND operation_id>? ORDER BY operation_id', (*namespace.as_tuple, cursor))
        row = reader.fixed_v3('graph_bundle_operations',
            ('operation_id', 'digest', 'activity_id', 'effect_id', 'commit_seq'), where, args)
        if row is None:
            break
        operation, cursor = row[0], row[0]
        event = events.get((row[2], operation))
        if event is None:
            raise AuthorityUnavailable('Natural census legacy_unknown: Graph bundle has no actual event metadata')
        column = _NaturalReceiptClassificationColumnV3(reader, operation)
        while not column.complete:
            with reader.quantum_v3() as meter:
                column.advance(meter)
        raw = column.raw
        if type(raw) is not dict or raw.get('commit_seq') != row[4]:
            raise AuthorityUnavailable('Natural census legacy_unknown: Graph receipt metadata has no exact commit identity')
        markers = tuple(name for name in ('natural_dispatch_candidate', 'dispatch_candidate',
            'contact_dispatch_candidate') if name in raw)
        if len(markers) > 1:
            raise AuthorityUnavailable('Natural census legacy_unknown: conflicting actual final producer metadata')
        natural_batches = tuple(batch for batch in event[1] if batch[2].startswith('d09.natural_'))
        if markers == ('natural_dispatch_candidate',):
            marker, locator = raw[markers[0]], raw.get(_FIELD_V1)
            if (marker.get('schema') != 'sylanne.d11.natural_dispatch_candidate.v2'
                    or marker.get('status') != 'natural_paid_review_current_hold' or not natural_batches
                    or type(locator) is not dict or type(locator.get('metadata')) is not dict):
                raise AuthorityUnavailable('Natural census legacy_unknown: Natural producer lacks its actual final locator')
            metadata = locator['metadata']
            recipe = metadata.get('recipe')
            if type(recipe) is not dict or type(recipe.get('generation_parent_original_id')) is not str:
                raise AuthorityUnavailable('Natural census legacy_unknown: final lineage metadata is incomplete')
            digest = _natural_metadata_digest_v3(reader, metadata)
            if digest != locator.get('metadata_sha256'):
                raise AuthorityUnavailable('Natural census actual locator metadata digest differs')
            naturals.append((operation, recipe['generation_parent_original_id'], digest))
        elif markers:
            name = markers[0]
            schemas = ({'sylanne.d11.dispatch_candidate.v1'} if name == 'dispatch_candidate' else
                {'sylanne.d11.contact_dispatch_candidate.v1', 'sylanne.d11.contact_dispatch_candidate.v2',
                 'sylanne.d11.contact_dispatch_candidate.v3'})
            if (raw[name].get('schema') not in schemas or natural_batches or _FIELD_V1 in raw
                    or not event[1] or 'dispatch_admission' not in raw):
                raise AuthorityUnavailable('Natural census legacy_unknown: unrelated final producer is not classified')
        elif event[1] or _FIELD_V1 in raw or 'dispatch_admission' in raw:
            raise AuthorityUnavailable('Natural census legacy_unknown: batch/final metadata has no registered producer')
        bundles[operation] = (row, raw.get('dispatch_admission'), column.sha256, column.byte_count)
    for (session, operation), event in events.items():
        if event[1] and operation not in bundles:
            raise AuthorityUnavailable('Natural census legacy_unknown: batch event has no actual final receipt')
    cursor = None
    while True:
        where, args = ('bot=? AND persona=? ORDER BY admission_ref', namespace.as_tuple) if cursor is None else (
            'bot=? AND persona=? AND admission_ref>? ORDER BY admission_ref', (*namespace.as_tuple, cursor))
        row = reader.fixed_v3('graph_dispatch_admissions',
            ('admission_ref', 'operation_id', 'effect_id', 'admission_digest', 'graph_revision', 'graph_epoch', 'receipt_digest'), where, args)
        if row is None:
            break
        cursor = row[0]
        bundle = bundles.get(row[1])
        marker = None if bundle is None else bundle[1]
        if (bundle is None or bundle[0][3] != row[2] or type(marker) is not dict
                or marker.get('schema') != 'sylanne.d11.dispatch_admission.v1'
                or marker.get('ref') != row[0] or marker.get('digest') != row[6]
                or row[1] in admissions):
            raise AuthorityUnavailable('Natural census legacy_unknown: admission has no unique actual classified Graph final')
        admissions[row[1]] = row
    for operation, bundle in bundles.items():
        if bundle[1] is not None and operation not in admissions:
            raise AuthorityUnavailable('Natural census actual final has no complete admission metadata')
    result = {'events': events, 'bundles': bundles, 'admissions': admissions, 'naturals': tuple(naturals)}
    if include_roster_versions:result['roster_versions']=tuple(roster_versions)
    if include_runtime_jobs:result['runtime_jobs']=tuple(runtime_jobs)
    return result


class _ActualAuthorityNaturalParentCensusV3:
    def __init__(self, issuer, maintenance, capsule, facts, selected, operation, census_operation):
        if issuer is not _ISSUER or type(facts) is not dict or set(facts) != _PARENT_CENSUS_FIELDS:
            raise TypeError('actual complete Natural parent metadata census issuer required')
        self.maintenance, self.capsule, self.facts = maintenance, capsule, facts
        self.selected, self.operation, self.context = selected, operation, selected.context
        self.census_operation = census_operation
        _PARENT_CENSUSES[self] = self._identity_v3()

    def _identity_v3(self):
        return (self.maintenance, self.capsule, canonical_digest(self.facts),
                self.selected, self.operation, self.census_operation, self.context)

    def release_v3(self):
        if _PARENT_CENSUSES.pop(self, None) is not None:
            try:
                self.selected.release_v3()
            finally:
                try:
                    self.operation.release()
                finally:
                    self.census_operation.release()


def prepare_actual_authority_natural_parent_census_v3(maintenance, capsule, *, credential, subject):
    """Actual capsule plus a complete classified selected Graph metadata census."""
    from contextlib import closing
    import sqlite3
    from pathlib import Path
    from ..authority_service.natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from ..authority_service.d13_cache_use_contract_v2 import D13NaturalParentInputReceiptV3
    from .natural_roster_metadata_read_v3 import (prepare_authority_natural_roster_metadata_v3,
        _RosterMetadataReadV3)
    from .natural_same_batch_history_v3 import read_natural_roster_head_v1
    from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,
        begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3)
    if (type(maintenance) is not InstalledNaturalDispositionMaintenanceServiceV1
            or type(capsule) is not D13NaturalParentInputReceiptV3):
        raise AuthorityUnavailable('actual installed Natural maintenance/input capsule required')
    maintenance._paired(credential, subject)
    # This resolves owner_parent_input from its exact current Core operation;
    # caller DTO equality alone cannot issue the selected proof.
    selected = prepare_authority_natural_roster_metadata_v3(maintenance,
        parent_original_id=capsule.parent_original_id, capsule=capsule)
    operation = census_operation = handle = None
    foreign = {}
    issued = False
    try:
        _require_actual_authority_parent_capsule_v3(maintenance, capsule)
        if selected.capsule != capsule or set(selected.child_locators) != {child[1] for child in capsule.child_identities}:
            raise AuthorityUnavailable('Natural parent selected metadata lost its actual complete Core capsule')
        with closing(sqlite3.connect(Path(selected.storage['graph_path']).as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            handle = bind_runtime_database_from_control_v3(db, control=maintenance.owner.control, role='graph')
            if handle is None:
                raise AuthorityUnavailable('Natural parent census requires the actual selected Graph')
            census_operation = begin_runtime_storage_operation_v3(db, 'natural-parent-corpus:' + capsule.operation_id, None)
            census_reader = _RosterMetadataReadV3(maintenance, db, census_operation, capsule)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(census_operation, db), selected.bind_v3(db):
                corpus = _natural_graph_parent_census_v3(census_reader)
                corpus_digest = _natural_metadata_digest_v3(census_reader,
                    {'events': tuple((key, value) for key, value in sorted(corpus['events'].items())),
                     'bundles': tuple(sorted(corpus['bundles'].items())),
                     'admissions': tuple(sorted(corpus['admissions'].items())),
                     'natural_locators': corpus['naturals'], 'headers': tuple(census_reader.headers)})
            db.rollback()
            handle.close(); handle = None
        # Every Natural candidate, including unrelated historical parents, must
        # have actual Core lineage and a fully verified selected final locator.
        # No plan-ref heuristic classifies an unknown legacy/imported final.
        for _, parent, _ in corpus['naturals']:
            if parent != capsule.parent_original_id and parent not in foreign:
                foreign[parent] = prepare_authority_natural_roster_metadata_v3(maintenance,
                    parent_original_id=parent)
                _require_actual_authority_parent_capsule_v3(maintenance, foreign[parent].capsule)
        effects = tuple(maintenance.execution.read_current_effect(credential=credential,
            subject=subject, effect_id=child[2]) for child in capsule.child_identities)
        observed = tuple(maintenance.execution.read_current_observation_receipt_v1(
            credential=credential, subject=subject, effect_id=child[2]) if effect.state == 'observed' else None
            for child, effect in zip(capsule.child_identities, effects))
        with closing(sqlite3.connect(Path(selected.storage['graph_path']).as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            handle = bind_runtime_database_from_control_v3(db, control=maintenance.owner.control, role='graph')
            if handle is None:
                raise AuthorityUnavailable('Natural parent proof lost the actual selected Graph')
            operation = begin_runtime_storage_operation_v3(db, 'natural-parent-census:' + capsule.operation_id, None)
            if operation.selection_digest != census_operation.selection_digest:
                raise AuthorityUnavailable('Natural parent metadata phases changed selected storage')
            reader = _RosterMetadataReadV3(maintenance, db, operation, capsule)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(operation, db), selected.bind_v3(db):
                head = read_natural_roster_head_v1(db, capsule.namespace, capsule.parent_original_id)
                graph_operations, classified = [], []
                lineage = (capsule.generation_original_id, capsule.generation_original_digest,
                           capsule.review_original_id, capsule.review_original_digest)
                for final_operation, parent, digest in corpus['naturals']:
                    actual = selected if parent == capsule.parent_original_id else foreign[parent]
                    actual_capsule = actual.capsule
                    allowed = {child[1] for child in actual_capsule.child_identities}
                    if final_operation not in allowed:
                        raise AuthorityUnavailable('Natural metadata final lies outside its complete actual Core child manifest')
                    locator = actual.read_child_locator_v3(db, final_operation)
                    if locator is None or _natural_metadata_digest_v3(reader, locator) != digest:
                        raise AuthorityUnavailable('Natural final census differs from its actual verified selected locator')
                    actual_lineage = (actual_capsule.generation_original_id, actual_capsule.generation_original_digest,
                                      actual_capsule.review_original_id, actual_capsule.review_original_digest)
                    if actual_lineage == lineage:
                        if actual_capsule != capsule:
                            raise AuthorityUnavailable('Natural same-lineage final has a different immutable parent capsule')
                        graph_operations.append(final_operation)
                    elif (actual_lineage[0] == lineage[0] or actual_lineage[2] == lineage[2]):
                        raise AuthorityUnavailable('Natural final census has an ambiguous generation/review lineage')
                    classified.append((final_operation, actual_capsule.input_digest, digest))
                admissions, outbounds, locators = [], [], []
                for child, observation in zip(capsule.child_identities, observed):
                    locator = selected.read_child_locator_v3(db, child[1])
                    if (locator is not None) != (child[1] in graph_operations):
                        raise AuthorityUnavailable('Natural complete namespace census differs from exact child presence/absence')
                    admission = _natural_child_admission_metadata_v3(reader, child, locator)
                    outbound = _natural_child_outbound_metadata_v3(reader, child, observation, admission)
                    admissions.append(admission); outbounds.append(outbound); locators.append(locator)
                snapshot = _natural_metadata_digest_v3(reader,
                    {'schema': 'sylanne3.d13.actual-parent-graph-snapshot.v3', 'namespace': capsule.namespace,
                     'selection_digest': operation.selection_digest, 'stamp': selected.stamp,
                     'selected_headers': tuple(selected.headers), 'census_headers': tuple(reader.headers),
                     'complete_namespace_metadata_digest': corpus_digest})
                graph_operations = tuple(sorted(graph_operations))
                facts = {'roster_head': head, 'admissions': tuple(admissions), 'outbounds': tuple(outbounds),
                    'graph_final_operation_ids': graph_operations, 'graph_snapshot_digest': snapshot,
                    'graph_census_digest': _natural_metadata_digest_v3(reader,
                        {'schema': 'sylanne3.d13.actual-parent-graph-census.v3', 'capsule_digest': capsule.input_digest,
                         'snapshot_digest': snapshot, 'classified_final_lineages': tuple(classified),
                         'child_locators': tuple(locators), 'admissions': tuple(admissions),
                         'outbounds': tuple(outbounds), 'graph_final_operation_ids': graph_operations})}
            db.rollback()
            handle.close(); handle = None
        selected.context.require_current('business')
        proof = _ActualAuthorityNaturalParentCensusV3(_ISSUER, maintenance, capsule, facts,
            selected, operation, census_operation)
        issued = True
        return proof
    finally:
        if handle is not None:
            handle.close()
        for proof in foreign.values():
            proof.release_v3()
        if not issued:
            try:
                if operation is not None:
                    operation.release()
            finally:
                try:
                    if census_operation is not None:
                        census_operation.release()
                finally:
                    selected.release_v3()


def require_actual_authority_natural_parent_census_v3(proof, maintenance, capsule):
    """Pure private proof/current-context check; safe inside the frozen Core tx."""
    if (type(proof) is not _ActualAuthorityNaturalParentCensusV3
            or _PARENT_CENSUSES.get(proof) != proof._identity_v3()
            or proof.maintenance is not maintenance or proof.capsule != capsule
            or proof.operation.closed or proof.census_operation.closed or set(proof.facts) != _PARENT_CENSUS_FIELDS
            or type(proof.facts['admissions']) is not tuple or type(proof.facts['outbounds']) is not tuple
            or len(proof.facts['admissions']) != capsule.child_count
            or len(proof.facts['outbounds']) != capsule.child_count):
        raise AuthorityUnavailable('Natural parent closure requires its actual independently issued complete census')
    proof.selected._actual_v3()
    proof.context.require_current('business')
    return dict(proof.facts), proof.context


def close_graph_natural_parent_after_outbound_v3(graph, *, namespace, generation_original_id, permit):
    """Continue the same parent after actual outbound adoption, without reopening a job."""
    from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
    if not _graph_use_enabled_v2(graph):
        return
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3
    store = graph._GraphCoordinator__store
    with runtime_storage_operation_v3(store._db, operation_id='d13-natural-parent-lookup:' + generation_original_id):
        with store._lock, runtime_storage_quantum_v3(store._db) as meter:
            if store._db.in_transaction:
                raise AuthorityUnavailable('natural parent completion cannot inherit outbound Graph SQL')
            store._db.execute('BEGIN')
            try:
                row = _runtime_bounded_fixed_row_v3(store._db, meter, 'graph_natural_generation_preparations_v2',
                    ('parent_original_id',), 'bot=? AND persona=? AND original_operation_id=?',
                    (*namespace.as_tuple, generation_original_id))
                if row is None:
                    raise AuthorityUnavailable('actual adopted outbound has no original natural parent identity')
                other = _runtime_bounded_fixed_row_v3(store._db, meter, 'graph_natural_generation_preparations_v2',
                    ('parent_original_id',), 'bot=? AND persona=? AND original_operation_id=? AND parent_original_id<>?',
                    (*namespace.as_tuple, generation_original_id, row[0]))
                if other is not None:
                    raise AuthorityUnavailable('actual outbound natural parent identity is ambiguous')
            finally:
                store._db.rollback()
    parent = row[0]
    pending = _PARENT_CLOSES.setdefault(graph, {})
    if parent not in pending:
        pending[parent] = (namespace, permit)
    _reconcile_parent_closures_v3(graph, selected_parent=parent)


def _reconcile_parent_closures_v3(graph, *, selected_parent=None):
    from ..authority_service.d13_original_owner_v3 import D13NaturalRosterNotTerminalV3
    pending = _PARENT_CLOSES.get(graph, {})
    port = graph._GraphCoordinator__d13_cache_use_control_v2
    for parent, (namespace, permit) in tuple(pending.items()):
        if selected_parent is not None and parent != selected_parent:
            continue
        if graph._GraphCoordinator__store._db.in_transaction:
            raise AuthorityUnavailable('natural parent closure cannot inherit Graph SQL')
        try:
            port.close_natural_parent_for_fence_v3(namespace=namespace, authority_namespace=permit.namespace,
                permit=permit, parent_original_id=parent)
        except D13NaturalRosterNotTerminalV3:
            continue
        pending.pop(parent)


_PRE_REVIEW_CENSUSES_V3=WeakKeyDictionary()
_PRE_REVIEW_FIELDS_V3=frozenset({'roster_head','generation_locator','review_preparation','review_acquisition',
    'graph_final_operation_ids','graph_admissions','graph_snapshot_digest','graph_census_digest'})


def _pre_review_metadata_reader_v3(maintenance,db,operation,parse_original,registration):
    from .natural_roster_metadata_read_v3 import _RosterMetadataReadV3
    from ..authority_service.d13_cache_use_contract_v2 import D13NaturalGenerationParseReceiptV3
    class ParseMetadataReadV3(_RosterMetadataReadV3):
        def __init__(self):
            if type(parse_original)is not D13NaturalGenerationParseReceiptV3:
                raise AuthorityUnavailable('Natural pre-review metadata requires its actual parse original')
            self.service,self.db,self.operation=maintenance,db,operation
            self.parse_original,self.registration=parse_original,registration
            self.namespace=parse_original.namespace;self.headers=[]
    return ParseMetadataReadV3()


def _natural_preparation_corpus_v3(reader):
    from .natural_reply_job_v2 import natural_job_ids_v2,_seal
    ns=reader.namespace;generations={};reviews={};headers=[]
    for stage,table in (('generation','graph_natural_generation_preparations_v2'),('review','graph_natural_review_preparations_v2')):
        installed=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",(table,))
        if installed is None:
            headers.append((stage,None));continue
        cursor=None
        while True:
            where,args=('bot=? AND persona=? ORDER BY parent_original_id',ns.as_tuple)if cursor is None else(
                'bot=? AND persona=? AND parent_original_id>? ORDER BY parent_original_id',(*ns.as_tuple,cursor))
            row=reader.fixed_v3(table,('parent_original_id','job_id','original_operation_id','state','worker_fence','typed_request_digest','terminal_receipt_digest','terminal_output_digest'),where,args)
            if row is None:break
            cursor=row[0];column=_natural_metadata_column_v3(reader,table,'seal_json',('bot','persona','parent_original_id'),(*ns.as_tuple,cursor))
            with reader.quantum_v3()as meter:
                meter.require_available(column.byte_count*8+4096);raw=column.require_v3(reader)
            try:seal=_seal(stage,raw)
            except (KeyError,TypeError,ValueError)as exc:
                raise AuthorityUnavailable('Natural pre-review census has an unknown legacy seal schema')from exc
            ids=natural_job_ids_v2(ns,cursor,stage)
            if(seal.namespace!=ns or(row[1],row[2])!=ids[:2]
                    or(seal.job_id,seal.original_operation_id,seal.acquire_operation_id,seal.call_id,seal.reservation_operation_id)!=ids):
                raise AuthorityUnavailable('Natural pre-review census has unclassified preparation identity')
            if stage=='generation':
                if seal.c02_operation_id!=cursor:raise AuthorityUnavailable('Natural generation metadata changed its actual parent')
                generations[cursor]=(row,seal,column.sha256)
            else:reviews[cursor]=(row,seal,column.sha256)
            headers.append((stage,row,column.sha256,column.byte_count))
    for parent,(row,review,digest)in reviews.items():
        generation=generations.get(parent)
        if generation is None or(review.generation_original_operation_id,review.generation_call_id,review.generation_frozen_input_digest)!=(
                generation[1].original_operation_id,generation[1].call_id,generation[1].frozen_input_digest):
            raise AuthorityUnavailable('Natural terminal census has unknown review generation lineage')
    jobs_present=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",('runtime_jobs',))
    if jobs_present is not None:
        for kind,selected in (('natural_generation',generations),('natural_review',reviews)):
            cursor=None
            while True:
                where,args=('bot_id=? AND persona_id=? AND work_kind=? ORDER BY job_id',(*ns.as_tuple,kind))if cursor is None else(
                    'bot_id=? AND persona_id=? AND work_kind=? AND job_id>? ORDER BY job_id',(*ns.as_tuple,kind,cursor))
                row=reader.fixed_v3('runtime_jobs',('job_id','operation_id','phase','work_kind'),where,args)
                if row is None:break
                cursor=row[0]
                matches=[v for v in selected.values()if v[1].job_id==row[0]and v[1].original_operation_id==row[1]]
                if len(matches)!=1:raise AuthorityUnavailable('Natural terminal census has an unclassified actual '+kind+' job')
    return generations,reviews,tuple(headers)


def _pre_review_preparations_v3(reader,parse_original):
    generations,reviews,headers=_natural_preparation_corpus_v3(reader)
    actual=generations.get(parse_original.parent_original_id)
    if actual is None:raise AuthorityUnavailable('Natural actual parsed generation has no selected Graph preparation')
    row,seal,digest=actual
    locator=(seal.job_id,seal.original_operation_id,digest,seal.frozen_input_digest,seal.call_id)
    expected=(parse_original.generation_job_id,parse_original.generation_original_id,parse_original.generation_original_digest,
        parse_original.frozen_input_digest,parse_original.generation_call_id)
    if(locator!=expected or canonical_digest(seal)!=digest or row[3]not in ('acquired','terminal')
            or row[5]!=parse_original.typed_model_request_digest
            or row[3]=='terminal'and row[6]!=parse_original.terminal_receipt_digest
            or row[3]=='acquired'and row[6:]!=(None,None)):
        raise AuthorityUnavailable('Natural parse original differs from its actual terminal Graph generation')
    if parse_original.parent_original_id in reviews:raise AuthorityUnavailable('Natural no-review closure already has an actual review preparation')
    if any(review.generation_original_operation_id==parse_original.generation_original_id for row,review,digest in reviews.values()):
        raise AuthorityUnavailable('Natural no-review closure has an actual same-generation review attempt')
    _require_no_natural_stage_attempts_v3(reader,parse_original.parent_original_id,'review')
    return locator,tuple(headers)


class _ActualAuthorityNaturalPreReviewCensusV3:
    def __init__(self,issuer,maintenance,parse_original,registration,facts,context,operation,census_operation,core_basis,stamp):
        if issuer is not _ISSUER or set(facts)!=_PRE_REVIEW_FIELDS_V3:
            raise TypeError('actual complete Natural pre-review metadata issuer required')
        self.maintenance,self.parse_original,self.registration=maintenance,parse_original,registration
        self.facts,self.context,self.operation,self.census_operation=facts,context,operation,census_operation
        self.core_basis_v3,self.graph_stamp_v3=core_basis,stamp
        _PRE_REVIEW_CENSUSES_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.maintenance,self.parse_original,self.registration,canonical_digest(self.facts),self.context,self.operation,self.census_operation,self.core_basis_v3,self.graph_stamp_v3)
    def release_v3(self):
        if _PRE_REVIEW_CENSUSES_V3.pop(self,None)is not None:
            try:self.operation.release()
            finally:
                try:self.census_operation.release()
                finally:self.core_basis_v3.release_v3()


def prepare_actual_authority_natural_pre_review_census_v3(maintenance,parse_original,*,credential,subject):
    """Authenticate a real parse, then classify the actual selected Graph metadata."""
    from contextlib import closing
    from pathlib import Path
    import sqlite3
    from ..authority_service.natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from ..authority_service.d13_original_owner_v3 import require_actual_d13_generation_parse_original_v3,prepare_actual_d13_natural_pre_review_basis_v3
    from ..authority_service.d13_cache_use_contract_v2 import D13NaturalGenerationParseReceiptV3
    from .natural_roster_metadata_read_v3 import _stamp_v3
    from ..runtime_storage_v3 import bind_runtime_database_from_control_v3,begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3
    if type(maintenance)is not InstalledNaturalDispositionMaintenanceServiceV1 or type(parse_original)is not D13NaturalGenerationParseReceiptV3:
        raise AuthorityUnavailable('Natural pre-review census requires actual installed maintenance and typed parse original')
    maintenance._paired(credential,subject)
    service=maintenance.owner.core._d13_cache_use_controls_v2.get(maintenance.owner.namespace)
    if(service is None or service.namespace!=maintenance.owner.namespace_id or service.installation_id!=maintenance.owner.installation_id):
        raise AuthorityUnavailable('Natural pre-review census lacks its actual paired Core owner control')
    actual,registration=require_actual_d13_generation_parse_original_v3(service,parse_original)
    if actual!=parse_original or actual.parse_outcome not in ('no_reply_hold','output_rejected'):
        raise AuthorityUnavailable('Natural no-review closure requires actual terminal parser disposition')
    core_basis=prepare_actual_d13_natural_pre_review_basis_v3(service,actual)
    operation=census_operation=handle=None;foreign={};issued=False
    context=storage=member=None
    try:
        context,storage,member=maintenance.owner._storage()
        with closing(sqlite3.connect(Path(storage['graph_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON');handle=bind_runtime_database_from_control_v3(db,control=maintenance.owner.control,role='graph')
            if handle is None:raise AuthorityUnavailable('Natural pre-review census requires actual selected Graph storage')
            census_operation=begin_runtime_storage_operation_v3(db,'natural-pre-review-corpus:'+actual.operation_id,None)
            reader=_pre_review_metadata_reader_v3(maintenance,db,census_operation,actual,registration)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(census_operation,db):
                stamp=_stamp_v3(db,actual.namespace)
                locator,preparations=_pre_review_preparations_v3(reader,actual)
                corpus=_natural_graph_parent_census_v3(reader,include_roster_versions=True)
                rosters=_natural_roster_inventory_v3(reader,corpus)
                if(actual.first_operation_id in corpus['bundles']or actual.first_operation_id in corpus['admissions']
                        or any(row[2]==actual.first_effect_id for row in corpus['admissions'].values())
                        or any(bundle[0][3]==actual.first_effect_id for bundle in corpus['bundles'].values())):
                    raise AuthorityUnavailable('Natural no-review closure has a committed final/admission at its actual first identity')
                if any(parent==actual.parent_original_id for _,parent,_ in corpus['naturals']):
                    raise AuthorityUnavailable('Natural no-review closure already has an actual Graph final')
                corpus_digest=_natural_metadata_digest_v3(reader,{'events':tuple(sorted(corpus['events'].items())),
                    'bundles':tuple(sorted(corpus['bundles'].items())),'admissions':tuple(sorted(corpus['admissions'].items())),
                    'naturals':corpus['naturals'],'roster_versions':corpus['roster_versions'],'rosters':tuple(rosters),
                    'preparations':preparations,'headers':tuple(reader.headers)})
                if _stamp_v3(db,actual.namespace)!=stamp:raise AuthorityUnavailable('Natural pre-review metadata snapshot changed')
            db.rollback();handle.close();handle=None
        # Core signed foreign lineage is resolved only after the Graph transaction closes.
        by_token,expected_rosters=_prepare_foreign_natural_corpus_v3(maintenance,corpus,stamp,foreign)
        with closing(sqlite3.connect(Path(storage['graph_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON');handle=bind_runtime_database_from_control_v3(db,control=maintenance.owner.control,role='graph')
            if handle is None:raise AuthorityUnavailable('Natural pre-review proof lost its selected Graph storage')
            operation=begin_runtime_storage_operation_v3(db,'natural-pre-review-census:'+actual.operation_id,None)
            if operation.selection_digest!=census_operation.selection_digest:raise AuthorityUnavailable('Natural pre-review phases changed selected storage')
            reader=_pre_review_metadata_reader_v3(maintenance,db,operation,actual,registration)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(operation,db):
                if _stamp_v3(db,actual.namespace)!=stamp:raise AuthorityUnavailable('Natural pre-review Graph changed before final classification')
                classified=_verify_foreign_natural_corpus_v3(reader,corpus,foreign,by_token,expected_rosters,rosters,
                    excluded_generation_original_id=actual.generation_original_id)
                snapshot=_natural_metadata_digest_v3(reader,{'schema':'sylanne3.d13.actual-pre-review-graph-snapshot.v3',
                    'namespace':actual.namespace,'selection_digest':operation.selection_digest,'stamp':stamp,
                    'parse_digest':actual.parse_digest,'registration_digest':registration.registration_digest,
                    'complete_namespace_metadata_digest':corpus_digest,'headers':tuple(reader.headers)})
                facts={'roster_head':None,'generation_locator':locator,'review_preparation':None,'review_acquisition':None,
                    'graph_final_operation_ids':(),'graph_admissions':(),'graph_snapshot_digest':snapshot,
                    'graph_census_digest':_natural_metadata_digest_v3(reader,{'schema':'sylanne3.d13.actual-pre-review-graph-census.v3',
                        'parse_digest':actual.parse_digest,'snapshot_digest':snapshot,'generation_locator':locator,
                        'classified_final_lineages':tuple(classified),'classified_roster_versions':tuple(expected_rosters),
                        'review_preparation':None,'review_acquisition':None,'graph_final_operation_ids':(),'graph_admissions':()})}
            db.rollback();handle.close();handle=None
        maintenance.owner.control.verify_member_v1(member,prepared=False);context.require_current('business')
        proof=_ActualAuthorityNaturalPreReviewCensusV3(_ISSUER,maintenance,actual,registration,facts,context,operation,census_operation,core_basis,stamp)
        issued=True;return proof
    finally:
        if handle is not None:handle.close()
        for value in foreign.values():value.release_v3()
        if not issued:
            try:
                if operation is not None:operation.release()
            finally:
                try:
                    if census_operation is not None:census_operation.release()
                finally:core_basis.release_v3()


def require_actual_authority_natural_pre_review_census_v3(proof,maintenance,parse_original):
    """Pure private metadata proof; never opens Graph/Core SQL in the caller tx."""
    if(type(proof)is not _ActualAuthorityNaturalPreReviewCensusV3 or _PRE_REVIEW_CENSUSES_V3.get(proof)!=proof._identity_v3()
            or proof.maintenance is not maintenance or proof.parse_original!=parse_original
            or proof.operation.closed or proof.census_operation.closed or set(proof.facts)!=_PRE_REVIEW_FIELDS_V3):
        raise AuthorityUnavailable('Natural no-review closure needs its actual independently prepared metadata census')
    proof.context.require_current('business')
    return dict(proof.facts),proof.context



def _require_actual_review_writer_identity_v3(proof,*,registering=False):
    state=_REVIEW_WRITERS_V3.get(proof)
    if(state is None or state!=(proof.reader,proof.work,proof.operation,proof.review_writer_scope,
            state[4],state[5],proof.seal_column,canonical_digest(proof.material))
            or proof.review_writer_scope.permit is not proof.permit):
        raise AuthorityUnavailable('Natural review writer lost its actual Source Work/attempt/permit identity')
    if registering:
        if proof.release_requested or proof.operation.closed:
            raise AuthorityUnavailable('ended Natural review writer cannot register another obligation')
        state[4]._actual()
    return state


def prepare_actual_graph_natural_review_writer_v3(graph,prepared_full_read,*,scope,parent_original_id):
    """Issue only from the real retained FULL result and an actual new WRITE permit."""
    from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
    if not _graph_use_enabled_v2(graph):return None
    from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3,NATURAL_MODEL_FULL_READ_V3
    from .dispatch_initial_source_read_v3 import HostNaturalSavedOriginalReadV3
    from .natural_producer_qualification_v1 import require_prepared_host_natural_producers_v3
    from ..authority_service.v2_contract import FencePermitV2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if type(prepared_full_read)is not PreparedCurrentGraphFullReadV3:
        raise AuthorityUnavailable('Natural review WRITE requires its actual current Source FULL Work; no synchronous DTO substitute')
    full=prepared_full_read;full._actual();reader=full.work.state;store=graph._GraphCoordinator__store;db=store._db
    if(full.graph is not graph or full.contract!=NATURAL_MODEL_FULL_READ_V3 or full.prepared_producer_members is None
            or full.prefinal is None or reader.source_locator.c02_operation_id!=parent_original_id
            or scope.namespace!=full.namespace or scope.operation!='write'or type(scope.permit)is not FencePermitV2
            or scope.permit.operation!='write'or scope.operation_id!=scope.permit.operation_id
            or scope.authority_namespace!=full.scope.authority_namespace or scope.generation!=full.scope.generation
            or scope.pinned_anchor!=full.scope.pinned_anchor or scope.graph_revision!=full.graph_stamp[0].graph_revision
            or scope.graph_epoch!=full.graph_stamp[1]or db.in_transaction):
        raise AuthorityUnavailable('Natural review writer changed actual Source selection/WRITE attempt/anchor')
    port=graph._GraphCoordinator__d13_cache_use_control_v2
    if graph._GraphCoordinator__content_fence_v2.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Natural review writer requires its actual current same-WRITE Core permit')
    with store._lock,runtime_storage_quantum_v3(db)as meter:
        db.execute('BEGIN')
        try:
            full.require_current(graph,db,full.namespace,required_families=frozenset())
            require_prepared_host_natural_producers_v3(full.prepared_producer_members,reader=reader,scope=full.scope)
            producer=full.prepared_producer_members.c04_decoder_owner
            if (producer is None or producer.reader is not reader
                    or producer.prepared is not full.prepared_producer_members or not producer.complete):
                raise AuthorityUnavailable('Natural review writer lost its actual retained producer original')
            task=producer.saved_reader
            if type(task)is not HostNaturalSavedOriginalReadV3 or task.parent_original_id!=parent_original_id:
                raise AuthorityUnavailable('Natural review writer lacks its actual saved-generation Source producer')
            _require_sources_v3(task,meter)
            saved=task.require_v3(reader);column=task.natural_json['seal_json'];raw=column.require_v3(reader)
            if(saved is None or saved!=full.prepared_producer_members.saved or saved.stage!='generation'
                    or saved.parent_original_id!=parent_original_id or saved.state!='terminal'
                    or canonical_digest(saved.seal)!=column.sha256 or raw['c02_operation_id']!=parent_original_id):
                raise AuthorityUnavailable('Natural review writer generation differs from actual complete Source/seal EOF')
            material=dict(parent_original_id=parent_original_id,generation_job_id=saved.seal.job_id,
                generation_original_id=saved.seal.original_operation_id,generation_call_id=saved.seal.call_id,
                generation_frozen_input_digest=saved.seal.frozen_input_digest,review_job_id=None,review_original_id=None,
                retention_instance_ref='d13-natural-review-writer-retention-v3:'+canonical_digest((full.namespace,
                    full.operation.operation_id,scope.operation_id,scope.permit.token,full.selection_digest,parent_original_id,column.sha256)),
                selection_digest=full.selection_digest)
        finally:db.rollback()
    entry=(parent_original_id,'review_writer',scope.permit.operation_id,scope.permit.token)
    entries=_BY_WORK.setdefault(full.work,{})
    proof=entries.get(entry)
    if proof is not None:
        _require_actual_review_writer_identity_v3(proof,registering=True)
        if proof.material!=material or proof.review_writer_scope is not scope:raise AuthorityUnavailable('Natural review writer attempt replay changed actual identity')
        return proof
    proof=D13GraphNaturalOriginalAdmissionProofV3(_ISSUER,reader,full.work,port,material,column,review_writer_scope=scope)
    _REVIEW_WRITERS_V3[proof]=(reader,full.work,full.operation,scope,full,task,column,canonical_digest(material))
    entries[entry]=proof
    return proof


def resolve_actual_graph_natural_review_writer_v3(proof):
    _require_actual_review_writer_identity_v3(proof,registering=True)
    if proof.reader.db.in_transaction:raise AuthorityUnavailable('Natural review writer Core acknowledgement must precede Graph SQL')
    if proof.registration is None:
        values=dict(namespace=proof.reader.namespace,authority_namespace=proof.permit.namespace,permit=proof.permit,natural_admission=proof)
        if proof.attempted:registration=proof.port.inspect_natural_original_for_fence_v3(**values)
        else:
            proof.attempted=True;registration=proof.port.acquire_natural_original_for_fence_v3(**values)
        if registration is None:raise AuthorityUnavailable('Natural review writer acknowledgement is unknown; retain its exact obligation')
        proof.registration=registration
    return proof


def require_actual_graph_natural_review_writer_v3(proof,graph,scope,parent_original_id):
    state=_require_actual_review_writer_identity_v3(proof,registering=True);full,task=state[4:6]
    if(proof.work.coordinator is not graph or proof.review_writer_scope is not scope
            or proof.material['parent_original_id']!=parent_original_id or proof.registration is None):
        raise AuthorityUnavailable('Natural review Graph write lacks its actual acknowledged same-attempt writer')
    full.require_current(graph,proof.reader.db,proof.reader.namespace,required_families=frozenset())
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(proof.reader.db)as meter:_require_sources_v3(task,meter)
    return proof


def record_actual_graph_natural_review_writer_outcome_v3(proof,graph,scope,parent_original_id):
    """Derive completed SQL outcome from the real attempt and preparation metadata."""
    _require_actual_review_writer_identity_v3(proof)
    db=graph._GraphCoordinator__store._db
    if(proof.work.coordinator is not graph or proof.review_writer_scope is not scope
            or proof.material['parent_original_id']!=parent_original_id or db.in_transaction or proof.operation.closed):
        raise AuthorityUnavailable('Natural review writer outcome requires its actual retained post-transaction attempt')
    from .natural_reply_job_v2 import natural_job_ids_v2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    ns=proof.reader.namespace;ids=natural_job_ids_v2(ns,parent_original_id,'review')
    with graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(db)as meter:
        installed=_runtime_bounded_fixed_row_v3(db,meter,'sqlite_master',('name',),
            "type='table' AND name=?",('graph_natural_review_attempts_v2',))
        attempt=None if installed is None else _runtime_bounded_fixed_row_v3(db,meter,'graph_natural_review_attempts_v2',('attempt_id','state'),
            'bot=? AND persona=? AND parent_original_id=?',(*ns.as_tuple,parent_original_id))
        saved=_runtime_bounded_fixed_row_v3(db,meter,'graph_natural_review_preparations_v2',('job_id','original_operation_id'),
            'bot=? AND persona=? AND parent_original_id=?',(*ns.as_tuple,parent_original_id))
    if attempt==(scope.operation_id,'committed')and saved==ids[:2]:outcome='committed'
    elif saved is None and(attempt is None or attempt==(scope.operation_id,'closed')):outcome='rolled_back'
    else:raise AuthorityUnavailable('Natural review writer SQL outcome is unknown; retain its actual obligation')
    prior=_REVIEW_WRITER_OUTCOMES_V3.get(proof)
    if prior is not None and prior!=outcome:raise AuthorityUnavailable('Natural review writer cannot replace its actual terminal SQL outcome')
    _REVIEW_WRITER_OUTCOMES_V3[proof]=outcome
    return outcome


def _natural_roster_inventory_v3(reader,corpus):
    from ..domains.d09.natural_disposition_v1 import TYPE
    rosters=[];cursor=None
    while True:
        where,args=('bot=? AND persona=? AND type_name=? ORDER BY token',(*reader.namespace.as_tuple,TYPE))if cursor is None else(
            'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',(*reader.namespace.as_tuple,TYPE,cursor))
        row=reader.fixed_v3('graph_atoms',('token','revision','valid','value_cell_id'),where,args)
        if row is None:break
        cursor=row[0];rosters.append(row)
    # Orphaned/imported roster history cannot disappear merely
    # because it is absent from the Graph event write inventory.
    event_rosters=set(corpus['roster_versions']);history_cursor=None
    while True:
        where,args=('event_bot=? AND event_persona=? ORDER BY token,revision',reader.namespace.as_tuple)if history_cursor is None else(
            'event_bot=? AND event_persona=? AND (token>? OR (token=? AND revision>?)) ORDER BY token,revision',
            (*reader.namespace.as_tuple,history_cursor[0],history_cursor[0],history_cursor[1]))
        historical=reader.fixed_v3('graph_history',('token','revision','event_session','event_id'),where,args)
        if historical is None:break
        history_cursor=historical[:2]
        from ..graph_types import AtomKey
        key=AtomKey.from_token(historical[0])
        if key.type_name==TYPE and historical not in event_rosters:
            raise AuthorityUnavailable('Natural pre-review census has an orphaned unclassified roster history')
    return tuple(rosters)


def _prepare_foreign_natural_corpus_v3(maintenance,corpus,stamp,foreign):
    from .natural_roster_metadata_read_v3 import prepare_authority_natural_roster_metadata_v3
    from ..authority_service.natural_disposition_maintenance_v1 import natural_disposition_original_ref_v1
    from ..domains.d09.natural_disposition_v1 import natural_disposition_from_wire_v1,natural_disposition_key_v1
    for _,parent,_ in corpus['naturals']:
        if parent not in foreign:
            foreign[parent]=prepare_authority_natural_roster_metadata_v3(maintenance,parent_original_id=parent)
            _require_actual_authority_parent_capsule_v3(maintenance,foreign[parent].capsule)
            if foreign[parent].stamp!=stamp:raise AuthorityUnavailable('Natural foreign metadata changed the selected Graph snapshot')
    by_token={proof.head[0].token:proof for proof in foreign.values()if proof.head is not None}
    expected_rosters={}
    for token,revision,session,event_id in corpus['roster_versions']:
        proof=by_token.get(token)
        if proof is None:raise AuthorityUnavailable('Natural pre-review census has an unclassified roster history')
        parent=proof.parent_original_id;kind='roster_prepared'if revision==1 else'maintenance_prepared'
        ref=natural_disposition_original_ref_v1(maintenance.owner.namespace,maintenance.owner.installation_id,parent,kind,event_id)
        prepared=maintenance.originals.read(ref)
        committed=maintenance.originals.read(natural_disposition_original_ref_v1(maintenance.owner.namespace,
            maintenance.owner.installation_id,parent,'roster_committed'if revision==1 else'maintenance_committed',event_id))
        if(prepared is None or committed is None or committed.payload['prepared_original_ref']!=prepared.original_ref
                or committed.payload['permit']!=prepared.payload['permit']):
            raise AuthorityUnavailable('Natural roster history lacks its actual signed Core prepared/committed producer')
        value=natural_disposition_from_wire_v1(prepared.payload['expected_next_value'])
        if natural_disposition_key_v1(value).token!=token or value.revision!=revision or value.parent_original_id!=parent:
            raise AuthorityUnavailable('Natural roster history differs from its actual foreign Core lineage')
        expected_rosters[(token,revision,session,event_id)]=(value,prepared.operation_id)
    return by_token,expected_rosters


def _verify_foreign_natural_corpus_v3(reader,corpus,foreign,by_token,expected_rosters,rosters,*,excluded_generation_original_id=None):
    db=reader.db
    from ..domains.d09.natural_disposition_v1 import natural_disposition_key_v1
    classified=[]
    for final_operation,parent,digest in corpus['naturals']:
        selected=foreign[parent]
        if final_operation not in {child[1]for child in selected.capsule.child_identities}:
            raise AuthorityUnavailable('Natural foreign final is outside its actual complete Core child manifest')
        value=selected.read_child_locator_v3(db,final_operation)
        if value is None or _natural_metadata_digest_v3(reader,value)!=digest:
            raise AuthorityUnavailable('Natural foreign final differs from its actual selected metadata locator')
        if excluded_generation_original_id is not None and selected.capsule.generation_original_id==excluded_generation_original_id:
            raise AuthorityUnavailable('Natural no-review closure has an actual same-generation final lineage')
        classified.append((final_operation,selected.capsule.input_digest,digest))
    for token,revision,valid,cell_id in rosters:
        selected=by_token.get(token)
        if selected is None or selected.head is None or (selected.head[1],valid)!=(revision,1):
            raise AuthorityUnavailable('Natural pre-review census has an unclassified current roster')
        selected.require_current_v3(db,reader.namespace,selected.parent_original_id)
    for identity,(value,producer)in expected_rosters.items():
        token,revision,session,event_id=identity
        row=reader.fixed_v3('graph_history',('event_bot','event_persona','event_session','event_id','valid','value_cell_id'),
            'token=? AND revision=?',(token,revision))
        if row is None or row[:5]!=(*reader.namespace.as_tuple,session,event_id,1)or row[5]is None:
            raise AuthorityUnavailable('Natural classified roster has no actual immutable Graph history')
        reader.cell_v3(row[5],natural_disposition_key_v1(value),value.to_wire(),producer)
    return tuple(classified)


_UNUSED_COUNTER_CENSUSES_V3=WeakKeyDictionary()
_UNUSED_COUNTER_FIELDS_V3=frozenset({'generation_preparation','generation_acquisition','generation_call','generation_adoption',
    'review_preparation','review_acquisition','roster_head','graph_final_operation_ids','graph_admissions',
    'cpu_prepared','cpu_job','graph_snapshot_digest','graph_census_digest'})


def _require_no_natural_stage_attempts_v3(reader,parent,stage):
    from .natural_reply_job_v2 import natural_job_ids_v2
    if stage not in ('generation','review'):raise AuthorityUnavailable('unregistered Natural terminal metadata stage')
    ns=reader.namespace;ids=natural_job_ids_v2(ns,parent,stage);prefix='graph_natural_'+stage
    key_column='original_operation_id'if stage=='generation'else'parent_original_id';key_value=ids[1]if stage=='generation'else parent
    recipes=[(prefix+'_attempts_v2',(key_column,'input_digest','attempt_id','graph_revision','graph_epoch','state'),key_column,key_value),
        (prefix+'_acquires_v2',('acquire_operation_id','request_digest','attempt_id','graph_revision','graph_epoch','state'),'acquire_operation_id',ids[2]),
        (prefix+'_terminals_v2',('original_operation_id','request_digest','attempt_id','graph_revision','graph_epoch','terminal_receipt_digest','output_digest','state'),'original_operation_id',ids[1]),
        (prefix+'_output_reads_v2',('original_operation_id','last_attempt'),'original_operation_id',ids[1])]
    if stage=='generation':recipes.append((prefix+'_scopes_v2',('parent_original_id','original_seal_digest'),'parent_original_id',parent))
    else:recipes.extend((('graph_natural_review_content_reads_v2',('parent_original_id','last_attempt'),'parent_original_id',parent),
        ('graph_natural_paid_review_reads_v2',('original_operation_id','last_attempt'),'original_operation_id',ids[1])))
    for table,columns,key_column,value in recipes:
        exists=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",(table,))
        if exists is not None and reader.fixed_v3(table,columns,'bot=? AND persona=? AND '+key_column+'=?',(*ns.as_tuple,value))is not None:
            raise AuthorityUnavailable('Natural terminal census has an actual '+stage+' attempt/acquisition/terminal read')
    acquisition=reader.fixed_v3('graph_bundle_operations',('operation_id','digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,ids[2]))
    jobs_present=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",('runtime_jobs',))
    job=None if jobs_present is None else reader.fixed_v3('runtime_jobs',('job_id','operation_id','phase','work_kind'),
        'bot_id=? AND persona_id=? AND (job_id=? OR operation_id=? OR operation_id=?)',(*ns.as_tuple,ids[0],ids[1],ids[2]))
    if acquisition is not None or job is not None:raise AuthorityUnavailable('Natural terminal census has an actual '+stage+' acquisition/job')


def _counter_metadata_reader_v3(maintenance,db,operation,birth,registration):
    from .natural_roster_metadata_read_v3 import _RosterMetadataReadV3
    from ..authority_service.d13_cache_use_contract_v2 import D13CounterFrameBirthReceiptV3
    class CounterMetadataReadV3(_RosterMetadataReadV3):
        def __init__(self):
            if type(birth)is not D13CounterFrameBirthReceiptV3:raise AuthorityUnavailable('Counter metadata requires its actual birth original')
            self.service,self.db,self.operation=maintenance,db,operation
            self.birth,self.registration=birth,registration;self.namespace=birth.namespace;self.headers=[]
    return CounterMetadataReadV3()


def _unused_counter_cpu_metadata_v3(reader,birth,corpus):
    from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
    from ..authority_service.internal_work_contract import InternalWorkBindingV1
    from ..graph_coordinator import namespace_ref
    from .d13_counter_cpu_quote_policy_v1 import D13_COUNTER_CPU_WORK_KIND
    prepared=None;ns=reader.namespace
    installed=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",('graph_c04_internal_work_prepared_v1',))
    header=None if installed is None else reader.fixed_v3('graph_c04_internal_work_prepared_v1',('binding_digest','prepared_digest'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,birth.counter_operation_id))
    if header is not None:
        column=_natural_metadata_column_v3(reader,'graph_c04_internal_work_prepared_v1','prepared_json',('bot','persona','operation_id'),(*ns.as_tuple,birth.counter_operation_id))
        with reader.quantum_v3()as meter:
            meter.require_available(column.byte_count*8+4096);raw=column.require_v3(reader)
        value=dict(raw);binding=InternalWorkBindingV1(**value.pop('binding'));value['read_versions']=tuple(tuple(v)for v in value['read_versions'])
        prepared=C04InternalWorkPreparedV1(binding=binding,**value)
        if(canonical_digest(raw)!=header[1]or binding.binding_digest!=header[0]or prepared.prepared_digest!=header[1]
                or (binding.namespace,binding.operation_id,binding.activity_id,binding.execution_id,binding.input_digest,binding.algorithm_ref,
                    binding.algorithm_build_digest,binding.parent_budget_lease_ref,binding.activation_generation,prepared.owner_grant_digest)!=
                (namespace_ref(ns),birth.counter_operation_id,birth.planned_activity_id,birth.planned_execution_id,birth.input_digest,
                    birth.algorithm_ref,birth.algorithm_build_digest,birth.parent_budget_lease_ref,birth.activation_generation,birth.owner_grant_digest)):
            raise AuthorityUnavailable('Counter CPU metadata differs from its actual immutable birth/prepared binding')
    fields=('job_id','operation_id','activity_id','effect_id','work_kind','phase','fence','cancel_epoch','result_ref')
    jobs_present=reader.fixed_v3('sqlite_master',('name',),"type='table' AND name=?",('runtime_jobs',))
    row=None if jobs_present is None else reader.fixed_v3('runtime_jobs',fields,'bot_id=? AND persona_id=? AND job_id=?',(*ns.as_tuple,birth.planned_job_id))
    job=None if row is None else dict(zip(fields,row))
    if(prepared is None)!=(job is None):raise AuthorityUnavailable('Counter CPU preparation/job metadata is incomplete')
    if job is not None and (job['job_id'],job['operation_id'],job['activity_id'],job['effect_id'],job['work_kind'])!=(
            birth.planned_job_id,birth.counter_operation_id,birth.planned_activity_id,birth.planned_execution_id,D13_COUNTER_CPU_WORK_KIND):
        raise AuthorityUnavailable('Counter CPU job metadata differs from its actual planned identities')
    if prepared is None:
        from ..graph_types import AtomKey
        if any(AtomKey.from_token(v[0]).name==birth.planned_job_id for v in corpus['runtime_jobs']):
            raise AuthorityUnavailable('Counter CPU has orphaned historical preparation/adoption metadata')
    return prepared,job


class _ActualAuthorityUnusedCounterCensusV3:
    def __init__(self,issuer,maintenance,birth,registration,facts,context,operation,census_operation,basis,stamp):
        if issuer is not _ISSUER or set(facts)!=_UNUSED_COUNTER_FIELDS_V3:raise TypeError('actual complete unused Counter metadata issuer required')
        self.maintenance,self.birth,self.registration,self.facts=maintenance,birth,registration,facts
        self.context,self.operation,self.census_operation,self.core_basis_v3,self.graph_stamp_v3=context,operation,census_operation,basis,stamp
        _UNUSED_COUNTER_CENSUSES_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return(self.maintenance,self.birth,self.registration,canonical_digest(self.facts),self.context,self.operation,self.census_operation,self.core_basis_v3,self.graph_stamp_v3)
    def release_v3(self):
        if _UNUSED_COUNTER_CENSUSES_V3.pop(self,None)is not None:
            try:self.operation.release()
            finally:
                try:self.census_operation.release()
                finally:self.core_basis_v3.release_v3()


def prepare_actual_authority_unused_counter_census_v3(maintenance,birth,*,credential,subject):
    from contextlib import closing
    from pathlib import Path
    import sqlite3
    from ..authority_service.natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from ..authority_service.d13_cache_use_contract_v2 import D13CounterFrameBirthReceiptV3
    from ..authority_service.d13_original_owner_v3 import require_actual_d13_counter_birth_original_v3,prepare_actual_d13_unused_counter_basis_v3
    from .natural_roster_metadata_read_v3 import _stamp_v3
    from .natural_reply_job_v2 import natural_job_ids_v2
    from ..graph_types import AtomKey
    from ..runtime_storage_v3 import bind_runtime_database_from_control_v3,begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3
    if type(maintenance)is not InstalledNaturalDispositionMaintenanceServiceV1 or type(birth)is not D13CounterFrameBirthReceiptV3:
        raise AuthorityUnavailable('unused Counter census requires actual installed maintenance and typed birth original')
    maintenance._paired(credential,subject)
    service=maintenance.owner.core._d13_cache_use_controls_v2.get(maintenance.owner.namespace)
    if(service is None or service.namespace!=maintenance.owner.namespace_id or service.installation_id!=maintenance.owner.installation_id):
        raise AuthorityUnavailable('unused Counter census lacks its actual paired Core owner control')
    actual,registration=require_actual_d13_counter_birth_original_v3(service,birth)
    ids=natural_job_ids_v2(actual.namespace,actual.parent_original_id,'generation')
    if actual.generation_call_id!=ids[3]:raise AuthorityUnavailable('Counter birth generation call has no registered actual Natural identity')
    basis=prepare_actual_d13_unused_counter_basis_v3(service,actual)
    operation=census_operation=handle=None;foreign={};issued=False
    try:
        context,storage,member=maintenance.owner._storage()
        with closing(sqlite3.connect(Path(storage['graph_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON');handle=bind_runtime_database_from_control_v3(db,control=maintenance.owner.control,role='graph')
            if handle is None:raise AuthorityUnavailable('unused Counter census requires actual selected Graph storage')
            census_operation=begin_runtime_storage_operation_v3(db,'unused-counter-corpus:'+actual.operation_id,None)
            reader=_counter_metadata_reader_v3(maintenance,db,census_operation,actual,registration);db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(census_operation,db):
                stamp=_stamp_v3(db,actual.namespace);generations,reviews,preparations=_natural_preparation_corpus_v3(reader)
                if actual.parent_original_id in generations or actual.parent_original_id in reviews:
                    raise AuthorityUnavailable('Counter draft already has an actual generation/review preparation')
                if any(seal.call_id==actual.generation_call_id for row,seal,digest in generations.values()):
                    raise AuthorityUnavailable('Counter draft has an ambiguous actual generation call lineage')
                _require_no_natural_stage_attempts_v3(reader,actual.parent_original_id,'generation')
                _require_no_natural_stage_attempts_v3(reader,actual.parent_original_id,'review')
                corpus=_natural_graph_parent_census_v3(reader,include_roster_versions=True,include_runtime_jobs=True)
                if any(AtomKey.from_token(v[0]).name==ids[0]for v in corpus['runtime_jobs']):
                    raise AuthorityUnavailable('Counter draft has an actual historical generation adoption')
                rosters=_natural_roster_inventory_v3(reader,corpus)
                if(any(parent==actual.parent_original_id for _,parent,_ in corpus['naturals'])
                        or actual.first_operation_id in corpus['bundles']or actual.first_operation_id in corpus['admissions']
                        or any(row[2]==actual.first_effect_id for row in corpus['admissions'].values())
                        or any(bundle[0][3]==actual.first_effect_id for bundle in corpus['bundles'].values())):
                    raise AuthorityUnavailable('Counter draft already has an actual final/admission/effect')
                prepared,job=_unused_counter_cpu_metadata_v3(reader,actual,corpus)
                corpus_digest=_natural_metadata_digest_v3(reader,{'events':tuple(sorted(corpus['events'].items())),
                    'bundles':tuple(sorted(corpus['bundles'].items())),'admissions':tuple(sorted(corpus['admissions'].items())),
                    'naturals':corpus['naturals'],'roster_versions':corpus['roster_versions'],'runtime_jobs':corpus['runtime_jobs'],
                    'rosters':rosters,'preparations':preparations,'cpu_prepared_digest':None if prepared is None else prepared.prepared_digest,
                    'cpu_job':job,'headers':tuple(reader.headers)})
                if _stamp_v3(db,actual.namespace)!=stamp:raise AuthorityUnavailable('unused Counter metadata snapshot changed')
            db.rollback();handle.close();handle=None
        by_token,expected_rosters=_prepare_foreign_natural_corpus_v3(maintenance,corpus,stamp,foreign)
        with closing(sqlite3.connect(Path(storage['graph_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON');handle=bind_runtime_database_from_control_v3(db,control=maintenance.owner.control,role='graph')
            if handle is None:raise AuthorityUnavailable('unused Counter proof lost actual selected Graph storage')
            operation=begin_runtime_storage_operation_v3(db,'unused-counter-census:'+actual.operation_id,None)
            if operation.selection_digest!=census_operation.selection_digest:raise AuthorityUnavailable('unused Counter phases changed selected storage')
            reader=_counter_metadata_reader_v3(maintenance,db,operation,actual,registration);db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(operation,db):
                if _stamp_v3(db,actual.namespace)!=stamp:raise AuthorityUnavailable('unused Counter Graph changed before final classification')
                classified=_verify_foreign_natural_corpus_v3(reader,corpus,foreign,by_token,expected_rosters,rosters,
                    excluded_generation_original_id=ids[1])
                snapshot=_natural_metadata_digest_v3(reader,{'schema':'sylanne3.d13.actual-unused-counter-graph-snapshot.v3',
                    'namespace':actual.namespace,'selection_digest':operation.selection_digest,'stamp':stamp,'birth_digest':actual.birth_digest,
                    'registration_digest':registration.registration_digest,'complete_namespace_metadata_digest':corpus_digest,'headers':tuple(reader.headers)})
                facts={'generation_preparation':None,'generation_acquisition':None,'generation_call':None,'generation_adoption':(),
                    'review_preparation':None,'review_acquisition':None,'roster_head':None,'graph_final_operation_ids':(),'graph_admissions':(),
                    'cpu_prepared':prepared,'cpu_job':job,'graph_snapshot_digest':snapshot,
                    'graph_census_digest':_natural_metadata_digest_v3(reader,{'schema':'sylanne3.d13.actual-unused-counter-graph-census.v3',
                        'birth_digest':actual.birth_digest,'snapshot_digest':snapshot,'classified_final_lineages':classified,
                        'classified_roster_versions':tuple(expected_rosters),'generation_job_id':ids[0],'generation_call_id':actual.generation_call_id,
                        'cpu_prepared_digest':None if prepared is None else prepared.prepared_digest,'cpu_job':job})}
            db.rollback();handle.close();handle=None
        maintenance.owner.control.verify_member_v1(member,prepared=False);context.require_current('business')
        proof=_ActualAuthorityUnusedCounterCensusV3(_ISSUER,maintenance,actual,registration,facts,context,operation,census_operation,basis,stamp)
        issued=True;return proof
    finally:
        if handle is not None:handle.close()
        for value in foreign.values():value.release_v3()
        if not issued:
            try:
                if operation is not None:operation.release()
            finally:
                try:
                    if census_operation is not None:census_operation.release()
                finally:basis.release_v3()


def require_actual_authority_unused_counter_census_v3(proof,maintenance,birth):
    if(type(proof)is not _ActualAuthorityUnusedCounterCensusV3 or _UNUSED_COUNTER_CENSUSES_V3.get(proof)!=proof._identity_v3()
            or proof.maintenance is not maintenance or proof.birth!=birth or proof.operation.closed or proof.census_operation.closed
            or set(proof.facts)!=_UNUSED_COUNTER_FIELDS_V3):
        raise AuthorityUnavailable('unused Counter closure requires its actual independently prepared metadata census')
    proof.context.require_current('business')
    return dict(proof.facts),proof.context


def _require_actual_generation_writer_identity_v3(proof,*,registering=False):
    state=_GENERATION_WRITERS_V3.get(proof)
    if(state is None or state!=(proof.reader,proof.work,proof.operation,proof.generation_writer_scope,
            state[4],proof.seal_column,state[6],canonical_digest(proof.material))
            or proof.generation_writer_scope.permit is not proof.permit):
        raise AuthorityUnavailable('Natural generation writer lost its actual Source Work/Counter/attempt identity')
    if registering:
        if proof.release_requested or proof.operation.closed:
            raise AuthorityUnavailable('ended Natural generation writer cannot register another obligation')
        state[4]._actual()
    return state


def _require_generation_writer_sources_v3(full):
    material=full.source_material
    if material is None or full.prepared_producer_members is None:
        raise AuthorityUnavailable('Natural generation writer lacks its complete actual Source/producer qualification')
    material.require_current(db=full.db,prepared_full_read=full,namespace=full.namespace,
        source_ref=material.source_ref,audiences=material.audiences)
    from .natural_producer_qualification_v1 import require_prepared_host_natural_producers_v3
    require_prepared_host_natural_producers_v3(full.prepared_producer_members,reader=full.work.state,scope=full.scope)
    return material


def _require_generation_writer_full_scope_v3(graph,full,scope,parent_original_id,bundle):
    """Closed READ-to-WRITE or same-WRITE producer paths, each with its real issuer."""
    from .current_graph_full_read_v3 import NATURAL_MODEL_FULL_READ_V3,NATURAL_ADMIN_PREPARE_FULL_V3
    from ..host.authority_profile import require_current_owner_metadata_installation_v3
    require_current_owner_metadata_installation_v3(graph,expected_bundle=bundle)
    if full.contract is NATURAL_MODEL_FULL_READ_V3:
        return
    if full.contract is not NATURAL_ADMIN_PREPARE_FULL_V3:
        raise AuthorityUnavailable('Natural generation writer has no registered actual Source recipe')
    reader=full.work.state;borrowed=reader.borrowed
    if (type(borrowed)is not tuple or len(borrowed)!=5 or full.scope is not scope
            or borrowed[0]is not graph._GraphCoordinator__bootstrap or borrowed[1]is not bundle
            or borrowed[2]is not scope or borrowed[3]!=parent_original_id
            or reader.source_locator is None or borrowed[4]!=reader.source_locator.source_ref
            or reader.producer_phase!='prepare'):
        raise AuthorityUnavailable('Natural generation borrowed Source crossed its actual Root/WRITE/C02')
    namespace=graph._require_natural_admin_full_read_scope_v3(borrowed[0],installed_bundle=bundle,
        scope=scope,parent_original_id=parent_original_id,source_ref=borrowed[4])
    if namespace!=full.namespace or graph._validate_natural_admin_full_read_scope_v3(borrowed)!=reader.fence:
        raise AuthorityUnavailable('Natural generation borrowed Source lost its actual current Root stamp')


def prepare_actual_graph_natural_generation_writer_v3(graph,prepared_full_read,*,scope,parent_original_id,counted,installed_bundle):
    """Register the first Graph writer from actual Source FULL and signed Counter birth lineage."""
    from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
    if not _graph_use_enabled_v2(graph):return None
    from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3
    from .d13_natural_counter_preflight_v7 import D13CountedNaturalPreflightV7
    from ..host.authority_profile import AdminInstallationBundle
    from ..authority_service.v2_contract import FencePermitV2
    from ..authority_service.d13_core_counter_contract_v1 import verify_signed_d13_core_wire_evidence_v1
    from .natural_reply_job_v2 import natural_job_ids_v2
    from .first_ingress_v2 import trusted_upper
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if(type(prepared_full_read)is not PreparedCurrentGraphFullReadV3 or type(counted)is not D13CountedNaturalPreflightV7
            or type(installed_bundle)is not AdminInstallationBundle):
        raise AuthorityUnavailable('Natural generation WRITE requires its actual current Source Work and independent Counter original')
    full=prepared_full_read;full._actual();reader=full.work.state;store=graph._GraphCoordinator__store;db=store._db
    frame=counted.frame;ids=natural_job_ids_v2(full.namespace,parent_original_id,'generation')
    _require_generation_writer_full_scope_v3(graph,full,scope,parent_original_id,installed_bundle)
    if(full.graph is not graph or full.prefinal is None
            or reader.source_locator.c02_operation_id!=parent_original_id or scope.namespace!=full.namespace
            or scope.operation!='write'or type(scope.permit)is not FencePermitV2 or scope.permit.operation!='write'
            or scope.operation_id!=scope.permit.operation_id or scope.authority_namespace!=full.scope.authority_namespace
            or scope.generation!=full.scope.generation or scope.pinned_anchor!=full.scope.pinned_anchor
            or scope.graph_revision!=full.graph_stamp[0].graph_revision or scope.graph_epoch!=full.graph_stamp[1]
            or installed_bundle.installation_policy.namespace!=full.namespace or db.in_transaction
            or(frame.namespace,frame.c02_operation_id,frame.generation_call_id,frame.authority_namespace,frame.activation_generation)!=
                (full.namespace,parent_original_id,ids[3],scope.authority_namespace,scope.generation)):
        raise AuthorityUnavailable('Natural generation writer changed actual Source selection/Counter lineage/WRITE attempt')
    port=graph._GraphCoordinator__d13_cache_use_control_v2
    content=graph._GraphCoordinator__content_fence_v2
    if content.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Natural generation writer requires its current same-WRITE Core permit')
    now=trusted_upper(content.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    verify_signed_d13_core_wire_evidence_v1(installed_bundle.d13_wire_policy,counted.envelope,
        selector=counted.selector,frame=frame,now_utc=now)
    with store._lock,runtime_storage_quantum_v3(db):
        db.execute('BEGIN')
        try:
            full.require_current(graph,db,full.namespace,required_families=frozenset())
            _require_generation_writer_sources_v3(full)
            material=dict(parent_original_id=parent_original_id,generation_job_id=ids[0],generation_original_id=ids[1],
                generation_call_id=ids[3],generation_frozen_input_digest=frame.raw_authority_digest,
                review_job_id=None,review_original_id=None,
                retention_instance_ref='d13-natural-generation-writer-retention-v3:'+canonical_digest((full.namespace,
                    full.operation.operation_id,scope.operation_id,scope.permit.token,full.selection_digest,parent_original_id,
                    frame.frame_intent_digest,counted.envelope.evidence_digest)),selection_digest=full.selection_digest)
        finally:db.rollback()
    entry=(parent_original_id,'generation_writer',scope.permit.operation_id,scope.permit.token)
    entries=_BY_WORK.setdefault(full.work,{})
    proof=entries.get(entry)
    if proof is not None:
        _require_actual_generation_writer_identity_v3(proof,registering=True)
        if proof.material!=material or proof.generation_writer_scope is not scope or proof.seal_column is not counted:
            raise AuthorityUnavailable('Natural generation writer replay changed its actual Counter/attempt')
        return proof
    proof=D13GraphNaturalOriginalAdmissionProofV3(_ISSUER,reader,full.work,port,material,counted,generation_writer_scope=scope)
    _GENERATION_WRITERS_V3[proof]=(reader,full.work,full.operation,scope,full,counted,installed_bundle,canonical_digest(material))
    entries[entry]=proof
    return proof


def resolve_actual_graph_natural_generation_writer_v3(proof):
    _require_actual_generation_writer_identity_v3(proof,registering=True)
    if proof.reader.db.in_transaction:raise AuthorityUnavailable('Natural generation writer Core ACK must precede Graph SQL')
    if proof.registration is None:
        values=dict(namespace=proof.reader.namespace,authority_namespace=proof.permit.namespace,permit=proof.permit,natural_admission=proof)
        if proof.attempted:registration=proof.port.inspect_natural_original_for_fence_v3(**values)
        else:
            proof.attempted=True;registration=proof.port.acquire_natural_original_for_fence_v3(**values)
        if registration is None:raise AuthorityUnavailable('Natural generation writer ACK is unknown; retain its exact obligation')
        proof.registration=registration
    return proof


def require_actual_graph_natural_generation_writer_v3(proof,graph,scope,parent_original_id):
    state=_require_actual_generation_writer_identity_v3(proof,registering=True);full=state[4]
    if(proof.work.coordinator is not graph or proof.generation_writer_scope is not scope
            or proof.material['parent_original_id']!=parent_original_id or proof.registration is None):
        raise AuthorityUnavailable('Natural generation write lacks its actual acknowledged same-attempt writer')
    full.require_current(graph,proof.reader.db,proof.reader.namespace,required_families=frozenset())
    _require_generation_writer_sources_v3(full)
    return proof


def record_actual_graph_natural_generation_writer_outcome_v3(proof,graph,scope,parent_original_id):
    """Keep the Counter writer until the actual Graph attempt outcome and final retention."""
    _require_actual_generation_writer_identity_v3(proof)
    db=graph._GraphCoordinator__store._db
    if(proof.work.coordinator is not graph or proof.generation_writer_scope is not scope
            or proof.material['parent_original_id']!=parent_original_id or db.in_transaction or proof.operation.closed):
        raise AuthorityUnavailable('Natural generation writer outcome requires its actual retained post-transaction attempt')
    from .natural_reply_job_v2 import natural_job_ids_v2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    ns=proof.reader.namespace;ids=natural_job_ids_v2(ns,parent_original_id,'generation')
    with graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(db)as meter:
        installed=_runtime_bounded_fixed_row_v3(db,meter,'sqlite_master',('name',),
            "type='table' AND name=?",('graph_natural_generation_attempts_v2',))
        attempt=None if installed is None else _runtime_bounded_fixed_row_v3(db,meter,'graph_natural_generation_attempts_v2',('attempt_id','state'),
            'bot=? AND persona=? AND original_operation_id=?',(*ns.as_tuple,ids[1]))
        saved=_runtime_bounded_fixed_row_v3(db,meter,'graph_natural_generation_preparations_v2',('job_id','original_operation_id'),
            'bot=? AND persona=? AND parent_original_id=?',(*ns.as_tuple,parent_original_id))
    if attempt==(scope.operation_id,'committed')and saved==ids[:2]:outcome='committed'
    elif saved is None and(attempt is None or attempt==(scope.operation_id,'closed')):outcome='rolled_back'
    else:raise AuthorityUnavailable('Natural generation writer SQL outcome is unknown; retain its actual obligation')
    prior=_GENERATION_WRITER_OUTCOMES_V3.get(proof)
    if prior is not None and prior!=outcome:raise AuthorityUnavailable('Natural generation writer cannot replace its actual SQL outcome')
    _GENERATION_WRITER_OUTCOMES_V3[proof]=outcome
    return outcome
