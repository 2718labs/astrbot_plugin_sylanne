"""Actual consumer pin ownership, separate from Graph transactions and DTO lifetime.

A pending or failed cleanup remains strongly owned until Core acknowledges the
original release. Neither a reader clearing its buffers nor permit expiry drops
that obligation. Private admissions are not serialized as read authority.
"""
from dataclasses import replace
from hashlib import sha256
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d13_cache_use_contract_v2 import selected_payloads_v2
from ..runtime_contracts import canonical_digest, canonical_serialize

_ADMISSIONS = WeakKeyDictionary()
_WORK_OWNERS = WeakKeyDictionary()
_GRAPH_OWNERS = WeakKeyDictionary()
_RETAINED = {}
_ISSUER = object()


class D13CacheUseAdmissionRequiredV2(Exception):
    """The same Work must leave Graph SQL before resolving this acquire."""
    def __init__(self, work):
        self.work = work
        super().__init__('actual D13 payload awaits durable same-permit use pin')


class _ConsumerAdmissionV2:
    def __init__(self, issuer, owner, selected, kind, owner_ref):
        if issuer is not _ISSUER:
            raise TypeError('actual consumer admission issuer required')
        self.owner, self.port, self.permit = owner, owner.port, owner.permit
        self.selected, self.kind, self.owner_ref = selected, kind, owner_ref
        self.binding = dict(consumer_owner_ref=owner_ref,
            consumer_operation_id=owner.operation_id, consumer_kind=kind,
            consumer_cohort_digest=self.port.use_policy.consumer_cohort_digest)
        _ADMISSIONS[self] = (owner, self.port, self.permit, selected, kind, owner_ref, dict(self.binding))


def require_d13_cache_use_consumer_admission_v2(admission, *, port, permit, selected_payloads, action):
    state = _ADMISSIONS.get(admission)
    if state is None:
        raise AuthorityUnavailable('D13 control requires actual private consumer ownership')
    owner, original_port, original_permit, selected, kind, owner_ref, binding = state
    if (port is not original_port or permit is not original_permit
            or admission.owner is not owner or admission.port is not port
            or admission.permit is not permit or admission.selected != selected
            or admission.kind != kind or admission.owner_ref != owner_ref or admission.binding != binding
            or action not in ('acquire', 'transfer', 'release', 'inspect')
            or not set(selected_payloads_v2(tuple(selected_payloads))) <= set(selected)):
        raise AuthorityUnavailable('D13 control admission changed its original consumer/payload/permit')
    port._actual()
    if action in ('acquire', 'transfer'):
        owner.require_live()
    elif _RETAINED.get(owner.owner_id) is not owner:
        raise AuthorityUnavailable('D13 cleanup lost the actual strongly retained original owner')
    return dict(binding)


class _AuthorityConsumerOwnerV2:
    def __init__(self, work):
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        from ..authority_service.d13_cache_use_control_v2 import installed_d13_cache_use_local_port_v2
        if type(work) is not AuthorityGraphReadWorkV3:
            raise AuthorityUnavailable('D13 Authority consumer requires the actual original Work')
        work._actual()
        service = work.controller.fences.core._d13_cache_use_controls_v2.get(work.permit.namespace)
        if (service is None or service.core is not work.controller.fences.core
                or service.fences is not work.controller.fences or service.namespace != work.namespace):
            raise AuthorityUnavailable('D13 reader has no exact installed namespace use service')
        self.work, self.permit, self.operation = work, work.permit, work.operation
        self.operation_id = work.permit.operation_id
        self.port = installed_d13_cache_use_local_port_v2(service=service,
            credential=work.credential, subject=work.subject)
        self.owner_id = 'd13-authority-consumer:' + canonical_digest((work.namespace, self.permit.token,
            self.operation_id, work.controller.kind))
        if self.owner_id in _RETAINED:
            raise AuthorityUnavailable('D13 original consumer ownership already retained')
        self.entries, self.pending = {}, None
        self.release_requested = False
        _RETAINED[self.owner_id] = self

    def require_live(self):
        self.work._actual()
        if (self.work.operation is not self.operation or self.work.permit is not self.permit
                or self.release_requested or _WORK_OWNERS.get(self.work) is not self
                or _RETAINED.get(self.owner_id) is not self):
            raise AuthorityUnavailable('D13 original consumer cannot acquire after ownership ended')
        return self


def _owner(work):
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        owner = _AuthorityConsumerOwnerV2(work)
        _WORK_OWNERS[work] = owner
    return owner.require_live()


def _logical_payload_identity(work, metadata, metadata_ref, meter):
    """The initial committed producer survives standby activation and cell remap."""
    from ..domains.d13.derived_block_metadata_v2 import derived_block_metadata_key_v2
    from ..runtime_storage_v3 import read_runtime_cell_origin_v3
    if (not work.db.in_transaction or metadata.namespace != work.namespace
            or derived_block_metadata_key_v2(metadata).token != metadata_ref.ref):
        raise AuthorityUnavailable('D13 pin selection requires the actual current metadata quantum')
    history = meter.read_fixed_row(work.db, 'graph_history',
        ('revision', 'valid', 'value_cell_id', 'event_bot', 'event_persona', 'event_session', 'event_id'),
        'token=? ORDER BY revision', (metadata_ref.ref,))
    if (history is None or history[:2] != (1, 1) or history[3:5] != work.namespace.as_tuple
            or history[5] != 'd13-derived-cache-v6' or not history[6].startswith('d13-paid-derived-complete:')):
        raise AuthorityUnavailable('D13 initial committed payload producer is unknown; use HOLD')
    header = meter.read_fixed_row(work.db, 'segmented_cells_v1',
        ('codec_id', 'erasure_owner_ref', 'producer_operation_id', 'total_bytes', 'segment_count',
            'payload_sha256', 'ordered_segment_root', 'origin_scope_digest'), 'cell_id=?', (history[2],))
    if header is None:
        raise AuthorityUnavailable('D13 initial logical metadata origin is absent')
    initial_bytes = canonical_serialize(replace(metadata, status='standby')).encode('utf-8')
    meter.charge_encode(len(initial_bytes))
    if header[3] != len(initial_bytes) or header[5] != sha256(initial_bytes).hexdigest():
        raise AuthorityUnavailable('D13 current metadata changed its initial logical payload identity')
    origin = read_runtime_cell_origin_v3(work.db, history[2], header=header, meter=meter)
    if origin is not None and (origin['operation_id'] != history[6] or header[2] != history[6]):
        raise AuthorityUnavailable('D13 initial producer has another verified runtime origin')
    event = meter.read_fixed_row(work.db, 'graph_events', ('digest', 'revisions', 'epoch_revision'),
        'bot=? AND persona=? AND session=? AND event_id=?', tuple(history[3:]))
    attempt = meter.read_fixed_row(work.db, 'graph_d13_worker_attempts_v2', ('request_digest', 'pre_graph_epoch'),
        'bot=? AND persona=? AND operation_id=?', (*work.namespace.as_tuple, history[6]))
    columns = work.db.execute('PRAGMA table_info(graph_d13_worker_attempts_v2)').fetchall()
    meter.charge_read(sum(len(column[1]) + 16 for column in columns))
    receipt_column = 'receipt_json_cell_id' if any(column[1] == 'receipt_json_cell_id' for column in columns) else 'receipt_json'
    committed = work.db.execute('SELECT ' + receipt_column + ' IS NOT NULL FROM graph_d13_worker_attempts_v2 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*work.namespace.as_tuple, history[6])).fetchone()
    meter.charge_read(8)
    if event is None or attempt is None or committed != (1,):
        raise AuthorityUnavailable('D13 initial payload origin has no committed producer receipt/epoch')
    from ..domains.d13.logical_payload_identity_v2 import initial_logical_payload_identity_v2
    return initial_logical_payload_identity_v2(metadata,metadata_ref=metadata_ref,
        initial_metadata=replace(metadata,status='standby'),initial_history=tuple(history),
        producer_attempt=tuple(attempt),event=tuple(event))


def _bundle_use_enabled_v2(bundle):
    from ..host.authority_profile import AdminInstallationBundle
    if type(bundle) is not AdminInstallationBundle:
        raise AuthorityUnavailable('D13 optional policy boundary requires its actual installed bundle')
    use, maintenance = bundle.d13_cache_use_control_v2, bundle.d13_derived_cache_maintenance_v2
    if use is None and maintenance is None:
        return False
    if use is None or maintenance is None:
        raise AuthorityUnavailable('D13 optional cache control policy pair is incomplete')
    if not use.enabled:
        return False
    from ..authority_service.d13_cache_use_contract_v2 import require_cache_policy_pair_v2
    require_cache_policy_pair_v2(use, maintenance)
    return True


def _authority_use_enabled_v2(work):
    from .installed_d13_natural_frame_v6 import require_authority_derived_blocks_reader_v6
    return _bundle_use_enabled_v2(require_authority_derived_blocks_reader_v6(work).bundle)


def _graph_use_enabled_v2(graph):
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise AuthorityUnavailable('D13 optional use boundary lost its actual installed assembly')
    if not _bundle_use_enabled_v2(assembly.admin_bundle):
        return False
    from .d13_consumer_manifest_v3 import require_actual_d13_host_consumer_ready_v3
    require_actual_d13_host_consumer_ready_v3(graph)
    return True


def prepare_authority_d13_cache_use_v2(work, *, metadata, metadata_ref, meter):
    """Graph-local selection only. The sentinel never performs a Core request."""
    if not _authority_use_enabled_v2(work):
        return ()
    owner = _owner(work)
    identity = _logical_payload_identity(work, metadata, metadata_ref, meter)
    key = identity[:3]
    entry = owner.entries.get(key)
    if entry is None:
        operation_id = 'd13-use-acquire:' + canonical_digest((owner.owner_id, key))
        admission = _ConsumerAdmissionV2(_ISSUER, owner, (identity,),
            'authority_source_receiver', owner.owner_id + ':' + canonical_digest(key))
        entry = dict(identity=identity, metadata=metadata, metadata_ref=metadata_ref,
            admission=admission, operation_id=operation_id, pins=None, attempted=False,
            release_operation_id='d13-use-release:' + canonical_digest((owner.owner_id, key)),
            registration=None, registration_attempted=False, original_proof=None, close_proof=None, close_receipt=None,
            successor_registration=None)
        owner.entries[key] = entry
    elif entry['identity'] != identity or entry['metadata'] != metadata or entry['metadata_ref'] != metadata_ref:
        raise AuthorityUnavailable('D13 same-Work selected metadata changed before Body')
    if entry['pins'] is None:
        if owner.pending is not None and owner.pending is not entry:
            raise AuthorityUnavailable('D13 original Work already has an unresolved payload acquire')
        owner.pending = entry
        raise D13CacheUseAdmissionRequiredV2(work)
    return entry['pins']


def resolve_authority_d13_cache_use_v2(work):
    """Run outside Graph SQL and retain the original acquire identity if unknown."""
    owner = _WORK_OWNERS.get(work)
    if owner is None or owner.pending is None:
        return False
    owner.require_live()
    if work.db.in_transaction or owner.port.service.core._db.in_transaction:
        raise AuthorityUnavailable('D13 acquire must precede a new Graph quantum')
    work._check_permission_v3()
    entry = owner.pending
    _register_source_receiver_v3(owner,entry)
    values = dict(namespace=work.namespace, authority_namespace=owner.permit.namespace,
        permit=owner.permit, operation_id=entry['operation_id'],
        selected_payloads=(entry['identity'],), consumer_admission=entry['admission'])
    if entry['attempted']:
        pins = owner.port.inspect_acquisition_v2(**values)
    else:
        entry['attempted'] = True
        pins = owner.port.acquire_for_fence_v2(**values)
    from ..authority_service.d13_cache_use_contract_v2 import D13CachePinReceiptV2
    from ..authority_service.d13_cache_use_control_v2 import _D13CachePinLeaseV2
    if (len(pins) != 1 or type(pins[0]) is not _D13CachePinLeaseV2
            or type(pins[0].receipt) is not D13CachePinReceiptV2 or pins[0].receipt.state != 'active'):
        raise AuthorityUnavailable('D13 original acquire has no confirmed active pin; Body remains HOLD')
    entry['pins'], owner.pending = pins, None
    return True


def require_authority_d13_payload_pin_v2(work, *, metadata, metadata_ref, meter):
    if not _authority_use_enabled_v2(work):
        return ()
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        raise AuthorityUnavailable('D13 Body has no original consumer pin admission')
    owner.require_live()
    matches = [entry for entry in owner.entries.values()
        if entry['metadata'] == metadata and entry['metadata_ref'] == metadata_ref]
    if len(matches) != 1 or not matches[0]['pins']:
        raise AuthorityUnavailable('D13 Body cannot precede its exact durable active pin acknowledgement')
    return matches[0]['pins']


def release_authority_d13_cache_use_v2(work):
    """Only call when the actual final retained content owner releases its value."""
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        return
    if not work.closed and work.db is not None and work.db.in_transaction:
        raise AuthorityUnavailable('D13 real consumer cleanup cannot share Graph SQL')
    owner.release_requested = True
    _release_owner(owner)


def _release_owner(owner):
    from ..authority_service.d13_cache_use_contract_v2 import D13OwnerCloseReceiptV3
    from ..authority_service.d13_original_owner_v3 import D13SourceReceiverAwaitingTerminalV3
    if not owner.operation.closed:
        raise AuthorityUnavailable('D13 Source receiver cleanup awaits its actual final retention close')
    pending = False
    for entry in owner.entries.values():
        if entry['close_receipt'] is not None:
            continue
        if entry['registration'] is None:
            if not entry['registration_attempted']:
                continue
            _register_source_receiver_v3(owner,entry,inspect_only=True)
        registration = entry['registration']
        proof = prepare_d13_source_receiver_closure_v3(owner,entry)
        try:
            closed = owner.port.close_original_owner_v3(registration,close_admission=proof)
        except D13SourceReceiverAwaitingTerminalV3:
            # Only Core's exact still-active original fence outcome is pending.
            # Preserve this receiver/pin/proof; finish_fence wakes same-op cleanup.
            pending = True
            continue
        if (type(closed) is not D13OwnerCloseReceiptV3 or closed.owner_ref != registration.owner_ref
                or closed.registration_digest != registration.registration_digest
                or closed.namespace != registration.namespace
                or closed.authority_namespace != registration.authority_namespace):
            raise AuthorityUnavailable('D13 final retention close lacks its exact durable original acknowledgement')
        entry['close_receipt'],entry['pins'] = closed,()
    if pending:
        return False
    for entry in owner.entries.values():
        _ADMISSIONS.pop(entry['admission'],None)
        if entry['original_proof'] is not None:
            _SOURCE_RECEIVER_ORIGINALS_V3.pop(entry['original_proof'],None)
        if entry['close_proof'] is not None:
            _SOURCE_RECEIVER_CLOSURES_V3.pop(entry['close_proof'],None)
        entry['original_proof'] = entry['close_proof'] = None
    owner.entries.clear()
    owner.pending = None
    _RETAINED.pop(owner.owner_id)
    if type(owner) is _AuthorityConsumerOwnerV2:
        _WORK_OWNERS.pop(owner.work,None)
    else:
        _GRAPH_OWNERS.pop(owner.reader,None)


def reconcile_d13_cache_use_cleanup_v2(*, service):
    """Retry only release-requested originals after the actual maintenance fence ends."""
    for owner in tuple(_RETAINED.values()):
        if type(owner) is _AuthorityConsumerOwnerV2 and owner.port.service is service and owner.release_requested:
            _release_owner(owner)


def require_d13_cache_use_coverage_installation_v2(coverage, *, policy, maintenance_policy):
    if type(coverage) is not _D13CacheUseCoverageInstallationV2:
        raise AuthorityUnavailable('D13 coverage needs actual Root census/drain and future consumer manifest')
    return coverage.require_current(policy=policy, maintenance_policy=maintenance_policy)


class _D13CacheUseCoverageInstallationV2:
    def __init__(self, issuer, *, qualification, control, gate, policy, maintenance_policy, manifest):
        if issuer is not _ISSUER:
            raise TypeError('actual D13 installed coverage producer required')
        self.qualification, self.control, self.gate = qualification, control, gate
        self.policy, self.maintenance_policy, self.manifest = policy, maintenance_policy, manifest
        self.original = None

    def require_current(self, *, policy, maintenance_policy):
        from ..authority_service.c09_storage_maintenance_v1 import VerifiedInstalledPeerRegistryActivationV3
        from ..authority_service.c09_writer_peer_originals_v3 import (VerifiedPeerRetirementCoverageV3,
            VerifiedPreparedPeerRetirementCoverageV3)
        if policy is not self.policy or maintenance_policy is not self.maintenance_policy:
            raise AuthorityUnavailable('D13 complete coverage crossed its exact installed signed policy pair')
        with self.control._resource_sql_quantum_v3() as meter:
            # This manifest must be issued by the actual complete consumer wiring,
            # including Authority/Counter and retained Host frame receivers.
            from .d13_consumer_manifest_v3 import InstalledD13ConsumerManifestV3
            if (type(self.manifest) is not InstalledD13ConsumerManifestV3
                    or self.manifest is not getattr(self.control, '_d13_cache_use_consumer_manifest_v2', None)):
                raise AuthorityUnavailable('D13 complete future consumer registry has no actual installed Root owner')
            proof = self.qualification
            if type(proof) is VerifiedInstalledPeerRegistryActivationV3:
                proof.require_current(control=self.control, gate=self.gate, meter=meter)
                self.manifest.require_actual_fresh_qualification_v3(proof,
                    control=self.control, gate=self.gate, meter=meter)
            elif type(proof) in (VerifiedPeerRetirementCoverageV3, VerifiedPreparedPeerRetirementCoverageV3):
                proof.require_current(meter=meter)
                if self.gate._operation != proof.operation_id:
                    raise AuthorityUnavailable('D13 upgrade lost continuous old-cohort Gate exclusion')
            else:
                raise AuthorityUnavailable('D13 coverage has no actual full Root genesis or durable cohort drain')
            material = self.manifest.require_d13_pin_only_consumers_v2(control=self.control, gate=self.gate,
                policy=policy, meter=meter)
            original = self.manifest.coverage_original_v3()
            if (original['schema'] != 'sylanne3.d13.cache-use-complete-coverage.v3'
                    or original['installation_id'] != policy.installation_id
                    or original['namespace'] != policy.namespace
                    or original['consumer_cohort_digest'] != policy.consumer_cohort_digest
                    or original['future_consumers'] != material):
                raise AuthorityUnavailable('D13 actual signed coverage original crossed its installed policy/cohort')
            digest = canonical_digest(original)
            if digest != maintenance_policy.coverage_digest:
                raise AuthorityUnavailable('D13 actual complete coverage differs from signed maintenance digest')
            if self.original is not None and self.original != original:
                raise AuthorityUnavailable('D13 complete coverage original changed during installation')
            self.original = original
            return maintenance_policy.coverage_ref, digest, digest


def prepare_d13_cache_use_coverage_installation_v2(*, qualification, control, gate,
        policy, maintenance_policy, consumer_manifest):
    """Installation-only producer; an absent manifest remains legacy_unknown/HOLD."""
    coverage = _D13CacheUseCoverageInstallationV2(_ISSUER, qualification=qualification,
        control=control, gate=gate, policy=policy, maintenance_policy=maintenance_policy, manifest=consumer_manifest)
    coverage.require_current(policy=policy, maintenance_policy=maintenance_policy)
    return coverage


class _GraphConsumerOwnerV2:
    def __init__(self, work):
        from ..graph_worker import GraphStorageWorkV3
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlPortV2
        if type(work) is not GraphStorageWorkV3 or work.kind != 'current_graph_full_read_v3':
            raise AuthorityUnavailable('D13 Graph consumer requires the actual full-read Work')
        reader, graph = work.state, work.coordinator
        if (type(reader) is not _OrdinaryFullReadV3 or reader.work is not work
                or reader.graph is not graph or reader.operation is not work.operation):
            raise AuthorityUnavailable('D13 Graph consumer changed its private full-read reader')
        port = graph._GraphCoordinator__d13_cache_use_control_v2
        if type(port) is not InstalledD13CacheUseControlPortV2 or port.use_policy.namespace != reader.namespace:
            raise AuthorityUnavailable('D13 Graph consumer has no actual installed namespace use port')
        port._actual()
        self.work, self.reader, self.graph, self.port = work, reader, graph, port
        self.permit, self.operation = reader.fence.scope.permit, work.operation
        self.operation_id = work.operation_id
        self.owner_id = 'd13-graph-consumer:' + canonical_digest((reader.namespace,
            self.permit.token, self.operation_id))
        if self.owner_id in _RETAINED:
            raise AuthorityUnavailable('D13 original Graph consumer already has retained ownership')
        self.entries, self.pending, self.release_requested = {}, None, False
        _RETAINED[self.owner_id] = self

    def require_live(self):
        work, reader = self.work, self.reader
        work._require_invocation(self.graph)
        if (work.state is not reader or reader.work is not work or reader.operation is not self.operation
                or work.operation is not self.operation or self.operation.closed
                or reader.fence.scope.permit is not self.permit or self.release_requested
                or _GRAPH_OWNERS.get(reader) is not self or _RETAINED.get(self.owner_id) is not self):
            raise AuthorityUnavailable('D13 original Graph consumer ownership ended or changed')
        return self


def prepare_graph_d13_cache_use_v2(work, *, metadata, metadata_ref, meter):
    """Called in the actual Graph metadata quantum before leaving for Core acquire."""
    if not _graph_use_enabled_v2(work.coordinator):
        return ()
    owner = _GRAPH_OWNERS.get(work.state)
    if owner is None:
        owner = _GraphConsumerOwnerV2(work)
        _GRAPH_OWNERS[work.state] = owner
    owner.require_live()
    identity = _logical_payload_identity(owner.reader, metadata, metadata_ref, meter)
    key = identity[:3]
    entry = owner.entries.get(key)
    if entry is None:
        admission = _ConsumerAdmissionV2(_ISSUER, owner, (identity,), 'graph_source_receiver',
            owner.owner_id + ':' + canonical_digest(key))
        entry = dict(identity=identity, metadata=metadata, metadata_ref=metadata_ref,
            admission=admission, operation_id='d13-use-acquire:' + canonical_digest((owner.owner_id, key)),
            pins=None, attempted=False,
            release_operation_id='d13-use-release:' + canonical_digest((owner.owner_id, key)),
            registration=None, registration_attempted=False, original_proof=None, close_proof=None, close_receipt=None,
            successor_registration=None)
        owner.entries[key] = entry
    elif entry['identity'] != identity or entry['metadata'] != metadata or entry['metadata_ref'] != metadata_ref:
        raise AuthorityUnavailable('D13 same-Work Graph selected metadata changed before Body')
    if entry['pins'] is None:
        if owner.pending is not None and owner.pending is not entry:
            raise AuthorityUnavailable('D13 Graph Work already awaits its original payload acquire')
        owner.pending = entry
        raise D13CacheUseAdmissionRequiredV2(work)
    return entry['pins']


def resolve_graph_d13_cache_use_v2(work):
    owner = _GRAPH_OWNERS.get(work.state)
    if owner is None or owner.pending is None:
        return False
    owner.require_live()
    reader, graph = owner.reader, owner.graph
    if reader.db.in_transaction:
        raise AuthorityUnavailable('D13 Graph use control cannot inherit Graph SQL')
    if reader.borrowed is None:
        graph._authorize(reader.lease, reader.authority, reader.contract.domains, owner_read=reader.contract.owner_read)
        graph._validate_read_fence_v3(reader.fence)
    elif graph._validate_natural_admin_full_read_scope_v3(reader.borrowed) != reader.fence:
        raise AuthorityUnavailable('D13 Graph use control lost its actual borrowed permit')
    entry = owner.pending
    _register_source_receiver_v3(owner,entry)
    values = dict(namespace=reader.namespace, authority_namespace=owner.permit.namespace,
        permit=owner.permit, operation_id=entry['operation_id'], selected_payloads=(entry['identity'],),
        consumer_admission=entry['admission'])
    if entry['attempted']:
        pins = owner.port.inspect_acquisition_v2(**values)
    else:
        entry['attempted'] = True
        pins = owner.port.acquire_for_fence_v2(**values)
    from ..authority_service.d13_cache_use_contract_v2 import D13CachePinReceiptV2
    from ..authority_service.d13_cache_use_control_v2 import _D13CachePinLeaseV2
    if (len(pins) != 1 or type(pins[0]) is not _D13CachePinLeaseV2
            or type(pins[0].receipt) is not D13CachePinReceiptV2 or pins[0].receipt.state != 'active'):
        raise AuthorityUnavailable('D13 Graph original acquire has no confirmed active acknowledgement')
    entry['pins'], owner.pending = pins, None
    return True


def require_d13_graph_payload_pin_v2(db, metadata):
    from .current_graph_full_read_v3 import _BOUND, PreparedCurrentGraphFullReadV3
    bound = _BOUND.get()
    if bound is None or type(bound[0]) is not PreparedCurrentGraphFullReadV3 or bound[2] is not db:
        raise AuthorityUnavailable('D13 Body requires the actual prepared full-read consumer Binder')
    prepared, graph, _, work, operation = bound
    prepared.require_current(graph, db, metadata.namespace, required_families=frozenset())
    if not _graph_use_enabled_v2(graph):
        return ()
    owner = _GRAPH_OWNERS.get(work.state)
    if owner is None or owner.work is not work or owner.operation is not operation:
        raise AuthorityUnavailable('D13 Body has no actual Graph original consumer ownership')
    owner.require_live()
    entries = [entry for entry in owner.entries.values() if entry['metadata'] == metadata]
    if len(entries) != 1 or not entries[0]['pins']:
        raise AuthorityUnavailable('D13 Body cannot precede its Graph durable active pin acknowledgement')
    return entries[0]['pins']


def release_graph_d13_cache_use_v2(work):
    """The real final owned-response/frame retention release calls this exactly once."""
    owner = _GRAPH_OWNERS.get(work.state)
    if owner is None:
        return
    if owner.reader.db.in_transaction:
        raise AuthorityUnavailable('D13 Graph final consumer release cannot inherit Graph SQL')
    owner.release_requested = True
    if not owner.operation.closed:
        raise AuthorityUnavailable('D13 Graph receiver release requires its actual final closed retention')
    for entry in owner.entries.values():
        if entry['registration'] is not None:
            prepare_d13_source_receiver_closure_v3(owner,entry)
    # Final retention callbacks only record the actual event and wake the
    # installed worker. Even a synchronous caller must not perform control RPC.
    wake = owner.graph._GraphCoordinator__d13_cache_use_release_wake_v3
    if wake is not None:
        wake()


def reconcile_graph_d13_cache_use_cleanup_v2(graph):
    for owner in tuple(_RETAINED.values()):
        if type(owner) is _GraphConsumerOwnerV2 and owner.graph is graph and owner.release_requested:
            _release_owner(owner)
    from .d13_natural_original_use_v3 import reconcile_graph_natural_original_cleanup_v3
    reconcile_graph_natural_original_cleanup_v3(graph)


_GRAPH_SELECTIONS = WeakKeyDictionary()


class _GraphD13CacheUseSelectionV2:
    """Actual current conversation's LIMIT16 candidate metadata; no payload/Source Body."""
    def __init__(self, issuer, work, *, collection, question_ref, meter):
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
        from .d13_current_collection_v6 import CurrentD13CollectionV6, _snapshot
        if (issuer is not _ISSUER or type(work.state) is not _OrdinaryFullReadV3
                or work.state.work is not work or not work.state.db.in_transaction
                or type(collection) is not CurrentD13CollectionV6):
            raise AuthorityUnavailable('D13 selection requires its actual same-Work current collection quantum')
        reader = work.state
        if reader.source_material is None or not reader.source_material.complete:
            raise AuthorityUnavailable('D13 selection lacks the actual completed root Source material')
        material = reader.source_material.proof
        require_prepared_current_source_material_v3(material, prefinal_inventory=reader.prefinal,
            actual_entry=reader.source_locator)
        window = collection.window
        if (material.source_ref != question_ref or window.namespace != reader.namespace
                or window.conversation_ref != material.inputs.conversation_ref
                or canonical_digest(_snapshot(reader.db, reader.namespace)) != collection.snapshot_commitment):
            raise AuthorityUnavailable('D13 selected collection changed its actual root/conversation/snapshot')
        self.work, self.reader, self.collection, self.material = work, reader, collection, material
        self.question_ref = question_ref
        self.db, self.operation = reader.db, reader.operation
        self.cursor, self.count, self.reserved = '', 0, 0
        from .d13_maintenance_read_v2 import _Metadata
        self.metadata = _Metadata(self.operation)
        self.cell = self.head = self.payload = None
        self.rows, self.complete = [], False
        self.retained_sizes = {}
        _GRAPH_SELECTIONS[self] = (work, reader, collection, material, question_ref, reader.operation, reader.graph_stamp)
        reader.prefinal.require_current(meter=meter)

    def reserve(self, amount):
        peak = amount + sum(self.retained_sizes.values()) * 10
        if peak > self.reserved:
            self.operation.retain(peak - self.reserved)
            self.reserved = peak

    def _actual(self, meter):
        reader = self.reader
        if (_GRAPH_SELECTIONS.get(self) != (self.work, reader, self.collection, self.material,
                self.question_ref, reader.operation, reader.graph_stamp)
                or self.work.state is not reader or reader.work is not self.work
                or self.operation is not reader.operation or self.operation.closed or not self.db.in_transaction):
            raise AuthorityUnavailable('D13 selection lost its actual same-Work metadata quantum')
        self.work._require_invocation(reader.graph)
        reader.prefinal.require_current(meter=meter)

    def advance(self, *, meter):
        from ..domains.d13.derived_block_metadata_v2 import (METADATA_TYPE,
            decode_derived_block_metadata_v2, derived_block_metadata_key_v2)
        from ..graph_types import AtomKey, Owner
        from ..runtime_contracts import VersionedRef
        from .d13_maintenance_read_v2 import _Cell
        self._actual(meter)
        if self.complete:
            return self
        if self.cell is not None:
            if not self.cell.complete:
                self.cell.advance(meter)
                return self
            metadata = self.cell.value
            window = self.collection.window
            if (metadata.namespace != window.namespace or derived_block_metadata_key_v2(metadata).token != self.head[0]
                    or (metadata.block_ref, metadata.payload_digest, metadata.payload_length_bytes) != self.payload):
                raise AuthorityUnavailable('D13 candidate metadata changed its actual retained payload identity')
            if (metadata.status in ('standby', 'active')
                    and metadata.turn_expiries[0].sequence >= self.collection.pages[-1].first_sequence
                    and metadata.turn_expiries[-1].sequence <= window.order_watermark):
                self.rows.append((metadata, VersionedRef(self.head[0], self.head[1])))
                self.retained_sizes[self.head[0]] = self.cell.cell.header[3]
                self.rows.sort(key=lambda row: (-row[0].turn_expiries[-1].sequence, row[1].ref))
                if len(self.rows) > 16:
                    dropped = self.rows.pop()
                    self.retained_sizes.pop(dropped[1].ref)
            self.cell = self.head = self.payload = None
            return self
        row = self.db.execute('SELECT block_ref,payload_digest,length(payload_bytes) '
            'FROM graph_d11_derived_cache_payloads_v1 WHERE bot=? AND persona=? AND block_ref>? '
            'ORDER BY block_ref LIMIT 1', (*self.reader.namespace.as_tuple, self.cursor)).fetchone()
        meter.charge_read(0 if row is None else len(row[0].encode('utf-8')) + 96)
        if row is None:
            self.complete = True
            return self
        self.count += 1
        if self.count > 256:
            raise AuthorityUnavailable('D13 actual retained payload inventory exceeds installed fixed capacity')
        self.cursor, self.payload = row[0], tuple(row)
        token = AtomKey(Owner('persona', *self.reader.namespace.as_tuple), METADATA_TYPE, row[0]).token
        head = meter.read_fixed_row(self.db, 'graph_atoms', ('token', 'revision', 'valid', 'value_cell_id'),
            'token=? AND bot=? AND persona=?', (token, *self.reader.namespace.as_tuple))
        if head is None or head[2] != 1:
            raise AuthorityUnavailable('D13 candidate retained payload has no actual current metadata')
        self.head = tuple(head)
        self.cell = _Cell(self, head[3], token, decode_derived_block_metadata_v2)
        return self

    def require_candidates_v2(self, work, *, meter):
        self._actual(meter)
        if work is not self.work or not self.complete:
            raise AuthorityUnavailable('D13 exact metadata candidate selection has not completed EOF')
        window = self.collection.window
        # Preserve the original namespace/status/range ORDER BY LIMIT16 before
        # applying current scene/Source predicates, matching the independent Core.
        return tuple((metadata, ref) for metadata, ref in self.rows
            if window.trusted_utc < metadata.expires_at_utc
            and metadata.scene_ref == window.scene_ref and metadata.audience_ref == window.audience_ref
            and metadata.conversation_ref == window.conversation_ref
            and set(metadata.source_dependencies) <= set(window.source_dependencies)
            and self.question_ref not in metadata.source_dependencies)

    def release_payload_v3(self):
        _GRAPH_SELECTIONS.pop(self, None)
        self.rows.clear()
        self.retained_sizes.clear()
        self.cell = self.head = self.payload = self.material = self.collection = None


def begin_graph_d13_cache_use_selection_v2(work, *, collection, question_ref, meter):
    return _GraphD13CacheUseSelectionV2(_ISSUER, work, collection=collection,
        question_ref=question_ref, meter=meter)


def require_actual_authority_d13_selected_payloads_v3(work, projected_blocks):
    """Counter owner registration consumes its actual private current pair EOF only."""
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    if type(work) is not AuthorityGraphReadWorkV3 or work.controller.kind != 'counter':
        raise AuthorityUnavailable('D13 original owner registration requires the actual Counter Source Work')
    work._actual()
    reader = work.counter_pair_reader
    if reader is None:
        raise AuthorityUnavailable('D13 Counter original owner has no actual pair producer')
    pair = reader.require_current_v7(work)
    if type(projected_blocks) is not tuple or projected_blocks is not pair.projected_blocks:
        raise AuthorityUnavailable('D13 original owner selection differs from the actual Counter pair EOF')
    if not projected_blocks:
        return ()
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        raise AuthorityUnavailable('D13 Counter original owner lacks its actual confirmed Source pins')
    owner.require_live()
    result = []
    for projection in projected_blocks:
        entries = [entry for entry in owner.entries.values()
            if entry['metadata'] == projection.metadata and entry['metadata_ref'] == projection.ref]
        if len(entries) != 1 or not entries[0]['pins']:
            raise AuthorityUnavailable('D13 durable original cannot precede its actual selected active Source pins')
        result.append(entries[0]['identity'])
    return selected_payloads_v2(tuple(result))


_SOURCE_RECEIVER_ORIGINALS_V3 = WeakKeyDictionary()
_SOURCE_RECEIVER_CLOSURES_V3 = WeakKeyDictionary()


class D13SourceReceiverOriginalProofV3:
    """One actual selected payload receiver, before the first protected Body byte."""
    def __init__(self, issuer, owner, entry):
        from ..authority_service.d13_cache_use_contract_v2 import D13SourceReceiverOwnerLocatorV3
        if issuer is not _ISSUER or entry not in owner.entries.values():
            raise TypeError('actual Source receiver producer required')
        owner.require_live()
        admission = entry['admission']
        kind = 'authority_source_receiver' if type(owner) is _AuthorityConsumerOwnerV2 else 'graph_source_receiver'
        locator = D13SourceReceiverOwnerLocatorV3(kind, owner.permit.operation_id,
            owner.permit.token, canonical_digest(owner.permit), admission.owner_ref,
            'd13-source-retention-v3:' + canonical_digest((owner.operation_id, owner.permit.token,
                owner.operation.selection_digest, admission.owner_ref)))
        if kind=='authority_source_receiver':
            from ..authority_service.d13_original_owner_v3 import bind_actual_authority_source_locator_v4
            locator=bind_actual_authority_source_locator_v4(owner,locator)
        commitment = canonical_digest(('d13.source-receiver-original.v3', locator,
            entry['metadata_ref'], entry['metadata'], (entry['identity'],)))
        material = dict(owner_ref=admission.owner_ref, owner_kind=kind,
            original_operation_id=owner.permit.operation_id, original_locator=locator,
            original_commitment=commitment,
            producer_binding_digest=canonical_digest((locator, commitment,
                owner.operation.selection_digest, canonical_digest(owner.permit))),
            payload_identities=(entry['identity'],), subject=owner.permit.subject,
            permit_token=owner.permit.token, permit_digest=canonical_digest(owner.permit))
        self.owner, self.entry, self.material = owner, entry, material
        _SOURCE_RECEIVER_ORIGINALS_V3[self] = (owner, entry, canonical_digest(material))


def prepare_d13_source_receiver_original_v3(owner, entry):
    if entry['original_proof'] is None:
        entry['original_proof'] = D13SourceReceiverOriginalProofV3(_ISSUER, owner, entry)
    return entry['original_proof']


def _source_receiver_material_v3(proof, *, port, permit, live):
    if type(proof) is not D13SourceReceiverOriginalProofV3:
        raise AuthorityUnavailable('D13 Source receiver requires its actual private producer proof')
    state = _SOURCE_RECEIVER_ORIGINALS_V3.get(proof)
    if state is None:
        raise AuthorityUnavailable('D13 Source receiver original producer is no longer registered')
    owner, entry, digest = state
    if (proof.owner is not owner or proof.entry is not entry or port is not owner.port
            or permit is not owner.permit or canonical_digest(proof.material) != digest
            or _RETAINED.get(owner.owner_id) is not owner or entry not in owner.entries.values()
            or proof.material['owner_ref'] != entry['admission'].owner_ref
            or proof.material['payload_identities'] != (entry['identity'],)):
        raise AuthorityUnavailable('D13 Source receiver proof changed its actual Work/payload/permit/retention')
    if live:
        owner.require_live()
    port._actual()
    return owner, entry, dict(proof.material)


def require_d13_source_receiver_client_v3(proof, *, port, permit, action='register'):
    owner, entry, material = _source_receiver_material_v3(proof, port=port, permit=permit,
        live=action == 'register')
    if action not in ('register', 'inspect'):
        raise AuthorityUnavailable('D13 private Source original cannot claim a terminal outcome')
    return material


def require_d13_source_receiver_original_v3(proof, *, service, db, action='register'):
    owner, entry, material = _source_receiver_material_v3(proof, port=proof.owner.port,
        permit=proof.owner.permit, live=action == 'register')
    if (type(owner) is not _AuthorityConsumerOwnerV2 or owner.port.service is not service
            or service.core._db is not db or not db.in_transaction
            or owner.port.credential is not owner.work.credential or owner.port.subject != owner.work.subject):
        raise AuthorityUnavailable('D13 local Source original lost its actual authenticated Core producer transaction')
    if action not in ('register', 'execute'):
        raise AuthorityUnavailable('D13 Source original action differs from its actual producer')
    return material, owner.port.credential, owner.permit


class D13SourceReceiverClosureProofV3:
    """Actual final source-receiver retention, independent of durable-frame termination."""
    def __init__(self, issuer, owner, entry):
        if issuer is not _ISSUER or not owner.release_requested or not owner.operation.closed:
            raise AuthorityUnavailable('D13 Source closure requires its actual final retained receiver release')
        registration = entry['registration']
        if registration is None:
            raise AuthorityUnavailable('D13 Source closure cannot invent an unknown owner registration')
        ref = registration.original_locator.retention_id + ':released'
        digest = canonical_digest(('d13.actual-source-receiver-final-retention.v3', registration.registration_digest,
            registration.original_locator, owner.operation.operation_id, owner.operation.selection_digest))
        material = dict(disposition_kind='terminal',
            disposition_ref=registration.original_operation_id + ':source-finished',
            disposition_digest=canonical_digest(('d13.source-receiver-finished.v3',
                registration.owner_ref, registration.permit_digest, registration.registration_digest)),
            retention_release_ref=ref, retention_release_digest=digest, successor_transfer_digest=None)
        successor = entry['successor_registration']
        if successor is not None:
            material.update(disposition_kind='transferred', disposition_ref=successor.operation_id,
                disposition_digest=successor.registration_digest,
                successor_transfer_digest=canonical_digest(('d13.source-receiver-transfer.v3',
                    registration.registration_digest, successor.registration_digest,
                    tuple(identity[:3] for identity in registration.payload_identities))))
        self.owner, self.entry, self.registration, self.material = owner, entry, registration, material
        self.release_original = None
        _SOURCE_RECEIVER_CLOSURES_V3[self] = (owner, entry, registration, canonical_digest(material))


def prepare_d13_source_receiver_closure_v3(owner, entry):
    if entry['close_proof'] is None:
        entry['close_proof'] = D13SourceReceiverClosureProofV3(_ISSUER, owner, entry)
    return entry['close_proof']


def _source_receiver_closure_v3(proof, *, port):
    if type(proof) is not D13SourceReceiverClosureProofV3:
        raise AuthorityUnavailable('D13 receiver closure requires the actual private final retention producer')
    state = _SOURCE_RECEIVER_CLOSURES_V3.get(proof)
    if state is None:
        raise AuthorityUnavailable('D13 receiver final retention producer was never issued')
    owner, entry, registration, digest = state
    if (proof.owner is not owner or proof.entry is not entry or proof.registration is not registration
            or canonical_digest(proof.material) != digest or port is not owner.port
            or _RETAINED.get(owner.owner_id) is not owner or not owner.release_requested or not owner.operation.closed
            or entry['registration'] is not registration):
        raise AuthorityUnavailable('D13 final retention proof changed its exact original receiver/registration')
    port._actual()
    return owner, entry, registration, dict(proof.material)


def require_d13_source_receiver_closure_v3(proof, *, service, db):
    owner, entry, registration, material = _source_receiver_closure_v3(proof, port=proof.owner.port)
    if (type(owner) is not _AuthorityConsumerOwnerV2 or owner.port.service is not service
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 local receiver close lost its actual original authenticated Core service')
    return registration, material, owner.port.credential


def require_d13_source_receiver_release_client_v3(proof, *, port):
    """Serialize only an acknowledged installed peer and a real final receiver event."""
    from ..authority_service.d13_cache_use_contract_v2 import D13RetentionReleaseOriginalV3, owner_operation_id_v3
    owner, entry, registration, material = _source_receiver_closure_v3(proof, port=port)
    if type(owner) is not _GraphConsumerOwnerV2:
        raise AuthorityUnavailable('D13 remote retention release requires its actual installed Graph peer')
    if proof.release_original is None:
        release_operation = owner_operation_id_v3(registration.namespace, registration.owner_ref, 'owner_close')
        values = dict(producer_kind_version=registration.producer_kind_version,
            owner_ref=registration.owner_ref, registration_digest=registration.registration_digest,
            payload_set_digest=registration.payload_digest, peer_admission_digest=registration.peer_admission_digest,
            process_incarnation=registration.process_incarnation, original_permit_digest=registration.permit_digest,
            retention_instance_ref=registration.retention_instance_ref, release_operation_id=release_operation)
        values['request_digest'] = canonical_digest(('d13.installed-source-retention-release.v3', values,
            material['retention_release_digest']))
        proof.release_original = D13RetentionReleaseOriginalV3(**values)
    return proof.release_original


def _register_source_receiver_v3(owner,entry,*,inspect_only=False):
    from ..authority_service.d13_cache_use_contract_v2 import D13OwnerRegistrationReceiptV3
    if entry['registration'] is not None:
        return entry['registration']
    proof = prepare_d13_source_receiver_original_v3(owner,entry) if entry['original_proof'] is None else entry['original_proof']
    values = dict(namespace=owner.port.use_policy.namespace,authority_namespace=owner.permit.namespace,
        permit=owner.permit,owner_admission=proof)
    if inspect_only or entry['registration_attempted']:
        registration = owner.port.inspect_original_owner_for_fence_v3(**values)
    else:
        entry['registration_attempted'] = True
        registration = owner.port.register_original_owner_for_fence_v3(**values)
    material = proof.material
    if (type(registration) is not D13OwnerRegistrationReceiptV3
            or registration.namespace != owner.port.use_policy.namespace
            or registration.authority_namespace != owner.permit.namespace
            or registration.installation_id != owner.port.use_policy.installation_id
            or registration.use_policy_ref != owner.port.use_policy.policy_ref
            or registration.use_policy_digest != owner.port.use_policy.digest
            or registration.consumer_cohort_digest != owner.port.use_policy.consumer_cohort_digest
            or any(getattr(registration,name) != value for name,value in material.items())):
        raise AuthorityUnavailable('D13 original Source receiver registration is unknown or differs; preserve original operation')
    entry['registration'] = registration
    return registration


def require_actual_authority_natural_d13_payloads_v3(work,frozen):
    """Natural durable owners consume the actual model Source replay's private EOF."""
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from .installed_d13_natural_frame_v7 import _AuthorityCurrentNaturalFrameV7
    from .natural_frozen_original_read_v3 import PreparedAuthorityNaturalFrozenReadV3
    if type(work) is not AuthorityGraphReadWorkV3 or work.controller.kind != 'model':
        raise AuthorityUnavailable('D13 natural owner registration requires its actual model Source Work')
    work._actual()
    reader = work.history_current_reader
    if type(reader) is not _AuthorityCurrentNaturalFrameV7 or reader.work is not work:
        raise AuthorityUnavailable('D13 natural owner has no actual V7 current Source replay')
    original = work.originals[(work.parent_original_id,'generation')]
    eof = original.frozen_eof
    if (type(eof) is not PreparedAuthorityNaturalFrozenReadV3 or not eof.complete
            or eof.result is not frozen or original.saved.frozen is not frozen or reader.frozen is not frozen):
        raise AuthorityUnavailable('D13 natural owner differs from the actual saved generation typed frozen EOF')
    eof._actual()
    if reader.require_current_v7(issuer=reader.issuer,frozen=frozen,parent_original_id=work.parent_original_id,
            now_utc=work.now_utc,same_batch_prepared=reader.same_batch_prepared) is not work.history_current:
        raise AuthorityUnavailable('D13 natural owner current replay EOF is not this Work original')
    refs = frozen.input.history_selection.block_refs
    if type(refs) is not tuple or len(refs) > 4:
        raise AuthorityUnavailable('D13 natural owner needs its exact bounded original block refs')
    if not refs:
        return ()
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        raise AuthorityUnavailable('D13 natural original has no actual confirmed current Source pins')
    owner.require_live()
    identities = []
    for ref in refs:
        entries = [entry for entry in owner.entries.values() if entry['metadata_ref'] == ref]
        if len(entries) != 1 or not entries[0]['pins']:
            raise AuthorityUnavailable('D13 natural owner must retain every actual original selected payload')
        identities.append(entries[0]['identity'])
    return selected_payloads_v2(tuple(identities))


def bind_authority_d13_source_successor_v3(work,actual_natural_registration):
    """Bind only actual acknowledged natural owners covering this Source's keys."""
    from ..authority_service.d13_original_owner_v3 import require_actual_natural_source_successor_v3
    successor = require_actual_natural_source_successor_v3(work,actual_natural_registration)
    owner = _WORK_OWNERS.get(work)
    if owner is None:
        return
    owner.require_live()
    if (successor.namespace != owner.port.use_policy.namespace
            or successor.authority_namespace != owner.permit.namespace
            or successor.permit_token != owner.permit.token
            or successor.permit_digest != canonical_digest(owner.permit)
            or successor.owner_kind not in ('natural_generation_original','natural_review_original')):
        raise AuthorityUnavailable('D13 Source successor differs from its actual namespace/original permit/natural producer')
    covered = {identity[:3] for identity in successor.payload_identities}
    for entry in owner.entries.values():
        if entry['identity'][:3] not in covered:
            continue
        registration = entry['registration']
        if registration is None or not entry['pins'] or entry['close_proof'] is not None:
            raise AuthorityUnavailable('D13 successor cannot replace an unknown, unconfirmed or already closing Source owner')
        if entry['successor_registration'] not in (None,successor):
            raise AuthorityUnavailable('D13 Source owner already belongs to another actual successor')
        entry['successor_registration'] = successor
