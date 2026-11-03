"""Private actual Counter producer ownership; wire locators never issue authority."""
from dataclasses import asdict
from contextlib import contextmanager
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from .d13_cache_use_contract_v2 import D13CounterFrameOwnerLocatorV3
from ..runtime_contracts import canonical_digest, canonical_serialize

_ISSUER = object()
_PROOFS = WeakKeyDictionary()


class D13SourceReceiverAwaitingTerminalV3(AuthorityUnavailable):
    """Actual retained receiver release awaits its still-active original model fence."""


def counter_frame_owner_ref_v3(namespace, operation_id):
    return 'd13-counter-frame-owner-v3:' + canonical_digest((namespace, operation_id, 'counter_frame_draft'))


def _control(counter):
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    if type(counter) is not InstalledD13CoreCounterServiceV1 or not counter._lock._is_owned():
        raise AuthorityUnavailable('D13 owner requires its actual locked installed Counter producer')
    service = counter.core._d13_cache_use_controls_v2.get(counter.bridge.namespace)
    if (type(service) is not InstalledD13CacheUseControlServiceV2 or service.core is not counter.core
            or service.fences is not counter.fences or service.namespace != counter.namespace
            or service.authority_namespace != counter.bridge.namespace
            or service.installation_id != counter.policy.installation.installation_id):
        raise AuthorityUnavailable('D13 Counter owner requires explicit installed V3 use-control cohort')
    return service


class _CounterOriginalOwnerProofV3:
    def __init__(self, issuer, *, counter, scope, operation_id, current=None, work=None, payloads=None, draft=None):
        if issuer is not _ISSUER:
            raise TypeError('actual Counter owner producer required')
        self.counter, self.scope, self.operation_id = counter, scope, operation_id
        self.current, self.work, self.payloads, self.draft = current, work, payloads, draft
        self.writer = None
        _PROOFS[self] = (counter, scope, operation_id, current, work, payloads, draft, None)

    def require_v3(self, *, service, db, action):
        c, scope = self.counter, self.scope
        state = _PROOFS.get(self)
        if (state is None or state[0] is not c or state[1] is not scope or state[2] != self.operation_id
                or state[3] is not self.current or state[4] is not self.work or state[5] != self.payloads
                or state[6] is not self.draft or state[7] is not self.writer
                or _control(c) is not service or db is not c.core._db or not db.in_transaction):
            raise AuthorityUnavailable('D13 owner proof lost its actual Counter/Core transaction')
        scope.require_current_v3()
        if action == 'register':
            require_natural_parent_open_in_tx_v3(service, db, self.draft['selector']['c02_operation_id'])
            from ..runtime_storage_v3 import _CorePayloadWriteV3
            writer = self.writer
            if (self.work is None or scope.child is not self.work or scope.source_call is None
                    or self.work.counter_result is not self.current or self.work.permit is not scope.source_call.permit
                    or type(writer) is not _CorePayloadWriteV3 or writer.db is not db or writer.phase != 'ready'
                    or writer.key != (c.bridge.namespace, self.operation_id, 'draft')
                    or writer.table != 'authority_d13_counter_originals_v1' or writer.value != self.draft):
                raise AuthorityUnavailable('D13 registration lost its actual canonical Counter draft/qualified Source producer')
            writer._require_current_v3()
            locator = D13CounterFrameOwnerLocatorV3(self.operation_id,
                self.draft['frame_intent_id'], self.draft['frame_intent_digest'], self.draft['selector']['c02_operation_id'])
            permit = self.work.permit
            material = dict(owner_ref=counter_frame_owner_ref_v3(c.namespace, self.operation_id),
                owner_kind='counter_frame_draft', original_operation_id=self.operation_id,
                original_locator=locator, original_commitment=writer.digest,
                producer_binding_digest=canonical_digest((c.policy.policy_digest, locator, writer.digest,
                    self.current.source_scope_digest, self.current.owner_grant_digest,
                    canonical_digest(permit), self.work.selection_digest)),
                payload_identities=self.payloads, subject=self.work.subject,
                retention_instance_ref=scope.d13_frame_retention_instance_v3,
                permit_token=permit.token, permit_digest=canonical_digest(permit))
            return material, self.work.credential, permit
        if action != 'execute':
            raise AuthorityUnavailable('Counter owner proof does not authorize terminal or retention release')
        registration = service._live_owner_v3(db, counter_frame_owner_ref_v3(c.namespace, self.operation_id))
        require_natural_parent_open_in_tx_v3(service, db, registration.original_locator.parent_original_id)
        return dict(owner_ref=counter_frame_owner_ref_v3(c.namespace, self.operation_id),
            original_operation_id=self.operation_id), scope.credential, None


def prepare_d13_counter_frame_owner_v3(counter, current, draft):
    """Before Core SQL, capture the actual complete Source Work selection."""
    from .d13_core_counter_source_v1 import (
        require_counter_call_resource_scope_v3, require_current_authority_counter_call_work_v3)
    from ..runtime.d13_cache_use_admission_v2 import require_actual_authority_d13_selected_payloads_v3
    service = _control(counter)
    scope = require_counter_call_resource_scope_v3(counter, draft['selector']['counter_operation_id'])
    work = require_current_authority_counter_call_work_v3(counter, current)
    pending = counter._pending_owner_draft_v3
    if (work is None or pending is None or pending[0] is not draft or pending[1] is not current or pending[2] is not work
            or draft['selector'] != asdict(work.request) or work.controller.fences.core is not service.core):
        raise AuthorityUnavailable('D13 registration needs the actual newly produced Counter draft and qualified Source Work')
    try:
        payloads = require_actual_authority_d13_selected_payloads_v3(work, current.pair.projected_blocks)
        return _CounterOriginalOwnerProofV3(_ISSUER, counter=counter, scope=scope,
            operation_id=scope.selector.counter_operation_id, current=current, work=work, payloads=payloads, draft=draft)
    finally:
        counter._pending_owner_draft_v3 = None


def bind_d13_counter_owner_writer_v3(proof, writer):
    if type(proof) is not _CounterOriginalOwnerProofV3 or proof not in _PROOFS or proof.writer is not None:
        raise AuthorityUnavailable('D13 actual Counter draft producer can bind its canonical writer once')
    proof.writer = writer
    _PROOFS[proof] = (*_PROOFS[proof][:7], writer)
    return proof


def prepare_d13_counter_original_use_v3(counter, operation_id):
    from .d13_core_counter_source_v1 import require_counter_call_resource_scope_v3
    _control(counter)
    scope = require_counter_call_resource_scope_v3(counter, operation_id)
    return _CounterOriginalOwnerProofV3(_ISSUER, counter=counter, scope=scope, operation_id=operation_id)


def require_d13_original_owner_proof_v3(proof, *, service, db, action):
    if type(proof) is _NaturalOriginalOwnerProofV3:
        return proof.require_v3(service=service, db=db, action=action)
    if type(proof) is _CounterOriginalOwnerProofV3:
        return proof.require_v3(service=service, db=db, action=action)
    if type(proof) is _AuthenticatedSourceReceiverProofV3:
        return proof.require_v3(service=service, db=db, action=action)
    from ..runtime.d13_cache_use_admission_v2 import (
        D13SourceReceiverOriginalProofV3, require_d13_source_receiver_original_v3)
    if type(proof) is D13SourceReceiverOriginalProofV3:
        return require_d13_source_receiver_original_v3(proof, service=service, db=db, action=action)
    raise AuthorityUnavailable('actual privately issued original owner producer proof required')


def require_d13_owner_closure_proof_v3(proof, *, service, db):
    if type(proof) is _CurrentCoreReceiverCloseProofV4:
        return _current_core_receiver_closure_v4(proof, service, db)
    if type(proof) is _ActualUnusedCounterClosureProofV3:
        return _actual_unused_counter_closure_v3(proof, service, db)
    if type(proof) is _ActualPreReviewClosureProofV3:
        return _actual_pre_review_closure_v3(proof, service, db)
    if type(proof) is _RetiredReceiverCloseProofV3:
        return _retired_receiver_closure_v3(proof, service, db)
    if type(proof) is _PermanentNaturalParentClosureProofV3:
        return _permanent_natural_parent_closure_v3(proof, service, db)
    if type(proof) is _NaturalRosterClosureProofV3:
        return _natural_roster_closure_v3(proof, service, db)
    if type(proof) is _NaturalTransferProofV3:
        return _natural_transfer_closure_v3(proof, service, db)
    if type(proof) is _AuthenticatedSourceReceiverProofV3:
        return require_authenticated_d13_receiver_closure_v3(proof, service=service, db=db)
    from ..runtime.d13_cache_use_admission_v2 import (
        D13SourceReceiverClosureProofV3, require_d13_source_receiver_closure_v3)
    if type(proof) is D13SourceReceiverClosureProofV3:
        registration, material, credential = require_d13_source_receiver_closure_v3(proof, service=service, db=db)
        if material['disposition_kind'] == 'transferred':
            _require_actual_source_successor_in_tx_v3(service, db, registration, material)
        else:
            material.update(_source_receiver_terminal_in_tx_v3(service, db, registration))
        return registration, material, credential
    raise AuthorityUnavailable('D13 closure requires actual disposition and final retention-release producers')

_REMOTE_PROOFS_V3 = WeakKeyDictionary()
_REMOTE_PRODUCER_KINDS_V3 = {'graph_source_receiver': 'sylanne3.d13.graph-source-receiver.v3'}


def _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit=None):
    """Read the actual signed Control admission for the real TLS-bound peer."""
    import json
    from .installed_policy_v2 import InstalledAuthorityPolicyV2
    policy = service.core._authorize_callback.__self__
    installed = server._installations_v2.get((credential.certificate_sha256, profile_id))
    if installed is None or permit is not None and permit.holder != installed.administrator_holder:
        raise AuthorityUnavailable('D13 named metadata producer differs from its actual installed peer/holder')
    expected_role = (profile_id, service.authority_namespace,
        installed.administrator_holder, service.use_policy.consumer_cohort_digest)
    if (type(policy) is not InstalledAuthorityPolicyV2
            or policy._d13_owner_peers_v3.get(credential.certificate_sha256) != expected_role):
        raise AuthorityUnavailable('D13 retention producer has no exact installed peer/profile/namespace/holder/cohort role')
    from .c09_selected_history_v3 import _bounded
    from .c09_writer_peer_originals_v3 import require_writer_peer_schema_v3
    from .c09_process_identity_v1 import read_process_identity_v1
    if server._bound_v2_service(credential, profile_id, manifest_digest, service.authority_namespace) is not service.fences:
        raise AuthorityUnavailable('D13 remote producer is outside its actual TLS profile/manifest/namespace')
    control = service.core._c09_storage_reader_v1
    gate = control._writer_peer_gate_v3
    peer = (credential.certificate_sha256, profile_id)
    with control._resource_sql_quantum_v3() as meter:
        with gate._condition:
            current = gate._current_context_v3(action='business')
            original = gate._peer_admission_originals_v3.get(peer)
            live = gate._peers.get(peer)
            if (original is None or live is None or gate._operation is not None
                    or original['schema'] != 'sylanne3.c09.writer-peer-admission.v3'
                    or original['peer'] != list(peer)
                    or original['authority_id'] != control.authority_id
                    or original['installation_id'] != service.installation_id
                    or original['namespace'] != service.authority_namespace
                    or (original['manifest_digest'], original['pointer_version'], original['storage_generation']) !=
                        (current.manifest_digest, current.pointer_version, current.storage_generation)
                    or live[0:2] != (current.pointer_version, current.storage_generation)
                    or live[3] != original['process_incarnation'] or live[4] != original['process_original']
                    or read_process_identity_v1(live[4]['pid']) != live[4]):
                raise AuthorityUnavailable('D13 named remote producer has no actual current peer/process admission')
            with control._db() as db:
                require_writer_peer_schema_v3(control, db)
                row = _bounded(db, meter).execute('SELECT admission_json,manifest_digest,pointer_version,storage_generation '
                    'FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                    (original['admission_digest'],)).fetchone()
            if row is None or json.loads(row[0]) != original or row[1:] != (
                    current.manifest_digest, current.pointer_version, current.storage_generation):
                raise AuthorityUnavailable('D13 remote producer differs from its actual durable Control admission')
            control.verify_original_v1(original, 'admission_digest')
            return dict(original)


class _AuthenticatedSourceReceiverProofV3:
    def __init__(self, issuer, *, server, service, credential, profile_id, manifest_digest,
            permit, material, admission, release_original=None):
        if issuer is not _ISSUER:
            raise TypeError('actual TLS/Control-bound receiver producer required')
        self.server, self.service, self.credential = server, service, credential
        self.profile_id, self.manifest_digest, self.permit = profile_id, manifest_digest, permit
        self.material, self.admission, self.release_original = material, admission, release_original
        _REMOTE_PROOFS_V3[self] = (server, service, credential, profile_id, manifest_digest, permit,
            canonical_digest(material), canonical_digest(admission), release_original)

    def require_v3(self, *, service, db, action):
        state = _REMOTE_PROOFS_V3.get(self)
        if (state is None or state[0] is not self.server or state[1] is not service
                or state[2] is not self.credential or state[3:5] != (self.profile_id, self.manifest_digest)
                or state[5] is not self.permit or state[6:8] !=
                    (canonical_digest(self.material), canonical_digest(self.admission))
                or state[8] is not self.release_original or service.core._db is not db or not db.in_transaction):
            raise AuthorityUnavailable('D13 remote producer proof lost its real authenticated Core transaction')
        actual = _actual_peer_admission_v3(self.server, service, self.credential, self.profile_id, self.manifest_digest, self.permit)
        if actual != self.admission:
            raise AuthorityUnavailable('D13 remote producer cannot replace its registered peer/process incarnation')
        if action != 'register' or self.release_original is not None:
            raise AuthorityUnavailable('D13 remote receiver registration does not authorize another action')
        from .d13_cache_use_contract_v2 import D13NaturalReceiverOwnerLocatorV3
        locator = self.material['original_locator']
        if type(locator) is D13NaturalReceiverOwnerLocatorV3:
            live, payloads = _natural_live_owner_for_receiver_in_tx_v3(service, db, locator, self.server)
            if (self.material['payload_identities'] != payloads
                    or self.material['original_commitment'] !=
                        canonical_digest(('d13.natural-receiver-original.v3', locator, live.registration_digest))):
                raise AuthorityUnavailable('D13 natural receiver lost its actual live original/payload owner')
        return dict(self.material), self.credential, self.permit


def prepare_authenticated_d13_source_receiver_v3(server, service, *, credential, profile_id,
        manifest_digest, permit, owner_material):
    from .d13_cache_use_contract_v2 import owner_locator_from_wire_v3, owner_payloads_v3, D13SourceReceiverOwnerLocatorV3
    fields = {'owner_ref', 'owner_kind', 'original_operation_id', 'original_locator', 'original_commitment',
        'producer_binding_digest', 'payload_identities', 'subject', 'permit_token', 'permit_digest'}
    if type(owner_material) is not dict or set(owner_material) != fields:
        raise AuthorityUnavailable('D13 remote receiver registration requires its exact typed producer material')
    material = dict(owner_material)
    locator = owner_locator_from_wire_v3(material['original_locator'])
    payloads = owner_payloads_v3(tuple(tuple(value) for value in material['payload_identities']))
    if (type(locator) is not D13SourceReceiverOwnerLocatorV3 or material['owner_kind'] not in _REMOTE_PRODUCER_KINDS_V3
            or locator.owner_kind != material['owner_kind'] or len(payloads) != 1
            or locator.receiver_id != material['owner_ref'] or material['original_operation_id'] != permit.operation_id
            or locator.source_operation_id != permit.operation_id or locator.source_permit_token != permit.token
            or locator.source_permit_digest != canonical_digest(permit)
            or material['subject'] != permit.subject or permit.subject != 'mtls:sha256:' + credential.certificate_sha256
            or material['permit_token'] != permit.token or material['permit_digest'] != canonical_digest(permit)):
        raise AuthorityUnavailable('D13 remote receiver crossed its actual typed Source permit/payload/subject')
    admission = _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
    material.update(original_locator=locator, payload_identities=payloads,
        peer_admission_digest=admission['admission_digest'], process_incarnation=admission['process_incarnation'],
        producer_kind_version=_REMOTE_PRODUCER_KINDS_V3[material['owner_kind']], retention_instance_ref=locator.retention_id)
    return _AuthenticatedSourceReceiverProofV3(_ISSUER, server=server, service=service, credential=credential,
        profile_id=profile_id, manifest_digest=manifest_digest, permit=permit, material=material, admission=admission)


def prepare_authenticated_d13_retention_release_v3(server, service, *, credential, profile_id,
        manifest_digest, permit, release_original):
    from .d13_cache_use_contract_v2 import D13RetentionReleaseOriginalV3
    if type(release_original) is not D13RetentionReleaseOriginalV3:
        raise AuthorityUnavailable('D13 actual typed installed retention producer original required')
    service.core._require(credential, 'd13_cache_use_attest_retention_release', service.authority_namespace, permit.holder)
    admission = _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
    return _AuthenticatedSourceReceiverProofV3(_ISSUER, server=server, service=service, credential=credential,
        profile_id=profile_id, manifest_digest=manifest_digest, permit=permit,
        material={}, admission=admission, release_original=release_original)


def _source_receiver_terminal_in_tx_v3(service, db, registration):
    from .v2_contract import decode_bytes
    from .d13_cache_use_contract_v2 import (D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3,
        D13AuthoritySourceReceiverOwnerLocatorV4)
    locator = registration.original_locator
    if (type(locator) not in (D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3, D13AuthoritySourceReceiverOwnerLocatorV4)
            or registration.owner_kind not in ('authority_source_receiver', 'graph_source_receiver')):
        raise AuthorityUnavailable('D13 source receiver terminal requires its actual typed receiver original')
    row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
        (service.authority_namespace, registration.original_operation_id)).fetchone()
    if row is None:
        raise AuthorityUnavailable('D13 Core has no actual original Source fence; retain receiver ownership')
    permit = decode_bytes(row[0])
    if (permit.token != registration.permit_token or canonical_digest(permit) != registration.permit_digest
            or permit.subject != registration.subject or locator.source_operation_id != permit.operation_id
            or locator.source_permit_token != permit.token or locator.source_permit_digest != canonical_digest(permit)):
        raise AuthorityUnavailable('D13 source receiver terminal belongs to another actual Core original')
    if row[1] == 'active':
        raise D13SourceReceiverAwaitingTerminalV3('D13 actual source scope released; original model fence remains active')
    if row[1] != 'finished':
        raise AuthorityUnavailable('D13 Core has no actual original Source fence terminal; retain receiver ownership')
    return dict(disposition_kind='terminal', disposition_ref='authority-v2-fence:' + permit.operation_id,
        disposition_digest=canonical_digest((permit, 'finished')), successor_transfer_digest=None)


def require_authenticated_d13_receiver_closure_v3(proof, *, service, db):
    from .d13_cache_use_contract_v2 import owner_operation_id_v3
    state = _REMOTE_PROOFS_V3.get(proof)
    if type(proof) is not _AuthenticatedSourceReceiverProofV3 or state is None or proof.release_original is None:
        raise AuthorityUnavailable('D13 remote closure has no actual authenticated retention producer')
    if (state[0] is not proof.server or state[1] is not service or state[2] is not proof.credential
            or state[5] is not proof.permit or state[8] is not proof.release_original
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 remote retention producer changed its actual server/Core/permit identity')
    actual = _actual_peer_admission_v3(proof.server, service, proof.credential, proof.profile_id, proof.manifest_digest, proof.permit)
    value = proof.release_original
    registration = service._owner_operation_v3(db, value.owner_ref, 'owner_register')
    if (registration is None or registration.owner_kind != 'graph_source_receiver'
            or registration.registration_digest != value.registration_digest
            or registration.payload_digest != value.payload_set_digest
            or registration.peer_admission_digest != actual['admission_digest']
            or registration.peer_admission_digest != value.peer_admission_digest
            or registration.process_incarnation != actual['process_incarnation']
            or registration.process_incarnation != value.process_incarnation
            or registration.producer_kind_version != value.producer_kind_version
            or registration.retention_instance_ref != value.retention_instance_ref
            or registration.permit_digest != value.original_permit_digest
            or registration.permit_digest != canonical_digest(proof.permit)
            or registration.subject != 'mtls:sha256:' + proof.credential.certificate_sha256
            or value.release_operation_id != owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_close')
            or registration.consumer_cohort_digest != service.use_policy.consumer_cohort_digest):
        raise AuthorityUnavailable('D13 retention witness differs from its exact registered peer/cohort/process/receiver')
    material = _source_receiver_terminal_in_tx_v3(service, db, registration)
    material.update(retention_release_ref=value.release_operation_id, retention_release_digest=canonical_digest(value),
        retention_original=value)
    return registration, material, proof.credential

_RETENTION_PROOFS_V3 = WeakKeyDictionary()


class _ActualOwnerRetentionProofV3:
    def __init__(self, issuer, *, producer, registration, credential, material):
        if issuer is not _ISSUER:
            raise TypeError('actual closed retained owner producer required')
        self.producer, self.registration, self.credential, self.material = producer, registration, credential, material
        _RETENTION_PROOFS_V3[self] = (producer, registration, credential, canonical_digest(material))


def require_d13_owner_retention_release_v3(proof, *, service, db):
    state = _RETENTION_PROOFS_V3.get(proof)
    if (type(proof) is not _ActualOwnerRetentionProofV3 or state is None
            or state[0] is not proof.producer or state[1] is not proof.registration
            or state[2] is not proof.credential or state[3] != canonical_digest(proof.material)
            or db is not service.core._db or not db.in_transaction):
        raise AuthorityUnavailable('D13 retention release lacks its actual private final event and Core transaction')
    registration = proof.registration
    if registration.owner_kind == 'counter_frame_draft':
        from .d13_core_counter_source_v1 import _CounterCallResourceScopeV3, _COUNTER_RESOURCE_SCOPES_V3
        scope = proof.producer
        from .current_authority_graph_read_v3 import actual_authority_graph_release_v3
        if (type(scope) is not _CounterCallResourceScopeV3 or scope not in _COUNTER_RESOURCE_SCOPES_V3
                or any(actual_authority_graph_release_v3(work) is not scope.lease
                    for work in scope.d13_source_receivers_v3)
                or scope.active or scope.source_call is not None or scope.readers or scope.originals
                or scope.lease is None or not scope.lease.closed or scope.core is not service.core
                or scope.d13_frame_owner_registration_v3 is not registration
                or scope.d13_frame_retention_instance_v3 != registration.retention_instance_ref):
            raise AuthorityUnavailable('D13 Counter retention event is not its registered actual drained closed outer scope')
    elif registration.owner_kind in ('natural_generation_original', 'natural_review_original'):
        _require_actual_natural_retention_v3(proof, service)
    else:
        raise AuthorityUnavailable('D13 durable retention producer kind is not installed')
    return registration, dict(proof.material), proof.credential


def record_d13_counter_scope_retention_v3(scope):
    from .d13_core_counter_source_v1 import _CounterCallResourceScopeV3, _COUNTER_RESOURCE_SCOPES_V3
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(scope) is not _CounterCallResourceScopeV3 or scope not in _COUNTER_RESOURCE_SCOPES_V3:
        raise AuthorityUnavailable('D13 retention can only originate in its actual Counter scope close')
    registration = scope.d13_frame_owner_registration_v3
    if registration is None:
        return
    service = _control(scope.service)
    material = dict(retention_instance_ref=scope.d13_frame_retention_instance_v3,
        scope_operation_id=scope.lease.operation_id, resource_selection_digest=scope.lease.selection_digest,
        producer_binding_digest=canonical_digest(('d13.actual-counter-retention-release.v3',
            registration.registration_digest, scope.d13_frame_retention_instance_v3,
            scope.lease.operation_id, scope.lease.selection_digest)))
    proof = _ActualOwnerRetentionProofV3(_ISSUER, producer=scope, registration=registration,
        credential=scope.credential, material=material)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-counter-retention:' + registration.owner_ref):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            return service.record_original_owner_retention_in_tx_v3(db, proof)


_NATURAL_OWNER_PROOFS_V3 = WeakKeyDictionary()
_NATURAL_TRANSFER_PROOFS_V3 = WeakKeyDictionary()


def natural_stage_owner_ref_v3(namespace, job_id):
    return 'd13-natural-stage-owner-v3:' + canonical_digest((namespace, job_id))


def _natural_control_v3(model):
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from ..runtime.d13_cache_use_admission_v2 import _bundle_use_enabled_v2
    if type(model) is not AuthorityV2ModelEgressService:
        raise AuthorityUnavailable('D13 natural owner requires its actual installed model service')
    from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
    verifier = model._graph_verifier
    if type(verifier) is not PinnedCurrentModelEgressGraphVerifier:
        raise AuthorityUnavailable('D13 optional natural boundary needs its exact installed current verifier')
    bundle = verifier._artifact_draft_bundle
    if bundle is None:
        if verifier._natural_history is not None:
            raise AuthorityUnavailable('D13 optional legacy verifier has inconsistent actual history/bundle wiring')
        selected = False
    else:
        selected = _bundle_use_enabled_v2(bundle)
    if not selected:
        core = model._fences.core
        with core._lock:
            if core._db.in_transaction:
                _require_natural_no_cache_history_in_tx_v3(model, core._db)
            else:
                with core._tx() as db:
                    _require_natural_no_cache_history_in_tx_v3(model, db)
        return None
    if model._graph_verifier._natural_history is None or model._graph_verifier._natural_history._bundle is not bundle:
        raise AuthorityUnavailable('D13 enabled natural owner lost its exact installed history/bundle cohort')
    counter = model._d13_provider_http_counter_v1
    if counter is None:
        raise AuthorityUnavailable('D13 natural owner has no actual installed same-Core Counter producer')
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    service = model._fences.core._d13_cache_use_controls_v2.get(model._fences.namespace)
    if (type(service) is not InstalledD13CacheUseControlServiceV2 or service.core is not model._fences.core
            or service.fences is not model._fences or service.use_policy is not bundle.d13_cache_use_control_v2):
        raise AuthorityUnavailable('D13 natural original has no exact installed V3 owner cohort')
    return service


class _NaturalOriginalOwnerProofV3:
    def __init__(self, issuer, work, material, stage, generation, saved, parent_input=None):
        if issuer is not _ISSUER:
            raise TypeError('actual sealed natural original producer required')
        self.work, self.material, self.stage = work, material, stage
        self.generation_seal, self.saved_seal = generation.seal, saved.seal
        self.generation_terminal = (generation.state, generation.terminal_receipt_digest, generation.terminal_output_digest)
        self.frozen_digest = generation.frozen.frozen_input_digest
        self.registration = None
        self.created = False
        self.parent_input = parent_input
        _NATURAL_OWNER_PROOFS_V3[self] = (work, canonical_digest(material), stage,
            self.generation_seal, self.saved_seal, self.generation_terminal, self.frozen_digest, canonical_digest(parent_input))

    def require_v3(self, *, service, db, action):
        work = self.work
        state = _NATURAL_OWNER_PROOFS_V3.get(self)
        if (state != (work, canonical_digest(self.material), self.stage, self.generation_seal,
                    self.saved_seal, self.generation_terminal, self.frozen_digest, canonical_digest(self.parent_input))
                or _natural_control_v3(work.controller.service) is not service
                or work.controller.service._store._db is not db or not db.in_transaction or work.closed):
            raise AuthorityUnavailable('D13 natural owner lost its actual qualified Source Work/Core original')
        work._actual()
        if action != 'register':
            raise AuthorityUnavailable('D13 natural registration is not an arbitrary execution or close witness')
        require_natural_parent_open_in_tx_v3(service, db, work.parent_original_id)
        return dict(self.material), work.credential, work.permit


def prepare_d13_natural_stage_owner_v3(work):
    """Only a fully qualified actual sealed Graph stage can become a durable owner."""
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from ..runtime.dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
    from ..runtime.d13_cache_use_admission_v2 import require_actual_authority_natural_d13_payloads_v3
    from .d13_cache_use_contract_v2 import D13NaturalOriginalOwnerLocatorV3
    import secrets
    if type(work) is not AuthorityGraphReadWorkV3 or work.controller.kind != 'model':
        raise AuthorityUnavailable('actual natural model Source Work required')
    if not work.model_natural:
        return None
    service = _natural_control_v3(work.controller.service)
    if service is None:
        return None
    work._actual()
    stage = {'natural_generation': 'generation', 'natural_review': 'review'}[work.owner_model_work_kind]
    original = work.originals[(work.parent_original_id, stage)]
    generation_original = work.originals[(work.parent_original_id, 'generation')]
    require_actual_authority_natural_original_v3(original)
    require_actual_authority_natural_original_v3(generation_original)
    generation, saved = generation_original.saved, original.saved
    if (not work.complete or saved is None or saved.state != 'acquired'
            or saved.seal.job_id != work.request.job_id or saved.typed_request_digest != work.request.request_digest
            or saved.seal.acquire_operation_id != work.request.operation_id
            or stage == 'review' and (generation.state != 'terminal'
                or saved.seal.generation_original_operation_id != generation.seal.original_operation_id
                or saved.seal.generation_output_digest != generation.terminal_output_digest)):
        raise AuthorityUnavailable('D13 natural owner requires the actual acquired sealed stage and original current binding')
    payloads = require_actual_authority_natural_d13_payloads_v3(work, generation.frozen)
    kind = 'natural_' + stage + '_original'
    locator = D13NaturalOriginalOwnerLocatorV3(kind, saved.seal.job_id,
        work.parent_original_id, saved.seal.original_operation_id, stage)
    commitment = canonical_digest((locator, tuple(sorted((name, column.sha256, column.byte_count)
        for name, column in original.columns.items())), original.meta))
    material = dict(owner_ref=natural_stage_owner_ref_v3(work.namespace, work.request.job_id),
        owner_kind=kind, original_operation_id=saved.seal.original_operation_id,
        original_locator=locator, original_commitment=commitment,
        producer_binding_digest=_natural_binding_digest_v3(work.namespace, work.request, stage, commitment),
        payload_identities=payloads, subject=work.subject, permit_token=work.permit.token,
        permit_digest=canonical_digest(work.permit),
        retention_instance_ref='d13-natural-retention-v3:' + secrets.token_hex(24))
    parent_input = None
    if stage == 'review':
        from .current_authority_graph_read_v3 import PreparedAuthorityReviewCanonicalV3
        eof = original.frozen_eof
        if (type(eof) is not PreparedAuthorityReviewCanonicalV3 or not eof.complete
                or eof.work is not work or eof.result is not saved.frozen
                or eof.generation is not generation.seal or eof.output_digest != generation.terminal_output_digest):
            raise AuthorityUnavailable('D13 parent input capsule requires its actual already-parsed review Source EOF')
        eof._actual_v3()
        plan = generation.frozen.input.plan
        count = len(eof.output['semantic_segments']) if eof.semantic else 1
        identities = []
        for index in range(count):
            digest = canonical_digest({'plan': plan.plan_ref, 'output': eof.output_digest, 'index': index})
            identities.append((index, plan.final_operation_id if index == 0 else 'operation:natural-segment:' + digest,
                plan.final_effect_id if index == 0 else 'effect:natural-segment:' + digest))
        parent_input = dict(parent_original_id=work.parent_original_id,
            generation_original_id=generation.seal.original_operation_id,
            generation_original_digest=canonical_digest(generation.seal),
            review_original_id=saved.seal.original_operation_id, review_original_digest=canonical_digest(saved.seal),
            plan_ref=plan.plan_ref.ref, plan_revision=plan.plan_ref.version,
            first_operation_id=plan.final_operation_id, first_effect_id=plan.final_effect_id,
            whole_output_digest=eof.output_digest, child_count=count, child_identities=tuple(identities),
            child_identity_digest=canonical_digest(tuple(identities)), source_column_digest=eof.column.sha256,
            source_column_bytes=eof.column.byte_count, producer_binding_digest=canonical_digest((
                'd13.actual-parent-input-identity.v3', generation.seal, saved.seal,
                eof.column.sha256, eof.column.byte_count, work.selection_digest, canonical_digest(work.permit))))
    return _NaturalOriginalOwnerProofV3(_ISSUER, work, material, stage, generation, saved, parent_input=parent_input)


def _natural_binding_digest_v3(namespace, intent, stage, commitment):
    return canonical_digest(('d13.actual-natural-model-producer.v3', namespace, intent.authority_id,
        intent.job_id, intent.operation_id, intent.request_digest, intent.binding_digest, stage, commitment))


class _NaturalTransferProofV3:
    def __init__(self, issuer, source, predecessor, successor, retention):
        if issuer is not _ISSUER:
            raise TypeError('actual sealed successor transfer producer required')
        self.source, self.predecessor, self.successor, self.retention = source, predecessor, successor, retention
        _NATURAL_TRANSFER_PROOFS_V3[self] = (source, predecessor, successor, retention)


def _natural_transfer_closure_v3(proof, service, db):
    if _NATURAL_TRANSFER_PROOFS_V3.get(proof) != (proof.source, proof.predecessor, proof.successor, proof.retention):
        raise AuthorityUnavailable('D13 transfer lost its actual sealed successor producer')
    source, old, new, retained = proof.source, proof.predecessor, proof.successor, proof.retention
    source.require_v3(service=service, db=db, action='register')
    if (service._owner_operation_v3(db, new.owner_ref, 'owner_register') != new
            or service._owner_operation_v3(db, old.owner_ref, 'owner_retention_release') != retained
            or retained.registration_digest != old.registration_digest
            or retained.retention_instance_ref != old.retention_instance_ref):
        raise AuthorityUnavailable('D13 successor transfer lacks the exact actual retained-release original')
    terminal_digest = None
    if old.owner_kind == 'counter_frame_draft':
        if new.owner_kind != 'natural_generation_original' or source.stage != 'generation':
            raise AuthorityUnavailable('D13 Counter frame can transfer only to its actual sealed natural generation')
    elif old.owner_kind == 'natural_generation_original':
        model = source.work.controller.service
        record = model._store._read(db, source.generation_seal.call_id)
        if record is None or record.state != 'observed':
            raise AuthorityUnavailable('D13 independent review has no actual completed Core generation')
        admission, report, terminal = model._store.read_admission_locked(db, record.intent)
        row = model._fences.fences._row(db, record.intent.operation_id)
        if (new.owner_kind != 'natural_review_original' or source.stage != 'review'
                or old.original_locator.original_id != source.saved_seal.generation_original_operation_id
                or record.intent.job_id != old.original_locator.job_id or terminal is None
                or source.generation_terminal[0] != 'terminal'
                or canonical_digest(terminal) != source.generation_terminal[1]
                or source.saved_seal.generation_output_digest != source.generation_terminal[2]
                or terminal.report_digest != report or terminal.observation_digest != record.observation_digest
                or row is None or row[6] != 'finished'
                or row[8:10] != (record.intent.call_id, terminal.finish_digest)
                or {value[:3] for value in old.payload_identities} != {value[:3] for value in new.payload_identities}):
            raise AuthorityUnavailable('D13 review transfer lost the actual same-generation terminal/output/payload owner')
        terminal_digest = canonical_digest(terminal)
    else:
        raise AuthorityUnavailable('D13 durable predecessor does not belong to this actual natural successor')
    transfer = canonical_digest(('d13.actual-natural-successor-transfer.v3', old.registration_digest,
        new.registration_digest, old.payload_digest, new.payload_digest, source.material['original_commitment'], terminal_digest))
    return old, dict(disposition_kind='transferred', disposition_ref=new.operation_id,
        disposition_digest=new.registration_digest, retention_release_ref=retained.operation_id,
        retention_release_digest=retained.retention_digest, successor_transfer_digest=transfer), source.work.credential


def register_d13_natural_stage_owner_v3(proof):
    """Register the actual successor before closing any predecessor obligation."""
    if proof is None:
        return
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    from .d13_provider_http_admission_v1 import read_runtime_counter_operations_for_call_v3, _read_counter_phase
    from .d13_core_counter_contract_v1 import D13CoreFrameIntentHeaderV7, d13_core_counter_from_wire_v1
    model = proof.work.controller.service
    service = _natural_control_v3(model)
    counter = model._d13_provider_http_counter_v1
    # The actual Counter producer lock precedes Core SQL and excludes a concurrent new Counter Body read.
    with counter._lock:
        with runtime_storage_operation_v3(service.core._db, operation_id=proof.work.permit.operation_id):
            with service.core._tx() as db, runtime_storage_quantum_v3(db):
                prior = service._owner_operation_v3(db, proof.material['owner_ref'], 'owner_register')
                if prior is not None:
                    if (prior.original_locator != proof.material['original_locator']
                            or prior.original_commitment != proof.material['original_commitment']
                            or prior.producer_binding_digest != proof.material['producer_binding_digest']
                            or {value[:3] for value in prior.payload_identities} !=
                                {value[:3] for value in proof.material['payload_identities']}):
                        raise AuthorityUnavailable('D13 natural replay cannot replace its original sealed producer/payload identity')
                    proof.registration = service._live_owner_v3(db, prior.owner_ref)
                    if proof.stage == 'review':
                        capsule = service._owner_operation_v3(db, prior.owner_ref, 'owner_parent_input')
                        if capsule is None:
                            raise AuthorityUnavailable('D13 existing review has no original input capsule; legacy_unknown')
                    return
                rows = read_runtime_counter_operations_for_call_v3(db, counter=counter,
                    namespace=service.authority_namespace, call_id=proof.generation_seal.call_id)
                if len(rows) != 1:
                    raise AuthorityUnavailable('D13 natural original has no one actual committed Counter frame')
                frame = d13_core_counter_from_wire_v1(_read_counter_phase(db, counter, rows[0][0], 'header'), D13CoreFrameIntentHeaderV7)
                counter_owner = service._owner_operation_v3(db, counter_frame_owner_ref_v3(service.namespace, frame.counter_operation_id), 'owner_register')
                if (counter_owner is None or counter_owner.original_locator.frame_intent_digest != frame.frame_intent_digest
                        or proof.frozen_digest not in (frame.raw_authority_digest, frame.compressed_authority_digest)
                        or not {value[:3] for value in proof.material['payload_identities']} <=
                            {value[:3] for value in counter_owner.payload_identities}):
                    raise AuthorityUnavailable('D13 actual sealed natural choice differs from its registered counted frame')
                predecessor_ref = (counter_owner.owner_ref if proof.stage == 'generation' else
                    natural_stage_owner_ref_v3(service.namespace, proof.generation_seal.job_id))
                predecessor = service._live_owner_v3(db, predecessor_ref)
                retained = service._owner_operation_v3(db, predecessor_ref, 'owner_retention_release')
                if retained is None:
                    raise AuthorityUnavailable('D13 actual predecessor final retention is unresolved; keep its original pins')
                successor = service.register_original_owner_in_tx_v3(db, proof)
                if proof.stage == 'review':
                    _record_actual_parent_input_in_tx_v3(service, db, proof, successor)
                closure = _NaturalTransferProofV3(_ISSUER, proof, predecessor, successor, retained)
                service.close_original_owner_in_tx_v3(db, closure)
                proof.registration, proof.created = successor, True


def record_d13_natural_scope_retention_v3(proof):
    if proof is None or not proof.created:
        return
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    service = _natural_control_v3(proof.work.controller.service)
    material = dict(retention_instance_ref=proof.registration.retention_instance_ref,
        scope_operation_id=proof.work.operation.operation_id, resource_selection_digest=proof.work.selection_digest,
        producer_binding_digest=canonical_digest(('d13.actual-natural-source-retention-release.v3',
            proof.registration.registration_digest, proof.registration.retention_instance_ref,
            proof.work.operation.operation_id, proof.work.selection_digest)))
    final = _ActualOwnerRetentionProofV3(_ISSUER, producer=proof, registration=proof.registration,
        credential=proof.work.credential, material=material)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-natural-retention:' + proof.registration.owner_ref):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            return service.record_original_owner_retention_in_tx_v3(db, final)


def _require_actual_natural_retention_v3(proof, service):
    from .current_authority_graph_read_v3 import actual_authority_graph_release_v3
    original = proof.producer
    state = _NATURAL_OWNER_PROOFS_V3.get(original)
    if (type(original) is not _NaturalOriginalOwnerProofV3 or state is None or original.registration is not proof.registration
            or not original.created or not original.work.closed or not original.work.operation.closed
            or actual_authority_graph_release_v3(original.work) is not original.work.operation
            or original.work.controller.service._fences.core is not service.core
            or original.material['retention_instance_ref'] != proof.registration.retention_instance_ref):
        raise AuthorityUnavailable('D13 natural retention is not the actual registered Source scope final release')


def require_d13_natural_model_execution_in_tx_v3(db, model, intent):
    if not intent.job_id.startswith(('natural-generation-job:', 'natural-review-job:')):
        return
    service = _natural_control_v3(model)
    if service is None:
        return
    record = model._store.read_locked(db, intent)
    registration = service._live_owner_v3(db, natural_stage_owner_ref_v3(service.namespace, intent.job_id))
    locator = registration.original_locator
    if (registration.owner_kind == 'natural_review_original'
            and service._owner_operation_v3(db, registration.owner_ref, 'owner_parent_input') is None):
        raise AuthorityUnavailable('D13 historical review cannot start execution without its actual input capsule')
    if (locator.job_id != intent.job_id or registration.owner_kind != 'natural_' + locator.stage + '_original'
            or registration.producer_binding_digest != _natural_binding_digest_v3(service.namespace,
                intent, locator.stage, registration.original_commitment)
            or not model._store.is_fence_bound_locked(db, intent) or record.state not in ('prepared', 'dispatch_started')):
        raise AuthorityUnavailable('D13 actual natural original execution was closed, changed or never admitted')
    from .d13_cache_use_contract_v2 import payload_key_v2
    for identity in registration.payload_identities:
        pin_id = 'd13-owner-pin-v3:' + canonical_digest((service.namespace, registration.owner_ref,
            payload_key_v2(service.namespace, identity)))
        row = db.execute('SELECT state,consumer_owner_ref FROM authority_d13_cache_use_pins_v2 WHERE namespace=? AND pin_id=?',
            (service.authority_namespace, pin_id)).fetchone()
        if row != ('active', registration.owner_ref):
            raise AuthorityUnavailable('D13 natural execution lost its exact real active payload ownership')


def require_actual_natural_source_successor_v3(work, registration):
    matches = [proof for proof in _NATURAL_OWNER_PROOFS_V3
        if proof.work is work and proof.registration is registration]
    if len(matches) != 1:
        raise AuthorityUnavailable('D13 source successor has no actual same-Work Core acknowledgement')
    proof = matches[0]
    work._actual()
    if (registration.original_locator != proof.material['original_locator']
            or registration.original_commitment != proof.material['original_commitment']
            or registration.producer_binding_digest != proof.material['producer_binding_digest']
            or {value[:3] for value in registration.payload_identities} !=
                {value[:3] for value in proof.material['payload_identities']}):
        raise AuthorityUnavailable('D13 source receiver cannot adopt a different acknowledged sealed successor')
    return registration


def _require_actual_source_successor_in_tx_v3(service, db, old, material):
    from .d13_cache_use_contract_v2 import cache_use_result_from_wire_v3, D13OwnerRegistrationReceiptV3
    import json
    row = db.execute('SELECT action,result_json FROM authority_d13_cache_use_operations_v2 '
        'WHERE namespace=? AND operation_id=?', (service.authority_namespace, material['disposition_ref'])).fetchone()
    if row is None or row[0] != 'owner_register':
        raise AuthorityUnavailable('D13 Source transfer has no actual committed successor registration')
    successor = cache_use_result_from_wire_v3(json.loads(row[1]))
    if (type(successor) is not D13OwnerRegistrationReceiptV3
            or successor.owner_kind not in ('natural_generation_original', 'natural_review_original')
            or successor.registration_digest != material['disposition_digest']
            or successor.permit_token != old.permit_token or successor.permit_digest != old.permit_digest
            or not {identity[:3] for identity in old.payload_identities} <=
                {identity[:3] for identity in successor.payload_identities}
            or service._live_owner_v3(db, successor.owner_ref) != successor):
        raise AuthorityUnavailable('D13 actual Source successor does not own this exact original permit/payload')
    expected = canonical_digest(('d13.source-receiver-transfer.v3', old.registration_digest,
        successor.registration_digest, tuple(identity[:3] for identity in old.payload_identities)))
    if material['successor_transfer_digest'] != expected:
        raise AuthorityUnavailable('D13 Source transfer commitment differs from its actual confirmed successor')


def refuse_closed_d13_natural_original_before_body_v3(model, intent):
    """Existing closed original metadata rejects execution replay before frozen Body."""
    if not intent.job_id.startswith(('natural-generation-job:', 'natural-review-job:')):
        return
    service = _natural_control_v3(model)
    if service is None:
        return
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    with runtime_storage_operation_v3(service.core._db, operation_id=intent.operation_id):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            service._policy(db)
            owner_ref = natural_stage_owner_ref_v3(service.namespace, intent.job_id)
            if service._owner_operation_v3(db, owner_ref, 'owner_register') is not None:
                registration = service._live_owner_v3(db, owner_ref)
                if (registration.owner_kind == 'natural_review_original'
                        and service._owner_operation_v3(db, owner_ref, 'owner_parent_input') is None):
                    raise AuthorityUnavailable('D13 historical review has no actual input capsule; Body replay remains HOLD')


def natural_receiver_owner_ref_v3(namespace, permit, retention_instance_ref, selection_digest):
    return 'd13-natural-receiver-v3:' + canonical_digest((namespace, permit.operation_id,
        permit.token, retention_instance_ref, selection_digest))


def _natural_live_owner_for_receiver_in_tx_v3(service, db, locator, server):
    """Only the actual live generation or its confirmed live review transfer authorizes Body."""
    require_natural_parent_open_in_tx_v3(service, db, locator.parent_original_id)
    from .d13_cache_use_contract_v2 import D13NaturalOriginalOwnerLocatorV3
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    from .d13_provider_http_admission_v1 import read_runtime_counter_operations_for_call_v3, _read_counter_phase
    from .d13_core_counter_contract_v1 import D13CoreFrameIntentHeaderV7, d13_core_counter_from_wire_v1
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    model = server._v2_model_egress[service.authority_namespace]
    counter = model._d13_provider_http_counter_v1
    expected = natural_job_ids_v2(service.namespace, locator.parent_original_id, 'generation')
    if (type(counter) is not InstalledD13CoreCounterServiceV1 or counter.core is not service.core
            or (locator.generation_job_id, locator.generation_original_id, locator.generation_call_id) !=
                (expected[0], expected[1], expected[3])):
        raise AuthorityUnavailable('D13 natural receiver lost its actual same-Core Counter/generation identity')
    generation = service._owner_operation_v3(db,
        natural_stage_owner_ref_v3(service.namespace, locator.generation_job_id), 'owner_register')
    if generation is None:
        rows = read_runtime_counter_operations_for_call_v3(db, counter=counter,
            namespace=service.authority_namespace, call_id=locator.generation_call_id)
        if len(rows) != 1:
            raise AuthorityUnavailable('D13 original has no unique actual Counter call/header; legacy_unknown')
        frame = d13_core_counter_from_wire_v1(_read_counter_phase(db, counter, rows[0][0], 'header'), D13CoreFrameIntentHeaderV7)
        counted = service._owner_operation_v3(db,
            counter_frame_owner_ref_v3(service.namespace, frame.counter_operation_id), 'owner_register')
        if (counted is None or counted.original_locator.frame_intent_digest != frame.frame_intent_digest
                or frame.c02_operation_id != locator.parent_original_id or frame.generation_call_id != locator.generation_call_id
                or locator.generation_frozen_input_digest not in (frame.raw_authority_digest, frame.compressed_authority_digest)):
            raise AuthorityUnavailable('D13 natural seal differs from its actual registered Counter choice/header')
        birth = service._owner_operation_v3(db, counted.owner_ref, 'owner_counter_birth')
        if (birth is None or birth.registration_digest != counted.registration_digest
                or birth.parent_original_id != locator.parent_original_id
                or birth.counter_operation_id != frame.counter_operation_id
                or birth.generation_call_id != locator.generation_call_id
                or birth.frame_intent_id != frame.frame_intent_id
                or birth.frame_intent_digest != frame.frame_intent_digest
                or birth.draft_commitment != counted.original_commitment):
            raise AuthorityUnavailable('D13 queued generation has no exact actual Counter birth/header producer')
        if locator.review_job_id is not None:
            raise AuthorityUnavailable('D13 review cannot use an unregistered generation')
        live = service._live_owner_v3(db, counted.owner_ref)
        _require_owner_payload_pins_in_tx_v3(service, db, live)
        if locator.generation_frozen_input_digest == frame.raw_authority_digest:
            return live, ()
        selected = []
        for binding in frame.block_bindings:
            matches = [value for value in live.payload_identities
                if value[:2] == (binding.metadata_ref, binding.payload_digest)]
            if len(matches) != 1:
                raise AuthorityUnavailable('D13 compressed initial original lost its exact counted selected payload')
            selected.append(matches[0])
        from .d13_cache_use_contract_v2 import owner_payloads_v3
        return live, owner_payloads_v3(tuple(selected))
    if (type(generation.original_locator) is not D13NaturalOriginalOwnerLocatorV3
            or generation.owner_kind != 'natural_generation_original'
            or generation.original_locator.parent_original_id != locator.parent_original_id
            or generation.original_locator.original_id != locator.generation_original_id):
        raise AuthorityUnavailable('D13 natural receiver has no exact registered generation original; legacy_unknown')
    closed = service._owner_operation_v3(db, generation.owner_ref, 'owner_close')
    if closed is None:
        if locator.review_job_id is not None:
            raise AuthorityUnavailable('D13 natural review has no confirmed actual generation transfer')
        live = service._live_owner_v3(db, generation.owner_ref)
    else:
        if closed.disposition_kind != 'transferred' or closed.registration_digest != generation.registration_digest:
            raise AuthorityUnavailable('D13 generation original execution is permanently closed')
        row = db.execute('SELECT action,result_json FROM authority_d13_cache_use_operations_v2 '
            'WHERE namespace=? AND operation_id=?', (service.authority_namespace, closed.disposition_ref)).fetchone()
        from .d13_cache_use_contract_v2 import cache_use_result_from_wire_v3, D13OwnerRegistrationReceiptV3
        import json
        successor = None if row is None or row[0] != 'owner_register' else cache_use_result_from_wire_v3(json.loads(row[1]))
        if (type(successor) is not D13OwnerRegistrationReceiptV3
                or type(successor.original_locator) is not D13NaturalOriginalOwnerLocatorV3
                or successor.owner_kind != 'natural_review_original'
                or successor.registration_digest != closed.disposition_digest
                or successor.original_locator.parent_original_id != locator.parent_original_id
                or locator.review_job_id is not None and
                    (successor.original_locator.job_id, successor.original_locator.original_id) !=
                        (locator.review_job_id, locator.review_original_id)
                or {value[:3] for value in successor.payload_identities} !=
                    {value[:3] for value in generation.payload_identities}):
            raise AuthorityUnavailable('D13 closed generation has no exact confirmed independent-review successor')
        live = service._live_owner_v3(db, successor.owner_ref)
    if (live.owner_kind == 'natural_review_original'
            and service._owner_operation_v3(db, live.owner_ref, 'owner_parent_input') is None):
        raise AuthorityUnavailable('D13 historical review input capsule is unknown before frozen Body')
    _require_owner_payload_pins_in_tx_v3(service, db, live)
    return live, live.payload_identities


def _require_owner_payload_pins_in_tx_v3(service, db, registration):
    from .d13_cache_use_contract_v2 import payload_key_v2
    for identity in registration.payload_identities:
        pin_id = 'd13-owner-pin-v3:' + canonical_digest((service.namespace, registration.owner_ref,
            payload_key_v2(service.namespace, identity)))
        row = db.execute('SELECT state,consumer_owner_ref FROM authority_d13_cache_use_pins_v2 '
            'WHERE namespace=? AND pin_id=?', (service.authority_namespace, pin_id)).fetchone()
        if row != ('active', registration.owner_ref):
            raise AuthorityUnavailable('D13 natural original lost its actual registered payload retention')


def prepare_authenticated_d13_natural_receiver_in_tx_v3(server, service, db, *, credential,
        profile_id, manifest_digest, permit, natural_material):
    from .d13_cache_use_contract_v2 import D13NaturalReceiverOwnerLocatorV3
    fields = {'parent_original_id', 'generation_job_id', 'generation_original_id',
        'review_job_id', 'review_original_id', 'generation_call_id', 'generation_frozen_input_digest',
        'retention_instance_ref', 'selection_digest'}
    if (type(natural_material) is not dict or set(natural_material) != fields
            or permit.operation not in ('read', 'write') or permit.subject != 'mtls:sha256:' + credential.certificate_sha256
            or db is not service.core._db or not db.in_transaction):
        raise AuthorityUnavailable('D13 natural receiver requires its exact authenticated active READ original')
    admission = _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
    owner_ref = natural_receiver_owner_ref_v3(service.namespace, permit,
        natural_material['retention_instance_ref'], natural_material['selection_digest'])
    locator = D13NaturalReceiverOwnerLocatorV3('graph_source_receiver',
        natural_material['parent_original_id'], natural_material['generation_job_id'],
        natural_material['generation_original_id'], natural_material['generation_call_id'],
        natural_material['generation_frozen_input_digest'], natural_material['review_job_id'],
        natural_material['review_original_id'], permit.operation_id, permit.token,
        canonical_digest(permit), owner_ref, natural_material['retention_instance_ref'],
        natural_material['selection_digest'])
    live, payloads = _natural_live_owner_for_receiver_in_tx_v3(service, db, locator, server)
    if live.owner_kind == 'natural_review_original':
        from dataclasses import replace
        locator = replace(locator, review_job_id=live.original_locator.job_id,
            review_original_id=live.original_locator.original_id)
    material = dict(owner_ref=owner_ref, owner_kind='graph_source_receiver',
        original_operation_id=permit.operation_id, original_locator=locator,
        original_commitment=canonical_digest(('d13.natural-receiver-original.v3', locator, live.registration_digest)),
        producer_binding_digest=canonical_digest(('d13.actual-natural-receiver.v3', locator,
            canonical_digest(permit), admission['admission_digest'])),
        payload_identities=payloads, subject=permit.subject, permit_token=permit.token,
        permit_digest=canonical_digest(permit), peer_admission_digest=admission['admission_digest'],
        process_incarnation=admission['process_incarnation'],
        producer_kind_version='sylanne3.d13.graph-source-receiver.v3',
        retention_instance_ref=locator.retention_id)
    return _AuthenticatedSourceReceiverProofV3(_ISSUER, server=server, service=service,
        credential=credential, profile_id=profile_id, manifest_digest=manifest_digest,
        permit=permit, material=material, admission=admission)


class D13NaturalRosterNotTerminalV3(AuthorityUnavailable):
    """An actual finite parent still has execution or retained-reader obligations."""


_NATURAL_ROSTER_CLOSE_PROOFS_V3 = WeakKeyDictionary()


class _NaturalRosterClosureProofV3:
    def __init__(self, issuer, *, service, maintenance, head, metadata_proof, credential,
            context, birth, current, committed, execution_head, execution_rows, model):
        if issuer is not _ISSUER:
            raise TypeError('actual installed roster closure producer required')
        self.service, self.maintenance, self.head = service, maintenance, head
        self.metadata_proof, self.credential, self.context = metadata_proof, credential, context
        self.birth, self.current, self.committed = birth, current, committed
        self.execution_head, self.execution_rows, self.model = execution_head, execution_rows, model
        _NATURAL_ROSTER_CLOSE_PROOFS_V3[self] = (service, maintenance, head, metadata_proof, credential,
            context, birth, current, committed, execution_head, execution_rows, model)


def _natural_roster_closure_v3(proof, service, db):
    from ..runtime.d13_natural_original_use_v3 import require_actual_authority_natural_roster_outbound_v3
    from .natural_disposition_maintenance_v1 import ORIGINAL_TABLE
    from .v2_contract import ExecutionBindingV2, FencePermitV2, from_wire
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    state = _NATURAL_ROSTER_CLOSE_PROOFS_V3.get(proof)
    if (state is None or state != (service, proof.maintenance, proof.head, proof.metadata_proof,
            proof.credential, proof.context, proof.birth, proof.current, proof.committed,
            proof.execution_head, proof.execution_rows, proof.model) or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 roster closure lost its actual independently frozen Core producer')
    maintenance, roster = proof.maintenance, proof.head[2]
    admissions, observations, adoptions, context = require_actual_authority_natural_roster_outbound_v3(
        proof.metadata_proof, maintenance, proof.head)
    if context is not proof.context or not len(admissions) == len(observations) == len(adoptions) == len(roster.children):
        raise AuthorityUnavailable('D13 final roster metadata does not cover its complete immutable child manifest')
    context.require_current('business')
    maintenance.owner._require_projection_pointer_in_tx_v1(db, context)
    row = db.execute('SELECT payload_json,payload_digest,signature FROM ' + ORIGINAL_TABLE +
        ' WHERE authority_namespace=? AND installation_id=? AND kind IN (\'roster_committed\',\'maintenance_committed\') '
        "AND json_extract(payload_json,'$.parent_original_id')=? "
        "ORDER BY json_extract(payload_json,'$.payload.next_revision') DESC LIMIT 1",
        (service.authority_namespace, service.installation_id, roster.parent_original_id)).fetchone()
    actual = None if row is None else maintenance.originals._decode(row)
    if actual != proof.committed or actual.payload['next_revision'] != proof.head[1]:
        raise AuthorityUnavailable('D13 parent closure no longer names its latest actually committed complete roster')
    review_job = natural_job_ids_v2(
        service.namespace, roster.parent_original_id, 'review')[0]
    review = service._live_owner_v3(db, natural_stage_owner_ref_v3(service.namespace, review_job))
    if (review.owner_kind != 'natural_review_original' or review.original_locator.parent_original_id != roster.parent_original_id
            or review.original_locator.original_id != roster.review_original_operation_id):
        raise AuthorityUnavailable('D13 roster belongs to another actual independent review original')
    generation_job = natural_job_ids_v2(service.namespace, roster.parent_original_id, 'generation')[0]
    generation = service._owner_operation_v3(db, natural_stage_owner_ref_v3(service.namespace, generation_job), 'owner_register')
    transferred = None if generation is None else service._owner_operation_v3(db, generation.owner_ref, 'owner_close')
    if (generation is None or generation.original_locator.original_id != roster.generation_original_operation_id
            or transferred is None or transferred.disposition_kind != 'transferred'
            or transferred.disposition_ref != review.operation_id or transferred.disposition_digest != review.registration_digest):
        raise AuthorityUnavailable('D13 final roster lost its exact confirmed generation-to-review transfer')
    retained = _actual_parent_retention_in_tx_v3(service, db, roster.parent_original_id, generation, review)
    model = proof.model
    if model._store._db is not db or model._fences is not service.fences:
        raise AuthorityUnavailable('D13 roster closure lost its actual same-Core model terminal producer')
    model_terminals = []
    for stage in ('generation', 'review'):
        ids = natural_job_ids_v2(service.namespace, roster.parent_original_id, stage)
        record = model._store._read(db, ids[3])
        if record is None or record.state != 'observed' or record.intent.job_id != ids[0]:
            raise D13NaturalRosterNotTerminalV3('D13 complete parent model stage is not actually observed')
        admission, report, terminal = model._store.read_admission_locked(db, record.intent)
        fence = service.fences.fences._row(db, record.intent.operation_id)
        if (terminal is None or terminal.report_digest != report or terminal.observation_digest != record.observation_digest
                or record.observation_digest != proof.birth.payload[stage + '_observation_digest']
                or fence is None or fence[6] != 'finished' or fence[10] is not None
                or fence[8:10] != (record.intent.call_id, terminal.finish_digest)):
            raise AuthorityUnavailable('D13 roster has no exact actual model admission/report/terminal/fence chain')
        model_terminals.append(canonical_digest((admission, terminal)))
    owner = service.core._row(db, service.authority_namespace)
    execution = maintenance.execution
    effects = []
    for child, admission, observed, adoption in zip(roster.children, admissions, observations, adoptions):
        effect = execution._read_current_effect_locked_v4(db, effect_id=child.effect_id,
            execution_head=proof.execution_head, execution_rows=proof.execution_rows, owner=owner)
        if effect.state != 'observed' or effect.observation_outcome not in ('accepted', 'delivered'):
            raise D13NaturalRosterNotTerminalV3('D13 complete child roster still has an absent or unknown effect')
        mutation = execution.fences.mutation_locked(db, effect.mutation_id)
        completed = None if mutation is None else execution._completed_result(mutation)
        if completed is None or completed[0] != observed:
            raise AuthorityUnavailable('D13 outbound adoption differs from the independently verified Core observation')
        binding = observed.pending.platform_observation.binding
        if (type(binding) is not ExecutionBindingV2 or observed.pending.phase != 'observed'
                or (binding.origin.operation_id, binding.origin.effect_id) != (child.operation_id, child.effect_id)
                or admission.admission.operation_id != child.operation_id
                or admission.admission.effect_id != child.effect_id or admission.admission.payload_digest != child.payload_digest
                or binding.admission_receipt_digest != admission.receipt_digest
                or adoption['schema'] != 'd13.outbound_adoption.v1'
                or adoption['observation_digest'] != canonical_digest(observed)):
            raise AuthorityUnavailable('D13 complete child final/admission/observation identity differs')
        attempt = 'natural-final:' + canonical_digest({'namespace': service.namespace.as_tuple,
            'operation_id': child.operation_id})[:48]
        final = service.fences.fences._row(db, attempt)
        adopted = from_wire(adoption['permit'])
        adopted_row = service.fences.fences._row(db, adopted.operation_id)
        if (final is None or final[6] != 'finished' or final[10] is not None
                or type(adopted) is not FencePermitV2 or adopted.operation != 'write'
                or adopted_row is None or service.fences.fences._permit(adopted_row) != adopted
                or adopted_row[6] != 'finished' or adopted_row[10] is not None
                or adopted_row[8:10] != (adoption['operation_id'], adoption['finish_digest'])):
            raise D13NaturalRosterNotTerminalV3('D13 actual child final or outbound adoption write is still unresolved')
        effects.append((child.operation_id, child.effect_id, admission.receipt_digest,
            canonical_digest(observed), canonical_digest(adoption), canonical_digest(effect)))
    disposition = canonical_digest(('d13.actual-complete-natural-roster.v3', review.registration_digest,
        proof.birth.digest, proof.current.digest, proof.committed.digest, roster.identity_manifest_digest,
        tuple(model_terminals), tuple(effects), retained.retention_digest))
    return review, dict(disposition_kind='terminal', disposition_ref=proof.committed.original_ref,
        disposition_digest=disposition, retention_release_ref=retained.operation_id,
        retention_release_digest=retained.retention_digest, successor_transfer_digest=None), proof.credential


def close_authenticated_d13_natural_roster_v3(server, service, *, credential, profile_id,
        manifest_digest, permit, parent_original_id):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    from ..runtime.d13_natural_original_use_v3 import (prepare_actual_authority_natural_roster_outbound_v3,
        require_actual_authority_natural_roster_outbound_v3)
    from .natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from .v2_contract import decode_bytes
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    service.core._require(credential, 'd13_cache_use_close_original', service.authority_namespace, permit.holder)
    _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
    owner = server._owner_stop_reply_services_v1.get((service.authority_namespace, service.installation_id))
    maintenance = None if owner is None else owner.natural_disposition_maintenance
    if type(maintenance) is not InstalledNaturalDispositionMaintenanceServiceV1 or maintenance.owner.core is not service.core:
        raise AuthorityUnavailable('D13 roster closure has no actual independent installed natural metadata producer')
    if permit.operation not in ('read', 'write'):
        raise AuthorityUnavailable('D13 parent metadata closure requires its actual existing READ or borrowed WRITE scope')
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-parent-closure-state:' + parent_original_id):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            service._policy(db)
            actual = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                (service.authority_namespace, permit.operation_id)).fetchone()
            if actual is None or decode_bytes(actual[0]) != permit or actual[1] not in ('active', 'finished'):
                raise AuthorityUnavailable('D13 parent closure lost its exact actual original permit')
            review_ref = natural_stage_owner_ref_v3(service.namespace,
                natural_job_ids_v2(service.namespace, parent_original_id, 'review')[0])
            prior = actual_natural_parent_closure_in_tx_v3(service, db, parent_original_id)
            if prior is not None:
                return prior
            capsule = service._owner_operation_v3(db, review_ref, 'owner_parent_input')
            parse_original = None
            if capsule is None:
                generation_ref = natural_stage_owner_ref_v3(service.namespace,
                    natural_job_ids_v2(service.namespace, parent_original_id, 'generation')[0])
                parse_original = service._owner_operation_v3(db, generation_ref, 'owner_generation_parse')
                if parse_original is None:
                    raise AuthorityUnavailable('D13 parent has no actual input capsule or generation parse original; legacy_unknown')
            verdict = service._owner_operation_v3(db, review_ref, 'owner_review_verdict')
            stopped = _actual_owner_stop_for_parent_in_tx_v3(service, db, parent_original_id, permit.generation)
    if capsule is None:
        return _close_actual_pre_review_parent_v3(server, service, maintenance, parse_original,
            credential=credential, permit=permit)
    snapshot = maintenance._snapshot(parent_original_id=parent_original_id)
    if (snapshot is None or stopped is not None or verdict is not None and verdict.verdict in ('rewrite', 'hold')
            or any(child.continuation_state in ('cancelled', 'superseded') for child in snapshot[4][2].children)):
        return _close_actual_permanent_parent_v3(server, service, maintenance, capsule,
            credential=credential, permit=permit)
    context, _, _, _, head, _, _, _ = snapshot
    birth, current = maintenance._require_committed_head_v1(head)
    committed = maintenance.originals.latest_committed(parent_original_id)
    metadata = prepare_actual_authority_natural_roster_outbound_v3(maintenance, head,
        credential=credential, subject=permit.subject)
    try:
        _, _, _, actual_context = require_actual_authority_natural_roster_outbound_v3(metadata, maintenance, head)
        with runtime_storage_operation_v3(service.core._db, operation_id='d13-natural-parent-close:' + parent_original_id):
            with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                service.fences._current_locked(db, deletion, execution,
                    holder=permit.holder, generation=permit.generation)
                service._policy(db)
                row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                    (service.authority_namespace, permit.operation_id)).fetchone()
                if (row is None or decode_bytes(row[0]) != permit or row[1] not in ('active', 'finished')
                        or permit.subject != 'mtls:sha256:' + credential.certificate_sha256):
                    raise AuthorityUnavailable('D13 parent closure lost its actual installed original permit/subject')
                review_job = natural_job_ids_v2(service.namespace, parent_original_id, 'review')[0]
                prior = service._owner_operation_v3(db, natural_stage_owner_ref_v3(service.namespace, review_job), 'owner_close')
                if prior is not None:
                    return prior
                verified_head, rows = maintenance.execution.journal._scan_locked()
                if verified_head != execution:
                    raise AuthorityUnavailable('D13 roster close execution journal changed after its frozen boundary')
                proof = _NaturalRosterClosureProofV3(_ISSUER, service=service, maintenance=maintenance, head=head,
                    metadata_proof=metadata, credential=credential, context=actual_context, birth=birth, current=current,
                    committed=committed, execution_head=verified_head, execution_rows=rows,
                    model=server._v2_model_egress[service.authority_namespace])
                return service.close_original_owner_in_tx_v3(db, proof)
    finally:
        metadata.release_v3()


_NATURAL_REVIEW_VERDICT_PRODUCERS_V3 = WeakKeyDictionary()


def install_d13_natural_review_verdict_producer_v3(review_output_service, model_service):
    from .v2_natural_review_output_service import AuthorityV2NaturalReviewOutputService
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    if (type(review_output_service) is not AuthorityV2NaturalReviewOutputService
            or type(model_service) is not AuthorityV2ModelEgressService
            or review_output_service._store is not model_service._store
            or review_output_service._fences is not model_service._fences):
        raise AuthorityUnavailable('D13 review verdict producer requires the actual installed same-Core model/output services')
    prior = _NATURAL_REVIEW_VERDICT_PRODUCERS_V3.get(review_output_service)
    if prior is not None and prior is not model_service:
        raise AuthorityUnavailable('D13 actual review verdict producer cannot replace its installed model')
    _NATURAL_REVIEW_VERDICT_PRODUCERS_V3[review_output_service] = model_service


def record_actual_d13_natural_review_verdict_v3(review_output_service, *, credential, request):
    from .v2_natural_review_output_service import AuthorityV2NaturalReviewOutputService
    from .d13_cache_use_contract_v2 import (D13NaturalReviewVerdictReceiptV3,
        REVIEW_VERDICT_SCHEMA_V3, owner_operation_id_v3, PROTOCOL)
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(review_output_service) is not AuthorityV2NaturalReviewOutputService:
        raise AuthorityUnavailable('actual natural review parse lifecycle required')
    model = _NATURAL_REVIEW_VERDICT_PRODUCERS_V3.get(review_output_service)
    if model is None:
        raise AuthorityUnavailable('D13 review verdict producer lacks its actual installed bundle/model binding')
    service = _natural_control_v3(model)
    if service is None:
        return
    with review_output_service._delivery_lock:
        pending = review_output_service._d13_review_parse_v3.get(request.read_attempt_id)
        if (pending is None or pending[0] is not request
                or request.read_attempt_id not in review_output_service._inflight_deliveries
                or review_output_service._inflight_deliveries[request.read_attempt_id] is not None):
            raise AuthorityUnavailable('D13 verdict requires the actual original parse in its still-active Source delivery')
        _, original, observation, intent, terminal, permit, parsed, output = pending
    saved, generation, binding, seal_digest, intent_digest, terminal_digest = original
    if (saved.seal.original_operation_id != request.original_operation_id
            or generation.seal.original_operation_id != request.generation_original_operation_id
            or output.request is not request or output.verdict != parsed.verdict
            or output.output_digest != parsed.output_digest or output.observation_digest != observation.digest
            or terminal_digest != canonical_digest(terminal) or output.original_seal_digest != seal_digest):
        raise AuthorityUnavailable('D13 verdict lost its actual parsed original/seal/model observation')
    service.core._require(credential, 'd13_cache_use_register_original', service.authority_namespace, permit.holder)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-review-verdict:' + request.original_operation_id):
        with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
            anchor = service.fences._current_locked(db, deletion, execution,
                holder=permit.holder, generation=permit.generation)
            service.fences.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
            service._policy(db)
            registration = service._live_owner_v3(db, natural_stage_owner_ref_v3(service.namespace, request.job_id))
            record = model._store.read_locked(db, intent)
            admission, report, actual_terminal = model._store.read_admission_locked(db, intent)
            if (registration.owner_kind != 'natural_review_original'
                    or registration.original_locator.original_id != saved.seal.original_operation_id
                    or registration.original_locator.parent_original_id != request.parent_original_id
                    or record.state != 'observed' or record.observation_digest != observation.digest
                    or actual_terminal != terminal or terminal.report_digest != report
                    or terminal.observation_digest != record.observation_digest):
                raise AuthorityUnavailable('D13 parsed review verdict has no exact actual paid terminal/admission chain')
            stable = dict(parent_original_id=request.parent_original_id,
                generation_original_id=generation.seal.original_operation_id,
                generation_original_digest=canonical_digest(generation.seal),
                review_original_id=saved.seal.original_operation_id, review_original_digest=seal_digest,
                generation_output_digest=request.generation_output_digest, review_output_digest=parsed.output_digest,
                verdict=parsed.verdict, observation_digest=observation.digest,
                terminal_receipt_digest=terminal_digest, original_intent_digest=intent_digest,
                typed_model_request_digest=binding.typed_request_digest,
                parse_binding_digest=canonical_digest(('d13.actual-natural-review-parse.v3',
                    generation.seal, saved.seal, binding.typed_request_digest, observation.digest, parsed.output_digest, parsed.verdict)))
            prior = service._owner_operation_v3(db, registration.owner_ref, 'owner_review_verdict')
            if prior is not None:
                if (prior.registration_digest != registration.registration_digest
                        or any(getattr(prior, key) != value for key, value in stable.items())):
                    raise AuthorityUnavailable('D13 immutable natural review verdict cannot change on replay')
                return prior
            service._no_reclaim_v3(db)
            producer = dict(**stable, producer_permit_operation_id=permit.operation_id,
                producer_permit_digest=canonical_digest(permit))
            values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
                installation_id=service.installation_id, owner_ref=registration.owner_ref,
                registration_digest=registration.registration_digest, **producer,
                operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_review_verdict'),
                request_digest=canonical_digest((PROTOCOL, 'owner_review_verdict', registration.registration_digest, producer)),
                control_revision=service._revision(db), schema=REVIEW_VERDICT_SCHEMA_V3)
            values['verdict_digest'] = canonical_digest(values)
            return service._record(db, 'owner_review_verdict', D13NaturalReviewVerdictReceiptV3(**values))


def _record_actual_parent_input_in_tx_v3(service, db, proof, registration):
    from .d13_cache_use_contract_v2 import (D13NaturalParentInputReceiptV3,
        PARENT_INPUT_SCHEMA_V3, PROTOCOL, owner_operation_id_v3)
    proof.require_v3(service=service, db=db, action='register')
    if proof.stage != 'review' or proof.parent_input is None:
        raise AuthorityUnavailable('D13 complete parent input capsule needs its actual qualified review producer')
    material = proof.parent_input
    values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=registration.owner_ref,
        registration_digest=registration.registration_digest, **material,
        operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_parent_input'),
        request_digest=canonical_digest((PROTOCOL, 'owner_parent_input', registration.registration_digest, material)),
        control_revision=service._revision(db), schema=PARENT_INPUT_SCHEMA_V3)
    values['input_digest'] = canonical_digest(values)
    return service._record(db, 'owner_parent_input', D13NaturalParentInputReceiptV3(**values))


def require_natural_parent_open_in_tx_v3(service, db, parent_original_id):
    """Deny-only permanent barrier; absence grants neither Source nor execution."""
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    review_job = natural_job_ids_v2(service.namespace, parent_original_id, 'review')[0]
    owner_ref = natural_stage_owner_ref_v3(service.namespace, review_job)
    generation_ref = natural_stage_owner_ref_v3(service.namespace,
        natural_job_ids_v2(service.namespace, parent_original_id, 'generation')[0])
    if (service._owner_operation_v3(db, owner_ref, 'owner_parent_disposition') is not None
            or service._owner_operation_v3(db, owner_ref, 'owner_close') is not None
            or service._owner_operation_v3(db, generation_ref, 'owner_pre_review_disposition') is not None
            or db.execute("SELECT 1 FROM authority_d13_cache_use_operations_v2 WHERE namespace=? "
                "AND action='owner_unused_counter_disposition' "
                "AND json_extract(result_json,'$.parent_original_id')=? LIMIT 1",
                (service.authority_namespace, parent_original_id)).fetchone() is not None):
        raise AuthorityUnavailable('D13 natural parent input/continuation was permanently closed')


def require_actual_counter_parent_open_v3(counter, selector):
    if not counter._d13_use_enabled_v3():
        return
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    service = _control(counter)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-parent-use:' + selector.counter_operation_id):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            service._policy(db)
            require_natural_parent_open_in_tx_v3(service, db, selector.c02_operation_id)


def _actual_parent_retention_in_tx_v3(service, db, parent, generation, review):
    retained = service._owner_operation_v3(db, review.owner_ref, 'owner_retention_release')
    if retained is None or retained.registration_digest != review.registration_digest:
        raise D13NaturalRosterNotTerminalV3('D13 actual review Source retention has not been released')
    counted_rows = db.execute("SELECT json_extract(result_json,'$.owner_ref'),"
        "json_extract(result_json,'$.registration_digest') FROM authority_d13_cache_use_operations_v2 "
        "WHERE namespace=? AND action='owner_close' "
        "AND json_extract(result_json,'$.owner_ref') LIKE 'd13-counter-frame-owner-v3:%' "
        "AND json_extract(result_json,'$.disposition_kind')='transferred' "
        "AND json_extract(result_json,'$.disposition_ref')=? LIMIT 2",
        (service.authority_namespace, generation.operation_id)).fetchall()
    if len(counted_rows) != 1:
        raise AuthorityUnavailable('D13 final roster lost its one actual predecessor Counter transfer')
    counted = service._owner_operation_v3(db, counted_rows[0][0], 'owner_register')
    if (counted is None or counted.owner_kind != 'counter_frame_draft'
            or counted.registration_digest != counted_rows[0][1]):
        raise AuthorityUnavailable('D13 final roster predecessor Counter original differs')
    # A full identity manifest is closed only after all actual parent readers drain.
    pending = db.execute("SELECT 1 FROM authority_d13_cache_use_operations_v2 r WHERE r.namespace=? "
        "AND r.action='owner_register' AND json_extract(r.result_json,'$.owner_kind') IN "
        "('graph_source_receiver','authority_source_receiver','host_frame_receiver') "
        "AND (json_extract(r.result_json,'$.original_locator.parent_original_id')=? OR "
        "json_extract(r.result_json,'$.permit_token') IN (?,?,?)) AND NOT EXISTS("
        "SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=r.namespace AND c.action='owner_close' "
        "AND json_extract(c.result_json,'$.registration_digest')=json_extract(r.result_json,'$.registration_digest')) LIMIT 1",
        (service.authority_namespace, parent, review.permit_token, generation.permit_token, counted.permit_token)).fetchone()
    if pending is not None:
        raise D13NaturalRosterNotTerminalV3('D13 complete parent still has an actual retained execution receiver')
    return retained


def _actual_natural_model_census_in_tx_v3(service, db, model, capsule):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    from .v2_model_egress_contract import ModelNoDispatchWitnessV1
    from .v2_model_egress_wire import from_wire
    import json
    results = []
    if model._store._db is not db or model._fences is not service.fences:
        raise AuthorityUnavailable('D13 final parent model census crossed its actual Core producer')
    for stage in ('generation', 'review'):
        ids = natural_job_ids_v2(service.namespace, capsule.parent_original_id, stage)
        record = model._store._read(db, ids[3])
        if record is None or record.intent.job_id != ids[0]:
            raise AuthorityUnavailable('D13 parent has no exact original model row; unknown is not never-started')
        fence = service.fences.fences._row(db, record.intent.operation_id)
        if fence is None or fence[6] != 'finished' or fence[10] is not None:
            raise D13NaturalRosterNotTerminalV3('D13 original model call/fence is still active or pending')
        if record.state == 'observed':
            admission, report, terminal = model._store.read_admission_locked(db, record.intent)
            if (terminal is None or terminal.report_digest != report
                    or terminal.observation_digest != record.observation_digest
                    or fence[8:10] != (record.intent.call_id, terminal.finish_digest)):
                raise AuthorityUnavailable('D13 final model terminal lacks its exact admission/report/finished original')
            results.append((stage, 'observed', record.observation_digest, canonical_digest(terminal)))
            continue
        if stage != 'review' or record.state != 'prepared':
            raise D13NaturalRosterNotTerminalV3('D13 model dispatch has no actual independently confirmed terminal')
        row = db.execute('SELECT request_digest,witness_json,witness_digest,signature FROM authority_model_no_dispatch_witnesses_v1 '
            'WHERE namespace=? AND call_id=? AND authority_id=? AND installation_id=?',
            (service.authority_namespace, record.intent.call_id, record.intent.authority_id, service.installation_id)).fetchone()
        if row is None:
            raise D13NaturalRosterNotTerminalV3('D13 original prepared review has no actual no-dispatch witness')
        witness = from_wire(json.loads(row[1]), ModelNoDispatchWitnessV1)
        witness.require_signature_v1(model._graph_verifier._issuer._signer)
        permit = service.fences.fences._permit(fence)
        if (row[0] != witness.request.identity_digest or row[2:] != (witness.digest, witness.signature)
                or witness.request.intent != record.intent or witness.original_permit != permit
                or canonical_serialize(json.loads(row[1])) != row[1]
                or fence[8:10] != (record.intent.call_id, witness.finish_digest)
                or witness.finish_digest != service.fences.fences.model_terminal_finish_digest(record.intent, permit, 'not_dispatched')
                or db.execute('SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?', (record.intent.call_id,)).fetchone() is not None
                or db.execute('SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?', (record.intent.call_id,)).fetchone() is not None):
            raise AuthorityUnavailable('D13 model never-started scope differs from its actual signed absence/finish original')
        results.append((stage, 'never_started', None, witness.digest))
    return tuple(results)


def _actual_owner_stop_for_parent_in_tx_v3(service, db, parent, generation):
    from .owner_stop_reply_v1 import PLAN_SCHEMA, validate_owner_stop_reply_core_row_v1
    from ..runtime.lifecycle_operations_v1 import decode_original
    import json
    rows = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? "
        "AND json_extract(plan_json,'$.schema')=? AND json_extract(plan_json,'$.scope.c02_operation_id')=? "
        "AND json_extract(plan_json,'$.request.installation_id')=? ORDER BY rowid LIMIT 2",
        (service.authority_namespace, PLAN_SCHEMA, parent, service.installation_id)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise AuthorityUnavailable('D13 parent stop has ambiguous actual Owner control originals')
    row = rows[0]
    validate_owner_stop_reply_core_row_v1(row)
    plan, original = json.loads(row[7]), decode_original(json.loads(row[3]))
    if plan['scope']['namespace'] != asdict(service.namespace) or original.activation_generation != generation:
        raise AuthorityUnavailable('D13 parent stop original crossed its actual namespace/activation')
    return original.original_ref, original.original_digest.removeprefix('sha256:')


def _actual_absent_child_attempt_in_tx_v3(service, db, capsule, child, admission, graph_operations):
    from .v2_contract import decode_bytes, FenceNeverBegunReceiptV2, canonical_bytes
    from .natural_disposition_maintenance_v1 import ORIGINAL_TABLE
    _, operation, effect = child
    attempt = 'natural-final:' + canonical_digest({'namespace': service.namespace.as_tuple, 'operation_id': operation})[:48]
    final = service.fences.fences._row(db, attempt)
    dispatch = service.fences.fences._row(db, operation)
    if (dispatch is not None and (dispatch[6] != 'finished' or dispatch[10] is not None)
            or final is not None and (final[6] != 'finished' or final[10] is not None)):
        raise D13NaturalRosterNotTerminalV3('D13 child has an actual active first-write/dispatch attempt')
    if db.execute("SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND operation_id IN (?,?) "
            "AND state='pending' LIMIT 1", (service.authority_namespace, operation, attempt)).fetchone() is not None:
        raise D13NaturalRosterNotTerminalV3('D13 child has a pending actual execution mutation')
    if admission is not None:
        if (final is None or operation not in graph_operations
                or (admission.admission.operation_id, admission.admission.effect_id) != (operation, effect)):
            raise AuthorityUnavailable('D13 absent effect has no exact actually adopted final/admission original')
        return ('adopted_never_dispatched', canonical_digest((final[:7], final[8:11])), admission.receipt_digest)
    if operation in graph_operations:
        raise AuthorityUnavailable('D13 final Graph operation exists without its actual admission')
    if final is not None:
        rows = db.execute('SELECT payload_json,payload_digest,signature FROM ' + ORIGINAL_TABLE +
            " WHERE authority_namespace=? AND installation_id=? AND kind='rejected_no_commit' "
            "AND json_extract(payload_json,'$.payload.permit.operation_id')=? LIMIT 2",
            (service.authority_namespace, service.installation_id, attempt)).fetchall()
        if len(rows) != 1:
            raise D13NaturalRosterNotTerminalV3('D13 existing final write lacks its actual finished no-commit refusal')
        # The installed producer's private signature is independently verified by the caller.
        return ('finished_refusal', rows[0])
    never = db.execute('SELECT request_id,request_digest,receipt FROM authority_v2_never_begun WHERE operation_id=?',
        (attempt,)).fetchone()
    if never is None:
        # The new immutable parent disposition below is the permanent deny barrier for this proven absent attempt.
        return ('absent_before_parent_revocation', attempt)
    receipt = decode_bytes(never[2])
    if (type(receipt) is not FenceNeverBegunReceiptV2
            or never != (receipt.request_id, receipt.request_digest, canonical_bytes(receipt))
            or receipt.namespace != service.authority_namespace or receipt.installation_id != service.installation_id
            or receipt.operation_id != attempt):
        raise AuthorityUnavailable('D13 existing never-begun original differs from its actual child scope')
    return ('never_begun', canonical_digest(receipt))


_PERMANENT_PARENT_CLOSURES_V3 = WeakKeyDictionary()


class _PermanentNaturalParentClosureProofV3:
    def __init__(self, issuer, *, service, maintenance, model, capsule, metadata, context,
            credential, anchor, execution_head, execution_rows, birth=None, current=None, committed=None):
        if issuer is not _ISSUER:
            raise TypeError('actual permanent natural parent producer required')
        self.service, self.maintenance, self.model, self.capsule = service, maintenance, model, capsule
        self.metadata, self.context, self.credential = metadata, context, credential
        self.anchor, self.execution_head, self.execution_rows = anchor, execution_head, execution_rows
        self.birth, self.current, self.committed = birth, current, committed
        _PERMANENT_PARENT_CLOSURES_V3[self] = (service, maintenance, model, capsule, metadata, context,
            credential, anchor, execution_head, execution_rows, birth, current, committed)


def _permanent_natural_parent_closure_v3(proof, service, db):
    from ..runtime.d13_natural_original_use_v3 import require_actual_authority_natural_parent_census_v3
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    from .natural_disposition_maintenance_v1 import (ORIGINAL_TABLE, validate_original_terminal_fence_in_tx_v1)
    from .d13_cache_use_contract_v2 import (D13NaturalParentDispositionReceiptV3,
        PARENT_DISPOSITION_SCHEMA_V3, PROTOCOL, owner_operation_id_v3)
    from .v2_contract import ExecutionBindingV2, from_wire
    if (_PERMANENT_PARENT_CLOSURES_V3.get(proof) != (service, proof.maintenance, proof.model, proof.capsule,
            proof.metadata, proof.context, proof.credential, proof.anchor, proof.execution_head, proof.execution_rows,
            proof.birth, proof.current, proof.committed) or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 permanent parent disposition lost its actual frozen Core producer')
    capsule, maintenance, parent = proof.capsule, proof.maintenance, proof.capsule.parent_original_id
    facts, context = require_actual_authority_natural_parent_census_v3(proof.metadata, maintenance, capsule)
    fields = {'roster_head', 'admissions', 'outbounds', 'graph_final_operation_ids',
        'graph_snapshot_digest', 'graph_census_digest'}
    if (type(facts) is not dict or set(facts) != fields or context is not proof.context
            or len(facts['admissions']) != capsule.child_count or len(facts['outbounds']) != capsule.child_count):
        raise AuthorityUnavailable('D13 permanent parent requires its complete actually issued metadata census')
    context.require_current('business')
    maintenance.owner._require_projection_pointer_in_tx_v1(db, context)
    review = service._live_owner_v3(db, capsule.owner_ref)
    if (service._owner_operation_v3(db, capsule.owner_ref, 'owner_parent_input') != capsule
            or review.registration_digest != capsule.registration_digest
            or review.original_locator.original_id != capsule.review_original_id):
        raise AuthorityUnavailable('D13 cleanup cannot manufacture or replace its actual parent input identity capsule')
    generation = service._owner_operation_v3(db, natural_stage_owner_ref_v3(service.namespace,
        natural_job_ids_v2(service.namespace, parent, 'generation')[0]), 'owner_register')
    transferred = None if generation is None else service._owner_operation_v3(db, generation.owner_ref, 'owner_close')
    if (generation is None or generation.original_locator.original_id != capsule.generation_original_id
            or transferred is None or transferred.disposition_kind != 'transferred'
            or transferred.disposition_ref != review.operation_id or transferred.disposition_digest != review.registration_digest):
        raise AuthorityUnavailable('D13 permanent parent lost its actual confirmed generation/review lineage')
    retained = _actual_parent_retention_in_tx_v3(service, db, parent, generation, review)
    for output_service, model in tuple(_NATURAL_REVIEW_VERDICT_PRODUCERS_V3.items()):
        if model is proof.model:
            with output_service._delivery_lock:
                if any(request[0].parent_original_id == parent for request in output_service._d13_review_parse_v3.values()):
                    raise D13NaturalRosterNotTerminalV3('D13 actual review parse/Source delivery is still retained')
    models = _actual_natural_model_census_in_tx_v3(service, db, proof.model, capsule)
    verdict = service._owner_operation_v3(db, capsule.owner_ref, 'owner_review_verdict')
    stop = _actual_owner_stop_for_parent_in_tx_v3(service, db, parent, proof.anchor.activation_generation)
    head = facts['roster_head']
    if head is not None:
        roster = head[2]
        row = db.execute('SELECT payload_json,payload_digest,signature FROM ' + ORIGINAL_TABLE +
            " WHERE authority_namespace=? AND installation_id=? AND kind IN ('roster_committed','maintenance_committed') "
            "AND json_extract(payload_json,'$.parent_original_id')=? "
            "ORDER BY json_extract(payload_json,'$.payload.next_revision') DESC LIMIT 1",
            (service.authority_namespace, service.installation_id, parent)).fetchone()
        committed = None if row is None else maintenance.originals._decode(row)
        if (committed != proof.committed or proof.current is None
                or (roster.generation_original_operation_id, roster.generation_original_digest,
                    roster.review_original_operation_id, roster.review_original_digest, roster.whole_output_digest) !=
                    (capsule.generation_original_id, capsule.generation_original_digest,
                        capsule.review_original_id, capsule.review_original_digest, capsule.whole_output_digest)
                or tuple((child.index, child.operation_id, child.effect_id) for child in roster.children) != capsule.child_identities):
            raise AuthorityUnavailable('D13 permanent parent changed its independently signed complete roster')
    if verdict is not None and verdict.verdict in ('rewrite', 'hold'):
        if (head is not None or models[1][1] != 'observed'
                or verdict.registration_digest != review.registration_digest
                or (verdict.generation_original_id, verdict.generation_original_digest,
                    verdict.review_original_id, verdict.review_original_digest, verdict.generation_output_digest) !=
                    (capsule.generation_original_id, capsule.generation_original_digest,
                        capsule.review_original_id, capsule.review_original_digest, capsule.whole_output_digest)
                or verdict.observation_digest != models[1][2] or verdict.terminal_receipt_digest != models[1][3]):
            raise AuthorityUnavailable('D13 nonpass disposition has no exact actual paid verdict/terminal/original chain')
        kind, cause_ref, cause_digest = 'nonpass', verdict.operation_id, verdict.verdict_digest
    elif stop is not None:
        kind, cause_ref, cause_digest = 'owner_stop', *stop
    elif (head is not None and proof.current.kind == 'maintenance_prepared'
            and any(child.continuation_state == 'superseded'
                and child.cause_kind == 'adopted_relevant_ingress' and child.cause_ref is not None
                and child.cause_digest is not None for child in head[2].children)):
        kind, cause_ref, cause_digest = 'superseded', proof.current.original_ref, proof.current.digest
    else:
        raise D13NaturalRosterNotTerminalV3('D13 parent has no actual nonpass, permanent Owner stop or signed supersession')
    graph_operations = tuple(facts['graph_final_operation_ids'])
    permitted_operations = {child[1] for child in capsule.child_identities}
    if len(set(graph_operations)) != len(graph_operations) or not set(graph_operations) <= permitted_operations:
        raise AuthorityUnavailable('D13 final Graph census contains an unknown or duplicate child outside the complete manifest')
    owner = service.core._row(db, service.authority_namespace)
    children = []
    for child, admission, outbound in zip(capsule.child_identities, facts['admissions'], facts['outbounds']):
        index, operation, effect_id = child
        effect = maintenance.execution._read_current_effect_locked_v4(db, effect_id=effect_id,
            execution_head=proof.execution_head, execution_rows=proof.execution_rows, owner=owner)
        if effect.state == 'unresolved' or effect.state == 'observed' and effect.observation_outcome not in ('accepted', 'delivered'):
            raise D13NaturalRosterNotTerminalV3('D13 stopped parent still has an unknown external effect')
        if kind == 'nonpass' and (effect.state != 'absent' or admission is not None or outbound is not None or operation in graph_operations):
            raise AuthorityUnavailable('D13 nonpass parent already has final/admission/effect facts; cannot assert never-started')
        if effect.state == 'absent':
            if kind == 'superseded':
                stopped = head[2].children[index]
                if (stopped.continuation_state != 'superseded' or stopped.cause_kind != 'adopted_relevant_ingress'
                        or stopped.cause_ref is None or stopped.cause_digest is None):
                    raise D13NaturalRosterNotTerminalV3('D13 unstarted child has no exact signed permanent supersession')
            if outbound is not None:
                raise AuthorityUnavailable('D13 absent child effect has an unexpected adopted outbound original')
            attempt = _actual_absent_child_attempt_in_tx_v3(service, db, capsule, child, admission, graph_operations)
            if attempt[0] == 'finished_refusal':
                refusal = maintenance.originals._decode(attempt[1])
                validate_original_terminal_fence_in_tx_v1(db, refusal)
                attempt = ('finished_refusal', refusal.original_ref, refusal.digest)
            children.append((child, canonical_digest(effect), attempt))
            continue
        if effect.state != 'observed' or admission is None or outbound is None or operation not in graph_operations:
            raise D13NaturalRosterNotTerminalV3('D13 actual dispatched child lacks its complete adopted terminal metadata')
        observed, adoption = outbound
        completed = maintenance.execution._completed_result(maintenance.execution.fences.mutation_locked(db, effect.mutation_id))
        binding = observed.pending.platform_observation.binding
        if (completed is None or completed[0] != observed or type(binding) is not ExecutionBindingV2
                or (binding.origin.operation_id, binding.origin.effect_id) != (operation, effect_id)
                or (admission.admission.operation_id, admission.admission.effect_id) != (operation, effect_id)
                or binding.admission_receipt_digest != admission.receipt_digest
                or adoption['schema'] != 'd13.outbound_adoption.v1'
                or adoption['observation_digest'] != canonical_digest(observed)):
            raise AuthorityUnavailable('D13 stopped child observation/admission differs from the independently frozen Core originals')
        adopted = from_wire(adoption['permit'])
        adopted_row = service.fences.fences._row(db, adopted.operation_id)
        if (adopted_row is None or service.fences.fences._permit(adopted_row) != adopted
                or adopted_row[6] != 'finished' or adopted_row[10] is not None
                or adopted_row[8:10] != (adoption['operation_id'], adoption['finish_digest'])):
            raise D13NaturalRosterNotTerminalV3('D13 stopped child outbound adoption still lacks its actual finished write')
        children.append((child, canonical_digest(effect), admission.receipt_digest,
            canonical_digest(observed), canonical_digest(adoption)))
    material = dict(parent_original_id=parent, generation_original_id=capsule.generation_original_id,
        generation_original_digest=capsule.generation_original_digest, review_original_id=capsule.review_original_id,
        review_original_digest=capsule.review_original_digest, disposition_kind=kind,
        cause_ref=cause_ref, cause_digest=cause_digest,
        child_derivation_schema='sylanne3.d13.natural-child-identity-derivation.v3',
        child_identities=capsule.child_identities, child_identity_digest=capsule.child_identity_digest,
        census_root=canonical_digest((capsule.input_digest, facts['graph_census_digest'], models, tuple(children),
            retained.retention_digest, canonical_digest(proof.anchor))),
        census_count=len(children), core_head_digest=canonical_digest(proof.anchor),
        graph_snapshot_digest=facts['graph_snapshot_digest'], retention_digest=retained.retention_digest)
    values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=review.owner_ref,
        registration_digest=review.registration_digest, **material,
        operation_id=owner_operation_id_v3(service.namespace, review.owner_ref, 'owner_parent_disposition'),
        request_digest=canonical_digest((PROTOCOL, 'owner_parent_disposition', review.registration_digest, material)),
        control_revision=service._revision(db), schema=PARENT_DISPOSITION_SCHEMA_V3)
    values['disposition_digest'] = canonical_digest(values)
    original = service._record(db, 'owner_parent_disposition', D13NaturalParentDispositionReceiptV3(**values))
    return review, dict(disposition_kind='never_started' if models[1][1] == 'never_started' else 'terminal',
        disposition_ref=original.operation_id, disposition_digest=original.disposition_digest,
        retention_release_ref=retained.operation_id, retention_release_digest=retained.retention_digest,
        successor_transfer_digest=None), proof.credential


def _close_actual_permanent_parent_v3(server, service, maintenance, capsule, *,
        credential, permit):
    from ..runtime.d13_natural_original_use_v3 import (prepare_actual_authority_natural_parent_census_v3,
        require_actual_authority_natural_parent_census_v3)
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    from .v2_contract import decode_bytes
    metadata = prepare_actual_authority_natural_parent_census_v3(maintenance, capsule,
        credential=credential, subject=permit.subject)
    try:
        facts, context = require_actual_authority_natural_parent_census_v3(metadata, maintenance, capsule)
        head = facts['roster_head']
        birth = current = committed = None
        if head is not None:
            birth, current = maintenance._require_committed_head_v1(head)
            committed = maintenance.originals.latest_committed(capsule.parent_original_id)
        with runtime_storage_operation_v3(service.core._db, operation_id='d13-parent-revocation:' + capsule.parent_original_id):
            with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                anchor = service.fences._current_locked(db, deletion, execution,
                    holder=permit.holder, generation=permit.generation)
                row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                    (service.authority_namespace, permit.operation_id)).fetchone()
                if (row is None or decode_bytes(row[0]) != permit or row[1] not in ('active', 'finished')
                        or permit.subject != 'mtls:sha256:' + credential.certificate_sha256):
                    raise AuthorityUnavailable('D13 permanent parent disposition lost its actual authenticated original scope')
                service._policy(db)
                prior = service._owner_operation_v3(db, capsule.owner_ref, 'owner_close')
                if prior is not None:
                    return prior
                verified_head, rows = maintenance.execution.journal._scan_locked()
                if verified_head != execution:
                    raise AuthorityUnavailable('D13 permanent parent execution census changed after its actual frozen boundary')
                proof = _PermanentNaturalParentClosureProofV3(_ISSUER, service=service, maintenance=maintenance,
                    model=server._v2_model_egress[service.authority_namespace], capsule=capsule, metadata=metadata,
                    context=context, credential=credential, anchor=anchor, execution_head=verified_head,
                    execution_rows=rows, birth=birth, current=current, committed=committed)
                return service.close_original_owner_in_tx_v3(db, proof)
    finally:
        metadata.release_v3()


@contextmanager
def bind_actual_counter_owner_metadata_v3(proof, *, service, db):
    if type(proof) is not _CounterOriginalOwnerProofV3:
        raise AuthorityUnavailable('D13 actual Counter producer metadata scope required')
    state = _PROOFS.get(proof)
    if (state is None or state[0] is not proof.counter or state[1] is not proof.scope
            or _control(proof.counter) is not service or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 Counter metadata scope lost its actual private owner proof/Core')
    scope = proof.scope.require_current_v3()
    from .d13_cache_use_control_v2 import _OwnerMetadataV3, _bind_owner_metadata_v3
    if scope.d13_owner_metadata_v3 is None:
        scope.d13_owner_metadata_v3 = _OwnerMetadataV3(scope.lease)
    with _bind_owner_metadata_v3(scope.lease, scope.d13_owner_metadata_v3):
        yield scope.d13_owner_metadata_v3


_RETIRED_RECEIVER_CLOSES_V3 = WeakKeyDictionary()
_RETIRED_RECEIVER_CLEANUPS_V3 = WeakKeyDictionary()


class _RetiredReceiverCloseProofV3:
    def __init__(self, issuer, progress, service, registration, retirement, terminal):
        if issuer is not _ISSUER:
            raise TypeError('actual drained maintenance retirement producer required')
        self.progress, self.service, self.registration = progress, service, registration
        self.retirement, self.terminal = retirement, terminal
        _RETIRED_RECEIVER_CLOSES_V3[self] = (progress, service, registration, retirement, terminal)


def _retired_receiver_closure_v3(proof, service, db):
    from .d13_cache_use_contract_v2 import (
        D13RetiredReceiverOriginalV3, RETIRED_RECEIVER_SCHEMA_V3, PROTOCOL, owner_operation_id_v3)
    if (_RETIRED_RECEIVER_CLOSES_V3.get(proof) !=
            (proof.progress, service, proof.registration, proof.retirement, proof.terminal)
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 retired receiver lost its private actual Core producer')
    progress, registration = proof.progress, proof.registration
    progress.require_gate_v3()
    service.core._require(progress.maintenance.credential, 'delete', progress.maintenance.closure.namespace)
    if service._live_owner_v3(db, registration.owner_ref) != registration:
        raise AuthorityUnavailable('D13 peer retirement cannot replace an actual registered receiver')
    operation_id = owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_peer_retirement')
    material = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=registration.owner_ref,
        registration_digest=registration.registration_digest, peer_admission_digest=registration.peer_admission_digest,
        process_incarnation=registration.process_incarnation, producer_kind_version=registration.producer_kind_version,
        retention_instance_ref=registration.retention_instance_ref, payload_set_digest=registration.payload_digest,
        maintenance_operation_id=progress.operation_id, retirement_digest=proof.retirement['retirement_digest'],
        retirement_completion_digest=progress.coverage.original['completion_digest'],
        quiescence_digest=progress.quiescence['quiescence_digest'],
        source_manifest_digest=progress.coverage.original['manifest_digest'],
        source_pointer_version=progress.coverage.original['pointer_version'],
        source_storage_generation=progress.coverage.original['storage_generation'],
        source_permit_token=registration.permit_token, source_permit_digest=registration.permit_digest,
        terminal_ref=proof.terminal[0], terminal_digest=proof.terminal[1], operation_id=operation_id,
        schema=RETIRED_RECEIVER_SCHEMA_V3)
    request_digest = canonical_digest((PROTOCOL, 'owner_peer_retirement', material))
    prior = service._owner_operation_v3(db, registration.owner_ref, 'owner_peer_retirement')
    if prior is not None:
        if prior.request_digest != request_digest:
            raise AuthorityUnavailable('D13 retired receiver changed its original retirement/terminal evidence')
        original = prior
    else:
        values = dict(material, request_digest=request_digest, control_revision=service._revision(db))
        values['retirement_original_digest'] = canonical_digest(values)
        original = service._record(db, 'owner_peer_retirement', D13RetiredReceiverOriginalV3(**values))
    return registration, dict(disposition_kind='peer_retired',
        disposition_ref=original.operation_id, disposition_digest=original.retirement_original_digest,
        retention_release_ref=original.operation_id, retention_release_digest=original.retirement_original_digest,
        successor_transfer_digest=None), progress.maintenance.credential


def require_d13_owner_close_authorization_v3(proof, *, service, db, credential):
    if type(proof) is _CurrentCoreReceiverCloseProofV4:
        if (proof.progress.service is not service or credential is not proof.progress.credential
                or _CURRENT_CORE_RECEIVER_CLOSES_V4.get(proof) is None):
            raise AuthorityUnavailable('D13 local Core retirement lost its actual maintenance credential/private proof')
        proof.progress.require_v4(db=db)
        service.core._require(credential, 'delete', service.authority_namespace)
    elif type(proof) is _RetiredReceiverCloseProofV3:
        state = _RETIRED_RECEIVER_CLOSES_V3.get(proof)
        if state is None or state[1] is not service or credential is not proof.progress.maintenance.credential:
            raise AuthorityUnavailable('D13 retirement close requires the actual installed maintenance credential')
        proof.progress.require_gate_v3()
        service.core._require(credential, 'delete', proof.progress.maintenance.closure.namespace)
    else:
        service.core._require(credential, 'd13_cache_use_close_original', service.authority_namespace)



def _retirement_d13_selected_v3(maintenance):
    from .deployment_config import AuthorityDeploymentConfig, InstalledNaturalModelAuthorityV2
    from ..host.authority_profile import AdminInstallationBundle
    from ..runtime.d13_cache_use_admission_v2 import _bundle_use_enabled_v2
    config = maintenance.gate._installed_config_v3
    if (type(config) is not AuthorityDeploymentConfig
            or maintenance._installed_deployment_config_v2 is not config):
        raise AuthorityUnavailable('D13 optional retirement boundary requires its actual installed deployment')
    item = (config.natural_model_authorities_v2 or {}).get(maintenance.closure.namespace)
    assets = (config.d13_cache_use_assets_v2 or {}).get(maintenance.closure.namespace)
    if item is None:
        if assets is not None:
            raise AuthorityUnavailable('D13 installed use assets have no actual selected natural bundle')
        return False
    if type(item) is not InstalledNaturalModelAuthorityV2:
        raise AuthorityUnavailable('D13 retirement crossed its actual installed natural Authority')
    bundle = item.installation_bundle
    if bundle is None:
        if assets is not None:
            raise AuthorityUnavailable('D13 installed use assets have no actual policy bundle')
        return False
    if (type(bundle) is not AdminInstallationBundle
            or bundle.installation_policy.namespace != maintenance.namespace_id
            or bundle.installation_policy.authority_namespace != maintenance.closure.namespace
            or bundle.installation_policy.installation_id != maintenance.control.installation_id):
        raise AuthorityUnavailable('D13 optional retirement bundle crossed namespace/installation')
    enabled = _bundle_use_enabled_v2(bundle)
    if enabled:
        if assets is None:
            raise AuthorityUnavailable('D13 enabled retirement policy has no actual installed use assets')
        assets.require_installation_v2(bundle)
    elif assets is not None:
        raise AuthorityUnavailable('D13 unselected retirement policy has enabled installed use assets')
    return enabled

class _RetiredReceiverCleanupV3:
    def __init__(self, issuer, maintenance, coverage, quiescence, recovery, continuation):
        if issuer is not _ISSUER:
            raise TypeError('actual C09 receiver retirement producer required')
        self.maintenance, self.coverage, self.quiescence = maintenance, coverage, quiescence
        self.recovery, self.operation_id, self.continuation = recovery, coverage.operation_id, continuation
        self.after, self.closed, self.failed, self.complete = '', 0, None, False
        self.phase, self.pending_registration, self.pending_write_proof = 'select', None, None
        maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from .d13_cache_use_control_v2 import _owner_metadata_heap_v3
        return _owner_metadata_heap_v3((self.quiescence, self.after, self.failed, self.pending_registration)) + 8192

    def require_gate_v3(self):
        m, gate = self.maintenance, self.maintenance.gate
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        from .c09_writer_peer_originals_v3 import _require_gate
        if (type(m) is not InstalledC09MaintenanceV1 or gate._installed_maintenance_v3 is not m
                or _RETIRED_RECEIVER_CLEANUPS_V3.get(m) is not self
                or gate._operation != self.operation_id or gate._active != 0
                or gate._closing_continuation is not self.continuation
                or not self.recovery and gate._epoch != self.quiescence['revoked_admission_epoch']):
            raise AuthorityUnavailable('D13 retirement cleanup requires its actual continuously drained maintenance Gate')
        _require_gate(m.control, gate)
        if self.continuation is not None:
            gate.require_final_continuation_v3(self.continuation, operation_id=self.operation_id, observe=False)
        m.core._require(m.credential, 'delete', m.closure.namespace)

    def require_coverage_v3(self):
        from .c09_writer_peer_originals_v3 import (
            VerifiedPeerRetirementCoverageV3, VerifiedPreparedPeerRetirementCoverageV3,
            require_writer_quiescence_original_v3, read_writer_peer_retirement_coverage_for_prepared_v3)
        self.require_gate_v3()
        m = self.maintenance
        with m.control._resource_sql_quantum_v3() as meter:
            if type(self.coverage) is VerifiedPeerRetirementCoverageV3 and self.recovery is False:
                if self.coverage.progress.control is not m.control or self.coverage.progress.gate is not m.gate:
                    raise AuthorityUnavailable('D13 retirement coverage belongs to another actual maintenance installation')
                self.coverage.require_current(meter=meter)
            elif type(self.coverage) is VerifiedPreparedPeerRetirementCoverageV3 and self.recovery is True:
                if self.coverage.control is not m.control:
                    raise AuthorityUnavailable('D13 cold retirement coverage belongs to another Control')
                actual = read_writer_peer_retirement_coverage_for_prepared_v3(m.control, m.gate,
                    operation_id=self.operation_id, context=self.coverage.context)
                if actual.original != self.coverage.original:
                    raise AuthorityUnavailable('D13 cold retirement lost its actual old-to-current PREPARED mapping')
                self.coverage.require_current(meter=meter)
            else:
                raise AuthorityUnavailable('D13 retirement requires exact live coverage or explicit prepared recovery coverage')
            complete = require_writer_quiescence_original_v3(m.control, self.quiescence,
                meter=meter, operation_id=self.operation_id)
            if complete != self.coverage.original:
                raise AuthorityUnavailable('D13 retirement quiescence differs from its complete signed peer EOF')

    def read_retirement_v3(self, service, registration):
        import json
        from .c09_writer_peer_originals_v3 import (
            _bounded, _ROOT_PEER_RETIREMENT, _RETIREMENT, _verify_root_cohort_peer_retirement_v3)
        control, complete = self.maintenance.control, self.coverage.original
        if (registration.owner_kind not in ('graph_source_receiver', 'host_frame_receiver')
                or registration.peer_admission_digest is None or registration.process_incarnation is None
                or registration.retention_instance_ref is None):
            raise AuthorityUnavailable('D13 peer retirement has no registered remote receiver incarnation')
        with control._resource_sql_quantum_v3() as meter:
            with control._db() as db:
                row = _bounded(db, meter).execute('SELECT admission_json FROM c09_writer_peer_admissions_v3 '
                    'WHERE admission_digest=?', (registration.peer_admission_digest,)).fetchone()
                retired = _bounded(db, meter).execute('SELECT retirement_json FROM c09_writer_peer_retirements_v3 '
                    'WHERE operation_id=? AND admission_digest=?',
                    (self.operation_id, registration.peer_admission_digest)).fetchone()
            if row is None or retired is None:
                raise AuthorityUnavailable('D13 receiver has no exact durable admission/retirement original')
            admission, retirement = json.loads(row[0]), json.loads(retired[0])
            control.verify_original_v1(admission, 'admission_digest')
            control.verify_original_v1(retirement, 'retirement_digest')
            point = ('manifest_digest', 'pointer_version', 'storage_generation')
            if (admission['schema'] != 'sylanne3.c09.writer-peer-admission.v3'
                    or admission['admission_digest'] != registration.peer_admission_digest
                    or admission['process_incarnation'] != registration.process_incarnation
                    or admission['authority_id'] != control.authority_id
                    or admission['installation_id'] != service.installation_id
                    or admission['namespace'] != service.authority_namespace
                    or registration.subject != 'mtls:sha256:' + admission['peer'][0]
                    or any(admission[name] != complete[name] for name in point)
                    or retirement['authority_id'] != control.authority_id
                    or retirement['installation_id'] != service.installation_id
                    or retirement['namespace'] != service.authority_namespace
                    or retirement['maintenance_operation_id'] != self.operation_id
                    or retirement['admission_digest'] != registration.peer_admission_digest
                    or retirement['original_process'] != admission['process_original']
                    or any(retirement[name] != admission[name] for name in point)):
                raise AuthorityUnavailable('D13 retired receiver differs from the exact signed old peer/process/selection')
            if retirement['schema'] == _ROOT_PEER_RETIREMENT:
                _verify_root_cohort_peer_retirement_v3(control, self.operation_id, admission, retirement, meter)
            elif retirement['schema'] != _RETIREMENT:
                raise AuthorityUnavailable('D13 receiver retirement has no qualified physical peer disposition')
            return retirement

    def advance_v3(self):
        from .d13_cache_use_control_v2 import (
            InstalledD13CacheUseControlServiceV2, _OwnerMetadataV3, _bind_owner_metadata_v3)
        from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
        from .d13_cache_use_contract_v2 import D13OwnerRegistrationReceiptV3, owner_operation_id_v3
        self.require_coverage_v3()
        m = self.maintenance
        if not _retirement_d13_selected_v3(m):
            with m.core._tx() as db:
                for table in ('authority_d13_cache_use_policies_v2',
                        'authority_d13_cache_use_operations_v2', 'authority_d13_cache_use_pins_v2'):
                    present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                    if present is not None and db.execute('SELECT 1 FROM ' + table + ' WHERE namespace=? LIMIT 1',
                            (m.closure.namespace,)).fetchone() is not None:
                        raise AuthorityUnavailable('D13 unselected deployment has historical use originals; legacy_unknown remains HOLD')
            self.complete = True
            return self.result_v3('complete', 'retired_receiver_not_selected')
        service = m.core._d13_cache_use_controls_v2.get(m.closure.namespace)
        if (type(service) is not InstalledD13CacheUseControlServiceV2 or service.core is not m.core
                or service.namespace != m.namespace_id or service.authority_namespace != m.closure.namespace
                or service.installation_id != m.control.installation_id):
            raise AuthorityUnavailable('D13 retirement cleanup has no exact installed V3 same-Core service')
        registration = self.pending_registration
        if registration is not None and self.phase == 'prepare_write':
            from ..runtime.d13_retired_receiver_metadata_v3 import prepare_actual_d13_retired_write_terminal_v3
            # The producer finishes actual selected Graph metadata outside every
            # Core transaction. Its lease survives until the acknowledged close.
            self.pending_write_proof = prepare_actual_d13_retired_write_terminal_v3(m, registration,
                retirement_coverage=self.coverage, quiescence_original=self.quiescence)
            self.phase = 'consume'
            return self.result_v3('progress', 'retired_receiver_write_metadata')
        # The private cursor advances only after a skipped classified owner or
        # an actually committed receiver close; no caller can skip an unknown.
        with service.fences._frozen() as (db, deletion, execution, _):
            with runtime_storage_operation_v3(db, operation_id='d13-retired-receiver:' + self.operation_id) as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), runtime_storage_quantum_v3(db) as meter:
                        service._policy(db)
                        if registration is None:
                            meter.require_available(8192)
                            found = db.execute('SELECT operation_id FROM authority_d13_cache_use_operations_v2 '
                                "WHERE namespace=? AND action='owner_register' AND operation_id>? "
                                'ORDER BY operation_id COLLATE BINARY LIMIT 1',
                                (service.authority_namespace, self.after)).fetchone()
                            if found is None:
                                self.complete = True
                                return self.result_v3('complete', 'retired_receiver_eof')
                            row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                                ('action', 'request_digest', 'result_json'), 'namespace=? AND operation_id=?',
                                (service.authority_namespace, found[0]), 'retirement_scan')
                            registration = provider.decode(row, 'retirement_scan', meter)
                            if (type(registration) is not D13OwnerRegistrationReceiptV3
                                    or row[:2] != ('owner_register', registration.request_digest)
                                    or registration.operation_id != found[0]
                                    or found[0] != owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_register')
                                    or registration.namespace != service.namespace
                                    or registration.authority_namespace != service.authority_namespace
                                    or registration.installation_id != service.installation_id):
                                raise AuthorityUnavailable('D13 retirement census found an unclassified original')
                            existing = service._owner_operation_v3(db, registration.owner_ref, 'owner_close')
                            if existing is not None:
                                if existing.registration_digest != registration.registration_digest:
                                    raise AuthorityUnavailable('D13 retired receiver closure belongs to another original')
                                self.after = found[0]
                                return self.result_v3('progress', 'retired_receiver_already_closed')
                            if registration.owner_kind not in ('graph_source_receiver', 'host_frame_receiver'):
                                self.after = found[0]
                                return self.result_v3('progress', 'retired_receiver_other_durable_owner')
                            fence = service.fences.fences._row(db, registration.original_operation_id)
                            if fence is None:
                                raise AuthorityUnavailable('D13 retired receiver has no saved original Source permit')
                            permit = service.fences.fences._permit(fence)
                            self.pending_registration = registration
                            self.phase = 'prepare_write' if permit.operation == 'write' else 'consume'
                            return self.result_v3('progress', 'retired_receiver_selected')
                        actual = service._live_owner_v3(db, registration.owner_ref)
                        if actual != registration:
                            raise AuthorityUnavailable('D13 retired receiver changed between metadata selection and final consumption')
                        retirement = self.read_retirement_v3(service, registration)
                        terminal = _retired_receiver_terminal_v3(self, service, db, registration, deletion, execution)
                        proof = _RetiredReceiverCloseProofV3(_ISSUER, self, service, registration, retirement, terminal)
                        try:
                            service.close_original_owner_in_tx_v3(db, proof)
                        finally:
                            _RETIRED_RECEIVER_CLOSES_V3.pop(proof, None)
                finally:
                    operation.unregister_retained_state_v3(provider)
        # This point is after the real Core transaction committed.
        if self.pending_write_proof is not None:
            self.pending_write_proof.release_v3()
        self.pending_registration = self.pending_write_proof = None
        self.phase, self.after = 'select', registration.operation_id
        self.closed += 1
        return self.result_v3('progress', 'retired_receiver_closed')
    def result_v3(self, status, phase):
        return dict(status=status, phase=phase, after_operation_id=self.after,
            closed_receivers=self.closed, first_failure=self.failed)


def _retired_receiver_terminal_v3(progress, service, db, registration, deletion, execution):
    from .d13_cache_use_contract_v2 import D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3
    locator = registration.original_locator
    row = service.fences.fences._row(db, registration.original_operation_id)
    if row is None or type(locator) not in (D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3):
        raise AuthorityUnavailable('D13 retired receiver has no actual typed saved Source fence')
    permit = service.fences.fences._permit(row)
    if (permit.namespace != service.authority_namespace or permit.subject != registration.subject
            or permit.token != registration.permit_token or canonical_digest(permit) != registration.permit_digest
            or locator.source_operation_id != permit.operation_id or locator.source_permit_token != permit.token
            or locator.source_permit_digest != canonical_digest(permit) or row[10] is not None):
        raise AuthorityUnavailable('D13 retired receiver differs from its actual saved Source permit or has pending work')
    service.fences.fences._require_no_migration(db)
    if row[6] == 'active' and permit.operation == 'read':
        anchor = service.fences._current_locked(db, deletion, execution,
            holder=permit.holder, generation=permit.generation)
        if anchor != permit.pinned_anchor:
            raise AuthorityUnavailable('D13 retired READ current anchor differs; preserve its actual obligation')
        cleanup_id = 'd13-retirement-read-finish:' + canonical_digest((
            progress.operation_id, permit.operation_id, permit.token))
        digest = 'sha256:' + canonical_digest(('sylanne3.d13.retirement-read-finish.v3',
            progress.coverage.original['completion_digest'], progress.quiescence['quiescence_digest'], permit))
        service.fences.fences.finish_fence_locked(db, permit, subject=registration.subject,
            current_anchor=anchor, request_id=cleanup_id, request_digest=digest)
        row = service.fences.fences._row(db, permit.operation_id)
    if permit.operation == 'model_egress':
        return _retired_model_terminal_v3(progress, service, db, registration, permit, row)
    if permit.operation == 'write':
        return _retired_write_terminal_core_v3(progress, service, db, registration, permit, row, deletion, execution)
    # A WRITE finished flag alone cannot supply its actual committed/refused original.
    if row[6] != 'finished' or permit.operation != 'read' or row[8] is None or row[9] is None:
        raise AuthorityUnavailable('D13 retired non-READ receiver awaits its actual protocol terminal or confirmed successor')
    return ('authority-v2-fence:' + permit.operation_id, canonical_digest((permit, row[6], row[8:11])))


def advance_d13_retired_receiver_cleanup_v3(maintenance, *, retirement_coverage, quiescence_original, recovery=False, continuation=None):
    """One actual receiver per C09 actor step, after drain and before capture."""
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    if type(maintenance) is not InstalledC09MaintenanceV1 or type(recovery) is not bool:
        raise AuthorityUnavailable('actual installed C09 maintenance retirement invocation required')
    progress = _RETIRED_RECEIVER_CLEANUPS_V3.get(maintenance)
    if progress is None or progress.complete and (progress.coverage is not retirement_coverage
            or progress.recovery is not recovery or progress.continuation is not continuation):
        progress = _RetiredReceiverCleanupV3(_ISSUER, maintenance, retirement_coverage, dict(quiescence_original), recovery, continuation)
        _RETIRED_RECEIVER_CLEANUPS_V3[maintenance] = progress
    elif (progress.coverage is not retirement_coverage or progress.quiescence != quiescence_original
            or progress.recovery is not recovery or progress.continuation is not continuation):
        raise AuthorityUnavailable('D13 receiver retirement cannot replace its actual original cleanup scope')
    if progress.failed is not None:
        return progress.result_v3('hold', 'retired_receiver_first_failure')
    if progress.complete:
        progress.require_coverage_v3()
        return progress.result_v3('complete', 'retired_receiver_eof')
    prior = progress.after, progress.closed, progress.complete
    try:
        from ..runtime_storage_v3 import bind_retired_receiver_runtime_operation_v4
        with bind_retired_receiver_runtime_operation_v4(progress):
            return progress.advance_v3()
    except Exception as exc:
        progress.after, progress.closed, progress.complete = prior
        progress.failed = type(exc).__name__ + ': ' + str(exc)
        return progress.result_v3('hold', 'retired_receiver_first_failure')



class _PreparedRetiredReceiverEOFV4(_RetiredReceiverCleanupV3):
    def advance_v3(self):
        from .d13_cache_use_control_v2 import (
            InstalledD13CacheUseControlServiceV2, _OwnerMetadataV3, _bind_owner_metadata_v3)
        from .d13_cache_use_contract_v2 import D13OwnerRegistrationReceiptV3, owner_operation_id_v3
        from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
        self.require_coverage_v3()
        m = self.maintenance
        if m.core._db.execute('PRAGMA query_only').fetchone() != (1,):
            raise AuthorityUnavailable('initial PREPARED receiver EOF requires actual query-only Core')
        selected = _retirement_d13_selected_v3(m)
        service = m.core._d13_cache_use_controls_v2.get(m.closure.namespace) if selected else None
        if selected and (type(service) is not InstalledD13CacheUseControlServiceV2
                or service.core is not m.core or service.namespace != m.namespace_id
                or service.authority_namespace != m.closure.namespace
                or service.installation_id != m.control.installation_id):
            raise AuthorityUnavailable('PREPARED receiver EOF has no actual installed same-Core V3 service')
        with runtime_storage_operation_v3(m.core._db,
                operation_id='d13-prepared-receiver-eof:' + self.operation_id) as operation:
            provider = _OwnerMetadataV3(operation)
            try:
                with m.core._tx() as db:
                    with _bind_owner_metadata_v3(operation, provider), runtime_storage_quantum_v3(db) as meter:
                        if not selected:
                            for table in ('authority_d13_cache_use_policies_v2',
                                    'authority_d13_cache_use_operations_v2', 'authority_d13_cache_use_pins_v2'):
                                if (db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                                        (table,)).fetchone() is not None
                                        and db.execute('SELECT 1 FROM ' + table + ' WHERE namespace=? LIMIT 1',
                                            (m.closure.namespace,)).fetchone() is not None):
                                    raise AuthorityUnavailable('unselected PREPARED storage has D13 legacy_unknown originals')
                            self.complete = True
                            return self.result_v3('complete', 'retired_receiver_not_selected')
                        service._policy(db)
                        meter.require_available(8192)
                        found = db.execute('SELECT operation_id FROM authority_d13_cache_use_operations_v2 '
                            "WHERE namespace=? AND action='owner_register' AND operation_id>? "
                            'ORDER BY operation_id COLLATE BINARY LIMIT 1',
                            (service.authority_namespace, self.after)).fetchone()
                        if found is None:
                            self.complete = True
                            return self.result_v3('complete', 'retired_receiver_prepared_eof')
                        row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                            ('action', 'request_digest', 'result_json'), 'namespace=? AND operation_id=?',
                            (service.authority_namespace, found[0]), 'prepared_retirement_scan')
                        registration = provider.decode(row, 'prepared_retirement_scan', meter)
                        if (type(registration) is not D13OwnerRegistrationReceiptV3
                                or row[:2] != ('owner_register', registration.request_digest)
                                or registration.operation_id != found[0]
                                or found[0] != owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_register')
                                or registration.namespace != service.namespace
                                or registration.authority_namespace != service.authority_namespace
                                or registration.installation_id != service.installation_id):
                            raise AuthorityUnavailable('PREPARED receiver EOF found an unclassified original')
                        if registration.owner_kind in ('authority_source_receiver', 'graph_source_receiver', 'host_frame_receiver'):
                            _require_prepared_receiver_closed_in_tx_v4(self, service, db, registration, provider, meter)
                        self.after = found[0]
                        return self.result_v3('progress', 'retired_receiver_prepared_original_checked')
            finally:
                operation.unregister_retained_state_v3(provider)


def _require_prepared_receiver_closed_in_tx_v4(progress, service, db, registration, provider, meter):
    from .d13_cache_use_contract_v2 import payload_key_v2, D13OwnerRegistrationReceiptV3
    closed = service._owner_operation_v3(db, registration.owner_ref, 'owner_close')
    if closed is None or closed.registration_digest != registration.registration_digest:
        raise AuthorityUnavailable('PREPARED receiver still requires an actual close write; preserve its obligation')
    if closed.disposition_kind in ('peer_retired', 'core_retired'):
        action = 'owner_peer_retirement' if closed.disposition_kind == 'peer_retired' else 'owner_core_retirement'
        retained = service._owner_operation_v3(db, registration.owner_ref, action)
        digest = None if retained is None else (
            retained.retirement_original_digest if action == 'owner_peer_retirement' else retained.retirement_digest)
        if (retained is None or retained.registration_digest != registration.registration_digest
                or (closed.disposition_ref, closed.disposition_digest, closed.retention_release_ref,
                    closed.retention_release_digest) != (retained.operation_id, digest, retained.operation_id, digest)
                or retained.source_permit_digest != registration.permit_digest):
            raise AuthorityUnavailable('PREPARED receiver close lost its actual retirement/retention original')
        if action == 'owner_core_retirement':
            progress.maintenance.control.verify_original_v1(asdict(retained), 'retirement_digest')
    elif closed.retention_original is None:
        # The local final-release producer is committed in the closed receipt;
        # it was issued only after the actual retained operation closed.
        locator = registration.original_locator
        if (registration.owner_kind != 'authority_source_receiver'
                or closed.retention_release_ref != locator.retention_id + ':released'):
            raise AuthorityUnavailable('PREPARED receiver has no actual retained final-release original')
    else:
        value = closed.retention_original
        if (value.registration_digest != registration.registration_digest
                or value.payload_set_digest != registration.payload_digest
                or value.peer_admission_digest != registration.peer_admission_digest
                or value.process_incarnation != registration.process_incarnation
                or value.retention_instance_ref != registration.retention_instance_ref
                or value.original_permit_digest != registration.permit_digest):
            raise AuthorityUnavailable('PREPARED receiver retained witness differs from registration')
    if closed.disposition_kind == 'transferred':
        row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
            ('action', 'request_digest', 'result_json'), 'namespace=? AND operation_id=?',
            (service.authority_namespace, closed.disposition_ref), 'prepared_successor')
        successor = None if row is None else provider.decode(row, 'prepared_successor', meter)
        if (type(successor) is not D13OwnerRegistrationReceiptV3
                or row[:2] != ('owner_register', successor.request_digest)
                or successor.operation_id != closed.disposition_ref
                or successor.registration_digest != closed.disposition_digest
                or successor.namespace != registration.namespace or successor.installation_id != registration.installation_id
                or not {identity[:3] for identity in registration.payload_identities} <=
                       {identity[:3] for identity in successor.payload_identities}):
            raise AuthorityUnavailable('PREPARED receiver transfer lost its actual confirmed successor')
    else:
        fence = service.fences.fences._row(db, registration.original_operation_id)
        if (fence is None or fence[6] != 'finished' or fence[10] is not None
                or service.fences.fences._permit(fence).token != registration.permit_token
                or canonical_digest(service.fences.fences._permit(fence)) != registration.permit_digest):
            raise AuthorityUnavailable('PREPARED receiver has no actual finished original Source terminal')
    for identity in registration.payload_identities:
        key = payload_key_v2(service.namespace, identity)
        pin_id = 'd13-owner-pin-v3:' + canonical_digest((service.namespace, registration.owner_ref, key))
        pin = provider.fixed(db, meter, 'authority_d13_cache_use_pins_v2',
            ('state', 'consumer_owner_ref', 'release_operation_id'), 'namespace=? AND pin_id=?',
            (service.authority_namespace, pin_id), 'prepared_receiver_pin')
        if pin != ('released', registration.owner_ref, closed.operation_id):
            raise AuthorityUnavailable('PREPARED closed receiver still has an unknown payload obligation')
    if db.execute("SELECT 1 FROM authority_d13_cache_use_pins_v2 WHERE namespace=? "
            "AND consumer_owner_ref=? AND state='active' LIMIT 1",
            (service.authority_namespace, registration.owner_ref)).fetchone() is not None:
        raise AuthorityUnavailable('PREPARED closed receiver retains an active unclassified pin')


def advance_d13_retired_receiver_eof_for_prepared_v4(maintenance, *, retirement_coverage,
                                                   quiescence_original, continuation=None):
    """One read-only historical receiver check; never finish or close a fence."""
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from .c09_writer_peer_originals_v3 import VerifiedPreparedPeerRetirementCoverageV3
    if (type(maintenance) is not InstalledC09MaintenanceV1
            or type(retirement_coverage) is not VerifiedPreparedPeerRetirementCoverageV3):
        raise AuthorityUnavailable('actual initial PREPARED maintenance/retirement coverage required')
    progress = _RETIRED_RECEIVER_CLEANUPS_V3.get(maintenance)
    if progress is None or progress.complete and type(progress) is not _PreparedRetiredReceiverEOFV4:
        progress = _PreparedRetiredReceiverEOFV4(_ISSUER, maintenance, retirement_coverage,
            dict(quiescence_original), True, continuation)
        _RETIRED_RECEIVER_CLEANUPS_V3[maintenance] = progress
    if (type(progress) is not _PreparedRetiredReceiverEOFV4 or progress.coverage is not retirement_coverage
            or progress.quiescence != quiescence_original or progress.continuation is not continuation):
        raise AuthorityUnavailable('PREPARED receiver EOF cannot replace an incomplete cleanup scope')
    if progress.failed is not None:
        return progress.result_v3('hold', 'retired_receiver_prepared_first_failure')
    try:
        if progress.complete:
            progress.require_coverage_v3()
            return progress.result_v3('complete', 'retired_receiver_prepared_eof')
        from ..runtime_storage_v3 import bind_prepared_receiver_eof_runtime_operation_v4
        with bind_prepared_receiver_eof_runtime_operation_v4(progress):
            return progress.advance_v3()
    except Exception as exc:
        progress.failed = type(exc).__name__ + ': ' + str(exc)
        return progress.result_v3('hold', 'retired_receiver_prepared_first_failure')


def _retired_model_terminal_v3(progress, service, db, registration, permit, fence):
    import json
    from .v2_model_egress_store import AuthorityV2ModelEgressStore
    from .v2_model_egress_contract import ModelAdmissionV2, ModelTerminalReceiptV2
    from .v2_model_egress_contract import ModelNoDispatchWitnessV1
    from .v2_model_egress_wire import from_wire
    from ..runtime_contracts import canonical_serialize
    from .d13_cache_use_control_v2 import _OWNER_METADATA_V3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    provider = _OWNER_METADATA_V3.get()
    with runtime_storage_quantum_v3(db) as meter:
        meter.require_available(8192)
        calls = db.execute('SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? AND operation_id=? LIMIT 2',
            (service.authority_namespace, permit.operation_id)).fetchall()
        if len(calls) != 1:
            raise AuthorityUnavailable('D13 retired model Source has no unique actual Core original')
        call_id = calls[0][0]
        ledger = provider.fixed(db, meter, 'authority_model_egress_v1',
            ('identity_json', 'state', 'observation_digest'), 'call_id=?', (call_id,), 'retired_model_ledger')
        if ledger[1] == 'observed':
            row = provider.fixed(db, meter, 'authority_model_admissions_v2',
                ('admission_id', 'admission_json', 'report_digest', 'receipt_json'), 'call_id=?',
                (call_id,), 'retired_model_admission')
            if row is None or row[2] is None or row[3] is None:
                raise AuthorityUnavailable('D13 retired observed model has no complete actual admission/report/terminal')
        elif ledger[1] == 'prepared':
            row = provider.fixed(db, meter, 'authority_model_no_dispatch_witnesses_v1',
                ('request_digest', 'witness_json', 'witness_digest', 'signature'),
                'namespace=? AND call_id=? AND authority_id=? AND installation_id=?',
                (service.authority_namespace, call_id, permit.authority_id, service.installation_id),
                'retired_model_no_dispatch')
            if row is None:
                raise AuthorityUnavailable('D13 retired prepared model has no actual signed no-dispatch original')
        else:
            raise AuthorityUnavailable('D13 retired model has an active/unknown execution effect; preserve its receiver')
        amount = sum(len(value.encode('utf-8')) for value in (*ledger, *row) if type(value) is str)
        if amount * 12 + 4096 > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('D13 retired model metadata exceeds its actual reserved decode arena')
        provider.operation.reserve_retained_state_growth_v3(provider, amount * 12 + 4096)
        try:
            record = AuthorityV2ModelEgressStore._read(db, call_id)
            intent = record.intent
            if ((intent.authority_id, intent.namespace, intent.subject, intent.operation_id, intent.fence_token,
                    intent.fence_epoch, intent.fence_revision, intent.anchor_digest) !=
                    (permit.authority_id, permit.namespace, permit.subject, permit.operation_id, permit.token,
                    permit.fence_epoch, permit.revision, canonical_digest(asdict(permit.pinned_anchor)))
                    or not AuthorityV2ModelEgressStore.is_fence_bound_locked(db, intent)
                    or fence[6] != 'finished' or fence[10] is not None):
                raise AuthorityUnavailable('D13 retired model terminal differs from its actual original intent/permit')
            if record.state == 'observed':
                admission = ModelAdmissionV2(**json.loads(row[1]))
                terminal = ModelTerminalReceiptV2(**json.loads(row[3]))
                provider.decoded['retired_model_protocol'] = (record, admission, terminal)
                if (canonical_serialize(asdict(admission)) != row[1] or canonical_serialize(asdict(terminal)) != row[3]
                        or admission.admission_id != row[0] or terminal.report_digest != row[2]
                        or (admission.authority_id, admission.namespace, admission.subject, admission.operation_id,
                            admission.call_id, admission.request_digest, admission.provider_config_digest) !=
                           (intent.authority_id, intent.namespace, intent.subject, intent.operation_id,
                            intent.call_id, intent.request_digest, intent.provider_config_digest)
                        or (terminal.admission_id, terminal.call_id, terminal.request_digest,
                            terminal.installation_id, terminal.host_incarnation) !=
                           (admission.admission_id, admission.call_id, admission.request_digest,
                            admission.installation_id, admission.host_incarnation)
                        or admission.installation_id != service.installation_id
                        or terminal.observation_digest != record.observation_digest
                        or fence[8:10] != (intent.call_id, terminal.finish_digest)
                        or terminal.finish_digest != service.fences.fences.model_terminal_finish_digest(
                            intent, permit, 'completed', record.observation_digest)):
                    raise AuthorityUnavailable('D13 retired model actual admission/report/observation terminal chain differs')
                return ('authority-model-terminal:' + intent.call_id,
                    canonical_digest((intent, admission, terminal, fence[8:11])))
            witness = from_wire(json.loads(row[1]), ModelNoDispatchWitnessV1)
            provider.decoded['retired_model_protocol'] = (record, witness)
            item = (progress.maintenance.gate._installed_config_v3.natural_model_authorities_v2 or {}).get(
                service.authority_namespace)
            if item is None:
                raise AuthorityUnavailable('D13 retired no-dispatch original has no actual installed model signer')
            witness.require_signature_v1(item.d11_issuer._signer)
            if (row[0] != witness.request.identity_digest or row[2:] != (witness.digest, witness.signature)
                    or canonical_serialize(json.loads(row[1])) != row[1]
                    or witness.request.intent != intent or witness.original_permit != permit
                    or fence[8:10] != (intent.call_id, witness.finish_digest)
                    or witness.finish_digest != service.fences.fences.model_terminal_finish_digest(intent, permit, 'not_dispatched')
                    or db.execute('SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?', (call_id,)).fetchone() is not None
                    or db.execute('SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?', (call_id,)).fetchone() is not None):
                raise AuthorityUnavailable('D13 retired model no-dispatch differs from its actual signed absence/finish original')
            return ('authority-model-no-dispatch:' + intent.call_id, canonical_digest((intent, witness, fence[8:11])))
        finally:
            provider.operation.finish_retained_state_growth_v3(provider)


def _retired_write_terminal_core_v3(progress, service, db, registration, permit, fence, deletion, execution):
    from ..runtime.d13_retired_receiver_metadata_v3 import (
        RetiredOwnerWriteTerminalMetadataV3, require_actual_d13_retired_write_terminal_v3)
    from ..runtime_contracts import CommitReceipt
    saved, kind, metadata, context = require_actual_d13_retired_write_terminal_v3(
        progress.pending_write_proof, maintenance=progress.maintenance, registration=registration)
    if (saved != permit or kind != 'owner_write_committed'
            or type(metadata) is not RetiredOwnerWriteTerminalMetadataV3
            or metadata.attempt_id != permit.operation_id or metadata.attempt_id != registration.original_operation_id
            or type(metadata.receipt) is not CommitReceipt
            or metadata.receipt.status not in ('committed', 'duplicate')
            or metadata.receipt.operation_id != metadata.owner_operation_id
            or metadata.receipt_digest != canonical_digest(metadata.receipt)):
        raise AuthorityUnavailable('D13 retired WRITE differs from its actual complete selected Owner original')
    attempt, request, owner = metadata.attempt_id, metadata.request_digest, metadata.owner_operation_id
    if attempt.startswith('owner-stop-projection:'):
        schema, expected_attempt = 'w01.owner-domain-write.v3', 'owner-stop-projection:' + owner
    elif attempt.startswith('owner-task-domain-'):
        schema, expected_attempt = 'w01.owner-task-domain-write.v1', 'owner-task-domain-' + request[:48]
    elif attempt.startswith('foreground-domain-v2-'):
        schema, expected_attempt = 'w01.foreground-domain-write.v1', 'foreground-domain-v2-' + request[:48]
    elif attempt.startswith('foreground-domain-'):
        schema, expected_attempt = 'w01.foreground-domain-write.v1', 'foreground-domain-' + request[:48]
    elif attempt.startswith('owner-domain-'):
        schema = 'w01.owner-domain-write.v3'
        expected_attempt = 'owner-domain-' + canonical_digest((service.namespace, owner, request))[:48]
    else:
        raise AuthorityUnavailable('D13 retired WRITE has no installed exact Owner protocol family')
    finish = ('finish:' + expected_attempt, 'sha256:' + canonical_digest(dict(
        schema=schema, operation_id=owner, request_digest=request, permit_token=permit.token)))
    if (attempt != expected_attempt or fence[6] != 'finished' or fence[10] is not None
            or fence[8:10] != finish
            or (metadata.formal_finish_request_id, metadata.formal_finish_request_digest) != finish):
        raise AuthorityUnavailable('D13 retired WRITE has no exact formal committed Core finish receipt')
    context.require_current('maintenance')
    # Independent journal heads and actual Core state are checked in the same
    # frozen transaction that records retirement and releases the receiver pins.
    anchor = service.fences._current_locked(db, deletion, execution, require_clear=False)
    return ('graph-owner-write:' + metadata.original_ref, canonical_digest((
        permit, metadata, finish, anchor, context.manifest_digest, context.pointer_version)))


_NATURAL_GENERATION_PARSE_PRODUCERS_V3 = WeakKeyDictionary()
_GENERATION_PARSE_PROOFS_V3 = WeakKeyDictionary()
_GENERATION_OUTPUT_CLEANUPS_V3 = WeakKeyDictionary()


def install_d13_natural_generation_parse_producer_v3(output_service, model_service):
    from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    if (type(output_service) is not AuthorityV2NaturalGenerationOutputService
            or type(model_service) is not AuthorityV2ModelEgressService
            or output_service._store is not model_service._store or output_service._fences is not model_service._fences):
        raise AuthorityUnavailable('D13 generation parse requires the actual installed same-Core paid output/model producers')
    prior = _NATURAL_GENERATION_PARSE_PRODUCERS_V3.get(output_service)
    if prior is not None and prior is not model_service:
        raise AuthorityUnavailable('D13 generation parse producer cannot replace its actual installed model')
    _NATURAL_GENERATION_PARSE_PRODUCERS_V3[output_service] = model_service


class _ActualGenerationParseProofV3:
    def __init__(self, issuer, output, pending, parsed, outcome, reason):
        if issuer is not _ISSUER:
            raise TypeError('actual paid generation parser lifecycle required')
        self.output, self.pending, self.parsed, self.outcome, self.reason = output, pending, parsed, outcome, reason
        _GENERATION_PARSE_PROOFS_V3[self] = (output, pending, parsed, outcome, reason)


def parse_actual_d13_natural_generation_output_v3(output_service, *, credential, request):
    from ..model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1
    from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7, freeze_natural_reply_request_v7
    from ..model_broker.natural_reply import _parse_natural_reply_output_payload
    model = _NATURAL_GENERATION_PARSE_PRODUCERS_V3.get(output_service)
    if model is None:
        raise AuthorityUnavailable('D13 actual generation output parser lacks its installed producer binding')
    with output_service._delivery_lock:
        pending = output_service._d13_generation_parse_v3.get(request.read_attempt_id)
    if (pending is None or pending[0] is not request
            or request.read_attempt_id not in output_service._inflight_deliveries
            or output_service._inflight_deliveries[request.read_attempt_id] is not None):
        raise AuthorityUnavailable('D13 generation parser has no actual still-active Source delivery')
    _, original, observation, intent, terminal, permit, _ = pending
    frozen, result = original[0].frozen, observation.result
    control = _natural_control_v3(model)
    if control is None:
        if type(result) is not dict or set(result) != {'text'} or type(result['text']) is not str:
            raise AuthorityUnavailable('natural provider result shape differs')
        return parse_natural_reply_output_current_v1(result['text'], frozen)
    # The frozen-input qualification is outside the rejection exception domain.
    if type(frozen) is not FrozenNaturalReplyRequestV7 or freeze_natural_reply_request_v7(
            frozen.input, frozen.installation) != frozen:
        raise AuthorityUnavailable('D13 paid generation parser lost its actual complete V7 frozen original')
    def rejected(reason):
        proof = _ActualGenerationParseProofV3(_ISSUER, output_service, pending, None, 'output_rejected', reason)
        with output_service._delivery_lock:
            output_service._d13_generation_parse_v3[request.read_attempt_id] = (*pending[:6], proof)
        output_service._fences.validate_fence(credential=credential, subject=output_service._read_subject, permit=permit)
        if output_service._graph.read(request, intent, terminal, include_reported_usage=True) != original:
            raise AuthorityUnavailable('natural original changed after the actual parser rejection')
        record_actual_d13_natural_generation_parse_v3(output_service, credential=credential, request=request)
    if type(result) is not dict or set(result) != {'text'} or type(result['text']) is not str:
        rejected('provider_result_shape')
        raise AuthorityUnavailable('natural provider result shape differs')
    try:
        parsed = _parse_natural_reply_output_payload(result['text'], frozen)
    except ValueError:
        # Only this closed pure output validator is in the rejection domain.
        rejected('canonical_payload_rejected')
        raise
    if parsed.status not in ('no_reply_hold', 'untrusted_content_candidate'):
        raise AuthorityUnavailable('D13 actual generation parser returned an unregistered outcome')
    proof = _ActualGenerationParseProofV3(_ISSUER, output_service, pending, parsed,
        'no_reply_hold' if parsed.status == 'no_reply_hold' else 'adoptable', None)
    with output_service._delivery_lock:
        output_service._d13_generation_parse_v3[request.read_attempt_id] = (*pending[:6], proof)
    return parsed


def record_actual_d13_natural_generation_parse_v3(output_service, *, credential, request):
    from hashlib import sha256
    from .d13_cache_use_contract_v2 import (
        D13NaturalGenerationParseReceiptV3, GENERATION_PARSE_SCHEMA_V3, owner_operation_id_v3, PROTOCOL)
    from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION, TEMPLATE_DIGEST, OUTPUT_SCHEMA
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    model = _NATURAL_GENERATION_PARSE_PRODUCERS_V3.get(output_service)
    if model is None:
        raise AuthorityUnavailable('actual generation parse producer has no same-Core model binding')
    service = _natural_control_v3(model)
    if service is None:
        return None
    with output_service._delivery_lock:
        pending = output_service._d13_generation_parse_v3.get(request.read_attempt_id)
        if (pending is None or pending[0] is not request
                or output_service._inflight_deliveries.get(request.read_attempt_id, True) is not None):
            raise AuthorityUnavailable('D13 generation fact has no actual active Source parse lifecycle')
    _, original, observation, intent, terminal, permit, proof = pending
    if (_GENERATION_PARSE_PROOFS_V3.get(proof) !=
            (output_service, proof.pending, proof.parsed, proof.outcome, proof.reason)
            or proof.pending[:6] != pending[:6]):
        raise AuthorityUnavailable('D13 generation parse cannot be supplied by a caller output DTO')
    saved, binding, seal_digest, intent_digest, terminal_digest = original[:5]
    plan, parsed = saved.frozen.input.plan, proof.parsed
    if (saved.seal.original_operation_id != request.original_operation_id
            or saved.seal.job_id != request.job_id or seal_digest != canonical_digest(saved.seal)
            or intent_digest != canonical_digest(intent) or terminal_digest != canonical_digest(terminal)
            or intent.call_id != request.call_id):
        raise AuthorityUnavailable('D13 generation parse lost its actual paid sealed original identities')
    result = observation.result
    raw_digest = sha256(result['text'].encode('utf-8')).hexdigest() if (
        type(result) is dict and set(result) == {'text'} and type(result['text']) is str) else canonical_digest(result)
    stable = dict(parent_original_id=request.c02_operation_id, generation_job_id=request.job_id,
        generation_original_id=saved.seal.original_operation_id, generation_original_digest=seal_digest,
        generation_call_id=intent.call_id, frozen_input_digest=saved.frozen.frozen_input_digest,
        plan_ref=plan.plan_ref.ref, plan_revision=plan.plan_ref.version,
        first_operation_id=plan.final_operation_id, first_effect_id=plan.final_effect_id,
        raw_output_digest=raw_digest, parsed_output_digest=None if parsed is None else parsed.output_digest,
        parse_outcome=proof.outcome, rejection_code=proof.reason,
        parser_version='sylanne3.d13.actual-generation-output-parser.v3',
        template_version=TEMPLATE_VERSION, template_digest=TEMPLATE_DIGEST, output_schema=OUTPUT_SCHEMA,
        observation_digest=observation.digest, terminal_receipt_digest=terminal_digest,
        original_intent_digest=intent_digest, typed_model_request_digest=binding.typed_request_digest,
        parser_binding_digest=canonical_digest(('d13.actual-generation-parse.v3', saved.seal,
            TEMPLATE_VERSION, TEMPLATE_DIGEST, OUTPUT_SCHEMA, raw_digest, proof.outcome, proof.reason,
            None if parsed is None else parsed.output_digest)))
    service.core._require(credential, 'd13_cache_use_register_original', service.authority_namespace, permit.holder)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-generation-parse:' + request.original_operation_id):
        with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
            anchor = service.fences._current_locked(db, deletion, execution, holder=permit.holder, generation=permit.generation)
            service.fences.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
            service._policy(db)
            registration = service._live_owner_v3(db, natural_stage_owner_ref_v3(service.namespace, request.job_id))
            record = model._store.read_locked(db, intent)
            admission, report, actual_terminal = model._store.read_admission_locked(db, intent)
            if (registration.owner_kind != 'natural_generation_original'
                    or registration.original_locator.original_id != saved.seal.original_operation_id
                    or registration.original_locator.parent_original_id != request.c02_operation_id
                    or record.state != 'observed' or record.observation_digest != observation.digest
                    or actual_terminal != terminal or terminal.report_digest != report
                    or terminal.observation_digest != observation.digest):
                raise AuthorityUnavailable('D13 generation parse has no exact actual paid terminal/admission/original chain')
            prior = service._owner_operation_v3(db, registration.owner_ref, 'owner_generation_parse')
            if prior is not None:
                if (prior.registration_digest != registration.registration_digest
                        or any(getattr(prior, key) != value for key, value in stable.items())):
                    raise AuthorityUnavailable('D13 actual generation parse cannot change on replay')
                return prior
            service._no_reclaim_v3(db)
            producer = dict(**stable, producer_permit_operation_id=permit.operation_id,
                producer_permit_digest=canonical_digest(permit))
            values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
                installation_id=service.installation_id, owner_ref=registration.owner_ref,
                registration_digest=registration.registration_digest, **producer,
                operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_generation_parse'),
                request_digest=canonical_digest((PROTOCOL, 'owner_generation_parse', registration.registration_digest, producer)),
                control_revision=service._revision(db), schema=GENERATION_PARSE_SCHEMA_V3)
            values['parse_digest'] = canonical_digest(values)
            fact = service._record(db, 'owner_generation_parse', D13NaturalGenerationParseReceiptV3(**values))
    _GENERATION_OUTPUT_CLEANUPS_V3.setdefault(output_service, {})[request.read_attempt_id] = (
        service, fact, permit, credential)
    return fact


def _record_actual_counter_birth_in_tx_v3(service, db, proof, registration):
    from .d13_cache_use_contract_v2 import D13CounterFrameBirthReceiptV3, COUNTER_BIRTH_SCHEMA_V3, owner_operation_id_v3, PROTOCOL
    from .d13_core_counter_service_v1 import _ALGORITHM
    if type(proof) is not _CounterOriginalOwnerProofV3 or proof not in _PROOFS:
        raise AuthorityUnavailable('D13 Counter birth requires its actual canonical writer/Source producer')
    material, _, _ = proof.require_v3(service=service, db=db, action='register')
    draft, counter = proof.draft, proof.counter
    if (material['owner_ref'] != registration.owner_ref or registration.original_commitment != proof.writer.digest
            or material['original_commitment'] != proof.writer.digest):
        raise AuthorityUnavailable('D13 Counter birth differs from the actual canonical draft owner')
    stable = dict(parent_original_id=draft['selector']['c02_operation_id'],
        counter_operation_id=proof.operation_id, frame_intent_id=draft['frame_intent_id'],
        frame_intent_digest=draft['frame_intent_digest'], draft_commitment=proof.writer.digest,
        input_digest=draft['input_digest'], plan_ref=draft['selector']['plan_ref']['ref'],
        plan_revision=draft['selector']['plan_ref']['version'], generation_call_id=draft['generation_call_id'],
        activation_generation=draft['activation_generation'],
        first_operation_id=proof.current.prospective.plan.final_operation_id,
        first_effect_id=proof.current.prospective.plan.final_effect_id, planned_job_id=draft['job_id'], planned_execution_id=draft['execution_id'], planned_activity_id=draft['activity_id'],
        algorithm_ref=_ALGORITHM, algorithm_build_digest=counter.worker.program_sha256,
        source_ref=draft['source_ref']['ref'], source_revision=draft['source_ref']['version'],
        source_scope_digest=draft['source_scope_digest'], owner_grant_digest=draft['owner_grant_digest'],
        owner_responsibility_digest=draft['owner_responsibility_digest'],
        parent_budget_lease_ref=draft['parent_budget_lease_ref'], budget_grant_digest=draft['budget_grant_digest'],
        policy_digest=counter.policy.policy_digest,
        planned_binding_digest=canonical_digest(('d13.actual-counter-birth.v3', draft['job_id'], draft['execution_id'],
            draft['activity_id'], draft['input_digest'], _ALGORITHM, counter.worker.program_sha256,
            draft['parent_budget_lease_ref'], draft['budget_grant_digest'], draft['owner_grant_digest'])))
    prior = service._owner_operation_v3(db, registration.owner_ref, 'owner_counter_birth')
    if prior is not None:
        if (prior.registration_digest != registration.registration_digest
                or any(getattr(prior, key) != value for key, value in stable.items())):
            raise AuthorityUnavailable('D13 Counter birth cannot change its actual planned job/binding on replay')
        return prior
    present = db.execute('SELECT 1 FROM authority_d13_counter_originals_v1 WHERE namespace=? '
        "AND counter_operation_id=? AND phase='draft'", (service.authority_namespace, proof.operation_id)).fetchone()
    if present is not None:
        raise AuthorityUnavailable('D13 historical draft has no original birth; cleanup cannot backfill from Body')
    values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=registration.owner_ref, registration_digest=registration.registration_digest,
        **stable, operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_counter_birth'),
        request_digest=canonical_digest((PROTOCOL, 'owner_counter_birth', registration.registration_digest, stable)),
        control_revision=service._revision(db), schema=COUNTER_BIRTH_SCHEMA_V3)
    values['birth_digest'] = canonical_digest(values)
    return service._record(db, 'owner_counter_birth', D13CounterFrameBirthReceiptV3(**values))


def reconcile_actual_d13_generation_output_cleanup_v3(server, output_service, *, credential,
        profile_id, manifest_digest, read_attempt_id):
    """One exact parse-origin READ finish event; no new Source or registration."""
    from ..runtime.d13_cache_use_admission_v2 import (
        _RETAINED, _AuthorityConsumerOwnerV2, _release_owner)
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    pending = _GENERATION_OUTPUT_CLEANUPS_V3.get(output_service, {}).get(read_attempt_id)
    if pending is None:
        return None
    service, fact, permit, original_credential = pending
    if (output_service not in _NATURAL_GENERATION_PARSE_PRODUCERS_V3
            or credential.certificate_sha256 != original_credential.certificate_sha256):
        raise AuthorityUnavailable('D13 generation cleanup changed its actual paid parse producer/subject')
    server._bound_v2_service(credential, profile_id, manifest_digest, service.authority_namespace)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-generation-read-finish:' + read_attempt_id):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            actual = service._owner_operation_v3(db, fact.owner_ref, 'owner_generation_parse')
            row = service.fences.fences._row(db, permit.operation_id)
            basis = dict(read_attempt_id=read_attempt_id, permit=asdict(permit))
            finish = ('natural-output-finish:' + canonical_digest(basis), 'sha256:' + canonical_digest(dict(
                action='finish_natural_generation_output_read', **basis)))
            if (actual != fact or fact.producer_permit_operation_id != permit.operation_id
                    or fact.producer_permit_digest != canonical_digest(permit)
                    or row is None or service.fences.fences._permit(row) != permit):
                raise AuthorityUnavailable('D13 generation cleanup has no exact original parse/read fence')
            if row[6] != 'finished':
                return dict(status='pending_finish', read_attempt_id=read_attempt_id)
            if row[10] is not None or row[8:10] != finish:
                raise AuthorityUnavailable('D13 generation cleanup lacks the exact actual output READ finish ACK')
    for owner in tuple(_RETAINED.values()):
        if (type(owner) is _AuthorityConsumerOwnerV2 and owner.port.service is service
                and owner.permit.token == permit.token and owner.release_requested):
            _release_owner(owner)
    # Receiver owners keep their own strong unknown/ACK state. The first paid
    # parse fact stays durable even after this one authenticated event completes.
    _GENERATION_OUTPUT_CLEANUPS_V3[output_service].pop(read_attempt_id, None)
    if not _GENERATION_OUTPUT_CLEANUPS_V3[output_service]:
        _GENERATION_OUTPUT_CLEANUPS_V3.pop(output_service, None)
    if fact.parse_outcome in ('no_reply_hold', 'output_rejected'):
        return close_authenticated_d13_natural_roster_v3(server, service, credential=credential,
            profile_id=profile_id, manifest_digest=manifest_digest, permit=permit,
            parent_original_id=fact.parent_original_id)
    return dict(status='finished', read_attempt_id=read_attempt_id)


def _require_natural_no_cache_history_in_tx_v3(model, db):
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    core = model._fences.core
    if db is not core._db or not db.in_transaction or not core._lock._is_owned():
        raise AuthorityUnavailable('actual optional natural metadata transaction required')
    with runtime_storage_operation_v3(db, operation_id='d13-natural-optional-metadata'), runtime_storage_quantum_v3(db) as meter:
        meter.require_available(8192)
        for table in ('authority_d13_cache_use_policies_v2', 'authority_d13_cache_use_operations_v2',
                'authority_d13_cache_use_pins_v2'):
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if exists is not None and db.execute('SELECT 1 FROM ' + table + ' WHERE namespace=? LIMIT 1',
                    (model._fences.namespace,)).fetchone() is not None:
                raise AuthorityUnavailable('D13 unselected natural profile has prior use-policy/owner/pin originals; legacy_unknown remains HOLD')


def require_actual_d13_generation_parse_original_v3(service, parse_original):
    """Authenticate only the small saved Core original; never execution permission."""
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2, _OwnerMetadataV3, _bind_owner_metadata_v3
    from .d13_cache_use_contract_v2 import D13NaturalGenerationParseReceiptV3
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2 or type(parse_original) is not D13NaturalGenerationParseReceiptV3:
        raise AuthorityUnavailable('actual protected D13 generation parse original required')
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-generation-parse-metadata:' + parse_original.operation_id) as operation:
        provider = _OwnerMetadataV3(operation)
        try:
            with _bind_owner_metadata_v3(operation, provider), service.core._tx() as db, runtime_storage_quantum_v3(db):
                actual = service._owner_operation_v3(db, parse_original.owner_ref, 'owner_generation_parse')
                registration = service._owner_operation_v3(db, parse_original.owner_ref, 'owner_register')
                if (actual != parse_original or registration is None
                        or registration.registration_digest != actual.registration_digest
                        or registration.owner_kind != 'natural_generation_original'
                        or registration.original_locator.parent_original_id != actual.parent_original_id
                        or registration.original_locator.job_id != actual.generation_job_id
                        or registration.original_locator.original_id != actual.generation_original_id):
                    raise AuthorityUnavailable('D13 generation parse has no exact actual immutable Core registration/producer')
                return actual, registration
        finally:
            operation.unregister_retained_state_v3(provider)


_PRE_REVIEW_BASES_V3 = WeakKeyDictionary()


class _ActualNaturalPreReviewBasisV3:
    def __init__(self, issuer, service, parse_original, registration, revision):
        if issuer is not _ISSUER:
            raise TypeError('actual frozen Core pre-review census basis required')
        self.service, self.parse_original = service, parse_original
        self.registration, self.revision = registration, revision
        _PRE_REVIEW_BASES_V3[self] = (service, parse_original, registration, revision)

    def release_v3(self):
        _PRE_REVIEW_BASES_V3.pop(self, None)


def _actual_generation_parse_in_tx_v3(service, db, parse_original):
    from .d13_cache_use_contract_v2 import D13NaturalGenerationParseReceiptV3
    if type(parse_original) is not D13NaturalGenerationParseReceiptV3:
        raise AuthorityUnavailable('actual protected generation parse original required')
    actual = service._owner_operation_v3(db, parse_original.owner_ref, 'owner_generation_parse')
    registration = service._owner_operation_v3(db, parse_original.owner_ref, 'owner_register')
    if (actual != parse_original or registration is None
            or registration.registration_digest != actual.registration_digest
            or registration.owner_kind != 'natural_generation_original'
            or registration.original_locator.parent_original_id != actual.parent_original_id
            or registration.original_locator.job_id != actual.generation_job_id
            or registration.original_locator.original_id != actual.generation_original_id):
        raise AuthorityUnavailable('D13 generation parse differs from its actual immutable producer/registration')
    return actual, registration


def _actual_pre_review_retention_in_tx_v3(service, db, parse_original, generation):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    if parse_original.parse_outcome not in ('no_reply_hold', 'output_rejected'):
        raise AuthorityUnavailable('D13 adoptable output cannot issue an absent-review disposition')
    if service._live_owner_v3(db, generation.owner_ref) != generation:
        raise AuthorityUnavailable('D13 absent-review census has no live original generation')
    review_ref = natural_stage_owner_ref_v3(service.namespace,
        natural_job_ids_v2(service.namespace, parse_original.parent_original_id, 'review')[0])
    if service._owner_operation_v3(db, review_ref, 'owner_register') is not None:
        raise D13NaturalRosterNotTerminalV3('D13 actual review registration already owns this generation')
    retained = _actual_parent_retention_in_tx_v3(service, db,
        parse_original.parent_original_id, generation, generation)
    fence = service.fences.fences._row(db, parse_original.producer_permit_operation_id)
    if (fence is None or fence[6] != 'finished' or fence[10] is not None
            or canonical_digest(service.fences.fences._permit(fence)) != parse_original.producer_permit_digest):
        raise D13NaturalRosterNotTerminalV3('D13 original generation parse READ has no actual final finish acknowledgement')
    permit = service.fences.fences._permit(fence)
    basis = dict(read_attempt_id=permit.operation_id, permit=asdict(permit))
    if (permit.operation != 'read' or fence[8:10] != (
            'natural-output-finish:' + canonical_digest(basis),
            'sha256:' + canonical_digest(dict(action='finish_natural_generation_output_read', **basis)))):
        raise AuthorityUnavailable('D13 generation parse READ finish differs from its formal producer acknowledgement')
    return retained


def prepare_actual_d13_natural_pre_review_basis_v3(service, parse_original):
    """Capture before Graph EOF; a changed Core head invalidates the entire census."""
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('actual installed D13 Core service required')
    with runtime_storage_operation_v3(service.core._db,
            operation_id='d13-pre-review-basis:' + parse_original.operation_id):
        with service.fences._frozen() as (db, _, _, _), runtime_storage_quantum_v3(db):
            service._policy(db)
            actual, generation = _actual_generation_parse_in_tx_v3(service, db, parse_original)
            require_natural_parent_open_in_tx_v3(service, db, actual.parent_original_id)
            _actual_pre_review_retention_in_tx_v3(service, db, actual, generation)
            row = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
                (service.authority_namespace,)).fetchone()
            if row is None:
                raise AuthorityUnavailable('D13 absent-review census has no installed monotonic namespace head')
            return _ActualNaturalPreReviewBasisV3(_ISSUER, service, actual, generation, row[0])


def require_actual_d13_natural_pre_review_basis_v3(service, db, basis, parse_original):
    if (type(basis) is not _ActualNaturalPreReviewBasisV3
            or _PRE_REVIEW_BASES_V3.get(basis) !=
                (service, parse_original, basis.registration, basis.revision)
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 pre-review census lost its actual private Core basis')
    row = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
        (service.authority_namespace,)).fetchone()
    if row != (basis.revision,):
        raise D13NaturalRosterNotTerminalV3('D13 Core ownership changed after Graph census; discard the whole absence proof')
    actual, generation = _actual_generation_parse_in_tx_v3(service, db, parse_original)
    if generation != basis.registration:
        raise AuthorityUnavailable('D13 pre-review census changed its original generation registration')
    require_natural_parent_open_in_tx_v3(service, db, actual.parent_original_id)
    return actual, generation, _actual_pre_review_retention_in_tx_v3(service, db, actual, generation)


_PRE_REVIEW_CLOSES_V3 = WeakKeyDictionary()


class _ActualPreReviewClosureProofV3:
    def __init__(self, issuer, service, maintenance, model, parse_original, metadata,
            context, credential, anchor, execution_head, execution_rows):
        if issuer is not _ISSUER:
            raise TypeError('actual frozen pre-review disposition producer required')
        self.service, self.maintenance, self.model = service, maintenance, model
        self.parse_original, self.metadata, self.context = parse_original, metadata, context
        self.credential, self.anchor = credential, anchor
        self.execution_head, self.execution_rows = execution_head, execution_rows
        _PRE_REVIEW_CLOSES_V3[self] = (service, maintenance, model, parse_original, metadata,
            context, credential, anchor, execution_head, execution_rows)


def _actual_pre_review_model_in_tx_v3(service, db, model, original):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    if model._fences is not service.fences or model._store._db is not db:
        raise AuthorityUnavailable('D13 pre-review model census crossed its actual Core service')
    record = model._store._read(db, original.generation_call_id)
    if (record is None or record.state != 'observed' or record.intent.job_id != original.generation_job_id
            or canonical_digest(record.intent) != original.original_intent_digest
            or record.observation_digest != original.observation_digest):
        raise D13NaturalRosterNotTerminalV3('D13 original generation has no exact actual paid observation')
    admission, report, terminal = model._store.read_admission_locked(db, record.intent)
    fence = service.fences.fences._row(db, record.intent.operation_id)
    if (terminal is None or terminal.report_digest != report
            or terminal.observation_digest != original.observation_digest
            or canonical_digest(terminal) != original.terminal_receipt_digest
            or fence is None or fence[6] != 'finished' or fence[10] is not None
            or fence[8:10] != (record.intent.call_id, terminal.finish_digest)):
        raise AuthorityUnavailable('D13 pre-review disposition lost its actual terminal/admission/finish original')
    ids = natural_job_ids_v2(service.namespace, original.parent_original_id, 'review')
    if (model._store._read(db, ids[3]) is not None
            or db.execute('SELECT 1 FROM authority_model_original_identity_v2 WHERE namespace=? AND job_id=?',
                (service.authority_namespace, ids[0])).fetchone() is not None
            or db.execute('SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?', (ids[3],)).fetchone() is not None
            or db.execute('SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?', (ids[3],)).fetchone() is not None
            or service.fences.fences._row(db, ids[2]) is not None
            or service.fences.fences._row(db, ids[3]) is not None):
        raise D13NaturalRosterNotTerminalV3('D13 actual review call/acquisition/admission exists; absence cannot close it')
    return (canonical_digest(record.intent), canonical_digest(admission), report, canonical_digest(terminal))


def _actual_pre_review_closure_v3(proof, service, db):
    from ..runtime.d13_natural_original_use_v3 import require_actual_authority_natural_pre_review_census_v3
    from .d13_cache_use_contract_v2 import (D13NaturalPreReviewDispositionReceiptV3,
        PRE_REVIEW_DISPOSITION_SCHEMA_V3, owner_operation_id_v3, PROTOCOL)
    if (_PRE_REVIEW_CLOSES_V3.get(proof) != (service, proof.maintenance, proof.model,
            proof.parse_original, proof.metadata, proof.context, proof.credential, proof.anchor,
            proof.execution_head, proof.execution_rows) or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 pre-review disposition requires its actual private frozen producer')
    facts, context = require_actual_authority_natural_pre_review_census_v3(
        proof.metadata, proof.maintenance, proof.parse_original)
    original, generation, retained = require_actual_d13_natural_pre_review_basis_v3(
        service, db, proof.metadata.core_basis_v3, proof.parse_original)
    if (context is not proof.context or type(facts) is not dict or set(facts) != {
            'roster_head', 'generation_locator', 'review_preparation', 'review_acquisition',
            'graph_final_operation_ids', 'graph_admissions', 'graph_snapshot_digest', 'graph_census_digest'}
            or facts['roster_head'] is not None or facts['review_preparation'] is not None
            or facts['review_acquisition'] is not None or facts['graph_final_operation_ids'] != ()
            or facts['graph_admissions'] != () or facts['generation_locator'] !=
                (original.generation_job_id, original.generation_original_id, original.generation_original_digest,
                    original.frozen_input_digest, original.generation_call_id)):
        raise AuthorityUnavailable('D13 absent-review disposition lacks its exact complete actual Graph metadata census')
    context.require_current('business')
    proof.maintenance.owner._require_projection_pointer_in_tx_v1(db, context)
    model = _actual_pre_review_model_in_tx_v3(service, db, proof.model, original)
    owner = service.core._row(db, service.authority_namespace)
    effect = proof.maintenance.execution._read_current_effect_locked_v4(db,
        effect_id=original.first_effect_id, execution_head=proof.execution_head,
        execution_rows=proof.execution_rows, owner=owner)
    if effect.state != 'absent':
        raise D13NaturalRosterNotTerminalV3('D13 non-adoptable generation has an actual or unresolved execution effect')
    final_attempt = 'natural-final:' + canonical_digest({
        'namespace': service.namespace.as_tuple, 'operation_id': original.first_operation_id})[:48]
    if (service.fences.fences._row(db, final_attempt) is not None
            or service.fences.fences._row(db, original.first_operation_id) is not None
            or db.execute('SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND operation_id IN (?,?) LIMIT 1',
                (service.authority_namespace, original.first_operation_id, final_attempt)).fetchone() is not None):
        raise D13NaturalRosterNotTerminalV3('D13 non-adoptable generation has an actual final/dispatch attempt')
    material = dict(parent_original_id=original.parent_original_id,
        generation_original_id=original.generation_original_id,
        generation_original_digest=original.generation_original_digest,
        parse_original_ref=original.operation_id, parse_digest=original.parse_digest,
        disposition_kind=original.parse_outcome,
        census_root=canonical_digest((original.parse_digest, facts['graph_census_digest'], model,
            proof.execution_head, retained.retention_digest, proof.metadata.core_basis_v3.revision)),
        core_head_digest=canonical_digest(proof.anchor),
        graph_snapshot_digest=facts['graph_snapshot_digest'], retention_digest=retained.retention_digest)
    values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=generation.owner_ref,
        registration_digest=generation.registration_digest, **material,
        operation_id=owner_operation_id_v3(service.namespace, generation.owner_ref, 'owner_pre_review_disposition'),
        request_digest=canonical_digest((PROTOCOL, 'owner_pre_review_disposition',
            generation.registration_digest, material)),
        control_revision=service._revision(db), schema=PRE_REVIEW_DISPOSITION_SCHEMA_V3)
    values['disposition_digest'] = canonical_digest(values)
    disposition = service._record(db, 'owner_pre_review_disposition',
        D13NaturalPreReviewDispositionReceiptV3(**values))
    return generation, dict(disposition_kind='terminal', disposition_ref=disposition.operation_id,
        disposition_digest=disposition.disposition_digest, retention_release_ref=retained.operation_id,
        retention_release_digest=retained.retention_digest, successor_transfer_digest=None), proof.credential


def _close_actual_pre_review_parent_v3(server, service, maintenance, original, *, credential, permit):
    from ..runtime.d13_natural_original_use_v3 import (prepare_actual_authority_natural_pre_review_census_v3,
        require_actual_authority_natural_pre_review_census_v3)
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    from .v2_contract import decode_bytes
    metadata = prepare_actual_authority_natural_pre_review_census_v3(maintenance, original,
        credential=credential, subject=permit.subject)
    try:
        _, context = require_actual_authority_natural_pre_review_census_v3(metadata, maintenance, original)
        with runtime_storage_operation_v3(service.core._db,
                operation_id='d13-pre-review-close:' + original.parent_original_id):
            with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                anchor = service.fences._current_locked(db, deletion, execution,
                    holder=permit.holder, generation=permit.generation)
                row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                    (service.authority_namespace, permit.operation_id)).fetchone()
                if (row is None or decode_bytes(row[0]) != permit or row[1] not in ('active', 'finished')
                        or permit.subject != 'mtls:sha256:' + credential.certificate_sha256):
                    raise AuthorityUnavailable('D13 pre-review closure lost its actual authenticated original scope')
                service._policy(db)
                prior = service._owner_operation_v3(db, original.owner_ref, 'owner_close')
                if prior is not None:
                    return prior
                verified_head, rows = maintenance.execution.journal._scan_locked()
                if verified_head != execution:
                    raise AuthorityUnavailable('D13 pre-review execution census changed after its frozen boundary')
                proof = _ActualPreReviewClosureProofV3(_ISSUER, service, maintenance,
                    server._v2_model_egress[service.authority_namespace], original, metadata, context,
                    credential, anchor, verified_head, rows)
                return service.close_original_owner_in_tx_v3(db, proof)
    finally:
        metadata.release_v3()

def actual_natural_parent_closure_in_tx_v3(service, db, parent_original_id):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    review_ref = natural_stage_owner_ref_v3(service.namespace,
        natural_job_ids_v2(service.namespace, parent_original_id, 'review')[0])
    result = service._owner_operation_v3(db, review_ref, 'owner_close')
    if result is not None:
        return result
    generation_ref = natural_stage_owner_ref_v3(service.namespace,
        natural_job_ids_v2(service.namespace, parent_original_id, 'generation')[0])
    disposition = service._owner_operation_v3(db, generation_ref, 'owner_pre_review_disposition')
    result = service._owner_operation_v3(db, generation_ref, 'owner_close')
    if disposition is None or result is None:
        return None
    if (result.disposition_kind != 'terminal' or result.disposition_ref != disposition.operation_id
            or result.disposition_digest != disposition.disposition_digest
            or result.registration_digest != disposition.registration_digest):
        raise AuthorityUnavailable('D13 generation closure has no exact permanent parent disposition')
    return result


def require_actual_d13_counter_birth_original_v3(service, birth):
    """Authenticate its saved bounded canonical-draft birth, without reading draft Body."""
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2, _OwnerMetadataV3, _bind_owner_metadata_v3
    from .d13_cache_use_contract_v2 import D13CounterFrameBirthReceiptV3
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2 or type(birth) is not D13CounterFrameBirthReceiptV3:
        raise AuthorityUnavailable('actual protected Counter draft birth original required')
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-counter-birth-metadata:' + birth.operation_id) as operation:
        provider = _OwnerMetadataV3(operation)
        try:
            with _bind_owner_metadata_v3(operation, provider), service.core._tx() as db, runtime_storage_quantum_v3(db):
                service._policy(db)
                actual = service._owner_operation_v3(db, birth.owner_ref, 'owner_counter_birth')
                registration = service._owner_operation_v3(db, birth.owner_ref, 'owner_register')
                if (actual != birth or registration is None or registration.owner_kind != 'counter_frame_draft'
                        or registration.registration_digest != actual.registration_digest
                        or registration.original_commitment != actual.draft_commitment
                        or registration.original_locator.counter_operation_id != actual.counter_operation_id
                        or registration.original_locator.parent_original_id != actual.parent_original_id
                        or registration.original_locator.frame_intent_id != actual.frame_intent_id
                        or registration.original_locator.frame_intent_digest != actual.frame_intent_digest):
                    raise AuthorityUnavailable('D13 Counter birth has no exact actual original registration/canonical draft commitment')
                return actual, registration
        finally:
            operation.unregister_retained_state_v3(provider)


_UNUSED_COUNTER_BASES_V3 = WeakKeyDictionary()


class _ActualUnusedCounterBasisV3:
    def __init__(self, issuer, service, birth, registration, revision):
        if issuer is not _ISSUER:
            raise TypeError('actual frozen Core unused-Counter census basis required')
        self.service, self.birth, self.registration, self.revision = service, birth, registration, revision
        _UNUSED_COUNTER_BASES_V3[self] = (service, birth, registration, revision)

    def release_v3(self):
        _UNUSED_COUNTER_BASES_V3.pop(self, None)


def _actual_counter_birth_in_tx_v3(service, db, birth):
    from .d13_cache_use_contract_v2 import D13CounterFrameBirthReceiptV3
    if type(birth) is not D13CounterFrameBirthReceiptV3:
        raise AuthorityUnavailable('actual immutable Counter birth required')
    actual = service._owner_operation_v3(db, birth.owner_ref, 'owner_counter_birth')
    registration = service._owner_operation_v3(db, birth.owner_ref, 'owner_register')
    if (actual != birth or registration is None or registration.owner_kind != 'counter_frame_draft'
            or registration.registration_digest != birth.registration_digest
            or registration.original_commitment != birth.draft_commitment
            or registration.original_locator.parent_original_id != birth.parent_original_id
            or registration.original_locator.counter_operation_id != birth.counter_operation_id):
        raise AuthorityUnavailable('D13 unused Counter census lost its actual canonical draft birth/registration')
    return actual, registration


def _actual_unused_counter_retention_in_tx_v3(service, db, birth, registration):
    from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
    from .v2_model_egress_store import AuthorityV2ModelEgressStore
    if service._live_owner_v3(db, registration.owner_ref) != registration:
        raise AuthorityUnavailable('D13 unused Counter is not its original live owner')
    retained = service._owner_operation_v3(db, registration.owner_ref, 'owner_retention_release')
    if retained is None or retained.registration_digest != registration.registration_digest:
        raise D13NaturalRosterNotTerminalV3('D13 unused Counter actual outer scope still retains its draft')
    stopped = _actual_owner_stop_for_parent_in_tx_v3(service, db, birth.parent_original_id, birth.activation_generation)
    if stopped is None:
        raise D13NaturalRosterNotTerminalV3('D13 unused Counter has no actual permanent Owner-stop disposition')
    for stage in ('generation', 'review'):
        ids = natural_job_ids_v2(service.namespace, birth.parent_original_id, stage)
        ref = natural_stage_owner_ref_v3(service.namespace, ids[0])
        if (service._owner_operation_v3(db, ref, 'owner_register') is not None
                or AuthorityV2ModelEgressStore._read(db, ids[3]) is not None):
            raise D13NaturalRosterNotTerminalV3('D13 unused Counter has an actual adopted natural original/model call')
    if AuthorityV2ModelEgressStore._read(db, birth.generation_call_id) is not None:
        raise D13NaturalRosterNotTerminalV3('D13 counted generation call was actually adopted')
    pending = db.execute("SELECT 1 FROM authority_d13_cache_use_operations_v2 r WHERE r.namespace=? "
        "AND r.action='owner_register' AND json_extract(r.result_json,'$.owner_kind') IN "
        "('graph_source_receiver','authority_source_receiver','host_frame_receiver') "
        "AND (json_extract(r.result_json,'$.original_locator.parent_original_id')=? OR "
        "json_extract(r.result_json,'$.permit_token')=?) AND NOT EXISTS("
        "SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=r.namespace AND c.action='owner_close' "
        "AND json_extract(c.result_json,'$.registration_digest')=json_extract(r.result_json,'$.registration_digest')) LIMIT 1",
        (service.authority_namespace, birth.parent_original_id, registration.permit_token)).fetchone()
    if pending is not None:
        raise D13NaturalRosterNotTerminalV3('D13 unused Counter still has an actual retained receiver/writer')
    return retained, stopped


def prepare_actual_d13_unused_counter_basis_v3(service, birth):
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('actual installed D13 Core service required')
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-unused-counter-basis:' + birth.operation_id):
        with service.fences._frozen() as (db, _, _, _), runtime_storage_quantum_v3(db):
            service._policy(db)
            actual, registration = _actual_counter_birth_in_tx_v3(service, db, birth)
            require_natural_parent_open_in_tx_v3(service, db, actual.parent_original_id)
            _actual_unused_counter_retention_in_tx_v3(service, db, actual, registration)
            row = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
                (service.authority_namespace,)).fetchone()
            if row is None:
                raise AuthorityUnavailable('D13 unused Counter census has no installed namespace head')
            return _ActualUnusedCounterBasisV3(_ISSUER, service, actual, registration, row[0])


def require_actual_d13_unused_counter_basis_v3(service, db, basis, birth):
    if (type(basis) is not _ActualUnusedCounterBasisV3
            or _UNUSED_COUNTER_BASES_V3.get(basis) != (service, birth, basis.registration, basis.revision)
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 unused Counter census lost its actual private frozen basis')
    row = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
        (service.authority_namespace,)).fetchone()
    if row != (basis.revision,):
        raise D13NaturalRosterNotTerminalV3('D13 ownership changed after Counter census; discard the whole absence proof')
    actual, registration = _actual_counter_birth_in_tx_v3(service, db, birth)
    if registration != basis.registration:
        raise AuthorityUnavailable('D13 unused Counter census changed its actual immutable registration')
    require_natural_parent_open_in_tx_v3(service, db, actual.parent_original_id)
    retained, stopped = _actual_unused_counter_retention_in_tx_v3(service, db, actual, registration)
    return actual, registration, retained, stopped


_UNUSED_COUNTER_CLOSES_V3 = WeakKeyDictionary()


class _ActualUnusedCounterClosureProofV3:
    def __init__(self, issuer, service, maintenance, counter, birth, metadata, context,
            credential, anchor, execution_head, execution_rows):
        if issuer is not _ISSUER:
            raise TypeError('actual frozen unused Counter disposition producer required')
        self.service, self.maintenance, self.counter, self.birth = service, maintenance, counter, birth
        self.metadata, self.context, self.credential, self.anchor = metadata, context, credential, anchor
        self.execution_head, self.execution_rows = execution_head, execution_rows
        _UNUSED_COUNTER_CLOSES_V3[self] = (service, maintenance, counter, birth, metadata, context,
            credential, anchor, execution_head, execution_rows)


def _actual_unused_counter_cpu_v3(proof, service, facts):
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from ..runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1
    from ..runtime.d13_counter_cpu_quote_policy_v1 import D13_COUNTER_CPU_WORK_KIND
    counter, birth = proof.counter, proof.birth
    if (type(counter) is not InstalledD13CoreCounterServiceV1 or counter.core is not service.core
            or counter.fences is not service.fences or counter.bridge is not proof.maintenance.execution):
        raise AuthorityUnavailable('D13 unused Counter has no actual installed same-Core CPU producer')
    prepared, job = facts['cpu_prepared'], facts['cpu_job']
    if prepared is not None:
        if type(prepared) is not C04InternalWorkPreparedV1:
            raise AuthorityUnavailable('D13 unused Counter requires its exact actual CPU preparation original')
        binding = prepared.binding
        if (binding.namespace != service.authority_namespace or binding.operation_id != birth.counter_operation_id
                or binding.activity_id != birth.planned_activity_id or binding.execution_id != birth.planned_execution_id
                or binding.input_digest != birth.input_digest or binding.activation_generation != birth.activation_generation
                or binding.algorithm_ref != birth.algorithm_ref or binding.algorithm_build_digest != birth.algorithm_build_digest
                or binding.parent_budget_lease_ref != birth.parent_budget_lease_ref
                or prepared.owner_grant_digest != birth.owner_grant_digest):
            raise AuthorityUnavailable('D13 actual CPU preparation differs from its immutable Counter birth')
    else:
        binding = None
    if job is not None:
        if (type(job) is not dict or set(job) != {'job_id', 'operation_id', 'activity_id',
                'effect_id', 'work_kind', 'phase', 'fence', 'cancel_epoch', 'result_ref'}
                or (job['job_id'], job['operation_id'], job['activity_id'], job['work_kind']) !=
                    (birth.planned_job_id, birth.counter_operation_id, birth.planned_activity_id, D13_COUNTER_CPU_WORK_KIND)):
            raise AuthorityUnavailable('D13 actual CPU job metadata differs from its immutable Counter birth')
    claim = terminal = None
    journal = proof.maintenance.execution.journal
    for row in proof.execution_rows:
        if not row[4].startswith(b'{"binding":'):
            continue
        actual_binding, actual_claim, actual_terminal = journal._decode_internal_row(row)
        if (actual_binding.operation_id != birth.counter_operation_id
                and actual_binding.execution_id != birth.planned_execution_id):
            continue
        if binding is None or actual_binding != binding:
            raise AuthorityUnavailable('D13 CPU journal has an unclassified Counter claim outside its actual preparation')
        if actual_terminal is None:
            claim = actual_claim
        else:
            terminal = actual_terminal
    if claim is None:
        if terminal is not None or job is not None and (job['phase'] != 'cancelled' or job['cancel_epoch'] < 1):
            raise D13NaturalRosterNotTerminalV3('D13 unclaimed Counter job remains startable or lacks actual cancellation')
        return canonical_digest(('actual_counter_claim_absent', prepared, job, proof.execution_head)), 'never_started'
    if (terminal is None or terminal.status == 'unknown'
            or not counter.internal_work.verify_installed_terminal(binding, claim, terminal)):
        raise D13NaturalRosterNotTerminalV3('D13 Counter CPU claim has no actual independently verified terminal')
    expected = 'completed' if terminal.status == 'completed' else 'failed'
    if job is None or job['phase'] != expected:
        raise D13NaturalRosterNotTerminalV3('D13 Counter terminal is not adopted by its actual final CPU job')
    return canonical_digest(('actual_counter_terminal', binding, claim, terminal, job, proof.execution_head)), 'terminal'


def _actual_unused_counter_closure_v3(proof, service, db):
    from ..runtime.d13_natural_original_use_v3 import require_actual_authority_unused_counter_census_v3
    from .d13_cache_use_contract_v2 import (D13UnusedCounterDispositionReceiptV3,
        UNUSED_COUNTER_DISPOSITION_SCHEMA_V3, owner_operation_id_v3, PROTOCOL)
    if (_UNUSED_COUNTER_CLOSES_V3.get(proof) != (service, proof.maintenance, proof.counter, proof.birth,
            proof.metadata, proof.context, proof.credential, proof.anchor, proof.execution_head, proof.execution_rows)
            or service.core._db is not db or not db.in_transaction):
        raise AuthorityUnavailable('D13 unused Counter disposition has no actual private frozen Core producer')
    facts, context = require_actual_authority_unused_counter_census_v3(proof.metadata, proof.maintenance, proof.birth)
    birth, registration, retained, stopped = require_actual_d13_unused_counter_basis_v3(
        service, db, proof.metadata.core_basis_v3, proof.birth)
    fields = {'generation_preparation', 'generation_acquisition', 'generation_call', 'generation_adoption',
        'review_preparation', 'review_acquisition', 'roster_head', 'graph_final_operation_ids',
        'graph_admissions', 'cpu_prepared', 'cpu_job', 'graph_snapshot_digest', 'graph_census_digest'}
    if (context is not proof.context or type(facts) is not dict or set(facts) != fields
            or any(facts[name] is not None for name in ('generation_preparation', 'generation_acquisition',
                'generation_call', 'review_preparation', 'review_acquisition', 'roster_head'))
            or any(facts[name] != () for name in ('generation_adoption', 'graph_final_operation_ids', 'graph_admissions'))):
        raise AuthorityUnavailable('D13 unused Counter lacks its exact complete actual no-adoption Graph census')
    context.require_current('business')
    proof.maintenance.owner._require_projection_pointer_in_tx_v1(db, context)
    cpu, disposition_kind = _actual_unused_counter_cpu_v3(proof, service, facts)
    owner = service.core._row(db, service.authority_namespace)
    effect = proof.maintenance.execution._read_current_effect_locked_v4(db,
        effect_id=birth.first_effect_id, execution_head=proof.execution_head,
        execution_rows=proof.execution_rows, owner=owner)
    final_attempt = 'natural-final:' + canonical_digest({
        'namespace': service.namespace.as_tuple, 'operation_id': birth.first_operation_id})[:48]
    if (effect.state != 'absent' or service.fences.fences._row(db, final_attempt) is not None
            or service.fences.fences._row(db, birth.first_operation_id) is not None
            or db.execute('SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND operation_id IN (?,?) LIMIT 1',
                (service.authority_namespace, birth.first_operation_id, final_attempt)).fetchone() is not None):
        raise D13NaturalRosterNotTerminalV3('D13 unused Counter parent already has an actual final/dispatch effect or attempt')
    material = dict(parent_original_id=birth.parent_original_id,
        counter_birth_ref=birth.operation_id, counter_birth_digest=birth.birth_digest,
        cause_ref=stopped[0], cause_digest=stopped[1], cpu_census_digest=cpu,
        census_root=canonical_digest((birth.birth_digest, facts['graph_census_digest'], cpu,
            proof.execution_head, stopped, retained.retention_digest, proof.metadata.core_basis_v3.revision)),
        core_head_digest=canonical_digest(proof.anchor), graph_snapshot_digest=facts['graph_snapshot_digest'],
        retention_digest=retained.retention_digest)
    values = dict(namespace=service.namespace, authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=registration.owner_ref,
        registration_digest=registration.registration_digest, **material,
        operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_unused_counter_disposition'),
        request_digest=canonical_digest((PROTOCOL, 'owner_unused_counter_disposition', registration.registration_digest, material)),
        control_revision=service._revision(db), schema=UNUSED_COUNTER_DISPOSITION_SCHEMA_V3)
    values['disposition_digest'] = canonical_digest(values)
    disposition = service._record(db, 'owner_unused_counter_disposition', D13UnusedCounterDispositionReceiptV3(**values))
    return registration, dict(disposition_kind=disposition_kind, disposition_ref=disposition.operation_id,
        disposition_digest=disposition.disposition_digest, retention_release_ref=retained.operation_id,
        retention_release_digest=retained.retention_digest, successor_transfer_digest=None), proof.credential


def close_authenticated_d13_unused_counter_v3(server, service, *, credential, profile_id,
        manifest_digest, permit, parent_original_id, counter_operation_id):
    from .natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from .v2_contract import decode_bytes
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    from ..runtime.d13_natural_original_use_v3 import (prepare_actual_authority_unused_counter_census_v3,
        require_actual_authority_unused_counter_census_v3)
    service.core._require(credential, 'd13_cache_use_close_original', service.authority_namespace, permit.holder)
    _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
    owner = server._owner_stop_reply_services_v1.get((service.authority_namespace, service.installation_id))
    maintenance = None if owner is None else owner.natural_disposition_maintenance
    if (type(maintenance) is not InstalledNaturalDispositionMaintenanceServiceV1
            or maintenance.owner.core is not service.core or permit.operation not in ('read', 'write')):
        raise AuthorityUnavailable('D13 unused Counter requires its actual installed metadata maintenance/permit')
    ref = counter_frame_owner_ref_v3(service.namespace, counter_operation_id)
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-unused-counter-state:' + counter_operation_id):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            service._policy(db)
            row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                (service.authority_namespace, permit.operation_id)).fetchone()
            if (row is None or decode_bytes(row[0]) != permit or row[1] not in ('active', 'finished')
                    or permit.subject != 'mtls:sha256:' + credential.certificate_sha256):
                raise AuthorityUnavailable('D13 unused Counter metadata census lost its actual original authenticated scope')
            birth = service._owner_operation_v3(db, ref, 'owner_counter_birth')
            if birth is None or birth.parent_original_id != parent_original_id:
                raise AuthorityUnavailable('D13 historical Counter has no exact actual birth; legacy_unknown')
            prior = service._owner_operation_v3(db, ref, 'owner_close')
            if prior is not None:
                if service._owner_operation_v3(db, ref, 'owner_unused_counter_disposition') is None:
                    raise AuthorityUnavailable('D13 Counter was transferred; unused-parent closure cannot replace that lineage')
                return prior
    metadata = prepare_actual_authority_unused_counter_census_v3(maintenance, birth,
        credential=credential, subject=permit.subject)
    try:
        _, context = require_actual_authority_unused_counter_census_v3(metadata, maintenance, birth)
        with runtime_storage_operation_v3(service.core._db, operation_id='d13-unused-counter-close:' + counter_operation_id):
            with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                anchor = service.fences._current_locked(db, deletion, execution,
                    holder=permit.holder, generation=permit.generation)
                row = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                    (service.authority_namespace, permit.operation_id)).fetchone()
                if (row is None or decode_bytes(row[0]) != permit or row[1] not in ('active', 'finished')
                        or permit.subject != 'mtls:sha256:' + credential.certificate_sha256):
                    raise AuthorityUnavailable('D13 unused Counter closure lost its actual original authenticated scope')
                service._policy(db)
                prior = service._owner_operation_v3(db, ref, 'owner_close')
                if prior is not None:
                    return prior
                verified, rows = maintenance.execution.journal._scan_locked()
                if verified != execution:
                    raise AuthorityUnavailable('D13 Counter execution census changed after its actual frozen boundary')
                proof = _ActualUnusedCounterClosureProofV3(_ISSUER, service, maintenance,
                    server._d13_core_counters_v1[service.authority_namespace], birth, metadata, context,
                    credential, anchor, verified, rows)
                return service.close_original_owner_in_tx_v3(db, proof)
    finally:
        metadata.release_v3()


_CORE_BIRTHS_V4 = WeakKeyDictionary()
_CORE_INSTANCE_NONCES_V4 = WeakKeyDictionary()


class _ActualCoreBirthProofV4:
    def __init__(self, issuer, service, daemon, control, original, nonce):
        if issuer is not _ISSUER:
            raise TypeError('actual installed Core/process/Root birth producer required')
        self.service, self.daemon, self.control = service, daemon, control
        self.original, self.nonce, self.lease = original, nonce, daemon._lock_handle

    def require_v4(self):
        from .c09_process_identity_v1 import read_process_identity_v1
        import os
        service, daemon, original = self.service, self.daemon, self.original
        if (_CORE_BIRTHS_V4.get(service) is not self or _CORE_INSTANCE_NONCES_V4.get(service.core) != self.nonce
                or daemon.core is not service.core or daemon.server._core is not service.core
                or daemon.c09_control is not self.control or daemon._lock_handle is not self.lease
                or self.control.lease is not self.lease or daemon._closed
                or read_process_identity_v1(os.getpid()) != original.authority_process_original
                or original.namespace != service.namespace or original.authority_namespace != service.authority_namespace
                or original.installation_id != service.installation_id
                or original.use_policy_digest != service.use_policy.digest
                or original.consumer_cohort_digest != service.use_policy.consumer_cohort_digest):
            raise AuthorityUnavailable('D13 local V4 receiver lost its actual Core/process/instance-lock birth')
        self.lease.require_held()
        self.control.verify_original_v1(asdict(original), 'birth_digest')
        return original


def install_actual_d13_core_incarnation_v4(service, *, qualification, daemon):
    """Only the actual fresh installer may publish a new explicit local-v4 birth."""
    from .d13_cache_use_control_v2 import (InstalledD13CacheUseControlServiceV2, _FRESH_INSTALLATIONS_V3)
    from ..runtime.d13_consumer_manifest_v3 import require_actual_d13_core_birth_material_v4
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('actual installed D13 Core service required')
    matches = [item for item in _FRESH_INSTALLATIONS_V3 if item.service is service]
    if len(matches) != 1:
        raise AuthorityUnavailable('D13 Core birth requires its exact private fresh installation transaction')
    installation = matches[0].require_v3()
    if (installation.manifest.daemon is not daemon
            or installation.manifest.activation.qualification is not qualification
            or installation.phase != 'installing' or installation.constructing or installation.finalized is not None):
        raise AuthorityUnavailable('D13 Core birth is outside its actual fresh consumer installation phase')
    db = installation.db
    with runtime_storage_operation_v3(db, operation_id='d13-core-birth-v4'):
        with runtime_storage_quantum_v3(db):
            control, material = require_actual_d13_core_birth_material_v4(qualification,
                service=service, daemon=daemon, installation=installation)
            if control is not installation.coverage.control:
                raise AuthorityUnavailable('D13 fresh Core birth changed its actual Control')
            return _record_actual_core_birth_in_tx_v4(_ISSUER, service=service, daemon=daemon,
                control=control, material=material, profile=installation.manifest.request.consumer_mode,
                credential=installation.credential, db=db)


def require_actual_d13_core_birth_v4(service):
    proof = _CORE_BIRTHS_V4.get(service)
    if type(proof) is not _ActualCoreBirthProofV4:
        raise AuthorityUnavailable('D13 explicit local-v4 profile has no actual installed Core birth')
    return proof.require_v4()



def require_actual_fresh_d13_core_birth_operation_v4(service, *, daemon, db):
    """Return only this uncommitted installer's exact immutable birth row."""
    from .d13_cache_use_control_v2 import (
        InstalledD13CacheUseControlServiceV2, _FRESH_INSTALLATIONS_V3,
        _OwnerMetadataV3, _bind_owner_metadata_v3)
    from .d13_cache_use_contract_v2 import cache_use_to_wire_v2
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('actual fresh installed Core birth service required')
    matches = [item for item in _FRESH_INSTALLATIONS_V3 if item.service is service]
    if len(matches) != 1:
        raise AuthorityUnavailable('fresh birth inventory requires its exact private installation')
    installation = matches[0].require_v3()
    if (installation.manifest.daemon is not daemon or installation.db is not db
            or service.core._db is not db or not db.in_transaction
            or installation.phase != 'installing' or installation.constructing
            or installation.finalized is not None or not service.core._lock._is_owned()):
        raise AuthorityUnavailable('fresh birth inventory is outside its original installation transaction')
    proof = _CORE_BIRTHS_V4.get(service)
    if type(proof) is not _ActualCoreBirthProofV4 or proof.daemon is not daemon:
        raise AuthorityUnavailable('fresh birth inventory has no actual same-daemon private acknowledgement')
    birth = proof.require_v4()
    with runtime_storage_operation_v3(db, operation_id='d13-fresh-birth-inventory-v4') as operation:
        provider = _OwnerMetadataV3(operation)
        try:
            with _bind_owner_metadata_v3(operation, provider), runtime_storage_quantum_v3(db) as meter:
                actual = service._owner_operation_v3(db, birth.owner_ref, 'owner_core_birth')
                row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                    ('namespace', 'operation_id', 'action', 'request_digest', 'result_json'),
                    'namespace=? AND operation_id=?',
                    (service.authority_namespace, birth.operation_id), 'fresh_core_birth_inventory')
                expected = (service.authority_namespace, birth.operation_id, 'owner_core_birth',
                    birth.request_digest, canonical_serialize(cache_use_to_wire_v2(birth)))
                if actual != birth or row != expected:
                    raise AuthorityUnavailable('fresh birth inventory differs from actual immutable Core original')
                return expected
        finally:
            operation.unregister_retained_state_v3(provider)


def bind_actual_authority_source_locator_v4(owner, locator):
    from ..runtime.d13_cache_use_admission_v2 import _AuthorityConsumerOwnerV2
    from .d13_cache_use_contract_v2 import D13AuthoritySourceReceiverOwnerLocatorV4, D13SourceReceiverOwnerLocatorV3
    if type(owner) is not _AuthorityConsumerOwnerV2 or type(locator) is not D13SourceReceiverOwnerLocatorV3:
        raise AuthorityUnavailable('D13 local-v4 locator requires its actual qualified Authority Source owner')
    owner.require_live()
    service = owner.port.service
    proof = _CORE_BIRTHS_V4.get(service)
    if proof is None:
        from ..runtime.d13_consumer_manifest_v3 import installed_d13_consumer_cohort_digest_v3
        if service.use_policy.consumer_cohort_digest == installed_d13_consumer_cohort_digest_v3():
            raise AuthorityUnavailable('D13 explicit local-v4 cohort has no current actual Core birth; cannot downgrade to V3')
        return locator
    birth = proof.require_v4()
    return D13AuthoritySourceReceiverOwnerLocatorV4(locator.owner_kind, locator.source_operation_id,
        locator.source_permit_token, locator.source_permit_digest, locator.receiver_id, locator.retention_id,
        owner.operation.selection_digest, birth.core_incarnation_id, birth.operation_id, birth.birth_digest)


def require_actual_authority_source_locator_in_tx_v4(service, db, locator):
    from .d13_cache_use_contract_v2 import D13AuthoritySourceReceiverOwnerLocatorV4
    if type(locator) is not D13AuthoritySourceReceiverOwnerLocatorV4:
        return
    birth = require_actual_d13_core_birth_v4(service)
    actual = service._owner_operation_v3(db, birth.owner_ref, 'owner_core_birth')
    if (actual != birth or locator.core_incarnation_id != birth.core_incarnation_id
            or locator.core_birth_original_ref != birth.operation_id or locator.core_birth_original_digest != birth.birth_digest):
        raise AuthorityUnavailable('D13 local-v4 Source receiver differs from its actual registered Core birth')

def revoke_uncommitted_d13_core_birth_v4(service):
    _CORE_BIRTHS_V4.pop(service, None)


def detach_closed_actual_d13_core_birth_v4(daemon):
    """Release only process-local producer metadata after the actual Core is closed."""
    from .daemon import AuthorityDaemon
    if type(daemon) is not AuthorityDaemon or not daemon._closed or daemon.core._db is not None:
        raise AuthorityUnavailable('D13 Core birth binding can detach only after actual daemon/Core close')
    for service, proof in tuple(_CORE_BIRTHS_V4.items()):
        if proof.daemon is daemon:
            _CORE_BIRTHS_V4.pop(service, None)
    _CORE_INSTANCE_NONCES_V4.pop(daemon.core, None)
    progress = _CURRENT_CORE_RECEIVER_CLEANUPS_V4.pop(daemon, None)
    if progress is not None:
        from contextlib import ExitStack
        with ExitStack() as cleanup:
            cleanup.callback(progress.control.unregister_c09_retained_state_v3, progress)
            if progress.pending_cap is not None:
                cleanup.callback(progress.pending_cap.release_v4)
            if progress.pending_write_proof is not None:
                cleanup.callback(progress.pending_write_proof.release_v3)


def reconcile_actual_d13_owner_stop_unused_counter_v3(server, service, *, credential,
        profile_id, manifest_digest, stop_original):
    """One actual stopped-parent Counter; no new permit, Source or execution is issued."""
    from .owner_stop_reply_v1 import (InstalledOwnerStopReplyServiceV1,
        require_owner_stop_reply_original_v1, validate_owner_stop_reply_core_row_v1)
    from ..runtime.lifecycle_operations_v1 import decode_original
    from ..runtime.d13_natural_original_use_v3 import (prepare_actual_authority_unused_counter_census_v3,
        require_actual_authority_unused_counter_census_v3)
    from .d13_cache_use_control_v2 import _OwnerMetadataV3, _bind_owner_metadata_v3, _actual_owner_fixed_row_v3
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    import json
    original = require_owner_stop_reply_original_v1(stop_original)
    owner = server._owner_stop_reply_services_v1.get((service.authority_namespace, service.installation_id))
    if (type(owner) is not InstalledOwnerStopReplyServiceV1 or owner.core is not service.core
            or original.namespace != service.namespace):
        raise AuthorityUnavailable('D13 stopped Counter cleanup requires its actual installed Owner-stop producer')
    maintenance = owner.natural_disposition_maintenance
    if maintenance is None or maintenance.owner is not owner:
        raise AuthorityUnavailable('D13 stopped Counter cleanup lost its actual independent metadata producer')
    service.core._require(credential, 'd13_cache_use_close_original', service.authority_namespace)
    _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest)
    with runtime_storage_operation_v3(service.core._db,
            operation_id='d13-stop-counter-discovery:' + original.operation_id) as operation:
        provider = _OwnerMetadataV3(operation)
        try:
            with _bind_owner_metadata_v3(operation, provider), service.core._tx() as db, runtime_storage_quantum_v3(db) as meter:
                service._policy(db)
                row = meter.read_fixed_row(db, 'authority_d12_operation_originals_v1',
                    ('authority_namespace', 'operation_id', 'original_ref', 'original_json',
                        'actor', 'session_request_json', 'owner_head', 'plan_json', 'source_original_ref'),
                    'authority_namespace=? AND operation_id=?', (service.authority_namespace, original.operation_id))
                if row is None:
                    raise AuthorityUnavailable('D13 stopped Counter cleanup has no actual saved Owner-stop original')
                validate_owner_stop_reply_core_row_v1(row)
                actual = decode_original(json.loads(row[3]))
                if actual != original:
                    raise AuthorityUnavailable('D13 stopped Counter cleanup changed its exact actual Core stop original')
                plan = json.loads(row[7])
                if plan['request']['installation_id'] != service.installation_id:
                    raise AuthorityUnavailable('D13 stopped Counter cleanup crossed its installed Owner-stop scope')
                parent = plan['scope']['c02_operation_id']
                selected = _actual_owner_fixed_row_v3(db, meter, 'authority_d13_cache_use_operations_v2',
                    ('operation_id', 'result_json'),
                    "namespace=? AND action='owner_counter_birth' "
                    "AND json_extract(result_json,'$.parent_original_id')=? AND NOT EXISTS("
                    "SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=? AND c.action='owner_close' "
                    "AND json_extract(c.result_json,'$.registration_digest')="
                    "json_extract(authority_d13_cache_use_operations_v2.result_json,'$.registration_digest')) "
                    "ORDER BY operation_id",
                    (service.authority_namespace, parent, service.authority_namespace), slot='stopped_counter_birth')
                if selected is None:
                    unknown = db.execute("SELECT 1 FROM authority_d13_cache_use_operations_v2 r WHERE r.namespace=? "
                        "AND r.action='owner_register' AND json_extract(r.result_json,'$.owner_kind')='counter_frame_draft' "
                        "AND (json_extract(r.result_json,'$.original_locator.parent_original_id')=? "
                        "OR json_type(r.result_json,'$.original_locator.parent_original_id') IS NULL) "
                        "AND NOT EXISTS(SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=r.namespace "
                        "AND c.action='owner_close' AND json_extract(c.result_json,'$.registration_digest')="
                        "json_extract(r.result_json,'$.registration_digest')) LIMIT 1",
                        (service.authority_namespace, parent)).fetchone()
                    if unknown is not None:
                        raise AuthorityUnavailable('D13 stopped parent retains an unknown legacy Counter without its actual birth')
                    return dict(status='complete', parent_original_id=parent)
                from .d13_cache_use_contract_v2 import cache_use_result_from_wire_v3, D13CounterFrameBirthReceiptV3
                birth = cache_use_result_from_wire_v3(json.loads(selected[1]))
                if (type(birth) is not D13CounterFrameBirthReceiptV3 or birth.operation_id != selected[0]
                        or birth.parent_original_id != parent):
                    raise AuthorityUnavailable('D13 stopped-parent birth discovery is not its exact immutable typed original')
                _actual_counter_birth_in_tx_v3(service, db, birth)
        finally:
            operation.unregister_retained_state_v3(provider)
    metadata = prepare_actual_authority_unused_counter_census_v3(maintenance, birth,
        credential=credential, subject='mtls:sha256:' + credential.certificate_sha256)
    try:
        _, context = require_actual_authority_unused_counter_census_v3(metadata, maintenance, birth)
        with runtime_storage_operation_v3(service.core._db,
                operation_id='d13-stopped-counter-close:' + birth.counter_operation_id):
            with service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                anchor = service.fences._current_locked(db, deletion, execution)
                service._policy(db)
                if _actual_owner_stop_for_parent_in_tx_v3(service, db, parent, birth.activation_generation) != (
                        original.original_ref, original.original_digest.removeprefix('sha256:')):
                    raise AuthorityUnavailable('D13 stopped Counter changed its independently saved permanent cause')
                verified, rows = maintenance.execution.journal._scan_locked()
                if verified != execution:
                    raise AuthorityUnavailable('D13 stopped Counter execution census changed after its actual frozen boundary')
                proof = _ActualUnusedCounterClosureProofV3(_ISSUER, service, maintenance,
                    server._d13_core_counters_v1[service.authority_namespace], birth, metadata, context,
                    credential, anchor, verified, rows)
                receipt = service.close_original_owner_in_tx_v3(db, proof)
                return dict(status='closed_one', parent_original_id=parent,
                    counter_operation_id=birth.counter_operation_id, closure=receipt)
    finally:
        metadata.release_v3()


def _record_actual_core_birth_in_tx_v4(issuer, *, service, daemon, control, material, profile, credential, db):
    from .d13_cache_use_contract_v2 import D13AuthorityCoreBirthReceiptV4, CORE_BIRTH_SCHEMA_V4, owner_operation_id_v3, PROTOCOL, cache_use_from_wire_v2
    from .c09_process_identity_v1 import read_process_identity_v1
    import os, secrets
    if (issuer is not _ISSUER or service.core._db is not db or not db.in_transaction
            or not service.core._lock._is_owned()):
        raise AuthorityUnavailable('D13 Core birth recording requires its actual qualified private installer transaction')
    fields = {'authority_process_original', 'root_observation_original',
        'root_authority_observation_digest', 'root_process_census_digest',
        'authority_spec_digest', 'instance_lock_ref', 'selected_manifest_digest', 'pointer_version',
        'storage_generation', 'producer_binding_digest'}
    if (type(material) is not dict or set(material) != fields
            or control is not daemon.c09_control or control.lease is not daemon._lock_handle
            or material['authority_process_original'] != read_process_identity_v1(os.getpid())):
        raise AuthorityUnavailable('D13 Core birth differs from its actual Root process/Control/instance-lock material')
    import json
    material = dict(material, root_observation_original=json.loads(canonical_serialize(
        material['root_observation_original'])))
    prior = _CORE_BIRTHS_V4.get(service)
    if prior is not None:
        actual = prior.require_v4()
        if any(getattr(actual, name) != value for name, value in material.items()):
            raise AuthorityUnavailable('D13 Core birth cannot change its actual Root/process material')
        return actual
    service.core._require(credential, 'd13_cache_use_install', service.authority_namespace)
    nonce = _CORE_INSTANCE_NONCES_V4.setdefault(service.core, secrets.token_hex(32))
    ref = 'd13-authority-core-incarnation-v4:' + canonical_digest((service.namespace,
        material['authority_process_original'], nonce, service.installation_id))
    values = dict(namespace=asdict(service.namespace), authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, authority_id=control.authority_id,
        control_store_id=control.control_store_id, owner_ref=ref, core_incarnation_id=ref,
        birth_profile=profile,
        core_instance_nonce_digest=canonical_digest(nonce), **material,
        use_policy_ref=service.use_policy.policy_ref, use_policy_digest=service.use_policy.digest,
        consumer_cohort_digest=service.use_policy.consumer_cohort_digest,
        operation_id=owner_operation_id_v3(service.namespace, ref, 'owner_core_birth'), schema=CORE_BIRTH_SCHEMA_V4)
    values['request_digest'] = canonical_digest((PROTOCOL, 'owner_core_birth', values))
    values['control_revision'] = service._revision(db)
    signed = control.sign_original_v1(CORE_BIRTH_SCHEMA_V4, values, 'birth_digest')
    from .d13_cache_use_contract_v2 import cache_use_from_wire_v2
    original = cache_use_from_wire_v2(signed, D13AuthorityCoreBirthReceiptV4)
    service._record(db, 'owner_core_birth', original)
    proof = _ActualCoreBirthProofV4(_ISSUER, service, daemon, control, original, nonce)
    _CORE_BIRTHS_V4[service] = proof
    return proof.require_v4()


def install_actual_current_d13_core_incarnation_v4(service, *, qualification, daemon):
    """A new current Core birth under its existing installed policy and Root hold."""
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    from .daemon import AuthorityDaemon
    from ..runtime.d13_consumer_manifest_v3 import (require_actual_current_d13_core_birth_material_v4,
        installed_d13_consumer_cohort_digest_v3)
    from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
    if (type(service) is not InstalledD13CacheUseControlServiceV2 or type(daemon) is not AuthorityDaemon
            or daemon.core is not service.core or daemon.server._core is not service.core
            or daemon._closed or daemon.is_listening or service.core._db is None
            or service.core._db.in_transaction or not service.use_policy.enabled
            or service.use_policy.consumer_cohort_digest != installed_d13_consumer_cohort_digest_v3()):
        raise AuthorityUnavailable('D13 current Core birth requires its actual closed-entry local-v4 installation')
    control, gate = daemon.c09_control, daemon.c09_gate
    if (control is None or gate is None or gate.control is not control
            or control.lease is not daemon._lock_handle or gate._operation is not None or gate._active):
        raise AuthorityUnavailable('D13 current Core birth lost its actual continuous pending bootstrap Gate/lease')
    with control._resource_sql_quantum_v3() as meter:
        hold = gate.require_pending_start_bootstrap_scope_v3(meter=meter)
    # The exact current-qualification accessor rejects every other producer or
    # changed Root hold; this branch never borrows a fresh constructor transaction.
    with runtime_storage_operation_v3(service.core._db, operation_id='d13-current-core-birth-v4'):
        with service.core._tx() as db, runtime_storage_quantum_v3(db):
            service._policy(db)
            actual_control, material = require_actual_current_d13_core_birth_material_v4(qualification,
                service=service, daemon=daemon, db=db)
            profile = qualification.consumer_mode
            with control._resource_sql_quantum_v3() as meter:
                if (actual_control is not control
                        or gate.require_pending_start_bootstrap_scope_v3(meter=meter) is not hold):
                    raise AuthorityUnavailable('D13 current Core birth changed its actual Root hold/Control')
            credential = daemon.config.local_administrator_credential('d13_cache_use_install', service.authority_namespace)
            return _record_actual_core_birth_in_tx_v4(_ISSUER, service=service, daemon=daemon,
                control=control, material=material, profile=profile, credential=credential, db=db)


_CURRENT_CORE_RECEIVER_CLEANUPS_V4 = WeakKeyDictionary()
_CURRENT_CORE_RECEIVER_CLOSES_V4 = WeakKeyDictionary()


class _CurrentCoreReceiverCloseProofV4:
    def __init__(self, issuer, progress, physical, terminal, successor):
        if issuer is not _ISSUER:
            raise TypeError('actual current-bootstrap retired Core receiver producer required')
        self.progress, self.physical, self.terminal, self.successor = progress, physical, terminal, successor
        _CURRENT_CORE_RECEIVER_CLOSES_V4[self] = (progress, physical, terminal, successor)


def _current_core_receiver_closure_v4(proof, service, db):
    from .d13_cache_use_contract_v2 import (D13RetiredCoreReceiverOriginalV4,
        CORE_RETIREMENT_SCHEMA_V4, cache_use_from_wire_v2, owner_operation_id_v3, PROTOCOL)
    progress = proof.progress
    if (_CURRENT_CORE_RECEIVER_CLOSES_V4.get(proof) !=
            (progress, proof.physical, proof.terminal, proof.successor) or progress.service is not service):
        raise AuthorityUnavailable('D13 retired local Core close lost its actual private producer')
    progress.require_v4(db=db)
    registration, birth = progress.pending_registration, progress.pending_birth
    if service._live_owner_v3(db, registration.owner_ref) != registration:
        raise AuthorityUnavailable('D13 retired local receiver changed its original active registration')
    actual_birth = service._owner_operation_v3(db, birth.owner_ref, 'owner_core_birth')
    progress.control.verify_original_v1(asdict(birth), 'birth_digest')
    physical = progress.pending_cap.require_current(control=progress.control, gate=progress.gate,
        birth=birth, qualification=progress.qualification)
    if (actual_birth != birth or canonical_digest(physical) != canonical_digest(proof.physical)
            or physical['birth_selector_digest'] != canonical_digest(asdict(birth))
            or physical['old_root_observation_digest'] != birth.root_process_census_digest
            or physical['old_authority_process_original'] != birth.authority_process_original
            or physical['birth_storage_manifest_digest'] != birth.selected_manifest_digest
            or physical['birth_pointer_version'] != birth.pointer_version
            or physical['birth_storage_generation'] != birth.storage_generation):
        raise AuthorityUnavailable('D13 retired local receiver changed its independently qualified Root/birth/selection')
    current = require_actual_d13_core_birth_v4(service)
    values = dict(namespace=asdict(service.namespace), authority_namespace=service.authority_namespace,
        installation_id=service.installation_id, owner_ref=registration.owner_ref,
        registration_digest=registration.registration_digest, core_incarnation_id=birth.core_incarnation_id,
        core_birth_original_ref=birth.operation_id, core_birth_original_digest=birth.birth_digest,
        current_core_birth_ref=current.operation_id, current_core_birth_digest=current.birth_digest,
        birth_profile=birth.birth_profile, physical_retirement_original=proof.physical,
        physical_retirement_digest=canonical_digest(proof.physical), source_permit_token=registration.permit_token,
        source_permit_digest=registration.permit_digest, terminal_ref=proof.terminal[0],
        terminal_digest=proof.terminal[1],
        operation_id=owner_operation_id_v3(service.namespace, registration.owner_ref, 'owner_core_retirement'),
        schema=CORE_RETIREMENT_SCHEMA_V4)
    values['request_digest'] = canonical_digest((PROTOCOL, 'owner_core_retirement', values))
    values['control_revision'] = service._revision(db)
    signed = progress.control.sign_original_v1(CORE_RETIREMENT_SCHEMA_V4, values, 'retirement_digest')
    retained = cache_use_from_wire_v2(signed, D13RetiredCoreReceiverOriginalV4)
    service._record(db, 'owner_core_retirement', retained)
    material = dict(disposition_kind='core_retired', disposition_ref=retained.operation_id,
        disposition_digest=retained.retirement_digest, retention_release_ref=retained.operation_id,
        retention_release_digest=retained.retirement_digest, successor_transfer_digest=None)
    if proof.successor is not None:
        material.update(proof.successor)
        _require_actual_source_successor_in_tx_v3(service, db, registration, material)
    return registration, material, progress.credential


def _current_retired_core_terminal_v4(progress, service, db, registration, deletion, execution):
    from .d13_cache_use_contract_v2 import D13AuthoritySourceReceiverOwnerLocatorV4
    locator = registration.original_locator
    row = service.fences.fences._row(db, registration.original_operation_id)
    if row is None or type(locator) is not D13AuthoritySourceReceiverOwnerLocatorV4:
        raise AuthorityUnavailable('D13 retired local receiver has no actual V4 saved Source fence')
    permit = service.fences.fences._permit(row)
    if (permit.namespace != service.authority_namespace or permit.subject != registration.subject
            or permit.token != registration.permit_token or canonical_digest(permit) != registration.permit_digest
            or locator.source_operation_id != permit.operation_id or locator.source_permit_token != permit.token
            or locator.source_permit_digest != canonical_digest(permit) or row[10] is not None):
        raise AuthorityUnavailable('D13 retired local receiver changed its exact permit or has pending work')
    service.fences.fences._require_no_migration(db)
    candidates = db.execute("SELECT json_extract(r.result_json,'$.owner_ref') FROM authority_d13_cache_use_operations_v2 r "
        "WHERE r.namespace=? AND r.action='owner_register' AND json_extract(r.result_json,'$.permit_token')=? "
        "AND json_extract(r.result_json,'$.owner_kind') IN ('natural_generation_original','natural_review_original') "
        "AND NOT EXISTS(SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=r.namespace "
        "AND c.action='owner_close' AND json_extract(c.result_json,'$.registration_digest')="
        "json_extract(r.result_json,'$.registration_digest')) ORDER BY r.operation_id LIMIT 2",
        (service.authority_namespace, registration.permit_token)).fetchall()
    if len(candidates) > 1:
        raise AuthorityUnavailable('D13 retired local Source has ambiguous durable successor originals')
    if candidates:
        successor = service._live_owner_v3(db, candidates[0][0])
        transfer = dict(disposition_kind='transferred', disposition_ref=successor.operation_id,
            disposition_digest=successor.registration_digest,
            successor_transfer_digest=canonical_digest(('d13.source-receiver-transfer.v3',
                registration.registration_digest, successor.registration_digest,
                tuple(identity[:3] for identity in registration.payload_identities))))
        _require_actual_source_successor_in_tx_v3(service, db, registration, transfer)
        return (successor.operation_id, successor.registration_digest), transfer
    if row[6] == 'active' and permit.operation == 'read':
        anchor = service.fences._current_locked(db, deletion, execution,
            holder=permit.holder, generation=permit.generation)
        if anchor != permit.pinned_anchor:
            raise AuthorityUnavailable('D13 retired local READ anchor differs; original obligation remains')
        request_id = 'd13-core-retirement-read-finish-v4:' + canonical_digest((
            progress.pending_birth.birth_digest, registration.registration_digest))
        request_digest = 'sha256:' + canonical_digest(('sylanne3.d13.core-retirement-read-finish.v4',
            progress.pending_birth.birth_digest, progress.pending_physical, permit))
        service.fences.fences.finish_fence_locked(db, permit, subject=registration.subject,
            current_anchor=anchor, request_id=request_id, request_digest=request_digest)
        row = service.fences.fences._row(db, permit.operation_id)
    if permit.operation == 'model_egress':
        return _retired_model_terminal_v3(progress, service, db, registration, permit, row), None
    if permit.operation == 'write':
        return _retired_write_terminal_core_v3(progress, service, db, registration, permit, row, deletion, execution), None
    if permit.operation != 'read' or row[6] != 'finished' or row[8] is None or row[9] is None:
        raise AuthorityUnavailable('D13 retired local Source awaits its actual protocol terminal or durable successor')
    return ('authority-v2-fence:' + permit.operation_id, canonical_digest((permit, row[6], row[8:11]))), None


class _CurrentCoreReceiverCleanupV4:
    def __init__(self, issuer, daemon, qualification, service, hold):
        if issuer is not _ISSUER:
            raise TypeError('actual current-bootstrap local Core cleanup producer required')
        self.daemon, self.qualification, self.service, self.hold = daemon, qualification, service, hold
        self.maintenance, self.control, self.gate = daemon.c09_maintenance, daemon.c09_control, daemon.c09_gate
        self.credential = self.maintenance.credential
        self.after, self.closed, self.failed, self.complete = '', 0, None, False
        self.pending_registration = self.pending_birth = self.pending_cap = self.pending_physical = None
        self.pending_write_proof = None
        self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from .d13_cache_use_control_v2 import _owner_metadata_heap_v3
        return _owner_metadata_heap_v3((self.after, self.failed, self.pending_registration,
            self.pending_birth, self.pending_physical)) + 8192

    def require_v4(self, *, db=None):
        from ..runtime.d13_consumer_manifest_v3 import require_actual_d13_current_core_receiver_cleanup_v4
        if _CURRENT_CORE_RECEIVER_CLEANUPS_V4.get(self.daemon) is not self:
            raise AuthorityUnavailable('D13 current Core cleanup lost its actual private state')
        with self.control._resource_sql_quantum_v3() as meter:
            require_actual_d13_current_core_receiver_cleanup_v4(self.qualification, self.daemon,
                self.hold, meter, db=db)
        if (self.maintenance.core is not self.service.core or self.service.core is not self.daemon.core
                or self.maintenance.control is not self.control):
            raise AuthorityUnavailable('D13 current Core cleanup crossed its actual selected Core/Control')
        self.service.core._require(self.credential, 'delete', self.service.authority_namespace)

    def result_v4(self, status, phase):
        return dict(status=status, phase=phase, closed_receivers=self.closed,
            after_operation_id=self.after, first_failure=self.failed)

    def advance_v4(self):
        from .d13_cache_use_control_v2 import _OwnerMetadataV3, _bind_owner_metadata_v3, _actual_owner_fixed_row_v3
        from .d13_cache_use_contract_v2 import (D13OwnerRegistrationReceiptV3,
            D13AuthoritySourceReceiverOwnerLocatorV4, D13AuthorityCoreBirthReceiptV4, cache_use_result_from_wire_v3)
        from ..runtime_storage_v3 import runtime_storage_operation_v3, runtime_storage_quantum_v3
        import json
        self.require_v4()
        service = self.service
        if self.pending_registration is None:
            with runtime_storage_operation_v3(service.core._db, operation_id='d13-current-core-receiver-select') as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), service.core._tx() as db, runtime_storage_quantum_v3(db) as meter:
                        self.require_v4(db=db)
                        service._policy(db)
                        current = require_actual_d13_core_birth_v4(service)
                        selected = _actual_owner_fixed_row_v3(db, meter, 'authority_d13_cache_use_operations_v2',
                            ('operation_id', 'result_json'),
                            "namespace=? AND action='owner_register' AND operation_id>? "
                            "AND json_extract(result_json,'$.owner_kind')='authority_source_receiver' "
                            "AND json_extract(result_json,'$.original_locator.schema')=? "
                            "AND json_extract(result_json,'$.original_locator.core_incarnation_id')<>? "
                            "AND NOT EXISTS(SELECT 1 FROM authority_d13_cache_use_operations_v2 c "
                            "WHERE c.namespace=? AND c.action='owner_close' AND "
                            "json_extract(c.result_json,'$.registration_digest')="
                            "json_extract(authority_d13_cache_use_operations_v2.result_json,'$.registration_digest')) "
                            "ORDER BY operation_id",
                            (service.authority_namespace, self.after,
                                'sylanne3.d13.authority-source-receiver-owner-locator.v4',
                                current.core_incarnation_id, service.authority_namespace), slot='retired_current_core_receiver')
                        if selected is None:
                            legacy = db.execute("SELECT 1 FROM authority_d13_cache_use_operations_v2 r WHERE r.namespace=? "
                                "AND r.action='owner_register' AND json_extract(r.result_json,'$.owner_kind')='authority_source_receiver' "
                                "AND COALESCE(json_extract(r.result_json,'$.original_locator.schema'),'')<>? "
                                "AND NOT EXISTS(SELECT 1 FROM authority_d13_cache_use_operations_v2 c WHERE c.namespace=r.namespace "
                                "AND c.action='owner_close' AND json_extract(c.result_json,'$.registration_digest')="
                                "json_extract(r.result_json,'$.registration_digest')) LIMIT 1",
                                (service.authority_namespace, 'sylanne3.d13.authority-source-receiver-owner-locator.v4')).fetchone()
                            if legacy is not None:
                                raise AuthorityUnavailable('D13 unbound historical local Authority receiver remains legacy_unknown')
                            self.complete = True
                            return self.result_v4('complete', 'retired_local_core_receiver_eof')
                        registration = cache_use_result_from_wire_v3(json.loads(selected[1]))
                        locator = registration.original_locator
                        if (type(registration) is not D13OwnerRegistrationReceiptV3
                                or type(locator) is not D13AuthoritySourceReceiverOwnerLocatorV4
                                or registration.operation_id != selected[0]
                                or registration.namespace != service.namespace
                                or registration.installation_id != service.installation_id):
                            raise AuthorityUnavailable('D13 retired local receiver discovery changed its typed actual original')
                        birth = service._owner_operation_v3(db, locator.core_incarnation_id, 'owner_core_birth')
                        if (type(birth) is not D13AuthorityCoreBirthReceiptV4
                                or birth.operation_id != locator.core_birth_original_ref
                                or birth.birth_digest != locator.core_birth_original_digest
                                or birth.core_incarnation_id == current.core_incarnation_id):
                            raise AuthorityUnavailable('D13 retired local receiver has no exact old signed Core birth')
                        self.control.verify_original_v1(asdict(birth), 'birth_digest')
                        self.pending_registration, self.pending_birth = registration, birth
                finally:
                    operation.unregister_retained_state_v3(provider)
        if self.pending_cap is None:
            from .d13_core_authority_retirement_v4 import (read_installed_core_authority_retirement_v4,
                VerifiedInstalledCoreAuthorityRetirementV4)
            self.require_v4()
            cap = read_installed_core_authority_retirement_v4(control=self.control, gate=self.gate,
                birth=self.pending_birth, producer_original=self.qualification)
            if cap is None:
                return self.result_v4('progress', 'old_local_core_physical_retirement')
            if type(cap) is not VerifiedInstalledCoreAuthorityRetirementV4:
                raise AuthorityUnavailable('D13 local Core retirement requires its actual private Root physical cap')
            self.pending_cap = cap
            physical = cap.require_current(control=self.control, gate=self.gate,
                birth=self.pending_birth, qualification=self.qualification)
            self.pending_physical = json.loads(canonical_serialize(physical))
        # The actual WRITE metadata producer runs outside the frozen Core transaction.
        if self.pending_write_proof is None:
            with runtime_storage_operation_v3(service.core._db, operation_id='d13-retired-core-permit-kind'):
                with service.core._tx() as db, runtime_storage_quantum_v3(db):
                    row = service.fences.fences._row(db, self.pending_registration.original_operation_id)
                    permit = None if row is None else service.fences.fences._permit(row)
            if permit is not None and permit.operation == 'write':
                from ..runtime.d13_retired_receiver_metadata_v3 import prepare_actual_d13_current_core_write_terminal_v4
                self.pending_write_proof = prepare_actual_d13_current_core_write_terminal_v4(
                    self.maintenance, self.pending_registration, qualification=self.qualification,
                    retirement_cap=self.pending_cap)
        with runtime_storage_operation_v3(service.core._db, operation_id='d13-current-core-receiver-close') as operation:
            provider = _OwnerMetadataV3(operation)
            try:
                with _bind_owner_metadata_v3(operation, provider), service.fences._frozen() as (db, deletion, execution, _), runtime_storage_quantum_v3(db):
                    self.require_v4(db=db)
                    physical = self.pending_cap.require_current(control=self.control, gate=self.gate,
                        birth=self.pending_birth, qualification=self.qualification)
                    self.control.verify_original_v1(asdict(self.pending_birth), 'birth_digest')
                    if (service._owner_operation_v3(db, self.pending_birth.owner_ref, 'owner_core_birth') != self.pending_birth
                            or canonical_digest(physical) != canonical_digest(self.pending_physical)
                            or physical['birth_selector_digest'] != canonical_digest(asdict(self.pending_birth))):
                        raise AuthorityUnavailable('D13 local Core physical proof changed before its actual fence disposition')
                    terminal, successor = _current_retired_core_terminal_v4(self, service, db,
                        self.pending_registration, deletion, execution)
                    proof = _CurrentCoreReceiverCloseProofV4(_ISSUER, self, self.pending_physical, terminal, successor)
                    service.close_original_owner_in_tx_v3(db, proof)
            finally:
                operation.unregister_retained_state_v3(provider)
        # Release actual metadata/custody only after the Core close committed.
        if self.pending_write_proof is not None:
            self.pending_write_proof.release_v3()
        self.pending_cap.release_v4()
        self.after = self.pending_registration.operation_id
        self.pending_registration = self.pending_birth = self.pending_cap = self.pending_physical = None
        self.pending_write_proof = None
        self.closed += 1
        return self.result_v4('progress', 'retired_local_core_receiver_closed')


def advance_actual_d13_current_core_receiver_cleanup_v4(daemon, *, qualification):
    from .daemon import AuthorityDaemon
    from .d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    if type(daemon) is not AuthorityDaemon or daemon.c09_maintenance is None:
        raise AuthorityUnavailable('D13 current local Core cleanup needs its actual installed dormant daemon')
    service = daemon.core._d13_cache_use_controls_v2.get(daemon.c09_maintenance.closure.namespace)
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('D13 selected local-v4 cleanup has no actual installed use-control service')
    progress = _CURRENT_CORE_RECEIVER_CLEANUPS_V4.get(daemon)
    if progress is None:
        progress = _CurrentCoreReceiverCleanupV4(_ISSUER, daemon, qualification, service,
            daemon.c09_gate._pending_start_bootstrap_hold_v3)
        _CURRENT_CORE_RECEIVER_CLEANUPS_V4[daemon] = progress
    elif progress.qualification is not qualification or progress.service is not service:
        raise AuthorityUnavailable('D13 current local Core cleanup cannot replace its actual original qualification')
    progress.require_v4()
    if progress.failed is not None:
        return progress.result_v4('hold', 'retired_local_core_receiver_first_failure')
    if progress.complete:
        return progress.result_v4('complete', 'retired_local_core_receiver_eof')
    try:
        return progress.advance_v4()
    except Exception as failure:
        progress.failed = type(failure).__name__ + ': ' + str(failure)
        return progress.result_v4('hold', 'retired_local_core_receiver_first_failure')


def require_actual_d13_current_core_receiver_cleanup_complete_v4(daemon, *, qualification):
    progress = _CURRENT_CORE_RECEIVER_CLEANUPS_V4.get(daemon)
    if (type(progress) is not _CurrentCoreReceiverCleanupV4 or progress.qualification is not qualification
            or not progress.complete or progress.failed is not None
            or progress.pending_registration is not None or progress.pending_birth is not None
            or progress.pending_cap is not None or progress.pending_physical is not None
            or progress.pending_write_proof is not None):
        raise AuthorityUnavailable('D13 current Core bootstrap has no exact complete receiver-retirement metadata EOF')
    progress.require_v4()
    return progress
