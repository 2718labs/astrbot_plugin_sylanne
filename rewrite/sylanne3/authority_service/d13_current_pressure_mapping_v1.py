"""Signed current pressure facts from one actual settled Counter Source Work."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields, replace
import json
from weakref import WeakKeyDictionary

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .contract import AuthorityUnavailable
from .d13_core_counter_contract_v1 import (
    D13CoreFullWireEnvelopeV1, InstalledD13WirePolicyV7, SIGNING_DOMAIN as COUNTER_DOMAIN,
    _sha, _text, _time, _uint)
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize

MAPPING_SCHEMA = 'sylanne3.d13.current-pressure-mapping.v1'
ENVELOPE_SCHEMA = 'sylanne3.d13.current-pressure-mapping.envelope.v1'
ORIGINAL_SCHEMA = 'sylanne3.d13.current-pressure-mapping.original.v1'
SELECTION_SCHEMA = 'sylanne3.d13.current-pressure-selection-policy.v1'
SIGNING_DOMAIN = (MAPPING_SCHEMA + chr(0)).encode('ascii')
SELECTION_RULE = 'd13.latest-sequence-slots-ttl.v1'
_ISSUER = object()
_VERIFIED = WeakKeyDictionary()
_GRANT_COLUMNS = WeakKeyDictionary()
_SELECTIONS = WeakKeyDictionary()


def pressure_selection_policy_wire_v1(actual_policy):
    from ..runtime.d13_technical_policy import (
        AdminD13PrecompressionPolicyV1, AdminD13PaidPrecompressionPolicyV1)
    if type(actual_policy) is AdminD13PrecompressionPolicyV1:
        kind = 'technical'
    elif type(actual_policy) is AdminD13PaidPrecompressionPolicyV1:
        kind = 'paid'
    else:
        raise TypeError('actual typed installed D13 pressure policy required')
    return {'kind': kind, 'policy': json.loads(canonical_serialize(actual_policy))}



def _pressure_selection_policy_from_wire_v1(value):
    from ..runtime.d13_technical_policy import (
        AdminD13PrecompressionPolicyV1, AdminD13PaidPrecompressionPolicyV1)
    from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
    if type(value) is not dict or set(value) != {'kind', 'policy'}:
        raise ValueError('exact public pressure policy projection required')
    classes = {'technical': AdminD13PrecompressionPolicyV1, 'paid': AdminD13PaidPrecompressionPolicyV1}
    if value['kind'] not in classes:
        raise ValueError('unknown public pressure policy kind')
    cls = classes[value['kind']]
    def typed_body(raw, expected):
        if (type(raw) is not dict
                or set(raw) != {'$type', *(field.name for field in fields(expected))}
                or raw['$type'] != expected.__module__ + '.' + expected.__qualname__):
            raise ValueError('exact canonical typed pressure policy fields required')
        result = dict(raw)
        result.pop('$type')
        return result
    body = typed_body(value['policy'], cls)
    body['namespace'] = NamespaceId(**typed_body(body['namespace'], NamespaceId))
    if cls is AdminD13PaidPrecompressionPolicyV1:
        body['selected_main'] = D13PrecompressionInstallationV1(
            **typed_body(body['selected_main'], D13PrecompressionInstallationV1))
    policy = cls(**body)
    if pressure_selection_policy_wire_v1(policy) != value:
        raise ValueError('pressure policy public canonical projection differs')
    return policy


def _selection_digest(origin_digest, policy, grant_digest):
    return canonical_digest({'schema': SELECTION_SCHEMA, 'origin_digest': origin_digest,
                             'policy': policy, 'grant_original_digest': grant_digest})


def _bounded(value):
    if len(canonical_serialize(value)) > 65536:
        raise ValueError('pressure metadata exceeds existing RPC descriptor bound')


@dataclass(frozen=True, slots=True)
class D13CurrentPressureMemberV1:
    sequence: int
    raw_ref: VersionedRef
    source_ref: VersionedRef
    access_ref: VersionedRef
    trusted_utc: float

    def __post_init__(self):
        _uint(self.sequence, 'sequence')
        _time(self.trusted_utc, 'trusted_utc')
        if any(type(value) is not VersionedRef for value in
               (self.raw_ref, self.source_ref, self.access_ref)):
            raise ValueError('pressure member requires exact versioned references')


@dataclass(frozen=True, slots=True)
class D13CurrentPressureMappingV1:
    namespace: NamespaceId
    installation_id: str
    authority_namespace: str
    counter_operation_id: str
    frame_intent_digest: str
    counter_evidence_digest: str
    collection_digest: str
    collection_snapshot_commitment: str
    selection_policy_digest: str
    selection_policy: dict
    selection_policy_origin_digest: str
    grant_original_digest: str
    selection_rule: str
    max_slots: int
    history_token_budget: int
    ttl_seconds: int
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    conversation_ref: str
    owner_ref: str
    order_watermark: int
    access_epoch: int
    delete_epoch: int
    activation_epoch: int
    first_sequence: int
    last_sequence: int
    selected_members: tuple[D13CurrentPressureMemberV1, ...]
    missing_ranges: tuple[tuple[int, int], ...]
    expired_sequences: tuple[int, ...]
    unclosed_sequences: tuple[int, ...]
    selected_window_digest: str
    frozen_at_utc: float
    expires_at_utc: float
    schema: str = MAPPING_SCHEMA

    def __post_init__(self):
        if (self.schema != MAPPING_SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.scene_ref) is not VersionedRef or type(self.audience_ref) is not VersionedRef
                or self.selection_rule != SELECTION_RULE or type(self.ttl_seconds) is not int
                or self.ttl_seconds != 259200):
            raise ValueError('exact current pressure mapping scope required')
        for name in ('installation_id', 'authority_namespace', 'counter_operation_id',
                     'conversation_ref', 'owner_ref'):
            _text(getattr(self, name), name)
        for name in ('frame_intent_digest', 'counter_evidence_digest', 'collection_digest',
                     'collection_snapshot_commitment', 'selection_policy_digest',
                     'selection_policy_origin_digest', 'grant_original_digest', 'selected_window_digest'):
            _sha(getattr(self, name), name)
        if (type(self.selection_policy) is not dict
                or set(self.selection_policy) != {'kind', 'policy'}
                or self.selection_policy['kind'] not in ('technical', 'paid')
                or type(self.selection_policy['policy']) is not dict
                or self.selection_policy_digest != _selection_digest(
                    self.selection_policy_origin_digest, self.selection_policy, self.grant_original_digest)):
            raise ValueError('closed pressure selection policy commitment differs')
        policy = _pressure_selection_policy_from_wire_v1(self.selection_policy)
        if (policy.namespace, policy.installation_id, policy.max_slots, policy.history_token_budget) != (
                self.namespace, self.installation_id, self.max_slots, self.history_token_budget):
            raise ValueError('pressure public policy selection scope differs')
        _uint(self.max_slots, 'max_slots', 3)
        _uint(self.history_token_budget, 'history_token_budget', 1)
        if self.max_slots > 64:
            raise ValueError('pressure selection exceeds actual bounded window')
        for name in ('order_watermark', 'access_epoch', 'delete_epoch', 'activation_epoch',
                     'first_sequence', 'last_sequence'):
            _uint(getattr(self, name), name)
        if ((self.first_sequence, self.last_sequence) !=
                (max(0, self.order_watermark-self.max_slots+1), self.order_watermark)):
            raise ValueError('pressure mapping must cover latest sequence slots')
        if (type(self.selected_members) is not tuple or len(self.selected_members) > self.max_slots
                or any(type(member) is not D13CurrentPressureMemberV1 for member in self.selected_members)
                or tuple(member.sequence for member in self.selected_members) !=
                    tuple(sorted(set(member.sequence for member in self.selected_members)))
                or any(not self.first_sequence <= member.sequence <= self.last_sequence
                       for member in self.selected_members)):
            raise ValueError('pressure member sequence manifest differs')
        for values in (self.expired_sequences, self.unclosed_sequences):
            if (type(values) is not tuple or values != tuple(sorted(set(values)))
                    or any(type(v) is not int or not self.first_sequence <= v <= self.last_sequence
                           for v in values)):
                raise ValueError('pressure slot quality manifest differs')
        if (type(self.missing_ranges) is not tuple or any(
                type(pair) is not tuple or len(pair) != 2
                or any(type(v) is not int for v in pair) or not 0 <= pair[0] <= pair[1]
                for pair in self.missing_ranges)):
            raise ValueError('pressure missing range manifest differs')
        _time(self.frozen_at_utc, 'frozen_at_utc')
        _time(self.expires_at_utc, 'expires_at_utc')
        if not self.frozen_at_utc < self.expires_at_utc <= self.frozen_at_utc + policy.deadline_after_seconds:
            raise ValueError('pressure fact absolute lifetime is empty')
        _bounded(self)


@dataclass(frozen=True, slots=True)
class D13CurrentPressureMappingEnvelopeV1:
    payload: D13CurrentPressureMappingV1
    key_id: str
    signature: str
    schema: str = ENVELOPE_SCHEMA

    def __post_init__(self):
        if self.schema != ENVELOPE_SCHEMA or type(self.payload) is not D13CurrentPressureMappingV1:
            raise ValueError('exact signed current pressure envelope required')
        _text(self.key_id, 'key_id')
        if type(self.signature) is not str or len(base64.b64decode(self.signature, validate=True)) != 64:
            raise ValueError('exact Ed25519 pressure mapping signature required')
        _bounded(self)


def _closed(value, cls):
    if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
        raise ValueError('exact closed pressure mapping wire fields required')
    return dict(value)


def pressure_mapping_from_wire_v1(value):
    raw = _closed(value, D13CurrentPressureMappingEnvelopeV1)
    payload = _closed(raw['payload'], D13CurrentPressureMappingV1)
    for name, cls in (('namespace', NamespaceId), ('scene_ref', VersionedRef), ('audience_ref', VersionedRef)):
        payload[name] = cls(**_closed(payload[name], cls))
    members = []
    if type(payload['selected_members']) not in (list, tuple):
        raise ValueError('pressure member wire array required')
    for member in payload['selected_members']:
        item = _closed(member, D13CurrentPressureMemberV1)
        for name in ('raw_ref', 'source_ref', 'access_ref'):
            item[name] = VersionedRef(**_closed(item[name], VersionedRef))
        members.append(D13CurrentPressureMemberV1(**item))
    payload['selected_members'] = tuple(members)
    payload['missing_ranges'] = tuple(tuple(pair) for pair in payload['missing_ranges'])
    for name in ('expired_sequences', 'unclosed_sequences'):
        payload[name] = tuple(payload[name])
    raw['payload'] = D13CurrentPressureMappingV1(**payload)
    return D13CurrentPressureMappingEnvelopeV1(**raw)


def pressure_mapping_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {'schema', 'envelope', 'selection_policy_origin'} or raw['schema'] != ORIGINAL_SCHEMA:
        raise ValueError('exact retained pressure mapping original required')
    envelope = pressure_mapping_from_wire_v1(raw['envelope'])
    from .d13_pressure_policy_origin_v1 import validate_d13_pressure_policy_origin_v1
    origin = validate_d13_pressure_policy_origin_v1(raw['selection_policy_origin'])
    if (origin['profile']['installation_id'] != envelope.payload.installation_id
            or canonical_digest(origin) != envelope.payload.selection_policy_origin_digest):
        raise ValueError('retained pressure mapping provenance differs')
    return envelope, origin


class VerifiedCurrentD13PressureMappingV1:
    __slots__ = ('_payload', '_counter', '_proof', '_work', '__weakref__')

    def __init__(self, issuer, payload, counter, proof, work):
        if issuer is not _ISSUER:
            raise TypeError('actual verified current pressure mapping required')
        self._payload, self._counter, self._proof, self._work = payload, counter, proof, work
        _VERIFIED[self] = canonical_digest(payload)

    @property
    def payload(self):
        if _VERIFIED.get(self) != canonical_digest(self._payload):
            raise AuthorityUnavailable('current pressure verification was released or altered')
        return self._payload

    def release_v1(self):
        _VERIFIED.pop(self, None)
        self._payload = self._counter = self._proof = self._work = None


def verify_current_d13_pressure_mapping_v1(wire_policy, envelope, *, counter_envelope,
                                           policy_read_proof, work, now_utc):
    from ..runtime.d13_deterministic_applicability_v3 import require_actual_d13_pressure_policy_read_v1
    if type(wire_policy) is not InstalledD13WirePolicyV7 or type(counter_envelope) is not D13CoreFullWireEnvelopeV1:
        raise TypeError('actual installed V7 counter policy and signed evidence required')
    if type(envelope) is dict:
        envelope = pressure_mapping_from_wire_v1(envelope)
    if type(envelope) is not D13CurrentPressureMappingEnvelopeV1:
        raise TypeError('exact signed current pressure mapping required')
    policy, grant, signature, grant_expiry = require_actual_d13_pressure_policy_read_v1(policy_read_proof, work)
    public = pressure_selection_policy_wire_v1(policy)
    p, count, frame = envelope.payload, counter_envelope.payload, counter_envelope.payload.frame
    _time(now_utc, 'now_utc')
    if (envelope.key_id != wire_policy.counter_key_id or counter_envelope.key_id != envelope.key_id
            or frame.install_id != wire_policy.installation.installation_id
            or frame.policy_digest != wire_policy.policy_digest or frame.template_digest != wire_policy.template_digest
            or count.http_binding_contract_digest != wire_policy.http_binding_contract_digest
            or p.selection_policy != public or p.grant_original_digest != canonical_digest((grant, signature))
            or (p.namespace, p.installation_id, p.authority_namespace, p.counter_operation_id,
                p.frame_intent_digest, p.counter_evidence_digest, p.collection_digest,
                p.collection_snapshot_commitment, p.frozen_at_utc) !=
               (frame.namespace, frame.install_id, frame.authority_namespace, frame.counter_operation_id,
                frame.frame_intent_digest, counter_envelope.evidence_digest, frame.collection_digest,
                frame.collection_snapshot_commitment, frame.frozen_at_utc)
            or (p.namespace, p.installation_id, p.max_slots, p.history_token_budget) !=
               (policy.namespace, policy.installation_id, policy.max_slots, policy.history_token_budget)
            or p.expires_at_utc > min(frame.expires_at_utc, grant_expiry,
                                     frame.frozen_at_utc + policy.deadline_after_seconds)
            or not p.frozen_at_utc <= now_utc < p.expires_at_utc):
        raise AuthorityUnavailable('pressure mapping differs from current installed policy/grant/Counter scope')
    for name in ('counter_policy_fingerprint', 'tokenizer_fingerprint', 'wire_policy_fingerprint',
                 'serializer_fingerprint', 'applicability_fingerprint'):
        if getattr(count, name) != getattr(wire_policy, name):
            raise AuthorityUnavailable('pressure Counter installed measurement asset differs')
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(wire_policy.counter_public_key_hex))
    key.verify(base64.b64decode(counter_envelope.signature, validate=True),
               COUNTER_DOMAIN + canonical_serialize(asdict(count)).encode('utf-8'))
    key.verify(base64.b64decode(envelope.signature, validate=True),
               SIGNING_DOMAIN + canonical_serialize(p).encode('ascii'))
    return VerifiedCurrentD13PressureMappingV1(_ISSUER, p, count, policy_read_proof, work)


def pressure_mapping_exact_tokens_v1(verified):
    from ..runtime.d13_deterministic_applicability_v3 import require_actual_d13_pressure_policy_read_v1
    if type(verified) is not VerifiedCurrentD13PressureMappingV1:
        raise TypeError('actual private pressure verification required')
    payload = verified.payload
    policy, grant, signature, _expiry = require_actual_d13_pressure_policy_read_v1(verified._proof, verified._work)
    if (pressure_selection_policy_wire_v1(policy) != payload.selection_policy
            or canonical_digest((grant, signature)) != payload.grant_original_digest):
        raise AuthorityUnavailable('pressure policy/grant changed before consumption')
    evidence = verified._counter
    return evidence.raw_lower_tokens if evidence.raw_lower_tokens == evidence.raw_upper_tokens else None


class AuthorityPressureGrantColumnV1:
    """One private fixed D11 column belonging to the actual Counter Source Work."""
    def __init__(self, issuer, work, policy, signature):
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        if issuer is not _ISSUER:
            raise TypeError('actual pressure policy grant producer required')
        work._actual()
        self.owner, self.policy, self.signature = work, policy, signature
        self.signer = work.service.observer.issuer._signer
        self.key = (policy.lease_id, policy.grant_version)
        self.column = DispatchOriginalJSONReadV3(work, table='runtime_budget_grants',
            column='grant_json', key_columns=('lease_id', 'version'), key=self.key)
        self.complete = False
        self.verifier = None
        _GRANT_COLUMNS[self] = (work, self.column, self.signer, policy, signature,
                                work.operation, work.scope, work.selection_digest, self.key)
        self.verifier = self.signer.begin_original_stream_verification_v3('budget-grant.v1', self)

    def advance(self, meter):
        require_authority_pressure_grant_column_v1(self, signer=self.signer, kind='budget-grant.v1')
        _require_grant_head(self.owner, self.policy, self.signature, meter)
        column = self.column
        if column.fragment_offset < len(column.fragment):
            self.verifier.update(column.fragment[column.fragment_offset:
                                                  column.fragment_offset+1024])
        if not column.advance(meter):
            return False
        self.signer.finish_original_stream_verification_v3(
            'budget-grant.v1', self.signature, self, self.verifier)
        self.complete = True
        return True

    def release_v1(self):
        _GRANT_COLUMNS.pop(self, None)
        self.owner = self.column = self.policy = self.signer = self.verifier = None


def require_authority_pressure_grant_column_v1(original, *, signer, kind,
                                                signature=None, verifier=None, complete=False):
    if type(original) is not AuthorityPressureGrantColumnV1:
        raise AuthorityUnavailable('actual fixed Authority pressure grant column required')
    work = original.owner
    if (work is None or _GRANT_COLUMNS.get(original) !=
            (work, original.column, original.signer, original.policy, original.signature,
             work.operation, work.scope, work.selection_digest, original.key)
            or signer is not original.signer or signer is not work.service.observer.issuer._signer
            or kind != 'budget-grant.v1' or not work.complete):
        raise AuthorityUnavailable('pressure grant signature changed actual Source Work/issuer')
    work._actual()
    if complete:
        if (not original.column.complete or signature != original.signature
                or verifier is not original.verifier):
            raise AuthorityUnavailable('pressure grant signature lacks actual complete column EOF')
        original.column.require_v3(work)
    return original


def _require_grant_head(work, policy, signature, meter):
    lease = meter.read_fixed_row(work.db, 'runtime_budget_leases', ('bot_id', 'persona_id'),
                                  'lease_id=?', (policy.lease_id,))
    row = meter.read_fixed_row(work.db, 'runtime_budget_grants', ('version', 'status', 'signature'),
        'lease_id=? ORDER BY version DESC', (policy.lease_id,))
    if lease != work.namespace.as_tuple or row != (policy.grant_version, 'active', signature):
        raise AuthorityUnavailable('pressure policy D11 grant is no longer the same active version')


def _read_pressure_grant(counter, work, policy):
    from ..runtime.issuers import _decode_grant
    with work.quantum_v3() as meter:
        row = meter.read_fixed_row(work.db, 'runtime_budget_grants', ('version', 'status', 'signature'),
            'lease_id=? ORDER BY version DESC', (policy.lease_id,))
        if row is None or row[:2] != (policy.grant_version, 'active'):
            raise AuthorityUnavailable('current installed pressure grant is absent')
        _require_grant_head(work, policy, row[2], meter)
        column = AuthorityPressureGrantColumnV1(_ISSUER, work, policy, row[2])
    try:
        while not column.complete:
            with work.quantum_v3() as meter:
                column.advance(meter)
        with work.quantum_v3() as meter:
            _require_grant_head(work, policy, row[2], meter)
            wire = canonical_serialize(column.column.require_v3(work))
            meter.charge_encode(len(wire))
            grant = _decode_grant(wire)
        if ((grant.grant_id, grant.version, grant.lease_id, grant.bot_id, grant.persona_id) !=
                (policy.grant_id, policy.grant_version, policy.lease_id, *work.namespace.as_tuple)
                or policy.work_kind not in grant.allowed_work_kinds
                or any(grant.max_ceiling.get(name, 0) < amount
                       for name, amount in policy.quote_ceiling.items())
                or grant.valid_until_utc is not None and work.now_utc >= grant.valid_until_utc):
            raise AuthorityUnavailable('actual signed pressure grant does not cover installed policy')
        return grant, row[2]
    finally:
        column.release_v1()


class _PressureSelectionContextV1:
    def __init__(self, issuer, work, current):
        if issuer is not _ISSUER:
            raise TypeError('actual completed Counter selection producer required')
        self.work, self.current, self.db = work, current, work.db
        full = current.pair.collection.window
        self.window = replace(full, turns=(), source_dependencies=(), read_set=(full.audience_ref,))
        _SELECTIONS[self] = (work, current, current.pair, current.pair.collection,
                            self.db, self.window, work.scope, work.operation, work.selection_digest)

    def require_current(self, db, namespace, scene_ref, conversation_ref):
        work, current = self.work, self.current
        if (_SELECTIONS.get(self) != (work, current, current.pair, current.pair.collection,
                self.db, self.window, work.scope, work.operation, work.selection_digest)
                or db is not self.db or not db.in_transaction or namespace != work.namespace
                or scene_ref != current.prospective.plan.scene_id
                or conversation_ref != self.window.conversation_ref
                or work.counter_pair_reader.require_current_v7(work) is not current.pair):
            raise AuthorityUnavailable('pressure selection crossed actual full Source EOF/snapshot')
        work._actual()

    def release_v1(self):
        _SELECTIONS.pop(self, None)
        self.work = self.current = self.db = self.window = None



def _require_original_full_collection_binding_v1(work, current, frame):
    from ..runtime.runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
    collection = current.pair.collection
    # Counter's own prepare/settle events change the current Graph snapshot.
    # The original frame fixes the comparison domain, while all current window
    # bytes and page facts still come from this actual complete Source Work.
    value = {'schema': 'sylanne3.d13.core-collection-binding.v7',
        'snapshot': frame.collection_snapshot_commitment,
        'window': replace(collection.window, trusted_utc=frame.frozen_at_utc),
        'pages': tuple((page.before_sequence, page.max_slots, page.first_sequence,
            page.last_sequence, page.page_status, page.expired_sequences, page.unclosed_sequences)
            for page in collection.pages)}
    stream = RuntimeCanonicalStreamV3(value, work.operation)
    while not stream.complete:
        with work.quantum_v3() as meter:
            stream.read_fragment(meter)
    if stream.hash.hexdigest() != frame.collection_digest:
        raise AuthorityUnavailable('actual full Counter collection differs from original frame domain')


def _selection_window(counter, work, current, policy):
    from .current_authority_graph_read_v3 import bind_prepared_authority_graph_read_v3
    from ..runtime.d13_current_window import _read_current_d13_window_for_authority_v1
    from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
    context = _PressureSelectionContextV1(_ISSUER, work, current)
    observation = {'expired': [], 'unclosed': []}
    try:
        with work.quantum_v3() as meter:
            with bind_prepared_authority_graph_read_v3(work.prepared, service=work.service, db=work.db, meter=meter):
                context.require_current(work.db, work.namespace, current.prospective.plan.scene_id,
                                        context.window.conversation_ref)
                window = _read_current_d13_window_for_authority_v1(
                    work.db, work.namespace, current.prospective.plan.scene_id,
                    context.window.conversation_ref, policy.max_slots, work.now_utc,
                    expected_activation_generation=current.current_self.activation_generation,
                    _collector_context=context, _page_observation=observation)
                if any(getattr(window, name) != getattr(current.pair.collection.window, name) for name in
                       ('namespace', 'owner_ref', 'conversation_ref', 'scene_ref', 'audience_ref',
                        'order_watermark', 'access_epoch', 'delete_epoch', 'activation_epoch')):
                    raise AuthorityUnavailable('pressure small window changed full qualified scope')
                stream = _CanonicalComparisonV3(replace(window, trusted_utc=current.frozen_at_utc),
                                                 operation=work.operation)
        while not stream.complete:
            with work.quantum_v3() as meter:
                stream.advance(meter)
        return window, tuple(observation['expired']), tuple(observation['unclosed']), stream.digest
    finally:
        context.release_v1()


def retain_current_d13_pressure_mapping_v1(counter, *, current, counter_envelope):
    from .d13_core_counter_source_v1 import require_current_authority_counter_call_work_v3
    from .d13_pressure_policy_origin_v1 import require_verified_installed_d13_pressure_policy_v1
    from .current_authority_graph_read_v3 import bind_prepared_authority_graph_read_v3
    if type(counter_envelope) is not D13CoreFullWireEnvelopeV1:
        raise TypeError('actual newly settled signed Counter evidence required')
    observer = counter.source.observer
    bundle = observer.installed_bundle
    if bundle.d13_precompression is None and bundle.d13_paid_precompression is None:
        return None
    work = require_current_authority_counter_call_work_v3(counter, current)
    proof = require_verified_installed_d13_pressure_policy_v1(observer=observer, bundle=bundle, work=work)
    work.counter_material_scope.require_current_v7(work)
    policy, origin = proof.require_current(observer=observer, bundle=bundle, work=work)
    frame = counter_envelope.payload.frame
    with work.quantum_v3() as meter:
        with bind_prepared_authority_graph_read_v3(work.prepared, service=work.service, db=work.db, meter=meter):
            work.counter_pair_reader.require_counter_draft_material_v7(work)
            if (work.counter_pair_reader.require_current_v7(work) is not current.pair
                    or (frame.counter_operation_id, frame.namespace, frame.install_id, frame.authority_namespace,
                        frame.frozen_at_utc) !=
                       (work.request.counter_operation_id, work.namespace, policy.installation_id,
                        counter.bridge.namespace, current.frozen_at_utc)):
                raise AuthorityUnavailable('pressure mapping does not match actual full Counter material EOF')
    _require_original_full_collection_binding_v1(work, current, frame)
    grant, signature = _read_pressure_grant(counter, work, policy)
    public = pressure_selection_policy_wire_v1(policy)
    origin_digest, grant_digest = canonical_digest(origin), canonical_digest((grant, signature))
    saved = counter._original(frame.counter_operation_id, 'pressure_mapping_v1')
    if saved is not None:
        envelope, previous_origin = pressure_mapping_original_from_wire_v1(saved)
        p = envelope.payload
        if (p.counter_evidence_digest != counter_envelope.evidence_digest or previous_origin != origin
                or p.selection_policy != public or p.grant_original_digest != grant_digest
                or not p.frozen_at_utc <= work.now_utc < p.expires_at_utc):
            raise AuthorityUnavailable('retained pressure mapping belongs to another original/current grant')
        return envelope
    window, expired, unclosed, digest = _selection_window(counter, work, current, policy)
    limits = [frame.expires_at_utc, frame.frozen_at_utc + policy.deadline_after_seconds,
              work.deadline_utc, *(member.trusted_utc+259200 for member in window.turns)]
    if grant.valid_until_utc is not None:
        limits.append(grant.valid_until_utc)
    expiry = min(value for value in limits if value is not None)
    if not frame.frozen_at_utc <= work.now_utc < expiry:
        raise AuthorityUnavailable('current pressure Source/policy/grant original lifetime ended')
    members = tuple(D13CurrentPressureMemberV1(turn.sequence, turn.raw_ref, turn.source_ref,
                    turn.access_ref, turn.trusted_utc) for turn in window.turns)
    payload = D13CurrentPressureMappingV1(
        namespace=work.namespace, installation_id=frame.install_id,
        authority_namespace=frame.authority_namespace, counter_operation_id=frame.counter_operation_id,
        frame_intent_digest=frame.frame_intent_digest, counter_evidence_digest=counter_envelope.evidence_digest,
        collection_digest=frame.collection_digest, collection_snapshot_commitment=frame.collection_snapshot_commitment,
        selection_policy_digest=_selection_digest(origin_digest, public, grant_digest),
        selection_policy=public, selection_policy_origin_digest=origin_digest, grant_original_digest=grant_digest,
        selection_rule=SELECTION_RULE, max_slots=policy.max_slots, history_token_budget=policy.history_token_budget,
        ttl_seconds=259200, scene_ref=window.scene_ref, audience_ref=window.audience_ref,
        conversation_ref=window.conversation_ref, owner_ref=window.owner_ref,
        order_watermark=window.order_watermark, access_epoch=window.access_epoch,
        delete_epoch=window.delete_epoch, activation_epoch=window.activation_epoch,
        first_sequence=max(0, window.order_watermark-policy.max_slots+1), last_sequence=window.order_watermark,
        selected_members=members, missing_ranges=window.missing_ranges, expired_sequences=expired,
        unclosed_sequences=unclosed, selected_window_digest=digest,
        frozen_at_utc=frame.frozen_at_utc, expires_at_utc=expiry)
    signature_bytes = counter._key.sign(SIGNING_DOMAIN+canonical_serialize(payload).encode('ascii'))
    envelope = D13CurrentPressureMappingEnvelopeV1(
        payload, counter.policy.counter_key_id, base64.b64encode(signature_bytes).decode('ascii'))
    proof.require_current(observer=observer, bundle=bundle, work=work)
    with work.quantum_v3() as meter:
        _require_grant_head(work, policy, signature, meter)
    counter._record(frame.counter_operation_id, 'pressure_mapping_v1',
        {'schema': ORIGINAL_SCHEMA, 'envelope': asdict(envelope),
         'selection_policy_origin': origin}, source=current)
    return envelope


def read_current_d13_pressure_mapping_v1(counter, *, counter_operation_id, read_credential, subject):
    """Read one retained signed metadata original; never create or renew a count."""
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from ..runtime_storage_v3 import (runtime_storage_operation_v3, runtime_storage_quantum_v3,
                                     begin_core_payload_read_v3)
    if (type(counter) is not InstalledD13CoreCounterServiceV1
            or subject != counter.source.self_identity._read_subject):
        raise AuthorityUnavailable('actual installed Counter metadata reader required')
    _text(counter_operation_id, 'counter_operation_id')
    counter.core._require(read_credential, 'read', counter.bridge.namespace)
    key = (counter.bridge.namespace, counter_operation_id, 'pressure_mapping_v1')
    with counter._lock:
        with runtime_storage_operation_v3(counter.core._db,
                operation_id='d13-pressure-read:'+counter_operation_id):
            reader = begin_core_payload_read_v3(counter.core._db, 'authority_d13_counter_originals_v1', key)
            try:
                while not reader.complete:
                    with counter.core._tx() as db:
                        with runtime_storage_quantum_v3(db) as meter:
                            counter.core._require(read_credential, 'read', counter.bridge.namespace)
                            reader.advance(meter=meter)
                with counter.core._tx() as db:
                    with runtime_storage_quantum_v3(db):
                        original = reader.require_v3(db, 'authority_d13_counter_originals_v1', key)
                        if original is None:
                            return None
                        envelope, _origin = pressure_mapping_original_from_wire_v1(
                            original.decoded_v3(db, 'authority_d13_counter_originals_v1', key))
                        if (envelope.payload.namespace != counter.namespace
                                or envelope.payload.installation_id != counter.policy.installation.installation_id
                                or envelope.payload.counter_operation_id != counter_operation_id
                                or envelope.payload.authority_namespace != counter.bridge.namespace):
                            raise AuthorityUnavailable('pressure mapping metadata locator differs')
                        return envelope
            finally:
                reader.release_payload_v3()
