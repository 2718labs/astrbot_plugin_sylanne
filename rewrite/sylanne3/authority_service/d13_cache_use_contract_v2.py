"""Closed D13 cache-use control originals; DTOs confer no Source or eviction right."""
from dataclasses import asdict, dataclass, fields
import math

from ..runtime_contracts import NamespaceId, canonical_digest

USE_POLICY_SCHEMA = 'sylanne3.d13.cache-use-control-policy.v3'
OBSERVATION_SCHEMA = 'sylanne3.d13.cache-use-observation.v3'
PIN_SCHEMA = 'sylanne3.d13.cache-use-pin-receipt.v3'
PROTOCOL = 'd13.derived-use.v3'
CONTROL_SCOPE = ('acquire_own', 'transfer_own', 'release_own', 'register_original', 'close_original', 'require_original_execution_use', 'attest_retention_release')


def _text(value, name):
    if type(value) is not str or not value or len(value.encode('utf-8')) > 4096:
        raise ValueError('D13 bounded nonempty control identifier required: ' + name)


def _sha(value, name):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('D13 SHA256 required: ' + name)


def _uint(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('D13 exact control integer required: ' + name)


def payload_identity_v2(value):
    if type(value) is not tuple or len(value) != 4:
        raise ValueError('D13 payload identity requires its actual four fixed fields')
    ref, digest, origin, revision = value
    _text(ref, 'block_ref')
    _sha(digest, 'payload_digest')
    _sha(origin, 'initial_metadata_origin_scope_digest')
    _uint(revision, 'current_revision', 1)
    return value


def selected_payloads_v2(values):
    if type(values) is not tuple or not 1 <= len(values) <= 16:
        raise ValueError('D13 use control requires one to sixteen exact payloads')
    for value in values:
        payload_identity_v2(value)
    if len({value[:3] for value in values}) != len(values):
        raise ValueError('D13 use selection repeats a logical payload')
    return values


def payload_key_v2(namespace, identity):
    payload_identity_v2(identity)
    if type(namespace) is not NamespaceId:
        raise ValueError('D13 exact payload namespace required')
    # A metadata revision or physical cell remap never sheds an outstanding pin.
    return canonical_digest((PROTOCOL, namespace, identity[:3]))


@dataclass(frozen=True, slots=True)
class AdminD13CacheUseControlPolicyV2:
    policy_id: str
    version: int
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    consumer_cohort_digest: str
    peer_maintenance_policy_ref: str
    policy_pair_digest: str
    valid_until: float
    enabled: bool = False
    protocol: str = PROTOCOL
    control_scope: tuple = CONTROL_SCOPE
    schema: str = USE_POLICY_SCHEMA

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema != USE_POLICY_SCHEMA
                or self.protocol != PROTOCOL or self.control_scope != CONTROL_SCOPE
                or type(self.enabled) is not bool or type(self.valid_until) not in (int, float)
                or not math.isfinite(self.valid_until)):
            raise ValueError('D13 exact explicitly enabled control policy required')
        for name in ('policy_id', 'authority_namespace', 'installation_id', 'peer_maintenance_policy_ref'):
            _text(getattr(self, name), name)
        for name in ('consumer_cohort_digest', 'policy_pair_digest'):
            _sha(getattr(self, name), name)
        _uint(self.version, 'version', 1)

    @property
    def policy_ref(self):
        return 'd13-cache-use-policy-v3:' + self.policy_id + ':' + str(self.version)

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def cache_policy_pair_digest_v2(use_policy, maintenance_policy):
    use = asdict(use_policy)
    maintenance = asdict(maintenance_policy)
    use.pop('policy_pair_digest')
    use.pop('peer_maintenance_policy_ref')
    maintenance.pop('policy_pair_digest')
    maintenance.pop('use_control_policy_ref')
    return canonical_digest((use, maintenance))


def require_cache_policy_pair_v2(use_policy, maintenance_policy):
    from ..runtime.d13_derived_cache_maintenance_v2 import AdminD13DerivedCacheMaintenancePolicyV2
    if (type(use_policy) is not AdminD13CacheUseControlPolicyV2
            or type(maintenance_policy) is not AdminD13DerivedCacheMaintenancePolicyV2
            or not use_policy.enabled or use_policy.namespace != maintenance_policy.namespace
            or use_policy.installation_id != maintenance_policy.installation_id
            or use_policy.consumer_cohort_digest != maintenance_policy.consumer_cohort_digest
            or use_policy.peer_maintenance_policy_ref != maintenance_policy.link_ref
            or maintenance_policy.use_control_policy_ref != use_policy.policy_ref
            or use_policy.policy_pair_digest != maintenance_policy.policy_pair_digest
            or use_policy.policy_pair_digest != cache_policy_pair_digest_v2(use_policy, maintenance_policy)):
        raise ValueError('D13 independently signed cache policies do not bind the same explicit pair')
    return use_policy, maintenance_policy


@dataclass(frozen=True, slots=True)
class D13CacheUseEntryV2:
    identity: tuple
    active_count: int
    unknown_count: int
    coverage: str
    query_complete: bool

    def __post_init__(self):
        payload_identity_v2(self.identity)
        _uint(self.active_count, 'active_count')
        _uint(self.unknown_count, 'unknown_count')
        if self.coverage not in ('complete', 'legacy_unknown') or type(self.query_complete) is not bool:
            raise ValueError('D13 exact use coverage/completeness required')
        if self.coverage == 'legacy_unknown' and (self.unknown_count == 0 or self.query_complete):
            raise ValueError('D13 legacy coverage must retain its explicit unresolved obligation')


@dataclass(frozen=True, slots=True)
class D13CacheUseObservationV2:
    schema: str
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    policy_digest: str
    permit_token: str
    permit_digest: str
    anchor_digest: str
    activation_generation: int
    storage_generation: int
    selection_digest: str
    coverage_ref: str
    coverage_digest: str
    coverage_state: str
    control_revision: int
    selected_digest: str
    entries: tuple
    observation_digest: str

    def __post_init__(self):
        if self.schema != OBSERVATION_SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError('D13 exact cache-use observation required')
        for name in ('authority_namespace', 'installation_id', 'permit_token', 'coverage_ref'):
            _text(getattr(self, name), name)
        for name in ('policy_digest', 'permit_digest', 'anchor_digest', 'selection_digest',
                'coverage_digest', 'selected_digest', 'observation_digest'):
            _sha(getattr(self, name), name)
        for name in ('activation_generation', 'storage_generation', 'control_revision'):
            _uint(getattr(self, name), name)
        if self.coverage_state not in ('complete', 'legacy_unknown') or type(self.entries) is not tuple:
            raise ValueError('D13 exact cache-use observation coverage required')
        if any(type(entry) is not D13CacheUseEntryV2 or entry.coverage != self.coverage_state for entry in self.entries):
            raise ValueError('D13 use observation entries differ from its actual coverage')
        selected = selected_payloads_v2(tuple(entry.identity for entry in self.entries))
        if canonical_digest(selected) != self.selected_digest:
            raise ValueError('D13 use observation selected payloads differ')
        material = asdict(self)
        material.pop('observation_digest')
        if canonical_digest(material) != self.observation_digest:
            raise ValueError('D13 use observation exact metadata commitment differs')


@dataclass(frozen=True, slots=True)
class D13CachePinReceiptV2:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    pin_id: str
    payload_identity: tuple
    consumer_owner_ref: str
    consumer_operation_id: str
    consumer_kind: str
    consumer_cohort_digest: str
    subject: str
    state: str
    control_revision: int
    operation_id: str
    request_digest: str
    permit_token: str
    permit_digest: str
    successor_pin_id: str | None = None
    schema: str = PIN_SCHEMA

    def __post_init__(self):
        if self.schema != PIN_SCHEMA or type(self.namespace) is not NamespaceId or self.state not in ('active', 'released', 'unknown'):
            raise ValueError('D13 exact durable pin receipt required')
        payload_identity_v2(self.payload_identity)
        for name in ('authority_namespace', 'installation_id', 'pin_id', 'consumer_owner_ref',
                'consumer_operation_id', 'consumer_kind', 'subject', 'operation_id', 'permit_token'):
            _text(getattr(self, name), name)
        for name in ('consumer_cohort_digest', 'request_digest', 'permit_digest'):
            _sha(getattr(self, name), name)
        _uint(self.control_revision, 'control_revision', 1)
        if self.successor_pin_id is not None:
            _text(self.successor_pin_id, 'successor_pin_id')


def cache_use_to_wire_v2(value):
    if type(value) not in (D13CacheUseObservationV2, D13CachePinReceiptV2, D13OwnerRegistrationReceiptV3, D13OwnerCloseReceiptV3, D13OwnerRetentionReleaseReceiptV3, D13NaturalReviewVerdictReceiptV3, D13NaturalParentDispositionReceiptV3, D13NaturalParentInputReceiptV3, D13RetiredReceiverOriginalV3, D13ControlledSDKConsumerReadyReceiptV3, D13CounterFrameBirthReceiptV3, D13NaturalGenerationParseReceiptV3, D13NaturalPreReviewDispositionReceiptV3, D13UnusedCounterDispositionReceiptV3, D13AuthorityCoreBirthReceiptV4, D13RetiredCoreReceiverOriginalV4):
        raise TypeError('D13 closed use control original required')
    return asdict(value)


def cache_use_from_wire_v2(raw, cls):
    if cls not in (D13CacheUseObservationV2, D13CachePinReceiptV2, D13OwnerRegistrationReceiptV3, D13OwnerCloseReceiptV3, D13OwnerRetentionReleaseReceiptV3, D13NaturalReviewVerdictReceiptV3, D13NaturalParentDispositionReceiptV3, D13NaturalParentInputReceiptV3, D13RetiredReceiverOriginalV3, D13ControlledSDKConsumerReadyReceiptV3, D13CounterFrameBirthReceiptV3, D13NaturalGenerationParseReceiptV3, D13NaturalPreReviewDispositionReceiptV3, D13UnusedCounterDispositionReceiptV3, D13AuthorityCoreBirthReceiptV4, D13RetiredCoreReceiverOriginalV4) or type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError('D13 use control wire fields differ')
    values = dict(raw)
    values['namespace'] = NamespaceId(**values['namespace'])
    if cls is D13CacheUseObservationV2:
        values['entries'] = tuple(D13CacheUseEntryV2(**{**entry, 'identity': tuple(entry['identity'])}) for entry in values['entries'])
    elif cls is D13CachePinReceiptV2:
        values['payload_identity'] = tuple(values['payload_identity'])
    elif cls is D13OwnerRegistrationReceiptV3:
        values['payload_identities'] = tuple(tuple(value) for value in values['payload_identities'])
        values['original_locator'] = owner_locator_from_wire_v3(values['original_locator'])
    if cls in (D13NaturalParentDispositionReceiptV3, D13NaturalParentInputReceiptV3):
        values['child_identities'] = tuple(tuple(child) for child in values['child_identities'])
    if cls is D13OwnerCloseReceiptV3 and values['retention_original'] is not None:
        values['retention_original'] = retention_release_from_wire_v3(values['retention_original'])
    return cls(**values)


def use_policy_from_payload_v2(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(AdminD13CacheUseControlPolicyV2)}:
        raise ValueError('D13 exact signed use-policy fields required')
    values = dict(raw)
    values['namespace'] = NamespaceId(**values['namespace'])
    values['control_scope'] = tuple(values['control_scope'])
    return AdminD13CacheUseControlPolicyV2(**values)

OWNER_REGISTRATION_SCHEMA_V3 = 'sylanne3.d13.owner-registration.v3'
OWNER_CLOSE_SCHEMA_V3 = 'sylanne3.d13.owner-close.v3'
OWNER_KINDS_V3 = ('counter_frame_draft', 'natural_generation_original', 'natural_review_original',
    'authority_source_receiver', 'host_frame_receiver', 'graph_source_receiver')


@dataclass(frozen=True, slots=True)
class D13CounterFrameOwnerLocatorV3:
    counter_operation_id: str
    frame_intent_id: str
    frame_intent_digest: str
    parent_original_id: str
    stage: str = 'draft'
    schema: str = 'sylanne3.d13.counter-frame-owner-locator.v3'

    def __post_init__(self):
        if self.schema != 'sylanne3.d13.counter-frame-owner-locator.v3' or self.stage != 'draft':
            raise ValueError('D13 exact Counter draft locator required')
        _text(self.counter_operation_id, 'counter_operation_id')
        _text(self.frame_intent_id, 'frame_intent_id')
        _sha(self.frame_intent_digest, 'frame_intent_digest')
        _text(self.parent_original_id, 'parent_original_id')


@dataclass(frozen=True, slots=True)
class D13NaturalOriginalOwnerLocatorV3:
    owner_kind: str
    job_id: str
    parent_original_id: str
    original_id: str
    stage: str
    schema: str = 'sylanne3.d13.natural-original-owner-locator.v3'

    def __post_init__(self):
        stages = {'natural_generation_original': 'generation', 'natural_review_original': 'review'}
        if self.schema != 'sylanne3.d13.natural-original-owner-locator.v3' or stages.get(self.owner_kind) != self.stage:
            raise ValueError('D13 exact natural generation/review locator required')
        for name in ('job_id', 'parent_original_id', 'original_id'):
            _text(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class D13SourceReceiverOwnerLocatorV3:
    owner_kind: str
    source_operation_id: str
    source_permit_token: str
    source_permit_digest: str
    receiver_id: str
    retention_id: str
    schema: str = 'sylanne3.d13.source-receiver-owner-locator.v3'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.source-receiver-owner-locator.v3'
                or self.owner_kind not in ('authority_source_receiver', 'host_frame_receiver', 'graph_source_receiver')):
            raise ValueError('D13 exact installed Source receiver locator required')
        for name in ('source_operation_id', 'source_permit_token', 'receiver_id', 'retention_id'):
            _text(getattr(self, name), name)
        _sha(self.source_permit_digest, 'source_permit_digest')


@dataclass(frozen=True, slots=True)
class D13NaturalReceiverOwnerLocatorV3:
    owner_kind: str
    parent_original_id: str
    generation_job_id: str
    generation_original_id: str
    generation_call_id: str
    generation_frozen_input_digest: str
    review_job_id: str | None
    review_original_id: str | None
    source_operation_id: str
    source_permit_token: str
    source_permit_digest: str
    receiver_id: str
    retention_id: str
    selection_digest: str
    schema: str = 'sylanne3.d13.natural-receiver-owner-locator.v3'

    def __post_init__(self):
        if self.schema != 'sylanne3.d13.natural-receiver-owner-locator.v3' or self.owner_kind != 'graph_source_receiver':
            raise ValueError('D13 exact installed natural original receiver required')
        for name in ('parent_original_id', 'generation_job_id', 'generation_original_id', 'generation_call_id',
                'source_operation_id', 'source_permit_token', 'receiver_id', 'retention_id'):
            _text(getattr(self, name), name)
        if (self.review_job_id is None) != (self.review_original_id is None):
            raise ValueError('D13 natural receiver review lineage must be complete')
        if self.review_job_id is not None:
            _text(self.review_job_id, 'review_job_id')
            _text(self.review_original_id, 'review_original_id')
        _sha(self.source_permit_digest, 'source_permit_digest')
        _sha(self.selection_digest, 'selection_digest')
        _sha(self.generation_frozen_input_digest, 'generation_frozen_input_digest')


def owner_locator_from_wire_v3(raw):
    classes = (D13CounterFrameOwnerLocatorV3, D13NaturalOriginalOwnerLocatorV3, D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3, D13AuthoritySourceReceiverOwnerLocatorV4)
    if type(raw) is not dict:
        raise ValueError('D13 typed owner locator required')
    for cls in classes:
        if raw.get('schema') == cls.__dataclass_fields__['schema'].default and set(raw) == {f.name for f in fields(cls)}:
            return cls(**raw)
    raise ValueError('D13 owner locator schema or fields differ')


def owner_payloads_v3(values):
    if type(values) is not tuple or len(values) > 16:
        raise ValueError('D13 original owner needs its exact bounded complete payload set')
    return () if not values else selected_payloads_v2(values)


def owner_operation_id_v3(namespace, owner_ref, action):
    if type(namespace) is not NamespaceId or action not in ('owner_register', 'owner_close', 'owner_retention_release', 'owner_review_verdict', 'owner_parent_disposition', 'owner_parent_input', 'owner_peer_retirement', 'owner_counter_birth', 'owner_generation_parse', 'owner_pre_review_disposition', 'owner_unused_counter_disposition', 'owner_core_birth', 'owner_core_retirement'):
        raise ValueError('D13 exact deterministic owner operation required')
    _text(owner_ref, 'owner_ref')
    return 'd13-owner-v3:' + action + ':' + canonical_digest((PROTOCOL, namespace, owner_ref, action))


@dataclass(frozen=True, slots=True)
class D13OwnerRegistrationReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    use_policy_ref: str
    use_policy_digest: str
    consumer_cohort_digest: str
    owner_ref: str
    owner_kind: str
    original_operation_id: str
    original_locator: object
    original_commitment: str
    producer_binding_digest: str
    payload_identities: tuple
    payload_digest: str
    subject: str
    permit_token: str
    permit_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    registration_digest: str
    peer_admission_digest: str | None = None
    process_incarnation: str | None = None
    producer_kind_version: str | None = None
    retention_instance_ref: str | None = None
    schema: str = OWNER_REGISTRATION_SCHEMA_V3

    def __post_init__(self):
        if self.schema != OWNER_REGISTRATION_SCHEMA_V3 or type(self.namespace) is not NamespaceId or self.owner_kind not in OWNER_KINDS_V3:
            raise ValueError('D13 V3 original owner registration required')
        locator = self.original_locator
        expected_kind = ('counter_frame_draft' if type(locator) is D13CounterFrameOwnerLocatorV3
            else locator.owner_kind if type(locator) in (D13NaturalOriginalOwnerLocatorV3, D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3, D13AuthoritySourceReceiverOwnerLocatorV4) else None)
        if expected_kind != self.owner_kind:
            raise ValueError('D13 owner kind differs from its exact typed producer locator')
        for name in ('authority_namespace', 'installation_id', 'use_policy_ref', 'owner_ref',
                'original_operation_id', 'subject', 'permit_token', 'operation_id'):
            _text(getattr(self, name), name)
        for name in ('use_policy_digest', 'consumer_cohort_digest', 'original_commitment',
                'producer_binding_digest', 'payload_digest', 'permit_digest', 'request_digest', 'registration_digest'):
            _sha(getattr(self, name), name)
        peer_fields = (self.peer_admission_digest, self.process_incarnation, self.producer_kind_version, self.retention_instance_ref)
        if self.owner_kind in ('graph_source_receiver', 'host_frame_receiver'):
            if (any(value is None for value in peer_fields) or type(locator) not in (D13SourceReceiverOwnerLocatorV3, D13NaturalReceiverOwnerLocatorV3)
                    or self.retention_instance_ref != locator.retention_id
                    or self.producer_kind_version != {'graph_source_receiver': 'sylanne3.d13.graph-source-receiver.v3',
                        'host_frame_receiver': 'sylanne3.d13.host-frame-receiver.v3'}[self.owner_kind]):
                raise ValueError('D13 remote receiver registration lacks its installed peer/process/retention original')
            _sha(self.peer_admission_digest, 'peer_admission_digest')
            _text(self.process_incarnation, 'process_incarnation')
            _text(self.retention_instance_ref, 'retention_instance_ref')
        elif self.owner_kind in ('counter_frame_draft', 'natural_generation_original', 'natural_review_original'):
            if any(value is not None for value in peer_fields[:3]) or self.retention_instance_ref is None:
                raise ValueError('D13 local durable producer needs its actual registered retention instance')
            _text(self.retention_instance_ref, 'retention_instance_ref')
        elif any(value is not None for value in peer_fields):
            raise ValueError('D13 local owner cannot impersonate a remote retention producer')
        payloads = owner_payloads_v3(self.payload_identities)
        if canonical_digest(payloads) != self.payload_digest:
            raise ValueError('D13 original owner payload set commitment differs')
        if self.operation_id != owner_operation_id_v3(self.namespace, self.owner_ref, 'owner_register'):
            raise ValueError('D13 registration changed its deterministic original operation')
        _uint(self.control_revision, 'control_revision', 1)
        material = asdict(self)
        material.pop('registration_digest')
        if canonical_digest(material) != self.registration_digest:
            raise ValueError('D13 exact immutable owner registration commitment differs')


@dataclass(frozen=True, slots=True)
class D13RetentionReleaseOriginalV3:
    producer_kind_version: str
    owner_ref: str
    registration_digest: str
    payload_set_digest: str
    peer_admission_digest: str
    process_incarnation: str
    original_permit_digest: str
    retention_instance_ref: str
    release_operation_id: str
    request_digest: str
    schema: str = 'sylanne3.d13.retention-release-original.v3'

    def __post_init__(self):
        if self.schema != 'sylanne3.d13.retention-release-original.v3' or self.producer_kind_version not in (
                'sylanne3.d13.graph-source-receiver.v3', 'sylanne3.d13.host-frame-receiver.v3'):
            raise ValueError('D13 installed named V3 retention producer required')
        for name in ('owner_ref', 'process_incarnation', 'retention_instance_ref', 'release_operation_id'):
            _text(getattr(self, name), name)
        for name in ('registration_digest', 'payload_set_digest', 'peer_admission_digest', 'original_permit_digest', 'request_digest'):
            _sha(getattr(self, name), name)


def retention_release_from_wire_v3(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D13RetentionReleaseOriginalV3)}:
        raise ValueError('D13 exact typed retention-release original required')
    return D13RetentionReleaseOriginalV3(**raw)


@dataclass(frozen=True, slots=True)
class D13OwnerCloseReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    disposition_kind: str
    disposition_ref: str
    disposition_digest: str
    retention_release_ref: str
    retention_release_digest: str
    successor_transfer_digest: str | None
    operation_id: str
    request_digest: str
    control_revision: int
    close_digest: str
    retention_original: object | None = None
    schema: str = OWNER_CLOSE_SCHEMA_V3

    def __post_init__(self):
        if (self.schema != OWNER_CLOSE_SCHEMA_V3 or type(self.namespace) is not NamespaceId
                or self.disposition_kind not in ('terminal', 'never_started', 'transferred', 'peer_retired', 'core_retired')):
            raise ValueError('D13 actual terminal/revocation/confirmed-transfer closure required')
        for name in ('authority_namespace', 'installation_id', 'owner_ref', 'disposition_ref',
                'retention_release_ref', 'operation_id'):
            _text(getattr(self, name), name)
        for name in ('registration_digest', 'disposition_digest', 'retention_release_digest', 'request_digest', 'close_digest'):
            _sha(getattr(self, name), name)
        if (self.disposition_kind == 'transferred') != (self.successor_transfer_digest is not None):
            raise ValueError('D13 transferred owner closure needs its confirmed successor commitment')
        if self.successor_transfer_digest is not None:
            _sha(self.successor_transfer_digest, 'successor_transfer_digest')
        if self.retention_original is not None:
            value = self.retention_original
            if (type(value) is not D13RetentionReleaseOriginalV3 or value.owner_ref != self.owner_ref
                    or value.registration_digest != self.registration_digest
                    or value.release_operation_id != self.operation_id
                    or canonical_digest(value) != self.retention_release_digest):
                raise ValueError('D13 remote closure differs from its exact retained final-release original')
        if self.operation_id != owner_operation_id_v3(self.namespace, self.owner_ref, 'owner_close'):
            raise ValueError('D13 closure changed its deterministic original operation')
        _uint(self.control_revision, 'control_revision', 1)
        material = asdict(self)
        material.pop('close_digest')
        if canonical_digest(material) != self.close_digest:
            raise ValueError('D13 actual owner closure commitment differs')


def cache_use_result_from_wire_v3(raw):
    classes = (D13CacheUseObservationV2, D13CachePinReceiptV2, D13OwnerRegistrationReceiptV3, D13OwnerCloseReceiptV3, D13OwnerRetentionReleaseReceiptV3, D13NaturalReviewVerdictReceiptV3, D13NaturalParentDispositionReceiptV3, D13NaturalParentInputReceiptV3, D13RetiredReceiverOriginalV3, D13ControlledSDKConsumerReadyReceiptV3, D13CounterFrameBirthReceiptV3, D13NaturalGenerationParseReceiptV3, D13NaturalPreReviewDispositionReceiptV3, D13UnusedCounterDispositionReceiptV3, D13AuthorityCoreBirthReceiptV4, D13RetiredCoreReceiverOriginalV4)
    schemas = (OBSERVATION_SCHEMA, PIN_SCHEMA, OWNER_REGISTRATION_SCHEMA_V3, OWNER_CLOSE_SCHEMA_V3, RETENTION_SCHEMA_V3, REVIEW_VERDICT_SCHEMA_V3, PARENT_DISPOSITION_SCHEMA_V3, PARENT_INPUT_SCHEMA_V3, RETIRED_RECEIVER_SCHEMA_V3, CONTROLLED_SDK_READY_SCHEMA_V3, COUNTER_BIRTH_SCHEMA_V3, GENERATION_PARSE_SCHEMA_V3, PRE_REVIEW_DISPOSITION_SCHEMA_V3, UNUSED_COUNTER_DISPOSITION_SCHEMA_V3, CORE_BIRTH_SCHEMA_V4, CORE_RETIREMENT_SCHEMA_V4)
    for cls, schema in zip(classes, schemas):
        if type(raw) is dict and raw.get('schema') == schema:
            return cache_use_from_wire_v2(raw, cls)
    raise ValueError('D13 V3 closed receipt union required')

RETENTION_SCHEMA_V3 = 'sylanne3.d13.owner-retention-release.v3'


@dataclass(frozen=True, slots=True)
class D13OwnerRetentionReleaseReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    retention_instance_ref: str
    scope_operation_id: str
    resource_selection_digest: str
    producer_binding_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    retention_digest: str
    schema: str = RETENTION_SCHEMA_V3

    def __post_init__(self):
        if self.schema != RETENTION_SCHEMA_V3 or type(self.namespace) is not NamespaceId:
            raise ValueError('D13 exact actual owner retention-release original required')
        for name in ('authority_namespace', 'installation_id', 'owner_ref', 'retention_instance_ref',
                'scope_operation_id', 'operation_id'):
            _text(getattr(self, name), name)
        for name in ('registration_digest', 'resource_selection_digest', 'producer_binding_digest',
                'request_digest', 'retention_digest'):
            _sha(getattr(self, name), name)
        if self.operation_id != owner_operation_id_v3(self.namespace, self.owner_ref, 'owner_retention_release'):
            raise ValueError('D13 retention release changed its deterministic original operation')
        _uint(self.control_revision, 'control_revision', 1)
        material = asdict(self)
        material.pop('retention_digest')
        if canonical_digest(material) != self.retention_digest:
            raise ValueError('D13 actual retention release commitment differs')


REVIEW_VERDICT_SCHEMA_V3 = 'sylanne3.d13.natural-review-verdict.v3'
PARENT_DISPOSITION_SCHEMA_V3 = 'sylanne3.d13.natural-parent-disposition.v3'


def _validate_natural_core_original_v3(value, schema, action, digest_field):
    if value.schema != schema or type(value.namespace) is not NamespaceId:
        raise ValueError('D13 exact typed natural Core original required')
    for field in fields(value):
        name, member = field.name, getattr(value, field.name)
        if name in ('namespace', 'schema', 'child_identities'):
            continue
        if name in ('parsed_output_digest', 'rejection_code') and member is None:
            continue
        if name in ('source_pointer_version', 'source_storage_generation', 'activation_generation'):
            _uint(member, name)
        elif name in ('control_revision', 'census_count', 'plan_revision', 'source_revision', 'child_count', 'source_column_bytes'):
            _uint(member, name, 1)
        elif name.endswith('_digest') or name == 'census_root':
            _sha(member, name)
        else:
            _text(member, name)
    if value.operation_id != owner_operation_id_v3(value.namespace, value.owner_ref, action):
        raise ValueError('D13 natural Core original changed its deterministic operation')
    material = asdict(value)
    material.pop(digest_field)
    if canonical_digest(material) != getattr(value, digest_field):
        raise ValueError('D13 natural Core original commitment differs')


@dataclass(frozen=True, slots=True)
class D13NaturalReviewVerdictReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    generation_original_id: str
    generation_original_digest: str
    review_original_id: str
    review_original_digest: str
    generation_output_digest: str
    review_output_digest: str
    verdict: str
    observation_digest: str
    terminal_receipt_digest: str
    original_intent_digest: str
    typed_model_request_digest: str
    parse_binding_digest: str
    producer_permit_operation_id: str
    producer_permit_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    verdict_digest: str
    schema: str = REVIEW_VERDICT_SCHEMA_V3

    def __post_init__(self):
        if self.verdict not in ('pass', 'rewrite', 'hold'):
            raise ValueError('D13 actual parsed natural review verdict is invalid')
        _validate_natural_core_original_v3(self, REVIEW_VERDICT_SCHEMA_V3, 'owner_review_verdict', 'verdict_digest')


@dataclass(frozen=True, slots=True)
class D13NaturalParentDispositionReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    generation_original_id: str
    generation_original_digest: str
    review_original_id: str
    review_original_digest: str
    disposition_kind: str
    cause_ref: str
    cause_digest: str
    child_derivation_schema: str
    child_identities: tuple
    child_identity_digest: str
    census_root: str
    census_count: int
    core_head_digest: str
    graph_snapshot_digest: str
    retention_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    disposition_digest: str
    schema: str = PARENT_DISPOSITION_SCHEMA_V3

    def __post_init__(self):
        if self.disposition_kind not in ('nonpass', 'owner_stop', 'superseded'):
            raise ValueError('D13 bodyless parent disposition requires an actual permanent cause')
        if (self.child_derivation_schema != 'sylanne3.d13.natural-child-identity-derivation.v3'
                or type(self.child_identities) is not tuple or not 1 <= len(self.child_identities) <= 4
                or tuple(child[0] for child in self.child_identities) != tuple(range(len(self.child_identities)))
                or any(type(child) is not tuple or len(child) != 3 for child in self.child_identities)
                or self.child_identity_digest != canonical_digest(self.child_identities)):
            raise ValueError('D13 permanent natural disposition needs its complete deterministic child census')
        for _, operation_id, effect_id in self.child_identities:
            _text(operation_id, 'child operation_id')
            _text(effect_id, 'child effect_id')
        _validate_natural_core_original_v3(self, PARENT_DISPOSITION_SCHEMA_V3, 'owner_parent_disposition', 'disposition_digest')


PARENT_INPUT_SCHEMA_V3 = 'sylanne3.d13.natural-parent-input-identity.v3'


@dataclass(frozen=True, slots=True)
class D13NaturalParentInputReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    generation_original_id: str
    generation_original_digest: str
    review_original_id: str
    review_original_digest: str
    plan_ref: str
    plan_revision: int
    first_operation_id: str
    first_effect_id: str
    whole_output_digest: str
    child_count: int
    child_identities: tuple
    child_identity_digest: str
    source_column_digest: str
    source_column_bytes: int
    producer_binding_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    input_digest: str
    schema: str = PARENT_INPUT_SCHEMA_V3

    def __post_init__(self):
        if (type(self.child_count) is not int or not 1 <= self.child_count <= 4
                or type(self.child_identities) is not tuple or len(self.child_identities) != self.child_count
                or any(type(child) is not tuple or len(child) != 3 for child in self.child_identities)
                or tuple(child[0] for child in self.child_identities) != tuple(range(self.child_count))
                or self.child_identity_digest != canonical_digest(self.child_identities)):
            raise ValueError('D13 actual parent input capsule needs its complete bounded identity manifest')
        from ..runtime_contracts import VersionedRef
        plan = VersionedRef(self.plan_ref, self.plan_revision)
        expected = []
        for index in range(self.child_count):
            digest = canonical_digest({'plan': plan, 'output': self.whole_output_digest, 'index': index})
            expected.append((index, self.first_operation_id if index == 0 else 'operation:natural-segment:' + digest,
                self.first_effect_id if index == 0 else 'effect:natural-segment:' + digest))
        if self.child_identities != tuple(expected):
            raise ValueError('D13 parent input identities differ from their actual derivation')
        _validate_natural_core_original_v3(self, PARENT_INPUT_SCHEMA_V3, 'owner_parent_input', 'input_digest')


RETIRED_RECEIVER_SCHEMA_V3 = 'sylanne3.d13.retired-receiver-original.v3'


@dataclass(frozen=True, slots=True)
class D13RetiredReceiverOriginalV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    peer_admission_digest: str
    process_incarnation: str
    producer_kind_version: str
    retention_instance_ref: str
    payload_set_digest: str
    maintenance_operation_id: str
    retirement_digest: str
    retirement_completion_digest: str
    quiescence_digest: str
    source_manifest_digest: str
    source_pointer_version: int
    source_storage_generation: int
    source_permit_token: str
    source_permit_digest: str
    terminal_ref: str
    terminal_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    retirement_original_digest: str
    schema: str = RETIRED_RECEIVER_SCHEMA_V3

    def __post_init__(self):
        if self.producer_kind_version not in (
                'sylanne3.d13.graph-source-receiver.v3', 'sylanne3.d13.host-frame-receiver.v3'):
            raise ValueError('D13 peer retirement original is restricted to registered remote receivers')
        _validate_natural_core_original_v3(self, RETIRED_RECEIVER_SCHEMA_V3, 'owner_peer_retirement', 'retirement_original_digest')


CONTROLLED_SDK_READY_SCHEMA_V3 = 'sylanne3.d13.controlled-sdk-consumer-ready.v3'


def controlled_sdk_consumer_ready_operation_id_v3(namespace, peer_admission_digest, consumer_cohort_digest):
    if type(namespace) is not NamespaceId:
        raise ValueError('actual controlled SDK namespace required')
    _sha(peer_admission_digest, 'peer_admission_digest')
    _sha(consumer_cohort_digest, 'consumer_cohort_digest')
    return 'd13-controlled-sdk-ready-v3:' + canonical_digest((namespace, peer_admission_digest, consumer_cohort_digest))


@dataclass(frozen=True, slots=True)
class D13ControlledSDKConsumerReadyReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    authority_id: str
    control_store_id: str
    use_policy_ref: str
    use_policy_digest: str
    consumer_cohort_digest: str
    peer_certificate_sha256: str
    profile_id: str
    peer_admission_digest: str
    process_incarnation: str
    process_original_digest: str
    selected_manifest_digest: str
    pointer_version: int
    storage_generation: int
    descriptor_digest: str
    process_census_digest: str
    producer_binding_digest: str
    resource_operation_id: str
    resource_selection_digest: str
    resource_deadline_utc: str | None
    operation_id: str
    request_digest: str
    control_revision: int
    key_id: str
    ready_digest: str
    signature: str
    schema: str = CONTROLLED_SDK_READY_SCHEMA_V3

    def __post_init__(self):
        from .c09_storage_control_v1 import digest
        if self.schema != CONTROLLED_SDK_READY_SCHEMA_V3 or type(self.namespace) is not NamespaceId:
            raise ValueError('D13 exact controlled SDK consumer ready original required')
        for field in fields(self):
            name, value = field.name, getattr(self, field.name)
            if name in ('namespace', 'schema'):
                continue
            if name == 'resource_deadline_utc':
                if value is not None:
                    from ..runtime.d11_offline_originals_v1 import _utc
                    _utc(value)
            elif name in ('pointer_version', 'storage_generation'):
                _uint(value, name)
            elif name == 'control_revision':
                _uint(value, name, 1)
            elif name.endswith('_digest') or name in ('peer_certificate_sha256', 'signature'):
                _sha(value, name)
            else:
                _text(value, name)
        if self.operation_id != controlled_sdk_consumer_ready_operation_id_v3(
                self.namespace, self.peer_admission_digest, self.consumer_cohort_digest):
            raise ValueError('controlled SDK ready original changed its exact admission/cohort operation')
        material = asdict(self)
        material.pop('ready_digest')
        material.pop('signature')
        if digest(material) != self.ready_digest:
            raise ValueError('controlled SDK ready Control-key original digest differs')


COUNTER_BIRTH_SCHEMA_V3 = 'sylanne3.d13.counter-frame-birth.v3'
GENERATION_PARSE_SCHEMA_V3 = 'sylanne3.d13.natural-generation-parse.v3'


@dataclass(frozen=True, slots=True)
class D13CounterFrameBirthReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    counter_operation_id: str
    frame_intent_id: str
    frame_intent_digest: str
    draft_commitment: str
    input_digest: str
    plan_ref: str
    plan_revision: int
    generation_call_id: str
    activation_generation: int
    first_operation_id: str
    first_effect_id: str
    planned_job_id: str
    planned_execution_id: str
    planned_activity_id: str
    algorithm_ref: str
    algorithm_build_digest: str
    source_ref: str
    source_revision: int
    source_scope_digest: str
    owner_grant_digest: str
    owner_responsibility_digest: str
    parent_budget_lease_ref: str
    budget_grant_digest: str
    policy_digest: str
    planned_binding_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    birth_digest: str
    schema: str = COUNTER_BIRTH_SCHEMA_V3

    def __post_init__(self):
        _sha(self.draft_commitment, 'draft_commitment')
        _validate_natural_core_original_v3(self, COUNTER_BIRTH_SCHEMA_V3, 'owner_counter_birth', 'birth_digest')


@dataclass(frozen=True, slots=True)
class D13NaturalGenerationParseReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    generation_job_id: str
    generation_original_id: str
    generation_original_digest: str
    generation_call_id: str
    frozen_input_digest: str
    plan_ref: str
    plan_revision: int
    first_operation_id: str
    first_effect_id: str
    raw_output_digest: str
    parsed_output_digest: str | None
    parse_outcome: str
    rejection_code: str | None
    parser_version: str
    template_version: str
    template_digest: str
    output_schema: str
    observation_digest: str
    terminal_receipt_digest: str
    original_intent_digest: str
    typed_model_request_digest: str
    parser_binding_digest: str
    producer_permit_operation_id: str
    producer_permit_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    parse_digest: str
    schema: str = GENERATION_PARSE_SCHEMA_V3

    def __post_init__(self):
        if self.parse_outcome not in ('adoptable', 'no_reply_hold', 'output_rejected'):
            raise ValueError('D13 generation parse needs its exact actual deterministic outcome')
        if self.parse_outcome == 'output_rejected':
            if self.parsed_output_digest is not None or self.rejection_code not in (
                    'canonical_payload_rejected', 'provider_result_shape'):
                raise ValueError('D13 generation rejection has no closed actual parser reason')
        elif self.parsed_output_digest is None or self.rejection_code is not None:
            raise ValueError('D13 parsed generation outcome needs its actual canonical output digest')
        _validate_natural_core_original_v3(self, GENERATION_PARSE_SCHEMA_V3, 'owner_generation_parse', 'parse_digest')


PRE_REVIEW_DISPOSITION_SCHEMA_V3 = 'sylanne3.d13.natural-pre-review-disposition.v3'


@dataclass(frozen=True, slots=True)
class D13NaturalPreReviewDispositionReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    generation_original_id: str
    generation_original_digest: str
    parse_original_ref: str
    parse_digest: str
    disposition_kind: str
    census_root: str
    core_head_digest: str
    graph_snapshot_digest: str
    retention_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    disposition_digest: str
    schema: str = PRE_REVIEW_DISPOSITION_SCHEMA_V3

    def __post_init__(self):
        if self.disposition_kind not in ('no_reply_hold', 'output_rejected'):
            raise ValueError('D13 pre-review disposition requires its actual deterministic parse outcome')
        _validate_natural_core_original_v3(self, PRE_REVIEW_DISPOSITION_SCHEMA_V3,
            'owner_pre_review_disposition', 'disposition_digest')


UNUSED_COUNTER_DISPOSITION_SCHEMA_V3 = 'sylanne3.d13.unused-counter-disposition.v3'


@dataclass(frozen=True, slots=True)
class D13UnusedCounterDispositionReceiptV3:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    parent_original_id: str
    counter_birth_ref: str
    counter_birth_digest: str
    cause_ref: str
    cause_digest: str
    cpu_census_digest: str
    census_root: str
    core_head_digest: str
    graph_snapshot_digest: str
    retention_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    disposition_digest: str
    schema: str = UNUSED_COUNTER_DISPOSITION_SCHEMA_V3

    def __post_init__(self):
        _validate_natural_core_original_v3(self, UNUSED_COUNTER_DISPOSITION_SCHEMA_V3,
            'owner_unused_counter_disposition', 'disposition_digest')


@dataclass(frozen=True, slots=True)
class D13AuthoritySourceReceiverOwnerLocatorV4:
    owner_kind: str
    source_operation_id: str
    source_permit_token: str
    source_permit_digest: str
    receiver_id: str
    retention_id: str
    selection_digest: str
    core_incarnation_id: str
    core_birth_original_ref: str
    core_birth_original_digest: str
    schema: str = 'sylanne3.d13.authority-source-receiver-owner-locator.v4'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.authority-source-receiver-owner-locator.v4'
                or self.owner_kind != 'authority_source_receiver'):
            raise ValueError('D13 explicit local Core-incarnation V4 receiver locator required')
        for name in ('source_operation_id', 'source_permit_token', 'receiver_id', 'retention_id',
                'core_incarnation_id', 'core_birth_original_ref'):
            _text(getattr(self, name), name)
        for name in ('source_permit_digest', 'selection_digest', 'core_birth_original_digest'):
            _sha(getattr(self, name), name)


CORE_BIRTH_SCHEMA_V4 = 'sylanne3.d13.authority-core-birth.v4'


@dataclass(frozen=True, slots=True)
class D13AuthorityCoreBirthReceiptV4:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    authority_id: str
    control_store_id: str
    owner_ref: str
    core_incarnation_id: str
    birth_profile: str
    core_instance_nonce_digest: str
    authority_process_original: dict
    root_observation_original: dict
    root_authority_observation_digest: str
    root_process_census_digest: str
    authority_spec_digest: str
    instance_lock_ref: str
    selected_manifest_digest: str
    pointer_version: int
    storage_generation: int
    use_policy_ref: str
    use_policy_digest: str
    consumer_cohort_digest: str
    producer_binding_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    key_id: str
    birth_digest: str
    signature: str
    schema: str = CORE_BIRTH_SCHEMA_V4

    def __post_init__(self):
        from .c09_storage_control_v1 import digest
        if self.schema != CORE_BIRTH_SCHEMA_V4 or type(self.namespace) is not NamespaceId:
            raise ValueError('D13 exact Control-signed local Core V4 birth original required')
        if self.birth_profile not in ('production_root', 'controlled_sdk'):
            raise ValueError('D13 local Core birth requires its explicit Root producer profile')
        original = self.authority_process_original
        if (type(original) is not dict or set(original) != {'pid', 'platform', 'birth'}
                or type(original['pid']) is not int or original['pid'] < 1
                or original['platform'] not in ('windows', 'linux')):
            raise ValueError('D13 Core birth requires the complete actual process original')
        _text(original['birth'], 'process birth')
        root = self.root_observation_original
        if type(root) is not dict:
            raise ValueError('D13 Core birth requires its full actual Root producer original')
        if self.birth_profile == 'production_root':
            from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
            observation = decode_process_supervisor_observation_v2(root)
            if (observation.service_role != 'authority' or observation.state != 'active'
                    or observation.main_process_original != original
                    or observation.spec_digest != self.authority_spec_digest
                    or observation.observation_digest != self.root_authority_observation_digest):
                raise ValueError('D13 Core birth differs from its complete actual Authority-role Root observation')
        else:
            from ..host.c09_controlled_sdk_bootstrap_v3 import validate_controlled_sdk_root_census_original_v4
            validate_controlled_sdk_root_census_original_v4(root)
            if (root['authority_process']['pid'] != original['pid']
                    or root['authority_process']['birth'] != original['birth']
                    or canonical_digest(root['authority_process']) != self.root_authority_observation_digest):
                raise ValueError('D13 SDK Core birth differs from its complete actual held Root census')
        if canonical_digest(root) != self.root_process_census_digest:
            raise ValueError('D13 Core birth full Root evidence differs from its signed producer commitment')
        for field in fields(self):
            name, value = field.name, getattr(self, field.name)
            if name in ('namespace', 'schema', 'authority_process_original', 'root_observation_original'):
                continue
            if name in ('pointer_version', 'storage_generation'):
                _uint(value, name)
            elif name == 'control_revision':
                _uint(value, name, 1)
            elif name.endswith('_digest') or name == 'signature':
                _sha(value, name)
            else:
                _text(value, name)
        if (self.owner_ref != self.core_incarnation_id
                or self.operation_id != owner_operation_id_v3(self.namespace, self.owner_ref, 'owner_core_birth')):
            raise ValueError('D13 Core birth changed its exact incarnation/original operation')
        material = asdict(self)
        material.pop('birth_digest')
        material.pop('signature')
        if digest(material) != self.birth_digest:
            raise ValueError('D13 Control-signed Core birth digest differs')


def validate_core_authority_retirement_original_v4(original, *, birth_profile):
    """Historical closed metadata only; physical authority comes from its private Root cap."""
    common = {'schema', 'birth_profile', 'birth_original_ref', 'birth_original_digest', 'birth_selector_digest',
        'core_incarnation_id', 'authority_id', 'installation_id', 'control_store_id', 'namespace',
        'old_authority_process_original', 'birth_storage_manifest_digest', 'birth_pointer_version',
        'birth_storage_generation', 'old_root_observation_digest', 'observer_hold_nonce', 'complete'}
    production = {'old_root_process_original', 'old_ancestor_root_process_original',
        'old_pid_namespace_identity', 'old_mount_namespace_identity', 'old_procfs_identity',
        'observer_process_original', 'kernel_boot_id', 'observer_spec_digest', 'lifetime_id',
        'launch_id', 'cohort_source_root', 'root_pidfd_exit', 'census_count', 'census_root',
        'eof_digest', 'resource_scope_original_digest'}
    sdk = {'old_root_process_original', 'old_pid_namespace_identity', 'old_mount_namespace_identity',
        'current_root_census_digest', 'source_phase', 'source_node', 'source_setup_sha256',
        'source_process_identity', 'actual_exit_code', 'original_pidfd_ready', 'recursive_populated',
        'waitpid_reaped', 'resource_operation_id', 'root_process_original', 'prior_receipt_digest', 'eof_digest'}
    schema = {'production_root': 'sylanne3.d13.core-authority-retirement.production-root.v4',
        'controlled_sdk': 'sylanne3.d13.core-authority-retirement.controlled-sdk.v4'}
    if (birth_profile not in schema or type(original) is not dict
            or set(original) != common | (production if birth_profile == 'production_root' else sdk)
            or original['schema'] != schema[birth_profile] or original['birth_profile'] != birth_profile
            or original['complete'] is not True):
        raise ValueError('D13 exact complete Root core-authority retirement metadata required')
    def process(value):
        if (type(value) is not dict or set(value) != {'pid', 'platform', 'birth'}
                or type(value['pid']) is not int or value['pid'] < 1 or value['platform'] != 'linux'):
            raise ValueError('D13 Root retirement requires its exact actual Linux process identity')
        _text(value['birth'], 'process birth')
    process_fields = {'old_authority_process_original', 'old_root_process_original',
        'old_ancestor_root_process_original', 'observer_process_original', 'root_process_original'}
    special = {'schema', 'birth_profile', 'complete', 'root_pidfd_exit', 'census_count',
        'original_pidfd_ready', 'recursive_populated', 'waitpid_reaped', 'old_procfs_identity',
        'source_process_identity', 'actual_exit_code'}
    for name, value in original.items():
        if name in process_fields:
            process(value)
        elif name in ('birth_pointer_version', 'birth_storage_generation'):
            _uint(value, name)
        elif name in special:
            continue
        elif name.endswith('_digest') or name in ('birth_storage_manifest_digest',
                'cohort_source_root', 'census_root', 'source_setup_sha256'):
            _sha(value, name)
        else:
            _text(value, name)
    if birth_profile == 'production_root':
        identity = original['old_procfs_identity']
        if (type(identity) is not dict or set(identity) != {'device', 'inode'}
                or original['root_pidfd_exit'] is not True
                or type(original['census_count']) is not int or original['census_count'] != 0
                or original['census_root'] != canonical_digest(())):
            raise ValueError('D13 production Root retirement lacks its exact procfs/pidfd/empty-census original')
        _uint(identity['device'], 'procfs device')
        _uint(identity['inode'], 'procfs inode', 1)
        expected = canonical_digest((original['cohort_source_root'], original['kernel_boot_id'],
            (), original['observer_hold_nonce']))
    else:
        source = original['source_process_identity']
        if (type(source) is not dict or set(source) != {'pid', 'birth', 'mount_namespace', 'pid_namespace'}
                or type(source['pid']) is not int or source['pid'] < 1
                or type(original['actual_exit_code']) is not int
                or original['original_pidfd_ready'] is not True or original['waitpid_reaped'] is not True
                or original['recursive_populated'] is not False
                or (source['pid'], source['birth']) !=
                    (original['old_authority_process_original']['pid'], original['old_authority_process_original']['birth'])
                or source['mount_namespace'] != original['old_mount_namespace_identity']
                or source['pid_namespace'] != original['old_pid_namespace_identity']):
            raise ValueError('D13 SDK Root retirement lacks its exact reaped pidfd/namespace/cgroup EOF original')
        for name in ('birth', 'mount_namespace', 'pid_namespace'):
            _text(source[name], name)
        expected = canonical_digest((original['birth_original_digest'], original['prior_receipt_digest'],
            original['current_root_census_digest'], original['observer_hold_nonce']))
    if original['eof_digest'] != expected:
        raise ValueError('D13 Root physical-retirement EOF commitment differs')
    return original


CORE_RETIREMENT_SCHEMA_V4 = 'sylanne3.d13.retired-core-receiver-original.v4'


@dataclass(frozen=True, slots=True)
class D13RetiredCoreReceiverOriginalV4:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    owner_ref: str
    registration_digest: str
    core_incarnation_id: str
    core_birth_original_ref: str
    core_birth_original_digest: str
    current_core_birth_ref: str
    current_core_birth_digest: str
    birth_profile: str
    physical_retirement_original: dict
    physical_retirement_digest: str
    source_permit_token: str
    source_permit_digest: str
    terminal_ref: str
    terminal_digest: str
    operation_id: str
    request_digest: str
    control_revision: int
    key_id: str
    retirement_digest: str
    signature: str
    schema: str = CORE_RETIREMENT_SCHEMA_V4

    def __post_init__(self):
        from .c09_storage_control_v1 import digest
        if self.schema != CORE_RETIREMENT_SCHEMA_V4 or type(self.namespace) is not NamespaceId:
            raise ValueError('D13 exact Control-signed retired local Core receiver original required')
        original = validate_core_authority_retirement_original_v4(
            self.physical_retirement_original, birth_profile=self.birth_profile)
        if (canonical_digest(original) != self.physical_retirement_digest
                or original['birth_original_ref'] != self.core_birth_original_ref
                or original['birth_original_digest'] != self.core_birth_original_digest
                or original['core_incarnation_id'] != self.core_incarnation_id
                or original['installation_id'] != self.installation_id
                or original['namespace'] != self.authority_namespace):
            raise ValueError('D13 retired Core receiver differs from its complete actual Root physical original')
        for field in fields(self):
            name, value = field.name, getattr(self, field.name)
            if name in ('namespace', 'schema', 'physical_retirement_original'):
                continue
            if name == 'control_revision':
                _uint(value, name, 1)
            elif name.endswith('_digest') or name == 'signature':
                _sha(value, name)
            else:
                _text(value, name)
        if self.operation_id != owner_operation_id_v3(self.namespace, self.owner_ref, 'owner_core_retirement'):
            raise ValueError('D13 local Core receiver retirement changed its deterministic original operation')
        material = asdict(self)
        material.pop('retirement_digest')
        material.pop('signature')
        if digest(material) != self.retirement_digest:
            raise ValueError('D13 Control-signed retired Core receiver digest differs')


@dataclass(frozen=True, slots=True)
class D13PendingNaturalParentClosuresV3:
    """Authenticated metadata discovery; candidates grant no execution or close right."""
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    activation_generation: int
    after_operation_id: str
    cursor: str
    limit: int
    scanned_count: int
    eof: bool
    candidates: tuple[tuple[str, str, str, str], ...]
    schema: str = 'sylanne3.d13.pending-natural-parent-closures.v3'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.pending-natural-parent-closures.v3'
                or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.limit) is not int or not 1 <= self.limit <= 4
                or type(self.scanned_count) is not int or not 0 <= self.scanned_count <= self.limit
                or type(self.eof) is not bool or self.eof != (self.scanned_count < self.limit)
                or type(self.candidates) is not tuple or len(self.candidates) > self.scanned_count):
            raise ValueError('exact bounded natural parent metadata page required')
        for name in ('authority_namespace', 'authority_id', 'installation_id'):
            _text(getattr(self, name), name)
        for cursor in (self.after_operation_id, self.cursor):
            if type(cursor) is not str or len(cursor) > 192:
                raise ValueError('bounded natural parse operation cursor required')
        if ((self.scanned_count == 0 and self.cursor != self.after_operation_id)
                or (self.scanned_count > 0 and self.cursor <= self.after_operation_id)):
            raise ValueError('natural metadata cursor must advance only over actual scanned rows')
        previous = self.after_operation_id
        for candidate in self.candidates:
            if type(candidate) is not tuple or len(candidate) != 4:
                raise ValueError('exact bodyless natural parent candidate required')
            parent, parse_digest, owner_ref, operation = candidate
            for value in (parent, owner_ref, operation):
                if type(value) is not str or not 1 <= len(value) <= 192:
                    raise ValueError('bounded natural parent original locator required')
            _sha(parse_digest, 'parse_digest')
            if not previous < operation <= self.cursor:
                raise ValueError('natural candidates must retain their actual parse operation order')
            previous = operation


def pending_natural_parent_closures_from_wire_v3(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D13PendingNaturalParentClosuresV3)}:
        raise ValueError('closed natural parent metadata page wire required')
    namespace = raw['namespace']
    if type(namespace) is not dict or set(namespace) != {'bot_id', 'persona_id'}:
        raise ValueError('exact natural parent Graph namespace wire required')
    candidates = raw['candidates']
    if type(candidates) is not list or any(type(value) is not list for value in candidates):
        raise ValueError('exact natural parent candidate array wire required')
    return D13PendingNaturalParentClosuresV3(**dict(raw, namespace=NamespaceId(**namespace),
        candidates=tuple(tuple(value) for value in candidates)))



@dataclass(frozen=True, slots=True)
class D13NaturalParentClosureOriginalV3:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    activation_generation: int
    candidate: tuple[str, str, str, str]
    parse_original: D13NaturalGenerationParseReceiptV3
    registration: D13OwnerRegistrationReceiptV3
    schema: str = 'sylanne3.d13.natural-parent-closure-original.v3'

    def __post_init__(self):
        parse, registration = self.parse_original, self.registration
        if (self.schema != 'sylanne3.d13.natural-parent-closure-original.v3'
                or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(parse) is not D13NaturalGenerationParseReceiptV3
                or type(registration) is not D13OwnerRegistrationReceiptV3
                or type(self.candidate) is not tuple
                or self.candidate != (parse.parent_original_id, parse.parse_digest, parse.owner_ref, parse.operation_id)
                or parse.parse_outcome not in ('no_reply_hold', 'output_rejected')
                or parse.namespace != self.namespace or registration.namespace != self.namespace
                or parse.authority_namespace != self.authority_namespace
                or registration.authority_namespace != self.authority_namespace
                or parse.installation_id != self.installation_id
                or registration.installation_id != self.installation_id
                or parse.registration_digest != registration.registration_digest
                or parse.owner_ref != registration.owner_ref):
            raise ValueError('exact immutable natural parse/registration metadata required')
        for name in ('authority_namespace', 'authority_id', 'installation_id'):
            _text(getattr(self, name), name)


def natural_parent_closure_original_from_wire_v3(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D13NaturalParentClosureOriginalV3)}:
        raise ValueError('closed natural parent original metadata wire required')
    namespace = raw['namespace']
    if type(namespace) is not dict or set(namespace) != {'bot_id', 'persona_id'} or type(raw['candidate']) is not list:
        raise ValueError('exact natural parent namespace/candidate wire required')
    return D13NaturalParentClosureOriginalV3(**dict(raw, namespace=NamespaceId(**namespace),
        candidate=tuple(raw['candidate']),
        parse_original=cache_use_result_from_wire_v3(raw['parse_original']),
        registration=cache_use_result_from_wire_v3(raw['registration'])))


@dataclass(frozen=True, slots=True)
class D13NaturalParentClosureCandidateV4:
    parent_original_id: str
    owner_ref: str
    registration_digest: str
    origin_kind: str
    origin_operation_id: str
    origin_digest: str
    schema: str = 'sylanne3.d13.natural-parent-closure-candidate.v4'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.natural-parent-closure-candidate.v4'
                or self.origin_kind not in ('generation_parse', 'parent_input')):
            raise ValueError('exact natural parent closure V4 origin kind required')
        for name in ('parent_original_id', 'owner_ref', 'origin_operation_id'):
            value = getattr(self, name)
            if type(value) is not str or not 1 <= len(value) <= 192:
                raise ValueError('bounded actual natural closure locator required')
        _sha(self.registration_digest, 'registration_digest')
        _sha(self.origin_digest, 'origin_digest')


def natural_parent_closure_candidate_from_wire_v4(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(D13NaturalParentClosureCandidateV4)}:
        raise ValueError('closed natural closure candidate V4 wire required')
    return D13NaturalParentClosureCandidateV4(**raw)


@dataclass(frozen=True, slots=True)
class D13PendingNaturalParentClosuresV4:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    activation_generation: int
    after_operation_id: str
    cursor: str
    limit: int
    scanned_count: int
    eof: bool
    candidates: tuple[D13NaturalParentClosureCandidateV4, ...]
    schema: str = 'sylanne3.d13.pending-natural-parent-closures.v4'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.pending-natural-parent-closures.v4'
                or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.limit) is not int or not 1 <= self.limit <= 4
                or type(self.scanned_count) is not int or not 0 <= self.scanned_count <= self.limit
                or type(self.eof) is not bool or self.eof != (self.scanned_count < self.limit)
                or type(self.candidates) is not tuple or len(self.candidates) > self.scanned_count):
            raise ValueError('exact bounded V4 parent metadata page required')
        for name in ('authority_namespace', 'authority_id', 'installation_id'):
            _text(getattr(self, name), name)
        for cursor in (self.after_operation_id, self.cursor):
            if type(cursor) is not str or len(cursor) > 192:
                raise ValueError('bounded actual V4 metadata cursor required')
        if ((self.scanned_count == 0 and self.cursor != self.after_operation_id)
                or (self.scanned_count > 0 and self.cursor <= self.after_operation_id)):
            raise ValueError('V4 cursor must advance only over actual scanned originals')
        previous = self.after_operation_id
        for candidate in self.candidates:
            if (type(candidate) is not D13NaturalParentClosureCandidateV4
                    or not previous < candidate.origin_operation_id <= self.cursor):
                raise ValueError('V4 candidates must retain their actual original order')
            previous = candidate.origin_operation_id


def pending_natural_parent_closures_from_wire_v4(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(D13PendingNaturalParentClosuresV4)}:
        raise ValueError('closed V4 natural parent metadata page required')
    namespace = raw['namespace']
    if type(namespace) is not dict or set(namespace) != {'bot_id', 'persona_id'} or type(raw['candidates']) is not list:
        raise ValueError('exact V4 namespace/candidate array required')
    return D13PendingNaturalParentClosuresV4(**dict(raw, namespace=NamespaceId(**namespace),
        candidates=tuple(natural_parent_closure_candidate_from_wire_v4(value) for value in raw['candidates'])))


_NATURAL_PARENT_CORE_WAITING_V4 = (
    'generation_output_read_open', 'review_model_pending', 'review_output_pending', 'review_output_read_open', 'roster_write_open')
_NATURAL_PARENT_WAITING_V4 = (*_NATURAL_PARENT_CORE_WAITING_V4,
    'roster_pending', 'child_not_started', 'outbound_adoption_pending')


@dataclass(frozen=True, slots=True)
class D13NaturalParentClosureWaitingV4:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    activation_generation: int
    candidate: D13NaturalParentClosureCandidateV4
    reason: str
    state_digest: str
    read_operation_id: str
    schema: str = 'sylanne3.d13.natural-parent-closure-waiting.v4'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.natural-parent-closure-waiting.v4'
                or type(self.namespace) is not NamespaceId
                or type(self.candidate) is not D13NaturalParentClosureCandidateV4
                or self.reason not in _NATURAL_PARENT_WAITING_V4):
            raise ValueError('exact independently verified natural waiting metadata required')
        _uint(self.activation_generation, 'activation_generation', 1)
        _sha(self.state_digest, 'state_digest')
        for name in ('authority_namespace', 'authority_id', 'installation_id', 'read_operation_id'):
            _text(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class D13NaturalParentClosureOriginalV4:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    activation_generation: int
    candidate: D13NaturalParentClosureCandidateV4
    arm: str
    registration: D13OwnerRegistrationReceiptV3
    generation_registration: D13OwnerRegistrationReceiptV3
    parse_original: D13NaturalGenerationParseReceiptV3 | None
    parent_input: D13NaturalParentInputReceiptV3 | None
    generation_transfer: D13OwnerCloseReceiptV3 | None
    review_verdict: D13NaturalReviewVerdictReceiptV3 | None
    closed_receipt: D13OwnerCloseReceiptV3 | None
    waiting_reason: str | None
    waiting_state_digest: str | None
    permanent_disposition: tuple[str, str] | None
    schema: str = 'sylanne3.d13.natural-parent-closure-original.v4'

    def __post_init__(self):
        candidate, registration, generation = self.candidate, self.registration, self.generation_registration
        if (self.schema != 'sylanne3.d13.natural-parent-closure-original.v4'
                or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(candidate) is not D13NaturalParentClosureCandidateV4
                or type(registration) is not D13OwnerRegistrationReceiptV3
                or type(generation) is not D13OwnerRegistrationReceiptV3
                or registration.owner_ref != candidate.owner_ref
                or registration.registration_digest != candidate.registration_digest
                or generation.owner_kind != 'natural_generation_original'
                or type(generation.original_locator) is not D13NaturalOriginalOwnerLocatorV3
                or generation.original_locator.parent_original_id != candidate.parent_original_id):
            raise ValueError('exact V4 immutable natural owner metadata required')
        values = [registration, generation]
        if self.arm == 'pre_review':
            parse = self.parse_original
            if (candidate.origin_kind != 'generation_parse' or type(parse) is not D13NaturalGenerationParseReceiptV3
                    or registration != generation or self.parent_input is not None
                    or self.generation_transfer is not None or self.review_verdict is not None
                    or parse.parse_outcome not in ('no_reply_hold', 'output_rejected')
                    or (parse.parent_original_id, parse.owner_ref, parse.registration_digest, parse.operation_id, parse.parse_digest) !=
                        (candidate.parent_original_id, candidate.owner_ref, candidate.registration_digest,
                            candidate.origin_operation_id, candidate.origin_digest)
                    or parse.generation_original_id != generation.original_locator.original_id
                    or parse.generation_job_id != generation.original_locator.job_id):
                raise ValueError('V4 pre-review arm needs its exact actual parse/registration')
            values.append(parse)
        elif self.arm == 'review_parent':
            capsule, transfer, verdict = self.parent_input, self.generation_transfer, self.review_verdict
            if (candidate.origin_kind != 'parent_input' or self.parse_original is not None
                    or type(capsule) is not D13NaturalParentInputReceiptV3
                    or type(transfer) is not D13OwnerCloseReceiptV3
                    or registration.owner_kind != 'natural_review_original'
                    or type(registration.original_locator) is not D13NaturalOriginalOwnerLocatorV3
                    or registration.original_locator.parent_original_id != candidate.parent_original_id
                    or (capsule.parent_original_id, capsule.owner_ref, capsule.registration_digest, capsule.operation_id, capsule.input_digest) !=
                        (candidate.parent_original_id, candidate.owner_ref, candidate.registration_digest,
                            candidate.origin_operation_id, candidate.origin_digest)
                    or capsule.generation_original_id != generation.original_locator.original_id
                    or capsule.review_original_id != registration.original_locator.original_id
                    or (transfer.owner_ref, transfer.registration_digest, transfer.disposition_kind,
                        transfer.disposition_ref, transfer.disposition_digest) !=
                        (generation.owner_ref, generation.registration_digest, 'transferred',
                            registration.operation_id, registration.registration_digest)):
                raise ValueError('V4 review-parent arm needs its actual capsule/generation transfer')
            values.extend((capsule, transfer))
            if verdict is not None:
                if (type(verdict) is not D13NaturalReviewVerdictReceiptV3
                        or (verdict.parent_original_id, verdict.owner_ref, verdict.registration_digest,
                            verdict.generation_original_id, verdict.review_original_id) !=
                            (candidate.parent_original_id, candidate.owner_ref, candidate.registration_digest,
                                capsule.generation_original_id, capsule.review_original_id)
                        or (verdict.generation_original_digest, verdict.review_original_digest) !=
                            (capsule.generation_original_digest, capsule.review_original_digest)):
                    raise ValueError('V4 verdict differs from its actual capsule/registration')
                values.append(verdict)
        else:
            raise ValueError('closed V4 natural metadata arm required')
        if self.closed_receipt is not None:
            if (type(self.closed_receipt) is not D13OwnerCloseReceiptV3
                    or self.closed_receipt.owner_ref != candidate.owner_ref
                    or self.closed_receipt.registration_digest != candidate.registration_digest
                    or self.closed_receipt.disposition_kind == 'transferred'):
                raise ValueError('V4 already-closed ACK must actually close this final owner')
            values.append(self.closed_receipt)
        if ((self.waiting_reason is None) != (self.waiting_state_digest is None)
                or self.waiting_reason is not None and (self.waiting_reason not in _NATURAL_PARENT_CORE_WAITING_V4
                    or self.closed_receipt is not None)):
            raise ValueError('V4 actual Core waiting metadata cannot replace a close ACK')
        if self.waiting_state_digest is not None:
            _sha(self.waiting_state_digest, 'waiting_state_digest')
        if self.permanent_disposition is not None:
            if type(self.permanent_disposition) is not tuple or len(self.permanent_disposition) != 2:
                raise ValueError('V4 permanent cause must name its actual original/digest')
            _text(self.permanent_disposition[0], 'permanent_disposition_ref')
            _sha(self.permanent_disposition[1], 'permanent_disposition_digest')
        for value in values:
            if (value.namespace != self.namespace or value.authority_namespace != self.authority_namespace
                    or value.installation_id != self.installation_id):
                raise ValueError('V4 natural originals crossed the actual installation/namespace')
        for name in ('authority_namespace', 'authority_id', 'installation_id'):
            _text(getattr(self, name), name)


def natural_parent_closure_original_from_wire_v4(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(D13NaturalParentClosureOriginalV4)}:
        raise ValueError('closed V4 parent original metadata wire required')
    namespace = raw['namespace']
    if type(namespace) is not dict or set(namespace) != {'bot_id', 'persona_id'}:
        raise ValueError('exact V4 natural parent namespace required')
    values = dict(raw, namespace=NamespaceId(**namespace),
        candidate=natural_parent_closure_candidate_from_wire_v4(raw['candidate']))
    if raw['permanent_disposition'] is not None:
        if type(raw['permanent_disposition']) is not list:
            raise ValueError('exact V4 permanent original reference array required')
        values['permanent_disposition'] = tuple(raw['permanent_disposition'])
    for name in ('registration', 'generation_registration', 'parse_original', 'parent_input',
            'generation_transfer', 'review_verdict', 'closed_receipt'):
        values[name] = None if raw[name] is None else cache_use_result_from_wire_v3(raw[name])
    return D13NaturalParentClosureOriginalV4(**values)
