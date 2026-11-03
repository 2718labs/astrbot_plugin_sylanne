"""Explicit D06 detail retention; values describe state and never grant Source access."""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
import math
from types import UnionType
from typing import get_args, get_origin, get_type_hints, Union

from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ...authority_service.v2_clock import IngressClockSampleV2, CLOCK_SCHEMA
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1

POLICY_TYPE = 'd06.retention_policy.v1'
DETAIL_TYPE = 'd06.detail_retention.v1'
READ_TYPE = 'd06.retention_read.v1'
CONTRIBUTION_TYPE = 'd06.retention_contribution.v1'
OPERATOR_VERSION = 'd06.detail-retention.exponential.v1'
TIME_BASIS = 'd11_utc_seconds_v1'
STABILITY_RULE = 'affine_encoding_weight_v1'


def _text(value, label):
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError('invalid retention ' + label)


def _digest(value, label):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('invalid retention ' + label + ' digest')


def _finite(value, label, *, lower=0.0, upper=None):
    if (type(value) not in (int, float) or not math.isfinite(value) or value < lower
            or upper is not None and value > upper):
        raise ValueError('invalid finite retention ' + label)
    return float(value)


def _positive(value, label):
    if type(value) is not int or value < 1:
        raise ValueError('positive retention ' + label + ' required')


def _version(value, namespace, kinds):
    if (type(value) is not GraphVersion or value.revision < 1
            or NamespaceId.from_key(value.key) != namespace or value.key.type_name not in kinds):
        raise ValueError('retention version has another namespace, type or revision')


def _original(value):
    if type(value) is not ProductionOriginalRefV1:
        raise TypeError('actual typed retention original locator required')


def _tuple(values, expected, label):
    if type(values) is not tuple or any(type(v) is not expected for v in values):
        raise TypeError('retention ' + label + ' requires exact typed tuple')


def retention_payload_v1(value):
    if type(value) is AtomKey:
        return value.token
    if is_dataclass(value):
        return {f.name: retention_payload_v1(getattr(value, f.name)) for f in fields(value)}
    if type(value) in (tuple, list):
        return [retention_payload_v1(v) for v in value]
    if type(value) is dict:
        return {k: retention_payload_v1(v) for k, v in value.items()}
    return value


def retention_payload_digest_v1(value):
    return canonical_digest(retention_payload_v1(value))


@dataclass(frozen=True, slots=True)
class MemoryRetentionPolicyDefinitionV1:
    operator_version: str
    time_basis: str
    stability_rule: str
    initial_r: float
    s_min_seconds: float
    s_max_seconds: float
    eta_retrieved: float
    eta_blurred: float
    archive_below: float
    maintenance_resource_policy_ref: str
    maintenance_resource_policy_version: int
    version: int

    def __post_init__(self):
        if (self.operator_version != OPERATOR_VERSION or self.time_basis != TIME_BASIS
                or self.stability_rule != STABILITY_RULE):
            raise ValueError('unregistered explicit retention operator, clock or stability rule')
        for name in ('initial_r', 'eta_retrieved', 'eta_blurred', 'archive_below'):
            object.__setattr__(self,name,_finite(getattr(self, name), name, upper=1.0))
        lo = _finite(self.s_min_seconds, 'S minimum')
        hi = _finite(self.s_max_seconds, 'S maximum')
        if not 0 < lo <= hi:
            raise ValueError('retention stability bounds must be positive and ordered')
        _text(self.maintenance_resource_policy_ref, 'maintenance policy')
        _positive(self.maintenance_resource_policy_version, 'maintenance policy version')
        object.__setattr__(self,'s_min_seconds',lo)
        object.__setattr__(self,'s_max_seconds',hi)
        _positive(self.version, 'policy version')


@dataclass(frozen=True, slots=True)
class MemoryRetentionPolicyV1:
    namespace: NamespaceId
    policy_ref: str
    policy_revision: int
    definition: MemoryRetentionPolicyDefinitionV1
    issuing_operation_id: str
    issued_at_utc: float
    owner_guard_digest: str
    installation_id: str
    manifest_digest: str
    signature: str
    schema: str = POLICY_TYPE

    def __post_init__(self):
        key = AtomKey.from_token(self.policy_ref)
        if (self.schema != POLICY_TYPE or type(self.namespace) is not NamespaceId
                or NamespaceId.from_key(key) != self.namespace or key.type_name != POLICY_TYPE
                or key.owner.kind != 'persona' or type(self.definition) is not MemoryRetentionPolicyDefinitionV1):
            raise ValueError('retention policy has another installed namespace or closed type')
        _positive(self.policy_revision, 'policy graph revision')
        for name in ('issuing_operation_id', 'installation_id', 'signature'):
            _text(getattr(self, name), name)
        _finite(self.issued_at_utc, 'policy issue time')
        _digest(self.owner_guard_digest, 'Owner guard')
        _digest(self.manifest_digest, 'installation manifest')


@dataclass(frozen=True, slots=True)
class RetentionDetailV1:
    detail_id: str
    quote_sha256: str
    quote_byte_count: int
    source_span: tuple[int, int] | None
    span_status: str
    encoding_weight: float
    r_last: float
    stability_seconds: float
    last_actual_update_utc: float

    def __post_init__(self):
        _digest(self.detail_id, 'detail identity')
        _digest(self.quote_sha256, 'quote')
        _positive(self.quote_byte_count, 'quote byte count')
        if self.span_status not in {'unique_span', 'ambiguous_span'}:
            raise ValueError('retention detail needs an explicit quote span status')
        if self.span_status == 'unique_span':
            if (type(self.source_span) is not tuple or len(self.source_span) != 2
                    or any(type(v) is not int for v in self.source_span)
                    or not 0 <= self.source_span[0] < self.source_span[1]):
                raise ValueError('retention detail needs its exact character span')
        elif self.source_span is not None:
            raise ValueError('ambiguous retention quote must not choose one occurrence')
        _finite(self.encoding_weight, 'encoding weight', upper=1.0)
        _finite(self.r_last, 'retained strength', upper=1.0)
        if _finite(self.stability_seconds, 'stability') <= 0:
            raise ValueError('retention stability must remain positive')
        _finite(self.last_actual_update_utc, 'last actual update')


@dataclass(frozen=True, slots=True)
class DetailRetentionV1:
    namespace: NamespaceId
    source_version: GraphVersion
    trace_version: GraphVersion
    policy_version: GraphVersion
    policy_original_digest: str
    policy_definition_digest: str
    policy_definition: MemoryRetentionPolicyDefinitionV1
    c02_original: ProductionOriginalRefV1
    c02_receipt_digest: str
    encoding_time_utc: float
    details: tuple[RetentionDetailV1, ...]
    tier: str
    last_cause_commit_seq: int
    last_contribution_ref: str | None
    schema: str = DETAIL_TYPE

    def __post_init__(self):
        if self.schema != DETAIL_TYPE or type(self.namespace) is not NamespaceId:
            raise ValueError('retention state namespace/schema differs')
        _version(self.source_version, self.namespace, {'memory.source'})
        _version(self.trace_version, self.namespace, {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'})
        _version(self.policy_version, self.namespace, {POLICY_TYPE})
        if (type(self.policy_definition) is not MemoryRetentionPolicyDefinitionV1
                or retention_payload_digest_v1(self.policy_definition) != self.policy_definition_digest):
            raise ValueError('retention state changed its original policy definition')
        for name in ('policy_original_digest', 'policy_definition_digest', 'c02_receipt_digest'):
            _digest(getattr(self, name), name)
        _original(self.c02_original)
        _finite(self.encoding_time_utc, 'C02 adoption time')
        _tuple(self.details, RetentionDetailV1, 'details')
        if (len(self.details) > 128 or len({v.detail_id for v in self.details}) != len(self.details)
                or self.tier not in {'hot', 'archive', 'protected'}
                or type(self.last_cause_commit_seq) is not int or self.last_cause_commit_seq < 0):
            raise ValueError('retention state exceeds the actual bounded detail/causal domain')
        if any(v.last_actual_update_utc < self.encoding_time_utc for v in self.details):
            raise ValueError('retention actual update precedes the real C02 seed')
        if self.last_contribution_ref is not None:
            key = AtomKey.from_token(self.last_contribution_ref)
            if NamespaceId.from_key(key) != self.namespace or key.type_name != CONTRIBUTION_TYPE:
                raise ValueError('retention contribution cursor crossed namespace/type')


@dataclass(frozen=True, slots=True)
class RetentionReadDetailV1:
    detail_id: str
    source_span: tuple[int, int] | None
    span_status: str
    accessibility: float
    stability_seconds: float
    last_actual_update_utc: float

    def __post_init__(self):
        _digest(self.detail_id, 'read detail')
        _finite(self.accessibility, 'read accessibility', upper=1.0)
        if _finite(self.stability_seconds, 'read stability') <= 0:
            raise ValueError('retention read stability must be positive')
        _finite(self.last_actual_update_utc, 'read last actual update')
        if self.span_status == 'unique_span':
            if (type(self.source_span) is not tuple or len(self.source_span) != 2
                    or any(type(v) is not int for v in self.source_span)
                    or not 0 <= self.source_span[0] < self.source_span[1]):
                raise ValueError('retention read lost its exact Source character span')
        elif self.span_status != 'ambiguous_span' or self.source_span is not None:
            raise ValueError('retention read has an unknown span state')


@dataclass(frozen=True, slots=True)
class RetentionClockObservationV1:
    sample: IngressClockSampleV2
    monotonic_before_seconds: float
    monotonic_after_seconds: float
    utc_upper_bound_seconds: float
    evaluation_monotonic_seconds: float
    evaluation_utc: float
    interface_version: str

    def __post_init__(self):
        if type(self.sample) is not IngressClockSampleV2 or self.interface_version != CLOCK_SCHEMA:
            raise ValueError('retention clock must preserve the complete actual paired sample')
        for name in ('monotonic_before_seconds', 'monotonic_after_seconds', 'utc_upper_bound_seconds',
                'evaluation_monotonic_seconds', 'evaluation_utc'):
            _finite(getattr(self, name), name)
        if not self.monotonic_before_seconds <= self.monotonic_after_seconds <= self.evaluation_monotonic_seconds:
            raise ValueError('retention paired clock interval is inverted')
        expected = math.nextafter(math.fsum((self.utc_upper_bound_seconds,
            self.evaluation_monotonic_seconds - self.monotonic_after_seconds)), math.inf)
        if self.evaluation_utc != expected:
            raise ValueError('retention time differs from the existing paired-clock upper arithmetic')


@dataclass(frozen=True, slots=True)
class MemoryRetentionReadV1:
    namespace: NamespaceId
    activity_id: str
    preparation_operation_id: str
    source_version: GraphVersion
    trace_version: GraphVersion
    state_version: GraphVersion | None
    policy_version: GraphVersion | None
    evaluation_utc: float
    clock_observation: RetentionClockObservationV1
    clock_observation_digest: str
    source_read_versions: tuple[GraphVersion, ...]
    details: tuple[RetentionReadDetailV1, ...]
    status: str
    schema: str = READ_TYPE

    def __post_init__(self):
        if self.schema != READ_TYPE or type(self.namespace) is not NamespaceId:
            raise ValueError('retention read namespace/schema differs')
        for name in ('activity_id', 'preparation_operation_id'):
            _text(getattr(self, name), name)
        _version(self.source_version, self.namespace, {'memory.source'})
        _version(self.trace_version, self.namespace, {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'})
        _finite(self.evaluation_utc, 'read time')
        if (type(self.clock_observation) is not RetentionClockObservationV1
                or self.clock_observation.evaluation_utc != self.evaluation_utc
                or retention_payload_digest_v1(self.clock_observation) != self.clock_observation_digest):
            raise ValueError("retention read changed its actual same-Work clock observation")
        _tuple(self.source_read_versions, GraphVersion, 'Source reads')
        _tuple(self.details, RetentionReadDetailV1, 'read details')
        if (len(self.source_read_versions) > 1024 or len({v.key for v in self.source_read_versions}) != len(self.source_read_versions)
                or len(self.details) > 128 or len({v.detail_id for v in self.details}) != len(self.details)):
            raise ValueError('retention read exceeds its original Work bounds')
        if self.status == 'initialized':
            _version(self.state_version, self.namespace, {DETAIL_TYPE})
            _version(self.policy_version, self.namespace, {POLICY_TYPE})
        elif (self.status != 'uninitialized' or self.state_version is not None
                or self.policy_version is not None or self.details):
            raise ValueError('uninitialized retention must not invent an old seed')


@dataclass(frozen=True, slots=True)
class RetentionDetailChangeV1:
    detail_id: str
    actual_state: str
    before_r: float
    after_r: float

    def __post_init__(self):
        _digest(self.detail_id, 'contribution detail')
        if self.actual_state not in {'retrieved', 'blurred'}:
            raise ValueError('only actually retrieved/blurred details can receive a contribution')
        _finite(self.before_r, 'before strength', upper=1.0)
        _finite(self.after_r, 'after strength', upper=1.0)
        if self.after_r < self.before_r:
            raise ValueError('actual retention contribution cannot lower decayed strength')


@dataclass(frozen=True, slots=True)
class MemoryRetentionContributionV1:
    namespace: NamespaceId
    causal_activity_id: str
    source_target: str
    cause_kind: str
    c04_adoption_original: ProductionOriginalRefV1
    recollection_version: GraphVersion
    projection_version: GraphVersion
    retention_read_version: GraphVersion
    previous_state_version: GraphVersion
    resulting_state_version: GraphVersion
    cause_commit_seq: int
    cause_time_utc: float
    changes: tuple[RetentionDetailChangeV1, ...]
    schema: str = CONTRIBUTION_TYPE

    def __post_init__(self):
        if self.schema != CONTRIBUTION_TYPE or self.cause_kind != 'internal_recollection':
            raise ValueError('retention contribution has another causal family')
        _text(self.causal_activity_id, 'causal activity')
        key = AtomKey.from_token(self.source_target)
        if key.type_name != 'memory.source' or NamespaceId.from_key(key) != self.namespace:
            raise ValueError('retention contribution targets another Source namespace')
        _original(self.c04_adoption_original)
        _version(self.recollection_version, self.namespace, {'d06.recollection.v1'})
        _version(self.projection_version, self.namespace, {'d06.recollection_projection.v1'})
        _version(self.retention_read_version, self.namespace, {READ_TYPE})
        _version(self.previous_state_version, self.namespace, {DETAIL_TYPE})
        _version(self.resulting_state_version, self.namespace, {DETAIL_TYPE})
        if (self.resulting_state_version.key != self.previous_state_version.key
                or self.resulting_state_version.revision != self.previous_state_version.revision + 1):
            raise ValueError('retention contribution must bind its actual state CAS')
        _positive(self.cause_commit_seq, 'actual cause sequence')
        _finite(self.cause_time_utc, 'actual cause time')
        _tuple(self.changes, RetentionDetailChangeV1, 'contribution changes')
        if len(self.changes) > 128 or len({v.detail_id for v in self.changes}) != len(self.changes):
            raise ValueError('retention contribution repeats a detail')


def retention_detail_id_v1(namespace, source_version, trace_version, exact_quote):
    _version(source_version, namespace, {'memory.source'})
    _version(trace_version, namespace, {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'})
    _text(exact_quote, 'exact quote')
    return canonical_digest((namespace, source_version, trace_version, exact_quote))


def detail_retention_key_v1(namespace, source_version, trace_version):
    marker = canonical_digest((namespace, source_version, trace_version))[:48]
    return AtomKey(Owner('event', *namespace.as_tuple, source_version.key.owner.subject), DETAIL_TYPE, marker)


def retention_read_key_v1(namespace, activity_id, preparation_operation_id, source_ref):
    return AtomKey(Owner('activity', *namespace.as_tuple, activity_id), READ_TYPE,
        canonical_digest((preparation_operation_id, source_ref))[:48])


def retention_contribution_key_v1(namespace, causal_activity_id, source_target):
    # Deliberately independent of attempt and policy revision.
    return AtomKey(Owner('activity', *namespace.as_tuple, causal_activity_id), CONTRIBUTION_TYPE,
        canonical_digest((source_target, 'internal_recollection'))[:48])


def retention_strength_v1(detail, evaluation_utc):
    if type(detail) is not RetentionDetailV1:
        raise TypeError('actual typed detail state required for decay')
    now = _finite(evaluation_utc, 'evaluation time')
    if now < detail.last_actual_update_utc:
        raise ValueError('retention cause order must be reconciled before an earlier time')
    return detail.r_last * math.exp(-(now - detail.last_actual_update_utc) / detail.stability_seconds)


def seed_retention_details_v1(namespace, source_version, trace_version, source_text, quoted_details, definition, encoding_utc):
    import hashlib
    if type(source_text) is not str or type(definition) is not MemoryRetentionPolicyDefinitionV1:
        raise TypeError('retention seed requires the actual Source text and explicit policy')
    if type(quoted_details) is not tuple or len(quoted_details) > 128:
        raise ValueError('retention C02 quotes exceed the actual bounded seed')
    result = []
    for quote, weight in quoted_details:
        _text(quote, 'C02 quote')
        _finite(weight, 'C02 encoding weight', upper=1.0)
        first = source_text.find(quote)
        if first < 0:
            raise ValueError('retention seed quote is not literal actual Source text')
        ambiguous = source_text.find(quote, first + 1) >= 0
        encoded = quote.encode('utf-8')
        result.append(RetentionDetailV1(retention_detail_id_v1(namespace, source_version, trace_version, quote),
            hashlib.sha256(encoded).hexdigest(), len(encoded), None if ambiguous else (first, first + len(quote)),
            'ambiguous_span' if ambiguous else 'unique_span', weight, definition.initial_r,
            definition.s_min_seconds + weight * (definition.s_max_seconds - definition.s_min_seconds), encoding_utc))
    if len({v.detail_id for v in result}) != len(result):
        raise ValueError('actual C02 quote list repeats a detail')
    return tuple(result)


def retention_read_details_v1(state, evaluation_utc):
    if type(state) is not DetailRetentionV1:
        raise TypeError('typed current retention state required')
    return tuple(RetentionReadDetailV1(v.detail_id, v.source_span, v.span_status,
        retention_strength_v1(v, evaluation_utc), v.stability_seconds, v.last_actual_update_utc) for v in state.details)


def detail_cues_from_retention_read_v1(value):
    from ...memory_reconstruction import DetailCue
    if type(value) is not MemoryRetentionReadV1:
        raise TypeError('frozen typed retention read required')
    return tuple(DetailCue(v.detail_id, v.source_span, v.accessibility)
        for v in value.details if v.span_status == 'unique_span')


def contribute_retention_details_v1(state, *, cause_time_utc, actual_detail_states):
    if type(state) is not DetailRetentionV1 or type(actual_detail_states) is not tuple:
        raise TypeError('retention contribution requires actual state and adopted detail states')
    cause_time_utc = _finite(cause_time_utc, 'actual adoption time')
    if any(cause_time_utc < detail.last_actual_update_utc for detail in state.details):
        raise ValueError('retention actual cause time precedes a committed detail update')
    selected = dict(actual_detail_states)
    if (len(selected) != len(actual_detail_states) or not set(selected) <= {v.detail_id for v in state.details}
            or any(v not in {'retrieved', 'blurred', 'inferred', 'unavailable', 'uncertain'} for v in selected.values())):
        raise ValueError('actual adopted retention detail identity/state differs')
    details, changes = [], []
    for detail in state.details:
        actual = selected.get(detail.detail_id)
        if actual not in {'retrieved', 'blurred'} or detail.span_status != 'unique_span':
            details.append(detail)
            continue
        before = retention_strength_v1(detail, cause_time_utc)
        eta = state.policy_definition.eta_retrieved if actual == 'retrieved' else state.policy_definition.eta_blurred
        after = before + eta * (1.0 - before)
        details.append(replace(detail, r_last=after, last_actual_update_utc=cause_time_utc))
        changes.append(RetentionDetailChangeV1(detail.detail_id, actual, before, after))
    return tuple(details), tuple(changes)


def retention_candidate_tier_v1(state, *, evaluation_utc, protection_reasons):
    if type(protection_reasons) is not tuple or any(type(v) is not str or not v for v in protection_reasons):
        raise TypeError('explicit complete protection reasons required')
    if protection_reasons:
        return 'protected'
    return 'hot' if any(retention_strength_v1(v, evaluation_utc) >= state.policy_definition.archive_below
        for v in state.details) else 'archive'


def decode_retention_value_v1(value, expected):
    origin, args = get_origin(expected), get_args(expected)
    if origin in (Union, UnionType):
        if value is None and type(None) in args:
            return None
        choices = [t for t in args if t is not type(None)]
        if len(choices) != 1:
            raise TypeError('unregistered retention wire union')
        return decode_retention_value_v1(value, choices[0])
    if origin is tuple:
        if type(value) not in (list, tuple):
            raise TypeError('retention wire tuple required')
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(decode_retention_value_v1(v, args[0]) for v in value)
        if len(value) != len(args):
            raise ValueError('retention wire tuple length differs')
        return tuple(decode_retention_value_v1(v, t) for v, t in zip(value, args, strict=True))
    if expected is AtomKey:
        return AtomKey.from_token(value)
    if is_dataclass(expected):
        if type(value) is not dict or set(value) != {f.name for f in fields(expected)}:
            raise ValueError('retention wire closed fields differ for ' + expected.__name__)
        hints = get_type_hints(expected)
        return expected(**{f.name: decode_retention_value_v1(value[f.name], hints[f.name]) for f in fields(expected)})
    if expected is float:
        return _finite(value, 'wire number')
    if expected is type(None):
        if value is not None:
            raise TypeError('retention null required')
        return None
    if expected in (str, int, bool):
        if type(value) is not expected:
            raise TypeError('retention exact wire scalar required')
        return value
    raise TypeError('unregistered retention wire value')


_TYPES = {POLICY_TYPE: MemoryRetentionPolicyV1, DETAIL_TYPE: DetailRetentionV1,
    READ_TYPE: MemoryRetentionReadV1, CONTRIBUTION_TYPE: MemoryRetentionContributionV1}


def retention_type_specs_v1():
    result = []
    for name, cls in _TYPES.items():
        def validate(value, expected=cls):
            decode_retention_value_v1(value, expected)
        result.append(TypeSpec(name, ('persona',) if name == POLICY_TYPE else ('event',) if name == DETAIL_TYPE else ('activity',),
            'state' if name in {POLICY_TYPE, DETAIL_TYPE} else 'source', validate,
            immutable=name in {READ_TYPE, CONTRIBUTION_TYPE}, writer_domain='d06',
            schema_hash=canonical_digest((name,OPERATOR_VERSION,TIME_BASIS,STABILITY_RULE,
                tuple((t.__name__,tuple((f.name,str(f.type)) for f in fields(t))) for t in (
                    cls,MemoryRetentionPolicyDefinitionV1,RetentionDetailV1,RetentionReadDetailV1,
                    RetentionClockObservationV1,IngressClockSampleV2,ProductionOriginalRefV1,NamespaceId,GraphVersion))))))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class RetentionProtectionMemberV1:
    provider: str
    subject_version: GraphVersion
    value_digest: str
    support_source_refs: tuple[str, ...]

    def __post_init__(self):
        _text(self.provider, 'protection provider')
        if type(self.subject_version) is not GraphVersion or self.subject_version.revision < 1:
            raise ValueError('actual positive protection subject version required')
        _digest(self.value_digest, 'protection metadata value')
        if type(self.support_source_refs) is not tuple or len(set(self.support_source_refs)) != len(self.support_source_refs):
            raise ValueError('protection support roots must be a distinct typed tuple')
        for ref in self.support_source_refs:
            if AtomKey.from_token(ref).type_name != 'memory.source':
                raise ValueError('protection support must identify an actual Source')


@dataclass(frozen=True, slots=True)
class RetentionProtectionSnapshotV1:
    namespace: NamespaceId
    source_ref: str
    census_digest: str
    census_count: int
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int
    control_query_epochs: tuple[QueryEpoch, ...]
    members: tuple[RetentionProtectionMemberV1, ...]
    control_originals: tuple[ProductionOriginalRefV1, ...]
    control_coverage_digest: str
    reasons: tuple[str, ...]

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or NamespaceId.from_key(AtomKey.from_token(self.source_ref)) != self.namespace:
            raise ValueError('protection snapshot namespace must be exact')
        for value in (self.census_digest, self.control_coverage_digest):
            _digest(value, 'complete protection coverage')
        if type(self.census_count) is not int or not 0 <= self.census_count <= 1024 or type(self.graph_epoch) is not int or self.graph_epoch < 0:
            raise ValueError('protection coverage must stay within the actual current inventory')
        if type(self.read_versions) is not tuple or len(self.read_versions) > 1024:
            raise ValueError('protection CAS must retain its actual bounded head set')
        for version in self.read_versions:
            if type(version) is not GraphVersion or version.revision < 0 or NamespaceId.from_key(version.key) != self.namespace:
                raise ValueError('protection CAS member must have its actual namespace/revision')
        if type(self.control_query_epochs) is not tuple or any(type(e) is not QueryEpoch for e in self.control_query_epochs):
            raise ValueError('actual Control protection query epochs required')
        if type(self.members) is not tuple or any(type(m) is not RetentionProtectionMemberV1 for m in self.members):
            raise ValueError('typed protection members required')
        if type(self.reasons) is not tuple or len(set(self.reasons)) != len(self.reasons):
            raise ValueError('protection reasons must preserve their unique actual providers')



def decode_retention_graph_row_v1(key, revision, value):
    if type(key) is not AtomKey or key.type_name not in _TYPES or type(revision) is not int or revision<1:
        raise ValueError('exact registered positive retention Graph row required')
    result=decode_retention_value_v1(value,_TYPES[key.type_name])
    if NamespaceId.from_key(key)!=result.namespace:
        raise ValueError('retention Graph row crossed its payload namespace')
    if key.type_name==POLICY_TYPE:
        expected=AtomKey.from_token(result.policy_ref)
        if result.policy_revision!=revision:raise ValueError('retention signed policy Graph revision differs')
    elif key.type_name==DETAIL_TYPE:
        expected=detail_retention_key_v1(result.namespace,result.source_version,result.trace_version)
    elif key.type_name==READ_TYPE:
        expected=retention_read_key_v1(result.namespace,result.activity_id,result.preparation_operation_id,result.source_version.key.token)
        if revision!=1:raise ValueError('immutable retention read has another revision')
    else:
        expected=retention_contribution_key_v1(result.namespace,result.causal_activity_id,result.source_target)
        if revision!=1:raise ValueError('immutable retention contribution has another revision')
    if key!=expected:raise ValueError('retention Graph row has another canonical address')
    return result
