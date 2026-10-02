"""Interval-preserving Life trace with separately invalidatable current use.

This trace is a deterministic projection of an independently adopted numerical
baseline. Its MeaningFacets remain subjective interpretations; no model scalar
or content-only once identity is reused. Snapshot-only access cannot qualify it.
"""
from dataclasses import dataclass
import json
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d04.affect import _decode_appraisal
from ..domains.d04.interval_projection_v2 import D04AxisProjectionIntervalV2
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..graph_types import AtomKey, GraphVersion, GraphWrite, TypeSpec
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1
from .d06_internal_life_episode_v2 import EpisodeReadV2, _sha
from .d04_life_encoding_baseline_v1 import (PrepareLifeEncodingBaselineRequestV1,
    D04LifeEncodingBaselineV1, read_plan_life_encoding_baseline_v1,
    read_current_life_encoding_baseline_v1, require_current_life_encoding_baseline_v1,
    life_encoding_baseline_ids_v1, _interval, OPERATION as BASELINE_OPERATION)

OPERATION = 'adopt_internal_life_numeric_trace'
TRACE = 'memory.internal_life_numeric_trace.v1'
PROVENANCE = 'memory.internal_life_numeric_provenance.v1'
ELIGIBILITY = 'memory.internal_life_numeric_eligibility.v1'
KINDS = (TRACE, PROVENANCE, ELIGIBILITY)
SIGNED_KIND = 'numeric_trace_v1'
PROPOSAL_SCHEMA = 'd06.internal-life-numeric-trace.proposal.v1'
PROPOSAL_HASH = schema_hash({'schema': PROPOSAL_SCHEMA, 'types': KINDS,
    'issuer': 'installed_private_w01_numeric_baseline_witness', 'numeric_representation': 'outward_intervals',
    'causal_effect': 'not_identified'})
CURRENT_TYPES = frozenset({'memory.source', 'memory.access', 'd06.source_correction_head.v1',
    'd01.persona_activation.v1', 'd01.persona_plan.v1', 'd03.self_identity_mapping.v1', 'd03.self_perspective.v1',
    'd03.world_event', 'd07.current_interpretation.v1', 'd07.belief_revision.v1', 'd04.appraisal_bundle.v1',
    'memory.episode.v2', 'memory.episode_provenance.v2', 'memory.episode_eligibility.v2',
    'd06.internal_life_event.v1'})
_STAGES = {}
_CURRENT = {}


@dataclass(frozen=True, slots=True)
class AdoptLifeNumericTraceRequestV1:
    episode_ref: str
    causal_operation_id: str
    joint_operation_id: str

    def __post_init__(self):
        PrepareLifeEncodingBaselineRequestV1(self.episode_ref, self.causal_operation_id, self.joint_operation_id)


def life_numeric_trace_keys_v1(namespace, episode_ref, joint_operation_id):
    episode = AtomKey.from_token(episode_ref)
    if episode.type_name != 'memory.episode.v2' or NamespaceId.from_key(episode) != namespace:
        raise ValueError('Life numeric trace requires exact Episode-v2 namespace')
    name = canonical_digest((TRACE, namespace, episode_ref, joint_operation_id))[:48]
    return tuple(AtomKey(episode.owner, kind, name) for kind in KINDS)


def life_numeric_trace_operation_v1(namespace, episode_ref, joint_operation_id):
    return 'life-numeric-trace:' + life_numeric_trace_keys_v1(namespace, episode_ref, joint_operation_id)[0].name


@dataclass(frozen=True, slots=True)
class InternalLifeNumericTraceV1:
    namespace: NamespaceId
    trace_ref: str
    episode_ref: str
    occurrence_digest: str
    producing_operation_id: str
    baseline: D04LifeEncodingBaselineV1
    then_feeling_versions: tuple[tuple[str, int], ...]
    interpretation_versions: tuple[tuple[str, int], ...]
    meaning_facets: tuple[tuple[str, str, str], ...]
    axis_intervals: tuple[D04AxisProjectionIntervalV2, ...]
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    numeric_error_digest: str
    schema: str = TRACE
    completion: str = 'authenticated_numeric_interval_trace'
    assertion_scope: str = 'subjective_state_interpretation_temporal_association'
    causal_effect: str = 'not_identified'
    semantic_calibration: str = 'unvalidated'

    def __post_init__(self):
        if (self.schema != TRACE or type(self.baseline) is not D04LifeEncodingBaselineV1
                or self.baseline.namespace != self.namespace or self.baseline.episode_ref != self.episode_ref
                or self.baseline.occurrence_digest != self.occurrence_digest
                or self.trace_ref != life_numeric_trace_keys_v1(self.namespace, self.episode_ref, self.baseline.joint_operation_id)[0].token
                or self.producing_operation_id != life_numeric_trace_operation_v1(self.namespace, self.episode_ref, self.baseline.joint_operation_id)
                or self.completion != 'authenticated_numeric_interval_trace'
                or self.assertion_scope != 'subjective_state_interpretation_temporal_association'
                or self.causal_effect != 'not_identified' or self.semantic_calibration != 'unvalidated'):
            raise ValueError('Life numeric trace cannot promote intervals or interpretation to identified affect')
        _sha(self.occurrence_digest); _sha(self.numeric_error_digest)
        _interval(self.salience_interval, 0.0, 1.0); _interval(self.tone_interval, -1.0, 1.0)
        if (self.salience_interval != self.baseline.salience_interval or self.tone_interval != self.baseline.tone_interval
                or self.numeric_error_digest != self.baseline.numeric_error_digest):
            raise ValueError('Life trace cannot replace its certified interval endpoints or error')
        for values, kinds in ((self.then_feeling_versions, {'d04.authored_feeling_state.v1'}),
                              (self.interpretation_versions, {'d07.current_interpretation.v1', 'd07.belief_revision.v1'})):
            if type(values) is not tuple or not 1 <= len(values) <= 128 or len({r for r, _ in values}) != len(values):
                raise ValueError('Life trace exact numerical/context versions are incomplete')
            for ref, revision in values:
                key = AtomKey.from_token(ref)
                if key.type_name not in kinds or NamespaceId.from_key(key) != self.namespace or type(revision) is not int or revision < 1:
                    raise ValueError('Life trace version type/namespace differs')
        if (type(self.axis_intervals) is not tuple or len(self.axis_intervals) != 24 * len(self.then_feeling_versions)
                or any(type(axis) is not D04AxisProjectionIntervalV2 for axis in self.axis_intervals)):
            raise ValueError('Life trace must preserve all original member/axis intervals')
        for offset in range(0, len(self.axis_intervals), 24):
            axes = self.axis_intervals[offset:offset + 24]
            if tuple(axis.axis_id for axis in axes) != REGISTERED_AXIS_IDS or len({axis.checkpoint_ref for axis in axes}) != 1:
                raise ValueError('Life trace numerical axis order/member changed')
            for axis in axes:
                _interval((axis.lower, axis.upper), -1.0, 1.0)
        if (type(self.meaning_facets) is not tuple or not 1 <= len(self.meaning_facets) <= 128
                or len({(r, f) for r, f, _ in self.meaning_facets}) != len(self.meaning_facets)):
            raise ValueError('Life trace bounded MeaningFacet references differ')
        for ref, facet, digest in self.meaning_facets:
            if AtomKey.from_token(ref).type_name != 'd04.appraisal_bundle.v1' or not facet:
                raise ValueError('Life trace MeaningFacet must retain its actual appraisal')
            _sha(digest)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class InternalLifeNumericProvenanceV1:
    trace: InternalLifeNumericTraceV1
    owner_head_digest: str
    historical_reads: tuple[EpisodeReadV2, ...]
    current_reads: tuple[EpisodeReadV2, ...]
    schema: str = PROVENANCE

    def __post_init__(self):
        if self.schema != PROVENANCE or type(self.trace) is not InternalLifeNumericTraceV1:
            raise ValueError('Life numeric provenance schema differs')
        _sha(self.owner_head_digest)
        for rows in (self.historical_reads, self.current_reads):
            if (type(rows) is not tuple or not 1 <= len(rows) <= 1024 or any(type(r) is not EpisodeReadV2 for r in rows)
                    or tuple(r.ref for r in rows) != tuple(sorted({r.ref for r in rows}))):
                raise ValueError('Life numeric provenance requires complete bounded original rows')
        from ..graph_types import OWNER_GRANT_TYPE
        expected = tuple(row for row in self.historical_reads if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES | {OWNER_GRANT_TYPE})
        if self.current_reads != expected:
            raise ValueError('Life numeric current projection is not its complete original current-read closure')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class InternalLifeNumericEligibilityV1:
    trace_ref: str
    provenance_ref: str
    provenance_digest: str
    producing_operation_id: str
    schema: str = ELIGIBILITY

    def __post_init__(self):
        _sha(self.provenance_digest)
        trace = AtomKey.from_token(self.trace_ref); provenance = AtomKey.from_token(self.provenance_ref)
        if (self.schema != ELIGIBILITY or trace.type_name != TRACE or provenance.type_name != PROVENANCE
                or trace.owner != provenance.owner or trace.name != provenance.name):
            raise ValueError('Life trace eligibility must reference its exact immutable fact')


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericTraceStageV1:
    frame: object
    request: AdoptLifeNumericTraceRequestV1
    baseline: object
    environment: object
    provenance: InternalLifeNumericProvenanceV1
    primary_stage: object


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CurrentLifeNumericTraceV1:
    trace: InternalLifeNumericTraceV1
    provenance: InternalLifeNumericProvenanceV1
    baseline: object


def decode_life_numeric_trace_value_v1(kind, raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    types = {TRACE: InternalLifeNumericTraceV1, PROVENANCE: InternalLifeNumericProvenanceV1,
             ELIGIBILITY: InternalLifeNumericEligibilityV1}
    if kind not in types: raise ValueError('unregistered Life numeric trace type')
    value = decode_typed_production_value_v1(raw, types[kind])
    if plain_v1(value) != raw: raise ValueError('Life numeric trace wire differs')
    return value


def life_numeric_trace_type_specs_v1():
    return tuple(TypeSpec(kind, ('event',), 'state' if kind == ELIGIBILITY else 'source',
        lambda raw, kind=kind: decode_life_numeric_trace_value_v1(kind, raw), immutable=kind != ELIGIBILITY,
        writer_domain='d06', schema_hash=schema_hash({'type': kind, 'proposal': PROPOSAL_HASH})) for kind in KINDS)


def read_plan_life_numeric_trace_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not AdoptLifeNumericTraceRequestV1 or operation_kind != OPERATION:
        raise TypeError('exact Life numerical trace locator required')
    base = read_plan_life_encoding_baseline_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind=BASELINE_OPERATION, request=PrepareLifeEncodingBaselineRequestV1(
            request.episode_ref, request.causal_operation_id, request.joint_operation_id))
    return production_read_plan_v1(base.fixed_type_ids,
        (*base.exact_keys, *life_numeric_trace_keys_v1(namespace, request.episode_ref, request.joint_operation_id)),
        base.source_roots, base.required_original_refs)


def _trace(db, frame, baseline):
    require_current_life_encoding_baseline_v1(baseline, db=db, frame=frame)
    original, proof = baseline.original, baseline.c04_record.proof
    read = CurrentDomainReadV1(frame)
    facets = []
    for ref, _ in original.appraisal_acceptance_digests:
        appraisal = _decode_appraisal(read.head(db, ref, required=True).value)
        facets.extend((ref, f.facet_id, canonical_digest(plain_v1(f))) for f in appraisal.meaning_facets
            if original.source_ref in f.source_refs)
    return InternalLifeNumericTraceV1(original.namespace,
        life_numeric_trace_keys_v1(original.namespace, original.episode_ref, original.joint_operation_id)[0].token,
        original.episode_ref, original.occurrence_digest,
        life_numeric_trace_operation_v1(original.namespace, original.episode_ref, original.joint_operation_id), original,
        tuple((m.feeling_ref, m.feeling_revision) for m in proof.feeling_bindings),
        tuple((v.ref, v.revision) for v in proof.interpretation_versions), tuple(sorted(facets)),
        proof.projection.normalized_axes, proof.projection.salience_interval, proof.projection.tone_interval,
        canonical_digest(plain_v1(proof.numeric_error)))


def _provenance(frame, trace):
    from ..graph_types import OWNER_GRANT_TYPE
    rows = tuple(EpisodeReadV2(atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in sorted(frame.snapshot.atoms, key=lambda atom: atom.key.token))
    current = tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES | {OWNER_GRANT_TYPE})
    return InternalLifeNumericProvenanceV1(trace, frame.owner_guard.owner_head_digest, rows, current)


def _writes(provenance):
    trace = provenance.trace
    keys = life_numeric_trace_keys_v1(trace.namespace, trace.episode_ref, trace.baseline.joint_operation_id)
    eligibility = InternalLifeNumericEligibilityV1(keys[0].token, keys[1].token, provenance.digest, trace.producing_operation_id)
    dependencies = tuple(dict.fromkeys((*keys[:2], *(AtomKey.from_token(r.ref) for r in provenance.current_reads))))
    return (GraphWrite(keys[0], plain_v1(trace), ()), GraphWrite(keys[1], plain_v1(provenance), ()),
        GraphWrite(keys[2], plain_v1(eligibility), dependencies))


def validate_life_numeric_trace_proposal_v1(proposal, snapshot):
    if (proposal.domain != 'd06' or proposal.proposal_schema != PROPOSAL_SCHEMA
            or proposal.proposal_schema_hash != PROPOSAL_HASH or proposal.envelope.identity.phase != OPERATION
            or len(proposal.typed_writes) != 3):
        raise ValueError('Life numeric trace needs its dedicated exact proposal')
    provenance = decode_life_numeric_trace_value_v1(PROVENANCE, proposal.typed_writes[1].value)
    if proposal.typed_writes != _writes(provenance):
        raise ValueError('Life numeric trace three-member immutable/current write set differs')
    guard = {v.key: v.revision for v in proposal.envelope.version_guard.read_versions}
    for write in proposal.typed_writes:
        atom = snapshot.get(write.key)
        if atom is None or atom.revision != 0 or atom.valid or guard.get(write.key) != 0:
            raise ValueError('Life numerical trace output lacks actual absence read')
    return proposal


def stage_life_numeric_trace_in_transaction_v1(db, *, frame, request, installed_readers, environment):
    if type(request) is not AdoptLifeNumericTraceRequestV1:
        raise TypeError('exact Life numeric trace request required')
    baseline = read_current_life_encoding_baseline_v1(db, frame=frame,
        request=PrepareLifeEncodingBaselineRequestV1(request.episode_ref, request.causal_operation_id, request.joint_operation_id),
        installed_readers=installed_readers, environment=environment)
    trace = _trace(db, frame, baseline)
    if frame.envelope.identity.operation_id != trace.producing_operation_id:
        raise ValueError('Life numeric trace caller operation changed its once identity')
    read = CurrentDomainReadV1(frame)
    provenance = _provenance(frame, trace)
    writes = _writes(provenance)
    for write in writes:
        atom = read.head(db, write.key)
        if atom.revision or atom.valid: raise ValueError('Life numeric trace already exists; use current reader')
    primary = stage_result_v1(frame, 'd06', OPERATION, request, writes=writes,
        provenance={'numeric_trace_provenance': plain_v1(provenance)},
        proposal_schema=PROPOSAL_SCHEMA, proposal_hash=PROPOSAL_HASH)
    for proposal in primary.proposals: validate_life_numeric_trace_proposal_v1(proposal, frame.snapshot)
    stage = LifeNumericTraceStageV1(frame, request, baseline, environment, provenance, primary)
    identity = id(stage)
    _STAGES[identity] = (weakref.ref(stage, lambda _: _STAGES.pop(identity, None)), db)
    return stage


def verify_life_numeric_trace_stage_v1(db, stage, *, installed_readers):
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life numeric trace is not this privately issued SQL stage')
    baseline = read_current_life_encoding_baseline_v1(db, frame=stage.frame,
        request=PrepareLifeEncodingBaselineRequestV1(stage.request.episode_ref, stage.request.causal_operation_id, stage.request.joint_operation_id),
        installed_readers=installed_readers, environment=stage.environment)
    expected = _provenance(stage.frame, _trace(db, stage.frame, baseline))
    if expected != stage.provenance or tuple(w for p in stage.primary_stage.proposals for w in p.typed_writes) != _writes(expected):
        raise ValueError('Life numerical trace was not reissued from its actual current baseline')
    return stage


def record_life_numeric_trace_after_cas_v1(db, *, stage, issuer, receipt):
    from .c04_encoding_baseline_store_v3 import _receipt
    from .d11_life_preparation_v1 import _record
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life trace recording requires its original SQL stage')
    trace = stage.provenance.trace; writes = _writes(stage.provenance)
    actual = _receipt(db, trace.namespace, trace.producing_operation_id)
    if (actual != receipt or actual.read_versions != stage.frame.envelope.version_guard.read_versions
            or set(actual.write_versions) != {GraphVersion(w.key, 1) for w in writes}):
        raise ValueError('Life numeric trace actual three-member W01 receipt differs')
    for write in writes:
        row = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (write.key.token,)).fetchone()
        if row != (canonical_serialize(write.value), 1, trace.producing_operation_id):
            raise ValueError('Life numeric trace original must follow same-transaction actual CAS')
    return _record(db, issuer=issuer, namespace=trace.namespace, kind=SIGNED_KIND, ref=trace.trace_ref,
        operation_id=trace.producing_operation_id, value=stage.provenance)


def read_current_life_numeric_trace_v1(db, *, frame, request, installed_readers, environment):
    from .d11_life_preparation_v1 import _read
    from .c04_encoding_baseline_store_v3 import _receipt
    baseline = read_current_life_encoding_baseline_v1(db, frame=frame,
        request=PrepareLifeEncodingBaselineRequestV1(request.episode_ref, request.causal_operation_id, request.joint_operation_id),
        installed_readers=installed_readers, environment=environment)
    expected_trace = _trace(db, frame, baseline)
    saved = _read(db, issuer=installed_readers.issuer, namespace=expected_trace.namespace, kind=SIGNED_KIND, ref=expected_trace.trace_ref)
    if saved is None: raise ValueError('Life numeric trace signed producer is unavailable; HOLD')
    provenance = decode_life_numeric_trace_value_v1(PROVENANCE, saved[0])
    if (provenance.trace != expected_trace or saved[1] != expected_trace.producing_operation_id
            or provenance.owner_head_digest != frame.owner_guard.owner_head_digest):
        raise ValueError('Life numeric trace current original/Owner differs')
    read = CurrentDomainReadV1(frame); actual = _receipt(db, expected_trace.namespace, expected_trace.producing_operation_id)
    writes = _writes(provenance)
    from .d06_life_numeric_context_v1 import require_life_numeric_shared_original_v1
    payload = require_life_numeric_shared_original_v1(db, namespace=expected_trace.namespace,
        operation_id=expected_trace.producing_operation_id, operation_kind=OPERATION, receipt=actual, writes=writes)
    if payload['provenance'].get('numeric_trace_provenance') != plain_v1(provenance):
        raise ValueError('Life numeric trace shared original differs from its signed provenance')
    for write in writes:
        atom = read.head(db, write.key, required=True)
        history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (write.key.token,)).fetchone()
        if (atom.revision != 1 or atom.value != write.value or GraphVersion(write.key, 1) not in actual.write_versions
                or history != (canonical_serialize(write.value), 1, expected_trace.producing_operation_id)):
            raise ValueError('Life numeric trace fact/provenance/eligibility differs from its original')
    for row in provenance.current_reads:
        atom = read.head(db, row.ref)
        if (atom.revision, canonical_digest(atom.value), atom.valid) != (row.revision, row.digest, row.valid):
            raise ValueError('Life numeric trace current Source/Owner/context changed')
    expected_dependencies = tuple(sorted((key.token, 1 if key in {w.key for w in writes} else next(
        row.revision for row in provenance.current_reads if row.ref == key.token)) for key in writes[-1].dependencies))
    actual_dependencies = tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies '
        'WHERE dependent_token=? ORDER BY dependency_token', (writes[-1].key.token,)))
    if actual_dependencies != expected_dependencies:
        raise ValueError('Life numeric trace actual invalidation edges differ')
    for row in provenance.historical_reads:
        if row.revision == 0: continue
        history = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?', (row.ref, row.revision)).fetchone()
        if history is None or canonical_digest(json.loads(history[0])) != row.digest or bool(history[1]) != row.valid:
            raise ValueError('Life numeric trace original read history changed')
    result = CurrentLifeNumericTraceV1(expected_trace, provenance, baseline)
    identity = id(result)
    _CURRENT[identity] = (weakref.ref(result, lambda _: _CURRENT.pop(identity, None)), db, frame)
    return result


def require_current_life_numeric_trace_v1(value, *, db, frame):
    issued = _CURRENT.get(id(value))
    if issued is None or issued[0]() is not value or issued[1] is not db or issued[2] is not frame or not db.in_transaction:
        raise ValueError('Life numeric trace requires its actual installed current consumer; HOLD')
    require_current_life_encoding_baseline_v1(value.baseline, db=db, frame=frame)
    return value.trace


def require_installed_life_numeric_trace_reader_v1():
    raise ValueError('snapshot-only Life numerical trace use has no current Owner/Source qualification; HOLD')


class InstalledInternalLifeNumericReaderV1:
    """Current numerical use under the real readonly Owner/Authority fence.

    This follows the installed content-reader contract. It emits no Graph
    event, domain original or new persistent carrier. Qualified return values
    describe the current read; retaining a DTO does not retain authorization.
    """
    def __init__(self, *, graph, installed_readers):
        from ..graph_coordinator import GraphCoordinator
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        if (type(graph) is not GraphCoordinator or type(installed_readers) is not InstalledD06StructuredExperienceReadersV1
                or installed_readers.resource_issuer is not installed_readers.issuer.resource_issuer
                or installed_readers.issuer is not graph._GraphCoordinator__d11_issuer
                or installed_readers.resource_issuer is not graph._GraphCoordinator__d02_issuer
                or installed_readers.body_quote_authority is not graph._GraphCoordinator__body_quote_authority):
            raise ValueError('Life numeric reader needs its actual installed Graph and readers')
        self._graph, self._readers = graph, installed_readers

    def read(self, *, authority, lease, request, activity_id):
        from dataclasses import replace
        from ..graph_coordinator import OwnerLeaseBindingV1
        from .domain_production_frame_v1 import freeze_domain_production_frame_v1
        from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1, read_current_domain_policy_refs_v1
        from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3
        from .d04_installed_numeric_v3 import _ready_from_original_v3
        from .installed_c04_encoding_context_v3 import observe_installed_c04_encoding_environment_v3
        graph, store = self._graph, self._graph._GraphCoordinator__store
        graph._authorize(lease, authority, frozenset({'d06'}), owner_read=True)
        owner = graph._GraphCoordinator__owner_leases.get(lease)
        session = graph._GraphCoordinator__owner_session_proofs.get(lease)
        if (type(owner) is not OwnerLeaseBindingV1 or session is None
                or type(request) is not AdoptLifeNumericTraceRequestV1
                or authority.purpose != 'consolidation' or len(authority.audience) != 1
                or authority.audience[0] == '*' or type(activity_id) is not str or not activity_id):
            raise ValueError('Life current numeric use requires its actual Owner/session and consolidation scope')
        if NamespaceId.from_key(AtomKey.from_token(request.episode_ref)) != authority.namespace:
            raise ValueError('Life current numeric locator crosses namespace')
        context = {}
        def observe(scope):
            guard, current = graph._owner_binding_in_fence(authority, scope, owner.principal, owner, session)
            env = observe_installed_c04_encoding_environment_v3(graph, graph._GraphCoordinator__bootstrap, authority.namespace)
            context.update(scope=scope, owner=current, environment=env)
            return guard, scope.permit
        def current_read():
            db = store._db
            db.execute('BEGIN')
            try:
                prepared = read_d04_numeric_prepared_v3(db, authority.namespace, request.joint_operation_id)
                if prepared is None: raise ValueError('Life current numeric use lacks its actual prepared CPU original')
                continuation = json.loads(prepared.job_payload_json)['continuation']
                if (continuation.get('schema') != 'd04.internal-life-numeric-continuation.v1'
                        or continuation.get('episode_ref') != request.episode_ref
                        or continuation.get('causal_operation_id') != request.causal_operation_id):
                    raise ValueError('Life current numeric request differs from its actual CPU lineage')
                ready = _ready_from_original_v3(prepared)
                plan = read_plan_life_numeric_trace_v1(db, namespace=authority.namespace, activity_id=activity_id,
                    operation_kind=OPERATION, request=request)
                policies = read_current_domain_policy_refs_v1(db, namespace=authority.namespace,
                    plan=plan, installed_readers=self._readers)
                originals = read_current_domain_original_refs_v1(db, namespace=authority.namespace,
                    plan=plan, installed_readers=self._readers)
                # The historical envelope supplies the actual source/recipe
                # metadata only. Current Authority and the whole read guard
                # are reissued from this actual readonly fence and SQL frame.
                envelope = replace(ready.preparation.envelope, authority=authority,
                    identity=replace(ready.preparation.envelope.identity, activity_id=activity_id))
                frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope,
                    current_owner=context['owner'], scope=context['scope'], plan=plan,
                    now_utc=context['environment'].as_known_at, observed_originals=originals,
                    installed_policy_refs=policies)
                value = read_current_life_numeric_trace_v1(db, frame=frame, request=request,
                    installed_readers=self._readers, environment=context['environment'])
                return require_current_life_numeric_trace_v1(value, db=db, frame=frame)
            finally:
                db.rollback()
        return graph._read_v2(authority, current_read, fence_observer=observe)
