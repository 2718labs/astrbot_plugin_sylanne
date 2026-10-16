"""Real Life occurrence context for a distinct paid numerical appraisal.

D03 records the authenticated execution interval; D07 suspends interpretation.
The model may suggest MeaningFacets. Neither those suggestions nor this context
identify an activity-caused affect. Only the installed W01 witness may adopt the
separate D03/D07 proposals, with the signed original in that same transaction.
"""
from dataclasses import dataclass
import json
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.context import WorldEvent
from ..domains.d03.self_perspective import SelfPerspective
from ..domains.d07 import CurrentInterpretationCandidate, Stance, EvidenceStatus
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord
from ..runtime_contracts import DependencySet, DomainProposal, NamespaceId, SourceQualification, canonical_digest, canonical_serialize, schema_hash
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1
from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
from .d06_internal_life_episode_v2 import internal_life_episode_read_inputs_v2, PROVENANCE, decode_internal_life_value_v2
from .d04_life_before_original_v1 import (_read_current_life_d04_before_and_cause_v1, require_current_life_d04_before_qualification_v1,
    life_d04_before_current_read_inputs_v1)

OPERATION = 'prepare_internal_life_numeric_context'
SCHEMA = 'd06.internal-life-numeric-context.v1'
KIND = 'numeric_context_v1'
D03_SCHEMA = 'd03.internal-life-context.v1'
D07_SCHEMA = 'd07.internal-life-presence.v1'
PROPOSAL_HASHES = {name: schema_hash({'schema': name, 'issuer': SCHEMA,
    'scope': 'authenticated_occurrence_only', 'adoption': 'installed_private_w01_witness'})
    for name in (D03_SCHEMA, D07_SCHEMA)}
_ACTIVE = {}
_CURRENT = {}


@dataclass(frozen=True, slots=True)
class PrepareLifeNumericContextRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        EncodeInternalLifeRequestV1(self.episode_ref, self.causal_operation_id)


def life_numeric_context_ids_v1(namespace, episode_ref):
    suffix = canonical_digest((SCHEMA, namespace, episode_ref))[:48]
    return {'operation': 'life-numeric-context:' + suffix,
            'original': 'life-numeric-context-original:' + suffix,
            'event': 'world:internal-life-numeric:' + suffix,
            'interpretation': 'life-presence:' + suffix}


def life_numeric_context_keys_v1(namespace, episode_ref, activity_id):
    ids = life_numeric_context_ids_v1(namespace, episode_ref)
    return (AtomKey(Owner('event', *namespace.as_tuple, ids['event']), 'd03.world_event', 'current'),
            AtomKey(Owner('activity', *namespace.as_tuple, activity_id), 'd07.current_interpretation.v1', ids['interpretation']))


@dataclass(frozen=True, slots=True)
class LifeNumericContextOriginalV1:
    namespace: NamespaceId
    original_ref: str
    operation_id: str
    episode_ref: str
    occurrence_digest: str
    execution_id: str
    before_ref: str
    before_digest: str
    source_ref: str
    source_revision: int
    source_digest: str
    perspective_ref: str
    perspective_revision: int
    event_ref: str
    interpretation_ref: str
    activation_generation: int
    graph_incarnation: str
    owner_head_digest: str
    world_event: WorldEvent
    interpretation: CurrentInterpretationCandidate
    schema: str = SCHEMA
    assertion_scope: str = 'authenticated_occurrence_interpretation_unassessed'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        ids = life_numeric_context_ids_v1(self.namespace, self.episode_ref)
        if (self.schema != SCHEMA or self.assertion_scope != 'authenticated_occurrence_interpretation_unassessed'
                or self.original_ref != ids['original'] or self.operation_id != ids['operation']
                or type(self.world_event) is not WorldEvent or type(self.interpretation) is not CurrentInterpretationCandidate
                or self.world_event.kind != 'd10_internal_life_step_completed'
                or self.world_event.reality != 'host_observed'
                or self.world_event.source_refs != (self.source_ref,)
                or self.interpretation.source_refs != (self.source_ref,)
                or self.interpretation.stance is not Stance.SUSPEND
                or self.interpretation.evidence_status is not EvidenceStatus.INSUFFICIENT
                or self.interpretation.subjective_conviction != 0.0
                or self.interpretation.interpretation_id != ids['interpretation']):
            raise ValueError('Life context cannot promote an unassessed meaning or external fact')
        keys = life_numeric_context_keys_v1(self.namespace, self.episode_ref, self.interpretation.activity_id)
        if (self.event_ref, self.interpretation_ref) != tuple(k.token for k in keys):
            raise ValueError('Life numeric context graph identities differ')
        for name in ('occurrence_digest', 'before_digest', 'source_digest', 'owner_head_digest'):
            _sha(getattr(self, name))
        for ref in (self.episode_ref, self.source_ref, self.perspective_ref, self.event_ref, self.interpretation_ref):
            if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace:
                raise ValueError('Life numeric context crosses namespace')
        if any(type(x) is not int or x < 1 for x in (self.source_revision, self.perspective_revision, self.activation_generation)):
            raise ValueError('Life context versions must be positive')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericContextStageV1:
    frame: object
    request: PrepareLifeNumericContextRequestV1
    original: LifeNumericContextOriginalV1
    primary_stage: object
    proposals: tuple


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CurrentLifeNumericContextV1:
    original: LifeNumericContextOriginalV1
    cause: object
    before: object
    source_qualification: SourceQualification


def decode_life_numeric_context_original_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, LifeNumericContextOriginalV1)
    if plain_v1(value) != raw:
        raise ValueError('Life context original wire differs')
    return value


def read_plan_life_numeric_context_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not PrepareLifeNumericContextRequestV1 or operation_kind != OPERATION:
        raise TypeError('exact Life context operation and locator required')
    keys, roots, originals = internal_life_episode_read_inputs_v2(db, namespace, request.episode_ref)
    before_keys, before_roots, before_originals = life_d04_before_current_read_inputs_v1(
        db, namespace=namespace, episode_ref=request.episode_ref)
    return production_read_plan_v1(('d01.persona_activation.v1', 'd01.persona_plan.v1', 'd03.self_perspective.v1'),
        (*keys, *before_keys, *life_numeric_context_keys_v1(namespace, request.episode_ref, activity_id)),
        tuple(dict.fromkeys((*roots, *before_roots))), (*originals, *before_originals, request.causal_operation_id))


def require_life_numeric_occurrence_time_v3(now, *, occurrence_completed_at, source_recorded_at):
    if occurrence_completed_at > now or source_recorded_at > now:
        raise ValueError('Life context cannot precede its actual occurrence')


def _derive(db, frame, request, installed_readers):
    read = CurrentDomainReadV1(frame); read.check(db)
    locator = EncodeInternalLifeRequestV1(request.episode_ref, request.causal_operation_id)
    cause, before = _read_current_life_d04_before_and_cause_v1(
        db, frame=frame, request=locator, installed_readers=installed_readers)
    episode, digest = require_current_life_d04_before_qualification_v1(before, db=db, frame=frame)
    proof = cause.occurrence; event = proof.event; activity = event.activity
    if episode != request.episode_ref or digest != canonical_digest(plain_v1(proof)):
        raise ValueError('Life context before belongs to another occurrence')
    source_atom = read.head(db, activity.source_ref, required=True)
    source = SourceRecord.from_dict(source_atom.value)
    perspective_atom = read.head(db, event.perspective_ref, required=True)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    perspective = decode_typed_production_value_v1(perspective_atom.value, SelfPerspective)
    require_life_numeric_occurrence_time_v3(frame.now_utc,occurrence_completed_at=activity.completed_at,
        source_recorded_at=source.recorded_at)
    ids = life_numeric_context_ids_v1(event.namespace, request.episode_ref)
    keys = life_numeric_context_keys_v1(event.namespace, request.episode_ref, activity.activity_id)
    world = WorldEvent(ids['event'], 'd10_internal_life_step_completed',
        ((perspective.self_entity_ref, 'internal_role_actor'),), activity.started_at,
        activity.completed_at, source.recorded_at, perspective.scene_ref, (activity.source_ref,), 'host_observed')
    interpretation = CurrentInterpretationCandidate(ids['interpretation'], activity.activity_id,
        'life-occurrence:' + canonical_digest((activity.execution_id, activity.terminal_original_ref))[:48],
        '本次内部活动已按认证终端完成；具体意义及对感受的影响尚未判定。',
        Stance.SUSPEND, 0.0, EvidenceStatus.INSUFFICIENT, (activity.source_ref,), (source.provenance_root,),
        ('meaning_unassessed', 'activity_caused_affect_not_identified', 'processed_text_external_truth_not_reassessed'))
    original = LifeNumericContextOriginalV1(event.namespace, ids['original'], ids['operation'], request.episode_ref,
        canonical_digest(plain_v1(proof)), activity.execution_id, before.original_ref, canonical_digest(plain_v1(before)),
        source_atom.key.token, source_atom.revision, canonical_digest(source_atom.value),
        perspective_atom.key.token, perspective_atom.revision, keys[0].token, keys[1].token,
        event.activation_generation, event.graph_incarnation, frame.owner_guard.owner_head_digest, world, interpretation)
    qualification = SourceQualification(source_refs=(activity.source_ref,), source_family='derived',
        occurred_at=source.occurred_at, learned_at=source.recorded_at, content_reality='inference',
        evidence_eligibility='ineligible', subjective_confidence=None, internal_activity_actuality='actual')
    return original, cause, before, qualification


def _writes(original):
    event_key, interpretation_key = life_numeric_context_keys_v1(original.namespace, original.episode_ref,
        original.interpretation.activity_id)
    return (GraphWrite(event_key, plain_v1(original.world_event), ()),
        GraphWrite(interpretation_key, {'schema': 'd07.current_interpretation.v1', **plain_v1(original.interpretation)}, ()))


def validate_life_numeric_context_proposal_v1(proposal, snapshot):
    """Closed shape check only; the installed W01 witness reissues actual facts."""
    schema = D03_SCHEMA if proposal.domain == 'd03' else D07_SCHEMA if proposal.domain == 'd07' else None
    if (schema is None or proposal.proposal_schema != schema or proposal.proposal_schema_hash != PROPOSAL_HASHES[schema]
            or proposal.envelope.identity.phase != OPERATION or len(proposal.typed_writes) != 1):
        raise ValueError('Life context proposal is outside its dedicated contract')
    write = proposal.typed_writes[0]
    reads = {v.key: v.revision for v in proposal.envelope.version_guard.read_versions}
    if (reads.get(write.key) != 0 or write.dependencies or snapshot.get(write.key) is None
            or snapshot.get(write.key).revision != 0 or snapshot.get(write.key).valid
            or not proposal.dependencies.historical_provenance or proposal.dependencies.current_invalidation):
        raise ValueError('Life context needs exact absence and historical provenance')
    if schema == D03_SCHEMA:
        value = dict(write.value)
        value['source_refs'] = tuple(value['source_refs'])
        value['participant_roles'] = tuple(tuple(x) for x in value['participant_roles'])
        event = WorldEvent(**value)
        if (write.key.type_name != 'd03.world_event' or write.key.owner.subject != event.event_id
                or write.key.name != 'current' or event.kind != 'd10_internal_life_step_completed'
                or event.reality != 'host_observed'):
            raise ValueError('Life context is not its occurrence event candidate')
        sources = event.source_refs
    else:
        value = dict(write.value)
        if value.pop('schema', None) != 'd07.current_interpretation.v1':
            raise ValueError('Life interpretation schema differs')
        value['stance'], value['evidence_status'] = Stance(value['stance']), EvidenceStatus(value['evidence_status'])
        for name in ('source_refs', 'source_families', 'meaningful_unknowns'): value[name] = tuple(value[name])
        item = CurrentInterpretationCandidate(**value)
        if (write.key.type_name != 'd07.current_interpretation.v1' or write.key.name != item.interpretation_id
                or write.key.owner.subject != item.activity_id or item.stance is not Stance.SUSPEND
                or item.evidence_status is not EvidenceStatus.INSUFFICIENT or item.subjective_conviction != 0.0):
            raise ValueError('Life interpretation must suspend semantic assessment')
        sources = item.source_refs
    if len(sources) != 1 or not set(sources) <= set(proposal.envelope.source_qualification.source_refs):
        raise ValueError('Life context qualified internal Source differs')
    for version in proposal.dependencies.historical_provenance:
        atom = snapshot.get(version.key)
        if atom is None or not atom.valid or atom.revision != version.revision or reads.get(version.key) != version.revision:
            raise ValueError('Life context provenance was not actually read')
    return proposal


def stage_life_numeric_context_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not PrepareLifeNumericContextRequestV1:
        raise TypeError('exact Life context locator required')
    original, cause, before, qualification = _derive(db, frame, request, installed_readers)
    if (frame.envelope.identity.operation_id != original.operation_id
            or frame.envelope.identity.phase != OPERATION):
        raise ValueError('Life context occurrence identity/current qualification differs')
    read = CurrentDomainReadV1(frame)
    writes = _writes(original)
    for write in writes:
        atom = read.head(db, write.key)
        if atom.revision or atom.valid:
            raise ValueError('Life context already exists; use its authenticated current reader')
    history = tuple(v for v in frame.snapshot.versions if v.revision > 0)
    proposals = tuple(validate_life_numeric_context_proposal_v1(DomainProposal(domain, schema,
        PROPOSAL_HASHES[schema], frame.envelope, (write,), DependencySet(historical_provenance=history), (), ()), frame.snapshot)
        for domain, schema, write in zip(('d03', 'd07'), (D03_SCHEMA, D07_SCHEMA), writes, strict=True))
    primary = stage_result_v1(frame, 'd06', OPERATION, request,
        provenance={'context_original': plain_v1(original), 'before_original_digest': canonical_digest(plain_v1(before))})
    stage = LifeNumericContextStageV1(frame, request, original, primary, proposals)
    identity = id(stage)
    _ACTIVE[identity] = (weakref.ref(stage, lambda _: _ACTIVE.pop(identity, None)), db)
    return stage


def verify_life_numeric_context_stage_v1(db, stage, *, installed_readers):
    issued = _ACTIVE.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life context is not this installed SQL-issued stage')
    derived, *_ = _derive(db, stage.frame, stage.request, installed_readers)
    if derived != stage.original:
        raise ValueError('Life numeric context actual current originals changed')
    if tuple(p.typed_writes[0] for p in stage.proposals) != _writes(derived):
        raise ValueError('Life context exact two-member write set changed')
    return stage


def record_life_numeric_context_after_cas_v1(db, *, stage, issuer, receipt):
    issued = _ACTIVE.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life context requires its original staging transaction')
    from .c04_encoding_baseline_store_v3 import _receipt
    from .d11_life_preparation_v1 import _record
    original = stage.original
    actual = _receipt(db, original.namespace, original.operation_id)
    expected = tuple(GraphVersion(w.key, 1) for w in _writes(original))
    if (actual != receipt or actual.read_versions != stage.frame.envelope.version_guard.read_versions
            or set(actual.write_versions) != set(expected)):
        raise ValueError('Life context actual W01 CAS receipt differs')
    for write in _writes(original):
        row = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (write.key.token,)).fetchone()
        if row != (canonical_serialize(write.value), 1, original.operation_id):
            raise ValueError('Life context original must follow exact same-transaction CAS')
    return _record(db, issuer=issuer, namespace=original.namespace, kind=KIND, ref=original.original_ref,
        operation_id=original.operation_id, value=original)


def require_life_numeric_shared_original_v1(db, *, namespace, operation_id, operation_kind, receipt, writes):
    """Verify the complete actual W01 domain original, including composite writes."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if operation_kind not in {OPERATION, 'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace'}:
        raise ValueError('Life shared original selector is outside its closed private phases')
    saved = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if (saved is None or saved['domain'] != 'd06' or saved['operation_kind'] != operation_kind
            or saved['receipt'] != receipt or saved['read_versions'] != receipt.read_versions
            or saved['payload'].get('writes') != plain_v1(writes)
            or saved['payload'].get('identity', {}).get('phase') != operation_kind):
        raise ValueError('Life numeric signed companion lacks its complete shared W01 original')
    return saved['payload']


def read_current_life_numeric_context_v1(db, *, frame, request, installed_readers):
    from .d11_life_preparation_v1 import _read
    expected, cause, before, qualification = _derive(db, frame, request, installed_readers)
    saved = _read(db, issuer=installed_readers.issuer, namespace=expected.namespace, kind=KIND, ref=expected.original_ref)
    if saved is None:
        raise ValueError('actual signed Life numerical context is unavailable; HOLD')
    original = decode_life_numeric_context_original_v1(saved[0])
    if original != expected or saved[1] != original.operation_id:
        raise ValueError('Life numerical context current lineage or Owner changed')
    from .c04_encoding_baseline_store_v3 import _receipt
    actual = _receipt(db, original.namespace, original.operation_id)
    payload = require_life_numeric_shared_original_v1(db, namespace=original.namespace,
        operation_id=original.operation_id, operation_kind=OPERATION, receipt=actual, writes=_writes(original))
    if payload['provenance'].get('context_original') != plain_v1(original):
        raise ValueError('Life context shared original has a different authenticated occurrence')
    read = CurrentDomainReadV1(frame)
    for write in _writes(original):
        atom = read.head(db, write.key, required=True)
        from .current_life_numeric_native_read_v3 import read_bound_native_numeric_history_v3
        handled,history=read_bound_native_numeric_history_v3(db,write.key.token,1,('value', 'valid', 'event_id'))
        if not handled:
            history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (write.key.token,)).fetchone()
        if (atom.revision != 1 or atom.value != write.value
                or GraphVersion(write.key, 1) not in actual.write_versions
                or history != (canonical_serialize(write.value), 1, original.operation_id)):
            raise ValueError('Life context current projection differs from its actual producer')
    result = CurrentLifeNumericContextV1(original, cause, before, qualification)
    identity = id(result)
    _CURRENT[identity] = (weakref.ref(result, lambda _: _CURRENT.pop(identity, None)), db, frame)
    return result


def require_current_life_numeric_context_v1(value, *, db, frame):
    issued = _CURRENT.get(id(value))
    if issued is None or issued[0]() is not value or issued[1] is not db or issued[2] is not frame or not db.in_transaction:
        raise ValueError('Life numeric context DTO is not this SQL/current-reader qualification')
    CurrentDomainReadV1(frame).check(db)
    require_current_life_d04_before_qualification_v1(value.before, db=db, frame=frame)
    return value


def freeze_current_life_numeric_appraisal_v1(db, *, frame, request, installed_readers):
    """Re-read the signed context, current Source and actual D01 role, then freeze.

    The installed registry injects the real freshly obtained Owner guard and
    its installation bundle. No caller PersonaView or model input is accepted.
    """
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..host.authority_profile import AdminInstallationBundle
    from ..domains.d01 import PersonaDomain, _activation_key
    from ..domains.d06 import source_correction_head_key
    from ..memory_types import access_key
    from ..model_broker.d04_appraisal import (AppraisalInputV1, AppraisalInstallationV1,
        QualifiedAppraisalSourceV1, BoundInterpretationV1, freeze_appraisal_request_v1)
    from ..model_broker.internal_life_numeric_v1 import WORK_KIND, TEMPLATE_VERSION
    from ..runtime_contracts import VersionedRef
    context = read_current_life_numeric_context_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    require_current_life_numeric_context_v1(context, db=db, frame=frame)
    bundle = getattr(installed_readers, 'life_numeric_bundle', None)
    guard = getattr(installed_readers, 'life_numeric_owner_guard', None)
    if (type(bundle) is not AdminInstallationBundle or type(guard) is not OwnerAuthorizationGuardV1
            or guard.namespace != frame.envelope.authority.namespace
            or guard.authorization_head.removeprefix('sha256:') != frame.owner_guard.owner_head_digest
            or guard.pending_revoke_operation_id):
        raise ValueError('Life numeric appraisal lacks its installed bundle/current Owner guard')
    workflow = getattr(bundle.model_workflows, 'life_numeric', None)
    if (workflow is None or workflow.work_kind != WORK_KIND or workflow.template_version != TEMPLATE_VERSION
            or workflow.purpose != 'consolidation' or frame.envelope.authority.purpose != 'consolidation'
            or not set(frame.envelope.authority.audience) <= set(workflow.audiences)):
        raise ValueError('Life numeric appraisal installed workflow/purpose/audience differs')
    read = CurrentDomainReadV1(frame); read.check(db)
    original = context.original
    records = read.source_family(db, (original.source_ref,), purpose='consolidation')
    source = records[original.source_ref]
    if source.source_kind != 'internal' or source.assertion_status != 'confirmed':
        raise ValueError('Life numeric appraisal requires its actual confirmed internal occurrence')
    source_atom = read.head(db, original.source_ref, required=True)
    access = read.head(db, access_key(*original.namespace.as_tuple, source.source_id), required=True)
    correction = read.head(db, source_correction_head_key(original.namespace, source.source_id))
    role = PersonaDomain.resolve_active_role(frame.snapshot, namespace=original.namespace, current_guard=guard)
    for version in role.read_versions:
        if read.head(db, version.key, required=True).revision != version.revision:
            raise ValueError('Life appraisal role is not the actual complete current plan')
    # No social-role completeness is inferred from an internal occurrence.
    view = PersonaDomain().project(role.plan, context_tags=(), role_binding_complete=False)
    role_atom = read.head(db, _activation_key(original.namespace), required=True)
    event_atom = read.head(db, original.event_ref, required=True)
    interpretation_atom = read.head(db, original.interpretation_ref, required=True)
    perspective_atom = read.head(db, original.perspective_ref, required=True)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    perspective = decode_typed_production_value_v1(perspective_atom.value, SelfPerspective)
    input_value = AppraisalInputV1(original.namespace,
        (QualifiedAppraisalSourceV1(source, VersionedRef(source_atom.key.token, source_atom.revision),
            VersionedRef(access.key.token, access.revision), VersionedRef(correction.key.token, correction.revision)),),
        context.source_qualification, VersionedRef(event_atom.key.token, event_atom.revision), original.world_event,
        VersionedRef(role_atom.key.token, role_atom.revision), view,
        (BoundInterpretationV1(VersionedRef(interpretation_atom.key.token, interpretation_atom.revision), original.interpretation),),
        perspective.self_entity_ref)
    frozen = freeze_appraisal_request_v1(input_value, AppraisalInstallationV1(
        bundle.installation_policy.installation_id, workflow.provider_id, workflow.model_id,
        workflow.provider_config_ref, workflow.provider_config_digest, workflow.max_output_tokens))
    return context, frozen
