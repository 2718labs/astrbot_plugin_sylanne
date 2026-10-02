"""Life-only interval baseline over authenticated before and adopted joint work.

The old C04 arithmetic and immutable numerical store are reused. Life's signed
companion has its own version and never impersonates a first-ingress baseline.
The installed W01 witness commits a read event before recording either original
in the same transaction. No supplied interval, model result or decoded record
can stand in for current Source/Owner/native/math qualification.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import math
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d04.affect import _decode_appraisal
from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1, joint_state_payload_v1
from ..domains.d04.numeric_drive import decode_sourced_numeric_drive
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1
from .d06_life_numeric_context_v1 import (PrepareLifeNumericContextRequestV1,
    read_plan_life_numeric_context_v1, read_current_life_numeric_context_v1,
    require_current_life_numeric_context_v1, OPERATION as CONTEXT_OPERATION)
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
from .c04_encoding_baseline_store_v3 import _receipt, read_c04_encoding_baseline_v3
from .c04_encoding_baseline_service_v3 import issue_and_record_c04_encoding_baseline_v3

OPERATION = 'prepare_internal_life_interval_baseline'
SCHEMA = 'd04.life-encoding-baseline.v1'
KIND = 'd04_interval_baseline_v1'
COMPONENT_TYPES = ('d04.numeric_checkpoint.v1', 'd04.numeric_checkpoint.v2',
    'd04.feeling_state.v1', 'd04.mood_field.v1', 'd04.authored_feeling_state.v1', 'd04.authored_mood_state.v1')
INVENTORIES = (*COMPONENT_TYPES, 'd04.appraisal_bundle.v1', 'd07.current_interpretation.v1', 'd07.belief_revision.v1')
_STAGES = {}
_CURRENT = {}


@dataclass(frozen=True, slots=True)
class PrepareLifeEncodingBaselineRequestV1:
    episode_ref: str
    causal_operation_id: str
    joint_operation_id: str

    def __post_init__(self):
        PrepareLifeNumericContextRequestV1(self.episode_ref, self.causal_operation_id)
        if type(self.joint_operation_id) is not str or not 1 <= len(self.joint_operation_id) <= 512:
            raise ValueError('Life baseline needs the actual adopted joint locator')


def life_encoding_baseline_ids_v1(namespace, episode_ref, joint_operation_id):
    suffix = canonical_digest((SCHEMA, namespace, episode_ref, joint_operation_id))[:48]
    return {'operation': 'life-interval-baseline:' + suffix, 'original': 'd04-life-interval:' + suffix}


def _interval(value, lower, upper):
    if (type(value) is not tuple or len(value) != 2
            or any(type(x) is not float or not math.isfinite(x) for x in value)
            or not lower <= value[0] <= value[1] <= upper):
        raise ValueError('Life numeric interval is not a finite ordered outward bound')


@dataclass(frozen=True, slots=True)
class D04LifeEncodingBaselineV1:
    namespace: NamespaceId
    original_ref: str
    encoding_operation_id: str
    episode_ref: str
    occurrence_digest: str
    execution_id: str
    before_ref: str
    before_digest: str
    context_ref: str
    context_digest: str
    source_ref: str
    source_revision: int
    perspective_ref: str
    joint_operation_id: str
    c04_record_digest: str
    proof_digest: str
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    numeric_error_digest: str
    native_manifest_sha256: str
    native_sha256: str
    readout_sha256: str
    policy_digest: str
    as_known_at: float
    owner_head_digest: str
    activation_generation: int
    graph_incarnation: str
    appraisal_acceptance_digests: tuple[tuple[str, str], ...]
    schema: str = SCHEMA
    selection_scope: str = 'explicit_installed_root_complete_inventory'
    assertion_scope: str = 'authenticated_state_interpretation_temporal_association'
    causal_effect: str = 'not_identified'
    semantic_calibration: str = 'unvalidated'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        ids = life_encoding_baseline_ids_v1(self.namespace, self.episode_ref, self.joint_operation_id)
        if (self.schema != SCHEMA or self.original_ref != ids['original'] or self.encoding_operation_id != ids['operation']
                or self.selection_scope != 'explicit_installed_root_complete_inventory'
                or self.assertion_scope != 'authenticated_state_interpretation_temporal_association'
                or self.causal_effect != 'not_identified' or self.semantic_calibration != 'unvalidated'
                or type(self.as_known_at) is not float or not math.isfinite(self.as_known_at)
                or type(self.source_revision) is not int or self.source_revision < 1
                or type(self.activation_generation) is not int or self.activation_generation < 1):
            raise ValueError('Life baseline temporal/semantic scope or exact identity differs')
        for name in ('occurrence_digest', 'before_digest', 'context_digest', 'c04_record_digest', 'proof_digest',
                     'numeric_error_digest', 'native_manifest_sha256', 'native_sha256', 'readout_sha256', 'policy_digest', 'owner_head_digest'):
            _sha(getattr(self, name))
        _interval(self.salience_interval, 0.0, 1.0); _interval(self.tone_interval, -1.0, 1.0)
        if (type(self.appraisal_acceptance_digests) is not tuple or not self.appraisal_acceptance_digests
                or tuple(ref for ref, _ in self.appraisal_acceptance_digests) != tuple(sorted({ref for ref, _ in self.appraisal_acceptance_digests}))):
            raise ValueError('Life baseline needs a closed actual numeric appraisal acceptance set')
        for ref, digest in self.appraisal_acceptance_digests:
            if AtomKey.from_token(ref).type_name != 'd04.appraisal_bundle.v1':
                raise ValueError('Life baseline appraisal locator type differs')
            _sha(digest)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeEncodingBaselineStageV1:
    frame: object
    request: PrepareLifeEncodingBaselineRequestV1
    context: object
    environment: object
    appraisal_acceptance_digests: tuple[tuple[str, str], ...]
    output_digest: str
    owner_epoch: int
    owner_fence_digest: str
    primary_stage: object


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CurrentLifeEncodingBaselineV1:
    original: D04LifeEncodingBaselineV1
    context: object
    c04_record: object


def decode_life_encoding_baseline_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, D04LifeEncodingBaselineV1)
    if plain_v1(value) != raw:
        raise ValueError('Life interval baseline wire is not canonical')
    return value


def read_plan_life_encoding_baseline_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not PrepareLifeEncodingBaselineRequestV1 or operation_kind != OPERATION:
        raise TypeError('exact Life interval baseline request required')
    base = read_plan_life_numeric_context_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind=CONTEXT_OPERATION,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id))
    # Discover all actual drive Sources for current qualification. These are
    # untrusted read-plan locators; the private stage authenticates each drive.
    from .d04_joint_advance_v2 import _decode_numeric_candidate
    row = db.execute('SELECT numeric_receipt_json FROM graph_d04_joint_numeric_originals_v1 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*namespace.as_tuple, request.joint_operation_id)).fetchone()
    if row is None:
        raise ValueError('Life baseline actual joint numeric original is unavailable; HOLD')
    numeric = _decode_numeric_candidate(row[0])
    roots = tuple(dict.fromkeys((*base.source_roots, *(item[2] for item in numeric.source_versions))))
    keys = (*base.exact_keys, *(AtomKey.from_token(item[0]) for item in numeric.source_versions))
    return production_read_plan_v1(tuple(dict.fromkeys((*base.fixed_type_ids, *INVENTORIES))),
        keys, roots, base.required_original_refs)


def _environment(db, frame, environment):
    from .installed_c04_encoding_context_v3 import C04EncodingEnvironmentV3, _ENVIRONMENTS
    if (type(environment) is not C04EncodingEnvironmentV3 or _ENVIRONMENTS.get(id(environment)) is not environment
            or environment.namespace != frame.envelope.authority.namespace
            or db is not environment.graph._GraphCoordinator__store._db
            or not environment.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('Life baseline requires the actual installed clock/assets observation')
    assembly = environment.graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.installation_policy.manifest_digest != environment.manifest_sha256:
        raise ValueError('Life baseline installed numerical package changed')
    return environment


def _current_inputs(db, frame, request, installed_readers, environment):
    from .d04_joint_advance_v2 import _decode_numeric_candidate
    from .d04_semantic_mapping_v3 import read_d04_mapping_acceptance_v3
    from .d06_life_numeric_task_v1 import require_current_life_numeric_appraisal_acceptance_v1
    read = CurrentDomainReadV1(frame); read.check(db)
    env = _environment(db, frame, environment)
    context = read_current_life_numeric_context_v1(db, frame=frame,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id), installed_readers=installed_readers)
    require_current_life_numeric_context_v1(context, db=db, frame=frame)
    ns, source_ref = context.original.namespace, context.original.source_ref
    output = read_d04_joint_output_original_v1(db, ns, request.joint_operation_id)
    if output is None or output.schema != 'd04.joint-state-output.v2':
        raise ValueError('Life baseline needs its actual authored joint adoption')
    before = context.before
    expected_pairs = {m.checkpoint.ref: m for m in before.members}
    if set(expected_pairs) != {m.checkpoint_ref for m in output.members}:
        raise ValueError('Life encoding component differs from its explicit before-root inventory')
    expected_refs = set()
    root_candidates = set()
    for member in output.members:
        predecessor = expected_pairs[member.checkpoint_ref]
        historical_cp = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
            (predecessor.checkpoint.ref, predecessor.checkpoint.revision)).fetchone()
        if historical_cp is None or historical_cp[1] != 1:
            raise ValueError('Life authenticated before checkpoint history disappeared')
        root_candidate_digest = json.loads(historical_cp[0])['root_candidate_digest']
        root_candidates.add(root_candidate_digest)
        if (member.predecessor_state_ref != predecessor.state.ref
                or member.predecessor_checkpoint_revision < predecessor.checkpoint.revision
                or member.predecessor_state_revision < predecessor.state.revision
                or member.next_checkpoint.root_candidate_digest != root_candidate_digest
                or member.next_state.root_operation_id != before.root_operation_id):
            raise ValueError('Life interval joint does not continue its authenticated before root')
        for ref, version, value in ((member.checkpoint_ref, member.predecessor_checkpoint_revision + 1,
                joint_checkpoint_payload_v1(member.next_checkpoint)), (member.predecessor_state_ref,
                member.predecessor_state_revision + 1, joint_state_payload_v1(member.next_state))):
            atom = read.head(db, ref, required=True)
            if atom.revision != version or atom.value != value:
                raise ValueError('Life encoding current numeric member is not the adopted joint output')
            expected_refs.add(ref)
    inventory = {atom.key.token for kind in COMPONENT_TYPES for atom in read.complete_inventory(db, kind)
        if atom.key.token in expected_refs or atom.value.get('root_operation_id') == before.root_operation_id
        or atom.value.get('root_candidate_digest') in root_candidates}
    if inventory != expected_refs:
        raise ValueError('Life encoding root component current inventory differs')
    row = db.execute('SELECT numeric_receipt_json FROM graph_d04_joint_numeric_originals_v1 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple, request.joint_operation_id)).fetchone()
    if row is None: raise ValueError('Life actual numeric receipt is absent')
    candidate = _decode_numeric_candidate(row[0])
    appraisals = {}
    for ref, revision, *rest in candidate.source_versions:
        history = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?', (ref, revision)).fetchone()
        if history is None or history[1] != 1: raise ValueError('Life joint drive history is absent')
        drive = decode_sourced_numeric_drive(json.loads(history[0]))
        read.source_family(db, (drive.source_ref,), purpose='consolidation')
        if drive.source_ref != source_ref: continue
        if drive.source_revision != context.original.source_revision:
            raise ValueError('Life joint uses another Source version')
        mapping = read_d04_mapping_acceptance_v3(db, ns, drive.mapping_compiler_ref)
        if mapping is None: raise ValueError('Life actual installed drive mapping is absent')
        mapped = mapping[0]
        matches = [w for w in mapped['output_writes'] if w['value']['drive_id'] == drive.drive_id]
        if len(matches) != 1 or canonical_serialize(matches[0]['value']) != canonical_serialize(plain_v1(drive)):
            raise ValueError('Life source drive differs from its actual mapping original')
        appref = mapped['appraisal_acceptance_ref']
        accepted = require_current_life_numeric_appraisal_acceptance_v1(db, frame=frame, context=context,
            appraisal_ref=appref, installed_readers=installed_readers)
        if accepted.digest != mapped['appraisal_acceptance_digest']:
            raise ValueError('Life drive cites a different paid numerical appraisal')
        atom = read.head(db, appref, required=True)
        if atom.revision != accepted.appraisal_revision or canonical_serialize(atom.value) != accepted.appraisal_value_json:
            raise ValueError('Life adopted MeaningFacet original changed')
        appraisal = _decode_appraisal(atom.value)
        selected = tuple(f for f in appraisal.meaning_facets if source_ref in f.source_refs)
        if not selected or appraisal.learned_at > env.as_known_at:
            raise ValueError('Life encoding lacks its already-known source-specific MeaningFacet')
        for facet in selected:
            interpretation = read.head(db, facet.interpretation_ref, required=True)
            if (interpretation.key.token != context.original.interpretation_ref
                    or source_ref not in interpretation.value['source_refs']):
                raise ValueError('Life MeaningFacet is not its actual internal interpretation')
        wall_end = datetime.fromisoformat(mapped['clock']['wall_end_utc'].replace('Z', '+00:00')).timestamp()
        if not context.cause.occurrence.event.activity.completed_at <= wall_end <= env.as_known_at:
            raise ValueError('Life semantic advance does not follow its actual activity')
        appraisals[appref] = accepted.digest
    if not appraisals: raise ValueError('Life baseline has no actual internal-Source numeric drive')
    # C04's context issuer includes every source-specific appraisal in the
    # actual read set. Require all of them to have this distinct paid lineage.
    for atom in read.complete_inventory(db, 'd04.appraisal_bundle.v1'):
        if not atom.valid: continue
        appraisal = _decode_appraisal(atom.value)
        if any(source_ref in f.source_refs for f in appraisal.meaning_facets):
            accepted = require_current_life_numeric_appraisal_acceptance_v1(db, frame=frame, context=context,
                appraisal_ref=atom.key.token, installed_readers=installed_readers)
            if appraisals.get(atom.key.token) != accepted.digest:
                raise ValueError('Life baseline has an appraisal outside its actual joint mapping set')
    if env.as_known_at < context.cause.occurrence.event.activity.completed_at:
        raise ValueError('Life encoding clock predates completion')
    return context, output, tuple(sorted(appraisals.items()))


def stage_current_life_encoding_baseline_v1(db, *, frame, request, installed_readers, environment):
    if type(request) is not PrepareLifeEncodingBaselineRequestV1:
        raise TypeError('exact Life interval baseline locator required')
    ids = life_encoding_baseline_ids_v1(frame.envelope.authority.namespace, request.episode_ref, request.joint_operation_id)
    if frame.envelope.identity.operation_id != ids['operation'] or frame.envelope.identity.phase != OPERATION:
        raise ValueError('Life baseline stable producing operation differs')
    context, output, accepted = _current_inputs(db, frame, request, installed_readers, environment)
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    owner_guard = getattr(installed_readers, 'life_numeric_owner_guard', None)
    if (type(owner_guard) is not OwnerAuthorizationGuardV1 or owner_guard.namespace != context.original.namespace
            or owner_guard.authorization_head.removeprefix('sha256:') != frame.owner_guard.owner_head_digest):
        raise ValueError('Life baseline actual Owner authorization revision is unavailable')
    from ..runtime_contracts import FenceScope
    scope = getattr(installed_readers, 'life_numeric_scope', None)
    metadata, epoch = environment.graph._v2_graph_stamp(context.original.namespace)
    if (type(scope) is not FenceScope or scope.namespace != context.original.namespace
            or scope.operation != 'write' or scope.generation != frame.activation_generation
            or scope.graph_epoch != epoch or epoch != frame.snapshot.epochs[0]
            or scope.graph_revision != metadata.graph_revision
            or not environment.graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise ValueError('Life baseline actual current W01 write scope changed')
    fence_digest = canonical_digest(asdict(scope.permit))
    primary = stage_result_v1(frame, 'd06', OPERATION, request, provenance={
        'schema': SCHEMA, 'context_digest': context.original.digest, 'before_digest': context.original.before_digest,
        'joint_output_digest': output.original_digest, 'appraisal_acceptance_digests': accepted,
        'as_known_at': environment.as_known_at, 'causal_effect': 'not_identified'})
    result = LifeEncodingBaselineStageV1(frame, request, context, environment, accepted, output.original_digest, owner_guard.authorization_revision, fence_digest, primary)
    identity = id(result)
    _STAGES[identity] = (weakref.ref(result, lambda _: _STAGES.pop(identity, None)), db)
    return result


def verify_life_encoding_baseline_stage_v1(db, stage, *, installed_readers):
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life baseline stage is not this SQL-issued original')
    context, output, accepted = _current_inputs(db, stage.frame, stage.request, installed_readers, stage.environment)
    if (context.original != stage.context.original or output.original_digest != stage.output_digest
            or accepted != stage.appraisal_acceptance_digests
            or canonical_digest(asdict(installed_readers.life_numeric_scope.permit)) != stage.owner_fence_digest
            or installed_readers.life_numeric_owner_guard.authorization_revision != stage.owner_epoch):
        raise ValueError('Life current interval-baseline premises changed')
    return stage


def _from_record(context, record, accepted):
    c = context.original; proof = record.proof
    ids = life_encoding_baseline_ids_v1(c.namespace, c.episode_ref, record.joint_operation_id)
    return D04LifeEncodingBaselineV1(c.namespace, ids['original'], ids['operation'], c.episode_ref,
        c.occurrence_digest, c.execution_id, c.before_ref, c.before_digest, c.original_ref, c.digest,
        c.source_ref, c.source_revision, c.perspective_ref, record.joint_operation_id, record.record_digest,
        proof.proof_digest, proof.projection.salience_interval, proof.projection.tone_interval,
        canonical_digest(plain_v1(proof.numeric_error)), proof.native_manifest_sha256, proof.native_sha256,
        proof.readout_sha256, proof.policy_digest, proof.as_known_at, c.owner_head_digest,
        c.activation_generation, c.graph_incarnation, accepted)


def record_life_encoding_baseline_after_cas_v1(db, *, stage, issuer, receipt):
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life baseline recording requires its issuing transaction')
    c = stage.context.original; frame = stage.frame; env = stage.environment
    ids = life_encoding_baseline_ids_v1(c.namespace, c.episode_ref, stage.request.joint_operation_id)
    actual = _receipt(db, c.namespace, ids['operation'])
    if actual != receipt or actual.write_versions or actual.read_versions != frame.envelope.version_guard.read_versions:
        raise ValueError('Life baseline requires its exact actual zero-write W01 read receipt')
    record = issue_and_record_c04_encoding_baseline_v3(db, namespace=c.namespace,
        encoding_operation_id=ids['operation'], joint_operation_id=stage.request.joint_operation_id,
        source_ref=c.source_ref, perspective_ref=c.perspective_ref, baseline_id=ids['original'],
        owner_fence_digest=stage.owner_fence_digest, as_known_at=float(env.as_known_at),
        owner_epoch=stage.owner_epoch, access_epoch=frame.envelope.version_guard.access_epoch,
        delete_epoch=frame.envelope.version_guard.delete_epoch, asset=env.asset, policy=env.policy)
    original = _from_record(stage.context, record, stage.appraisal_acceptance_digests)
    from .d11_life_preparation_v1 import _record
    _record(db, issuer=issuer, namespace=c.namespace, kind=KIND, ref=original.original_ref,
        operation_id=original.encoding_operation_id, value=original)
    return original


def read_current_life_encoding_baseline_v1(db, *, frame, request, installed_readers, environment):
    from .d11_life_preparation_v1 import _read
    if type(request) is not PrepareLifeEncodingBaselineRequestV1:
        raise TypeError('exact Life baseline locator required')
    # Current use authenticates historical numerical output; subsequent D04
    # advancement must not relabel this encoding-time baseline as latest state.
    context = read_current_life_numeric_context_v1(db, frame=frame,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id), installed_readers=installed_readers)
    _environment(db, frame, environment)
    ids = life_encoding_baseline_ids_v1(context.original.namespace, request.episode_ref, request.joint_operation_id)
    saved = _read(db, issuer=installed_readers.issuer, namespace=context.original.namespace, kind=KIND, ref=ids['original'])
    if saved is None: raise ValueError('signed Life interval baseline is unavailable; HOLD')
    original = decode_life_encoding_baseline_v1(saved[0])
    record = read_c04_encoding_baseline_v3(db, namespace=original.namespace,
        encoding_operation_id=ids['operation'], source_ref=context.original.source_ref)
    if (saved[1] != ids['operation'] or original != _from_record(context, record, original.appraisal_acceptance_digests)
            or record.proof.policy_digest != canonical_digest(plain_v1(environment.policy))
            or record.proof.readout_sha256 != environment.asset.asset_sha256
            or record.proof.native_manifest_sha256 != environment.manifest_sha256):
        raise ValueError('Life baseline signed context/installed numerical identities differ')
    from .d06_life_numeric_context_v1 import require_life_numeric_shared_original_v1
    payload = require_life_numeric_shared_original_v1(db, namespace=original.namespace,
        operation_id=original.encoding_operation_id, operation_kind=OPERATION, receipt=record.encoding_receipt, writes=())
    expected_provenance = {'schema': SCHEMA, 'context_digest': context.original.digest,
        'before_digest': context.original.before_digest, 'joint_output_digest': record.proof.output_original_digest,
        'appraisal_acceptance_digests': original.appraisal_acceptance_digests,
        'as_known_at': original.as_known_at, 'causal_effect': 'not_identified'}
    if payload['provenance'] != plain_v1(expected_provenance):
        raise ValueError('Life baseline shared original has different numerical premises')
    from .d06_life_numeric_task_v1 import require_current_life_numeric_appraisal_acceptance_v1
    for ref, digest in original.appraisal_acceptance_digests:
        accepted = require_current_life_numeric_appraisal_acceptance_v1(db, frame=frame, context=context,
            appraisal_ref=ref, installed_readers=installed_readers)
        if accepted.digest != digest: raise ValueError('Life baseline paid appraisal is no longer qualified')
    # Every historical contributing Source remains independently current for
    # this consumer; historical existence alone never restores revoked access.
    from .d04_joint_advance_v2 import _decode_numeric_candidate
    raw = db.execute('SELECT numeric_receipt_json FROM graph_d04_joint_numeric_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
        (*original.namespace.as_tuple, original.joint_operation_id)).fetchone()
    if raw is None: raise ValueError('Life baseline actual numeric source closure is absent')
    candidate = _decode_numeric_candidate(raw[0])
    read = CurrentDomainReadV1(frame)
    roots = tuple(sorted({item[2] for item in candidate.source_versions}))
    if roots: read.source_family(db, roots)
    result = CurrentLifeEncodingBaselineV1(original, context, record)
    identity = id(result)
    _CURRENT[identity] = (weakref.ref(result, lambda _: _CURRENT.pop(identity, None)), db, frame)
    return result


def require_current_life_encoding_baseline_v1(value, *, db, frame):
    issued = _CURRENT.get(id(value))
    if issued is None or issued[0]() is not value or issued[1] is not db or issued[2] is not frame or not db.in_transaction:
        raise ValueError('Life baseline DTO is not this current SQL-issued reader qualification')
    require_current_life_numeric_context_v1(value.context, db=db, frame=frame)
    return value
