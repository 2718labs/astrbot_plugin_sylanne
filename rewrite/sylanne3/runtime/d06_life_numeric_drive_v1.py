"""Actual internal-Life paid appraisal to installed all-member semantic drives.

The endpoint is the immutable actual appraisal adoption clock, never a model
candidate timestamp. Installed semantic/clock authority is observed before SQL
by W01's real fence context. This module grants neither CPU nor model work.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2
from ..domains.d04.numeric_drive import numeric_drive_id, TYPE_NAME as DRIVE_TYPE, decode_sourced_numeric_drive
from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1
from .d06_life_numeric_context_v1 import (PrepareLifeNumericContextRequestV1, read_plan_life_numeric_context_v1,
    freeze_current_life_numeric_appraisal_v1, read_current_life_numeric_context_v1,
    require_current_life_numeric_context_v1, life_numeric_context_ids_v1, decode_life_numeric_context_original_v1,
    OPERATION as CONTEXT_OPERATION, KIND as CONTEXT_KIND)
from .d04_life_before_original_v1 import decode_life_d04_before_original_v1, KIND as BEFORE_KIND
from .d04_life_encoding_baseline_v1 import COMPONENT_TYPES
from .d04_semantic_mapping_v3 import (read_current_d04_role_clock_v3, stage_current_d04_drive_in_transaction_v3,
    record_d04_mapping_acceptance_after_cas_v3, read_d04_mapping_acceptance_v3, D04RoleClockOriginalV3)

OPERATION = 'prepare_internal_life_numeric_drive'
SCHEMA = 'd04.life-numeric-drive-original.v1'
KIND = 'numeric_drive_v1'
PROPOSAL_SCHEMA = 'd04.internal-life-numeric-drive.proposal.v1'
PROPOSAL_HASH = schema_hash({'schema': PROPOSAL_SCHEMA, 'type': DRIVE_TYPE,
    'issuer': 'installed_private_life_paid_mapping_witness', 'purpose': 'consolidation'})
_STAGES = {}
_CURRENT = {}


@dataclass(frozen=True, slots=True)
class PrepareLifeNumericDriveRequestV1:
    episode_ref: str
    causal_operation_id: str
    appraisal_ref: str

    def __post_init__(self):
        PrepareLifeNumericContextRequestV1(self.episode_ref, self.causal_operation_id)
        key = AtomKey.from_token(self.appraisal_ref)
        if key.type_name != 'd04.appraisal_bundle.v1' or (key.owner.bot, key.owner.persona) != (AtomKey.from_token(self.episode_ref).owner.bot, AtomKey.from_token(self.episode_ref).owner.persona):
            raise ValueError('Life drive requires its actual adopted appraisal locator')


def life_numeric_drive_ids_v1(namespace, episode_ref, appraisal_ref):
    suffix = canonical_digest((SCHEMA, namespace, episode_ref, appraisal_ref))[:48]
    return {'operation': 'life-numeric-drive:' + suffix, 'original': 'life-numeric-drive-original:' + suffix}


@dataclass(frozen=True, slots=True)
class LifeNumericDriveOriginalV1:
    namespace: NamespaceId
    original_ref: str
    operation_id: str
    episode_ref: str
    context_ref: str
    context_digest: str
    before_digest: str
    source_ref: str
    appraisal_ref: str
    appraisal_acceptance_digest: str
    appraisal_adoption_operation_id: str
    mapping_ref: str
    mapping_digest: str
    root_ref: str
    clock: D04RoleClockOriginalV3
    drive_versions: tuple[tuple[str, int], ...]
    schema: str = SCHEMA
    assertion_scope: str = 'subjective_semantic_mapping_not_identified_causation'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        ids = life_numeric_drive_ids_v1(self.namespace, self.episode_ref, self.appraisal_ref)
        if (self.schema != SCHEMA or self.assertion_scope != 'subjective_semantic_mapping_not_identified_causation'
                or self.operation_id != ids['operation'] or self.original_ref != ids['original']
                or type(self.clock) is not D04RoleClockOriginalV3
                or type(self.drive_versions) is not tuple or not self.drive_versions
                or tuple(ref for ref, _ in self.drive_versions) != tuple(sorted({ref for ref, _ in self.drive_versions}))):
            raise ValueError('Life drive closed identity/clock/version scope differs')
        for digest in (self.context_digest, self.before_digest, self.appraisal_acceptance_digest, self.mapping_digest): _sha(digest)
        for ref, revision in self.drive_versions:
            if AtomKey.from_token(ref).type_name != DRIVE_TYPE or revision != 1:
                raise ValueError('Life drive requires immutable sourced-drive version one')
        if self.root_ref not in dict(self.clock.member_predecessor_cursors):
            raise ValueError('Life drive root must belong to its complete actual component')

    @property
    def digest(self): return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericDriveStageV1:
    frame: object
    request: PrepareLifeNumericDriveRequestV1
    context: object
    mapping_stage: object
    original: LifeNumericDriveOriginalV1
    primary_stage: object


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CurrentLifeNumericDriveV1:
    original: LifeNumericDriveOriginalV1
    context: object


def decode_life_numeric_drive_original_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, LifeNumericDriveOriginalV1)
    if plain_v1(value) != raw: raise ValueError('Life drive original canonical wire differs')
    return value


def _adoption(db, namespace, appraisal_ref):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (appraisal_ref,)).fetchone()
    if history is None or history[1] != 1: raise ValueError('Life drive actual appraisal history is absent')
    adopted = read_adopted_domain_operation_v1(db, namespace, history[2])
    if (adopted is None or adopted['domain'] != 'd04'
            or adopted['operation_kind'] != 'adopt_internal_life_numeric'
            or GraphVersion(AtomKey.from_token(appraisal_ref), 1) not in adopted['receipt'].write_versions):
        raise ValueError('Life drive appraisal lacks its actual numeric adoption')
    now = adopted['payload']['now_utc']
    if type(now) not in (int, float): raise ValueError('Life appraisal actual adoption clock is absent')
    wall_end = datetime.fromtimestamp(now, timezone.utc).isoformat().replace('+00:00', 'Z')
    return adopted, wall_end


def _plan_inputs(db, namespace, request):
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    from .d11_role_clock_installation_v1 import role_clock_mapping_id_v1
    from .clock import get_clock_mapping
    context_raw = raw_life_original_v1(db, namespace, CONTEXT_KIND,
        life_numeric_context_ids_v1(namespace, request.episode_ref)['original'])
    if context_raw is None: raise ValueError('Life drive actual context is unavailable')
    context = decode_life_numeric_context_original_v1(context_raw)
    raw = raw_life_original_v1(db, namespace, BEFORE_KIND, context.before_ref)
    if raw is None: raise ValueError('Life drive actual before root is unavailable')
    before = decode_life_d04_before_original_v1(raw)
    adopted, wall_end = _adoption(db, namespace, request.appraisal_ref)
    mapping = get_clock_mapping(db, role_clock_mapping_id_v1(namespace))
    refs = tuple(sorted(m.checkpoint.ref for m in before.members))
    checkpoints = []
    for ref in refs:
        row = db.execute('SELECT value,valid FROM graph_atoms WHERE token=?', (ref,)).fetchone()
        if row is None or row[1] != 1: raise ValueError('Life drive actual selected checkpoint is absent')
        checkpoints.append(decode_authored_numeric_checkpoint_v2(json.loads(row[0])))
    clock = read_current_d04_role_clock_v3(db, mapping_id=mapping.mapping_id, expected_mapping_version=mapping.version,
        checkpoints=tuple(checkpoints), checkpoint_refs=refs, wall_end_utc=wall_end)
    keys = tuple(AtomKey(Owner('persona', *namespace.as_tuple), DRIVE_TYPE,
        numeric_drive_id(ref, context.source_ref, clock.role_start, clock.role_end)) for ref in refs)
    return context, before, adopted, clock, keys


def read_plan_life_numeric_drive_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not PrepareLifeNumericDriveRequestV1 or operation_kind != OPERATION:
        raise TypeError('exact Life numerical drive locator required')
    base = read_plan_life_numeric_context_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind=CONTEXT_OPERATION, request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id))
    context, before, adopted, clock, keys = _plan_inputs(db, namespace, request)
    return production_read_plan_v1(tuple(dict.fromkeys((*base.fixed_type_ids, *COMPONENT_TYPES))),
        (*base.exact_keys, AtomKey.from_token(request.appraisal_ref), *keys), base.source_roots, base.required_original_refs)


def _compile(db, frame, request, installed_readers):
    from ..domains.d01 import PersonaDomain
    from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
    from .d06_life_numeric_task_v1 import require_current_life_numeric_appraisal_acceptance_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    context, frozen = freeze_current_life_numeric_appraisal_v1(db, frame=frame,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id), installed_readers=installed_readers)
    ns = context.original.namespace
    accepted = require_current_life_numeric_appraisal_acceptance_v1(db, frame=frame, context=context,
        appraisal_ref=request.appraisal_ref, installed_readers=installed_readers)
    planned, before, adopted, clock, keys = _plan_inputs(db, ns, request)
    if (planned != context.original or before != context.before or adopted['receipt'].operation_id != accepted.operation_id
            or adopted['payload']['now_utc'] < context.cause.occurrence.event.activity.completed_at
            or adopted['payload']['now_utc'] > frame.now_utc):
        raise ValueError('Life drive planned interval differs from its authenticated current adoption')
    reader = getattr(installed_readers, 'life_numeric_mapping_reader', None)
    bundle = installed_readers.life_numeric_bundle
    if (type(reader) is not InstalledD04SemanticMappingReaderV3
            or db is not reader.graph._GraphCoordinator__store._db
            or reader.graph._GraphCoordinator__d04_semantic_mapping_reader is not reader
            or reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise ValueError('Life drive actual installed semantic mapping reader is absent')
    installed = reader(db, ns)
    if set(ref for ref, _ in installed.block_shares) != {m.checkpoint.ref for m in before.members}:
        raise ValueError('Life drive allocation differs from the explicit before-root complete inventory')
    if reader.current_role_clock_identity(db, ns) != (clock.mapping_id, clock.mapping_version):
        raise ValueError('Life drive actual Owner-approved clock changed')
    read = CurrentDomainReadV1(frame); read.check(db)
    for kind in COMPONENT_TYPES: read.complete_inventory(db, kind)
    for key in keys:
        atom = read.head(db, key)
        if atom.revision or atom.valid: raise ValueError('Life source dose already mapped; read original')
    policy = bundle.d04_semantic_drive
    if policy is None: raise ValueError('Life drive requires explicit installed semantic dose policy')
    grant = installed_readers.issuer.current_budget_grant(db, policy.lease_id)
    lease = get_budget_lease(db, policy.lease_id)
    if (lease is None or lease.state != 'active' or policy.work_kind not in grant.allowed_work_kinds
            or grant.valid_until_utc <= frame.now_utc or grant.grant_id != policy.grant_id
            or grant.version != policy.grant_version or grant.lease_id != lease.lease_id):
        raise ValueError('Life drive current signed dose grant is unavailable')
    require_budget_family_admissible(db, lease.lease_id)
    role = PersonaDomain.resolve_active_role(frame.snapshot, namespace=ns, current_guard=installed_readers.life_numeric_owner_guard)
    stage = stage_current_d04_drive_in_transaction_v3(db, namespace=ns, appraisal_ref=request.appraisal_ref,
        frozen=frozen, snapshot=frame.snapshot, role=role, condition=reader.current_role_condition(db, ns),
        installed_mapping=installed, installed_mapping_reader=reader, dose_policy=policy,
        dose_grant_version=grant.version, clock=clock, audience=frame.envelope.authority.audience,
        purpose='consolidation', interpretation_level='candidate')
    if set(w.key for w in stage.writes) != set(keys):
        raise ValueError('Life mapping omitted or invented a selected component/source dose')
    ids = life_numeric_drive_ids_v1(ns, request.episode_ref, request.appraisal_ref)
    original = LifeNumericDriveOriginalV1(ns, ids['original'], ids['operation'], request.episode_ref,
        context.original.original_ref, context.original.digest, context.before.digest, context.original.source_ref,
        request.appraisal_ref, accepted.digest, accepted.operation_id, stage.original_ref, stage.original_digest,
        sorted(m.checkpoint.ref for m in before.members)[0], clock, tuple(sorted((w.key.token, 1) for w in stage.writes)))
    return context, stage, original


def validate_life_numeric_drive_proposal_v1(proposal, snapshot):
    if (proposal.domain != 'd04' or proposal.proposal_schema != PROPOSAL_SCHEMA
            or proposal.proposal_schema_hash != PROPOSAL_HASH or proposal.envelope.identity.phase != OPERATION
            or not 1 <= len(proposal.typed_writes) <= 16):
        raise ValueError('Life drive requires its dedicated bounded mapping proposal')
    guarded = {v.key: v.revision for v in proposal.envelope.version_guard.read_versions}
    for write in proposal.typed_writes:
        value = decode_sourced_numeric_drive(write.value)
        atom = snapshot.get(write.key)
        if (write.key.type_name != DRIVE_TYPE or write.key.name != value.drive_id or write.dependencies
                or atom is None or atom.revision != 0 or atom.valid or guarded.get(write.key) != 0):
            raise ValueError('Life drive source identity or actual absence read differs')
    return proposal


def stage_life_numeric_drive_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not PrepareLifeNumericDriveRequestV1: raise TypeError('exact Life drive request required')
    context, mapping_stage, original = _compile(db, frame, request, installed_readers)
    if frame.envelope.identity.operation_id != original.operation_id:
        raise ValueError('Life drive caller changed its actual occurrence/appraisal once identity')
    primary = stage_result_v1(frame, 'd04', OPERATION, request, writes=mapping_stage.writes,
        provenance={'life_numeric_drive_original': plain_v1(original)}, proposal_schema=PROPOSAL_SCHEMA, proposal_hash=PROPOSAL_HASH)
    for proposal in primary.proposals: validate_life_numeric_drive_proposal_v1(proposal, frame.snapshot)
    result = LifeNumericDriveStageV1(frame, request, context, mapping_stage, original, primary)
    identity = id(result); _STAGES[identity] = (weakref.ref(result, lambda _: _STAGES.pop(identity, None)), db)
    return result


def verify_life_numeric_drive_stage_v1(db, stage, *, installed_readers):
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life drive requires this privately issued SQL stage')
    _, mapping, original = _compile(db, stage.frame, stage.request, installed_readers)
    if original != stage.original or mapping != stage.mapping_stage:
        raise ValueError('Life current paid mapping/clock/dose changed before CAS')
    return stage


def record_life_numeric_drive_after_cas_v1(db, *, stage, issuer, receipt):
    from .c04_encoding_baseline_store_v3 import _receipt
    from .d11_life_preparation_v1 import _record
    issued = _STAGES.get(id(stage)); original = stage.original
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life drive record requires original issuing transaction')
    actual = _receipt(db, original.namespace, original.operation_id)
    if (actual != receipt or actual.read_versions != stage.frame.envelope.version_guard.read_versions
            or set(actual.write_versions) != {GraphVersion(w.key, 1) for w in stage.mapping_stage.writes}):
        raise ValueError('Life drive actual all-member W01 CAS differs')
    written_keys = {write.key for write in stage.mapping_stage.writes}
    for write in stage.mapping_stage.writes:
        for version in stage.mapping_stage.read_versions:
            if version.revision > 0 and version.key not in written_keys:
                existing = db.execute('SELECT dependency_revision FROM graph_dependency_edges '
                    'WHERE dependent_token=? AND dependency_token=? AND edge_kind=? AND operation_id=?',
                    (write.key.token, version.key.token, 'historical_provenance', original.operation_id)).fetchone()
                if existing is not None and existing != (version.revision,):
                    raise ValueError('Life drive historical edge conflicts with its actual mapping read')
                if existing is None:
                    db.execute('INSERT INTO graph_dependency_edges(dependent_token,dependency_token,'
                        'dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)',
                        (write.key.token, version.key.token, version.revision, 'historical_provenance', original.operation_id))
    record_d04_mapping_acceptance_after_cas_v3(db, stage.mapping_stage)
    return _record(db, issuer=issuer, namespace=original.namespace, kind=KIND, ref=original.original_ref,
        operation_id=original.operation_id, value=original)


def read_current_life_numeric_drive_v1(db, *, frame, request, installed_readers):
    from .d11_life_preparation_v1 import _read
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d06_life_numeric_task_v1 import require_current_life_numeric_appraisal_acceptance_v1
    from .d04_semantic_mapping_v3 import require_current_d04_role_clock_v3
    context = read_current_life_numeric_context_v1(db, frame=frame,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id), installed_readers=installed_readers)
    accepted = require_current_life_numeric_appraisal_acceptance_v1(db, frame=frame, context=context,
        appraisal_ref=request.appraisal_ref, installed_readers=installed_readers)
    ids = life_numeric_drive_ids_v1(context.original.namespace, request.episode_ref, request.appraisal_ref)
    saved = _read(db, issuer=installed_readers.issuer, namespace=context.original.namespace, kind=KIND, ref=ids['original'])
    if saved is None: raise ValueError('actual signed Life drive original is unavailable; HOLD')
    original = decode_life_numeric_drive_original_v1(saved[0])
    if (original.context_digest != context.original.digest or original.before_digest != context.before.digest
            or original.appraisal_acceptance_digest != accepted.digest or original.appraisal_adoption_operation_id != accepted.operation_id
            or saved[1] != original.operation_id or original.operation_id != ids['operation']):
        raise ValueError('Life drive current context/appraisal original differs')
    mapping = read_d04_mapping_acceptance_v3(db, original.namespace, original.mapping_ref)
    adopted = read_adopted_domain_operation_v1(db, original.namespace, original.operation_id)
    mapping_writes = None if mapping is None else [
        {'key': AtomKey(Owner(**w['key']['owner']), w['key']['type_name'], w['key']['name']).token,
         'value': w['value'], 'dependencies': [AtomKey(Owner(**k['owner']), k['type_name'], k['name']).token for k in w['dependencies']]}
        for w in mapping[0]['output_writes']]
    if (mapping is None or mapping[1] != original.mapping_digest or adopted is None or adopted['domain'] != 'd04'
            or adopted['operation_kind'] != OPERATION
            or adopted['payload']['provenance'].get('life_numeric_drive_original') != plain_v1(original)
            or canonical_serialize(adopted['payload']['writes']) != canonical_serialize(mapping_writes)):
        raise ValueError('Life drive lacks its exact complete shared mapping producer')
    read = CurrentDomainReadV1(frame); read.check(db)
    require_current_d04_role_clock_v3(db, original.clock)
    for ref, revision in original.drive_versions:
        atom = read.head(db, ref, required=True)
        history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?', (ref, revision)).fetchone()
        if (atom.revision != revision or GraphVersion(atom.key, revision) not in adopted['receipt'].write_versions
                or history != (canonical_serialize(atom.value), 1, original.operation_id)):
            raise ValueError('Life current drive is not its actual mapping write')
        drive = decode_sourced_numeric_drive(atom.value)
        checkpoint = read.head(db, drive.checkpoint_ref, required=True)
        if checkpoint.revision != drive.checkpoint_revision:
            raise ValueError('Life drive predecessor advanced; original CPU preparation must be resumed')
    result = CurrentLifeNumericDriveV1(original, context)
    identity = id(result); _CURRENT[identity] = (weakref.ref(result, lambda _: _CURRENT.pop(identity, None)), db, frame)
    return result


def require_current_life_numeric_drive_v1(value, *, db, frame):
    issued = _CURRENT.get(id(value))
    if issued is None or issued[0]() is not value or issued[1] is not db or issued[2] is not frame or not db.in_transaction:
        raise ValueError('Life drive DTO is not this current SQL-qualified producer')
    require_current_life_numeric_context_v1(value.context, db=db, frame=frame)
    return value
