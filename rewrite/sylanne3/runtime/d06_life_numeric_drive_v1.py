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
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    history = _producer_original_point_v3(db,table="graph_history",columns=("event_id","value","valid"),
        key_columns=("token","revision"),key=(appraisal_ref,1),
        legacy_reader=lambda:db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1",
            (appraisal_ref,)).fetchone())
    if history is None or history[2] != 1: raise ValueError('Life drive actual appraisal history is absent')
    adopted = read_adopted_domain_operation_v1(db, namespace, history[0])
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
        from .d01_production_operations_v1 import raw_head_value_v1
        raw = raw_head_value_v1(db,namespace,AtomKey.from_token(ref))
        if raw is None: raise ValueError('Life drive actual selected checkpoint is absent')
        checkpoints.append(decode_authored_numeric_checkpoint_v2(raw))
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
    bind_prepared_numeric_drive_stage_v3(db,result)
    return result


def verify_life_numeric_drive_stage_v1(db, stage, *, installed_readers):
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life drive requires this privately issued SQL stage')
    _, mapping, original = _compile(db, stage.frame, stage.request, installed_readers)
    if original != stage.original or mapping != stage.mapping_stage:
        raise ValueError('Life current paid mapping/clock/dose changed before CAS')
    bind_prepared_numeric_drive_stage_v3(db,stage)
    return stage


def record_life_numeric_drive_after_cas_v1(db, *, stage, issuer, receipt,drive_commit_witness_v3):
    from .d06_life_numeric_commit_v1 import require_current_life_numeric_drive_write_v3,record_current_life_numeric_drive_original_v3
    issued = _STAGES.get(id(stage)); original = stage.original
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life drive record requires original issuing transaction')
    actual=require_current_life_numeric_drive_write_v3(db,witness=drive_commit_witness_v3,stage=stage,receipt=receipt,writes=stage.mapping_stage.writes)
    capsule=require_active_numeric_drive_inputs_v3(db,drive_commit_witness_v3,stage,receipt)
    if (actual != receipt or actual.read_versions != stage.frame.envelope.version_guard.read_versions
            or set(actual.write_versions) != {GraphVersion(w.key, 1) for w in stage.mapping_stage.writes}):
        raise ValueError('Life drive actual all-member W01 CAS differs')
    written_keys = {write.key for write in stage.mapping_stage.writes}
    for write in stage.mapping_stage.writes:
        for version in stage.mapping_stage.read_versions:
            if version.revision > 0 and version.key not in written_keys:
                key=(write.key.token,version.key.token,'historical_provenance',original.operation_id)
                prior=next((None if row[4]is None else (dict(zip(row[3],row[4]))["dependency_revision"],)
                    for row in capsule.points if row[:3]==("graph_dependency_edges",
                    ("dependent_token","dependency_token","edge_kind","operation_id"),key)),None)
                if not any(row[:3]==("graph_dependency_edges",("dependent_token","dependency_token","edge_kind","operation_id"),key)
                        for row in capsule.points):raise ValueError('Drive dependency edge lacked actual prepared EOF')
                with runtime_storage_quantum_v3(db)as meter:
                    existing=_runtime_bounded_fixed_row_v3(db,meter,"graph_dependency_edges",("dependency_revision",),
                        "dependent_token=? AND dependency_token=? AND edge_kind=? AND operation_id=?",key)
                if existing!=prior:raise ValueError('Drive dependency edge changed after actual prepared EOF')
                if existing is not None and existing != (version.revision,):
                    raise ValueError('Life drive historical edge conflicts with its actual mapping read')
                if existing is None:
                    db.execute('INSERT INTO graph_dependency_edges(dependent_token,dependency_token,'
                        'dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)',
                        (write.key.token, version.key.token, version.revision, 'historical_provenance', original.operation_id))
    record_d04_mapping_acceptance_after_cas_v3(db,stage.mapping_stage,drive_commit_witness_v3=drive_commit_witness_v3)
    return record_current_life_numeric_drive_original_v3(db,witness=drive_commit_witness_v3,stage=stage,issuer=issuer,receipt=receipt,writes=stage.mapping_stage.writes)


def _require_life_numeric_drive_producer_membership_v1(db, original):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
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
    return adopted


def read_current_life_numeric_drive_v1(db, *, frame, request, installed_readers):
    from .d11_life_preparation_v1 import _read
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
    adopted = _require_life_numeric_drive_producer_membership_v1(db, original)
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

from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary
from types import MappingProxyType
from dataclasses import asdict
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from .current_method_learning_read_v3 import _MethodBudgetGrantReadV3

_DRIVE_INPUTS_V3=WeakKeyDictionary()
_DRIVE_SELECTIONS_V3=WeakKeyDictionary()
_DRIVE_STAGE_INPUTS_V3={}
_DRIVE_ACTIVE_V3=ContextVar("sylanne_numeric_drive_active_write_v3",default=None)
_DRIVE_ORIGINAL_COLUMNS_V3=("producing_operation_id","payload_json","payload_digest","signature")
_CLOCK_COLUMNS_V3=("mapping_id","version","wall_origin_utc","character_origin","rate","valid_from_utc","valid_until_utc","policy_ref","issuer_domain")

def _drive_reader_v3(reader):
    from .current_method_learning_read_v3 import require_actual_source_owner_metadata_work_v1
    from .current_life_numeric_metadata_v1 import require_numeric_method_sources_v1
    r=require_actual_source_owner_metadata_work_v1(reader)
    if r.operation_kind!=OPERATION:raise AuthorityUnavailable("Drive inputs require the exact current Numeric Method")
    require_numeric_method_sources_v1(r)
    return r

def _drive_policy_v3(reader):
    r=_drive_reader_v3(reader)
    assembly=r.graph._GraphCoordinator__d04_installed_joint_assembly
    policy=assembly.admin_bundle.d04_semantic_drive
    if policy is None:raise AuthorityUnavailable("Drive requires its actual installed dose policy")
    return assembly,policy

class DriveDoseGrantTaskV3(_MethodBudgetGrantReadV3):
    def __init__(self,reader,lease_id):
        assembly,policy=_drive_policy_v3(reader)
        if lease_id!=policy.lease_id or lease_id==reader.parent_budget_lease_ref:
            raise AuthorityUnavailable("Drive dose grant needs the exact distinct installed policy lease")
        super().__init__(reader,lease_id)
        self.assembly,self.policy=assembly,policy
        self.ancestry=None
    def advance(self,meter):
        if self.metadata is not None and self.column is None:
            from .current_method_learning_read_v3 import MethodJSONColumnV3,_ISSUER
            self.owner.require_current(meter=meter)
            self.require_metadata_v3(meter)
            # Bind the actual task column before its constructor starts HMAC.
            self.column=object.__new__(MethodJSONColumnV3)
            MethodJSONColumnV3.__init__(self.column,_ISSUER,self.owner,
                table="runtime_budget_grants",column="grant_json",
                key_columns=("lease_id","version"),key=self.metadata[:2],
                signer=self.owner.graph._GraphCoordinator__d11_issuer._signer,
                signature_kind="budget-grant.v1",signature=self.metadata[2])
            return
        return super().advance(meter)
    def require_metadata_v3(self,meter):
        r=self.owner
        assembly,policy=_drive_policy_v3(r)
        if assembly is not self.assembly or policy is not self.policy:
            raise AuthorityUnavailable("Drive dose grant changed actual installation policy")
        row=super().require_metadata_v3(meter)
        if row[:2]!=(policy.lease_id,policy.grant_version):
            raise AuthorityUnavailable("Drive dose grant latest approved version differs")
        headers=[];current=policy.lease_id;seen=set()
        while current is not None:
            if current in seen:raise AuthorityUnavailable("Drive dose budget ancestry has a cycle")
            seen.add(current)
            value=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_leases",
                ("parent_id","bot_id","persona_id","currency","version","state"),"lease_id=?",(current,))
            if value is None or value[1:3]!=r.namespace.as_tuple or value[5]!="active":
                raise AuthorityUnavailable("Drive dose budget ancestry is unavailable")
            headers.append((current,value))
            current=value[0]
        if r.parent_budget_lease_ref not in seen:
            raise AuthorityUnavailable("Drive dose policy is not in the actual original Root budget family")
        from .budget import require_budget_family_admissible
        require_budget_family_admissible(r.db,policy.lease_id)
        actual=tuple(headers)
        if self.ancestry is not None and actual!=self.ancestry:
            raise AuthorityUnavailable("Drive dose budget ancestry changed after EOF")
        if self.ancestry is None:self.ancestry=actual;r.operation.retain(sum(len(str(x))for x in actual)*8+4096)
        return row

def require_drive_dose_signature_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    r=original.owner
    _,policy=_drive_policy_v3(r)
    task=r.attachments.get(("drive_dose_grant",policy.lease_id))
    if (type(task)is not DriveDoseGrantTaskV3 or task.owner is not r or task.column is not original
            or original.table!="runtime_budget_grants" or original.column!="grant_json"
            or original.key_columns!=("lease_id","version") or original.key!=task.metadata[:2]
            or original.key!=(policy.lease_id,policy.grant_version)or kind!="budget-grant.v1"
            or signer is not r.graph._GraphCoordinator__d11_issuer._signer
            or original.signer is not signer or original.signature_kind!=kind or original.signature!=task.metadata[2]):
        raise AuthorityUnavailable("Drive dose signature escaped its actual fixed policy task")
    with runtime_storage_quantum_v3(r.db)as meter:task.require_metadata_v3(meter)
    if complete and (not original.complete or signature!=original.signature
            or verifier is not original.signature_state or original.signature_bytes!=original.byte_count):
        raise AuthorityUnavailable("Drive dose signature lacks actual complete HMAC EOF")
    return original

def read_bound_drive_dose_grant_v3(reader,lease_id):
    from .current_method_learning_read_v3 import _need_method_input
    r=_drive_reader_v3(reader)
    _,policy=_drive_policy_v3(r)
    if lease_id!=policy.lease_id or lease_id==r.parent_budget_lease_ref:
        raise AuthorityUnavailable("Drive dose read escaped actual distinct policy lease")
    identity=("drive_dose_grant",lease_id);task=r.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(r,identity)
    if type(task)is not DriveDoseGrantTaskV3 or task.owner is not r:
        raise AuthorityUnavailable("Drive dose grant is not this actual Work EOF")
    with runtime_storage_quantum_v3(r.db)as meter:task.require_metadata_v3(meter)
    if not task.column.signature_verified:raise AuthorityUnavailable("Drive dose HMAC EOF is unavailable")
    from .issuers import BudgetLeaseGrant
    raw=task.column.json_v3();raw["allowed_work_kinds"]=tuple(raw["allowed_work_kinds"]);grant=BudgetLeaseGrant(**raw)
    if ((grant.grant_id,grant.version,grant.lease_id)!=(policy.grant_id,policy.grant_version,policy.lease_id)
            or (grant.bot_id,grant.persona_id)!=r.namespace.as_tuple or policy.work_kind not in grant.allowed_work_kinds
            or grant.valid_until_utc<=r.frame_fields[2]):
        raise AuthorityUnavailable("Drive dose grant identity/work/namespace/deadline differs")
    return True,grant

def require_drive_input_selector_v3(reader,request):
    r=_drive_reader_v3(reader)
    table,columns,keycols,key=request
    if table=="graph_d11_life_originals_v1" and (len(key)!=4 or key[2]!=KIND):return False
    if table=="graph_d04_originals_v3" and (len(key)!=4 or key[2]!="semantic_mapping"):return False
    selection=_DRIVE_SELECTIONS_V3.get(r)
    if selection is None:raise AuthorityUnavailable("Drive fixed point lacks its actual derived Sourcequalified selection")
    mapping_ref,ids,keys,versions,clock=selection
    table,columns,keycols,key=request
    if table=="graph_d04_originals_v3":
        expected=(table,("payload_json","payload_digest"),("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,"semantic_mapping",mapping_ref))
    elif table=="graph_d11_life_originals_v1":
        expected=(table,_DRIVE_ORIGINAL_COLUMNS_V3,("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,KIND,ids["original"]))
    elif table=="graph_dependency_edges":
        if (tuple(columns)!=("dependency_revision",)or tuple(keycols)!=("dependent_token","dependency_token","edge_kind","operation_id")
                or len(key)!=4 or key[0]not in keys or key[1]not in versions
                or tuple(key[2:])!=("historical_provenance",ids["operation"])):
            raise AuthorityUnavailable("Drive provenance edge escaped actual derived members/read set")
        return True
    else:return False
    if (table,tuple(columns),tuple(keycols),tuple(key))!=expected:
        raise AuthorityUnavailable("Drive original prior escaped its exact derived metadata identity")
    return True

class PreparedNumericDriveInputsV3:
    def __init__(self,reader,context,before,adopted,clock,keys,installed,acceptance,mapping_ref,mapping_prior,life_prior,points,clock_rows,dose_task):
        self.reader,self.work,self.operation,self.selection=reader,reader.work,reader.operation,reader.selection_digest
        self.context,self.before,self.adopted,self.clock=context,before,adopted,clock
        self.keys,self.installed,self.acceptance,self.mapping_ref=keys,installed,acceptance,mapping_ref
        self.mapping_prior,self.life_prior=mapping_prior,life_prior
        self.points,self.clock_rows,self.dose_task=tuple(points),tuple(clock_rows),dose_task
        self.frame_fields=reader.frame_fields;self.before_stamp=reader.graph_stamp
        _DRIVE_INPUTS_V3[self]=self._identity_v3()
    def _identity_v3(self):
        return (self.reader,self.work,self.operation,self.selection,self.context,self.before,self.adopted,self.clock,
            self.keys,self.installed,self.acceptance,self.mapping_ref,self.mapping_prior,self.life_prior,
            self.points,self.clock_rows,self.dose_task,self.frame_fields,self.before_stamp)
    def require_stage_v3(self,db,stage):
        from .current_method_learning_read_v3 import _method_active,_READERS
        r=self.reader;issued=_STAGES.get(id(stage))
        if (_DRIVE_INPUTS_V3.get(self)!=self._identity_v3()or r not in _READERS or _method_active(db)is not r
                or r.work is not self.work or r.operation is not self.operation or self.operation.closed
                or not r.inputs_sealed or not r.business_started or issued is None or issued[0]()is not stage or issued[1]is not db
                or type(stage)is not LifeNumericDriveStageV1 or stage.request!=r.request
                or stage.frame.envelope.identity!=self.frame_fields[0].identity
                or stage.frame.snapshot!=self.frame_fields[1]or stage.frame.owner_guard!=self.frame_fields[3]
                or stage.context.original!=self.context or stage.context.before!=self.before
                or stage.original.clock!=self.clock or stage.original.mapping_ref!=self.mapping_ref
                or stage.original.appraisal_acceptance_digest!=self.acceptance.digest
                or {w.key.token for w in stage.mapping_stage.writes}!=set(self.keys)
                or stage.mapping_stage.proofs!=(self.acceptance,self.installed)
                or not {v.key.token for v in stage.mapping_stage.read_versions if v.revision>0 and v.key.token not in self.keys}
                    <=set(_DRIVE_SELECTIONS_V3[r][3])):
            raise AuthorityUnavailable("Drive fresh WRITE stage differs from actual retained Source EOF")
        return self

def capture_prepared_numeric_drive_inputs_v3(reader):
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .domain_production_registry_v1 import installed_operation_v1,installed_readers_for_operation_v1
    from .d06_life_numeric_task_v1 import require_current_life_numeric_appraisal_acceptance_v1
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    from .d04_semantic_mapping_v3 import evidence_payload_v3
    from .dispatch_current_inventory_v3 import _heap
    r=_drive_reader_v3(reader)
    if r.read_finished:raise AuthorityUnavailable("Drive preparation requires actual unfinished current READ")
    frame=CurrentOperationFrameV1(*r.frame_fields)
    readers=installed_readers_for_operation_v1(r.graph,installed_operation_v1(OPERATION),scope=r.fence.scope,owner_guard=r.owner_guard)
    context,before,adopted,clock,keys=_plan_inputs(r.db,r.namespace,r.request)
    current=read_current_life_numeric_context_v1(r.db,frame=frame,
        request=PrepareLifeNumericContextRequestV1(r.request.episode_ref,r.request.causal_operation_id),installed_readers=readers)
    if current.original!=context or current.before!=before:raise AuthorityUnavailable("Drive actual READ context/before differs")
    acceptance=require_current_life_numeric_appraisal_acceptance_v1(r.db,frame=frame,context=current,
        appraisal_ref=r.request.appraisal_ref,installed_readers=readers)
    installed=readers.life_numeric_mapping_reader(r.db,r.namespace)
    mapping_ref="d04-mapping:"+canonical_digest({"appraisal_acceptance":acceptance.digest,
        "mapping_installation":installed.digest,"clock":evidence_payload_v3(clock)})
    ids=life_numeric_drive_ids_v1(r.namespace,r.request.episode_ref,r.request.appraisal_ref)
    refs=frozenset(key.token for key in keys);versions={v.key.token:v.revision for v in frame.snapshot.versions if v.revision>0 and v.key.token not in refs}
    _DRIVE_SELECTIONS_V3[r]=(mapping_ref,ids,refs,MappingProxyType(versions),clock)
    _,mapping_prior=read_bound_method_learning_attachment_v3(r.db,table="graph_d04_originals_v3",
        columns=("payload_json","payload_digest"),key_columns=("bot","persona","kind","original_ref"),
        key=(*r.namespace.as_tuple,"semantic_mapping",mapping_ref))
    _,life_prior=read_bound_method_learning_attachment_v3(r.db,table="graph_d11_life_originals_v1",
        columns=_DRIVE_ORIGINAL_COLUMNS_V3,key_columns=("bot","persona","kind","original_ref"),
        key=(*r.namespace.as_tuple,KIND,ids["original"]))
    if mapping_prior is not None and (canonical_serialize(json.loads(mapping_prior[0]))!=mapping_prior[0]
            or canonical_digest(json.loads(mapping_prior[0]))!=mapping_prior[1]):
        raise AuthorityUnavailable("Drive mapping prior canonical EOF differs")
    if life_prior is not None:
        from .d11_life_preparation_v1 import SIGN_KIND
        raw=json.loads(life_prior[1])
        if life_prior[0]!=ids["operation"]or canonical_serialize(raw)!=life_prior[1]or canonical_digest(raw)!=life_prior[2]:
            raise AuthorityUnavailable("Drive signed prior canonical EOF differs")
        readers.issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,KIND,ids["original"],life_prior[2])),life_prior[3])
    for ref in sorted(refs):
        for token,revision in sorted(versions.items()):
            _,edge=read_bound_method_learning_attachment_v3(r.db,table="graph_dependency_edges",columns=("dependency_revision",),
                key_columns=("dependent_token","dependency_token","edge_kind","operation_id"),
                key=(ref,token,"historical_provenance",ids["operation"]))
            if edge is not None and edge!=(revision,):raise AuthorityUnavailable("Drive existing provenance edge differs")
    assembly,policy=_drive_policy_v3(r)
    if policy.lease_id!=r.parent_budget_lease_ref:read_bound_drive_dose_grant_v3(r,policy.lease_id)
    dose_task=r.budget_task if policy.lease_id==r.parent_budget_lease_ref else r.attachments[("drive_dose_grant",policy.lease_id)]
    clock_rows=[]
    with runtime_storage_quantum_v3(r.db)as meter:
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_character_clocks",_CLOCK_COLUMNS_V3,
            "mapping_id=? AND version=?",(clock.mapping_id,clock.mapping_version))
        latest=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_character_clocks",("version",),
            "mapping_id=? ORDER BY version DESC",(clock.mapping_id,))
        if row is None or latest!=(clock.clock_head_version,):raise AuthorityUnavailable("Drive current clock header differs")
        clock_rows.extend((("runtime_character_clocks",_CLOCK_COLUMNS_V3,"mapping_id=? AND version=?",(clock.mapping_id,clock.mapping_version),row),
            ("runtime_character_clocks",("version",),"mapping_id=? ORDER BY version DESC",(clock.mapping_id,),latest)))
    points=[(p.table,p.key_columns,p.key,p.metadata_columns,p.metadata)for p in r.points.values()if p.complete]
    capsule=PreparedNumericDriveInputsV3(r,context,before,adopted,clock,refs,installed,acceptance,mapping_ref,mapping_prior,life_prior,points,clock_rows,dose_task)
    r.operation.retain(_heap((context,before,adopted,clock,refs,mapping_prior,life_prior,points,clock_rows))*2+65536)
    r.prepared_numeric_drive_inputs_v3=capsule
    return capsule

def bind_prepared_numeric_drive_stage_v3(db,stage):
    from .current_method_learning_read_v3 import _method_active,_require_current_general_method_source_write_phase_v1
    r=_method_active(db)
    if r is None:return
    capsule=r.prepared_numeric_drive_inputs_v3
    capsule.require_stage_v3(db,stage)
    phase=_require_current_general_method_source_write_phase_v1(r)
    identity=id(stage)
    _DRIVE_STAGE_INPUTS_V3[identity]=(weakref.ref(stage,lambda _:_DRIVE_STAGE_INPUTS_V3.pop(identity,None)),capsule,phase[1])

@contextmanager
def bind_active_numeric_drive_inputs_v3(db,*,witness,receipt):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db);capsule=r.prepared_numeric_drive_inputs_v3
    capsule.require_stage_v3(db,witness.stage)
    registered=_DRIVE_STAGE_INPUTS_V3.get(id(witness.stage))
    if registered is None or registered[0]()is not witness.stage or registered[1]is not capsule or registered[2]is not witness.scope:
        raise AuthorityUnavailable("Drive ACTIVE writer differs from registered fresh WRITE stage")
    with runtime_storage_quantum_v3(db)as meter:
        for table,keycols,key,cols,expected in capsule.points:
            actual=_runtime_bounded_fixed_row_v3(db,meter,table,cols," AND ".join(n+"=?"for n in keycols),key)
            if table=="graph_atoms"and key[0]in capsule.keys:continue
            if actual!=expected:raise AuthorityUnavailable("Drive ACTIVE original metadata changed after actual EOF")
        for table,cols,where,key,expected in capsule.clock_rows:
            if _runtime_bounded_fixed_row_v3(db,meter,table,cols,where,key)!=expected:
                raise AuthorityUnavailable("Drive ACTIVE clock changed after actual frozen EOF")
    token=_DRIVE_ACTIVE_V3.set((capsule,witness,receipt))
    try:yield capsule
    finally:_DRIVE_ACTIVE_V3.reset(token)

def require_active_numeric_drive_inputs_v3(db,witness,stage,receipt):
    from .domain_production_commit_v1 import _ACTIVE
    active=_DRIVE_ACTIVE_V3.get()
    if (active is None or active[1]is not witness or active[2]is not receipt or _ACTIVE.get(id(witness))is not witness
            or witness.stage is not stage or witness.scope.operation!="write"or not db.in_transaction
            or not witness.graph._GraphCoordinator__store._lock._is_owned()):
        raise AuthorityUnavailable("Drive record requires actual private ACTIVE WRITE inputs")
    active[0].require_stage_v3(db,stage)
    return active[0]

def release_prepared_numeric_drive_inputs_v3(reader):
    _DRIVE_SELECTIONS_V3.pop(reader,None)
    peak=_DRIVE_RECHECKS_V3.pop(reader,None)
    if peak is not None:peak.value=None
    capsule=reader.prepared_numeric_drive_inputs_v3
    if capsule is None:return
    _DRIVE_INPUTS_V3.pop(capsule,None)
    for key,record in tuple(_DRIVE_STAGE_INPUTS_V3.items()):
        if record[1]is capsule:_DRIVE_STAGE_INPUTS_V3.pop(key,None)
    capsule.context=capsule.before=capsule.adopted=capsule.installed=capsule.acceptance=None
    capsule.mapping_prior=capsule.life_prior=capsule.points=capsule.clock_rows=capsule.frame_fields=capsule.dose_task=None
    reader.prepared_numeric_drive_inputs_v3=None

_DRIVE_RECHECKS_V3=WeakKeyDictionary()

class _DriveMetadataPeakV3:
    def __init__(self,reader):
        self.reader,self.value=reader,None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .dispatch_current_inventory_v3 import _heap
        return _heap(self.value)+256

def _drive_metadata_row_v3(reader,meter,table,columns,where,key):
    from .current_method_learning_read_v3 import require_actual_source_owner_metadata_work_v1
    from .c09_paged_sql_v2 import _quote
    r=require_actual_source_owner_metadata_work_v1(reader)
    if r.operation_kind!=OPERATION:raise AuthorityUnavailable("Drive metadata peak requires exact actual Method Work")
    peak=_DRIVE_RECHECKS_V3.get(r)
    if peak is None:peak=_DriveMetadataPeakV3(r);_DRIVE_RECHECKS_V3[r]=peak
    lengths=r.db.execute("SELECT "+",".join("length(CAST("+_quote(n)+" AS BLOB))"for n in columns)
        +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",key).fetchone()
    meter.charge_read(8*len(columns))
    if lengths is None:
        peak.value=None;r.operation.refresh_retained_state_v3(peak);return None
    amount=sum(n or 0 for n in lengths)
    meter.require_available(amount+256)
    r.operation.reserve_retained_state_growth_v3(peak,amount*8+4096)
    peak.value=meter.read_fixed_row(r.db,table,columns,where,key)
    r.operation.finish_retained_state_growth_v3(peak)
    return peak.value

def recheck_drive_numeric_metadata_header_v3(task,meter):
    from .current_life_numeric_metadata_v1 import NumericMetadataTaskV1
    r=task.reader
    if type(task)is not NumericMetadataTaskV1 or r.attachments.get(("numeric_owner_metadata",task.identity))is not task:
        raise AuthorityUnavailable("Drive metadata header lacks exact actual fixed task registry")
    return _drive_metadata_row_v3(r,meter,task.table,task.header_columns,
        " AND ".join(n+"=?"for n in task.key_columns),task.key)

def recheck_drive_numeric_source_header_v3(reader,meter,task):
    from .current_method_learning_read_v3 import _GENERAL_METHOD_SOURCE_TASKS_V1
    if (_GENERAL_METHOD_SOURCE_TASKS_V1.get(reader,{}).get(task.key.token)is not task or task.reader()is not reader
            or NamespaceId.from_key(task.key)!=reader.namespace):
        raise AuthorityUnavailable("Drive Source header lacks exact actual ancestor task registry")
    return _drive_metadata_row_v3(reader,meter,"graph_atoms",("revision","valid","value_cell_id"),
        "token=? AND bot=? AND persona=?",(task.key.token,*reader.namespace.as_tuple))

def recheck_drive_numeric_point_header_v3(task,meter):
    from .current_method_learning_read_v3 import _MethodPointReadV3
    r=task.owner
    if type(task)is not _MethodPointReadV3 or r.points.get(task.request)is not task:
        raise AuthorityUnavailable("Drive point header lacks exact actual fixed EOF task registry")
    return _drive_metadata_row_v3(r,meter,task.table,task.metadata_columns,
        " AND ".join(n+"=?"for n in task.key_columns),task.key)


def record_current_drive_mapping_original_v3(db,mapping_stage,witness):
    stage=witness.stage
    active=_DRIVE_ACTIVE_V3.get()
    if active is None:raise AuthorityUnavailable("Drive mapping requires actual ACTIVE writer")
    capsule=require_active_numeric_drive_inputs_v3(db,witness,stage,active[2])
    if (stage.mapping_stage is not mapping_stage or mapping_stage.original_ref!=capsule.mapping_ref
            or mapping_stage.clock!=capsule.clock):
        raise AuthorityUnavailable("Drive mapping record escaped actual selected typed mapping/clock")
    from .d06_life_numeric_commit_v1 import require_current_life_numeric_drive_write_v3
    require_current_life_numeric_drive_write_v3(db,witness=witness,stage=stage,receipt=active[2],writes=mapping_stage.writes)
    raw=json.loads(mapping_stage.original_payload_json)
    wire=canonical_serialize(raw);digest=canonical_digest(raw)
    if wire!=mapping_stage.original_payload_json or digest!=mapping_stage.original_digest:
        raise AuthorityUnavailable("Drive typed mapping original canonical digest differs")
    key=(*mapping_stage.namespace.as_tuple,"semantic_mapping",mapping_stage.original_ref)
    with runtime_storage_quantum_v3(db)as meter:
        actual=_runtime_bounded_fixed_row_v3(db,meter,"graph_d04_originals_v3",("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",key)
    prior=None if capsule.mapping_prior is None else (capsule.mapping_prior[1],)
    if actual!=prior:raise AuthorityUnavailable("Drive mapping prior changed after actual EOF")
    if capsule.mapping_prior is not None:
        if capsule.mapping_prior!=(wire,digest):raise AuthorityUnavailable("Drive immutable mapping prior differs")
    else:db.execute("INSERT INTO graph_d04_originals_v3 VALUES(?,?,?,?,?,?)",(*key,wire,digest))
    return digest
