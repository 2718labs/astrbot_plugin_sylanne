"""Closed original-result shape for the independent Life numerical appraisal worker.

Requests are locators, never read permissions. A service must separately load
the actual prepared/acquired originals, current Owner/Source qualifications,
egress ledger, terminal and paid cost before returning this response. A model
terminal does not establish a numeric adoption COMMIT or certified intervals.
"""
from dataclasses import dataclass, fields
import math

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2
from .v2_model_egress_wire import to_wire as terminal_wire, from_wire as terminal_from_wire

SCHEMA = 'd06.internal-life-numeric-model-result-read.v1'
PURPOSE = 'internal_life_numeric_consolidation_v1'


def _sha(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Life model-result original commitment differs')


def life_numeric_read_attempt_id_v1(consumer_operation_id, attempt):
    identifier(consumer_operation_id,'consumer_operation_id')
    if type(attempt) is not int or not 1<=attempt<=64:
        raise ValueError('Life model-result attempt is outside its finite sequence')
    return 'life-numeric-result-read:'+canonical_digest({
        'schema':SCHEMA,'consumer_operation_id':consumer_operation_id,'attempt':attempt})[:48]


@dataclass(frozen=True, slots=True)
class LifeNumericModelResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    episode_ref: str
    occurrence_digest: str
    causal_operation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    prepared_digest: str
    model_request_digest: str
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = PURPOSE
    schema: str = SCHEMA

    def __post_init__(self):
        from ..runtime.d06_internal_life_episode_v2 import EPISODE
        if (self.schema!=SCHEMA or self.purpose!=PURPOSE or type(self.namespace) is not NamespaceId):
            raise ValueError('Life model-result reader scope differs')
        for name in ('authority_id','authority_namespace','installation_id','causal_operation_id',
                'job_id','acquire_operation_id','original_operation_id','call_id','consumer_operation_id','read_attempt_id'):
            identifier(getattr(self,name),name)
        if type(self.episode_ref) is not str or len(self.episode_ref)>4096:
            raise ValueError('Life model-result Episode locator differs')
        episode=AtomKey.from_token(self.episode_ref)
        if episode.type_name!=EPISODE or NamespaceId.from_key(episode)!=self.namespace:
            raise ValueError('Life model-result Episode type/namespace differs')
        for value in (self.occurrence_digest,self.binding_digest,self.prepared_digest,self.model_request_digest):_sha(value)
        suffix=self.job_id.removeprefix('life-numeric-job:')
        if (self.job_id!='life-numeric-job:'+suffix or len(suffix)!=48
                or any(c not in '0123456789abcdef' for c in suffix)
                or (self.original_operation_id,self.acquire_operation_id,self.call_id,self.consumer_operation_id)!=
                    ('life-numeric-prepare:'+suffix,'life-numeric-acquire:'+suffix,
                     'life-numeric-call:'+suffix,'life-numeric-adopt:'+suffix)
                or not any(self.read_attempt_id==life_numeric_read_attempt_id_v1(self.consumer_operation_id,n)
                    for n in range(1,65))):
            raise ValueError('Life model-result selector is outside its original once family')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class LifeNumericModelResultReadV1:
    request: LifeNumericModelResultReadRequestV1
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    read_at_utc: float
    current_scope_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        request,observation,receipt=self.request,self.observation,self.terminal_receipt
        _sha(self.current_scope_digest)
        if (self.schema!=SCHEMA or type(request) is not LifeNumericModelResultReadRequestV1
                or type(observation) is not ModelEgressObservationV1 or type(receipt) is not ModelTerminalReceiptV2
                or observation.status!='completed' or type(self.read_at_utc) not in (int,float)
                or not math.isfinite(self.read_at_utc) or self.read_at_utc<=0
                or (observation.authority_id,observation.namespace,observation.operation_id,
                    observation.call_id,observation.request_digest)!=
                    (request.authority_id,request.authority_namespace,request.acquire_operation_id,
                     request.call_id,request.model_request_digest)
                or (receipt.call_id,receipt.request_digest,receipt.observation_digest,receipt.installation_id)!=
                    (request.call_id,request.model_request_digest,observation.digest,request.installation_id)):
            raise ValueError('Life actual completed model result/terminal differ')

    def require_original(self,intent,prepared,frozen,binding):
        """Structural comparison only; arguments must come from authenticated SQL."""
        from ..runtime.d06_life_numeric_task_v1 import InternalLifeNumericPreparedV1
        from ..model_broker.internal_life_numeric_v1 import FrozenInternalLifeNumericRequestV1
        from ..runtime.d06_life_numeric_worker_v1 import LifeNumericWorkerBindingV1
        request=self.request
        if (type(intent) is not ModelEgressIntentV1 or type(prepared) is not InternalLifeNumericPreparedV1
                or type(frozen) is not FrozenInternalLifeNumericRequestV1
                or type(binding) is not LifeNumericWorkerBindingV1
                or binding.prepared_digest!=prepared.digest or request.prepared_digest!=prepared.digest
                or binding.namespace!=prepared.namespace or binding.job_id!=prepared.job_id
                or frozen.digest!=prepared.frozen_digest
                or frozen.identity.episode_ref!=prepared.episode_ref
                or (request.namespace,request.installation_id,request.episode_ref,request.occurrence_digest,
                    request.causal_operation_id,request.job_id,request.original_operation_id,
                    request.acquire_operation_id,request.call_id,request.binding_digest)!=
                    (prepared.namespace,prepared.installation_id,prepared.episode_ref,prepared.occurrence_digest,
                     prepared.causal_operation_id,prepared.job_id,
                     prepared.prepare_operation_id,prepared.acquire_operation_id,prepared.call_id,binding.digest)
                or (intent.authority_id,intent.namespace,intent.job_id,intent.operation_id,
                    intent.acquire_operation_id,intent.call_id,intent.request_digest,intent.binding_digest)!=
                    (request.authority_id,request.authority_namespace,prepared.job_id,prepared.acquire_operation_id,
                     prepared.acquire_operation_id,prepared.call_id,request.model_request_digest,binding.digest)
                or self.observation.subject!=intent.subject or intent.subject!=binding.worker_subject):
            raise ValueError('Life delivered result differs from its actual occurrence/prepared once call')


def life_numeric_result_to_wire_v1(value):
    if type(value) is LifeNumericModelResultReadRequestV1:return plain_v1(value)
    if type(value) is not LifeNumericModelResultReadV1:raise TypeError('closed Life model-result DTO required')
    data=plain_v1(value)
    from .v2_model_egress_contract import model_observation_to_wire_v1
    data['observation']=model_observation_to_wire_v1(value.observation)
    data['terminal_receipt']=terminal_wire(value.terminal_receipt)
    return data


def _shape(raw,kind):
    if type(raw) is not dict or set(raw)!={field.name for field in fields(kind)}:
        raise ValueError('Life model-result wire exact fields differ')
    return dict(raw)


def life_numeric_result_from_wire_v1(raw,kind):
    if kind not in (LifeNumericModelResultReadRequestV1,LifeNumericModelResultReadV1):
        raise ValueError('unsupported Life model-result wire type')
    data=_shape(raw,kind)
    if kind is LifeNumericModelResultReadRequestV1:
        data['namespace']=NamespaceId(**_shape(data['namespace'],NamespaceId))
    else:
        data['request']=life_numeric_result_from_wire_v1(data['request'],LifeNumericModelResultReadRequestV1)
        from .v2_model_egress_contract import model_observation_from_wire_v1
        data['observation']=model_observation_from_wire_v1(data['observation'])
        if len(data['observation'].usage)>64 or len(data['observation'].cost)>64:
            raise ValueError('Life model-result observation amount pairs differ')
        data['terminal_receipt']=terminal_from_wire(data['terminal_receipt'],ModelTerminalReceiptV2)
    result=kind(**data)
    if canonical_serialize(life_numeric_result_to_wire_v1(result))!=canonical_serialize(raw):
        raise ValueError('Life model-result wire is noncanonical')
    return result


from dataclasses import dataclass, replace, asdict
from datetime import datetime
import json
import math
import sqlite3

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..model_broker.internal_life_numeric_v1 import (
    WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST,
)
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOwnerGuardV1, ProductionQueryCoverageV1,
    ProductionOperationLimitsV1,
)
from ..runtime.d06_life_numeric_worker_v1 import _read_committed_life_numeric_request_originals_v1
from ..runtime.d06_life_numeric_task_v1 import (
    PrepareInternalLifeNumericRequestV1, read_plan_life_numeric_prepare_v1,
)
from ..runtime.d06_internal_life_encoding_v1 import (
    EncodeInternalLifeRequestV1, read_current_internal_life_encoding_cause_v1,
)
from ..runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from ..runtime.domain_production_read_plans_v1 import read_current_domain_original_refs_v1
from ..runtime.jobs import get_job
from ..runtime.d11_types import job_graph_write
from ..runtime.budget import require_budget_family_admissible
from ..host.model_workflows_v3 import AdminModelWorkflowsV3
from ..host.model_workflows_v4 import AdminModelWorkflowsV4
from ..host.model_workflows_v5 import AdminModelWorkflowsV5
from ..host.model_workflows_v6 import AdminModelWorkflowsV6
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from .v2_model_egress_contract import ModelEgressIntentV1


@dataclass(frozen=True, slots=True)
class LifeNumericCurrentModelGraphV1:
    prepared: object
    binding: object
    frozen: object
    job: object
    request: object
    owner_guard: object
    storage_admission: object
    current_scope_digest: str
    valid_until_utc: float


def _current_frame(db, prepared, request, readers, now):
    """Finite complete read material, never an installed issuance marker."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise ValueError('Life model current read requires one actual SQL snapshot')
    ns = prepared.namespace
    locator = PrepareInternalLifeNumericRequestV1(prepared.episode_ref,
        prepared.causal_operation_id)
    plan = read_plan_life_numeric_prepare_v1(db, namespace=ns, activity_id=prepared.activity_id,
        operation_kind='prepare_internal_life_numeric', request=locator)
    limits = ProductionOperationLimitsV1()
    epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', ns.as_tuple).fetchone()
    barriers = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?', ns.as_tuple).fetchone()
    if epoch is None or barriers is None:
        raise ValueError('Life model current Graph epochs are missing')
    atoms = {}
    def load(key):
        if type(key) is not AtomKey or NamespaceId.from_key(key) != ns:
            raise ValueError('Life model current input crossed namespace')
        if key not in atoms:
            if len(atoms) >= limits.max_graph_heads:
                raise ValueError('Life model complete read inventory exceeds installed bound; HOLD')
            row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
                (key.token, *ns.as_tuple)).fetchone()
            atoms[key] = _atom(key, row)
        return atoms[key]
    pages = []
    query = QueryEpoch(ns, 'namespace', epoch[0])
    for kind in plan.fixed_type_ids:
        rows = db.execute('SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? '
            'ORDER BY token LIMIT ?', (*ns.as_tuple, kind, limits.max_query_rows + 1)).fetchall()
        if len(rows) > limits.max_query_rows:
            raise ValueError('Life model complete query inventory exceeds installed bound; HOLD')
        versions = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in rows)
        for version in versions: load(version.key)
        pages.append(ProductionQueryCoverageV1(query, kind, versions, True, None))
    for key in plan.exact_keys: load(key)
    # The installed read plan already derives every Source's own Access and
    # absent correction head plus its ancestors from real current provenance.
    # Require every actual acquired read as well; never silently trim a row.
    for version in request.envelope.version_guard.read_versions:
        if load(version.key).revision != version.revision:
            raise ValueError('Life model acquired read version changed')
    snapshot = GraphSnapshot(tuple(sorted(atoms.values(), key=lambda atom: atom.key.token)),
        (NamespaceEpoch(*ns.as_tuple, epoch[0]),))
    owner = load(owner_grant_key(*ns.as_tuple))
    if not owner.valid or owner.revision != 1:
        raise ValueError('Life model current Owner grant is not active')
    guard = ProductionOwnerGuardV1(owner.key.token, owner.revision, canonical_digest(owner.value), prepared.owner_head_digest)
    envelope = replace(request.envelope, version_guard=replace(request.envelope.version_guard,
        read_versions=snapshot.versions, query_epochs=(query,), access_epoch=barriers[0], delete_epoch=barriers[1]))
    originals = read_current_domain_original_refs_v1(db, namespace=ns, plan=plan, installed_readers=readers)
    return CurrentOperationFrameV1(envelope, snapshot, now, guard, prepared.activation_generation,
        tuple(pages), (), originals, limits)


def _atom(key, row):
    if row is None:
        return GraphAtom(key, 0, {}, False)
    if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not int or row[0] < 1
            or type(row[1]) is not str or type(row[2]) is not int or row[2] not in {0, 1}):
        raise ValueError('Life model actual SQL head shape/revision/valid differs')
    value = json.loads(row[1])
    if type(value) is not dict or canonical_serialize(value) != row[1]:
        raise ValueError('Life model actual SQL head bytes are not canonical')
    return GraphAtom(key, row[0], value, row[2] == 1)


class InstalledLifeNumericModelGraphReaderV1:
    """Exact installation components, not an externally supplied callback."""
    def __init__(self, *, owner_storage, structured_readers, bundle, read_subject):
        from ..host.authority_profile import AdminInstallationBundle
        workflows=bundle.model_workflows if type(bundle) is AdminInstallationBundle else None
        if (type(bundle) is not AdminInstallationBundle or type(read_subject) is not str
                or not read_subject.startswith("mtls:sha256:")
                or type(owner_storage) is not InstalledD12OwnerStorageAdmissionServiceV1
                or type(structured_readers) is not InstalledD06StructuredExperienceReadersV1
                or type(workflows) not in (AdminModelWorkflowsV3, AdminModelWorkflowsV4,
                    AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7) or workflows.life_numeric is None
                or structured_readers.resource_issuer is not structured_readers.issuer.resource_issuer):
            raise TypeError('actual installed Life Owner/original readers and workflow required')
        policy=bundle.installation_policy
        if (owner_storage.installation_id!=policy.installation_id
                or owner_storage.namespace_id!=policy.namespace
                or owner_storage.namespace!=policy.authority_namespace
                or owner_storage.holder!=policy.administrator_holder
                or owner_storage.fences.core is not owner_storage.core):
            raise ValueError('Life reader components belong to another actual installation')
        self.owner_storage, self.readers, self.workflows = owner_storage, structured_readers, workflows
        self.bundle,self.read_subject=bundle,read_subject

    def read(self, db, intent, now, *, allow_accounted_result=False):
        if (type(intent) is not ModelEgressIntentV1 or type(now) not in (float, int)
                or not math.isfinite(now) or type(allow_accounted_result) is not bool):
            raise ValueError('actual Life model input and trusted clock required')
        owner_service = self.owner_storage
        job = get_job(db, intent.job_id)
        if job is None or job.work_kind != WORK_KIND:
            raise ValueError('Life model once running job is missing')
        ns = NamespaceId(job.bot_id, job.persona_id)
        if ns != owner_service.namespace_id or intent.namespace != owner_service.namespace:
            raise ValueError('Life model selected installation/namespace differs')
        prepared, binding, request, adopted = _read_committed_life_numeric_request_originals_v1(db,
            namespace=ns, issuer=self.readers.issuer, job_id=job.job_id)
        # Refuse an already canceled/retired worker before constructing its
        # complete Source frame. The same signed acquisition was verified above;
        # all Source/Owner/deadline checks still apply to every live worker.
        if (job.phase != 'running' or job.operation_id != prepared.prepare_operation_id
                or job.fence != intent.worker_fence or job.fence != request.envelope.authority.worker_fence
                or job.cancel_epoch != 0 or job.lease_holder != intent.subject or job.lease_holder != binding.worker_subject
                or job.result_ref is not None or job.lease_expires_utc is None):
            raise ValueError('Life model installed workflow/current worker/input identity changed')
        frozen = prepared.frozen
        workflow = self.workflows.life_numeric
        with owner_service.fences._frozen() as (core_db, deletion, execution, _):
            anchor = owner_service.fences._current_locked(core_db, deletion, execution)
            head = owner_service._head_in_tx(core_db)
            actor, login = owner_service._background_identity_in_tx(core_db, head)
        metadata, grant, admission = owner_service._read_graph(owner_head=head, anchor=anchor)
        current = GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision '
            'FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?', ns.as_tuple).fetchone(), ns)
        epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', ns.as_tuple).fetchone()
        if current != metadata or current is None or epoch is None:
            raise ValueError('Life model selected current Graph/storage snapshot differs')
        req = current.requirements
        if ((req.authority_id, req.authority_namespace, req.activation_generation, req.graph_incarnation,
                req.revocation_epoch) != (intent.authority_id, intent.namespace, prepared.activation_generation,
                prepared.graph_incarnation, intent.authority_revocation_epoch)
                or (intent.authority_activation_generation, intent.authority_deletion_seq, intent.authority_execution_seq) !=
                    (anchor.activation_generation, anchor.deletion_seq, anchor.execution_seq)
                or (not allow_accounted_result and (current.graph_revision, epoch[0]) != (intent.graph_revision, intent.graph_epoch))
                or allow_accounted_result and (current.graph_revision < intent.graph_revision or epoch[0] < intent.graph_epoch)
                or head.guard.authorization_head.removeprefix('sha256:') != prepared.owner_head_digest
                or grant['principal'] != asdict(head.issue_operation.principal)
                or grant['activation_generation'] != prepared.activation_generation
                or 'consolidation' not in grant['purposes'] or prepared.audience[0] not in grant['audiences']
                or actor.actor_id != binding.owner_actor or login.principal != binding.owner_principal
                or head.issue_operation.principal!=binding.owner_principal
                or intent.subject!=binding.worker_subject or binding.worker_subject!=self.read_subject
                or binding.installation_id!=self.bundle.installation_policy.installation_id
                or binding.manifest_digest!=self.bundle.installation_policy.manifest_digest
                or binding.owner_guard.owner_head_digest!=head.guard.authorization_head.removeprefix("sha256:")
                or "workbench.create" not in grant["capabilities"]):
            raise ValueError('Life model actual Owner/actor/generation/current storage changed')
        # Qualification uses the actual Owner authority saved in the durable
        # acquisition. This is read material, never a rewritten model grant.
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_contracts import AuthorityContext
        owner_authority=decode_typed_production_value_v1(adopted['payload']['authority'],AuthorityContext)
        owner_request=replace(request,envelope=replace(request.envelope,authority=owner_authority))
        frame = _current_frame(db, prepared, owner_request, self.readers, float(now))
        from ..runtime.d06_life_numeric_task_v1 import _current
        from copy import copy
        current_readers = copy(self.readers)
        current_readers.life_numeric_bundle = self.bundle
        current_readers.life_numeric_owner_guard = head.guard
        _, _, context, current_frozen = _current(db, frame,
            PrepareInternalLifeNumericRequestV1(prepared.episode_ref, prepared.causal_operation_id), current_readers)
        if current_frozen != frozen:
            raise ValueError('Life numeric actual current context/appraisal input changed')
        if ((workflow.work_kind, workflow.purpose, workflow.template_version) != (WORK_KIND, 'consolidation', TEMPLATE_VERSION)
                or (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.max_output_tokens) !=
                    (frozen.appraisal.installation.provider_id, frozen.appraisal.installation.model_id, frozen.appraisal.installation.provider_config_digest, frozen.appraisal.installation.max_output_tokens)
                or (request.call_id, request.digest, request.identity.operation_id, request.prompt_template_digest) !=
                    (intent.call_id, intent.request_digest, prepared.acquire_operation_id, TEMPLATE_DIGEST)
                or (intent.operation_id, intent.acquire_operation_id, intent.binding_digest) !=
                    (prepared.acquire_operation_id, prepared.acquire_operation_id, binding.digest)
                or (intent.provider_id, intent.model_id, intent.provider_config_digest, intent.max_output_tokens) !=
                    (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.max_output_tokens)
                or request.payload != json.loads(frozen.canonical_wire)
                or request.envelope.authority.purpose != 'consolidation'
                or request.envelope.authority.audience != (prepared.audience[0],)
                or request.required_capabilities != frozenset(workflow.required_capabilities)
                or request.privacy_tier != workflow.privacy_tier or request.timeout_seconds != workflow.timeout_seconds
                or prepared.provider_config_ref != workflow.provider_config_ref
                or now >= min(binding.deadline_utc, request.envelope.deadline_utc,
                    datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace('Z', '+00:00')).timestamp())):
            raise ValueError('Life model installed workflow/current worker/input identity changed')
        quote = self.readers.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
        reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations '
            'WHERE lease_id=? AND operation_id=?', (quote.parent_budget_lease_ref, prepared.prepare_operation_id)).fetchone()
        reserve = db.execute("SELECT digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*ns.as_tuple, prepared.prepare_operation_id)).fetchone()
        allowed = {'settled'} if allow_accounted_result else {'reserved'}
        if (canonical_digest(quote) != prepared.quote_digest or quote.work_kind != WORK_KIND
                or quote.operation_id != prepared.prepare_operation_id or quote.resource_ref != prepared.provider_config_ref
                or reserve != (prepared.reservation_digest,) or reservation is None
                or reservation[:2] != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)))
                or reservation[2] not in allowed or now >= quote.valid_until_utc
                or (intent.budget_lease_id, intent.budget_reservation_operation_id, intent.budget_reservation_digest, intent.budget_ceiling) !=
                    (quote.parent_budget_lease_ref, prepared.prepare_operation_id, prepared.reservation_digest, tuple(sorted(quote.ceiling.items())))):
            raise ValueError('Life model actual signed quote/once reserve/settlement ledger changed')
        parent=self.readers.issuer.current_budget_grant(db,quote.parent_budget_lease_ref)
        if (WORK_KIND not in parent.allowed_work_kinds or now>=parent.valid_until_utc
                or WORK_KIND not in self.bundle.installation_policy.root_grant.allowed_work_kinds):
            raise ValueError('Life worker current Root budget capability expired or changed')
        if not allow_accounted_result: require_budget_family_admissible(db, quote.parent_budget_lease_ref)
        sources = tuple(sorted((v.key.owner.subject, v.revision) for v in request.envelope.version_guard.read_versions
            if v.key.type_name == 'memory.source' and v.revision > 0))
        accesses = tuple(sorted((v.key.owner.subject, v.revision) for v in request.envelope.version_guard.read_versions
            if v.key.type_name == 'memory.access' and v.revision > 0))
        if (intent.source_revisions != sources or intent.access_revisions != accesses
                or intent.source_refs != tuple(ref for ref, _ in sources)
                or (intent.access_epoch, intent.delete_epoch) !=
                    (frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)):
            raise ValueError('Life model Source/access closure differs from actual acquired input')
        atom = db.execute('SELECT value,valid FROM graph_atoms WHERE token=?', (job_graph_write(job).key.token,)).fetchone()
        if atom != (canonical_serialize(job_graph_write(job).value), 1):
            raise ValueError('Life model actual running-job projection changed')
        with owner_service.fences._frozen() as (core_db, deletion, execution, _):
            if (owner_service.fences._current_locked(core_db, deletion, execution) != anchor
                    or owner_service._head_in_tx(core_db) != head
                    or owner_service._background_identity_in_tx(core_db, head) != (actor, login)):
                raise ValueError('Life model actual Owner/paired identity changed during current read')
        scope_digest = canonical_digest({'schema':'d06.internal-life-numeric-current-model.v1',
            'prepared_digest':prepared.digest, 'worker_binding_digest':binding.digest, 'current_reads':frame.snapshot.versions,
            'query_coverage':frame.query_coverage, 'owner_guard':head.guard,
            'storage_admission':admission, 'source_rights':(intent.access_epoch,intent.delete_epoch)})
        valid_until = min(binding.deadline_utc, request.envelope.deadline_utc,
            datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp(),
            datetime.fromisoformat(job.lease_expires_utc.replace('Z', '+00:00')).timestamp(),
            quote.valid_until_utc, quote.deadline_utc, parent.valid_until_utc)
        return LifeNumericCurrentModelGraphV1(prepared, binding, frozen, job, request,
            head.guard, admission, scope_digest, valid_until)
