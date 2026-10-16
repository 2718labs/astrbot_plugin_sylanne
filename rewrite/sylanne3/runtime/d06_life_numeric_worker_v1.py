"""Actual Owner-to-installed-worker issuance for the independent numeric job."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..runtime_contracts import (NamespaceId, QueryEpoch, VersionedRef, CommitReceipt,
    canonical_digest, canonical_serialize, schema_hash)
from ..graph_types import GraphVersion
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..model_broker.internal_life_numeric_v1 import WORK_KIND, TEMPLATE_DIGEST, internal_life_numeric_ids_v1
from .d06_life_numeric_task_v1 import (_current, PrepareInternalLifeNumericRequestV1,
    read_life_numeric_prepared_v1, read_plan_life_numeric_prepare_v1)
from .d11_types import job_graph_write, TYPE_SCHEMA_HASHES
from .jobs import get_job, acquire_job
from .d11_life_preparation_v1 import _read, _record

OPERATION = 'acquire_internal_life_numeric'
PROPOSAL_SCHEMA = 'd11.internal-life-numeric-acquisition.v1'
PROPOSAL_HASH = schema_hash({'schema': PROPOSAL_SCHEMA,
    'job_schema': TYPE_SCHEMA_HASHES['runtime.job'], 'transition': 'Owner_authorized_TLS_worker_once'})
_ISSUED = {}
_STAGES = {}


@dataclass(frozen=True, slots=True)
class AcquireInternalLifeNumericRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        PrepareInternalLifeNumericRequestV1(self.episode_ref, self.causal_operation_id)


@dataclass(frozen=True, slots=True)
class LifeNumericWorkerBindingV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    worker_subject: str
    installation_grant_digest: str
    owner_principal: OwnerPrincipalV1
    owner_actor: str
    owner_lease_digest: str
    owner_guard: ProductionOwnerGuardV1
    target_admission_digest: str
    storage_admission_digest: str
    prepared_digest: str
    job_id: str
    acquire_operation_id: str
    call_id: str
    scope_commitment: str
    permit_commitment: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    activation_generation: int
    deadline_utc: float
    schema: str = 'd06.internal-life-numeric-worker-binding.v1'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        import math
        if (type(self.namespace) is not NamespaceId or type(self.owner_principal) is not OwnerPrincipalV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or self.schema != 'd06.internal-life-numeric-worker-binding.v1'):
            raise ValueError('Life numeric binding closed identity differs')
        suffix = self.job_id.removeprefix('life-numeric-job:')
        if (len(suffix) != 48 or any(c not in '0123456789abcdef' for c in suffix)
                or self.job_id != 'life-numeric-job:' + suffix
                or self.acquire_operation_id != 'life-numeric-acquire:' + suffix
                or self.call_id != 'life-numeric-call:' + suffix):
            raise ValueError('Life numeric binding independent once identity differs')
        for name in ('manifest_digest', 'installation_grant_digest', 'owner_lease_digest',
                'target_admission_digest', 'storage_admission_digest', 'prepared_digest',
                'scope_commitment', 'permit_commitment'):
            _sha(getattr(self, name))
        for name in ('installation_id', 'worker_subject', 'owner_actor', 'graph_incarnation'):
            if type(getattr(self, name)) is not str or not 1 <= len(getattr(self, name)) <= 512:
                raise ValueError('Life numeric binding reference differs')
        if (any(type(v) is not int or v < 1 for v in (self.graph_revision, self.graph_epoch, self.activation_generation))
                or type(self.deadline_utc) not in (int, float) or not math.isfinite(self.deadline_utc)):
            raise ValueError('Life numeric binding current versions/deadline differ')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def decode_life_numeric_worker_binding_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, LifeNumericWorkerBindingV1)
    if canonical_serialize(plain_v1(value)) != canonical_serialize(raw):
        raise ValueError('Life numeric binding noncanonical')
    return value


@dataclass(frozen=True, slots=True)
class _NumericIssuanceV1:
    runtime: object
    scope: object
    guard: object
    owner: object
    bundle: object
    grant: object


def issue_installed_life_numeric_worker_v1(runtime, scope, guard, owner):
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from ..graph_coordinator import OwnerLeaseBindingV1
    from ..host.v2_fence_port import V2FencePort
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_contracts import FenceScope
    if (type(runtime) is not InstalledDomainOperationRuntimeV1 or type(scope) is not FenceScope
            or type(owner) is not OwnerLeaseBindingV1 or type(guard) is not OwnerAuthorizationGuardV1):
        raise TypeError('Life numeric worker requires actual runtime/Owner fence')
    runtime._current()
    graph = runtime.graph
    port, assembly = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__d04_installed_joint_assembly
    if type(port) is not V2FencePort or assembly is None:
        raise ValueError('Life numeric worker requires its installed authenticated port')
    bundle, grant = assembly.admin_bundle, port.installation_grant
    policy = bundle.installation_policy
    workflow = getattr(bundle.model_workflows, 'life_numeric', None)
    if (workflow is None or workflow.work_kind != WORK_KIND or WORK_KIND not in policy.root_grant.allowed_work_kinds
            or (grant.authority_id, grant.installation_id, grant.manifest_digest, grant.administrator_holder) !=
               (policy.expected_authority_id, policy.installation_id, policy.manifest_digest, policy.administrator_holder)
            or (scope.namespace, scope.authority_namespace, scope.permit.subject, scope.permit.holder) !=
               (policy.namespace, policy.authority_namespace, grant.subject, grant.administrator_holder)
            or scope.operation != 'write' or scope.permit.operation != 'write'
            or scope.pinned_anchor != scope.permit.pinned_anchor
            or owner.namespace != scope.namespace or guard.namespace != scope.namespace
            or guard.installation_id != grant.installation_id or guard.authority_id != grant.authority_id
            or owner.authorization_head != guard.authorization_head
            or owner.authorization_revision != guard.authorization_revision
            or owner.revocation_epoch != guard.minimum_revocation_epoch or guard.minimum_revocation_revision != 0
            or guard.pending_revoke_operation_id is not None or 'workbench.create' not in owner.capabilities
            or 'consolidation' not in owner.purposes or port.validate_fence(scope) != scope.permit):
        raise ValueError('Life numeric worker delegation is outside actual installed Owner capability')
    issued = _NumericIssuanceV1(runtime, scope, guard, owner, bundle, grant)
    _ISSUED[id(issued)] = issued
    return issued


def require_installed_life_numeric_worker_v1(issued, frame=None):
    if (type(issued) is not _NumericIssuanceV1 or _ISSUED.get(id(issued)) is not issued
            or getattr(issued.runtime, '_active_life_numeric_issuance_v1', None) is not issued):
        raise ValueError('Life numeric worker needs its exact active private issuance')
    issued.runtime._current()
    graph = issued.runtime.graph
    if (graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not issued.bundle
            or graph._GraphCoordinator__content_fence_v2.installation_grant != issued.grant):
        raise ValueError('Life numeric installed identity changed')
    if frame is not None and (frame.envelope.authority.actor != issued.owner.actor
            or frame.owner_guard.owner_head_digest != issued.owner.authorization_head.removeprefix('sha256:')
            or frame.envelope.authority.namespace != issued.scope.namespace
            or frame.activation_generation != issued.scope.generation):
        raise ValueError('Life numeric Owner frame differs from actual delegation')
    return issued


def release_installed_life_numeric_worker_v1(issued):
    if _ISSUED.get(id(issued)) is issued: _ISSUED.pop(id(issued), None)


def read_plan_life_numeric_acquire_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not AcquireInternalLifeNumericRequestV1 or operation_kind != OPERATION:
        raise TypeError('Life numeric acquisition exact locator required')
    return read_plan_life_numeric_prepare_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind='prepare_internal_life_numeric',
        request=PrepareInternalLifeNumericRequestV1(request.episode_ref, request.causal_operation_id))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericAcquisitionStageV1:
    stage: object
    prepared: object
    frozen: object
    job: object
    request: object
    frame: object
    binding: LifeNumericWorkerBindingV1
    issuance: object


def stage_acquire_life_numeric_in_transaction_v1(db, *, frame, request, installed_readers):
    from .internal_life_worker_binding_v2 import owner_lease_commitment_v2
    from ..model_broker.broker import ModelCallRequest
    if type(request) is not AcquireInternalLifeNumericRequestV1:
        raise TypeError('Life numeric exact acquisition locator required')
    issued = require_installed_life_numeric_worker_v1(installed_readers.life_numeric_issuance, frame)
    bundle, workflow, context, frozen = _current(db, frame, request, installed_readers)
    ids = internal_life_numeric_ids_v1(frozen.identity)
    p = read_life_numeric_prepared_v1(db, namespace=context.original.namespace,
        issuer=installed_readers.issuer, job_id=ids['job'])
    if (p.frozen != frozen or bundle is not issued.bundle or frame.envelope.identity.operation_id != ids['acquire']
            or frame.envelope.identity.phase != OPERATION or p.owner_head_digest != frame.owner_guard.owner_head_digest):
        raise ValueError('Life numeric acquisition changed its actual prepared input/Owner')
    job = get_job(db, p.job_id)
    if job is None or job.phase != 'queued' or job.fence or job.cancel_epoch:
        raise ValueError('Life numeric once worker cannot be reacquired')
    if tuple(v for v in frame.snapshot.versions if v.key == job_graph_write(job).key) != (GraphVersion(job_graph_write(job).key, 1),):
        raise ValueError('Life numeric acquisition needs its actual queued graph job')
    deadline = min(frame.envelope.deadline_utc, datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp())
    owner, scope = issued.owner, issued.scope
    b = LifeNumericWorkerBindingV1(p.namespace, issued.grant.installation_id, issued.grant.manifest_digest,
        issued.grant.subject, canonical_digest(issued.grant), owner.principal, owner.actor,
        owner_lease_commitment_v2(owner), frame.owner_guard, canonical_digest(owner.target_admission),
        canonical_digest(owner.storage_admission), p.digest, p.job_id, ids['acquire'], p.call_id,
        canonical_digest(scope), canonical_digest(scope.permit), p.graph_incarnation,
        scope.graph_revision, scope.graph_epoch.revision, scope.generation, deadline)
    job = acquire_job(db, p.job_id, b.worker_subject,
        now_utc=datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace('+00:00', 'Z'),
        lease_seconds=min(3600, int(workflow.timeout_seconds) + 120))
    key = job_graph_write(job).key
    guard = replace(frame.envelope.version_guard,
        read_versions=tuple(GraphVersion(v.key, v.revision + 1) if v.key == key else v for v in frame.snapshot.versions),
        query_epochs=tuple(QueryEpoch(v.namespace, v.scope_ref, v.revision + 1) for v in frame.envelope.version_guard.query_epochs),
        resource_lease_versions=(VersionedRef(p.quote_id, 1),))
    envelope = replace(frame.envelope,
        identity=replace(frame.envelope.identity, phase='internal_life_numeric_v1'),
        authority=replace(frame.envelope.authority, actor=b.worker_subject, worker_fence=job.fence,
                          capability_ref='life-numeric-worker:' + b.digest),
        version_guard=guard, source_qualification=context.source_qualification,
        deadline_utc=deadline, monotonic_deadline=frame.envelope.monotonic_deadline - (frame.envelope.deadline_utc - deadline))
    model = ModelCallRequest(envelope, p.call_id, workflow.provider_id, workflow.model_id,
        frozenset(workflow.required_capabilities), workflow.privacy_tier, TEMPLATE_DIGEST,
        json.loads(frozen.canonical_wire), workflow.timeout_seconds, workflow.max_output_tokens)
    primary = stage_result_v1(frame, 'd11', OPERATION, request, writes=(job_graph_write(job),),
        provenance={'binding': plain_v1(b), 'binding_digest': b.digest, 'request_digest': model.digest},
        proposal_schema=PROPOSAL_SCHEMA, proposal_hash=PROPOSAL_HASH)
    validate_life_numeric_acquisition_proposal_v1(primary.proposals[0], frame.snapshot, b)
    result = LifeNumericAcquisitionStageV1(primary, p, frozen, job, model, frame, b, issued)
    identity = id(result)
    _STAGES[identity] = (weakref.ref(result, lambda _: _STAGES.pop(identity, None)), db,
        context, bundle, frozen.digest, installed_readers.issuer, installed_readers.resource_issuer, db.total_changes)
    return result


def validate_life_numeric_acquisition_proposal_v1(proposal, snapshot, binding):
    if (type(binding) is not LifeNumericWorkerBindingV1 or proposal.domain != 'd11'
            or proposal.proposal_schema != PROPOSAL_SCHEMA or proposal.proposal_schema_hash != PROPOSAL_HASH
            or proposal.envelope.identity.phase != OPERATION or len(proposal.typed_writes) != 1
            or proposal.envelope.identity.operation_id != binding.acquire_operation_id
            or proposal.envelope.authority.namespace != binding.namespace
            or proposal.envelope.authority.actor != binding.owner_actor
            or proposal.envelope.authority.purpose != 'consolidation'):
        raise ValueError('Life numeric acquisition proposal differs')
    write = proposal.typed_writes[0]
    # The actual private issuance verifier below proves the complete job;
    # this schema check additionally forbids unrelated runtime writes.
    prior = snapshot.get(write.key)
    if (write.key.type_name != 'runtime.job' or write.key.name != binding.job_id
            or NamespaceId.from_key(write.key) != binding.namespace
            or prior is None or prior.revision != 1 or not prior.valid
            or write.value.get('job_id') != binding.job_id or write.value.get('phase') != 'running'
            or write.value.get('work_kind') != WORK_KIND or write.value.get('fence') != 1
            or write.value.get('lease_holder') != binding.worker_subject):
        raise ValueError('Life numeric proposal is not its once TLS worker transition')
    return proposal


def verify_life_numeric_acquisition_in_transaction_v1(db, staged, readers):
    entry = _STAGES.get(id(staged))
    if entry is None or entry[0]() is not staged or entry[1] is not db or not db.in_transaction:
        raise ValueError('Life numeric acquisition lacks exact private issuance')
    require_installed_life_numeric_worker_v1(staged.issuance, staged.frame)
    p = staged.prepared
    if (db.total_changes != entry[7] or readers.life_numeric_bundle is not entry[3]
            or readers.issuer is not entry[5] or readers.resource_issuer is not entry[6]
            or staged.frozen.digest != entry[4]):
        raise ValueError('Life numeric acquisition qualification changed before CAS')
    from .d06_life_numeric_context_v1 import require_current_life_numeric_context_v1
    require_current_life_numeric_context_v1(entry[2], db=db, frame=staged.frame)
    bundle, frozen = entry[3], staged.frozen
    if (bundle is not staged.issuance.bundle or frozen != staged.frozen
            or get_job(db, p.job_id) != staged.job
            or read_life_numeric_prepared_v1(db, namespace=p.namespace, issuer=readers.issuer, job_id=p.job_id) != p
            or staged.binding.prepared_digest != p.digest
            or len(staged.stage.proposals) != 1
            or staged.stage.proposals[0].envelope != staged.frame.envelope
            or staged.stage.proposals[0].typed_writes != (job_graph_write(staged.job),)):
        raise ValueError('Life numeric acquired actual input/worker changed')
    validate_life_numeric_acquisition_proposal_v1(staged.stage.proposals[0], staged.frame.snapshot, staged.binding)
    return staged


def record_life_numeric_acquisition_after_cas_v1(db, *, staged, issuer, receipt):
    from .reply_model_job import reply_request_wire_v1
    from .domain_production_originals_v1 import _receipt_wire
    entry = _STAGES.get(id(staged))
    p, b = staged.prepared, staged.binding
    if (entry is None or entry[0]() is not staged or entry[1] is not db or not db.in_transaction
            or type(receipt) is not CommitReceipt or receipt.operation_id != b.acquire_operation_id
            or receipt.status != 'committed'):
        raise ValueError('Life numeric acquired originals require actual same-transaction CAS')
    actual = db.execute('SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*p.namespace.as_tuple, b.acquire_operation_id)).fetchone()
    write = job_graph_write(staged.job)
    history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=2', (write.key.token,)).fetchone()
    if (actual != (receipt.operation_digest, receipt.commit_seq)
            or receipt.write_versions != (GraphVersion(write.key, 2),)
            or history != (canonical_serialize(write.value), 1, b.acquire_operation_id)):
        raise ValueError('Life numeric acquisition CAS does not bind its exact worker job')
    for kind, value in (
        ('numeric_binding_v1', b),
        ('numeric_request_v1', {'schema': 'd06.internal-life-numeric-request.v1', 'prepared_digest': p.digest,
            'binding_digest': b.digest, 'request_digest': staged.request.digest,
            'wire': canonical_serialize(reply_request_wire_v1(staged.request.envelope, staged.request))}),
        ('numeric_acquire_commit_v1', {'schema': 'd06.internal-life-numeric-acquire-commit.v1',
            'prepared_digest': p.digest, 'binding_digest': b.digest, 'receipt': _receipt_wire(receipt),
            'request_digest': staged.request.digest, 'receipt_digest': canonical_digest(receipt)})):
        _record(db, issuer=issuer, namespace=p.namespace, kind=kind, ref=p.job_id,
            operation_id=b.acquire_operation_id, value=value)
    _STAGES.pop(id(staged), None)
    return b.digest


def _read_committed_life_numeric_request_originals_v1(db, *, namespace, issuer, job_id):
    from .natural_reply_job_v2 import _request_from_wire
    from .d04_root_original_store_v1 import _receipt
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1, _receipt_wire
    p = read_life_numeric_prepared_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    rows = [_read(db, issuer=issuer, namespace=namespace, kind=k, ref=job_id) for k in
            ('numeric_binding_v1', 'numeric_request_v1', 'numeric_acquire_commit_v1')]
    if any(r is None for r in rows): raise ValueError('Life numeric complete acquisition originals absent')
    b = decode_life_numeric_worker_binding_v1(rows[0][0])
    raw, committed = rows[1][0], rows[2][0]
    model = _request_from_wire(raw['wire'])
    receipt = _receipt(db, namespace, b.acquire_operation_id)
    adopted = read_adopted_domain_operation_v1(db, namespace, b.acquire_operation_id)
    key = job_graph_write(get_job(db, job_id)).key
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    prior=_producer_original_point_v3(db,table="graph_history",columns=("event_id","value","valid"),
        key_columns=("token","revision"),key=(key.token,2),
        legacy_reader=lambda:db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=2",
            (key.token,)).fetchone())
    history=None if prior is None else(prior[1],prior[2],prior[0])
    if (b.prepared_digest != p.digest or b.job_id != p.job_id or b.namespace != namespace
            or any(r[1] != b.acquire_operation_id for r in rows)
            or raw['prepared_digest'] != p.digest or raw['binding_digest'] != b.digest
            or raw['request_digest'] != model.digest or committed['request_digest'] != model.digest
            or committed['prepared_digest'] != p.digest or committed['binding_digest'] != b.digest
            or committed['receipt_digest'] != canonical_digest(receipt)
            or model.identity.phase != 'internal_life_numeric_v1' or model.call_id != p.call_id
            or model.prompt_template_digest != TEMPLATE_DIGEST
            or dict(model.payload) != json.loads(p.frozen.canonical_wire)
            or model.envelope.authority.actor != b.worker_subject
            or committed['receipt'] != _receipt_wire(receipt)
            or type(receipt) is not CommitReceipt or receipt.status != 'committed'
            or receipt.write_versions != (GraphVersion(key, 2),)
            or adopted is None or adopted['domain'] != 'd11' or adopted['operation_kind'] != OPERATION
            or adopted['receipt'] != receipt
            or adopted['payload']['provenance']['binding_digest'] != b.digest
            or adopted['payload']['provenance']['request_digest'] != model.digest
            or history is None or history[1:] != (1, b.acquire_operation_id)
            or json.loads(history[0]).get('lease_holder') != b.worker_subject
            or json.loads(history[0]).get('phase') != 'running'
            or json.loads(history[0]).get('work_kind') != WORK_KIND
            or json.loads(history[0]).get('fence') != 1):
        raise ValueError('Life numeric signed request/binding/actual receipt differs')
    return p, b, model, adopted


def read_committed_life_numeric_request_v1(db, *, namespace, issuer, job_id):
    # Public ABI stays the exact three originals. The private same-call reader
    # also returns the acquisition it already fully verified in this SQL read.
    prepared, binding, request, _ = _read_committed_life_numeric_request_originals_v1(
        db, namespace=namespace, issuer=issuer, job_id=job_id)
    return prepared, binding, request
