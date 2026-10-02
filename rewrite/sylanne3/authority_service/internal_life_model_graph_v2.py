"""Installed current Life content inputs; no model result or grant is issued.

The preparation and acquisition are historical originals. Current rights are
requalified from the actual Core Owner head and a bounded Graph snapshot on
every read. Public DTOs and persisted qualification digests confer no rights.
"""
from dataclasses import dataclass, replace, asdict
from datetime import datetime
import json
import math
import sqlite3

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..model_broker.internal_life_content_v1 import (
    WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST, thaw_internal_life_content_request_v1,
)
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOwnerGuardV1, ProductionQueryCoverageV1,
    ProductionOperationLimitsV1,
)
from ..runtime.internal_life_content_worker_v2 import read_committed_internal_life_request_v2
from ..runtime.internal_life_content_preparation_v1 import (
    PrepareInternalLifeContentRequestV1, read_plan_internal_life_content_v1,
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
from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from .v2_model_egress_contract import ModelEgressIntentV1


@dataclass(frozen=True, slots=True)
class InternalLifeCurrentModelGraphV2:
    prepared: object
    binding: object
    frozen: object
    job: object
    request: object
    owner_guard: object
    storage_admission: object
    current_scope_digest: str


def _current_frame(db, prepared, request, readers, now):
    """Finite complete read material, never an installed issuance marker."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise ValueError('Life model current read requires one actual SQL snapshot')
    ns = prepared.namespace
    locator = PrepareInternalLifeContentRequestV1(prepared.episode_ref,
        thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json)).input.cause.occurrence.event.causal_operation_id)
    plan = read_plan_internal_life_content_v1(db, namespace=ns, activity_id=prepared.activity_id,
        operation_kind='prepare_internal_life_content', request=locator)
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


class InstalledInternalLifeModelGraphReaderV2:
    """Exact installation components, not an externally supplied callback."""
    def __init__(self, *, owner_storage, structured_readers, bundle, read_subject):
        from ..host.authority_profile import AdminInstallationBundle
        workflows=bundle.model_workflows if type(bundle) is AdminInstallationBundle else None
        if (type(bundle) is not AdminInstallationBundle or type(read_subject) is not str
                or not read_subject.startswith("mtls:sha256:")
                or type(owner_storage) is not InstalledD12OwnerStorageAdmissionServiceV1
                or type(structured_readers) is not InstalledD06StructuredExperienceReadersV1
                or type(workflows) is not AdminModelWorkflowsV3 or workflows.life_content is None
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
        prepared, binding, request = read_committed_internal_life_request_v2(db,
            namespace=ns, issuer=self.readers.issuer, job_id=job.job_id)
        frozen = thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
        workflow = self.workflows.life_content
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
                or 'consolidation' not in grant['purposes'] or frozen.input.audience not in grant['audiences']
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
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_contracts import AuthorityContext
        adopted=read_adopted_domain_operation_v1(db,ns,prepared.acquire_operation_id)
        owner_authority=decode_typed_production_value_v1(adopted['payload']['authority'],AuthorityContext)
        owner_request=replace(request,envelope=replace(request.envelope,authority=owner_authority))
        frame = _current_frame(db, prepared, owner_request, self.readers, float(now))
        cause = read_current_internal_life_encoding_cause_v1(db, frame=frame,
            request=EncodeInternalLifeRequestV1(prepared.episode_ref, frozen.input.cause.occurrence.event.causal_operation_id),
            installed_readers=self.readers)
        if canonical_serialize(plain_v1(cause)) != canonical_serialize(plain_v1(frozen.input.cause)):
            raise ValueError('Life model current occurrence/causal originals changed')
        if ((workflow.work_kind, workflow.purpose, workflow.template_version) != (WORK_KIND, 'consolidation', TEMPLATE_VERSION)
                or (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.max_output_tokens) !=
                    (frozen.provider_id, frozen.model_id, frozen.provider_config_digest, frozen.max_output_tokens)
                or (request.call_id, request.digest, request.identity.operation_id, request.prompt_template_digest) !=
                    (intent.call_id, intent.request_digest, prepared.acquire_operation_id, TEMPLATE_DIGEST)
                or (intent.operation_id, intent.acquire_operation_id, intent.binding_digest) !=
                    (prepared.acquire_operation_id, prepared.acquire_operation_id, binding.digest)
                or (intent.provider_id, intent.model_id, intent.provider_config_digest, intent.max_output_tokens) !=
                    (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.max_output_tokens)
                or request.payload != json.loads(frozen.wire_json)
                or request.envelope.authority.purpose != 'consolidation'
                or request.envelope.authority.audience != (frozen.input.audience,)
                or request.required_capabilities != frozenset(workflow.required_capabilities)
                or request.privacy_tier != workflow.privacy_tier or request.timeout_seconds != workflow.timeout_seconds
                or prepared.provider_config_ref != workflow.provider_config_ref
                or job.phase != 'running' or job.operation_id != prepared.prepare_operation_id
                or job.fence != intent.worker_fence or job.fence != request.envelope.authority.worker_fence
                or job.cancel_epoch != 0 or job.lease_holder != intent.subject or job.lease_holder != binding.worker_subject
                or job.result_ref is not None or job.lease_expires_utc is None
                or now >= min(frozen.input.expires_at_utc, request.envelope.deadline_utc,
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
        scope_digest = canonical_digest({'schema':'d06.internal-life-content-current-model.v2',
            'prepared_digest':prepared.digest, 'worker_binding_digest':binding.digest, 'current_reads':frame.snapshot.versions,
            'query_coverage':frame.query_coverage, 'owner_guard':head.guard,
            'storage_admission':admission, 'source_rights':(intent.access_epoch,intent.delete_epoch)})
        return InternalLifeCurrentModelGraphV2(prepared, binding, frozen, job, request, head.guard, admission, scope_digest)
