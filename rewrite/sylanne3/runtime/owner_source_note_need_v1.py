"""D07 current fixed-recipe Need from an actual independent Owner SourceNote task."""
from dataclasses import dataclass, replace
import json
import math

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d07 import D07DomainProvider
from ..domains.d07.qualified_attention_read import read_qualified_focus_attention_ticket
from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1, ProductionOriginalRefV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d06_ingress_recall_v1 import LEDGER_TYPES
from .d11_life_preparation_v1 import _read
from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2, OwnerSourceNoteTaskResponsibilityV2
from .owner_source_note_task_v1 import (read_owner_source_note_task_authorization_v2,
    require_current_owner_source_note_task_authorization_v2)
from .jobs import get_job
from .d11_types import job_graph_write

OPERATION = 'prepare_owner_source_note_need_v1'
RESPONSIBILITY_KIND = 'owner_source_note_task_responsibility_v2'
CREATE_OPERATION = 'create_owner_source_note_task_v1'
_READERS_KEY = object()


@dataclass(frozen=True, slots=True)
class PrepareOwnerSourceNoteNeedRequestV1:
    authorization_original_ref: str
    task_job_ref: str

    def __post_init__(self):
        if (type(self.authorization_original_ref) is not str or not self.authorization_original_ref.startswith('owner-source-note-authorization:')
                or AtomKey.from_token(self.task_job_ref).type_name != 'runtime.job'):
            raise ValueError('Owner Need selects its actual authorization and independent task job')


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteNeedOriginalV2:
    namespace: NamespaceId
    authorization_original_ref: str
    authorization_original_digest: str
    cause_original_ref: str
    cause_original_digest: str
    responsibility_ref: str
    responsibility_digest: str
    task_job_head: GraphVersion
    task_job_digest: str
    goal_head: GraphVersion
    plan_head: GraphVersion
    body_source_head: GraphVersion
    body_source_digest: str
    self_mapping_head: GraphVersion
    self_mapping_digest: str
    owner_guard: ProductionOwnerGuardV1
    focus_head: GraphVersion
    focus_digest: str
    attention_ticket_head: GraphVersion
    attention_ticket_digest: str
    ledger_coverage: tuple[ProductionQueryCoverageV1, ...]
    required_checks: tuple[str, ...]
    missing_items: tuple[str, ...]
    original_deadline_utc: float
    mode: str = 'explicit_owner_source_note'
    schema: str = 'd07.owner-source-note-need-original.v2'

    def __post_init__(self):
        if (self.mode != 'explicit_owner_source_note' or self.schema != 'd07.owner-source-note-need-original.v2'
                or type(self.namespace) is not NamespaceId or type(self.owner_guard) is not ProductionOwnerGuardV1):
            raise ValueError('Owner Need has another fixed-recipe authority contract')
        for head,kind in ((self.task_job_head,'runtime.job'),(self.goal_head,'d08.goal.v1'),(self.plan_head,'d08.personal_plan.v1'),
                (self.body_source_head,'memory.source'),(self.self_mapping_head,'d03.self_identity_mapping.v1'),
                (self.focus_head,'d07.focus.v1'),(self.attention_ticket_head,'d07.attention_ticket.v1')):
            if type(head) is not GraphVersion or head.revision < 1 or head.key.type_name != kind or NamespaceId.from_key(head.key) != self.namespace:
                raise ValueError('Owner Need head crossed its actual scope/type/version')
        for digest in (self.authorization_original_digest,self.cause_original_digest,self.responsibility_digest,self.task_job_digest,
                self.body_source_digest,self.self_mapping_digest,self.focus_digest,self.attention_ticket_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Owner Need original commitment differs')
        if (type(self.ledger_coverage) is not tuple or len(self.ledger_coverage) != len(LEDGER_TYPES)
                or {page.type_id for page in self.ledger_coverage} != set(LEDGER_TYPES)
                or any(type(page) is not ProductionQueryCoverageV1 or not page.complete or page.continuation_ref is not None for page in self.ledger_coverage)
                or type(self.required_checks) is not tuple or not self.required_checks or len(self.required_checks) > 16
                or any(type(item) is not str or not item for item in self.required_checks)
                or self.missing_items != () or type(self.original_deadline_utc) not in (float,int) or not math.isfinite(self.original_deadline_utc)):
            raise ValueError('Owner Need requires complete actual ledger coverage and fixed-recipe checks')


class InstalledOwnerSourceNoteNeedReadersV1:
    def __init__(self,key,*,issuer,installed_bundle,body_quote_authority,body_readers):
        if key is not _READERS_KEY: raise TypeError('Owner Need uses its actual installed Self factory')
        self.issuer,self.installed_bundle,self.body_quote_authority = issuer,installed_bundle,body_quote_authority
        self.body_readers = body_readers


def install_owner_source_note_need_readers_v1(graph):
    from ..graph_coordinator import GraphCoordinator
    if type(graph) is not GraphCoordinator: raise TypeError('actual installed Graph coordinator required')
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None: raise MissingProductionOriginalV1('actual_Owner_Need_installed_bundle')
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    body = InstalledD02ProductionReadersV1(issuer=graph._GraphCoordinator__d11_issuer,
        body_quote_authority=graph._GraphCoordinator__body_quote_authority,
        role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
    return InstalledOwnerSourceNoteNeedReadersV1(_READERS_KEY,body_readers=body,issuer=graph._GraphCoordinator__d11_issuer,
        installed_bundle=assembly.admin_bundle,body_quote_authority=graph._GraphCoordinator__body_quote_authority)


def _actual_current_need(db, *, frame, request, readers):
    if type(readers) is not InstalledOwnerSourceNoteNeedReadersV1 or type(request) is not PrepareOwnerSourceNoteNeedRequestV1:
        raise TypeError('actual installed Owner fixed-recipe Need readers required')
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    saved = read_owner_source_note_task_authorization_v2(db,namespace=ns,original_ref=request.authorization_original_ref,issuer=readers.issuer)
    if saved is None: raise MissingProductionOriginalV1('actual_signed_Owner_task_authorization_for_Need')
    auth,_ = saved
    require_current_owner_source_note_task_authorization_v2(db,frame=frame,authorization=auth,
        issuer=readers.issuer,installed_bundle=readers.installed_bundle,body_quote_authority=readers.body_quote_authority)
    key = AtomKey.from_token(request.task_job_ref); head = read.head(db,key,required=True); job = get_job(db,key.name)
    if (head.value != job_graph_write(job).value or job.phase != 'running' or job.cancel_epoch
            or (job.activity_id,job.budget_ref) != (frame.envelope.identity.activity_id,auth.cause.parent_budget_lease_ref)
            or frame.envelope.authority.worker_fence != job.fence):
        raise ValueError('Owner Need changed the actual current claimed Self task/job/root')
    continuation = decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
    if continuation.authorization_original_ref != auth.original_ref or continuation.authorization_original_digest != auth.digest or continuation.cancel_generation:
        raise ValueError('Owner Need cannot borrow another task authorization or cancellation generation')
    from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
    saved_responsibility = read_owner_source_note_task_responsibility_v2(db,namespace=ns,
        original_ref=continuation.responsibility_ref,issuer=readers.issuer)
    if saved_responsibility is None: raise MissingProductionOriginalV1('actual_signed_independent_Owner_task_responsibility')
    responsibility, signed_auth, created = saved_responsibility
    if signed_auth != auth:
        raise ValueError('Owner Need responsibility changed its actual signed task authorization')
    if (created is None or created['operation_kind'] != CREATE_OPERATION
            or responsibility.digest != continuation.responsibility_digest
            or responsibility.authorization_original_ref != auth.original_ref or responsibility.authorization_original_digest != auth.digest
            or responsibility.cause_original_ref != auth.cause.original_ref or responsibility.cause_original_digest != auth.cause.digest
            or responsibility.owner_guard != frame.owner_guard or responsibility.parent_budget_lease_ref != auth.cause.parent_budget_lease_ref
            or responsibility.original_deadline_utc != auth.cause.original_deadline_utc
            or frame.envelope.authority.actor != responsibility.self_entity_ref):
        raise ValueError('Owner Need lost its actual independent signed Self responsibility')
    read.original(request.authorization_original_ref); read.original(auth.cause.original_ref); read.committed_operation(db,created['receipt'].operation_id)
    mapping = read.head(db,responsibility.self_mapping_head.key,required=True)
    if mapping.revision != responsibility.self_mapping_head.revision or canonical_digest(mapping.value) != responsibility.self_mapping_digest:
        raise MissingProductionOriginalV1('Owner_Need_current_actual_self_mapping')
    focus = None
    for audience in frame.envelope.authority.audience:
        for purpose in ('context','consolidation'):
            member = read_qualified_focus_attention_ticket(frame.snapshot,ns,now=frame.now_utc,audience=audience,purpose=purpose)
            if (member is None or member.attention.ticket.concern_ref != auth.request.project_ref
                    or member.attention.ticket.causal_root != auth.request.body_source_ref
                    or auth.request.body_source_ref not in member.attention.ticket.source_refs):
                raise MissingProductionOriginalV1('actual_Owner_SourceNote_Focus_attention_before_Need')
            focus = member
    if focus is None: raise MissingProductionOriginalV1('actual_Owner_SourceNote_Need_audience')
    focus_head = read.head(db,focus.attention.focus_version.key,required=True)
    ticket = read.head(db,focus.attention.ticket_version.key,required=True)
    for member in (focus_head,ticket):
        origin = db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=?',(member.key.token,member.revision)).fetchone()
        if origin is None: raise MissingProductionOriginalV1('actual_Owner_Need_focus_producer')
        adopted = read_adopted_domain_operation_v1(db,ns,origin[0])
        if adopted is None or adopted['operation_kind'] not in {'focus_life_project','focus_owner_source_note_task_v1'}:
            raise ValueError('Owner Need focus must come from its actual explicit project producer')
        if adopted['operation_kind'] == 'focus_owner_source_note_task_v1':
            from .d07_life_project_focus_v1 import FocusOwnerSourceNoteTaskRequestV1, owner_task_focus_operation_id_v1
            command = decode_typed_production_value_v1(adopted['payload']['request'], FocusOwnerSourceNoteTaskRequestV1)
            provenance = adopted['payload']['provenance']
            if (command != FocusOwnerSourceNoteTaskRequestV1(auth.original_ref,key.token)
                    or origin[0] != owner_task_focus_operation_id_v1(ns,auth)
                    or provenance['authorization_original_digest'] != auth.digest
                    or provenance['owner_project_ref'] != auth.request.project_ref
                    or provenance['owner_project_source_ref'] != auth.request.body_source_ref
                    or provenance['owner_focus_selection'] != 'owner_task_project'):
                raise ValueError('Owner Need focus belongs to another signed task or project')
        read.committed_operation(db,origin[0])
    for kind in LEDGER_TYPES: read.complete_inventory(db,kind)
    coverage = tuple(page for page in frame.query_coverage if page.type_id in LEDGER_TYPES)
    pins = {name:(version,digest) for name,version,digest in auth.heads}
    from .d08_life_admission_v1 import PAIRS
    return OwnerSourceNoteNeedOriginalV2(ns,auth.original_ref,auth.digest,auth.cause.original_ref,auth.cause.digest,
        continuation.responsibility_ref,responsibility.digest,GraphVersion(key,head.revision),canonical_digest(head.value),
        pins['goal'][0],pins['plan'][0],pins['body_source'][0],pins['body_source'][1],responsibility.self_mapping_head,
        responsibility.self_mapping_digest,frame.owner_guard,GraphVersion(focus_head.key,focus_head.revision),canonical_digest(focus_head.value),
        GraphVersion(ticket.key,ticket.revision),canonical_digest(ticket.value),coverage,tuple(kind for kind,_ in PAIRS),(),
        min(auth.cause.original_deadline_utc,focus.attention.ticket.valid_until))


def stage_prepare_owner_source_note_need_v1(db, *, frame, request, installed_readers):
    need = _actual_current_need(db,frame=frame,request=request,readers=installed_readers)
    provider = D07DomainProvider()
    return stage_result_v1(frame,'d07',OPERATION,request,provenance={'owner_source_note_need':need},
        proposal_schema="d07.proposal.v1",proposal_hash=provider.descriptor.request_schema_hash)


def read_owner_source_note_need_original_v2(db, *, namespace, original_ref):
    if not original_ref.startswith('d07-current:'): return None
    rows = db.execute('SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_kind=? AND original_digest LIKE ? LIMIT 2',
        (*namespace.as_tuple,OPERATION,original_ref[len('d07-current:'):]+'%')).fetchall()
    if len(rows) != 1:return None
    actual = read_adopted_domain_operation_v1(db,namespace,rows[0][0])
    if actual is None or 'd07-current:' + actual['original_digest'][:48] != original_ref: return None
    value = decode_typed_production_value_v1(actual['payload']['provenance']['owner_source_note_need'],OwnerSourceNoteNeedOriginalV2)
    return value,actual


def require_current_owner_source_note_need_v1(db, *, frame, original_ref, installed_readers):
    saved = read_owner_source_note_need_original_v2(db,namespace=frame.envelope.authority.namespace,original_ref=original_ref)
    if saved is None: raise MissingProductionOriginalV1('actual_adopted_Owner_SourceNote_Need_original')
    old,actual = saved
    request = decode_typed_production_value_v1(actual['payload']['request'],PrepareOwnerSourceNoteNeedRequestV1)
    current = _actual_current_need(db,frame=frame,request=request,readers=installed_readers)
    require_owner_note_legal_task_job_progress_v1(db,namespace=current.namespace,previous_head=old.task_job_head,
        previous_digest=old.task_job_digest,current_head=current.task_job_head,current_digest=current.task_job_digest,
        authorization_original_ref=current.authorization_original_ref,responsibility_digest=current.responsibility_digest,
        max_rows=frame.limits.max_query_rows)
    if (replace(current,ledger_coverage=old.ledger_coverage,task_job_head=old.task_job_head,task_job_digest=old.task_job_digest) != old
            or any(current_page.row_versions != old_page.row_versions for current_page,old_page in zip(current.ledger_coverage,old.ledger_coverage))):
        raise MissingProductionOriginalV1('Owner_SourceNote_Need_current_inputs_changed')
    original = CurrentDomainReadV1(frame).original(original_ref,kind='d07.current-' + OPERATION,digest=actual['original_digest'])
    from ..domains.d08.personal_candidate_v1 import CurrentPersonalNeedQualificationV1
    keys = {version.key for version in actual['read_versions']}
    versions = tuple(GraphVersion(key,CurrentDomainReadV1(frame).head(db,key).revision) for key in sorted(keys,key=lambda key:key.token))
    original = replace(original,read_versions=tuple(GraphVersion(version.key,CurrentDomainReadV1(frame).head(db,version.key).revision) if version.key == old.task_job_head.key else version for version in original.read_versions))
    return CurrentPersonalNeedQualificationV1(original,current.plan_head,current.goal_head,versions,current.ledger_coverage,
        True,False,(),current.original_deadline_utc)


def read_plan_owner_source_note_need_v1(db, *, namespace, request, installed_readers):
    from ..graph_types import Owner, owner_grant_key
    auth_saved = read_owner_source_note_task_authorization_v2(db,namespace=namespace,
        original_ref=request.authorization_original_ref,issuer=installed_readers.issuer)
    if auth_saved is None:
        return production_read_plan_v1((),(AtomKey.from_token(request.task_job_ref),),(),(request.authorization_original_ref,))
    auth,_ = auth_saved
    keys = [owner_grant_key(*namespace.as_tuple),AtomKey.from_token(request.task_job_ref),
        AtomKey(Owner('persona',*namespace.as_tuple),'d07.focus.v1',namespace.persona_id),*(version.key for _,version,_ in auth.heads)]
    originals = [auth.original_ref,auth.cause.original_ref]
    job = get_job(db,AtomKey.from_token(request.task_job_ref).name)
    continuation = decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
    originals.append(continuation.responsibility_ref)
    from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
    saved = read_owner_source_note_task_responsibility_v2(db,namespace=namespace,original_ref=continuation.responsibility_ref,
        issuer=installed_readers.issuer)
    if saved is not None:
        keys.append(saved[0].self_mapping_head.key); originals.append(saved[2]['receipt'].operation_id)
    roots = list(auth.source_refs)
    focus = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d07.focus.v1' AND valid=1",namespace.as_tuple).fetchall()
    if len(focus) > 1: raise MissingProductionOriginalV1('unique_current_Owner_task_Focus')
    if focus:
        # FocusState retains the selected ticket ref; actual typed reader revalidates it.
        value = json.loads(focus[0][0]); ref = value['primary_ticket_ref']
        if ref is not None: keys.append(AtomKey.from_token(ref))
    return production_read_plan_v1((*LEDGER_TYPES,'d07.attention_ticket.v1','d02.body_profile.v1','d02.body_state.v1','d02.reservation.v1'),
        keys,roots,originals)


def require_owner_note_legal_task_job_progress_v1(db, *, namespace, previous_head, previous_digest,
        current_head, current_digest, authorization_original_ref, responsibility_digest, max_rows):
    """Only actual same-task acquire/checkpoint W01 history can advance the qualified job carrier."""
    from .owner_source_note_task_execution_v1 import decode_owner_source_note_task_job_v1
    from .owner_source_note_task_contract_v1 import ACQUIRE_OPERATION, CHECKPOINT_OPERATION
    if previous_head.key != current_head.key or NamespaceId.from_key(current_head.key) != namespace or current_head.revision < previous_head.revision:
        raise ValueError('Owner task progress cannot substitute or roll back a job')
    previous = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
        (previous_head.key.token,previous_head.revision)).fetchone()
    if previous is None or previous[1] != 1 or canonical_digest(json.loads(previous[0])) != previous_digest:
        raise ValueError('Owner task Need lost its actual original qualified job history')
    if current_head == previous_head:
        if current_digest != previous_digest: raise ValueError('Owner task unchanged revision changed its actual digest')
        return True
    rows = db.execute('SELECT revision,event_id,value,valid FROM graph_history WHERE token=? AND revision>? AND revision<=? ORDER BY revision LIMIT ?',
        (current_head.key.token,previous_head.revision,current_head.revision,max_rows+1)).fetchall()
    if len(rows) > max_rows or len(rows) != current_head.revision-previous_head.revision:
        raise MissingProductionOriginalV1('bounded_complete_actual_Owner_task_job_progress')
    previous_value = json.loads(previous[0]); expected_revision = previous_head.revision
    for revision,operation,value,valid in rows:
        actual = read_adopted_domain_operation_v1(db,namespace,operation)
        if (revision != expected_revision+1 or valid != 1 or actual is None or actual['domain'] != 'd11'
                or actual['operation_kind'] not in {ACQUIRE_OPERATION,CHECKPOINT_OPERATION}
                or actual['receipt'].write_versions != (GraphVersion(current_head.key,revision),)):
            raise ValueError('Owner task job progress lacks its exact named W01/receipt transition')
        proof = actual['payload']['provenance']
        if set(proof) != {'before_job','after_job','owner_task_responsibility'}:
            raise ValueError('Owner task job progress has another closed provenance')
        before = decode_owner_source_note_task_job_v1(proof['before_job'],namespace=namespace)
        after = decode_owner_source_note_task_job_v1(proof['after_job'],namespace=namespace)
        responsibility = decode_typed_production_value_v1(proof['owner_task_responsibility'],OwnerSourceNoteTaskResponsibilityV2)
        if (job_graph_write(before).key != current_head.key or job_graph_write(before).value != previous_value
                or job_graph_write(after).key != current_head.key or job_graph_write(after).value != json.loads(value)
                or responsibility.authorization_original_ref != authorization_original_ref or responsibility.digest != responsibility_digest):
            raise ValueError('Owner task legal progress changed its actual job/responsibility lineage')
        previous_value = json.loads(value); expected_revision = revision
    if canonical_digest(previous_value) != current_digest:
        raise ValueError('Owner task current head differs from its actual complete W01 progress chain')
    return True
