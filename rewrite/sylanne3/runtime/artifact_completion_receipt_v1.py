"""D06 completion facts derived only from a satisfied Artifact W01 history.

The Source discloses completion of registered work, never correctness of the
created content. The original lives in the existing domain-production journal;
there is no second receipt database or model-generated response.
"""
from dataclasses import dataclass
import json
import math

from ..graph_types import AtomKey, GraphVersion, GraphWrite, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_phase_sequence_v2
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1

OPERATION = 'derive_artifact_completion_receipt_v1'
SCHEMA = 'd06.artifact-completion-receipt.v1'


def receipt_ids_v1(selector):
    if (type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.phase_kind != 'check'
            or selector.phase_index != len(artifact_draft_phase_sequence_v2(selector.method_ref)) - 1):
        raise ValueError('receipt requires the final selected method phase')
    marker = canonical_digest((SCHEMA, selector))[:48]
    ids = dict(zip(('producer','source_id','receipt','operation','effect','batch'),
        (prefix + marker for prefix in ('artifact-completion-source:', 'artifact-completion:',
         'artifact-completion-receipt:', 'artifact-receipt-message:', 'artifact-receipt-effect:', 'artifact-receipt-batch:'))))
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    ids['activity']=foreground_cycle_ids_v1(selector.task.namespace,selector.task.c02_operation_id)[0]
    return ids


@dataclass(frozen=True, slots=True)
class DeriveArtifactCompletionReceiptRequestV1:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        receipt_ids_v1(self.selector)


@dataclass(frozen=True, slots=True)
class ArtifactCompletionReceiptOriginalV1:
    selector: ArtifactDraftPhaseSelectorV2
    receipt_id: str
    producer_operation_id: str
    message_operation_id: str
    effect_id: str
    source_ref: str
    source_digest: str
    source_access_digest: str
    parent_source_heads: tuple[tuple[GraphVersion, str], ...]
    completion_digest: str
    completion_receipt_digest: str
    completion_operation_id: str
    milestone_ref: str
    milestone_digest: str
    full_check_ref: str
    full_check_digest: str
    file_result_ref: str
    file_result_digest: str
    file_content_digest: str
    allocation_digest: str
    owner_guard: ProductionOwnerGuardV1
    installation_id: str
    manifest_digest: str
    recorded_at_utc: float
    original_deadline_utc: float
    schema: str = SCHEMA

    def __post_init__(self):
        ids = receipt_ids_v1(self.selector)
        if (self.schema != SCHEMA or type(self.owner_guard) is not ProductionOwnerGuardV1
                or (self.receipt_id,self.producer_operation_id,self.message_operation_id,self.effect_id,self.source_ref) !=
                    (ids['receipt'],ids['producer'],ids['operation'],ids['effect'],
                     source_key(*self.namespace.as_tuple,ids['source_id']).token)
                or not 1 <= len(self.parent_source_heads) <= 2
                or len({head.key for head,_ in self.parent_source_heads}) != len(self.parent_source_heads)):
            raise ValueError('completion receipt changed its exact task/Source/once identity')
        for name in ('source_digest','source_access_digest','completion_digest','completion_receipt_digest',
                'milestone_digest','full_check_digest','file_result_digest','file_content_digest','allocation_digest','manifest_digest'):
            _digest_v1(getattr(self,name))
        for head,digest in self.parent_source_heads:
            if (type(head) is not GraphVersion or head.revision < 1 or head.key.type_name != 'memory.source'
                    or NamespaceId.from_key(head.key) != self.namespace):
                raise ValueError('completion receipt requires its actual parent Source heads')
            _digest_v1(digest)
        if (any(type(t) not in (int,float) or not math.isfinite(t) for t in (self.recorded_at_utc,self.original_deadline_utc))
                or not 0 <= self.recorded_at_utc < self.original_deadline_utc):
            raise ValueError('completion receipt exceeded its original deadline')

    @property
    def namespace(self): return self.selector.task.namespace

    @property
    def digest(self): return canonical_digest(plain_v1(self))

    @property
    def text(self):
        return ('本次任务的文件生成与已登记检查已完成。\n'
            '内容 SHA-256：' + self.file_content_digest + '\n完成收据：' + self.receipt_id)


def _digest_v1(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('completion receipt requires full original commitments')


def receipt_from_wire_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, ArtifactCompletionReceiptOriginalV1)
    if plain_v1(value) != raw: raise ValueError('completion receipt is not canonical')
    return value


def _current_inputs_v1(db, *, namespace, selector, issuer, installed_bundle, owner_guard, now_utc, audiences):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d11_artifact_draft_content_v1 import read_current_completed_artifact_method_history_v2
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    from .artifact_receipt_allocation_v3 import read_actual_artifact_receipt_allocation_v3, resolve_current_artifact_receipt_budget_v3
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    if not audiences or tuple(sorted(set(audiences))) != tuple(audiences):
        raise ValueError('completion requires its exact nonempty delivery audiences')
    history, commit = read_current_completed_artifact_method_history_v2(db,namespace=namespace,selector=selector,
        issuer=issuer,owner_guard=owner_guard,installed_bundle=installed_bundle)
    if history.state != 'satisfied': raise MissingProductionOriginalV1('actual_satisfied_Artifact_method_not_partial')
    milestone = read_current_artifact_task_milestone_v2(db,namespace=namespace,
        original_ref=history.milestone_original_ref,issuer=issuer)
    from .jobs import get_job
    job = get_job(db,AtomKey.from_token(selector.task.cycle_job_ref).name)
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    from .foreground_cycle_v1 import require_current_foreground_responsibility_v1
    responsibility=require_current_foreground_responsibility_v1(db,namespace=namespace,job=job,
        installed_bundle=installed_bundle,issuer=issuer,owner_guard=owner_guard,purpose='consolidation',
        audiences=audiences,now_utc=now_utc)
    if responsibility is None or responsibility.root_registration_ref!=selector.task.root_registration_ref:
        raise MissingProductionOriginalV1('actual_same_Root_current_Artifact_responsibility')
    mapping=_artifact_receipt_sql_v1(db,'SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,responsibility.self_mapping_ref)).fetchone()
    if mapping is None or mapping[1]!=1 or background_json_loads_v3(mapping[0])['self_entity_ref']!=history.actor_ref:
        raise ValueError('receipt cannot transfer a completed task to a different current Self')
    if (type(continuation.call_plan) is not ForegroundCallPlanV3
            or continuation.call_plan.phase_group.selector != selector
            or continuation.call_plan.phase_group.completed_phase_originals != history.ordered_phase_originals
            or continuation.pending_effect_refs or continuation.wait is not None):
        raise MissingProductionOriginalV1('actual_complete_V3_method_without_pending_or_unknown_effect')
    _,allocation,_,_ = read_actual_artifact_receipt_allocation_v3(db,namespace=namespace,
        c02_operation_id=selector.task.c02_operation_id,source_ref=continuation.source_ref,issuer=issuer)
    _,grant = resolve_current_artifact_receipt_budget_v3(db,namespace=namespace,
        c02_operation_id=selector.task.c02_operation_id,source_ref=continuation.source_ref,issuer=issuer,
        installed_bundle=installed_bundle,now_utc=now_utc,owner_guard=owner_guard)
    deadline = min(history.original_deadline_utc,grant.valid_until_utc)
    if not history.completed_at_utc <= now_utc < deadline:
        raise MissingProductionOriginalV1('actual_completed_receipt_within_original_deadline')
    roots = tuple(dict.fromkeys((continuation.source_ref,history.source_head.key.token)))
    family = _source_family_current_sql_v1(db,namespace=namespace,roots=roots,purpose='expression',audiences=audiences)
    _source_family_current_sql_v1(db,namespace=namespace,roots=roots,purpose='consolidation',audiences=audiences)
    heads=[];permissions=[]
    for version in family:
        if version.key.type_name not in {'memory.source','memory.access'}: continue
        row=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,version.key.token)).fetchone()
        if row is None or row[2]!=1 or row[0]!=version.revision: raise ValueError('receipt Source family changed during qualification')
        value=background_json_loads_v3(row[1]);permissions.append((set(value['audiences']),set(value['purposes'])))
        if version.key.token in roots: heads.append((version,background_json_digest_v3(row[1],value)))
    if len(heads)!=len(roots): raise MissingProductionOriginalV1('actual_task_and_content_Source_heads')
    allowed_audiences=tuple(sorted(set.intersection(*(a for a,_ in permissions))))
    allowed_purposes=tuple(sorted(set.intersection(*(p for _,p in permissions))))
    if not set(audiences)<=set(allowed_audiences) or not {'expression','consolidation'}<=set(allowed_purposes):
        raise MissingProductionOriginalV1('actual_receipt_Source_family_expression_intersection')
    return history,commit,milestone,allocation,deadline,tuple(sorted(heads,key=lambda row:row[0].key.token)),allowed_audiences,allowed_purposes,family


def _receipt_values_v1(*,selector,inputs,owner_guard,installed_bundle,recorded_at_utc):
    history,commit,milestone,allocation,deadline,heads,audiences,purposes,_=inputs
    ns=selector.task.namespace;ids=receipt_ids_v1(selector)
    # Compute immutable text before the Source commitment; text never includes
    # caller prose, the created document, filesystem paths, or model claims.
    text=('本次任务的文件生成与已登记检查已完成。\n内容 SHA-256：'+milestone.readback.content_digest+'\n完成收据：'+ids['receipt'])
    source=SourceRecord(ids['source_id'],text,history.actor_ref,'internal','confirmed',history.completed_at_utc,
        recorded_at_utc,ids['receipt'],audiences,purposes,tuple(head.key.owner.subject for head,_ in heads),'same_root')
    access={'source_id':source.source_id,'audiences':list(audiences),'purposes':list(purposes),'status':'active','recorded_at':recorded_at_utc}
    validate_access(access)
    policy=installed_bundle.installation_policy
    receipt=ArtifactCompletionReceiptOriginalV1(selector,ids['receipt'],ids['producer'],ids['operation'],ids['effect'],
        source_key(*ns.as_tuple,source.source_id).token,canonical_digest(source.to_dict()),canonical_digest(access),heads,
        history.digest,canonical_digest(commit),history.settlement_operation_id,milestone.original_ref,milestone.digest,
        milestone.full_check_original_ref,milestone.full_check_original_digest,history.file_result_ref,history.file_result_digest,
        milestone.readback.content_digest,allocation.digest,owner_guard,policy.installation_id,policy.manifest_digest,recorded_at_utc,deadline)
    if receipt.text!=source.text: raise ValueError('receipt Source changed its fixed completion rendering')
    return receipt,source,access


def stage_derive_artifact_completion_receipt_v1(db, *, frame, request, installed_readers):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from ..domains.d06 import D06DomainProvider
    if type(request) is not DeriveArtifactCompletionReceiptRequestV1 or type(installed_readers) is not InstalledArtifactDraftModelReadersV1:
        raise TypeError('receipt requires exact installed Artifact readers and selector')
    read=CurrentDomainReadV1(frame);read.check(db)
    ns=frame.envelope.authority.namespace;ids=receipt_ids_v1(request.selector)
    if ns!=request.selector.task.namespace or frame.envelope.identity.operation_id!=ids['producer']:
        raise ValueError('receipt changed its actual namespace or deterministic producer operation')
    inputs=_current_inputs_v1(db,namespace=ns,selector=request.selector,issuer=installed_readers.issuer,
        installed_bundle=installed_readers.installed_bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,audiences=frame.envelope.authority.audience)
    if inputs[0].actor_ref!=frame.envelope.authority.actor:
        raise ValueError('receipt producer changed its actual completed Self actor')
    value,source,access=_receipt_values_v1(selector=request.selector,inputs=inputs,owner_guard=frame.owner_guard,
        installed_bundle=installed_readers.installed_bundle,recorded_at_utc=frame.now_utc)
    read.source_family(db,tuple(head.key.token for head,_ in value.parent_source_heads),purpose='expression')
    sk=AtomKey.from_token(value.source_ref);ak=access_key(*ns.as_tuple,source.source_id)
    if read.head(db,sk).revision or read.head(db,ak).revision:
        raise ValueError('receipt Source already exists or was erased; recover the same original, never revive')
    provider=D06DomainProvider()
    return stage_result_v1(frame,'d06',OPERATION,request,
        writes=(GraphWrite(sk,source.to_dict(),tuple(head.key for head,_ in value.parent_source_heads)),GraphWrite(ak,access,(sk,))),
        provenance={'artifact_completion_receipt':value,'receipt_source':source,'receipt_access':access},
        proposal_schema='d06.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)


def require_artifact_completion_receipt_history_v1(db, *, namespace, original):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    value=receipt_from_wire_v1(original['payload']['provenance']['artifact_completion_receipt'])
    if ((original['domain'],original['operation_kind'])!=('d06',OPERATION)
            or value.namespace!=namespace or original['receipt'].operation_id!=value.producer_operation_id
            or original['payload']['request']!=plain_v1(DeriveArtifactCompletionReceiptRequestV1(value.selector))
            or original['payload']['coverage']!='complete' or original['payload']['now_utc']!=value.recorded_at_utc
            or original['payload']['owner_guard']!=plain_v1(value.owner_guard)):
        raise ValueError('completion receipt lacks its actual same-W01 D06 producer')
    from .artifact_original_child_locators_v3 import artifact_original_child_locators_v3
    artifact_original_child_locators_v3(kind='artifact_completion_receipt_v1',value=value)
    source=SourceRecord.from_dict(original['payload']['provenance']['receipt_source'])
    access=original['payload']['provenance']['receipt_access'];validate_access(access)
    sk=AtomKey.from_token(value.source_ref);ak=access_key(*namespace.as_tuple,source.source_id)
    expected=(GraphVersion(sk,1),GraphVersion(ak,1))
    if (set(original['receipt'].write_versions)!=set(expected) or len(original['receipt'].write_versions)!=2
            or source.text!=value.text or source.provenance_root!=value.receipt_id
            or source.source_kind!='internal' or source.assertion_status!='confirmed'
            or source.parent_source_ids!=tuple(head.key.owner.subject for head,_ in value.parent_source_heads)
            or canonical_digest(source.to_dict())!=value.source_digest or canonical_digest(access)!=value.source_access_digest):
        raise ValueError('receipt producer changed actual Source/Access/parents/exact CAS writes')
    for head,digest in value.parent_source_heads:
        if head not in original['read_versions']: raise ValueError('receipt omitted an actual parent Source CAS read')
    for version,digest in zip(expected,(value.source_digest,value.source_access_digest)):
        row=_artifact_receipt_sql_v1(db,'SELECT event_id,value,valid FROM graph_history WHERE event_bot=? AND event_persona=? AND token=? AND revision=?',
            (*namespace.as_tuple,version.key.token,version.revision)).fetchone()
        if row is None or row[0]!=value.producer_operation_id or row[2]!=1 or background_json_digest_v3(row[1],background_json_loads_v3(row[1]))!=digest:
            raise ValueError('receipt Source/Access birth lost actual producer W01 history')
    return value


def read_current_artifact_completion_receipt_v1(db, *, namespace, selector, issuer, installed_bundle, owner_guard, now_utc, audiences, prepared_inventory=None):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    if prepared_inventory is not None:
        from .artifact_receipt_original_read_v1 import require_prepared_artifact_completion_receipt_v1
        return require_prepared_artifact_completion_receipt_v1(db,namespace=namespace,selector=selector,issuer=issuer,
            installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,audiences=audiences,
            prepared_inventory=prepared_inventory)
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    ids=receipt_ids_v1(selector)
    original=read_adopted_domain_operation_v1(db,namespace,ids['producer'])
    if original is None: raise MissingProductionOriginalV1('actual_D06_Artifact_completion_receipt_producer')
    value=require_artifact_completion_receipt_history_v1(db,namespace=namespace,original=original)
    inputs=_current_inputs_v1(db,namespace=namespace,selector=selector,issuer=issuer,installed_bundle=installed_bundle,
        owner_guard=owner_guard,now_utc=now_utc,audiences=audiences)
    expected,source,access=_receipt_values_v1(selector=selector,inputs=inputs,owner_guard=owner_guard,
        installed_bundle=installed_bundle,recorded_at_utc=value.recorded_at_utc)
    if value!=expected: raise ValueError('receipt changed actual completion, Root, Owner, allocation, deadline or parents')
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    _source_family_current_sql_v1(db,namespace=namespace,roots=(value.source_ref,),purpose='expression',audiences=audiences)
    for ref,digest in ((value.source_ref,value.source_digest),(access_key(*namespace.as_tuple,source.source_id).token,value.source_access_digest)):
        row=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',(*namespace.as_tuple,ref)).fetchone()
        if row is None or row[0]!=1 or row[2]!=1 or background_json_digest_v3(row[1],background_json_loads_v3(row[1]))!=digest:
            raise ValueError('receipt Source/Access was removed, corrected, changed or withdrawn; HOLD')
    return value


def read_plan_artifact_completion_receipt_v1(db, *, namespace, request, installed_readers, now_utc, audiences):
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    job=get_job(db,AtomKey.from_token(request.selector.task.cycle_job_ref).name)
    responsibility=read_original_foreground_responsibility_for_c09_v1(db,namespace=namespace,job=job,issuer=installed_readers.issuer)
    owner=responsibility.owner_guard
    continuation=foreground_cycle_from_wire_v1(job.continuation)
    inputs=_current_inputs_v1(db,namespace=namespace,selector=request.selector,issuer=installed_readers.issuer,
        installed_bundle=installed_readers.installed_bundle,owner_guard=owner,now_utc=now_utc,
        audiences=audiences)
    history,_,milestone,_,_,_,_,_,family=inputs
    ids=receipt_ids_v1(request.selector)
    keys=tuple(dict.fromkeys((owner_grant_key(*namespace.as_tuple),AtomKey.from_token(responsibility.self_mapping_ref),AtomKey.from_token(request.selector.task.cycle_job_ref),
        *(head.key for head in family),*(member.after.key for member in history.members),history.progress_head.key,
        source_key(*namespace.as_tuple,ids['source_id']),access_key(*namespace.as_tuple,ids['source_id']))))
    return production_read_plan_v1((),keys,tuple(head.key.token for head,_ in inputs[5]),
        (*tuple(ref for ref,_ in history.ordered_phase_originals),history.milestone_original_ref,history.file_result_ref,
         request.selector.task.root_registration_ref))


def read_current_artifact_completion_receipt_by_operation_v1(db, *, namespace, operation_id, issuer, installed_bundle, owner_guard, now_utc, audiences):
    prefix='artifact-receipt-message:'
    if (type(operation_id) is not str or not operation_id.startswith(prefix)
            or len(operation_id)!=len(prefix)+48 or any(c not in '0123456789abcdef' for c in operation_id[len(prefix):])):
        raise ValueError('exact Artifact receipt message operation required')
    producer=read_adopted_domain_operation_v1(db,namespace,'artifact-completion-source:'+operation_id[len(prefix):])
    if producer is None: raise MissingProductionOriginalV1('actual_same_message_D06_receipt_producer')
    value=require_artifact_completion_receipt_history_v1(db,namespace=namespace,original=producer)
    if value.message_operation_id!=operation_id: raise ValueError('receipt recovery crossed its original message operation')
    return read_current_artifact_completion_receipt_v1(db,namespace=namespace,selector=value.selector,issuer=issuer,
        installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,audiences=audiences)


def qualify_artifact_completion_receipt_foreground_v1(db, *, request, continuation, issuer, installed_bundle, owner_guard, now_utc):
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    if type(continuation.call_plan) is not ForegroundCallPlanV3:
        raise ValueError('receipt cannot upgrade an older natural or Artifact call plan')
    selector=continuation.call_plan.phase_group.selector
    body=DeriveArtifactCompletionReceiptRequestV1(selector)
    inputs=_current_inputs_v1(db,namespace=request.namespace,selector=selector,issuer=issuer,
        installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,audiences=request.audiences)
    if (request.operation_kind!=OPERATION or request.operation_id!=receipt_ids_v1(selector)['producer']
            or request.plan_ref!=selector.plan_ref or request.draft_root_registration_ref!=selector.task.root_registration_ref
            or request.purpose!='consolidation' or request.c02_operation_id!=selector.task.c02_operation_id
            or request.parent_budget_lease_ref!=continuation.call_plan.parent_budget_lease_ref
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(OPERATION),body)):
        raise ValueError('receipt Self admission changed its exact completed task/typed command/Root')
    return {head.key.token for head,_ in inputs[5]}, inputs[4]
