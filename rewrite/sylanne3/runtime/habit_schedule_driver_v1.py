"""One durable Habit subscription per policy revision and one installed nearest timer."""
from dataclasses import asdict,dataclass,fields,replace
from datetime import datetime,timezone
import asyncio
import math
from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1,HabitWindowCueOriginalV1,habit_window_cue_selector_from_wire_v1,habit_window_cue_original_from_wire_v1
from ..domains.d10.habit_policy_v1 import GraphAdoptedHabitPolicyV1,habit_policy_key_v1
from ..domains.d10.habit_occurrence_v1 import habit_window_v1
from ..graph_types import AtomKey,GraphVersion,GraphWrite
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize,schema_hash
from .jobs import PersistentJob,get_job,create_job,_save_job,_record_operation,_prior_operation
from .d11_types import job_graph_write,reconcile_runtime_write
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1,StagedDomainOperationV1

SUBSCRIPTION_KIND='habit_subscription_v1'
CUE_INPUT_KIND='habit_window_cue_v1'
CUE_PRODUCER='record_habit_window_cue_v1'

@dataclass(frozen=True,slots=True)
class HabitSubscriptionV1:
    namespace:NamespaceId
    policy_ref:str
    policy_revision:int
    policy_digest:str
    standing_original_ref:str
    standing_original_digest:str
    window_index:int
    window_id:str
    window_start_utc:float
    window_end_utc:float
    due_at_utc:float
    original_deadline_utc:float
    cancellation_generation:int
    source_refs:tuple[str,...]
    schema:str='d11.habit-subscription.v1'
    def __post_init__(self):
        if self.schema!='d11.habit-subscription.v1'or type(self.namespace)is not NamespaceId or type(self.policy_revision)is not int or self.policy_revision<1 or type(self.window_index)is not int or self.window_index<0 or type(self.cancellation_generation)is not int or self.cancellation_generation<0 or not self.window_start_utc<=self.due_at_utc<self.window_end_utc or self.original_deadline_utc<=self.window_start_utc:raise ValueError('Habit subscription retains exact current policy and original cursor/TTL')
        if AtomKey.from_token(self.policy_ref).type_name!='d10.habit_policy.v1'or not self.source_refs:raise ValueError('Habit subscription requires its actual policy/Source locators')

@dataclass(frozen=True,slots=True)
class HabitSubscriptionNoWindowV1:
    namespace:NamespaceId
    policy_ref:str
    policy_revision:int
    policy_digest:str
    standing_original_ref:str
    standing_original_digest:str
    next_window_index:int
    original_deadline_utc:float
    cancellation_generation:int
    source_refs:tuple[str,...]
    reason:str='no_executable_window'
    schema:str='d11.habit-subscription-no-window.v1'
    def __post_init__(self):
        if self.schema!='d11.habit-subscription-no-window.v1'or self.reason!='no_executable_window'or type(self.namespace)is not NamespaceId or self.policy_revision<1 or self.next_window_index<0 or self.cancellation_generation<0 or AtomKey.from_token(self.policy_ref).type_name!='d10.habit_policy.v1':raise ValueError('nonexecuting subscription retains actual policy identity and original deadline')

@dataclass(frozen=True,slots=True)
class HabitWindowScheduleCensusV1:
    namespace:NamespaceId
    policy_ref:str
    window_id:str
    occurrence_refs:tuple[str,...]
    graph_cue_original_refs:tuple[str,...]
    core_cue_original_refs:tuple[str,...]
    observed_versions:tuple[GraphVersion,...]
    query_coverage:tuple
    coverage:str
    @property
    def consumed(self):return bool(self.occurrence_refs or self.graph_cue_original_refs or self.core_cue_original_refs)

def habit_subscription_to_wire_v1(value):
    if type(value)not in (HabitSubscriptionV1,HabitSubscriptionNoWindowV1):raise TypeError('actual typed Habit subscription variant required')
    return asdict(value)
def habit_subscription_from_wire_v1(raw):
    if type(raw)is not dict:raise TypeError('Habit subscription wire object required')
    cls=HabitSubscriptionNoWindowV1 if raw['schema']=='d11.habit-subscription-no-window.v1'else HabitSubscriptionV1
    if set(raw)!={f.name for f in fields(cls)}:raise ValueError('Habit subscription closed fields differ')
    return cls(**{**raw,'namespace':NamespaceId(**raw['namespace']),'source_refs':tuple(raw['source_refs'])})
def habit_subscription_job_id_v1(namespace,policy_id,revision):return 'habit-subscription:'+canonical_digest((namespace,policy_id,revision))[:48]
def habit_subscription_activity_id_v1(namespace,policy_id):return 'habit-schedule:'+canonical_digest((namespace,policy_id))[:48]
def _utc(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')

def new_habit_subscription_job_v1(frame,policy,*,window_index):
    if type(policy)is not GraphAdoptedHabitPolicyV1:raise TypeError('subscription requires actual adopted Core policy mirror')
    d=policy.definition
    if d.state!='enabled'or frame.now_utc>=d.original_valid_until_utc:raise MissingProductionOriginalV1('live_enabled_habit_subscription_policy')
    start=d.window_anchor_utc+window_index*d.window_seconds
    policy_ref=habit_policy_key_v1(d.namespace,d.policy_id).token
    if start>=d.original_valid_until_utc:
        value=HabitSubscriptionNoWindowV1(d.namespace,policy_ref,d.revision,policy.digest,policy.core_original_ref,policy.core_original_digest,window_index,d.original_valid_until_utc,d.cancellation_generation,d.source_refs)
        wake=None;phase='deferred'
    else:
        window_id,start,end=habit_window_v1(d,start)
        value=HabitSubscriptionV1(d.namespace,policy_ref,d.revision,policy.digest,policy.core_original_ref,policy.core_original_digest,window_index,window_id,start,end,start,d.original_valid_until_utc,d.cancellation_generation,d.source_refs)
        wake={'kind':'habit_window_due','due_at_utc':start,'window_id':window_id};phase='waiting'
    job_id=habit_subscription_job_id_v1(d.namespace,d.policy_id,d.revision)
    return PersistentJob(job_id,frame.envelope.identity.operation_id,habit_subscription_activity_id_v1(d.namespace,d.policy_id),None,*d.namespace.as_tuple,'habit-policy:'+policy.digest[:48],phase,SUBSCRIPTION_KIND,habit_subscription_to_wire_v1(value),wake,_utc(d.original_valid_until_utc),d.parent_root_grant_ref,'resource:unallocated',{'habit_subscription':'1'},None,None,0,0,{},None)

def next_habit_subscription_job_v1(job,policy,core_cue):
    current=habit_subscription_from_wire_v1(job.continuation);d=policy.definition
    if type(current)is not HabitSubscriptionV1 or job.work_kind!=SUBSCRIPTION_KIND or job.phase!='waiting'or job.lease_holder is not None or core_cue.selector.window_id!=current.window_id or core_cue.selector.expected_job_cancel_epoch!=job.cancel_epoch:raise ValueError('Habit wake lost its exact durable waiting cursor')
    index=current.window_index+1;start=d.window_anchor_utc+index*d.window_seconds
    if start>=current.original_deadline_utc:return replace(job,phase='completed',wake_condition=None,result_ref=core_cue.original_ref)
    window_id,start,end=habit_window_v1(d,start)
    updated=replace(current,window_index=index,window_id=window_id,window_start_utc=start,window_end_utc=end,due_at_utc=start)
    return replace(job,continuation=habit_subscription_to_wire_v1(updated),wake_condition={'kind':'habit_window_due','due_at_utc':start,'window_id':window_id})

@dataclass(frozen=True,slots=True)
class RecordHabitWindowCueRequestV1:
    policy_ref:str
    policy_revision:int
    subscription_job_ref:str
    subscription_job_revision:int
    window_id:str
    def __post_init__(self):
        if AtomKey.from_token(self.policy_ref).type_name!='d10.habit_policy.v1'or AtomKey.from_token(self.subscription_job_ref).type_name!='runtime.job'or self.policy_revision<1 or self.subscription_job_revision<1 or not self.window_id:raise ValueError('cue request fixes the actual existing subscription and policy window')
def record_habit_window_cue_request_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(RecordHabitWindowCueRequestV1)}:raise ValueError('Habit timecue request fields differ')
    return RecordHabitWindowCueRequestV1(**raw)

@dataclass(frozen=True,slots=True)
class HabitScheduleEntryV1:
    policy:GraphAdoptedHabitPolicyV1
    subscription:HabitSubscriptionV1|HabitSubscriptionNoWindowV1
    job:PersistentJob
    job_head:GraphVersion
    coverage:str
    missing_inputs:tuple[str,...]

@dataclass(frozen=True,slots=True)
class HabitScheduleScanV1:
    namespace:NamespaceId
    entries:tuple[HabitScheduleEntryV1,...]
    nearest_due_utc:float|None
    coverage:str
    continuation_ref:str|None
    missing_inputs:tuple[str,...]

@dataclass(frozen=True,slots=True)
class HabitScheduleStageV1:
    stage:StagedDomainOperationV1
    before_jobs:tuple[PersistentJob,...]
    after_jobs:tuple[PersistentJob,...]
    core_cue_original:HabitWindowCueOriginalV1|None=None


def apply_habit_schedule_jobs_in_transaction_v1(db,*,stage,frame):
    if type(stage)is not HabitScheduleStageV1 or not db.in_transaction:raise TypeError('Habit subscription changes require their exact same-W01 typed stage')
    before={j.job_id:j for j in stage.before_jobs};after={j.job_id:j for j in stage.after_jobs}
    if len(before)!=len(stage.before_jobs)or len(after)!=len(stage.after_jobs)or not set(before)<=set(after):raise ValueError('Habit subscription transition drops an original job identity')
    for identity,new in after.items():
        old=before.get(identity)
        if new.work_kind!=SUBSCRIPTION_KIND or new.effect_id is not None or new.lease_holder is not None or new.resource_ref!='resource:unallocated':raise ValueError('Habit timer bookkeeping cannot dispatch or acquire worker resources')
        key=job_graph_write(new).key;head=frame.snapshot.get(key)
        if head is None:raise ValueError('Habit subscription current/absence head was not part of original CAS')
        if old is None:
            if head.revision!=0 or head.valid:raise ValueError('new subscription already has a Graph head')
            create_job(db,new,'habit-subscription-create:'+canonical_digest((stage.stage.operation_id,identity))[:40],canonical_digest(new))
        else:
            if old.phase=='deferred'and type(habit_subscription_from_wire_v1(old.continuation))is not HabitSubscriptionNoWindowV1:raise ValueError('only exact no-window subscription may remain deferred')
            if get_job(db,identity)!=old or head.value!=job_graph_write(old).value or new.budget_ref!=old.budget_ref or new.deadline_utc!=old.deadline_utc or new.cancel_epoch<old.cancel_epoch or old.phase not in {'waiting','deferred','cancelled','completed'}:raise ValueError('Habit cursor/control changed actual current job, Root or original deadline')
            operation='habit-subscription-update:'+canonical_digest((stage.stage.operation_id,identity))[:40];digest=canonical_digest((old,new))
            prior=_prior_operation(db,old,operation,'habit_subscription',digest)
            if prior is None:_save_job(db,new);_record_operation(db,new,operation,'habit_subscription',digest)
            elif prior!=new:raise ValueError('Habit cursor replay conflicts with original job transition')
        reconcile_runtime_write(db,job_graph_write(new))


def attach_habit_schedule_stage_v1(base,*,frame,before_jobs,after_jobs,core_cue_original=None,window_census=None):
    import json
    from ..runtime_contracts import DomainProposal,DependencySet
    from .d11_types import D11RuntimeProvider,D11_PROPOSAL_SCHEMA
    if type(base)is not StagedDomainOperationV1:raise TypeError('subscription transition attaches only to actual closed B3 stage')
    writes=tuple(job_graph_write(job)for job in after_jobs)
    if len({w.key for w in writes})!=len(writes)or not {w.key for w in writes}<=set(v.key for v in frame.snapshot.versions):raise ValueError('subscription heads/absences must be in the original CAS set')
    raw=json.loads(base.original_payload_json)
    from ..domains.d01.production_operations_v1 import plain_v1
    raw['provenance']['habit_subscription_transition']={'before':tuple(asdict(job)for job in before_jobs),'after':tuple(asdict(job)for job in after_jobs),'core_cue_original':None if core_cue_original is None else plain_v1(core_cue_original),'window_census':None if window_census is None else plain_v1(window_census)}
    raw['writes']+=plain_v1(writes)
    digest=canonical_digest(raw);original=ProductionOriginalRefV1(base.domain+'.current-'+base.operation_kind,base.domain+'-current:'+digest[:48],digest,base.read_versions)
    from .domain_production_contracts_v1 import ProductionOutboxStageV1
    outbox=tuple(ProductionOutboxStageV1(item.namespace,item.causal_operation_id,item.receiver_domain,item.event_kind,original)for item in base.outbox)
    proposal=DomainProposal('d11',D11_PROPOSAL_SCHEMA,D11RuntimeProvider().descriptor.request_schema_hash,frame.envelope,writes,DependencySet(),(),())
    updated=replace(base,proposals=(*base.proposals,proposal),original_payload_json=canonical_serialize(raw),original_digest=digest,outbox=outbox)
    return HabitScheduleStageV1(updated,tuple(before_jobs),tuple(after_jobs),core_cue_original)

def policy_habit_subscription_jobs_v1(db,*,frame,policy,before_policy):
    before=[];after=[];census=None
    if before_policy is not None:
        d=before_policy.definition
        identity=habit_subscription_job_id_v1(d.namespace,d.policy_id,d.revision)
        from .d11_types import runtime_job_key
        key=runtime_job_key(*d.namespace.as_tuple,habit_subscription_activity_id_v1(d.namespace,d.policy_id),identity)
        atom=CurrentDomainReadV1(frame).head(db,key)
        if atom.revision:
            old=get_job(db,identity)
            if old.work_kind!=SUBSCRIPTION_KIND or atom.value!=job_graph_write(old).value:raise ValueError('Habit prior subscription SQL/Graph mirror changed')
            before.append(old)
            if old.phase=='deferred'and type(habit_subscription_from_wire_v1(old.continuation))is not HabitSubscriptionNoWindowV1:raise ValueError('deferred subscription lost its exact no-window variant')
            if old.phase in {'waiting','deferred'}:after.append(replace(old,phase='cancelled',wake_condition=None,cancel_epoch=old.cancel_epoch+1))
            elif old.phase in {'cancelled','completed'}:after.append(old)
            else:raise ValueError('Habit subscription unexpectedly acquired execution or unknown work')
        elif d.state=='enabled':raise MissingProductionOriginalV1('actual_previous_habit_subscription')
    if policy.definition.state=='enabled':
        from .current_habit_source_read_v3 import read_current_habit_schedule_census_v3
        from .domain_production_contracts_v1 import actual_frame_read_versions_v1
        d=policy.definition;index=max(0,math.floor((frame.now_utc-d.window_anchor_utc)/d.window_seconds))
        window_id,_,_=habit_window_v1(d,d.window_anchor_utc+index*d.window_seconds)
        census=read_current_habit_schedule_census_v3(db,frame=frame,policy_ref=habit_policy_key_v1(d.namespace,d.policy_id).token,window_id=window_id)
        if type(census)is not HabitWindowScheduleCensusV1 or(census.namespace,census.policy_ref,census.window_id,census.coverage)!=(d.namespace,habit_policy_key_v1(d.namespace,d.policy_id).token,window_id,'complete')or census.query_coverage!=frame.query_coverage or not set(census.observed_versions)<=set(actual_frame_read_versions_v1(frame)):raise ValueError('subscription cursor requires current complete cross-revision occurrence and Graph/Core cue census')
        if census.consumed:index+=1
        after.append(new_habit_subscription_job_v1(frame,policy,window_index=index))
    return tuple(before),tuple(after),census


def habit_window_cue_request_v1(selector):
    return RecordHabitWindowCueRequestV1(selector.policy_ref,selector.policy_revision,selector.subscription_job_ref,selector.subscription_job_revision,selector.window_id)

def habit_window_cue_operation_id_v1(stable_key):return 'habit-window-cue-write:'+stable_key[:48]

def _cue_command_digest_v1(request):
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    return habit_typed_command_digest_v1(installed_operation_v1('record_habit_window_cue_v1'),request)

def habit_window_cue_selector_v1(entry):
    if type(entry)is not HabitScheduleEntryV1 or type(entry.subscription)is not HabitSubscriptionV1 or entry.coverage!='complete'or entry.missing_inputs:raise MissingProductionOriginalV1('actual_current_habit_subscription_and_policy')
    policy,subscription,job=entry.policy,entry.subscription,entry.job;definition=policy.definition
    request=RecordHabitWindowCueRequestV1(subscription.policy_ref,subscription.policy_revision,entry.job_head.key.token,entry.job_head.revision,subscription.window_id)
    stable=canonical_digest((definition.namespace,definition.policy_id,subscription.window_id))
    return HabitWindowCueSelectorV1(namespace=definition.namespace,installation_id=policy.installation_id,policy_ref=subscription.policy_ref,policy_revision=subscription.policy_revision,policy_digest=subscription.policy_digest,standing_authorization_original_ref=subscription.standing_original_ref,standing_authorization_original_digest=subscription.standing_original_digest,subscription_job_ref=entry.job_head.key.token,subscription_job_revision=entry.job_head.revision,expected_job_fence=job.fence,expected_lease_holder=job.lease_holder,expected_job_cancel_epoch=job.cancel_epoch,cancellation_generation=subscription.cancellation_generation,window_id=subscription.window_id,window_start_utc=subscription.window_start_utc,window_end_utc=subscription.window_end_utc,due_at_utc=subscription.due_at_utc,operation_id=habit_window_cue_operation_id_v1(stable),request_digest=_cue_command_digest_v1(request),parent_root_grant_ref=job.budget_ref,parent_root_grant_digest=definition.parent_root_grant_digest,original_deadline_utc=subscription.original_deadline_utc)

class InstalledHabitScheduleDriverV1:
    def __init__(self,context):
        from ..runtime_context import RuntimeContext
        from ..graph_worker import GraphWorker
        if type(context)is not RuntimeContext or type(context._worker)is not GraphWorker :raise TypeError('Habit driver requires its actual installed RuntimeContext/worker/coordinator')
        self.context=context;self._timer=None;self._task=None;self._stopping=True;self._last_error=None;self._notified=False
    async def start_v1(self):
        if not self._stopping:raise ValueError('Habit schedule driver already started')
        self._stopping=False;self.notify_v1()
    def notify_v1(self):
        if self._stopping:return
        if self._timer is not None:self._timer.cancel();self._timer=None
        if self._task is not None and not self._task.done():self._notified=True;return
        if self._task is None or self._task.done():
            self._notified=False
            self._task=asyncio.create_task(self.run_due_v1());self._task.add_done_callback(self._done_v1)
    def _done_v1(self,task):
        if not task.cancelled():self._last_error=task.exception()
        if self._notified and not self._stopping:self.notify_v1()
    def _arm_v1(self,due):
        import time
        if self._timer is not None:self._timer.cancel();self._timer=None
        if due is not None and not self._stopping:
            # The host wall clock only schedules notification; Core proves time.
            self._timer=asyncio.get_running_loop().call_later(max(0.0,due-time.time()),self.notify_v1)
    async def run_due_v1(self):
        import time
        from ..graph_worker import OwnedGraphStorageResultV3
        owned=await self.context._worker.call(lambda graph:graph.read_current_habit_schedule_v3(self.context))
        if type(owned)is not OwnedGraphStorageResultV3:raise TypeError('Habit scan must retain its actual Source-qualified storage result')
        scan,retention=owned.take_value_v3()
        try:
            if type(scan)is not HabitScheduleScanV1 or scan.namespace!=self.context._v2_namespace:raise ValueError('Habit scan crossed installed namespace')
            due=tuple(entry for entry in scan.entries if type(entry.subscription)is HabitSubscriptionV1 and entry.coverage=='complete'and not entry.missing_inputs and entry.subscription.due_at_utc<=time.time())
            selected=min(due,key=lambda e:(e.subscription.due_at_utc,e.job.job_id))if due else None
            selector=None if selected is None else habit_window_cue_selector_v1(selected)
            nearest=scan.nearest_due_utc
        finally:retention.release()
        if self._stopping:return
        if selector is None:self._arm_v1(nearest);return
        committed=await self.context._worker.call(lambda graph:graph.record_current_habit_window_cue_v1(self.context,selector))
        if type(committed)is not OwnedGraphStorageResultV3:raise TypeError('Habit cue write must retain its actual storage result')
        receipt,retention=committed.take_value_v3()
        try:
            from .domain_production_originals_v1 import _receipt
            from .c09_foreground_attempt_v1 import _RECEIPT_FIELDS
            if (type(receipt)is not dict or set(receipt)!=_RECEIPT_FIELDS
                    or receipt['schema']!='sylanne.domain-production-receipt.v1'
                    or (receipt['domain'],receipt['operation_kind'],receipt['operation_id'])
                        !=('d11',CUE_PRODUCER,selector.operation_id)):
                raise TypeError('Habit cue requires its exact installed domain-production receipt')
            actual=_receipt(receipt['receipt'])
            if actual.operation_id!=selector.operation_id or canonical_digest(actual)!=receipt['receipt_digest']:
                raise ValueError('Habit cue receipt differs from its actual W01 COMMIT')
            status=actual.status
        finally:retention.release()
        if status in {'committed','duplicate'}and not self._stopping:
            self._timer=asyncio.get_running_loop().call_later(0.0,self.notify_v1)
    async def close_v1(self):
        self._stopping=True
        if self._timer is not None:self._timer.cancel();self._timer=None
        if self._task is not None:await asyncio.shield(self._task)


def stage_record_habit_window_cue_v1(db,*,frame,request,installed):
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3,require_current_habit_core_inputs_v3
    from .d10_habit_v1 import _policy
    from ..domains.d01.production_operations_v1 import stage_result_v1,plain_v1
    from .d11_types import D11RuntimeProvider,D11_PROPOSAL_SCHEMA
    from .domain_mesh_tick_v1 import MeshTickInputsV1,stage_joint_habit_mesh_companion_v1,combine_semantic_mesh_stage_v1
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=CUE_PRODUCER,request=request)
    read=CurrentDomainReadV1(frame);read.check(db)
    policy_atom,policy=_policy(db,read,request.policy_ref,request.policy_revision)
    facts=require_current_habit_core_inputs_v3(db,frame=frame,operation_kind=CUE_PRODUCER,request=request);core=facts.timecue_original
    if type(core)is not HabitWindowCueOriginalV1:raise TypeError('actual independent Core time observation required')
    selector=core.selector
    job=get_job(db,AtomKey.from_token(request.subscription_job_ref).name)
    head=read.head(db,request.subscription_job_ref,required=True);subscription=habit_subscription_from_wire_v1(job.continuation)
    if type(subscription)is not HabitSubscriptionV1:raise MissingProductionOriginalV1('no_executable_window')
    if head.revision!=request.subscription_job_revision or head.value!=job_graph_write(job).value or job.phase!='waiting'or job.work_kind!=SUBSCRIPTION_KIND or job.lease_holder is not None:raise ValueError('Habit time observation lost its actual waiting subscription')
    if habit_window_cue_request_v1(selector)!=request or selector.request_digest!=_cue_command_digest_v1(request)or selector.operation_id!=frame.envelope.identity.operation_id or selector.operation_id!=habit_window_cue_operation_id_v1(selector.cue_stable_key)or (selector.policy_ref,selector.policy_revision,selector.policy_digest,selector.standing_authorization_original_ref,selector.standing_authorization_original_digest,selector.subscription_job_ref,selector.subscription_job_revision,selector.window_id,selector.window_start_utc,selector.window_end_utc,selector.due_at_utc,selector.expected_job_fence,selector.expected_lease_holder,selector.expected_job_cancel_epoch,selector.cancellation_generation,selector.original_deadline_utc)!=(policy_atom.key.token,policy.definition.revision,policy.digest,policy.core_original_ref,policy.core_original_digest,head.key.token,head.revision,subscription.window_id,subscription.window_start_utc,subscription.window_end_utc,subscription.due_at_utc,job.fence,job.lease_holder,job.cancel_epoch,subscription.cancellation_generation,subscription.original_deadline_utc):raise ValueError('Core time cue changed its exact policy/subscription/window/Root/clock request')
    if core.owner_head_digest.removeprefix('sha256:')!=frame.owner_guard.owner_head_digest or core.clock_lower_utc<subscription.due_at_utc or core.clock_upper_utc>=subscription.original_deadline_utc:raise ValueError('time cue is outside actual current Owner or original Root deadline')
    d=policy.definition
    execution_deadline=min(subscription.window_end_utc,subscription.due_at_utc+d.execution_seconds,d.original_valid_until_utc)
    if core.clock_lower_utc<execution_deadline<=core.clock_upper_utc:raise MissingProductionOriginalV1('actual_clock_bound_wholly_before_or_after_habit_deadline')
    expected_state='due'if core.clock_upper_utc<execution_deadline else d.miss_policy
    if core.execution_state!=expected_state:raise ValueError('Habit time observation changed the original miss rule or backfilled an on-time cue')
    after=next_habit_subscription_job_v1(job,policy,core)
    causal=ProductionOriginalRefV1('d11.habit_window_cue',core.original_ref,core.digest)
    inputs=MeshTickInputsV1(causal_original=causal,source_roots=d.source_refs,predecessors=(),semantic_originals=(causal,),semantic_versions=(GraphVersion(head.key,head.revision),),cancellation_generation=d.cancellation_generation,semantic_digest=canonical_digest((d.policy_id,subscription.window_id,core.execution_state)),original_deadline_utc=subscription.original_deadline_utc)
    companion=stage_joint_habit_mesh_companion_v1(db,frame=frame,operation_kind=CUE_PRODUCER,request=request,actual_inputs=inputs)
    events=(('d10','habit_cue_observed_requires_occurrence'),)if core.execution_state=='due'else ()
    base=stage_result_v1(frame,'d11',CUE_PRODUCER,request,provenance={'core_cue_original':core,'policy_head':GraphVersion(policy_atom.key,policy_atom.revision),'semantic_mesh':companion.trace},receiver_events=events)
    schedule=attach_habit_schedule_stage_v1(base,frame=frame,before_jobs=(job,),after_jobs=(after,),core_cue_original=core)
    if core.execution_state!='due':
        from ..domains.d10.habit_occurrence_v1 import HabitDispositionV1
        from ..domains.d10.habit_policy_v1 import HABIT_DISPOSITION_TYPE
        from ..graph_types import Owner,GraphWrite
        from ..runtime_contracts import DomainProposal,DependencySet
        identity='habit-disposition:'+canonical_digest((d.namespace,d.policy_id,d.revision,subscription.window_id,core.original_ref,d.miss_policy))[:48]
        disposition=HabitDispositionV1(d.namespace,identity,policy_atom.key.token,d.revision,subscription.window_id,core.original_ref,d.miss_policy,core.original_ref,execution_deadline,core.clock_lower_utc,d.source_refs)
        key=AtomKey(Owner('persona',*d.namespace.as_tuple,d.namespace.persona_id),HABIT_DISPOSITION_TYPE,identity)
        absent=read.head(db,key)
        if absent.revision or absent.valid:raise ValueError('missed Habit window already has its immutable disposition')
        write=GraphWrite(key,plain_v1(disposition))
        proposal=DomainProposal('d10','d10.proposal.v1',schema_hash({'domain':'d10','proposal':1}),frame.envelope,(write,),DependencySet(),(),())
        import json
        raw=json.loads(schedule.stage.original_payload_json);raw['provenance']['miss_disposition']=plain_v1(disposition);raw['writes'].append(plain_v1(write))
        digest=canonical_digest(raw)
        schedule=replace(schedule,stage=replace(schedule.stage,proposals=(*schedule.stage.proposals,proposal),original_payload_json=canonical_serialize(raw),original_digest=digest))
    return replace(schedule,stage=combine_semantic_mesh_stage_v1(schedule.stage,companion))

def read_actual_habit_cue_v1(db,*,frame,policy,original_ref,original_digest,issuer):
    from .current_habit_source_read_v3 import read_bound_current_habit_cue_original_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_mesh_contract_v1 import project_actual_habit_cue_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    core=read_bound_current_habit_cue_original_v3(db,frame=frame,original_ref=original_ref,original_digest=original_digest)
    if type(core)is not HabitWindowCueOriginalV1 or(core.original_ref,core.digest)!=(original_ref,original_digest):raise ValueError('Habit cue differs from the actual previously issued independent clock original')
    s=core.selector;d=policy.definition
    if(s.namespace,s.policy_ref,s.policy_revision,s.standing_authorization_original_ref,s.standing_authorization_original_digest)!=(d.namespace,habit_policy_key_v1(d.namespace,d.policy_id).token,d.revision,policy.core_original_ref,policy.core_original_digest):raise ValueError('time cue belongs to another exact adopted standing policy')
    operation=habit_window_cue_operation_id_v1(s.cue_stable_key);read=CurrentDomainReadV1(frame);read.committed_operation(db,operation)
    observed=read_adopted_domain_operation_v1(db,d.namespace,operation)
    if observed is None or(observed['domain'],observed['operation_kind'])!=('d11',CUE_PRODUCER)or observed['payload']['provenance']['core_cue_original']!=plain_v1(core):raise ValueError('time cue lost its actual atomic Graph wake and original cursor producer')
    read.source_family(db,d.source_refs,purpose='context')
    return project_actual_habit_cue_v1(core,producer_original=ProductionOriginalRefV1('d11.current-record_habit_window_cue_v1','d11-current:'+observed['original_digest'][:48],observed['original_digest']),producer_operation_id=operation,predicate_digest=canonical_digest(d.cue_predicate),source_refs=d.source_refs)


@dataclass(frozen=True,slots=True)
class SemanticHabitCueObservationV1:
    namespace:NamespaceId
    policy_ref:str
    policy_revision:int
    cue_stable_key:str
    occurred_at_utc:float
    predicate_digest:str
    source_refs:tuple[str,...]
    producer_operation_id:str
    cue_original_ref:str
    cue_original_digest:str
    @property
    def clock_lower_utc(self):return self.occurred_at_utc
    @property
    def clock_upper_utc(self):return self.occurred_at_utc
    @property
    def execution_state(self):return 'due'


def habit_schedule_companion_matches_v1(stage,proposal):
    """Exact subscription bookkeeping companion; this pure check grants no execution right."""
    import json
    from .d10_habit_v1 import POLICY_OPERATIONS,habit_request_from_wire_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1,HABIT_DISPOSITION_TYPE,HABIT_POLICY_TYPE
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from .jobs import _job_from_dict
    from .d11_types import D11_PROPOSAL_SCHEMA
    policy_companion=stage.domain=='d10'and stage.operation_kind in POLICY_OPERATIONS and proposal.domain=='d11'
    miss_companion=stage.domain=='d11'and stage.operation_kind==CUE_PRODUCER and proposal.domain=='d10'
    if not(policy_companion or miss_companion):return False
    raw=json.loads(stage.original_payload_json);proof=raw['provenance'];transition=proof['habit_subscription_transition']
    before=tuple(_job_from_dict(j)for j in transition['before']);after=tuple(_job_from_dict(j)for j in transition['after'])
    by_before={j.job_id:j for j in before};by_after={j.job_id:j for j in after}
    if len(by_before)!=len(before)or len(by_after)!=len(after)or not set(by_before)<=set(by_after)or len(after)>2 or stage.jobs or stage.paid_cost_originals:raise ValueError('Habit schedule companion keeps exact old/new subscription identities and no executable jobs or costs')
    original_writes=tuple(decode_typed_production_value_v1(w,GraphWrite)for w in raw['writes'])
    if len({w.key for w in original_writes})!=len(original_writes):raise ValueError('Habit subscription original repeats a Graph member')
    job_writes=tuple(job_graph_write(j)for j in after);heads={v.key:v.revision for v in stage.read_versions}
    for job in after:
        if job.work_kind!=SUBSCRIPTION_KIND or(job.bot_id,job.persona_id)!=stage.namespace.as_tuple or job.effect_id is not None or job.lease_holder is not None or job.resource_ref!='resource:unallocated'or job_graph_write(job)not in original_writes or job_graph_write(job).key not in heads:raise ValueError('Habit schedule companion is only its exact same-CAS nonexecuting subscription')
        old=by_before.get(job.job_id)
        if old is None:
            continuation=habit_subscription_from_wire_v1(job.continuation)
            expected_phase='deferred'if type(continuation)is HabitSubscriptionNoWindowV1 else 'waiting'
            if heads[job_graph_write(job).key]!=0 or job.phase!=expected_phase or job.cancel_epoch!=0:raise ValueError('Habit new subscription must be born from actual absence in its exact executable or no-window state')
        elif(old.budget_ref,old.deadline_utc,old.job_id,old.activity_id)!=(job.budget_ref,job.deadline_utc,job.job_id,job.activity_id):raise ValueError('Habit bookkeeping cannot widen original Root/TTL or change old job identity')
    if proposal.envelope!=next(p.envelope for p in stage.proposals if p.domain==stage.domain)or proposal.envelope.version_guard.read_versions!=stage.read_versions or proposal.contribution_keys or proposal.required_bundle_parts:raise ValueError('Habit schedule companion must share the whole original envelope/readset without a new bundle')
    if policy_companion:
        if proposal.proposal_schema!=D11_PROPOSAL_SCHEMA or proposal.typed_writes!=job_writes or sum(p.domain=='d11'and any(w.key.type_name=='runtime.job'for w in p.typed_writes)for p in stage.proposals)!=1:raise ValueError('Habit policy has exactly its actual subscription job partition')
        request=habit_request_from_wire_v1(stage.operation_kind,raw['request']);policy=graph_adopted_habit_policy_from_wire_v1(proof['policy']);d=policy.definition
        if request.definition!=d or len(tuple(w for w in original_writes if w.key.type_name==HABIT_POLICY_TYPE))!=1:raise ValueError('Habit subscription binds its exact actual adopted policy and typed management request')
        new=tuple(j for j in after if j.job_id not in by_before)
        if len(new)!=(1 if d.state=='enabled'else 0):raise ValueError('Habit management creates one subscription only for its enabled revision')
        if new:
            value=habit_subscription_from_wire_v1(new[0].continuation)
            if(value.policy_ref,value.policy_revision,value.policy_digest,value.standing_original_ref,value.standing_original_digest,value.cancellation_generation,value.original_deadline_utc,new[0].budget_ref)!=(habit_policy_key_v1(d.namespace,d.policy_id).token,d.revision,policy.digest,policy.core_original_ref,policy.core_original_digest,d.cancellation_generation,d.original_valid_until_utc,d.parent_root_grant_ref):raise ValueError('Habit new subscription differs from the actual standing revision or original Root')
            if type(value)is HabitSubscriptionNoWindowV1 and new[0].wake_condition is not None:raise ValueError('no-executable-window subscription cannot arm a timer')
        for old in before:
            updated=by_after[old.job_id]
            expected=replace(old,phase='cancelled',wake_condition=None,cancel_epoch=old.cancel_epoch+1)if old.phase in {'waiting','deferred'}else old
            if updated!=expected:raise ValueError('Habit management preserves or cancels only the actual prior subscription')
    else:
        if transition['core_cue_original']is None or len(before)!=1 or len(after)!=1:raise ValueError('Habit miss has exactly the actual Core clock and one cursor transition')
        from .joint_habit_provenance_v1 import habit_window_cue_from_domain_plain_v1
        core=habit_window_cue_from_domain_plain_v1(transition['core_cue_original']);old=before[0];subscription=habit_subscription_from_wire_v1(old.continuation)
        if type(subscription)is not HabitSubscriptionV1 or core.execution_state not in {'skipped','wait','reschedule-required'}or core.selector.operation_id!=stage.operation_id or core.selector.window_id!=subscription.window_id:raise ValueError('Habit late disposition cannot substitute an on-time cue or new execution')
        if proposal.proposal_schema!='d10.proposal.v1'or proposal.proposal_schema_hash!=schema_hash({'domain':'d10','proposal':1})or len(proposal.typed_writes)!=1 or proposal.typed_writes[0].key.type_name!=HABIT_DISPOSITION_TYPE:raise ValueError('Habit late bookkeeping writes exactly one disposition')
        write=proposal.typed_writes[0];value=habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE,write.value)
        if write not in original_writes or heads.get(write.key)!=0 or(value.namespace,value.policy_ref,value.policy_revision,value.window_id,value.cue_original_ref,value.disposition,value.reason_ref,value.recorded_at_utc,value.source_refs)!=(stage.namespace,subscription.policy_ref,subscription.policy_revision,subscription.window_id,core.original_ref,core.execution_state,core.original_ref,core.clock_lower_utc,subscription.source_refs)or value.original_deadline_utc>core.clock_lower_utc:raise ValueError('Habit miss must retain the real Core clock and original window without an execution or Experience')
        if stage.outbox:raise ValueError('late Habit bookkeeping cannot notify a runnable occurrence')
    return True
