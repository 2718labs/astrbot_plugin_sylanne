"""Independent Source profile for the fixed D07 current World concern recipe."""
from dataclasses import dataclass,field
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,Owner,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _heap

D07_SOURCE_OPERATIONS_V3=frozenset({"serve_concern"})
D07_SOURCE_WORK_KIND_V3="current_d07_source_read_v3"
D07_SOURCE_INVENTORIES_V3=("d07.attention_ticket.v1","d07.focus.v1","d07.concern_round.v1",
    "d07.reflection_checkpoint.v1","d07.working_set.v1","d02.body_profile.v1",
    "d02.body_state.v1","d02.reservation.v1")
_STATES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_PROPOSALS={}

@dataclass(slots=True)
class _D07SourceStateV3:
    reader:object
    identity:tuple
    tasks:dict=field(default_factory=dict)
    graph_refs:set=field(default_factory=set)
    jobs:set=field(default_factory=set)
    terminals:dict=field(default_factory=dict)
    originals:set=field(default_factory=set)
    versions:set=field(default_factory=set)
    prepared_keys:set=field(default_factory=set)
    source_permission:object=None
    plan:object=None

def _identity(r):
    return(r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,r.request,
        r.operation_id,r.activity_id,r.authority,r.lease,r.owner_binding)

def register_d07_source_work_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    require_current_beta1_source_work_v3(r)
    if(r in _STATES or r.work.kind!=D07_SOURCE_WORK_KIND_V3 or r.operation_kind!="serve_concern"
            or type(r.request)is not ServeCurrentConcernRequestV1):
        raise AuthorityUnavailable("D07 Source profile requires its actual installed current concern command")
    pin=getattr(r,"d07_dispatch_pin_v3",None)
    if pin is None or pin[5]!="world"or pin[6]!=r.owner_binding:
        raise AuthorityUnavailable("D07 World Source requires its private original classifier/Owner handoff")
    _STATES[r]=_D07SourceStateV3(r,_identity(r))

def require_d07_source_work_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    s=_STATES.get(r);actual=_identity(r)
    if(s is None or s.reader is not r or r.work.kind!=D07_SOURCE_WORK_KIND_V3
            or s.identity[:-1]!=actual[:-1]
            or s.identity[-1]is not actual[-1]and s.source_permission is not None):
        raise AuthorityUnavailable("D07 Source profile crossed its actual Work/current Owner/selection")
    return s

def pin_d07_source_owner_entry_v3(r):
    s=require_d07_source_work_v3(r)
    if r.general_owner_entry is None:raise AuthorityUnavailable("D07 Source lacks its independent current Owner EOF")
    s.identity=_identity(r)

def _active(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind not in D07_SOURCE_OPERATIONS_V3:return None
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    if is_foreground_command_source_reader_v3(r):return None
    require_d07_source_work_v3(r)
    return r

def _source_refs(r,values):
    values=tuple(values)
    if len(set(values))!=len(values):
        raise AuthorityUnavailable("D07 fixed metadata Source locators repeat")
    for value in values:
        key=AtomKey.from_token(value)
        if key.type_name!="memory.source"or NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("D07 metadata Source locator crossed canonical namespace")
    return values

def d07_source_metadata_spec_v3(r,identity):
    s=require_d07_source_work_v3(r)
    kind,*args=identity
    if kind=="d07_original":
        family,original=args
        if family not in {"semantic_question","reflection_request"}or original!=r.request.trigger_original_ref:
            raise AuthorityUnavailable("D07 signed metadata escaped its exact current trigger")
        return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,family,original),("payload_digest","signature"),
            (("schema",),("source_refs",),("target_ref",),("reflection_ref",),
             ("cognition_adoption_receipt_ref",),("causal_root_ref",),("causal_depth_original_ref",)),None)
    if kind=="d07_graph":
        token=args[0];key=AtomKey.from_token(token)
        if token not in s.graph_refs or NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("D07 graph metadata was not selected by the fixed census/signed question")
        return("graph_atoms","value",("token","bot","persona"),(token,*r.namespace.as_tuple),
            ("revision","valid","value_cell_id"),(("schema",),("source_refs",)),None)
    if kind=="d07_job":
        job_id=args[0]
        if job_id not in s.jobs:raise AuthorityUnavailable("D07 job metadata was not selected by actual activity EOF")
        return("runtime_jobs","continuation_json",("job_id",),(job_id,),
            ("job_id","bot_id","persona_id","activity_id","work_kind","operation_id","phase","fence","cancel_epoch",
             "result_ref","budget_ref","snapshot_ref","deadline_utc"),
            (("source_refs",),("registered_request","snapshot_refs"),("cognition_adoption_receipt_ref",),
             ("causal_root_ref",),("causal_depth_original_ref",),("dedicated_budget_original_ref",)),None)
    raise AuthorityUnavailable("unregistered private D07 metadata profile")

def finish_d07_source_metadata_v3(task,value):
    from types import MappingProxyType
    r=task.reader;s=require_d07_source_work_v3(r)
    kind,*args=task.identity
    if kind=="d07_original":
        from .d07_execution_v1 import SIGN_KIND
        family,original=args
        pin=r.d07_dispatch_pin_v3
        if(family,original,*task.metadata)!=pin[:4]:
            raise AuthorityUnavailable("D07 World signed original changed after independent classification")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,family,original,task.metadata[0])),task.metadata[1])
        roots=_source_refs(r,value["source_refs"])
        if family=="semantic_question":
            from ..domains.d03.world_history_v1 import VIEW_TYPE
            fields=task.column.beta1_metadata_fields_seen
            if fields!={"schema","question_key","question","target_ref","source_refs"}:
                raise AuthorityUnavailable("D07 World question fields differ from exact signed schema")
            target=value["target_ref"]
            key=AtomKey.from_token(target["ref"])
            if(value["schema"]!="d07.registered-semantic-question.v1"or set(target)!={"ref","version"}
                    or key.type_name!=VIEW_TYPE or NamespaceId.from_key(key)!=r.namespace
                    or type(target["version"])is not int or target["version"]<1):
                raise AuthorityUnavailable("D07 current Source profile requires its signed exact World view target")
            s.graph_refs.add(key.token);s.versions.add((key.token,target["version"]))
        else:
            key=AtomKey.from_token(value["reflection_ref"])
            if key.type_name!="d07.reflection_checkpoint.v1"or NamespaceId.from_key(key)!=r.namespace:
                raise AuthorityUnavailable("D07 reflection metadata crossed its canonical checkpoint")
            s.graph_refs.add(key.token)
        s.originals.add(original)
        return MappingProxyType({**value,"source_refs":roots})
    if kind=="d07_graph":
        token=args[0];key=AtomKey.from_token(token)
        expected=r.heads.get(token)
        if task.metadata!=expected or expected is None:
            raise AuthorityUnavailable("D07 metadata graph original changed its complete census header")
        roots=_source_refs(r,value.get("source_refs",())if key.type_name=="d07.attention_ticket.v1"and expected[1]==0 else value["source_refs"])
        if key.type_name=="d07.attention_ticket.v1":
            if expected[1]and value["schema"]!="d07.attention_ticket.v1":
                raise AuthorityUnavailable("D07 ticket metadata has another registered graph schema")
        else:
            from ..domains.d03.world_history_v1 import VIEW_TYPE
            if key.type_name!=VIEW_TYPE or expected[1]!=1 or(token,task.metadata[0])not in s.versions:
                raise AuthorityUnavailable("D07 graph metadata is outside its exact signed World revision")
        return roots
    if kind=="d07_job":
        header=dict(zip(task.header_columns,task.metadata))
        if(header["job_id"]!=args[0]or(header["bot_id"],header["persona_id"])!=r.namespace.as_tuple
                or header["activity_id"]!=r.activity_id or not header["work_kind"].startswith("d07.")):
            raise AuthorityUnavailable("D07 metadata job crossed actual same activity/namespace/work kind")
        roots=_source_refs(r,value.get("source_refs",()))
        registered=value.get("registered_request")
        if registered is not None:roots=tuple(dict.fromkeys((*roots,*_source_refs(r,registered["snapshot_refs"]))))
        for name in("cognition_adoption_receipt_ref","causal_root_ref","causal_depth_original_ref","dedicated_budget_original_ref"):
            if value.get(name):s.originals.add(value[name])
        if header["result_ref"]:
            s.originals.add(header["result_ref"]);s.terminals[args[0]]=header["result_ref"]
        if registered is not None:s.originals.add(header["budget_ref"])
        return roots
    raise AuthorityUnavailable("unregistered D07 metadata completion")

class _D07PlanMetadataTaskV3:
    def __init__(self,r):
        self.reader=r;self.phase="question";self.complete=False;self.result=None
        self.roots=set();self.after="";self.job_count=0;self.ticket_index=0
        self.tickets=();self.leaf=None;self.question=None
    def _leaf(self,identity,meter):
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        s=require_d07_source_work_v3(self.reader)
        task=s.tasks.get(identity)
        if task is None:task=create_current_beta1_metadata_task_v3(self.reader,identity);s.tasks[identity]=task
        if not task.complete:task.advance(meter);return False,None
        task.require_header_v3(meter)
        return True,task.result
    def advance(self,meter):
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        r=self.reader;r.require_current(meter=meter);s=require_d07_source_work_v3(r)
        if self.complete:self.require_v3(meter);return True
        if self.phase=="question":
            done,value=self._leaf(("d07_original","semantic_question",r.request.trigger_original_ref),meter)
            if not done:return False
            if value is None:
                self.phase="reflection";return False
            self.question=value;self.roots.update(value["source_refs"]);self.phase="target";return False
        if self.phase=="reflection":
            done,value=self._leaf(("d07_original","reflection_request",r.request.trigger_original_ref),meter)
            if not done:return False
            if value is None:raise AuthorityUnavailable("D07 current concern has no actual signed trigger original")
            self.roots.update(value["source_refs"])
            for name in("cognition_adoption_receipt_ref","causal_root_ref","causal_depth_original_ref"):
                s.originals.add(value[name])
            # Reflection has an independent installed Source profile; a trigger
            # cannot silently switch the World command to that other algorithm.
            raise AuthorityUnavailable("D07 World Source command cannot substitute a reflection trigger")
        if self.phase=="target":
            target=self.question["target_ref"]
            done,roots=self._leaf(("d07_graph",target["ref"]),meter)
            if not done:return False
            if roots is None or set(roots)!=set(self.question["source_refs"]):
                raise AuthorityUnavailable("D07 signed question Source roots differ from actual World original EOF")
            self.roots.update(roots)
            self.tickets=tuple(sorted(token for token,head in r.heads.items()
                if AtomKey.from_token(token).type_name=="d07.attention_ticket.v1"))
            if len(self.tickets)>128:raise AuthorityUnavailable("D07 full ticket metadata exceeds original bound")
            s.graph_refs.update(self.tickets);self.phase="tickets";return False
        if self.phase=="tickets":
            if self.ticket_index==len(self.tickets):self.phase="jobs";return False
            done,roots=self._leaf(("d07_graph",self.tickets[self.ticket_index]),meter)
            if not done:return False
            self.roots.update(roots);self.ticket_index+=1;return False
        if self.phase=="jobs":
            row=_beta1_metadata_row_v3(r,meter,"runtime_jobs",("job_id",),
                "bot_id=? AND persona_id=? AND activity_id=? AND work_kind LIKE 'd07.%' AND job_id>? ORDER BY job_id",
                (*r.namespace.as_tuple,r.activity_id,self.after))
            if row is None:self.phase="seal";return False
            self.job_count+=1
            if self.job_count>16:raise AuthorityUnavailable("D07 current job metadata exceeds original 16-row bound")
            self.after=row[0];s.jobs.add(row[0]);self.phase="job_leaf";return False
        if self.phase=="job_leaf":
            done,roots=self._leaf(("d07_job",self.after),meter)
            if not done:return False
            if roots is None:raise AuthorityUnavailable("D07 current selected job disappeared before metadata EOF")
            self.roots.update(roots);self.phase="prepared_leaf";return False
        if self.phase=="prepared_leaf":
            done,prepared=self._leaf(("d07_prepared",self.after),meter)
            if not done:return False
            if prepared is None:raise AuthorityUnavailable("D07 current job lacks its actual signed prepared original")
            self.roots.update(prepared["roots"])
            s.prepared_keys.update(v.key for v in prepared["versions"])
            s.versions.update((v.key.token,v.revision)for v in prepared["versions"])
            self.phase="terminal_leaf"if self.after in s.terminals else "jobs";return False
        if self.phase=="terminal_leaf":
            done,terminal=self._leaf(("d07_terminal",self.after),meter)
            if not done:return False
            if terminal is None:raise AuthorityUnavailable("D07 current job terminal original is missing")
            self.roots.update(terminal["roots"])
            s.prepared_keys.update(v.key for v in terminal["versions"])
            s.versions.update((v.key.token,v.revision)for v in terminal["versions"])
            self.phase="jobs";return False
        if self.phase=="seal":
            from .d01_production_operations_v1 import production_read_plan_v1
            from .d12_current_d07_policy_v1 import active_scheme_head_key
            from ..domains.d07.concern_round import concern_round_key
            keys={owner_grant_key(*r.namespace.as_tuple),active_scheme_head_key(r.namespace),
                concern_round_key(r.namespace,r.request.category),
                AtomKey(Owner("activity",*r.namespace.as_tuple,r.activity_id),"d07.cognitive_activity.v1",r.activity_id),
                *s.prepared_keys,*(AtomKey.from_token(token)for token in s.graph_refs)}
            s.versions.update((token,head[0])for token,head in r.heads.items()
                if AtomKey.from_token(token).type_name in D07_SOURCE_INVENTORIES_V3)
            self.result=production_read_plan_v1(D07_SOURCE_INVENTORIES_V3,keys,sorted(self.roots),sorted(s.originals))
            s.plan=self.result;self.complete=True;return True
        raise AuthorityUnavailable("unregistered D07 fixed metadata phase")
    def require_v3(self,meter):
        r=self.reader;s=require_d07_source_work_v3(r);r.require_current(meter=meter)
        if not self.complete or s.plan is not self.result:
            raise AuthorityUnavailable("D07 fixed metadata closure lacks actual EOF")
        for task in s.tasks.values():
            if task is not self:task.require_header_v3(meter)
        current=tuple(sorted(token for token,head in r.heads.items()
            if AtomKey.from_token(token).type_name in D07_SOURCE_INVENTORIES_V3))
        # The original full graph census binds complete positive and negative
        # membership of every fixed inventory, including invalid members.
        expected=tuple((token,r.heads[token])for token in current)
        if not r.graph_eof or not r.inventory_sealed or self.inventory!=expected:
            raise AuthorityUnavailable("D07 eight fixed inventory metadata lost complete census EOF")
        return self

def create_d07_source_metadata_task_v3(r,identity):
    s=require_d07_source_work_v3(r)
    if identity!=("d07_plan",r.request):
        raise AuthorityUnavailable("D07 plan metadata changed its actual fixed command")
    key=("d07_plan",r.request)
    task=s.tasks.get(key)
    if task is None:
        task=_D07PlanMetadataTaskV3(r)
        task.inventory=tuple((token,r.heads[token])for token in sorted(r.heads)
            if AtomKey.from_token(token).type_name in D07_SOURCE_INVENTORIES_V3)
        s.tasks[key]=task
    return task

def read_bound_d07_source_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    r=_active(db)
    if r is None:return False,None
    if(namespace!=r.namespace or activity_id!=r.activity_id or operation_kind!=r.operation_kind or request!=r.request):
        raise AuthorityUnavailable("D07 read plan crossed its originating command")
    s=require_d07_source_work_v3(r);task=s.tasks.get(("d07_plan",r.request))
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",("d07_plan",r.request)))
    with runtime_storage_quantum_v3(db)as meter:task.require_v3(meter)
    return True,task.result

def d07_source_groups_v3(r,roots):
    s=require_d07_source_work_v3(r)
    task=s.tasks.get(("d07_plan",r.request))
    if(task is None or not task.complete or s.plan!=r.selected_plan or tuple(sorted(set(roots)))!=tuple(sorted(s.plan.source_roots))
            or r.authority.purpose!="context"or r.selected_envelope.authority.purpose!="context"
            or r.authority.audience!=(r.audience_ref,)or r.selected_envelope.authority.audience!=(r.audience_ref,)):
        raise AuthorityUnavailable("D07 Sources require its actual fixed context/current audience complete metadata recipe")
    with runtime_storage_quantum_v3(r.db)as meter:task.require_v3(meter)
    return(("context",(r.audience_ref,),tuple(roots)),)

def require_d07_sources_v3(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    s=require_d07_source_work_v3(r);cap=qualify_current_beta1_source_groups_v3(r,roots)
    s.source_permission=cap
    s.versions.update((v.key.token,v.revision)for v in cap.versions if v.key.type_name=="memory.source")
    return cap

def require_d07_source_body_v3(r,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    s=require_d07_source_work_v3(r)
    if table=="graph_atoms"and require_beta1_source_control_point_v3(r,
            (table,("revision","value","valid"),("token","bot","persona"),tuple(key))):return
    if(table=="runtime_budget_grants"and r.budget_task is not None
            and tuple(key)==tuple(r.budget_task.metadata[:2])and key[0]==r.parent_budget_lease_ref):return
    cap=s.source_permission
    if cap is None:raise AuthorityUnavailable("D07 selected body requires independent all-parent Source completion")
    cap.require_for_v3(r)
    if table in {"graph_atoms","graph_history"}:
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=r.namespace:raise AuthorityUnavailable("D07 body crossed namespace")
        if table=="graph_history":
            if(atom.token,key[1])not in s.versions:raise AuthorityUnavailable("D07 history has no actual signed selected revision")
        elif atom not in r.selected_plan.exact_keys and atom.token not in cap.source_refs and atom.type_name not in D07_SOURCE_INVENTORIES_V3:
            raise AuthorityUnavailable("D07 body escaped its exact fixed selection")
        return
    if table=="graph_d07_execution_originals_v1":
        if key[:2]!=r.namespace.as_tuple or (key[-1]not in s.originals and not(key[-2]in {"prepared","accounting_prepared","prepare_commit","paid_cost","body_cost"}and key[-1]in s.jobs)):
            raise AuthorityUnavailable("D07 signed original escaped fixed trigger/current job locators")
        return
    if table=="runtime_jobs"and tuple(key)==(key[0],)and key[0]in s.jobs:return
    raise AuthorityUnavailable("D07 body is outside its closed own Source point recipe")

def require_d07_source_point_v3(r,request):
    s=require_d07_source_work_v3(r);table,columns,key_columns,key=request
    if len(key)!=len(key_columns):raise AuthorityUnavailable("D07 point requires exact full primary key")
    if table=="graph_atoms"and tuple(key_columns)==("token","bot","persona")and tuple(columns)==("revision","value","valid"):
        require_d07_source_body_v3(r,table,key);return
    if table=="graph_history"and tuple(key_columns)==("token","revision")and tuple(columns)in{
            ("event_id","value","valid"),("value","valid","event_id"),("event_id","valid"),
            ("event_bot","event_persona","event_id","valid")}:
        require_d07_source_body_v3(r,table,key);return
    if table=="graph_d07_execution_originals_v1"and tuple(key_columns)==("bot","persona","kind","original_ref")and tuple(columns)==("payload_json","payload_digest","signature"):
        require_d07_source_body_v3(r,table,key);return
    from .domain_background_read_v3 import _D07_POINT_COLUMNS
    if table=="runtime_jobs"and tuple(key_columns)==("job_id",)and set(columns)<=_D07_POINT_COLUMNS[table]|{"job_id"}:
        require_d07_source_body_v3(r,table,key);return
    raise AuthorityUnavailable("D07 point shape has no closed own Source registration")

def register_d07_source_write_phase_v3(inputs,scope,current_owner):
    from .current_method_learning_read_v3 import _method_active
    r=inputs.owner;s=require_d07_source_work_v3(r)
    if not r.inputs_sealed:return
    if(not r.read_finished or not r.business_started or scope.operation!="write"or scope is r.fence.scope
            or current_owner!=r.owner_binding or inputs.plan!=r.selected_plan or _method_active(r.db)is not r):
        raise AuthorityUnavailable("D07 requires its actual fresh same-Work WRITE/Owner")
    if s.source_permission is None:raise AuthorityUnavailable("D07 WRITE cannot prepare missing Source authority")
    _WRITES[r]=(inputs,scope,current_owner,_identity(r),r.selected_plan)

def require_d07_source_write_phase_v3(r):
    from .current_method_learning_read_v3 import _method_active
    value=_WRITES.get(r)
    if(value is None or value[3]!=_identity(r)or value[4]!=r.selected_plan or _method_active(r.db)is not r
            or not r.read_finished or not r.inputs_sealed or not r.business_started):
        raise AuthorityUnavailable("D07 Source permission lost actual fresh WRITE binding")
    return value

def register_d07_source_stage_v3(db,stage,*,request):
    r=_active(db)
    if r is None:return stage
    s=require_d07_source_work_v3(r);require_d07_source_write_phase_v3(r)
    if request!=r.request:raise AuthorityUnavailable("D07 private stage changed its actual command request")
    cap=require_d07_sources_v3(r,r.selected_plan.source_roots)
    identity=id(stage)
    _PROPOSALS[identity]=(stage,r,r.work,r.operation,r.selection_digest,cap,canonical_digest(stage))
    return stage

def require_d07_source_stage_v3(db,stage):
    r=_active(db)
    if r is None:return stage
    record=_PROPOSALS.get(id(stage))
    if(record is None or record[0]is not stage or record[1]is not r
            or record[2:5]!=(r.work,r.operation,r.selection_digest)or record[-1]!=canonical_digest(stage)):
        raise AuthorityUnavailable("D07 stage was not issued by its actual Source-qualified private producer")
    record[5].require_for_v3(r);require_d07_source_write_phase_v3(r)
    return stage

def release_d07_source_work_v3(r):
    _STATES.pop(r,None);_WRITES.pop(r,None)
    for key,record in tuple(_PROPOSALS.items()):
        if record[1]is r:_PROPOSALS.pop(key,None)

def read_bound_d07_source_original_refs_v3(db,*,namespace,plan,installed_readers,external):
    from .d07_execution_v1 import read_current_original_ref_v1
    r=_active(db)
    if r is None:return False,None
    s=require_d07_source_work_v3(r)
    if namespace!=r.namespace or plan!=r.selected_plan or set(plan.required_original_refs)!=s.originals:
        raise AuthorityUnavailable("D07 original refs changed the actual fixed metadata plan")
    require_d07_sources_v3(r,plan.source_roots)
    if installed_readers is None or installed_readers.issuer is not r.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable("D07 original refs lost the actual installed same-Work issuer")
    result=[]
    for original_ref in plan.required_original_refs:
        original=read_current_original_ref_v1(db,namespace,original_ref,issuer=installed_readers.issuer)
        if original is not None:result.append(original)
    for original in external:
        if original.kind in {"d11.restore_anchor","d11.trusted_tick","d11.clock_sample","d03.current_self_identity"}:
            result.append(original)
    return True,tuple(result)
