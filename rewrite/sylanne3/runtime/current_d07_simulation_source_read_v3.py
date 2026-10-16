"""Independent Source work for actual registered D07 simulation preparation."""
from dataclasses import dataclass,field,replace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,Owner,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _heap
from .d07_source_owner_read_v3 import D07_SOURCE_INVENTORIES_V3,_source_refs

D07_SIMULATION_SOURCE_WORK_KIND_V3="current_d07_simulation_source_read_v3"
SIMULATION_METADATA_INVENTORY_TYPES_V3=frozenset((*D07_SOURCE_INVENTORIES_V3[:5],"d07.simulation_forecast_plan.v1"))
_SIMULATIONS=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_FRAMES=WeakKeyDictionary()
_STAGES={}

@dataclass(slots=True)
class _SimulationSourceStateV3:
    reader:object
    identity:tuple
    tasks:dict=field(default_factory=dict)
    selected:set=field(default_factory=set)
    histories:set=field(default_factory=set)
    producers:dict=field(default_factory=dict)
    absent_trigger_producers:set=field(default_factory=set)
    jobs:set=field(default_factory=set)
    terminals:dict=field(default_factory=dict)
    prepared_keys:set=field(default_factory=set)
    originals:set=field(default_factory=set)
    cap:object=None
    plan:object=None
    metadata:object=None
    forecast:object=None
    final:bool=False
    trigger_kind:object=None

def _identity(r):
    return(r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,r.request,
        r.operation_id,r.activity_id,r.authority,r.lease,r.owner_binding)

def register_current_d07_simulation_source_work_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    from .d07_current_behavior_v1 import RunCurrentSimulationRequestV1
    require_current_beta1_source_work_v3(r)
    if(r in _SIMULATIONS or r.operation_kind!="run_simulation"
            or r.work.kind!=D07_SIMULATION_SOURCE_WORK_KIND_V3 or type(r.request)is not RunCurrentSimulationRequestV1):
        raise AuthorityUnavailable("D07 simulation requires its exact independent installed Source command")
    _SIMULATIONS[r]=_SimulationSourceStateV3(r,_identity(r))

def require_current_d07_simulation_source_work_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    s=_SIMULATIONS.get(r);actual=_identity(r)
    if(s is None or s.identity[:-1]!=actual[:-1]or s.identity[-1]is not actual[-1]and s.cap is not None):
        raise AuthorityUnavailable("D07 simulation lost actual original Work/current Owner")
    return s

def pin_current_d07_simulation_owner_v3(r):
    s=require_current_d07_simulation_source_work_v3(r);s.identity=_identity(r)

def _active(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind!="run_simulation":return None
    require_current_d07_simulation_source_work_v3(r)
    return r

def _version(r,value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    v=decode_typed_production_value_v1(value,GraphVersion)
    if NamespaceId.from_key(v.key)!=r.namespace or v.revision<1:
        raise AuthorityUnavailable("simulation frozen version crossed canonical namespace/revision")
    return v

def simulation_metadata_spec_v3(r,identity):
    s=require_current_d07_simulation_source_work_v3(r);kind,*args=identity
    if kind=="simulation_request":
        if args[0]!=r.request.simulation_request_ref:raise AuthorityUnavailable("simulation original selector changed")
        return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,"simulation_request",args[0]),("payload_digest","signature"),
            (("schema",),("request","activity_id"),("request","snapshot_refs"),("request_digest",),("dedicated_budget_ref",)),None)
    if kind=="simulation_trigger":
        family,original=args
        if original!=r.request.trigger_original_ref or family!=s.trigger_kind:
            raise AuthorityUnavailable("simulation trigger metadata changed actual registered family")
        paths=(("schema",),("source_refs",),("request","snapshot_refs"))
        if family=="prepared":
            paths=(("schema",),("namespace",),("job_id",),("operation_id",),("activity_id",),("work_kind",),("read_rows",))
        return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,family,original),("payload_digest","signature"),paths,None)
    if kind=="simulation_graph":
        token=args[0];key=AtomKey.from_token(token)
        if token not in s.selected or NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("simulation metadata Graph key was not selected by fixed EOF locators")
        return("graph_atoms","value",("token","bot","persona"),(token,*r.namespace.as_tuple),
            ("revision","valid","value_cell_id"),(("schema",),("namespace",),("source_refs",),
            ("simulation_request_ref",),("simulation_activity_id",),("baseline_snapshot",),
            ("baseline_assumption_ref",),("alternative_assumption_refs",),("forecasts",),
            ("calibration_policy_ref",),("conditions",),("question_key",),("current",)),None)
    if kind=="simulation_job":
        job=args[0]
        if job not in s.jobs:raise AuthorityUnavailable("simulation job lacks actual same-activity metadata selector")
        return("runtime_jobs","continuation_json",("job_id",),(job,),
            ("job_id","bot_id","persona_id","activity_id","work_kind","operation_id","phase","fence","cancel_epoch",
             "result_ref","budget_ref","snapshot_ref","deadline_utc"),
            (("source_refs",),("registered_request","snapshot_refs"),("simulation_request_ref",),
             ("cognition_adoption_receipt_ref",),("causal_root_ref",),("causal_depth_original_ref",),("dedicated_budget_original_ref",)),None)
    if kind=="simulation_producer":
        operation=args[0]
        if operation not in s.producers:raise AuthorityUnavailable("simulation producer was not derived from exact actual Graph history")
        return("graph_domain_production_originals_v1","read_versions_json",("bot","persona","operation_id"),
            (*r.namespace.as_tuple,operation),("domain","operation_kind","request_digest","original_digest","receipt_digest"),((),),None)
    raise AuthorityUnavailable("unregistered simulation metadata profile")

def retain_current_d07_simulation_metadata_path_v3(task,path):
    if task.identity[0]=="simulation_trigger"and task.identity[1]=="prepared":
        from .d07_source_preparation_members_v3 import retain_d07_prepared_metadata_path_v3
        return retain_d07_prepared_metadata_path_v3(task,path)
    if task.identity[0]!="simulation_graph":
        return any(p[:len(path)]==path or path[:len(p)]==p for p in task.paths)
    if not path:return True
    if path[0]=="conditions":
        return len(path)<3 or path[2]==0
    if path[0]=="forecasts":
        if len(path)<3:return True
        if type(path[1])is not int:return False
        return path[2]in{"namespace","schema","source_refs","assumption_heads","condition_goal_head","condition_goal_revision",
            "target_head","condition_predicate_ref","branch_ref","assumption_refs","prediction_id"}
    return path[0]in{"schema","namespace","source_refs","simulation_request_ref","simulation_activity_id","baseline_snapshot",
        "baseline_assumption_ref","alternative_assumption_refs","calibration_policy_ref","question_key","current"}

def finish_current_d07_simulation_metadata_v3(task,value):
    from types import MappingProxyType
    r=task.reader;s=require_current_d07_simulation_source_work_v3(r);kind,*args=task.identity
    if kind=="simulation_request":
        from .d07_execution_v1 import SIGN_KIND
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,"simulation_request",args[0],task.metadata[0])),task.metadata[1])
        if(task.column.beta1_metadata_fields_seen!={"schema","request","request_digest","dedicated_budget_ref","owner_guard"}
                or value["schema"]!="d07.registered-simulation-original.v1"):
            raise AuthorityUnavailable("simulation registered original differs from exact signed schema")
        roots=_source_refs(r,value["request"]["snapshot_refs"])
        if not roots:raise AuthorityUnavailable("simulation original has no actual frozen Source snapshot")
        s.originals.update((r.request.simulation_request_ref,r.request.trigger_original_ref,value["dedicated_budget_ref"]))
        return MappingProxyType({**value,"snapshot_refs":roots})
    if kind=="simulation_trigger":
        from .d07_execution_v1 import SIGN_KIND
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,args[0],args[1],task.metadata[0])),task.metadata[1])
        if args[0]=="prepared":
            from .d07_source_preparation_members_v3 import require_d07_trigger_prepared_metadata_v3
            roots,versions=require_d07_trigger_prepared_metadata_v3(task,value)
            s.prepared_keys.update(v.key for v in versions);s.histories.update((v.key.token,v.revision)for v in versions)
            return roots
        return tuple(dict.fromkeys((*_source_refs(r,value.get("source_refs",())),
            *_source_refs(r,value.get("request",{}).get("snapshot_refs",())))))
    if kind=="simulation_job":
        header=dict(zip(task.header_columns,task.metadata))
        if((header["bot_id"],header["persona_id"])!=r.namespace.as_tuple or header["activity_id"]!=r.activity_id
                or not header["work_kind"].startswith("d07.")):
            raise AuthorityUnavailable("simulation job metadata crossed same-activity namespace")
        roots=_source_refs(r,value.get("source_refs",()))
        registered=value.get("registered_request")
        if registered is not None:roots=tuple(dict.fromkeys((*roots,*_source_refs(r,registered["snapshot_refs"]))))
        for name in("cognition_adoption_receipt_ref","causal_root_ref","causal_depth_original_ref","dedicated_budget_original_ref"):
            if value.get(name):s.originals.add(value[name])
        if header["result_ref"]:
            s.originals.add(header["result_ref"]);s.terminals[args[0]]=header["result_ref"]
        if registered is not None:s.originals.add(header["budget_ref"])
        return roots
    if kind=="simulation_producer":
        if task.metadata[1]not in s.producers[args[0]]:
            raise AuthorityUnavailable("simulation actual original producer kind differs from adopted exact Graph history")
        result=[]
        for token,revision in value:
            key=AtomKey.from_token(token)
            if NamespaceId.from_key(key)!=r.namespace or type(revision)is not int or revision<0:
                raise AuthorityUnavailable("simulation producer read metadata crossed actual namespace/revision")
            if key.type_name=="memory.source":result.append(token)
        return tuple(result)
    if kind=="simulation_graph":
        token=args[0];key=AtomKey.from_token(token);expected=r.heads.get(token)
        if task.metadata!=expected or expected is None:
            raise AuthorityUnavailable("simulation metadata Graph original changed its full census physical header")
        from ..domains.d07.prediction_v1 import FORECAST_PLAN_TYPE
        from ..domains.d01.conditioned_self_v1 import CONDITION_TYPE,require_conditioned_record_locator_v1
        if key.type_name in {FORECAST_PLAN_TYPE,CONDITION_TYPE}:
            roots=require_conditioned_record_locator_v1(value,task.column.beta1_metadata_fields_seen,
                namespace=r.namespace,type_name=key.type_name)
        else:roots=(token,)if key.type_name=="memory.source"else _source_refs(r,value.get("source_refs",()))
        if key.type_name==CONDITION_TYPE:value={**value,"condition_ids":tuple(row[0]for row in value["conditions"])}
        return MappingProxyType({**value,"source_refs":tuple(roots)})
    raise AuthorityUnavailable("unregistered simulation metadata completion")

class _SimulationMetadataClosureV3:
    def __init__(self,r):
        self.reader=r;self.phase="request";self.complete=False;self.result=None
        self.index=0;self.after="";self.count=0;self.roots=set();self.queue=[];self.forecasts=[];self.c1=[]
        self.producer_roots=set();self.registered=None;self.forecast=None;self.trigger=None
    def _leaf(self,identity,meter):
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        s=require_current_d07_simulation_source_work_v3(self.reader)
        task=s.tasks.get(identity)
        if task is None:task=create_current_beta1_metadata_task_v3(self.reader,identity);s.tasks[identity]=task
        if not task.complete:task.advance(meter);return False,None
        task.require_header_v3(meter);return True,task.result
    def _origin(self,token,meter,*,trigger=False):
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        r=self.reader;s=require_current_d07_simulation_source_work_v3(r);head=r.heads[token];key=AtomKey.from_token(token)
        row=_beta1_metadata_row_v3(r,meter,"graph_history",("event_bot","event_persona","event_id","valid","value_cell_id"),
            "token=? AND revision=?",(token,head[0]))
        if row is None or row[:2]!=r.namespace.as_tuple or row[3]!=head[1]or row[4]!=head[2]:
            raise AuthorityUnavailable("simulation selected Graph metadata has no exact actual namespace/history member")
        expected={"d07.simulation_forecast_plan.v1":"register_simulation_forecast_plan_v1",
            "d01.condition_predicate.v1":"register_condition_predicate_v1",
            "d07.current_interpretation.v1":"adopt_current_c1_method_conditions_v1"}.get(key.type_name)
        if trigger:
            from .domain_production_registry_v1 import installed_operation_v1
            producer=_beta1_metadata_row_v3(r,meter,"graph_domain_production_originals_v1",("domain","operation_kind"),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,row[2]))
            if producer is None:s.absent_trigger_producers.add(row[2])
            else:
                if installed_operation_v1(producer[1]).domain!=producer[0]:
                    raise AuthorityUnavailable("simulation explicit trigger has an unregistered actual domain producer")
                s.producers.setdefault(row[2],set()).add(producer[1])
        elif expected is not None:s.producers.setdefault(row[2],set()).add(expected)
        s.histories.add((token,head[0]))
    def advance(self,meter):
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        from ..domains.d07.prediction_v1 import FORECAST_PLAN_TYPE
        from ..domains.d01.conditioned_self_v1 import CONDITION_TYPE
        r=self.reader;r.require_current(meter=meter);s=require_current_d07_simulation_source_work_v3(r)
        if self.complete:self.require_v3(meter);return True
        if self.phase=="request":
            done,value=self._leaf(("simulation_request",r.request.simulation_request_ref),meter)
            if not done:return False
            if value is None:raise AuthorityUnavailable("actual signed registered simulation request is absent")
            self.registered=value;self.roots.update(value["snapshot_refs"])
            self.phase="trigger";return False
        if self.phase=="trigger":
            try:key=AtomKey.from_token(r.request.trigger_original_ref)
            except (ValueError,TypeError):
                self.phase="trigger_original";return False
            if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("simulation trigger crossed canonical namespace")
            s.selected.add(key.token)
            done,trigger=self._leaf(("simulation_graph",key.token),meter)
            if not done:return False
            if trigger is None or r.heads[key.token][1]!=1:raise AuthorityUnavailable("simulation current trigger original is absent or invalid")
            self.trigger=key.token;self.roots.update(trigger["source_refs"]);s.histories.add((key.token,r.heads[key.token][0]))
            from ..domains.d01.method_learning_v1 import VALUE_TYPES
            if key.type_name=="d07.current_interpretation.v1"or key.type_name in VALUE_TYPES:
                self._origin(key.token,meter,trigger=True)
            self.phase="plan_list";return False
        if self.phase=="trigger_original":
            row=_beta1_metadata_row_v3(r,meter,"graph_d07_execution_originals_v1",("kind",),
                "bot=? AND persona=? AND original_ref=? AND kind IN ('semantic_question','reflection_request','prepared','adopted','simulation_request','simulation_budget','execution') ORDER BY kind",
                (*r.namespace.as_tuple,r.request.trigger_original_ref))
            if row is None:raise AuthorityUnavailable("simulation trigger has no actual registered original family")
            s.trigger_kind=row[0]
            done,trigger=self._leaf(("simulation_trigger",row[0],r.request.trigger_original_ref),meter)
            if not done:return False
            if trigger is None:raise AuthorityUnavailable("simulation trigger signed original disappeared")
            self.roots.update(trigger);self.phase="plan_list";return False
        if self.phase=="plan_list":
            self.queue=sorted(token for token in r.heads if AtomKey.from_token(token).type_name==FORECAST_PLAN_TYPE)
            if len(self.queue)>128:raise AuthorityUnavailable("forecast plan metadata exceeds original fixed-family bound")
            s.selected.update(self.queue);self.phase="plans";return False
        if self.phase=="plans":
            if self.index==len(self.queue):
                if len(self.forecasts)>1:raise AuthorityUnavailable("simulation has nonunique actual preregistered forecast plan")
                self.forecast=self.forecasts[0]if self.forecasts else None;s.forecast=self.forecast
                pending=set()
                if self.forecast is not None:
                    token,value=self.forecast
                    if r.heads[token][1]!=1:raise AuthorityUnavailable("simulation matching forecast Plan is invalid")
                    if set(value["source_refs"])!=set(self.registered["snapshot_refs"]):
                        raise AuthorityUnavailable("forecast Plan must bind every actual registered snapshot Source")
                    self.roots.update(value["source_refs"])
                    for raw in value["baseline_snapshot"]:
                        version=_version(r,raw)
                        if r.heads.get(version.key.token,())[:2]!=(version.revision,1):
                            raise AuthorityUnavailable("simulation Plan frozen baseline Source revision changed")
                    for prediction in value["forecasts"]:
                        if not set(prediction["source_refs"])<=set(self.registered["snapshot_refs"]):
                            raise AuthorityUnavailable("forecast child cannot add an undeclared frozen snapshot Source")
                        self.roots.update(_source_refs(r,prediction["source_refs"]))
                        pending.add(prediction["condition_predicate_ref"])
                        for raw in(*prediction["assumption_heads"],prediction["condition_goal_head"],prediction["target_head"]):
                            version=_version(r,raw)
                            if r.heads.get(version.key.token,())[:2]!=(version.revision,1):
                                raise AuthorityUnavailable("simulation forecast frozen exact assumption/Goal/target revision changed")
                            s.selected.add(version.key.token)
                    pending.update((value["baseline_assumption_ref"],*value["alternative_assumption_refs"]))
                self.queue=sorted(pending);self.index=0;s.selected.update(self.queue);self.phase="conditions";return False
            token=self.queue[self.index]
            done,value=self._leaf(("simulation_graph",token),meter)
            if not done:return False
            if value is None:raise AuthorityUnavailable("forecast Plan census member disappeared before metadata EOF")
            if value["simulation_request_ref"]==r.request.simulation_request_ref:
                self.forecasts.append((token,value));self._origin(token,meter)
            self.index+=1;return False
        if self.phase=="conditions":
            if self.index==len(self.queue):
                if self.forecast is None:self.phase="jobs";return False
                self.queue=sorted(token for token in r.heads if AtomKey.from_token(token).type_name=="d07.current_interpretation.v1")
                if len(self.queue)>128:raise AuthorityUnavailable("simulation current C1 metadata exceeds original family bound")
                s.selected.update(self.queue);self.index=0;self.phase="c1";return False
            token=self.queue[self.index];key=AtomKey.from_token(token)
            if key.type_name!=CONDITION_TYPE:raise AuthorityUnavailable("simulation declared assumption is not its registered Condition predicate")
            done,value=self._leaf(("simulation_graph",token),meter)
            if not done:return False
            if value is None or r.heads[token][1]!=1:raise AuthorityUnavailable("simulation declared Condition is not current and valid")
            if not set(value["source_refs"])<=set(self.registered["snapshot_refs"]):
                raise AuthorityUnavailable("simulation Condition body would require an undeclared Source outside frozen snapshot")
            self.roots.update(value["source_refs"]);self._origin(token,meter);self.index+=1;return False
        if self.phase=="c1":
            if self.index==len(self.queue):self.phase="jobs";return False
            token=self.queue[self.index];done,value=self._leaf(("simulation_graph",token),meter)
            if not done:return False
            if value is None:raise AuthorityUnavailable("simulation C1 metadata census member disappeared")
            if self.forecast is not None and r.heads[token][1]and value.get("current")is True:
                from ..domains.d07 import decode_method_condition_question_v1
                scope=decode_method_condition_question_v1(value.get("question_key"))
                relevant=tuple(p for p in self.forecast[1]["forecasts"]if scope is not None and
                    (scope["goal_ref"],scope["goal_revision"])==(_version(r,p["condition_goal_head"]).key.token,p["condition_goal_revision"]))
                if relevant:
                    if not set(value["source_refs"])<=set(self.registered["snapshot_refs"]):
                        raise AuthorityUnavailable("simulation current C1 facts require undeclared snapshot Sources")
                    self.roots.update(value["source_refs"]);self.c1.append((token,r.heads[token][0],scope["goal_ref"],scope["goal_revision"],scope["condition_id"]))
                    self._origin(token,meter)
            self.index+=1;return False
        if self.phase=="jobs":
            row=_beta1_metadata_row_v3(r,meter,"runtime_jobs",("job_id",),
                "bot_id=? AND persona_id=? AND activity_id=? AND work_kind LIKE 'd07.%' AND job_id>? ORDER BY job_id",
                (*r.namespace.as_tuple,r.activity_id,self.after))
            if row is None:
                self.queue=sorted(s.producers);self.index=0;self.phase="producers";return False
            self.count+=1
            if self.count>16:raise AuthorityUnavailable("simulation current activity job inventory exceeds original bound")
            self.after=row[0];s.jobs.add(row[0]);self.phase="job";return False
        if self.phase=="job":
            done,roots=self._leaf(("simulation_job",self.after),meter)
            if not done:return False
            if roots is None:raise AuthorityUnavailable("simulation current selected job disappeared")
            self.roots.update(roots);self.phase="prepared";return False
        if self.phase=="prepared":
            done,prepared=self._leaf(("simulation_prepared",self.after),meter)
            if not done:return False
            if prepared is None:raise AuthorityUnavailable("simulation current job lacks signed actual prepared original")
            self.roots.update(prepared["roots"])
            s.prepared_keys.update(v.key for v in prepared["versions"])
            s.histories.update((v.key.token,v.revision)for v in prepared["versions"])
            self.phase="terminal"if self.after in s.terminals else "jobs";return False
        if self.phase=="terminal":
            done,terminal=self._leaf(("d07_terminal",self.after),meter)
            if not done:return False
            if terminal is None:raise AuthorityUnavailable("simulation current job terminal original is missing")
            self.roots.update(terminal["roots"])
            s.prepared_keys.update(v.key for v in terminal["versions"])
            s.histories.update((v.key.token,v.revision)for v in terminal["versions"])
            self.phase="jobs";return False
        if self.phase=="producers":
            if self.index==len(self.queue):self.phase="seal";return False
            done,roots=self._leaf(("simulation_producer",self.queue[self.index]),meter)
            if not done:return False
            if roots is None:raise AuthorityUnavailable("simulation adopted producer original is missing")
            self.producer_roots.update(roots);self.index+=1;return False
        if self.phase=="seal":
            from .d01_production_operations_v1 import production_read_plan_v1
            from .d12_current_d07_policy_v1 import active_scheme_head_key
            relevant=set()
            if self.trigger is not None:relevant.add(self.trigger)
            if self.forecast is not None:
                token,value=self.forecast;relevant.add(token)
                for p in value["forecasts"]:
                    declared={(_version(r,v).key.token,_version(r,v).revision)for v in p["assumption_heads"]}
                    condition=s.tasks[("simulation_graph",p["condition_predicate_ref"])].result
                    goal=_version(r,p["condition_goal_head"]).key.token
                    matches=tuple((token,revision,condition_id)for token,revision,goal_ref,goal_revision,condition_id in self.c1
                        if(goal_ref,goal_revision)==(goal,p["condition_goal_revision"])and condition_id in condition["condition_ids"])
                    if(declared!={(token,revision)for token,revision,_ in matches}
                            or len({condition_id for _,_,condition_id in matches})!=len(matches)):
                        raise AuthorityUnavailable("simulation frozen C1 condition set is not actual complete unique current set")
                    relevant.add(p["condition_predicate_ref"])
                    relevant.update(_version(r,v).key.token for v in(*p["assumption_heads"],p["condition_goal_head"],p["target_head"]))
                relevant.update((value["baseline_assumption_ref"],*value["alternative_assumption_refs"]))
            s.selected.update(relevant)
            keys={owner_grant_key(*r.namespace.as_tuple),active_scheme_head_key(r.namespace),
                AtomKey(Owner("activity",*r.namespace.as_tuple,r.activity_id),"d07.cognitive_activity.v1",r.activity_id),
                *s.prepared_keys,*(AtomKey.from_token(token)for token in relevant)}
            self.result=production_read_plan_v1((*D07_SOURCE_INVENTORIES_V3,FORECAST_PLAN_TYPE),keys,sorted(self.roots),sorted(s.originals))
            s.plan=self.result;s.metadata=self;self.complete=True;return True
        raise AuthorityUnavailable("unregistered simulation fixed metadata phase")
    def require_v3(self,meter):
        r=self.reader;s=require_current_d07_simulation_source_work_v3(r);r.require_current(meter=meter)
        if not self.complete or s.metadata is not self or not r.graph_eof or not r.inventory_sealed:
            raise AuthorityUnavailable("simulation metadata closure lost actual fixed complete EOF")
        from .current_beta1_source_read_v3 import _Beta1MetadataTaskV3
        for task in s.tasks.values():
            if type(task)is _Beta1MetadataTaskV3:task.require_header_v3(meter)
        return self

class _FinalizeSimulationPlanV3:
    def __init__(self,r):
        self.reader=r;self.complete=False;self.point=None
    def advance(self,meter):
        from .current_method_learning_read_v3 import _MethodPointReadV3
        from ..domains.d07 import D07DomainProvider
        r=self.reader;s=require_current_d07_simulation_source_work_v3(r);r.require_current(meter=meter)
        s.cap.require_for_v3(r)
        request=("graph_d07_execution_originals_v1",("payload_json","payload_digest","signature"),
            ("bot","persona","kind","original_ref"),(*r.namespace.as_tuple,"simulation_request",r.request.simulation_request_ref))
        if self.point is None:
            self.point=r.points.get(request)
            if self.point is None:self.point=_MethodPointReadV3(r,request);r.points[request]=self.point
        if not self.point.complete:self.point.advance(meter);return False
        row=self.point.require_row_v3(meter)
        original=s.tasks[("simulation_request",r.request.simulation_request_ref)]
        if row is None or row[1:]!=original.metadata or self.point.values["payload_json"].canonical_digest!=original.metadata[0]:
            raise AuthorityUnavailable("simulation selected whole body differs from its metadata EOF original")
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from ..domains.d07 import SimulationRequest
        r.operation.retain(_heap(self.point.values["payload_json"].frozen)*4+4096)
        value=_detach_value_v3(self.point.values["payload_json"].frozen)["request"]
        registered=SimulationRequest(**{**value,"snapshot_refs":tuple(value["snapshot_refs"]),"alternatives":tuple(value["alternatives"]),
            "predictions":tuple(tuple(p)for p in value["predictions"]),"unknowns":tuple(value["unknowns"])})
        if(tuple(registered.snapshot_refs)!=s.metadata.registered["snapshot_refs"]
                or canonical_digest(registered)!=s.metadata.registered["request_digest"]):
            raise AuthorityUnavailable("simulation actual typed frozen request changed after Source completion")
        branches=tuple(AtomKey(Owner("activity",*r.namespace.as_tuple,r.activity_id),"d07.simulation_branch.v1",b.branch_id)
            for b in D07DomainProvider.simulate(registered).branches)
        s.plan=replace(s.plan,exact_keys=tuple(sorted(set((*s.plan.exact_keys,*branches)),key=lambda k:k.token)))
        r.selected_plan=s.plan;s.final=True;self.complete=True;return True

def create_current_d07_simulation_metadata_task_v3(r,identity):
    s=require_current_d07_simulation_source_work_v3(r)
    if identity==("simulation_plan",r.request):
        task=s.tasks.get(identity)
        if task is None:task=_SimulationMetadataClosureV3(r);s.tasks[identity]=task
        return task
    if identity==("simulation_finalize",r.request)and s.cap is not None and not r.inputs_sealed:
        task=s.tasks.get(identity)
        if task is None:task=_FinalizeSimulationPlanV3(r);s.tasks[identity]=task
        return task
    raise AuthorityUnavailable("simulation metadata task changed its actual installed fixed request")

def read_bound_current_d07_simulation_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    r=_active(db)
    if r is None:return False,None
    if(namespace!=r.namespace or activity_id!=r.activity_id or operation_kind!="run_simulation"or request!=r.request):
        raise AuthorityUnavailable("simulation read plan crossed original command")
    s=require_current_d07_simulation_source_work_v3(r);task=s.tasks.get(("simulation_plan",r.request))
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",("simulation_plan",r.request)))
    with runtime_storage_quantum_v3(db)as meter:task.require_v3(meter)
    return True,s.plan

def simulation_source_groups_v3(r,roots):
    s=require_current_d07_simulation_source_work_v3(r)
    if(s.plan is None or r.selected_plan!=s.plan or tuple(sorted(set(roots)))!=tuple(sorted(s.plan.source_roots))
            or r.authority.purpose!="context"or r.authority.audience!=(r.audience_ref,)
            or r.selected_envelope.authority.purpose!="context"or r.selected_envelope.authority.audience!=(r.audience_ref,)):
        raise AuthorityUnavailable("simulation Sources differ from actual same-Owner context/snapshot groups")
    with runtime_storage_quantum_v3(r.db)as meter:s.metadata.require_v3(meter)
    return(("context",(r.audience_ref,),tuple(roots)),)

def require_current_d07_simulation_sources_v3(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    s=require_current_d07_simulation_source_work_v3(r)
    cap=qualify_current_beta1_source_groups_v3(r,roots);s.cap=cap
    if not s.metadata.producer_roots<=set(cap.source_refs):
        raise AuthorityUnavailable("simulation producer read Sources escaped actual frozen Source ancestor closure")
    s.histories.update((v.key.token,v.revision)for v in cap.versions if v.key.type_name=="memory.source")
    if not s.final:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",("simulation_finalize",r.request)))
    return cap

def require_current_d07_simulation_body_v3(r,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    s=require_current_d07_simulation_source_work_v3(r)
    if table=="graph_atoms"and require_beta1_source_control_point_v3(r,
            (table,("revision","value","valid"),("token","bot","persona"),tuple(key))):return
    if table=="runtime_budget_grants"and r.budget_task is not None and tuple(key)==tuple(r.budget_task.metadata[:2])and key[0]==r.parent_budget_lease_ref:return
    if s.cap is None:raise AuthorityUnavailable("simulation body requires independent complete all-parent Source permission")
    s.cap.require_for_v3(r)
    if table in{"graph_atoms","graph_history"}:
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=r.namespace:raise AuthorityUnavailable("simulation body crossed canonical namespace")
        if table=="graph_history":
            if(atom.token,key[1])not in s.histories:raise AuthorityUnavailable("simulation historical body has no exact selected actual revision")
        elif atom not in r.selected_plan.exact_keys and atom.token not in s.cap.source_refs and atom.type_name not in D07_SOURCE_INVENTORIES_V3:
            raise AuthorityUnavailable("simulation body escaped exact fixed selected recipe")
        return
    if table=="graph_d07_execution_originals_v1"and tuple(key[:2])==r.namespace.as_tuple and (key[-1]in s.originals or key[-2]in {"prepared","accounting_prepared","prepare_commit","paid_cost","body_cost"}and key[-1]in s.jobs):return
    if table=="graph_domain_production_originals_v1"and tuple(key[:2])==r.namespace.as_tuple and (key[-1]in s.producers or key[-1]in s.absent_trigger_producers):return
    if table=="graph_bundle_operations"and tuple(key[:2])==r.namespace.as_tuple and key[-1]in s.producers:return
    if table=="runtime_jobs"and key[0]in s.jobs:return
    raise AuthorityUnavailable("simulation body point has no own fixed selector")

def require_current_d07_simulation_point_v3(r,request):
    table,columns,key_columns,key=request
    shapes={
        ("graph_atoms",("revision","value","valid"),("token","bot","persona")),
        ("graph_history",("event_id","value","valid"),("token","revision")),
        ("graph_history",("value","valid","event_id"),("token","revision")),
        ("graph_history",("event_id","valid"),("token","revision")),
        ("graph_history",("event_bot","event_persona","event_id","valid"),("token","revision")),
        ("graph_d07_execution_originals_v1",("payload_json","payload_digest","signature"),("bot","persona","kind","original_ref")),
        ("graph_domain_production_originals_v1",("domain","operation_kind","request_digest","original_digest","original_payload_json","read_versions_json","bundle_digest","receipt_json","receipt_digest"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("receipt_json","commit_seq"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("receipt_json",),("bot","persona","operation_id")),
        ("graph_bundle_operations",("commit_seq",),("bot","persona","operation_id"))}
    if len(key)!=len(key_columns):raise AuthorityUnavailable("simulation point requires exact full fixed key")
    if request[:3]not in shapes:
        from .domain_background_read_v3 import _D07_POINT_COLUMNS
        if table!="runtime_jobs"or tuple(key_columns)!=("job_id",)or not set(columns)<=_D07_POINT_COLUMNS[table]|{"job_id"}:
            raise AuthorityUnavailable("unregistered simulation fixed point shape")
    return require_current_d07_simulation_body_v3(r,table,key)

def register_current_d07_simulation_write_phase_v3(inputs,scope,current_owner):
    from .current_method_learning_read_v3 import _method_active
    r=inputs.owner;s=require_current_d07_simulation_source_work_v3(r)
    if not r.inputs_sealed:return
    if(not r.read_finished or not r.business_started or scope.operation!="write"or scope is r.fence.scope
            or _method_active(r.db)is not r or current_owner!=r.owner_binding or inputs.plan!=r.selected_plan
            or s.cap is None or not s.final):
        raise AuthorityUnavailable("simulation requires its actual new same-Work current Owner WRITE")
    _WRITES[r]=(inputs,scope,current_owner,_identity(r),s.plan)

def require_current_d07_simulation_write_phase_v3(r):
    from .current_method_learning_read_v3 import _method_active
    value=_WRITES.get(r);s=require_current_d07_simulation_source_work_v3(r)
    if(value is None or value[3]!=_identity(r)or value[4]!=s.plan or _method_active(r.db)is not r
            or not r.read_finished or not r.inputs_sealed or not r.business_started):
        raise AuthorityUnavailable("simulation Source permission lost actual current WRITE")
    return value

def current_d07_simulation_inventory_metadata_v3(inputs,type_id):
    from ..domains.d07.prediction_v1 import FORECAST_PLAN_TYPE
    r=inputs.owner;s=require_current_d07_simulation_source_work_v3(r)
    if type_id not in SIMULATION_METADATA_INVENTORY_TYPES_V3 or inputs.plan!=s.plan:raise AuthorityUnavailable("simulation metadata coverage changed fixed family")
    with runtime_storage_quantum_v3(r.db)as meter:s.metadata.require_v3(meter)
    return tuple(GraphVersion(AtomKey.from_token(token),head[0])for token,head in sorted(r.heads.items())
        if AtomKey.from_token(token).type_name==type_id)

def register_current_d07_simulation_source_frame_v3(db,frame,scope):
    r=_active(db)
    if r is None:return frame
    s=require_current_d07_simulation_source_work_v3(r)
    if r.inputs_sealed:
        value=require_current_d07_simulation_write_phase_v3(r)
        if value[1]is not scope:raise AuthorityUnavailable("simulation frame crossed actual fresh WRITE permit")
    if(frame.envelope.identity.operation_id!=r.operation_id or frame.envelope.identity.activity_id!=r.activity_id
            or frame.envelope.authority.namespace!=r.namespace or frame.envelope.identity.phase!="run_simulation"
            or frame.envelope.parent_budget_lease_ref!=r.parent_budget_lease_ref or frame.envelope.deadline_utc>r.operation.deadline_utc):
        raise AuthorityUnavailable("simulation frame changed actual original command/root")
    _FRAMES.setdefault(r,{})[id(frame)]=(frame,scope,s.plan,s.cap)
    return frame

def require_current_d07_simulation_source_frame_v3(db,*,frame,simulation_request_ref):
    r=_active(db)
    if r is None:raise AuthorityUnavailable("simulation forecast requires its actual originating own Source Work")
    s=require_current_d07_simulation_source_work_v3(r);registered=_FRAMES.get(r,{}).get(id(frame))
    if(registered is None or registered[0]is not frame or registered[2:]!=(s.plan,s.cap)
            or r.request.simulation_request_ref!=simulation_request_ref or not r.inputs_sealed):
        raise AuthorityUnavailable("simulation forecast consumer received an unissued frame/Plan selector")
    require_current_d07_simulation_write_phase_v3(r);s.cap.require_for_v3(r)
    return r

def read_current_d07_simulation_forecast_plan_v3(r,*,frame,simulation_request_ref):
    require_current_d07_simulation_source_frame_v3(r.db,frame=frame,simulation_request_ref=simulation_request_ref)
    s=require_current_d07_simulation_source_work_v3(r)
    if s.forecast is None:return None
    token,metadata=s.forecast
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..domains.d07.prediction_v1 import SimulationForecastPlanV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    atom=CurrentDomainReadV1(frame).head(r.db,token,required=True)
    value=decode_typed_production_value_v1(atom.value,SimulationForecastPlanV1)
    if value.simulation_request_ref!=simulation_request_ref:
        raise AuthorityUnavailable("simulation actual typed forecast Plan changed its metadata selector")
    return atom,value

def register_current_d07_simulation_stage_v3(db,stage,*,request):
    r=_active(db)
    if r is None:return stage
    s=require_current_d07_simulation_source_work_v3(r);require_current_d07_simulation_write_phase_v3(r)
    if request!=r.request:raise AuthorityUnavailable("simulation private stage changed its actual registered request")
    s.cap.require_for_v3(r);_STAGES[id(stage)]=(stage,r,r.work,r.operation,r.selection_digest,canonical_digest(stage))
    return stage

def require_current_d07_simulation_stage_v3(db,stage):
    r=_active(db)
    if r is None:return stage
    row=_STAGES.get(id(stage))
    if(row is None or row[:5]!=(stage,r,r.work,r.operation,r.selection_digest)or row[0]is not stage or row[-1]!=canonical_digest(stage)):
        raise AuthorityUnavailable("simulation stage was not issued by actual Source-qualified private producer")
    require_current_d07_simulation_write_phase_v3(r);require_current_d07_simulation_source_work_v3(r).cap.require_for_v3(r)
    return stage

def release_current_d07_simulation_source_work_v3(r):
    _SIMULATIONS.pop(r,None);_WRITES.pop(r,None);_FRAMES.pop(r,None)
    for key,row in tuple(_STAGES.items()):
        if row[1]is r:_STAGES.pop(key,None)

def read_current_d07_simulation_history_v3(db,ref,revision):
    r=_active(db)
    if r is None:raise AuthorityUnavailable("simulation historical consumer lacks actual own Source Work")
    require_current_d07_simulation_body_v3(r,"graph_history",(ref,revision))
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    handled,row=read_bound_method_learning_attachment_v3(db,table="graph_history",
        columns=("event_id","value","valid"),key_columns=("token","revision"),key=(ref,revision))
    if not handled:raise AuthorityUnavailable("simulation historical consumer lost actual same-Work attachment")
    return row

def read_bound_current_d07_simulation_original_refs_v3(db,*,namespace,plan,installed_readers,external):
    r=_active(db)
    if r is None:return False,None
    s=require_current_d07_simulation_source_work_v3(r)
    if namespace!=r.namespace or plan!=s.plan or set(plan.required_original_refs)!=s.originals:
        raise AuthorityUnavailable("simulation original read plan changed actual fixed Source recipe")
    require_current_d07_simulation_sources_v3(r,plan.source_roots)
    if installed_readers is None or installed_readers.issuer is not r.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable("simulation original refs lost actual installed same-Work D11 issuer")
    from .d07_execution_v1 import read_current_original_ref_v1
    from .domain_production_read_plans_v1 import _graph_original
    result=[]
    for ref in plan.required_original_refs:
        original=read_current_original_ref_v1(db,namespace,ref,issuer=installed_readers.issuer)
        if original is None and ref==r.request.trigger_original_ref:original=_graph_original(db,namespace,ref)
        if original is not None:result.append(original)
    for original in external:
        if original.kind in{"d11.restore_anchor","d11.trusted_tick","d11.clock_sample","d03.current_self_identity"}:
            result.append(original)
    return True,tuple(result)
