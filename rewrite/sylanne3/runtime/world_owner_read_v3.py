"""Private World metadata/ALL/selected-body recipes on the existing W01 Work.

The outer Method Work supplies paging, retention and the actual original fence;
only this registry can issue or consume a World Source permission.
"""
from __future__ import annotations

from dataclasses import dataclass,field
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d03.world_history_v1 import INPUT_TYPE,VIEW_TYPE,EXPRESSION_TYPE,WORLD_OPERATIONS
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from .dispatch_current_inventory_v3 import _heap
from ..runtime_storage_v3 import runtime_storage_quantum_v3

_WORLD_OWNER_OPERATIONS_V1=frozenset(WORLD_OPERATIONS)
_WORLD_STATES=WeakKeyDictionary()
_WORLD_WRITE_PHASES=WeakKeyDictionary()


@dataclass(slots=True)
class _WorldState:
    reader: object
    identity: tuple
    allowed_history: set=field(default_factory=set)
    metadata_points: set=field(default_factory=set)
    tasks: dict=field(default_factory=dict)
    source_permission: object=None
    index_refs: set=field(default_factory=set)


def _identity(reader):
    return (reader.work,reader.operation,reader.fence,reader.namespace,reader.selection_digest,
        reader.graph_stamp,reader.request,reader.operation_id,reader.authority,reader.owner_binding)


def register_world_owner_work_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3,WORLD_SOURCE_WORK_KIND_V3
    require_current_beta1_source_work_v3(reader)
    if reader.work.kind!=WORLD_SOURCE_WORK_KIND_V3 or reader in _WORLD_STATES:
        raise AuthorityUnavailable("World profile requires its own once-issued Source Work")
    state=_WorldState(reader,_identity(reader));_WORLD_STATES[reader]=state
    versions=()
    if reader.operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        value=reader.request.assertion
        versions=(value.event_version,value.perspective_version,value.interpretation_version)
    elif reader.operation_kind=="query_world_view_v1":versions=(reader.request.perspective_version,)
    elif reader.operation_kind=="project_world_perspective_v1":versions=(reader.request.view_version,)
    for version in versions:
        if version is not None:
            if NamespaceId.from_key(version.key)!=reader.namespace or version.revision<1:
                raise AuthorityUnavailable("World request version crossed its actual namespace/revision")
            state.allowed_history.add((version.key.token,version.revision))

def pin_world_owner_entry_v3(reader):
    state=require_world_owner_work_v3(reader)
    if reader.general_owner_entry is None:
        raise AuthorityUnavailable("World profile needs its actual completed independent Owner entry")
    state.identity=_identity(reader)


def require_world_owner_work_v3(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    state=_WORLD_STATES.get(reader)
    if (type(reader)is not _MethodLearningReadV3 or reader not in _READERS
            or reader.operation_kind not in _WORLD_OWNER_OPERATIONS_V1 or reader.work is None
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.coordinator is not reader.graph or reader.operation.closed
            or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or state is None or state.reader is not reader):
        raise AuthorityUnavailable("World metadata requires its actual same Work/operation")
    reader.work._require_invocation(reader.graph)
    actual=_identity(reader)
    # MetaOwner may replace only the provisional Owner object in that same
    # first entry. No Source permission exists during this transition.
    if state.identity[:-1]!=actual[:-1] or state.identity[-1] is not actual[-1] and state.source_permission is not None:
        raise AuthorityUnavailable("World Work changed its selection/fence/request/current Owner")
    return state


def _world_active(db):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None or reader.operation_kind not in _WORLD_OWNER_OPERATIONS_V1:
        return None
    require_world_owner_work_v3(reader)
    return reader


def world_source_groups_v3(reader,roots):
    require_world_owner_work_v3(reader)
    purpose=("consolidation"if reader.operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}else
        "expression"if reader.operation_kind=="project_world_perspective_v1"else reader.request.purpose)
    audience=reader.request.audience if reader.operation_kind=="query_world_view_v1"else reader.audience_ref
    if (reader.authority.purpose!=purpose or reader.selected_envelope.authority.purpose!=purpose
            or reader.selected_envelope.authority.audience!=(audience,)):
        raise AuthorityUnavailable("World purpose/audience differs from its actual fixed recipe")
    return ((purpose,(audience,),tuple(roots)),)

def require_world_sources_v3(reader,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_world_owner_work_v3(reader)
    cap=qualify_current_beta1_source_groups_v3(reader,roots)
    state.source_permission=cap
    state.allowed_history.update((v.key.token,v.revision)for v in cap.versions if v.key.type_name=="memory.source")
    return cap


def require_world_body_v3(reader,table,key):
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    state=require_world_owner_work_v3(reader)
    if (table,tuple(key)) in state.metadata_points:
        return
    if(table=="runtime_budget_grants"and reader.budget_task is not None
            and tuple(key)==tuple(reader.budget_task.metadata[:2])and key[0]==reader.parent_budget_lease_ref):return
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    if require_beta1_source_control_point_v3(reader,(table,("revision","value","valid"),("token","bot","persona"),tuple(key))):
        return
    cap=state.source_permission
    if cap is None:
        raise AuthorityUnavailable("World body requires all current Source groups before reading")
    cap.require_for_v3(reader)
    if table in {"graph_atoms","graph_history"}:
        atom=AtomKey.from_token(key[0])
        if table=="graph_history":
            if (atom.token,key[1]) not in state.allowed_history:
                raise AuthorityUnavailable("World historical body is outside its signed locator closure")
        elif atom not in reader.selected_plan.exact_keys and atom.token not in cap.source_refs:
            raise AuthorityUnavailable("World body is outside its exact current selection")
    elif table=="graph_domain_production_originals_v1":
        if key[-1]not in state.tasks.get("adoption_operations",set()):
            raise AuthorityUnavailable("World original body is outside its exact producing COMMIT")
    else:
        raise AuthorityUnavailable("World original body is outside its exact fixed point recipe")


def require_world_point_v3(reader,request):
    from .d03_world_history_v1 import TABLE,ERASURE_TABLE,ERASURE_COLUMNS
    state=require_world_owner_work_v3(reader)
    table,columns,key_columns,key=request
    if len(key)!=len(key_columns):
        raise AuthorityUnavailable("World point requires its full fixed key")
    if table in {"graph_atoms","graph_history","graph_dependencies"}:
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=reader.namespace:
            raise AuthorityUnavailable("World Graph point crossed namespace")
    elif tuple(key[:2])!=reader.namespace.as_tuple and table!="runtime_budget_grants":
        raise AuthorityUnavailable("World point crossed namespace")
    allowed={
        ("graph_atoms",("revision","value","valid"),("token","bot","persona")),
        ("graph_history",("event_id","value","valid"),("token","revision")),
        ("graph_history",("value","valid","event_id"),("token","revision")),
        ("graph_history",("event_bot","event_persona","event_id","valid"),("token","revision")),
        ("graph_history",("event_id","valid"),("token","revision")),
        ("graph_domain_production_originals_v1",("domain","operation_kind","request_digest","original_digest","original_payload_json","read_versions_json","bundle_digest","receipt_json","receipt_digest"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),("bot","persona","operation_id")),
        (ERASURE_TABLE,ERASURE_COLUMNS,("bot","persona","assertion_commitment","known_sequence")),
        ("graph_bundle_operations",("receipt_json","commit_seq"),("bot","persona","operation_id")),
        ("graph_bundle_operations",("receipt_json",),("bot","persona","operation_id")),
        ("graph_bundle_operations",("commit_seq",),("bot","persona","operation_id")),
        (TABLE,("payload_json","payload_digest","signature","source_refs_json","assertion_id","assertion_commitment","known_sequence","supersedes_ref"),("bot","persona","original_ref")),
    }
    if request[:3] not in allowed:
        raise AuthorityUnavailable("World selected point shape is not registered")
    if table==ERASURE_TABLE:
        if (key[2],key[3])not in state.tasks.get("barriers",set()):
            raise AuthorityUnavailable("World erasure metadata was not selected by this actual knowledge page")
        state.metadata_points.add((table,tuple(key)))
    elif table=="graph_domain_production_originals_v1":
        if key[-1]not in state.tasks.get("adoption_operations",set()):
            raise AuthorityUnavailable("World original was not derived from its exact adopted history")
        require_world_body_v3(reader,table,key)
    elif table==TABLE:
        if key[-1] not in state.index_refs:
            raise AuthorityUnavailable("World index point was not selected from its actual page or predecessor")
        state.metadata_points.add((table,tuple(key)))
    elif table=="graph_bundle_operations":
        if key[-1] not in state.tasks.get("adoption_operations",set()):
            raise AuthorityUnavailable("World receipt is not from its signed actual locator")
        state.metadata_points.add((table,tuple(key)))
    elif table=="graph_history" and "value" not in columns:
        if (key[0],key[1]) not in state.allowed_history:
            raise AuthorityUnavailable("World history metadata has no actual signed locator")
    elif table=="graph_atoms":
        return
    else:
        require_world_body_v3(reader,table,key)


def register_world_index_locator_v3(db,ref,*,index=None):
    reader=_world_active(db)
    if reader is None:
        return
    state=require_world_owner_work_v3(reader)
    if index is None:
        if ref not in state.index_refs:
            value=reader.request.assertion if reader.operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"} else None
            if value is None or ref not in (value.supersedes_ref,value.correction_ref,*value.dispute_refs):
                raise AuthorityUnavailable("World metadata locator was not derived from the fixed request/page")
            state.index_refs.add(ref)
        return
    if index.input_version.key.token!=ref or ref not in state.index_refs:
        raise AuthorityUnavailable("World signed index did not match its selected locator")
    state.allowed_history.add((ref,index.input_version.revision))
    for version in (index.event_version,index.perspective_version,index.interpretation_version):
        if version is not None:
            state.allowed_history.add((version.key.token,version.revision))
    state.tasks.setdefault("adoption_operations",set()).add(index.adoption_operation_id)


class WorldIndexPageTaskV3:
    def __init__(self,reader,request):
        self.reader,self.request=reader,request
        self.rows=[];self.after=request.cursor.after_assertion_commitment if request.cursor else ""
        self.complete=False;self.watermark=None
    def advance(self,meter):
        from .d03_world_history_v1 import TABLE
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        state=require_world_owner_work_v3(self.reader)
        if self.watermark is None:
            row=_runtime_bounded_fixed_row_v3(self.reader.db,meter,"graph_bundle_sequence",("last_seq",),
                "bot=? AND persona=?",self.reader.namespace.as_tuple)
            self.watermark=row[0] if row else 0
            if self.request.knowledge_as_of>self.watermark:
                raise AuthorityUnavailable("World requested knowledge sequence has not committed")
        from .d03_world_history_v1 import WORLD_PAGE_SQL
        meter.require_available(4096)
        row=self.reader.db.execute(WORLD_PAGE_SQL,
            (*self.reader.namespace.as_tuple,*self.reader.namespace.as_tuple,self.after,
                self.request.knowledge_as_of,self.request.knowledge_as_of,1)).fetchone()
        meter.charge_read(4096)
        if row is None:
            self.complete=True;return True
        self.reader.operation.retain(_heap(row)+1024)
        self.rows.append(row);self.after=row[1]
        if row[0]=="revision":state.index_refs.add(row[3])
        elif row[0]=="erasure":state.tasks.setdefault("barriers",set()).add((row[1],row[2]))
        else:raise AuthorityUnavailable("World page has an unregistered fixed metadata entry")
        if len(self.rows)==self.request.coverage_bound+1:
            self.complete=True
        return self.complete


class _WorldLatestMetadataTaskV3:
    def __init__(self,reader,identity):
        from .d03_world_history_v1 import world_assertion_commitment_v1
        require_world_owner_work_v3(reader)
        if(reader.operation_kind not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}or identity!=world_assertion_commitment_v1(
                reader.namespace,reader.request.assertion.assertion_id,reader.graph._GraphCoordinator__d11_issuer)):
            raise AuthorityUnavailable("World latest predecessor is not its actual fixed assertion identity")
        self.reader,self.identity=reader,identity;self.complete=False;self.result=None
    def advance(self,meter):
        from .d03_world_history_v1 import WORLD_LATEST_SQL
        r=self.reader;r.require_current(meter=meter);require_world_owner_work_v3(r)
        if self.complete:return True
        meter.require_available(4096)
        self.result=r.db.execute(WORLD_LATEST_SQL,(*r.namespace.as_tuple,self.identity,
            *r.namespace.as_tuple,self.identity)).fetchone()
        meter.charge_read(4096);r.operation.retain(_heap(self.result)+1024)
        state=require_world_owner_work_v3(r)
        if self.result is not None:
            if self.result[0]=="revision":state.index_refs.add(self.result[2])
            elif self.result[0]=="erasure":state.tasks.setdefault("barriers",set()).add((self.identity,self.result[1]))
            else:raise AuthorityUnavailable("World latest metadata has an unregistered entry kind")
        self.complete=True;return True

def world_latest_metadata_v3(db,namespace,identity):
    r=_world_active(db)
    if r is None:return False,None
    if namespace!=r.namespace:raise AuthorityUnavailable("World latest metadata crossed its actual namespace")
    state=require_world_owner_work_v3(r);key=("latest",identity)
    task=state.tasks.get(key)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",key))
    return True,task.result


def world_page_metadata_rows_v3(db,namespace,request):
    reader=_world_active(db)
    if reader is None:
        return False,None
    if namespace!=reader.namespace or reader.operation_kind!="query_world_view_v1" or request!=reader.request:
        raise AuthorityUnavailable("World page metadata changed its actual query")
    state=require_world_owner_work_v3(reader)
    task=state.tasks.get(("page",request.query_digest))
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(reader,("world_metadata",("page",request)))
    return True,(tuple(task.rows),task.watermark)


class WorldViewSourceKeysTaskV3:
    def __init__(self,reader,version):
        self.reader,self.version=reader,version;self.rows=[];self.after="";self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;require_world_owner_work_v3(r)
        head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid"),"token=? AND bot=? AND persona=?",
            (self.version.key.token,*r.namespace.as_tuple))
        if head!=(self.version.revision,1):
            raise AuthorityUnavailable("World view locator metadata changed")
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_dependencies",("dependency_token",),
            "dependent_token=? AND dependency_token>? ORDER BY dependency_token",(self.version.key.token,self.after))
        if row is None:
            state=require_world_owner_work_v3(r)
            state.allowed_history.add((self.version.key.token,self.version.revision))
            self.complete=True;return True
        self.after=row[0]
        if AtomKey.from_token(row[0]).type_name=="memory.source":
            r.operation.retain(1024+8*len(row[0]));self.rows.append(row[0])
            if len(self.rows)>16:
                raise AuthorityUnavailable("World view exceeds original semantic root bound")
        return False


def world_view_source_keys_v3(db,namespace,version):
    r=_world_active(db)
    if r is None:
        return False,None
    state=require_world_owner_work_v3(r)
    if (r.operation_kind!="project_world_perspective_v1"or r.request.view_version!=version or namespace!=r.namespace):
        raise AuthorityUnavailable("World view metadata is not its exact actual expression selector")
    task=state.tasks.get(("view_sources",version))
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",("view_sources",version)))
    return True,tuple(task.rows)


def register_world_historical_operation_v3(db,version,operation_id):
    r=_world_active(db)
    if r is None:
        return
    state=require_world_owner_work_v3(r)
    if (version.key.token,version.revision) not in state.allowed_history:
        raise AuthorityUnavailable("World historical operation is not from its signed exact version")
    state.tasks.setdefault("adoption_operations",set()).add(operation_id)


def create_world_metadata_task_v3(reader,request):
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import create_d07_source_metadata_task_v3
        return create_d07_source_metadata_task_v3(reader,request)
    state=require_world_owner_work_v3(reader)
    kind,value=request
    if kind in {"world_producer","input_head"}:
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        key=(kind,value)
        if key not in state.tasks:state.tasks[key]=create_current_beta1_metadata_task_v3(reader,key)
        return state.tasks[key]
    if kind=="latest" and reader.operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        key=("latest",value)
        if key not in state.tasks:state.tasks[key]=_WorldLatestMetadataTaskV3(reader,value)
        return state.tasks[key]
    if kind=="view_sources"and reader.operation_kind=="project_world_perspective_v1"and value==reader.request.view_version:
        key=("view_sources",value)
        if key not in state.tasks:
            state.tasks[key]=WorldViewSourceKeysTaskV3(reader,value)
        return state.tasks[key]
    if kind=="page" and reader.operation_kind=="query_world_view_v1" and value==reader.request:
        key=("page",value.query_digest)
        if key not in state.tasks:
            state.tasks[key]=WorldIndexPageTaskV3(reader,value)
        return state.tasks[key]
    raise AuthorityUnavailable("World metadata task has no actual installed selector")


def register_world_write_phase_v3(inputs,scope,current_owner):
    reader=inputs.owner
    state=require_world_owner_work_v3(reader)
    if not reader.inputs_sealed:
        return
    if (not reader.read_finished or not reader.business_started or scope.operation!="write"
            or scope is reader.fence.scope or current_owner!=reader.owner_binding or inputs.plan!=reader.selected_plan):
        raise AuthorityUnavailable("World cached READ must enter its exact current same-Work WRITE")
    _WORLD_WRITE_PHASES[reader]=(inputs,scope,current_owner,_identity(reader),reader.selected_plan)
    if state.source_permission is None:
        raise AuthorityUnavailable("World WRITE cannot prepare missing Source permission")


def require_world_write_phase_v3(reader):
    from .current_method_learning_read_v3 import _method_active
    value=_WORLD_WRITE_PHASES.get(reader)
    if (value is None or value[3]!=_identity(reader) or value[4]!=reader.selected_plan
            or _method_active(reader.db)is not reader or not reader.inputs_sealed or not reader.business_started):
        raise AuthorityUnavailable("World Source WRITE lost its original sealed Work/Owner/selection")
    return value


def release_world_owner_read_v3(reader):
    state=_WORLD_STATES.pop(reader,None)
    _WORLD_WRITE_PHASES.pop(reader,None)

def read_bound_world_attachment_v3(db,*,table,columns,key_columns,key):
    r=_world_active(db)
    if r is None:
        return False,None
    from .current_method_learning_read_v3 import _need_method_input,MethodJSONColumnV3
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    require_world_point_v3(r,request)
    point=r.points.get(request)
    if point is None or not point.complete:
        _need_method_input(r,("point",request))
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        row=point.require_row_v3(meter)
    if row is None:
        return True,None
    if table=="graph_history":
        from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
        with runtime_storage_quantum_v3(db)as meter:
            metadata=_beta1_metadata_row_v3(r,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",tuple(key))
        actual=dict(zip(columns,row))
        if(metadata is None or metadata[:2]!=r.namespace.as_tuple
                or "event_id"in actual and actual["event_id"]!=metadata[2]
                or "valid"in actual and actual["valid"]!=metadata[3]):
            raise AuthorityUnavailable("World historical event identity differs from its exact namespace/version")
        require_world_owner_work_v3(r).tasks.setdefault("adoption_operations",set()).add(metadata[2])
    return True,tuple(value.wire if type(value)is MethodJSONColumnV3 else value for value in row)

_WORLD_STAGED_PROPOSALS={}

def register_world_staged_proposal_v3(db,proposal,*,request,operation_kind):
    from weakref import ref
    from ..runtime_contracts import DomainProposal
    r=_world_active(db)
    if(r is None or type(proposal)is not DomainProposal or r.operation_kind!=operation_kind
            or r.request!=request or not r.business_started or not r.read_finished
            or proposal.envelope.identity.operation_id!=r.operation_id
            or proposal.envelope.identity.phase!=operation_kind):
        raise AuthorityUnavailable("World proposal requires its actual fixed Source-qualified producer stage")
    cap=require_world_sources_v3(r,r.selected_plan.source_roots)
    require_world_write_phase_v3(r)
    expected={"adopt_world_assertion_v1":("d03",INPUT_TYPE),"relearn_world_assertion_v1":("d03",INPUT_TYPE),
        "query_world_view_v1":("d03",VIEW_TYPE),"project_world_perspective_v1":("d09",EXPRESSION_TYPE)}[operation_kind]
    if(proposal.domain!=expected[0]or any(w.key.type_name!=expected[1]or w.key not in r.selected_plan.exact_keys
            for w in proposal.typed_writes)):
        raise AuthorityUnavailable("World proposal escaped its fixed producer/write selection")
    identity=id(proposal)
    original=ref(proposal,lambda _: _WORLD_STAGED_PROPOSALS.pop(identity,None))
    _WORLD_STAGED_PROPOSALS[identity]=(original,r,r.work,r.operation,r.selection_digest,cap,
        operation_kind,request,canonical_digest(proposal))

def require_world_staged_proposal_v3(proposal):
    value=_WORLD_STAGED_PROPOSALS.get(id(proposal))
    if value is None or value[0]()is not proposal:
        raise AuthorityUnavailable("World typed proposal was not issued by its actual current Source Work")
    _,r,work,operation,selection,cap,kind,request,digest=value
    if(work is not r.work or operation is not r.operation or selection!=r.selection_digest
            or r.operation_kind!=kind or r.request!=request or canonical_digest(proposal)!=digest):
        raise AuthorityUnavailable("World proposal changed after its actual fixed stage")
    require_world_owner_work_v3(r);cap.require_for_v3(r);require_world_write_phase_v3(r)
    return proposal

def world_metadata_spec_v3(reader,identity):
    state=require_world_owner_work_v3(reader)
    if type(identity)is tuple and len(identity)==2 and identity[0]=="input_head":
        if reader.operation_kind not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
            raise AuthorityUnavailable("World input metadata requires its exact adopt/relearn request")
        value=reader.request.assertion
        versions=tuple(v for v in(value.event_version,value.interpretation_version)if v is not None)
        if identity[1]not in versions:raise AuthorityUnavailable("World input metadata is outside its actual event/cognition versions")
        version=identity[1]
        return("graph_atoms","value",("token","bot","persona"),(version.key.token,*reader.namespace.as_tuple),
            ("revision","valid","value_cell_id"),(("source_refs",),),None)
    if(type(identity)is not tuple or len(identity)!=2 or identity[0]!="world_producer"
            or identity[1]not in state.tasks.get("adoption_operations",set())):
        raise AuthorityUnavailable("World producer locator is not its exact authenticated index/history operation")
    return ("graph_domain_production_originals_v1","original_payload_json",("bot","persona","operation_id"),
        (*reader.namespace.as_tuple,identity[1]),("domain","operation_kind","request_digest","original_digest"),
        (("schema",),("namespace",),("identity","operation_id"),("provenance","world_source_roots")),None)

def finish_world_metadata_v3(task,value):
    from types import MappingProxyType
    reader=task.reader;state=require_world_owner_work_v3(reader)
    if task.identity[0]=="input_head":
        version=task.identity[1]
        if task.metadata[:2]!=(version.revision,1):raise AuthorityUnavailable("World actual input metadata changed revision/validity")
        roots=tuple(value["source_refs"])
        if(not roots or len(set(roots))!=len(roots)or any(AtomKey.from_token(ref).type_name!="memory.source"
                or NamespaceId.from_key(AtomKey.from_token(ref))!=reader.namespace for ref in roots)):
            raise AuthorityUnavailable("World event/cognition metadata has invalid actual Source locators")
        return roots
    domain,kind,request_digest,original_digest=task.metadata
    namespace=NamespaceId(**value["namespace"])
    operation_id=value["identity"]["operation_id"]
    roots=tuple(value["provenance"]["world_source_roots"])
    if(domain!="d03"or kind not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}
            or namespace!=reader.namespace or operation_id!=task.identity[1]
            or value["schema"]!="d03.current-"+kind+".v1"
            or len(set(roots))!=len(roots)
            or any(NamespaceId.from_key(AtomKey.from_token(ref))!=reader.namespace
                or AtomKey.from_token(ref).type_name!="memory.source"for ref in roots)):
        raise AuthorityUnavailable("World producer locator does not bind its exact original/schema/Source namespace")
    return MappingProxyType({"domain":domain,"operation_kind":kind,"operation_id":operation_id,
        "namespace":namespace,"schema":value["schema"],"world_source_roots":roots,"original_digest":original_digest})

def world_producer_metadata_v3(db,namespace,operation_id):
    r=_world_active(db)
    if r is None:return False,None
    if namespace!=r.namespace:raise AuthorityUnavailable("World producer metadata crossed its actual namespace")
    state=require_world_owner_work_v3(r);identity=("world_producer",operation_id)
    world_metadata_spec_v3(r,identity)
    task=state.tasks.get(identity)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(r,("world_metadata",identity))
    if task.result is None:raise AuthorityUnavailable("World producer original is absent after its authenticated locator")
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v3(meter)
    return True,task.result

def require_world_plan_metadata_v3(reader):
    state=require_world_owner_work_v3(reader)
    if reader.operation_kind not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:return
    value=reader.request.assertion
    actual=set()
    for version in(value.event_version,value.interpretation_version):
        if version is None:continue
        identity=("input_head",version)
        task=state.tasks.get(identity)
        if task is None or not task.complete:
            from .current_method_learning_read_v3 import _need_method_input
            _need_method_input(reader,("world_metadata",identity))
        if task.result is None:raise AuthorityUnavailable("World actual event/cognition metadata is absent")
        with runtime_storage_quantum_v3(reader.db)as meter:task.require_header_v3(meter)
        actual.update(task.result)
    if actual!=set(value.source_refs):
        raise AuthorityUnavailable("World declared Source roots differ from actual event/cognition metadata EOF")
