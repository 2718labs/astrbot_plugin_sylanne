"""Independent World Source Work; existing Method supplies bounded mechanics."""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import GraphStorageWorkV3
from ..runtime_contracts import canonical_digest

WORLD_SOURCE_WORK_KIND_V3="current_world_source_read_v3"
D07_SOURCE_WORK_KIND_V3="current_d07_source_read_v3"
D07_SIMULATION_SOURCE_WORK_KIND_V3="current_d07_simulation_source_read_v3"
D07_DISPATCH_WORK_KIND_V3="current_d07_dispatch_read_v3"
HABIT_SOURCE_WORK_KIND_V3="current_habit_source_read_v3"
CONDITIONED_SELF_WORK_KIND_V3="current_conditioned_self_source_read_v3"
BETA1_SOURCE_WORK_KINDS_V3=frozenset({WORLD_SOURCE_WORK_KIND_V3,D07_SOURCE_WORK_KIND_V3,D07_SIMULATION_SOURCE_WORK_KIND_V3,CONDITIONED_SELF_WORK_KIND_V3,HABIT_SOURCE_WORK_KIND_V3})
_WORLD_WORKS=WeakKeyDictionary()

def beta1_source_operation_v3(operation_kind):
    if operation_kind=='input:freeze_joint_window_node_command_v1':return True
    if operation_kind=='read_beta1_owner_state_v1':return True
    from .current_habit_source_read_v3 import habit_source_operation_types_v3
    if operation_kind in habit_source_operation_types_v3() and operation_kind not in {'prepare_life','prepare_source_note_body'}:return True
    from .current_conditioned_self_read_v3 import conditioned_operation_types_v3
    if operation_kind in conditioned_operation_types_v3():return True
    from ..domains.d03.world_history_v1 import WORLD_OPERATIONS
    return operation_kind in WORLD_OPERATIONS or operation_kind in {"serve_concern","run_simulation"}

def beta1_source_work_kind_v3(operation_kind):
    from .current_habit_source_read_v3 import habit_source_operation_types_v3
    if operation_kind in habit_source_operation_types_v3() and operation_kind not in {'prepare_life','prepare_source_note_body'}:return HABIT_SOURCE_WORK_KIND_V3
    from .current_conditioned_self_read_v3 import conditioned_operation_types_v3
    if operation_kind in conditioned_operation_types_v3():return CONDITIONED_SELF_WORK_KIND_V3
    if not beta1_source_operation_v3(operation_kind):
        raise AuthorityUnavailable("unregistered World Source operation")
    if operation_kind=="run_simulation":return D07_SIMULATION_SOURCE_WORK_KIND_V3
    return D07_SOURCE_WORK_KIND_V3 if operation_kind=="serve_concern"else WORLD_SOURCE_WORK_KIND_V3

def _identity_v3(reader):
    return(reader.graph,reader.runtime,reader.work,reader.operation,reader.fence,reader.fence.scope,
        reader.authority,reader.lease,reader.session_proof,reader.operation_kind,reader.request,
        reader.request_digest,reader.operation_id,reader.activity_id,reader.audience_ref,
        reader.parent_budget_lease_ref,reader.selection_digest,reader.graph_stamp,reader.catalogue_hash,
        reader.initial_monotonic_deadline,reader.work.kind,getattr(reader,"d07_dispatch_classify_v3",False),
        getattr(reader,"d07_dispatch_pin_v3",None))

def register_current_beta1_source_work_v3(reader,work):
    if reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import register_owner_state_reader_v3
        register_owner_state_reader_v3(reader,work)
        if reader in _WORLD_WORKS:raise AuthorityUnavailable('Owner state Source reader registers exactly once')
        _WORLD_WORKS[reader]=_identity_v3(reader)
        return work
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        return _register_habit_beta1_reader_v3(reader,work)
    if work.kind==CONDITIONED_SELF_WORK_KIND_V3:return _register_conditioned_beta1_reader_v3(reader,work)
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    from .domain_production_registry_v1 import installed_operation_v1
    installed=installed_operation_v1(reader.operation_kind)
    if(type(reader)is not _MethodLearningReadV3 or reader not in _READERS
            or type(work)is not GraphStorageWorkV3 or not beta1_source_operation_v3(reader.operation_kind)
            or work.kind!=beta1_source_reader_work_kind_v3(reader)or reader.work is not work
            or work.state is not reader or work.operation is not reader.operation
            or work.coordinator is not reader.graph or work.operation_id!=reader.operation_id
            or work.deadline_utc!=reader.operation.deadline_utc or work.selection_digest!=reader.selection_digest
            or type(reader.request)is not installed.request_type or reader.fence.scope.operation!="read"
            or reader.session_proof is None or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or reader.projection_types or reader.preplan_families
            or any((reader.background_followup,reader.background_host_lifecycle,reader.background_offline))
            or installed.capability not in reader.owner_binding.capabilities or reader in _WORLD_WORKS):
        raise AuthorityUnavailable("World Source Work requires its exact installed originating Owner command")
    work._require_invocation(reader.graph,initial=True)
    reader.graph._authorize(reader.lease,reader.authority,beta1_source_reader_required_domains_v3(reader),owner_read=True)
    _WORLD_WORKS[reader]=_identity_v3(reader)
    if getattr(reader,"d07_dispatch_classify_v3",False):
        from .d07_source_dispatch_read_v3 import register_d07_dispatch_read_v3
        register_d07_dispatch_read_v3(reader)
    elif reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import register_frozen_joint_source_v3
        register_frozen_joint_source_v3(reader)
    elif reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import register_d07_source_work_v3
        register_d07_source_work_v3(reader)
    elif reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import register_current_d07_simulation_source_work_v3
        register_current_d07_simulation_source_work_v3(reader)
    else:
        from .world_owner_read_v3 import register_world_owner_work_v3
        register_world_owner_work_v3(reader)
    return work

def require_current_beta1_source_work_identity_v3(reader):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    if(type(reader)is not _MethodLearningReadV3 or reader not in _READERS
            or _WORLD_WORKS.get(reader)!=_identity_v3(reader)or reader.operation.closed
            or reader.work.kind!=beta1_source_reader_work_kind_v3(reader)or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.work.coordinator is not reader.graph
            or reader.fence.scope.operation!="read"):
        raise AuthorityUnavailable("World Source Work lost its own private issuance/selection/READ")
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_source_factory_reader_v3
        require_habit_source_factory_reader_v3(reader,reader.work)
    elif reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_source_factory_reader_v3
        require_conditioned_source_factory_reader_v3(reader,reader.work)
    else:reader.graph._authorize(reader.lease,reader.authority,beta1_source_reader_required_domains_v3(reader),owner_read=True)
    return reader

def require_current_beta1_source_work_v3(reader):
    r=require_current_beta1_source_work_identity_v3(reader)
    r.work._require_invocation(r.graph)
    import time
    deadline=r.operation.deadline_utc if r.selected_envelope is None else min(r.operation.deadline_utc,r.selected_envelope.deadline_utc)
    if time.monotonic()>=r.initial_monotonic_deadline-(r.operation.deadline_utc-deadline):
        raise AuthorityUnavailable("World Source Work exceeded its original READ/Root monotonic deadline")
    return r

def prepare_current_beta1_owner_entry_v3(reader):
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import prepare_habit_owner_entry_v3
        return prepare_habit_owner_entry_v3(reader)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import prepare_conditioned_owner_entry_v3
        return prepare_conditioned_owner_entry_v3(reader)
    r=require_current_beta1_source_work_v3(reader)
    if r.general_owner_entry is None:
        from ..authority_service.owner_location_read_v3 import prepare_current_host_method_owner_read_entry_v3
        r.general_owner_entry=prepare_current_host_method_owner_read_entry_v3(r)
    r.general_owner_entry.require_permission_v3(r)
    with r.store._lock:r.general_owner_entry.require_for_v3(r)
    if getattr(r,"d07_dispatch_classify_v3",False):
        from .d07_source_dispatch_read_v3 import pin_d07_dispatch_owner_v3
        pin_d07_dispatch_owner_v3(r)
    elif r.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import pin_owner_state_owner_v3
        pin_owner_state_owner_v3(r)
    elif r.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import pin_frozen_joint_owner_v3
        pin_frozen_joint_owner_v3(r)
    elif r.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import pin_d07_source_owner_entry_v3
        pin_d07_source_owner_entry_v3(r)
    elif r.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import pin_current_d07_simulation_owner_v3
        pin_current_d07_simulation_owner_v3(r)
    else:
        from .world_owner_read_v3 import pin_world_owner_entry_v3
        pin_world_owner_entry_v3(r)
    return r.general_owner_entry

def require_beta1_source_w09_command_v3(work,*,graph,operation_kind,request,authority,lease,
        operation_id,activity_id,audience_ref,parent_budget_lease_ref):
    r=require_current_beta1_source_work_identity_v3(work.state)
    if(r.work is not work or r.graph is not graph or r.operation_kind!=operation_kind
            or r.request!=request or r.authority is not authority or r.lease is not lease
            or r.operation_id!=operation_id or r.activity_id!=activity_id or r.audience_ref!=audience_ref
            or r.parent_budget_lease_ref!=parent_budget_lease_ref or work.deadline_utc!=r.operation.deadline_utc):
        raise AuthorityUnavailable("World W09 continuation crossed its actual Owner command/Root/deadline")
    return r

def release_current_beta1_source_work_v3(reader):
    if _WORLD_WORKS.pop(reader,None)is None:return
    for task in tuple(_METADATA_TASKS):
        if task.reader is reader:
            if task.column is not None:_METADATA_COLUMNS.pop(task.column,None)
            _METADATA_TASKS.pop(task,None)
    cap=_SOURCE_GROUPS.pop(reader,None)
    if cap is not None:_WORLD_SOURCE_CAPS.pop(cap,None)
    _SOURCE_TASKS.pop(reader,None);_SOURCE_PENDING.pop(reader,None)
    _SOURCE_RESERVATIONS.pop(reader,None);_RECHECK_PEAKS.pop(reader,None)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import release_habit_source_work_v3
        release_habit_source_work_v3(reader)
    elif reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import release_conditioned_self_work_v3
        release_conditioned_self_work_v3(reader)
    elif getattr(reader,"d07_dispatch_classify_v3",False):
        from .d07_source_dispatch_read_v3 import release_d07_dispatch_read_v3
        release_d07_dispatch_read_v3(reader)
    elif reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import release_owner_state_reader_v3
        release_owner_state_reader_v3(reader)
    elif reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import release_frozen_joint_source_v3
        release_frozen_joint_source_v3(reader)
    elif reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import release_d07_source_work_v3
        release_d07_source_work_v3(reader)
    elif reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import release_current_d07_simulation_source_work_v3
        release_current_d07_simulation_source_work_v3(reader)
    else:
        from .world_owner_read_v3 import release_world_owner_read_v3
        release_world_owner_read_v3(reader)
    from .d07_source_preparation_members_v3 import release_d07_source_preparation_members_v3
    release_d07_source_preparation_members_v3(reader)
    if reader.general_owner_entry is not None:
        reader.general_owner_entry.release_v3();reader.general_owner_entry=None

def require_beta1_source_terminal_value_v3(value,work):
    from .named_joint_source_work_v3 import named_joint_host_reader_v3,require_named_joint_terminal_v3
    if named_joint_host_reader_v3(work.state):return require_named_joint_terminal_v3(value,work)
    if getattr(work.state,'operation_kind',None)=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import require_owner_state_terminal_v3
        return require_owner_state_terminal_v3(value,work)
    if work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_source_terminal_value_v3
        return require_habit_source_terminal_value_v3(value,work)
    if work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_source_terminal_value_v3
        return require_conditioned_source_terminal_value_v3(value,work)
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if(type(value)is not PreparedMethodDomainInputsV3 or work.kind not in BETA1_SOURCE_WORK_KINDS_V3
            or value.owner is not work.state):
        raise AuthorityUnavailable("World Source Work returned an unissued terminal value")
    return value.require_business_result_v3(work)
from types import MappingProxyType
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _heap
_SOURCE_ISSUER=object()
_SOURCE_TASKS=WeakKeyDictionary()
_SOURCE_RESERVATIONS=WeakKeyDictionary()
_SOURCE_PENDING=WeakKeyDictionary()
_SOURCE_GROUPS=WeakKeyDictionary()
_WORLD_SOURCE_CAPS=WeakKeyDictionary()
_RECHECK_PEAKS=WeakKeyDictionary()

class _Beta1MetadataRecheckPeakV3:
    def __init__(self,reader):
        self.value=None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):return _heap(self.value)+256

def _beta1_metadata_row_v3(reader,meter,table,columns,where,key):
    from .c09_paged_sql_v2 import _quote
    r=require_current_beta1_source_work_v3(reader)
    peak=_RECHECK_PEAKS.get(r)
    if peak is None:peak=_Beta1MetadataRecheckPeakV3(r);_RECHECK_PEAKS[r]=peak
    lengths=r.db.execute("SELECT "+",".join("length(CAST("+_quote(n)+" AS BLOB))"for n in columns)
        +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",key).fetchone()
    meter.charge_read(8*len(columns))
    if lengths is None:
        peak.value=None;r.operation.refresh_retained_state_v3(peak);return None
    amount=sum(n or 0 for n in lengths);meter.require_available(amount+256)
    r.operation.reserve_retained_state_growth_v3(peak,amount*8+4096)
    peak.value=meter.read_fixed_row(r.db,table,columns,where,key)
    r.operation.finish_retained_state_growth_v3(peak)
    return peak.value

def _source_caps_v3(reader):
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import habit_source_cap_registry_v3
        return habit_source_cap_registry_v3(reader)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import conditioned_source_cap_registry_v3
        return conditioned_source_cap_registry_v3(reader)
    require_current_beta1_source_work_v3(reader)
    return _WORLD_SOURCE_CAPS

def _source_groups_v3(reader,roots):
    r=require_current_beta1_source_work_v3(reader)
    if r.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import habit_source_groups_v3
        groups=habit_source_groups_v3(r,roots)
    elif r.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import conditioned_source_groups_v3
        groups=conditioned_source_groups_v3(r,roots)
    elif r.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import owner_state_source_groups_v3
        groups=owner_state_source_groups_v3(r,roots)
    elif r.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import frozen_joint_source_groups_v3
        groups=frozen_joint_source_groups_v3(r,roots)
    elif r.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import d07_source_groups_v3
        groups=d07_source_groups_v3(r,roots)
    elif r.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import simulation_source_groups_v3
        groups=simulation_source_groups_v3(r,roots)
    else:
        from .world_owner_read_v3 import world_source_groups_v3
        groups=world_source_groups_v3(r,roots)
    union=tuple(sorted({ref for purpose,audiences,refs in groups for ref in refs}))
    if (r.selected_plan is None or union!=tuple(sorted(set(r.selected_plan.source_roots)))
            or union!=tuple(sorted(set(roots)))or any(not audiences or not set(audiences)<=set(r.owner_binding.audiences)
                or purpose not in r.owner_binding.purposes for purpose,audiences,refs in groups)):
        raise AuthorityUnavailable("Beta1 Source groups changed their fixed plan/current Owner intersection")
    return tuple((purpose,tuple(audiences),tuple(sorted(set(refs))))for purpose,audiences,refs in groups)

def create_current_beta1_source_metadata_task_v3(reader,ref):
    require_current_beta1_source_work_v3(reader)
    if ref not in _SOURCE_PENDING.get(reader,set()):
        raise AuthorityUnavailable("Beta1 Source leaf was not derived from its actual fixed root/parent selector")
    tasks=_SOURCE_TASKS.setdefault(reader,{})
    task=tasks.get(ref)
    if task is None:task=_Beta1SourceMetadataEOFV3(_SOURCE_ISSUER,reader,ref);tasks[ref]=task
    return task

def require_beta1_source_control_point_v3(reader,request):
    from ..memory_types import source_key,access_key
    from ..domains.d06 import source_correction_head_key
    table,columns,key_columns,key=request
    if (table,tuple(columns),tuple(key_columns))!=("graph_atoms",("revision","value","valid"),("token","bot","persona")):
        return False
    if len(key)!=3 or tuple(key[1:])!=reader.namespace.as_tuple:return False
    atom=AtomKey.from_token(key[0])
    if atom==owner_grant_key(*reader.namespace.as_tuple):
        return reader.general_owner_entry is not None
    source=source_key(*reader.namespace.as_tuple,atom.owner.subject or "")
    leaf=_SOURCE_TASKS.get(reader,{}).get(source.token)
    if leaf is None or not leaf.complete or atom not in {access_key(*reader.namespace.as_tuple,source.owner.subject),
            source_correction_head_key(reader.namespace,source.owner.subject)}:
        return False
    with runtime_storage_quantum_v3(reader.db)as meter:leaf.require_v1(reader,meter)
    return True

class _Beta1SourcePermissionV3:
    def __init__(self,issuer,reader,groups,records,versions):
        if issuer is not _SOURCE_ISSUER:raise AuthorityUnavailable("actual Beta1 Source completion issuer required")
        self.reader,self.groups,self.records,self.versions=reader,groups,records,versions
        self.source_refs=tuple(sorted(records))
        self.owner_entry=reader.general_owner_entry
        _source_caps_v3(reader)[self]=(_identity_v3(reader),groups,self.source_refs,versions,self.owner_entry,reader.owner_binding)
    def require_for_v3(self,reader):
        r=require_current_beta1_source_work_v3(reader)
        if (_source_caps_v3(r).get(self)!=(_identity_v3(r),self.groups,self.source_refs,self.versions,
                r.general_owner_entry,r.owner_binding)or _SOURCE_GROUPS.get(r)is not self
                or _source_groups_v3(r,r.selected_plan.source_roots)!=self.groups):
            raise AuthorityUnavailable("Beta1 Source permission crossed its own Work/profile/current Owner/metadata EOF")
        if not r.read_finished:self.owner_entry.require_for_v3(r)
        else:
            require_beta1_source_write_phase_v3(r)
        with runtime_storage_quantum_v3(r.db)as meter:
            for ref in self.source_refs:_SOURCE_TASKS[r][ref].require_v1(r,meter)
            for version in self.versions:
                row=_beta1_metadata_row_v3(r,meter,"graph_atoms",("revision",),"token=? AND bot=? AND persona=?",
                    (version.key.token,*r.namespace.as_tuple))
                if(0 if row is None else row[0])!=version.revision:
                    raise AuthorityUnavailable("Beta1 Source/Access/Correction full-parent current revision changed")
        return self

def qualify_current_beta1_source_groups_v3(reader,roots):
    if getattr(reader,"d07_dispatch_classify_v3",False):
        raise AuthorityUnavailable("D07 metadata classifier can never issue or consume a Source permission")
    from .current_method_learning_read_v3 import _need_method_input,method_graph_head_v3
    from ..memory_types import source_key,access_key
    from ..domains.d06 import source_correction_head_key
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    r=require_current_beta1_source_work_v3(reader);groups=_source_groups_v3(r,roots)
    if r.general_owner_entry is None:raise AuthorityUnavailable("Beta1 Sources require completed independent current Owner EOF")
    cap=_SOURCE_GROUPS.get(r)
    if cap is not None:return cap.require_for_v3(r)
    r.general_owner_entry.require_for_v3(r)
    records,versions,visited,active={}, {},set(),set()
    def visit(ref,purpose,audiences):
        group_key=(ref,purpose,audiences)
        if group_key in active:raise AuthorityUnavailable("Beta1 Source ancestry is cyclic")
        if group_key in visited:return
        key=AtomKey.from_token(ref)
        if key!=source_key(*r.namespace.as_tuple,key.owner.subject or ""):
            raise AuthorityUnavailable("Beta1 Source locator is not its canonical namespace Source")
        task=_SOURCE_TASKS.get(r,{}).get(ref)
        if task is None or not task.complete:
            if r.inputs_sealed:raise AuthorityUnavailable("Beta1 body requested an unprepared Source ancestor")
            _SOURCE_PENDING.setdefault(r,set()).add(ref)
            _need_method_input(r,("beta1_source_metadata",ref))
        with runtime_storage_quantum_v3(r.db)as meter:task.require_v1(r,meter)
        access=method_graph_head_v3(r.db,r.namespace,access_key(*r.namespace.as_tuple,key.owner.subject))
        correction=method_graph_head_v3(r.db,r.namespace,source_correction_head_key(r.namespace,key.owner.subject))
        record=None
        for audience in audiences:
            record=_qualify_source_rights_values_v3(r.namespace,ref,task,access,correction,
                audience=audience,purpose=purpose,metadata_only=True)
            if record is None:raise AuthorityUnavailable("Beta1 current Source/Access/Correction/purpose/audience denied")
        active.add(group_key)
        for parent in record.parent_source_ids:visit(source_key(*r.namespace.as_tuple,parent).token,purpose,audiences)
        active.remove(group_key);visited.add(group_key);records[ref]=record
        for atom in(task,access,correction):
            atom_key=task.key if atom is task else atom.key
            versions[atom_key]=GraphVersion(atom_key,atom.revision)
    for purpose,audiences,refs in groups:
        for ref in refs:visit(ref,purpose,audiences)
    r.operation.retain(_heap((groups,tuple(records),tuple(versions.values())))+1024)
    cap=_Beta1SourcePermissionV3(_SOURCE_ISSUER,r,groups,records,tuple(sorted(versions.values(),key=lambda v:v.key.token)))
    _SOURCE_GROUPS[r]=cap
    return cap.require_for_v3(r)

def _beta1_source_heap_v3(reader,extra=0):
    from .dispatch_current_inventory_v3 import _heap
    require_current_beta1_source_work_v3(reader)
    tasks=_SOURCE_TASKS.get(reader,{})
    size=_heap(tuple((t.header,t.fragment,t.metadata) for t in tasks.values()))+extra+65536
    for task in tasks.values():
        if task.parser is not None:
            parser=task.parser
            size+=parser._source_heap_bytes()+_heap((parser._stack,parser._string,parser._literal,parser._number,parser._active_scalar))
    reserved=_SOURCE_RESERVATIONS.get(reader,0)
    if size>reserved:
        reader.operation.retain(size-reserved);_SOURCE_RESERVATIONS[reader]=size
    return size


def _new_beta1_source_parser_v3(reader,*,ensure_ascii):
    from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
    from weakref import ref
    owner=ref(reader)
    class _WorldSourceParser(C09MemorySourceJSONStreamV3):
        def _source_require_arena(self,extra=0):
            _beta1_source_heap_v3(owner(),extra)
            return super()._source_require_arena(extra)
    return _WorldSourceParser(ensure_ascii=ensure_ascii)


class _Beta1SourceMetadataEOFV3:
    def __init__(self,issuer,reader,ref):
        if issuer is not _SOURCE_ISSUER:raise TypeError("actual World Source metadata leaf issuer required")
        require_current_beta1_source_work_v3(reader)
        from weakref import ref as weak_ref
        self.reader=weak_ref(reader);self.key=AtomKey.from_token(ref)
        if self.key.type_name!="memory.source"or NamespaceId.from_key(self.key)!=reader.namespace:
            raise ValueError("World Source metadata leaf crossed actual Source namespace")
        self.header=None;self.cell=None;self.parser=None;self.fragment=b"";self.offset=0;self.total=None
        self.phase="header";self.metadata=None;self.sha256=None;self.complete=False

    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        reader=self.reader();reader.require_current(meter=meter)
        if self.complete:self.require_v1(reader,meter);return True
        if self.header is not None:
            current=_beta1_metadata_row_v3(reader,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple))
            if current!=self.header:raise AuthorityUnavailable("World Source physical head changed")
        if self.phase=="header":
            self.header=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",
                ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",
                (self.key.token,*reader.namespace.as_tuple))
            if self.header is None or self.header[0]<1 or self.header[1]!=1:
                raise ValueError("World Source metadata lost its actual positive current head")
            self.cell=begin_runtime_cell_read_v3(reader.db,self.header[2],erasure_owner_ref=self.key.token)if self.header[2]is not None else None
            codec=None if self.cell is None else self.cell.header[0]
            if codec not in(None,"canonical-json.ascii.v1","canonical-json.utf8.v1"):
                raise ValueError("World Source metadata has another actual cell codec")
            self.parser=_new_beta1_source_parser_v3(reader,ensure_ascii=codec!="canonical-json.utf8.v1")
            self.phase="source";return False
        if self.fragment:
            part=self.fragment[:1024]
            _beta1_source_heap_v3(reader,len(part)*4+65536)
            self.parser.feed(part,lambda event:None)
            self.fragment=self.fragment[len(part):]
            return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(reader.db):
                if self.total is None:
                    meter.require_available(1024)
                    row=reader.db.execute("SELECT typeof(value),length(CAST(value AS BLOB)) FROM graph_atoms "
                        "WHERE token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple)).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0]!="text":raise ValueError("World Source original byte length/kind disappeared")
                    self.total=row[1]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(reader.db,table="graph_atoms",column="value",
                        where="token=? AND bot=? AND persona=?",parameters=(self.key.token,*reader.namespace.as_tuple),
                        start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("World Source original byte count/kind changed")
                    self.offset+=len(chunk)
                else:chunk=None
        if chunk is not None:
            _beta1_source_heap_v3(reader,len(chunk)+65536);self.fragment=chunk;return False
        result=self.parser.finish()
        if self.cell is not None:
            if(result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                raise ValueError("World Source actual raw EOF/cell digest differs")
        elif result.byte_count!=self.total:raise ValueError("World Source legacy original EOF differs")
        _beta1_source_heap_v3(reader,_heap(self.parser._source_metadata))
        metadata=dict(self.parser._source_metadata)
        for name in("audiences","purposes","parent_source_ids"):metadata[name]=tuple(metadata[name])
        if metadata["source_id"]!=self.key.owner.subject:
            raise ValueError("World Source metadata identity differs from actual key")
        _beta1_source_heap_v3(reader,_heap(metadata))
        self.metadata=MappingProxyType(metadata);self.sha256=result.sha256;self.complete=True
        self.parser=None;self.cell=None;self.fragment=b""
        return True

    def require_v1(self,reader,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if self.reader()is not reader or _SOURCE_TASKS.get(reader,{}).get(self.key.token)is not self or not self.complete:
            raise ValueError("World Source metadata is not this actual Work's complete original leaf")
        reader.require_current(meter=meter)
        current=_beta1_metadata_row_v3(reader,meter,"graph_atoms",
            ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple))
        if current!=self.header:raise ValueError("World Source metadata changed its physical head after actual EOF")
        return self


    @property
    def revision(self):return self.header[0]
    @property
    def valid(self):return bool(self.header[1])



_METADATA_TASKS=WeakKeyDictionary()
_METADATA_COLUMNS=WeakKeyDictionary()
_METADATA_ISSUER=object()

def _metadata_profile_v3(reader,identity):
    if reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import owner_state_metadata_spec_v3
        return owner_state_metadata_spec_v3(reader,identity)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import habit_metadata_spec_v3
        return habit_metadata_spec_v3(reader,identity)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import conditioned_metadata_spec_v3
        return conditioned_metadata_spec_v3(reader,identity)
    require_current_beta1_source_work_v3(reader)
    if getattr(reader,"d07_dispatch_classify_v3",False):
        from .d07_source_dispatch_read_v3 import d07_dispatch_metadata_spec_v3
        return d07_dispatch_metadata_spec_v3(reader,identity)
    if identity[0]=="d07_terminal":
        from .d07_source_preparation_members_v3 import d07_terminal_metadata_spec_v3
        return d07_terminal_metadata_spec_v3(reader,identity[1])
    if identity[0]in {"d07_prepared","simulation_prepared"}:
        from .d07_source_preparation_members_v3 import d07_prepared_metadata_spec_v3
        return d07_prepared_metadata_spec_v3(reader,identity[1])
    if reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import simulation_metadata_spec_v3
        return simulation_metadata_spec_v3(reader,identity)
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import d07_source_metadata_spec_v3
        return d07_source_metadata_spec_v3(reader,identity)
    from .world_owner_read_v3 import world_metadata_spec_v3
    return world_metadata_spec_v3(reader,identity)

def _require_metadata_task_v3(task,meter=None):
    record=_METADATA_TASKS.get(task)
    if record is None or record!=(task.reader,task.identity,task.reader.work,task.reader.operation):
        raise AuthorityUnavailable("Beta1 locator metadata lost its private same-Work task")
    r=require_current_beta1_source_work_v3(task.reader)
    if _metadata_profile_v3(r,task.identity)!=task.spec:
        raise AuthorityUnavailable("Beta1 locator metadata changed its fixed profile")
    r.require_current(meter=meter)
    return r

class _Beta1MetadataTaskV3:
    def __init__(self,issuer,reader,identity):
        if issuer is not _METADATA_ISSUER:raise AuthorityUnavailable("private Beta1 fixed metadata task required")
        self.reader,self.identity=reader,identity
        self.spec=_metadata_profile_v3(reader,identity)
        self.table,self.column_name,self.key_columns,self.key,self.header_columns,self.paths,self.signature_kind=self.spec
        self.metadata=None;self.column=None;self.complete=False;self.result=None
        self.reserved=0
        _METADATA_TASKS[self]=(reader,identity,reader.work,reader.operation)
    def require_header_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=_require_metadata_task_v3(self,meter)
        where=" AND ".join(name+"=?"for name in self.key_columns)
        current=_beta1_metadata_row_v3(r,meter,self.table,self.header_columns,where,self.key)
        if self.metadata!=current:raise AuthorityUnavailable("Beta1 locator original header changed after full EOF")
        return current
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3
        r=_require_metadata_task_v3(self,meter)
        if self.complete:self.require_header_v3(meter);return True
        if self.metadata is None:
            where=" AND ".join(name+"=?"for name in self.key_columns)
            self.metadata=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,self.header_columns,where,self.key)
            if self.metadata is None:
                self.complete=True;self.result=None;return True
            return False
        self.require_header_v3(meter)
        if self.column is None:
            cell=None
            if "value_cell_id"in self.header_columns:
                cell_id=self.metadata[self.header_columns.index("value_cell_id")]
                if cell_id is not None:cell=begin_runtime_cell_read_v3(r.db,cell_id,erasure_owner_ref=self.key[0])
            signer=r.graph._GraphCoordinator__d11_issuer._signer if self.signature_kind is not None else None
            signature=self.metadata[self.header_columns.index("signature")]if signer is not None else None
            self.column=_Beta1MetadataColumnV3(self,cell=cell,signer=signer,signature=signature)
            return False
        if not self.column.advance(meter):return False
        self.require_header_v3(meter)
        from .dispatch_current_inventory_v3 import _detach_value_v3
        r.operation.retain(_heap(self.column.frozen)*4+4096)
        value=_detach_value_v3(self.column.frozen)
        digest_name={"original_payload_json":"original_digest","payload_json":"payload_digest"}.get(self.column_name)
        if digest_name is not None and digest_name in self.header_columns:
            expected=self.metadata[self.header_columns.index(digest_name)]
            if self.column.canonical_digest!=expected:
                raise AuthorityUnavailable("Beta1 signed locator whole original digest differs")
        if r.operation_kind=='read_beta1_owner_state_v1':
            from .beta1_owner_state_read_v3 import finish_owner_state_metadata_v3
            self.result=finish_owner_state_metadata_v3(self,value)
        elif r.work.kind==HABIT_SOURCE_WORK_KIND_V3:
            from .current_habit_source_read_v3 import finish_habit_metadata_v3
            self.result=finish_habit_metadata_v3(self,value)
        elif r.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
            from .current_conditioned_self_read_v3 import finish_conditioned_metadata_v3
            self.result=finish_conditioned_metadata_v3(self,value)
        elif getattr(r,"d07_dispatch_classify_v3",False):
            from .d07_source_dispatch_read_v3 import finish_d07_dispatch_metadata_v3
            self.result=finish_d07_dispatch_metadata_v3(self,value)
        elif self.identity[0]=="d07_terminal":
            from .d07_source_preparation_members_v3 import finish_d07_terminal_metadata_v3
            self.result=finish_d07_terminal_metadata_v3(self,value)
        elif self.identity[0]in {"d07_prepared","simulation_prepared"}:
            from .d07_source_preparation_members_v3 import finish_d07_prepared_metadata_v3
            self.result=finish_d07_prepared_metadata_v3(self,value)
        elif r.operation_kind=="run_simulation":
            from .current_d07_simulation_source_read_v3 import finish_current_d07_simulation_metadata_v3
            self.result=finish_current_d07_simulation_metadata_v3(self,value)
        elif r.operation_kind=="serve_concern":
            from .d07_source_owner_read_v3 import finish_d07_source_metadata_v3
            self.result=finish_d07_source_metadata_v3(self,value)
        else:
            from .world_owner_read_v3 import finish_world_metadata_v3
            self.result=finish_world_metadata_v3(self,value)
        self.complete=True
        return True

def create_current_beta1_metadata_task_v3(reader,identity):
    return _Beta1MetadataTaskV3(_METADATA_ISSUER,reader,identity)

# The column retains only the fixed profile, while canonical parsing/signature
# verification consumes every byte of the physical original.
_METADATA_CONSTRUCTING=WeakKeyDictionary()

def _Beta1MetadataColumnV3(task,*,cell,signer,signature):
    from .current_method_learning_read_v3 import MethodJSONColumnV3,_ISSUER
    r=_require_metadata_task_v3(task)
    _METADATA_CONSTRUCTING[r]=task
    try:
        column=MethodJSONColumnV3(_ISSUER,r,table=task.table,column=task.column_name,key_columns=task.key_columns,key=task.key,
            cell=cell,signer=signer,signature_kind=task.signature_kind,signature=signature,
            beta1_metadata_task=task,beta1_metadata_issuer=_METADATA_ISSUER)
    finally:_METADATA_CONSTRUCTING.pop(r,None)
    _METADATA_COLUMNS[column]=(task,r,r.work,r.operation,task.spec)
    column.semantic_decoder=column.semantic_hash=None
    if cell is not None and cell.header[0]=="canonical-json.utf8.v1":
        import codecs,hashlib
        column.semantic_decoder=codecs.getincrementaldecoder("utf8")("strict");column.semantic_hash=hashlib.sha256()
    return column

def retain_beta1_metadata_path_v3(column,path):
    task=column.beta1_metadata_task
    _require_metadata_task_v3(task)
    if(_METADATA_COLUMNS.get(column)!=(task,task.reader,task.reader.work,task.reader.operation,task.spec)
            or task.column is not column):
        raise AuthorityUnavailable("Beta1 metadata path has no actual private column/task")
    if task.reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import retain_habit_metadata_path_v3
        return retain_habit_metadata_path_v3(task,path)
    if task.reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import retain_conditioned_metadata_path_v3
        return retain_conditioned_metadata_path_v3(task,path)
    if task.identity[0]in {"d07_prepared","simulation_prepared"}:
        from .d07_source_preparation_members_v3 import retain_d07_prepared_metadata_path_v3
        return retain_d07_prepared_metadata_path_v3(task,path)
    if task.identity[0]=="d07_terminal":
        return any(p[:len(path)]==path or path[:len(p)]==p for p in task.paths)
    if task.reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import retain_current_d07_simulation_metadata_path_v3
        return retain_current_d07_simulation_metadata_path_v3(task,path)
    if not path:return True
    return any(selected[:len(path)]==path or path[:len(selected)]==selected for selected in task.paths)

def advance_beta1_metadata_column_v3(c,meter):
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,_quote
    from .dispatch_current_inventory_v3 import _heap,_freeze_value_v3
    r=_require_metadata_task_v3(c.beta1_metadata_task,meter);c._actual()
    if c.complete:return True
    if c.fragment_offset<len(c.fragment):
        end=min(c.fragment_offset+1024,len(c.fragment));chunk=c.fragment[c.fragment_offset:end]
        c._reserve_v3(131072);c.parser.feed(chunk,c._emit_v3)
        if c.semantic_decoder is not None:
            from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
            _D07AuthorityGraphMetadataColumnV3._semantic_v3(c,chunk,meter)
        c.fragment_offset=end;c._flush_text_v3();return False
    if c.cell is not None:chunk=c.cell.read_fragment(meter=meter)
    else:
        where=" AND ".join(_quote(name)+"=?"for name in c.key_columns)
        with legacy_cell_read_transaction_v2(c.db):
            if c.total is None:
                row=c.db.execute("SELECT typeof("+_quote(c.column)+"),length(CAST("+_quote(c.column)+" AS BLOB)) FROM "+
                    _quote(c.table)+" WHERE "+where,c.key).fetchone();meter.charge_read(16)
                if row is None or row[0]!="text":raise AuthorityUnavailable("Beta1 fixed locator original disappeared")
                c.total=row[1]
            if c.offset<c.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(c.db,table=c.table,column=c.column,
                    where=where,parameters=c.key,start=c.offset,length=min(16384,c.total-c.offset),meter=meter)
                if(total,kind)!=(c.total,"text"):raise AuthorityUnavailable("Beta1 locator original byte count/kind changed")
                c.offset+=len(chunk)
            else:chunk=None
    if chunk is not None:
        if c.signature_state is not None:c.signature_state.update(chunk);c.signature_bytes+=len(chunk)
        c.fragment,c.fragment_offset=chunk,0;return False
    parsed=c.parser.finish()
    if c.cell is not None:
        if(parsed.sha256,parsed.byte_count)!=(c.cell.finish(meter=meter),c.cell.header[3]):
            raise AuthorityUnavailable("Beta1 locator physical cell whole EOF differs")
    elif parsed.byte_count!=c.total:raise AuthorityUnavailable("Beta1 locator whole original EOF differs")
    if c.semantic_decoder is not None:
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
        _D07AuthorityGraphMetadataColumnV3._semantic_v3(c,b"",meter,final=True)
        c.canonical_digest=c.semantic_hash.hexdigest()
    else:c.canonical_digest=parsed.sha256
    c._reserve_v3(_heap(c.value)*2+1024);c.frozen=_freeze_value_v3(c.value)
    c.sha256,c.byte_count=parsed.sha256,parsed.byte_count
    c.value=None;c.nodes={};c.scalar=bytearray();c.fragment=b"";c.parser=None
    c.semantic_decoder=c.semantic_hash=None
    c.complete=True
    if c.signature_state is not None:
        c.signer.finish_original_stream_verification_v3(c.signature_kind,c.signature,c,c.signature_state)
        c.signature_verified=True
    return True
    

def require_beta1_metadata_column_task_v3(task,owner,*,issuer,table,column,key_columns,key):
    _require_metadata_task_v3(task)
    if (issuer is not _METADATA_ISSUER or _METADATA_CONSTRUCTING.get(owner)is not task or task.reader is not owner or (table,column,tuple(key_columns),tuple(key))!=
            (task.table,task.column_name,task.key_columns,task.key) or task.column is not None):
        raise AuthorityUnavailable("Beta1 locator column lacks its exact pending physical task")
    return task

def require_beta1_metadata_signature_v3(column,*,signer,kind,signature=None,verifier=None,complete=False):
    task=getattr(column,"beta1_metadata_task",None)
    if task is None:return False,None
    r=_require_metadata_task_v3(task)
    if (task.column is not column and _METADATA_CONSTRUCTING.get(r)is not task
            or column.owner is not r or column.table!=task.table or column.column!=task.column_name
            or column.key_columns!=task.key_columns or column.key!=task.key
            or signer is not r.graph._GraphCoordinator__d11_issuer._signer or kind!=task.signature_kind
            or task.metadata is None or "signature"not in task.header_columns
            or column.signature!=task.metadata[task.header_columns.index("signature")]
            or signature is not None and signature!=column.signature
            or complete and(not column.complete or verifier is not column.signature_state
                or signature!=column.signature or column.signature_bytes!=column.byte_count)):
        raise AuthorityUnavailable("Beta1 metadata signature crossed its actual task/original/current installed signer")
    return True,column

def advance_current_beta1_source_work_v3(graph,work):
    from .named_joint_source_work_v3 import named_joint_host_reader_v3,advance_named_joint_host_work_v3
    if named_joint_host_reader_v3(work.state):return advance_named_joint_host_work_v3(graph,work)
    if getattr(work.state,'operation_kind',None)=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import advance_owner_state_read_v3
        return advance_owner_state_read_v3(graph,work)
    if work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import advance_current_habit_source_work_v3
        return advance_current_habit_source_work_v3(graph,work)
    if work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import advance_current_conditioned_self_read_v3
        return advance_current_conditioned_self_read_v3(graph,work)
    if work.kind==D07_DISPATCH_WORK_KIND_V3:
        from .d07_source_dispatch_read_v3 import advance_current_d07_dispatch_read_v3
        return advance_current_d07_dispatch_read_v3(graph,work)
    reader=require_current_beta1_source_work_v3(work.state)
    if reader.graph is not graph or reader.work is not work:raise AuthorityUnavailable("World advancement crossed its private factory")
    from .current_method_learning_read_v3 import advance_current_method_learning_read_v3
    return advance_current_method_learning_read_v3(graph,work)

def finish_current_beta1_source_work_v3(graph,work,error):
    from .named_joint_source_work_v3 import named_joint_host_reader_v3,finish_named_joint_host_work_v3
    if named_joint_host_reader_v3(work.state):return finish_named_joint_host_work_v3(graph,work,error)
    if work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import finish_current_habit_source_work_v3
        return finish_current_habit_source_work_v3(graph,work,error)
    if work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import finish_current_conditioned_self_read_v3
        return finish_current_conditioned_self_read_v3(graph,work,error)
    reader=work.state
    if(_WORLD_WORKS.get(reader)!=_identity_v3(reader)or reader.graph is not graph or reader.work is not work):
        raise AuthorityUnavailable("World finalization crossed its private factory")
    from .current_method_learning_read_v3 import finish_current_method_learning_read_v3
    return finish_current_method_learning_read_v3(graph,work,error)

def beta1_source_required_domains_v3(operation_kind):
    if operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import DOMAINS
        return DOMAINS
    from .current_habit_source_read_v3 import habit_source_operation_types_v3,habit_source_required_domains_v3
    if operation_kind in habit_source_operation_types_v3() and operation_kind not in {'prepare_life','prepare_source_note_body'}:
        return habit_source_required_domains_v3(operation_kind)
    from .current_conditioned_self_read_v3 import conditioned_operation_types_v3,conditioned_source_required_domains_v3
    if operation_kind in conditioned_operation_types_v3():return conditioned_source_required_domains_v3(operation_kind)
    if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1","query_world_view_v1"}:
        return frozenset({"d03","d06","d11"})
    if operation_kind=="project_world_perspective_v1":
        return frozenset({"d03","d06","d08","d09","d11"})
    if operation_kind=="serve_concern":
        return frozenset({"d02","d03","d06","d07","d11"})
    if operation_kind=="run_simulation":
        return frozenset({"d01","d02","d06","d07","d08","d10","d11"})
    raise AuthorityUnavailable("unregistered independent Source command domains")

def require_beta1_source_body_v3(reader,table,key):
    if reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import require_frozen_joint_body_v3
        return require_frozen_joint_body_v3(reader,table,key)
    if reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import require_owner_state_body_v3
        return require_owner_state_body_v3(reader,table,key)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_body_v3
        return require_habit_body_v3(reader,table,key)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_body_v3
        return require_conditioned_body_v3(reader,table,key)
    if reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_body_v3
        return require_current_d07_simulation_body_v3(reader,table,key)
    if getattr(reader,"d07_dispatch_classify_v3",False):
        from ..graph_types import owner_grant_key
        if table=="graph_atoms"and tuple(key)==(owner_grant_key(*reader.namespace.as_tuple).token,*reader.namespace.as_tuple)and reader.general_owner_entry is not None:return
        raise AuthorityUnavailable("D07 classifier has no protected body or Source permission")
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_source_body_v3
        return require_d07_source_body_v3(reader,table,key)
    from .world_owner_read_v3 import require_world_body_v3
    return require_world_body_v3(reader,table,key)

def require_beta1_source_point_v3(reader,request):
    if reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import require_frozen_joint_point_v3
        return require_frozen_joint_point_v3(reader,request)
    if reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import require_owner_state_point_v3
        return require_owner_state_point_v3(reader,request)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_point_v3
        return require_habit_point_v3(reader,request)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_point_v3
        return require_conditioned_point_v3(reader,request)
    if reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_point_v3
        return require_current_d07_simulation_point_v3(reader,request)
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_source_point_v3
        return require_d07_source_point_v3(reader,request)
    from .world_owner_read_v3 import require_world_point_v3
    return require_world_point_v3(reader,request)

def require_beta1_source_groups_v3(reader,roots):
    if reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import require_frozen_joint_sources_v3
        return require_frozen_joint_sources_v3(reader,roots)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_sources_v3
        return require_habit_sources_v3(reader,roots)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_sources_v3
        return require_conditioned_sources_v3(reader,roots)
    if reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_sources_v3
        return require_current_d07_simulation_sources_v3(reader,roots)
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_sources_v3
        return require_d07_sources_v3(reader,roots)
    from .world_owner_read_v3 import require_world_sources_v3
    return require_world_sources_v3(reader,roots)

def register_beta1_source_write_phase_v3(inputs,scope,current_owner):
    if inputs.owner.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import register_frozen_joint_write_v3
        return register_frozen_joint_write_v3(inputs,scope,current_owner)
    if inputs.owner.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import register_habit_write_phase_v3
        return register_habit_write_phase_v3(inputs,scope,current_owner)
    if inputs.owner.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import register_conditioned_write_phase_v3
        return register_conditioned_write_phase_v3(inputs,scope,current_owner)
    if inputs.owner.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import register_current_d07_simulation_write_phase_v3
        return register_current_d07_simulation_write_phase_v3(inputs,scope,current_owner)
    if inputs.owner.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import register_d07_source_write_phase_v3
        return register_d07_source_write_phase_v3(inputs,scope,current_owner)
    from .world_owner_read_v3 import register_world_write_phase_v3
    return register_world_write_phase_v3(inputs,scope,current_owner)

def require_beta1_source_write_phase_v3(reader):
    if reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import require_frozen_joint_write_v3
        return require_frozen_joint_write_v3(reader)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_write_phase_v3
        return require_habit_write_phase_v3(reader)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_write_phase_v3
        return require_conditioned_write_phase_v3(reader)
    if reader.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_write_phase_v3
        return require_current_d07_simulation_write_phase_v3(reader)
    if reader.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_source_write_phase_v3
        return require_d07_source_write_phase_v3(reader)
    from .world_owner_read_v3 import require_world_write_phase_v3
    return require_world_write_phase_v3(reader)

def require_beta1_source_plan_metadata_v3(reader):
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import require_habit_source_plan_metadata_v3
        return require_habit_source_plan_metadata_v3(reader)
    if reader.work.kind==CONDITIONED_SELF_WORK_KIND_V3:
        from .current_conditioned_self_read_v3 import require_conditioned_owner_ready_v3
        return require_conditioned_owner_ready_v3(reader)
    require_current_beta1_source_work_v3(reader)
    if reader.operation_kind=='input:freeze_joint_window_node_command_v1':
        from .frozen_joint_command_source_v3 import require_frozen_joint_source_v3
        return require_frozen_joint_source_v3(reader)
    if reader.operation_kind in {"serve_concern","run_simulation"}:return
    from .world_owner_read_v3 import require_world_plan_metadata_v3
    return require_world_plan_metadata_v3(reader)


def beta1_source_reader_work_kind_v3(reader):
    from .current_habit_source_read_v3 import _HabitPendingSourceV3
    if type(reader.source_pending_owner)is _HabitPendingSourceV3:return HABIT_SOURCE_WORK_KIND_V3
    if getattr(reader,"d07_dispatch_classify_v3",False):
        if reader.operation_kind!="serve_concern":raise AuthorityUnavailable("D07 classifier cannot change operation")
        return D07_DISPATCH_WORK_KIND_V3
    return beta1_source_work_kind_v3(reader.operation_kind)

def beta1_source_reader_required_domains_v3(reader):
    if reader.operation_kind=='read_beta1_owner_state_v1':
        from .beta1_owner_state_read_v3 import owner_state_required_domains_v3
        return owner_state_required_domains_v3(reader.request)
    if reader.work.kind==HABIT_SOURCE_WORK_KIND_V3:
        from .current_habit_source_read_v3 import habit_source_required_domains_v3
        return habit_source_required_domains_v3(reader.operation_kind)
    return frozenset({"d07"})if getattr(reader,"d07_dispatch_classify_v3",False)else beta1_source_required_domains_v3(reader.operation_kind)


def _register_conditioned_beta1_reader_v3(reader,work):
    from .current_conditioned_self_read_v3 import require_conditioned_source_factory_reader_v3,register_conditioned_self_owner_work_v3
    require_conditioned_source_factory_reader_v3(reader,work,registration=True)
    if reader in _WORLD_WORKS:raise AuthorityUnavailable('conditioned Source reader registers only once per actual READ scope')
    _WORLD_WORKS[reader]=_identity_v3(reader)
    register_conditioned_self_owner_work_v3(reader)
    return work



def _register_habit_beta1_reader_v3(reader,work):
    from .current_habit_source_read_v3 import require_habit_source_factory_reader_v3,register_habit_source_work_v3
    require_habit_source_factory_reader_v3(reader,work,registration=True)
    if reader in _WORLD_WORKS:raise AuthorityUnavailable('Habit Source registers only once per actual independently issued READ Scope')
    _WORLD_WORKS[reader]=_identity_v3(reader)
    register_habit_source_work_v3(reader)
    return work

def require_pending_beta1_owner_factory_v3(capsule,graph,operation,fence,authority,operation_kind,request):
    from .current_habit_source_read_v3 import _HabitPendingSourceV3,require_pending_habit_factory_v3
    if type(capsule)is _HabitPendingSourceV3:
        return require_pending_habit_factory_v3(capsule,graph=graph,operation=operation,fence=fence,
            authority=authority,operation_kind=operation_kind,request=request)
    from .current_conditioned_self_read_v3 import _ConditionedPendingOwnerV3,require_pending_conditioned_factory_v3
    if type(capsule)is _ConditionedPendingOwnerV3:
        return require_pending_conditioned_factory_v3(capsule,graph=graph,operation=operation,fence=fence,
            authority=authority,operation_kind=operation_kind,request=request)
    raise AuthorityUnavailable('pending Owner constructor requires an exact privately issued closed Source factory')


def reset_current_beta1_source_permission_v3(reader):
    if reader.work.kind!=CONDITIONED_SELF_WORK_KIND_V3:
        raise AuthorityUnavailable('Source renewal is restricted to the actual unsealed conditioned output phase')
    from .current_conditioned_self_read_v3 import require_conditioned_output_requalification_v3
    state=require_conditioned_output_requalification_v3(reader)
    cap=_SOURCE_GROUPS.pop(reader,None)
    if cap is not None:state.source_caps.pop(cap,None)
    state.source_permission=None


def require_pending_beta1_owner_reader_current_v3(reader,*,meter=None):
    from .current_habit_source_read_v3 import _HabitPendingSourceV3,require_habit_pending_current_v3
    if type(reader.source_pending_owner)is _HabitPendingSourceV3:return require_habit_pending_current_v3(reader,meter=meter)
    from .current_conditioned_self_read_v3 import _ConditionedPendingOwnerV3,require_conditioned_pending_current_v3
    if type(reader.source_pending_owner)is _ConditionedPendingOwnerV3:
        return require_conditioned_pending_current_v3(reader,meter=meter)
    raise AuthorityUnavailable('pending Owner control requires its exact privately issued Source reader')
