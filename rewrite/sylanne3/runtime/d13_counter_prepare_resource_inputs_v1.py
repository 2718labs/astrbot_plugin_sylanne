"""Resource metadata and Body EOF belonging only to the actual counter preparation FULL Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d13_core_counter_contract_v1 import D13CounterCPUPrepareInstructionV1
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
from .c04_body_resource_inputs_v3 import C04ResourceMetadataReadV3,C04ResourceRowsReadV3
from .current_character_labor_adoption_v1 import _payload_heap_v1

_READERS=WeakKeyDictionary()
_COMPLETE=WeakKeyDictionary()
_BOUND=ContextVar("d13_counter_prepare_resource_inputs_v1",default=None)


class D13CounterPrepareResourceReadV1:
    def __init__(self,full):
        _full_v1(full)
        self.full=full
        self.graph,self.db,self.namespace,self.operation=full.graph,full.db,full.namespace,full.operation
        self.work,self.graph_stamp=full.work,full.graph_stamp
        self.instruction=full.d13_counter_instruction
        if type(self.instruction)is not D13CounterCPUPrepareInstructionV1:
            raise AuthorityUnavailable("counter resource instruction is not the actual typed Core locator")
        self.policy=self.graph._GraphCoordinator__body_quote_authority.policy(self.db,self.namespace,
            self.instruction.body_policy_id,self.instruction.body_policy_version)
        self.resource_metadata=C04ResourceMetadataReadV3(self,self.policy)
        self.resource_tokens={self.resource_metadata.profile_key.token,self.resource_metadata.state_key.token}
        self.allow_reservation_census=False
        self.phase="metadata";self.current=None;self.profile=self.state=None
        self.reservations=[];self.complete=False;self.consumed=False;self.output=None
        self.material=self.rights=None
        self.operation.register_retained_state_v3(self)

    def _identity_v1(self):
        return(self.full,self.work,self.operation,self.db,self.namespace,self.graph_stamp,self.instruction,self.policy)

    def require_current_v1(self,meter=None):
        if _READERS.get(self.full)is not self or self._identity_v1()!=self.identity:
            raise AuthorityUnavailable("counter resources lost their actual issued FULL Work")
        _full_v1(self.full,db=self.db,meter=meter)
        if self.full.d13_counter_instruction is not self.instruction:
            raise AuthorityUnavailable("counter resources changed their immutable Core instruction")
        return self

    def _runtime_retained_heap_bytes_v3(self):
        return self.resource_metadata._runtime_retained_heap_bytes_v3()+65536+_payload_heap_v1(
            (self.policy,self.profile,self.state,self.reservations,
             None if self.current is None else(self.current.values,self.current.reader.values)))

    def require_resource_reader_v3(self):
        self.require_current_v1()
        if self.phase not in {"profile","state","reservations"}:
            raise AuthorityUnavailable("counter resource Body precedes complete Source ALL")
        self.full.source_material.require_rights_seal_v3()

    def advance_body_v1(self,meter):
        self.require_current_v1(meter)
        if self.complete:return True
        if self.phase=="metadata":
            self.resource_metadata.require_v3(meter)
            rights=self.full.source_material.require_rights_seal_v3()
            self.material=self.full.source_material.proof
            if self.material is None:
                raise AuthorityUnavailable("counter resource Body requires its completed original Source material")
            self.rights=rights
            groups=self.full.owner_groups
            for purpose,audiences,roots in groups:
                if self.resource_metadata.roots<=set(roots):
                    if all((ref,purpose,audience,False)in rights.rights
                            or(ref,purpose,audience,True)in rights.rights
                            for ref in self.resource_metadata.roots for audience in audiences):
                        break
            else:raise AuthorityUnavailable("counter resources were not included in an actual complete Source group")
            self.phase="profile";return False
        if self.current is None:
            if self.phase=="reservations":self.current=C04ResourceRowsReadV3(self,reservations=True)
            else:
                key=self.resource_metadata.profile_key if self.phase=="profile"else self.resource_metadata.state_key
                self.current=C04ResourceRowsReadV3(self,token=key.token)
            return False
        if not self.current.advance_v3():return False
        values=self.current.values
        if self.phase in {"profile","state"}:
            if len(values)!=1 or values[0][2]!=1:
                raise AuthorityUnavailable("counter current Body resource is absent or invalid")
            key,revision,valid,value=values[0]
            if self.phase=="profile":self.profile=(key,revision,value);self.phase="state"
            else:self.state=(key,revision,value);self.phase="reservations";self.allow_reservation_census=True
            self.current=None;return False
        for key,revision,valid,value in values:
            if valid!=1:raise AuthorityUnavailable("counter reservation census contains an invalid original")
            self.reservations.append((key,revision,value))
        self.current=None;self.complete=True;self.phase="complete"
        _COMPLETE[self]=self._body_identity_v1()
        return True

    def _body_identity_v1(self):
        return(self.full,self.work,self.operation,self.instruction,self.profile,self.state,
            tuple(self.reservations),tuple(sorted(self.resource_metadata.heads.items())),
            tuple(sorted(self.resource_metadata.versions.items(),key=lambda item:item[0].token)),
            self.material,self.rights)

    def require_inputs_v1(self,*,db,instruction,scope):
        self.require_current_v1()
        if(not self.complete or _COMPLETE.get(self)!=self._body_identity_v1()
                or self.consumed or db is not self.db or not db.in_transaction
                or instruction is not self.instruction or scope is not self.full.fence.scope):
            raise AuthorityUnavailable("counter resource packet is not this original WRITE transaction")
        self.resource_metadata.require_v3()
        with runtime_storage_quantum_v3(db)as meter:
            for ref,expected in self.resource_metadata.heads.items():
                actual=meter.read_fixed_row(db,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(ref,*self.namespace.as_tuple))
                if actual!=expected:
                    raise AuthorityUnavailable("counter resource metadata changed before its CPU/Body quote")
        return self

    @property
    def versions(self):
        return tuple(self.resource_metadata.versions.values())

    def consume_v1(self,output):
        if self.consumed:raise AuthorityUnavailable("counter resource packet was already consumed")
        self.consumed=True;self.output=output
        return output

    def release_v1(self):
        if _READERS.get(self.full)is not self:return
        _READERS.pop(self.full,None);_COMPLETE.pop(self,None)
        self.operation.unregister_retained_state_v3(self)
        self.current=self.profile=self.state=self.output=self.material=self.rights=None
        self.reservations.clear()
        self.resource_metadata.heads.clear();self.resource_metadata.versions.clear()
        self.resource_metadata.roots.clear();self.resource_metadata.edges.clear()
        self.resource_metadata.pending.clear();self.resource_metadata.members.clear()


def _full_v1(full,*,db=None,meter=None):
    from .current_graph_full_read_v3 import (_OrdinaryFullReadV3,
        require_actual_d13_counter_prepare_full_reader_v1)
    if type(full)is not _OrdinaryFullReadV3:
        raise AuthorityUnavailable("actual private counter preparation FULL reader required")
    return require_actual_d13_counter_prepare_full_reader_v1(full,db=db,meter=meter)


def require_actual_d13_counter_resource_reader_v1(reader,*,meter=None):
    if type(reader)is not D13CounterPrepareResourceReadV1:
        raise AuthorityUnavailable("actual named counter resource reader required")
    return reader.require_current_v1(meter)


def advance_d13_counter_prepare_resource_metadata_v1(full,meter):
    _full_v1(full,meter=meter)
    task=_READERS.get(full)
    if task is None:
        task=D13CounterPrepareResourceReadV1(full)
        task.identity=task._identity_v1();_READERS[full]=task
        return False
    return task.resource_metadata.advance_v3(meter)


def require_d13_counter_prepare_resource_metadata_v1(full,*,meter=None):
    _full_v1(full,meter=meter)
    task=_READERS.get(full)
    if type(task)is not D13CounterPrepareResourceReadV1:
        raise AuthorityUnavailable("counter preparation has no complete resource discovery")
    task.require_current_v1(meter)
    return task.resource_metadata.require_v3(meter)


def advance_d13_counter_prepare_resources_v1(full,meter):
    _full_v1(full,meter=meter)
    task=_READERS.get(full)
    if type(task)is not D13CounterPrepareResourceReadV1:
        raise AuthorityUnavailable("counter resource discovery must precede its Body continuation")
    return task.advance_body_v1(meter)


def require_d13_counter_prepare_resource_inputs_v1(full,*,db,instruction,scope):
    task=_READERS.get(full)
    if type(task)is not D13CounterPrepareResourceReadV1:
        raise AuthorityUnavailable("counter preparation requires its actual resource packet")
    return task.require_inputs_v1(db=db,instruction=instruction,scope=scope)


@contextmanager
def bind_d13_counter_prepare_resource_inputs_v1(packet):
    require_actual_d13_counter_resource_reader_v1(packet)
    if not packet.complete:raise AuthorityUnavailable("counter resource Body EOF is incomplete")
    token=_BOUND.set(packet)
    try:
        with bind_runtime_storage_operation_v3(packet.operation,packet.db):yield packet
    finally:_BOUND.reset(token)


def bound_d13_counter_prepare_source_v1(db,namespace):
    packet=_BOUND.get()
    if packet is None:return None
    require_actual_d13_counter_resource_reader_v1(packet)
    if packet.db is not db or packet.namespace!=namespace or not db.in_transaction:
        raise AuthorityUnavailable("counter Source binder changed its actual namespace/transaction")
    from .current_graph_full_read_v3 import require_bound_graph_full_read_proof_for_db_v3
    proof=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=packet.full.contract.families)
    if proof.work.state is not packet.full or proof.source_material is not packet.material:
        raise AuthorityUnavailable("counter Source projection is not its same-Work complete Source material")
    proof.source_material.require_current(db=db,prepared_full_read=proof,namespace=namespace,
        source_ref=packet.instruction.source_ref.ref,audiences=proof.source_material.audiences)
    return proof


def release_d13_counter_prepare_resources_v1(full):
    task=_READERS.get(full)
    if task is not None:task.release_v1()


class HostD13CounterRouteMetadataInventoryV1:
    """Route metadata backed by this counter's actual FULL proof, without a second reader."""
    family="d13_counter_prepare"
    def __init__(self,proof):
        self.proof=proof
        self.namespace,self.query,self.projection=proof.namespace,proof.query,proof.projection

    def require_current(self,db,namespace,query):
        if bound_d13_counter_prepare_source_v1(db,namespace)is not self.proof or query!=self.query:
            raise AuthorityUnavailable("counter route metadata changed its same-Work Source proof")
        return self

    def source_metadata(self,db,namespace,query,key,*,require_grant=False):
        self.require_current(db,namespace,query)
        return self.proof.source_metadata(self.proof.graph,db,namespace,key)

    def atom_rows(self,db,namespace,query,type_names,columns):
        self.require_current(db,namespace,query)
        if tuple(type_names)!=("d03.account_binding",)or tuple(columns)!=("token","revision","value"):
            raise AuthorityUnavailable("counter route inventory has only its original account metadata query")
        from .current_graph_full_read_v3 import require_bound_graph_full_atom_rows_v3
        return require_bound_graph_full_atom_rows_v3(db,namespace,query,type_names,columns)


def read_host_d13_counter_scope_v1(proof,*,db,d02_issuer,context,namespace,c02_operation_id,
        source_ref,now_utc,epoch):
    """Use complete Source material and the same official D03/route algorithms."""
    if(bound_d13_counter_prepare_source_v1(db,namespace)is not proof
            or proof.work.state.d13_counter_instruction.c02_operation_id!=c02_operation_id
            or proof.work.state.d13_counter_instruction.source_ref.ref!=source_ref
            or proof.projection.epochs!=(epoch,)):
        raise AuthorityUnavailable("counter prospective plan changed its actual Source/C02/epoch")
    from ..domains.d07 import _qualify_focus_attention_values_v3
    attention=_qualify_focus_attention_values_v3(proof.projection,namespace,now=now_utc,
        source_reader=lambda key:proof.source_metadata(proof.graph,db,namespace,key))
    if attention is None:raise AuthorityUnavailable("counter current Source-qualified focus/attention is unavailable")
    from .reply_model_job import read_current_reply_model_inputs_v1,read_current_reply_route_manifest_v2
    inputs=read_current_reply_model_inputs_v1(db,d02_issuer,namespace,proof.source_material.inputs.c02_receipt,
        source_ref,proof.projection,attention,prepared_full_read=proof)
    route=read_current_reply_route_manifest_v2(db,namespace,inputs,source_ref)
    from .reply_entity_route_v2 import read_current_reply_entity_route_binding_v2
    binding=read_current_reply_entity_route_binding_v2(db,namespace,route,proof.query,now_utc=now_utc,
        prepared_inventory=HostD13CounterRouteMetadataInventoryV1(proof))
    from .dispatch_current_projection import read_current_dispatch_projection,derive_current_domain_reads
    from ..domains.d03.context import RoleBindingRequest
    projection=read_current_dispatch_projection(db,namespace,proof.projection,proof.query)
    request=RoleBindingRequest(f"persona:{namespace.persona_id}",binding.target_entity_ref,
        None,route.scene_ref,"expression","reply",now_utc,True)
    role_read,boundary_read=derive_current_domain_reads(db,projection,request,context)
    if(role_read.status!="complete"or len(role_read.matched_bindings)!=1
            or projection.coverage!="full"or boundary_read.coverage!="full"):
        raise AuthorityUnavailable("counter current private scene role is not uniquely Source-qualified")
    matched=role_read.matched_bindings[0]
    selected=tuple(atom for atom in projection.role_bindings
        if atom.key.name==matched and atom.value.get("scene_ref")==route.scene_ref)
    if len(selected)!=1:raise AuthorityUnavailable("counter actual scene role metadata is absent")
    from ..runtime_contracts import VersionedRef
    scene=VersionedRef(selected[0].key.token,selected[0].revision)
    audience=VersionedRef(binding.binding_version.key.token,binding.binding_version.revision)
    return(inputs,route,binding,proof.projection,proof.query,role_read,boundary_read,scene,audience)


@contextmanager
def bind_current_d13_counter_self_scope_v1(full,*,db):
    """Bind the actual Root-issued counter scope to its same-Work Source material."""
    from .current_graph_full_read_v3 import require_actual_d13_counter_prepare_full_reader_v1
    from .d13_counter_prepare_owner_v1 import require_actual_d13_counter_owner_issuance_v1
    require_actual_d13_counter_prepare_full_reader_v1(full,db=db)
    packet=require_d13_counter_prepare_resource_inputs_v1(full,db=db,
        instruction=full.d13_counter_instruction,scope=full.fence.scope)
    issued=full.d13_counter_owner_issuance
    original_owner=require_actual_d13_counter_owner_issuance_v1(issued,full.graph,
        full.authority,issued.operation_id)
    if(full.fence.scope.operation!="write"or original_owner!=full.owner_binding):
        raise AuthorityUnavailable("counter preparation changed its original independently observed Owner WRITE")
    with bind_d13_counter_prepare_resource_inputs_v1(packet):yield issued
