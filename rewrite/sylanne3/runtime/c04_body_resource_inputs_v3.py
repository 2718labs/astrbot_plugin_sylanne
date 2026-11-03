"""Private current C04 Body resource inputs; this is not a business Source grant."""
from contextlib import contextmanager
from contextvars import ContextVar
from secrets import token_hex
from threading import get_ident
from weakref import WeakKeyDictionary
import json,time

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d02 import BodyDomain,BodyProfile,BodyState,_reservation
from ..graph_types import AtomKey,GraphAtom,GraphVersion,Owner
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import (runtime_storage_v3,RuntimeGraphRowsReadV3,
    bind_runtime_storage_operation_v3,runtime_storage_quantum_v3,
    begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,_operation)
from ..graph_worker import GraphStorageWorkV3,GraphStorageStepV3,create_graph_storage_work_v3
from .dispatch_current_inventory_v3 import _heap
from .current_character_labor_adoption_v1 import _payload_heap_v1

KIND="current_c04_body_resource_inputs_v3"
_KEY=object()
_READERS=WeakKeyDictionary()
_PACKETS=WeakKeyDictionary()
_CAPSULES=WeakKeyDictionary()
_BOUND=ContextVar("c04_body_resource_inputs_v3",default=None)
RESOURCE_TYPES=frozenset(("d02.body_profile.v1","d02.body_state.v1","d02.reservation.v1"))


class C04ResourceMetadataReadV3:
    """Fixed heads and complete dependency metadata; never a resource Body reader."""
    def __init__(self,owner,policy):
        self.owner,self.policy=owner,policy
        self.heads={};self.versions={};self.roots=set();self.edges={}
        self.profile_key=BodyDomain.profile_write(policy.profile).key
        self.state_key=BodyDomain.state_write(owner.namespace,policy.initial_state).key
        self.pending=[self.profile_key.token,self.state_key.token]
        self.current=None;self.after="";self.cursor="";self.members=[];self.complete=False

    def _runtime_retained_heap_bytes_v3(self):
        return 8192+_heap((self.heads,self.versions,self.roots,self.edges,self.pending,self.members))

    def advance_v3(self,meter):
        _require_c04_resource_metadata_owner_v3(self.owner,meter)
        if self.complete:return True
        if self.current is not None:
            row=meter.read_fixed_row(self.owner.db,"graph_dependencies",("dependency_token","dependency_revision"),
                "dependent_token=? AND dependency_token>? ORDER BY dependency_token",(self.current,self.after))
            if row is not None:
                ref,revision=row;key=AtomKey.from_token(ref)
                if NamespaceId.from_key(key)!=self.owner.namespace:
                    raise AuthorityUnavailable("C04 resource dependency crossed its actual namespace")
                current=meter.read_fixed_row(self.owner.db,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(ref,*self.owner.namespace.as_tuple))
                if current is None or current[0]!=revision:
                    raise AuthorityUnavailable("C04 resource dependency no longer has its exact current revision")
                prior=self.versions.get(key)
                if prior is not None and prior.revision!=revision:
                    raise AuthorityUnavailable("C04 resource metadata dependencies disagree on a version")
                self.owner.operation.retain(2048+len(ref)*4)
                self.versions[key]=GraphVersion(key,revision)
                self.edges[self.current].add(ref);self.after=ref
                if key.type_name=="memory.source":self.roots.add(ref);self.heads[ref]=current
                elif ref not in self.heads:self.pending.append(ref)
                return False
            self.current=None;self.after="";return False
        if self.pending:
            ref=self.pending.pop()
            if ref in self.heads:return False
            key=AtomKey.from_token(ref)
            row=meter.read_fixed_row(self.owner.db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(ref,*self.owner.namespace.as_tuple))
            version=GraphVersion(key,0 if row is None else row[0])
            prior=self.versions.get(key)
            if prior is not None and prior!=version:
                raise AuthorityUnavailable("C04 resource dependency head changed during discovery")
            self.owner.operation.retain(2048+len(ref)*4)
            self.heads[ref]=row;self.versions[key]=version;self.edges[ref]=set()
            if row is not None:self.current=ref
            return False
        row=meter.read_fixed_row(self.owner.db,"graph_atoms",("token","revision","valid","value_cell_id"),
            "bot=? AND persona=? AND owner_kind=? AND type_name=? AND token>? ORDER BY token",
            (*self.owner.namespace.as_tuple,"activity","d02.reservation.v1",self.cursor))
        if row is not None:
            if len(self.members)>=1024:
                raise AuthorityUnavailable("C04 resource metadata reservation census exceeds its original 1024 bound")
            self.cursor=row[0];self.members.append(row[0]);self.pending.append(row[0])
            return False
        active=set();done=set()
        def visit(ref):
            if ref in active:raise AuthorityUnavailable("C04 resource metadata dependency cycle")
            if ref in done:return
            active.add(ref)
            for dependency in self.edges.get(ref,()):visit(dependency)
            active.remove(ref);done.add(ref)
        for ref in self.edges:visit(ref)
        self.complete=True;return True

    def require_v3(self,meter=None):
        _require_c04_resource_metadata_owner_v3(self.owner,meter)
        if not self.complete:raise AuthorityUnavailable("C04 complete resource HEAD/dependency/census EOF required")
        return self


def _require_c04_resource_metadata_owner_v3(owner,meter=None):
    from .d13_counter_prepare_resource_inputs_v1 import (
        D13CounterPrepareResourceReadV1,require_actual_d13_counter_resource_reader_v1)
    if type(owner)is D13CounterPrepareResourceReadV1:
        return require_actual_d13_counter_resource_reader_v1(owner,meter=meter)
    if type(owner)is CurrentC04BodyResourceReadV3:
        return require_actual_c04_body_resource_reader_v3(owner,meter=meter)
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    from .foreground_command_source_v3 import _state_v3
    if type(owner)is not BorrowedMethodLearningReadV3 or owner not in _READERS or owner.operation_kind!="prepare_ingress_c04_v1":
        raise AuthorityUnavailable("actual C04 resource metadata issuer required")
    state=_state_v3(owner)
    if state.owner_entry is None or state.phase not in {"preparation","metadata","rights","qualified"}:
        raise AuthorityUnavailable("Self C04 resource metadata requires its original Owner-qualified Work")
    owner.work._require_invocation(owner.graph);owner.require_current(meter=meter)
    state.owner_entry.require_for_v3(owner)
    return owner


_SELF_METADATA=WeakKeyDictionary()


def advance_self_c04_body_resource_metadata_v3(reader,meter):
    _require_c04_resource_metadata_owner_v3(reader,meter)
    task=_SELF_METADATA.get(reader)
    if task is None:
        from .foreground_command_source_v3 import _bundle_v3
        bundle=_bundle_v3(reader)
        policy=reader.graph._GraphCoordinator__body_quote_authority.policy(reader.db,reader.namespace,
            bundle.d06_recall.body_policy_id,bundle.d06_recall.body_policy_version)
        task=C04ResourceMetadataReadV3(reader,policy)
        _SELF_METADATA[reader]=task;reader.operation.register_retained_state_v3(task)
        return False
    return task.advance_v3(meter)


def require_self_c04_body_resource_metadata_v3(reader,meter=None):
    task=_SELF_METADATA.get(reader)
    if type(task)is not C04ResourceMetadataReadV3 or task.owner is not reader:
        raise AuthorityUnavailable("Self C04 has no actual complete resource metadata census")
    return task.require_v3(meter)


class C04ResourceRowsReadV3:
    """One actual Graph row/cell quantum, after the issuer has admitted its keys."""
    def __init__(self,owner,*,token=None,history=False,after_revision=0,before_revision=None,reservations=False):
        require_c04_resource_row_owner_v3(owner)
        owner.require_resource_reader_v3()
        if reservations:
            if history or token is not None or not owner.allow_reservation_census:
                raise AuthorityUnavailable("this resource issuer cannot open a Body family")
            where="bot=? AND persona=? AND owner_kind=? AND type_name=?"
            args=(*owner.namespace.as_tuple,"activity","d02.reservation.v1")
        else:
            if token not in owner.resource_tokens:
                raise AuthorityUnavailable("resource row is outside the actual admitted token set")
            if history:
                where="token=? AND event_bot=? AND event_persona=? AND revision>=? AND revision<=?"
                args=(token,*owner.namespace.as_tuple,after_revision,before_revision)
            else:
                where="token=? AND bot=? AND persona=?"
                args=(token,*owner.namespace.as_tuple)
        self.owner=owner
        self.reader=RuntimeGraphRowsReadV3(owner.db,("token","revision","value","valid"),
            where=where,parameters=args,history=history,order_by=("token","revision")if history else("token",))
        self.complete=False
        self.index=0
        self.values=[]

    def advance_v3(self):
        require_c04_resource_row_owner_v3(self.owner)
        self.owner.require_resource_reader_v3()
        if self.complete:return True
        self.reader.advance()
        if self.index<len(self.reader.values):
            token,revision,wire,valid=self.reader.values[self.index]
            from .d13_counter_prepare_resource_inputs_v1 import D13CounterPrepareResourceReadV1
            if type(self.owner)in {CurrentC04BodyResourceReadV3,SelfC04BodyResourceReadV3,D13CounterPrepareResourceReadV1}:
                metadata=self.owner.resource_metadata
                head=metadata.heads.get(token)
                if head is None or head[:2]!=(revision,valid):
                    raise AuthorityUnavailable("resource Body escaped its complete pre-Source metadata census")
            self.owner.operation.retain(len(wire)*12+65536)
            raw=json.loads(wire)
            if canonical_serialize(raw)!=wire:
                raise AuthorityUnavailable("resource cell lacks its complete canonical JSON original")
            key=AtomKey.from_token(token)
            if key.type_name=="d02.body_profile.v1":value=BodyProfile(**{**raw,"namespace":NamespaceId(**raw["namespace"]),
                "applicable_axes":tuple(raw["applicable_axes"]),"work_kinds":tuple(raw["work_kinds"])})
            elif key.type_name=="d02.body_state.v1":value=BodyState(**raw)
            elif key.type_name=="d02.reservation.v1":value=_reservation(raw)
            else:raise AuthorityUnavailable("unregistered Body resource cell")
            self.values.append((key,revision,valid,value))
            self.index+=1
            if len(self.values)>1024 and self.owner.allow_reservation_census:
                raise AuthorityUnavailable("Body reservation census exceeds its original 1024 member limit")
        self.complete=self.reader.complete and self.index==len(self.reader.values)
        if self.complete and self.owner.allow_reservation_census:
            if tuple(key.token for key,_,_,_ in self.values)!=tuple(self.owner.resource_metadata.members):
                raise AuthorityUnavailable("resource Body census differs from its fixed complete metadata EOF")
        return self.complete


class C04BodyResourceInputsV3:
    def __init__(self,key,*,issuer,db,operation,namespace,envelope,policy_id,policy_version,profile,state,reservations,versions):
        if key is not _KEY:raise TypeError("actual C04 resource EOF issuer required")
        self.issuer,self.db,self.operation,self.namespace=issuer,db,operation,namespace
        self.envelope,self.policy_id,self.policy_version=envelope,policy_id,policy_version
        self.profile,self.state,self.reservations=profile,state,tuple(reservations)
        self.versions=tuple(versions)
        self.consumed=False
        self.output=None
        _PACKETS[self]=(issuer,db,operation,namespace,envelope,policy_id,policy_version,
            profile,state,self.reservations,self.versions)

    def require_v3(self,db,*,envelope,policy_id,policy_version):
        if (_PACKETS.get(self)!=(self.issuer,self.db,self.operation,self.namespace,self.envelope,
                self.policy_id,self.policy_version,self.profile,self.state,self.reservations,self.versions)
                or self.consumed or db is not self.db or not db.in_transaction
                or envelope is not self.envelope or (policy_id,policy_version)!=(self.policy_id,self.policy_version)
                or self.operation.closed or _operation(runtime_storage_v3(db))is not self.operation):
            raise AuthorityUnavailable("C04 resource packet is not this live original preparation")
        self.issuer.require_resource_inputs_current_v3(self)
        with runtime_storage_quantum_v3(db)as meter:
            for version in self.versions:
                row=meter.read_fixed_row(db,"graph_atoms",("revision",),"token=? AND bot=? AND persona=?",
                    (version.key.token,*self.namespace.as_tuple))
                if (0 if row is None else row[0])!=version.revision:
                    raise AuthorityUnavailable("C04 resource member changed before quote/reservation")
        return self

    def consume_v3(self,output):
        if self.consumed:raise AuthorityUnavailable("C04 resource packet was already consumed")
        self.consumed=True;self.output=output
        return output

    def release_v3(self):
        _PACKETS.pop(self,None)
        self.profile=self.state=self.output=None
        self.reservations=self.versions=()


class _SelfC04ResourceIssuerV3:
    def __init__(self,scope,proof):
        self.scope,self.proof=scope,proof

    def require_resource_inputs_current_v3(self,packet):
        from .c04_self_scope_v4 import require_self_c04_scope_v4
        actual=require_self_c04_scope_v4(self.scope,packet.db)
        self.proof.require_issued_current_v3(packet.db,actual.scope,actual.issued)
        if self.proof.owner.operation is not packet.operation or actual.frame.envelope is not packet.envelope:
            raise AuthorityUnavailable("Self C04 resources crossed their actual Source EOF/WRITE scope")


def issue_self_c04_body_resource_inputs_v3(scope,*,db,prepared_inputs):
    from .c04_self_scope_v4 import require_self_c04_scope_v4
    from .current_method_learning_read_v3 import PreparedBorrowedMethodDomainInputsV3,_BORROWED_INPUTS
    from .foreground_command_source_v3 import require_foreground_command_prepared_v3
    actual=require_self_c04_scope_v4(scope,db)
    if type(prepared_inputs)is not PreparedBorrowedMethodDomainInputsV3 or prepared_inputs not in _BORROWED_INPUTS:
        raise AuthorityUnavailable("Self C04 resources need the actual completed Borrowed Source inputs")
    prepared_inputs.require_issued_current_v3(db,actual.scope,actual.issued)
    source=require_foreground_command_prepared_v3(prepared_inputs)
    r=prepared_inputs.owner
    if (source is None or r.operation_kind!="prepare_ingress_c04_v1"
            or r.namespace!=actual.frame.envelope.authority.namespace
           ):
        raise AuthorityUnavailable("Self C04 Source plan lacks its independent complete resource census")
    policy=actual.graph._GraphCoordinator__body_quote_authority.policy(db,r.namespace,
        actual.bundle.d06_recall.body_policy_id,actual.bundle.d06_recall.body_policy_version)
    collector=require_self_c04_body_resource_eof_v3(r)
    if collector.policy!=policy:raise AuthorityUnavailable("Self C04 resource policy changed after its signed EOF")
    profile_key,profile_revision,profile_value=collector.profile
    state_key,state_revision,state_value=collector.state
    reservations=tuple(collector.reservations)
    issuer=_SelfC04ResourceIssuerV3(actual,prepared_inputs)
    packet=C04BodyResourceInputsV3(_KEY,issuer=issuer,db=db,operation=r.operation,namespace=r.namespace,
        envelope=actual.frame.envelope,policy_id=policy.policy_id,policy_version=policy.version,
        profile=collector.profile,state=collector.state,reservations=reservations,
        versions=(GraphVersion(profile_key,profile_revision),GraphVersion(state_key,state_revision),
            *(GraphVersion(k,v)for k,v,_ in reservations),*collector.resource_metadata.versions.values()))
    r.operation.retain(_payload_heap_v1((packet.profile,packet.state,packet.reservations,packet.versions))+65536)
    return packet


class CurrentC04BodyResourceReadV3:
    def __init__(self,graph,authority,lease,envelope,policy_id,policy_version,operation,fence,bundle,now):
        self.graph,self.authority,self.lease,self.envelope=graph,authority,lease,envelope
        self.policy_id,self.policy_version=policy_id,policy_version
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.namespace,self.operation,self.fence=authority.namespace,operation,fence
        self.bundle,self.graph_stamp,self.selection_digest=bundle,(fence.metadata,fence.epoch),operation.selection_digest
        self.read_scope=fence.scope
        self.owner_binding,self.session=graph._GraphCoordinator__owner_leases[lease],graph._GraphCoordinator__owner_session_proofs[lease]
        self.thread,self.work=get_ident(),None
        self.read_finished=False;self.write_scope=None
        self.owner_entry=self.current_owner_guard=None
        self.owner_task=None
        self.phase="root_header";self.root_header=self.root_column=None
        self.monotonic_deadline=min(envelope.monotonic_deadline,time.monotonic()+operation.deadline_utc-now)
        self.pending=list(envelope.source_qualification.source_refs)
        self.inspections={};self.controls={};self.records={};self.source_versions={}
        self.current_ref=self.current_task=self.current_rows=self.current_control=None
        self.resource_tokens=set()
        self.allow_reservation_census=False
        self.policy=self.profile=self.state=None
        self.resource_metadata=None
        self.reservations=[];self.result=None
        self.complete=False

    def identity_v3(self):
        return(self.graph,self.authority,self.lease,self.envelope,self.policy_id,self.policy_version,self.operation,
            self.fence,self.bundle,self.work,self.owner_binding,self.session,self.thread,self.selection_digest,self.graph_stamp)

    def require_current(self,*,meter=None):
        if (_READERS.get(self)!=self.identity_v3()or self.thread!=get_ident()or self.operation.closed
                or time.monotonic()>=self.monotonic_deadline
                or self.work.state is not self or self.work.operation is not self.operation
                or runtime_storage_v3(self.db)is not self.operation.handle
                or self.graph._GraphCoordinator__owner_leases.get(self.lease)is not self.owner_binding
                or self.graph._GraphCoordinator__owner_session_proofs.get(self.lease)is not self.session):
            raise AuthorityUnavailable("current C04 resource Work lost its actual Owner/selection/invocation")
        self.work._require_invocation(self.graph)
        if meter is not None:
            if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
                raise AuthorityUnavailable("current C04 resource Graph changed during EOF")
            self.operation.handle.require_current(meter)
            if self.root_header is not None:
                grant=self.bundle.installation_policy.root_grant
                if meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                        "lease_id=? ORDER BY version DESC",(grant.lease_id,))!=self.root_header:
                    raise AuthorityUnavailable("C04 current Root resource original changed")
        return self

    def require_v1(self,meter=None):return self.require_current(meter=meter)

    def require_resource_reader_v3(self):
        self.require_current()
        if self.phase not in {"profile","state","reservations"}:
            raise AuthorityUnavailable("current C04 Body read precedes actual Source ALL")

    def require_owner_reader_v3(self):
        return require_current_c04_body_resource_owner_reader_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return 65536+(0 if self.resource_metadata is None else self.resource_metadata._runtime_retained_heap_bytes_v3())+_payload_heap_v1((self.policy,self.envelope))+_heap((self.records,self.controls,self.source_versions,self.reservations,
            None if self.current_rows is None else(self.current_rows.values,self.current_rows.reader.values),
            self.profile,self.state,self.current_control,
            None if self.root_column is None else(self.root_column.body,self.root_column.fragment,self.root_column.value)))

    def _resources_v3(self):
        self.resource_metadata.require_v3()
        profile=BodyDomain.profile_write(self.policy.profile).key
        state=BodyDomain.state_write(self.namespace,self.policy.initial_state).key
        self.resource_tokens={profile.token,state.token}
        self.phase="profile";self.current_rows=C04ResourceRowsReadV3(self,token=profile.token)

    def advance_v3(self,meter):
        self.require_current(meter=meter)
        if self.phase in {"root_header","root_original"}:
            grant=self.bundle.installation_policy.root_grant
            head=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if head is None or head[:2]!=(grant.version,"active")or self.root_header is not None and head!=self.root_header:
                raise AuthorityUnavailable("C04 resource work lost its actual current Root resource grant")
            self.root_header=head
            if self.root_column is None:
                from .current_character_labor_adoption_v1 import _LocatorMetadataColumnV1
                self.root_column=_LocatorMetadataColumnV1(self,"runtime_budget_grants","grant_json",
                    ("lease_id","version"),(grant.lease_id,grant.version),
                    signature_kind="budget-grant.v1",signature=head[2])
                self.phase="root_original";return
            if not self.root_column.advance(meter):return
            from .issuers import _decode_grant
            if _decode_grant(self.root_column.body.decode("utf-8"))!=grant:
                raise AuthorityUnavailable("C04 actual Root original differs from its protected installation")
            self.policy=self.graph._GraphCoordinator__body_quote_authority.policy(self.db,self.namespace,self.policy_id,self.policy_version)
            self.resource_metadata=C04ResourceMetadataReadV3(self,self.policy)
            self.phase="resource_metadata";return
        if self.phase=="resource_metadata":
            if not self.resource_metadata.advance_v3(meter):return
            self.pending.extend(sorted(self.resource_metadata.roots))
            self.source_versions.update(self.resource_metadata.versions)
            self.phase="sources";return
        if self.phase=="sources":
            from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
            from ..memory_types import access_key,source_key
            from ..domains.d06 import source_correction_head_key
            from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
            if self.current_ref is None:
                if not self.pending:
                    self._check_source_closure_v3()
                    self._resources_v3();return
                ref=self.pending.pop()
                if ref in self.records:return
                if len(self.records)>=256:raise AuthorityUnavailable("C04 Source closure exceeds the existing ancestor bound")
                self.current_ref=ref
                self.current_task=InspectionMetadataReadV3(self,AtomKey.from_token(ref))
                self.inspections[ref]=self.current_task
            if not self.current_task.complete:
                self.current_task.advance(meter);return
            original=self.current_task.result.require_v3(self,meter)
            key=AtomKey.from_token(self.current_ref)
            access=access_key(*self.namespace.as_tuple,key.owner.subject)
            correction=source_correction_head_key(self.namespace,key.owner.subject)
            for control in(access,correction):
                if control.token not in self.controls:
                    self._read_control_v3(control,meter);return
            record=None
            for audience in self.authority.audience:
                record=_qualify_source_rights_values_v3(self.namespace,key.token,original,self.controls[access.token],
                    self.controls[correction.token],audience=audience,purpose=self.authority.purpose,metadata_only=True)
                if record is None:raise AuthorityUnavailable("C04 Source/Access/Correction current rights denied")
            self.records[key.token]=record
            for atom in(original,self.controls[access.token],self.controls[correction.token]):
                expected=self.source_versions.get(atom.key)
                if expected is not None and expected.revision!=atom.revision:
                    raise AuthorityUnavailable("C04 resource Source original disagrees with its exact metadata dependency")
                self.source_versions[atom.key]=GraphVersion(atom.key,atom.revision)
            self.pending.extend(source_key(*self.namespace.as_tuple,p).token for p in record.parent_source_ids)
            self.current_ref=self.current_task=None;return
        if not self.current_rows.advance_v3():return
        rows=self.current_rows.values
        if self.phase in {"profile","state"}:
            if len(rows)!=1 or rows[0][2]!=1:raise AuthorityUnavailable("actual current C04 Body original unavailable")
            key,revision,valid,value=rows[0]
            if self.phase=="profile":
                self.profile=(key,revision,value);self.phase="state"
                token=BodyDomain.state_write(self.namespace,self.policy.initial_state).key.token
                self.current_rows=C04ResourceRowsReadV3(self,token=token);return
            self.state=(key,revision,value);self.phase="reservations";self.allow_reservation_census=True
            self.current_rows=C04ResourceRowsReadV3(self,reservations=True);return
        for key,revision,valid,value in rows:
            if valid!=1:raise AuthorityUnavailable("C04 reservation census contains invalid original")
            self.reservations.append((key,revision,value))
        packet=C04BodyResourceInputsV3(_KEY,issuer=self,db=self.db,operation=self.operation,namespace=self.namespace,
            envelope=self.envelope,policy_id=self.policy_id,policy_version=self.policy_version,
            profile=self.profile,state=self.state,reservations=self.reservations,
            versions=(*self.source_versions.values(),GraphVersion(self.profile[0],self.profile[1]),
                GraphVersion(self.state[0],self.state[1]),*(GraphVersion(k,v)for k,v,_ in self.reservations)))
        self.complete=True;self.result=PreparedC04BodyResourceV3(_KEY,self,packet);self.phase="complete"

    def _read_control_v3(self,key,meter):
        # Access and Correction are independently validated metadata, not Source text.
        head=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
            "token=? AND bot=? AND persona=?",(key.token,*self.namespace.as_tuple))
        if head is None:
            self.controls[key.token]=GraphAtom(key,0,{},False);return
        from ..runtime_storage_v3 import RuntimeCellReadV3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if self.current_control is None:
            cell=RuntimeCellReadV3(self.operation.handle,head[2],erasure_owner_ref=key.token,meter=meter)
            self.current_control=(key,head,cell,
                C09CanonicalJSONStreamV2(ensure_ascii=cell.header[0]=="canonical-json.ascii.v1"),bytearray())
            return
        selected,original,cell,parser,data=self.current_control
        if selected!=key or original!=head:raise AuthorityUnavailable("C04 Source metadata control changed")
        if cell.ordinal<cell.header[4]:
            fragment=cell.read_fragment(meter=meter)
            self.operation.retain(len(fragment)*12+65536);parser.feed(fragment,lambda event:None);data.extend(fragment);return
        parsed=parser.finish();digest=cell.finish(meter=meter)
        if parsed.sha256!=digest:raise AuthorityUnavailable("C04 control lacks complete canonical EOF")
        meter.charge_encode(len(data))
        self.controls[key.token]=GraphAtom(key,head[0],json.loads(data),bool(head[1]))
        self.current_control=None

    def _check_source_closure_v3(self):
        from ..memory_types import source_key
        active=set();done=set()
        def visit(ref):
            if ref in active:raise AuthorityUnavailable("cyclic C04 Source closure")
            if ref in done:return
            active.add(ref)
            for parent in self.records[ref].parent_source_ids:visit(source_key(*self.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref)
        for ref in (*self.envelope.source_qualification.source_refs,*self.resource_metadata.roots):visit(ref)
        if (self.authority.purpose not in self.owner_binding.purposes
                or not set(self.authority.audience)<=set(self.owner_binding.audiences)):
            raise AuthorityUnavailable("C04 Source request is outside actual Owner grant intersection")

    def require_resource_inputs_current_v3(self,packet):
        if self.result is None or self.result.packet is not packet or not self.read_finished or self.write_scope is None:
            raise AuthorityUnavailable("C04 resources require their actual READ ACK and newly observed WRITE")
        record=_WRITES.get(self.result)
        if record is None or record[0]is not self or record[2]is not self.write_scope or record[3]!="observed":
            raise AuthorityUnavailable("C04 resource packet has no actual fresh Owner WRITE observation")
        with runtime_storage_quantum_v3(self.db)as meter:
            self.require_current(meter=meter)
            self.owner_entry.require_write_v3(self,self.write_scope,record[4],record[5],meter)
        for original in self.inspections.values():
            with runtime_storage_quantum_v3(self.db)as meter:original.result.require_v3(self,meter)

    def release_payload_v3(self):
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
        if _READERS.pop(self,None)is None:return
        release_inspection_metadata_owner_v3(self)
        if self.result is not None:
            _WRITES.pop(self.result,None);_CAPSULES.pop(self.result,None);self.result.packet.release_v3()
        if self.owner_task is not None:self.owner_task.release_v3();self.owner_task=None
        if self.owner_entry is not None:
            self.owner_entry.release_v3();self.owner_entry=None
        self.inspections.clear();self.controls.clear();self.records.clear();self.source_versions.clear()
        self.current_rows=self.current_control=self.current_task=self.result=self.root_column=self.resource_metadata=None
        self.reservations.clear()
        self.operation.unregister_retained_state_v3(self)


class PreparedC04BodyResourceV3:
    def __init__(self,key,reader,packet):
        if key is not _KEY or not reader.complete:raise TypeError("actual complete C04 resource Source EOF required")
        self.reader,self.packet=reader,packet
        _CAPSULES[self]=(reader,reader.work,packet)

    def require_invocation_v3(self,graph,*,authority,lease,envelope,body_policy_id,body_policy_version):
        r=self.reader;r.require_current()
        if (_CAPSULES.get(self)!=(r,r.work,self.packet)or r.graph is not graph
                or authority is not r.authority or lease is not r.lease or envelope is not r.envelope
                or (body_policy_id,body_policy_version)!=(r.policy_id,r.policy_version)):
            raise AuthorityUnavailable("C04 resource capsule crossed its original Owner command")
        return self

    def observe_write_v3(self,graph,authority,lease,scope,original_owner,session_proof,metadata,epoch):
        r=self.reader
        self.require_invocation_v3(graph,authority=authority,lease=lease,envelope=r.envelope,
            body_policy_id=r.policy_id,body_policy_version=r.policy_version)
        if (not r.read_finished or r.write_scope is not None or(scope.graph_revision,scope.graph_epoch)!=(metadata.graph_revision,epoch)
                or(metadata,epoch)!=r.graph_stamp or original_owner is not r.owner_binding or session_proof is not r.session):
            raise AuthorityUnavailable("C04 resource WRITE changed its Source/Owner/Graph comparison")
        if r.owner_entry is None or self in _WRITES:
            raise AuthorityUnavailable("C04 resource WRITE requires its actual completed independent Owner entry")
        r.write_scope=scope
        _WRITES[self]=(r,self.packet,scope,"pending",None,None)
        try:
            guard,owner=r.owner_entry.observe_write_v3(r,scope,original_owner,session_proof)
            if(owner.actor,owner.grant_revision,owner.grant_digest)!=(original_owner.actor,original_owner.grant_revision,original_owner.grant_digest):
                raise AuthorityUnavailable("C04 resource current Owner changed before WRITE")
        except BaseException:
            _WRITES[self]=(r,self.packet,scope,"failed",None,None)
            raise
        _WRITES[self]=(r,self.packet,scope,"observed",guard,owner)
        return guard,owner

    def release_payload_v3(self):self.reader.release_payload_v3()


def require_actual_c04_body_resource_reader_v3(reader,*,meter=None):
    if type(reader)is not CurrentC04BodyResourceReadV3:raise AuthorityUnavailable("actual named C04 resource reader required")
    return reader.require_current(meter=meter)


@contextmanager
def bind_prepared_c04_body_resource_v3(capsule):
    if type(capsule)is not PreparedC04BodyResourceV3 or capsule not in _CAPSULES:
        raise AuthorityUnavailable("actual C04 resource capsule required")
    token=_BOUND.set(capsule)
    try:
        with bind_runtime_storage_operation_v3(capsule.reader.operation,capsule.reader.db):yield capsule
    finally:_BOUND.reset(token)


def bound_c04_body_resource_v3():return _BOUND.get()


def begin_current_c04_body_resource_inputs_v3(graph,authority,lease,*,envelope,body_policy_id,body_policy_version):
    from ..graph_worker import require_graph_storage_work_admission_v3
    from ..host.authority_profile import current_owner_metadata_installation_v3
    require_graph_storage_work_admission_v3(graph)
    graph._authorize(lease,authority,frozenset(("d02","d04","d06","d07","d11")),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or session is None or "c04.internal_work.prepare"not in owner.capabilities or envelope.authority is not authority:
        raise AuthorityUnavailable("C04 resources need their actual signed Owner command")
    db=graph._GraphCoordinator__store._db
    if db.in_transaction or graph._GraphCoordinator__store._lock._is_owned():
        raise AuthorityUnavailable("C04 resource admission must precede Graph SQL")
    from .first_ingress_v2 import trusted_upper
    bundle=current_owner_metadata_installation_v3(graph)[0]
    if authority.namespace!=bundle.installation_policy.namespace:raise AuthorityUnavailable("C04 resource namespace differs from protected installation")
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline=min(envelope.deadline_utc,bundle.installation_policy.root_grant.valid_until_utc)
    if now>=deadline:raise AuthorityUnavailable("C04 original resource deadline expired")
    if not envelope.source_qualification.source_refs:raise AuthorityUnavailable("C04 resource Source roots are absent")
    opid="c04-body-resource:"+token_hex(16)
    operation=begin_runtime_storage_operation_v3(db,opid,deadline)
    fence=None;r=None
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            fence=graph._begin_read_fence_v3(authority,operation_id=opid,owner_session_proof=session)
            r=CurrentC04BodyResourceReadV3(graph,authority,lease,envelope,body_policy_id,body_policy_version,operation,fence,
                bundle,now)
        r.work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=opid,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
        _READERS[r]=r.identity_v3();operation.register_retained_state_v3(r)
        return r.work
    except BaseException as first:
        if r is not None:
            try:r.release_payload_v3()
            except BaseException as later:first.add_note("C04 resource factory payload cleanup failed: "+type(later).__name__)
        if fence is not None:
            try:graph._finish_read_fence_v3(fence)
            except BaseException as later:first.add_note("C04 resource READ cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note("C04 resource retention cleanup failed: "+type(later).__name__)
        raise


def advance_current_c04_body_resource_inputs_v3(graph,work):
    r=require_actual_c04_body_resource_reader_v3(work.state)
    if r.graph is not graph or r.work is not work:raise AuthorityUnavailable("C04 resource Work changed")
    graph._validate_read_fence_v3(r.fence)
    if r.owner_entry is None:
        from ..authority_service.owner_location_read_v3 import prepare_current_host_c04_body_resource_owner_entry_v3
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            if r.owner_task is None:r.owner_task=prepare_current_host_c04_body_resource_owner_entry_v3(r)
            if not r.owner_task.advance():return GraphStorageStepV3("progress")
            r.owner_entry=r.owner_task.take_result_v3();r.owner_task=None
    actual=r.owner_entry.require_permission_v3(r)
    if actual!=r.owner_binding:
        raise AuthorityUnavailable("C04 independent Owner EOF differs from its original actual lease")
    r.current_owner_guard=r.owner_entry.current_owner_guard
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        r.db.execute("BEGIN")
        try:
            with runtime_storage_quantum_v3(r.db)as meter:r.advance_v3(meter)
        finally:r.db.rollback()
    graph._validate_read_fence_v3(r.fence)
    if r.owner_entry.require_permission_v3(r)!=r.owner_binding:
        raise AuthorityUnavailable("C04 independent Owner changed across its metadata quantum")
    r.current_owner_guard=r.owner_entry.current_owner_guard
    return GraphStorageStepV3("complete",r.result)if r.complete else GraphStorageStepV3("progress")


def finish_current_c04_body_resource_inputs_v3(graph,work,error):
    r=require_actual_c04_body_resource_reader_v3(work.state)
    try:
        if not r.read_finished:
            graph._finish_read_fence_v3(r.fence);r.read_finished=True
        if error is None:work.result_lease=work.operation
    except BaseException as finish_error:
        first=error if error is not None else finish_error
        if first is not finish_error:first.add_note("C04 resource READ finish failed: "+type(finish_error).__name__)
        try:r.release_payload_v3()
        except BaseException as later:first.add_note("C04 resource payload cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(work.operation)
        except BaseException as later:first.add_note("C04 resource retention cleanup failed: "+type(later).__name__)
        raise first
    if error is not None:
        try:r.release_payload_v3()
        except BaseException as later:error.add_note("C04 resource payload cleanup failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(work.operation)
        except BaseException as later:error.add_note("C04 resource retention cleanup failed: "+type(later).__name__)

def require_c04_resource_row_owner_v3(owner):
    from .d13_counter_prepare_resource_inputs_v1 import (
        D13CounterPrepareResourceReadV1,require_actual_d13_counter_resource_reader_v1)
    if type(owner)is D13CounterPrepareResourceReadV1:
        return require_actual_d13_counter_resource_reader_v1(owner)
    if type(owner)is CurrentC04BodyResourceReadV3:
        return require_actual_c04_body_resource_reader_v3(owner)
    if type(owner)is SelfC04BodyResourceReadV3:return owner.require_current_v3()
    from .c04_body_accounting_inputs_v3 import CurrentC04BodyAccountingReadV3
    if type(owner)is CurrentC04BodyAccountingReadV3:return owner.require_current_v3()
    raise AuthorityUnavailable("Body resource cells require their actual named current/accounting issuer")


def require_c04_resource_reservation_after_cas_v3(db,packet,receipt):
    from ..graph_types import GraphReceipt
    if (type(packet)is not C04BodyResourceInputsV3 or packet not in _PACKETS
            or not packet.consumed or packet.db is not db or not db.in_transaction
            or packet.operation.closed or packet.output is None
            or type(receipt)is not GraphReceipt or receipt.status!="committed"):
        raise AuthorityUnavailable("actual consumed C04 resource packet and reservation CAS required")
    write=packet.output.body.reservation_write
    if GraphVersion(write.key,1)not in receipt.revisions:
        raise AuthorityUnavailable("C04 resource receipt omits its actual first reservation")
    with runtime_storage_quantum_v3(db)as meter:
        if meter.read_fixed_row(db,"graph_atoms",("revision","valid"),
                "token=? AND bot=? AND persona=?",(write.key.token,*packet.namespace.as_tuple))!=(1,1):
            raise AuthorityUnavailable("C04 actual reservation header differs from staged first CAS")
    return write


def require_consumed_c04_body_resource_inputs_v3(packet,*,db):
    if (type(packet)is not C04BodyResourceInputsV3 or packet not in _PACKETS
            or not packet.consumed or packet.output is None or packet.db is not db
            or not db.in_transaction or packet.operation.closed):
        raise AuthorityUnavailable("actual same-transaction consumed C04 resources required through final freeze")
    return packet

_SELF_READERS=WeakKeyDictionary()


class SelfC04BodyResourceReadV3:
    """Resource-only attachment to the real foreground Source Work."""
    def __init__(self,reader):
        source=_require_self_c04_source_identity_v3(reader)
        self.resource_metadata=require_self_c04_body_resource_metadata_v3(reader)
        if not self.resource_metadata.roots<=set(source.rights.sources):
            raise AuthorityUnavailable("Self C04 resource Source ancestors were not in its actual foreground Source ALL")
        for key,version in self.resource_metadata.versions.items():
            if key.type_name=="memory.source" and source.rights.versions.get(key)!=version.revision:
                raise AuthorityUnavailable("Self C04 resource Source ancestry changed its actual selected version")
        self.reader,self.source=reader,source
        self.graph,self.db,self.namespace,self.operation=reader.graph,reader.db,reader.namespace,reader.operation
        self.work,self.graph_stamp=reader.work,reader.graph_stamp
        self.policy=self.graph._GraphCoordinator__body_quote_authority.policy(self.db,self.namespace,
            source.reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.d06_recall.body_policy_id,
            source.reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.d06_recall.body_policy_version)
        self.resource_tokens={BodyDomain.profile_write(self.policy.profile).key.token,
            BodyDomain.state_write(self.namespace,self.policy.initial_state).key.token}
        self.allow_reservation_census=False
        self.phase="profile";self.profile=self.state=self.current=None
        self.reservations=[];self.complete=False
        self.operation.register_retained_state_v3(self)

    def identity_v3(self):
        r=self.reader
        return(r,r.work,r.operation,r.issued,r.issued.scope,r.selection_digest,r.graph_stamp,self.source)

    def require_current_v3(self,meter=None):
        from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
        r=self.reader
        if(type(r)is not BorrowedMethodLearningReadV3 or r not in _READERS
                or _SELF_READERS.get(r)is not self or r.operation_kind!="prepare_ingress_c04_v1"
                or r.work is not self.work or r.operation is not self.operation
                or r.graph_stamp!=self.graph_stamp or self.operation.closed
                or _require_self_c04_source_identity_v3(r)is not self.source):
            raise AuthorityUnavailable("Self C04 resource attachment lost its actual foreground Source Work")
        r.work._require_invocation(r.graph)
        r.require_current(meter=meter)
        return self

    def require_resource_reader_v3(self):
        self.require_current_v3()
        if self.phase not in {"profile","state","reservations"}:
            raise AuthorityUnavailable("Self C04 resource reader is outside its finite Source-qualified phase")

    def _runtime_retained_heap_bytes_v3(self):
        return 65536+_payload_heap_v1((self.policy,self.profile,self.state,self.reservations,
            None if self.current is None else(self.current.values,self.current.reader.values)))

    def advance_v3(self,meter):
        self.require_current_v3(meter)
        if self.complete:return True
        if self.current is None:
            if self.phase=="reservations":self.current=C04ResourceRowsReadV3(self,reservations=True)
            else:
                key=BodyDomain.profile_write(self.policy.profile).key if self.phase=="profile"else BodyDomain.state_write(self.namespace,self.policy.initial_state).key
                self.current=C04ResourceRowsReadV3(self,token=key.token)
            return False
        if not self.current.advance_v3():return False
        if self.phase in {"profile","state"}:
            if len(self.current.values)!=1 or self.current.values[0][2]!=1:
                raise AuthorityUnavailable("Self C04 current Body resource is unavailable")
            key,revision,valid,value=self.current.values[0]
            if self.phase=="profile":self.profile=(key,revision,value);self.phase="state"
            else:self.state=(key,revision,value);self.phase="reservations";self.allow_reservation_census=True
            self.current=None;return False
        for key,revision,valid,value in self.current.values:
            if valid!=1:raise AuthorityUnavailable("Self C04 complete reservation census contains invalid original")
            self.reservations.append((key,revision,value))
        self.current=None;self.complete=True;self.phase="complete"
        return True

    def release_v3(self):
        if _SELF_READERS.get(self.reader)is self:_SELF_READERS.pop(self.reader,None)
        self.operation.unregister_retained_state_v3(self)
        self.current=self.profile=self.state=None
        self.reservations.clear()


def advance_self_c04_body_resource_inputs_v3(reader,meter):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    if type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS or reader.operation_kind!="prepare_ingress_c04_v1":
        raise AuthorityUnavailable("actual Self C04 foreground Source Work required")
    _require_self_c04_source_identity_v3(reader)
    task=_SELF_READERS.get(reader)
    if task is None:
        task=SelfC04BodyResourceReadV3(reader);_SELF_READERS[reader]=task
        return False
    return task.advance_v3(meter)


def require_self_c04_body_resource_eof_v3(reader):
    task=_SELF_READERS.get(reader)
    if type(task)is not SelfC04BodyResourceReadV3 or not task.complete:
        raise AuthorityUnavailable("Self C04 resource Source/canonical/census EOF is incomplete")
    return task.require_current_v3()


def release_self_c04_body_resource_inputs_v3(reader):
    task=_SELF_READERS.get(reader)
    if task is not None:task.release_v3()
    metadata=_SELF_METADATA.pop(reader,None)
    if metadata is not None:
        reader.operation.unregister_retained_state_v3(metadata)
        metadata.heads.clear();metadata.versions.clear();metadata.roots.clear()
        metadata.edges.clear();metadata.pending.clear();metadata.members.clear()

def _require_self_c04_source_identity_v3(reader):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    from .foreground_command_source_v3 import _state_v3,ForegroundCommandSourceCapabilityV3,_CAPABILITIES
    if type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS or reader.operation_kind!="prepare_ingress_c04_v1":
        raise AuthorityUnavailable("actual foreground Self C04 Source identity required")
    source=_state_v3(reader);cap=source.capability
    if(type(cap)is not ForegroundCommandSourceCapabilityV3 or source.phase!="qualified"
            or _CAPABILITIES.get(cap)!=cap._identity_v3()):
        raise AuthorityUnavailable("Self C04 resource Body precedes its actual foreground Source ALL")
    source.owner_entry.require_for_v3(reader)
    return source

_WRITES=WeakKeyDictionary()


def require_current_c04_body_resource_owner_reader_v3(reader):
    r=require_actual_c04_body_resource_reader_v3(reader)
    groups=((r.authority.purpose,tuple(r.authority.audience),tuple(r.envelope.source_qualification.source_refs)),)
    return r.graph,r.graph._GraphCoordinator__content_fence_v2,r.bundle,r.fence.scope,groups


def c04_body_resource_owner_identity_v3(reader):
    r=require_actual_c04_body_resource_reader_v3(reader)
    return(r,r.work,r.operation,r.fence.scope,r.envelope,r.policy_id,r.policy_version,
        r.bundle,r.selection_digest,r.graph_stamp,r.owner_binding,r.session)


def require_current_c04_body_resource_owner_write_reader_v3(reader,scope):
    r=require_actual_c04_body_resource_reader_v3(reader)
    capsule=r.result
    record=_WRITES.get(capsule)
    if(_CAPSULES.get(capsule)!=(r,r.work,capsule.packet)
            or record is None or record[:3]!=(r,capsule.packet,scope)
            or record[3]not in {"pending","observed"} or r.write_scope is not scope
            or not r.read_finished or scope.namespace!=r.namespace or scope.operation!="write"
            or scope.permit.operation!="write"
            or scope.generation!=r.authority.activation_generation
            or(scope.graph_revision,scope.graph_epoch)!=(r.graph_stamp[0].graph_revision,r.graph_stamp[1])):
        raise AuthorityUnavailable("C04 Owner WRITE is not this actual retained Source capsule transition")
    return r
