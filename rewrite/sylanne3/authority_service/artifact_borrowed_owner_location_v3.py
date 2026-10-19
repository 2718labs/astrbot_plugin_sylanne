"""Owner17 for an actual Borrowed Artifact original WRITE; no process grant."""
from dataclasses import dataclass,InitVar
from datetime import datetime
from threading import get_ident
from weakref import WeakKeyDictionary
import json,time
from .contract import AuthorityUnavailable
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from .v2_owner_contract import OwnerPrincipalV1
from ..graph_types import owner_grant_key,validate_owner_grant_v1
from ..runtime_contracts import AuthorityContext,FenceScope

_KIND='host_artifact_borrowed_header'
_CALLERS=WeakKeyDictionary()
_ENTRIES=WeakKeyDictionary()
_COMPLETED=WeakKeyDictionary()
_KEY=object()


def _actual_v3(reader):
    from ..runtime.artifact_borrowed_source_v3 import require_artifact_borrowed_owner_reader_v3
    from ..runtime.current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_require_borrowed_issuance_v3
    from ..runtime.foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    from .owner_location_read_v3 import _require_owner_operation_v3
    from ..runtime.foreground_command_source_v3 import is_foreground_command_source_reader_v3,require_foreground_command_owner_reader_v3
    state=(require_foreground_command_owner_reader_v3(reader)if is_foreground_command_source_reader_v3(reader)
        else require_artifact_borrowed_owner_reader_v3(reader))
    if type(reader)is not BorrowedMethodLearningReadV3 or type(reader.issued)is not _IssuedForegroundActivityV1:
        raise AuthorityUnavailable('Artifact Owner17 requires actual private Borrowed Foreground input')
    graph=reader.graph;scope=reader.issued.scope
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    bundle=None if assembly is None else assembly.admin_bundle
    port=graph._GraphCoordinator__content_fence_v2
    evidence=_require_borrowed_issuance_v3(reader.issued,graph)
    if(type(bundle)is not AdminInstallationBundle or type(port)is not V2FencePort
            or type(scope)is not FenceScope or scope.operation!='write'
            or evidence!=reader.evidence or evidence.request!=reader.selector
            or evidence.current_self.permit!=scope.permit or scope.namespace!=reader.namespace
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or bundle.installation_policy.namespace!=reader.namespace
            or scope.authority_namespace!=bundle.installation_policy.authority_namespace
            or scope.permit.holder!=bundle.installation_policy.administrator_holder
            or port.installation_grant.installation_id!=bundle.installation_policy.installation_id
            or reader.operation.closed or reader.operation.deadline_utc is None
            or reader.work.operation is not reader.operation or reader.work.state is not reader):
        raise AuthorityUnavailable('Artifact Owner17 crossed its actual installation/original WRITE')
    control=_require_owner_operation_v3(reader.operation,db=reader.db,namespace=reader.namespace)
    return state,graph,port,bundle,scope,evidence,control


def _identity_v3(reader):
    state,graph,port,bundle,scope,evidence,control=_actual_v3(reader)
    return(state,graph,port,bundle,scope,evidence,control,reader.work,reader.operation,
        reader.selection_digest,reader.graph_stamp,reader.operation.deadline_utc)


def observe_artifact_borrowed_owner_authority_v3(reader):
    from ..runtime.first_ingress_v2 import trusted_upper
    state,graph,port,bundle,scope,evidence,control=_actual_v3(reader)
    if reader.db.in_transaction:raise AuthorityUnavailable('Artifact Owner permission must precede SQL')
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable('Artifact original Foreground WRITE permit changed')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    until=datetime.fromisoformat(evidence.valid_until_utc.replace('Z','+00:00')).timestamp()
    if now>=min(reader.operation.deadline_utc,reader.selector.requested_deadline_utc,until):
        raise AuthorityUnavailable('Artifact Owner17 exceeded its original Foreground deadline')
    if time.monotonic()>=state.initial_monotonic_deadline:
        raise AuthorityUnavailable('Artifact Owner17 exceeded its original monotonic deadline')
    current,permit=port.get_current_background_owner_authority_for_fence_v1(
        namespace=scope.namespace,authority_namespace=scope.authority_namespace,permit=scope.permit)
    if(type(current)is not D12CurrentOwnerAuthorityV1 or permit!=scope.permit
            or current.guard.namespace!=scope.namespace or current.guard.authority_id!=scope.pinned_anchor.authority_id
            or current.guard.minimum_revocation_revision!=0 or current.guard.pending_revoke_operation_id is not None
            or port.validate_fence(scope)!=scope.permit):
        raise AuthorityUnavailable('Artifact original WRITE has no actual current paired Owner authority')
    return current


def require_artifact_borrowed_owner_caller_v3(proof,graph_stamp=None):
    saved=_CALLERS.get(proof)
    if saved is None:raise AuthorityUnavailable('Artifact Owner caller has no actual private registration')
    reader,identity=saved
    state,graph,port,bundle,scope,evidence,control=_actual_v3(reader)
    if(identity!=_identity_v3(reader)or proof.kind!=_KIND or proof.request is not reader
            or proof.graph is not graph or proof.service is not reader.runtime or proof.port is not port
            or proof.bundle is not bundle or proof.scope is not scope or proof.authority is not None
            or proof.principal is not None or proof.control is not control
            or proof.retained_operation is not reader.operation or proof.selection_digest!=reader.selection_digest
            or proof.namespace!=reader.namespace or proof.original_permit!=scope.permit
            or proof.subject!=scope.permit.subject or proof.permission_anchor!=scope.pinned_anchor
            or proof.graph_comparison_anchor!=scope.pinned_anchor or proof.deadline_utc!=reader.operation.deadline_utc
            or proof.installation_id!=bundle.installation_policy.installation_id
            or proof.holder!=bundle.installation_policy.administrator_holder
            or graph_stamp is not None and graph_stamp!=reader.graph_stamp):
        raise AuthorityUnavailable('Artifact Owner17 caller changed its exact original Work/Scope/selection')
    return reader


def require_artifact_borrowed_owner_permission_v3(proof):
    reader=require_artifact_borrowed_owner_caller_v3(proof)
    if observe_artifact_borrowed_owner_authority_v3(reader)!=proof.current_owner_authority:
        raise AuthorityUnavailable('Artifact original current Owner authority changed')
    entry=_COMPLETED.get(proof)
    if entry is not None:
        _,_,_,authority,principal,_=entry
        pair=proof.port.current_owner_principal_binding(namespace=proof.namespace,
            authority_namespace=proof.scope.authority_namespace,principal=principal)
        if(pair is None or pair.principal!=principal or pair.actor_id!=authority.actor
                or pair.installation_id!=proof.installation_id):
            raise AuthorityUnavailable('Artifact actual Owner principal pairing changed')
    return proof


def _binding_v3(proof,facts,authority,principal):
    from .owner_location_read_v3 import require_owner_location_caller_proof_v3
    from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
    reader=require_artifact_borrowed_owner_caller_v3(proof)
    require_owner_location_caller_proof_v3(proof,phase='before',graph_stamp=reader.graph_stamp)
    facts.require_for_v3(proof)
    metadata,current,scope=facts.metadata,proof.current_owner_authority,proof.scope
    if(metadata.graph_revision!=scope.graph_revision or facts.graph_epoch!=scope.graph_epoch
            or metadata.requirements.namespace!=scope.namespace
            or metadata.requirements.authority_namespace!=scope.authority_namespace
            or not reader.graph._anchor_matches(metadata.requirements,scope.pinned_anchor)):
        raise AuthorityUnavailable('Artifact Owner EOF changed actual selected Graph location')
    value=reader.graph._owner_graph_binding_from_current_metadata_v3(authority,principal,
        metadata=metadata,graph_epoch=facts.graph_epoch,atom=facts.atom,proof_row=facts.proof_row,
        epochs=facts.epochs,target_admission=current.target_admission,
        storage_admission=current.storage_admission,current_guard=current.guard)
    guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,
        value.grant_revision,value.grant_digest.removeprefix('sha256:'),value.authorization_head.removeprefix('sha256:'))
    expected=reader.evidence.owner_guard
    if((guard.grant_ref,guard.grant_revision,guard.grant_digest,guard.owner_head_digest)!=(
            expected.grant_ref,expected.grant_revision,expected.grant_digest.removeprefix('sha256:'),expected.owner_head_digest.removeprefix('sha256:'))
            or(value.access_epoch,value.delete_epoch)!=reader.expected_rights
            or current.guard.authorization_head!=value.authorization_head
            or current.guard.authorization_revision!=value.authorization_revision
            or current.guard.minimum_revocation_epoch!=value.revocation_epoch):
        raise AuthorityUnavailable('Artifact Owner17 EOF differs from actual Foreground/Core current facts')
    return value


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _ArtifactBorrowedOwnerEntryV3:
    issuer:InitVar[object]
    def __post_init__(self,issuer):
        if issuer is not _KEY:raise AuthorityUnavailable('Actual Artifact Owner EOF producer required')
    def require_for_v3(self,reader):
        proof,work,facts,authority,principal,owner=_ENTRIES[self]
        if proof.request is not reader:raise AuthorityUnavailable('Artifact Owner entry crossed originating Source reader')
        actual=_binding_v3(proof,facts,authority,principal)
        if actual!=owner:raise AuthorityUnavailable('Artifact actual Owner binding changed after complete EOF')
        return actual
    def require_permission_v3(self,reader):
        from .owner_location_read_v3 import _require_owner_permission_outside_graph_v3
        proof=_ENTRIES[self][0]
        if proof.request is not reader:raise AuthorityUnavailable('Artifact Owner permission crossed actual Source Work')
        _require_owner_permission_outside_graph_v3(proof)
        with reader.store._lock:return self.require_for_v3(reader)
    @property
    def owner_acl_authority(self):return _ENTRIES[self][3]
    @property
    def owner_principal(self):return _ENTRIES[self][4]
    @property
    def current_owner_guard(self):return _ENTRIES[self][0].current_owner_authority.guard
    def release_v3(self):
        state=_ENTRIES.pop(self,None)
        if state is not None:
            proof,work,*_=state
            try:work.close_v3()
            finally:_COMPLETED.pop(proof,None);_CALLERS.pop(proof,None);proof.release_v3()


def prepare_current_host_artifact_borrowed_owner_read_entry_v3(reader):
    from .owner_location_read_v3 import (OwnerLocationCallerProofV3,_OWNER_CALLER_ISSUER_V3,
        prepare_owner_location_read_work_v3,owner_location_read_quantum_v3,
        _require_owner_permission_outside_graph_v3)
    state,graph,port,bundle,scope,evidence,control=_actual_v3(reader)
    current=observe_artifact_borrowed_owner_authority_v3(reader);policy=bundle.installation_policy
    proof=OwnerLocationCallerProofV3(_OWNER_CALLER_ISSUER_V3,kind=_KIND,graph=graph,
        service=reader.runtime,owner_service=None,controller=None,port=port,bundle=bundle,
        scope=scope,authority=None,principal=None,current_owner_authority=current,current_owner_head=None,
        retained_operation=reader.operation,control=control,selection_digest=reader.selection_digest,
        namespace=reader.namespace,installation_id=policy.installation_id,holder=policy.administrator_holder,
        permission_anchor=scope.pinned_anchor,graph_comparison_anchor=scope.pinned_anchor,
        credential=None,subject=scope.permit.subject,original_permit=scope.permit,request=reader,
        deadline_utc=reader.operation.deadline_utc,thread=get_ident())
    _CALLERS[proof]=(reader,_identity_v3(reader));work=None;entry=None
    try:
        work=prepare_owner_location_read_work_v3(proof)
        while not work.complete:
            with owner_location_read_quantum_v3(proof)as meter:progress=work.advance(meter=meter)
            if type(progress)is dict and progress.get('phase')=='owner_location_quantum_commit':
                work.complete_reserved_quantum_v3(proof)
        facts=work.result.require_for_v3(proof)
        grant=json.loads(facts.atom[1]);validate_owner_grant_v1(grant)
        principal=OwnerPrincipalV1(**grant['principal'])
        pair=port.current_owner_principal_binding(namespace=scope.namespace,
            authority_namespace=scope.authority_namespace,principal=principal)
        if pair is None or pair.principal!=principal or pair.installation_id!=policy.installation_id:
            raise AuthorityUnavailable('Artifact Owner17 actual paired principal is absent')
        authority=AuthorityContext(pair.actor_id,'d12',owner_grant_key(*scope.namespace.as_tuple).token,
            scope.namespace,('d11',),reader.purpose,reader.audiences,grant['issuer_ref'],scope.generation)
        owner=_binding_v3(proof,facts,authority,principal)
        entry=_ArtifactBorrowedOwnerEntryV3(_KEY)
        _ENTRIES[entry]=(proof,work,facts,authority,principal,owner)
        _COMPLETED[proof]=_ENTRIES[entry]
        _require_owner_permission_outside_graph_v3(proof)
        return entry
    except BaseException as exc:
        if entry is not None:_ENTRIES.pop(entry,None)
        if work is not None:work.cancel_v3(exc)
        _COMPLETED.pop(proof,None);_CALLERS.pop(proof,None);proof.release_v3();raise
