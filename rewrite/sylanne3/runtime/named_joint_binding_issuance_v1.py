"""Private fresh-WRITE issuer for exact prospective named Joint registration."""
from contextlib import contextmanager
from dataclasses import replace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_named_joint_binding_v1 import NamedJointBindingCurrentV1
from ..runtime_contracts import canonical_digest

_KEY=object()
_ISSUED=WeakKeyDictionary()


def require_named_joint_same_facts_v1(before,after):
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteCurrentV1
    if type(before)is NamedJointSourceNoteCurrentV1 and type(after)is NamedJointSourceNoteCurrentV1:
        original=after.original_evidence if before.original_evidence is not None else None
        normalized=replace(after,permit=before.permit,current_self=replace(after.current_self,permit=before.current_self.permit,
            request_operation_id=before.current_self.request_operation_id),original_evidence=original,
            observed_at_utc=before.observed_at_utc,valid_until_utc=before.valid_until_utc)
        if normalized!=before:raise AuthorityUnavailable('Named SourceNote changed actual current Window/Root/Source/future facts')
        return after
    if type(before)is not NamedJointBindingCurrentV1 or type(after)is not NamedJointBindingCurrentV1:
        raise AuthorityUnavailable('Named Joint requires two actual typed independent current observations')
    current=replace(after.current_self,permit=before.current_self.permit,
        request_operation_id=before.current_self.request_operation_id)
    normalized=replace(after,permit=before.permit,current_self=current,
        observed_at_utc=before.observed_at_utc,valid_until_utc=before.valid_until_utc)
    if normalized!=before:
        raise AuthorityUnavailable('Named Joint fresh Scope changed original Window/Plan/prior qualification/Root/Source/index facts')
    return after


class _IssuedNamedJointBindingV1:
    def __init__(self,key,reader,scope,port,evidence):
        if key is not _KEY:raise TypeError('Named Joint WRITE has no public issuer')
        self.reader,self.graph,self.scope,self.port,self.evidence=reader,reader.graph,scope,port,evidence
        self.selector,self.command=reader.selector,reader.request
        self.operation,self.selection_digest=reader.operation,reader.selection_digest
        _ISSUED[self]=(reader,reader.work,reader.operation,scope,port,evidence,
            reader.selector,reader.request,reader.operation.deadline_utc,canonical_digest(evidence))


def require_named_joint_issuance_v1(issued,graph,scope):
    from .named_joint_source_work_v3 import require_named_joint_host_reader_v3
    if type(issued)is not _IssuedNamedJointBindingV1:
        raise AuthorityUnavailable('Named Joint WRITE requires its exact private installed issuer')
    r=require_named_joint_host_reader_v3(issued.reader)
    expected=(r,r.work,r.operation,scope,issued.port,issued.evidence,r.selector,r.request,
        r.operation.deadline_utc,canonical_digest(issued.evidence))
    if(_ISSUED.get(issued)!=expected or issued.graph is not graph or r.graph is not graph
            or issued.scope is not scope or r.write_scope is not scope or r.issued is not issued
            or not r.read_finished or r.phase!='write' or scope.operation!='write'
            or scope.operation_id!=named_joint_scope_operation_id_v1(r.selector) or scope.permit!=issued.evidence.permit
            or issued.evidence.request!=r.selector):
        raise AuthorityUnavailable('Named Joint WRITE left its original Work/selector/command/permit/Source lifetime')
    issued.port.require_issued_write_v1(scope=scope,request=r.selector,evidence=issued.evidence)
    return issued.evidence


def require_named_joint_write_owner_identity_v3(reader,scope,issued):
    require_named_joint_issuance_v1(issued,reader.graph,scope)
    if reader.inputs is None or reader.inputs.metadata_only or not reader.inputs.complete:
        raise AuthorityUnavailable('Named Joint fresh Owner WRITE cannot precede actual independent Host Source completion')
    return reader.inputs


@contextmanager
def named_joint_binding_for_fence_v1(reader,scope):
    from ..host.current_named_joint_binding_port_v1 import installed_named_joint_binding_port_v1
    port=installed_named_joint_binding_port_v1(reader.context)
    evidence,observed=port.current_for_fence_v1(scope=scope,request=reader.selector)
    if observed!=scope.permit:raise AuthorityUnavailable('Named Joint fresh current observation changed actual permit')
    require_named_joint_same_facts_v1(reader.read_evidence,evidence)
    require_named_joint_same_facts_v1(reader.inputs.observed,evidence)
    issued=_IssuedNamedJointBindingV1(_KEY,reader,scope,port,evidence)
    reader.write_scope,reader.issued=scope,issued
    from contextlib import ExitStack
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,ForegroundActivityRequestV1
    try:
        with ExitStack()as lifetime:
            issued.original_issuance=None
            if type(reader.selector)is NamedJointSourceNoteSelectorV1:
                original=reader.selector.original_selector
                if type(original)is ForegroundActivityRequestV1:
                    from .foreground_activity_issuance_v1 import foreground_activity_for_fence_v1
                    factory=foreground_activity_for_fence_v1
                else:
                    from .owner_source_note_task_issuance_v1 import owner_source_note_task_for_fence_v1
                    factory=owner_source_note_task_for_fence_v1
                issued.original_issuance=lifetime.enter_context(factory(reader.graph,scope=scope,request=original))
                if issued.original_issuance.evidence!=evidence.original_evidence:
                    raise AuthorityUnavailable('Named SourceNote changed its exact original WRITE issuance')
            yield issued
    finally:
        reader.issued=None;reader.write_scope=None
        _ISSUED.pop(issued,None);port.release_write_v1(scope)


def reobserve_named_joint_binding_v1(issued):
    evidence=require_named_joint_issuance_v1(issued,issued.graph,issued.scope)
    current,permit=issued.port.current_for_fence_v1(scope=issued.scope,request=issued.selector)
    if permit!=issued.scope.permit:raise AuthorityUnavailable('Named Joint reobservation changed the original WRITE permit')
    require_named_joint_same_facts_v1(evidence,current)
    return evidence


def named_joint_scope_operation_id_v1(selector):
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,source_note_scope_operation_id_v1
    return source_note_scope_operation_id_v1(selector)if type(selector)is NamedJointSourceNoteSelectorV1 else selector.operation_id


def named_joint_finish_digest_v1(selector,permit):
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,ForegroundActivityRequestV1
    if type(selector)is NamedJointSourceNoteSelectorV1:
        original=selector.original_selector
        return 'sha256:'+canonical_digest({'schema':'w01.foreground-domain-write.v1'if type(original)is ForegroundActivityRequestV1 else 'w01.owner-task-domain-write.v1',
            'operation_id':original.operation_id,'request_digest':canonical_digest(original),'permit_token':permit.token})
    return 'sha256:'+canonical_digest({'schema':'w01.named-joint-binding.v1',
        'selector':selector,'operation_id':selector.operation_id,'permit_token':permit.token})
