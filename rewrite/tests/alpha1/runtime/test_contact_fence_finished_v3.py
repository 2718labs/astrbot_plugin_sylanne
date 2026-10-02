"""Actual protected Core/journal reads and paired-port transport seams.

The Core service tests use synthetic temporary stores with a test credential
authorizer. Port tests retain a controlled transport, not actual mTLS. The
installed Contact recovery node covers the real paired TLS endpoint.
"""
from dataclasses import replace
import pytest

from test_authority_v2_fence_service import installed
from test_v2_fence_port import port, NAMESPACE, ANCHOR
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import canonical_digest
from sylanne3.authority_service.contact_fence_finished_v3 import (
    ContactFenceFinishedOriginalV3,contact_finished_to_wire_v3,contact_finished_from_wire_v3,
)
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.runtime_contracts import FenceScope

OP='owner-domain-'+'a'*48
D='sha256:'+'d'*64


def actual_finished(service):
    anchor=service.current_anchor(credential='ok',subject='subject-a')
    permit=service.begin_fence(credential='ok',subject='subject-a',holder='holder-a',
        operation='write',operation_id=OP,expected_anchor=anchor)
    service.finish_fence(credential='ok',subject='subject-a',permit=permit,
        request_id='finish:'+OP,request_digest=D)
    return permit


def close(values):
    _,core,_,deletion,guard,execution,_=values
    core.close();deletion.close();guard.close();execution.close()


def test_real_core_finished_identity_reads_are_readonly_and_repeatable(tmp_path):
    values=installed(tmp_path);service,core,*_=values
    try:
        permit=actual_finished(service)
        before=core._db.total_changes
        original=service.read_contact_finished_original_v3(credential='ok',subject='subject-a',permit=permit)
        assert original.finish_request_id=='finish:'+OP and original.finish_request_digest==D
        assert original.permit_commitment==canonical_digest(permit)
        assert contact_finished_from_wire_v3(contact_finished_to_wire_v3(original))==original
        assert service.read_contact_finished_original_v3(credential='ok',subject='subject-a',permit=permit)==original
        assert core._db.total_changes==before
    finally:close(values)


@pytest.mark.parametrize('change',('subject','credential','permit','generation','namespace','missing'))
def test_actual_core_refuses_wrong_identity_or_current_generation(tmp_path,change):
    values=installed(tmp_path);service=values[0]
    try:
        permit=actual_finished(service);credential='ok';subject='subject-a'
        if change=='subject':subject='other'
        elif change=='credential':credential='bad'
        elif change=='permit':permit=replace(permit,token='b'*64)
        elif change=='generation':permit=replace(permit,generation=permit.generation+1,
            pinned_anchor=replace(permit.pinned_anchor,activation_generation=permit.generation+1))
        elif change=='namespace':permit=replace(permit,namespace='other',pinned_anchor=replace(permit.pinned_anchor,namespace='other'))
        else:permit=replace(permit,operation_id='owner-domain-'+'b'*48)
        with pytest.raises(AuthorityUnavailable):
            service.read_contact_finished_original_v3(credential=credential,subject=subject,permit=permit)
    finally:close(values)


def test_active_or_journal_drift_is_not_finished(tmp_path):
    values=installed(tmp_path);service,_,_,deletion,*_=values
    try:
        anchor=service.current_anchor(credential='ok',subject='subject-a')
        permit=service.begin_fence(credential='ok',subject='subject-a',holder='holder-a',operation='write',operation_id=OP,expected_anchor=anchor)
        with pytest.raises(AuthorityUnavailable):service.read_contact_finished_original_v3(credential='ok',subject='subject-a',permit=permit)
        service.finish_fence(credential='ok',subject='subject-a',permit=permit,request_id='finish:'+OP,request_digest=D)
        deletion.append_intent(namespace='ns-a',operation_id='delete-a',closure_roots=('item-a',),epoch=1,policy_ref='policy-a')
        with pytest.raises(AuthorityUnavailable):service.read_contact_finished_original_v3(credential='ok',subject='subject-a',permit=permit)
    finally:close(values)


def test_write_only_credential_cannot_read_finished_original(tmp_path):
    values=installed(tmp_path);service,core,*_=values
    try:
        permit=actual_finished(service)
        original_authorizer=core._authorize_callback
        requested=[]
        def authorize(credential,action,namespace,holder):
            requested.append(action)
            if credential=='write-only':return action=='write'
            return original_authorizer(credential,action,namespace,holder)
        core._authorize_callback=authorize
        before=core._db.total_changes
        with pytest.raises(AuthorityUnavailable,match='authentication denied'):
            service.read_contact_finished_original_v3(
                credential='write-only',subject='subject-a',permit=permit)
        assert requested==['current'] and core._db.total_changes==before
    finally:close(values)


def prepare_port(adapter,transport):
    permit=adapter.begin_fence(namespace=NAMESPACE,authority_namespace='ns-a',holder='holder-a',generation=1,
        operation='write',operation_id=OP,expected_anchor=ANCHOR)
    scope=FenceScope(NAMESPACE,'ns-a',1,'write',OP,permit,ANCHOR,NamespaceEpoch(*NAMESPACE.as_tuple,0),0)
    async def read_original(request,handshake,actual_permit):
        transport._on_owner_loop()
        assert transport.finished is not None
        p,request_id,digest=transport.finished
        return ContactFenceFinishedOriginalV3(p,canonical_digest(p),request_id,digest,p.pinned_anchor)
    transport.read_contact_finished_original_v3=read_original
    return scope


def test_lost_ack_is_confirmed_without_duplicate_finish_or_generic_begin_retry(port):
    adapter,transport=port;scope=prepare_port(adapter,transport)
    adapter._timeout=.05;transport.lose_finish_after_once=True
    with pytest.raises(RuntimeError):adapter.finish_fence(scope,request_id='finish:'+OP,request_digest=D)
    assert adapter._pending_finish is not None and len(transport.finish_requests)==1
    original=adapter.read_contact_finished_original_v3(scope,request_id='finish:'+OP,request_digest=D)
    assert original.permit==scope.permit and adapter._pending_finish is None
    adapter.read_contact_finished_original_v3(scope,request_id='finish:'+OP,request_digest=D)
    assert len(transport.finish_requests)==1
    next_permit=adapter.begin_fence(namespace=NAMESPACE,authority_namespace='ns-a',holder='holder-a',generation=1,
        operation='read',operation_id='new-read',expected_anchor=ANCHOR)
    assert len(transport.finish_requests)==1
    adapter.finish_fence(replace(scope,operation='read',operation_id='new-read',permit=next_permit),
        request_id='finish:new-read',request_digest=D)


def test_wrong_finished_identity_does_not_clear_original_pending_ack(port):
    adapter,transport=port;scope=prepare_port(adapter,transport)
    adapter._timeout=.05;transport.lose_finish_after_once=True
    with pytest.raises(RuntimeError):adapter.finish_fence(scope,request_id='finish:'+OP,request_digest=D)
    pending=adapter._pending_finish
    with pytest.raises(RuntimeError,match='finished identity differs'):
        adapter.read_contact_finished_original_v3(scope,request_id='another-finish',request_digest=D)
    assert adapter._pending_finish is pending and len(transport.finish_requests)==1
    adapter.read_contact_finished_original_v3(scope,request_id='finish:'+OP,request_digest=D)
    assert adapter._pending_finish is None and len(transport.finish_requests)==1


def test_changed_graph_stamp_cannot_clear_original_pending_ack(port):
    adapter,transport=port;scope=prepare_port(adapter,transport)
    adapter._timeout=.05;transport.lose_finish_after_once=True
    with pytest.raises(RuntimeError):adapter.finish_fence(scope,request_id='finish:'+OP,request_digest=D)
    adapter._timeout=1.0
    pending=adapter._pending_finish
    with pytest.raises(RuntimeError,match='another pending finish'):
        adapter.read_contact_finished_original_v3(
            replace(scope,graph_revision=scope.graph_revision+1),request_id='finish:'+OP,request_digest=D)
    assert adapter._pending_finish is pending and len(transport.finish_requests)==1
    adapter.read_contact_finished_original_v3(scope,request_id='finish:'+OP,request_digest=D)
    assert adapter._pending_finish is None and len(transport.finish_requests)==1
