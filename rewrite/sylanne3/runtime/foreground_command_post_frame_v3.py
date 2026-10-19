"""Exact post-CAS frames for unchanged registered foreground input bodies.

This is a successor of one actual commit. It never restores the pre-CAS Source
capability or admits another command, Source, clock window or business read.
"""
import time
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import GraphVersion
from ..runtime_contracts import NamespaceId

EMPTY_INPUT_DOMAINS_V3 = {
    'input:freeze_values': 'd01',
    'input:register_artifact_draft_plan_v3': 'd10',
    'input:register_life_outcome_v2': 'd10',
    'input:register_artifact_phase_draft_plan_v2': 'd10',
}
_POST_FRAMES_V3 = {}


def prepare_foreground_input_successor_histories_v3(reader):
    from .current_method_learning_read_v3 import (
        _METHOD_ARTIFACT_POST_OPERATIONS_V3,_HISTORY_COLUMNS,
        read_bound_method_learning_attachment_v3)
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    empty = reader.operation_kind in EMPTY_INPUT_DOMAINS_V3
    action = (reader.operation_kind in _METHOD_ARTIFACT_POST_OPERATIONS_V3
        and is_foreground_command_source_reader_v3(reader))
    if not empty and not action:return
    for atom in reader.frame_fields[0].atoms:
        if atom.revision == 0:continue
        handled,_ = read_bound_method_learning_attachment_v3(reader.db,table='graph_history',
            columns=_HISTORY_COLUMNS,key_columns=('token','revision'),key=(atom.key.token,atom.revision))
        if not handled:
            raise AuthorityUnavailable('Input successor history did not use its actual retained pre-CAS Work')


def require_foreground_input_post_witness_v3(reader,db,graph,prior_frame,stage,receipt,scope,issued,process_lease):
    from .foreground_command_writer_outputs_v3 import require_foreground_command_writer_prior_v3
    if reader.graph is not graph:raise AuthorityUnavailable('Input successor crossed its actual Graph owner')
    return require_foreground_command_writer_prior_v3(db,reader=reader,prior_frame=prior_frame,
        stage=stage,actual_receipt=receipt,scope=scope,issued=issued,process_lease=process_lease)


def source_bound_successor_guard_v3(successor):
    """Retain metadata-only CAS versions without loading their business bodies."""
    versions = {v.key:v.revision for v in successor.prior_frame.envelope.version_guard.read_versions}
    for v in successor.receipt.write_versions:versions[v.key]=v.revision
    for key,revision in versions.items():
        if NamespaceId.from_key(key)!=successor.namespace:
            raise AuthorityUnavailable('Input successor metadata guard crossed its actual namespace')
        row=successor._small_v3('graph_atoms',('revision',),'token=? AND bot=? AND persona=?',
            (key.token,*successor.namespace.as_tuple))
        if (0 if row is None else row[0])!=revision:
            raise AuthorityUnavailable('Input successor changed a sealed metadata-only CAS dependency')
    return tuple(GraphVersion(k,v)for k,v in sorted(versions.items(),key=lambda row:row[0].token))


def register_foreground_command_post_frame_v3(db,prior_frame,frame,successor):
    from .current_method_learning_read_v3 import PreparedMethodPostCommitV3
    from .foreground_command_source_v3 import _FRAMES,_CAPABILITIES
    if type(successor)is not PreparedMethodPostCommitV3:
        raise TypeError('Actual exact post-CAS input successor required')
    successor.require_current_v3()
    if db is not successor.db or prior_frame is not successor.prior_frame:
        raise AuthorityUnavailable('Input post-frame crossed its actual same-transaction successor')
    original=_FRAMES.get(id(prior_frame))
    if original is None:return frame
    actual,state,prepared=original
    if(actual is not prior_frame or state.reader is not successor.owner
            or prepared is not successor.owner.result or _CAPABILITIES.get(state.capability)!=state.capability.identity
            or frame.snapshot is not successor.snapshot or frame.query_coverage!=successor.coverage):
        raise AuthorityUnavailable('Input post-frame lost its actual pre-CAS Source and exact sealed successor')
    _POST_FRAMES_V3[id(frame)]=(frame,successor,original)
    return frame


def require_foreground_command_post_source_family_v3(frame,db,roots,*,purpose=None,audience=None):
    found=_POST_FRAMES_V3.get(id(frame))
    if found is None:return False
    actual,successor,original=found
    from .foreground_command_source_v3 import _FRAMES,_CAPABILITIES
    prior,state,prepared=original
    if(actual is not frame or db is not successor.db or _FRAMES.get(id(prior))is not original
            or state.reader is not successor.owner or prepared is not successor.owner.result
            or _CAPABILITIES.get(state.capability)!=state.capability.identity):
        raise AuthorityUnavailable('Input post-frame Source binding is no longer its exact retained original')
    successor.require_current_v3()
    if time.monotonic()>=state.monotonic_deadline:
        raise AuthorityUnavailable('Input post-frame exceeded its original Source monotonic deadline')
    purpose=purpose or frame.envelope.authority.purpose
    audiences=(audience,)if audience is not None else frame.envelope.authority.audience
    if not set(audiences)<=set(state.original_audiences):
        raise AuthorityUnavailable('Input post-frame audience exceeds its original Source qualification')
    for ref in roots:
        if ref not in state.rights.sources or purpose not in state.original_root_purposes.get(ref,frozenset()):
            raise AuthorityUnavailable('Input post-frame cannot add an unqualified Source or purpose')
    return True


def release_foreground_command_post_frames_v3(successor):
    for key,value in tuple(_POST_FRAMES_V3.items()):
        if value[1]is successor:_POST_FRAMES_V3.pop(key)


def record_foreground_empty_input_after_cas_v3(db,*,runtime,frame,stage,primary,receipt,scope,issued,process_lease,readers):
    from .current_method_learning_read_v3 import _method_active,BorrowedMethodLearningReadV3,bind_method_post_commit_v3
    from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
    reader=_method_active(db)
    if(primary.operation_kind not in EMPTY_INPUT_DOMAINS_V3 or type(reader)is not BorrowedMethodLearningReadV3
            or type(issued)is not _IssuedForegroundActivityV1):
        return False,None,None
    writer=require_foreground_input_post_witness_v3(reader,db,runtime.graph,frame,primary,receipt,scope,issued,process_lease)
    if writer is None:raise AuthorityUnavailable('Actual foreground input has no captured writer for its post-CAS recorder')
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1
    from .domain_production_inputs_v1 import record_current_domain_input_after_commit_v1
    original=record_adopted_domain_operation_v1(db,primary,receipt)
    with bind_method_post_commit_v3(db,graph=runtime.graph,prior_frame=frame,stage=primary,
            actual_receipt=receipt,scope=scope,issued=issued,process_lease=process_lease)as successor:
        produced=record_current_domain_input_after_commit_v1(db,frame=frame,staged_input=stage,
            actual_receipt=receipt,installed_readers=readers,_successor_v3=successor)
    return True,original,produced
