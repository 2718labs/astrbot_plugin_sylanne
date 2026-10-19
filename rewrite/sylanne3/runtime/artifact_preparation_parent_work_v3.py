"""Actual Source Work material, activated only for its one synchronous compiler call."""
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from sys import getsizeof
from weakref import WeakKeyDictionary, ref

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import runtime_storage_v3
from ..domains.d01.production_operations_v1 import plain_v1

_PENDING = WeakKeyDictionary()


def _material_heap_v3(value,seen=None):
    if seen is None:seen=set()
    identity=id(value)
    if identity in seen:return 0
    seen.add(identity)
    size=getsizeof(value)
    if is_dataclass(value) and not isinstance(value,type):
        return size+sum(_material_heap_v3(getattr(value,f.name),seen)for f in fields(value))
    if type(value)is dict:
        return size+sum(_material_heap_v3(k,seen)+_material_heap_v3(v,seen)for k,v in value.items())
    if type(value)in(tuple,list,set,frozenset):
        return size+sum(_material_heap_v3(item,seen)for item in value)
    return size


class _PreparedParentV3:
    def __init__(self,reader,task,handle,material):
        self.reader=ref(reader)
        self.identity=_reader_identity_v3(reader)
        self.task,self.handle,self.material=task,handle,material
        self.material_digest=handle.material_digest
        self.operation=reader.operation

    def _runtime_retained_heap_bytes_v3(self):
        handle=self.handle
        metadata=None if handle is None else (handle.material_digest,handle.task,
            handle.parent_prepare_operation_id,handle.goal_head,handle.plan_head,handle.candidates_digest)
        return getsizeof(self)+getsizeof(self.__dict__)+_material_heap_v3((
            self.identity,self.task,self.material,self.material_digest,metadata))

    def require_v3(self,reader,task):
        if (self.reader() is not reader or self.identity!=_reader_identity_v3(reader)
                or self.task!=task or self.handle is None or self.material is None
                or self.operation is not reader.operation or self.handle.graph is not reader.graph
                or self.handle.task!=task or self.handle.material_digest!=self.material_digest
                or canonical_digest(plain_v1(self.material))!=self.material_digest):
            raise AuthorityUnavailable("preparation parent changed its actual Work, scope, task or material")
        return self


def _reader_identity_v3(reader):
    return (id(reader.work),id(reader.issued),id(reader.issued.scope),id(reader.selected_plan),
        id(reader.frame_fields),reader.selector,reader.selection_digest,reader.request_digest,
        reader.graph_stamp,reader.authority_epochs,reader.owner_head,reader.expected_rights,
        reader.material_owner_guard)


def _actual_reader_v3(reader):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS,_BOUND
    if (type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or reader.work is None or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.work.coordinator is not reader.graph
            or reader.operation.closed or runtime_storage_v3(reader.db)is not reader.operation.handle
            or not reader.inventory_sealed or reader.selected_plan is None or reader.frame_fields is None
            or _BOUND.get()!=(reader.inventory,reader.graph,reader.db)):
        raise AuthorityUnavailable("preparation parent requires its actual bound Source/readset Work")
    reader.inventory._actual()
    return reader


def prepare_borrowed_artifact_preparation_parent_v3(reader):
    from .artifact_host_control_entry_v3 import borrowed_control_preparation_task_v3
    task=borrowed_control_preparation_task_v3(reader)
    if task is None:return
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2
    from .artifact_phase_postconditions_v1 import prepare_candidate_preparation_parent_for_graph_v3
    _actual_reader_v3(reader)
    if (type(task)is not ArtifactDraftTaskSelectorV1 or task.namespace!=reader.namespace
            or reader.inputs_sealed or reader.business_started or not reader.db.in_transaction
            or not reader.store._lock._is_owned()):
        raise AuthorityUnavailable("parent material must be prepared in this Source Work before input sealing")
    prior_ref=_PENDING.get(reader)
    if prior_ref is not None:
        prior=prior_ref()
        if prior is None:raise AuthorityUnavailable("actual preparation parent retention ended")
        prior.require_v3(reader,task)
        return
    handle,material=prepare_candidate_preparation_parent_for_graph_v3(reader.graph,
        request=CurrentArtifactTaskChoiceRequestV2(task),installed_readers=reader.installed_readers)
    prepared=_PreparedParentV3(reader,task,handle,material)
    reader.operation.register_retained_state_v3(prepared)
    _PENDING[reader]=ref(prepared)


@contextmanager
def activate_borrowed_artifact_preparation_parent_v3(reader):
    from .artifact_host_control_entry_v3 import borrowed_control_preparation_task_v3
    task=borrowed_control_preparation_task_v3(reader)
    if task is None:yield None;return
    from .artifact_phase_postconditions_v1 import activate_candidate_preparation_parent_for_graph_v3
    _actual_reader_v3(reader)
    if not reader.inputs_sealed or not reader.business_started or reader.business_completed:
        raise AuthorityUnavailable("preparation parent activates only for its original synchronous compiler")
    pending_ref=_PENDING.get(reader)
    pending=None if pending_ref is None else pending_ref()
    if pending is None:raise AuthorityUnavailable("actual Source Work has no retained preparation parent")
    pending.require_v3(reader,task)
    with activate_candidate_preparation_parent_for_graph_v3(reader.graph,handle=pending.handle)as handle:
        yield handle


def release_borrowed_artifact_preparation_parent_v3(reader):
    pending_ref=_PENDING.pop(reader,None)
    pending=None if pending_ref is None else pending_ref()
    if pending is not None:
        pending.operation.unregister_retained_state_v3(pending)
        pending.material=pending.handle=pending.task=None
