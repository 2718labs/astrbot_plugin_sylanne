"""Actual same-Work task choice locators; metadata never grants Source permission."""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey

_TASKS=WeakKeyDictionary()

class _TaskChoiceReadV3:
    def __init__(self,reader,locator):
        from .artifact_task_choice_catalogue_metadata_v3 import ArtifactTaskChoiceCatalogueMetadataV3
        self.reader=reader;self.work=reader.work;self.operation=reader.operation;self.locator=locator
        root,c02,source=locator
        self.catalogue=ArtifactTaskChoiceCatalogueMetadataV3(reader,root_ref=root,c02_operation_id=c02,source_ref=source)
        self.complete=False
    def require_v3(self):
        r=self.reader
        if (_TASKS.get(r)is not self or r.work is not self.work or self.work.state is not r
                or r.operation is not self.operation or self.operation.closed):
            raise AuthorityUnavailable('Task choice metadata changed its actual originating Work')
        return r
    def advance(self,meter):
        r=self.require_v3();r.require_current(meter=meter)
        self.complete=self.catalogue.advance(meter)
        return self.complete
    def close_v3(self):
        self.catalogue.close_v3();self.reader=self.work=None


def _locator_v3(reader,task):
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_require_borrowed_issuance_v3
    if type(reader)is BorrowedMethodLearningReadV3:
        _require_borrowed_issuance_v3(reader.issued,reader.graph)
        s=reader.selector
        if (task.namespace!=reader.namespace or task.c02_operation_id!=s.c02_operation_id
                or task.root_registration_ref!=s.draft_root_registration_ref):
            raise AuthorityUnavailable('Task catalogue crossed its actual foreground task/Root')
        return task.root_registration_ref,task.c02_operation_id,s.cue_source_ref
    from .current_conditioned_personal_choice_v3 import personal_choice_locator_for_reader_v3
    selected=personal_choice_locator_for_reader_v3(reader)
    if selected is None or task!=selected.task:
        raise AuthorityUnavailable('Task catalogue needs its exact actual prepared personal choice')
    from .current_conditioned_self_read_v3 import require_conditioned_owner_ready_v3
    require_conditioned_owner_ready_v3(reader)
    return task.root_registration_ref,task.c02_operation_id,selected.source_ref


def require_task_choice_catalogue_v3(reader,task):
    from .current_method_learning_read_v3 import _need_method_input
    locator=_locator_v3(reader,task);pending=_TASKS.get(reader)
    if pending is None or not pending.complete:
        _need_method_input(reader,('task_choice_catalogue',locator))
    if pending.locator!=locator:raise AuthorityUnavailable('One Work cannot replace its original task catalogue')
    pending.require_v3()
    return pending.catalogue


def start_task_choice_catalogue_v3(reader,locator):
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    root,c02,source=locator
    task=artifact_draft_task_selector_v1(reader.namespace,c02_operation_id=c02,root_registration_ref=root)
    if _locator_v3(reader,task)!=locator:raise AuthorityUnavailable('Task catalogue changed its actual Source locator')
    pending=_TASKS.get(reader)
    if pending is None:
        if reader.inputs_sealed:raise AuthorityUnavailable('Task catalogue cannot begin after input sealing')
        pending=_TaskChoiceReadV3(reader,locator);_TASKS[reader]=pending
    if pending.locator!=locator:raise AuthorityUnavailable('Task catalogue original locator changed')
    return pending


def seed_conditioned_task_choice_catalogue_v3(reader,locator,state):
    from .current_conditioned_personal_choice_v3 import _register_choice_signed_v3
    catalogue=require_task_choice_catalogue_v3(reader,locator.task);result=catalogue.result_v3()
    state.source_roots.update(result.source_roots)
    for item in result.originals:
        _register_choice_signed_v3(locator,item['kind'],item['ref'],item['payload_digest'])
        state.adoption_operations.add(item['operation_id']);state.required_domain_producers.add(item['operation_id'])
        for version in (*item['read_versions'],*item['write_versions']):
            state.selected_keys.add(version.key)
            if version.revision:state.allowed_history.add((version.key.token,version.revision))


def read_task_choice_original_refs_v3(db,*,kind,task,goal_head,plan_head,method_ref=None):
    from ..authority_service.artifact_task_choice_catalogue_v3 import read_bound_original_task_choice_catalogue_v3
    handled,refs=read_bound_original_task_choice_catalogue_v3(db,kind=kind,task=task,
        goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)
    if handled:return refs
    from .domain_background_read_v3 import _active_v3
    from .artifact_host_control_metadata_v3 import control_state_for_dispatch_v3
    background=_active_v3(db)
    if background is not None:
        control=control_state_for_dispatch_v3(background)
        if control is None:raise AuthorityUnavailable('Task lookup has no actual qualified control READ')
        return control.task_choice_catalogue_v3(kind,task=task,goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)
    from .current_method_learning_read_v3 import _method_active,BorrowedMethodLearningReadV3
    reader=_method_active(db)
    if reader is not None:
        from .foreground_command_source_v3 import is_foreground_command_source_reader_v3,read_foreground_command_task_choice_refs_v3
        if is_foreground_command_source_reader_v3(reader):
            return read_foreground_command_task_choice_refs_v3(reader,kind=kind,task=task,
                goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)
        catalogue=require_task_choice_catalogue_v3(reader,task)
        if type(reader)is BorrowedMethodLearningReadV3:
            qualified={v.key.token for v in reader.evidence.read_versions if v.key.type_name=='memory.source'}
            if not set(catalogue.result_v3().source_roots)<=qualified:
                raise AuthorityUnavailable('Task choice added Source outside actual fresh foreground issuance')
        else:
            from .current_conditioned_self_read_v3 import require_conditioned_sources_v3
            require_conditioned_sources_v3(reader,catalogue.result_v3().source_roots)
        return catalogue.lookup_v3(kind,task=task,goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)
    raise AuthorityUnavailable('Task lookup requires its actual independently qualified Owner/Source Work')


def release_task_choice_catalogue_v3(reader):
    pending=_TASKS.pop(reader,None)
    if pending is not None:pending.close_v3()
