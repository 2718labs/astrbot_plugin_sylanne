"""Private, current-fenced commit of the installed finite domain operation set.

No public DTO can issue a witness. The concrete installed runtime rebuilds the
stage in the actual transaction and binds it to that Graph, permit and bundle.
"""
from dataclasses import dataclass, replace
import json

from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import StagedDomainOperationV1
from .domain_production_originals_v1 import record_adopted_domain_operation_v1, _receipt_wire
from .d11_types import D11_PROPOSAL_SCHEMA, D11RuntimeProvider, job_graph_write, reconcile_runtime_write
from .jobs import create_job

OUTBOX_TABLE = 'graph_domain_production_outbox_v1'


def install_domain_production_outbox_v1(db):
    db.execute('''CREATE TABLE IF NOT EXISTS graph_domain_production_outbox_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, dedupe_key TEXT NOT NULL,
        causal_operation_id TEXT NOT NULL, receiver_domain TEXT NOT NULL, event_kind TEXT NOT NULL,
        original_ref TEXT NOT NULL, original_digest TEXT NOT NULL, state TEXT NOT NULL,
        consumer_operation_id TEXT, receipt_json TEXT,
        PRIMARY KEY(bot,persona,dedupe_key))''')
    db.execute('CREATE INDEX IF NOT EXISTS graph_domain_production_outbox_pending_v1 '
        'ON graph_domain_production_outbox_v1(bot,persona,state,dedupe_key)')


@dataclass(frozen=True, slots=True)
class _ProductionCommitWitnessV1:
    runtime: object
    graph: object
    scope: object
    frame: object
    stage: object
    operation: object
    request: object
    owner: object
    guard: object
    bundle: DomainBundle
    external_originals: tuple


_ACTIVE = {}
_FOREGROUND_VALIDATED = {}
_FOREGROUND_APPLIED = {}

_GENERAL_GROWTH_COMMIT_KINDS_V1=frozenset(('freeze_general_growth_intent_v1',
    'register_general_growth_trial_start_v1','derive_general_growth_trial_v1','adopt_general_growth_v1'))
_GENERAL_GROWTH_PRECAS_VALIDATED_V1={}

class _GeneralGrowthVerifiedProvenanceV1:
    def __init__(self,witness,db,encoded):
        from ..runtime_storage_v3 import runtime_storage_v3,_operation
        self.witness,self.db,self.encoded=witness,db,encoded
        handle=runtime_storage_v3(db)
        if handle is None:raise ValueError('General growth requires its actual installed runtime retention handle')
        self.operation=_operation(handle);self.provenance=None
    def _runtime_retained_heap_bytes_v3(self):
        from sys import getsizeof
        from dataclasses import is_dataclass,fields
        seen=set()
        def size(value):
            if id(value)in seen:return 0
            seen.add(id(value));result=getsizeof(value)
            if type(value)is dict:result+=sum(size(k)+size(v)for k,v in value.items())
            elif type(value)in(list,tuple):result+=sum(size(v)for v in value)
            elif is_dataclass(value):
                result+=getsizeof(value.__dict__)if hasattr(value,'__dict__')else 0
                result+=sum(size(getattr(value,f.name))for f in fields(value))
            return result
        return getsizeof(self)+size(self.encoded)+size(self.provenance)
    def decode_v1(self):
        from sys import getsizeof
        quote=escape=number=False
        objects=arrays=strings=numbers=keys=digits=literals=0
        for character in self.encoded:
            if quote:
                if escape:escape=False
                elif character=='\\':escape=True
                elif character=='"':quote=False
                continue
            if character=='"':quote=True;strings+=1;number=False
            elif character=='{':objects+=1;number=False
            elif character=='[':arrays+=1;number=False
            elif character==':':keys+=1;number=False
            elif character in '-0123456789':
                if not number:numbers+=1;number=True
                if character in '0123456789':digits+=1
            elif character in '.eE+':pass
            elif character in 'tfn':literals+=1;number=False
            else:number=False
        nodes=objects+arrays+strings+numbers+literals
        dictionaries=objects*(getsizeof({})+8*(8+24))+keys*(4*8+3*24)
        lists=arrays*(getsizeof([])+8*8)+nodes*2*8
        text=strings*getsizeof(chr(0x10000))+4*len(self.encoded)
        numeric=numbers*(getsizeof(0)+4)+4*((4*digits+29)//30)
        # The JSON map, typed validation, and its canonical plain map coexist.
        # Dataclass slots/dictionaries are bounded by their corresponding JSON
        # object's actual field count; tuple construction uses the array census.
        typed=objects*(2*getsizeof({})+getsizeof(self)+getsizeof(self.__dict__))+keys*(8+24)+arrays*getsizeof(())+nodes*8
        bound=3*(dictionaries+lists+text+numeric)+typed+5*(4*len(self.encoded)+getsizeof(''))
        self.operation.register_retained_state_v3(self)
        try:
            self.operation.reserve_retained_state_growth_v3(self,bound)
            try:
                payload=json.loads(self.encoded)
                from .domain_production_erasure_v1 import validate_domain_stage_provenance_v1
                kind=self.witness.operation.operation_kind
                validate_domain_stage_provenance_v1('d01',kind,payload['provenance'])
                from .domain_production_erasure_v1 import (_general_growth_provenance_types_v1,
                    decode_typed_production_value_v1)
                self.provenance=({name:(raw if cls is None else decode_typed_production_value_v1(raw,cls))
                    for name,cls in _general_growth_provenance_types_v1(kind).items()
                    for raw in (payload['provenance'][name],)}if payload['provenance']else {})
            finally:self.operation.finish_retained_state_growth_v3(self)
        except BaseException:
            self.close_v1();raise
    def close_v1(self):
        self.operation.unregister_retained_state_v3(self);self.provenance=None


from contextlib import contextmanager
from threading import get_ident
from ..runtime_contracts import CommitReceipt
_GENERAL_GROWTH_POSTCAS_V1={}


def _general_growth_post_cas_metadata_v1(db,namespace):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        epoch=_runtime_bounded_fixed_row_v3(db,meter,'graph_epochs',('revision',),
            'bot=? AND persona=?',namespace.as_tuple)
        requirements=_runtime_bounded_fixed_row_v3(db,meter,'graph_recovery_metadata_v2',
            ('schema','requirements_json','graph_revision'),'bot=? AND persona=?',namespace.as_tuple)
    return epoch,requirements

@contextmanager
def _general_growth_post_cas_v1(witness,db,primary,receipt):
    pre=_GENERAL_GROWTH_PRECAS_VALIDATED_V1.get(id(witness))
    if (pre is None or pre[0] is not witness or pre[1] is not db or _ACTIVE.get(id(witness)) is not witness
            or primary.original_payload_json!=pre[2] or type(receipt) is not CommitReceipt
            or receipt.status!='committed' or receipt.operation_id!=primary.operation_id
            or receipt.operation_digest!=witness.bundle.digest
            or receipt.read_versions!=witness.frame.envelope.version_guard.read_versions
            or witness.scope.operation!='write' or db is not witness.graph._GraphCoordinator__store._db
            or not db.in_transaction or not witness.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('General growth post-CAS requires its actual successful verified W01')
    first_three=witness.operation.operation_kind!='adopt_general_growth_v1'
    if first_three and (primary.jobs or any(p.typed_writes for p in witness.bundle.proposals)):
        raise ValueError('General input signing cannot carry Source/Owner/Control or business writes')
    expected_keys={write.key for proposal in witness.bundle.proposals for write in proposal.typed_writes}
    if {version.key for version in receipt.write_versions}!=expected_keys:
        raise ValueError('General growth actual receipt write members differ from its verified bundle')
    epoch,requirements=_general_growth_post_cas_metadata_v1(db,primary.namespace)
    if epoch is None or requirements is None:
        raise ValueError('General growth actual post-CAS metadata is absent')
    from ..graph_store import GraphStore
    metadata=GraphStore._decode_recovery(requirements,primary.namespace)
    if not witness.graph._anchor_matches(metadata.requirements,witness.scope.pinned_anchor):
        raise ValueError('General growth post-CAS changed Source/Owner/Control anchor')
    if pre[3].operation.closed or pre[3].provenance is None:
        raise ValueError('General growth verified provenance retention ended before its actual receipt')
    _GENERAL_GROWTH_POSTCAS_V1[id(witness)]=(witness,db,primary,receipt,pre[2],get_ident(),epoch,requirements,pre[3])
    try:yield witness
    finally:_GENERAL_GROWTH_POSTCAS_V1.pop(id(witness),None)


def require_general_growth_after_cas_witness_v1(witness,*,db,frame,producing_operation_id,request,receipt,operation_kind):
    entry=_GENERAL_GROWTH_POSTCAS_V1.get(id(witness))
    if (entry is None or entry[0] is not witness or entry[1] is not db or entry[3] is not receipt
            or frame is not witness.frame or request is not witness.request or entry[5]!=get_ident()
            or operation_kind not in _GENERAL_GROWTH_COMMIT_KINDS_V1
            or operation_kind!=witness.operation.operation_kind or producing_operation_id!=entry[2].operation_id
            or witness.runtime.graph is not witness.graph or witness.scope.operation!='write'
            or not db.in_transaction or not witness.graph._GraphCoordinator__store._lock._is_owned()
            or entry[2].original_payload_json!=entry[4]):
        raise ValueError('General original signing crossed its exact same-transaction post-CAS handle')
    epoch,metadata=_general_growth_post_cas_metadata_v1(db,entry[2].namespace)
    if (epoch,metadata)!=(entry[6],entry[7]):
        raise ValueError('General input signing lost its actual post-CAS metadata')
    if entry[8].operation.closed or entry[8].provenance is None:
        raise ValueError('General growth same-CAS provenance retention ended')
    return entry[8].provenance


def _record_general_growth_after_cas_v1(readers,db,*,witness,frame,primary,request,receipt):
    kind=primary.operation_kind
    if kind=='freeze_general_growth_intent_v1':
        return readers.freeze_current_general_growth_after_commit_v1(db,frame=frame,
            producing_operation_id=primary.operation_id,request=request,receipt=receipt,witness=witness)
    if kind=='register_general_growth_trial_start_v1':
        return (readers.start_current_general_growth_trial_after_commit_v1(db,frame=frame,
            producing_operation_id=primary.operation_id,request=request,receipt=receipt,witness=witness),)
    if kind=='derive_general_growth_trial_v1':
        return (readers.derive_current_general_growth_trial_from_adopted_progress_v1(db,frame=frame,
            producing_operation_id=primary.operation_id,request=request,receipt=receipt,witness=witness),)
    return ()


def _record_general_growth_pre_cas_validation_v1(witness,graph,db,bundle):
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.operation.operation_kind not in _GENERAL_GROWTH_COMMIT_KINDS_V1
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('General growth requires its real active W01 pre-CAS witness')
    owner_task=getattr(witness.runtime,'_active_owner_task_issuance_v1',None)
    foreground=getattr(witness.runtime,'_active_foreground_issuance_v1',None)
    if owner_task is not None:
        issued,_=_require_owner_task_witness_v1(witness,graph,db,bundle)
        rebuilt_frame,rebuilt,_=witness.runtime.compile_owner_task_in_transaction_v1(db,
            operation=witness.operation,request=witness.request,envelope=witness.frame.envelope,
            scope=witness.scope,issued=issued,now_utc=witness.frame.now_utc,
            external_originals=witness.external_originals)
    elif foreground is not None:
        issued,_=_require_foreground_witness_v1(witness,graph,db,bundle)
        rebuilt_frame,rebuilt,_=witness.runtime.compile_foreground_in_transaction(db,
            operation=witness.operation,request=witness.request,envelope=witness.frame.envelope,
            scope=witness.scope,issued=issued,now_utc=witness.frame.now_utc,
            external_originals=witness.external_originals)
    else:
        rebuilt_frame,rebuilt,_=witness.runtime.compile_in_transaction(db,operation=witness.operation,
            request=witness.request,envelope=witness.frame.envelope,scope=witness.scope,
            owner=witness.owner,guard=witness.guard,now_utc=witness.frame.now_utc,
            external_originals=witness.external_originals)
    primary,proposals,*_= _members(rebuilt)
    if not proposals:
        registration=graph._GraphCoordinator__providers[witness.operation.domain]
        proposals=(DomainProposal(witness.operation.domain,registration[1],registration[2],
            witness.frame.envelope,(),DependencySet(),(),()),)
    if (rebuilt_frame!=witness.frame or rebuilt!=witness.stage or proposals!=bundle.proposals
            or primary.operation_kind!=witness.operation.operation_kind):
        raise ValueError('General growth actual qualification or provenance changed before its CAS')
    pre=_GENERAL_GROWTH_PRECAS_VALIDATED_V1.get(id(witness))
    if pre is None:
        holder=_GeneralGrowthVerifiedProvenanceV1(witness,db,primary.original_payload_json)
        holder.decode_v1()
        _GENERAL_GROWTH_PRECAS_VALIDATED_V1[id(witness)]=(witness,db,primary.original_payload_json,holder)
    elif pre[0]is not witness or pre[1]is not db or pre[2]!=primary.original_payload_json:
        raise ValueError('General growth exact verified payload changed in its actual CAS')
    return witness


def require_owner_stop_projection_commit_v1(witness, graph, db, bundle=None):
    from types import SimpleNamespace
    from .owner_stop_reply_v1 import OwnerStopReplyProjectionStageV1, stage_owner_stop_reply_projection_v1
    from .domain_production_contracts_v1 import require_owner_stop_projection_frame_v1
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) is not OwnerStopReplyProjectionStageV1
            or witness.operation.operation_kind != "owner_stop_reply_v1"
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle is not None and witness.bundle != bundle):
        raise ValueError("Stop projection requires its exact active installed W01 witness")
    observed = require_owner_stop_projection_frame_v1(witness.frame)
    if (witness.runtime._active_owner_stop_projection_v1 is not witness.frame.issuance
            or witness.request != observed.request or witness.stage.original != observed.initial_original
            or witness.scope != witness.frame.issuance.scope
            or witness.bundle.envelope != witness.frame.envelope
            or witness.bundle.proposals != witness.stage.stage.proposals):
        raise ValueError("Stop projection changed its original private Owner/permit bundle")
    rebuilt = stage_owner_stop_reply_projection_v1(db, frame=witness.frame, request=witness.request,
        original=observed.initial_original, installed_readers=SimpleNamespace(issuer=graph._GraphCoordinator__d11_issuer))
    if rebuilt != witness.stage:
        raise ValueError("Stop projection actual metadata changed before CAS")
    return witness


def foreground_domain_finish_digest_v1(selector, permit):
    return "sha256:" + canonical_digest({"schema": "w01.foreground-domain-write.v1",
        "operation_id": selector.operation_id, "request_digest": canonical_digest(selector), "permit_token": permit.token})


def owner_task_domain_finish_digest_v1(selector, permit):
    return 'sha256:' + canonical_digest({'schema':'w01.owner-task-domain-write.v1',
        'operation_id':selector.operation_id,'request_digest':canonical_digest(selector),'permit_token':permit.token})


def _require_owner_task_witness_v1(witness, graph, db, bundle):
    from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
    from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
    issued=getattr(witness.runtime,'_active_owner_task_issuance_v1',None)
    if getattr(witness.runtime,'_active_foreground_issuance_v1',None) is not None:
        raise ValueError('Owner task and foreground issuances cannot overlap')
    evidence=require_owner_source_note_task_issuance_v1(issued,graph,witness.scope)
    envelope=bundle.envelope
    if (evidence.request.request_digest!=owner_task_typed_command_digest_v1(witness.operation,witness.request)
            or envelope.authority.issuer_domain!=witness.operation.domain
            or envelope.identity.phase!=witness.operation.operation_kind
            or envelope.identity.operation_id!=evidence.request.operation_id
            or envelope.authority.actor!=evidence.current_self.self_entity_ref
            or witness.frame.owner_guard!=evidence.owner_guard
            or not {proposal.domain for proposal in bundle.proposals}<=set(evidence.allowed_write_domains)):
        raise ValueError('Owner task final command/domain/actor differs from its real private issuance')
    return issued,evidence


def _require_foreground_witness_v1(witness, graph, db, bundle):
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    issued = getattr(witness.runtime, "_active_foreground_issuance_v1", None)
    evidence = require_foreground_activity_issuance_v1(issued, graph, witness.scope)
    envelope = bundle.envelope
    if (evidence.request.request_digest != foreground_typed_command_digest_v1(witness.operation, witness.request)
            or envelope.authority.issuer_domain != witness.operation.domain
            or envelope.identity.phase != witness.operation.operation_kind
            or envelope.identity.operation_id != evidence.request.operation_id
            or envelope.authority.actor != evidence.current_self.self_entity_ref
            or witness.frame.owner_guard != evidence.owner_guard
            or not {proposal.domain for proposal in bundle.proposals} <= set(evidence.allowed_write_domains)):
        raise ValueError("final foreground issuer/phase/body/domain/actor differs from actual issued qualification")
    if witness.operation.operation_kind == "await_existing_artifact_revision_v1":
        from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
        key = project_checkpoint_key_v1(evidence.request.namespace, witness.request.project_ref)
        writes = tuple(write for proposal in bundle.proposals for write in proposal.typed_writes)
        if (len(bundle.proposals) != 1 or bundle.proposals[0].domain != "d10"
                or len(writes) != 1 or writes[0].key != key
                or writes[0].value["state"] != "waiting" or writes[0].value["next_step"] is not None):
            raise ValueError("artifact waiting bridge may write only its exact metadata checkpoint")
    return issued, evidence


def apply_foreground_cycle_before_graph_write_v1(witness, graph, db):
    from .c04_ingress_preparation_v4 import _SelfC04CommitV4, apply_self_c04_prepare_once_v4
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4, apply_self_c04_adoption_once_v4
    if type(witness) is _SelfC04CommitV4:
        return apply_self_c04_prepare_once_v4(witness, graph, db)
    if type(getattr(witness, "stage", None)) is SelfC04AdoptionStageV4:
        return apply_self_c04_adoption_once_v4(witness, graph, db)
    """The fixed W01 guard calls this after current CAS guards, before projection reconciliation."""
    from .habit_schedule_driver_v1 import HabitScheduleStageV1,apply_habit_schedule_jobs_in_transaction_v1
    if type(getattr(witness,'stage',None))is HabitScheduleStageV1:
        if _ACTIVE.get(id(witness))is not witness or _FOREGROUND_VALIDATED.get(id(witness))is not witness or id(witness)in _FOREGROUND_APPLIED:
            raise ValueError('Habit job mirrors require their exact privately validated same-W01 witness')
        apply_habit_schedule_jobs_in_transaction_v1(db,stage=witness.stage,frame=witness.frame)
        _FOREGROUND_APPLIED[id(witness)]=witness
        return True
    from .cancel_owner_source_note_task_v1 import CancelOwnerSourceNoteTaskStageV1,apply_cancel_owner_source_note_task_in_transaction_v1
    if type(getattr(witness,'stage',None)) is CancelOwnerSourceNoteTaskStageV1:
        if (_ACTIVE.get(id(witness)) is not witness or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
                or id(witness) in _FOREGROUND_APPLIED):
            raise ValueError('Owner cancellation once apply requires its exact current W01 witness')
        apply_cancel_owner_source_note_task_in_transaction_v1(db,stage=witness.stage)
        _FOREGROUND_APPLIED[id(witness)]=witness
        return True
    from .owner_source_note_task_execution_v1 import (OwnerSourceNoteTaskStageV1,
        apply_owner_source_note_task_stage_in_transaction_v1)
    if type(getattr(witness,'stage',None)) is OwnerSourceNoteTaskStageV1:
        if (_ACTIVE.get(id(witness)) is not witness or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
                or id(witness) in _FOREGROUND_APPLIED):
            raise ValueError('Owner task once apply requires its exact privately validated W01 witness')
        _require_owner_task_witness_v1(witness,graph,db,witness.bundle)
        apply_owner_source_note_task_stage_in_transaction_v1(db,stage=witness.stage)
        _FOREGROUND_APPLIED[id(witness)]=witness
        return True
    from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1, apply_ingress_recall_result_once_v1
    if type(getattr(witness, "stage", None)) is D07IngressRecallResultStageV1:
        return apply_ingress_recall_result_once_v1(witness, graph, db)
    from .d07_ingress_recall_acquisition_v1 import D07IngressRecallAcquisitionStageV1, apply_ingress_recall_acquisition_once_v1
    if type(getattr(witness, "stage", None)) is D07IngressRecallAcquisitionStageV1:
        return apply_ingress_recall_acquisition_once_v1(witness, graph, db)
    from .d07_ingress_recall_preparation_v1 import D07IngressRecallMaterializedStageV1, apply_ingress_recall_cycle_once_v1
    if type(getattr(witness, "stage", None)) is D07IngressRecallMaterializedStageV1:
        return apply_ingress_recall_cycle_once_v1(witness, graph, db)
    from .foreground_cycle_v1 import ForegroundCycleStageV1, apply_foreground_cycle_stage_v1
    from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV1, ArtifactDraftModelStageV2, apply_artifact_draft_model_stage_v1
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2, apply_artifact_draft_content_stage_v1
    from .owner_stop_reply_v1 import OwnerStopReplyProjectionStageV1, apply_owner_stop_reply_projection_once_v1
    if type(getattr(witness, "stage", None)) is OwnerStopReplyProjectionStageV1:
        from types import SimpleNamespace
        require_owner_stop_projection_commit_v1(witness, graph, db)
        if id(witness) in _FOREGROUND_APPLIED:
            raise ValueError("Stop projection cannot apply twice in one CAS")
        from ..authority_service.owner_stop_reply_metadata_v1 import bind_host_owner_stop_reply_metadata_v1
        issued=graph._GraphCoordinator__domain_production_runtime_v1._active_owner_stop_projection_v1
        with bind_host_owner_stop_reply_metadata_v1(issued,db):
            apply_owner_stop_reply_projection_once_v1(db, witness.stage,
                SimpleNamespace(issuer=graph._GraphCoordinator__d11_issuer))
        _FOREGROUND_APPLIED[id(witness)] = witness
        return True
    if type(getattr(witness, "stage", None)) not in {ForegroundCycleStageV1, ArtifactDraftModelStageV1, ArtifactDraftModelStageV2, ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2}:
        return False
    if (_ACTIVE.get(id(witness)) is not witness or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or id(witness) in _FOREGROUND_APPLIED):
        raise ValueError("foreground once-apply requires its privately validated exact W01 witness")
    issued, evidence = _require_foreground_witness_v1(witness, graph, db, witness.bundle)
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    readers = installed_readers_for_operation_v1(graph, witness.operation, scope=witness.scope,
        owner_guard=evidence.owner_guard, foreground_issuance=issued)
    if type(witness.stage) in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2}:
        return apply_artifact_draft_model_stage_v1(witness, graph, db, readers)
    if type(witness.stage) in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2}:
        return apply_artifact_draft_content_stage_v1(witness, graph, db, readers)
    if type(witness.stage) is ArtifactDraftPhaseVerificationStageV2:
        from .d11_artifact_draft_content_v1 import apply_artifact_draft_phase_verification_stage_v2
        return apply_artifact_draft_phase_verification_stage_v2(witness, graph, db, readers)
    apply_foreground_cycle_stage_v1(db, witness.stage, readers)
    _FOREGROUND_APPLIED[id(witness)] = witness
    return True


def _rebuild_current_habit_stage_v1(runtime,db,*,operation,request,frame,stage,scope):
    from .habit_control_issuance_v1 import require_habit_control_issuance_v1 as require_habit_activity_issuance_v1
    from .habit_activity_runtime_v1 import require_current_habit_commit_v1
    from .current_habit_source_read_v3 import require_habit_compile_inputs_v3
    from .domain_production_registry_v1 import stage_installed_domain_operation_v1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    issued=runtime._active_habit_issuance_v1
    evidence=require_habit_activity_issuance_v1(issued,runtime.graph,scope)
    require_current_habit_commit_v1(runtime,db,operation=operation,request=request,frame=frame,stage=stage,scope=scope)
    if getattr(runtime,'_active_owner_task_issuance_v1',None)is not None or runtime._active_foreground_issuance_v1 is not None or frame.envelope.authority.actor!=evidence.current_self.self_entity_ref:raise ValueError('Habit restage cannot borrow another issuance or actor')
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,CurrentHabitMaintenanceReadV1
    read=CurrentHabitMaintenanceReadV1(frame)if type(frame)is CurrentHabitMaintenanceFrameV1 else CurrentDomainReadV1(frame)
    read.check(db)
    _,_,_,readers=require_habit_compile_inputs_v3(db,graph=runtime.graph,scope=scope,issued=issued,operation=operation,request=request,now_utc=frame.now_utc)
    rebuilt=stage_installed_domain_operation_v1(db,operation=operation,frame=frame,request=request,installed_readers=readers)
    require_current_habit_commit_v1(runtime,db,operation=operation,request=request,frame=frame,stage=rebuilt,scope=scope)
    if rebuilt!=stage:raise ValueError('Habit actual Source/Owner/Root/phase stage changed before its original CAS')
    return rebuilt


def _require_current_habit_witness_v1(witness,graph,db,bundle):
    from .habit_control_issuance_v1 import require_habit_control_issuance_v1 as require_habit_activity_issuance_v1
    from .habit_activity_runtime_v1 import require_current_habit_commit_v1
    issued=witness.runtime._active_habit_issuance_v1
    evidence=require_habit_activity_issuance_v1(issued,graph,witness.scope)
    require_current_habit_commit_v1(witness.runtime,db,operation=witness.operation,request=witness.request,frame=witness.frame,stage=witness.stage,scope=witness.scope)
    if witness.owner is not None or witness.guard!=evidence.owner_guard or witness.frame.envelope!=bundle.envelope:raise ValueError('Habit actual witness changed its independent Owner/Source command')
    from .d11_life_preparation_v1 import LifePreparationStageV1,verify_life_preparation_in_transaction_v1
    if type(witness.stage)is LifePreparationStageV1:
        from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
        verify_life_preparation_in_transaction_v1(db,witness.stage,issuer=graph._GraphCoordinator__d11_issuer,resource_issuer=graph._GraphCoordinator__d02_issuer)
        if life_preparation_bundle_v1(graph,witness.stage)!=bundle:raise ValueError('Habit Life witness changed the actual job and single occurrence same-CAS bundle')
    else:
        rebuilt=_rebuild_current_habit_stage_v1(witness.runtime,db,operation=witness.operation,request=witness.request,frame=witness.frame,stage=witness.stage,scope=witness.scope)
        if _members(rebuilt)[1]!=bundle.proposals:raise ValueError('Habit exact rebuilt proposal set differs from its original bundle')
        from .habit_schedule_driver_v1 import HabitScheduleStageV1
        if type(rebuilt)is HabitScheduleStageV1:_FOREGROUND_VALIDATED[id(witness)]=witness
    return witness


def require_current_production_commit_v1(witness, graph, db, bundle, v2_write):
    from .c04_ingress_preparation_v4 import _SelfC04CommitV4, require_self_c04_prepare_commit_v4
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4, require_self_c04_adoption_commit_v4
    if type(witness) is _SelfC04CommitV4:
        return require_self_c04_prepare_commit_v4(witness, graph, db, bundle, v2_write)
    if type(getattr(witness, "stage", None)) is SelfC04AdoptionStageV4:
        return require_self_c04_adoption_commit_v4(witness, graph, db, bundle, v2_write)
    from .internal_life_content_worker_v2 import InternalLifeContentAcquisitionStageV2
    if type(getattr(witness,'stage',None)) is InternalLifeContentAcquisitionStageV2:
        from .internal_life_content_worker_v2 import (
            require_exact_internal_life_acquisition_issuance_v2,
            verify_internal_life_acquisition_in_transaction_v2, internal_life_acquisition_bundle_v2)
        require_exact_internal_life_acquisition_issuance_v2(witness,graph,bundle)
        if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
                or not graph._GraphCoordinator__store._lock._is_owned()
                or v2_write is None or witness.scope.graph_revision!=v2_write[0].graph_revision
                or witness.scope.graph_epoch!=v2_write[1]
                or not graph._anchor_matches(v2_write[0].requirements,witness.scope.pinned_anchor)):
            raise ValueError('Life worker dual-role witness lost its actual original write fence')
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        verify_internal_life_acquisition_in_transaction_v2(db,witness.stage,readers)
        if internal_life_acquisition_bundle_v2(witness.stage)!=bundle:
            raise ValueError('Life worker exact dual-role bundle changed')
        return witness
    from .d11_offline_adoption_v1 import _OfflineCommitWitnessV1, require_offline_commit_v1
    if type(witness) is _OfflineCommitWitnessV1:
        return require_offline_commit_v1(witness, graph, db, bundle, v2_write)
    from .d11_life_adoption_v1 import _LifeCommitWitnessV1, require_life_commit_v1
    if type(witness) is _LifeCommitWitnessV1:
        return require_life_commit_v1(witness, graph, db, bundle, v2_write)
    from .contact_final_stage_v1 import _ContactFinalCommitWitnessV1, require_contact_final_commit_v1
    if type(witness) is _ContactFinalCommitWitnessV1:
        return require_contact_final_commit_v1(witness, graph, db, bundle, v2_write)
    from .contact_final_stage_v2 import _ContactFinalCommitWitnessV2, require_contact_final_commit_v2
    if type(witness) is _ContactFinalCommitWitnessV2:
        return require_contact_final_commit_v2(witness, graph, db, bundle, v2_write)
    from .contact_final_stage_v3 import _ContactFinalCommitWitnessV3, require_contact_final_commit_v3
    if type(witness) is _ContactFinalCommitWitnessV3:
        return require_contact_final_commit_v3(witness, graph, db, bundle, v2_write)
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle != witness.bundle or v2_write is None
            or witness.scope.graph_revision != v2_write[0].graph_revision
            or witness.scope.graph_epoch != v2_write[1]
            or witness.scope.permit.pinned_anchor != witness.scope.pinned_anchor
            or not graph._anchor_matches(v2_write[0].requirements, witness.scope.pinned_anchor)):
        raise ValueError('installed domain commit witness/current Graph fence differs')
    witness.runtime._current()
    primary_census,*_=_members(witness.stage)
    from .habit_census_provenance_v1 import require_current_habit_census_payload_v1
    require_current_habit_census_payload_v1(witness.frame,json.loads(primary_census.original_payload_json))
    from .named_joint_binding_write_v1 import current_named_joint_write_v1,require_named_joint_commit_witness_v1
    if current_named_joint_write_v1(witness.runtime)is not None:
        return require_named_joint_commit_witness_v1(witness,graph,db,bundle)
    from .conditioned_child_write_v1 import current_conditioned_child_write_v1,require_conditioned_child_witness_v1
    if current_conditioned_child_write_v1(witness.runtime)is not None:
        return require_conditioned_child_witness_v1(witness,graph,db,bundle)
    if witness.runtime._active_habit_issuance_v1 is not None:
        return _require_current_habit_witness_v1(witness,graph,db,bundle)
    from .habit_schedule_driver_v1 import HabitScheduleStageV1,stage_record_habit_window_cue_v1
    if type(witness.stage)is HabitScheduleStageV1:
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        if witness.operation.operation_kind=='record_habit_window_cue_v1':
            rebuilt=stage_record_habit_window_cue_v1(db,frame=witness.frame,request=witness.request,installed=readers)
        else:
            from .d10_habit_v1 import stage_current_habit_operation_v1
            rebuilt=stage_current_habit_operation_v1(db,frame=witness.frame,request=witness.request,installed_readers=readers,operation_kind=witness.operation.operation_kind)
        if rebuilt!=witness.stage or witness.stage.stage.proposals!=bundle.proposals:raise ValueError('Habit subscription actual current Source/job/CAS transition changed')
        _FOREGROUND_VALIDATED[id(witness)]=witness
        return witness
    if witness.operation.operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import verify_contact_prospective_stage_v1
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        verify_contact_prospective_stage_v1(db,frame=witness.frame,request=witness.request,installed_readers=readers,stage=witness.stage)
        if witness.stage.proposals!=bundle.proposals:raise ValueError('Contact prospective barrier-only bundle changed')
        return witness
    from .contact_plan_physical_write_v3 import PreparedContactPlanPhysicalV3,require_contact_plan_commit_v3
    if type(witness.stage) is PreparedContactPlanPhysicalV3:
        return require_contact_plan_commit_v3(witness,graph,db,bundle,v2_write)
    from .owner_material_source_storage_v3 import (
        StagedDomainOperationV3,require_owner_material_sealed_stage_v3,
    )
    if type(witness.stage) is StagedDomainOperationV3:
        require_owner_material_sealed_stage_v3(
            witness.stage,witness.runtime,db,frame=witness.frame,
            request=witness.request,scope=witness.scope,
            installed_readers=witness.stage.prepared.readers)
        if (witness.stage.operation_kind!=witness.operation.operation_kind
                or witness.stage.proposals!=bundle.proposals):
            raise ValueError('sealed Owner Source operation or actual W01 proposals changed')
        return witness
    if witness.operation.operation_kind in _GENERAL_GROWTH_COMMIT_KINDS_V1:
        return _record_general_growth_pre_cas_validation_v1(witness,graph,db,bundle)
    from .owner_stop_reply_v1 import OwnerStopReplyProjectionStageV1
    if type(witness.stage) is OwnerStopReplyProjectionStageV1:
        return require_owner_stop_projection_commit_v1(witness, graph, db, bundle)
    owner_task=getattr(witness.runtime,'_active_owner_task_issuance_v1',None)
    if owner_task is not None:
        issued,evidence=_require_owner_task_witness_v1(witness,graph,db,bundle)
        from .d11_life_preparation_v1 import LifePreparationStageV1,verify_life_preparation_in_transaction_v1
        if type(witness.stage) is LifePreparationStageV1:
            from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
            verify_life_preparation_in_transaction_v1(db,witness.stage,issuer=graph._GraphCoordinator__d11_issuer,
                resource_issuer=graph._GraphCoordinator__d02_issuer)
            if life_preparation_bundle_v1(graph,witness.stage)!=bundle:
                raise ValueError('Owner task SourceNote preparation changed its actual job-only bundle')
            return witness
        rebuilt_frame,rebuilt,_=witness.runtime.compile_owner_task_in_transaction_v1(db,
            operation=witness.operation,request=witness.request,envelope=witness.frame.envelope,
            scope=witness.scope,issued=issued,now_utc=witness.frame.now_utc,
            external_originals=witness.external_originals)
        if rebuilt_frame!=witness.frame or rebuilt!=witness.stage or _members(rebuilt)[1]!=bundle.proposals:
            raise ValueError('Owner task actual current stage changed before Graph CAS')
        from .owner_source_note_task_execution_v1 import OwnerSourceNoteTaskStageV1,verify_owner_source_note_task_stage_v1
        if type(witness.stage) is OwnerSourceNoteTaskStageV1:
            verify_owner_source_note_task_stage_v1(witness.stage)
            _FOREGROUND_VALIDATED[id(witness)]=witness
        return witness
    foreground = getattr(witness.runtime, "_active_foreground_issuance_v1", None)
    if foreground is not None:
        issued, evidence = _require_foreground_witness_v1(witness, graph, db, bundle)
        from .d07_ingress_recall_preparation_v1 import D07IngressRecallMaterializedStageV1, verify_ingress_recall_model_commit_v1
        if type(witness.stage) is D07IngressRecallMaterializedStageV1:
            return verify_ingress_recall_model_commit_v1(witness, graph, db, bundle)
        from .foreground_cycle_v1 import ForegroundCycleStageV1, verify_foreground_cycle_stage_v1
        if type(witness.stage) is ForegroundCycleStageV1:
            from .domain_production_registry_v1 import installed_readers_for_operation_v1
            readers = installed_readers_for_operation_v1(graph, witness.operation, scope=witness.scope,
                owner_guard=evidence.owner_guard, foreground_issuance=issued)
            verify_foreground_cycle_stage_v1(db, witness.stage, readers)
            if witness.stage.stage.proposals != bundle.proposals:
                raise ValueError("foreground job bundle differs from its pure frozen proposal")
            _FOREGROUND_VALIDATED[id(witness)] = witness
            return witness
        from .d11_life_preparation_v1 import LifePreparationStageV1, verify_life_preparation_in_transaction_v1
        if type(witness.stage) is LifePreparationStageV1:
            from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
            verify_life_preparation_in_transaction_v1(db, witness.stage,
                issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
            if life_preparation_bundle_v1(graph, witness.stage) != bundle:
                raise ValueError("foreground draft Life preparation changed its actual job-only bundle")
            return witness
        frame, stage, _ = witness.runtime.compile_foreground_in_transaction(db, operation=witness.operation,
            request=witness.request, envelope=witness.frame.envelope, scope=witness.scope, issued=issued,
            now_utc=witness.frame.now_utc, external_originals=witness.external_originals)
        if frame != witness.frame or stage != witness.stage:
            raise ValueError("foreground exact stage changed at final Graph CAS")
        from .artifact_continuation_originals_v1 import ExistingArtifactRevisionStageV1
        from .artifact_task_observer_v1 import ArtifactTaskSettlementStageV1
        from .d08_personal_plan_v1 import ArtifactTaskPlanRevisionStageV2
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeStageV1
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV1, ArtifactDraftModelStageV2, validate_artifact_draft_model_proposal_v1
        from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2, validate_artifact_draft_content_job_proposal_v1
        from .d07_ingress_recall_acquisition_v1 import D07IngressRecallAcquisitionStageV1
        from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1
        if type(stage) in {D07IngressRecallAcquisitionStageV1, D07IngressRecallResultStageV1}:
            if stage.stage.proposals != bundle.proposals:
                raise ValueError("Self C3 acquisition changed its pure once job proposal")
            _FOREGROUND_VALIDATED[id(witness)] = witness
        elif type(stage) is IngressArtifactTaskScopeStageV1:
            if _members(stage)[1] != bundle.proposals:
                raise ValueError("Self task scope changed its exact D10/D08 bundle")
        elif type(stage) in {ArtifactTaskSettlementStageV1, ArtifactTaskPlanRevisionStageV2}:
            if _members(stage)[1] != bundle.proposals:
                raise ValueError("artifact task changed its exact same-W01 D08/D10 bundle")
        elif type(stage) is ExistingArtifactRevisionStageV1:
            if (*stage.stage.proposals, *stage.d10_stage.proposals) != bundle.proposals:
                raise ValueError("artifact amendment changed its exact shared D08/D10 bundle")
        elif type(stage) in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2}:
            for proposal in stage.stage.proposals:
                validate_artifact_draft_model_proposal_v1(proposal, frame.snapshot, stage)
            if stage.stage.proposals != bundle.proposals:
                raise ValueError("C4 model bundle differs from its exact privately rebuilt stage")
            _FOREGROUND_VALIDATED[id(witness)] = witness
        elif type(stage) in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2}:
            for proposal in stage.stage.proposals:
                if proposal.domain == "d11":
                    validate_artifact_draft_content_job_proposal_v1(proposal, frame.snapshot, stage)
            if stage.stage.proposals != bundle.proposals:
                raise ValueError("C4 content bundle differs from its exact privately rebuilt stage")
            _FOREGROUND_VALIDATED[id(witness)] = witness
        elif type(stage) is ArtifactDraftPhaseVerificationStageV2:
            if stage.stage.proposals != bundle.proposals:
                raise ValueError("phase verification changed its actual no-write W01 stage")
            _FOREGROUND_VALIDATED[id(witness)] = witness
        return witness
    from .cancel_owner_source_note_task_v1 import CancelOwnerSourceNoteTaskStageV1,verify_cancel_owner_source_note_task_stage_v1
    if type(witness.stage) is CancelOwnerSourceNoteTaskStageV1:
        frame,stage,_=witness.runtime.compile_in_transaction(db,operation=witness.operation,
            request=witness.request,envelope=witness.frame.envelope,scope=witness.scope,
            owner=witness.owner,guard=witness.guard,now_utc=witness.frame.now_utc,
            external_originals=witness.external_originals)
        if frame!=witness.frame or stage!=witness.stage or stage.stage.proposals!=bundle.proposals:
            raise ValueError('Owner task cancellation changed before actual Graph CAS')
        verify_cancel_owner_source_note_task_stage_v1(stage)
        _FOREGROUND_VALIDATED[id(witness)]=witness
        return witness
    # Rebuild before jobs/projections are staged; the concrete runtime froze it
    # under this exact independently validated write permit, with all policies
    # and current originals. Rechecking its full frozen readset below remains a
    # separate Graph CAS and never grants a model/native/platform execution.
    from .d07_execution_v1 import D07PreparationStageV1
    from .d10_offline_tick_execution_v1 import D10OfflineTickPreparationStageV1
    from .d11_life_preparation_v1 import LifePreparationStageV1
    from .contact_product_adapter_v1 import ContactModelStageV1
    from .contact_product_adapter_v2 import ContactModelStageV2
    from .d11_method_observation_v1 import MethodObservationStageV1
    from .internal_life_content_preparation_v1 import InternalLifeContentPreparationStageV1,verify_internal_life_content_preparation_in_transaction_v1
    from .internal_life_content_worker_v1 import InternalLifeContentAcquisitionStageV1
    from .internal_life_content_adoption_v1 import InternalLifeContentAdoptionStageV1,verify_content_stage_v1,content_bundle_v1
    from .d06_life_numeric_commit_v1 import _numeric_stage_types, require_exact_life_numeric_task_issuance_v1, verify_life_numeric_task_commit_v1
    if type(witness.stage) in _numeric_stage_types():
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        require_exact_life_numeric_task_issuance_v1(witness, graph, bundle)
        readers = installed_readers_for_operation_v1(graph, witness.operation,
            scope=witness.scope, owner_guard=witness.guard)
        verify_life_numeric_task_commit_v1(db, witness, readers)
        return witness
    from .d06_life_numeric_commit_v1 import life_numeric_math_stages_v1, require_exact_life_numeric_math_issuance_v1, verify_life_numeric_math_stage_v1
    if type(witness.stage) in life_numeric_math_stages_v1():
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        require_exact_life_numeric_math_issuance_v1(witness, graph, bundle)
        readers = installed_readers_for_operation_v1(graph, witness.operation,
            scope=witness.scope, owner_guard=witness.guard)
        verify_life_numeric_math_stage_v1(db, witness.stage, readers)
        return witness
    from .d06_life_numeric_context_v1 import LifeNumericContextStageV1, verify_life_numeric_context_stage_v1
    if type(witness.stage) is LifeNumericContextStageV1:
        from .d06_life_numeric_commit_v1 import require_exact_life_numeric_context_issuance_v1
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        require_exact_life_numeric_context_issuance_v1(witness, graph, bundle)
        readers = installed_readers_for_operation_v1(graph, witness.operation,
            scope=witness.scope, owner_guard=witness.guard)
        verify_life_numeric_context_stage_v1(db, witness.stage, installed_readers=readers)
    elif type(witness.stage) is InternalLifeContentAdoptionStageV1:
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        verify_content_stage_v1(db,witness.stage,readers,witness.request)
        if content_bundle_v1(witness.stage)!=bundle:raise ValueError('Life content actual four-member bundle changed')
    elif type(witness.stage) is InternalLifeContentAcquisitionStageV1:
        from .internal_life_content_worker_v1 import verify_internal_life_acquisition_in_transaction_v1, internal_life_acquisition_bundle_v1
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers = installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        verify_internal_life_acquisition_in_transaction_v1(db,witness.stage,readers)
        if internal_life_acquisition_bundle_v1(witness.stage) != bundle:
            raise ValueError('Life exact current acquired bundle differs')
    elif type(witness.stage) is InternalLifeContentPreparationStageV1:
        from .internal_life_content_commit_v1 import internal_life_content_preparation_bundle_v1
        from .domain_production_registry_v1 import installed_readers_for_operation_v1
        readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
        verify_internal_life_content_preparation_in_transaction_v1(db,witness.stage,readers,readers.life_content_bundle)
        if internal_life_content_preparation_bundle_v1(witness.stage)!=bundle:
            raise ValueError('Life exact independently checked preparation bundle differs')
    elif type(witness.stage) is D07PreparationStageV1:
        service = getattr(graph, '_GraphCoordinator__d07_execution_service_v1', None)
        if service is None:
            raise ValueError('actual D07 installed service disappeared')
        service.verify_preparation_in_transaction_v1(db, witness.stage)
        if _d07_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('D07 exact independently reissued preparation bundle differs')
    elif type(witness.stage) is D10OfflineTickPreparationStageV1:
        from .d10_offline_tick_execution_v1 import verify_offline_preparation_in_transaction_v1
        from .d11_offline_preparation_commit_v1 import offline_preparation_bundle_v1
        verify_offline_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        if offline_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('offline current prepared bundle differs')
    elif type(witness.stage) is LifePreparationStageV1:
        from .d11_life_preparation_v1 import verify_life_preparation_in_transaction_v1
        from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
        if type(witness.stage) is not LifePreparationStageV1:
            raise TypeError('exact installed Life preparation stage required')
        verify_life_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        if life_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('Life current prepared bundle differs')
    elif type(witness.stage) is MethodObservationStageV1:
        from .d11_method_observation_v1 import install_method_observation_readers_v1, stage_observe_method_comparison_v1
        readers = install_method_observation_readers_v1(graph, scope=witness.scope,
            owner_guard=witness.guard, owner_binding=witness.owner)
        rebuilt = stage_observe_method_comparison_v1(db, frame=witness.frame, request=witness.request, installed_readers=readers)
        if rebuilt != witness.stage or _members(rebuilt)[1] != bundle.proposals:
            raise ValueError("actual method measurement Source and billing support changed before CAS")
    elif type(witness.stage) is ContactModelStageV2:
        from .contact_product_adapter_v2 import verify_contact_model_preparation_in_transaction_v2
        from .contact_model_preparation_commit_v2 import contact_model_preparation_bundle_v2
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError('actual installed Contact V2 model assembly disappeared')
        verify_contact_model_preparation_in_transaction_v2(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            installed_bundle=assembly.admin_bundle)
        if contact_model_preparation_bundle_v2(graph, witness.stage) != bundle:
            raise ValueError('Contact V2 current prepared bundle differs')
    elif type(witness.stage) is ContactModelStageV1:
        from .contact_product_adapter_v1 import verify_contact_model_preparation_in_transaction_v1
        from .contact_model_preparation_commit_v1 import contact_model_preparation_bundle_v1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError('actual installed contact model assembly disappeared')
        verify_contact_model_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            installed_bundle=assembly.admin_bundle)
        if contact_model_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('contact current prepared bundle differs')
    else:
        from .contact_plan_adoption_v2 import ContactPlanStageV2,stage_adopt_current_contact_expression_plan_in_transaction_v2
        from .d06_internal_life_episode_v2 import InternalLifeEpisodeStageV2
        if type(witness.stage) is ContactPlanStageV2:
            from .domain_production_registry_v1 import installed_readers_for_operation_v1
            readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=witness.guard)
            readers.contact_policy_scope=witness.scope
            readers.current_contact_policy=getattr(witness.runtime,'_active_current_contact_policy_v1',None)
            rebuilt=stage_adopt_current_contact_expression_plan_in_transaction_v2(db,frame=witness.frame,
                request=witness.request,installed_readers=readers)
            if rebuilt!=witness.stage:
                raise ValueError('Contact Plan v2 actual SQL qualification changed before CAS')
        elif type(witness.stage) is InternalLifeEpisodeStageV2:
            from .d06_structured_experience_v1 import stage_encode_current_structured_experience_in_transaction_v1
            from .domain_production_registry_v1 import installed_readers_for_operation_v1
            readers = installed_readers_for_operation_v1(graph, witness.operation,
                scope=witness.scope, owner_guard=witness.guard)
            rebuilt = stage_encode_current_structured_experience_in_transaction_v1(db, frame=witness.frame,
                request=witness.request, installed_readers=readers)
            if rebuilt != witness.stage:
                raise ValueError('internal Life episode actual SQL qualification changed before CAS')
        elif witness.frame.envelope != bundle.envelope:
            raise ValueError('installed domain witness envelope differs')
    return witness


def _members(stage):
    from .habit_schedule_driver_v1 import HabitScheduleStageV1
    if type(stage)is HabitScheduleStageV1:return stage.stage,stage.stage.proposals,(),(),()
    from .owner_material_source_storage_v3 import StagedDomainOperationV3
    if type(stage) is StagedDomainOperationV3:
        stage.prepared.require_current()
        return stage,stage.proposals,(),(),()
    from .cancel_owner_source_note_task_v1 import CancelOwnerSourceNoteTaskStageV1,verify_cancel_owner_source_note_task_stage_v1
    if type(stage) is CancelOwnerSourceNoteTaskStageV1:
        verify_cancel_owner_source_note_task_stage_v1(stage)
        return stage.stage,stage.stage.proposals,(),(),()
    from .owner_source_note_task_execution_v1 import OwnerSourceNoteTaskStageV1,verify_owner_source_note_task_stage_v1
    if type(stage) is OwnerSourceNoteTaskStageV1:
        verify_owner_source_note_task_stage_v1(stage)
        return stage.stage,stage.stage.proposals,(),(),()
    from .d11_method_observation_v1 import MethodObservationStageV1, verify_method_observation_stage_v1
    if type(stage) is MethodObservationStageV1:
        verify_method_observation_stage_v1(stage)
        return stage.stage, (*stage.stage.proposals, *stage.memory_stage.proposals), (), (), ()
    from .artifact_task_observer_v1 import ArtifactTaskSettlementStageV1
    from .d08_personal_plan_v1 import ArtifactTaskPlanRevisionStageV2
    if type(stage) in {ArtifactTaskSettlementStageV1, ArtifactTaskPlanRevisionStageV2}:
        return stage.stage,(*stage.stage.proposals,*stage.checkpoint_stage.proposals),(),(),()
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeStageV1
    if type(stage) is IngressArtifactTaskScopeStageV1:
        amendment=() if stage.amendment_stage is None else stage.amendment_stage.proposals
        return stage.stage, (*stage.stage.proposals,*stage.goal_stage.proposals,*amendment), (), (), ()
    from .artifact_continuation_originals_v1 import ExistingArtifactRevisionStageV1
    if type(stage) is ExistingArtifactRevisionStageV1:
        return stage.stage, (*stage.stage.proposals, *stage.d10_stage.proposals), (), (), ()
    from .c04_ingress_preparation_v4 import SelfC04PreparationStageV4
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4
    if type(stage) in {SelfC04PreparationStageV4, SelfC04AdoptionStageV4}:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1
    if type(stage) is D07IngressRecallResultStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d07_ingress_recall_acquisition_v1 import D07IngressRecallAcquisitionStageV1
    if type(stage) is D07IngressRecallAcquisitionStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d07_ingress_recall_preparation_v1 import D07IngressRecallPreparationStageV1
    if type(stage) is D07IngressRecallPreparationStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(stage) is LifePreparationStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .owner_stop_reply_v1 import OwnerStopReplyProjectionStageV1
    if type(stage) is OwnerStopReplyProjectionStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV1, ArtifactDraftModelStageV2
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2
    if type(stage) in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2, ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2}:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .foreground_cycle_v1 import ForegroundCycleStageV1
    if type(stage) is ForegroundCycleStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d06_life_numeric_commit_v1 import life_numeric_math_stages_v1
    if type(stage) in life_numeric_math_stages_v1():
        return stage.primary_stage, stage.primary_stage.proposals, (), (), ()
    from .d06_life_numeric_context_v1 import LifeNumericContextStageV1
    if type(stage) is LifeNumericContextStageV1:
        return stage.primary_stage, stage.proposals, (), (), ()
    from .contact_plan_adoption_v2 import ContactPlanStageV2,verify_contact_plan_stage_v2
    if type(stage) is ContactPlanStageV2:
        verify_contact_plan_stage_v2(stage)
        return stage.stage,stage.stage.proposals,(),(),()
    from .d06_internal_life_episode_v2 import InternalLifeEpisodeStageV2
    if type(stage) is InternalLifeEpisodeStageV2:
        return stage.stage, stage.stage.proposals, stage.episode_refs, (), ()
    from .contact_plan_adoption_v1 import ContactPlanStageV1
    if type(stage) is ContactPlanStageV1:
        from .contact_product_adapter_v1 import verify_contact_plan_stage_v1
        verify_contact_plan_stage_v1(stage)
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d08_source_note_action_v1 import SourceNoteActionStageV1
    from .d02_life_body_preparation_v1 import LifeBodyPreparationStageV1
    if type(stage) is SourceNoteActionStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    if type(stage) is LifeBodyPreparationStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from ..domains.d06.structured_experience_v1 import StructuredExperienceBundleV1
    from ..domains.d10.production_operations_v1 import CurrentLifeEffectExperienceBundleV1
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from .d11_host_lifecycle_v1 import HostLifecycleStageV1
    if type(stage) is HostLifecycleStageV1:
        return stage.stage, (*stage.stage.proposals, stage.memory_proposal), (stage.original.source_ref,), (), ()
    if type(stage) is StagedDomainInputV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    if type(stage) is StagedDomainOperationV1:
        return stage, stage.proposals, (), (), ()
    if type(stage) is CurrentLifeEffectExperienceBundleV1:
        return (stage.life_stage, (*stage.life_stage.proposals, *stage.body_stage.proposals, stage.memory_proposal),
            stage.experience_refs, stage.d02_settlement_refs, stage.d11_cost_settlement_refs)
    if type(stage) is StructuredExperienceBundleV1:
        return stage.memory_stage, (*stage.memory_stage.proposals, stage.context_proposal), stage.episode_refs, (), ()
    raise TypeError('registered operation returned an unrecognized concrete stage')


def commit_installed_domain_operation_v1(runtime, db, *, operation, request, frame, stage,
        readers, scope, owner, guard, metadata, epoch, process_lease, external_originals=()):
    from .d07_source_owner_read_v3 import require_d07_source_stage_v3
    require_d07_source_stage_v3(db,stage)
    from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_stage_v3
    require_current_d07_simulation_stage_v3(db,stage)
    if runtime._active_habit_issuance_v1 is not None:
        from .habit_activity_runtime_v1 import require_current_habit_commit_v1
        require_current_habit_commit_v1(runtime,db,operation=operation,request=request,frame=frame,stage=stage,scope=scope)
    from .c04_ingress_preparation_v4 import SelfC04PreparationStageV4, commit_self_c04_prepare_v4
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4, commit_self_c04_adopt_v4
    if type(stage) in {SelfC04PreparationStageV4, SelfC04AdoptionStageV4}:
        commit = commit_self_c04_prepare_v4 if type(stage) is SelfC04PreparationStageV4 else commit_self_c04_adopt_v4
        return commit(runtime, db, operation=operation, request=request, frame=frame, stage=stage,
            readers=readers, scope=scope, metadata=metadata, epoch=epoch, process_lease=process_lease,
            owner=owner, guard=guard, external_originals=external_originals)
    graph = runtime.graph
    from .d07_ingress_recall_preparation_v1 import D07IngressRecallPreparationStageV1, commit_ingress_recall_preparation_v1
    if type(stage) is D07IngressRecallPreparationStageV1:
        return commit_ingress_recall_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d06_life_numeric_joint_v1 import LifeNumericJointStageV1
    if type(stage) is LifeNumericJointStageV1:
        from .d06_life_numeric_commit_v1 import commit_life_numeric_joint_stage_v1
        return commit_life_numeric_joint_stage_v1(runtime, db, stage=stage, operation=operation,
            frame=frame, scope=scope, metadata=metadata, epoch=epoch)
    from .d06_life_numeric_commit_v1 import _numeric_stage_types, commit_life_numeric_task_v1
    if type(stage) in _numeric_stage_types():
        return commit_life_numeric_task_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .internal_life_content_adoption_v1 import InternalLifeContentAdoptionStageV1,commit_content_adoption_v1
    if type(stage) is InternalLifeContentAdoptionStageV1:
        return commit_content_adoption_v1(runtime,db,operation=operation,request=request,preparation=stage,
            readers=readers,scope=scope,owner=owner,guard=guard,metadata=metadata,epoch=epoch,
            process_lease=process_lease,external_originals=external_originals)
    from .internal_life_content_worker_v2 import InternalLifeContentAcquisitionStageV2, commit_internal_life_acquisition_v2
    if type(stage) is InternalLifeContentAcquisitionStageV2:
        return commit_internal_life_acquisition_v2(runtime,db,operation=operation,request=request,
            preparation=stage,readers=readers,scope=scope,owner=owner,guard=guard,
            metadata=metadata,epoch=epoch,process_lease=process_lease,external_originals=external_originals)
    from .internal_life_content_worker_v1 import InternalLifeContentAcquisitionStageV1, commit_internal_life_acquisition_v1
    if type(stage) is InternalLifeContentAcquisitionStageV1:
        return commit_internal_life_acquisition_v1(runtime,db,operation=operation,request=request,
            preparation=stage,readers=readers,scope=scope,owner=owner,guard=guard,
            metadata=metadata,epoch=epoch,process_lease=process_lease,external_originals=external_originals)
    from .internal_life_content_preparation_v1 import InternalLifeContentPreparationStageV1
    if type(stage) is InternalLifeContentPreparationStageV1:
        from .internal_life_content_commit_v1 import commit_internal_life_content_preparation_v1
        return commit_internal_life_content_preparation_v1(runtime,db,operation=operation,request=request,
            preparation=stage,readers=readers,scope=scope,owner=owner,guard=guard,
            metadata=metadata,epoch=epoch,process_lease=process_lease,external_originals=external_originals)
    from .contact_final_stage_v1 import ContactFinalStageV1, commit_contact_final_stage_v1
    if type(stage) is ContactFinalStageV1:
        return commit_contact_final_stage_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .contact_final_stage_v2 import ContactFinalStageV2, commit_contact_final_stage_v2
    if type(stage) is ContactFinalStageV2:
        return commit_contact_final_stage_v2(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .contact_final_stage_v3 import ContactFinalStageV3, commit_contact_final_stage_v3
    if type(stage) is ContactFinalStageV3:
        return commit_contact_final_stage_v3(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .contact_product_adapter_v2 import ContactModelStageV2
    if type(stage) is ContactModelStageV2:
        from .contact_model_preparation_commit_v2 import commit_contact_model_preparation_v2
        return commit_contact_model_preparation_v2(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .contact_product_adapter_v1 import ContactModelStageV1
    if type(stage) is ContactModelStageV1:
        from .contact_model_preparation_commit_v1 import commit_contact_model_preparation_v1
        return commit_contact_model_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(stage) is LifePreparationStageV1:
        from .d11_life_preparation_commit_v1 import commit_life_preparation_v1
        return commit_life_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d10_offline_tick_execution_v1 import D10OfflineTickPreparationStageV1
    if type(stage) is D10OfflineTickPreparationStageV1:
        from .d11_offline_preparation_commit_v1 import commit_offline_preparation_v1
        return commit_offline_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d07_execution_v1 import D07PreparationStageV1
    if type(stage) is D07PreparationStageV1:
        return commit_d07_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    # Pure/current readers are replayed from the same real DB before any new
    # projection row. A caller cannot pass a prebuilt proposal as authorization.
    owner_task=getattr(runtime,'_active_owner_task_issuance_v1',None)
    issued = getattr(runtime, "_active_foreground_issuance_v1", None)
    from .owner_material_source_storage_v3 import (
        StagedDomainOperationV3,require_owner_material_sealed_stage_v3,
    )
    from .named_joint_binding_write_v1 import current_named_joint_write_v1,rebuild_named_joint_stage_v1
    if current_named_joint_write_v1(runtime)is not None:
        rebuilt_frame,rebuilt,_=rebuild_named_joint_stage_v1(runtime,db,operation=operation,request=request,frame=frame,scope=scope)
    elif runtime._active_habit_issuance_v1 is not None:
        rebuilt_frame=frame
        rebuilt=_rebuild_current_habit_stage_v1(runtime,db,operation=operation,request=request,frame=frame,stage=stage,scope=scope)
    elif type(stage) is StagedDomainOperationV3:
        if owner_task is not None or issued is not None:
            raise ValueError('Owner Source preparation cannot borrow foreground/task issuance')
        require_owner_material_sealed_stage_v3(
            stage,runtime,db,frame=frame,request=request,scope=scope,
            installed_readers=readers)
        rebuilt_frame,rebuilt=frame,stage
    elif operation.operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import verify_contact_prospective_stage_v1
        verify_contact_prospective_stage_v1(db,frame=frame,request=request,installed_readers=readers,stage=stage)
        rebuilt_frame,rebuilt=frame,stage
    elif owner_task is not None:
        if issued is not None:raise ValueError('Owner task and foreground issuances overlap')
        rebuilt_frame,rebuilt,_=runtime.compile_owner_task_in_transaction_v1(db,operation=operation,request=request,
            envelope=frame.envelope,scope=scope,issued=owner_task,now_utc=frame.now_utc,external_originals=external_originals)
    elif issued is not None:
        rebuilt_frame, rebuilt, _ = runtime.compile_foreground_in_transaction(db, operation=operation, request=request,
            envelope=frame.envelope, scope=scope, issued=issued, now_utc=frame.now_utc, external_originals=external_originals)
    else:
        rebuilt_frame, rebuilt, _ = runtime.compile_in_transaction(db, operation=operation, request=request,
            envelope=frame.envelope, scope=scope, owner=owner, guard=guard,
            now_utc=frame.now_utc, external_originals=external_originals)
    if rebuilt_frame != frame or rebuilt != stage:
        raise ValueError('current installed domain stage changed before atomic adoption')
    from .d02_life_body_preparation_v1 import LifeBodyPreparationStageV1, issue_life_body_quotes_before_cas_v1
    if type(stage) is LifeBodyPreparationStageV1:
        issue_life_body_quotes_before_cas_v1(db, frame=frame, staged=stage, installed_readers=readers)
    primary, proposals, experiences, settlements, paid_costs = _members(stage)
    if type(primary) is StagedDomainOperationV1:
        from .domain_mesh_tick_v1 import verify_semantic_mesh_composition_v1
        verify_semantic_mesh_composition_v1(db,frame=frame,stage=primary)
    if any(job.phase != 'waiting' or job.lease_holder is not None or job.fence or job.cancel_epoch
            or job.resource_ref != 'resource:unallocated' for job in primary.jobs):
        raise ValueError('pure domain staging can only persist unallocated waiting work')
    # Actual paid originals were independently reread by the fixed operation
    # reader. Referencing them here never settles them a second time.
    if paid_costs and not set(paid_costs) <= {value.original_ref for value in primary.paid_cost_originals}:
        raise ValueError('composite domain stage lacks its exact existing paid originals')
    job_writes = tuple(job_graph_write(job) for job in primary.jobs)
    if not set(write.key for write in job_writes) <= {v.key for v in frame.snapshot.versions}:
        raise ValueError('waiting job absence was not part of the original complete readset')
    for job, write in zip(primary.jobs, job_writes, strict=True):
        create_job(db, job, 'domain-wait:' + canonical_digest((primary.namespace, primary.operation_id, job.job_id))[:48],
            canonical_digest((primary.original_digest, job)))
        reconcile_runtime_write(db, write)
    if job_writes:
        provider = D11RuntimeProvider()
        proposals += (DomainProposal('d11', D11_PROPOSAL_SCHEMA, provider.descriptor.request_schema_hash,
            frame.envelope, job_writes, DependencySet(), (), ()),)
    if not proposals:
        registration = graph._GraphCoordinator__providers[operation.domain]
        proposals = (DomainProposal(operation.domain, registration[1], registration[2], frame.envelope,
            (), DependencySet(), (), ()),)
    bundle = DomainBundle(frame.envelope, tuple(proposals), experiences, (), settlements, (),
        (primary.operation_id,), tuple(write.key.token for write in job_writes), ())
    from .foreground_cycle_v1 import ForegroundCycleStageV1
    from .d07_ingress_recall_acquisition_v1 import D07IngressRecallAcquisitionStageV1
    from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1
    if type(stage) in {ForegroundCycleStageV1, D07IngressRecallAcquisitionStageV1, D07IngressRecallResultStageV1}:
        bundle = replace(bundle, persistent_job_refs=() if stage.after_job is None else (job_graph_write(stage.after_job).key.token,))
    from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV1, ArtifactDraftModelStageV2
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2
    if type(stage) in {ArtifactDraftModelStageV1, ArtifactDraftModelStageV2}:
        jobs = (stage.job,) if stage.after_cycle is None else (stage.job, stage.after_cycle)
        bundle = replace(bundle, persistent_job_refs=tuple(job_graph_write(job).key.token for job in jobs))
    elif type(stage) in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2}:
        bundle = replace(bundle, persistent_job_refs=(job_graph_write(stage.after_job).key.token,))
    from .owner_stop_reply_v1 import OwnerStopReplyProjectionStageV1
    if type(stage) is OwnerStopReplyProjectionStageV1:
        bundle = replace(bundle, persistent_job_refs=tuple(job_graph_write(job).key.token for job in stage.after_jobs))
    from .owner_source_note_task_execution_v1 import OwnerSourceNoteTaskStageV1
    if type(stage) is OwnerSourceNoteTaskStageV1:
        bundle=replace(bundle,persistent_job_refs=(job_graph_write(stage.after_job).key.token,))
    from .cancel_owner_source_note_task_v1 import CancelOwnerSourceNoteTaskStageV1
    if type(stage) is CancelOwnerSourceNoteTaskStageV1:
        bundle=replace(bundle,persistent_job_refs=(job_graph_write(stage.after_job).key.token,))
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, frame, stage, operation, request,
        owner, guard, bundle, tuple(external_originals))
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    finish_id = 'finish:' + scope.operation_id
    attempt = db.execute('SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*primary.namespace.as_tuple, primary.operation_id)).fetchone()
    if attempt is None or attempt[1] != scope.operation_id:
        raise ValueError('actual Owner operation original is absent')
    owner_task=getattr(runtime,'_active_owner_task_issuance_v1',None)
    issued = getattr(runtime, "_active_foreground_issuance_v1", None)
    from .conditioned_child_write_v1 import current_conditioned_child_write_v1
    conditioned=current_conditioned_child_write_v1(runtime)
    if conditioned is not None:
        from .conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
        from ..authority_service.conditioned_child_contract_v1 import conditioned_child_finish_digest_v1
        selector=conditioned[2];child=conditioned[3]
        evidence=require_conditioned_child_issuance_v1(child,graph,scope)
        if(owner_task is not None or issued is not None or runtime._active_habit_issuance_v1 is not None
                or evidence.selector!=selector or attempt!=(canonical_digest(selector),scope.operation_id)):
            raise ValueError('conditioned actual W01 attempt changed its private issued selector or borrowed another writer')
        finish_digest=conditioned_child_finish_digest_v1(selector,scope.permit)
    elif runtime._active_habit_issuance_v1 is not None:
        from .habit_control_issuance_v1 import (require_habit_control_issuance_v1 as require_habit_activity_issuance_v1,
            habit_control_request_digest_v1 as habit_activity_request_digest_v1,
            habit_control_finish_digest_v1 as habit_activity_finish_digest_v1)
        habit=runtime._active_habit_issuance_v1
        evidence=require_habit_activity_issuance_v1(habit,graph,scope)
        saved_permit=db.execute('SELECT permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',(*primary.namespace.as_tuple,primary.operation_id)).fetchone()
        if owner_task is not None or issued is not None or attempt[0]!=habit_activity_request_digest_v1(evidence.request)or attempt[1]!=evidence.request.operation_id or saved_permit!=(canonical_json(to_wire(scope.permit)),):raise ValueError('Habit original attempt changed its full selector, exact same permit or independent issuance')
        finish_digest=habit_activity_finish_digest_v1(habit,graph,scope)
    elif current_named_joint_write_v1(runtime)is not None:
        from .named_joint_binding_issuance_v1 import require_named_joint_issuance_v1,named_joint_finish_digest_v1
        named=current_named_joint_write_v1(runtime);reader,named_issued,named_scope,named_frame=named
        evidence=require_named_joint_issuance_v1(named_issued,graph,scope)
        if(owner_task is not None or issued is not None or scope is not named_scope or frame is not named_frame
                or attempt[:2]!=(canonical_digest(evidence.request),evidence.request.operation_id)):
            raise ValueError('Named Joint actual W01 attempt changed its private selector or Scope')
        finish_digest=named_joint_finish_digest_v1(evidence.request,scope.permit)
    elif owner_task is not None:
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        evidence=require_owner_source_note_task_issuance_v1(owner_task,graph,scope)
        if attempt[0]!=canonical_digest(evidence.request):
            raise ValueError('Owner task original attempt changed its exact selector')
        finish_digest=owner_task_domain_finish_digest_v1(evidence.request,scope.permit)
    elif issued is not None:
        from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
        evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
        if attempt[0] != canonical_digest(evidence.request):
            raise ValueError("foreground original attempt does not bind its full actual selector")
        finish_digest = foreground_domain_finish_digest_v1(evidence.request, scope.permit)
    else:
        finish_digest = 'sha256:' + canonical_digest({'schema': 'w01.owner-domain-write.v3',
            'operation_id': primary.operation_id, 'request_digest': attempt[0], 'permit_token': scope.permit.token})
    general_original=None
    general_produced=()
    numeric_trace_produced=None
    numeric_encoding_produced=None
    numeric_drive_produced=None
    _ACTIVE[id(witness)] = witness
    try:
        from .d07_general_growth_attention_v1 import capture_actual_general_growth_outcome_before_cas_v1
        general_growth_capture = capture_actual_general_growth_outcome_before_cas_v1(witness, db)
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, finish_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=frame.now_utc, domain_production_issuance_v1=witness)
        if type(stage) in {CancelOwnerSourceNoteTaskStageV1, OwnerSourceNoteTaskStageV1, ForegroundCycleStageV1, D07IngressRecallAcquisitionStageV1, D07IngressRecallResultStageV1, ArtifactDraftModelStageV1, ArtifactDraftModelStageV2, ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, ArtifactDraftPhaseVerificationStageV2, OwnerStopReplyProjectionStageV1} and _FOREGROUND_APPLIED.get(id(witness)) is not witness:
            raise ValueError("foreground actual W01 guard did not apply its frozen job stage")
        from .habit_schedule_driver_v1 import HabitScheduleStageV1
        if type(stage)is HabitScheduleStageV1 and _FOREGROUND_APPLIED.get(id(witness))is not witness:raise ValueError('Habit actual W01 guard did not apply its exact subscription mirrors')
        if conditioned is not None:
            conditioned_original=record_adopted_domain_operation_v1(db,primary,receipt)
            if conditioned[2].phase=='child':
                from .current_conditioned_self_read_v3 import record_conditioned_followup_child_disposition_after_cas_v3
                record_conditioned_followup_child_disposition_after_cas_v3(witness,db,frame=frame,stage=primary,
                    receipt=receipt,original=conditioned_original)
        from .joint_window_management_v1 import record_joint_window_management_after_cas_v1
        record_joint_window_management_after_cas_v1(db,witness=witness,primary=primary,receipt=receipt,issuer=graph._GraphCoordinator__d11_issuer)
        from .d10_habit_v1 import record_habit_managed_execution_after_cas_v1
        record_habit_managed_execution_after_cas_v1(db,witness=witness,primary=primary,receipt=receipt,issuer=graph._GraphCoordinator__d11_issuer)
        from .d06_life_numeric_drive_v1 import LifeNumericDriveStageV1,bind_active_numeric_drive_inputs_v3
        if type(stage)is LifeNumericDriveStageV1:
            from .d06_life_numeric_commit_v1 import record_life_numeric_math_stage_v1
            with bind_active_numeric_drive_inputs_v3(db,witness=witness,receipt=receipt):
                numeric_drive_produced=record_life_numeric_math_stage_v1(db,stage,readers.issuer,receipt,drive_commit_witness_v3=witness)
        from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1
        if type(stage)is LifeEncodingBaselineStageV1:
            from .c04_encoding_context_original_v3 import bind_actual_w01_life_encoding_inputs_v3
            from .d06_life_numeric_commit_v1 import record_life_numeric_math_stage_v1,require_current_life_encoding_write_v3
            require_current_life_encoding_write_v3(db,witness=witness,stage=stage,receipt=receipt)
            with bind_actual_w01_life_encoding_inputs_v3(db,witness=witness,receipt=receipt):
                numeric_encoding_produced=record_life_numeric_math_stage_v1(db,stage,readers.issuer,receipt,
                    encoding_commit_witness_v3=witness)
        from .d06_life_numeric_trace_v1 import LifeNumericTraceStageV1
        if type(stage)is LifeNumericTraceStageV1:
            from .d06_life_numeric_commit_v1 import record_life_numeric_math_stage_v1
            numeric_trace_produced=record_life_numeric_math_stage_v1(db,stage,readers.issuer,receipt,
                trace_commit_witness_v3=witness)
        if operation.operation_kind in _GENERAL_GROWTH_COMMIT_KINDS_V1 and primary.coverage=='complete':
            with _general_growth_post_cas_v1(witness,db,primary,receipt):
                general_original=record_adopted_domain_operation_v1(db,primary,receipt)
                general_produced=_record_general_growth_after_cas_v1(readers,db,witness=witness,
                    frame=frame,primary=primary,request=request,receipt=receipt)
        from .habit_followup_source_v3 import record_habit_followup_before_witness_release_v3
        record_habit_followup_before_witness_release_v3(witness,db,frame=frame,stage=primary,receipt=receipt)
    finally:
        _ACTIVE.pop(id(witness), None)
        _FOREGROUND_VALIDATED.pop(id(witness), None)
        _FOREGROUND_APPLIED.pop(id(witness), None)
        pre=_GENERAL_GROWTH_PRECAS_VALIDATED_V1.pop(id(witness),None)
        if pre is not None:pre[3].close_v1()
        _GENERAL_GROWTH_POSTCAS_V1.pop(id(witness),None)
    from .domain_production_inputs_v1 import StagedDomainInputV1, record_current_domain_input_after_commit_v1
    produced = general_produced
    if primary.operation_kind=="register_current_habit_source_note_life_plan_v1":
        from .d10_habit_v1 import record_habit_source_note_life_plan_after_cas_v1
        produced=(record_habit_source_note_life_plan_after_cas_v1(db,frame=frame,stage=primary,receipt=receipt,installed=readers),)
    from .contact_plan_adoption_v2 import ContactPlanStageV2,record_contact_plan_after_cas_v2
    if type(stage) is ContactPlanStageV2:
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        digest=record_contact_plan_after_cas_v2(db,stage=stage,issuer=readers.issuer,receipt=receipt)
        produced=(ProductionOriginalRefV1('d10.contact_plan.v2',stage.plan.contact_id,digest),)
    from .contact_plan_adoption_v1 import ContactPlanStageV1, record_contact_plan_after_cas_v1
    if type(stage) is ContactPlanStageV1:
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        digest = record_contact_plan_after_cas_v1(db, stage=stage, issuer=readers.issuer, receipt=receipt)
        produced = (ProductionOriginalRefV1("d10.contact_plan", stage.plan.contact_id, digest),)
    from .d08_source_note_action_v1 import SourceNoteActionStageV1, record_source_note_action_after_cas_v1
    from .d02_life_body_preparation_v1 import record_life_body_preparation_after_cas_v1
    if type(stage) is SourceNoteActionStageV1:
        produced = (record_source_note_action_after_cas_v1(db, frame=frame, staged=stage, receipt=receipt, issuer=readers.issuer),)
    if type(stage) is LifeBodyPreparationStageV1:
        produced = (record_life_body_preparation_after_cas_v1(db, frame=frame, staged=stage, receipt=receipt, issuer=readers.issuer),)
    from .d11_host_lifecycle_v1 import HostLifecycleStageV1, record_host_lifecycle_after_cas_v1
    if type(stage) is HostLifecycleStageV1:
        produced = (record_host_lifecycle_after_cas_v1(db, frame=frame,
            staged=stage, graph_receipt=receipt, issuer=readers.issuer),)
    if type(stage) is StagedDomainInputV1:
        produced = record_current_domain_input_after_commit_v1(db, frame=frame, staged_input=stage,
            actual_receipt=receipt, installed_readers=readers)
    from .d06_life_numeric_context_v1 import LifeNumericContextStageV1, record_life_numeric_context_after_cas_v1
    if type(stage) is LifeNumericContextStageV1:
        payload = json.loads(primary.original_payload_json)
        payload['writes'] = [{'key': write.key.token, 'value': write.value,
            'dependencies': [key.token for key in write.dependencies]}
            for proposal in stage.proposals for write in proposal.typed_writes]
        primary = replace(primary, original_payload_json=canonical_serialize(payload),
            original_digest=canonical_digest(payload))
        produced = (record_life_numeric_context_after_cas_v1(db, stage=stage,
            issuer=readers.issuer, receipt=receipt),)
    from .d06_life_numeric_commit_v1 import life_numeric_math_stages_v1, record_life_numeric_math_stage_v1
    if type(stage) in life_numeric_math_stages_v1():
        produced = ((numeric_drive_produced,) if numeric_drive_produced is not None
            else (numeric_trace_produced,) if numeric_trace_produced is not None
            else (numeric_encoding_produced,) if numeric_encoding_produced is not None
            else (record_life_numeric_math_stage_v1(db, stage, readers.issuer, receipt),))
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeStageV1
    from .artifact_task_observer_v1 import ArtifactTaskSettlementStageV1
    if type(stage) in {IngressArtifactTaskScopeStageV1,ArtifactTaskSettlementStageV1}:
        payload=json.loads(primary.original_payload_json)
        payload["writes"]=[{"key":write.key.token,"value":write.value,
            "dependencies":[key.token for key in write.dependencies]}
            for proposal in _members(stage)[1] for write in proposal.typed_writes]
        primary=replace(primary,original_payload_json=canonical_serialize(payload),original_digest=canonical_digest(payload))
    root_original = None
    if operation.operation_kind == "register_artifact_draft_root":
        from .foreground_activity_issuance_v1 import record_draft_root_registration_after_commit_v1
        root_original = record_draft_root_registration_after_commit_v1(db, graph=graph,
            issued=runtime._active_draft_root_registration_v1, frame=frame, receipt=receipt, issuer=readers.issuer)
        produced = (*produced, root_original)
    original=(general_original if general_original is not None else record_adopted_domain_operation_v1(db,primary,receipt))
    if operation.operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        from .d03_world_history_v1 import record_world_assertion_after_commit_v1
        produced=(*produced,record_world_assertion_after_commit_v1(db,stage=primary,receipt=receipt,installed_readers=readers))
    if operation.operation_kind=='prepare_contact_prospective_v1':
        from .contact_prospective_v1 import record_contact_prospective_after_commit_v1,contact_prospective_original_ref_v1,SIGN_KIND
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        birth=record_contact_prospective_after_commit_v1(db,graph=graph,stage=primary,receipt=receipt)
        produced=(*produced,ProductionOriginalRefV1(SIGN_KIND,
            contact_prospective_original_ref_v1(primary.namespace,request.contact_id,primary.operation_id),birth.digest))
    from .d07_general_growth_attention_v1 import record_actual_general_growth_outcome_after_cas_v1
    general_growth_trigger_original = record_actual_general_growth_outcome_after_cas_v1(db,
        capture=general_growth_capture, receipt=receipt, causal_original=original)
    if general_growth_trigger_original is not None:
        produced = (*produced, general_growth_trigger_original)
    from .d07_general_growth_attention_v1 import record_general_growth_attention_after_cas_v1
    general_growth_attention_original = record_general_growth_attention_after_cas_v1(db,
        frame=frame, stage=primary, receipt=receipt, issuer=graph._GraphCoordinator__d11_issuer)
    if general_growth_attention_original is not None:
        produced = (*produced, general_growth_attention_original)
    if type(stage) is CancelOwnerSourceNoteTaskStageV1:
        from .cancel_owner_source_note_task_v1 import record_cancel_owner_source_note_task_after_cas_v1
        produced=(*produced,*record_cancel_owner_source_note_task_after_cas_v1(db,frame=frame,
            stage=stage,receipt=receipt,installed_readers=readers))
    if operation.operation_kind in {'register_owner_source_note_life_plan_v1','register_owner_source_note_life_outcome_v1'}:
        from .owner_source_note_life_v1 import record_owner_source_note_life_after_cas_v1
        produced=(*produced,record_owner_source_note_life_after_cas_v1(db,frame=frame,stage=primary,
            receipt=receipt,installed_readers=readers))
    if operation.operation_kind=='input:freeze_owner_source_note_values_parent_v1':
        from .owner_source_note_values_v1 import record_owner_source_note_values_parent_after_cas_v1
        produced=(*produced,record_owner_source_note_values_parent_after_cas_v1(db,frame=frame,
            stage=primary,receipt=receipt,installed_readers=readers))
    if type(stage) is OwnerSourceNoteTaskStageV1:
        from .owner_source_note_task_execution_v1 import record_owner_source_note_task_execution_after_cas_v1
        produced=(*produced,*record_owner_source_note_task_execution_after_cas_v1(db,frame=frame,
            stage=stage,receipt=receipt,installed_readers=readers))
    from .d11_method_observation_v1 import record_method_observation_after_cas_v1
    produced = (*produced, *record_method_observation_after_cas_v1(db,
        frame=frame, stage=stage, receipt=receipt, issuer=graph._GraphCoordinator__d11_issuer))
    from .domain_production_registry_v1 import _POSTCONDITION_OPERATIONS
    if operation.operation_kind in _POSTCONDITION_OPERATIONS and primary.coverage == "complete":
        from .artifact_phase_postconditions_v1 import record_artifact_phase_postcondition_after_cas_v1
        produced = (*produced, record_artifact_phase_postcondition_after_cas_v1(db,
            frame=frame, stage=primary, receipt=receipt, issuer=readers.issuer))
    if operation.operation_kind == "register_artifact_task_milestone_v2" and primary.coverage == "complete":
        from .artifact_task_observer_v1 import record_artifact_task_milestone_after_cas_v2
        produced = (*produced, record_artifact_task_milestone_after_cas_v2(db,
            frame=frame, stage=primary, receipt=receipt, issuer=readers.issuer))
    if operation.operation_kind == "input:register_artifact_task_text_extent" and primary.coverage == "complete":
        from .artifact_task_text_extent_v1 import record_artifact_task_text_extent_after_cas_v1
        produced = (*produced, record_artifact_task_text_extent_after_cas_v1(db, frame=frame,
            stage=primary, receipt=receipt, issuer=readers.issuer))
    if operation.operation_kind == "submit_owner_source_note_task_v1" and primary.coverage == "complete":
        from .owner_source_note_task_v1 import record_owner_source_note_task_after_cas_v1
        produced = (*produced, record_owner_source_note_task_after_cas_v1(db, frame=frame,
            stage=primary, receipt=receipt, installed_readers=readers))
    if operation.operation_kind == "authorize_source_note_task_v1" and primary.coverage == "complete":
        from .source_note_task_authorization_v1 import record_source_note_task_authorization_after_cas_v1
        produced = (*produced, record_source_note_task_authorization_after_cas_v1(db, frame=frame,
            stage=primary, receipt=receipt, installed_readers=readers))
    if operation.operation_kind == "create_source_note_foreground_cycle_v1" and primary.coverage == "complete":
        from .source_note_foreground_v1 import record_source_note_responsibility_after_cas_v1
        produced = (*produced, record_source_note_responsibility_after_cas_v1(db, frame=frame,
            stage=primary, receipt=receipt, installed_readers=readers))
    if operation.operation_kind == "prepare_personal_candidates_v1" and primary.coverage == "complete":
        from .d08_personal_candidate_v1 import record_personal_candidates_after_cas_v1
        produced = (*produced, record_personal_candidates_after_cas_v1(db, frame=frame,
            stage=primary, receipt=receipt, issuer=readers.issuer))
    from .foreground_cycle_v1 import WakeArtifactDraftCycleRequestV1, WakeArtifactDraftCycleRequestV2, record_artifact_draft_wake_disposition_after_cas_v1
    if type(stage) is ForegroundCycleStageV1 and type(stage.request) in {WakeArtifactDraftCycleRequestV1, WakeArtifactDraftCycleRequestV2}:
        record_artifact_draft_wake_disposition_after_cas_v1(db, stage=stage, receipt=receipt)
    from .d06_internal_life_episode_v2 import InternalLifeEpisodeStageV2, PROVENANCE, decode_internal_life_value_v2, validate_internal_life_episode_history_v2
    if type(stage) is InternalLifeEpisodeStageV2:
        proof_write = next(write for proposal in primary.proposals for write in proposal.typed_writes if write.key.type_name == PROVENANCE)
        validate_internal_life_episode_history_v2(db, decode_internal_life_value_v2(PROVENANCE, proof_write.value))
    for event in primary.outbox:
        if (operation.operation_kind in _GENERAL_GROWTH_COMMIT_KINDS_V1
                and event.event_kind in {'general_growth_intent_available_for_future_trial',
                    'general_growth_trial_start_available_for_observation','general_growth_trial_completed_for_adoption'}):
            output_kind={'freeze_general_growth_intent_v1':'d01.general_growth_intent_v1',
                'register_general_growth_trial_start_v1':'d01.general_growth_trial_start_v1',
                'derive_general_growth_trial_v1':'d01.general_growth_trial_v1'}[operation.operation_kind]
            matches=tuple(value for value in general_produced if value.kind==output_kind)
            if len(matches)!=1:raise ValueError('General lifecycle requires its actual same-CAS signed produced input')
            event=replace(event,trigger_original=matches[0])
        if (general_growth_attention_original is not None and event.receiver_domain == "d07"
                and event.event_kind == "general_growth_attention_available_for_service"):
            event = replace(event, trigger_original=general_growth_attention_original)
        if (general_growth_trigger_original is not None and event.receiver_domain == 'd01'
                and event.event_kind == 'actual_life_outcome_available_for_growth'):
            event = replace(event, trigger_original=general_growth_trigger_original)
        if type(stage) is ArtifactTaskSettlementStageV1:
            event=replace(event,trigger_original=original)
        if root_original is not None:
            event = replace(event, trigger_original=root_original)
        row = (*primary.namespace.as_tuple, event.dedupe_key, event.causal_operation_id,
            event.receiver_domain, event.event_kind, event.trigger_original.original_ref,
            event.trigger_original.original_digest, 'pending', None, None)
        old = db.execute('SELECT * FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',
            row[:3]).fetchone()
        if old is not None and old != row:
            raise ValueError('domain followup event changed its durable identity')
        if old is None:
            db.execute('INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)', row)
    return {'schema': 'sylanne.domain-production-receipt.v1', 'domain': primary.domain,
        'operation_kind': primary.operation_kind, 'operation_id': primary.operation_id,
        'activity_id': primary.activity_id, 'original_ref': original.original_ref,
        'original_digest': original.original_digest, 'receipt': _receipt_wire(receipt),
        'receipt_digest': canonical_digest(receipt), 'job_states': [[j.job_id, j.phase] for j in
            ((stage.after_job,) if type(stage) is ForegroundCycleStageV1 else primary.jobs)],
        'coverage': primary.coverage, 'missing_inputs': list(primary.missing_inputs),
        'continuation_ref': primary.continuation_ref,
        'outbox': [event.dedupe_key for event in primary.outbox],
        'produced_originals': [{'kind': item.kind, 'original_ref': item.original_ref,
            'original_digest': item.original_digest} for item in produced]}


def _d07_preparation_bundle_v1(graph, preparation):
    from .d07_execution_v1 import D07PreparationStageV1
    if type(preparation) is not D07PreparationStageV1 or preparation.replayed:
        raise ValueError('D07 needs its actual first preparation, not a replayed DTO')
    frame, prepared = preparation.frame, preparation.prepared
    envelope = replace(frame.envelope, identity=replace(frame.envelope.identity,
        operation_id=prepared.prepare_operation_id, effect_id=None, phase='d07.cognitive.prepare.v1'))
    proposals = [replace(preparation.stage.proposal, envelope=envelope)]
    for domain, selected in (('d02', tuple(w for w in preparation.writes if w.key.type_name.startswith('d02.'))),
            ('d11', tuple(w for w in preparation.writes if w.key.type_name == 'runtime.job'))):
        registration = graph._GraphCoordinator__providers[domain]
        deps = {key for write in selected for key in write.dependencies}
        proposals.append(DomainProposal(domain, registration[1], registration[2], envelope, selected,
            DependencySet(current_invalidation=tuple(v for v in preparation.read_versions if v.key in deps)), (), ()))
    return DomainBundle(envelope, tuple(proposals), (), (), (), (), (prepared.prepare_operation_id,),
        (job_graph_write(preparation.job).key.token,), ())


def commit_d07_preparation_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from .d07_execution_v1 import record_d07_preparation_after_cas_v1
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    service = readers.execution_reader
    if service is not getattr(runtime.graph, '_GraphCoordinator__d07_execution_service_v1', None):
        raise ValueError('D07 preparation is not from this installed execution service')
    service.verify_preparation_in_transaction_v1(db, preparation)
    bundle = _d07_preparation_bundle_v1(runtime.graph, preparation)
    for write in preparation.writes:
        if write.key.type_name == 'runtime.job':
            reconcile_runtime_write(db, write)
    witness = _ProductionCommitWitnessV1(runtime, runtime.graph, scope, preparation.frame,
        preparation, operation, request, owner, guard, bundle, tuple(external_originals))
    base = preparation.prepared.operation_id
    attempt = db.execute('SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*preparation.prepared.namespace.as_tuple, base)).fetchone()
    if attempt is None or attempt[1] != scope.operation_id:
        raise ValueError('D07 original Owner operation is absent')
    finish_digest = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':base,'request_digest':attempt[0],'permit_token':scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = runtime.graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, 'finish:'+scope.operation_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
        from .d07_source_preparation_members_v3 import bind_d07_source_postcas_v3
        with bind_d07_source_postcas_v3(witness,receipt):
            original_digest = record_d07_preparation_after_cas_v1(db, service.d11_issuer, preparation, receipt)
    finally:
        _ACTIVE.pop(id(witness), None)
    return {'schema':'sylanne.domain-production-receipt.v1','domain':'d07',
        'operation_kind':operation.operation_kind,'operation_id':base,
        'prepare_operation_id':preparation.prepared.prepare_operation_id,
        'activity_id':preparation.prepared.activity_id,'original_ref':'d07-prepared:'+base,
        'original_digest':original_digest,'receipt':_receipt_wire(receipt),
        'receipt_digest':canonical_digest(receipt),'job_states':[[preparation.job.job_id,preparation.job.phase]],
        'coverage':'deferred','missing_inputs':['actual_d07_original_execution'],
        'continuation_ref':preparation.job.job_id,'outbox':[]}
