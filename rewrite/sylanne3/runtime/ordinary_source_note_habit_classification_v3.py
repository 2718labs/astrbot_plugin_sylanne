"""Positive ordinary SourceNote classification in its actual Borrowed Source Work."""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from .borrowed_habit_classification_v3 import require_borrowed_habit_metadata_eof_v3
_PROOFS=WeakKeyDictionary()
_BY_READER=WeakKeyDictionary()
_ISSUER=object()
_ORDINARY_KINDS={
    "d08.source-note-action-original.v2":"prepare_source_note_action",
    "d08.selected-source-note-action-original.v2":"prepare_selected_source_note_action_v2"}

def _reader_v3(db):
    from .current_method_learning_read_v3 import _method_active,BorrowedMethodLearningReadV3
    r=_method_active(db)
    if type(r)is not BorrowedMethodLearningReadV3 or r.operation_kind not in {"prepare_source_note_body","prepare_life"}:
        raise AuthorityUnavailable("Ordinary SourceNote requires its actual Borrowed Body/Life Work")
    require_borrowed_habit_metadata_eof_v3(r)
    return r

def _action_ref_v3(reader):
    from .d02_life_body_preparation_v1 import PrepareSourceNoteBodyRequestV1
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1,_read
    from .d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
    r=reader
    if r.operation_kind=="prepare_source_note_body":
        if type(r.request)is not PrepareSourceNoteBodyRequestV1:
            raise AuthorityUnavailable("Ordinary SourceNote Body needs its exact installed command")
        return r.request.action_intent_ref
    if type(r.request)is not PrepareCurrentLifeRequestV1:
        raise AuthorityUnavailable("Ordinary SourceNote Life needs its exact installed command")
    saved=_read(r.db,issuer=r.graph._GraphCoordinator__d11_issuer,namespace=r.namespace,
        kind="plan",ref=r.request.plan_original_ref)
    if saved is None:raise AuthorityUnavailable("Ordinary Life has no actual signed registered plan")
    plan=life_from_wire_v1(saved[0],RegisteredLifePlanV2)
    if type(plan)is not RegisteredLifePlanV2:
        raise AuthorityUnavailable("Ordinary SourceNote classification cannot stand in for an Artifact profile")
    return plan.action_intent.ref

def read_bound_ordinary_source_note_action_refs_v3(db,namespace,action_ref):
    from .current_method_learning_read_v3 import _method_active,BorrowedMethodLearningReadV3,method_graph_head_v3
    r=_method_active(db)
    if type(r)is not BorrowedMethodLearningReadV3 or r.operation_kind not in {"prepare_source_note_body","prepare_life"}:
        return False,None
    _reader_v3(db)
    if namespace!=r.namespace or action_ref!=_action_ref_v3(r):
        raise AuthorityUnavailable("Ordinary SourceNote Action locator changed its actual typed command/plan")
    key=AtomKey.from_token(action_ref)
    if NamespaceId.from_key(key)!=namespace or key.type_name!="d08.action_intent.v1":
        raise AuthorityUnavailable("Ordinary SourceNote Action crossed namespace/type")
    atom=method_graph_head_v3(db,namespace,key)
    if not atom.valid or atom.revision<1:raise AuthorityUnavailable("Ordinary SourceNote needs its actual live Action")
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row=_producer_original_point_v3(db,table="graph_history",
        columns=("event_id","valid","event_bot","event_persona","event_session"),
        key_columns=("token","revision"),key=(key.token,atom.revision),legacy_reader=lambda:None)
    if row is None or row[1:]!=(1,*namespace.as_tuple,atom.value["identity"]["activity_id"]):
        raise AuthorityUnavailable("Ordinary SourceNote Action has no actual producing history event")
    if atom.value["identity"]["operation_id"]!=row[0]:
        raise AuthorityUnavailable("Ordinary SourceNote cannot borrow another Action producer identity")
    return True,(("life-root:"+row[0],),)

def _facts_v3(reader):
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .d08_source_note_action_v1 import (require_source_note_action_original_v1,
        SourceNoteActionOriginalV1,SelectedSourceNoteActionOriginalV2)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    r=reader;metadata=require_borrowed_habit_metadata_eof_v3(r);action_ref=_action_ref_v3(r)
    if metadata.occurrences_for_action_v3(action_ref):
        raise AuthorityUnavailable("Habit managed Action cannot use ordinary SourceNote Body/Life")
    root=require_source_note_action_original_v1(r.db,namespace=r.namespace,action_intent_ref=action_ref,
        issuer=r.graph._GraphCoordinator__d11_issuer)
    if type(root)not in {SourceNoteActionOriginalV1,SelectedSourceNoteActionOriginalV2}:
        raise AuthorityUnavailable("Ordinary SourceNote requires its exact signed ordinary Action original")
    producer=read_adopted_domain_operation_v1(r.db,r.namespace,root.action_operation_id)
    kind=_ORDINARY_KINDS[root.schema]
    if(producer is None or(producer["domain"],producer["operation_kind"])!=("d08",kind)
            or producer["payload"]["schema"]!="d08.current-"+kind+".v1"
            or producer["payload"]["identity"]["phase"]!=kind
            or producer["receipt"].status!="committed"
            or producer["receipt"].operation_id!=root.action_operation_id
            or canonical_digest(producer["receipt"])!=root.receipt_digest):
        raise AuthorityUnavailable("Ordinary SourceNote needs its real ordinary Action producer COMMIT/schema")
    action=method_graph_head_v3(r.db,r.namespace,AtomKey.from_token(action_ref))
    if(not action.valid or root.action_intent_ref!=action_ref
            or root.action_intent_digest!=canonical_digest(action.value)
            or(action_ref,action.revision,root.action_intent_digest)not in root.write_commitments
            or root.activity_id!=r.activity_id or root.effect_id!=action.value["identity"]["effect_id"]
            or not set(r.audiences)<=set(root.audiences)
            or root.input_source_ref not in r.selected_plan.source_roots):
        raise AuthorityUnavailable("Ordinary SourceNote changed its current Action/Source/actual issued activity")
    return(root,GraphVersion(action.key,action.revision),root.action_intent_digest,
        producer["original_digest"],canonical_digest(producer["receipt"]),metadata.commitment)

class OrdinarySourceNoteHabitClassificationV3:
    def __init__(self,issuer,reader,facts):
        if issuer is not _ISSUER or reader.inputs_sealed:
            raise AuthorityUnavailable("Ordinary SourceNote classification requires actual presealed Source facts")
        self.reader,self.facts=reader,facts
        _PROOFS[self]=(reader,reader.work,reader.operation,reader.issued,reader.selected_plan,facts)
    def require_current_v3(self,db,frame,action_ref,issuer):
        r=_reader_v3(db)
        if(_PROOFS.get(self)!=(r,r.work,r.operation,r.issued,r.selected_plan,self.facts)
                or _BY_READER.get(r)is not self or not r.inputs_sealed or not r.business_started
                or issuer is not r.graph._GraphCoordinator__d11_issuer
                or frame.envelope.authority.namespace!=r.namespace
                or frame.envelope.identity.operation_id!=r.operation_id
                or frame.envelope.identity.phase!=r.operation_kind or frame.owner_guard!=r.evidence.owner_guard
                or frame.envelope.version_guard.read_versions!=frame.snapshot.versions
                or frame.snapshot.versions!=r.frame_fields[0].versions
                or action_ref!=self.facts[1].key.token):
            raise AuthorityUnavailable("Ordinary SourceNote classification lost its actual same-Work WRITE frame")
        r.result.require_issued_current_v3(db,r.issued.scope,r.issued)
        if _facts_v3(r)!=self.facts:
            raise AuthorityUnavailable("Ordinary SourceNote metadata/Action/producer changed before W01")
        return self

def prepare_current_ordinary_source_note_habit_classification_v3(reader):
    if reader.operation_kind not in {"prepare_source_note_body","prepare_life"}:return
    if reader.operation_kind=="prepare_life":
        from .d11_life_preparation_v1 import _read
        from .d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
        from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
        saved=_read(reader.db,issuer=reader.graph._GraphCoordinator__d11_issuer,namespace=reader.namespace,
            kind="plan",ref=reader.request.plan_original_ref)
        if saved is None:raise AuthorityUnavailable("Life classification has no actual signed registered plan")
        if type(life_from_wire_v1(saved[0],RegisteredLifePlanV2))is RegisteredDraftFilePlanV3:return
    facts=_facts_v3(reader)
    prior=_BY_READER.get(reader)
    if prior is not None:
        if prior.facts!=facts:raise AuthorityUnavailable("Ordinary SourceNote preparation changed its fixed facts")
        return
    _BY_READER[reader]=OrdinarySourceNoteHabitClassificationV3(_ISSUER,reader,facts)

def require_current_ordinary_source_note_habit_classification_v3(db,*,frame,action_ref,issuer):
    r=_reader_v3(db);proof=_BY_READER.get(r)
    if proof is None:raise AuthorityUnavailable("Actual positive ordinary SourceNote producer classification absent")
    return proof.require_current_v3(db,frame,action_ref,issuer)

def release_ordinary_source_note_habit_classification_v3(reader):
    proof=_BY_READER.pop(reader,None)
    if proof is not None:_PROOFS.pop(proof,None)
