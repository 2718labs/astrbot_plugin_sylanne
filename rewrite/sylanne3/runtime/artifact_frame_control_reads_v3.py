"""Actual Borrowed Artifact B/C frame composition; wire carriers grant no access."""
from dataclasses import replace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import GraphAtom,GraphVersion
from ..runtime_contracts import canonical_digest
from .domain_production_contracts_v1 import ProductionOperationLimitsV1,ProductionOriginalRefV1
from .artifact_model_control_contract_v1 import (
    ARTIFACT_MODEL_CONTROL_KINDS_V1,ARTIFACT_MODEL_CONTROL_PROVENANCE_V1,
    ArtifactModelControlReadsV1,artifact_model_control_reads_to_wire_v1)

_FRAMES={}
_BY_READER=WeakKeyDictionary()


def _prepared_v3(prepared):
    from .current_method_learning_read_v3 import (
        BorrowedMethodLearningReadV3,PreparedBorrowedMethodDomainInputsV3,_BORROWED_INPUTS)
    if type(prepared)is not PreparedBorrowedMethodDomainInputsV3:
        return None
    r=prepared.owner
    from .artifact_borrowed_source_v3 import ARTIFACT_BORROWED_OPERATIONS_V3
    if r.operation_kind not in ARTIFACT_BORROWED_OPERATIONS_V3:
        return None
    from .artifact_borrowed_source_v3 import (
        is_artifact_borrowed_source_reader_v3,artifact_borrowed_frame_control_v3)
    if not is_artifact_borrowed_source_reader_v3(r):return None
    if(type(r)is not BorrowedMethodLearningReadV3
            or _BORROWED_INPUTS.get(prepared)!=(r,prepared.plan,prepared.issued,r.graph_stamp,r.expected_rights)
            or prepared.plan!=r.selected_plan or prepared.issued is not r.issued):
        raise AuthorityUnavailable('Artifact frame needs its actual registered Borrowed Source inputs')
    prepared.require_issued_current_v3(r.db,r.issued.scope,r.issued)
    control=artifact_borrowed_frame_control_v3(prepared)
    if r.operation_kind in ARTIFACT_MODEL_CONTROL_KINDS_V1:
        if(type(control)is not ArtifactModelControlReadsV1 or control.operation_kind!=r.operation_kind
                or control.request_digest!=r.request_digest
                or control.habit_classification.phase_selector!=r.request.selector):
            raise AuthorityUnavailable('Artifact B/C carrier changed its actual Work/typed command')
    else:
        from .artifact_borrowed_source_v3 import require_artifact_borrowed_write_frame_reads_v3
        require_artifact_borrowed_write_frame_reads_v3(control,r)
    return r,control


def _versions_v3(*families):
    current={}
    for family in families:
        for v in family:
            if v.key in current and current[v.key]!=v.revision:
                raise AuthorityUnavailable('Artifact B/C current versions disagree on the same key')
            current[v.key]=v.revision
    return tuple(GraphVersion(key,revision)for key,revision in sorted(current.items(),key=lambda row:row[0].token))


def _coverage_v3(business,control):
    pages={}
    for page in(*business,*control):
        if page.type_id in pages and pages[page.type_id]!=page:
            raise AuthorityUnavailable('Artifact B/C complete query coverage differs for the same family')
        pages[page.type_id]=page
    return tuple(pages[key]for key in sorted(pages))


def compose_artifact_model_frame_fields_v3(prepared,snapshot,pages):
    """Combine genuine selected bodies and metadata CAS facts in the same Work."""
    actual=_prepared_v3(prepared)
    if actual is None:return snapshot,tuple(pages),None
    r,control=actual
    if(snapshot.versions!=control.business_read_versions
            or tuple(pages)!=control.business_query_coverage):
        raise AuthorityUnavailable('Artifact genuine business materialization differs from its exact preplan')
    from .artifact_borrowed_source_v3 import artifact_borrowed_control_body_atoms_v3
    atoms=tuple(artifact_borrowed_control_body_atoms_v3(prepared))
    if(tuple(sorted((GraphVersion(a.key,a.revision)for a in atoms),key=lambda v:v.key.token))
            !=tuple(sorted(control.control_body_versions,key=lambda v:v.key.token))
            or any(type(a)is not GraphAtom for a in atoms)):
        raise AuthorityUnavailable('Artifact control bodies differ from their actual qualified typed partition')
    by_key={a.key:a for a in snapshot.atoms}
    for atom in atoms:
        previous=by_key.get(atom.key)
        if previous is not None and(previous.revision!=atom.revision or previous.valid!=atom.valid
                or canonical_digest(previous.value)!=canonical_digest(atom.value)):
            raise AuthorityUnavailable('Artifact overlapping business/control body changed its real Original')
        by_key[atom.key]=atom
    if len(by_key)>ProductionOperationLimitsV1().max_graph_heads:
        raise AuthorityUnavailable('Artifact B/C bodies exceed the original complete head limit')
    full=replace(snapshot,atoms=tuple(by_key[key]for key in sorted(by_key,key=lambda k:k.token)))
    versions=_versions_v3(control.business_read_versions,control.control_read_versions)
    if not set(full.versions)<=set(versions):
        raise AuthorityUnavailable('Artifact body escaped its actual complete B/C readset')
    return full,_coverage_v3(control.business_query_coverage,control.control_query_coverage),versions


def register_artifact_model_source_frame_v3(db,frame,scope,prepared):
    actual=_prepared_v3(prepared)
    if actual is None:return frame
    r,control=actual
    full=_versions_v3(control.business_read_versions,control.control_read_versions)
    expected_body=_versions_v3(control.business_read_versions,control.control_body_versions)
    if(db is not r.db or scope is not r.issued.scope or not db.in_transaction
            or not r.store._lock._is_owned() or not r.business_started or r.business_completed
            or frame.envelope.identity.operation_id!=r.operation_id
            or frame.envelope.identity.phase!=r.operation_kind
            or frame.owner_guard!=r.material_owner_guard
            or frame.envelope.version_guard.read_versions!=full
            or frame.snapshot.versions!=expected_body
            or frame.query_coverage!=_coverage_v3(control.business_query_coverage,control.control_query_coverage)
            or frame.envelope.source_qualification.source_refs!=prepared.plan.source_roots):
        raise AuthorityUnavailable('Artifact frame changed its actual original WRITE/B/C qualification')
    record=(frame,r,prepared,control,scope,r.work,r.operation,r.graph_stamp,full)
    _FRAMES[id(frame)]=record
    _BY_READER.setdefault(r,set()).add(id(frame))
    return frame


def _record_v3(frame,*,current):
    saved=_FRAMES.get(id(frame))
    if saved is None:return None
    actual,r,prepared,control,scope,work,operation,stamp,full=saved
    if(actual is not frame or work is not r.work or operation is not r.operation
            or scope is not r.issued.scope or stamp!=r.graph_stamp
            or r.operation.closed or frame.envelope.version_guard.read_versions!=full):
        raise AuthorityUnavailable('Artifact frame lost its exact retained Work and original WRITE binding')
    if current:
        now=_prepared_v3(prepared)
        if now is None or now[0]is not r or now[1]!=control:
            raise AuthorityUnavailable('Artifact frame current Owner/Source/B/C facts changed')
    return saved


def current_artifact_model_frame_read_versions_v3(frame):
    record=_record_v3(frame,current=False)
    return None if record is None else record[8]


def artifact_model_business_read_versions_v3(db,frame):
    if frame.envelope.identity.phase not in ARTIFACT_MODEL_CONTROL_KINDS_V1|{"prepare_artifact_draft_model","acquire_artifact_draft_model"}:
        return frame.snapshot.versions
    record=_record_v3(frame,current=True)
    if record is None or record[1].db is not db:
        raise AuthorityUnavailable('Artifact model inputs have no actual business/control Source frame')
    return record[3].business_read_versions


def append_current_artifact_model_control_v3(frame,domain,kind,request,provenance):
    if domain!='d11'or kind not in ARTIFACT_MODEL_CONTROL_KINDS_V1:return provenance
    record=_record_v3(frame,current=True)
    if record is None or record[1].request!=request:
        raise AuthorityUnavailable('Artifact model producer needs its own actual current B/C frame')
    result=dict(provenance or{})
    if ARTIFACT_MODEL_CONTROL_PROVENANCE_V1 in result:
        raise AuthorityUnavailable('Artifact model business producer cannot inject its control carrier')
    result[ARTIFACT_MODEL_CONTROL_PROVENANCE_V1]=artifact_model_control_reads_to_wire_v1(record[3])
    return result


def require_artifact_model_post_commit_readsets_v3(owner,prior_frame,primary,receipt):
    """Verify actual pre-CAS facts without reviving their now-ended currentness."""
    record=_record_v3(prior_frame,current=False)
    if(record is None or record[1]is not owner or record[5]is not owner.work
            or primary.read_versions!=record[8]or receipt.read_versions!=record[8]
            or prior_frame.snapshot.versions!=_versions_v3(record[3].business_read_versions,
                record[3].control_body_versions)):
        raise AuthorityUnavailable('Artifact post-CAS scope lost its actual B/C producer/receipt readsets')
    if owner.operation_kind in ARTIFACT_MODEL_CONTROL_KINDS_V1:
        import json
        from .artifact_model_control_contract_v1 import artifact_model_control_reads_from_wire_v1
        provenance=json.loads(primary.original_payload_json)['provenance']
        if artifact_model_control_reads_from_wire_v1(provenance[ARTIFACT_MODEL_CONTROL_PROVENANCE_V1])!=record[3]:
            raise AuthorityUnavailable('Artifact post-CAS producer changed its complete original B/C carrier')
    return record[3]


def release_artifact_model_source_frames_v3(reader):
    for identity in _BY_READER.pop(reader,()):_FRAMES.pop(identity,None)


def append_artifact_model_control_originals_v3(prepared,observed_originals):
    actual=_prepared_v3(prepared)
    if actual is None:return observed_originals
    from .artifact_borrowed_source_v3 import artifact_borrowed_control_originals_v3
    originals=tuple(artifact_borrowed_control_originals_v3(prepared))
    selected={value.original_ref:value for value in observed_originals}
    for value in originals:
        if type(value)is not ProductionOriginalRefV1:
            raise AuthorityUnavailable('Artifact control Original must be an actual authenticated typed locator')
        if value.original_ref in selected and selected[value.original_ref]!=value:
            raise AuthorityUnavailable('Artifact business/control Original commitments conflict')
        selected[value.original_ref]=value
    return tuple(selected[ref]for ref in sorted(selected))

def artifact_model_frame_deadline_v3(prepared,deadline):
    actual=_prepared_v3(prepared)
    if actual is None:return deadline
    from .artifact_borrowed_source_v3 import artifact_borrowed_frame_deadline_v3
    return artifact_borrowed_frame_deadline_v3(prepared,deadline)

def artifact_model_frame_monotonic_deadline_v3(prepared,deadline):
    actual=_prepared_v3(prepared)
    if actual is None:return deadline
    from .artifact_borrowed_source_v3 import artifact_borrowed_frame_monotonic_deadline_v3
    return artifact_borrowed_frame_monotonic_deadline_v3(prepared,deadline)

def require_artifact_borrowed_frame_source_family_v3(frame,db,roots,*,purpose=None,audience=None):
    record=_record_v3(frame,current=True)
    if record is None:return False
    r=record[1]
    from .artifact_borrowed_source_v3 import require_artifact_borrowed_source_family_v3
    return require_artifact_borrowed_source_family_v3(r,frame,db,roots,purpose=purpose,audience=audience)
