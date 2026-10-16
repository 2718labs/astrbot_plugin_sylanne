"""Exact ended business-producer tuples for one actual Artifact MODEL Work."""
from weakref import WeakKeyDictionary
import hashlib
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from .v2_contract import canonical_bytes
from .v2_fence_store import AuthorityV2FenceStore
from .v2_contract import from_wire

_KEY=object()
_WORKS=WeakKeyDictionary()

class _ArtifactModelFinishedProducerV3:
    def __init__(self,key,reader,operation,header,permit,bundle):
        if key is not _KEY:raise AuthorityUnavailable("actual Artifact finished producer factory required")
        self.reader,self.actual_work,self.service=reader,reader.work,reader.installed
        self.namespace,self.subject,self.permit=reader.work.namespace,reader.work.subject,reader.work.permit
        self.producer_fence_candidates={operation:(header,permit,bundle)}
        self.operation,self.header,self.producer_permit,self.bundle=operation,header,permit,bundle
        self.result=None;self.failed=False;self.table=None;self.row=None
    def require_v3(self):
        from .artifact_model_source_read_v3 import artifact_model_namespace_recipe_v3
        r=artifact_model_namespace_recipe_v3(self.actual_work)
        if(r is not self.reader or r.capability is None or self.failed
                or _WORKS.get(self.actual_work,{}).get(self.operation)is not self
                or self.service is not r.installed or self.permit is not self.actual_work.permit
                or self.producer_fence_candidates!={self.operation:(self.header,self.producer_permit,self.bundle)}):
            raise AuthorityUnavailable("Artifact finished tuple lost same actual Source/Model Scope/producer")
        r.capability.require_v3();return self
    def _observe(self):return self.require_v3()
    @property
    def request(self):return ("artifact_model.producer_finished.v3",self.operation)
    @property
    def complete(self):return self.result is not None
    def advance(self,meter):
        self.require_v3()
        if self.result is None:raise AuthorityUnavailable("Artifact Core producer observation must precede Graph quantum")

def require_artifact_finished_work_v3(work):
    if type(work)is not _ArtifactModelFinishedProducerV3:raise AuthorityUnavailable("exact Artifact private finished reader required")
    return work.require_v3()

def observe_artifact_finished_producers_v3(work):
    """Only the paired outside-Graph model Owner quantum calls the Core reader."""
    if work.db.in_transaction:raise AuthorityUnavailable("Artifact producer Core read cannot run inside Graph SQL")
    for state in _WORKS.get(work,{}).values():
        state.require_v3()
        if state.result is not None:continue
        installed=state.service;owner=installed.owner_storage;fences=owner.fences
        permit,header=state.producer_permit,state.header
        try:
            with fences._frozen()as(db,deletion,execution,_):
                owner.core.require_current_storage_generation_locked(db,namespace=fences.namespace,action="business")
                anchor=fences._current_locked(db,deletion,execution,holder=work.permit.holder,generation=work.permit.generation)
                fences.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
                row=AuthorityV2FenceStore._row(db,permit.operation_id)
                if row is not None and(AuthorityV2FenceStore._permit(row)!=permit or row[7]!=canonical_bytes(permit)
                        or row[6]!="finished"or row[8:11]!=(header[5],header[6],None)):
                    raise AuthorityUnavailable("Artifact actual original producer Core row is not its exact finished tuple")
            if row is None:
                from .conditioned_child_c09_finished_v1 import require_accepted_conditioned_producer_fence_v1
                row=require_accepted_conditioned_producer_fence_v1(state,operation_id=state.operation,
                    header=header,permit=permit,bundle=state.bundle)
            state.result=canonical_digest((row[:7],hashlib.sha256(bytes(row[7])).hexdigest(),row[8:]))
        except BaseException:state.failed=True;raise


class _ArtifactProducerMetadataV3:
    def __init__(self,reader,request):
        if request[1]not in reader.original_operations:
            raise AuthorityUnavailable("Artifact producer metadata has no independently selected actual operation")
        self.reader,self.work,self.request=reader,reader.work,request
        self.table=self.row=None;self.column=None;self.complete=False;self.header=self.bundle=self.original=None
    def advance(self,meter):
        from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        r=self.reader;r.capability.require_v3();w=self.work;operation,kind,digest,receipt=self.request[1:]
        key=(*w.namespace.as_tuple,operation)
        if self.column is None:
            self.header=meter.read_fixed_row(w.db,"graph_bundle_fences_v2",("digest","pre_graph_revision","pre_graph_epoch",
                "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
                "bot=? AND persona=? AND operation_id=?",key)
            self.bundle=meter.read_fixed_row(w.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",key)
            self.original=meter.read_fixed_row(w.db,"graph_domain_production_originals_v1",
                ("domain","operation_kind","original_digest","receipt_digest"),"bot=? AND persona=? AND operation_id=?",key)
            if(self.original is None or self.original[1:]!=(kind,digest,receipt)
                    or self.header is None or self.bundle is None or self.bundle[0]!=self.header[0]or self.bundle[1]<1
                    or self.header[3:5]!=(self.header[1]+1,self.header[2]+1)or not all(self.header[5:])):
                raise AuthorityUnavailable("Artifact actual producer lost exact Graph COMMIT/fence/finish metadata")
            self.column=DispatchOriginalJSONReadV3(w,table="graph_bundle_fences_v2",column="permit_json",
                key_columns=("bot","persona","operation_id"),key=key);return
        if not self.column.advance(meter):return
        permit=from_wire(self.column.require_v3(w))
        if(permit.operation!="write"or permit.authority_id!=w.permit.authority_id
                or permit.namespace!=w.permit.namespace or permit.holder!=w.permit.holder):
            raise AuthorityUnavailable("Artifact original producer changed actual Core/namespace/holder/phase")
        states=_WORKS.setdefault(w,{})
        prior=states.get(operation)
        if prior is None:states[operation]=_ArtifactModelFinishedProducerV3(_KEY,r,operation,self.header,permit,self.bundle)
        elif(prior.header,prior.producer_permit,prior.bundle)!=(self.header,permit,self.bundle):
            raise AuthorityUnavailable("Artifact original producer tuple changed in same actual Work")
        r.finished_metadata[self.request]=self;self.complete=True

def require_artifact_model_producer_finished_v3(reader,*,operation,expected_kind,original_digest,receipt_digest):
    reader.capability.require_v3();w=reader.work
    if operation not in reader.original_operations:
        raise AuthorityUnavailable("Artifact old producer operation is not independently selected")
    from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    request=("artifact_model.producer_metadata.v3",operation,expected_kind,original_digest,receipt_digest)
    if request not in reader.finished_metadata:raise AuthorityGraphAttachmentRequiredV3(request)
    prior=_WORKS.get(w,{}).get(operation)
    if prior is None:raise AuthorityUnavailable("Artifact actual producer complete metadata has no original tuple")
    prior.require_v3()
    if prior.result is None:raise AuthorityGraphAttachmentRequiredV3(prior.request)
    return prior.result

def prepare_artifact_finished_attachment_v3(work,request):
    if len(request)==5 and request[0]=="artifact_model.producer_metadata.v3":
        from .artifact_model_source_read_v3 import artifact_model_namespace_recipe_v3
        r=artifact_model_namespace_recipe_v3(work)
        if r is None:raise AuthorityUnavailable("Artifact producer metadata lacks its actual Source Work")
        r.capability.require_v3();return _ArtifactProducerMetadataV3(r,request)
    if len(request)!=2 or request[0]!="artifact_model.producer_finished.v3":return None
    state=_WORKS.get(work,{}).get(request[1])
    if state is None:raise AuthorityUnavailable("Artifact finished continuation has no actual selected producer")
    return state.require_v3()

def release_artifact_finished_producers_v3(work):
    _WORKS.pop(work,None)
