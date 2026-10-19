"""D13 model and result Source material on the actual Authority READ/MODEL Work."""
from dataclasses import fields
import json
from types import MappingProxyType, SimpleNamespace
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, NamespaceEpoch
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from ..runtime.d13_paid_original_read_v3 import (
    D13PaidOriginalReadWorkV3, _ColumnV3, _FrozenMetadataV3, _IntentDigestMetadataV3, _JOB_COLUMNS)
from ..runtime.dispatch_current_inventory_v3 import _heap

_ISSUER=object()
_READERS=WeakKeyDictionary()
_INSTALLED=WeakKeyDictionary()
_PHASES=WeakKeyDictionary()


class InstalledD13AuthorityModelReaderV3:
    def __init__(self,*,owner_storage,bundle,issuer,model_service,worker_service):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .v2_model_egress_service import AuthorityV2ModelEgressService
        from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
        if (type(owner_storage)is not InstalledD12OwnerStorageAdmissionServiceV1
                or type(model_service)is not AuthorityV2ModelEgressService
                or type(worker_service)is not AuthorityV2WorkerModelResultReadService
                or bundle.d13_paid_precompression is None or model_service._store is not worker_service._store
                or model_service._fences is not worker_service._fences or model_service._fences is not owner_storage.fences
                or model_service._graph_verifier._issuer is not issuer
                or model_service._graph_verifier._artifact_draft_bundle is not bundle
                or model_service._graph_verifier._path!=owner_storage.graph_path
                or worker_service._graph._path!=owner_storage.graph_path):
            raise AuthorityUnavailable("D13 Source requires its actual installed Owner/model/result composition")
        self.owner_storage,self.bundle,self.issuer=owner_storage,bundle,issuer
        self.model_service,self.worker_service=model_service,worker_service
        _INSTALLED[self]=(owner_storage,bundle,issuer,model_service,worker_service)

    def require_v3(self,work):
        if (_INSTALLED.get(self)!=(self.owner_storage,self.bundle,self.issuer,self.model_service,self.worker_service)
                or work.controller.verifier._d13_paid_reader_v3 is not self
                or work.controller.service is not self.model_service
                or work.controller.fences is not self.owner_storage.fences
                or work.controller.control is not self.owner_storage.control
                or work.namespace!=self.owner_storage.namespace_id):
            raise AuthorityUnavailable("D13 installed Source crossed its actual controller/Owner/current Graph")
        return self


def register_d13_authority_model_phase_v3(work):
    if work.owner_model_work_kind!="d13.precompress.paid.v1":return
    installed=work.controller.verifier._d13_paid_reader_v3
    installed.require_v3(work)
    with work.controller.fences._frozen()as(db,deletion,execution,_):
        anchor=work.controller.fences._current_locked(db,deletion,execution,
            holder=work.permit.holder,generation=work.permit.generation)
        work.controller.fences.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
        record=work.service._store.read_locked(db,work.request)
        if record.intent!=work.request or record.state!="prepared":
            raise AuthorityUnavailable("D13 model Source requires its actual prepared Core original")
    _PHASES[work]=(installed,work.request,work.permit,work.operation,work.scope,"d13_model_policy")


def require_d13_authority_model_phase_v3(work,installed):
    installed.require_v3(work);work._actual()
    saved=_PHASES.get(work)
    if saved is None or saved[:5]!=(installed,work.request,work.permit,work.operation,work.scope):
        raise AuthorityUnavailable("D13 Owner header has no actual model/result phase")
    if saved[5]=="d13_result_read":require_d13_result_bridge_v3(work)
    return saved[5]


def require_d13_owner_header_v3(proof):
    work=proof.request
    installed=work.controller.verifier._d13_paid_reader_v3
    if (proof.kind!="authority_d13_paid_header" or proof.owner_service is not installed.owner_storage
            or proof.bundle is not installed.bundle or proof.controller is not work.controller
            or proof.service is not work.service or proof.scope is not work.scope
            or proof.retained_operation is not work.operation or proof.original_permit is not work.permit
            or proof.model_source_phase!=require_d13_authority_model_phase_v3(work,installed)):
        raise AuthorityUnavailable("D13 Owner proof crossed its private actual caller phase")


class _AuthorityD13FrozenMetadataV3(_FrozenMetadataV3):
    def _select(self,path):
        if path[:1]==("plan",) and len(path)==2 and path[-1]in{
                "candidate_ref","input_digest","first_sequence","last_sequence",
                "access_epoch","delete_epoch","activation_epoch"}:return True
        return super()._select(path)


class AuthorityD13PaidSourceV3:
    # These methods are algorithms over explicit cells and Source values. The
    # Host factory, registry, permission checks and completed proof are not used.
    _sources=D13PaidOriginalReadWorkV3._sources
    _access=D13PaidOriginalReadWorkV3._access
    _window_metadata=D13PaidOriginalReadWorkV3._window_metadata

    def __init__(self,issuer,work,installed,owner_entry):
        from .owner_location_read_v3 import _OWNER_MODEL_LOCATION_ENTRIES_V3
        if (issuer is not _ISSUER or work.owner_model_work_kind!="d13.precompress.paid.v1"
                or _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work,(None,))[0]is not installed
                or _OWNER_MODEL_LOCATION_ENTRIES_V3[work][4]is not owner_entry):
            raise AuthorityUnavailable("D13 Source requires its actual completed independent Owner EOF")
        installed.require_v3(work);require_d13_authority_model_phase_v3(work,installed)
        self.work,self.installed,self.owner_entry=work,installed,owner_entry
        self.db,self.namespace,self.operation=work.db,work.namespace,work.operation
        self.job_id=work.request.job_id;self.initial_now=self.now_utc=work.now_utc
        self.deadline=self.operation.deadline_utc;self.original_deadline=None
        self.authority=SimpleNamespace(actor=work.request.subject,audience=(None,),
            activation_generation=work.request.authority_activation_generation)
        self.args={"max_slots":64};self.window_policy=installed.bundle.d13_paid_precompression
        self.graph_stamp=None
        self.owner_guard_head=owner_entry.head.guard.authorization_head
        self.selection_digest=work.selection_digest
        self.phase="metadata";self.job=self.column=None;self.intent_head=None
        self.intent_metadata=self.frozen_metadata=self.intent_metadata_sha=None
        self.intent_digest_task=self.intent_projection=None
        self.frozen_versions,self.sources,self.source_heads,self.access_atoms={},{},{},{}
        self.pending_sources=[];self.qualified=False
        self.window_metadata=self.window_body=self.current_window=None
        self.metadata_atoms,self.metadata_columns={},{}
        self.epochs=self.owner_head=None;self.reserved=0;self.complete=False
        self.eof=self.verifier=self.plan=self.result=self.current_builder=None
        self.allowed_requests=set()
        self._identity=(work,installed,owner_entry,self.operation,work.scope,work.request,work.permit,work.selection_digest)
        _READERS[work]=self;self.reserve_v3()

    def require_registered_v3(self):
        if (type(self)is not AuthorityD13PaidSourceV3 or _READERS.get(self.work)is not self
                or self._identity!=(self.work,self.installed,self.owner_entry,self.work.operation,
                    self.work.scope,self.work.request,self.work.permit,self.work.selection_digest)):
            raise AuthorityUnavailable("D13 Source lost its exact actual Authority Work")
        self.work._actual();self.installed.require_v3(self.work)
        return self

    def require_current_v3(self,meter=None):
        self.require_registered_v3()
        if meter is not None:
            self.work.require_current(meter=meter)
            if self.graph_stamp is None:self.graph_stamp=(None,NamespaceEpoch(*self.namespace.as_tuple,self.work.graph_stamp[0]))
            epochs=meter.read_fixed_row(self.db,"graph_authority_epochs",("access_epoch","delete_epoch"),
                "bot=? AND persona=?",self.namespace.as_tuple)
            from ..graph_types import owner_grant_key
            owner=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=?",(owner_grant_key(*self.namespace.as_tuple).token,))
            if self.epochs is None:self.epochs,self.owner_head=epochs,owner
            elif (epochs,owner)!=(self.epochs,self.owner_head):
                raise AuthorityUnavailable("D13 current Source rights/Owner head changed")
        if self.work.now_utc>=min(self.deadline,self.original_deadline or self.deadline):
            raise AuthorityUnavailable("D13 paid READ original TTL/worker lease expired")
        return self

    def reserve_v3(self,extra=0):
        values=(self.intent_metadata,self.frozen_metadata,self.frozen_versions,self.sources,self.source_heads,
            self.access_atoms,self.pending_sources,self.metadata_atoms,self.metadata_columns,self.result)
        size=_heap(values)+65536+extra
        for metadata in (self.intent_metadata,self.frozen_metadata):
            if metadata is not None:size+=_heap(tuple(metadata.items()))
        if self.column is not None:
            c=self.column;size+=_heap((c.fragment,c.body,c.value))
            from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3,C09MemoryAccessJSONStreamV3
            from ..runtime.d13_paid_original_read_v3 import _IntentMetadataV3
            if type(c.parser)in(C09MemorySourceJSONStreamV3,C09MemoryAccessJSONStreamV3):
                size+=c.parser._source_heap_bytes()
            elif type(c.parser)is _IntentMetadataV3:
                size+=_heap((vars(c.parser),vars(c.parser.frozen),vars(c.parser.decoder),
                    vars(c.parser.frozen_parser)))

        if self.intent_projection is not None:
            size+=_heap((vars(self.intent_projection),vars(self.intent_projection.frozen),
                vars(self.intent_projection.decoder),vars(self.intent_projection.frozen_parser)))
        if self.window_metadata is not None:size+=_heap(vars(self.window_metadata))
        if self.window_body is not None:
            size+=_heap((self.window_body.points,self.window_body.families,self.window_body.queue))
            size+=sum(_heap(atom.value)for atom in self.window_body.atoms.values())
        size+=sum(_heap(tuple(source.metadata.items()))for source in self.sources.values())
        size+=sum(_heap(atom.value)for atom in self.access_atoms.values())
        size+=sum(_heap(atom.value)for atom in self.metadata_atoms.values())
        if self.current_builder is not None:size+=self.current_builder.heap_v3()
        if size>self.reserved:self.operation.retain(size-self.reserved);self.reserved=size

    def _metadata(self,meter):
        ns=self.namespace
        if self.job is None:
            self.job=meter.read_fixed_row(self.db,"runtime_jobs",_JOB_COLUMNS,"job_id=?",(self.job_id,))
            if (self.job is None or self.job[3:5]!=ns.as_tuple or self.job[6]!="d13.precompress.paid.v1"
                    or self.job[5]!="running" or self.job[12]!=0 or self.job[13]is not None
                    or self.job[9]!=self.work.request.subject or self.job[11]!=self.work.request.worker_fence):
                raise AuthorityUnavailable("D13 worker job is no longer current")
            self.intent_head=meter.read_fixed_row(self.db,"graph_d13_paid_intent_originals_v1",
                ("operation_id","original_digest"),"bot=? AND persona=? AND job_ref=?",(*ns.as_tuple,self.job_id))
            if self.intent_head is None:raise AuthorityUnavailable("D13 unique actual paid original is absent")
            self.column=_ColumnV3(self,table="graph_d13_paid_intent_originals_v1",column="original_json",
                key_columns=("bot","persona","job_ref"),key=(*ns.as_tuple,self.job_id),metadata=True)
            self.column.parser.frozen=_AuthorityD13FrozenMetadataV3()
            return
        self.column.advance(meter)
        if not self.column.complete:return
        parser=self.column.parser;outer,frozen=parser.scalars,parser.frozen.values
        if ((outer.get(("namespace","bot_id")),outer.get(("namespace","persona_id")))!=ns.as_tuple
                or outer.get(("binding","job_ref"))!=self.job_id
                or outer.get(("binding","original_operation_id"))!=self.job[1]
                or self.intent_head[0]!=self.job[1] or self.job[1]!=self.work.request.operation_id
                or frozen.get(("plan","job_ref"))!=self.job_id
                or (frozen.get(("window","namespace","bot_id")),frozen.get(("window","namespace","persona_id")))!=ns.as_tuple):
            raise AuthorityUnavailable("D13 frozen metadata crossed its actual original/job/namespace")
        scene=AtomKey.from_token(frozen[("window","scene_ref","ref")])
        if NamespaceId.from_key(scene)!=ns or scene.owner.kind!="scene":
            raise AuthorityUnavailable("D13 frozen scene crossed its actual namespace")
        self.scene_ref=scene.owner.subject
        self.authority.audience=(frozen[("window","conversation_ref")],)
        versions={}
        for path,ref in frozen.items():
            if path[-1:]!=("ref",):continue
            revision=frozen.get((*path[:-1],"version"))
            if (type(ref)is not str or type(revision)is not int or revision<0
                    or ref in versions and versions[ref]!=revision):
                raise AuthorityUnavailable("D13 original exact frozen references differ")
            versions[ref]=revision
        roots=[ref for ref in versions if AtomKey.from_token(ref).type_name=="memory.source"]
        if not roots or (frozen[("window","access_epoch")],frozen[("window","delete_epoch")])!=self.epochs:
            raise AuthorityUnavailable("D13 frozen Source closure/rights changed")
        if frozen[("window","activation_epoch")]!=self.authority.activation_generation:
            raise AuthorityUnavailable("D13 frozen activation changed")
        self.original_deadline=min(self.deadline,frozen[("plan","expires_at_utc")],
            outer[("binding","expires_at_utc")])
        self.frozen_versions=versions;self.intent_projection=parser
        self.intent_metadata_sha=self.column.sha256
        self.intent_digest_task=_IntentDigestMetadataV3(self,self.column)
        self.column=None;self.phase="intent_digest"

    def _metadata_authenticated(self):
        from ..domains.d13.precompression import PrecompressionPlan
        v=self.intent_projection.frozen.values
        def ref(path):return VersionedRef(v[(*path,"ref")],v[(*path,"version")])
        deps=sorted({path[2]for path in v if path[:2]==("plan","source_dependencies")})
        data={f.name:v[("plan",f.name)]for f in fields(PrecompressionPlan)
            if f.name not in {"source_dependencies","scene_ref","audience_ref"}}
        self.plan=PrecompressionPlan(**data,source_dependencies=tuple(ref(("plan","source_dependencies",i))for i in deps),
            scene_ref=ref(("plan","scene_ref")),audience_ref=ref(("plan","audience_ref")))
        self.intent_metadata=MappingProxyType(dict(self.intent_projection.scalars))
        self.frozen_metadata=MappingProxyType(dict(v))
        self.pending_sources=[ref for ref in self.frozen_versions if AtomKey.from_token(ref).type_name=="memory.source"]
        self.intent_projection=self.intent_digest_task=None;self.phase="census";self.reserve_v3()

    def window_atom_v3(self,key):return self.window_body.atom_v3(key)
    def window_family_v3(self,kind):return self.window_body.family_v3(kind)
    def window_original_point_v3(self,table,columns,key_columns,key):
        return self.window_body.original_point_v3(table,columns,key_columns,key)

    def _window_body(self,meter):
        from ..runtime.d13_current_window import begin_d13_paid_window_body_v3
        if self.window_body is None:self.window_body=begin_d13_paid_window_body_v3(self,self.window_metadata)
        self.window_body.advance_v3(meter)
        if not self.window_body.complete:return
        self.current_window=self.window_body.window;self.phase="eof"
        ns=self.namespace.as_tuple
        self.allowed_requests.update({
            ("graph_d13_paid_intent_originals_v1",("operation_id","original_json","original_digest"),("bot","persona","job_ref"),(*ns,self.job_id)),
            ("graph_d13_paid_call_originals_v1",("call_id","original_json","original_digest"),("bot","persona","job_ref"),(*ns,self.job_id))})
        from .d13_paid_block_verifier_v1 import build_installed_d13_paid_block_verifier_v1,PreparedD13PaidRequestEOFV3,_PAID_EOF_ISSUER_V3
        self.verifier=build_installed_d13_paid_block_verifier_v1(self.db,
            installation=self.installed.bundle.d13_paid_precompression.selected_main,
            resource_issuer=self.installed.issuer.resource_issuer,budget_issuer=self.installed.issuer,
            authority_store=self.installed.model_service._store,max_slots=64)
        self.eof=PreparedD13PaidRequestEOFV3(_PAID_EOF_ISSUER_V3,self.work,
            verifier=self.verifier,plan=self.plan,window=self.current_window)

    def advance_v3(self,meter):
        self.require_current_v3(meter)
        if self.phase=="metadata":self._metadata(meter)
        elif self.phase=="intent_digest":
            self.intent_digest_task.advance_v3(meter)
            if self.intent_digest_task.complete:self._metadata_authenticated()
        elif self.phase=="census":
            from .current_authority_graph_read_v3 import _AuthorityNamespaceReadV3,AuthorityGraphProjectionV3,_ISSUER as issuer
            work=self.work
            if work.namespace_reader is None:
                work.catalogue_reader.advance_v3(meter)
                if work.catalogue_reader.complete:
                    work.namespace_reader=_AuthorityNamespaceReadV3(work,catalogue=work.catalogue_reader.rows,
                        catalogue_hash=work.catalogue_reader.catalogue_hash)
            elif not work.namespace_reader.graph_eof:work.namespace_reader.advance_v3(meter)
            else:
                work.projection=AuthorityGraphProjectionV3(issuer,work);self.phase="window_metadata"
        elif self.phase=="window_metadata":self._window_metadata(meter)
        elif self.phase=="sources":
            self._sources(meter)
            if self.phase=="originals":self.phase="window_body"
        elif self.phase=="access":self._access(meter)
        elif self.phase=="window_body":self._window_body(meter)
        elif self.phase=="eof":
            self.eof.advance(meter=meter)
            if self.eof.complete:
                if self.eof.missing:raise AuthorityUnavailable("D13 actual model request original is absent")
                from .d13_authority_current_model_v3 import AuthorityD13CurrentModelReadV3
                self.current_builder=AuthorityD13CurrentModelReadV3(self);self.phase="current"
        elif self.phase=="current":
            self.current_builder.advance_v3(meter)
            if self.current_builder.complete:
                self.result=self.current_builder.result
                self.complete=True;self.phase="ready";self.work.phase="validate"
        else:raise AuthorityUnavailable("D13 Source has an unregistered actual phase")
        self.reserve_v3()

    def point_v3(self,request,meter):
        self.require_current_v3(meter)
        if not self.qualified or request not in self.allowed_requests:
            raise AuthorityUnavailable("D13 body is outside its actual signed original family")
        attachment=self.work.attachments.get(request)
        if attachment is None:
            from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
            raise AuthorityGraphAttachmentRequiredV3(request)
        return attachment.require_row_v3(self.work,meter)

    def release_v3(self):
        if self.current_builder is not None:self.current_builder.release_v3()
        if self.eof is not None:self.eof.release_payload_v3()
        self.eof=self.current_builder=self.verifier=self.column=self.intent_projection=self.intent_digest_task=None
        self.intent_metadata=self.frozen_metadata=None
        self.frozen_versions.clear();self.source_heads.clear();self.pending_sources.clear();self.allowed_requests.clear()
        _READERS.pop(self.work,None);_PHASES.pop(self.work,None)
        self.sources.clear();self.access_atoms.clear();self.metadata_atoms.clear();self.metadata_columns.clear()
        self.window_body=self.window_metadata=self.current_window=self.result=None


def d13_authority_source_reader_v3(work):
    reader=_READERS.get(work)
    return None if reader is None else reader.require_registered_v3()


def prepare_d13_authority_source_v3(work,installed,entry):
    if d13_authority_source_reader_v3(work)is None:
        return AuthorityD13PaidSourceV3(_ISSUER,work,installed,entry)
    return d13_authority_source_reader_v3(work)


def require_d13_authority_window_reader_v3(reader):
    if type(reader)is not AuthorityD13PaidSourceV3:return False
    reader.require_registered_v3();reader.require_current_v3()
    if not reader.qualified or reader.phase not in {"window_body","eof","ready"}or reader.window_body is None:
        raise AuthorityUnavailable("D13 Authority window requires actual all-Source current rights")
    return True


def require_d13_authority_paid_eof_v3(work,verifier,plan,window):
    reader=d13_authority_source_reader_v3(work)
    if reader is None:return False
    if (reader.phase!="eof"or not reader.qualified or reader.verifier is not verifier
            or reader.plan is not plan or reader.current_window is not window):
        raise AuthorityUnavailable("D13 actual paid EOF crossed its qualified Source candidate")
    return True


def observe_d13_source_clock_v3(work):
    reader=_READERS.get(work)
    if reader is None:return
    reader.require_registered_v3()
    if work.db.in_transaction:raise AuthorityUnavailable("D13 trusted clock observation must precede Graph SQL")
    now=work.controller.clock()
    import math
    deadline=min(reader.deadline,reader.original_deadline or reader.deadline)
    if reader.eof is not None and reader.eof.complete:deadline=min(deadline,reader.eof.request.envelope.deadline_utc)
    if type(now)not in(int,float)or not math.isfinite(now)or now>=deadline:
        raise AuthorityUnavailable("Authority read exceeded its original contract deadline")
    reader.now_utc=float(now)


def d13_namespace_metadata_column_v3(work,key,revision,valid,cell):
    reader=d13_authority_source_reader_v3(work)
    if reader is None:return False,None
    from ..graph_types import owner_grant_key
    from ..memory_types import access_key
    from ..domains.d03.self_perspective import self_mapping_key
    if key.type_name=="memory.source":return False,None
    selected=(key==owner_grant_key(*work.namespace.as_tuple)or key==self_mapping_key(work.namespace)
        or key.type_name==access_key(*work.namespace.as_tuple,"source-metadata-type").type_name)
    if not selected:return True,None
    from .d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
    return True,_D07AuthorityGraphMetadataColumnV3(reader,key,revision,valid,cell)


def require_d13_body_request_v3(work,request):
    reader=d13_authority_source_reader_v3(work)
    if reader is None:return False
    reader.require_registered_v3()
    if not reader.qualified or request not in reader.allowed_requests:
        raise AuthorityUnavailable("D13 requested body is outside its actual EOF-derived original family")
    return True


def read_bound_d13_authority_point_v3(db,*,table,columns,key_columns,key):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None or d13_authority_source_reader_v3(work)is None:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        return True,d13_authority_source_reader_v3(work).point_v3(request,meter)


def read_bound_d13_current_model_v3(db,intent,issuer,now):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_storage_quantum_v3
    work=_authority_attachment_owner_v3(db)
    if work is None:
        if runtime_storage_v3(db)is not None:
            raise AuthorityUnavailable("D13 current paid model requires its actual completed Source Work")
        return None
    reader=d13_authority_source_reader_v3(work)
    if (reader is None or not reader.complete or reader.phase!="ready"or reader.result is None
            or work.request is not intent or reader.installed.issuer is not issuer):
        raise AuthorityUnavailable("D13 current paid model lacks its actual full EOF seal")
    with runtime_storage_quantum_v3(db)as meter:reader.require_current_v3(meter)
    reader.eof.require_originals_v3(reader.verifier,reader.plan,reader.current_window)
    reader.current_builder.require_current_v3()
    return reader.result


def require_d13_current_frozen_v3(db,current):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None:return None
    reader=d13_authority_source_reader_v3(work)
    if reader is None or reader.result is not current:
        raise AuthorityUnavailable("D13 request shape lacks the same actual Source result seal")
    reader.current_builder.require_current_v3()
    original,frozen,call,request=reader.eof.require_originals_v3(reader.verifier,reader.plan,reader.current_window)
    if original is not current.original or request is not current.request:
        raise AuthorityUnavailable("D13 actual paid request and original seal differ")
    return frozen


def release_d13_authority_source_v3(work):
    reader=_READERS.get(work)
    if reader is not None:reader.release_v3()
    _PHASES.pop(work,None)


def require_d13_result_bridge_v3(work,*,observe=False):
    from .d13_authority_result_source_v3 import require_d13_result_bridge_v3 as require
    return require(work,observe=observe)
