"""Private Host financial invocation accepted only from actual paired metadata RPC."""
from dataclasses import dataclass
from threading import get_ident
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.artifact_no_dispatch_metadata_contract_v1 import ModelNoDispatchMetadataGrantV1
from ..runtime_storage_v3 import (runtime_storage_v3,begin_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3)


def _actual_metadata_heap_v1(value, seen):
    """Count retained scalar/container/dataclass storage without walking services."""
    import sys
    from dataclasses import fields, is_dataclass
    identity=id(value)
    if identity in seen:return 0
    seen.add(identity)
    amount=sys.getsizeof(value)
    if isinstance(value,dict):
        return amount+sum(_actual_metadata_heap_v1(k,seen)+_actual_metadata_heap_v1(v,seen) for k,v in value.items())
    if isinstance(value,(tuple,list,set,frozenset)):
        return amount+sum(_actual_metadata_heap_v1(v,seen) for v in value)
    if is_dataclass(value):
        if hasattr(value,'__dict__'):
            amount+=sys.getsizeof(value.__dict__)
        return amount+sum(_actual_metadata_heap_v1(getattr(value,f.name),seen) for f in fields(value))
    return amount


_ISSUER=object()
_VERIFIED=WeakKeyDictionary()
_INVOCATIONS=WeakKeyDictionary()


def _accept_verified_artifact_metadata_rpc_v1(issuer, *, port, bundle, grant, channel_binding):
    from ..host.v2_fence_port import V2FencePort
    from ..host.authority_profile import AdminInstallationBundle
    if (issuer is not _ARTIFACT_METADATA_RPC_ISSUER_V1 or type(port) is not V2FencePort
            or type(bundle) is not AdminInstallationBundle or type(grant) is not ModelNoDispatchMetadataGrantV1
            or channel_binding!=port._identity()[0].channel_binding_sha256):
        raise AuthorityUnavailable("actual paired Artifact metadata RPC acceptance required")
    policy=bundle.installation_policy;handshake,installed=port._identity()
    if (grant.request.namespace,grant.request.authority_namespace,grant.request.installation_id,
            grant.intent.authority_id,grant.subject,grant.holder)!=(policy.namespace,policy.authority_namespace,
            policy.installation_id,installed.authority_id,installed.subject,installed.administrator_holder):
        raise AuthorityUnavailable("financial metadata RPC crossed actual installed identity")
    _VERIFIED[grant]=(port,bundle,channel_binding)
    return grant


_ARTIFACT_METADATA_RPC_ISSUER_V1=object()


def require_verified_artifact_metadata_grant_v1(grant, *, port, bundle):
    if type(grant) is not ModelNoDispatchMetadataGrantV1 or _VERIFIED.get(grant)!=(port,bundle,port._identity()[0].channel_binding_sha256):
        raise AuthorityUnavailable("actual live paired financial metadata grant required")
    return grant


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class ActualArtifactNoDispatchMetadataInvocationV1:
    graph: object
    runtime: object
    port: object
    bundle: object
    grant: object
    control: object
    actual_db: object
    retained_operation: object
    selected_graph_member: object
    storage_context: object
    selection_digest: str
    namespace: object
    installation_id: str
    holder: str
    current_owner_head: object
    current_anchor: object
    thread_id: int
    _issuer: object

    def __post_init__(self):
        if self._issuer is not _ISSUER:raise AuthorityUnavailable("actual fixed Artifact financial invocation issuer required")
        _INVOCATIONS[self]=True
        self.retained_operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        seen={id(self)}
        amount=sys.getsizeof(self)
        for value in (self.grant,self.selected_graph_member,self.selection_digest,self.namespace,
                self.installation_id,self.holder,self.current_owner_head,self.current_anchor,self.thread_id):
            amount+=_actual_metadata_heap_v1(value,seen)
        return amount
    @property
    def principal(self):return self.current_owner_head.issue_operation.principal
    @property
    def original_request(self):return self.grant.request
    @property
    def original_intent(self):return self.grant.intent
    @property
    def operation_id(self):return self.grant.request.read_operation_id
    @property
    def registered_deadline_utc(self):return self.retained_operation.deadline_utc
    @property
    def current_owner_guard(self):return self.current_owner_head.guard
    @property
    def graph_path(self):return self.selected_graph_member["resolved_path"]
    @property
    def kind(self):return "artifact_no_dispatch_metadata"
    @property
    def authority_namespace(self):return self.grant.request.authority_namespace
    @property
    def original_permit(self):return self.grant
    @property
    def scope(self):return None

    def require_current_v1(self, *, phase, graph_stamp=None):
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
        from ..runtime_storage_v3 import RuntimeStorageOperationV3,_runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if (self not in _INVOCATIONS or self._issuer is not _ISSUER or phase not in {"before","after"}
                or type(self.runtime) is not InstalledArtifactDraftModelRuntimeV1
                or self.runtime.graph is not self.graph or self.runtime.bundle is not self.bundle
                or self.runtime.context._v2_artifact_draft_model_runtime_v1 is not self.runtime
                or self.thread_id!=get_ident() or self.actual_db is not self.graph._GraphCoordinator__store._db
                or type(self.retained_operation) is not RuntimeStorageOperationV3 or self.retained_operation.closed
                or self.retained_operation.operation_id!=self.operation_id
                or self.retained_operation.deadline_utc!=self.grant.core_registered_deadline_utc
                or runtime_storage_v3(self.actual_db).selection_digest!=self.selection_digest):
            raise AuthorityUnavailable("financial invocation left its actual controller/operation/selection")
        require_verified_artifact_metadata_grant_v1(self.grant,port=self.port,bundle=self.bundle)
        self.graph._admin(self.runtime.bootstrap)
        if self.actual_db.in_transaction:
            if graph_stamp is not None:
                metadata,epoch=graph_stamp;meter=current_c09_sql_meter_v2()
                current=_runtime_bounded_fixed_row_v3(self.actual_db,meter,"graph_recovery_metadata_v2",
                    ("graph_revision",),"bot=? AND persona=?",self.namespace.as_tuple)
                current_epoch=_runtime_bounded_fixed_row_v3(self.actual_db,meter,"graph_epochs",
                    ("revision",),"bot=? AND persona=?",self.namespace.as_tuple)
                if current!=(metadata.graph_revision,) or current_epoch!=(epoch.revision,):
                    raise AuthorityUnavailable("financial same-SQL graph comparison metadata changed")
            return self
        self.storage_context.require_current("business")
        observed=self.port.validate_current_artifact_no_dispatch_metadata_v1(bundle=self.bundle,grant=self.grant)
        if observed.digest!=self.grant.digest:
            raise AuthorityUnavailable("financial actual Core grant/original/current Owner lineage changed")
        return self

    def release_v1(self):
        self.retained_operation.unregister_retained_state_v3(self)
        _INVOCATIONS.pop(self,None)
        _VERIFIED.pop(self.grant,None)


def require_artifact_no_dispatch_metadata_invocation_v1(invocation, *, phase, graph_stamp=None):
    if type(invocation) is not ActualArtifactNoDispatchMetadataInvocationV1:
        raise AuthorityUnavailable("actual private Artifact financial invocation required")
    return invocation.require_current_v1(phase=phase,graph_stamp=graph_stamp)


def prepare_artifact_no_dispatch_metadata_invocation_v1(graph, *, runtime, port, grant):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    from ..host.v2_fence_port import V2FencePort
    if type(runtime) is not InstalledArtifactDraftModelRuntimeV1 or runtime.graph is not graph or type(port) is not V2FencePort:
        raise AuthorityUnavailable("actual installed Artifact/Graph/paired port required")
    require_verified_artifact_metadata_grant_v1(grant,port=port,bundle=runtime.bundle)
    graph._admin(runtime.bootstrap)
    db=graph._GraphCoordinator__store._db
    if db.in_transaction:raise AuthorityUnavailable("financial invocation must precede Graph SQL")
    handle=runtime_storage_v3(db)
    if handle is None or handle.selection_digest!=grant.selection_digest:
        raise AuthorityUnavailable("actual financial selected Graph retention handle differs")
    control=handle.context._reader
    context=handle.context
    members=tuple(m for m in context.manifest["members"] if m["role"]=="graph")
    if len(members)!=1 or (context.manifest_digest,context.pointer_version,context.storage_generation,
            members[0]["incarnation_or_journal_id"])!=(grant.storage_manifest_digest,grant.storage_pointer_version,
            grant.storage_generation,grant.graph_incarnation):
        raise AuthorityUnavailable("financial grant lost its selected same Graph/Control metadata")
    operation=begin_runtime_storage_operation_v3(db,grant.request.read_operation_id,grant.core_registered_deadline_utc)
    invocation=ActualArtifactNoDispatchMetadataInvocationV1(graph,runtime,port,runtime.bundle,grant,control,db,operation,
        members[0],context,handle.selection_digest,grant.request.namespace,grant.request.installation_id,
        grant.holder,grant.current_owner_head,grant.current_anchor,get_ident(),_ISSUER)
    try:invocation.require_current_v1(phase="before");return invocation
    except BaseException:
        invocation.release_v1();finish_runtime_storage_operation_v3(operation);raise
