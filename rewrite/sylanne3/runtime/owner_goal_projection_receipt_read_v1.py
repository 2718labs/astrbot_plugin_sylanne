"""Fixed original receipt EOF under a current private Goal metadata observation."""
from weakref import WeakSet
from dataclasses import asdict
from sys import getsizeof
from ..authority_service.contract import AuthorityUnavailable
from .owner_goal_projection_issuance_v1 import require_owner_goal_projection_v1
from .owner_goal_projection_v1 import TABLE,COLUMNS,validate_goal_projection_row_v1
from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
from .artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1

_LIVE=WeakSet()

class GoalProjectionReceiptReadWorkV1:
    def __init__(self,issued):
        observed=require_owner_goal_projection_v1(issued,issued.graph,issued.scope)
        if observed.scope_kind not in {"projection_write","projection_lookup"}:
            raise AuthorityUnavailable("actual Goal metadata receipt read observation required")
        self.core_invocation=self.core_facts=self.core_proof=None
        self.issued=issued;self.graph=issued.graph;self.scope=issued.scope
        self.db=self.graph._GraphCoordinator__store._db
        self.namespace=self.scope.namespace;self.operation=issued.retained_operation
        self.prefinal=self;self.closed=False;self.complete=False;self.result=None
        self.point=None;self.event_point=None;self.attempt_point=None
        _LIVE.add(self);self.operation.register_retained_state_v3(self)
        original=observed.original
        self.point=_HostProducerAttachmentV3(self,(TABLE,COLUMNS,
            ("bot","persona","goal_ref","root_registration_ref"),
            (*self.namespace.as_tuple,original.request.goal_ref,original.request.root_registration_ref)))

    @classmethod
    def from_actual_core_projection_v1(cls,invocation,*,owner_proof,owner_facts):
        from ..authority_service.goal_projection_metadata_invocation_v1 import require_goal_projection_metadata_invocation_v1
        require_goal_projection_metadata_invocation_v1(invocation,phase="before")
        owner_facts.require_for_v3(owner_proof)
        if invocation.scope_kind!="projection_write":
            raise AuthorityUnavailable("pending W01 bridge requires its held original WRITE")
        work=object.__new__(cls)
        work.core_invocation,work.core_facts,work.core_proof=invocation,owner_facts,owner_proof
        work.issued=work.graph=None;work.scope=invocation.original_permit
        work.db=invocation.actual_db;work.namespace=invocation.namespace;work.operation=invocation.retained_operation
        work.prefinal=work;work.closed=False;work.complete=False;work.result=None
        work.point=work.event_point=work.attempt_point=None
        _LIVE.add(work);work.operation.register_retained_state_v3(work)
        original=invocation.original
        work.point=_HostProducerAttachmentV3(work,(TABLE,COLUMNS,("bot","persona","goal_ref","root_registration_ref"),
            (*work.namespace.as_tuple,original.request.goal_ref,original.request.root_registration_ref)))
        return work

    @property
    def original(self):
        return self.core_invocation.original if self.core_invocation is not None else self.issued.observation.original
    @property
    def issuer(self):
        return self.core_invocation.issuer if self.core_invocation is not None else self.graph._GraphCoordinator__d11_issuer

    def require_current(self,*,meter=None):
        if self not in _LIVE or self.closed or self.operation.closed:
            raise AuthorityUnavailable("Goal receipt metadata Work is no longer live")
        if self.core_invocation is not None:
            self.core_invocation.require_current_v1(phase="before")
            self.core_facts.require_for_v3(self.core_proof)
        else:
            require_owner_goal_projection_v1(self.issued,self.graph,self.scope)
            metadata,epoch=self.graph._v2_graph_stamp(self.namespace)
            if self.issued.successor_view is not None:
                self.issued.successor_view.require_current_v1(self.issued)
            elif metadata.graph_revision!=self.scope.graph_revision or epoch!=self.scope.graph_epoch:
                raise AuthorityUnavailable("Goal receipt changed its actual selected Graph snapshot")
        self.operation.handle.require_current(meter)
        return self
    def _actual(self):return self.require_current()
    def _runtime_retained_heap_bytes_v3(self):
        seen={id(self)}
        amount=getsizeof(self)+getsizeof(self.__dict__)
        for name,value in self.__dict__.items():
            if name not in {"issued","graph","scope","db","operation","prefinal","point","event_point","attempt_point","core_invocation","core_facts","core_proof"}:
                amount+=_actual_metadata_heap_v1(name,seen)+_actual_metadata_heap_v1(value,seen)
        from ..authority_service.owner_location_read_v3 import _owner_location_parser_heap_v3
        for point in (self.point,self.event_point,self.attempt_point):
            if point is None or id(point) in seen:continue
            seen.add(id(point));amount+=getsizeof(point)+getsizeof(point.__dict__)
            for name,value in point.__dict__.items():
                if name not in {"owner","column","json_columns","stream"}:
                    amount+=_actual_metadata_heap_v1(name,seen)+_actual_metadata_heap_v1(value,seen)
            for column in tuple(point.json_columns.values())+(() if point.column is None else (point.column,)):
                if id(column) in seen:continue
                seen.add(id(column));amount+=getsizeof(column)+getsizeof(column.__dict__)
                for name,value in column.__dict__.items():
                    if name not in {"owner","db","operation","parser","cell"}:
                        amount+=_actual_metadata_heap_v1(name,seen)+_actual_metadata_heap_v1(value,seen)
                amount+=_owner_location_parser_heap_v3(column.parser,seen)
        return amount

    def advance(self,meter):
        self.require_current(meter=meter)
        if self.complete:return
        if not self.point.complete:self.point.advance(meter);return
        if self.point.row is None:self.complete=True;return
        if self.event_point is None:
            _,receipt=validate_goal_projection_row_v1(COLUMNS,self.point.row,
                issuer=self.issuer)
            original=self.original
            if (receipt.goal_ref,receipt.root_registration_ref,receipt.root_registration_digest)!=(
                    original.request.goal_ref,original.request.root_registration_ref,original.request.root_registration_digest):
                raise AuthorityUnavailable("Goal receipt belongs to another stable Goal/root")
            self.event_point=_HostProducerAttachmentV3(self,("graph_events",("digest",),
                ("bot","persona","session","event_id"),(*self.namespace.as_tuple,receipt.event_session,receipt.operation_id)))
            return
        if not self.event_point.complete:self.event_point.advance(meter);return
        _,receipt=validate_goal_projection_row_v1(COLUMNS,self.point.row,
            issuer=self.issuer)
        if self.event_point.row!=(receipt.event_digest,):
            raise AuthorityUnavailable("Goal projection lost its actual same-CAS event original")
        if self.core_invocation is not None:
            if receipt.operation_id!=self.core_invocation.operation_id:
                self.result=receipt;self.complete=True;return
            if self.attempt_point is None:
                self.attempt_point=_HostProducerAttachmentV3(self,("graph_owner_domain_attempts_v3",
                    ("request_digest","attempt_id","anchor_json","graph_revision","graph_epoch","permit_json","receipt_json"),
                    ("bot","persona","operation_id"),(*self.namespace.as_tuple,receipt.operation_id)))
                return
            if not self.attempt_point.complete:self.attempt_point.advance(meter);return
            import json
            from ..authority_service.v2_contract import to_wire
            from ..runtime_contracts import canonical_digest,canonical_serialize
            attempt=self.attempt_point.row;permit=self.core_invocation.original_permit
            row=self.point.row
            if (attempt is None or attempt[0:2]!=(receipt.request_digest,receipt.operation_id)
                    or json.loads(attempt[2])!=asdict(permit.pinned_anchor)
                    or attempt[3:5]!=(receipt.before_graph_revision,receipt.before_graph_epoch)
                    or json.loads(attempt[5])!=to_wire(permit) or attempt[6]!=row[9]
                    or (self.core_facts.metadata.graph_revision,self.core_facts.graph_epoch.revision)!=(
                        receipt.after_graph_revision,receipt.after_graph_epoch)):
                raise AuthorityUnavailable("pending Goal W01 bridge lacks actual same-attempt before/after COMMIT")
            from ..authority_service.owner_goal_projection_contract_v1 import GoalProjectionCommittedBridgeV1
            self.result=GoalProjectionCommittedBridgeV1(receipt.operation_id,receipt.request_digest,receipt.permit_digest,
                receipt.before_graph_revision,receipt.before_graph_epoch,receipt.after_graph_revision,receipt.after_graph_epoch,
                receipt.observation_digest,receipt.before_metadata_json,receipt.before_epoch_json,
                receipt.after_metadata_json,receipt.after_epoch_json,row[9],row[10],row[11],receipt.event_digest,canonical_digest(row),
                canonical_digest(attempt),self.core_invocation.selection_digest,
                canonical_digest((asdict(self.core_invocation.current_owner_head),
                    self.original.owner_grant_ref,self.core_facts.atom[0],
                    self.core_invocation.current_owner_head.grant_digest.removeprefix("sha256:"))))
            self.result.require_local_signature_v1(self.issuer,self.original)
            self.complete=True;return
        self.result=receipt;self.complete=True

    def require_result(self):
        self.require_current()
        if not self.complete:raise AuthorityUnavailable("Goal projection receipt whole metadata EOF required")
        return self.result
    def close_v1(self):
        if self.closed:return
        self.closed=True;_LIVE.discard(self)
        self.operation.unregister_retained_state_v3(self)
        from .dispatch_initial_source_read_v3 import _COLUMNS
        for point in (self.point,self.event_point,self.attempt_point):
            if point is None:continue
            for column in tuple(point.json_columns.values())+(() if point.column is None else (point.column,)):
                _COLUMNS.pop(column,None)
            point.json_columns.clear();point.column=None
        self.point=self.event_point=self.attempt_point=None

def require_goal_projection_receipt_read_work_v1(work,*,db):
    if type(work) is not GoalProjectionReceiptReadWorkV1 or work.db is not db:
        raise AuthorityUnavailable("actual fixed Goal receipt metadata Work required")
    return work.require_current()
