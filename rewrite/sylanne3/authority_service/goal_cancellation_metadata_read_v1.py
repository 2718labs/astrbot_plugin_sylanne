"""Fixed scalar Goal management EOF; no retained Goal/Source text or expression."""
from dataclasses import asdict
from hashlib import sha256
import json
from .contract import AuthorityUnavailable
from .owner_goal_cancellation_contract_v1 import GoalCancellationMetadataV1
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2, read_legacy_sql_cell_fragment_v2
from .c09_selected_history_v3 import _read_one
from ..graph_types import AtomKey, owner_grant_key


class _GoalMetadataCanonicalColumnV1:
    def __init__(self, invocation, *, kind, owner_work):
        from .owner_goal_cancellation_v1 import GoalManagementInvocationV1
        from .goal_projection_metadata_invocation_v1 import GoalProjectionMetadataInvocationV1
        if type(invocation) not in {GoalManagementInvocationV1,GoalProjectionMetadataInvocationV1} or kind not in {"goal","root"}:
            raise AuthorityUnavailable("actual fixed Goal management column required")
        self.invocation,self.kind,self.owner_work = invocation,kind,owner_work
        request = invocation.original_request
        self.table = "graph_atoms" if kind == "goal" else "graph_d11_life_originals_v1"
        self.column = "value" if kind == "goal" else "payload_json"
        self.where = "token=? AND bot=? AND persona=?" if kind == "goal" else "bot=? AND persona=? AND kind=? AND original_ref=?"
        self.parameters = ((request.goal_ref,*request.namespace.as_tuple) if kind == "goal" else
            (*request.namespace.as_tuple,"draft_root_capability",request.root_registration_ref))
        self.position,self.length,self.ordinal = 0,None,0
        self.cell_id,self.header,self.metadata,self.parser = None,None,None,None
        self.segment_root,self.sha256 = None,None
        self.scalar = bytearray(); self.values={}; self.complete=False
        self.nodes = 0

    def _event(self, event):
        # Only exact top-level scalar identities are retained. All predicate,
        # reason, abandon-condition and Source material is skipped by construction.
        names = {"goal_id","revision","state"} if self.kind == "goal" else {"registration_ref"}
        if len(event.path) == 1 and event.path[0] in names:
            if event.kind == "scalar_start": self.scalar.clear()
            elif event.kind == "scalar_chunk":
                if len(self.scalar) + len(event.raw) > 4096:
                    raise AuthorityUnavailable("actual Goal metadata scalar exceeds its existing identity bound")
                self.scalar.extend(event.raw)
            elif event.kind == "scalar_end":
                self.values[event.path[0]] = json.loads(bytes(self.scalar)); self.scalar.clear()

    def advance_v1(self, db, meter):
        invocation = self.invocation
        invocation.require_current_v1(phase="before")
        view = self.owner_work.view
        if self.complete: return
        if self.length is None:
            if self.kind == "goal":
                segmented = _read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'",(),meter) is not None
                self.metadata = _read_one(db,("SELECT revision,valid,value_cell_id FROM graph_atoms " if segmented else
                    "SELECT revision,valid FROM graph_atoms ")+"WHERE "+self.where,self.parameters,meter)
                expected = invocation.original_request.expected_goal_atom_revision
                if self.metadata is None or self.metadata[:2] != (expected,1):
                    raise AuthorityUnavailable("actual current Goal metadata version is missing/stale")
                self.cell_id = self.metadata[2] if segmented else None
            else:
                self.metadata = _read_one(db,"SELECT producing_operation_id,payload_digest,signature FROM "+self.table+
                    " WHERE "+self.where,self.parameters,meter)
                if self.metadata is None: raise AuthorityUnavailable("actual registered target C4 root original is absent")
            if self.cell_id is not None:
                from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
                self.header = meter.read_fixed_row(db,"segmented_cells_v1",
                    ("codec_id","erasure_owner_ref","producer_operation_id","total_bytes","segment_count",
                     "payload_sha256","ordered_segment_root","origin_scope_digest"),"cell_id=?",(self.cell_id,))
                if self.header is None or self.header[0] not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"} or self.header[1] != self.parameters[0]:
                    raise AuthorityUnavailable("actual Goal canonical cell/origin differs")
                read_selected_runtime_cell_origin_v3(db,selected_basis=view,role="graph",
                    cell_id=self.cell_id,header=self.header,meter=meter)
                self.length = self.header[3]
                self.segment_root = canonical_digest(("sylanne3.segmented-cell-genesis.v1",self.cell_id))
                self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.header[0] == "canonical-json.ascii.v1")
            else:
                with legacy_cell_read_transaction_v2(db):
                    _,self.length,kind = read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=0,length=0,meter=meter)
                if kind != "text": raise AuthorityUnavailable("actual Goal/root metadata column changed storage kind")
                self.parser = C09CanonicalJSONStreamV2(ensure_ascii=False)
        if self.position < self.length:
            if self.cell_id is not None:
                row = meter.read_fixed_row(db,"segmented_cell_segments_v1",("byte_offset","payload","payload_sha256"),
                    "cell_id=? AND ordinal=?",(self.cell_id,self.ordinal))
                if (row is None or row[0] != self.position or type(row[1]) is not bytes
                        or not 0 < len(row[1]) <= 16384 or sha256(row[1]).hexdigest() != row[2]):
                    raise AuthorityUnavailable("actual Goal metadata segment/ordered bytes differ")
                chunk = row[1]
                self.segment_root = canonical_digest(("sylanne3.segmented-cell-link.v1",self.segment_root,
                    self.cell_id,self.ordinal,self.position,len(chunk),row[2]))
                self.ordinal += 1
            else:
                with legacy_cell_read_transaction_v2(db):
                    chunk,total,kind = read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=self.position,
                        length=min(16384,self.length-self.position),meter=meter)
                if total != self.length or kind != "text":
                    raise AuthorityUnavailable("actual Goal/root metadata byte length changed during EOF")
            self.parser.feed(chunk,self._event); self.position += len(chunk)
            return
        if self.cell_id is not None and (self.ordinal != self.header[4] or self.segment_root != self.header[6]
                or _read_one(db,"SELECT 1 FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1",
                    (self.cell_id,self.ordinal),meter) is not None):
            raise AuthorityUnavailable("actual Goal cell count/root/extra EOF differs")
        result = self.parser.finish()
        if result.byte_count != self.length or self.cell_id is not None and result.sha256 != self.header[5]:
            raise AuthorityUnavailable("actual Goal metadata canonical whole EOF differs")
        self.sha256,self.complete = result.sha256,True


class GoalCancellationMetadataReadWorkV1:
    def __init__(self, invocation, *, owner_proof, owner_work, owner_facts):
        from .owner_goal_cancellation_v1 import GoalManagementInvocationV1,require_goal_management_invocation_v1
        from .goal_projection_metadata_invocation_v1 import GoalProjectionMetadataInvocationV1,require_goal_projection_metadata_invocation_v1
        if type(invocation) is GoalManagementInvocationV1:
            require_goal_management_invocation_v1(invocation,phase="before")
        elif type(invocation) is GoalProjectionMetadataInvocationV1:
            require_goal_projection_metadata_invocation_v1(invocation,phase="before")
        else:raise AuthorityUnavailable("actual private Goal metadata invocation required")
        owner_facts.require_for_v3(owner_proof)
        self.invocation,self.owner_proof,self.owner_work,self.owner_facts = invocation,owner_proof,owner_work,owner_facts
        self.phase,self.complete,self.result,self.grant = "owner",False,None,None
        self.column,self.goal_column,self.root_column,self.pending = None,None,None,None
        self.closed = False
        invocation.retained_operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        from .owner_location_read_v3 import _owner_location_parser_heap_v3
        seen={id(self)}
        amount=sys.getsizeof(self)+sys.getsizeof(self.__dict__)
        for name,value in self.__dict__.items():
            amount+=_actual_metadata_heap_v1(name,seen)
            if name not in {"invocation","owner_work","column","goal_column","root_column"}:
                amount+=_actual_metadata_heap_v1(value,seen)
        for column in (self.column,self.goal_column,self.root_column):
            if column is None or id(column) in seen:continue
            seen.add(id(column))
            amount+=sys.getsizeof(column)+sys.getsizeof(column.__dict__)
            for name,value in column.__dict__.items():
                amount+=_actual_metadata_heap_v1(name,seen)
                if name not in {"invocation","owner_work","parser"}:
                    amount+=_actual_metadata_heap_v1(value,seen)
            if column.parser is not None:amount+=_owner_location_parser_heap_v3(column.parser,seen)
        return amount
    def advance_v1(self, meter):
        if self.closed: raise AuthorityUnavailable("Goal metadata Work ended")
        operation = self.invocation.retained_operation
        operation.reserve_retained_state_growth_v3(self, 262144)
        try:
            return self._advance_reserved_v1(meter)
        finally:
            operation.finish_retained_state_growth_v3(self)

    def _advance_reserved_v1(self, meter):
        if self.closed: raise AuthorityUnavailable("Goal metadata Work ended")
        i = self.invocation; db=i.actual_db
        i.require_current_v1(phase="before")
        self.owner_facts.require_for_v3(self.owner_proof)
        i.retained_operation.refresh_retained_state_v3(self)
        if self.phase == "owner":
            from .owner_location_read_v3 import _owner_wire_digest_v3
            grant = json.loads(self.owner_facts.atom[1]); head=i.current_owner_head
            if (self.owner_facts.atom[0] != 1 or self.owner_facts.atom[2] != 1
                    or _owner_wire_digest_v3(grant) != head.grant_digest
                    or grant["principal"] != asdict(i.principal)
                    or grant["principal"] != asdict(head.issue_operation.principal)
                    or "workbench.control" not in grant["capabilities"]
                    or "workbench_user_action" not in grant["purposes"] or "owner" not in grant["audiences"]
                    or json.loads(self.owner_facts.proof_row[8]) != asdict(head.issue_proof)):
                raise AuthorityUnavailable("actual Goal management signed Owner grant/issue/control scope differs")
            self.grant = (owner_grant_key(*i.namespace.as_tuple).token,1,head.grant_digest.removeprefix("sha256:"))
            from ..runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1
            goal_key = artifact_goal_plan_keys_v1(i.namespace,c02_operation_id=i.original_request.c02_operation_id,
                root_registration_ref=i.original_request.root_registration_ref)[0]
            if goal_key.token != i.original_request.goal_ref:
                raise AuthorityUnavailable("Goal management selector retargeted the original C4 root task")
            self.column = _GoalMetadataCanonicalColumnV1(i,kind="goal",owner_work=self.owner_work);self.phase="goal";return
        if self.phase in {"goal","root"}:
            self.column.advance_v1(db,meter)
            if not self.column.complete: return
            if self.phase == "goal":
                self.goal_column = self.column
                self.column = _GoalMetadataCanonicalColumnV1(i,kind="root",owner_work=self.owner_work); self.phase="root"
            else:
                self.root_column=self.column;self.column=None;self.phase="joins"
            return
        if self.phase == "joins":
            request=i.original_request;goal=self.goal_column;root=self.root_column
            current_goal=_read_one(db,
                ("SELECT revision,valid,value_cell_id FROM graph_atoms " if goal.cell_id is not None
                    else "SELECT revision,valid FROM graph_atoms ")+"WHERE token=? AND bot=? AND persona=?",
                (request.goal_ref,*request.namespace.as_tuple),meter)
            if current_goal!=goal.metadata:
                raise AuthorityUnavailable("Goal metadata observation changed its accepted version before EOF publication")
            from ..runtime.d11_life_preparation_v1 import SIGN_KIND
            if root.sha256 != root.metadata[1] or root.sha256 != request.root_registration_digest or root.values != {"registration_ref":request.root_registration_ref}:
                raise AuthorityUnavailable("actual target C4 root EOF commitment/identity differs")
            i.issuer._signer.verify(SIGN_KIND,canonical_serialize((request.namespace,"draft_root_capability",
                request.root_registration_ref,root.sha256)),root.metadata[2])
            history=_read_one(db,"SELECT event_bot,event_persona,event_session,event_id,valid FROM graph_history WHERE token=? AND revision=?",
                (request.goal_ref,request.expected_goal_atom_revision),meter)
            if history is None or history[:2] != request.namespace.as_tuple or history[3:] != (request.goal_producing_operation_id,1):
                raise AuthorityUnavailable("actual Goal producing metadata history differs")
            event=_read_one(db,"SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                (*request.namespace.as_tuple,history[2],request.goal_producing_operation_id),meter)
            if event != (request.goal_producing_digest,):
                raise AuthorityUnavailable("actual Goal producing operation digest differs")
            values=goal.values
            self.pending=GoalCancellationMetadataV1(request.namespace,request.goal_ref,request.expected_goal_atom_revision,
                values["revision"],values["goal_id"],values["state"],goal.sha256,history[3],event[0],
                request.c02_operation_id,request.root_registration_ref,root.sha256,
                self.owner_facts.metadata.graph_revision,self.owner_facts.graph_epoch.revision,i.selection_digest)
            self.pending.require_request_v1(request);self.phase="quantum_commit"
            return
        if self.phase != "quantum_commit": raise AuthorityUnavailable("unregistered Goal metadata Work phase")

    def complete_quantum_v1(self):
        if self.phase == "quantum_commit":
            self.invocation.require_current_v1(phase="after")
            self.result,self.complete = self.pending,True

    def require_result_v1(self):
        if self.closed or not self.complete:
            raise AuthorityUnavailable("actual completed Goal metadata whole EOF required")
        return self.result

    def require_owner_grant_v1(self):
        self.require_result_v1();return self.grant

    def close_v1(self):
        if not self.closed:
            self.invocation.retained_operation.unregister_retained_state_v3(self)
            self.closed=True
