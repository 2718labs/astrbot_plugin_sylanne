"""Read-only replay of one actual named communication receipt, before literal access."""
from __future__ import annotations
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import CommitReceipt, canonical_digest
from ..runtime_contracts import OperationIdentity
from ..domains.d08.commitment_communication_v1 import TERMS_SCOPE_TYPE,commitment_communication_effect_id_v1
from .d08_commitment_scope_read_v1 import _ScopeJSONColumnV1
from ..host.post_c02_reply_driver import post_c02_reply_operation_id


class _NamedActionRecoveryMetadataV1(_ScopeJSONColumnV1):
    def _emit(self,event):
        if not event.path or event.path[0] in {"identity","action_id","source_refs"}:
            super()._emit(event)


class CommitmentCommunicationRecoveryReadV1:
    def __init__(self, owner):
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        self.operation_id = post_c02_reply_operation_id(owner.source_locator.c02_operation_id, owner.source_locator.source_ref)
        self.phase = "header"; self.columns = {}; self.column = None
        self.fence_header = None;self.header = self.event_epoch = None; self.result = None; self.complete = False
        self.operation.retain(65536)

    def _begin(self, tag, *, table, column, keys, key, cell_id=None):
        cls=_NamedActionRecoveryMetadataV1 if tag=="action" else _ScopeJSONColumnV1
        source=cls(self.owner,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id)
        if tag=="action":
            from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
            source.parser=_MetadataStreamV3(source,source.cell is None or source.cell.header[0]=="canonical-json.ascii.v1")
        self.column=(tag,source)

    def value(self, tag): return self.columns[tag].require_v3(self.owner)

    def advance(self, meter):
        owner = self.owner
        if self.complete: return True
        if self.column is not None:
            tag, column = self.column
            if column.advance(meter): self.columns[tag] = column; self.column = None
            return False
        if self.phase == "header":
            self.header = meter.read_fixed_row(self.db, "graph_bundle_operations",
                ("digest", "activity_id", "effect_id", "commit_seq"), "bot=? AND persona=? AND operation_id=?",
                (*owner.namespace.as_tuple, self.operation_id))
            if self.header is None: self.complete = True; return True
            self._begin("receipt", table="graph_bundle_operations", column="receipt_json",
                keys=("bot", "persona", "operation_id"), key=(*owner.namespace.as_tuple, self.operation_id))
            self.phase = "event"; return False
        if self.phase == "event":
            candidate = self.value("receipt").get("dispatch_candidate")
            if (type(candidate) is not dict or candidate.get("schema") != "sylanne.d11.dispatch_candidate.v1"
                    or candidate.get("status") != "source_qualified" or len(candidate.get("refs", ())) != 4
                    or candidate.get("source_refs") != [owner.source_locator.source_ref]):
                raise AuthorityUnavailable("existing operation is not this actual named generic Source-qualified receipt")
            self.candidate = candidate
            self.fence_header=meter.read_fixed_row(self.db,'graph_bundle_fences_v2',
                ('digest','pre_graph_revision','pre_graph_epoch','post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'),
                'bot=? AND persona=? AND operation_id=?',(*owner.namespace.as_tuple,self.operation_id))
            if self.fence_header is None or self.fence_header[0]!=self.header[0]:
                raise AuthorityUnavailable('named recovered receipt lost its actual original writer fence')
            self._begin('permit',table='graph_bundle_fences_v2',column='permit_json',keys=('bot','persona','operation_id'),key=(*owner.namespace.as_tuple,self.operation_id))
            self.phase='event_metadata';return False
        if self.phase == 'event_metadata':
            row = meter.read_fixed_row(self.db, "graph_events", ("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?", (*owner.namespace.as_tuple, self.header[1], self.operation_id))
            if row is None or row[0] != self.candidate["graph_epoch"]:
                raise AuthorityUnavailable("named receipt recovery lost its actual graph event")
            self.event_epoch = row[0]; self.queue = ["reads", "revisions"]; self.phase = "event_columns"; return False
        if self.phase == "event_columns":
            if self.queue:
                tag = self.queue.pop(0)
                self._begin(tag, table="graph_events", column=tag, keys=("bot", "persona", "session", "event_id"),
                    key=(*owner.namespace.as_tuple, self.header[1], self.operation_id)); return False
            ref, revision = self.candidate["refs"][0]; key = AtomKey.from_token(ref)
            if key.type_name != "d08.action_intent.v1" or [ref, revision] not in self.value("revisions"):
                raise AuthorityUnavailable("named recovery action is outside its actual committed event")
            row = meter.read_fixed_row(self.db, "graph_history", ("value_cell_id", "valid", "event_id"),
                "token=? AND revision=?", (ref, revision))
            if row is None or row[1:] != (1, self.operation_id):
                raise AuthorityUnavailable("named recovery actual action history was removed")
            self._begin("action", table="graph_history", column="value", keys=("token", "revision"),
                key=(ref, revision), cell_id=row[0]); self.phase = "verify"; return False
        if self.phase == "verify":
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            action=self.value("action")
            identity=decode_typed_production_value_v1(action["identity"],OperationIdentity)
            scope_key = AtomKey.from_token(owner.commitment_scope_ref)
            expected = canonical_digest({"scope": scope_key.token, "source": owner.source_locator.source_ref,
                "c02": owner.source_locator.c02_operation_id})
            effect = commitment_communication_effect_id_v1(scope_key.name)
            if (identity.phase != "commitment_literal_v1" or identity.canonical_input_digest != expected
                    or identity.operation_id != self.operation_id or identity.effect_id != effect
                    or self.header[1:3] != (identity.activity_id, effect)
                    or (not 1<=len(action["source_refs"])<=32 or owner.source_locator.source_ref not in action["source_refs"]
                        if scope_key.type_name==TERMS_SCOPE_TYPE else tuple(action["source_refs"])!=(owner.source_locator.source_ref,))
                    or [scope_key.token, 1] not in self.value("reads")):
                raise AuthorityUnavailable("existing receipt belongs to another original Scope/C02/Source intent")
            from .post_c02_reply_bundle_v2 import post_c02_dispatch_runtime_refs_v2
            job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(owner.namespace, identity)
            detail = self.value("receipt")
            if job_ref not in detail["ledger_refs"] and outbox_ref not in detail["outbox_refs"]:
                # Graph receipts may expose the job only through its outbox; the
                # exact same-event runtime row remains mandatory below.
                raise AuthorityUnavailable("named recovered receipt lost actual outbox/ledger identity")
            for ref in (job_ref, outbox_ref):
                if not any(row[0] == ref and row[1] == 1 for row in self.value("revisions")):
                    raise AuthorityUnavailable("named recovered runtime targets were not written by its actual event")
            receipt = CommitReceipt("committed", self.operation_id, self.header[0], self.header[1], self.header[2], self.header[3],
                tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in self.value("reads")),
                tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in self.value("revisions")),
                (NamespaceEpoch(*owner.namespace.as_tuple, self.event_epoch),),
                tuple(detail["ledger_refs"]), tuple(detail["outbox_refs"]))
            self.result = {"status": "commitment_communication_dispatch_committed", "operation_id": self.operation_id,
                "scope_ref": owner.commitment_scope_ref, "commit_receipt": receipt,
                "job_ref": job_ref, "outbox_ref": outbox_ref, "recovered": True}
            self.complete = True; return True
        raise AuthorityUnavailable("unregistered named receipt-recovery metadata phase")

    def require_current_v1(self, proof, graph, db):
        if (not self.complete or self.result is None or proof.work.state is not self.owner
                or proof.operation is not self.operation or graph is not self.owner.graph or db is not self.db
                or self.operation.closed):
            raise AuthorityUnavailable("actual complete named receipt-recovery Work required")
        row = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?", (*self.owner.namespace.as_tuple, self.operation_id)).fetchone()
        if row != self.header:
            raise AuthorityUnavailable("actual named original receipt changed during metadata recovery")
        return self.result

    def finish_original_v1(self,graph):
        from ..authority_service.v2_contract import from_wire,FencePermitV2
        from ..runtime_contracts import FenceScope
        from ..host.v2_fence_port import V2FenceOutcomeUnknown
        owner=self.owner
        if self.db.in_transaction or graph is not owner.graph or self.result is None:
            raise AuthorityUnavailable('named recovery original finish requires its actual outside-SQL phase')
        permit=from_wire(self.value('permit'))
        authority_namespace=owner.graph_stamp[0].requirements.authority_namespace
        if type(permit)is not FencePermitV2 or permit.operation!='write' or permit.namespace!=authority_namespace:
            raise AuthorityUnavailable('named recovery has another actual fence permit')
        port=graph._GraphCoordinator__content_fence_v2
        observed,state=port.get_fence_operation(namespace=owner.namespace,authority_namespace=authority_namespace,operation_id=permit.operation_id)
        if observed!=permit or state not in {'active','finished'}:
            raise V2FenceOutcomeUnknown('named original commit finish remains unresolved')
        if state=='active':
            with owner.store._lock:
                metadata,epoch=graph._v2_graph_stamp(owner.namespace)
                current=self.db.execute('SELECT digest,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?',(*owner.namespace.as_tuple,self.operation_id)).fetchone()
                if current!=self.fence_header or (metadata.graph_revision,epoch.revision)!=self.fence_header[3:5]:
                    raise V2FenceOutcomeUnknown('named committed original graph changed before finish recovery')
            scope=FenceScope(owner.namespace,authority_namespace,permit.generation,'write',permit.operation_id,permit,
                permit.pinned_anchor,NamespaceEpoch(*owner.namespace.as_tuple,self.fence_header[2]),self.fence_header[1])
            if port.validate_fence(scope)!=permit:raise V2FenceOutcomeUnknown('named original permit changed before finish replay')
            port.finish_fence(scope,request_id=self.fence_header[5],request_digest=self.fence_header[6])

    def release_v1(self):
        for column in self.columns.values(): column._frozen_value = None
        self.columns = {}; self.column = self.result = None
