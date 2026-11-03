"""Named ordinary FULL continuation: Source rights first, then exact Owner scope bytes."""
from __future__ import annotations
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..domains.d08.commitment_communication_v1 import (
    SCOPE_TYPE, SCOPE_TYPES, TERMS_SCOPE_TYPE, CommitmentTermsCommunicationIntentV2, decode_communication_scope_v1,
    scope_route_source_v1,scope_terms_match_v1,communication_scope_request_v1,communication_scope_version_key_v1, CommitmentCommunicationIntentV1, decode_commitment_communication_v1,
    commitment_terms_digest_v1,
)
from ..domains.d08.execution import _decode

_ISSUED = WeakKeyDictionary()


class _ScopeJSONColumnV1(DispatchOriginalJSONReadV3):
    def __init__(self, owner, **kwargs):
        super().__init__(owner, **kwargs)
        if self.cell is not None:
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")


class CommitmentScopeOriginalReadTaskV1:
    def __init__(self, owner):
        from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        self.material = owner.source_material.proof
        require_prepared_current_source_material_v3(self.material,
            prefinal_inventory=owner.prefinal, actual_entry=owner.prefinal.actual_entry)
        self.key = AtomKey.from_token(owner.commitment_scope_ref)
        if self.key.type_name not in SCOPE_TYPES or NamespaceId.from_key(self.key) != owner.namespace:
            raise AuthorityUnavailable("named communication scope crossed its exact registered namespace/type")
        self.scope_column = self.history_column = self.original_column = None
        self.scope = self.original = None
        self.scope_head = self.history_metadata = self.original_metadata = None
        self.phase = "scope"; self.complete = False
        self.current_self = None; self.observed = False; self.terms_dependencies=None

    def advance_v1(self, meter):
        owner = self.owner
        owner.prefinal.require_current(meter=meter)
        if self.phase == "scope":
            head = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*owner.namespace.as_tuple, self.key.token))
            expected_head=(owner.commitment_terms_locator.headers.get(self.key) if self.key.type_name==TERMS_SCOPE_TYPE else owner.heads.get(self.key.token))
            if head is None or head != expected_head or head[:2] != (1, 1):
                raise AuthorityUnavailable("actual immutable Owner communication scope is absent or changed")
            self.scope_head = head
            self.scope_column = _ScopeJSONColumnV1(owner, table="graph_atoms", column="value",
                key_columns=("token",), key=(self.key.token,), cell_id=head[2])
            self.phase = "scope_bytes"; return False
        if self.phase == "scope_bytes":
            if not self.scope_column.advance(meter): return False
            self.scope = decode_communication_scope_v1(self.scope_column.require_v3(owner))
            scope = self.scope
            if (scope.namespace != owner.namespace or scope_route_source_v1(scope) != owner.source_locator.source_ref
                    or set(self.material.roots) != set(scope.source_refs)
                    or self.material.audiences != (scope.conversation_ref,)
                    or owner.authority.audience != (scope.conversation_ref,)
                    or owner.authority.purpose != "expression"
                    or owner.commitment_send_deadline > scope.valid_until_utc):
                raise AuthorityUnavailable("Owner communication cannot borrow another Source root, external audience or deadline")
            current = owner.projection.get(scope.commitment.key)
            if current is None or not current.valid or current.revision != scope.commitment.revision:
                raise AuthorityUnavailable("Owner communication exact commitment version changed")
            commitment = _decode("d08.commitment.v1", current.value)
            if (canonical_digest(commitment) != scope.commitment_digest
                    or not scope_terms_match_v1(scope,commitment)
                    or (not set(commitment.source_refs)<=set(scope.source_refs) if type(scope) is CommitmentTermsCommunicationIntentV2 else commitment.source_refs != scope.source_refs)):
                raise AuthorityUnavailable("Owner communication original terms or full Source roots changed")
            if type(scope) is CommitmentTermsCommunicationIntentV2:
                from .current_commitment_fulfillment_source_v3 import TermsCommunicationDependenciesReadV3
                self.terms_dependencies=TermsCommunicationDependenciesReadV3(self);self.phase="terms_dependencies"
            else:self.phase="history"
            return False
        if self.phase=="terms_dependencies":
            if self.terms_dependencies.advance_v3(meter):self.phase="history"
            return False
        if self.phase == "history":
            row = meter.read_fixed_row(self.db, "graph_history", ("event_id", "valid", "value_cell_id"),
                "token=? AND revision=?", (self.key.token, 1))
            if row is None or row[:2] != (self.scope.approval_operation_id, 1):
                raise AuthorityUnavailable("communication scope lacks its actual Owner adoption history")
            self.history_metadata = row
            self.history_column = _ScopeJSONColumnV1(owner, table="graph_history", column="value",
                key_columns=("token", "revision"), key=(self.key.token, 1), cell_id=row[2])
            self.phase = "history_bytes"; return False
        if self.phase == "history_bytes":
            if not self.history_column.advance(meter): return False
            if self.history_column.require_v3(owner) != self.scope_column.require_v3(owner):
                raise AuthorityUnavailable("Owner communication current scope differs from original history")
            self.phase = "original"; return False
        if self.phase == "original":
            row=read_commitment_approval_original_header_v1(self.db,meter,owner.namespace,self.scope)
            self.original_metadata = row
            self.original_column = _ScopeJSONColumnV1(owner, table="graph_domain_production_originals_v1",
                column="original_payload_json", key_columns=("bot", "persona", "operation_id"),
                key=(*owner.namespace.as_tuple, self.scope.approval_operation_id), cell_id=None)
            self.phase = "original_bytes"; return False
        if self.phase == "original_bytes":
            if not self.original_column.advance(meter): return False
            value = self.original_column.require_v3(owner)
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from ..domains.d08.commitment_communication_v1 import RegisterCurrentCommitmentCommunicationInputRequestV1
            expected_request=communication_scope_request_v1(self.scope)
            request = decode_typed_production_value_v1(value["request"],type(expected_request))
            from ..domains.d01.production_operations_v1 import plain_v1
            from .domain_production_contracts_v1 import ProductionOwnerGuardV1
            guard = decode_typed_production_value_v1(value["owner_guard"], ProductionOwnerGuardV1)
            writes = tuple(write for write in value["writes"] if write["key"] == self.key.token)
            if (canonical_digest(value) != self.original_metadata[3]
                    or canonical_digest(plain_v1(request)) != self.original_metadata[2]
                    or guard != self.scope.owner_guard
                    or value["identity"]["operation_id"] != self.scope.approval_operation_id
                    or value["authority"]["actor"] != self.scope.approving_actor_ref
                    or len(writes) != 1 or writes[0]["value"] != self.scope_column.require_v3(owner)
                    or request != expected_request):
                raise AuthorityUnavailable("communication scope differs from actual finite Owner command receipt")
            self.original = value; self.complete = True
            _ISSUED[self] = (owner, self.material, self.key, self.scope_head, self.scope,
                self.history_metadata, self.original_metadata, canonical_digest(value))
            return True
        raise AuthorityUnavailable("unregistered commitment Source read phase")

    def observe_protected_v1(self):
        from ..host.self_identity_current_port import InstalledCurrentSelfIdentityPort
        from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
        owner = self.owner
        if owner.db.in_transaction or not self.complete:
            raise AuthorityUnavailable("current Self observation must follow complete Source/scope EOF outside SQL")
        port = owner.graph._GraphCoordinator__self_identity_port
        if type(port) is not InstalledCurrentSelfIdentityPort:
            raise AuthorityUnavailable("named promise needs the actual paired installed Self observer")
        current = port.current_self_identity(namespace=owner.namespace,
            authority_namespace=owner.fence.scope.authority_namespace,
            request_operation_id=owner.fence.scope.operation_id, permit=owner.fence.scope.permit)
        if (type(current) is not AuthorityCurrentSelfIdentityV1
                or current.permit != owner.fence.scope.permit
                or current.namespace != self.scope.namespace
                or current.role_head_id != self.scope.persona_head_id
                or current.graph_incarnation != self.scope.graph_incarnation
                or current.activation_generation != self.scope.activation_generation
                or current.owner_authorization_head.removeprefix("sha256:") != self.scope.owner_guard.owner_head_digest):
            raise AuthorityUnavailable("approved communication actual installed Self/Owner head was replaced")
        self.current_self = current; self.observed = True

    def require_current_v1(self, proof, graph, db):
        expected = _ISSUED.get(self)
        if (not self.complete or not self.observed or expected != (self.owner, self.material, self.key, self.scope_head, self.scope,
                self.history_metadata, self.original_metadata, canonical_digest(self.original))
                or proof.work.state is not self.owner or proof.operation is not self.operation
                or proof.source_material is not self.material or graph is not self.owner.graph or db is not self.db
                or self.operation.closed):
            raise AuthorityUnavailable("actual retained same-Work Owner communication scope proof required")
        head = db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*proof.namespace.as_tuple, self.key.token)).fetchone()
        if head != self.scope_head:
            raise AuthorityUnavailable("Owner communication scope head changed after its complete original read")
        return self.scope

    def release_v1(self):
        _ISSUED.pop(self, None)
        if self.terms_dependencies is not None:
            self.terms_dependencies.release_v1();self.terms_dependencies=None
        for name in ("scope_column", "history_column", "original_column"):
            column = getattr(self, name)
            if column is not None:
                column._frozen_value = None
                column.nodes = {}; column.scalar = bytearray(); column.fragment = b""
            setattr(self, name, None)
        self.scope = self.original = self.material = self.current_self = None


def read_commitment_approval_original_header_v1(db,meter,namespace,scope):
    row=meter.read_fixed_row(db,'graph_domain_production_originals_v1',
        ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,scope.approval_operation_id))
    expected_kind='input:register_commitment_terms_communication'if type(scope)is CommitmentTermsCommunicationIntentV2 else'input:register_commitment_communication'
    if row is None or row[:2]!=('d08',expected_kind):
        raise AuthorityUnavailable('Scope lacks its actual registered Owner producer Original')
    bundle=meter.read_fixed_row(db,'graph_bundle_operations',('digest','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,scope.approval_operation_id))
    from ..domains.d08.commitment_communication_v1 import communication_scope_key_v1
    scope_key=communication_scope_version_key_v1(scope)
    history=meter.read_fixed_row(db,'graph_history',('event_bot','event_persona','event_id','valid'),
        'token=? AND revision=?',(scope_key.token,1))
    if bundle is None or bundle[0]!=row[4]or bundle[1]<1 or history!=(*namespace.as_tuple,scope.approval_operation_id,1):
        raise AuthorityUnavailable('Scope approval Original is not the same actual W01 ledger/history adoption')
    return row
