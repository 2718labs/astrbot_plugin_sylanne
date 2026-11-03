"""Named generic P1/P2 SourceALL continuation and private exact-scope lifetime."""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, GraphAtom
from ..runtime_contracts import canonical_digest
from ..domains.d08.execution import _decode
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.commitment_communication_v1 import (
    USE_TYPE, USE_TYPES, CommitmentTermsCommunicationIntentV2, decode_communication_scope_v1, decode_communication_use_v1,
    scope_route_source_v1, communication_scope_request_v1, CommitmentCommunicationIntentV1, CommitmentPromiseUseV1,
    RegisterCurrentCommitmentCommunicationInputRequestV1, decode_commitment_communication_v1)
from .d08_commitment_scope_read_v1 import _ScopeJSONColumnV1

_TASKS = WeakKeyDictionary()
_BOUND = ContextVar("actual_named_commitment_dispatch_originals_v1", default=None)


class NamedCommitmentDispatchReadV1:
    def __init__(self, owner, action):
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        self.action = action; self.namespace = owner.namespace; self.operation_id = owner.binding.operation_id
        self.roots = tuple(action.source_refs)
        qualified = owner._require_source_roots_v3(self.roots, "expression", owner.admission.admission.audience)
        if not 1 <= len(self.roots) <= 32 or not set(self.roots) <= set(qualified):
            raise AuthorityUnavailable("named generic literal cannot precede complete current SourceALL expression qualification")
        self.qualified_sources = frozenset(qualified)
        self.columns = {}; self.current = None; self.queue = []
        self.phase = "bundle"; self.complete = False; self.needs_protected_observation = False
        self.observed = False; self.current_self = None; self.result = None
        self.scope = self.use = None; self.scope_head = self.use_head = None
        self.metadata = None; self.event_epoch = None; self.owner_original_metadata = None; self.terms_dependencies=None
        self.turn_order_head=None;self.turn_order_atom=None;self.slot_after="";self.slot_column=None;self.slot_scratch_peak=0;self.reservation=None
        owner.operation.retain(65536)
        _TASKS[self] = (owner, owner.operation, owner.fence.scope, action, self.qualified_sources)

    def _actual(self):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        owner = self.owner
        if (type(owner) is not _DispatchInventoryReadV3 or owner.family != "private_reply"
                or _TASKS.get(self) != (owner, owner.operation, owner.fence.scope, self.action, self.qualified_sources)
                or owner.operation.closed or not owner.graph_eof
                or owner.graph._v2_graph_stamp(owner.namespace) != owner.graph_stamp):
            raise AuthorityUnavailable("named generic source read lost its actual ordinary Work/Source EOF/stamp")

    def _begin(self, tag, *, table, column, keys, key, cell_id=None):
        self.current = (tag, _ScopeJSONColumnV1(self.owner, table=table, column=column,
            key_columns=keys, key=key, cell_id=cell_id))

    def _history(self, meter, tag, ref, revision, *, event_id=None):
        row = meter.read_fixed_row(self.db, "graph_history",
            ("value_cell_id", "valid", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=?", (ref, revision))
        key = AtomKey.from_token(ref)
        if (row is None or row[1] != 1 or (key.owner.bot, key.owner.persona) != self.namespace.as_tuple
                or row[2:4] != self.namespace.as_tuple or event_id is not None and row[5] != event_id):
            raise AuthorityUnavailable("named scope/use historical member lost its actual namespace/adoption event")
        self._begin(tag, table="graph_history", column="value", keys=("token", "revision"),
            key=(ref, revision), cell_id=row[0])

    def value(self, tag):
        return self.columns[tag].require_v3(self.owner)

    def advance(self, meter):
        self._actual()
        if self.complete: return True
        if self.current is not None:
            tag, column = self.current
            if column.advance(meter): self.columns[tag] = column; self.current = None
            return False
        owner = self.owner; namespace = self.namespace
        if self.phase == "bundle":
            self.metadata = meter.read_fixed_row(self.db, "graph_bundle_operations", ("activity_id", "effect_id"),
                "bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, self.operation_id))
            if self.metadata != (self.action.identity.activity_id, self.action.identity.effect_id):
                raise AuthorityUnavailable("named SourceALL actual generic candidate identity changed")
            self._begin("bundle", table="graph_bundle_operations", column="receipt_json",
                keys=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, self.operation_id))
            self.phase = "event"; return False
        if self.phase == "event":
            candidate = self.value("bundle").get("dispatch_candidate")
            if (type(candidate) is not dict or candidate.get("schema") != "sylanne.d11.dispatch_candidate.v1"
                    or candidate.get("status") != "source_qualified" or len(candidate.get("refs", ())) != 4):
                raise AuthorityUnavailable("named operation must use its actual qualified generic candidate family")
            self.candidate = candidate
            row = meter.read_fixed_row(self.db, "graph_events", ("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",
                (*namespace.as_tuple, self.metadata[0], self.operation_id))
            if row is None or row[0] != candidate["graph_epoch"]:
                raise AuthorityUnavailable("named candidate actual event epoch differs")
            self.event_epoch = row[0]; self.queue = ["revisions", "reads"]; self.phase = "event_columns"; return False
        if self.phase == "event_columns":
            if self.queue:
                tag = self.queue.pop(0)
                self._begin(tag, table="graph_events", column=tag, keys=("bot", "persona", "session", "event_id"),
                    key=(*namespace.as_tuple, self.metadata[0], self.operation_id)); return False
            revisions = self.value("revisions")
            uses = tuple((ref, revision) for ref, revision in revisions if AtomKey.from_token(ref).type_name in USE_TYPES)
            if len(uses) != 1 or uses[0][1] != 1:
                raise AuthorityUnavailable("named generic event lacks its unique same-commit PromiseUse")
            self.use_ref = uses[0][0]
            self.queue = [(ref, revision) for ref, revision in self.candidate["refs"]] + [uses[0]]
            self.phase = "members"; return False
        if self.phase == "members":
            if self.queue:
                ref, revision = self.queue.pop(0)
                if [ref, revision] not in self.value("revisions"):
                    raise AuthorityUnavailable("named generic four-member/use footprint changed")
                self._history(meter, (ref, revision), ref, revision, event_id=self.operation_id); return False
            self.use = decode_communication_use_v1(self.value((self.use_ref, 1)))
            self._history(meter, "scope", self.use.scope.key.token, self.use.scope.revision)
            self.phase = "scope"; return False
        if self.phase == "scope":
            self.scope = decode_communication_scope_v1(self.value("scope"))
            if type(self.scope)is CommitmentTermsCommunicationIntentV2:
                expected=require_named_commitment_policy_metadata_v3(owner)
                if expected!=(self.scope.policy_source_refs,self.scope.policy_audiences,self.scope.policy_read_versions):
                    raise AuthorityUnavailable('actual V2 Scope differs from its before-Source policy metadata')
                if self.scope.policy_source_refs:
                    owner._require_source_roots_v3(self.scope.policy_source_refs,'context',self.scope.policy_audiences)
            from ..domains.d03.prebatch_social import _private_route
            platform, audience, sender, message, scene = _private_route(self.db, namespace, scope_route_source_v1(self.scope))
            if (platform, audience, scene) != (self.scope.platform_ref, self.scope.conversation_ref, self.scope.scene_ref):
                raise AuthorityUnavailable("named SourceALL actual private ingress route differs from Owner approval")
            if (self.scope.source_refs != self.roots or self.scope.target_ref != self.action.target_ref
                    or owner.admission.admission.audience != (self.scope.conversation_ref,)
                    or owner.now_utc >= self.scope.valid_until_utc):
                raise AuthorityUnavailable("named original Source roots/audience/recipient/deadline changed")
            self.scope_head = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*namespace.as_tuple, self.use.scope.key.token))
            self.use_head = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*namespace.as_tuple, self.use_ref))
            if (self.scope_head is None or self.use_head is None
                    or self.scope_head[:2] != (1,1) or self.use_head[:2] != (1,1)
                    or type(self.scope) is CommitmentCommunicationIntentV1 and (self.scope_head != owner.heads.get(self.use.scope.key.token) or self.use_head != owner.heads.get(self.use_ref))):
                raise AuthorityUnavailable("named approved Scope/Use no longer its exact current sealed head")
            self._history(meter, "commitment", self.use.commitment.key.token, self.use.commitment.revision)
            if type(self.scope) is CommitmentTermsCommunicationIntentV2:
                from .current_commitment_fulfillment_source_v3 import TermsCommunicationDependenciesReadV3
                self.terms_dependencies=TermsCommunicationDependenciesReadV3(self);self.phase="terms_dependencies"
            else:self.phase="owner_original"
            return False
        if self.phase=="terms_dependencies":
            if self.terms_dependencies.advance_v3(meter):self.phase="owner_original"
            return False
        if self.phase == "owner_original":
            from .d08_commitment_scope_read_v1 import read_commitment_approval_original_header_v1
            row=read_commitment_approval_original_header_v1(self.db,meter,namespace,self.scope)
            self.owner_original_metadata = row
            self._begin("owner_original", table="graph_domain_production_originals_v1", column="original_payload_json",
                keys=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, self.scope.approval_operation_id), cell_id=None)
            self.phase = "verify"; return False
        if self.phase == "verify":
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .domain_production_contracts_v1 import ProductionOwnerGuardV1
            from .d08_commitment_communication_v1 import recover_commitment_dispatch_candidate_in_transaction_v1
            original = self.value("owner_original")
            expected_request=communication_scope_request_v1(self.scope)
            request = decode_typed_production_value_v1(original["request"],type(expected_request))
            guard = decode_typed_production_value_v1(original["owner_guard"], ProductionOwnerGuardV1)
            if (canonical_digest(original) != self.owner_original_metadata[3]
                    or canonical_digest(plain_v1(request)) != self.owner_original_metadata[2] or guard != self.scope.owner_guard
                    or original["identity"]["operation_id"] != self.scope.approval_operation_id
                    or request != expected_request
                    or [write["value"] for write in original["writes"]
                        if write["key"] == self.use.scope.key.token] != [self.value("scope")]):
                raise AuthorityUnavailable("named Scope changed its complete Owner command original")
            self.result = recover_commitment_dispatch_candidate_in_transaction_v1(self.db, namespace,
                self.operation_id, prepared_history=self)
            if self.result is None:
                raise AuthorityUnavailable("named generic original did not recover its exact typed lineage")
            self.phase='turn_order';return False
        if self.phase=='turn_order':
            from ..domains.d09.turn_order import turn_order_key
            key=turn_order_key(namespace,self.scope.scene_ref,self.scope.conversation_ref)
            self.turn_order_key=key
            self.turn_order_head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?',(key.token,*namespace.as_tuple))
            if self.turn_order_head is not None:
                if self.turn_order_head[1]!=1:raise AuthorityUnavailable('named P2 turn order is invalid')
                self._begin('turn_order',table='graph_atoms',column='value',keys=('token','bot','persona'),key=(key.token,*namespace.as_tuple),cell_id=self.turn_order_head[2])
            self.phase='turn_slot_census';return False
        if self.phase=='turn_slot_census':
            from .natural_outbound_receipt_adoption_read_v3 import _SlotMetadataColumnV3
            from ..domains.d09.turn_order import reserve_turn_slot_v1
            from .post_c02_reply_bundle_v2 import post_c02_dispatch_runtime_refs_v2
            if self.reservation is None:
                self.outbox_ref=post_c02_dispatch_runtime_refs_v2(namespace,self.action.identity)[1]
                if self.turn_order_head is not None:self.turn_order_atom=GraphAtom(self.turn_order_key,self.turn_order_head[0],self.value('turn_order'),True)
                self.reservation=reserve_turn_slot_v1(namespace,self.scope.scene_ref,self.scope.conversation_ref,'outbound',self.outbox_ref,current_order=self.turn_order_atom)
                self.absent_slot_head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(self.reservation.absent_slot.token,))
                if self.absent_slot_head is not None:raise AuthorityUnavailable('named P2 next turn slot already exists')
            if self.slot_column is not None:
                if not self.slot_column.advance(meter):return False
                if self.slot_column.require_v3(self)['origin_ref']==self.outbox_ref:raise AuthorityUnavailable('named P2 outbox already has an original reserved turn')
                self.slot_column=None;return False
            row=meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','value_cell_id'),'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',(*namespace.as_tuple,'d09.turn_slot.v1',self.slot_after))
            if row is not None:
                self.slot_after=row[0]
                if row[2]:self.slot_column=_SlotMetadataColumnV3(self,table='graph_atoms',column='value',key_columns=('token',),key=(row[0],),cell_id=row[3])
                return False
            self.needs_protected_observation=True;self.phase='observation';return False
        if self.phase == "observation":
            if not self.observed: return False
            self.complete = True; return True
        raise AuthorityUnavailable("unregistered named generic SourceALL phase")

    def require_current_v3(self,meter=None):
        self._actual()

    def reserve_slot_scratch_v3(self,size):
        if size>self.slot_scratch_peak:
            self.operation.retain(size-self.slot_scratch_peak);self.slot_scratch_peak=size

    def observe_protected_v1(self):
        from ..host.self_identity_current_port import InstalledCurrentSelfIdentityPort
        from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
        self._actual(); owner = self.owner
        if self.db.in_transaction or not self.needs_protected_observation or self.observed:
            raise AuthorityUnavailable("named P2 current Self observation requires its actual outside-SQL phase")
        port = owner.graph._GraphCoordinator__self_identity_port
        if type(port) is not InstalledCurrentSelfIdentityPort:
            raise AuthorityUnavailable("named generic SourceALL requires its actual installed Self port")
        current = port.current_self_identity(namespace=self.namespace, authority_namespace=owner.fence.scope.authority_namespace,
            request_operation_id=owner.fence.scope.operation_id, permit=owner.fence.scope.permit)
        if (type(current) is not AuthorityCurrentSelfIdentityV1 or current.permit != owner.fence.scope.permit
                or current.role_head_id != self.scope.persona_head_id
                or current.graph_incarnation != self.scope.graph_incarnation
                or current.activation_generation != self.scope.activation_generation
                or current.persona_ref != self.scope.subject_ref
                or current.owner_authorization_head.removeprefix("sha256:") != self.scope.owner_guard.owner_head_digest):
            raise AuthorityUnavailable("named final current Self/Owner differs from actual approved scope")
        self.current_self = current; self.observed = True; self.needs_protected_observation = False

    def require_for_v1(self, inventory, db):
        self._actual(); inventory._actual()
        if (not self.complete or not self.observed or inventory.db is not db or db is not self.db
                or inventory.operation is not self.operation or inventory.binding != self.owner.binding
                or inventory.graph_stamp != self.owner.graph_stamp
                or not self.qualified_sources <= inventory.qualified_sources):
            raise AuthorityUnavailable("named generic scope capability lost actual same-Work SourceALL/retention")
        for ref, expected in ((self.use.scope.key.token, self.scope_head), (self.use_ref, self.use_head)):
            current = db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*self.namespace.as_tuple, ref)).fetchone()
            if current != expected:
                raise AuthorityUnavailable("named original Scope/Use head changed before final claim")
        order=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(self.turn_order_key.token,*self.namespace.as_tuple)).fetchone()
        slot=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=?',(self.reservation.absent_slot.token,)).fetchone()
        if order!=self.turn_order_head or slot is not None:raise AuthorityUnavailable('named P2 selected turn order/slot changed before claim')
        inventory.source_family(db, self.roots, purpose="expression", audiences=(self.scope.conversation_ref,))
        if type(self.scope)is CommitmentTermsCommunicationIntentV2 and self.scope.policy_source_refs:
            self.owner._require_source_roots_v3(self.scope.policy_source_refs,"context",self.scope.policy_audiences)
        return self.scope

    @contextmanager
    def bind_v1(self, inventory, db):
        inventory._actual()
        if (not self.complete or not self.observed or self.operation.closed
                or _TASKS.get(self) != (self.owner, self.owner.operation, self.owner.fence.scope, self.action, self.qualified_sources)
                or inventory.operation is not self.operation or inventory.db is not db or db is not self.db
                or inventory.binding != self.owner.binding):
            raise AuthorityUnavailable("actual complete same-Work named scope binder required")
        # Binder lifetime alone confers no current Source permission. Every
        # actual P1/P2 criterion calls require_for_v1 inside its real transaction.
        token = _BOUND.set((self, inventory, db))
        try: yield self
        finally: _BOUND.reset(token)

    def release_v1(self):
        if self.terms_dependencies is not None:
            self.terms_dependencies.release_v1();self.terms_dependencies=None
        _TASKS.pop(self, None)
        for column in self.columns.values(): column._frozen_value = None
        self.columns = {}; self.current = self.scope = self.use = self.result = self.current_self = None
        self.slot_column=self.turn_order_atom=self.reservation=None

    @property
    def descriptors(self):
        if not self.complete:
            raise AuthorityUnavailable("named route descriptor cannot precede its complete Source/scope/use/Self proof")
        descriptors=((self.roots, "context", (self.scope.conversation_ref,),
            ("commitment_communication_scope_v1", self.use.scope.key.token, self.scope_head,
             self.use_ref, self.use_head, self.scope.approval_operation_id, self.owner_original_metadata)),)
        if type(self.scope)is CommitmentTermsCommunicationIntentV2 and self.scope.policy_source_refs:
            descriptors+=((self.scope.policy_source_refs,"context",self.scope.policy_audiences,
                ("commitment_policy_context_v2",self.use.scope.key.token,self.scope.policy_read_versions)),)
        return descriptors

    def row_v1(self): return (*self.metadata, None)
    def receipt_v1(self): return self.value("bundle")
    def event_v1(self): return (self.value("revisions"), self.event_epoch, self.value("reads"))
    def history_v1(self, ref, revision):
        if ref == self.use.scope.key.token: return self.value("scope")
        if ref == self.use.commitment.key.token: return self.value("commitment")
        return self.value((ref, revision))


def begin_named_commitment_dispatch_read_v1(owner):
    from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
    if type(owner) is not _DispatchInventoryReadV3 or owner.family != "private_reply" or not owner.graph_eof:
        raise AuthorityUnavailable("named reader belongs only to actual generic SourceALL EOF")
    selected = tuple(_decode("d08.action_intent.v1", atom.value) for atom in owner.atoms
        if atom.valid and atom.key.type_name == "d08.action_intent.v1" and atom.key.name == owner.admission.admission.action_ref)
    if len(selected) != 1 or canonical_digest(selected[0]) != owner.admission.admission.action_intent_digest:
        raise AuthorityUnavailable("generic SourceALL actual admitted action is unavailable")
    if selected[0].identity.phase != "commitment_literal_v1": return None
    return NamedCommitmentDispatchReadV1(owner, selected[0])


def current_named_dispatch_scope_for_action_v1(db, namespace, intent, *, now_utc):
    current = _BOUND.get()
    if current is None: return None
    task, inventory, actual_db = current
    task.require_for_v1(inventory, db)
    if (actual_db is not db or namespace != task.namespace or intent != task.action
            or not now_utc < task.scope.valid_until_utc):
        raise AuthorityUnavailable("named private-commitment exception changed its exact current action/deadline")
    return task.scope


def current_named_dispatch_recovery_v1(db, namespace, operation_id):
    current = _BOUND.get()
    if current is None: return None
    task, inventory, actual_db = current
    task.require_for_v1(inventory, db)
    if actual_db is not db or task.namespace != namespace or task.operation_id != operation_id:
        raise AuthorityUnavailable("named actual dispatch original locator changed")
    return task.result


def current_named_dispatch_atom_v1(db,namespace,key):
    current=_BOUND.get()
    if current is None:return None
    task,inventory,actual_db=current;task.require_for_v1(inventory,db)
    if actual_db is not db or namespace!=task.namespace:raise AuthorityUnavailable('named atom crossed actual P2 Work')
    versions=dict(task.result.write_versions)
    if key.token not in versions:raise AuthorityUnavailable('named P2 Body is outside its actual sealed members')
    return GraphAtom(key,versions[key.token],task.history_v1(key.token,versions[key.token]),True)


def current_named_outbound_reservation_v1(db,namespace,operation_id):
    current=_BOUND.get()
    if current is None:return None
    task,inventory,actual_db=current;task.require_for_v1(inventory,db)
    if actual_db is not db or namespace!=task.namespace or operation_id!=task.operation_id:raise AuthorityUnavailable('named turn reservation crossed actual P2 Work')
    batch_ref=task.result.evidence.batch_ref;batch_revision=dict(task.result.write_versions)[batch_ref]
    return task.reservation.writes,(GraphVersion(task.turn_order_key,0 if task.turn_order_head is None else task.turn_order_head[0]),GraphVersion(task.reservation.absent_slot,0),GraphVersion(AtomKey.from_token(batch_ref),batch_revision))


_POLICY_METADATA_TASKS=WeakKeyDictionary()
_POLICY_METADATA_OWNERS=WeakKeyDictionary()
_POLICY_METADATA_RESULTS=WeakKeyDictionary()


class _NamedPolicyMetadataColumnV3(_ScopeJSONColumnV1):
    def _emit(self,event):
        fields={'schema','namespace','scope','scope_digest','operation_id','action_id','effect_id',
            'policy_source_refs','policy_audiences','policy_read_versions'}
        if not event.path or event.path[0]in fields:super()._emit(event)


class NamedCommitmentPolicyMetadataV3:
    """Same P1/P2 Work's exact event->Use->Scope metadata, before policy Body."""
    def __init__(self,owner):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        if type(owner)is not _DispatchInventoryReadV3 or owner.family!='private_reply' or owner.work is None:
            raise AuthorityUnavailable('actual private reply Work required for policy metadata')
        self.owner=owner;self.operation=owner.operation;self.db=owner.db;self.namespace=owner.namespace
        self.operation_id=owner.binding.operation_id;self.phase='revisions';self.current=None
        self.columns={};self.headers={};self.complete=False;self.result=None;self.scope_ref=None
        _POLICY_METADATA_TASKS[self]=self._identity();_POLICY_METADATA_OWNERS[owner]=self
        owner.operation.retain(65536)
    def _identity(self):
        o=self.owner
        return(o,o.work,o.operation,o.fence.scope,o.graph_stamp,o.binding,o.admission)
    def _actual(self,meter=None):
        if (_POLICY_METADATA_TASKS.get(self)!=self._identity()or _POLICY_METADATA_OWNERS.get(self.owner)is not self
                or self.operation.closed):raise AuthorityUnavailable('policy metadata changed its actual dispatch Work')
        self.owner.require_current(meter=meter)
    def _begin(self,tag,table,column,keys,key,cell_id=None):
        self.current=(tag,_NamedPolicyMetadataColumnV3(self.owner,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id))
    def value(self,tag):return self.columns[tag].require_v3(self.owner)
    def advance(self,meter):
        self._actual(meter);o=self.owner
        for key,header in self.headers.items():
            if meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,key.token))!=header:
                raise AuthorityUnavailable('named policy metadata current Head changed')
        if self.complete:return True
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):self.columns[tag]=column;self.current=None
            return False
        if self.phase=='revisions':
            # Revision manifests are metadata; their entire canonical column reaches EOF.
            from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
            self.current=('revisions',DispatchOriginalJSONReadV3(o,table='graph_events',column='revisions',
                key_columns=('bot','persona','session','event_id'),key=(*self.namespace.as_tuple,o.admission.admission.activity_id,self.operation_id)))
            self.phase='use';return False
        if self.phase=='use':
            from ..domains.d08.commitment_communication_v1 import TERMS_USE_TYPE,TERMS_SCOPE_TYPE
            uses=tuple((AtomKey.from_token(ref),rev)for ref,rev in self.value('revisions')if AtomKey.from_token(ref).type_name in USE_TYPES)
            if not uses or len(uses)==1 and uses[0][0].type_name==USE_TYPE:
                self.complete=True;_POLICY_METADATA_RESULTS[self]=(None,None,());return True
            if len(uses)!=1 or uses[0][1]!=1 or uses[0][0].type_name!=TERMS_USE_TYPE:
                raise AuthorityUnavailable('named V2 policy selector requires one actual same-event PromiseUse')
            key,revision=uses[0]
            if(key.owner.bot,key.owner.persona)!=self.namespace.as_tuple:
                raise AuthorityUnavailable('V2 Use metadata key crossed actual namespace')
            row=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision=?',(key.token,revision))
            if row is None or row[1:]!=(1,*self.namespace.as_tuple,o.admission.admission.activity_id,self.operation_id):
                raise AuthorityUnavailable('V2 Use metadata is not the exact actual dispatch event')
            self._begin('use','graph_history','value',('token','revision'),(key.token,1),row[0]);self.phase='scope';return False
        if self.phase=='scope':
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from ..domains.d08.commitment_communication_v1 import TERMS_SCOPE_TYPE
            use=self.value('use');version=decode_typed_production_value_v1(use['scope'],GraphVersion)
            if (version.key.type_name!=TERMS_SCOPE_TYPE or version.revision!=1
                    or (version.key.owner.bot,version.key.owner.persona)!=self.namespace.as_tuple
                    or use['operation_id']!=self.operation_id or use['action_id']!=o.admission.admission.action_ref
                    or use['effect_id']!=o.admission.admission.effect_id):raise AuthorityUnavailable('V2 Use metadata changed its admitted identity')
            header=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,version.key.token))
            if header is None or header[:2]!=(1,1):raise AuthorityUnavailable('V2 policy approval is no longer current')
            self.headers[version.key]=header;self.scope_ref=version.key.token
            self._begin('scope','graph_atoms','value',('token',),(version.key.token,),header[2]);self.phase='finish';return False
        if self.phase=='finish':
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from ..domains.d08.commitment_communication_v1 import TERMS_SCOPE_TYPE
            value=self.value('scope');refs=tuple(value['policy_source_refs']);audiences=tuple(value['policy_audiences'])
            versions=tuple(decode_typed_production_value_v1(raw,GraphVersion)for raw in value['policy_read_versions'])
            if value['schema']!=TERMS_SCOPE_TYPE or not audiences or any(AtomKey.from_token(ref).type_name!='memory.source' or (AtomKey.from_token(ref).owner.bot,AtomKey.from_token(ref).owner.persona)!=self.namespace.as_tuple for ref in refs):
                raise AuthorityUnavailable('V2 policy metadata has no exact namespace/context binding')
            for v in versions:
                if v.key.type_name not in {'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'} or o.heads.get(v.key.token,())[:2]!=(v.revision,1):
                    raise AuthorityUnavailable('V2 approved current policy revision changed')
            self.result=(refs,audiences,versions);self.complete=True
            _POLICY_METADATA_RESULTS[self]=(self.result,self.scope_ref,tuple(sorted((key.token,header)for key,header in self.headers.items())))
            return True
        raise AuthorityUnavailable('unregistered named policy metadata phase')
    def require_v3(self,owner):
        self._actual()
        expected=(self.result,self.scope_ref,tuple(sorted((key.token,header)for key,header in self.headers.items())))
        if owner is not self.owner or not self.complete or _POLICY_METADATA_RESULTS.get(self)!=expected:
            raise AuthorityUnavailable('actual complete named policy metadata required')
        return self.result
    def release_v3(self):
        _POLICY_METADATA_TASKS.pop(self,None);_POLICY_METADATA_RESULTS.pop(self,None)
        if _POLICY_METADATA_OWNERS.get(self.owner)is self:_POLICY_METADATA_OWNERS.pop(self.owner,None)
        for column in self.columns.values():column._frozen_value=None
        if self.current is not None:self.current[1]._frozen_value=None
        self.columns.clear();self.headers.clear();self.current=None;self.result=None


def begin_named_commitment_policy_metadata_v3(owner):
    return NamedCommitmentPolicyMetadataV3(owner)


def require_named_commitment_policy_metadata_v3(owner):
    task=_POLICY_METADATA_OWNERS.get(owner)
    if task is None:raise AuthorityUnavailable('V2 dispatch requires its actual before-Source policy locator')
    return task.require_v3(owner)
