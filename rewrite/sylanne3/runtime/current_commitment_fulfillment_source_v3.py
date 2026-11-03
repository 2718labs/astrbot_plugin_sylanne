"""Exact terms metadata selectors and actual Source-qualified original streams."""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

def decode_typed_production_value_v1(value,expected):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as decode
    return decode(value,expected)

from ..domains.d08.commitment_communication_v1 import TERMS_SCOPE_TYPE
from ..domains.d08.commitment_fulfillment_v1 import TERMS_TYPE, ACCEPTANCE_TYPE

_LOCATORS = WeakKeyDictionary()
_LOCATOR_ROOTS = WeakKeyDictionary()
_METADATA_FIELDS = frozenset({"schema","namespace","source_refs","source_versions","inbound_versions",
    "inbound_source_ref","fulfillment_terms","terms_acceptance","route_source_ref","commitment","target_ref","counterparty_ref",
    "conversation_ref","platform_ref","role","approval_operation_id","create_operation_id","establishment_kind",
    "policy_source_refs","policy_audiences","policy_read_versions"})


class _TermsLocatorColumnV3(DispatchOriginalJSONReadV3):
    def _emit(self,event):
        if not event.path or event.path[0] in _METADATA_FIELDS:
            super()._emit(event)


class NamedCommitmentTermsLocatorMetadataV3:
    def __init__(self,reader):
        from .current_graph_full_read_v3 import COMMITMENT_COMMUNICATION_FULL_READ_V1
        if (reader.contract is not COMMITMENT_COMMUNICATION_FULL_READ_V1 or reader.work.state is not reader
                or reader.work.operation is not reader.operation or reader.prefinal is None
                or AtomKey.from_token(reader.commitment_scope_ref).type_name != TERMS_SCOPE_TYPE):
            raise AuthorityUnavailable("terms locator requires the actual named FULL Work and exact V2 selector")
        self.reader=reader;self.columns={};self.headers={};self.current=None;self.queue=[]
        self.complete=False;self.roots=();self.phase="scope"
        _LOCATORS[self]=self._identity()

    def _identity(self):
        r=self.reader
        return (r,r.work,r.operation,r.prefinal,r.commitment_scope_ref,r.source_locator,r.graph_stamp,r.selection_digest)

    def require_v3(self,reader):
        if (_LOCATORS.get(self)!=self._identity() or reader is not self.reader or reader.operation.closed
                or reader.work.state is not reader or not self.complete
                or _LOCATOR_ROOTS.get(self)!=(self.roots,tuple(sorted((key.token,header)for key,header in self.headers.items())),
                    tuple(sorted((tag,column.sha256,column.byte_count)for tag,column in self.columns.items())))):

            raise AuthorityUnavailable("actual completed same-Work V2 metadata selector required")
        reader.prefinal.require_current()
        return self.roots

    def value(self,tag):
        return self.columns[tag].require_v3(self.reader)

    def _begin(self,meter,tag,version):
        r=self.reader;key=version.key
        if NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("terms metadata dependency crossed namespace")
        row=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),
            "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,key.token))
        if row is None or row[:2]!=(version.revision,1):
            raise AuthorityUnavailable("V2 metadata dependency is absent or no longer the exact selected head")
        self.headers[key]=row
        column=_TermsLocatorColumnV3(r,table="graph_atoms",column="value",key_columns=("token","bot","persona"),
            key=(key.token,*r.namespace.as_tuple),cell_id=row[2])
        from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
        column.parser=_MetadataStreamV3(column,column.cell is None or column.cell.header[0]=="canonical-json.ascii.v1")
        self.current=(tag,column)

    def advance_v3(self,meter):
        r=self.reader
        if _LOCATORS.get(self)!=self._identity() or r.operation.closed:
            raise AuthorityUnavailable("V2 metadata selector changed its actual originating Work")
        r.prefinal.require_current(meter=meter)
        for key,header in self.headers.items():
            row=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),
                "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,key.token))
            if row!=header:raise AuthorityUnavailable("V2 metadata head changed during complete EOF selection")
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):self.columns[tag]=column;self.current=None
            return False
        if self.phase=="scope":
            self._begin(meter,"scope",GraphVersion(AtomKey.from_token(r.commitment_scope_ref),1));self.phase="dependencies";return False
        if self.phase=="dependencies":
            scope=self.value("scope")
            if scope["schema"]!=TERMS_SCOPE_TYPE:
                raise AuthorityUnavailable("exact V2 scope schema differs from its selected key")
            self.terms=decode_typed_production_value_v1(scope["fulfillment_terms"],GraphVersion)
            self.commitment=decode_typed_production_value_v1(scope["commitment"],GraphVersion)
            self.acceptance=None if scope["terms_acceptance"] is None else decode_typed_production_value_v1(scope["terms_acceptance"],GraphVersion)
            if self.terms.key.type_name!=TERMS_TYPE or self.terms.revision!=1 or self.commitment.key.type_name!="d08.commitment.v1":
                raise AuthorityUnavailable("V2 scope has no exact immutable terms/current commitment metadata")
            self.queue=[("terms",self.terms),("commitment",self.commitment)]
            if self.acceptance is not None:
                if self.acceptance.key.type_name!=ACCEPTANCE_TYPE or self.acceptance.revision!=1:
                    raise AuthorityUnavailable("V2 scope acceptance metadata type/version differs")
                self.queue.append(("acceptance",self.acceptance))
            self.phase="heads";return False
        if self.phase=="heads":
            if self.queue:
                tag,version=self.queue.pop(0);self._begin(meter,tag,version);return False
            scope=self.value("scope");commitment=self.value("commitment")
            terms=self.value("terms")
            roots=set(terms["source_refs"])
            if self.acceptance is not None:
                roots.add(self.value("acceptance")["inbound_source_ref"])
            roots.add(scope["route_source_ref"])
            if (not 1<=len(roots)<=32 or set(scope["source_refs"])!=roots
                    or not set(commitment["source_refs"])<=roots
                    or r.source_locator.source_ref!=scope["route_source_ref"]
                    or scope["target_ref"]!=commitment["counterparty_ref"] or terms["counterparty_ref"]!=scope["target_ref"]
                    or scope["role"]=="performance" and commitment["establishment_kind"]=="bilateral" and self.acceptance is None):
                raise AuthorityUnavailable("V2 complete terms/acceptance/route roots or actual target differ")
            for ref in roots:
                key=AtomKey.from_token(ref)
                if key.type_name!="memory.source" or NamespaceId.from_key(key)!=r.namespace:
                    raise AuthorityUnavailable("V2 root metadata crossed canonical Source namespace")
            policy_refs=tuple(scope['policy_source_refs']);policy_audiences=tuple(scope['policy_audiences'])
            policy_versions=tuple(decode_typed_production_value_v1(raw,GraphVersion)for raw in scope['policy_read_versions'])
            if len(roots|set(policy_refs))>32:raise AuthorityUnavailable(f'source_root_budget_exceeded(required_count={len(roots|set(policy_refs))},limit=32)')
            if not policy_audiences or any(NamespaceId.from_key(AtomKey.from_token(ref))!=r.namespace or AtomKey.from_token(ref).type_name!='memory.source'for ref in policy_refs):
                raise AuthorityUnavailable('V2 policy metadata crossed actual namespace/context audience')
            for version in policy_versions:
                if version.key.type_name not in {'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'} or r.heads.get(version.key.token,())[:2]!=(version.revision,1):
                    raise AuthorityUnavailable('V2 approved policy version changed before current qualification')
            self.policy_context=(policy_refs,policy_audiences,policy_versions)
            self.roots=tuple(sorted(roots));self.complete=True
            _LOCATOR_ROOTS[self]=(self.roots,tuple(sorted((key.token,header)for key,header in self.headers.items())),
                tuple(sorted((tag,column.sha256,column.byte_count)for tag,column in self.columns.items())))
            return True
        raise AuthorityUnavailable("unregistered V2 metadata selector phase")

    def release_v3(self):
        _LOCATORS.pop(self,None);_LOCATOR_ROOTS.pop(self,None)
        for column in self.columns.values():column._frozen_value=None
        if self.current is not None:self.current[1]._frozen_value=None
        self.current=None;self.columns.clear();self.headers.clear();self.queue.clear();self.roots=()


def begin_named_commitment_terms_locator_metadata_v3(reader):
    if AtomKey.from_token(reader.commitment_scope_ref).type_name!=TERMS_SCOPE_TYPE:return None
    return NamedCommitmentTermsLocatorMetadataV3(reader)


def require_named_commitment_terms_source_roots_v3(reader):
    locator=getattr(reader,"commitment_terms_locator",None)
    if type(locator) is not NamedCommitmentTermsLocatorMetadataV3:
        raise AuthorityUnavailable("V2 Source material requires its actual complete metadata root selector")
    return locator.require_v3(reader)


# These selectors are issued only while resolving one actual typed Owner command.
SOURCE_OPERATIONS = frozenset({"input:register_commitment_terms_communication", "acknowledge_commitment_terms", "settle_current_commitment_fulfillment"})


def _active_terms_v3(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    return r if r is not None and r.operation_kind in SOURCE_OPERATIONS else None


def _terms_state_v3(r):
    from .current_commitment_input_source_v3 import require_commitment_input_source_v3
    return require_commitment_input_source_v3(r)


def _need_terms_v3(r,identity):
    from .current_method_learning_read_v3 import _need_method_input
    task=_terms_state_v3(r).tasks.get(identity)
    if task is None or not task.complete:
        _need_method_input(r,("commitment_input_metadata",identity))
    return task


def lifecycle_outbound_receipt_ref_v3(reader):
    from ..domains.d08.commitment_fulfillment_v1 import AcknowledgeCurrentCommitmentTermsRequestV1,SettleCurrentCommitmentFulfillmentRequestV1
    request=reader.request
    if reader.operation_kind=="acknowledge_commitment_terms" and type(request) is AcknowledgeCurrentCommitmentTermsRequestV1:
        return request.outbound_offer_receipt_ref
    if reader.operation_kind=="settle_current_commitment_fulfillment" and type(request) is SettleCurrentCommitmentFulfillmentRequestV1:
        return request.performance_outbound_receipt_ref
    return request.outbound_receipt_ref


def terms_source_read_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    from ..domains.d08.commitment_fulfillment_v1 import acceptance_key_v1,evidence_key_v1
    from .current_commitment_input_source_v3 import TYPES
    r=_active_terms_v3(db)
    if r is None or r.namespace!=namespace or r.request!=request:
        raise AuthorityUnavailable("terms producer requires its exact originating typed Owner Source Work")
    state=_terms_state_v3(r)
    commitment=AtomKey.from_token(request.current_commitment.ref);terms=AtomKey.from_token(request.terms.ref)
    if NamespaceId.from_key(commitment)!=namespace or NamespaceId.from_key(terms)!=namespace:
        raise AuthorityUnavailable("terms producer request left its current Owner namespace")
    selected={commitment,terms}
    state.keys.update(selected)
    term_metadata=_need_terms_v3(r,terms.token).result
    current_metadata=_need_terms_v3(r,commitment.token).result
    state.roots.update(term_metadata["source_refs"]);state.roots.update(current_metadata["source_refs"])
    acceptance=acceptance_key_v1(namespace,commitment.name)
    # Current metadata headers establish real absence without opening Body.
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db) as meter:
        acceptance_header=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
            "bot=? AND persona=? AND token=?",(*namespace.as_tuple,acceptance.token))
    selected.add(acceptance)
    if acceptance_header is not None:
        if acceptance_header[:2]!=(1,1):raise AuthorityUnavailable("terms acceptance head is invalid or has changed")
        state.keys.add(acceptance);accepted=_need_terms_v3(r,acceptance.token).result
        state.roots.add(accepted["inbound_source_ref"])
    if operation_kind=="input:register_commitment_terms_communication":
        from ..domains.d08.commitment_communication_v1 import TERMS_SCOPE_TYPE,communication_scope_id_v1
        from ..graph_types import Owner
        selected.add(AtomKey(Owner("persona",*namespace.as_tuple),TERMS_SCOPE_TYPE,communication_scope_id_v1(namespace,request)))
        state.roots.add(request.source_ref)
        if request.role=="performance" and current_metadata["establishment_kind"]=="bilateral" and acceptance_header is None:
            raise AuthorityUnavailable("bilateral performance requires the actual prior immutable terms acceptance")
    else:
        meta=_need_terms_v3(r,("lifecycle_locator",))
        if meta.family!="commitment_literal":raise AuthorityUnavailable("terms evidence requires the actual named deterministic communication family")
        selected.update(AtomKey.from_token(ref)for ref,_ in meta.candidate["refs"])
        selected.update(AtomKey.from_token(ref)for ref,_ in (*meta.value("reads"),*meta.value("revisions"))
            if AtomKey.from_token(ref).type_name in {"d08.commitment_communication_intent.v2","d08.commitment_promise_use.v2"})
        state.roots.update(meta.candidate["source_refs"]);state.roots.add(meta.outbound[2])
        inbound=request.inbound_source_ref if operation_kind=="acknowledge_commitment_terms" else request.recipient_ack_source_ref
        if inbound is not None:state.roots.add(inbound)
        if operation_kind=="settle_current_commitment_fulfillment":selected.add(evidence_key_v1(namespace,commitment.name))
    # D03 actor and route consumers remain the existing exact current inventory.
    state.keys.update(AtomKey.from_token(token)for token in r.heads if AtomKey.from_token(token).type_name in TYPES)
    for key in sorted(state.keys,key=lambda key:key.token):
        if key.type_name in {"d08.commitment_communication_intent.v2","d08.commitment_promise_use.v2"}:continue
        task=_need_terms_v3(r,key.token)
        from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
        if key.type_name not in TYPES:state.roots.update(_source_refs_v3(task.result))
    if operation_kind!="input:register_commitment_terms_communication":
        # The actual authored Source has every adopted scope root as a parent.
        # Fact adoption uses its context closure, never a new expression grant.
        state.selector_dependency_refs.update(state.roots)
        state.roots={meta.outbound[2]}
        if inbound is not None:state.roots.add(inbound)
    from .current_commitment_input_source_v3 import prepare_current_commitment_applicability_v3
    prepare_current_commitment_applicability_v3(r)
    state.content_source_refs=set(state.roots)
    state.roots.update(state.policy_source_refs)
    if len(state.roots)>32:raise AuthorityUnavailable(f'source_root_budget_exceeded(required_count={len(state.roots)},limit=32)')
    selected.update(key for key in state.keys if key.type_name not in TYPES);selected.update(state.applicable_keys);selected.add(owner_grant_key(*namespace.as_tuple))
    for ref in state.roots|state.selector_dependency_refs:
        key=AtomKey.from_token(ref)
        if key.type_name!="memory.source" or NamespaceId.from_key(key)!=namespace:
            raise AuthorityUnavailable("terms metadata dependency left its exact canonical Source namespace")
    state.metadata_complete=True
    originals=tuple(key.token for key in (commitment,terms))
    if acceptance_header is not None:originals+=(acceptance.token,)
    plan=production_read_plan_v1(TYPES,tuple(sorted(selected,key=lambda key:key.token)),tuple(sorted(state.roots)),originals)
    if operation_kind=="input:register_commitment_terms_communication":
        from .persona_growth_birth_v1 import augment_persona_birth_plan_v1
        plan=augment_persona_birth_plan_v1(db,namespace=namespace,operation_kind=operation_kind,plan=plan)
    return plan


def terms_source_groups_v3(reader,roots):
    state=_terms_state_v3(reader)
    if not state.metadata_complete or set(roots)!=state.roots:
        raise AuthorityUnavailable("terms Source roots changed after actual complete metadata selection")
    content=state.content_source_refs
    groups=tuple(("context",(reader.audience_ref,),(root,))for root in sorted(content))
    if reader.operation_kind=="input:register_commitment_terms_communication":
        groups+=tuple(("expression",(reader.audience_ref,),(root,))for root in sorted(content))
    if state.policy_source_refs:groups+=(("context",state.policy_audiences,tuple(sorted(state.policy_source_refs))),)
    return groups


class CommitmentTermsHeadOriginalV3:
    def __init__(self,reader,ref,revision,*,_consumer=None):
        self.reader=reader;self.ref,self.revision=ref,revision;self.consumer=_consumer
        self._require_v3()
        self.columns={};self.current=None
        self.phase="history";self.complete=False;self.result=None;self.original=None
    def _require_v3(self,meter=None):
        r=self.reader
        if self.consumer is not None:
            return _require_actual_terms_dependency_consumer_v3(self.consumer,GraphVersion(AtomKey.from_token(self.ref),self.revision),meter)
        r.require_current(meter=meter)
        state=_terms_state_v3(r)
        if AtomKey.from_token(self.ref)not in r.selected_plan.exact_keys or state.permission is None:
            raise AuthorityUnavailable("terms original requires its actual Source-qualified exact plan")
        state.permission.require_for_v3(r)

    def _begin(self,tag,table,column,keys,key,cell_id=None):
        from .d08_commitment_scope_read_v1 import _ScopeJSONColumnV1
        self.current=(tag,_ScopeJSONColumnV1(self.reader,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id))
    def value(self,tag):return self.columns[tag].require_v3(self.reader)
    def advance(self,meter):
        r=self.reader;self._require_v3(meter)
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):self.columns[tag]=column;self.current=None
            return False
        if self.phase=="history":
            row=meter.read_fixed_row(r.db,"graph_history",("value_cell_id","valid","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=?",(self.ref,self.revision))
            if row is None or row[1]!=1 or row[2:4]!=r.namespace.as_tuple:
                raise AuthorityUnavailable("terms original has no actual current adopted history")
            self.history=row;self._begin("head","graph_history","value",("token","revision"),(self.ref,self.revision),row[0]);self.phase="event";return False
        if self.phase=="event":
            self._begin("revisions","graph_events","revisions",("bot","persona","session","event_id"),tuple(self.history[2:]));self.phase="producer";return False
        if self.phase=="producer":
            if [self.ref,self.revision]not in self.value("revisions"):
                raise AuthorityUnavailable("terms history is not in its actual W01 event")
            self.metadata=meter.read_fixed_row(r.db,"graph_domain_production_originals_v1",
                ("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,self.history[5]))
            self.bundle=meter.read_fixed_row(r.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,self.history[5]))
            if self.metadata is None or self.metadata[0]!="d08" or self.bundle is None or self.bundle[0]!=self.metadata[4]or self.bundle[1]<1:
                raise AuthorityUnavailable("terms original lacks actual same-commit producer ledger")
            self._begin("producer","graph_domain_production_originals_v1","original_payload_json",("bot","persona","operation_id"),(*r.namespace.as_tuple,self.history[5]));self.phase="verify";return False
        if self.phase=="verify":
            from ..runtime_contracts import canonical_digest
            self.original=self.value("producer");value=self.value("head")
            if (canonical_digest(self.original)!=self.metadata[3]or canonical_digest(self.original["request"])!=self.metadata[2]
                    or self.original["identity"]["operation_id"]!=self.history[5]
                    or [w["value"]for w in self.original["writes"]if w["key"]==self.ref]!=[value]):
                raise AuthorityUnavailable("terms producer original changed its actual request, write or identity")
            if AtomKey.from_token(self.ref).type_name==TERMS_TYPE:
                from ..domains.d08.commitment_fulfillment_v1 import CommitmentFulfillmentTermsV1,CreateCurrentCommitmentWithFulfillmentTermsInputRequestV1,CREATE_OPERATION,terms_key_v1
                terms=decode_typed_production_value_v1(value,CommitmentFulfillmentTermsV1)
                request=decode_typed_production_value_v1(self.original["request"],CreateCurrentCommitmentWithFulfillmentTermsInputRequestV1)
                reads=decode_typed_production_value_v1(self.original["read_versions"],tuple[GraphVersion,...])
                guards={v.key:v.revision for v in reads}
                if (self.metadata[1]!=CREATE_OPERATION or self.history[5]!=terms.create_operation_id or terms.commitment.revision!=1
                        or request.commitment_id!=terms.commitment.key.name or request.source_refs!=terms.source_refs
                        or request.fulfillment_kind!=terms.fulfillment_kind or request.deliverable_literal!=terms.deliverable_literal
                        or request.deadline_utc!=terms.deadline_utc or request.counterparty_ref!=terms.counterparty_ref
                        or guards.get(terms.commitment.key)!=0 or guards.get(terms_key_v1(r.namespace,request.commitment_id))!=0
                        or not set(terms.source_versions)<=set(reads)
                        or [terms.commitment.key.token,1]not in self.value("revisions")):
                    raise AuthorityUnavailable("immutable terms were not issued by their exact two-target birth and original Source/Access CAS")
            elif AtomKey.from_token(self.ref).type_name==ACCEPTANCE_TYPE:
                from ..domains.d08.commitment_fulfillment_v1 import CommitmentTermsAcceptanceV1,AcknowledgeCurrentCommitmentTermsRequestV1,ACK_OPERATION
                accepted=decode_typed_production_value_v1(value,CommitmentTermsAcceptanceV1)
                request=decode_typed_production_value_v1(self.original["request"],AcknowledgeCurrentCommitmentTermsRequestV1)
                reads=decode_typed_production_value_v1(self.original["read_versions"],tuple[GraphVersion,...])
                if (self.metadata[1]!=ACK_OPERATION or accepted.operation_id!=self.history[5]
                        or request.terms.ref!=accepted.terms.key.token or request.terms.version!=accepted.terms.revision
                        or request.current_commitment.ref!=accepted.previous_commitment.key.token
                        or request.current_commitment.version!=accepted.previous_commitment.revision
                        or request.inbound_source_ref!=accepted.inbound_source_ref
                        or request.outbound_offer_receipt_ref!=accepted.offer_receipt_ref
                        or not {accepted.terms,accepted.previous_commitment,*accepted.inbound_versions}<=set(reads)
                        or [accepted.resulting_commitment.key.token,accepted.resulting_commitment.revision]not in self.value("revisions")):
                    raise AuthorityUnavailable("terms acceptance lacks its exact actual inbound/offer/CAS producer origin")
            self.result=value;self.complete=True;return True
        raise AuthorityUnavailable("unregistered terms original EOF phase")
    def release_v1(self):
        for column in self.columns.values():column._frozen_value=None
        if self.current is not None:self.current[1]._frozen_value=None
        self.columns.clear();self.current=self.result=self.original=None


def read_bound_commitment_terms_originals_v3(db,*,namespace,plan):
    r=_active_terms_v3(db)
    if r is None:return False,None
    if r.namespace!=namespace or plan!=r.selected_plan:
        raise AuthorityUnavailable("terms originals changed their actual selected namespace/plan")
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..runtime_contracts import canonical_digest
    result=[]
    for ref in plan.required_original_refs:
        key=AtomKey.from_token(ref);atom=method_graph_head_v3(db,namespace,key)
        if not atom.valid:raise AuthorityUnavailable("terms current original head unavailable")
        task=_need_terms_v3(r,("terms_head_original",ref,atom.revision))
        if task.result!=atom.value:raise AuthorityUnavailable("terms current head differs from its complete actual producer history")
        result.append(ProductionOriginalRefV1(key.type_name,ref,canonical_digest(atom.value),(GraphVersion(key,atom.revision),)))
    if r.operation_kind!="input:register_commitment_terms_communication":
        _need_terms_v3(r,("lifecycle_originals",))
    return True,tuple(result)


def _require_actual_terms_dependency_consumer_v3(consumer,version,meter=None):
    from .d08_commitment_scope_read_v1 import CommitmentScopeOriginalReadTaskV1
    from .d08_commitment_dispatch_read_v1 import NamedCommitmentDispatchReadV1
    from .d08_commitment_outbound_receipt_v1 import NamedCommitmentOutboundReceiptMetadataV1
    from ..domains.d08.commitment_communication_v1 import CommitmentTermsCommunicationIntentV2
    scope=consumer.scope
    if type(scope) is not CommitmentTermsCommunicationIntentV2 or version not in (scope.fulfillment_terms,scope.terms_acceptance):
        raise AuthorityUnavailable("terms Body dependency is outside the exact actual V2 scope")
    if type(consumer) is CommitmentScopeOriginalReadTaskV1:
        owner=consumer.owner
        if owner.commitment_scope_task is not consumer or owner.work.state is not owner:
            raise AuthorityUnavailable("V2 dependency lost its actual FULL Source Work")
        owner.prefinal.require_current(meter=meter)
        from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
        material=require_prepared_current_source_material_v3(consumer.material,prefinal_inventory=owner.prefinal,actual_entry=owner.prefinal.actual_entry)
        if set(material.roots)!=set(scope.source_refs):raise AuthorityUnavailable("V2 dependency has another complete Source boundary")
        return owner
    if type(consumer) is NamedCommitmentDispatchReadV1:
        consumer._actual()
        if not set(scope.source_refs)<=consumer.qualified_sources:
            raise AuthorityUnavailable("V2 dispatch dependency lacks all actual Source rights")
        return consumer.owner
    if type(consumer) is NamedCommitmentOutboundReceiptMetadataV1:
        consumer._actual(meter)
        if scope.source_refs!=consumer.locator.source_refs:
            raise AuthorityUnavailable("V2 receipt dependency lacks its actual complete Source roots")
        return consumer.reader
    raise AuthorityUnavailable("unregistered exact terms original Body consumer")


class TermsCommunicationDependenciesReadV3:
    def __init__(self,consumer):
        from ..domains.d08.commitment_communication_v1 import CommitmentTermsCommunicationIntentV2
        if type(consumer.scope) is not CommitmentTermsCommunicationIntentV2:
            raise TypeError("exact V2 terms communication dependency required")
        self.consumer=consumer;self.scope=consumer.scope;self.tasks=[];self.current=None;self.terms=None;self.acceptance=None;self.complete=False
        self.queue=[self.scope.fulfillment_terms]
        if self.scope.terms_acceptance is not None:self.queue.append(self.scope.terms_acceptance)
    def advance_v3(self,meter):
        from ..domains.d08.commitment_fulfillment_v1 import CommitmentFulfillmentTermsV1,CommitmentTermsAcceptanceV1
        from ..runtime_contracts import canonical_digest
        if self.current is not None:
            if not self.current.advance(meter):return False
            task=self.current;self.tasks.append(task);self.current=None
            if AtomKey.from_token(task.ref).type_name==TERMS_TYPE:
                self.terms=decode_typed_production_value_v1(task.result,CommitmentFulfillmentTermsV1)
            else:self.acceptance=decode_typed_production_value_v1(task.result,CommitmentTermsAcceptanceV1)
            return False
        if self.queue:
            version=self.queue.pop(0);owner=_require_actual_terms_dependency_consumer_v3(self.consumer,version,meter)
            self.current=CommitmentTermsHeadOriginalV3(owner,version.key.token,version.revision,_consumer=self.consumer);return False
        scope=self.scope;terms=self.terms
        if (terms is None or terms.digest!=scope.fulfillment_terms_digest or scope.terms_digest!=terms.digest
                or terms.commitment.key!=scope.commitment.key or terms.counterparty_ref!=scope.target_ref
                or terms.render(scope.role,effect_id=_terms_effect_v3(scope))!=scope.approved_literal):
            raise AuthorityUnavailable("V2 literal differs from actual immutable birth terms and deterministic renderer")
        roots=set(terms.source_refs);roots.add(scope.route_source_ref)
        if self.acceptance is not None:
            accepted=self.acceptance
            if (accepted.terms!=scope.fulfillment_terms or accepted.terms_digest!=terms.digest or accepted.actor_ref!=scope.target_ref
                    or accepted.conversation_ref!=scope.conversation_ref):
                raise AuthorityUnavailable("V2 performance acceptance belongs to another terms digest, actor or conversation")
            roots.add(accepted.inbound_source_ref)
        if set(scope.source_refs)!=roots:
            raise AuthorityUnavailable("V2 literal discarded or added roots outside actual terms/acceptance/route original")
        self.complete=True;return True
    def release_v1(self):
        if self.current is not None:self.current.release_v1()
        for task in self.tasks:task.release_v1()
        self.tasks.clear();self.current=self.terms=self.acceptance=None;self.queue.clear()


def _terms_effect_v3(scope):
    from ..domains.d08.commitment_communication_v1 import commitment_communication_effect_id_v1
    return commitment_communication_effect_id_v1(scope.scope_id)


def require_named_commitment_policy_context_v3(reader):
    locator=getattr(reader,'commitment_terms_locator',None)
    if type(locator)is not NamedCommitmentTermsLocatorMetadataV3:
        raise AuthorityUnavailable('actual same-FULL complete V2 policy locator required')
    locator.require_v3(reader)
    value=locator.value('scope')
    expected=(tuple(value['policy_source_refs']),tuple(value['policy_audiences']),
        tuple(decode_typed_production_value_v1(raw,GraphVersion)for raw in value['policy_read_versions']))
    if locator.policy_context!=expected:raise AuthorityUnavailable('policy context changed after its actual metadata EOF')
    return expected
