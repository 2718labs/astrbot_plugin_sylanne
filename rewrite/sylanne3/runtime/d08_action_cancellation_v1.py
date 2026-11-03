"""Exact Owner cancellation of one current action; no execution or compensation authority."""
from dataclasses import replace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, DomainProposal, DependencySet, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import GoalExecutionProvider, _decode, _decode_intent
from ..domains.d08.production_operations_v1 import CancelCurrentActionRequestV1
from .d01_production_operations_v1 import CurrentDomainReadV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionReadPlanV1

OPERATION = 'cancel_action'
DOMAINS = frozenset({'d01','d06','d08','d11'})
_ISSUER = object()
_IDENTITIES = WeakKeyDictionary()
_WRITES = WeakKeyDictionary()


def _reader(db, namespace=None, request=None):
    from .current_method_learning_read_v3 import _method_active
    from .current_commitment_input_source_v3 import require_commitment_input_source_v3
    reader = _method_active(db)
    if reader is None or reader.operation_kind != OPERATION:
        raise AuthorityUnavailable('action cancellation requires its actual typed Owner Source Work')
    if (type(reader.request) is not CancelCurrentActionRequestV1 or namespace is not None and reader.namespace != namespace
            or request is not None and reader.request != request):
        raise AuthorityUnavailable('action cancellation changed its actual namespace/request')
    if NamespaceId.from_key(AtomKey.from_token(reader.request.action_intent_ref)) != reader.namespace:
        raise AuthorityUnavailable('action cancellation reference leaves its actual Owner namespace')
    state = require_commitment_input_source_v3(reader)
    return reader, state


def cancellation_key_v1(action_key):
    return AtomKey(action_key.owner,'d08.action_cancellation.v1',action_key.name)


def _need(reader, key):
    from .current_commitment_input_source_v3 import require_commitment_input_source_v3
    from .current_method_learning_read_v3 import _need_method_input
    state = require_commitment_input_source_v3(reader)
    state.keys.add(key)
    task = state.tasks.get(key.token)
    if task is None or not task.complete:
        _need_method_input(reader,('commitment_input_metadata',key.token))
    return task


class ActionCancellationIdentityMetadataV1:
    def __init__(self,issuer,reader,action,cancellation):
        if issuer is not _ISSUER:
            raise TypeError('actual cancellation metadata Source Work issuer required')
        self.reader,self.operation,self.request = reader,reader.operation,reader.request
        self.action,self.cancellation = action,cancellation
        self.action_header,self.cancellation_header = action.header,cancellation.header
        self.action_key = AtomKey.from_token(self.request.action_intent_ref)
        self.cancellation_key = cancellation_key_v1(self.action_key)
        raw,before = action.result,cancellation.result
        if (self.action_header[:2] != (self.request.expected_action_revision,1)
                or self.cancellation_header[0] < 1 or self.cancellation_header[1] != 1
                or raw['revision'] != self.request.expected_action_revision or raw['action_id'] != self.action_key.name
                or (before['action_id'],before['action_revision'],before['state'],before['cancel_epoch']) !=
                    (raw['action_id'],raw['revision'],'active',0)):
            raise AuthorityUnavailable('cancellation requires the exact current action and active cancellation head')
        self.activity,self.effect,self.attempt = (raw['identity'][name] for name in ('activity_id','effect_id','attempt_id'))
        self.sources,self.purpose = tuple(raw['source_refs']),raw['purpose']
        if (not self.sources or self.action_key.owner.subject != self.activity
                or (before['activity_id'],before['effect_id'],before['attempt_id'],tuple(before['source_refs'])) !=
                    (self.activity,self.effect,self.attempt,self.sources)
                or any(AtomKey.from_token(ref).type_name != 'memory.source' or NamespaceId.from_key(AtomKey.from_token(ref)) != reader.namespace for ref in self.sources)):
            raise AuthorityUnavailable('cancellation metadata changed the frozen action identity/Source scope')
        self.action_digest = before['action_digest']
        self.graph_stamp,self.selection_digest = reader.graph_stamp,reader.selection_digest
        _IDENTITIES[self] = self._identity()
    def _identity(self):
        return (self.reader,self.operation,self.request,self.action,self.cancellation,self.action_header,self.cancellation_header,
            self.action_key,self.cancellation_key,self.activity,self.effect,self.attempt,self.sources,self.purpose,self.action_digest,
            self.graph_stamp,self.selection_digest)
    def require_v1(self,reader):
        from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
        from .current_commitment_input_source_v3 import require_commitment_input_source_v3
        state = require_commitment_input_source_v3(reader)
        if (_IDENTITIES.get(self) != self._identity() or self.reader is not reader or self.operation is not reader.operation
                or self.operation.closed or state.cancellation_identity is not self
                or reader.graph_stamp != self.graph_stamp or reader.selection_digest != self.selection_digest
                or state.tasks.get(self.action_key.token) is not self.action or state.tasks.get(self.cancellation_key.token) is not self.cancellation):
            raise AuthorityUnavailable('action cancellation lost its actual same-Work metadata identity')
        reader.require_current()
        with runtime_storage_quantum_v3(reader.db) as meter:
            for key,header in ((self.action_key,self.action_header),(self.cancellation_key,self.cancellation_header)):
                if _runtime_bounded_fixed_row_v3(reader.db,meter,'graph_atoms',('revision','valid','value_cell_id'),
                        'token=? AND bot=? AND persona=?',(key.token,*reader.namespace.as_tuple)) != header:
                    raise AuthorityUnavailable('action cancellation current metadata head changed')
        return self


def current_action_cancellation_metadata_v1(db,*,namespace,request):
    reader,state = _reader(db,namespace,request)
    proof = getattr(state,'cancellation_identity',None)
    if proof is None:
        key = AtomKey.from_token(request.action_intent_ref)
        action,cancellation = _need(reader,key),_need(reader,cancellation_key_v1(key))
        proof = ActionCancellationIdentityMetadataV1(_ISSUER,reader,action,cancellation)
        state.cancellation_identity = proof
    return proof.require_v1(reader)


def action_cancellation_command_identity_v1(db,*,namespace,request):
    proof = current_action_cancellation_metadata_v1(db,namespace=namespace,request=request)
    return proof.activity,proof.effect,proof.purpose


def action_cancellation_read_plan_v1(db,*,namespace,activity_id,request):
    proof = current_action_cancellation_metadata_v1(db,namespace=namespace,request=request)
    if activity_id != proof.activity:
        raise AuthorityUnavailable('cancellation caller did not select the actual action activity')
    reader,state = _reader(db,namespace,request)
    state.roots.update(proof.sources);state.metadata_complete = True
    keys = tuple(sorted((owner_grant_key(*namespace.as_tuple),proof.action_key,proof.cancellation_key),key=lambda key:key.token))
    # Preserve the actual frozen Source tuple; no new Source or sorted substitute.
    return ProductionReadPlanV1((),keys,proof.sources,(proof.action_key.token,proof.cancellation_key.token))


def action_cancellation_source_groups_v1(reader,roots):
    proof = current_action_cancellation_metadata_v1(reader.db,namespace=reader.namespace,request=reader.request)
    if tuple(roots) != proof.sources or reader.selected_envelope.authority.purpose != proof.purpose:
        raise AuthorityUnavailable('cancellation changed the actual original Source tuple/purpose')
    return ((proof.purpose,(reader.audience_ref,),proof.sources),)


def bind_current_action_cancellation_identity_v1(graph,db,*,request,envelope,scope,owner_guard,owner_binding):
    proof = current_action_cancellation_metadata_v1(db,namespace=envelope.authority.namespace,request=request)
    reader,state = _reader(db,envelope.authority.namespace,request)
    if (reader.graph is not graph or envelope.identity.operation_id != reader.operation_id
            or envelope.identity.activity_id != proof.activity or scope.namespace != reader.namespace
            or owner_binding.actor != envelope.authority.actor or 'workbench.control' not in owner_binding.capabilities
            or owner_guard.authorization_head != owner_binding.authorization_head):
        raise AuthorityUnavailable('cancellation identity requires its actual current Owner/control/operation')
    updated = replace(envelope,identity=replace(envelope.identity,attempt_id=proof.attempt,effect_id=proof.effect))
    if reader.inputs_sealed:
        from .current_commitment_input_source_v3 import require_commitment_input_write_v3
        from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
        prepared = reader.result
        if type(prepared) is not PreparedMethodDomainInputsV3 or prepared.owner is not reader:
            raise AuthorityUnavailable('cancellation lost its actual once-sealed Source inputs')
        prepared.require_current_v3(db,scope,owner_binding)
        binding = require_commitment_input_write_v3(reader)
        if binding[1] is not scope or binding[2] != owner_binding or scope.operation != 'write' or state.permission is None:
            raise AuthorityUnavailable('cancellation identity lacks actual same-Work WRITE/Source ALL')
        state.permission.require_for_v3(reader)
        _WRITES[proof] = (scope,owner_guard,owner_binding,updated.identity)
    elif scope is not reader.fence.scope or owner_binding is not reader.owner_binding:
        raise AuthorityUnavailable('cancellation metadata planning cannot substitute its READ owner/scope')
    return updated


def read_bound_action_cancellation_originals_v1(db,*,namespace,plan):
    from .current_method_learning_read_v3 import _method_active,_need_method_input,method_graph_head_v3
    reader = _method_active(db)
    if reader is None or reader.operation_kind != OPERATION:return False,None
    _,state = _reader(db,namespace)
    if reader.selected_plan != plan or state.permission is None:
        raise AuthorityUnavailable('cancellation originals need their exact Source-qualified plan')
    state.permission.require_for_v3(reader)
    proof = current_action_cancellation_metadata_v1(db,namespace=namespace,request=reader.request)
    originals = []
    for key,header in ((proof.action_key,proof.action_header),(proof.cancellation_key,proof.cancellation_header)):
        atom = method_graph_head_v3(db,namespace,key)
        identity = ('lifecycle_head_original',key.token,header[0])
        task = state.tasks.get(identity)
        if task is None or not task.complete:_need_method_input(reader,('commitment_input_metadata',identity))
        if not atom.valid or atom.revision != header[0] or task.value('head') != atom.value:
            raise AuthorityUnavailable('cancellation current head differs from its actual complete adopted history')
        originals.append(ProductionOriginalRefV1(key.type_name,key.token,canonical_digest(atom.value),(GraphVersion(key,atom.revision),)))
    return True,tuple(originals)


def stage_cancel_current_action_v1(db,*,frame,request,installed_readers):
    reader,state = _reader(db,frame.envelope.authority.namespace,request)
    proof = current_action_cancellation_metadata_v1(db,namespace=reader.namespace,request=request)
    binding = _WRITES.get(proof)
    if (binding is None or binding[3] != frame.envelope.identity or binding[2] != reader.owner_binding
            or frame.envelope.identity.operation_id == proof.action.result['identity']['operation_id']):
        raise AuthorityUnavailable('cancellation stage lacks its actual new-operation WRITE identity proof')
    read = CurrentDomainReadV1(frame);read.check(db)
    action_atom = read.head(db,proof.action_key,required=True);cancel_atom = read.head(db,proof.cancellation_key,required=True)
    action,before = _decode_intent(action_atom.value),_decode('d08.action_cancellation.v1',cancel_atom.value)
    if (action_atom.revision != request.expected_action_revision or canonical_digest(action) != proof.action_digest
            or (action.identity.activity_id,action.identity.effect_id,action.identity.attempt_id,action.source_refs) !=
                (proof.activity,proof.effect,proof.attempt,proof.sources)
            or (before.state,before.cancel_epoch,cancel_atom.revision) != ('active',0,proof.cancellation_header[0])
            or frame.envelope.source_qualification.source_refs != proof.sources):
        raise AuthorityUnavailable('cancellation changed its exact action/active head/frozen Source tuple')
    read.source_family(db,proof.sources,purpose=proof.purpose)
    action_original,cancellation_original = (read.original(key.token)for key in (proof.action_key,proof.cancellation_key))
    provider = GoalExecutionProvider()
    proposal = DomainProposal('d08','d08.proposal.v1',provider.descriptor.request_schema_hash,frame.envelope,(),DependencySet(),(),())
    candidate = provider.prepare_action_cancellation(proposal,action,frame.snapshot,state='cancelled')
    after = _decode('d08.action_cancellation.v1',candidate.typed_writes[0].value)
    stage = stage_result_v1(frame,'d08',OPERATION,request,writes=candidate.typed_writes,
        provenance={'action_intent_ref':proof.action_key.token,'cancellation_before':before,'cancellation_after':after,
            'action_original':action_original,'cancellation_original':cancellation_original},
        contribution_keys=('d08-action-cancel:'+canonical_digest((proof.action_key,proof.action_header,proof.cancellation_header)),),
        proposal_schema='d08.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0],frame.snapshot)
    return stage


def release_current_action_cancellation_v1(state):
    proof = getattr(state,'cancellation_identity',None)
    if proof is not None:
        _WRITES.pop(proof,None);_IDENTITIES.pop(proof,None);state.cancellation_identity = None
