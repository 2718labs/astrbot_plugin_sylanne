"""Private Joint Source closure for the actual Contact READ and fresh WRITE."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..memory_types import source_key,access_key

_ISSUER=object()
_READS=WeakKeyDictionary()
_BY_PARENT=WeakKeyDictionary()
_CLOSED=WeakKeyDictionary()
_MATERIALS=WeakKeyDictionary()
_ACTIVE=ContextVar('contact_joint_closed_observation_v3',default=None)

# Semantic text is hashed as canonical stream tokens and is never retained by a locator.
_FIELDS={
    'index':frozenset({'schema','namespace','selector_kind','selector_key','binding_ref','binding_digest','binding_request_digest','source_refs'}),
    'binding':frozenset({'schema','namespace','node_id','plan_ref','plan_revision','owner_ref','action_kind','action_ref','action_revision',
        'action_digest','action_schema_ref','action_schema_revision','action_schema_digest','project_ref','recipe_ref','goal_ref','goal_id',
        'target_ref','target_entity_ref','role_ref','source_refs','progress_ref','executor','parent_budget_lease_ref','parent_grant_id',
        'parent_grant_version','parent_grant_digest','original_deadline_utc','purpose','audience','contact_id','prospective_original_ref',
        'prospective_original_digest','refresh_rule'}),
    'prospective':frozenset({'schema','namespace','contact_id','birth_operation_id','joint_preparation','terms','deadline_utc','refresh_rule'}),
    'preparation':frozenset({'schema','request','owner_ref','owner_acl_actor','contact_plan_ref','contact_plan_revision','contact_plan_original_digest',
        'reviewed_content_digest','contact_causal_original_ref','contact_causal_original_digest','parent_budget_lease_ref','parent_grant_id',
        'parent_grant_version','parent_grant_digest','absolute_deadline_utc','source_refs','purpose','audience','producer_operation_id',
        'input_request_digest','source_purpose_groups'}),
    'plan':frozenset({'plan_id','revision','nodes','acceptances','source_refs'}),
    'intent':frozenset({'plan_id','revision','nodes','source_refs','current_goal_refs'}),
    'adoption':frozenset({'request','authority'}),
    'scope':frozenset({'authority'}),
    'consent':frozenset({'plan_proposal_ref','participant_ref','plan_revision','terms_digest','accepted_scope','acceptance_interpretation_ref',
        'inbound_source_ref','outbound_receipt_refs'}),
    'external':frozenset({'schema','namespace','node_id','party_ref','source_refs','audience','purpose','original_deadline_utc'}),
    'compensation':frozenset({'schema','namespace','plan_ref','plan_revision','node_id','trigger_binding_ref','trigger_binding_digest',
        'repair_binding_ref','repair_binding_digest','trigger_kind','source_refs'}),
    'goal':frozenset({'source_refs'}),'interpretation':frozenset({'source_refs'}),
}
_RECIPES={
    'index':('graph_d10_production_inputs_v1','payload_json',('bot','persona','original_ref')),
    'binding':('graph_d10_production_inputs_v1','payload_json',('bot','persona','original_ref')),
    'prospective':('graph_contact_prospective_originals_v1','payload_json',('bot','persona','contact_id')),
    'preparation':('graph_d10_production_inputs_v1','payload_json',('bot','persona','original_ref')),
    'plan':('graph_atoms','value',('token','bot','persona')),
    'intent':('graph_d08_joint_plan_intents_v1','payload_json',('bot','persona','original_ref')),
    'adoption':('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id')),
    'scope':('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id')),
    'consent':('graph_d08_party_consents_v1','payload_json',('bot','persona','original_ref')),
    'external':('graph_d08_joint_node_originals_v1','payload_json',('bot','persona','original_ref')),
    'compensation':('graph_d08_joint_node_originals_v1','payload_json',('bot','persona','original_ref')),
    'goal':('graph_atoms','value',('token','bot','persona')),
    'interpretation':('graph_atoms','value',('token','bot','persona')),
}
_SIGNS={'graph_d10_production_inputs_v1':'d11.d10-production-input.v1',
    'graph_d08_joint_plan_intents_v1':'d11.d08-joint-plan-intent.v1',
    'graph_d08_party_consents_v1':'d11.d08-party-consent.v1',
    'graph_d08_joint_node_originals_v1':'d11.d08-joint-node-original.v1'}

@dataclass(frozen=True,slots=True)
class _JointLocatorProfileV3:
    kind:str
    locator:str


def _actual(work):
    from .contact_domain_source_v3 import require_contact_domain_work_v3
    work=require_contact_domain_work_v3(work)
    state=getattr(work,'joint_context_source',None)
    if (type(state)is not _ContactJointObservationReadV3 or _READS.get(state)!=state.identity
            or _BY_PARENT.get(work.parent)is not state or state.work is not work):
        raise AuthorityUnavailable('Contact Joint Source lost its actual private READ origin')
    state.require_current_v3()
    return state


def require_contact_joint_locator_profile_v3(parent,profile,table,column,key):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(parent,db=parent.db)
    state=_BY_PARENT.get(parent)
    if (type(profile)is not _JointLocatorProfileV3 or state is None or state.work.parent is not parent
            or (profile,table,column,tuple(key))not in state.column_recipes or parent.sealed):
        raise AuthorityUnavailable('Joint metadata locator is outside its exact originating Contact Work recipe')
    state.require_current_v3()
    return state


def contact_joint_locator_retains_path_v3(parent,profile,table,column,key,path):
    require_contact_joint_locator_profile_v3(parent,profile,table,column,key)
    if not path:return True
    if path[0]not in _FIELDS[profile.kind]:return False
    if profile.kind in ('plan','intent')and len(path)>=3 and path[0]=='nodes':
        return path[2]in {'node_id','owner_ref','depends_on','action_kind','cancellation_point','compensation_ref','resource_ref'}
    if profile.kind in ('adoption','scope'):
        if path[0]=='authority':return len(path)==1 or path[1]in {'purpose','audience'}
        return len(path)==1 or path[1]in {'joint_plan_proposal_ref','party_consent_original_refs'}
    if profile.kind=='binding'and path[0]=='executor':
        return len(path)==1 or path[1]in {'schema','prepare_contact_operation_id','qualified_outbox_dedupe_key',
            'authorization_original_ref','c02_operation_id','root_registration_ref','source_ref','phase_selector'} and path[1]!='phase_selector'
    return True


def observe_contact_joint_locator_event_v3(column,event):
    profile=column.joint_contact_metadata_profile
    require_contact_joint_locator_profile_v3(column.owner,profile,column.table,column.column,column.key)
    path=tuple(event.path)
    if profile.kind in ('plan','intent')and len(path)>=3 and path[0]=='nodes'and path[2]=='success_predicate':
        root=path[:3]
    elif profile.kind in ('plan','intent')and path and path[0]=='exit_rules':root=path[:1]
    elif profile.kind in ('binding','external')and path and path[0]=='success_predicate':root=path[:1]
    else:return
    states=column.joint_contact_hash_states
    if event.kind in ('object_start','array_start','scalar_start')and path==root:
        if root in states:raise AuthorityUnavailable('Joint predicate field occurs twice')
        states[root]=sha256()
    digest=states[root]
    # Token framing is independent of IO fragmentation and of the node array position.
    if event.kind=='scalar_chunk':
        if event.scalar_kind!='string':digest.update(event.raw)
    elif event.kind=='scalar_start':digest.update(b's:'+event.scalar_kind.encode()+b':' )
    elif event.kind=='scalar_end':digest.update(b';')
    elif event.kind=='key':digest.update(b'k:'+canonical_serialize(event.key).encode('ascii')+b';')
    else:digest.update(event.kind.encode('ascii')+b';')
    if event.kind in ('object_end','array_end','scalar_end')and path==root:
        column.joint_contact_field_hashes[root]=digest.hexdigest()


def observe_contact_joint_locator_codepoint_v3(column,path,codepoint):
    profile=column.joint_contact_metadata_profile
    path=tuple(path)
    if profile.kind in ('plan','intent')and len(path)>=3 and path[0]=='nodes'and path[2]=='success_predicate':root=path[:3]
    elif profile.kind in ('plan','intent')and path and path[0]=='exit_rules':root=path[:1]
    elif profile.kind in ('binding','external')and path and path[0]=='success_predicate':root=path[:1]
    else:return
    if codepoint>0xffff:
        scalar=codepoint-0x10000
        column.joint_contact_hash_states[root].update((0xd800+(scalar>>10)).to_bytes(4,'big'))
        column.joint_contact_hash_states[root].update((0xdc00+(scalar&0x3ff)).to_bytes(4,'big'))
    else:column.joint_contact_hash_states[root].update(codepoint.to_bytes(4,'big'))


def _detach(column):
    from .dispatch_current_inventory_v3 import _detach_value_v3
    if not column.complete:raise AuthorityUnavailable('Joint locator has not reached complete canonical EOF')
    return _detach_value_v3(column.frozen)


class _JointMetadataColumnReadV3:
    def __init__(self,state,kind,locator):
        self.state,self.profile=state,_JointLocatorProfileV3(kind,locator)
        self.table,self.column,self.keys=_RECIPES[kind]
        ns=state.work.namespace.as_tuple
        self.key=(locator,*ns)if self.table=='graph_atoms'else(*ns,locator)
        self.where=' AND '.join(name+'=?'for name in self.keys)
        self.column_read=None;self.metadata=None;self.complete=False;self.value=None;self.hashes={}
        state.column_recipes.add((self.profile,self.table,self.column,self.key))
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_background_read_v3 import BackgroundJSONColumnV3,_ISSUER as column_issuer
        o=self.state.work.parent
        self.state.require_current_v3(meter)
        if self.column_read is None:
            metadata=('revision','valid','type_name','value_cell_id')if self.table=='graph_atoms'else(
                ('original_digest','receipt_digest','domain','operation_kind')if self.profile.kind in ('adoption','scope')else
                ('birth_operation_id','payload_digest','signature','original_ref')if self.profile.kind=='prospective'else
                ('producing_operation_id','payload_digest','signature'))
            self.metadata_columns=metadata
            self.metadata=_runtime_bounded_fixed_row_v3(o.db,meter,self.table,metadata,self.where,self.key)
            if self.metadata is None:
                if self.profile.kind=='index':self.complete=True;return
                raise AuthorityUnavailable('Contact Joint exact original locator is absent')
            values=dict(zip(metadata,self.metadata))
            if self.table=='graph_atoms':
                atom=AtomKey.from_token(self.profile.locator)
                expected={'plan':'d08.joint_plan.v1','goal':'d08.goal.v1','interpretation':'d07.current_interpretation.v1'}[self.profile.kind]
                if values['valid']!=1 or values['revision']<1 or values['type_name']!=expected or atom.type_name!=expected:
                    raise AuthorityUnavailable('Joint current metadata locator changed type/revision/validity')
                self.state.graph_versions[atom.token]=values['revision']
                event=_runtime_bounded_fixed_row_v3(o.db,meter,'graph_history',('event_id',),'token=? AND revision=?',(atom.token,values['revision']))
                if event is None:raise AuthorityUnavailable('Joint metadata head lost its committed event')
                self.scope_operation=event[0]
            elif self.profile.kind=='prospective':self.scope_operation=values['birth_operation_id']
            elif self.profile.kind not in ('adoption','scope'):
                self.scope_operation=values['producing_operation_id']
            sign=_SIGNS.get(self.table)
            self.column_read=BackgroundJSONColumnV3(column_issuer,o,table=self.table,column=self.column,
                key_columns=self.keys,key=self.key,cell_id=values.get('value_cell_id'),
                signer=o.graph._GraphCoordinator__d11_issuer._signer if sign is not None else None,
                signature_kind=sign,signature=values.get('signature'),joint_contact_metadata_profile=self.profile)
            return
        if not self.column_read.advance(meter):return
        digest=self.column_read.semantic_sha256
        if self.table!='graph_atoms'and digest!=self.metadata[0 if self.profile.kind in ('adoption','scope')else 1]:
            raise AuthorityUnavailable('Joint locator whole canonical digest differs from signed original')
        self.value=_detach(self.column_read);self.hashes=dict(self.column_read.joint_contact_field_hashes)
        if self.profile.kind=='prospective':
            from .contact_prospective_v1 import SIGN_KIND,contact_prospective_original_ref_v1
            namespace=self.state.work.namespace
            if (self.value['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
                    or self.value['contact_id']!=self.profile.locator or self.value['birth_operation_id']!=self.metadata[0]
                    or self.metadata[3]!=contact_prospective_original_ref_v1(namespace,self.profile.locator,self.metadata[0])):
                raise AuthorityUnavailable('Joint Contact prospective locator differs from actual immutable birth')
            o.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((namespace,self.profile.locator,self.metadata[0],digest)),self.metadata[2])
        self.digest=digest;self.complete=True
        self.state.metadata[self.profile.kind,self.profile.locator]=self
    def require_current_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if not self.complete:raise AuthorityUnavailable('Joint metadata original has no complete actual EOF')
        current=_runtime_bounded_fixed_row_v3(self.state.work.db,meter,self.table,self.metadata_columns,self.where,self.key)
        if current!=self.metadata:raise AuthorityUnavailable('Joint exact locator changed after READ EOF')


class _ContactJointObservationReadV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER:raise AuthorityUnavailable('Contact Joint private producer required')
        self.work=work
        self.identity=(work,work.parent,work.operation,work.scope,work.graph_stamp,work.selection_digest,
            work.owner_guard,work.owner,work.selector)
        self.metadata={};self.column_recipes=set();self.graph_versions={};self.pending=None;self.queue=[]
        self.complete=False;self.groups=();self.enabled=False;self.anchor=None;self.phase='index'
        self.index_ref=None
    def require_current_v3(self,meter=None):
        w=self.work
        if (_READS.get(self)!=self.identity or self.identity!=(w,w.parent,w.operation,w.scope,w.graph_stamp,w.selection_digest,
                w.owner_guard,w.owner,w.selector)or w.closed or w.operation.closed):
            raise AuthorityUnavailable('Joint Contact Source origin/frame changed')
        if meter is not None:w.require_current(meter=meter)
        if self.enabled and _CLOSED.get(self)!=(self.identity,self.groups,self.metadata_commitment,
                tuple(sorted(self.graph_versions.items())),self._metadata_freeze_v3()):
            raise AuthorityUnavailable('Joint Contact closed metadata/Source groups changed')
        return self
    def enqueue(self,kind,locator):
        if (kind,locator)not in self.metadata and (kind,locator)not in self.queue:
            self.queue.append((kind,locator))
    def advance(self,meter):
        self.require_current_v3(meter)
        w=self.work
        if self.complete:return
        if self.phase=='index':
            from .joint_node_execution_v1 import joint_executor_index_ref_v1
            if w.selector.phase!='contact_final':self.complete=True;return
            if w.parent.entry is None or w.parent.entry[2]!='qualified_contact_opportunity_requires_action':
                raise AuthorityUnavailable('Joint Contact final must retain its exact old qualified Contact cause')
            self.old_cause=(w.parent.entry[0],w.selector.causal_dedupe)
            self.index_ref=joint_executor_index_ref_v1(w.namespace,'contact',self.old_cause)
            self.enqueue('index',self.index_ref);self.phase='index_eof'
        if self.pending is not None:
            self.pending.advance(meter)
            if self.pending.complete:self.pending=None
            return
        if self.queue:
            self.pending=_JointMetadataColumnReadV3(self,*self.queue.pop(0));return
        if self.phase=='index_eof':
            item=self.metadata.get(('index',self.index_ref))
            if item is None:self.complete=True;return
            index=item.value
            if (index['schema']!='d10.joint-executor-index.v1' or index['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}
                    or index['selector_kind']!='contact' or tuple(index['selector_key'])!=self.old_cause
                    or index['binding_ref']!='joint-node-binding:'+index['binding_digest']):
                raise AuthorityUnavailable('Joint Contact exact current executor index differs')
            self.anchor=index['binding_ref'];self.enqueue('binding',self.anchor);self.phase='anchor_eof';return
        if self.phase=='anchor_eof':
            anchor=self.metadata['binding',self.anchor].value
            if (anchor['schema']!='d10.joint-contact-prospective-binding.v1' or anchor['contact_id']!=w.selector.contact_id
                    or anchor['executor']['prepare_contact_operation_id']!=self.old_cause[0]
                    or anchor['executor']['qualified_outbox_dedupe_key']!=self.old_cause[1]
                    or anchor['owner_ref']!='persona:'+w.namespace.persona_id):
                raise AuthorityUnavailable('Joint Contact context cannot substitute another node/cause/birth')
            self.plan_ref,self.plan_revision=anchor['plan_ref'],anchor['plan_revision']
            self.enqueue('plan',self.plan_ref);self.enqueue('prospective',anchor['contact_id']);self.phase='birth_eof';return
        if self.phase=='birth_eof':
            birth=self.metadata['prospective',w.selector.contact_id]
            self.preparation_ref=birth.value['joint_preparation']['ref']
            self.enqueue('preparation',self.preparation_ref);self.phase='plan_eof';return
        if self.phase=='plan_eof':
            plan=self.metadata['plan',self.plan_ref].value
            if plan['revision']!=self.plan_revision or self.graph_versions[self.plan_ref]!=self.plan_revision:
                raise AuthorityUnavailable('Joint exact adopted Plan revision changed before Source selection')
            from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
            event=_runtime_bounded_fixed_row_v3(w.db,meter,'graph_history',('event_id',),'token=? AND revision=?',(self.plan_ref,self.plan_revision))
            if event is None:raise AuthorityUnavailable('Joint Plan lacks actual adopted history event')
            self.adoption_operation=event[0];self.enqueue('adoption',event[0]);self.phase='adoption_eof';return
        if self.phase=='adoption_eof':
            request=self.metadata['adoption',self.adoption_operation].value['request']
            self.proposal_ref=request['joint_plan_proposal_ref'];self.consent_refs=tuple(request['party_consent_original_refs'])
            self.enqueue('intent',self.proposal_ref)
            for ref in self.consent_refs:self.enqueue('consent',ref)
            plan=self.metadata['plan',self.plan_ref].value
            if not 1<=len(plan['nodes'])<=8:raise AuthorityUnavailable('Joint Plan node bound differs')
            for node in plan['nodes']:
                self.enqueue('binding'if node['owner_ref']=='persona:'+w.namespace.persona_id else'external',node['resource_ref'])
                if node['compensation_ref']is not None:self.enqueue('compensation',node['compensation_ref'])
            self.phase='contracts_eof';return
        if self.phase=='contracts_eof':
            intent=self.metadata['intent',self.proposal_ref].value
            for ref in intent['current_goal_refs']:self.enqueue('goal',ref)
            for ref in self.consent_refs:
                consent=self.metadata['consent',ref].value
                self.enqueue('interpretation',consent['acceptance_interpretation_ref'])
            for node in self.metadata['plan',self.plan_ref].value['nodes']:
                if node['compensation_ref']is not None:
                    auth=self.metadata['compensation',node['compensation_ref']].value
                    self.enqueue('binding',auth['repair_binding_ref'])
            self.phase='all_eof';return
        if self.phase=='all_eof':
            for item in tuple(self.metadata.values()):
                if item.profile.kind not in ('adoption','scope','index'):
                    self.enqueue('scope',item.scope_operation)
            self.phase='scopes_eof';return
        if self.phase=='scopes_eof':
            self._close_metadata_v3();self.complete=True;self.enabled=True
            _CLOSED[self]=(self.identity,self.groups,self.metadata_commitment,tuple(sorted(self.graph_versions.items())),self._metadata_freeze_v3())
            return
        raise AuthorityUnavailable('Joint Contact metadata has an unregistered phase')
    def _close_metadata_v3(self):
        w=self.work;plan_item=self.metadata['plan',self.plan_ref];plan=plan_item.value
        intent_item=self.metadata['intent',self.proposal_ref];intent=intent_item.value
        if (plan['plan_id'],plan['revision'],plan['nodes'],plan['source_refs'])!=(
                intent['plan_id'],intent['revision'],intent['nodes'],intent['source_refs'])or plan_item.hashes!=intent_item.hashes:
            raise AuthorityUnavailable('Joint adopted Plan changed signed proposal node slots')
        nodes={node['node_id']:node for node in plan['nodes']}
        if len(nodes)!=len(plan['nodes']):raise AuthorityUnavailable('Joint node identity repeats')
        consents={}
        for ref in self.consent_refs:
            c=self.metadata['consent',ref].value
            if (c['plan_proposal_ref']!=self.proposal_ref or c['plan_revision']!=self.plan_revision
                    or c['terms_digest']!=intent_item.digest or c['participant_ref']in consents
                    or not {n['node_id']for n in plan['nodes']if n['owner_ref']==c['participant_ref']}<=set(c['accepted_scope'])<=set(nodes)):
                raise AuthorityUnavailable('Joint party consent differs from exact proposal/revision/responsibility')
            consents[c['participant_ref']]=(ref,c)
        if set(consents)!={n['owner_ref']for n in plan['nodes']}:
            raise AuthorityUnavailable('Joint Plan Source has incomplete exact party consent coverage')
        acceptances={a['participant_ref']:a for a in plan['acceptances']}
        if set(acceptances)!=set(consents):raise AuthorityUnavailable('Joint actual Plan acceptance parties differ')
        for party,(_,c)in consents.items():
            a=acceptances[party]
            if (a['plan_revision']!=self.plan_revision or a['accepted_scope']!=c['accepted_scope']
                    or tuple(a['receipt_refs'])!=tuple(dict.fromkeys((c['inbound_source_ref'],*c['outbound_receipt_refs'])))):
                raise AuthorityUnavailable('Joint current Plan acceptance scope differs from signed consent')
        # First verify every concrete contract, including repair slots; only then form Source groups.
        specifications=[]
        for pos,node in enumerate(plan['nodes']):
            kind='binding'if node['owner_ref']=='persona:'+w.namespace.persona_id else'external'
            item=self.metadata[kind,node['resource_ref']];raw=item.value
            slot_hash=plan_item.hashes[('nodes',pos,'success_predicate')]
            if item.hashes.get(('success_predicate',))!=slot_hash or raw['node_id']!=node['node_id']:
                raise AuthorityUnavailable('Joint executor predicate/node differs from exact accepted slot')
            if kind=='binding':
                self._binding_slot_v3(item,node,repair=False)
                if node['resource_ref']==self.anchor:
                    if tuple(raw['audience'])!=(w.contact_locator.audience,)or raw['purpose']!='expression':
                        raise AuthorityUnavailable('Joint Contact node changed original recipient/expression scope')
                    preparation=self.metadata['preparation',self.preparation_ref]
                    p=preparation.value;birth=self.metadata['prospective',w.selector.contact_id].value
                    declared=p['request']
                    if (birth['joint_preparation']['digest']!=preparation.digest
                            or (declared['joint_plan_ref'],declared['joint_plan_revision'],declared['node_id'],p['owner_ref'])!=(
                                self.plan_ref,self.plan_revision,node['node_id'],node['owner_ref'])
                            or (declared['contact_id'],declared['prepare_contact_operation_id'],declared['qualified_contact_dedupe_key'])!=(
                                w.selector.contact_id,*self.old_cause)
                            or p['owner_acl_actor']!=w.owner.actor or tuple(p['audience'])!=tuple(raw['audience'])
                            or p['purpose']!=raw['purpose'] or set(p['source_refs'])!=set(raw['source_refs'])
                            or raw['prospective_original_digest']!=self.metadata['prospective',w.selector.contact_id].digest
                            or raw['prospective_original_ref']!=self.metadata['prospective',w.selector.contact_id].metadata[3]
                            or raw['refresh_rule']!=birth['refresh_rule']):
                        raise AuthorityUnavailable('Joint Contact Source groups have another exact signed birth/Preparation/node')
                    signed_groups=dict(p['source_purpose_groups'])
                    if any(ref not in signed_groups for ref in raw['source_refs']):
                        raise AuthorityUnavailable('Joint Contact binding ref lacks actual per-ref signed purpose coverage')
                    for ref,purposes in signed_groups.items():
                        if not purposes or not set(purposes)<={'expression','context'}:
                            raise AuthorityUnavailable('Joint Contact per-ref purposes differ from actual signed closed recipe')
                        specifications.append(((ref,),tuple(purposes),tuple(raw['audience'])))
                else:specifications.append((raw['source_refs'],(raw['purpose'],),tuple(raw['audience'])))
            else:
                if (raw['schema']!='d08.joint-external-node-contract.v1' or raw['party_ref']!=node['owner_ref']
                        or raw['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}
                        or node['resource_ref']!='joint-external-contract:'+item.digest):
                    raise AuthorityUnavailable('Joint external contract differs from actual exact responsible party')
                specifications.append((raw['source_refs'],(raw['purpose'],),tuple(raw['audience'])))
            if node['compensation_ref']is not None:
                auth_item=self.metadata['compensation',node['compensation_ref']];auth=auth_item.value
                if (kind!='binding' or not node['cancellation_point']or auth['schema']!='d08.joint-compensation-authorization.v1'
                        or (auth['plan_ref'],auth['plan_revision'],auth['node_id'],auth['trigger_binding_ref'],auth['trigger_binding_digest'])!=(
                            self.plan_ref,self.plan_revision,node['node_id'],node['resource_ref'],item.digest)
                        or node['compensation_ref']!='joint-node-compensation:'+auth_item.digest
                        or auth['trigger_kind']not in ('cancelled_settled','failed_verified_settled')
                        or auth['repair_binding_ref']==auth['trigger_binding_ref']):
                    raise AuthorityUnavailable('Joint compensation changed exact trigger/node responsibility')
                repair=self.metadata['binding',auth['repair_binding_ref']]
                self._binding_slot_v3(repair,node,repair=True)
                if repair.digest!=auth['repair_binding_digest']:
                    raise AuthorityUnavailable('Joint compensation repair differs from signed actual repair')
                r=repair.value
                specifications.append(((*auth['source_refs'],*r['source_refs']),(r['purpose'],),tuple(r['audience'])))
        if self.anchor not in {node['resource_ref']for node in plan['nodes']}:
            raise AuthorityUnavailable('Joint indexed Contact binding is absent from exact Plan slots')
        adopt=self.metadata['adoption',self.adoption_operation]
        if adopt.metadata[2:]!=('d08','adopt_joint_plan'):
            raise AuthorityUnavailable('Joint Plan locator has another actual adopted producer')
        specifications.append((plan['source_refs'],(adopt.value['authority']['purpose'],),tuple(adopt.value['authority']['audience'])))
        def original_scope(item):
            authority=self.metadata['scope',item.scope_operation].value['authority']
            return (authority['purpose'],),tuple(authority['audience'])
        specifications.append((intent['source_refs'],*original_scope(intent_item)))
        for ref in intent['current_goal_refs']:
            item=self.metadata['goal',ref]
            specifications.append((item.value['source_refs'],*original_scope(item)))
        for ref,c in consents.values():
            item=self.metadata['consent',ref]
            specifications.append(((c['inbound_source_ref'],),*original_scope(item)))
            semantic=self.metadata['interpretation',c['acceptance_interpretation_ref']]
            specifications.append((semantic.value['source_refs'],*original_scope(semantic)))
        groups={};active=set();seen=set()
        def visit(ref,purpose,audience):
            key=(ref,purpose,audience)
            if key in active:raise AuthorityUnavailable('Joint Source ancestry is cyclic')
            if key in seen:return
            atom=AtomKey.from_token(ref);original=w.sources.get(ref)
            if atom.type_name!='memory.source'or NamespaceId.from_key(atom)!=w.namespace or original is None:
                raise AuthorityUnavailable('Joint Source scope has no exact actual current metadata')
            if len(groups)>=256 and ref not in groups:raise AuthorityUnavailable('Joint Source ancestry exceeds original bound')
            active.add(key);groups.setdefault(ref,set()).add((purpose,audience))
            for parent in original.metadata['parent_source_ids']:visit(source_key(*w.namespace.as_tuple,parent).token,purpose,audience)
            active.remove(key);seen.add(key)
        for roots,purposes,audiences in specifications:
            for ref in roots:
                for purpose in purposes:
                    for audience in audiences:visit(ref,purpose,audience)
        owner=w.owner
        if any(p not in owner.purposes or a not in owner.audiences for values in groups.values()for p,a in values):
            raise AuthorityUnavailable('Current Contact Owner lacks independently signed Joint purpose/audience scope')
        self.groups=tuple((ref,tuple(sorted(values)))for ref,values in sorted(groups.items()))
        self.metadata_commitment=canonical_digest(tuple((kind,ref,item.digest,tuple(sorted(item.hashes.items())))
            for (kind,ref),item in sorted(self.metadata.items())))
    def _metadata_freeze_v3(self):
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        return tuple((kind,ref,_freeze_value_v3(item.value),tuple(sorted(item.hashes.items())))
            for (kind,ref),item in sorted(self.metadata.items()))
    def _binding_slot_v3(self,item,node,*,repair):
        raw=item.value;w=self.work
        if (raw['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}
                or (raw['plan_ref'],raw['plan_revision'],raw['node_id'],raw['owner_ref'])!=(
                    self.plan_ref,self.plan_revision,node['node_id'],node['owner_ref'])
                or not repair and raw['action_kind']!=node['action_kind']
                or item.profile.locator!='joint-node-binding:'+item.digest):
            raise AuthorityUnavailable('Joint signed binding is outside exact Plan/node/Owner slot')
    def require_body_v3(self):
        self.require_current_v3()
        w=self.work
        if not self.complete or not self.enabled or not w.complete or w.source_material is None:
            raise AuthorityUnavailable('Joint body cannot precede all independent Source/parent/purpose rights and EOF')
        if w.parent.sealed:
            from .contact_domain_source_v3 import require_contact_domain_fresh_write_v3
            require_contact_domain_fresh_write_v3(w,w.db)
        for ref,pairs in self.groups:
            witness=w.source_material.witnesses.get(ref)
            if witness is None or not set(p for p,_ in pairs)<=set(w.source_material.purposes.get(ref,())):
                raise AuthorityUnavailable('Joint retained Source body lost its exact independent purpose closure')
            witness.require_current_v3()
        return self


def begin_contact_joint_observation_read_v3(work):
    from .contact_domain_source_v3 import require_contact_domain_work_v3
    work=require_contact_domain_work_v3(work)
    if work.parent.sealed:raise AuthorityUnavailable('Joint Source preparation requires actual Contact READ')
    state=getattr(work,'joint_context_source',None)
    if state is not None:return _actual(work)
    state=_ContactJointObservationReadV3(_ISSUER,work)
    work.joint_context_source=state
    _READS[state]=state.identity;_BY_PARENT[work.parent]=state
    return state


@contextmanager
def bind_contact_joint_observation_v3(work,db):
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if type(work)is BackgroundReadWorkV3:
        state=_BY_PARENT.get(work)
        if state is None:yield None;return
    else:state=_actual(work)
    if state.work.db is not db:raise AuthorityUnavailable('Joint Contact observation crossed actual database')
    state.require_current_v3()
    token=_ACTIVE.set(state)
    try:yield state
    finally:_ACTIVE.reset(token)


def contact_joint_source_atom_v3(work,ref):
    state=_ACTIVE.get()
    if state is None:return False,None
    if work not in (state.work,state.work.parent):raise AuthorityUnavailable('Joint Source caller has another actual Work')
    state.require_body_v3()
    if ref not in dict(state.groups):return False,None
    material=state.work.source_material
    return True,GraphAtom(AtomKey.from_token(ref),material.witnesses[ref].revision,material.source_records[ref].to_dict(),True)


def require_contact_joint_body_v3(parent,table,key):
    state=_ACTIVE.get()
    if state is None:return False
    if parent is not state.work.parent:raise AuthorityUnavailable('Joint body caller crossed actual Contact parent')
    selected=any(item.table==table and item.key==tuple(key)for item in state.metadata.values())
    if selected:state.require_body_v3()
    elif table in ('graph_d10_production_inputs_v1','graph_d08_joint_node_originals_v1')and str(key[-1]).startswith(('joint-node-binding:','joint-external-contract:','joint-node-compensation:','joint-executor-index:')):
        raise AuthorityUnavailable('Contact cannot read unrelated Joint original bodies')
    elif table=='graph_atoms'and AtomKey.from_token(key[0]).type_name=='d08.joint_plan.v1':
        raise AuthorityUnavailable('Contact cannot read unrelated Joint Plan bodies')
    return selected


def advance_contact_joint_source_rights_v3(reader,meter):
    state=getattr(reader.work,'joint_context_source',None)
    if state is None or not state.enabled:return False
    state=_actual(reader.work)
    if reader.phase!='rights':return False
    w=reader.work;selection=reader.selection
    if not hasattr(reader,'joint_pending_v3'):
        groups={ref:set(values)for ref,values in state.groups}
        for ref,purposes in selection.purpose_groups:
            for purpose in purposes:groups.setdefault(ref,set()).add((purpose,selection.audience))
        active=set();seen=set()
        def visit(ref,purpose,audience):
            key=(ref,purpose,audience)
            if key in active:raise AuthorityUnavailable('Combined Contact/Joint Source ancestry is cyclic')
            if key in seen:return
            witness=w.sources.get(ref)
            if witness is None:raise AuthorityUnavailable('Contact/Joint Source parent lacks actual metadata EOF')
            if len(groups)>=selection.maximum_ancestors and ref not in groups:raise AuthorityUnavailable('Contact/Joint Source ancestry exceeds original bound')
            active.add(key);groups.setdefault(ref,set()).add((purpose,audience))
            for parent in witness.metadata['parent_source_ids']:visit(source_key(*w.namespace.as_tuple,parent).token,purpose,audience)
            active.remove(key);seen.add(key)
        for ref,values in tuple(groups.items()):
            for purpose,audience in tuple(values):visit(ref,purpose,audience)
        reader.joint_pending_v3=[(ref,purpose,audience)for ref,values in sorted(groups.items())for purpose,audience in sorted(values)]
        reader.joint_qualified_v3=set();reader.joint_all_groups_v3=tuple((ref,tuple(sorted(values)))for ref,values in sorted(groups.items()))
        reader.pending=[]
    if not reader.joint_pending_v3:
        required={(ref,purpose,audience)for ref,values in reader.joint_all_groups_v3 for purpose,audience in values}
        if required!=reader.joint_qualified_v3:raise AuthorityUnavailable('Contact/Joint all-purpose rights closure is incomplete')
        reader.phase='cell';return True
    ref,purpose,audience=reader.joint_pending_v3.pop()
    witness=w.sources[ref];witness.require_current_v3()
    key=AtomKey.from_token(ref);access=access_key(*w.namespace.as_tuple,key.owner.subject)
    from ..domains.d06 import source_correction_head_key
    correction=source_correction_head_key(w.namespace,key.owner.subject)
    access_atom=w.projection.get(access);head=w.projection.get(correction)
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    record=_qualify_source_rights_values_v3(w.namespace,ref,witness,access_atom,head,
        audience=audience,purpose=purpose,metadata_only=True)
    if record is None:raise AuthorityUnavailable('Contact/Joint current Source/parent/correction/purpose/audience rights differ')
    if ref not in reader.witnesses:
        reader.witnesses[ref]=witness;reader.metadata_records[ref]=record
        reader.versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,access_atom.revision),GraphVersion(correction,0)))
    reader.qualified_purposes.setdefault(ref,set()).add(purpose)
    reader.joint_qualified_v3.add((ref,purpose,audience));reader._reserve_v3()
    return True


def release_contact_joint_observation_v3(work):
    state=getattr(work,'joint_context_source',None)
    if state is None:return
    _READS.pop(state,None);_BY_PARENT.pop(work.parent,None);_CLOSED.pop(state,None)
    for material,entry in tuple(_MATERIALS.items()):
        if entry[0]is work:_MATERIALS.pop(material,None)
    state.metadata.clear();state.column_recipes.clear();state.groups=();state.pending=None
    work.joint_context_source=None


def register_contact_joint_material_v3(material,reader):
    state=getattr(reader.work,'joint_context_source',None)
    if state is None or not state.enabled:return
    state=_actual(reader.work)
    if not reader.complete or reader.phase!='seal':
        raise AuthorityUnavailable('Joint Source material requires actual complete rights/body EOF')
    _MATERIALS[material]=(reader.work,reader.joint_all_groups_v3)


def require_contact_joint_material_purpose_v3(material,*,work,source_ref,audiences,purpose):
    qualified=_MATERIALS.get(material)
    state=getattr(work,'joint_context_source',None)
    if state is None or not state.enabled:return
    state=_actual(work)
    if qualified is None or qualified[0]is not work:
        raise AuthorityUnavailable('Joint Source body has no actual independently closed purpose/audience material')
    groups=dict(qualified[1])
    if any((purpose,audience)not in groups.get(source_ref,())for audience in audiences):
        raise AuthorityUnavailable('Joint Source body cannot change its independently signed purpose/audience')


def contact_joint_original_point_v3(work,db,*,table,columns,key_columns,key):
    state=_ACTIVE.get()
    if state is None:return False,None
    if state.work is not work or work.db is not db:
        raise AuthorityUnavailable('Joint original caller has another actual Contact Work/database')
    selected=any(item.table==table and item.key==tuple(key)for item in state.metadata.values())
    if not selected:return False,None
    state.require_body_v3()
    from .domain_background_read_v3 import read_bound_background_graph_attachment_v3
    return read_bound_background_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
