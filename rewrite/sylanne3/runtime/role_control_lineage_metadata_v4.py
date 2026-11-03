"""Role-control history metadata on its actual originating Work or Owner WRITE.

Complete canonical originals authenticate control identity and current lineage.
They confer no PersonaPlan claim Body or semantic projection permission.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import Event,Scope
from ..graph_types import AtomKey,GraphVersion,NamespaceEpoch
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,runtime_storage_v3,_operation
from .d01_ordinary_origin_v3 import OrdinaryHeadCommitmentV3,OrdinaryBlockCommitmentV3,validate_ordinary_initial_v3

_KEY=object()
_OWNERS=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()
_TASKS=WeakKeyDictionary()
_METHOD_METADATA_MODES=frozenset({'method_policy_registration','method_single_event_read','method_qualified_review'})
_QUALIFIED_SELECTIONS_V4=WeakKeyDictionary()
_QUALIFIED_REVIEWS_V4=WeakKeyDictionary()
_QUALIFIED_CONTROLS_V4=WeakKeyDictionary()
_QUALIFIED_HEAD_CHAINS_V4=WeakKeyDictionary()
_QUALIFIED_OPERATION_IDS_V4=WeakKeyDictionary()
_QUALIFIED_ORIGINS_V4=WeakKeyDictionary()


class _RoleLineageDependencyV4(Exception):
    def __init__(self,identity):self.identity=identity


class _RoleControlLineageOriginOwnerV4:
    def __init__(self,key,parent):
        if key is not _KEY:raise TypeError('private role lineage metadata issuer required')
        from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3,_ORDINARY_READERS_V3
        from .role_control_rows_metadata_v4 import _OwnerWriteRoleControlsV4
        from .current_method_learning_read_v3 import _MethodLearningReadV3
        if type(parent)is BackgroundReadWorkV3:
            require_actual_background_attachment_owner_v3(parent,db=parent.db)
            if parent.kind=='offline'and parent.role_clocks:self.mode='background'
            else:
                from .d01_single_event_growth_v1 import require_single_event_review_target_metadata_work_v1
                require_single_event_review_target_metadata_work_v1(parent)
                self.mode='background_review'
            self.graph=parent.graph;self.namespace=parent.namespace
            self.scope=parent.fence.scope if parent.fence is not None else parent.read_scope
            self.work=parent.work
        elif type(parent)is _OrdinaryFullReadV3 and parent in _ORDINARY_READERS_V3:
            if not parent.graph_eof or parent.work is None or parent.work.state is not parent:
                raise AuthorityUnavailable('actual complete FULL metadata census required')
            self.mode='full';self.graph=parent.graph;self.namespace=parent.namespace
            self.scope=parent.fence.scope;self.work=parent.work
        elif type(parent)is _MethodLearningReadV3:
            qualified_selection=None
            from .current_method_learning_read_v3 import require_actual_method_learning_attachment_owner_v3
            from .d01_single_event_growth_v1 import(RegisterSingleEventGrowthPolicyRequestV1,
                ReadSingleEventGrowthRequestV1)
            require_actual_method_learning_attachment_owner_v3(parent,db=parent.db)
            if (parent.operation_kind=='register_single_event_growth_policy_v1'
                    and type(parent.request)is RegisterSingleEventGrowthPolicyRequestV1):
                self.mode='method_policy_registration'
            elif (parent.operation_kind=='read_single_event_growth_v1'
                    and type(parent.request)is ReadSingleEventGrowthRequestV1):
                self.mode='method_single_event_read'
            elif parent.operation_kind=='review_single_event_growth_v1':
                from .d01_single_event_growth_v1 import read_current_qualified_single_event_review_selection_v1
                qualified_selection=read_current_qualified_single_event_review_selection_v1(parent)
                if qualified_selection is None:
                    raise AuthorityUnavailable('role metadata review mode requires its actual current qualified V2 selector')
                self.mode='method_qualified_review'
            else:raise AuthorityUnavailable('role lineage has no exact registered single-event Method metadata request')
            if parent.fence.scope.operation!='read' or parent.fence.scope.namespace!=parent.namespace:
                raise AuthorityUnavailable('role lineage left its actual Method metadata READ namespace')
            parent.work._require_invocation(parent.graph)
            self.graph=parent.graph;self.namespace=parent.namespace
            self.scope=parent.fence.scope;self.work=parent.work
        elif type(parent)is _OwnerWriteRoleControlsV4:
            parent.require_v4();self.mode='owner_write';self.graph=parent.graph
            self.namespace=parent.namespace;self.scope=parent.scope;self.work=None
        else:raise AuthorityUnavailable('role lineage has no exact actual metadata owner')
        self.parent,self.db,self.operation=parent,parent.db,parent.operation
        self.graph_stamp=self.graph._v2_graph_stamp(self.namespace)
        self.origin_signer=self.graph._GraphCoordinator__d11_issuer._signer
        self.origin_history,self.origin_support_readsets,self.origin_columns={},{},[]
        self.columns,self.fixed_rows,self.selected_columns,self.selected_fixed={},{},set(),set()
        self.pending=None
        self.review_binding=(parent.handoff,parent.owner,parent.owner_guard,parent.read_scope)if self.mode=='background_review'else None
        self.method_binding=(parent.selection_digest,parent.owner_binding,parent.owner_guard,parent.request,
            parent.request_digest,parent.operation_kind,parent.operation.deadline_utc)if self.mode in _METHOD_METADATA_MODES else None
        _OWNERS[self]=(parent,self.db,self.operation,self.graph_stamp,self.scope,self.work,self.mode,self.review_binding,self.method_binding)
        if self.mode=='method_qualified_review':_QUALIFIED_SELECTIONS_V4[self]=qualified_selection
    def require_current_v4(self,meter=None):
        if _OWNERS.get(self)!=(self.parent,self.db,self.operation,self.graph_stamp,self.scope,self.work,self.mode,self.review_binding,self.method_binding):
            raise AuthorityUnavailable('role lineage private metadata owner identity changed')
        if self.operation.closed or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise AuthorityUnavailable('role lineage metadata operation/stamp changed')
        if self.mode in {'background','background_review'}:
            if self.mode=='background_review':
                from .d01_single_event_growth_v1 import require_single_event_review_target_metadata_work_v1
                p=require_single_event_review_target_metadata_work_v1(self.parent)
                h,owner,guard,scope=self.review_binding
                if(p.handoff is not h or p.owner is not owner or p.owner_guard!=guard
                        or p.read_scope is not scope or scope is not self.scope):
                    raise AuthorityUnavailable('review role lineage changed its actual retained Owner/READ handoff')
            from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
            require_actual_background_attachment_owner_v3(self.parent,db=self.db)
            if meter is None:
                with runtime_storage_quantum_v3(self.db)as current:self.parent.require_data_current_v3(current)
            else:self.parent.require_data_current_v3(meter)
        elif self.mode in _METHOD_METADATA_MODES:
            from .current_method_learning_read_v3 import require_actual_method_learning_attachment_owner_v3
            p=require_actual_method_learning_attachment_owner_v3(self.parent,db=self.db)
            p.work._require_invocation(p.graph)
            if(p.work is not self.work or p.operation is not self.operation or p.fence.scope is not self.scope
                    or p.owner_binding is not self.method_binding[1] or p.request is not self.method_binding[3]
                    or(p.selection_digest,p.owner_binding,p.owner_guard,p.request,p.request_digest,
                        p.operation_kind,p.operation.deadline_utc)!=self.method_binding):
                raise AuthorityUnavailable('single-event metadata lineage changed its actual Method/Owner/READ identity')
            p.require_current(meter=meter)
            if self.mode=='method_qualified_review':
                for selected in _QUALIFIED_SELECTIONS_V4[self]:selected.require_for_v1(p)
        elif self.mode=='full':
            from .current_graph_full_read_v3 import _ORDINARY_READERS_V3
            p=self.parent
            if(p not in _ORDINARY_READERS_V3 or p.work is not self.work or p.work.state is not p
                    or p.operation is not self.operation or runtime_storage_v3(self.db)is not self.operation.handle):
                raise AuthorityUnavailable('role lineage left its actual FULL Work/selection')
            if p.complete:
                from .current_graph_full_read_v3 import _BOUND
                bound=_BOUND.get()
                if bound is None or bound[0].work is not self.work or bound[0].operation is not self.operation:
                    raise AuthorityUnavailable('retained role metadata needs the actual FULL prepared Binder')
                bound[0]._actual()
            else:p.work._require_invocation(p.graph)
            if meter is None:
                with runtime_storage_quantum_v3(self.db)as current:p.operation.handle.require_current(current)
            else:p.operation.handle.require_current(meter)
        else:self.parent.require_v4()
        return self
    @contextmanager
    def quantum_v3(self):
        with runtime_storage_quantum_v3(self.db)as meter:
            self.require_current_v4(meter);yield meter;self.require_current_v4(meter)
    def release_v4(self):
        _OWNERS.pop(self,None);_QUALIFIED_SELECTIONS_V4.pop(self,None);_QUALIFIED_CONTROLS_V4.pop(self,None);_QUALIFIED_OPERATION_IDS_V4.pop(self,None);_QUALIFIED_ORIGINS_V4.pop(self,None)
        self.columns.clear();self.fixed_rows.clear();self.selected_columns.clear();self.selected_fixed.clear()
        self.origin_columns.clear();self.origin_history.clear();self.origin_support_readsets.clear();self.pending=None


def role_control_lineage_origin_owner_v4(owner):
    return type(owner)is _RoleControlLineageOriginOwnerV4 and owner in _OWNERS


def require_role_control_lineage_origin_owner_v4(owner):
    if not role_control_lineage_origin_owner_v4(owner):
        raise AuthorityUnavailable('actual private role-control metadata owner required')
    return owner.require_current_v4()


# These are the original lineage algorithms' fixed metadata columns, never a
# caller-defined SQL or Source selector.
_TABLE_COLUMNS={
    'graph_role_init_receipts_v1':frozenset({'receipt_json','operation_id'}),
    'graph_atoms':frozenset({'revision','valid','value_cell_id'}),
    'graph_history':frozenset({'token','revision','valid','event_bot','event_persona','event_session','event_id','value_cell_id'}),
    'graph_events':frozenset({'digest','epoch_revision'}),
    'graph_bundle_operations':frozenset({'digest','activity_id','effect_id','commit_seq'}),
    'graph_domain_production_originals_v1':frozenset({'domain','operation_kind','original_digest','bundle_digest','receipt_digest'})}
_FIXED_WHERE={
    'graph_role_init_receipts_v1':frozenset({'bot=? AND persona=?'}),
    'graph_atoms':frozenset({'bot=? AND persona=? AND token=?'}),
    'graph_history':frozenset({'token=? AND revision=?',
        'event_bot=? AND event_persona=? AND event_session=? AND event_id=? AND token>? ORDER BY token',
        'token=? AND revision>? AND revision<=? ORDER BY revision'}),
    'graph_events':frozenset({'bot=? AND persona=? AND session=? AND event_id=?'}),
    'graph_bundle_operations':frozenset({'bot=? AND persona=? AND operation_id=?'}),
    'graph_domain_production_originals_v1':frozenset({'bot=? AND persona=? AND operation_id=?'})}
_COLUMN_PROFILES={
    ('graph_role_init_receipts_v1','receipt_json'):frozenset({'initial_receipt'}),
    ('graph_history','value'):frozenset({'plan','activation','resources','ordinary_dedicated_member','single_event_review'}),
    ('graph_events','reads'):frozenset({'activation'}),
    ('graph_events','epoch_reads'):frozenset({'activation'}),
    ('graph_events','revisions'):frozenset({'activation'}),
    ('graph_events','invalidated'):frozenset({'activation'}),
    ('graph_bundle_operations','receipt_json'):frozenset({'activation'}),
    ('graph_domain_production_originals_v1','original_payload_json'):frozenset({'ordinary_unchanged_producer','single_event_review_operation'}),
    ('graph_domain_production_originals_v1','receipt_json'):frozenset({'activation'}),
    ('graph_domain_production_originals_v1','read_versions_json'):frozenset({'activation'})}


def read_role_control_lineage_fixed_v4(owner,table,columns,where,args):
    require_role_control_lineage_origin_owner_v4(owner)
    if (table not in _TABLE_COLUMNS or not set(columns)<=_TABLE_COLUMNS[table]
            or where not in _FIXED_WHERE[table]):
        raise AuthorityUnavailable('role lineage left its fixed metadata columns')
    if table=='graph_history'and where.startswith('token=?'):
        from ..runtime_contracts import NamespaceId
        if NamespaceId.from_key(AtomKey.from_token(args[0]))!=owner.namespace:
            raise AuthorityUnavailable('role lineage fixed history crossed namespace')
    elif tuple(args[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('role lineage fixed metadata crossed namespace')
    identity=('fixed',table,tuple(columns),where,tuple(args))
    owner.selected_fixed.add(identity)
    if identity not in owner.fixed_rows:raise _RoleLineageDependencyV4(identity)
    return owner.fixed_rows[identity]


def read_role_control_lineage_column_v4(owner,*,table,column,key_columns,key,profile,cell_id=None,signed_header=None):
    require_role_control_lineage_origin_owner_v4(owner)
    if (profile not in _COLUMN_PROFILES.get((table,column),())or signed_header is not None):
        raise AuthorityUnavailable('role lineage metadata has no registered column profile')
    if profile=='single_event_review':
        selected=_QUALIFIED_SELECTIONS_V4.get(owner)
        if(owner.mode!='method_qualified_review'or selected is None or table!='graph_history'
                or tuple(key_columns)!=('token','revision')or tuple(key)!=(selected[1].key.token,1)):
            raise AuthorityUnavailable('pending Review metadata has no exact qualified2 historical selector')
    if profile=='single_event_review_operation':
        if(owner.mode!='method_qualified_review'or table!='graph_domain_production_originals_v1'
                or tuple(key_columns)!=('bot','persona','operation_id')
                or tuple(key[:2])!=owner.namespace.as_tuple
                or key[2]not in _QUALIFIED_OPERATION_IDS_V4.get(owner,())):
            raise AuthorityUnavailable('qualified Review producer profile has no exact private selected operation')
    if table=='graph_history':
        if tuple(key_columns)!=('token','revision')or type(key[1])is not int or key[1]<1:
            raise AuthorityUnavailable('role lineage history requires its exact positive full key')
        from ..runtime_contracts import NamespaceId
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=owner.namespace:
            raise AuthorityUnavailable('role lineage history crossed namespace')
        if profile=='plan'and atom.type_name!='d01.persona_plan.v1':
            raise AuthorityUnavailable('role plan metadata profile has another family')
        if profile=='activation'and atom.type_name!='d01.persona_activation.v1':
            raise AuthorityUnavailable('role activation profile has another family')
    elif tuple(key[:2])!=owner.namespace.as_tuple:
        raise AuthorityUnavailable('role lineage original crossed namespace')
    identity=('column',table,column,tuple(key_columns),tuple(key),profile,cell_id)
    owner.selected_columns.add(identity)
    result=owner.columns.get(identity)
    if result is None or not result.complete:raise _RoleLineageDependencyV4(identity)
    result.require_v3();return result


class _RoleLineageColumnTaskV4:
    def __init__(self,owner,identity):
        if identity not in owner.selected_columns:raise AuthorityUnavailable('unselected role metadata column')
        from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3
        _,table,column,key_columns,key,profile,cell_id=identity
        self.column=OrdinaryOriginColumnV3(owner,table=table,column=column,key_columns=key_columns,key=key,
            profile=profile,cell_id=cell_id)
        self.complete=False
    def advance(self,meter):
        self.complete=self.column.advance(meter);return self.complete


@dataclass(frozen=True,eq=False)
class RoleControlLineageMetadataV4:
    owner:object
    initial:object
    current:object
    transitions:tuple
    ordered_root:str
    def require_current_v4(self):
        if _PROOFS.get(self)!=(self.owner,self.initial,self.current,self.transitions,self.ordered_root):
            raise AuthorityUnavailable('role-control lineage has no actual private complete proof')
        self.owner.require_current_v4();return self


class RoleControlLineageReadV4:
    def __init__(self,parent,control):
        self.owner=_RoleControlLineageOriginOwnerV4(_KEY,parent)
        self.control=control;self.complete=False;self.result=None;self.qualified_result=None
    def advance(self,meter):
        owner=self.owner;owner.require_current_v4(meter)
        if self.complete:self.result.require_current_v4();return True
        if owner.pending is not None:
            identity,task=owner.pending
            if identity[0]=='fixed':
                _,table,columns,where,args=identity
                owner.fixed_rows[identity]=meter.read_fixed_row(owner.db,table,columns,where,args)
                owner.pending=None;return False
            if task.advance(meter):
                owner.columns[identity]=task.column
                if task.column not in owner.origin_columns:owner.origin_columns.append(task.column)
                owner.pending=None
            return False
        try:
            qualified=_read_qualified_review_controls_v4(owner)if owner.mode=='method_qualified_review'else None
            proof=_read_lineage_v4(owner,self.control)
            if qualified is not None:
                _require_qualified_target_chain_v4(owner,proof,qualified)
                self.qualified_result=_issue_qualified_review_v4(self,proof,qualified)
        except _RoleLineageDependencyV4 as needed:
            identity=needed.identity
            owner.pending=(identity,None if identity[0]=='fixed'else _RoleLineageColumnTaskV4(owner,identity))
            return False
        self.result=proof;self.complete=True;return True
    def release_v4(self):
        if self.result is not None:
            _PROOFS.pop(self.result,None);_QUALIFIED_HEAD_CHAINS_V4.pop(self.result,None)
        if self.qualified_result is not None:_QUALIFIED_REVIEWS_V4.pop(self.qualified_result,None)
        self.qualified_result=None;self.result=None;self.owner.release_v4()


def _read_metadata_column_v4(owner,table,column,key_columns,key,profile,*,cell_id=None):
    from .d01_ordinary_origin_read_v3 import _column
    return _column(owner,table,column,key_columns,key,profile,cell_id=cell_id)


def _read_history_member_v4(owner,key,revision,*,body_metadata=False,expected_valid=True):
    from .d01_ordinary_origin_v3 import OrdinaryHistoryMemberV3
    from .d01_ordinary_origin_read_v3 import _fixed
    header=_fixed(owner,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
        'token=? AND revision=?',(key.token,revision))
    if header is None or header[:3]!=(int(expected_valid),*owner.namespace.as_tuple):
        raise AuthorityUnavailable('role lineage actual member header is absent/foreign')
    profile=('plan'if key.type_name=='d01.persona_plan.v1'else'activation')if body_metadata else'ordinary_dedicated_member'
    column=_read_metadata_column_v4(owner,'graph_history','value',('token','revision'),(key.token,revision),profile,cell_id=header[5])
    return OrdinaryHistoryMemberV3(GraphVersion(key,revision),column.semantic_digest,expected_valid,Scope(*header[1:4]),header[4]),column


def _require_invalidated_history_v4(owner,version,event):
    # GraphStore writes the new invalidated revision (r+1), reusing the actual
    # prior valid value at r. Physical cells may have been translated by C09;
    # compare complete logical EOF commitments, never cell-id equality.
    member,_ = _read_history_member_v4(owner,version.key,version.revision,expected_valid=False)
    previous,_ = _read_history_member_v4(owner,version.key,version.revision-1)
    if (member.event_scope!=event.scope or member.event_id!=event.event_id
            or member.value_digest!=previous.value_digest):
        raise AuthorityUnavailable('role producer invalidation lost its actual predecessor/whole-value commitment')
    return member


def _head_from_refs_v4(owner,plan_ref,activation_ref):
    from .d01_ordinary_origin_read_v3 import _typed
    from ..domains.d01 import PersonaActivation
    pm,pc=_read_history_member_v4(owner,plan_ref.key,plan_ref.revision,body_metadata=True)
    am,ac=_read_history_member_v4(owner,activation_ref.key,activation_ref.revision,body_metadata=True)
    activation=_typed(ac.metadata,PersonaActivation);raw=pc.metadata
    from dataclasses import asdict
    if (set(pc.fields[()])!={'plan_id','namespace','version','blocks','values','authored'}
            or raw['namespace']!=asdict(owner.namespace)or activation.namespace!=owner.namespace
            or (raw['plan_id'],raw['version'])!=(activation.plan_id,activation.plan_version)
            or pm.event_scope!=am.event_scope or pm.event_id!=am.event_id):
        raise AuthorityUnavailable('role control actual paired metadata differs')
    blocks=[]
    for i,block in enumerate(raw['blocks']):
        path=('blocks',i)
        if pc.fields[path]!={'block_id','kind','claim','plasticity'}or path+('claim',)not in pc.parser.claim_protocols:
            raise AuthorityUnavailable('role lineage block metadata EOF is incomplete')
        blocks.append(OrdinaryBlockCommitmentV3(block['block_id'],block['kind'],block['plasticity'],
            pc.commitments[path+('claim',)],pc.parser.claim_protocols[path+('claim',)]))
    return OrdinaryHeadCommitmentV3(owner.namespace,raw['plan_id'],raw['version'],raw['authored'],pm.ref,pc.semantic_digest,
        am.ref,ac.semantic_digest,activation,tuple(blocks),pc.commitments[('values',)])


def _transition_v4(owner,before,plan_ref,event_id):
    from .d01_ordinary_origin_read_v3 import _fixed,_event,_versions,_event_invalidated_versions_v3
    from .domain_production_originals_v1 import _receipt
    from .domain_production_registry_v1 import installed_operation_v1
    ns=owner.namespace;key=(*ns.as_tuple,event_id)
    header=_fixed(owner,'graph_domain_production_originals_v1',('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if header is None or header[0]!='d01'or installed_operation_v1(header[1]).domain!='d01':
        raise AuthorityUnavailable('role head change has no actual registered D01 producer')
    pc=_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','original_payload_json',
        ('bot','persona','operation_id'),key,'ordinary_unchanged_producer')
    payload=pc.metadata
    receipt=_receipt(_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','receipt_json',
        ('bot','persona','operation_id'),key,'activation').metadata)
    reads=_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','read_versions_json',
        ('bot','persona','operation_id'),key,'activation').metadata
    bundle=_fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    from dataclasses import asdict
    if (payload.get('namespace')!=asdict(ns)or payload.get('identity',{}).get('operation_id')!=event_id
            or payload['identity'].get('activity_id')!=receipt.activity_id
            or payload['identity'].get('effect_id')!=receipt.effect_id
            or pc.semantic_digest!=header[2]or canonical_digest(receipt)!=header[4]
            or payload.get('schema')!='d01.current-'+header[1]+'.v1'or payload.get('coverage')!='complete'
            or payload.get('missing_inputs')or payload.get('continuation_ref')is not None
            or receipt.status!='committed'or receipt.operation_id!=event_id
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or type(receipt.commit_seq)is not int or receipt.commit_seq<1 or header[3]!=receipt.operation_digest
            or _versions(payload['read_versions'])!=receipt.read_versions
            or tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in reads)!=receipt.read_versions):
        raise AuthorityUnavailable('role head original/receipt/full commit metadata differs')
    identity=payload['identity']
    event=Event(Scope(*ns.as_tuple,identity['activity_id']),event_id,payload['now_utc'],'domain_bundle',{'bundle_digest':header[3]})
    recorded=_event(owner,event)
    if (recorded.recorded_digest!=event.digest or recorded.reads!=receipt.read_versions
            or recorded.revisions!=receipt.write_versions or len(receipt.invalidated_epochs)!=1
            or (receipt.invalidated_epochs[0].bot,receipt.invalidated_epochs[0].persona)!=ns.as_tuple
            or recorded.epoch_revision!=receipt.invalidated_epochs[0].revision
            or recorded.epoch_reads!=(NamespaceEpoch(*ns.as_tuple,recorded.epoch_revision-1),)):
        raise AuthorityUnavailable('role head producer Graph event differs from its full original')
    from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
    compact=_read_metadata_column_v4(owner,'graph_bundle_operations','receipt_json',('bot','persona','operation_id'),key,'activation')
    rebuilt=reconstruct_graph_bundle_commit_receipt_v1(ns,event_id,(*bundle,canonical_serialize(compact.metadata)),
        (canonical_serialize(tuple((v.key.token,v.revision)for v in recorded.reads)),
         canonical_serialize(tuple((v.key.token,v.revision)for v in recorded.revisions)),recorded.epoch_revision))
    if rebuilt!=receipt:raise AuthorityUnavailable('role producer actual compact bundle receipt differs')
    from ..domains.d01 import _activation_key
    akey=_activation_key(ns)
    activations=tuple(v for v in receipt.write_versions if v.key==akey)
    if len(activations)!=1 or plan_ref not in receipt.write_versions:
        raise AuthorityUnavailable('role head producer did not write the actual paired plan/activation')
    after=_head_from_refs_v4(owner,plan_ref,activations[0])
    if (after.plan_id!=before.plan_id or after.version!=before.version+1
            or before.plan_ref not in receipt.read_versions or before.activation_ref not in receipt.read_versions):
        raise AuthorityUnavailable('role head actual predecessor/next version CAS differs')
    writes=payload['writes'];wanted={v.key:v.revision for v in receipt.write_versions}
    if len(wanted)!=len(receipt.write_versions)or len(writes)!=len(wanted):
        raise AuthorityUnavailable('role producer typed write metadata is not complete')
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    decoded={}
    for i,write in enumerate(writes):
        wkey=decode_typed_production_value_v1(write['key'],AtomKey)
        if wkey not in wanted or wkey in decoded:raise AuthorityUnavailable('role producer has foreign/repeated typed writes')
        member,column=_read_history_member_v4(owner,wkey,wanted[wkey])
        if (member.event_scope!=event.scope or member.event_id!=event_id
                or member.value_digest!=pc.commitments[('writes',i,'value')]):
            raise AuthorityUnavailable('role producer typed write has another actual whole-value history')
        decoded[wkey]=member
    invalidated=_event_invalidated_versions_v3(owner,event)
    if set(wanted).intersection(v.key for v in invalidated):
        raise AuthorityUnavailable('role producer repeats a write as an invalidated key')
    all_members={**wanted,**{v.key:v.revision for v in invalidated}}
    for version in invalidated:_require_invalidated_history_v4(owner,version,event)
    cursor='';count=0
    while True:
        row=_fixed(owner,'graph_history',('token','revision'),
            'event_bot=? AND event_persona=? AND event_session=? AND event_id=? AND token>? ORDER BY token',
            (*ns.as_tuple,event.scope.session,event_id,cursor))
        if row is None:break
        if all_members.get(AtomKey.from_token(row[0]))!=row[1]or count>=len(all_members):
            raise AuthorityUnavailable('role producer complete history member census has extra versions')
        cursor=row[0];count+=1
    if count!=len(all_members):raise AuthorityUnavailable('role producer complete history member census is missing writes/invalidations')
    return after,(header[1],event_id,header[2],header[4],recorded.recorded_digest,tuple(receipt.read_versions),tuple(receipt.write_versions))


def _read_lineage_v4(owner,control):
    from .d01_ordinary_origin_read_v3 import _initial,_fixed
    from ..domains.d01 import ActiveRoleHeadControlV3,_activation_key
    from ..graph_types import owner_grant_key
    if type(control)is not ActiveRoleHeadControlV3:
        raise AuthorityUnavailable('actual typed current role-control identity required')
    expected=(_activation_key(owner.namespace),control.plan_key,owner_grant_key(*owner.namespace.as_tuple))
    if len(control.read_versions)!=3 or tuple(v.key for v in control.read_versions)!=expected:
        raise AuthorityUnavailable('role lineage requires the actual ordered three control headers')
    for version in control.read_versions:
        current=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
            'bot=? AND persona=? AND token=?',(*owner.namespace.as_tuple,version.key.token))
        if current is None or current[:2]!=(version.revision,1):
            raise AuthorityUnavailable('role lineage control current header changed')
    initial=_initial(owner);head=validate_ordinary_initial_v3(initial)
    if(control.namespace!=owner.namespace or control.plan_key!=head.plan_ref.key
            or control.plan_version<1):
        raise AuthorityUnavailable('role control metadata has another initialized plan/head bound')
    versions={v.key:v.revision for v in control.read_versions}
    target=GraphVersion(control.plan_key,versions[control.plan_key])
    cursor=head.plan_ref.revision;transitions=[]
    qualified_heads=[head]if owner.mode=='method_qualified_review'else None
    root=canonical_digest(('role-control-lineage-metadata.v4',initial.receipt_digest,head))
    while cursor<target.revision:
        row=_fixed(owner,'graph_history',('revision','event_id'),
            'token=? AND revision>? AND revision<=? ORDER BY revision',(target.key.token,cursor,target.revision))
        if row is None:raise AuthorityUnavailable('role current plan has no complete actual producer history')
        actual=GraphVersion(target.key,row[0]);head,transition=_transition_v4(owner,head,actual,row[1])
        transitions.append(transition);root=canonical_digest((root,head,transition));cursor=row[0]
        if qualified_heads is not None:qualified_heads.append(head)
    if (head.plan_ref!=target or head.head_id!=control.head_id or head.version!=control.plan_version
            or versions.get(head.activation_ref.key)!=head.activation_ref.revision):
        raise AuthorityUnavailable('role current head/activation is not the complete authenticated lineage endpoint')
    proof=RoleControlLineageMetadataV4(owner,initial,head,tuple(transitions),root)
    _PROOFS[proof]=(owner,initial,head,proof.transitions,root)
    if qualified_heads is not None:_QUALIFIED_HEAD_CHAINS_V4[proof]=tuple(qualified_heads)
    return proof


def prepare_role_control_lineage_metadata_v4(parent,control):
    task=_TASKS.get(parent)
    if task is None:
        task=RoleControlLineageReadV4(parent,control);_TASKS[parent]=task
    if task.control!=control:raise AuthorityUnavailable('role metadata task changed its actual protected head')
    return task


def require_role_control_lineage_metadata_v4(parent,control):
    task=prepare_role_control_lineage_metadata_v4(parent,control)
    if task.owner.mode=='owner_write':
        while not task.complete:
            with task.owner.quantum_v3()as meter:task.advance(meter)
    if not task.complete:
        if task.owner.mode in {'background','background_review'}:
            from .domain_background_read_v3 import BackgroundReadNeededV3
            raise BackgroundReadNeededV3(('role_control_lineage_v4',))
        if task.owner.mode in _METHOD_METADATA_MODES:
            from .current_method_learning_read_v3 import _need_method_input
            _need_method_input(parent,('role_control_lineage_v4',))
        raise AuthorityUnavailable('role metadata lineage was not prepared by the actual originating Work')
    return task.result.require_current_v4()


def create_background_role_control_lineage_task_v4(owner):
    task=_TASKS.get(owner)
    if task is None or task.owner.mode not in {'background','background_review'}:
        raise AuthorityUnavailable('Background role lineage has no actual registered selection')
    task.owner.require_current_v4();return task


def create_current_method_role_control_lineage_task_v4(owner):
    task=_TASKS.get(owner)
    if task is None or task.owner.mode not in _METHOD_METADATA_MODES:
        raise AuthorityUnavailable('Method single-event metadata has no actual selected role lineage task')
    task.owner.require_current_v4();return task


def release_role_control_lineage_metadata_v4(parent):
    task=_TASKS.pop(parent,None)
    if task is not None:task.release_v4()


def release_installed_role_control_lineages_v4(reader,scope):
    for parent,task in tuple(_TASKS.items()):
        if (task.owner.mode=='owner_write'and parent.reader is reader and parent.scope is scope):
            _TASKS.pop(parent,None);task.release_v4()


def _qualified_operation_control_v4(owner,operation_id,kind):
    from .d01_ordinary_origin_read_v3 import _fixed,_event
    from .domain_production_originals_v1 import _receipt,reconstruct_graph_bundle_commit_receipt_v1
    ns=owner.namespace;key=(*ns.as_tuple,operation_id)
    header=_fixed(owner,'graph_domain_production_originals_v1',
        ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if header is None or header[:2]!=('d01',kind):
        raise AuthorityUnavailable('qualified Review has no exact registered D01 W01 producer')
    pc=_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','original_payload_json',
        ('bot','persona','operation_id'),key,'single_event_review_operation')
    payload=pc.metadata
    receipt=_receipt(_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','receipt_json',
        ('bot','persona','operation_id'),key,'activation').metadata)
    reads=_read_metadata_column_v4(owner,'graph_domain_production_originals_v1','read_versions_json',
        ('bot','persona','operation_id'),key,'activation').metadata
    bundle=_fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    from dataclasses import asdict
    if (payload.get('schema')!='d01.current-'+kind+'.v1'or payload.get('namespace')!=asdict(ns)
            or payload.get('coverage')!='complete'or pc.semantic_digest!=header[2]
            or receipt.status!='committed'or receipt.operation_id!=operation_id
            or canonical_digest(receipt)!=header[4]or receipt.operation_digest!=header[3]
            or type(receipt.commit_seq)is not int or receipt.commit_seq<1
            or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in reads)!=receipt.read_versions):
        raise AuthorityUnavailable('qualified Review producer canonical EOF/receipt/bundle metadata changed')
    identity=payload['identity']
    if (identity['operation_id']!=operation_id or identity['phase']!=kind
            or identity['activity_id']!=receipt.activity_id or identity['effect_id']!=receipt.effect_id):
        raise AuthorityUnavailable('qualified Review producer changed its actual W01 identity')
    event=Event(Scope(*ns.as_tuple,identity['activity_id']),operation_id,payload['now_utc'],
        'domain_bundle',{'bundle_digest':header[3]})
    recorded=_event(owner,event)
    if (recorded.recorded_digest!=event.digest or recorded.reads!=receipt.read_versions
            or recorded.revisions!=receipt.write_versions or len(receipt.invalidated_epochs)!=1
            or(receipt.invalidated_epochs[0].bot,receipt.invalidated_epochs[0].persona)!=ns.as_tuple
            or recorded.epoch_revision!=receipt.invalidated_epochs[0].revision
            or recorded.epoch_reads!=(NamespaceEpoch(*ns.as_tuple,recorded.epoch_revision-1),)):
        raise AuthorityUnavailable('qualified Review W01 event is not its actual complete receipt')
    compact=_read_metadata_column_v4(owner,'graph_bundle_operations','receipt_json',
        ('bot','persona','operation_id'),key,'activation')
    rebuilt=reconstruct_graph_bundle_commit_receipt_v1(ns,operation_id,
        (*bundle,canonical_serialize(compact.metadata)),
        (canonical_serialize(tuple((v.key.token,v.revision)for v in recorded.reads)),
         canonical_serialize(tuple((v.key.token,v.revision)for v in recorded.revisions)),recorded.epoch_revision))
    if rebuilt!=receipt:raise AuthorityUnavailable('qualified Review compact receipt differs from the actual W01 event')
    return payload,receipt,header[2],event


def _read_qualified_review_controls_v4(owner):
    prior=_QUALIFIED_CONTROLS_V4.get(owner)
    if prior is not None:return prior
    from .d01_ordinary_origin_read_v3 import _fixed,_typed
    from ..domains.d01.single_event_growth_v1 import SingleEventGrowthAdoptionV1,SingleEventGrowthReviewV2
    selected=_QUALIFIED_SELECTIONS_V4.get(owner)
    if owner.mode!='method_qualified_review'or selected is None:
        raise AuthorityUnavailable('qualified Review controls need their independently registered metadata selector')
    adopted,metadata=selected
    for value in selected:value.require_for_v1(owner.parent)
    adoption=_typed(adopted.value,SingleEventGrowthAdoptionV1)
    review=_typed(metadata.value,SingleEventGrowthReviewV2)
    av=GraphVersion(adopted.key,adopted.revision);rv=GraphVersion(metadata.key,metadata.revision)
    if(adopted.revision!=1 or metadata.revision!=2 or review.disposition!='qualified'
            or review.review_case_original is None):
        raise AuthorityUnavailable('qualified Review controls require the exact immutable adoption and current qualified2')
    am,ac=_read_history_member_v4(owner,av.key,av.revision)
    rm,rc=_read_history_member_v4(owner,rv.key,rv.revision)
    if(am.value_digest!=adopted.payload_digest or rm.value_digest!=metadata.payload_digest):
        raise AuthorityUnavailable('qualified Review actual current metadata differs from its complete history EOF')
    pending_version=GraphVersion(rv.key,1)
    pending_header=_fixed(owner,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
        'token=? AND revision=?',(rv.key.token,1))
    if(pending_header is None or pending_header[:3]!=(1,*owner.namespace.as_tuple)
            or pending_header[4]!=adoption.adoption_operation_id):
        raise AuthorityUnavailable('qualified Review has no actual valid same-adoption pending1 history')
    pending_column=_read_metadata_column_v4(owner,'graph_history','value',('token','revision'),
        (rv.key.token,1),'single_event_review',cell_id=pending_header[5])
    pending=_typed(pending_column.metadata,SingleEventGrowthReviewV2)
    fields=('namespace','adoption_ref','adoption_operation_id','adopted_head','target_block',
        'adopted_claim_digest','review_not_before_utc','review_due_utc','readout_valid_until_utc')
    if(pending.disposition!='pending'or any(getattr(pending,f)!=getattr(review,f)for f in fields)
            or review.adoption_ref!=av.key.token or review.adoption_operation_id!=adoption.adoption_operation_id
            or review.target_block!=adoption.target_block or review.adopted_claim_digest!=adoption.adopted_claim_digest):
        raise AuthorityUnavailable('qualified Review changed its actual first obligation/adoption/claim/window')
    _QUALIFIED_OPERATION_IDS_V4[owner]=(adoption.adoption_operation_id,rm.event_id)
    born,birth_receipt,birth_digest,birth_event=_qualified_operation_control_v4(owner,adoption.adoption_operation_id,'adopt_single_event_growth_v1')
    current,receipt,digest,event=_qualified_operation_control_v4(owner,rm.event_id,'review_single_event_growth_v1')
    if (am.event_scope!=birth_event.scope or am.event_id!=birth_event.event_id
            or Scope(*pending_header[1:4])!=birth_event.scope
            or pending_version not in birth_receipt.write_versions or av not in birth_receipt.write_versions
            or GraphVersion(rv.key,0)not in birth_receipt.read_versions
            or born['provenance']['single_event_adoption']!=adopted.value
            or born['provenance']['single_event_review']!=pending_column.metadata
            or rm.event_scope!=event.scope or rv not in receipt.write_versions
            or receipt.write_versions!=(rv,)or pending_version not in receipt.read_versions
            or current['provenance']['single_event_adoption']!=adopted.value
            or current['provenance']['single_event_review']!=metadata.value
            or not current['now_utc']<=review.reviewed_at_utc):
        raise AuthorityUnavailable('qualified Review is not its actual read1/write2 consumption with the same adopted payload')
    result=(selected,adoption,review,receipt,birth_receipt,digest)
    _QUALIFIED_CONTROLS_V4[owner]=result
    _QUALIFIED_ORIGINS_V4[owner]={
        'adopt_single_event_growth_v1':(adopted,{'domain':'d01','operation_kind':'adopt_single_event_growth_v1',
            'original_digest':birth_digest,'receipt':birth_receipt,'payload':born}),
        'review_single_event_growth_v1':(metadata,{'domain':'d01','operation_kind':'review_single_event_growth_v1',
            'original_digest':digest,'receipt':receipt,'payload':current})}
    return result


def _require_qualified_target_chain_v4(owner,lineage,qualified):
    _,adoption,review,receipt,_,_=qualified
    heads=_QUALIFIED_HEAD_CHAINS_V4.get(lineage)
    if heads is None:raise AuthorityUnavailable('qualified Review has no complete private current-target lineage')
    frozen=tuple(i for i,head in enumerate(heads)if head.plan_ref in receipt.read_versions)
    if len(frozen)!=1:raise AuthorityUnavailable('qualified Review receipt lacks its unique actual current plan at review')
    wanted=None
    for head in heads[frozen[0]:]:
        blocks=tuple(b for b in head.blocks if b.block_id==adoption.target_block)
        if (len(blocks)!=1 or blocks[0].claim_digest!=adoption.adopted_claim_digest
                or blocks[0].plasticity!='growth'or wanted is not None and blocks[0]!=wanted):
            raise AuthorityUnavailable('qualified Review target changed along its actual gapfree lineage')
        wanted=blocks[0]
    if lineage.current!=heads[-1]or review.adopted_claim_digest!=wanted.claim_digest:
        raise AuthorityUnavailable('qualified Review current target differs from its exact adopted claim')


@dataclass(frozen=True,eq=False)
class QualifiedSingleEventReviewMetadataV4:
    owner:object
    lineage:RoleControlLineageMetadataV4
    review:object
    producer_receipt:object
    @property
    def current(self):return self.lineage.current
    def require_recorded_origin_v4(self,reader,*,version,value,operation_kind):
        self.require_current_v4(reader)
        if operation_kind not in {'adopt_single_event_growth_v1','review_single_event_growth_v1'}:
            raise AuthorityUnavailable('qualified Review has no other recorded origin projection')
        selected,control=_QUALIFIED_ORIGINS_V4[self.owner][operation_kind]
        selected.require_for_v1(reader)
        if(type(version)is not GraphVersion or version!=GraphVersion(selected.key,selected.revision)
                or value!=selected.value):
            raise AuthorityUnavailable('qualified Review origin projection crossed its actual metadata head')
        return control
    def require_current_v4(self,reader):
        record=_QUALIFIED_REVIEWS_V4.get(self)
        task=_TASKS.get(reader)
        if (record is None or task is not record[0]or task.qualified_result is not self
                or task.owner is not self.owner or self.owner.parent is not reader
                or record[1]is not self.lineage or record[2]is not _QUALIFIED_CONTROLS_V4.get(self.owner)
                or self.review!=record[2][2]or self.producer_receipt!=record[2][3]):
            raise AuthorityUnavailable('qualified Review metadata is not this actual private Method result')
        self.lineage.require_current_v4()
        for value in record[2][0]:value.require_for_v1(reader)
        from .current_method_learning_read_v3 import actual_current_method_upper_utc_v1
        actual_current_method_upper_utc_v1(reader)
        # This proves a recorded fact only; the caller still applies the original readout cutoff.
        return self


def _issue_qualified_review_v4(task,lineage,qualified):
    if (_TASKS.get(task.owner.parent)is not task or lineage.owner is not task.owner
            or qualified is not _QUALIFIED_CONTROLS_V4.get(task.owner)):
        raise AuthorityUnavailable('qualified Review issuer needs its exact completed metadata task')
    proof=QualifiedSingleEventReviewMetadataV4(task.owner,lineage,qualified[2],qualified[3])
    _QUALIFIED_REVIEWS_V4[proof]=(task,lineage,qualified)
    from .dispatch_current_inventory_v3 import _heap
    chain=_QUALIFIED_HEAD_CHAINS_V4[lineage]
    receipts=qualified[3:5]
    task.owner.operation.retain(_heap((proof,qualified,chain,_QUALIFIED_ORIGINS_V4[task.owner]))
        +sum(_heap((r.read_versions,r.write_versions,r.invalidated_epochs))for r in receipts)
        +sum(_heap(head.blocks)for head in chain)+4096)
    return proof


def prepare_current_qualified_single_event_review_metadata_v4(reader):
    from .d01_single_event_growth_v1 import read_current_qualified_single_event_review_selection_v1
    selected=read_current_qualified_single_event_review_selection_v1(reader)
    if selected is None:return None
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    from ..domains.d01 import ActiveRoleHeadControlV3
    birth=current_persona_birth_control_v1(reader.db,namespace=reader.namespace)
    control=ActiveRoleHeadControlV3(reader.namespace,birth.head_id,birth.persona_head_version.key,birth.semantic_version,
        (birth.activation_version,birth.persona_head_version,birth.owner_grant_version),
        reader.graph_stamp[1].revision,reader.owner_guard.authorization_revision)
    require_role_control_lineage_metadata_v4(reader,control)
    return require_current_qualified_single_event_review_metadata_v4(reader)


def require_current_qualified_single_event_review_metadata_v4(reader):
    task=_TASKS.get(reader)
    if task is None or task.owner.mode!='method_qualified_review':return None
    if not task.complete or task.qualified_result is None:
        raise AuthorityUnavailable('qualified Review requires its completed original metadata READ')
    return task.qualified_result.require_current_v4(reader)
