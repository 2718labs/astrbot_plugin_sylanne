"""Fixed named Joint Core predicate over independently qualified current inputs.

The private semantic read adapter shares pure Joint predicates, never a Host
permission. Bounded point continuations remain in this Authority Work. Only the
fixed original executor, its selected graph families and authenticated producers
can be materialized after every purpose/audience Source group has reached ALL.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from types import SimpleNamespace
from dataclasses import replace
import json

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion, GraphSnapshot, NamespaceEpoch, owner_grant_key
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionQueryCoverageV1
from .named_joint_binding_source_read_v3 import (_fixed, _column, _run, _read_body, _head_positive,
    _positive, _source_refs, require_named_joint_inputs_v3)
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_BOUND = ContextVar('sylanne_named_joint_core_body_v1', default=None)
_GRAPHS = frozenset({'d08.joint_window.v1','d08.long_term_plan.v1','d08.joint_plan.v1',
    'd08.goal.v1','d08.action_intent.v1','d08.action_schema.v1','d08.action_outcome.v1','d08.action_cancellation.v1',
    'd10.life_project.v1','d10.activity_recipe.v1','d10.life_progress.v1','d10.project_checkpoint.v1',
    'd03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule','d05.relationship_projection',
    'd07.current_interpretation.v1','d07.attention_ticket.v1','d07.focus.v1','d07.concern_round.v1',
    'd08.personal_plan.v1','d08.decision_record.v2',
    'runtime.job','runtime.cost_settlement','d12.active_scheme_head.v1','d12.domain_scheme_selection.v1'})
_FAMILIES = frozenset({'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule',
    'd07.current_interpretation.v1','d07.attention_ticket.v1','d07.focus.v1','d07.concern_round.v1',
    'd08.goal.v1','d08.action_intent.v1','d08.action_schema.v1','d08.action_cancellation.v1',
    'd08.action_outcome.v1','d10.life_progress.v1','runtime.cost_settlement'})
_SOURCE_FIELDS = frozenset({'source_refs','source_ref','input_source_ref','body_source_ref','creation_evidence_refs','reason_refs'})


class _Needed(Exception):
    def __init__(self, request): self.request = request


class _SourceLocatorColumn(DispatchOriginalJSONReadV3):
    def _emit(self, event):
        if event.kind in {'object_start','array_start'} or any(part in _SOURCE_FIELDS for part in event.path):
            super()._emit(event)


def _precheck_column(state, table, column, key_columns, key, cell=None):
    value = _SourceLocatorColumn(state.work, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell)
    if value.cell is not None:
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        value.parser = C09CanonicalJSONStreamV2(ensure_ascii=value.cell.header[0]=='canonical-json.ascii.v1')
    locator = _run(state.work, value)
    if not _source_refs(locator) <= set(state.closure_refs):
        raise AuthorityUnavailable('Named Joint selected original requires an unqualified actual Source group')
    return value


def _bound(db):
    state = _BOUND.get()
    if state is None: return None
    require_named_joint_inputs_v3(state.work)
    if state.work.db is not db or state.metadata_only:
        raise AuthorityUnavailable('Named Joint current body crossed its actual Source Work/database')
    return state


def named_joint_core_read_for_frame_v1(frame):
    state = _BOUND.get()
    if state is None or getattr(state, 'semantic_frame', None) is not frame: return None
    require_named_joint_inputs_v3(state.work)
    return state.semantic_read


def named_joint_core_point_v1(db, *, table, columns, key_columns, key):
    state = _bound(db)
    if state is None: return False, None
    request = (table, tuple(columns), tuple(key_columns), tuple(key))
    if request not in state.point_rows: raise _Needed(('point', request))
    return True, state.point_rows[request]


def named_joint_core_inventory_v1(db, namespace, type_id, *, valid_only):
    state = _bound(db)
    if state is None: return None
    from ..runtime.named_joint_source_note_inputs_v1 import named_source_note_original_family_v1
    note_original=named_source_note_original_family_v1(state,type_id)
    if namespace != state.work.namespace or type_id not in _FAMILIES and not note_original:
        raise AuthorityUnavailable('Named Joint inventory escaped its fixed original Joint predicate families')
    rows = state.semantic_read.complete_inventory(db, type_id)
    return tuple(atom for atom in rows if not valid_only or atom.valid)


def _prepare_point(state, request):
    from ..runtime.natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    table, columns, key_columns, key = request
    graph_shape=table in {'graph_atoms','graph_history'}and set(columns)<=({'token','revision','value','valid','bot','persona','type_name','value_cell_id'}if table=='graph_atoms'else{'token','revision','value','valid','event_id','event_bot','event_persona','event_session','dependencies','value_cell_id'})
    d12_shape=(table=='graph_d12_domain_candidates_v1'and key_columns==('bot','persona','candidate_ref')and columns in {('candidate_json','candidate_sha256'),('domain','field_input_digest','proposal_schema_hash','candidate_digest','candidate_json','candidate_sha256')}and tuple(key[:2])==state.work.namespace.as_tuple and key[2]in state.d12_candidate_refs)
    from ..runtime.joint_window_command_v1 import joint_window_command_ref_v1
    frozen_ref=joint_window_command_ref_v1(state.work.namespace,state.request.argument.typed_request_digest)
    frozen_shape=(table=='graph_d10_production_inputs_v1'and columns==('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json')and key_columns==('bot','persona','original_ref')and key==(*state.work.namespace.as_tuple,frozen_ref))
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 and not graph_shape and not d12_shape and not frozen_shape:
        raise AuthorityUnavailable('Named Joint original has no registered fixed full-PK read shape')
    if table in {'graph_atoms','graph_history'}:
        graph_key = AtomKey.from_token(key[0])
        from ..runtime.named_joint_source_note_inputs_v1 import require_named_source_note_original_atom_v1
        note_original=require_named_source_note_original_atom_v1(state,graph_key)
        if NamespaceId.from_key(graph_key) != state.work.namespace or graph_key.type_name not in _GRAPHS and not note_original:
            raise AuthorityUnavailable('Named Joint selected graph original crossed its fixed type/namespace')
        if table == 'graph_atoms':
            _prepare_atom(state, graph_key)
        elif key not in state.selected_history:
            current=state.work.heads.get(graph_key.token)
            if graph_key.type_name!='d12.active_scheme_head.v1'or current is None or type(key[1])is not int or not 1<=key[1]<=current[0]:
                raise AuthorityUnavailable('Named Joint historical body was not selected by the actual current graph producer')
            state.selected_history.add(tuple(key))
    elif table in {'runtime_budget_grants','runtime_budget_leases','runtime_budget_reservations'}:
        if key[0] not in state.budget_lease_ids:
            raise AuthorityUnavailable('Named Joint budget read escaped its original actual parent family')
    elif table == 'runtime_resource_quotes':
        if tuple(key) not in state.quote_keys:
            raise AuthorityUnavailable('Named Joint quote was not selected by the original executor')
    elif table == 'runtime_jobs':
        if key[0] not in state.job_ids:
            raise AuthorityUnavailable('Named Joint job is outside its actual immutable executor/qualification lineage')
    elif tuple(key[:2]) != state.work.namespace.as_tuple:
        raise AuthorityUnavailable('Named Joint original crossed its actual namespace')
    if table == 'graph_domain_production_originals_v1' and key[2] not in state.producer_ids:
        from ..runtime.named_joint_source_note_inputs_v1 import admit_named_source_note_producer_v1
        if not admit_named_source_note_producer_v1(state,key[2]):raise AuthorityUnavailable('Named Joint W01 body is outside its actual current producing lineage')
    # Permission locator EOF precedes protected column materialization.
    for column in columns:
        if column in {'value','payload_json','original_payload_json','continuation_json'}:
            cell = None
            if table in {'graph_atoms','graph_history'} and column == 'value':
                current = _fixed(state.work, table, ('value_cell_id',),
                    ' AND '.join(name+'=?' for name in key_columns), key)
                if current is None:
                    state.point_rows[request] = None
                    return
                cell = current[0]
            exists = _fixed(state.work, table, (key_columns[0],),
                ' AND '.join(name+'=?' for name in key_columns), key)
            if exists is not None: _precheck_column(state, table, column, key_columns, key, cell)
    json_names=tuple(name for name in columns if name.endswith('_json')or name in {'value','reads','revisions','invalidated','dependencies','typed_request_wire'})
    metadata_columns=tuple(dict.fromkeys((*key_columns,*(name for name in columns if name not in json_names),
        *(('value_cell_id',)if table in {'graph_atoms','graph_history'}and'value'in columns else()))))
    header=_fixed(state.work,table,metadata_columns,' AND '.join(name+'=?'for name in key_columns),key)
    if header is None:row=None
    else:
        values=dict(zip(metadata_columns,header))
        for name in json_names:
            if name=='value'and table in {'graph_atoms','graph_history'}:
                raw=_column(state,table,name,key_columns,key,values['value_cell_id'])
            else:
                with state.work.quantum_v3()as meter:
                    storage=state.work.db.execute('SELECT typeof('+name+') FROM '+table+' WHERE '+' AND '.join(n+'=?'for n in key_columns),key).fetchone()
                    meter.charge_read(8)
                raw=None if storage is None or storage[0]=='null'else _column(state,table,name,key_columns,key)
            values[name]=None if raw is None else canonical_serialize(raw)
        row=tuple(values[name]for name in columns)
    state.point_rows[request]=row
    if row is not None:
        values = dict(zip(columns, row))
        if table == 'graph_history':
            state.producer_ids.add(values.get('event_id'))
            if AtomKey.from_token(key[0]).type_name=='d12.active_scheme_head.v1'and 'value'in values:
                state.d12_head_values[key[1]]=json.loads(values['value'])
        if table == 'graph_d11_life_originals_v1' or table in {'graph_d10_production_inputs_v1','graph_d08_joint_plan_intents_v1','graph_d08_party_consents_v1','graph_d08_joint_node_originals_v1'}:
            if values.get('producing_operation_id'): state.producer_ids.add(values['producing_operation_id'])


def _prepare_atom(state, key):
    from ..runtime.named_joint_source_note_inputs_v1 import require_named_source_note_original_atom_v1
    note_original=require_named_source_note_original_atom_v1(state,key)
    if key in state.bodies: return state.bodies[key]
    if key == owner_grant_key(*state.work.namespace.as_tuple):
        entry = state.owner_entry
        atom = GraphAtom(key, state.work.heads[key.token][0], entry.grant, True)
        state.bodies[key] = atom
        return atom
    if NamespaceId.from_key(key) != state.work.namespace or key.type_name not in _GRAPHS and not note_original:
        raise AuthorityUnavailable('Named Joint body escaped the closed original executor graph types')
    head = state.work.heads.get(key.token)
    if head is None:
        atom = GraphAtom(key, 0, {}, False); state.bodies[key] = atom
        return atom
    if not head[1]:
        atom = GraphAtom(key, head[0], {}, False); state.bodies[key] = atom
        return atom
    locator = _precheck_column(state, 'graph_atoms','value',('token',),(key.token,),head[2])
    atom = _read_body(state, key)
    from ..runtime.domain_production_erasure_v1 import _production_value_type_registry_v1
    _production_value_type_registry_v1().validate(key, atom.value)
    history = _fixed(state.work, 'graph_history', ('event_bot','event_persona','event_id','valid'),
        'token=? AND revision=?', (key.token,head[0]))
    if history is None or history[:2]!=state.work.namespace.as_tuple or not history[3]:
        raise AuthorityUnavailable('Named Joint selected body has no actual positive producing history')
    state.selected_history.add((key.token,head[0])); state.producer_ids.add(history[2])
    return atom


class _NamedSemanticRead:
    def __init__(self, state): self.state = state
    @property
    def frame(self): return self.state.semantic_frame
    def check(self, db):
        state = _bound(db)
        if state is not self.state or not db.in_transaction:
            raise AuthorityUnavailable('Named Joint predicate lost its actual independently qualified read quantum')
        return self.frame.snapshot
    def head(self, db, ref, *, required=False):
        self.check(db)
        key = AtomKey.from_token(ref) if type(ref) is str else ref
        from ..runtime.named_joint_source_note_inputs_v1 import require_named_source_note_original_atom_v1
        require_named_source_note_original_atom_v1(self.state,key)
        if key not in self.state.bodies: raise _Needed(('atom',key))
        atom = self.state.bodies[key]
        if required and(not atom.valid or atom.revision<1):
            from ..runtime.d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1('actual_named_joint_'+key.type_name)
        return atom
    def complete_inventory(self, db, type_id):
        self.check(db)
        from ..runtime.named_joint_source_note_inputs_v1 import named_source_note_original_family_v1
        note_original=named_source_note_original_family_v1(self.state,type_id)
        if type_id not in _FAMILIES and not note_original: raise AuthorityUnavailable('Named Joint predicate requested another complete type family')
        keys = tuple(AtomKey.from_token(ref) for ref in self.state.work.heads if AtomKey.from_token(ref).type_name==type_id)
        if len(keys)>128: raise AuthorityUnavailable('Named Joint predicate exceeds its actual complete family bound')
        return tuple(self.head(db,key) for key in keys)
    def source_family(self, db, roots, *, purpose=None, audience=None, allow_corrected=False):
        self.check(db)
        purpose = purpose or self.frame.envelope.authority.purpose
        audiences = (audience,) if audience is not None else self.frame.envelope.authority.audience
        records = {}; pending = list(roots)
        while pending:
            ref = pending.pop()
            if ref in records: continue
            matches = [material for material in self.state.materials if material.selection.purpose==purpose
                and material.selection.audience in audiences and ref in material.witnesses]
            if {material.selection.audience for material in matches} != set(audiences):
                raise AuthorityUnavailable('Named Joint predicate lacks exact current ALL Source purpose/audience proof')
            witness = matches[0].witnesses[ref].require_current_v3()
            records[ref] = SimpleNamespace(**dict(witness.metadata))
            from ..memory_types import source_key
            pending.extend(source_key(*self.state.work.namespace.as_tuple,parent).token for parent in witness.metadata['parent_source_ids'])
        return records
    def original(self, ref, *, kind=None, digest=None):
        state = self.state
        original = state.original_refs.get(ref)
        if original is None: raise _Needed(('original', ref))
        if kind is not None and original.kind!=kind or digest is not None and original.original_digest!=digest:
            raise AuthorityUnavailable('Named Joint predicate changed its exact immutable original kind/digest')
        return original
    def committed_operation(self, db, operation_id):
        self.check(db)
        result = self.state.originals.get(operation_id)
        if result is None: raise _Needed(('producer',operation_id))
        receipt = result['receipt']
        return receipt.operation_digest, canonical_serialize(receipt), receipt.commit_seq
    def adopted_interpretation(self, db, ref, *, question_scope):
        from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1
        return CurrentDomainReadV1.adopted_interpretation(self,db,ref,question_scope=question_scope)


def _refresh_frame(state):
    from .current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,refresh_named_source_note_frame_v1
    if type(state.request)is NamedJointSourceNoteSelectorV1:return refresh_named_source_note_frame_v1(state)
    ns=state.work.namespace;binding=state.request.command.binding
    versions=tuple(GraphVersion(atom.key,atom.revision) for atom in state.bodies.values())
    pages=tuple(ProductionQueryCoverageV1(QueryEpoch(ns,'namespace',state.work.graph_stamp[0]),kind,
        tuple(GraphVersion(AtomKey.from_token(ref),head[0]) for ref,head in state.work.heads.items() if AtomKey.from_token(ref).type_name==kind),True,None)
        for kind in sorted(_FAMILIES))
    state.semantic_frame=SimpleNamespace(snapshot=GraphSnapshot(tuple(state.bodies.values()),(NamespaceEpoch(*ns.as_tuple,state.work.graph_stamp[0]),)),
        query_coverage=pages,owner_guard=state.owner_guard,now_utc=state.work.now_utc,
        observed_originals=tuple(state.original_refs.values()),installed_policy_refs=(),
        activation_generation=state.current_self.activation_generation,
        limits=SimpleNamespace(max_query_rows=128,max_graph_heads=1024,max_source_roots=32,max_followup_jobs=16),
        envelope=SimpleNamespace(authority=SimpleNamespace(namespace=ns,purpose='context',audience=binding.audience,
            actor=state.current_self.self_entity_ref),parent_budget_lease_ref=binding.parent_budget_lease_ref,
            deadline_utc=min(state.work.deadline_utc,state.parent_grant.valid_until_utc),
            identity=SimpleNamespace(operation_id=state.request.operation_id,phase=state.request.operation_kind),
            version_guard=SimpleNamespace(read_versions=versions,access_epoch=state.work.graph_stamp[1],delete_epoch=state.work.graph_stamp[2])))


def _prepare_original(state, ref):
    from ..runtime.domain_production_read_plans_v1 import read_current_domain_original_refs_v1
    from ..runtime.d01_production_operations_v1 import production_read_plan_v1
    readers=_NamedJointCoreRegistrationReadersV1(state)
    plan=production_read_plan_v1((),(),(),(ref,))
    with state.work.quantum_v3():
        values=read_current_domain_original_refs_v1(state.work.db,namespace=state.work.namespace,plan=plan,installed_readers=readers)
    matches=tuple(value for value in values if value.original_ref==ref)
    if len(matches)!=1:raise AuthorityUnavailable('Named Joint actual registered original is absent: '+ref)
    state.original_refs[ref]=matches[0]


def _pump(state, function):
    while True:
        _refresh_frame(state)
        if getattr(state,'frame_factory',None)is not None:state.semantic_frame=state.frame_factory()
        token=_BOUND.set(state)
        try:
            with state.work.quantum_v3(): return function(state.semantic_frame)
        except _Needed as needed:
            pending=needed.request
        except BaseException:
            raise
        finally:_BOUND.reset(token)
        kind,value=pending
        if kind=='contact_plan':
            from .named_joint_contact_plan_v1 import prepare_named_joint_contact_plan_v1
            state.contact_plan=prepare_named_joint_contact_plan_v1(state)
        elif kind=='d12_compilation':_prepare_named_joint_compilation_v1(state,value)
        elif kind=='atom':_prepare_atom(state,value)
        elif kind=='point':_prepare_point(state,value)
        elif kind=='producer':
            if value not in state.producer_ids:raise AuthorityUnavailable('Named Joint predicate selected another actual producer')
            _positive(state,value)
        elif kind=='original':
            # The existing formal resolver uses the same closed point pump.
            token=_BOUND.set(state)
            try:
                try:_prepare_original(state,value)
                except _Needed as more:
                    if more.request[0]!='point':raise
                    _prepare_point(state,more.request[1])
            finally:_BOUND.reset(token)
        else:raise AuthorityUnavailable('Named Joint predicate has no registered continuation')


def _budget(state):
    from ..runtime.issuers import BudgetLeaseGrant
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    policy=state.service.installed_bundle.installation_policy;binding=state.request.command.binding
    chain=[];current=binding.parent_budget_lease_ref
    while current is not None:
        if current in state.budget_lease_ids or len(chain)>=32:raise AuthorityUnavailable('Named Joint original budget family is cyclic or exceeds its bound')
        state.budget_lease_ids.add(current)
        lease=_fixed(state.work,'runtime_budget_leases',('lease_id','parent_id','bot_id','persona_id','currency','state'), 'lease_id=?',(current,))
        latest=_fixed(state.work,'runtime_budget_grants',('version','signature','status'),'lease_id=? ORDER BY version DESC',(current,))
        debt=_fixed(state.work,'runtime_budget_debt_blocks',('lease_id',),'lease_id=?',(current,))
        if lease is None or lease[2:4]!=state.work.namespace.as_tuple or lease[5]!='active' or latest is None or latest[2]!='active' or debt is not None:
            raise AuthorityUnavailable('Named Joint original actual budget family is absent, foreign, revoked or blocked')
        raw=_column(state,'runtime_budget_grants','grant_json',('lease_id','version'),(current,latest[0]))
        state.service.issuer._signer.verify('budget-grant.v1',canonical_serialize(raw),latest[1])
        grant=decode_typed_production_value_v1(raw,BudgetLeaseGrant)
        if (grant.lease_id,grant.version,grant.bot_id,grant.persona_id,grant.currency)!=(current,latest[0],*state.work.namespace.as_tuple,lease[4]):
            raise AuthorityUnavailable('Named Joint signed grant differs from its actual original lease')
        chain.append((lease,grant));current=lease[1]
    if not chain or chain[-1][1]!=policy.root_grant or chain[-1][0][0]!=policy.root_lease.lease_id:
        raise AuthorityUnavailable('Named Joint cannot replace the actual installed original Root family')
    parent=chain[0][1]
    if (parent.grant_id,parent.version,canonical_digest(parent))!=(binding.parent_grant_id,binding.parent_grant_version,binding.parent_grant_digest):
        raise AuthorityUnavailable('Named Joint original parent grant id/version/digest changed')
    state.parent_grant=parent;state.budget_chain=tuple(chain)
    state.valid_until=min(state.work.deadline_utc,binding.original_deadline_utc,*(grant.valid_until_utc for _,grant in chain))
    if state.work.now_utc>=state.valid_until:raise AuthorityUnavailable('Named Joint original parent/Root deadline expired')
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    if type(binding)is JointArtifactProspectiveBindingV1:
        from ..runtime.d11_artifact_draft_contract_v1 import WORK_KIND as FILE_KIND
        required={FILE_KIND}
        if binding.executor.phase_selector is not None:
            from ..model_broker.artifact_draft_v1 import WORK_KIND as MODEL_KIND
            required.add(MODEL_KIND)
    else:
        required={'message'}
    if any(not required<=set(grant.allowed_work_kinds)for _,grant in chain):
        raise AuthorityUnavailable('Named Joint original signed parent/Root never admitted its actual executor route')


def _exact_node(state, node):
    binding=state.request.command.binding
    if (node.party_scope,node.goal_ref,node.project_ref,node.recipe_ref,node.target_ref,node.success_predicate,
            node.parent_grant_ref,node.parent_grant_digest,node.original_deadline_utc,node.purpose,node.audience,
            set(node.source_refs))!=(binding.owner_ref,binding.goal_ref,binding.project_ref,binding.recipe_ref,
            binding.target_ref,binding.success_predicate,binding.parent_budget_lease_ref,binding.parent_grant_digest,
            binding.original_deadline_utc,binding.purpose,binding.audience,set(binding.source_refs)):
        raise AuthorityUnavailable('Named Joint Node/command/actual input changed exact target/recipe/predicate/Root/purpose/audience')
    recipe=state.semantic_read.head(state.work.db,node.recipe_ref,required=True)
    if recipe.revision!=node.recipe_revision:raise AuthorityUnavailable('Named Joint exact original recipe revision changed')


def qualify_current_named_joint_body_v1(state):
    from .current_named_joint_binding_v1 import NamedJointBindingCurrentV1
    from ..runtime.current_joint_window_source_read_v3 import _current_window
    from ..runtime.joint_window_management_v1 import managed_window_selector_digest_v1
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1,qualify_artifact_prospective_binding_v1
    from ..runtime.joint_contact_prospective_binding_v1 import qualify_contact_prospective_binding_v1
    from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
    work=state.work;request=state.request;binding=request.command.binding
    require_named_joint_inputs_v3(work)
    state.point_rows={};state.original_refs={};state.selected_history=set();state.producer_ids=set()
    state.producer_ids.update(getattr(state,'input_metadata_producers',()))
    state.budget_lease_ids=set();state.quote_keys=set();state.job_ids=set()
    state.d12_head_values={};state.d12_compilations={};state.d12_candidate_refs=set()
    owner=owner_grant_key(*work.namespace.as_tuple)
    state.owner_guard=ProductionOwnerGuardV1(owner.token,work.heads[owner.token][0],canonical_digest(state.owner_entry.grant),
        state.owner_entry.head.guard.authorization_head.removeprefix('sha256:'))
    state.semantic_read=_NamedSemanticRead(state)
    _prepare_atom(state,owner)
    state.contact_plan=None
    if type(binding)is JointArtifactProspectiveBindingV1:
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        task=artifact_draft_task_selector_v1(work.namespace,c02_operation_id=binding.executor.c02_operation_id,
            root_registration_ref=binding.executor.root_registration_ref)
        state.job_ids.add(AtomKey.from_token(task.cycle_job_ref).name)
    else:
        state.quote_keys.add((state.contact_metadata['birth_locator']['quote']['id'],state.contact_metadata['birth_locator']['quote']['version']))
    _budget(state)
    from .named_joint_executor_evidence_v1 import prepare_named_joint_executor_originals_v1
    executor=prepare_named_joint_executor_originals_v1(state)
    selector=managed_window_selector_digest_v1(work.namespace,request.argument.executor_kind,
        request.argument.typed_input_original_ref,request.argument.typed_input_original_digest)
    with work.quantum_v3(): inventory=state.guard_inventory.require()
    matches=tuple(row for row in inventory.rows if row['selector_digest']==selector)
    if len(matches)!=1 or matches[0]['retired']:raise AuthorityUnavailable('Named Joint exact guard is absent or authentically retired')
    row=matches[0]
    state.producer_ids.add(row['registration_operation_id'])
    def predicate(frame):
        selected=_current_window(work.db,state.semantic_read,row,preparing=True,issuer=state.service.issuer)
        window_atom,window,plan_atom,plan,node=selected
        if window_atom.revision!=request.argument.window_revision:raise AuthorityUnavailable('Named Joint current Window revision changed')
        _exact_node(state,node)
        from ..runtime.joint_window_command_v1 import read_frozen_joint_window_command_v1
        frozen_command=read_frozen_joint_window_command_v1(work.db,frame=frame,node=node,issuer=state.service.issuer)
        if frozen_command.command!=request.command:raise AuthorityUnavailable('Named Joint command differs from its actual frozen command Original')
        qualifier=qualify_artifact_prospective_binding_v1 if type(binding)is JointArtifactProspectiveBindingV1 else qualify_contact_prospective_binding_v1
        _,status=qualifier(work.db,frame=frame,binding=binding,issuer=state.service.issuer)
        if status!='current':raise AuthorityUnavailable('Named Joint original executor is no longer current')
        from ..runtime.joint_prevalidated_input_v1 import freeze_current_joint_input_v1
        frozen=freeze_current_joint_input_v1(work.db,frame=frame,
            producer_kind='register_joint_node_execution_binding_v1',request=request.command,
            readers=_NamedJointCoreRegistrationReadersV1(state))
        state.index_proof_digest=canonical_digest(frozen['indices'])
        return selected
    window_atom,window,plan_atom,plan,node=_pump(state,predicate)

    prior_head=prior_ref=prior_digest=prior_results=None
    if window.prior_window_ref is not None:
        prior=state.bodies[AtomKey.from_token(window.prior_window_ref)]
        from ..domains.d08.long_term_plan_v1 import JOINT_WINDOW_TYPE,long_term_value_from_wire_v1
        from ..runtime.d08_long_term_plan_v1 import _joint_current
        _,qualification=_pump(state,lambda frame:_joint_current(work.db,frame,
            long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,prior.value),issuer=state.service.issuer,completed=True))
        prior_head=GraphVersion(prior.key,prior.revision);prior_ref=qualification.original_ref
        prior_digest=qualification.digest;prior_results=qualification.result_versions_digest
    wp=_head_positive(state,window_atom);lp=_head_positive(state,plan_atom)
    source_versions=tuple(sorted(set(version for material in state.materials for version in material.versions),key=lambda v:v.key.token))
    versions={version.key:version.revision for version in source_versions}
    versions.update((key,atom.revision)for key,atom in state.bodies.items())
    read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
    groups=tuple((purpose,(audience,),roots)for purpose,audience,roots in state.groups)
    proof=canonical_digest(('d10.named-joint-source-proof.v1',work.graph_stamp[1:],groups,source_versions,state.index_proof_digest,
        tuple(sorted((ref,witness.canonical_semantic_digest)for material in state.materials for ref,witness in material.witnesses.items()))))
    _refresh_frame(state)
    return NamedJointBindingCurrentV1(request,work.permit,state.current_self,state.owner_guard,
        GraphVersion(window_atom.key,window_atom.revision),canonical_digest(window_atom.value),'d08-current:'+wp['original_digest'][:48],wp['original_digest'],
        GraphVersion(plan_atom.key,plan_atom.revision),canonical_digest(plan_atom.value),'d08-current:'+lp['original_digest'][:48],lp['original_digest'],
        canonical_digest(node),request.argument.typed_input_original_ref,request.argument.typed_input_original_digest,binding.digest,
        executor,state.parent_grant,binding.original_deadline_utc,state.valid_until,read_versions,state.semantic_frame.query_coverage,
        source_versions,groups,proof,state.guard_inventory.digest,work.now_utc,prior_head,prior_ref,prior_digest,prior_results)


def named_joint_adopted_operation_v1(db,namespace,operation_id):
    state=_bound(db)
    if state is None:return False,None
    from ..runtime.named_joint_source_note_inputs_v1 import admit_named_source_note_producer_v1
    if namespace!=state.work.namespace or operation_id not in state.producer_ids and not admit_named_source_note_producer_v1(state,operation_id):
        raise AuthorityUnavailable('Named Joint immutable producer is outside its actual fixed original lineage')
    value=state.originals.get(operation_id)
    if value is None:raise _Needed(('producer',operation_id))
    return True,value


def named_joint_selected_price_v1(db,selector,selected,prepared,chosen):
    state=_bound(db)
    if state is None:return False
    phase=state.request.command.binding.executor.phase_selector
    if phase!=selector or state.originals.get(selected['receipt'].operation_id) is not selected:
        raise AuthorityUnavailable('Named Joint selected price has no actual original Decision producer')
    decision=state.bodies.get(AtomKey.from_token(selector.decision_ref))
    if decision is None or chosen.future_identity.action_ref!=decision.value['chosen_action_ref'] or chosen not in prepared.candidates:
        raise AuthorityUnavailable('Named Joint selected original price differs from actual Decision/candidate')
    state.quote_keys.add((chosen.quote_ref,1))
    return True


def named_joint_source_commitment_v1(db,namespace,head,digest):
    state=_bound(db)
    if state is None:return False
    if namespace!=state.work.namespace:raise AuthorityUnavailable('Named Joint Source commitment crossed namespace')
    matches=[(material,witness)for material in state.materials for ref,witness in material.witnesses.items()
        if ref==head.key.token and material.selection.purpose=='consolidation']
    if not matches:raise AuthorityUnavailable('Named Joint amendment Source lacks its original ALL consolidation proof')
    witness=matches[0][1].require_current_v3()
    if witness.revision!=head.revision or witness.canonical_semantic_digest!=digest:
        raise AuthorityUnavailable('Named Joint amendment Source changed its exact semantic commitment')
    if {material.selection.audience for material,_ in matches}!=set(witness.metadata['audiences']):
        raise AuthorityUnavailable('Named Joint amendment Source lacks an actual original audience group')
    return True


class _NamedJointCoreRegistrationReadersV1:
    def __init__(self,state):
        if _bound(state.work.db)is not state:raise AuthorityUnavailable('Core registration readers require actual bound independent Source')
        self.state,self.issuer=state,state.service.issuer


def require_named_joint_installed_artifact_v1(binding,readers):
    if type(readers)is not _NamedJointCoreRegistrationReadersV1:return False
    state=_bound(readers.state.work.db)
    if state is not readers.state or binding!=state.request.command.binding:
        raise AuthorityUnavailable('Core build check changed its exact private source command')
    policy=state.service.installed_bundle.installation_policy;build=state.service.artifact_build
    if ((policy.namespace,policy.installation_id,policy.manifest_digest)!=(binding.namespace,binding.installation_id,binding.manifest_digest)
            or(build['algorithm_build_digest'],build['postcondition_build_digest'])!=(binding.algorithm_build_digest,binding.postcondition_build_digest)):
        raise AuthorityUnavailable('Named Joint exact installed Artifact build differs')
    return True


def named_joint_compilation_original_v1(db,namespace,compiled_digest):
    state=_bound(db)
    if state is None:return False,None
    if namespace!=state.work.namespace or not any(value.get('compiled_digest')==compiled_digest for value in state.d12_head_values.values()):
        raise AuthorityUnavailable('Named Joint Context compilation is outside actual current scheme ancestry')
    if compiled_digest not in state.d12_compilations:raise _Needed(('d12_compilation',compiled_digest))
    return True,state.d12_compilations[compiled_digest]


def _prepare_named_joint_compilation_v1(state,digest):
    from ..runtime.scheme_original_store_v1 import CompilationOriginalV1,_compiled,_compilation_binding,_sha
    ns=state.work.namespace
    header=_fixed(state.work,'graph_d12_compilation_operations_v1',
        ('operation_id','source_input_digest','budget_receipt_digest','binding_digest'),
        'bot=? AND persona=? AND compiled_digest=? ORDER BY operation_id',(*ns.as_tuple,digest))
    raw_header=_fixed(state.work,'graph_d12_compilation_originals_v1',('original_sha256',),
        'bot=? AND persona=? AND compiled_digest=?',(*ns.as_tuple,digest))
    if header is None or raw_header is None:raise AuthorityUnavailable('Named Joint Context compilation Original is absent')
    _precheck_column(state,'graph_d12_compilation_originals_v1','original_json',('bot','persona','compiled_digest'),(*ns.as_tuple,digest))
    raw=_column(state,'graph_d12_compilation_originals_v1','original_json',('bot','persona','compiled_digest'),(*ns.as_tuple,digest))
    encoded=canonical_serialize(raw)
    original=CompilationOriginalV1(header[0],_compiled(encoded),header[1],header[2])
    if _sha(encoded)!=raw_header[0]or original.compiled.namespace!=ns or original.compiled.compiled_digest!=digest or _compilation_binding(original)!=header[3]:
        raise AuthorityUnavailable('Named Joint Context compilation actual immutable bytes/binding changed')
    state.d12_compilations[digest]=original
    state.d12_candidate_refs.update(receipt.candidate_ref for receipt in original.compiled.domain_receipts if receipt.domain=='d03')
