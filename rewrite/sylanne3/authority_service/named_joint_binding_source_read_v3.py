"""Authority-private named Joint metadata, Owner17, Source ALL and selected-body read."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from hashlib import sha256
import codecs
import time

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion, GraphSnapshot, NamespaceEpoch, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.dispatch_current_inventory_v3 import _heap
from ..runtime.current_joint_window_source_read_v3 import JointWindowGuardInventoryV3
from .current_named_joint_binding_v1 import NamedJointBindingCurrentV1, NamedJointExecutorOriginalV1

_KEY = object()
_WORKS = WeakKeyDictionary()
_SELECTIONS = WeakKeyDictionary()
_METADATA_FIELDS = frozenset({'schema', 'namespace', 'source_refs', 'long_term_plan_ref', 'long_term_plan_revision',
    'plan_id', 'revision', 'current_window_ref', 'state', 'purpose', 'audience', 'window_id', 'window_index', 'prior_window_ref',
    'node_drafts', 'original_deadline_utc', 'final_joint_plan_ref', 'final_joint_plan_revision', 'final_binding_refs',
    'final_terms_original_ref', 'final_terms_original_digest', 'party_acceptance_original_refs'})


class _MetadataStreamV3:
    def __init__(self, column, ascii_codec):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.column = column
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=ascii_codec)
        self.decoder = codecs.getincrementaldecoder('utf8')('strict')
        self.semantic = sha256()
    def feed(self, fragment, emit):
        text = self.decoder.decode(fragment)
        encoded = []
        for char in text:
            n = ord(char)
            if n < 127: encoded.append(char)
            elif n <= 65535: encoded.append('\\u' + format(n, '04x'))
            else:
                n -= 65536
                encoded.append('\\u' + format(55296 + (n >> 10), '04x') + '\\u' + format(56320 + (n & 1023), '04x'))
        self.column._reserve(8 * len(text) + 8192)
        self.semantic.update(''.join(encoded).encode('ascii'))
        self.parser.feed(fragment, emit)
    def finish(self):
        self.decoder.decode(b'', final=True)
        return self.parser.finish()


class _NamedMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, state, key, revision, valid, cell):
        self.state, self.graph_key, self.revision, self.valid = state, key, revision, valid
        super().__init__(state.work, table='graph_atoms', column='value', key_columns=('token',), key=(key.token,), cell_id=cell)
        self.stream = _MetadataStreamV3(self, self.cell.header[0] == 'canonical-json.ascii.v1')
        self.parser = self.stream
    def _emit(self, event):
        if not event.path or event.path[0] in _METADATA_FIELDS:
            super()._emit(event)
    def finish_metadata_v3(self):
        require_named_joint_authority_work_v3(self.state.work)
        raw = self.require_v3(self.state.work)
        self.state.metadata[self.graph_key.token] = (self.revision, self.valid, self.stream.semantic.hexdigest(), raw)


class _NamedSelectionV3:
    def __init__(self, state, roots, purpose, audience):
        self.work, self.roots, self.purpose, self.audience = state.work, roots, purpose, audience
        self.root, self.attention, self.maximum_ancestors = roots[0], None, 256
        _SELECTIONS[self] = (state.work, roots, purpose, audience, state.work.operation, state.work.scope)
    def require_v3(self, work):
        state = require_named_joint_authority_work_v3(work)
        if (_SELECTIONS.get(self) != (work, self.roots, self.purpose, self.audience, work.operation, work.scope)
                or (self.purpose, self.audience, self.roots) not in state.groups):
            raise AuthorityUnavailable('Named Joint Source selection left its fixed actual group')
        return self


class NamedJointAuthorityInputsV3:
    def __init__(self, key, work, service):
        if key is not _KEY:
            raise TypeError('Named Joint inputs need their private Authority factory')
        self.work, self.service = work, service
        self.request = work.request
        self.current_self = None
        self.owner_entry = None
        self.metadata_only = True
        self.metadata, self.bodies, self.originals = {}, {}, {}
        self.materials, self.groups, self.roots = [], (), ()
        self.guard_inventory = None
        self.observed = None
        self.complete = False
        self.closed = False
        self.initial_monotonic_deadline = time.monotonic() + max(0.0, work.deadline_utc - work.now_utc)
        _WORKS[work] = self
    def release_v3(self):
        if self.closed: return
        self.work.release_v3()
        self.closed = True
        _WORKS.pop(self.work, None)
        for material in self.materials: _SELECTIONS.pop(material.selection, None)
        self.metadata.clear(); self.bodies.clear(); self.originals.clear(); self.materials.clear()
    def current(self):
        if not self.complete or self.closed or self.observed is None:
            raise AuthorityUnavailable('Named Joint current needs its complete actual independent READ')
        require_named_joint_authority_work_v3(self.work)
        for material in self.materials:
            material.selection.require_v3(self.work)
            if material.phase != 'cell' or material.pending:
                raise AuthorityUnavailable('Named Joint Source ALL boundary changed')
            for witness in material.witnesses.values(): witness.require_current_v3()
        self.work._check_permission_v3()
        with self.work.quantum_v3() as meter: self.work.require_current(meter=meter)
        return self.observed


def named_joint_authority_work_v3(work):
    return _WORKS.get(work)


def require_named_joint_inputs_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    if type(work)is AuthorityGraphReadWorkV3:
        return require_named_joint_authority_work_v3(work)
    from ..runtime.named_joint_source_work_v3 import require_named_joint_host_bridge_v3
    return require_named_joint_host_bridge_v3(work)


def require_named_joint_authority_work_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from .current_named_joint_binding_v1 import InstalledCurrentNamedJointBindingV1
    state = _WORKS.get(work)
    if (type(work) is not AuthorityGraphReadWorkV3 or state is None or state.closed
            or state.work is not work or type(state.service) is not InstalledCurrentNamedJointBindingV1
            or work.service is not state.service or work.controller.verifier is not state.service
            or work.controller.kind != 'named_joint' or time.monotonic() >= state.initial_monotonic_deadline):
        raise AuthorityUnavailable('Named Joint cannot borrow another Authority Source Work')
    work._actual()
    return state


def named_joint_namespace_metadata_column_v3(work, key, revision, valid, cell):
    state = require_named_joint_authority_work_v3(work)
    if key.type_name not in {'d08.joint_window.v1', 'd08.long_term_plan.v1'}:
        return None
    return _NamedMetadataColumnV3(state, key, revision, valid, cell)


def _fixed(work, table, columns, where, parameters):
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    with work.quantum_v3() as meter:
        return _runtime_bounded_fixed_row_v3(work.db, meter, table, columns, where, parameters)


def _run(work, column):
    while not column.complete:
        with work.quantum_v3() as meter:
            column.advance(meter)
    return column.require_v3(work)


def _column(state, table, column, key_columns, key, cell=None):
    if state.metadata_only:
        raise AuthorityUnavailable('Named Joint protected body requires current Owner and every Source group EOF')
    reader = DispatchOriginalJSONReadV3(state.work, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell)
    if reader.cell is not None:
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        reader.parser = C09CanonicalJSONStreamV2(ensure_ascii=reader.cell.header[0] == 'canonical-json.ascii.v1')
    return _run(state.work, reader)


def _source_refs(value):
    from .habit_authority_source_read_v3 import _source_refs_v3
    return _source_refs_v3(value)


def _positive(state, operation_id, *, member=None, kind=None):
    from ..runtime.domain_production_originals_v1 import _receipt
    work = state.work
    key = (*work.namespace.as_tuple, operation_id)
    row = _fixed(work, 'graph_domain_production_originals_v1',
        ('domain', 'operation_kind', 'request_digest', 'original_digest', 'bundle_digest', 'receipt_digest'),
        'bot=? AND persona=? AND operation_id=?', key)
    table = 'graph_domain_production_originals_v1'
    physical = None
    if row is None:
        from ..runtime.domain_production_originals_v1 import PHYSICAL_TABLE
        physical = _fixed(work, PHYSICAL_TABLE,
            ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest','original_payload_cell_id'),
            'bot=? AND persona=? AND operation_id=?', key)
        if physical is not None:
            row, table = physical[:6], PHYSICAL_TABLE
    if row is None or kind is not None and row[1] != kind:
        raise AuthorityUnavailable('Named Joint actual immutable producer is absent')
    from .named_joint_binding_body_v1 import _precheck_column
    _precheck_column(state, table, 'original_payload_json' if physical is None else 'original_payload_cell_id',
        ('bot','persona','operation_id'),key,None if physical is None else physical[6])
    raw = _column(state, table, 'original_payload_json' if physical is None else 'original_payload_cell_id',
        ('bot', 'persona', 'operation_id'), key, None if physical is None else physical[6])
    receipt_raw = _column(state, table, 'receipt_json', ('bot', 'persona', 'operation_id'), key)
    receipt = _receipt(receipt_raw)
    actual = _fixed(work, 'graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'),
        'bot=? AND persona=? AND operation_id=?', key)
    if (canonical_digest(raw) != row[3] or raw['identity']['operation_id'] != operation_id
            or raw['identity']['phase'] != row[1] or raw['namespace'] != {'bot_id': work.namespace.bot_id, 'persona_id': work.namespace.persona_id}
            or receipt.status != 'committed' or canonical_digest(receipt) != row[5]
            or receipt.operation_id != operation_id or receipt.operation_digest != row[4]
            or actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq)
            or not _source_refs(raw) <= set(state.closure_refs)):
        raise AuthorityUnavailable('Named Joint producer lost its canonical phase/actual positive W01/qualified Source closure')
    if member is not None:
        if GraphVersion(member.key, member.revision) not in receipt.write_versions:
            raise AuthorityUnavailable('Named Joint selected Head is not an actual COMMIT member')
        writes = tuple(item for item in raw['writes'] if item['key'] == member.key.token)
        if len(writes) != 1 or writes[0]['value'] != member.value:
            raise AuthorityUnavailable('Named Joint selected body changed its actual W01 write')
    result = {'domain': row[0], 'operation_kind': row[1], 'original_digest': row[3], 'payload': raw, 'receipt': receipt,
        'read_versions': receipt.read_versions, 'request_digest': row[2]}
    state.originals[operation_id] = result
    from ..runtime.named_joint_source_note_inputs_v1 import seed_named_source_note_original_refs_v1
    seed_named_source_note_original_refs_v1(state,result)
    if row[1] in {'select_personal_step_v2','select_current_conditioned_personal_step_v1'}:
        state.producer_ids.add(raw['provenance']['prepared_candidates_operation_id'])
    return result


def _head_positive(state, atom, kind=None):
    row = _fixed(state.work, 'graph_history', ('event_bot', 'event_persona', 'event_id', 'valid'),
        'token=? AND revision=?', (atom.key.token, atom.revision))
    if row is None or tuple(row[:2]) != state.work.namespace.as_tuple or row[3] != 1:
        raise AuthorityUnavailable('Named Joint actual current Head producing history is absent')
    return _positive(state, row[2], member=atom, kind=kind)


def _life(state, role, ref, kind):
    from ..runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND
    from .current_named_joint_binding_v1 import NamedJointExecutorOriginalV1
    work = state.work
    row = _fixed(work, TABLE, ('producing_operation_id', 'payload_digest', 'signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?', (*work.namespace.as_tuple, kind, ref))
    if row is None:
        raise AuthorityUnavailable('Named Joint actual signed executor original is absent: ' + role)
    raw = _column(state, TABLE, 'payload_json', ('bot', 'persona', 'kind', 'original_ref'), (*work.namespace.as_tuple, kind, ref))
    digest = canonical_digest(raw)
    if digest != row[1] or not _source_refs(raw) <= set(state.closure_refs):
        raise AuthorityUnavailable('Named Joint original changed its exact digest or Source closure')
    state.service.issuer._signer.verify(SIGN_KIND, canonical_serialize((work.namespace, kind, ref, digest)), row[2])
    actual = _positive(state, row[0])
    proof = NamedJointExecutorOriginalV1(role, ref, digest, row[0], actual['original_digest'], canonical_digest(actual['receipt']))
    return raw, proof


def _read_body(state, key):
    work = state.work
    head = work.heads.get(key.token)
    if head is None or head[1] != 1:
        raise AuthorityUnavailable('Named Joint exact current body is absent')
    raw = _column(state, 'graph_atoms', 'value', ('token',), (key.token,), head[2])
    if not _source_refs(raw) <= set(state.closure_refs):
        raise AuthorityUnavailable('Named Joint selected body introduced an unqualified Source')
    state.bodies[key] = GraphAtom(key, head[0], raw, True)
    return state.bodies[key]


def _current_self(state):
    from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
    service, work = state.service, state.work
    s = service.self_identity
    request = SelfIdentityCurrentRequestV1(work.permit.authority_id, s._fences.namespace, work.namespace,
        s._installation_id, s._manifest_digest, work.request.operation_id, work.permit)
    value = s.current(credential=work.credential, subject=work.subject, request=request)
    if value is None or value.graph_epoch != work.namespace_reader.query.revision:
        raise AuthorityUnavailable('Named Joint metadata EOF differs from its actual current Self/Graph')
    state.current_self = value
    return value



class _InputSourceMetadataColumnV3(DispatchOriginalJSONReadV3):
    def _emit(self,event):
        source_fields={'source_refs','source_ref','input_source_ref','body_source_ref','creation_evidence_refs','reason_refs'}
        control_fields={'prepared_candidates_operation_id'}
        if event.kind in {'object_start','array_start'} or any(part in source_fields or part in control_fields or type(part)is str and(part.endswith('_source_head')or part.endswith('_source_ref'))for part in event.path):
            super()._emit(event)


def _named_input_source_metadata_v3(state):
    """Fixed original executor control locators, complete EOF before any Body."""
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    binding=state.request.command.binding
    if type(binding)is not JointArtifactProspectiveBindingV1:return ()
    from .named_joint_binding_body_v1 import _FAMILIES
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    task=artifact_draft_task_selector_v1(state.work.namespace,c02_operation_id=binding.executor.c02_operation_id,root_registration_ref=binding.executor.root_registration_ref)
    selected={binding.goal_ref,binding.project_ref,binding.recipe_ref,binding.target_entity_ref,binding.role_ref,task.cycle_job_ref}
    phase=binding.executor.phase_selector
    if phase is not None:selected.update((phase.decision_ref,phase.plan_ref))
    selected.update(ref for ref in state.work.heads if AtomKey.from_token(ref).type_name in _FAMILIES)
    context=set();other=set();producers=set();seen=set()
    context_types={'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule','d07.current_interpretation.v1','d07.attention_ticket.v1','d07.focus.v1','d07.concern_round.v1'}
    def metadata(table,name,keys,key,cell=None):
        column=_InputSourceMetadataColumnV3(state.work,table=table,column=name,key_columns=keys,key=key,cell_id=cell)
        column.stream=_MetadataStreamV3(column,column.cell is None or column.cell.header[0]=='canonical-json.ascii.v1')
        column.parser=column.stream
        raw=_run(state.work,column)
        return raw,column.stream.semantic.hexdigest()
    for ref in sorted(selected):
        key=AtomKey.from_token(ref);head=state.work.heads.get(ref)
        if head is None or not head[1]:continue
        raw,digest=metadata('graph_atoms','value',('token',),(ref,),head[2])
        (context if key.type_name in context_types else other).update(_source_refs(raw))
        if phase is not None and ref in {phase.decision_ref,phase.plan_ref}:
            row=_fixed(state.work,'graph_history',('event_bot','event_persona','event_id','valid'),'token=? AND revision=?',(ref,head[0]))
            if row is None or row[:2]!=state.work.namespace.as_tuple or row[3]!=1:raise AuthorityUnavailable('Named Joint phase locator lacks its actual positive history')
            producers.add(row[2])
    life=[('artifact_task_objective',binding.objective_ref),('artifact_task_scope',binding.task_scope_ref),('draft_root_capability',binding.executor.root_registration_ref)]
    if phase is not None and phase.prev_phase_original_ref is not None:life.append(('c4_phase_verified',phase.prev_phase_original_ref))
    from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
    for kind,ref in life:
        key=(*state.work.namespace.as_tuple,kind,ref)
        header=_fixed(state.work,TABLE,('producing_operation_id','payload_digest','signature'),'bot=? AND persona=? AND kind=? AND original_ref=?',key)
        if header is None:raise AuthorityUnavailable('Named Joint actual executor metadata original is absent')
        raw,digest=metadata(TABLE,'payload_json',('bot','persona','kind','original_ref'),key)
        if digest!=header[1]:raise AuthorityUnavailable('Named Joint executor metadata lost its canonical full EOF digest')
        state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((state.work.namespace,kind,ref,digest)),header[2])
        other.update(_source_refs(raw));producers.add(header[0])
    while producers-seen:
        operation=min(producers-seen);seen.add(operation);key=(*state.work.namespace.as_tuple,operation)
        table='graph_domain_production_originals_v1';name='original_payload_json';cell=None
        header=_fixed(state.work,table,('original_digest',),'bot=? AND persona=? AND operation_id=?',key)
        if header is None:
            from ..runtime.domain_production_originals_v1 import PHYSICAL_TABLE
            table=PHYSICAL_TABLE;name='original_payload_cell_id'
            header=_fixed(state.work,table,('original_digest','original_payload_cell_id'),'bot=? AND persona=? AND operation_id=?',key)
            if header is not None:cell=header[1]
        if header is None:raise AuthorityUnavailable('Named Joint fixed producing Original metadata is absent')
        raw,digest=metadata(table,name,('bot','persona','operation_id'),key,cell)
        if digest!=header[0]:raise AuthorityUnavailable('Named Joint immutable producer metadata changed its complete EOF')
        other.update(_source_refs(raw))
        pointer=raw.get('provenance',{}).get('prepared_candidates_operation_id')
        if pointer is not None:producers.add(pointer)
    # The original Artifact binding remains consolidation. Independent role and
    # entity controls retain context; they are never merged into binding roots.
    groups=[]
    if context:groups.append(('context',binding.audience,tuple(sorted(context))))
    other=(other-context)|set(binding.source_refs)
    if other:groups.append(('consolidation',binding.audience,tuple(sorted(other))))
    state.input_metadata_producers=tuple(sorted(seen))
    return tuple(groups)


def _metadata_groups(state):
    from .current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,note_metadata_groups_v1
    if type(state.request)is NamedJointSourceNoteSelectorV1:return note_metadata_groups_v1(state)
    work, command = state.work, state.request.command
    binding = command.binding
    window_entry = state.metadata.get(state.request.argument.window_ref)
    if window_entry is None or window_entry[0] != state.request.argument.window_revision or not window_entry[1]:
        raise AuthorityUnavailable('Named Joint actual current Window metadata differs')
    window = window_entry[3]
    plan_entry = state.metadata.get(window['long_term_plan_ref'])
    if plan_entry is None or not plan_entry[1]:
        raise AuthorityUnavailable('Named Joint actual LongPlan metadata absent')
    plan = plan_entry[3]
    node = next((n for n in window['node_drafts'] if n['node_id'] == state.request.argument.node_id), None)
    if node is None:
        raise AuthorityUnavailable('Named Joint actual Window node metadata absent')
    groups = {}
    def group(roots, purpose, audiences):
        for audience in audiences:
            groups.setdefault((purpose, audience), set()).update(roots)
    group(window['source_refs'], 'context', binding.audience)
    group(plan['source_refs'], plan['purpose'], plan['audience'])
    group(node['source_refs'], node['purpose'], node['audience'])
    # Contact's exact independent original purpose groups are resolved by its
    # signed prospective metadata before source material is opened.
    if state.request.argument.executor_kind == 'contact':
        from .named_joint_contact_metadata_v1 import read_named_joint_contact_metadata_v1
        contact = read_named_joint_contact_metadata_v1(state)
        state.contact_metadata = contact
        for ref, purposes in contact['source_purpose_groups']:
            for purpose in purposes: group((ref,), purpose, binding.audience)
    else:
        group(binding.source_refs, binding.purpose, binding.audience)
        for purpose,audiences,roots in _named_input_source_metadata_v3(state):group(roots,purpose,audiences)
    prior = window.get('prior_window_ref')
    if prior is not None:
        metadata = state.metadata.get(prior)
        if metadata is None or not metadata[1]:
            raise AuthorityUnavailable('Named Joint actual prior Window metadata absent')
        group(metadata[3]['source_refs'], 'context', binding.audience)
    result = tuple((purpose, audience, tuple(sorted(roots))) for (purpose, audience), roots in sorted(groups.items()))
    if any(not roots for _, _, roots in result):
        raise AuthorityUnavailable('Named Joint actual complete Source root group absent')
    state.window_metadata, state.plan_metadata, state.node_metadata = window, plan, node
    return result


def prepare_current_named_joint_inputs_v3(service, *, credential, subject, permit, request):
    from .current_authority_graph_read_v3 import (begin_authority_graph_read_work_v3, _AuthorityNamespaceReadV3,
        AuthorityGraphProjectionV3, _AuthoritySourceMaterialReadV3, _ISSUER)
    reading = service.clock()
    now = reading.utc_seconds + reading.utc_error_seconds
    deadline = min(request.command.binding.original_deadline_utc, service.installed_bundle.installation_policy.root_grant.valid_until_utc)
    work = begin_authority_graph_read_work_v3(service, credential=credential, subject=subject, permit=permit,
        namespace=request.namespace, request=request, parent_original_id=request.argument.typed_input_original_ref,
        now_utc=now, deadline_utc=deadline)
    state = NamedJointAuthorityInputsV3(_KEY, work, service)
    try:
        while not work.catalogue_reader.complete:
            with work.quantum_v3() as meter: work.catalogue_reader.advance_v3(meter)
        work.namespace_reader = _AuthorityNamespaceReadV3(work, catalogue=work.catalogue_reader.rows, catalogue_hash=work.catalogue_reader.catalogue_hash)
        while not work.namespace_reader.graph_eof:
            with work.quantum_v3() as meter: work.namespace_reader.advance_v3(meter)
        work.projection = AuthorityGraphProjectionV3(_ISSUER, work)
        from ..runtime.current_joint_window_source_read_v3 import create_joint_guard_inventory_for_work_v3
        state.guard_inventory = create_joint_guard_inventory_for_work_v3(work, service.issuer)
        while not state.guard_inventory.complete:
            with work.quantum_v3() as meter: state.guard_inventory.advance(meter)
        state.groups = _metadata_groups(state)
        _current_self(state)
        from .owner_location_read_v3 import prepare_owner_location_for_named_joint_graph_work_v3
        state.owner_entry = prepare_owner_location_for_named_joint_graph_work_v3(work)
        grant = state.owner_entry.grant
        if 'workbench.create' not in grant['capabilities'] or any(purpose not in grant['purposes'] or audience not in grant['audiences'] for purpose, audience, _ in state.groups):
            raise AuthorityUnavailable('Named Joint actual Owner does not cover the exact original purposes/audiences')
        state.roots = tuple(sorted({ref for _, _, roots in state.groups for ref in roots}))
        for purpose, audience, roots in state.groups:
            material = _AuthoritySourceMaterialReadV3(work, _NamedSelectionV3(state, roots, purpose, audience))
            state.materials.append(material)
            while material.phase == 'rights':
                with work.quantum_v3() as meter: material.advance_v3(meter)
        if any(material.phase != 'cell' or material.pending for material in state.materials):
            raise AuthorityUnavailable('Named Joint requires actual completed ALL for every Source group first')
        state.closure_refs = tuple(sorted({ref for material in state.materials for ref in material.witnesses}))
        state.metadata_only = False
        from .named_joint_binding_body_v1 import qualify_current_named_joint_body_v1
        state.observed = qualify_current_named_joint_body_v1(state)
        state.complete = True
        return state
    except BaseException:
        state.release_v3()
        raise
