"""Private Source ALL for the closed installed foreground command contract.

This adapter retains its own actual Borrowed Work, Owner EOF, locator/producer
EOF and Source capability. Core read_versions are version bounds only.
"""
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from weakref import WeakKeyDictionary, WeakSet
import time, json
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, GraphAtom, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from .source_correction_read_v3 import _heap
from .foreground_command_contract_v3 import foreground_command_source_spec_v3, foreground_command_evidence_locators_v3
_KEY = object()
_STATES = WeakKeyDictionary()
_CAPABILITIES = WeakKeyDictionary()
_C1_BINDINGS = WeakKeyDictionary()
_OUTPUTS = WeakKeyDictionary()
_FRAMES = {}

def _identity_v3(r):
    return (r.graph, r.runtime, r.operation, r.issued, r.issued.scope, r.selector, r.operation_kind, r.request, r.request_digest, r.namespace, r.graph_stamp, r.expected_rights, r.evidence, r.initial_now_utc, r.deadline_utc)

def register_foreground_command_constructor_v3(reader):
    spec = foreground_command_source_spec_v3(reader.operation_kind, reader.request, reader.selector)
    if spec is None:
        return False
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3, _READERS
    if type(reader) is not BorrowedMethodLearningReadV3 or reader not in _READERS or reader.work is not None or reader.operation.closed or (reader.issued.scope.operation != 'write') or (reader in _STATES):
        raise AuthorityUnavailable('Foreground Source needs its actual original private Borrowed constructor')
    _STATES[reader] = _ForegroundCommandStateV3(_KEY, reader, spec)
    reader.preplan_families = reader.projection_types = frozenset()
    return True

class _ForegroundCommandStateV3:

    def __init__(self, key, reader, spec):
        if key is not _KEY:
            raise AuthorityUnavailable('Actual private foreground Source factory required')
        self.reader, self.spec = (reader, spec)
        self.identity = _identity_v3(reader)
        self.work = None
        self.initial_monotonic = time.monotonic()
        self.monotonic_deadline = self.initial_monotonic + max(0.0, reader.deadline_utc - reader.initial_now_utc)
        self.deadline_utc = reader.deadline_utc
        self.original_parent_budget = reader.parent_budget_lease_ref
        self.original_purposes = (reader.purpose,)
        self.original_audiences = reader.audiences
        self.original_root_purposes = {}
        self.original_reserved = 0
        self.locator_versions, self.locator_roots = foreground_command_evidence_locators_v3(reader, spec)
        self.owner_entry = None
        self.metadata = None
        self.original_budget = None
        self.rights = None
        self.capability = None
        self.catalogue = None
        self.catalogue_merged = False
        self.preparation = None
        self.phase = 'owner'
        self.plan = None
        self.columns = WeakSet()
        self.producer_versions = {}
        self.expected_source_versions_v3 = {}
        self.registered_input_descriptors=()
        if reader.operation_kind=='evaluate_values':
            self.registered_input_descriptors=(
                ('graph_d01_production_inputs_v1','values_candidates',reader.request.candidate_set_ref,'input:freeze_values','candidate_set_ref'),
                ('graph_d01_production_inputs_v1','values_context',reader.request.context_ref,'input:freeze_values','context_ref'))
        self.registered_input_tasks=[];self.registered_input_index=0
        self.responsibility = None
        self.initial_monotonic_deadline = self.monotonic_deadline
        self.original_audiences = tuple(reader.audiences)
        self.c1 = None
        self.typed_metadata = {}

    @property
    def db(self):
        return self.reader.db

    @property
    def namespace(self):
        return self.reader.namespace

    @property
    def operation(self):
        return self.reader.operation

    @property
    def graph_stamp(self):
        return self.reader.graph_stamp

    @property
    def graph(self):
        return self.reader.graph

    @property
    def selection_digest(self):
        return self.reader.selection_digest

    @property
    def request(self):
        return self.reader.selector

    @property
    def scope(self):
        return self.reader.issued.scope

    @property
    def original_metadata(self):
        return self.metadata

    def require_current(self, *, meter=None):
        self.require_v3()
        self.reader.require_current(meter=meter)
        return self

    def require_v3(self):
        from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3, _READERS, _require_borrowed_issuance_v3
        r = self.reader
        if type(r) is not BorrowedMethodLearningReadV3 or r not in _READERS or _STATES.get(r) is not self or (self.identity != _identity_v3(r)) or r.operation.closed or (r.work is None) or (r.work.state is not r) or (r.work.operation is not r.operation) or (r.work.coordinator is not r.graph) or (r.work.kind != 'current_method_learning_read_v3') or (_require_borrowed_issuance_v3(r.issued, r.graph) != r.evidence) or (foreground_command_source_spec_v3(r.operation_kind, r.request, r.selector) != self.spec) or (time.monotonic() >= self.monotonic_deadline):
            raise AuthorityUnavailable('Foreground Source changed its actual Work/WRITE/typed command/issuance/deadline')
        if self.work is None:
            self.work = r.work
        elif self.work is not r.work:
            raise AuthorityUnavailable('Foreground Source cannot move between retained Works')
        return self

    @property
    def purpose(self):return self.reader.purpose
    @property
    def audiences(self):return self.reader.audiences
    @property
    def source_complete(self):return self.phase=='qualified'
    @property
    def current_roots(self):return tuple(sorted(self.metadata.roots))
    def require_current_v3(self,meter):return self.require_current(meter=meter)

def _state_v3(reader):
    state = _STATES.get(reader)
    if state is None:
        raise AuthorityUnavailable('No actual private foreground Source state')
    return state.require_v3()

def _require_state_v3(state):
    if type(state) is not _ForegroundCommandStateV3 or _state_v3(state.reader) is not state:
        raise AuthorityUnavailable('Foreground metadata has another actual private state')
    return state

def is_foreground_command_source_reader_v3(reader):
    if reader not in _STATES:
        return False
    _state_v3(reader)
    return True

def require_foreground_command_owner_reader_v3(reader):
    return _state_v3(reader)

def _clock_upper_v3(state):
    r = state.require_v3().reader
    from .first_ingress_v2 import trusted_upper
    port = r.graph._GraphCoordinator__content_fence_v2
    return trusted_upper(port.read_ingress_clock(r.graph._GraphCoordinator__scene_clock_policy))

def _reserve(state, value, extra=0):
    metadata = state.metadata
    size = _heap((metadata.rows, metadata.heads, metadata.families, metadata.roots, metadata.pending, metadata.originals, metadata.history_heads, metadata.historical_pending, metadata.catalogue_history_pending, metadata.required_originals, metadata.required_matches, value)) + extra + 65536
    if size > state.original_reserved:
        state.operation.retain(size - state.original_reserved)
        state.original_reserved = size
_LOCATOR_FIELDS = frozenset({'schema', 'namespace', 'kind', 'original_ref', 'original_digest', 'digest', 'ref', 'key', 'revision', 'source_refs', 'source_ref', 'input_source_ref', 'body_source_ref', 'creation_evidence_refs', 'reason_refs', 'read_versions', 'query_coverage', 'type_id', 'future_decision_ref', 'prepared_candidates_operation_id', 'objective_ref', 'objective_digest', 'goal_ref', 'project_ref', 'recipe_ref', 'target_entity_ref', 'role_binding_ref', 'plan_ref', 'plan_revision', 'plan_digest', 'decision_ref', 'decision_revision', 'decision_digest', 'method_ref', 'draft_root_registration_ref', 'root_registration_ref', 'c02_operation_id', 'operation_id', 'phase', 'parent_budget_lease_ref', 'parent_grant_ref', 'audiences', 'purpose', 'original_deadline_utc', 'valid_until_utc', 'authorization_original_ref', 'authorization_original_digest', 'cause', 'heads', 'owner_operation_id', 'extent_original_ref', 'postcondition_policy_ref', 'approval_original_ref', 'contract_ref', 'preparation_parent_original_ref', 'prev_phase_original_ref', 'quote_ref', 'quote_digest', 'quote_id', 'quote_version', 'job_id', 'call_id', 'effect_id', 'reservation_operation_id', 'fact_versions', 'protocol_ref', 'gp1_interpretation_ref', 'deadline_ref', 'counterparty_ref', 'subject_ref', 'entity_id', 'target_ref', 'source_head', 'plan_head', 'goal_head', 'body_policy_id', 'body_policy_version', 'effect_policy_ref', 'c1_intent_ref', 'source_revision', 'source_digest', 'c02_bundle_digest', 'c02_receipt_digest', 'c02_commit_seq', 'installation_id', 'manifest_digest', 'foreground_responsibility', 'selector', 'content_selector', 'condition_id', 'observation_basis_ref', 'basis_scope_digest', 'original_deadline_utc', 'registration_operation_id', 'task_source_head', 'task_root_source_head', 'content_source_head', 'candidate_set_ref', 'context_ref', 'candidate_heads', 'context_heads', 'condition_heads', 'condition_query_epoch', 'condition_source_refs', 'plan_original_ref', 'activity_scope_ref', 'activity_outcome_ref', 'body_preparation_ref', 'admission_ref', 'binding', 'project', 'recipe', 'action_intent', 'input_source', 'input_access', 'start_original_ref', 'terminal_original_ref', 'artifact_ref', 'paid_cost_refs'})


_CONTEXT_TYPES = frozenset({'d03.role_binding', 'd03.entity_anchor', 'd03.account_binding', 'd05.boundary_rule', 'd05.relationship_projection', 'd07.current_interpretation.v1', 'd07.focus.v1', 'd07.attention_ticket.v1', 'd07.concern_round.v1'})

class _CommandMetadataColumnV3(DispatchOriginalJSONReadV3):

    def __init__(self, work, *, table, column, key_columns, key, fields=None, cell_id=None):
        _require_state_v3(work)
        self.fields = fields
        super().__init__(work, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell_id)
        if self.cell is not None:
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')

    def _emit(self, event):
        if self.fields is None or not event.path or event.path[0] in self.fields:
            super()._emit(event)

@dataclass(frozen=True, slots=True)
class _CommandSourceLeafV3:
    key: AtomKey
    revision: int
    valid: bool
    metadata: object
    cell_id: str
    sha256: str
    header: tuple

class _CommandSourceColumnV3:

    def __init__(self, work, key):
        self.work, self.key = (work, key)
        self.phase = 'head'
        self.cell = self.parser = None
        self.fragment = b''
        self.offset = 0
        self.complete = False

    def advance(self, meter):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        work = self.work
        work.require_current(meter=meter)
        if self.phase == 'head':
            row = meter.read_fixed_row(work.db, 'graph_atoms', ('revision', 'valid', 'value_cell_id'), 'bot=? AND persona=? AND token=?', (*work.namespace.as_tuple, self.key.token))
            if row is None or row[0] < 1 or row[1] != 1 or (row[2] is None):
                raise AuthorityUnavailable('Foreground command Source current metadata is absent')
            self.head = row
            self.cell = begin_runtime_cell_read_v3(work.db, row[2], erasure_owner_ref=self.key.token)
            if self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
                raise AuthorityUnavailable('Foreground command Source has an unregistered physical codec')
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')
            self.phase = 'body'
            return False
        if self.offset < len(self.fragment):
            end = min(self.offset + 1024, len(self.fragment))
            _reserve(work, (work.original_metadata, self.parser._source_metadata), 65536)
            self.parser.feed(self.fragment[self.offset:end], lambda event: None)
            self.offset = end
            return False
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.offset = (fragment, 0)
            return False
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
            raise AuthorityUnavailable('Foreground command Source metadata did not reach actual canonical EOF')
        metadata = MappingProxyType({name: tuple(value) if type(value) is list else value for name, value in self.parser._source_metadata.items()})
        if metadata['source_id'] != self.key.owner.subject:
            raise AuthorityUnavailable('Foreground command Source metadata key differs')
        self.leaf = _CommandSourceLeafV3(self.key, self.head[0], True, metadata, self.head[2], digest, tuple(self.cell.header))
        self.complete = True
        self.fragment = b''
        self.parser = self.cell = None
        return True

class _CommandBudgetMetadataV3:

    def __init__(self, work):
        self.work = work
        self.current = work.original_parent_budget
        self.seen = set()
        self.leases = {}
        self.grants = {}
        self.column = None
        self.values = {}
        self.columns = []
        self.complete = False

    def advance(self, meter):
        from .budget import BudgetLease
        from .issuers import _decode_grant
        work = self.work
        work.require_current(meter=meter)
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            value = self.column.require_v3(work)
            if self.kind == 'grant':
                encoded = canonical_serialize(value)
                work.reader.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1', encoded, self.signature)
                grant = _decode_grant(encoded)
                if grant.lease_id != self.current or (grant.bot_id, grant.persona_id) != work.namespace.as_tuple or grant.version != self.grant_version:
                    raise AuthorityUnavailable('Foreground command original signed budget metadata differs')
                deadline = min(work.deadline_utc, grant.valid_until_utc)
                if _clock_upper_v3(work) >= deadline:
                    raise AuthorityUnavailable('Foreground command original budget deadline expired before body qualification')
                work.deadline_utc = float(deadline)
                self.grants[self.current] = grant
            else:
                self.values[self.kind] = value
            self.column = None
            return
        if self.columns:
            name = self.columns.pop()
            self.kind = name
            self.column = _CommandMetadataColumnV3(work, table='runtime_budget_leases', column=name, key_columns=('lease_id',), key=(self.current,))
            return
        if self.values:
            row = self.lease_head
            lease = BudgetLease(self.current, row[0], row[1], row[2], row[3], self.values['limits_json'], self.values['used_json'], self.values['reserved_json'], self.values['unconfirmed_json'], row[4], row[5])
            self.leases[self.current] = lease
            self.values = {}
            if lease.parent_id is None:
                self.complete = True
            else:
                self.current = lease.parent_id
            return
        if self.current in self.seen:
            raise AuthorityUnavailable('Foreground command original budget ancestry contains a cycle')
        self.seen.add(self.current)
        row = meter.read_fixed_row(work.db, 'runtime_budget_leases', ('parent_id', 'bot_id', 'persona_id', 'currency', 'version', 'state'), 'lease_id=?', (self.current,))
        debt = meter.read_fixed_row(work.db, 'runtime_budget_debt_blocks', ('lease_id',), 'lease_id=?', (self.current,))
        if row is None or row[1:3] != work.namespace.as_tuple or row[5] != 'active' or (debt is not None):
            raise AuthorityUnavailable('Foreground command original budget ancestry is unavailable or has unresolved debt')
        head = meter.read_fixed_row(work.db, 'runtime_budget_grants', ('version', 'signature', 'status'), 'lease_id=? ORDER BY version DESC', (self.current,))
        if head is None or head[2] != 'active':
            raise AuthorityUnavailable('Foreground command original signed budget grant is unavailable')
        self.lease_head = row
        self.grant_version, self.signature = head[:2]
        self.columns = ['limits_json', 'used_json', 'reserved_json', 'unconfirmed_json']
        self.kind = 'grant'
        self.column = _CommandMetadataColumnV3(work, table='runtime_budget_grants', column='grant_json', key_columns=('lease_id', 'version'), key=(self.current, head[0]))

class _CommandRightsV3:

    def __init__(self, work):
        self.work = work
        self.pending = list(sorted(work.original_metadata.roots))
        self.purposes = {ref: set(values) for ref, values in work.original_root_purposes.items()}
        self.sources, self.accesses, self.versions = ({}, {}, {})
        self.column = None
        self.source = None
        self.phase = 'source'
        self.complete = False

    def advance(self, meter):
        from ..memory_types import source_key, access_key, validate_access
        from ..domains.d06 import source_correction_head_key
        from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        work = self.work
        work.require_current(meter=meter)
        if self.source is not None:
            self.source.advance(meter)
            if not self.source.complete:
                return
            self.leaf = self.source.leaf
            self.source = None
            key = access_key(*work.namespace.as_tuple, self.leaf.key.owner.subject)
            head = meter.read_fixed_row(work.db, 'graph_atoms', ('revision', 'valid', 'value_cell_id'), 'bot=? AND persona=? AND token=?', (*work.namespace.as_tuple, key.token))
            if head is None or head[1] != 1:
                raise AuthorityUnavailable('Foreground command Source current Access metadata is absent')
            self.access_head = head
            self.column = _CommandMetadataColumnV3(work, table='graph_atoms', column='value', key_columns=('token',), key=(key.token,), cell_id=head[2])
            return
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            access = self.column.require_v3(work)
            validate_access(access)
            leaf = self.leaf
            record = _SourceMetadataRecordV3(leaf.metadata)
            key = leaf.key
            correction = source_correction_head_key(work.namespace, key.owner.subject)
            head = meter.read_fixed_row(work.db, 'graph_atoms', ('revision', 'valid'), 'bot=? AND persona=? AND token=?', (*work.namespace.as_tuple, correction.token))
            if head is not None or access['source_id'] != record.source_id or access['status'] != 'active' or (not self.purposes[key.token] <= set(record.purposes)) or (not self.purposes[key.token] <= set(access['purposes'])) or (not set(work.original_audiences) <= set(record.audiences)) or (not set(work.original_audiences) <= set(access['audiences'])):
                raise AuthorityUnavailable('Foreground command Source or ancestor current purpose/access/correction differs')
            from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
            access_atom=GraphAtom(access_key(*work.namespace.as_tuple,key.owner.subject),self.access_head[0],access,True)
            correction_atom=GraphAtom(correction,0,{},False)
            for actual_purpose in self.purposes[key.token]:
                for actual_audience in work.original_audiences:
                    if _qualify_source_rights_values_v3(work.namespace,key.token,leaf,access_atom,correction_atom,
                            audience=actual_audience,purpose=actual_purpose,metadata_only=True)is None:
                        raise AuthorityUnavailable('Foreground Source/Access/ancestor ALL denied current assertion/purpose/audience')
            self.sources[key.token] = leaf
            self.accesses[key.token] = access
            self.versions[key] = leaf.revision
            self.versions[access_key(*work.namespace.as_tuple, key.owner.subject)] = self.access_head[0]
            self.versions[correction] = 0
            for parent in record.parent_source_ids:
                ref = source_key(*work.namespace.as_tuple, parent).token
                before = self.purposes.setdefault(ref, set())
                prior = set(before)
                before.update(self.purposes[key.token])
                if ref in self.sources and before != prior:
                    self.sources.pop(ref)
                    self.accesses.pop(ref)
                self.pending.append(ref)
            self.column = None
            _reserve(work, (work.original_metadata.rows, self.sources, self.accesses, self.versions, self.pending))
            return
        while self.pending:
            ref = self.pending.pop()
            if ref in self.sources:
                continue
            if len(self.sources) >= 256:
                raise AuthorityUnavailable('Foreground command actual Source ancestry exceeds the existing bound')
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != work.namespace or key.type_name != 'memory.source':
                raise AuthorityUnavailable('Foreground command Source roots crossed the exact namespace')
            self.source = _CommandSourceColumnV3(work, key)
            return
        active, done = (set(), set())

        def visit(ref):
            if ref in active:
                raise AuthorityUnavailable('Foreground command actual Source ancestry contains a cycle')
            if ref in done:
                return
            active.add(ref)
            for parent in self.sources[ref].metadata['parent_source_ids']:
                visit(source_key(*work.namespace.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
        for ref in self.sources:
            visit(ref)
        self.complete = True

class _CommandLocatorColumnV3(DispatchOriginalJSONReadV3):

    def __init__(self, metadata, *, table, column, key_columns, key, cell_id=None):
        self.metadata = metadata
        super().__init__(metadata.work, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell_id)
        from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
        self.stream = _MetadataStreamV3(self, self.cell is None or self.cell.header[0] == 'canonical-json.ascii.v1')
        self.parser = self.stream

    def _emit(self, event):
        if event.path and event.path[-1]=='question' and event.kind not in {'object_start','array_start'}:return
        phase_selector = event.path[:3] == ('call_plan', 'phase_group', 'selector')
        if event.kind in {'object_start', 'array_start'} or phase_selector or (event.path and event.path[-1] == 'price') or any((part in _LOCATOR_FIELDS for part in event.path)):
            super()._emit(event)

def _locator_sources_v3(raw):
    from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
    result = _source_refs_v3(raw)

    def walk(value):
        if type(value) is dict:
            key = value.get('key')
            if type(key) is str and key.startswith('['):
                atom = AtomKey.from_token(key)
                if atom.type_name == 'memory.source':
                    result.add(key)
            for item in value.values():
                if type(item) in (dict, list):
                    walk(item)
        elif type(value) is list:
            for item in value:
                walk(item)
    walk(raw)
    return result

class _CommandMetadataV3:

    def __init__(self, work):
        self.work = work
        self.rows = {}
        self.heads = {}
        self.families = {}
        self.roots = set(work.locator_roots)
        self.pending = []
        self.context_roots = set()
        self.exact = {v.key.token for v in work.locator_versions}
        self.exact.add(owner_grant_key(*work.namespace.as_tuple).token)
        self.originals = {}
        self.producers = set()
        self.signed = set()
        self.job_authorization_digest=None
        self.quote_keys = set()
        self.job_ids = set()
        self.candidate_evidence_plan = None
        from .foreground_command_metadata_profiles_v3 import foreground_command_metadata_families_v3
        self.family_types = set(foreground_command_metadata_families_v3(work.spec.operation_kind))
        self.column = None
        self.cursor = ''
        self.deferred_family_types=set()
        self.family_eof = set()
        self.complete = False
        self.phase = 'job'
        self.original_cursor = ''
        self.history_cursor = ''
        self.history_heads = {}
        self.c02_history_heads = set()
        self.history_complete = False
        self.historical_pending = []
        self.catalogue_history_pending = []
        self.required_originals = set()
        self.required_matches = {}
        self.producer_scan_complete = False
        self.producer_scan_index = 0
        request = work.request
        self.job_key = AtomKey.from_token(request.cycle_job_ref)
        self.exact.add(self.job_key.token)
        self.job_ids.add(self.job_key.name)
        self.roots.update((request.cue_source_ref, request.plan_source_ref))
        self.exact.update(self.roots)
        if request.plan_ref is not None:
            self.exact.add(request.plan_ref)
        if request.draft_root_registration_ref is not None:
            from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
            self.signed.update((('draft_root_capability', request.draft_root_registration_ref), ('artifact_task_scope', task_scope_ref_v1(request.draft_root_registration_ref))))
        self.pending = list(sorted(self.exact))
        from ..domains.d01.production_operations_v1 import plain_v1
        self._fixed_original_edges(plain_v1(work.reader.request))

    def _column(self, table, column, keys, key, identity, header, cell=None):
        self.reading = (identity, header)
        if identity[0] == 'producer':
            self.column = _CommandProducerV3(self, table, column, keys, key, header, cell)
        else:
            self.column = _CommandLocatorColumnV3(self, table=table, column=column, key_columns=keys, key=key, cell_id=cell)
        self.work.columns.add(self.column)

    def _consume(self, raw, digest):
        w = self.work
        identity, header = self.reading
        kind = identity[0]
        if kind == 'head':
            ref = identity[1]
            self.rows[ref] = raw
            roots = _locator_sources_v3(raw)
            self.roots.update(roots)
            if AtomKey.from_token(ref).type_name in _CONTEXT_TYPES:
                self.context_roots.update(roots)
            for field in ('goal_ref', 'project_ref', 'recipe_ref', 'target_entity_ref', 'role_binding_ref', 'plan_ref', 'decision_ref', 'protocol_ref', 'gp1_interpretation_ref', 'deadline_ref'):
                value = raw.get(field)
                if type(value) is str and value not in self.exact:
                    key = AtomKey.from_token(value)
                    if NamespaceId.from_key(key) == w.namespace:
                        self.exact.add(value)
                        self.pending.append(value)
        elif kind == 'life':
            from .d11_life_preparation_v1 import SIGN_KIND
            if digest != header[1]:
                raise AuthorityUnavailable('Foreground command signed locator did not reach exact canonical whole EOF')
            w.reader.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND, canonical_serialize((w.namespace, identity[1], identity[2], digest)), header[2])
            if identity[1]=='source_note_task_authorization':
                q=w.reader.selector
                if(self.job_authorization_digest is not None and digest!=self.job_authorization_digest
                        or raw.get('namespace')!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}
                        or raw.get('request',{}).get('c02_operation_id')!=q.c02_operation_id
                        or raw.get('request',{}).get('source_ref')!=q.cue_source_ref
                        or raw.get('parent_budget_lease_ref')!=w.reader.parent_budget_lease_ref):
                    raise AuthorityUnavailable('Foreground SourceNote actual signed authorization changed original Source/C02/Root')
                self._deadline(raw['original_deadline_utc'])
            if identity[1] == 'c1_task_intent':
                from .foreground_command_source_v3 import _bind_signed_c1_metadata_v3
                _bind_signed_c1_metadata_v3(self, identity, header, raw)
            else:
                self.producers.add(header[0])
            self.originals[identity] = raw
            self.roots.update(_locator_sources_v3(raw))
            if identity[1] == 'artifact_task_scope' and raw.get('objective_ref') is not None:
                self.signed.add(('artifact_task_objective', raw['objective_ref']))
        elif kind == 'producer':
            if digest != header[2]:
                raise AuthorityUnavailable('Original producer locator did not reach its exact canonical whole EOF')
            if raw['identity']['operation_id'] != identity[1] or raw['identity']['phase'] != header[1]:
                raise AuthorityUnavailable('Original producer locator changed canonical identity phase')
            self.roots.update(_locator_sources_v3(raw))
            self.originals[identity] = raw
            pointer = raw.get('provenance', {}).get('prepared_candidates_operation_id')
            if pointer is not None:
                self.producers.add(pointer)
            prepared = raw.get('provenance', {}).get('prepared_candidates')
            if prepared is not None:
                self._all_candidate_plan(prepared, header[2])
                for candidate in prepared['candidates']:
                    if candidate.get('quote_ref') is not None:
                        self.quote_keys.add((candidate['quote_ref'], 1))
        elif kind in {'history', 'catalogue_history'}:
            if len(identity) == 4 and digest != identity[3]:
                raise AuthorityUnavailable('Foreground command signed historical control changed its exact whole EOF digest')
            self.roots.update(_locator_sources_v3(raw))
        elif kind == 'job_continuation':
            if raw.get('authorization_original_ref') is not None:
                from .source_note_task_authorization_v1 import KIND as AUTHORIZATION_KIND
                self.signed.add((AUTHORIZATION_KIND, raw['authorization_original_ref']))
                self.job_authorization_digest = raw['authorization_original_digest']
            call = raw.get('call_plan', {})
            group = call.get('phase_group')
            if group is not None:
                selector = group['selector']
                from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_from_wire_v2
                self.actual_selector = artifact_draft_from_wire_v2(selector, ArtifactDraftPhaseSelectorV2)
                self._fixed_original_edges(selector)
                for field in ('decision_ref', 'plan_ref'):
                    ref = selector[field]
                    if ref not in self.exact:
                        self.exact.add(ref)
                        self.pending.append(ref)
        self._fixed_original_edges(raw)
        if kind=='producer':
            responsibility=raw.get('provenance',{}).get('foreground_responsibility')
            if responsibility is not None:
                from .foreground_cycle_v1 import ForegroundResponsibilityV1
                from .source_note_foreground_v1 import ForegroundSourceNoteResponsibilityV1
                from .domain_production_erasure_v1 import decode_typed_production_value_v1
                variants={kind.__dataclass_fields__['schema'].default:kind for kind in (ForegroundResponsibilityV1,ForegroundSourceNoteResponsibilityV1)}
                cls=variants.get(responsibility.get('schema'))
                if cls is None:raise AuthorityUnavailable('Foreground responsibility is outside its exact registered variants')
                actual=decode_typed_production_value_v1(responsibility,cls)
                if(actual.namespace!=w.namespace or actual.c02_operation_id!=w.request.c02_operation_id
                        or actual.source_ref!=w.request.cue_source_ref or actual.parent_budget_lease_ref!=w.reader.parent_budget_lease_ref):
                    raise AuthorityUnavailable('Foreground actual responsibility producer changed its original Root/C02/Source')
                if w.responsibility is not None and w.responsibility!=actual:
                    raise AuthorityUnavailable('Foreground metadata producer changed its immutable responsibility')
                w.responsibility=actual
        _reserve(w, (self.rows, self.originals, self.roots, self.context_roots, self.pending))

    def _fixed_original_edges(self, raw):
        from .artifact_phase_postconditions_v1 import APPROVAL_KIND_V2, PREPARATION_PARENT_KIND_V1
        edges = {'objective_ref': 'artifact_task_objective', 'extent_original_ref': 'artifact_task_text_extent', 'postcondition_policy_ref': 'artifact_phase_postcondition_policy', 'approval_original_ref': APPROVAL_KIND_V2, 'contract_ref': 'artifact_phase_postcondition_contract', 'preparation_parent_original_ref': PREPARATION_PARENT_KIND_V1, 'prev_phase_original_ref': 'c4_phase_verified', 'observation_basis_ref':'artifact_phase_observation_basis_v1'}
        if raw.get('schema') in {'d11.ingress-artifact-task-scope.v1', 'd11.ingress-artifact-task-scope.v2', 'd11.ingress-artifact-task-scope.v3'}:
            from .foreground_command_source_v3 import _bind_task_scope_c1_v3
            _bind_task_scope_c1_v3(self, raw)
        for field, kind in edges.items():
            ref = raw.get(field)
            if ref is not None:
                self.signed.add((kind, ref))
        self.roots.update(_locator_sources_v3(raw))
        life_edges={'plan_original_ref':'plan','activity_scope_ref':'activity_scope','activity_outcome_ref':'outcome',
            'admission_ref':'action_admission','body_preparation_ref':'life_body_preparation','prepared_original_ref':'prepared'}
        for field,kind in life_edges.items():
            ref=raw.get(field)
            if ref is not None:self.signed.add((kind,ref))
        if raw.get('schema')=='d10.registered-life-outcome.v2' or ('terminal_original_ref'in raw and 'plan_original_ref'in raw):
            for field,kind in (('artifact_ref','adopted_life'),):
                ref=raw.get(field)
                if ref is not None:self.signed.add((kind,ref))
        if self.work.reader.operation_kind=='create_source_note_foreground_cycle_v1':
            ref=raw.get('authorization_original_ref')
            if ref is not None:self.signed.add(('source_note_task_authorization',ref))
        for child in ('plan','outcome','binding','request','content'):
            value=raw.get(child)
            if type(value)is dict:self._fixed_original_edges(value)
        for key in _metadata_graph_keys_v3(raw,self.work.namespace):
            if key.token not in self.exact:self.exact.add(key.token);self.pending.append(key.token)


    def _deadline(self, deadline):
        w = self.work
        if _clock_upper_v3(w) >= deadline:
            raise AuthorityUnavailable('Original request absolute deadline expired during metadata')
        w.deadline_utc = min(w.deadline_utc, float(deadline))

    def _all_candidate_plan(self, prepared, digest):
        from .artifact_recipe_metadata_v3 import artifact_candidate_evidence_plan_from_metadata_v3
        plan = artifact_candidate_evidence_plan_from_metadata_v3(prepared, preparation_original_digest=digest)
        if self.candidate_evidence_plan is not None:
            from .d01_production_operations_v1 import production_read_plan_v1
            prior = self.candidate_evidence_plan
            plan = production_read_plan_v1((*prior.fixed_type_ids, *plan.fixed_type_ids), (*prior.exact_keys, *plan.exact_keys), (*prior.source_roots, *plan.source_roots), (*prior.required_original_refs, *plan.required_original_refs))
        self.candidate_evidence_plan = plan
        if not self.cursor:self.family_types.update(plan.fixed_type_ids)
        else:self.deferred_family_types.update(plan.fixed_type_ids)
        self.roots.update(plan.source_roots)
        for key in plan.exact_keys:
            if key.token not in self.exact:
                self.exact.add(key.token)
                self.pending.append(key.token)
        before = set(self.required_originals)
        self.required_originals.update(plan.required_original_refs)
        if self.required_originals != before:
            self.original_cursor = ''
            self.producer_scan_index = 0
            self.producer_scan_complete = False

    def advance(self, meter):
        w = self.work
        w.require_current(meter=meter)
        if w.registered_input_index<len(w.registered_input_descriptors):
            index=w.registered_input_index
            if len(w.registered_input_tasks)==index:
                w.registered_input_tasks.append(_CommandRegisteredInputMetadataV3(w,w.registered_input_descriptors[index]))
            task=w.registered_input_tasks[index]
            if task.advance(meter):w.registered_input_index+=1
            return
        if self.column is not None:
            if not self.column.advance(meter):
                return
            self._consume(self.column.require_v3(w), self.column.stream.semantic.hexdigest())
            self.column = None
            return
        if self.phase == 'job':
            row = meter.read_fixed_row(w.db, 'runtime_jobs', ('bot_id', 'persona_id', 'deadline_utc', 'budget_ref'), 'job_id=?', (self.job_key.name,))
            if row is not None:
                if row[:2] != w.namespace.as_tuple:
                    raise AuthorityUnavailable('Original task job crossed actual namespace')
                self._deadline(datetime.fromisoformat(row[2].replace('Z', '+00:00')).timestamp())
                w.original_parent_budget = row[3]
            self.phase = 'selected'
            if row is not None:
                self._column('runtime_jobs', 'continuation_json', ('job_id',), (self.job_key.name,), ('job_continuation', self.job_key.name), row)
            return
        if not self.history_complete:
            row = meter.read_fixed_row(w.db, 'graph_history', ('token', 'revision', 'valid', 'value_cell_id'), 'event_bot=? AND event_persona=? AND event_id=? AND token>? ORDER BY token', (*w.namespace.as_tuple, w.request.c02_operation_id, self.history_cursor))
            if row is None:
                self.history_complete = True
                return
            self.history_cursor = row[0]
            key = AtomKey.from_token(row[0])
            if NamespaceId.from_key(key) != w.namespace:
                raise AuthorityUnavailable('Original C02 historical metadata crossed namespace')
            if row[2] and key.type_name in {'memory.episode.v1', 'memory.subjective_trace.v2'}:
                self.history_heads[row[0], row[1]] = row[2:]
                self.c02_history_heads.add((row[0], row[1]))
                self.exact.add(row[0])
                self.pending.append(row[0])
                self._column('graph_history', 'value', ('token', 'revision'), (row[0], row[1]), ('history', row[0]), row, row[3])
            return
        catalogue_history = getattr(self, 'catalogue_history_pending', None)
        if catalogue_history:
            ref, revision = catalogue_history.pop()
            row = meter.read_fixed_row(w.db, 'graph_history', ('valid', 'value_cell_id', 'event_bot', 'event_persona'), 'token=? AND revision=?', (ref, revision))
            if row is None or row[0] != 1 or row[2:] != w.namespace.as_tuple:
                raise AuthorityUnavailable('Task catalogue declared producer version lacks actual namespace history')
            self.history_heads[ref, revision] = row[:2]
            self._column('graph_history', 'value', ('token', 'revision'), (ref, revision), ('catalogue_history', ref, revision), row, row[1])
            return
        if self.historical_pending:
            ref, revision, digest = self.historical_pending.pop()
            row = meter.read_fixed_row(w.db, 'graph_history', ('valid', 'value_cell_id', 'event_bot', 'event_persona'), 'token=? AND revision=?', (ref, revision))
            if row is None or row[0] != 1 or row[2:] != w.namespace.as_tuple:
                raise AuthorityUnavailable('Foreground command signed historical control has no exact real history')
            self.history_heads[ref, revision] = row[:2]
            self._column('graph_history', 'value', ('token', 'revision'), (ref, revision), ('history', ref, revision, digest), row, row[1])
            return
        if self.pending:
            ref = self.pending.pop()
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != w.namespace:
                raise AuthorityUnavailable('Original exact control locator crossed namespace')
            row = meter.read_fixed_row(w.db, 'graph_atoms', ('revision', 'valid', 'value_cell_id'), 'token=?', (ref,))
            self.heads[ref] = (0, 0, None) if row is None else row
            if row is not None and key.type_name != 'memory.source':
                self._column('graph_atoms', 'value', ('token',), (ref,), ('head', ref), row, row[2])
                if key.type_name in {'d08.decision_record.v2', 'd08.personal_plan.v1', 'runtime.job', 'd07.current_interpretation.v1', 'd07.attention_ticket.v1'}:
                    history = meter.read_fixed_row(w.db, 'graph_history', ('event_id',), 'token=? AND revision=?', (ref, row[0]))
                    if history is not None:
                        self.producers.add(history[0])
            return
        if not self.cursor and self.deferred_family_types:
            self.family_types.update(self.deferred_family_types);self.deferred_family_types.clear()
        remaining=sorted(self.family_types-self.family_eof)
        if remaining:
            kind=remaining[0]
            row=meter.read_fixed_row(w.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',(*w.namespace.as_tuple,kind,self.cursor))
            if row is None:
                self.families.setdefault(kind,[]);self.family_eof.add(kind);self.cursor='';return
            self.cursor=row[0];members=self.families.setdefault(kind,[])
            if len(members)>=128:raise AuthorityUnavailable('Foreground exact fixed-family census exceeds original bound')
            members.append(GraphVersion(AtomKey.from_token(row[0]),row[1]));self.heads[row[0]]=row[1:]
            self._column('graph_atoms','value',('token',),(row[0],),('head',row[0]),row[1:],row[3]);return
        pending = sorted((identity for identity in self.signed if ('life', *identity) not in self.originals))
        if pending:
            kind, ref = pending[0]
            key = (*w.namespace.as_tuple, kind, ref)
            row = meter.read_fixed_row(w.db, 'graph_d11_life_originals_v1', ('producing_operation_id', 'payload_digest', 'signature'), 'bot=? AND persona=? AND kind=? AND original_ref=?', key)
            if row is None:
                if kind == 'artifact_task_scope':
                    self.originals['life', kind, ref] = {}
                    return
                raise AuthorityUnavailable('Original fixed signed metadata locator is absent')
            self._column('graph_d11_life_originals_v1', 'payload_json', ('bot', 'persona', 'kind', 'original_ref'), key, ('life', kind, ref), row)
            return
        if not self.producer_scan_complete and self.required_originals:
            from .domain_production_originals_v1 import PHYSICAL_TABLE
            table = ('graph_domain_production_originals_v1', PHYSICAL_TABLE)[self.producer_scan_index]
            row = meter.read_fixed_row(w.db, table, ('operation_id', 'domain', 'original_digest'), 'bot=? AND persona=? AND operation_id>? ORDER BY operation_id', (*w.namespace.as_tuple, self.original_cursor))
            if row is None:
                if self.producer_scan_index == 0:
                    self.producer_scan_index = 1
                    self.original_cursor = ''
                    return
                missing = {ref for ref in self.required_originals if '-current:' in ref and ref not in self.required_matches}
                if missing:
                    raise AuthorityUnavailable('Original ALL candidate evidence has no exact positive producer metadata')
                self.producer_scan_complete = True
                return
            self.original_cursor = row[0]
            ref = row[1] + '-current:' + row[2][:48]
            if ref in self.required_originals:
                prior = self.required_matches.setdefault(ref, row[0])
                if prior != row[0]:
                    raise AuthorityUnavailable('Original ALL candidate producer locator is ambiguous')
                self.producers.add(row[0])
            return
        pending = sorted((operation for operation in self.producers if ('producer', operation) not in self.originals))
        if pending:
            operation = pending[0]
            key = (*w.namespace.as_tuple, operation)
            table = 'graph_domain_production_originals_v1'
            name = 'original_payload_json'
            cell = None
            row = meter.read_fixed_row(w.db, table, ('domain', 'operation_kind', 'original_digest', 'bundle_digest'), 'bot=? AND persona=? AND operation_id=?', key)
            if row is None:
                from .domain_production_originals_v1 import PHYSICAL_TABLE
                table = PHYSICAL_TABLE
                name = 'original_payload_cell_id'
                row = meter.read_fixed_row(w.db, table, ('domain', 'operation_kind', 'original_digest', 'bundle_digest', 'original_payload_cell_id'), 'bot=? AND persona=? AND operation_id=?', key)
                if row is not None:
                    cell = row[4]
            if row is None:
                raise AuthorityUnavailable('Foreground command selected producer has no actual W01 metadata')
            bundle = meter.read_fixed_row(w.db, 'graph_bundle_operations', ('digest', 'commit_seq'), 'bot=? AND persona=? AND operation_id=?', key)
            if bundle is None or bundle[0] != row[3] or type(bundle[1]) is not int or (bundle[1] < 1):
                raise AuthorityUnavailable('Foreground command selected producer metadata has no actual positive COMMIT')
            self._column(table, name, ('bot', 'persona', 'operation_id'), key, ('producer', operation), row, cell)
            return
        if self.phase != 'budget':
            w.original_budget = _CommandBudgetMetadataV3(w)
            self.phase = 'budget'
            return
        w.original_budget.advance(meter)
        if not w.original_budget.complete:
            return
        w.original_root_purposes = {ref: {'context'} if ref in self.context_roots else set(w.original_purposes) for ref in self.roots}
        selected = set()
        selected.update((w.request.cue_source_ref, w.request.plan_source_ref))
        for identity, value in self.originals.items():
            if identity[0] == 'life' and identity[1] == 'owner_source_note_task_authorization_v2':
                for ref in value['source_refs']:
                    w.original_root_purposes.setdefault(ref, set()).update(('context', 'consolidation'))
        for ref in selected:
            w.original_root_purposes.setdefault(ref, set()).update(w.original_purposes)
        self.complete = True

class _CommandProducerV3:

    def __init__(self, metadata, table, column, keys, key, header, cell):
        self.metadata, self.state = (metadata, metadata.work)
        self.table, self.key, self.header = (table, key, header)
        self.columns = [_CommandLocatorColumnV3(metadata, table=table, column=column, key_columns=keys, key=key, cell_id=cell)]
        for name in ('read_versions_json', 'receipt_json'):
            self.columns.append(_CommandMetadataColumnV3(self.state, table=table, column=name, key_columns=keys, key=key))
        self.index = 0
        self.complete = False
        self.stream = self.columns[0].stream
        self.state.columns.update(self.columns)

    def advance(self, meter):
        s = self.state
        s.require_current(meter=meter)
        if self.index < len(self.columns):
            if self.columns[self.index].advance(meter):
                self.index += 1
            return False
        from .domain_production_originals_v1 import _receipt
        row = meter.read_fixed_row(s.db, self.table, ('domain', 'operation_kind', 'request_digest', 'original_digest', 'bundle_digest', 'receipt_digest'), 'bot=? AND persona=? AND operation_id=?', self.key)
        if row is None or (row[0], row[1], row[3], row[4]) != self.header[:4]:
            raise AuthorityUnavailable('Foreground producer header changed during whole EOF')
        raw = self.columns[0].require_v3(s)
        reads = self.columns[1].require_v3(s)
        receipt = _receipt(self.columns[2].require_v3(s))
        versions = tuple((GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in reads))
        from .domain_production_registry_v1 import installed_operation_v1
        if installed_operation_v1(row[1]).domain != row[0] or raw.get('namespace') != {'bot_id': s.namespace.bot_id, 'persona_id': s.namespace.persona_id} or raw.get('identity', {}).get('operation_id') != self.key[2] or (raw.get('identity', {}).get('phase') != row[1]) or (self.columns[0].stream.semantic.hexdigest() != row[3]) or (receipt.status != 'committed') or (receipt.operation_id != self.key[2]) or (receipt.operation_digest != row[4]) or (canonical_digest(receipt) != row[5]) or (receipt.read_versions != versions):
            raise AuthorityUnavailable('Foreground metadata lost actual producer/receipt/readset provenance')
        bundle = meter.read_fixed_row(s.db, 'graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'), 'bot=? AND persona=? AND operation_id=?', self.key)
        if bundle != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
            raise AuthorityUnavailable('Foreground producer lacks its actual positive W01 COMMIT')
        self.receipt = receipt
        self.sha256 = self.columns[0].sha256
        self.complete = True
        for v in (*versions, *receipt.write_versions):
            if NamespaceId.from_key(v.key) != s.namespace:
                raise AuthorityUnavailable('Foreground actual producer readset crossed namespace')
            self.metadata.exact.add(v.key.token)
            if v.key.token not in self.metadata.heads:
                self.metadata.pending.append(v.key.token)
            if v.key.type_name == 'memory.source':
                self.metadata.roots.add(v.key.token)
            if v.revision and (v.key.token, v.revision) not in self.metadata.history_heads:
                self.metadata.catalogue_history_pending.append((v.key.token, v.revision))
        s.producer_versions[self.key[2]] = versions
        return True

    def require_v3(self, state):
        if state is not self.state or not self.complete:
            raise AuthorityUnavailable('Foreground producer EOF belongs to another state')
        return self.columns[0].require_v3(state)
_CATALOGUE_OPERATIONS = frozenset({'prepare_personal_candidate_eligibility_v1', 'adopt_personal_candidate_eligibility_v1', 'input:register_artifact_task_text_extent', 'input:register_artifact_phase_postcondition_policy_v1', 'prepare_personal_candidates_v1', 'select_personal_step_v2', 'input:freeze_artifact_candidate_preparation_v1', 'input:freeze_values', 'evaluate_values'})

def _bundle_v3(reader):
    assembly = reader.graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise AuthorityUnavailable('Foreground metadata lost actual installed bundle')
    return assembly.admin_bundle

def _bind_task_scope_c1_v3(metadata, raw):
    s = metadata.work
    r = s.reader
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    if raw.get('c02_operation_id') != r.selector.c02_operation_id or raw.get('source_ref') != r.selector.cue_source_ref or raw.get('c1_intent_ref') != c1_task_intent_ref_v1(r.namespace, r.selector.c02_operation_id):
        raise AuthorityUnavailable('Foreground Scope changed actual signed C1/C02/Source locator')
    metadata.signed.add(('c1_task_intent', raw['c1_intent_ref']))

def _bind_signed_c1_metadata_v3(metadata, identity, header, raw):
    s = metadata.work
    r = s.reader
    q = r.selector
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    policy = _bundle_v3(r).installation_policy
    source = AtomKey.from_token(raw['source_ref'])
    if header[0] != q.c02_operation_id or identity[2] != c1_task_intent_ref_v1(r.namespace, q.c02_operation_id) or raw.get('schema') != 'd11.c1-artifact-task-intent-original.v1' or (raw.get('namespace') != plain_v1(r.namespace)) or (raw.get('c02_operation_id') != q.c02_operation_id) or (raw['source_ref'] != q.cue_source_ref) or (source.type_name != 'memory.source') or (NamespaceId.from_key(source) != r.namespace) or (type(raw['source_revision']) is not int) or (raw['source_revision'] < 1) or (raw['installation_id'] != policy.installation_id) or (raw['manifest_digest'] != policy.manifest_digest):
        raise AuthorityUnavailable('Foreground C1 metadata lost exact actual C02/Source/installation')
    with runtime_storage_quantum_v3(r.db) as meter:
        bundle = meter.read_fixed_row(r.db, 'graph_bundle_operations', ('digest', 'commit_seq'), 'bot=? AND persona=? AND operation_id=?', (*r.namespace.as_tuple, q.c02_operation_id))
    if bundle != (raw['c02_bundle_digest'], raw['c02_commit_seq']) or type(bundle[1]) is not int or bundle[1] < 1:
        raise AuthorityUnavailable('Foreground C1 metadata lacks actual positive direct C02 COMMIT')
    metadata.roots.add(source.token)
    metadata.historical_pending.append((source.token, raw['source_revision'], raw['source_digest']))
    if source.token not in metadata.exact:
        metadata.exact.add(source.token)
        metadata.pending.append(source.token)
    s.c1 = raw

def _merge_catalogue_v3(s):
    result = s.catalogue.result_v3()
    m = s.metadata
    roots = set(result.source_roots)
    keys = set()
    if result.goal_head is not None:
        keys.add(result.goal_head.key)
    if result.plan_head is not None:
        keys.add(result.plan_head.key)
    for original in result.originals:
        m.signed.add((original['kind'], original['ref']))
        m.producers.add(original['operation_id'])
        roots.update(original['source_roots'])
        for version in (*original['read_versions'], *original['write_versions']):
            if NamespaceId.from_key(version.key) != s.namespace:
                raise AuthorityUnavailable('Foreground task catalogue crossed namespace')
            keys.add(version.key)
            if version.revision and (version.key.token, version.revision) not in m.history_heads:
                m.catalogue_history_pending.append((version.key.token, version.revision))
    for ref in roots:
        key = AtomKey.from_token(ref)
        if key.type_name != 'memory.source' or NamespaceId.from_key(key) != s.namespace:
            raise AuthorityUnavailable('Foreground task catalogue has noncanonical Source')
        keys.add(key)
    m.roots.update(roots)
    for key in keys:
        if key.token not in m.exact:
            m.exact.add(key.token)
            m.pending.append(key.token)
    if m.candidate_evidence_plan is not None:
        from .d01_production_operations_v1 import production_read_plan_v1
        prior = m.candidate_evidence_plan
        m.candidate_evidence_plan = production_read_plan_v1(prior.fixed_type_ids, (*prior.exact_keys, *keys), (*prior.source_roots, *roots), (*prior.required_original_refs, *(o['ref'] for o in result.originals)))
    s.catalogue_merged = True



class ForegroundCommandSourceCapabilityV3:

    def __init__(self, key, state):
        if key is not _KEY or state.phase != 'qualified' or (not state.rights.complete):
            raise AuthorityUnavailable('Foreground Body requires actual Owner/metadata/Source ALL')
        state.monotonic_deadline=min(state.monotonic_deadline,state.initial_monotonic+max(0.0,state.deadline_utc-state.reader.initial_now_utc))
        self.state = state
        self.identity = self._identity_v3()
        _CAPABILITIES[self] = self.identity

    def _identity_v3(self):
        s = self.state
        r = s.reader
        return (s, s.identity, s.work, s.owner_entry, s.metadata, s.rights, s.original_budget, tuple(sorted(s.rights.versions.items(), key=lambda row: row[0].token)), tuple(sorted(((ref,frozenset(purposes))for ref,purposes in s.original_root_purposes.items()),key=lambda row:row[0])), s.catalogue, s.catalogue_merged, s.preparation, s.deadline_utc)

def require_v3(self):
    s = self.state
    s.require_v3()
    r = s.reader
    if s.capability is not self or _CAPABILITIES.get(self) != self._identity_v3() or s.phase != 'qualified':
        raise AuthorityUnavailable('Foreground Source capability changed actual Work/Owner/EOF/ALL binding')
    with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
        r.require_current(meter=meter)
        s.owner_entry.require_for_v3(r)
        if _clock_upper_v3(s) >= s.deadline_utc:
            raise AuthorityUnavailable('Foreground original Source deadline elapsed')
    return self

def advance_foreground_command_source_v3(reader):
    if reader not in _STATES:
        return False
    s = _state_v3(reader)
    if reader.db.in_transaction:
        raise AuthorityUnavailable('Foreground Source advancement must precede SQL Body transaction')
    if s.phase == 'qualified':
        s.capability.require_v3()
        return False
    if s.phase == 'owner':
        from ..authority_service.artifact_borrowed_owner_location_v3 import prepare_current_host_artifact_borrowed_owner_read_entry_v3
        if s.owner_entry is None:
            s.owner_entry = prepare_current_host_artifact_borrowed_owner_read_entry_v3(reader)
        s.owner_entry.require_permission_v3(reader)
        with reader.store._lock:
            reader.owner_binding = s.owner_entry.require_for_v3(reader)
        s.metadata = _CommandMetadataV3(s)
        if reader.operation_kind in _CATALOGUE_OPERATIONS:
            from .artifact_task_choice_catalogue_metadata_v3 import ArtifactTaskChoiceCatalogueMetadataV3
            s.catalogue = ArtifactTaskChoiceCatalogueMetadataV3(reader, root_ref=reader.selector.draft_root_registration_ref, c02_operation_id=reader.selector.c02_operation_id, source_ref=reader.selector.cue_source_ref)
            s.phase = 'catalogue'
        else:
            s.phase = 'metadata'
        return True
    with reader.store._lock, runtime_storage_quantum_v3(reader.db) as meter:
        reader.require_current(meter=meter)
        s.owner_entry.require_for_v3(reader)
        if s.phase == 'catalogue':
            if s.catalogue.advance(meter):
                _merge_catalogue_v3(s)
                s.phase = 'metadata'
        elif s.phase == 'metadata':
            s.metadata.advance(meter)
            if s.metadata.complete:
                for task in s.registered_input_tasks:task.require_producer_v3()
                if s.original_parent_budget != reader.parent_budget_lease_ref:
                    raise AuthorityUnavailable('Foreground metadata changed its actual original Root budget')
                if reader.operation_kind in _RECALL_OPERATIONS:
                    s.preparation = _CommandIngressMetadataV3(s)
                    s.phase = 'preparation'
                elif reader.operation_kind == 'serve_concern':
                    s.preparation = _CommandConcernMetadataV3(s)
                    s.phase = 'preparation'
                else:
                    s.phase = 'owner_rights'
        elif s.phase == 'preparation':
            if s.preparation.advance(meter):
                s.metadata.complete = False
                s.metadata.phase = 'selected'
                s.phase = 'metadata_final'
        elif s.phase == 'metadata_final':
            s.metadata.advance(meter)
            if s.metadata.complete:
                if type(s.preparation)is _CommandConcernMetadataV3:s.preparation.finalize_v3()
                s.phase = 'owner_rights'
        elif s.phase == 'owner_rights':
            owner = s.owner_entry.require_for_v3(reader)
            purposes = {p for values in s.original_root_purposes.values() for p in values}
            if not purposes <= set(owner.purposes) or not set(s.original_audiences) <= set(owner.audiences):
                raise AuthorityUnavailable('Foreground actual Owner denies complete independent Source groups')
            s.rights = _CommandRightsV3(s)
            s.phase = 'rights'
        elif s.phase == 'rights':
            s.rights.advance(meter)
            if s.rights.complete:
                for ref, leaf in s.rights.sources.items():
                    expected = s.expected_source_versions_v3.get(leaf.key)
                    if expected is not None and expected != leaf.revision:
                        raise AuthorityUnavailable('Foreground signed preparation Source changed actual version')
                s.phase = 'qualified'
                s.capability = ForegroundCommandSourceCapabilityV3(_KEY, s)
        else:
            raise AuthorityUnavailable('Foreground Source has no registered phase')
    return True

def _body_state_v3(reader):
    s = _state_v3(reader)
    if s.capability is None:
        raise AuthorityUnavailable('Foreground business Body precedes independent Source ALL')
    s.capability.require_v3()
    return s

def foreground_command_inventory_types_v3(reader):
    if reader not in _STATES:
        return frozenset()
    return frozenset(_body_state_v3(reader).metadata.families)

def require_foreground_command_seal_plan_v3(reader, plan):
    s = _body_state_v3(reader)
    m = s.metadata
    if not set(plan.fixed_type_ids) <= set(m.families) or not set(plan.source_roots) <= set(s.rights.sources) or any((key.token not in m.exact and key.type_name not in m.families and (key not in s.rights.versions) for key in plan.exact_keys)):
        raise AuthorityUnavailable('Foreground compiler plan escaped actual metadata/Source ALL')
    if s.plan is not None and s.plan != plan:
        raise AuthorityUnavailable('Foreground actual compiler plan changed after selected EOF')
    s.plan = plan
    return plan

def require_foreground_command_prepared_v3(prepared):
    from .current_method_learning_read_v3 import PreparedBorrowedMethodDomainInputsV3, _BORROWED_INPUTS
    if type(prepared) is not PreparedBorrowedMethodDomainInputsV3:
        return None
    r = prepared.owner
    if r not in _STATES:
        return None
    s = _body_state_v3(r)
    if _BORROWED_INPUTS.get(prepared) != (r, prepared.plan, prepared.issued, r.graph_stamp, r.expected_rights) or prepared.issued is not r.issued or prepared.plan != r.selected_plan or (prepared.plan != s.plan):
        raise AuthorityUnavailable('Foreground prepared proof lost its actual same-Work sealed plan')
    prepared.require_issued_current_v3(r.db, r.issued.scope, r.issued)
    return s

def require_foreground_command_point_v3(reader, request):
    if reader not in _STATES:
        return False
    s = _body_state_v3(reader)
    m = s.metadata
    table, columns, keys, key = request
    keys = tuple(keys)
    key = tuple(key)
    if len(keys) != len(key):
        raise AuthorityUnavailable('Foreground Body needs actual complete full key')
    if _require_c1_point_v3(s, request):
        return True
    if table in {'graph_atoms', 'graph_history'}:
        atom = AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom) != reader.namespace:
            raise AuthorityUnavailable('Foreground Body crossed namespace')
        if atom.type_name == 'memory.source':
            if atom.token not in s.rights.sources:
                raise AuthorityUnavailable('Foreground Source Body lacks independent ancestor ALL')
        elif atom.token not in m.exact and atom.type_name not in m.families  and (atom not in s.rights.versions):
            raise AuthorityUnavailable('Foreground Body has no actual EOF selected locator')
        raw = m.rows.get(atom.token)
        if raw is not None and (not _locator_sources_v3(raw) <= set(s.rights.sources)):
            raise AuthorityUnavailable('Foreground Body has unqualified Source locators')
        if table == 'graph_history' and (key[0], key[1]) not in m.history_heads and (m.heads.get(key[0], (0,))[0] != key[1]):
            raise AuthorityUnavailable('Foreground historical Body has no actual selected producer/history EOF')
    elif table in {'graph_domain_production_originals_v1', 'graph_domain_production_originals_v3'}:
        if tuple(key[:2]) != reader.namespace.as_tuple or ('producer', key[2]) not in m.originals:
            raise AuthorityUnavailable('Foreground producer Body precedes actual signed metadata/readset EOF')
    elif table == 'graph_d11_life_originals_v1':
        if tuple(key[:2]) != reader.namespace.as_tuple or ('life', key[2], key[3]) not in m.originals:
            raise AuthorityUnavailable('Foreground signed Body lacks exact actual signed metadata')
    elif table in {'runtime_budget_grants', 'runtime_budget_leases', 'runtime_budget_reservations', 'runtime_budget_operations'}:
        values = dict(zip(keys, key))
        if values.get('lease_id') not in s.original_budget.leases:
            raise AuthorityUnavailable('Foreground budget Body escaped actual signed Root ancestry')
    elif table == 'runtime_jobs':
        if key[0] not in m.job_ids:
            raise AuthorityUnavailable('Foreground job Body lacks actual typed current locator')
    elif table == 'runtime_resource_quotes':
        if tuple(key) not in m.quote_keys:
            raise AuthorityUnavailable('Foreground quote Body lacks actual signed typed preparation')
    elif table in {'graph_bundle_operations', 'graph_events'}:
        operation = dict(zip(keys, key)).get('operation_id', dict(zip(keys, key)).get('event_id'))
        if operation != reader.selector.c02_operation_id and operation not in m.producers:
            raise AuthorityUnavailable('Foreground event Body lacks exact actual producer lineage')
    elif table=='graph_d01_production_inputs_v1':
        if tuple(key[:2])!=reader.namespace.as_tuple or not any(
                identity[0]==table and identity[2]==key[2]for identity in s.typed_metadata):
            raise AuthorityUnavailable('Foreground D01 input Body lacks exact signed metadata/producer/readset EOF')
    elif table in {'graph_d07_execution_originals_v1', 'graph_c04_internal_work_prepared_v1'}:
        identity = (table, key[2], key[3]) if table == 'graph_d07_execution_originals_v1' else (table, 'prepared', key[2])
        if tuple(key[:2]) != reader.namespace.as_tuple or identity not in s.typed_metadata:
            raise AuthorityUnavailable('Foreground typed preparation Body has no actual signed metadata provenance')
    elif table == 'graph_dependencies':
        if key[0] not in m.exact and AtomKey.from_token(key[0]).type_name not in m.families:
            raise AuthorityUnavailable('Foreground dependencies escaped actual selected metadata')
    else:
        from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
        if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 or table not in {'graph_ingress_observations', 'runtime_job_operations', 'graph_owner_domain_attempts_v3', 'graph_d02_production_policies_v1', 'd02_fixed_body_policies_v1'}:
            raise AuthorityUnavailable('Foreground command has no fixed Body table profile')
        if tuple(key[:2]) != reader.namespace.as_tuple:
            raise AuthorityUnavailable('Foreground fixed control point crossed namespace')
    return True

def require_foreground_command_body_column_v3(reader, table, key):
    if reader not in _STATES:
        return False
    keys = {'graph_atoms': ('token', 'bot', 'persona') if len(key) == 3 else ('token',), 'graph_history': ('token', 'revision'), 'graph_d11_life_originals_v1': ('bot', 'persona', 'kind', 'original_ref'), 'graph_d07_execution_originals_v1': ('bot', 'persona', 'kind', 'original_ref'), 'graph_c04_internal_work_prepared_v1': ('bot', 'persona', 'operation_id'), 'graph_d01_production_inputs_v1':('bot','persona','original_ref'), 'graph_domain_production_originals_v1': ('bot', 'persona', 'operation_id'), 'graph_domain_production_originals_v3': ('bot', 'persona', 'operation_id'), 'graph_bundle_operations': ('bot', 'persona', 'operation_id'), 'runtime_jobs': ('job_id',), 'runtime_budget_grants': ('lease_id', 'version'), 'runtime_budget_leases': ('lease_id',), 'runtime_budget_reservations': ('lease_id', 'operation_id'), 'runtime_budget_operations': ('bot_id', 'persona_id', 'operation_id', 'phase'), 'runtime_resource_quotes': ('quote_id', 'version'), 'runtime_encoding_call_bindings_v1': ('bot', 'persona', 'job_id'), 'graph_first_ingress_c02_committed_seals_v2': ('bot', 'persona', 'operation_id'), 'graph_events': ('bot', 'persona', 'session', 'event_id')}.get(table)
    if keys is None:
        raise AuthorityUnavailable('Foreground Body column lacks exact registered table/full key')
    return require_foreground_command_point_v3(reader, (table, (), keys, tuple(key)))

def read_foreground_command_task_choice_refs_v3(reader, *, kind, task, goal_head, plan_head, method_ref=None):
    s = _body_state_v3(reader)
    if s.catalogue is None or not s.catalogue_merged or (not s.catalogue.complete):
        raise AuthorityUnavailable('Foreground D08 Body cannot begin task catalogue metadata')
    return s.catalogue.lookup_v3(kind, task=task, goal_head=goal_head, plan_head=plan_head, method_ref=method_ref)
_C02 = ('graph_first_ingress_c02_committed_seals_v2', ('evidence_json', 'bundle_digest'), ('bot', 'persona', 'operation_id'))
_BINDING = ('runtime_encoding_call_bindings_v1', ('source_id', 'source_revision', 'access_revision', 'budget_lease_id', 'budget_reservation_operation_id', 'binding_digest', 'model_request_digest', 'call_id', 'request_json'), ('bot', 'persona', 'job_id'))

def register_foreground_command_c1_binding_v3(db, *, c02_operation_id, read):
    from .current_method_learning_read_v3 import _method_active
    r = _method_active(db)
    if r not in _STATES:
        return False
    s = _body_state_v3(r)
    from .d11_life_preparation_v1 import _read
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from ..authority_service.v2_worker_model_result_contract import from_wire, WorkerModelResultReadV1
    from ..domains.d01.production_operations_v1 import plain_v1
    if c02_operation_id != r.selector.c02_operation_id or type(read) is not WorkerModelResultReadV1 or s.c1 is None:
        raise AuthorityUnavailable('Foreground C1 binding needs actual complete signed direct-C02 metadata')
    ref = c1_task_intent_ref_v1(r.namespace, c02_operation_id)
    saved = _read(db, issuer=r.graph._GraphCoordinator__d11_issuer, namespace=r.namespace, kind='c1_task_intent', ref=ref)
    if saved is None or saved[1] != c02_operation_id:
        raise AuthorityUnavailable('Foreground signed C1 Body is absent')
    raw = saved[0]
    actual = from_wire(json.loads(raw['worker_read_json']), WorkerModelResultReadV1)
    source = GraphVersion(AtomKey.from_token(raw['source_ref']), raw['source_revision'])
    receipt = _adopted_c02_v1(db, r.namespace, c02_operation_id)
    policy = _bundle_v3(r).installation_policy
    request = actual.request
    if canonical_digest(actual) != canonical_digest(read) or raw['namespace'] != plain_v1(r.namespace) or any((raw[k] != s.c1[k] for k in ('c02_operation_id', 'source_ref', 'source_revision', 'source_digest'))) or (raw['installation_id'] != policy.installation_id) or (raw['manifest_digest'] != policy.manifest_digest) or ((raw['c02_bundle_digest'], raw['c02_receipt_digest'], raw['c02_commit_seq']) != (receipt.operation_digest, canonical_digest(receipt), receipt.commit_seq)) or (source not in (*receipt.read_versions, *receipt.write_versions)) or (source.key.token not in s.rights.sources) or ((source.key.token, source.revision) not in s.metadata.history_heads) or (request.namespace != r.namespace) or (request.consumer_operation_id != c02_operation_id) or (request.installation_id != policy.installation_id) or (request.purpose != 'first_ingress_c02'):
        raise AuthorityUnavailable('Foreground C1 binding substituted actual protected result/Source/receipt/typed call')
    identity = (s, s.identity, s.work, r.operation, r.issued.scope, r.selection_digest, ref, request, source, canonical_digest(raw), canonical_digest(read))
    prior = _C1_BINDINGS.get(r)
    if prior is not None and prior != identity:
        raise AuthorityUnavailable('Foreground same-Work C1 binding changed')
    _C1_BINDINGS[r] = identity
    return True

def _require_c1_point_v3(s, request):
    table, columns, keys, key = request
    r = s.reader
    if table not in {_C02[0], _BINDING[0]}:
        return False
    if s.c1 is None:
        raise AuthorityUnavailable('Foreground C1 Body lacks actual complete signed metadata')
    allowed = (*_C02, (*r.namespace.as_tuple, r.selector.c02_operation_id))
    if table == _BINDING[0]:
        binding = _C1_BINDINGS.get(r)
        if binding is None or binding[:6] != (s, s.identity, s.work, r.operation, r.issued.scope, r.selection_digest):
            raise AuthorityUnavailable('Foreground encoding binding must register typed signed C1 result before load_binding')
        actual, source = binding[7:9]
        allowed = (*_BINDING, (*r.namespace.as_tuple, actual.job_id))
    if tuple(keys) != allowed[2] or tuple(key) != allowed[3] or (columns and tuple(columns) != allowed[1]):
        raise AuthorityUnavailable('Foreground C1 Body changed exact C02/job full key or columns')
    point = r.points.get(allowed)
    if point is not None and point.complete:
        with runtime_storage_quantum_v3(r.db) as meter:
            row = point.require_row_v3(meter)
        if row is None:
            raise AuthorityUnavailable('Foreground C1 actual Body disappeared')
        if table == _C02[0]:
            if row[1] != s.c1['c02_bundle_digest']:
                raise AuthorityUnavailable('Foreground actual C02 evidence bundle differs')
        else:
            from ..memory_types import source_key
            column = point.values.get('request_json')
            if source_key(*r.namespace.as_tuple, row[0]) != source.key or row[1] != source.revision or (row[4], row[5], row[6], row[7]) != (actual.original_operation_id, actual.binding_digest, actual.model_request_digest, actual.call_id) or (column is None) or (not column.complete) or (column.sha256 != actual.binding_digest):
                raise AuthorityUnavailable('Foreground encoding binding Body differs from actual Source/reservation/call EOF')
    return True

def require_foreground_command_source_family_v3(frame, db, roots, *, purpose=None, audience=None):
    from .foreground_command_post_frame_v3 import require_foreground_command_post_source_family_v3
    if require_foreground_command_post_source_family_v3(frame,db,roots,purpose=purpose,audience=audience):return True
    record = _FRAMES.get(id(frame))
    if record is None:
        return False
    actual, s, prepared = record
    if actual is not frame or db is not s.reader.db:
        raise AuthorityUnavailable('Foreground family crossed actual prepared frame')
    require_foreground_command_prepared_v3(prepared)
    purpose = purpose or frame.envelope.authority.purpose
    audiences = (audience,) if audience is not None else frame.envelope.authority.audience
    for ref in roots:
        if ref not in s.rights.sources or purpose not in s.original_root_purposes.get(ref, set()):
            raise AuthorityUnavailable('Foreground family escaped actual independent Source purpose ALL')
        if not set(audiences) <= set(s.original_audiences):
            raise AuthorityUnavailable('Foreground family escaped actual independent Source audience ALL')
    return True

def compose_foreground_command_frame_fields_v3(prepared, snapshot, pages):
    s = require_foreground_command_prepared_v3(prepared)
    if s is None:
        return (snapshot, tuple(pages), None)
    versions = {v.key: v.revision for v in snapshot.versions}
    metadata_versions = (*s.locator_versions, *(GraphVersion(k, v) for k, v in s.rights.versions.items()), *(GraphVersion(AtomKey.from_token(ref), head[0]) for ref, head in s.metadata.heads.items()))
    for v in metadata_versions:
        if v.key in versions and versions[v.key] != v.revision:
            raise AuthorityUnavailable('Foreground Body and metadata CAS versions differ')
        versions[v.key] = v.revision
    return (snapshot, tuple(pages), tuple((GraphVersion(k, v) for k, v in sorted(versions.items(), key=lambda row: row[0].token))))

def register_foreground_command_frame_v3(db, frame, scope, prepared):
    s = require_foreground_command_prepared_v3(prepared)
    if s is None:
        return frame
    r = s.reader
    if db is not r.db or scope is not r.issued.scope or (not db.in_transaction) or (not r.business_started) or r.business_completed or (frame.envelope.identity.operation_id != r.operation_id) or (frame.envelope.identity.phase != r.operation_kind) or (frame.owner_guard != r.material_owner_guard):
        raise AuthorityUnavailable('Foreground final frame changed actual same-Work issued WRITE')
    _FRAMES[id(frame)] = (frame, s, prepared)
    return frame

def foreground_command_frame_deadline_v3(prepared, deadline, monotonic=False):
    s = require_foreground_command_prepared_v3(prepared)
    if s is None:
        return deadline
    return min(deadline, s.monotonic_deadline if monotonic else s.deadline_utc)

def release_foreground_command_source_v3(reader):
    s = _STATES.pop(reader, None)
    if s is None:
        return
    _CAPABILITIES.pop(s.capability, None)
    _C1_BINDINGS.pop(reader, None)
    _OUTPUTS.pop(reader, None)
    for identity, record in tuple(_FRAMES.items()):
        if record[1] is s:
            _FRAMES.pop(identity, None)
    if s.catalogue is not None:
        s.catalogue.close_v3()
    if s.preparation is not None:
        s.preparation.close_v3()
    if s.owner_entry is not None:
        s.owner_entry.release_v3()
    from .dispatch_initial_source_read_v3 import _COLUMNS
    for column in tuple(s.columns):
        _COLUMNS.pop(column, None)
        _METADATA_SIGNATURES.pop(column,None)
        if isinstance(column, DispatchOriginalJSONReadV3):
            column.nodes = {}
            column.scalar = bytearray()
            column.fragment = b''
            column.parser = column.cell = column.value = None
            column._frozen_value = None
    for task in s.registered_input_tasks:
        task.column=task.roots_column=task.value=None
    s.registered_input_tasks.clear()
    s.columns.clear()
    s.typed_metadata.clear()
    s.capability = s.owner_entry = s.catalogue = s.preparation = s.metadata = s.rights = s.original_budget = None


_RECALL_OPERATIONS=frozenset({'prepare_ingress_recall_need_v1','prepare_ingress_recall_model_v1',
    'acquire_ingress_recall_model_v1','adopt_ingress_recall_model_v1','adopt_current_task_no_search_v1',
    'select_ingress_recall_seed_v1','prepare_ingress_c04_v1','adopt_ingress_c04_v1'})
_DOMAIN='graph_domain_production_originals_v1'
_D07='graph_d07_execution_originals_v1'
_C04='graph_c04_internal_work_prepared_v1'

class _CommandIngressColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,profile,**kwargs):
        self.state,self.profile=state,profile
        super().__init__(state.reader,**kwargs)
        from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
        from .artifact_host_ingress_recall_metadata_v3 import ingress_control_metadata_paths_v3
        self.capture=ConditionedLocatorJSONV3(self)
        role=profile[1]if type(profile)is tuple else None
        self.capture.retain_path_v3=(lambda path:True)if role is None else(lambda path:ingress_control_metadata_paths_v3(role,path))
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,
            ensure_ascii=self.cell is None or self.cell.header[0]=='canonical-json.ascii.v1')
        from .artifact_task_choice_catalogue_metadata_v3 import attach_task_catalogue_semantic_stream_v3
        attach_task_catalogue_semantic_stream_v3(self)
        state.columns.add(self)
    def _emit(self,event):
        self.capture._emit_v3(event);self.value=self.capture.value
    def _actual(self):self.state.require_v3();return self
    def release_retention_v3(self):
        from .dispatch_initial_source_read_v3 import _COLUMNS
        _COLUMNS.pop(self,None)
        self.nodes={};self.scalar=bytearray();self.fragment=b'';self.value=None;self.parser=self.capture=self.cell=None
        self._frozen_value=None

class _CommandIngressDomainV3:
    def __init__(self,owner,role,operation,domain,kind):
        self.owner,self.role,self.operation,self.domain,self.kind=owner,role,operation,domain,kind
        self.header=None;self.columns=[];self.index=0;self.complete=self.absent=False
        self.original=self.receipt=None;self.read_versions=()
    def advance(self,meter):
        from .domain_production_originals_v1 import _receipt
        s=self.owner.state;r=s.reader;key=(*r.namespace.as_tuple,self.operation)
        row=meter.read_fixed_row(r.db,_DOMAIN,('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
         'bot=? AND persona=? AND operation_id=?',key)
        if self.header is None:
            if row is None:self.complete=self.absent=True;return True
            if row[:2]!=(self.domain,self.kind):raise AuthorityUnavailable('Ingress fixed producer has another actual kind')
            self.header=tuple(row)
            self.columns=[_CommandIngressColumnV3(s,('control_ingress','producer:'+self.role)if name=='original_payload_json'else'control_small',
             table=_DOMAIN,column=name,key_columns=('bot','persona','operation_id'),key=key)
             for name in('original_payload_json','read_versions_json','receipt_json')];return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Ingress producer changed during EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        original,reads,raw=(c.require_v3(r)for c in self.columns);receipt=_receipt(raw)
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads)
        if(self.columns[0].sha256!=self.header[3]or original.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
         or original.get('schema')!=self.domain+'.current-'+self.kind+'.v1'or original.get('identity',{}).get('operation_id')!=self.operation
         or original.get('parent_budget')!=s.original_parent_budget
         or receipt.status!='committed'or receipt.operation_id!=self.operation or receipt.operation_digest!=self.header[4]
         or canonical_digest(receipt)!=self.header[5]or receipt.read_versions!=versions or len(versions)>1024):
            raise AuthorityUnavailable('Ingress producer canonical Original/receipt/readset EOF differs')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
         'bot=? AND persona=? AND operation_id=?',key)
        if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):raise AuthorityUnavailable('Ingress producer lacks actual W01')
        from ..domains.d01.production_operations_v1 import plain_v1
        if original.get('owner_guard')!=plain_v1(r.evidence.owner_guard):
            raise AuthorityUnavailable('Ingress producer changed its actual original Owner pairing')
        self.original,self.receipt,self.read_versions=original,receipt,versions;self.complete=True;return True
    def close_v3(self):
        for column in self.columns:column.release_retention_v3()

class _CommandIngressRowV3:
    def __init__(self,owner,role,table,kind,ref):
        self.owner,self.role,self.table,self.kind,self.ref=owner,role,table,kind,ref
        self.header=self.column=self.value=None;self.complete=self.absent=False
    def advance(self,meter):
        r=self.owner.state.reader
        if self.table==_D07:
            columns=('payload_digest','signature');keys=('bot','persona','kind','original_ref');key=(*r.namespace.as_tuple,self.kind,self.ref)
            where='bot=? AND persona=? AND kind=? AND original_ref=?';column='payload_json'
        elif self.table==_C04:
            columns=('binding_digest','prepared_digest');keys=('bot','persona','operation_id');key=(*r.namespace.as_tuple,self.ref)
            where='bot=? AND persona=? AND operation_id=?';column='prepared_json'
        else:
            columns=('signature',);keys=('quote_id','version');key=self.ref;where='quote_id=? AND version=?';column='quote_json'
        row=meter.read_fixed_row(r.db,self.table,columns,where,key)
        if self.header is None:
            if row is None:self.complete=self.absent=True;return True
            self.header=tuple(row);self.column=_CommandIngressColumnV3(self.owner.state,('control_ingress',self.role),
             table=self.table,column=column,key_columns=keys,key=key);return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Ingress exact row changed during EOF')
        if not self.column.advance(meter):return False
        value=self.column.require_v3(r)
        if self.table==_D07:
            from .d07_execution_v1 import SIGN_KIND
            if self.column.sha256!=self.header[0]:raise AuthorityUnavailable('Ingress signed D07 canonical EOF differs')
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,self.kind,self.ref,self.header[0])),self.header[1])
        elif self.table==_C04:
            if self.column.sha256!=self.header[1]:raise AuthorityUnavailable('Ingress C04 prepared canonical EOF differs')
        else:r.graph._GraphCoordinator__d11_issuer.resource_issuer._signer.verify('resource-quote.v1',canonical_serialize(value),self.header[0])
        self.value=value;self.complete=True;return True
    def close_v3(self):
        if self.column is not None:self.column.release_retention_v3()

class _CommandIngressMetadataV3:
    def __init__(self,state):
        if state.source_complete or state.owner_entry is None:raise AuthorityUnavailable('Ingress metadata requires Owner before Source Body')
        self.state=state;self.tasks=[];self.index=0;self.records={};self.roots=set(state.current_roots);self.keys={}
        self.need=self.prepared=self.routing=self.selection=self.c04=None;self.complete=False
        from .d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1,NEED_OPERATION
        from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1,OPERATION
        from .d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1,ACQUIRE_OPERATION
        from .d07_ingress_recall_result_v1 import ADOPT_OPERATION
        from .d06_ingress_c03_selection_v1 import ingress_c03_selection_operation_id_v1
        from .d06_ingress_c03_read_v1 import OPERATION as SELECT
        ns=state.reader.namespace;c02=state.reader.selector.c02_operation_id;self.ids=ingress_recall_model_ids_v1(ns,c02)
        self._domain('need',ingress_recall_need_operation_id_v1(ns,c02),'d07',NEED_OPERATION)
        self._domain('c3',self.ids['prepare'],'d07',OPERATION)
        self.tasks.append(('prepared',_CommandIngressRowV3(self,'signed:prepared',_D07,'prepared',self.ids['job'])))
        self._domain('acquire',ingress_recall_acquire_operation_id_v1(ns,c02),'d11',ACQUIRE_OPERATION)
        for kind,ref in(('prepare_commit',self.ids['job']),('request',self.ids['job']),('call',self.ids['job']),
         ('paid_cost',self.ids['job']),('body_cost',self.ids['job']),('result','d07-result:'+self.ids['call']),('execution','d07-terminal:'+self.ids['call'])):
            self.tasks.append((kind,_CommandIngressRowV3(self,'signed:'+kind,_D07,kind,ref)))
        self._domain('routing',self.ids['adopt'],'d07',ADOPT_OPERATION)
        self.tasks.append(('adopted',_CommandIngressRowV3(self,'signed:adopted',_D07,'adopted',self.ids['adopt'])))
        self._domain('selection',ingress_c03_selection_operation_id_v1(ns,c02),'d06',SELECT)
        state.reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.roots,self.keys,tuple(task.__dict__ for _,task in self.tasks),self.need,self.prepared,self.routing,self.selection,self.c04))*3+8192
    def _domain(self,role,operation,domain,kind):self.tasks.append((role,_CommandIngressDomainV3(self,role,operation,domain,kind)))
    def _record(self,role):return next(task for name,task in self.tasks if name==role)
    def _versions(self,versions):
        for version in versions:
            key=version.key
            if NamespaceId.from_key(key)!=self.state.reader.namespace:raise AuthorityUnavailable('Ingress readset crossed namespace')
            self.keys[key.token,version.revision]=version
            if key.type_name=='memory.source':
                self.roots.add(key.token);old=self.state.expected_source_versions_v3.setdefault(key,version.revision)
                if old!=version.revision:raise AuthorityUnavailable('Ingress signed parents disagree on a Source version')
    def _publish(self,role,task):
        if isinstance(task,_CommandIngressDomainV3):
            identity=(_DOMAIN,task.kind,task.operation)
            if task.absent:self.records[identity]=None;return
            self._versions((*task.read_versions,*task.receipt.write_versions))
            entry={'projection':task.original,'header':task.header,'payload_digest':task.header[3],'operation_id':task.operation,
             'source_roots':(),'selector':None,'producer_header':task.header,'read_versions':task.read_versions,'write_versions':task.receipt.write_versions}
        else:
            identity=(task.table,task.kind,task.ref)
            if task.absent:self.records[identity]=None;return
            entry={'projection':task.value,'header':task.header,'payload_digest':task.column.sha256,'operation_id':None,
             'source_roots':(),'selector':None,'producer_header':None}
        self.records[identity]=entry
    def advance(self,meter):
        s=self.state;s.require_current_v3(meter);s.owner_entry.require_for_v3(s.reader)
        if self.complete:return True
        if self.index>=len(self.tasks):self._finish();return True
        role,task=self.tasks[self.index]
        if not task.advance(meter):return False
        self._publish(role,task);self._validate(role,task);self.index+=1;s.reader.operation.refresh_retained_state_v3(self);return False
    def _validate(self,role,task):
        s=self.state;r=s.reader;q=r.selector
        from .foreground_cycle_v1 import foreground_cycle_ids_v1,foreground_responsibility_ref_v1
        from .d11_types import runtime_job_key
        activity,cycle=foreground_cycle_ids_v1(r.namespace,q.c02_operation_id);cycle_ref=runtime_job_key(*r.namespace.as_tuple,activity,cycle).token
        if task.absent:
            if role in{'c3_quote','c04_quote'}:raise AuthorityUnavailable('Ingress actual signed original quote is absent')
            if role=='prepared'and not self._record('c3').absent:raise AuthorityUnavailable('Ingress actual C3 producer lost signed preparation')
            if role=='adopted'and not self._record('routing').absent:raise AuthorityUnavailable('Ingress actual routing producer lost signed adoption')
            if role=='c04_prepared'and not self._record('c04_prepare').absent:raise AuthorityUnavailable('Ingress actual C04 producer lost prepared original')
            return
        if role in{'request','call','paid_cost','body_cost','result','execution','acquire','routing'}and self.prepared is None:
            raise AuthorityUnavailable('Ingress child original has no actual complete signed C3 preparation')
        if role=='need':
            from ..domains.d07 import IngressRecallNeedV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            self.need=decode_typed_production_value_v1(task.original['provenance']['need'],IngressRecallNeedV1);n=self.need;responsibility=s.responsibility
            if(n.c02_operation_id!=q.c02_operation_id or n.source_ref!=q.cue_source_ref or n.cycle_job_ref!=cycle_ref or responsibility is None
             or(n.responsibility_ref,n.responsibility_digest)!=(foreground_responsibility_ref_v1(r.namespace,q.c02_operation_id),responsibility.digest)
             or n.cancel_generation or n.policy_digest!=_bundle_v3(r).d06_recall.policy_digest):raise AuthorityUnavailable('Ingress Need changed C02/Source/cycle/responsibility/policy')
            self._versions((GraphVersion(AtomKey.from_token(n.source_ref),n.source_revision),GraphVersion(AtomKey.from_token(n.focus_ref),n.focus_revision),
             GraphVersion(AtomKey.from_token(n.attention_ticket_ref),n.attention_ticket_revision)))
        elif role=='prepared':
            p=task.value;n=self.need;producer=self._record('c3')
            if(n is None or producer.absent or p.get('schema')!='d07.ingress-recall-prepared.v1'
             or p.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
             or(p.get('operation_id'),p.get('job_id'),p.get('call_id'),p.get('execution_id'),p.get('adoption_operation_id'))!=
              (self.ids['prepare'],self.ids['job'],self.ids['call'],self.ids['execution'],self.ids['adopt'])
             or(p.get('activity_id'),p.get('effect_id'),p.get('attempt_id'))!=(activity,self.ids['effect'],self.ids['attempt'])
             or p.get('work_kind')!='recall_need'or p.get('c02_operation_id')!=q.c02_operation_id
             or(p.get('cycle_job_ref'),p.get('need_ref'),p.get('need_digest'),p.get('responsibility_ref'),p.get('responsibility_digest'))!=
              (cycle_ref,'d07-current:'+self._record('need').header[3][:48],canonical_digest(n),n.responsibility_ref,n.responsibility_digest)
             or p.get('cancel_generation')or p.get('recall_policy_digest')!=n.policy_digest
             or producer.original['provenance'].get('prepared_digest')!=task.header[0]):raise AuthorityUnavailable('Ingress signed prepared lost exact actual Need/producer digest')
            import json
            authority=json.loads(p['self_authority_json'])
            producer_authority=producer.original.get('authority',{})
            if(authority.get('actor')!=r.evidence.current_self.self_entity_ref or authority.get('actor')!=producer_authority.get('actor')
             or tuple(p['audience'])!=tuple(producer_authority.get('audience',()))or p['purpose']!=producer_authority.get('purpose')):
                raise AuthorityUnavailable('Ingress C3 prepared changed actual Self/purpose/audience')
            self.prepared=p;self._versions(tuple(GraphVersion(AtomKey.from_token(row['ref']),row['revision'])for row in p['read_rows']))
            self.tasks.append(('c3_quote',_CommandIngressRowV3(self,'quote','runtime_resource_quotes','quote',(p['quote_id'],p['quote_version']))))
        elif role=='prepare_commit':
            producer=self._record('c3')
            if(self.prepared is None or task.value.get('schema')!='d07.preparation-commit.v1'
             or task.value.get('prepared_digest')!=self._record('prepared').header[0]or task.value.get('prepare_operation_id')!=self.ids['prepare']
             or task.value.get('graph_receipt_digest')!=canonical_digest(producer.receipt)):raise AuthorityUnavailable('Ingress C3 commit lost actual signed prepared/W01')
            self._versions(tuple(GraphVersion(AtomKey.from_token(row['ref']),row['revision'])for row in task.value['post_read_rows']))
        elif role=='adopted':
            raw=task.value;producer=self._record('routing')
            if(self.prepared is None or producer.absent or raw.get('schema')!='d07.ingress-recall-adoption.v1'
             or raw.get('c02_operation_id')!=q.c02_operation_id or raw.get('cycle_job_ref')!=cycle_ref or raw.get('adoption_operation_id')!=self.ids['adopt']
             or raw.get('prepared_digest')!=self._record('prepared').header[0]or raw.get('graph_receipt_digest')!=canonical_digest(producer.receipt)
             or{k:v for k,v in raw.items()if k!='graph_receipt_digest'}!=producer.original['provenance']['adoption']):raise AuthorityUnavailable('Ingress routing lost actual signed preparation/W01 adoption')
            self.routing=raw;self.roots.update(raw.get('selected_source_refs',()))
        elif role=='selection':self._selection(task,cycle_ref)
        elif role=='c04_prepared':self._c04(task)
        elif role in{'c3_quote','c04_quote'}:
            from .issuers import ResourceQuote
            raw=dict(task.value);raw['outbox_refs']=tuple(raw['outbox_refs']);raw['d02_settlement_refs']=tuple(raw['d02_settlement_refs']);quote=ResourceQuote(**raw)
            expected=self.prepared['quote_digest']if role=='c3_quote'else self.c04.binding.resource_quote_digest
            operation=self.ids['prepare']if role=='c3_quote'else self.c04.binding.operation_id
            if((quote.bot_id,quote.persona_id)!=r.namespace.as_tuple or quote.operation_id!=operation
             or quote.parent_budget_lease_ref!=s.original_parent_budget or canonical_digest(quote)!=expected):raise AuthorityUnavailable('Ingress signed quote Root/operation/digest differs')
            s.metadata.quote_keys.add((quote.quote_id,quote.version))
    def _selection(self,task,cycle_ref):
        s=self.state;r=s.reader;q=r.selector
        from .d06_ingress_c03_selection_v1 import C03DirectSelectionOriginalV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        value=decode_typed_production_value_v1(task.original['provenance']['selection'],C03DirectSelectionOriginalV1);receipt=task.receipt
        if(self.need is None or self.routing is None or value.namespace!=r.namespace or value.c02_operation_id!=q.c02_operation_id
         or(value.cycle_job_ref,value.cue_source_ref)!=(cycle_ref,q.cue_source_ref)
         or(value.installation_id,value.manifest_digest)!=(_bundle_v3(r).installation_policy.installation_id,_bundle_v3(r).installation_policy.manifest_digest)
         or(value.need_ref,value.need_digest)!=('d07-current:'+self._record('need').header[3][:48],canonical_digest(self.need))
         or value.routing_adoption_ref!=self.ids['adopt']or value.routing_adoption_digest!=self._record('adopted').header[0]
         or(value.responsibility_ref,value.responsibility_digest)!=(self.need.responsibility_ref,self.need.responsibility_digest)
         or value.cancel_generation or(value.purpose,tuple(value.audience))!=(s.purpose,tuple(s.audiences))
         or len(receipt.invalidated_epochs)!=1 or receipt.invalidated_epochs[0].revision!=value.query_epoch.revision+1
         or task.original.get('writes')!=[]):raise AuthorityUnavailable('Ingress C03 lost actual Need/routing/Root/CAS bridge')
        self.selection=value;self._versions(value.source_family_read_versions)
        if value.selected_source_ref is None:return
        self._versions((GraphVersion(AtomKey.from_token(value.selected_source_ref),value.selected_source_revision),))
        from .c04_self_scope_v4 import ingress_c04_ids_v4,PREPARE_OPERATION
        from .c04_ingress_preparation_v4 import ADOPT_OPERATION
        self.c04_ids=ingress_c04_ids_v4(r.namespace,q.c02_operation_id,task.header[3]);self._domain('c04_prepare',self.c04_ids['prepare'],'d06',PREPARE_OPERATION)
        self.tasks.append(('c04_prepared',_CommandIngressRowV3(self,'c04',_C04,'prepared',self.c04_ids['prepare'])))
        self._domain('c04_adopt',self.c04_ids['adopt'],'d06',ADOPT_OPERATION)
    def _c04(self,task):
        s=self.state;r=s.reader;raw=dict(task.value);shape=dict(raw.pop('binding'))
        from ..authority_service.internal_work_contract import InternalWorkBindingV1
        from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
        from .c04_ingress_preparation_v4 import validate_self_c04_provenance_v4,PREPARE_OPERATION
        from ..graph_coordinator import namespace_ref
        binding=InternalWorkBindingV1(**shape);p=C04InternalWorkPreparedV1(binding=binding,**raw);producer=self._record('c04_prepare')
        if producer.absent:raise AuthorityUnavailable('Ingress C04 prepared lacks actual W01 producer')
        provenance=producer.original['provenance'];validate_self_c04_provenance_v4('d06',PREPARE_OPERATION,provenance)
        st=self._record('selection');selected=self.selection;bridge={'query_epoch':selected.query_epoch.revision,
         'commit_after_epoch':st.receipt.invalidated_epochs[0].revision,'metadata_receipt_digest':canonical_digest(st.receipt)}
        material=provenance.get('self_scope_original',{}).get('scope_payload')
        from .c04_prepare_service_v3 import c04_prepare_job_id_v3
        from .d11_types import runtime_job_key
        child_ref=runtime_job_key(*r.namespace.as_tuple,selected.child_activity_id,c04_prepare_job_id_v3(r.namespace,binding.operation_id)).token
        if(material is None or(binding.namespace,binding.operation_id,binding.execution_id,binding.activity_id)!=
          (namespace_ref(r.namespace),self.c04_ids['prepare'],self.c04_ids['execution'],selected.child_activity_id)
         or binding.parent_budget_lease_ref!=s.original_parent_budget or p.prepared_digest!=task.header[1]or binding.binding_digest!=task.header[0]
         or provenance['child_job_ref']!=child_ref
         or provenance['prepared_digest']!=task.header[1]or provenance['binding_digest']!=task.header[0]
         or material['selection_original_digest']!=st.header[3]or material['c03_metadata_bridge']!=bridge
         or material['request']['c02_operation_id']!=r.selector.c02_operation_id or material['request']['job_ref']!=selected.cycle_job_ref
         or material['request']['recall_policy_digest']!=_bundle_v3(r).d06_recall.policy_digest
         or material['request']['source_ref']!=r.selector.cue_source_ref or material['request']['c03_selection_ref']!='d06-current:'+st.header[3][:48]
         or material['request']['c03_selection_digest']!=canonical_digest(selected)or provenance['selection_ref']!='d06-current:'+st.header[3][:48]
         or provenance['initiating_self']!=r.evidence.current_self.self_entity_ref):raise AuthorityUnavailable('Ingress C04 native prepared/Root/C03 bridge differs')
        self.c04=p;self._versions(tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in p.read_versions))
        self.tasks.append(('c04_quote',_CommandIngressRowV3(self,'quote','runtime_resource_quotes','quote',(binding.resource_quote_ref,binding.resource_quote_version))))
    
def _finish(self):
    s=self.state;m=s.metadata
    for ref in self.roots:
        key=AtomKey.from_token(ref)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=s.namespace:
            raise AuthorityUnavailable('Foreground ingress declares noncanonical Source roots')
        m.roots.add(ref)
    for (ref,revision),version in self.keys.items():
        if ref not in m.exact:m.exact.add(ref);m.pending.append(ref)
        if revision and(ref,revision)not in m.history_heads:m.catalogue_history_pending.append((ref,revision))
    for identity,entry in self.records.items():
        s.typed_metadata[identity]=entry
        if identity[0]=='graph_domain_production_originals_v1':
            if entry is not None:m.producers.add(identity[2])
    if self.prepared is not None:m.job_ids.add(self.prepared['job_id'])
    if self.c04 is not None:
        from .c04_prepare_service_v3 import c04_prepare_job_id_v3
        m.job_ids.add(c04_prepare_job_id_v3(s.namespace,self.c04.binding.operation_id))
    self.complete=True
    def close_v3(self):
        for _,task in self.tasks:task.close_v3()
        self.state.reader.operation.unregister_retained_state_v3(self)


class _CommandConcernMetadataV3:
    def __init__(self,state):
        self.state=state;self.phase='question';self.complete=False;self.column=None;self.header=None
        self.question=None;self.output_ids=None;self.outputs=[];self.index=0
    def advance(self,meter):
        s=self.state;r=s.reader;s.require_current(meter=meter);s.owner_entry.require_for_v3(r)
        ref=r.request.trigger_original_ref;key=(*r.namespace.as_tuple,'semantic_question',ref)
        row=meter.read_fixed_row(r.db,_D07,('payload_digest','signature'),
            'bot=? AND persona=? AND kind=? AND original_ref=?',key)
        if self.header is None:
            if row is None:raise AuthorityUnavailable('Foreground concern lacks its actual signed trigger question')
            self.header=tuple(row)
            self.column=_CommandLocatorColumnV3(s.metadata,table=_D07,column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),key=key)
            s.columns.add(self.column);return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Foreground concern actual question changed during metadata EOF')
        if not self.column.complete:
            if not self.column.advance(meter):return False
            self.question=self.column.require_v3(s)
            from .d07_execution_v1 import SIGN_KIND
            if self.column.sha256!=self.header[0]:raise AuthorityUnavailable('Foreground concern question canonical EOF differs')
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((r.namespace,'semantic_question',ref,self.header[0])),self.header[1])
            q=self.question
            if q.get('schema')!='d07.artifact-phase-observation-question.v1':
                raise AuthorityUnavailable('Foreground command concern requires its actual Artifact observation question')
            from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v2,ArtifactDraftPhaseSelectorV2
            from .artifact_phase_observation_v1 import artifact_observation_ids_v1,KIND
            selector=artifact_draft_from_wire_v2(q['selector'],ArtifactDraftPhaseSelectorV2)
            ids=artifact_observation_ids_v1(selector,q['condition_id'])
            if(ids['question']!=ref or ids['basis']!=q['observation_basis_ref']
                    or ids['operation']!=r.operation_id or selector.task.c02_operation_id!=r.selector.c02_operation_id
                    or selector.task.namespace!=r.namespace or selector.task.root_registration_ref!=r.selector.draft_root_registration_ref):
                raise AuthorityUnavailable('Foreground concern trigger changed actual typed selector/operation/task')
            s.metadata.roots.update(q['source_refs'])
            s.metadata.signed.add((KIND,q['observation_basis_ref']))
            s.typed_metadata[_D07,'semantic_question',ref]={'projection':q,'payload_digest':self.header[0]}
            from .d07_execution_v1 import d07_execution_ids_v1
            self.output_ids=d07_execution_ids_v1(r.namespace,r.operation_id,'concern')
            self.outputs=[('prepared',self.output_ids['job']),('accounting_prepared',self.output_ids['job'])]
            from ..graph_types import Owner
            for type_id,name in (('runtime.job','job'),('d02.reservation.v1','reservation'),('d02.settlement.v1','settlement')):
                key=AtomKey(Owner('activity',*r.namespace.as_tuple,r.activity_id),type_id,self.output_ids[name])
                if key.token not in s.metadata.exact:s.metadata.exact.add(key.token);s.metadata.pending.append(key.token)
            self.phase='outputs';return False
        if self.index<len(self.outputs):
            kind,outref=self.outputs[self.index]
            header=meter.read_fixed_row(r.db,_D07,('payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,kind,outref))
            if header is not None:raise AuthorityUnavailable('Foreground concern output already exists; recover its actual operation receipt')
            s.typed_metadata[_D07,kind,outref]=None
            self.index+=1;return False
        self.complete=True;return True
    def finalize_v3(self):
        s=self.state;r=s.reader;q=self.question
        from .artifact_phase_observation_v1 import KIND
        basis=s.metadata.originals.get(('life',KIND,q['observation_basis_ref']))
        if basis is None:raise AuthorityUnavailable('Foreground concern lacks actual signed question-producing basis')
        question=basis.get('question')
        if question!=q:raise AuthorityUnavailable('Foreground concern signed basis and actual trigger question metadata differ')
        operation=basis.get('registration_operation_id')
        actual=s.metadata.originals.get(('producer',operation))
        if(actual is None or actual.get('identity',{}).get('phase')!='prepare_artifact_phase_observation_v1'
                or actual.get('provenance',{}).get('artifact_observation_basis')!=basis):
            raise AuthorityUnavailable('Foreground concern trigger lacks actual Domain->Question provenance')
        for name in('task_source_head','task_root_source_head','content_source_head'):
            head=basis[name];key=AtomKey.from_token(head['key'])
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=r.namespace:
                raise AuthorityUnavailable('Foreground concern basis Source heads crossed namespace')
            s.expected_source_versions_v3[key]=head['revision'];s.metadata.roots.add(key.token)
        s.metadata._deadline(q['original_deadline_utc'])
        s.metadata._deadline(basis['original_deadline_utc'])
    def close_v3(self):
        self.column=self.question=self.state=None;self.outputs.clear()

def read_foreground_command_d07_output_v3(db,issuer,namespace,kind,ref):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r not in _STATES or r.operation_kind!='serve_concern':return False,None
    s=_body_state_v3(r)
    if type(s.preparation)is not _CommandConcernMetadataV3 or(kind,ref)not in s.preparation.outputs:return False,None
    if namespace!=r.namespace or issuer is not r.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable('Foreground concern output crossed actual namespace/installed issuer')
    if not db.in_transaction or not r.business_started or r.business_completed:
        raise AuthorityUnavailable('Foreground concern output requires its own actual active WRITE')
    saved=_OUTPUTS.get(r,{}).get((kind,ref))
    if saved is None:return True,None
    from .dispatch_current_inventory_v3 import _detach_value_v3
    digest,signature,value,identity=saved
    if identity!=(s,s.work,r.operation,r.issued.scope,r.selection_digest):
        raise AuthorityUnavailable('Foreground concern output lost actual Work/WRITE identity')
    from .d07_execution_v1 import SIGN_KIND
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,ref,digest)),signature)
    return True,(_detach_value_v3(value),digest)

def register_foreground_command_d07_output_v3(db,issuer,namespace,kind,ref,wire,digest,signature):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r not in _STATES or r.operation_kind!='serve_concern':return False
    s=_body_state_v3(r)
    if type(s.preparation)is not _CommandConcernMetadataV3 or(kind,ref)not in s.preparation.outputs:return False
    if namespace!=r.namespace or issuer is not r.graph._GraphCoordinator__d11_issuer or not db.in_transaction or not r.business_started or r.business_completed:
        raise AuthorityUnavailable('Foreground concern output changed actual installed WRITE')
    from .d07_execution_v1 import SIGN_KIND
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    raw=json.loads(wire)
    if canonical_digest(raw)!=digest:raise AuthorityUnavailable('Foreground actual concern output bytes changed')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,ref,digest)),signature)
    record=(digest,signature,_freeze_value_v3(raw),(s,s.work,r.operation,r.issued.scope,r.selection_digest))
    prior=_OUTPUTS.setdefault(r,{}).get((kind,ref))
    if prior is not None and prior!=record:raise AuthorityUnavailable('Foreground concern reused actual output identity')
    _OUTPUTS[r][kind,ref]=record;return True

def read_bound_foreground_command_concern_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r not in _STATES or operation_kind!='serve_concern':return False,None
    s=_body_state_v3(r);task=s.preparation
    if(namespace!=r.namespace or activity_id!=r.activity_id or request!=r.request
            or type(task)is not _CommandConcernMetadataV3 or not task.complete):
        raise AuthorityUnavailable('Foreground concern plan changed actual completed trigger/Domain provenance')
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d07_source_owner_read_v3 import D07_SOURCE_INVENTORIES_V3
    roots=set(task.question['source_refs'])
    for token,raw in s.metadata.rows.items():
        if AtomKey.from_token(token).type_name in D07_SOURCE_INVENTORIES_V3:
            roots.update(_locator_sources_v3(raw))
    keys=tuple(sorted((AtomKey.from_token(ref)for ref in s.metadata.exact),key=lambda key:key.token))
    return True,production_read_plan_v1(D07_SOURCE_INVENTORIES_V3,keys,tuple(sorted(roots)),
        (r.request.trigger_original_ref,task.question['observation_basis_ref']))

def foreground_command_action_schema_complete_v3(reader):
    if reader not in _STATES:return False
    s=_body_state_v3(reader)
    from .current_method_learning_read_v3 import _ACTION_LOCATORS,ACTION_SCHEMA_LOCATOR_OPERATIONS_V3
    locator=reader.action_schema_locator
    if(reader.operation_kind not in ACTION_SCHEMA_LOCATOR_OPERATIONS_V3 or locator is None or not locator.complete
            or _ACTION_LOCATORS.get(locator)!=locator._identity_v3()
            or reader.selected_plan!=replace(s.plan,exact_keys=tuple(sorted(set((*s.plan.exact_keys,locator.key)),key=lambda key:key.token)))):
        raise AuthorityUnavailable('Foreground action schema extension lacks actual completed same-Work derived-key EOF')
    s.metadata.exact.add(locator.key.token);s.plan=reader.selected_plan;return True

def require_foreground_command_signature_column_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    if type(original)is not MethodJSONColumnV3 or original.owner not in _STATES:return False,None
    s=_body_state_v3(original.owner);original._actual()
    if original.table=='runtime_budget_grants':
        if original.key[0]not in s.original_budget.grants or kind!='budget-grant.v1':
            raise AuthorityUnavailable('Foreground signed Root column escaped actual complete ancestry')
        grant=s.original_budget.grants[original.key[0]]
        if original.key!=(grant.lease_id,grant.version)or signer is not s.reader.graph._GraphCoordinator__d11_issuer._signer:
            raise AuthorityUnavailable('Foreground budget signature changed actual installed lease/version/signer')
        if complete and(not original.complete or signature!=original.signature or verifier is not original.signature_state
                or original.signature_bytes!=original.byte_count):
            raise AuthorityUnavailable('Foreground signed budget column lacks actual whole-byte signature EOF')
        return True,original
    return False,None


def _metadata_graph_keys_v3(raw,namespace):
    result=set()
    def visit(value):
        if type(value)is dict:
            for name in ('key','ref'):
                token=value.get(name)
                if type(token)is str and token.startswith('['):
                    key=AtomKey.from_token(token)
                    if NamespaceId.from_key(key)!=namespace:raise AuthorityUnavailable('Foreground typed metadata Graph locator crossed namespace')
                    result.add(key)
            for child in value.values():
                if type(child)in(dict,list,tuple):visit(child)
        elif type(value)in(list,tuple):
            for child in value:visit(child)
    visit(raw);return result

_METADATA_SIGNATURES=WeakKeyDictionary()

class _CommandSignedMetadataStreamV3:
    def __init__(self,column,inner):self.column,self.inner=column,inner
    def feed(self,chunk,emit):
        self.column.signature_state.update(chunk);self.column.signature_bytes+=len(chunk)
        return self.inner.feed(chunk,emit)
    def finish(self):return self.inner.finish()

class _CommandInputColumnV3(_CommandLocatorColumnV3):
    def __init__(self,key,metadata,*,descriptor,signature):
        if key is not _KEY or descriptor not in metadata.work.registered_input_descriptors:
            raise AuthorityUnavailable('Foreground signed input needs actual private typed descriptor')
        self.descriptor=descriptor;table,kind,ref,producer,field=descriptor
        state=metadata.work
        super().__init__(metadata,table=table,column='payload_json',
            key_columns=('bot','persona','original_ref'),key=(*state.namespace.as_tuple,ref))
        self.signature,self.signature_kind=signature,'d11.d01-production-input.v1'
        self.signer=state.reader.graph._GraphCoordinator__d11_issuer._signer
        self.signature_state=None;self.signature_bytes=0;self.signature_verified=False
        _METADATA_SIGNATURES[self]=(state,descriptor,self.signer,self.signature_kind,signature,state.operation)
        self.signature_state=self.signer.begin_original_stream_verification_v3(self.signature_kind,self)
        self.parser=_CommandSignedMetadataStreamV3(self,self.parser)
    def advance(self,meter):
        if not super().advance(meter):return False
        if not self.signature_verified:
            self.signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
            self.signature_verified=True
        return True

def require_foreground_command_metadata_signature_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(original)is not _CommandInputColumnV3:raise AuthorityUnavailable('Actual private foreground signed metadata column required')
    state=original.metadata.work;state.require_v3()
    if(_METADATA_SIGNATURES.get(original)!=(state,original.descriptor,signer,kind,original.signature,state.operation)
            or signer is not state.reader.graph._GraphCoordinator__d11_issuer._signer or kind!=original.signature_kind
            or original.descriptor not in state.registered_input_descriptors):
        raise AuthorityUnavailable('Foreground input signature changed actual typed descriptor/Work/installed signer')
    if complete and(not original.complete or signature!=original.signature or verifier is not original.signature_state
            or original.signature_bytes!=original.byte_count):
        raise AuthorityUnavailable('Foreground signed input metadata lacks actual whole-byte HMAC EOF')
    return original

class _CommandRegisteredInputMetadataV3:
    def __init__(self,state,descriptor):
        self.state,self.descriptor=state,descriptor;self.header=None;self.column=None;self.roots_column=None
        self.value=None;self.complete=False
    def advance(self,meter):
        s=self.state;s.require_current(meter=meter);table,kind,ref,producer,field=self.descriptor
        key=(*s.namespace.as_tuple,ref)
        row=meter.read_fixed_row(s.db,table,('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',key)
        if self.header is None:
            if row is None or row[0]!=kind:raise AuthorityUnavailable('Foreground values input lacks actual signed typed Original')
            self.header=tuple(row)
            self.column=_CommandInputColumnV3(_KEY,s.metadata,descriptor=self.descriptor,signature=row[3])
            self.roots_column=_CommandMetadataColumnV3(s,table=table,column='source_refs_json',key_columns=('bot','persona','original_ref'),key=key)
            s.columns.update((self.column,self.roots_column));return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Foreground registered input changed actual header during EOF')
        if not self.column.complete:
            self.column.advance(meter);return False
        if not self.roots_column.complete:
            self.roots_column.advance(meter);return False
        if self.column.sha256!=self.header[2]:raise AuthorityUnavailable('Foreground registered input lacks actual canonical SHA EOF')
        raw=self.column.require_v3(s);roots=self.roots_column.require_v3(s)
        m=s.metadata;m.roots.update(roots);m.roots.update(_locator_sources_v3(raw));m.producers.add(self.header[1])
        for key in _metadata_graph_keys_v3(raw,s.namespace):
            if key.token not in m.exact:m.exact.add(key.token);m.pending.append(key.token)
        m._fixed_original_edges(raw)
        s.typed_metadata[table,kind,ref]={'projection':raw,'payload_digest':self.header[2],
            'producer':self.header[1],'source_roots':tuple(roots),'descriptor':self.descriptor}
        self.value=raw;self.complete=True;return True
    def require_producer_v3(self):
        s=self.state;m=s.metadata;table,kind,ref,producer_kind,field=self.descriptor
        original=m.originals.get(('producer',self.header[1]))
        if(original is None or original.get('identity',{}).get('phase')!=producer_kind
                or original.get('request',{}).get(field)!=ref):
            raise AuthorityUnavailable('Foreground values input has no exact actual freezing Domain producer')
        bound={v.key.token for v in s.producer_versions[self.header[1]]if v.key.type_name=='memory.source'}
        if not set(s.typed_metadata[table,kind,ref]['source_roots'])<=bound:
            raise AuthorityUnavailable('Foreground values input Source closure differs from actual producer readset')
