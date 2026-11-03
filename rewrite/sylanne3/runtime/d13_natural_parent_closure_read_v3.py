"""Fresh metadata-only Source/Owner Work for an immutable no-review disposition."""
from dataclasses import fields, is_dataclass
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..memory_types import source_key, access_key
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from ..runtime_storage_v3 import (runtime_storage_v3, runtime_storage_quantum_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3, RuntimeCellReadV3)
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

KIND = 'd13_natural_parent_closure_read_v3'
_READERS = WeakKeyDictionary()
_PREPARED = WeakKeyDictionary()
_PENDING = WeakKeyDictionary()
_METADATA = WeakKeyDictionary()
_ISSUER = object()


def _metadata_heap_v3(value, seen=None):
    from sys import getsizeof
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = getsizeof(value)
    if is_dataclass(value):
        return size + sum(_metadata_heap_v3(getattr(value, field.name), seen) for field in fields(value))
    if type(value) is dict:
        return size + sum(_metadata_heap_v3(key, seen) + _metadata_heap_v3(item, seen) for key, item in value.items())
    if type(value) in (tuple, list):
        return size + sum(_metadata_heap_v3(item, seen) for item in value)
    return size


class _MetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, owner, **arguments):
        super().__init__(owner, **arguments)
        if self.cell is not None:
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            if self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
                raise AuthorityUnavailable('parent cleanup metadata has another canonical codec')
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')


class D13NaturalParentClosureReadV3:
    def __init__(self, graph, bootstrap, candidate, root_entry):
        from ..runtime_context import require_d13_natural_parent_closure_root_entry_v3
        require_graph_storage_work_admission_v3(graph)
        entry = require_d13_natural_parent_closure_root_entry_v3(root_entry, graph, candidate=candidate)
        if bootstrap is not entry.bootstrap:
            raise AuthorityUnavailable('parent cleanup requires its actual Root READ entry')
        self.graph, self.bootstrap, self.root_entry = graph, bootstrap, entry
        self.store, self.db = graph._GraphCoordinator__store, graph._GraphCoordinator__store._db
        self.namespace, self.port, self.bundle = entry.namespace, entry.port, entry.bundle
        self.control_port = graph._GraphCoordinator__d13_cache_use_control_v2
        from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlPortV2
        if (type(self.control_port) is not InstalledD13CacheUseControlPortV2
                or self.control_port._actual().fence_port is not self.port or self.control_port.bundle is not self.bundle):
            raise AuthorityUnavailable('parent cleanup requires its actual installed D13 control port')
        self.operation, self.fence = entry.operation, entry.fence
        self.scope = self.read_scope = self.fence.scope
        self.authority, self.lease = entry.authority, entry.lease
        self.handle, self.selection_digest = self.operation.handle, self.operation.selection_digest
        from ..authority_service.d13_cache_use_contract_v2 import D13NaturalParentClosureCandidateV4
        self.candidate = candidate
        self.is_v4 = type(candidate) is D13NaturalParentClosureCandidateV4
        self.parent_original_id = candidate.parent_original_id if self.is_v4 else candidate[0]
        self.owner_ref = candidate.owner_ref if self.is_v4 else candidate[2]
        self.review_header = None
        self.readiness_metadata = None
        self.source_group_requirements = {}
        self.graph_stamp = (self.fence.metadata, self.fence.epoch)
        self.query = QueryEpoch(self.namespace, 'all', self.graph_stamp[1].revision)
        self.work = None
        self.original = self.seal = self.plan = self.metadata_seal = self.scoped = None
        self.versions, self.generation_header, self.scope_header, self.ingress_header = {}, None, None, None
        self.owner_entry = self.owner_binding = self.owner_guard = None
        self.groups = ()
        self.heads, self.columns, self.source_inspection_tasks, self.sources, self.access_atoms = {}, {}, {}, {}, {}
        self.pending, self.current, self.metadata_queue = [], None, []
        self.cell = self.parser = self.semantic_decoder = self.semantic_hash = None
        self.fragment, self.offset, self.position = b'', 0, 0
        self.eofs, self.metadata_row = [], None
        self.phase, self.complete, self.qualified, self.released = 'original', False, False, False
        self.receipt = self.result = None
        _READERS[self] = (graph, entry, candidate, self.operation, self.scope, self.selection_digest, self.graph_stamp)
        self.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return 65536 + _metadata_heap_v3((self.original, self.plan, self.seal, self.heads, self.columns,
            tuple(tuple(source.metadata.items()) for source in self.sources.values()), self.access_atoms,
            self.pending, self.metadata_queue, self.eofs, self.metadata_row, self.fragment,
            self.scoped, self.versions, self.generation_header, self.scope_header, self.ingress_header,
            self.review_header, self.source_group_requirements, self.readiness_metadata)) + (
            0 if self.parser is None else self.parser._source_heap_bytes())

    def fixed_v3(self, meter, table, columns, where, parameters):
        from .c09_paged_sql_v2 import _quote
        lengths = self.db.execute('SELECT ' + ','.join('length(CAST(' + _quote(c) + ' AS BLOB))' for c in columns)
            + ' FROM ' + _quote(table) + ' WHERE ' + where + ' LIMIT 1', parameters).fetchone()
        if lengths is None:
            self.metadata_row = None
            self.operation.refresh_retained_state_v3(self)
            return None
        amount = sum(value or 0 for value in lengths)
        meter.require_available(amount + 256)
        growth = amount * 12 + 4096
        if growth > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('parent cleanup fixed metadata exceeds its actual arena')
        self.operation.reserve_retained_state_growth_v3(self, growth)
        try:
            self.metadata_row = meter.read_fixed_row(self.db, table, columns, where, parameters)
            return self.metadata_row
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def require_current_v3(self, meter=None):
        return require_actual_d13_natural_parent_closure_reader_v3(self, meter=meter)

    def _head_v3(self, meter, key):
        row = self.fixed_v3(meter, 'graph_atoms', ('revision', 'valid', 'value_cell_id'),
            'bot=? AND persona=? AND token=?', (*self.namespace.as_tuple, key.token))
        self.heads[key.token] = row
        return row

    def _start_column_v3(self, tag, table, column, keys, key, cell_id=None):
        self.current = (tag, _MetadataColumnV3(self, table=table, column=column,
            key_columns=keys, key=key, cell_id=cell_id))

    def _advance_column_v3(self, meter):
        if self.current is None:
            return True
        tag, column = self.current
        if not column.advance(meter):
            return False
        self.columns[tag] = (column, column.require_v3(self))
        self.current = None
        return True

    def _waiting_v4(self, reason, state_digest):
        from ..authority_service.d13_cache_use_contract_v2 import D13NaturalParentClosureWaitingV4
        original = self.original
        waiting = D13NaturalParentClosureWaitingV4(self.namespace, original.authority_namespace,
            original.authority_id, original.installation_id, original.activation_generation,
            self.candidate, reason, state_digest, self.operation.operation_id)
        self.complete = True
        self.result = PreparedD13NaturalParentClosurePendingV4(_ISSUER, self, waiting)
        self.phase = 'complete'

    def _readiness_v4(self):
        original = self.original
        if original.waiting_reason is not None:
            self._waiting_v4(original.waiting_reason, original.waiting_state_digest)
            return
        if (original.arm != 'review_parent' or original.permanent_disposition is not None
                or original.review_verdict is not None and original.review_verdict.verdict in ('rewrite','hold')):
            self.phase = 'metadata'
            return
        if original.review_verdict is None:
            raise AuthorityUnavailable('ready review metadata lacks its actual verdict or permanent disposition')
        from ..host.v2_fence_port import require_natural_roster_metadata_rpc_v3
        from .natural_roster_metadata_read_v3 import _decode_roster_metadata_rpc_v3
        rpc = self.port.read_natural_roster_metadata_v3(namespace=self.namespace,
            authority_namespace=self.scope.authority_namespace, parent_original_id=self.parent_original_id)
        raw, port, namespace, authority_namespace, installation, parent = require_natural_roster_metadata_rpc_v3(
            rpc, port=self.port)
        capsule, head, locators, headers, core_refs, facts, stamp, selection = _decode_roster_metadata_rpc_v3(
            raw, namespace=self.namespace, authority_namespace=self.scope.authority_namespace,
            installation_id=original.installation_id, parent_original_id=self.parent_original_id)
        if (capsule != original.parent_input or selection != self.selection_digest
                or stamp != (self.graph_stamp[0].graph_revision, self.graph_stamp[1].revision)):
            raise AuthorityUnavailable('parent readiness changed its actual selected capsule/Graph snapshot')
        basis = (self.candidate, capsule.input_digest, core_refs, stamp, selection,
            None if head is None else (head[1], head[2].identity_manifest_digest,
                tuple((child.operation_id,child.effect_id,child.continuation_state) for child in head[2].children)))
        self.readiness_metadata = raw
        self.operation.refresh_retained_state_v3(self)
        if head is not None and any(child.continuation_state in ('cancelled','superseded') for child in head[2].children):
            self.phase = 'metadata'
            return
        effects = tuple(self.port.read_current_effect(namespace=self.namespace,
            authority_namespace=self.scope.authority_namespace, effect_id=child[2])
            for child in capsule.child_identities)
        self.readiness_metadata = (raw, effects)
        self.operation.refresh_retained_state_v3(self)
        if any(effect.state not in ('absent','observed') or effect.state == 'observed'
                and effect.observation_outcome not in ('accepted','delivered') for effect in effects):
            raise AuthorityUnavailable('parent readiness has an unresolved/unknown actual child effect')
        if head is None:
            if any(effect.state != 'absent' for effect in effects):
                raise AuthorityUnavailable('actual observed parent child has no signed/selected roster metadata')
            self._waiting_v4('roster_pending', canonical_digest(('d13.actual-roster-pending.v4',basis,effects)))
            return
        if any(effect.state == 'absent' for effect in effects):
            self._waiting_v4('child_not_started',canonical_digest(('d13.actual-child-not-started.v4',
                basis,effects)))
            return
        observations = tuple(self.port.read_current_observation_receipt_v1(namespace=self.namespace,
            authority_namespace=self.scope.authority_namespace, effect_id=child[2])
            for child in capsule.child_identities)
        self.readiness_metadata = (raw, effects, observations)
        self.operation.refresh_retained_state_v3(self)
        missing = []
        with self.store._lock:
            if self.db.in_transaction:
                raise AuthorityUnavailable('parent readiness cannot inherit Graph SQL')
            self.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(self.db) as meter:
                    self.require_current_v3(meter)
                    for child, observation in zip(capsule.child_identities, observations):
                        from ..authority_service.observation_refinement_contract_v3 import observation_platform_observation_v3
                        binding = observation_platform_observation_v3(observation).binding
                        if (binding.origin.operation_id, binding.origin.effect_id) != child[1:]:
                            raise AuthorityUnavailable('parent readiness observation replaced its actual child identity')
                        digest = canonical_digest(observation)
                        adopted = self.fixed_v3(meter,'graph_d13_outbound_observations_v1',
                            ('original_digest',),'bot=? AND persona=? AND final_operation_id=? AND observation_digest=?',
                            (*self.namespace.as_tuple,child[1],digest))
                        if adopted is None:
                            missing.append((child[1],digest))
            finally:
                self.db.rollback()
        if missing:
            self._waiting_v4('outbound_adoption_pending',canonical_digest(('d13.actual-adoption-pending.v4',
                basis,effects,tuple(canonical_digest(value) for value in observations),tuple(missing))))
            return
        self.readiness_metadata = None
        self.phase = 'metadata'

    def _generation_locator_v3(self):
        if not self.is_v4 or self.original.arm == 'pre_review':
            original = self.original.parse_original
            return (original.parent_original_id, original.generation_job_id, original.generation_original_id,
                original.generation_original_digest, original.plan_ref, original.plan_revision,
                original.first_operation_id, original.first_effect_id)
        capsule, generation = self.original.parent_input, self.original.generation_registration
        return (capsule.parent_original_id, generation.original_locator.job_id, capsule.generation_original_id,
            capsule.generation_original_digest, capsule.plan_ref, capsule.plan_revision,
            capsule.first_operation_id, capsule.first_effect_id)

    def _metadata_v3(self, meter):
        parent, job, original_id, digest, plan_ref, plan_revision, first_operation, first_effect = self._generation_locator_v3()
        key = (*self.namespace.as_tuple, parent)
        row = self.fixed_v3(meter, 'graph_natural_generation_preparations_v2',
            ('job_id', 'original_operation_id', 'state', 'graph_epoch', 'access_epoch', 'deletion_epoch'),
            'bot=? AND persona=? AND parent_original_id=?', key)
        if row is None or row[:2] != (job, original_id) or row[2] not in ('acquired', 'terminal'):
            raise AuthorityUnavailable('parent cleanup generation metadata differs from its actual Core original')
        pkey = AtomKey.from_token(plan_ref)
        from ..domains.d08.natural_plan import NATURAL_PLAN_TYPE_V2
        if pkey.type_name != NATURAL_PLAN_TYPE_V2 or (pkey.owner.bot, pkey.owner.persona) != self.namespace.as_tuple:
            raise AuthorityUnavailable('parent cleanup original does not locate its exact metadata plan')
        head = self._head_v3(meter, pkey)
        if head is None or head[:2] != (plan_revision, 1) or head[2] is None:
            raise AuthorityUnavailable('parent cleanup actual plan revision is unavailable')
        self.generation_header = row
        self.scope_header = self.fixed_v3(meter, 'graph_natural_generation_scopes_v2',
            ('original_seal_digest',), 'bot=? AND persona=? AND parent_original_id=?', key)
        if self.scope_header is None:
            raise AuthorityUnavailable('parent cleanup has no actual original Source group metadata')
        self.metadata_queue = [('seal', 'graph_natural_generation_preparations_v2', 'seal_json',
            ('bot', 'persona', 'parent_original_id'), key, None),
            ('plan', 'graph_atoms', 'value', ('token',), (pkey.token,), head[2]),
            ('reads', 'graph_natural_generation_preparations_v2', 'read_versions_json',
                ('bot', 'persona', 'parent_original_id'), key, None),
            ('queries', 'graph_natural_generation_preparations_v2', 'query_epochs_json',
                ('bot', 'persona', 'parent_original_id'), key, None),
            ('scope', 'graph_natural_generation_scopes_v2', 'proof_json',
                ('bot', 'persona', 'parent_original_id'), key, None)]
        if self.is_v4 and self.original.arm == 'review_parent':
            capsule, review = self.original.parent_input, self.original.registration
            self.review_header = self.fixed_v3(meter, 'graph_natural_review_preparations_v2',
                ('job_id', 'original_operation_id', 'state', 'typed_request_digest',
                    'terminal_receipt_digest', 'terminal_output_digest'),
                'bot=? AND persona=? AND parent_original_id=?', key)
            if (self.review_header is None or self.review_header[:2] !=
                    (review.original_locator.job_id, capsule.review_original_id)
                    or self.review_header[2] not in ('acquired', 'terminal')):
                raise AuthorityUnavailable('parent cleanup review metadata differs from its actual input capsule')
            self.metadata_queue.append(('review_seal', 'graph_natural_review_preparations_v2', 'seal_json',
                ('bot', 'persona', 'parent_original_id'), key, None))
        self.phase = 'metadata_columns'

    def _bind_metadata_v3(self):
        from .natural_reply_job_v2 import _seal
        from ..domains.d08.natural_plan import decode_natural_plan_v2, natural_plan_id_v2
        parent, job, original_id, digest, plan_ref, plan_revision, first_operation, first_effect = self._generation_locator_v3()
        self.seal = _seal('generation', self.columns['seal'][1])
        self.plan = decode_natural_plan_v2(self.columns['plan'][1])
        seal, plan = self.seal, self.plan
        if (seal.namespace != self.namespace or seal.c02_operation_id != parent
                or canonical_digest(seal) != digest or (seal.job_id, seal.original_operation_id) != (job, original_id)
                or plan.c02_operation_id != parent
                or (plan.final_operation_id, plan.final_effect_id) != (first_operation, first_effect)
                or plan.source_ref.ref != seal.source_ref
                or plan.plan_id != natural_plan_id_v2(self.namespace, parent, plan.source_ref.ref)):
            raise AuthorityUnavailable('parent cleanup exact seal/plan/Core lineage differs')
        if not self.is_v4 or self.original.arm == 'pre_review':
            parse = self.original.parse_original
            if (seal.call_id, seal.frozen_input_digest) != (parse.generation_call_id, parse.frozen_input_digest):
                raise AuthorityUnavailable('parent cleanup actual parse call/frozen commitment differs')
        else:
            capsule, registration = self.original.parent_input, self.original.registration
            review = _seal('review', self.columns['review_seal'][1])
            if (canonical_digest(review) != capsule.review_original_digest or review.namespace != self.namespace
                    or review.installation_id != self.original.installation_id
                    or (review.job_id, review.original_operation_id) !=
                        (registration.original_locator.job_id, capsule.review_original_id)
                    or (review.generation_original_operation_id, review.generation_call_id,
                        review.generation_frozen_input_digest, review.generation_output_digest) !=
                        (seal.original_operation_id, seal.call_id, seal.frozen_input_digest, capsule.whole_output_digest)):
                raise AuthorityUnavailable('parent cleanup review seal/capsule/actual generation transfer differs')
            verdict = self.original.review_verdict
            if verdict is not None and (self.review_header[3] != verdict.typed_model_request_digest
                    or self.review_header[2] == 'terminal' and self.review_header[4:] !=
                        (verdict.terminal_receipt_digest, verdict.review_output_digest)):
                raise AuthorityUnavailable('parent cleanup review terminal metadata differs from its actual verdict')
        from .natural_scoped_query_proof_v2 import natural_scoped_query_proof_from_wire_v2
        from .natural_reply_job_v2 import natural_graph_guard_digest_v2
        self.scoped = natural_scoped_query_proof_from_wire_v2(self.columns['scope'][1])
        scope = self.scoped.scope
        reads = tuple(GraphVersion(AtomKey.from_token(row['key']), row['revision']) for row in self.columns['reads'][1])
        queries = tuple(QueryEpoch(NamespaceId(**row['namespace']), row['scope_ref'], row['revision'])
            for row in self.columns['queries'][1])
        guard = natural_graph_guard_digest_v2(self.namespace, reads, queries,
            graph_epoch=self.generation_header[3], access_epoch=self.generation_header[4],
            deletion_epoch=self.generation_header[5])
        self.versions = {row.key.token: row.revision for row in reads}
        if (len(self.versions) != len(reads) or scope.namespace != self.namespace
                or self.scope_header != (self.columns['seal'][0].sha256,)
                or guard != seal.original_graph_guard_digest
                or scope.audience_id != plan.audience_id or scope.scene_ref != plan.scene_id
                or scope.account_binding_ref != plan.audience_ref.ref
                or any(self.versions.get(item.token) != item.revision for item in self.scoped.d06_closure)):
            raise AuthorityUnavailable('parent cleanup original scoped Source group/readset differs from its actual plan/seal')
        source_union = tuple(sorted(row.key.token for row in reads if row.key.type_name == 'memory.source'))
        if not {*scope.source_roots, seal.source_ref}.issubset(source_union):
            raise AuthorityUnavailable('parent cleanup original complete Source union is absent')
        # This is the saved complete closure, including ancestors; it is not
        # a new ordinary FULL or P2 request for up to 32 direct roots.
        if not source_union or len(source_union) > 256:
            raise AuthorityUnavailable('parent cleanup Source union exceeds its original closure bound')
        for ref in source_union:
            key = AtomKey.from_token(ref)
            if key != source_key(*self.namespace.as_tuple, key.owner.subject):
                raise AuthorityUnavailable('parent cleanup Source metadata crossed namespace')
        self.groups = (('expression', (scope.audience_id,), source_union),)
        self.phase = 'ingress_header'

    def _ingress_header_v3(self, meter):
        from .ingress_observation import ingress_ids
        sid = AtomKey.from_token(self.seal.source_ref).owner.subject
        self.ingress_operation_id = ingress_ids(sid)[2]
        key = (*self.namespace.as_tuple, self.ingress_operation_id)
        self.ingress_header = self.fixed_v3(meter, 'graph_first_ingress_identity_v1',
            ('source_ref', 'platform_ref', 'conversation_ref', 'sender_ref', 'message_id', 'visibility',
                'content_fingerprint', 'learned_at', 'bundle_digest'),
            'bot=? AND persona=? AND operation_id=?', key)
        if self.ingress_header is None:
            raise AuthorityUnavailable('parent cleanup original committed ingress metadata is absent')
        observed = self.fixed_v3(meter, 'ingress_first_observations',
            ('content_fingerprint', 'learned_at', 'bundle_digest'), 'bot=? AND persona=? AND operation_id=?', key)
        committed = self.fixed_v3(meter, 'graph_bundle_operations', ('digest',),
            'bot=? AND persona=? AND operation_id=?', key)
        scope = self.scoped.scope
        from .first_ingress_v2 import scene_ref_for_conversation
        if (scene_ref_for_conversation(self.namespace, self.ingress_header[1], self.ingress_header[2]) != scope.scene_ref
                or self.ingress_header[:4] != (sid, scope.platform_ref, scope.audience_id, scope.sender_ref)
                or self.ingress_header[5] != 'private' or observed != self.ingress_header[6:9]
                or committed != (self.ingress_header[8],)):
            raise AuthorityUnavailable('parent cleanup original Source group is not the actual committed private ingress')
        self.metadata_queue = [
            ('ingress_identity', 'graph_first_ingress_identity_v1', 'identity_json',
                ('bot', 'persona', 'operation_id'), key, None),
            ('ingress_intent', 'graph_first_ingress_intents_v2', 'identity_json',
                ('bot', 'persona', 'operation_id'), key, None)]
        self.phase = 'ingress_columns'

    def _bind_ingress_v3(self):
        identity, intent = self.columns['ingress_identity'][1], self.columns['ingress_intent'][1]
        header = self.ingress_header
        if (type(identity) is not dict or set(identity) != {'schema', 'namespace', 'operation_id',
                'source_ref', 'platform_ref', 'conversation_ref', 'sender_ref', 'message_id', 'visibility', 'lineage'}
                or identity['schema'] != 'sylanne3.ingress.identity.v1'
                or identity['namespace'] != list(self.namespace.as_tuple)
                or identity['operation_id'] != self.ingress_operation_id
                or tuple(identity[name] for name in ('source_ref', 'platform_ref', 'conversation_ref',
                    'sender_ref', 'message_id', 'visibility')) != header[:6]
                or type(intent) is not dict or intent.get('fingerprint') != header[6]):
            raise AuthorityUnavailable('parent cleanup canonical ingress identity/intent EOF differs')
        self.metadata_seal = (self.original,
            tuple((tag, column, column.sha256, column.byte_count) for tag, (column, value) in self.columns.items()),
            self.scoped, tuple(sorted(self.versions.items())), self.generation_header,
            self.scope_header, self.ingress_header, tuple(self.heads.items()), self.review_header, self.groups)
        _METADATA[self] = self.metadata_seal
        self.phase = 'owner'

    def _sources_v3(self, meter):
        from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
        from ..domains.d06 import source_correction_head_key
        if not self.pending:
            self._acyclic_v3()
            self.qualified = True
            self.phase = 'source_cell'
            return
        ref = self.pending[-1]
        if ref in self.sources:
            self.pending.pop()
            return
        if len(self.sources) >= 256:
            raise AuthorityUnavailable('parent cleanup Source ancestry exceeds its original bound')
        key = AtomKey.from_token(ref)
        task = self.source_inspection_tasks.get(ref)
        if task is None:
            correction = source_correction_head_key(self.namespace, key.owner.subject)
            if self._head_v3(meter, correction) is not None:
                raise AuthorityUnavailable('parent cleanup Source correction is pending')
            self.source_inspection_tasks[ref] = InspectionMetadataReadV3(self, key)
            return
        if not task.advance(meter):
            return
        original = task.result.require_v3(self, meter)
        if not original.valid:
            raise AuthorityUnavailable('parent cleanup Source metadata is invalid')
        self.heads[ref] = (original.revision, 1, original.cell_id)
        akey = access_key(*self.namespace.as_tuple, key.owner.subject)
        head = self._head_v3(meter, akey)
        if head is None or head[1] != 1 or head[2] is None:
            raise AuthorityUnavailable('parent cleanup current Source access is absent')
        self._start_column_v3(('access', ref), 'graph_atoms', 'value', ('token',), (akey.token,), head[2])
        self.phase = 'access'

    def _access_v3(self, meter):
        if not self._advance_column_v3(meter):
            return
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        ref = self.pending.pop()
        original = self.source_inspection_tasks[ref].result.require_v3(self, meter)
        key = original.key
        source = SimpleNamespace(key=key, revision=original.revision, valid=True, metadata=original.metadata)
        akey = access_key(*self.namespace.as_tuple, key.owner.subject)
        head = self.heads[akey.token]
        access = GraphAtom(akey, head[0], self.columns[('access', ref)][1], True)
        from ..domains.d06 import source_correction_head_key
        correction = source_correction_head_key(self.namespace, key.owner.subject)
        requirements = self.source_group_requirements[ref]
        if (self.versions.get(ref) != original.revision or self.versions.get(akey.token) != head[0]
                or self.versions.get(correction.token) != 0
                or any(_qualify_source_rights_values_v3(self.namespace, ref, source, access, None,
                    audience=audience, purpose=purpose, metadata_only=True) is None
                    for purpose, audience in requirements)):
            raise AuthorityUnavailable('parent cleanup Source original versions/current purpose/audience ALL are unavailable')
        self.sources[ref], self.access_atoms[ref] = source, access
        for parent in original.metadata['parent_source_ids']:
            token = source_key(*self.namespace.as_tuple, parent).token
            prior = self.source_group_requirements.setdefault(token, set())
            changed = not requirements <= prior
            prior.update(requirements)
            if changed and token in self.sources:
                self.sources.pop(token); self.access_atoms.pop(token)
            if token not in self.sources:
                self.pending.append(token)
        self.phase = 'sources'

    def _acyclic_v3(self):
        active, done = set(), set()
        def visit(ref):
            if ref in active:
                raise AuthorityUnavailable('parent cleanup Source ancestry is cyclic')
            if ref in done:
                return
            active.add(ref)
            for parent in self.sources[ref].metadata['parent_source_ids']:
                visit(source_key(*self.namespace.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
        for purpose, audiences, roots in self.groups:
            for ref in roots:
                visit(ref)

    def _source_all_v3(self, meter):
        from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
        from .d13_natural_original_sources_v3 import _NaturalOriginalSourceAllReadV3
        refs = tuple(sorted(self.sources))
        if self.position == len(refs):
            self.phase = 'close'
            return
        original = self.source_inspection_tasks[refs[self.position]].result.require_v3(self, meter)
        if self.phase == 'source_cell':
            import codecs
            from hashlib import sha256
            self.cell = RuntimeCellReadV3(self.handle, original.cell_id,
                erasure_owner_ref=original.key.token, meter=meter)
            if tuple(self.cell.header) != original.header or self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
                raise AuthorityUnavailable('parent cleanup qualified Source cell changed')
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')
            self.semantic_decoder = codecs.getincrementaldecoder('utf-8')('strict') if self.cell.header[0] == 'canonical-json.utf8.v1' else None
            self.semantic_hash = sha256() if self.semantic_decoder is not None else None
            self.fragment, self.offset, self.phase = b'', 0, 'source_all'
            return
        if self.offset < len(self.fragment):
            end = min(self.offset + 1024, len(self.fragment))
            fragment = self.fragment[self.offset:end]
            self.parser.feed(fragment, lambda event: None)
            _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self, fragment, meter)
            self.offset = end
            return
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.offset = fragment, 0
            return
        parsed, digest = self.parser.finish(), self.cell.finish(meter=meter)
        _NaturalOriginalSourceAllReadV3._semantic_body_fragment_v3(self, b'', meter, final=True)
        semantic = digest if self.semantic_hash is None else self.semantic_hash.hexdigest()
        metadata = {name: tuple(value) if type(value) is list else value for name, value in self.parser._source_metadata.items()}
        if ((parsed.sha256, parsed.byte_count) != (digest, original.header[3])
                or digest != original.payload_sha256 or semantic != original.semantic_digest
                or metadata != dict(original.metadata)):
            raise AuthorityUnavailable('parent cleanup qualified Source whole canonical EOF differs')
        self.eofs.append((original.key.token, digest, parsed.byte_count))
        self.cell = self.parser = self.semantic_decoder = self.semantic_hash = None
        self.fragment, self.offset, self.phase = b'', 0, 'source_cell'
        self.position += 1

    def advance_v3(self, meter):
        self.require_current_v3(meter)
        if self.phase == 'metadata':
            self._metadata_v3(meter)
        elif self.phase == 'metadata_columns':
            if not self._advance_column_v3(meter):
                return
            if self.metadata_queue:
                tag, table, column, keys, key, cell = self.metadata_queue.pop(0)
                self._start_column_v3(tag, table, column, keys, key, cell)
            else:
                self._bind_metadata_v3()
        elif self.phase == 'ingress_header':
            self._ingress_header_v3(meter)
        elif self.phase == 'ingress_columns':
            if not self._advance_column_v3(meter):
                return
            if self.metadata_queue:
                tag, table, column, keys, key, cell = self.metadata_queue.pop(0)
                self._start_column_v3(tag, table, column, keys, key, cell)
            else:
                self._bind_ingress_v3()
        elif self.phase == 'sources':
            self._sources_v3(meter)
        elif self.phase == 'access':
            self._access_v3(meter)
        elif self.phase in ('source_cell', 'source_all'):
            if not self.qualified or self.owner_binding is None:
                raise AuthorityUnavailable('parent cleanup Source ALL lacks its actual prior Owner/ancestry qualification')
            self.owner_entry.require_for_v3(self)
            self._source_all_v3(meter)
        else:
            raise AuthorityUnavailable('parent cleanup metadata phase is not registered')
        self.operation.refresh_retained_state_v3(self)

    def release_payload_v3(self):
        if self.released:
            return
        if self.owner_entry is not None:
            self.owner_entry.release_v3()
            self.owner_entry = self.owner_binding = self.owner_guard = None
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
        release_inspection_metadata_owner_v3(self)
        for column, value in self.columns.values():
            from .dispatch_initial_source_read_v3 import _COLUMNS
            _COLUMNS.pop(column, None)
        self.columns.clear()
        self.sources.clear()
        self.source_inspection_tasks.clear()
        self.heads.clear()
        self.access_atoms.clear()
        self.cell = self.parser = self.current = self.original = self.plan = self.seal = self.metadata_seal = None
        self.pending.clear()
        self.metadata_queue.clear()
        self.eofs.clear()
        self.versions.clear()
        self.scoped = self.generation_header = self.scope_header = self.ingress_header = None
        self.groups = ()
        self.review_header = self.readiness_metadata = None
        self.source_group_requirements.clear()
        self.metadata_row = self.semantic_decoder = self.semantic_hash = self.receipt = self.result = None
        self.fragment = b''
        _READERS.pop(self, None)
        _METADATA.pop(self, None)
        self.operation.unregister_retained_state_v3(self)
        self.released = True


def require_actual_d13_natural_parent_closure_reader_v3(reader, *, meter=None):
    from ..runtime_context import require_d13_natural_parent_closure_root_entry_v3
    from ..graph_worker import GraphStorageWorkV3
    if (type(reader) is not D13NaturalParentClosureReadV3
            or _READERS.get(reader) != (reader.graph, reader.root_entry, reader.candidate,
                reader.operation, reader.scope, reader.selection_digest, reader.graph_stamp)
            or reader.released or reader.operation.closed or type(reader.work) is not GraphStorageWorkV3
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.kind != KIND or reader.work.coordinator is not reader.graph
            or reader.work.operation_id != reader.operation.operation_id
            or reader.work.selection_digest != reader.selection_digest
            or reader.work.deadline_utc != reader.operation.deadline_utc
            or reader.operation is not reader.root_entry.operation
            or reader.fence is not reader.root_entry.fence
            or reader.authority is not reader.root_entry.authority or reader.lease is not reader.root_entry.lease
            or reader.bundle is not reader.root_entry.bundle or reader.port is not reader.root_entry.port
            or reader.namespace != reader.root_entry.namespace
            or reader.control_port is not reader.graph._GraphCoordinator__d13_cache_use_control_v2
            or reader.control_port._actual().fence_port is not reader.port
            or runtime_storage_v3(reader.db) is not reader.handle
            or reader.scope.operation != 'read' or reader.scope.permit.operation != 'read'
            or reader.fence.scope is not reader.scope or reader.scope.operation_id != reader.operation.operation_id):
        raise AuthorityUnavailable('parent cleanup lost its actual Root/Work/original READ identity')
    require_d13_natural_parent_closure_root_entry_v3(reader.root_entry, reader.graph, candidate=reader.candidate)
    if not reader.complete:
        reader.work._require_invocation(reader.graph)
    if meter is not None:
        if reader.graph._v2_graph_stamp(reader.namespace) != reader.graph_stamp:
            raise AuthorityUnavailable('parent cleanup Source metadata stamp changed')
        from .graph_d13_cache_use_collection_v2 import require_current_metadata_heads_v3
        require_current_metadata_heads_v3(reader.db, reader.namespace, reader.heads, meter, None)
    return reader


def require_current_d13_natural_parent_closure_owner_reader_v3(reader):
    r = require_actual_d13_natural_parent_closure_reader_v3(reader)
    seal = _METADATA.get(r)
    if (seal is None or seal != r.metadata_seal or r.groups != seal[-1]
            or r.original is not seal[0] or r.scoped is not seal[2]
            or tuple(sorted(r.versions.items())) != seal[3]
            or (r.generation_header, r.scope_header, r.ingress_header) != seal[4:7]
            or r.review_header != seal[-2]):
        raise AuthorityUnavailable('parent cleanup Owner requires its sealed parse/plan Source groups')
    return r.graph, r.port, r.bundle, r.scope, r.groups


def natural_parent_closure_metadata_identity_v3(reader):
    require_current_d13_natural_parent_closure_owner_reader_v3(reader)
    return _METADATA[reader]


class PreparedD13NaturalParentClosurePendingV4:
    def __init__(self, issuer, reader, waiting):
        if issuer is not _ISSUER or not reader.is_v4 or reader.original is None:
            raise AuthorityUnavailable('actual V4 independently checked waiting producer required')
        self.graph, self.namespace, self.parent_original_id = reader.graph, reader.namespace, reader.parent_original_id
        self.waiting = waiting
        _PENDING[self] = (self.graph, self.namespace, self.parent_original_id, waiting)

    def consume_pending_v4(self, graph, namespace, parent_original_id):
        if _PENDING.get(self) != (graph, namespace, parent_original_id, self.waiting):
            raise AuthorityUnavailable('waiting metadata belongs to another actual Root Work/parent')
        return self.waiting

    def release_payload_v3(self):
        _PENDING.pop(self, None)


class PreparedD13NaturalParentClosureV3:
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or reader.receipt is None:
            raise AuthorityUnavailable('parent closure requires its actual Core close ACK')
        self.namespace, self.parent_original_id = reader.namespace, reader.parent_original_id
        self.receipt = reader.receipt
        self.graph = reader.graph
        _PREPARED[self] = (self.graph, self.namespace, self.parent_original_id, self.receipt)

    def close_v3(self, graph, namespace, parent_original_id):
        if _PREPARED.get(self) != (graph, namespace, parent_original_id, self.receipt):
            raise AuthorityUnavailable('parent closure ACK belongs to another actual Work/parent')
        return self.receipt

    def release_payload_v3(self):
        _PREPARED.pop(self, None)


def begin_d13_natural_parent_closure_read_v3(graph, bootstrap, *, candidate, root_entry):
    from ..runtime_context import require_d13_natural_parent_closure_root_entry_v3
    entry = require_d13_natural_parent_closure_root_entry_v3(root_entry, graph, candidate=candidate)
    r = None
    try:
        r = D13NaturalParentClosureReadV3(graph, bootstrap, candidate, entry)
        r.work = create_graph_storage_work_v3(graph, kind=KIND, operation_id=r.operation.operation_id,
            selection_digest=r.selection_digest, deadline_utc=r.operation.deadline_utc, state=r, operation=r.operation)
        return r.work
    except BaseException as first:
        actions = [('READ finish', lambda: graph._finish_read_fence_v3(entry.fence))]
        if r is not None:
            actions.append(('payload release', r.release_payload_v3))
        actions.extend((('retention release', lambda: finish_runtime_storage_operation_v3(entry.operation)),
            ('process lease release', entry.release_process_lease_v3)))
        for label, action in actions:
            try:
                action()
            except BaseException as later:
                first.add_note('parent cleanup ' + label + ' failed: ' + type(later).__name__)
        raise


def begin_d13_natural_parent_closure_read_v4(graph, bootstrap, *, candidate, root_entry):
    from ..authority_service.d13_cache_use_contract_v2 import D13NaturalParentClosureCandidateV4
    if type(candidate) is not D13NaturalParentClosureCandidateV4:
        raise AuthorityUnavailable('exact V4 natural parent original candidate required')
    return begin_d13_natural_parent_closure_read_v3(graph, bootstrap, candidate=candidate, root_entry=root_entry)


def advance_d13_natural_parent_closure_read_v3(graph, work):
    r = work.state
    r.require_current_v3()
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        graph._validate_read_fence_v3(r.fence)
        from .source_inspection_metadata_read_v3 import resolve_pending_inspection_metadata_core_v3
        if resolve_pending_inspection_metadata_core_v3(work):
            return GraphStorageStepV3('progress')
        if r.phase == 'original':
            read_original = (r.port.read_natural_parent_closure_original_v4 if r.is_v4
                else r.port.read_natural_parent_closure_original_v3)
            r.original = read_original(namespace=r.namespace,
                authority_namespace=r.scope.authority_namespace, candidate=r.candidate)
            if r.is_v4 and r.original.closed_receipt is not None:
                r.receipt = r.original.closed_receipt
                r.complete = True
                r.result = PreparedD13NaturalParentClosureV3(_ISSUER, r)
            else:
                r.phase = 'readiness' if r.is_v4 else 'metadata'
        elif r.phase == 'readiness':
            r._readiness_v4()
        elif r.phase == 'owner':
            from ..authority_service.owner_location_read_v3 import prepare_current_host_d13_natural_parent_closure_owner_entry_v3
            entry = prepare_current_host_d13_natural_parent_closure_owner_entry_v3(r)
            try:
                r.owner_binding = entry.require_permission_v3(r)
                r.owner_entry, r.owner_guard = entry, entry.current_owner_guard
            except BaseException:
                entry.release_v3()
                raise
            for purpose, audiences, roots in r.groups:
                for ref in roots:
                    r.source_group_requirements.setdefault(ref, set()).update(
                        (purpose, audience) for audience in audiences)
            r.pending = list(sorted(r.source_group_requirements))
            r.phase = 'sources'
        elif r.phase == 'close':
            r.owner_entry.require_permission_v3(r)
            with r.store._lock:
                r.db.execute('BEGIN')
                try:
                    with runtime_storage_quantum_v3(r.db) as meter:
                        r.require_current_v3(meter)
                        for task in r.source_inspection_tasks.values():
                            task.require_current_v3(meter)
                finally:
                    r.db.rollback()
            from ..authority_service.d13_cache_use_contract_v2 import D13OwnerCloseReceiptV3
            receipt = r.control_port.close_natural_parent_for_fence_v3(namespace=r.namespace,
                authority_namespace=r.scope.authority_namespace, permit=r.scope.permit,
                parent_original_id=r.parent_original_id)
            if (type(receipt) is not D13OwnerCloseReceiptV3
                    or receipt.registration_digest != r.original.registration.registration_digest
                    or receipt.owner_ref != r.owner_ref or receipt.namespace != r.namespace):
                raise AuthorityUnavailable('parent cleanup Core close ACK does not match its actual parse registration')
            r.receipt = receipt
            r.complete = True
            r.result = PreparedD13NaturalParentClosureV3(_ISSUER, r)
        else:
            with r.store._lock:
                if r.db.in_transaction:
                    raise AuthorityUnavailable('parent cleanup cannot inherit a Graph transaction')
                r.db.execute('BEGIN')
                try:
                    with runtime_storage_quantum_v3(r.db) as meter:
                        r.advance_v3(meter)
                finally:
                    r.db.rollback()
        graph._validate_read_fence_v3(r.fence)
    return GraphStorageStepV3('complete', r.result) if r.complete else GraphStorageStepV3('progress')


def finish_d13_natural_parent_closure_read_v3(graph, work, error):
    r = work.state
    first = error
    for label, action in (
            ('READ finish', lambda: graph._finish_read_fence_v3(r.fence)),
            ('payload release', r.release_payload_v3),
            ('retention release', lambda: finish_runtime_storage_operation_v3(r.operation)),
            ('process lease release', r.root_entry.release_process_lease_v3)):
        try:
            action()
        except BaseException as later:
            if first is None:
                first = later
            else:
                first.add_note('parent cleanup ' + label + ' failed: ' + type(later).__name__)
    if first is not None and first is not error:
        raise first
