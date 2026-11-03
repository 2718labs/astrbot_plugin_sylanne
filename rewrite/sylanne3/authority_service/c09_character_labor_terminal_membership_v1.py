"""Private bounded W01 metadata membership for historical labor D02 joins."""
from copy import copy
from weakref import WeakSet
from hashlib import sha256
import json
from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold, read_legacy_sql_cell_fragment_v2
_TASKS = WeakSet()
_PROOFS = WeakSet()
_TOKEN = object()

class TerminalD02MembershipV1:
    """Authenticated D02 projection; this object is never a CommitReceipt."""

    def __init__(self, token, task, binding, segment, basis):
        if token is not _TOKEN or task not in _TASKS or (not task.complete):
            raise C09PagedCaptureHold('actual complete terminal source streams required')
        self.builder = task.builder
        self.graph = task.graph
        self.member_identity = task.member_identity
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        self.meter = current_c09_sql_meter_v2()
        self.source_scope_digest = self.builder.scope.scope_digest
        self.graph_source_digest = self.graph.pair.source_original.role_source_digest
        self.core_source_digest = self.builder.pair.source_original.role_source_digest
        self.namespace = binding.namespace
        self.binding_digest = binding.digest
        self.execution_id = binding.execution_id
        self.basis_digest = canonical_digest(plain_v1(basis))
        self.segment_digest = canonical_digest(plain_v1(segment))
        self.operation_id = task.operation_id
        self.activity_id = binding.activity_id
        self.effect_id = binding.effect_id
        self.status = 'committed'
        self.commit_seq = task.bundle[3]
        self.bundle_digest = task.bundle[0]
        self.event_digest = task.event[0]
        self.epoch = task.event[1]
        self.receipt_commitment = task.commitments[0]
        self.column_commitments = tuple(task.commitments[1:])
        self.full_write_count = task.counts[2]
        self.full_write_root = task.write_root
        self.read_versions = (task.before_body,)
        self.write_versions = task.d02_versions
        self.role_versions = task.role_versions
        self.original_commitment = canonical_digest(('d11.verified-terminal-D02-membership.v1', self.source_scope_digest, self.graph_source_digest, self.core_source_digest, self.namespace, self.binding_digest, self.execution_id, self.basis_digest, self.segment_digest, self.operation_id, self.activity_id, self.effect_id, self.commit_seq, self.bundle_digest, self.event_digest, self.epoch, self.receipt_commitment, self.column_commitments, self.full_write_count, self.full_write_root, self.read_versions, self.write_versions, self.role_versions))
        _PROOFS.add(self)

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 4096 + _retained_size((self.read_versions, self.write_versions, self.role_versions), set())

class _TerminalD02MembershipReadV1:

    def __init__(self, owner, *, binding, segment, basis):
        from .c09_character_labor_execution_v1 import _CharacterLaborCoreReverseReadV1, _LABOR_REVERSE
        if type(owner) is not _CharacterLaborCoreReverseReadV1 or owner not in _LABOR_REVERSE:
            raise C09PagedCaptureHold('actual final labor source owner required')
        self.builder = owner.builder
        self.graph = owner.graph
        self.member_identity = owner.member_identity
        self.binding = binding
        self.segment = segment
        self.basis = basis
        from ..runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
        self.operation_id = life_adoption_operation_id_v1(binding)
        self.stage = 0
        self.offset = 0
        self.total = None
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.hash = sha256()
        self.commitments = ()
        self.counts = (0, 0, 0, 0)
        self.scalar = bytearray()
        self.row_token = None
        self.row_revision = None
        self.before_body = None
        self.d02_versions = ()
        self.role_versions = ()
        self.receipt_arrays = ()
        self.receipt_hashes = {'ledger_refs': (), 'outbox_refs': ()}
        self.invalidated_hashes = ()
        self.meter_live = None
        self.write_root = canonical_digest(('d11.terminal-write-vector.v1', self.operation_id))
        self.bundle = None
        self.event = None
        self.complete = False
        _TASKS.add(self)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        state = tuple((getattr(self.parser, n) for n in self.parser.__slots__ if n != '_emit_callback'))
        return 16384 + _retained_size((self.binding, self.segment, self.basis, self.scalar, self.row_token, self.before_body, self.d02_versions, self.role_versions, self.receipt_hashes, self.invalidated_hashes, state), set())

    def require_current(self, owner):
        from .c09_character_labor_execution_v1 import _CharacterLaborCoreReverseReadV1, _LABOR_REVERSE
        if self not in _TASKS or type(owner) is not _CharacterLaborCoreReverseReadV1 or owner not in _LABOR_REVERSE or (owner.builder is not self.builder) or (owner.graph is not self.graph) or (owner.member_identity != self.member_identity):
            raise C09PagedCaptureHold('terminal membership left its exact actual source member')
        self.builder.require_current()
        self.graph.require_current()

    def _emit(self, event):
        from ..runtime.d02_character_labor_rebuild_v1 import LABOR_TERMINAL_BODY_TYPES_V1
        if self.stage == 0:
            if event.path == () and event.kind == 'array_start':
                raise C09PagedCaptureHold('actual W01 receipt must be a canonical object')
            if event.path in {('ledger_refs',), ('outbox_refs',)}:
                if event.kind == 'array_start':
                    self.receipt_arrays += event.path
                elif event.kind not in {'array_end', 'key'}:
                    raise C09PagedCaptureHold('actual W01 receipt reference fields must be arrays')
            if len(event.path) >= 2 and event.path[0] in {'ledger_refs', 'outbox_refs'}:
                if len(event.path) != 2 or event.kind in {'array_start', 'array_end', 'object_start', 'object_end', 'key'}:
                    raise C09PagedCaptureHold('actual W01 receipt references must be flat string arrays')
                if event.kind == 'scalar_start':
                    if event.scalar_kind != 'string':
                        raise C09PagedCaptureHold('actual W01 receipt references must be strings')
                    self.scalar = bytearray()
                elif event.kind == 'scalar_chunk':
                    self.scalar.extend(event.raw)
                elif event.kind == 'scalar_end':
                    value = json.loads(self.scalar)
                    self.scalar = bytearray()
                    if not value.strip():
                        raise C09PagedCaptureHold('actual W01 receipt reference is empty')
                    digest = sha256(value.encode('utf-8')).digest()
                    name = event.path[0]
                    if digest in self.receipt_hashes[name]:
                        raise C09PagedCaptureHold('actual W01 receipt references are not unique')
                    self.receipt_hashes[name] += (digest,)
            return
        path = event.path
        if event.kind in {'object_start', 'object_end'}:
            raise C09PagedCaptureHold('actual Graph version vectors contain only two-field arrays')
        if event.kind == 'array_start' and len(path) > 1:
            raise C09PagedCaptureHold('actual Graph version row has nested data')
        if event.kind == 'scalar_start':
            if len(path) != 2 or type(path[0]) is not int or path[0] != self.counts[self.stage] or (path[1] not in {0, 1}):
                raise C09PagedCaptureHold('actual Graph version vector shape changed')
            self.scalar = bytearray()
        elif event.kind == 'scalar_chunk':
            self.scalar.extend(event.raw)
        elif event.kind == 'scalar_end':
            value = json.loads(self.scalar)
            self.scalar = bytearray()
            if path[1] == 0:
                if type(value) is not str or self.row_token is not None:
                    raise C09PagedCaptureHold('actual Graph version token is not unique in its row')
                self.row_token = value
            else:
                if type(value) is not int or value < 0 or self.row_token is None or (self.row_revision is not None):
                    raise C09PagedCaptureHold('actual Graph version revision changed')
                self.row_revision = value
        elif event.kind == 'array_end' and len(path) == 1:
            if self.row_token is None or self.row_revision is None:
                raise C09PagedCaptureHold('actual Graph version row is incomplete')
            key = AtomKey.from_token(self.row_token)
            version = GraphVersion(key, self.row_revision)
            if NamespaceId.from_key(key) != self.binding.namespace:
                raise C09PagedCaptureHold('actual terminal Graph vector crosses namespace')
            if self.stage == 1:
                body = AtomKey(Owner('persona', *self.binding.namespace.as_tuple), 'd02.body_state.v1', self.basis.policy.profile_id)
                if key == body:
                    if self.before_body is not None or version.revision < 1:
                        raise C09PagedCaptureHold('terminal requires one exact before-Body read')
                    self.before_body = version
            elif self.stage == 2:
                if version.revision < 1:
                    raise C09PagedCaptureHold('actual terminal write must have a positive revision')
                self.write_root = canonical_digest(('d11.terminal-write-member.v1', self.write_root, self.counts[2], version))
                if key.type_name in LABOR_TERMINAL_BODY_TYPES_V1:
                    if any((v.key == key for v in self.d02_versions)):
                        raise C09PagedCaptureHold('terminal has duplicate D02 write members')
                    self.d02_versions += (version,)
                if key.type_name in {'runtime.job', 'runtime.cost_settlement', 'd11.life_artifact.v1'}:
                    if any((v.key == key for v in self.role_versions)):
                        raise C09PagedCaptureHold('terminal has duplicate job/cost/artifact members')
                    self.role_versions += (version,)
            elif self.stage == 3:
                if version.revision < 1:
                    raise C09PagedCaptureHold('actual terminal invalidation must have positive revision')
                digest = sha256(canonical_serialize(version).encode('utf-8')).digest()
                if digest in self.invalidated_hashes:
                    raise C09PagedCaptureHold('actual terminal invalidation vector is not unique')
                self.invalidated_hashes += (digest,)
                history = self.meter_live.read_fixed_row(self.graph.pair.source, 'graph_history', ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id'), 'token=? AND revision=?', (key.token, version.revision))
                if history != (0, *self.binding.namespace.as_tuple, self.binding.activity_id, self.operation_id):
                    raise C09PagedCaptureHold('terminal invalidation is not its actual same-event invalid history')
            counts = list(self.counts)
            counts[self.stage] += 1
            self.counts = tuple(counts)
            self.row_token = None
            self.row_revision = None

    def advance(self, owner, meter):
        self.require_current(owner)
        r = copy(self)
        r.parser = self.parser.copy()
        r.hash = self.hash.copy()
        r.scalar = bytearray(self.scalar)
        r.receipt_hashes = dict(self.receipt_hashes)
        _TASKS.add(r)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(r)
        b = self.binding
        db = self.graph.pair.source
        bundle = meter.read_fixed_row(db, 'graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'), 'bot=? AND persona=? AND operation_id=?', (*b.namespace.as_tuple, self.operation_id))
        event = meter.read_fixed_row(db, 'graph_events', ('digest', 'epoch_revision'), 'bot=? AND persona=? AND session=? AND event_id=?', (*b.namespace.as_tuple, b.activity_id, self.operation_id))
        if bundle is None or bundle[1:3] != (b.activity_id, b.effect_id) or event is None:
            raise C09PagedCaptureHold('terminal actual bundle/event original is absent')
        if self.bundle is not None and (self.bundle, self.event) != (bundle, event):
            raise C09PagedCaptureHold('terminal bundle/event changed across original source quanta')
        r.bundle = bundle
        r.event = event
        table = 'graph_bundle_operations' if self.stage == 0 else 'graph_events'
        column = ('receipt_json', 'reads', 'revisions', 'invalidated')[self.stage]
        where = 'bot=? AND persona=? AND operation_id=?' if self.stage == 0 else 'bot=? AND persona=? AND session=? AND event_id=?'
        params = (*b.namespace.as_tuple, self.operation_id) if self.stage == 0 else (*b.namespace.as_tuple, b.activity_id, self.operation_id)
        _, total, kind = read_legacy_sql_cell_fragment_v2(db, table=table, column=column, where=where, parameters=params, start=0, length=0, meter=meter)
        if kind != 'text' or (self.total is not None and self.total != total):
            raise C09PagedCaptureHold('terminal original metadata cell length/storage changed')
        r.total = total
        raw, actual, _ = read_legacy_sql_cell_fragment_v2(db, table=table, column=column, where=where, parameters=params, start=self.offset, length=min(4096, total - self.offset), meter=meter)
        if actual != total:
            raise C09PagedCaptureHold('terminal source metadata changed during full EOF')
        self.builder.session._control.require_c09_retained_arena_v3(meter=meter, additional_bytes=len(raw) * 12 + 16384)
        meter.require_available(len(raw) * 3 + 4096)
        r.hash.update(raw)
        r.meter_live = meter
        try:
            r.parser.feed(raw, r._emit)
        finally:
            r.meter_live = None
            r.parser._emit_callback = None
        r.offset += len(raw)
        meter.charge_encode(len(raw))
        self.builder.session._control.require_c09_retained_arena_v3(meter=meter)
        if r.offset == total:
            r.parser.finish()
            commitment = (column, r.hash.hexdigest(), total) if r.stage == 0 else (column, r.hash.hexdigest(), total, r.counts[r.stage])
            r.commitments += (commitment,)
            if r.stage == 0 and set(r.receipt_arrays) != {'ledger_refs', 'outbox_refs'}:
                raise C09PagedCaptureHold('terminal full receipt lacks its official reference arrays')
            r.stage += 1
            r.offset = 0
            r.total = None
            r.hash = sha256()
            r.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
            if r.stage == 4:
                if r.before_body is None or not r.d02_versions:
                    raise C09PagedCaptureHold('terminal EOF lacks its actual complete numeric Body roles')
                r.complete = True
        r.require_current(owner)
        return r

def bind_terminal_d02_membership_v1(task, owner, *, binding, terminal, segment, basis, core, meter):
    from .c09_character_labor_execution_v1 import _LaborFrozenSourcesV1
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_contract import canonical_bytes, from_wire
    from ..runtime.d11_life_preparation_v1 import life_ids_from_binding_v1
    from ..runtime.d11_types import runtime_job_key, runtime_cost_settlement_key
    if type(task) is not _TerminalD02MembershipReadV1:
        raise C09PagedCaptureHold('actual complete terminal source stream task required')
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    if current_c09_sql_meter_v2() is not meter:
        raise C09PagedCaptureHold('terminal projection issuance left its actual reserved quantum')
    task.require_current(owner)
    if not task.complete or task.binding != binding or task.segment != segment or (task.basis != basis) or (terminal.binding != binding) or (terminal.claim.payload.prepared_digest != basis.prepared_digest) or (type(core._character_labor_source_v1) is not _LaborFrozenSourcesV1) or (core.db is not owner.builder.pair.source):
        raise C09PagedCaptureHold('terminal source proof crossed its actual verified original interval')
    gate = 'd11-life-gate:adoption:' + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))
    row = AuthorityV2FenceStore._row(core, gate)
    if row is None:
        raise C09PagedCaptureHold('terminal numeric membership has no actual Core adoption fence')
    permit = AuthorityV2FenceStore._permit(row)
    if row[6] != 'finished' or row[10] is not None or row[7] != canonical_bytes(permit) or (permit.namespace != binding.authority_namespace) or (permit.authority_id != binding.authority_id) or (permit.subject != 'd11-life:' + binding.installation_id) or (permit.operation != 'write') or (permit.generation != binding.activation_generation) or (row[8] != gate + ':committed') or ((permit.pinned_anchor.execution_journal_id, permit.pinned_anchor.execution_seq, permit.pinned_anchor.execution_digest) != (terminal.journal_id, terminal.terminal_sequence, terminal.terminal_digest)):
        raise C09PagedCaptureHold('terminal source membership lost exact actual terminal-afterhead fence')
    graph = meter.read_fixed_row(task.graph.pair.source, 'graph_bundle_fences_v2', ('permit_json', 'pre_graph_revision', 'pre_graph_epoch', 'post_graph_revision', 'post_graph_epoch', 'finish_request_id', 'finish_request_digest'), 'bot=? AND persona=? AND operation_id=?', (*binding.namespace.as_tuple, task.operation_id))
    if graph is None or from_wire(json.loads(graph[0])) != permit or graph[3:5] != (graph[1] + 1, graph[2] + 1) or (graph[5:] != row[8:10]) or (graph[4] != task.event[1]):
        raise C09PagedCaptureHold('terminal projected members differ from actual finished Core/Graph W01')
    ns = binding.namespace
    required = {runtime_job_key(*ns.as_tuple, binding.activity_id, binding.job_id).token, runtime_cost_settlement_key(*ns.as_tuple, binding.activity_id, life_ids_from_binding_v1(binding)['reservation']).token}
    if not required <= {v.key.token for v in task.role_versions}:
        raise C09PagedCaptureHold('terminal projection lost actual job and original CPU cost roles')
    proof = TerminalD02MembershipV1(_TOKEN, task, binding, segment, basis)
    owner.builder.session._source_parser_arena_v3.add(proof)
    return proof

def require_terminal_d02_membership_v1(proof, *, binding, segment, basis):
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    if type(proof) is not TerminalD02MembershipV1 or proof not in _PROOFS or proof.namespace != binding.namespace or (proof.binding_digest != binding.digest) or (proof.execution_id != binding.execution_id) or (proof.basis_digest != canonical_digest(plain_v1(basis))) or (proof.segment_digest != canonical_digest(plain_v1(segment))) or (current_c09_sql_meter_v2() is not proof.meter):
        raise C09PagedCaptureHold('terminal D02 membership is not its actual private authenticated projection')
    proof.builder.require_current()
    proof.graph.require_current()
    return proof
