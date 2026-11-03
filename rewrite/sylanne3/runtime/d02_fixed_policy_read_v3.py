"""D02 admin-only fixed-policy comparison; no Body value leaves this Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from hashlib import sha256
import hmac
import json
import math
from threading import get_ident
import time
from uuid import uuid4
from weakref import WeakKeyDictionary

from ..contracts import Event, Scope
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from ..domains.d02 import BodyDomain, WorkComponent
from ..domains.d02.body_quote_original import FixedBodyPolicyV1
from ..graph_types import AtomKey, GraphReceipt, GraphVersion, NamespaceEpoch, owner_grant_key
from ..graph_worker import (GraphStorageStepV3, GraphStorageWorkV3,
    create_graph_storage_work_v3, require_graph_storage_work_admission_v3)
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import (RuntimeCellReadV3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    runtime_storage_quantum_v3, runtime_storage_v3, read_runtime_cell_origin_v3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3

WORK_KIND = 'd02_fixed_policy_read_v3'
_CAPABILITY = 'd02.body_policy.install'
_READERS = WeakKeyDictionary()
_CAPSULES = WeakKeyDictionary()
_BOUND = ContextVar('d02_fixed_policy_bound_v3', default=None)
_HEAD = ('revision', 'valid', 'value_cell_id')
_HISTORY = ('revision', 'valid', 'value_cell_id', 'event_bot', 'event_persona', 'event_session', 'event_id')
_ISSUE = ('operation_id', 'request_digest', 'grant_id', 'grant_digest', 'graph_incarnation',
    'graph_access_epoch', 'graph_epoch', 'graph_receipt_digest', 'proof_json')
_EVENT = ('digest', 'reads', 'epoch_reads', 'revisions', 'invalidated', 'epoch_revision')
_ATTEMPT = ('request_digest', 'attempt_id', 'anchor_json', 'graph_revision', 'graph_epoch', 'permit_json', 'receipt_json')
_POLICY_PATHS = {('policy_id',), ('version',), ('work_kind',), ('valid_until',),
    *(('component', name) for name in ('component_id', 'cost_category', 'fixed_cost', 'duration_rate'))}
_INPUT_PATHS = {('schema',), ('namespace', 'bot_id'), ('namespace', 'persona_id'),
    ('identity', 'operation_id'), ('identity', 'activity_id'), ('identity', 'effect_id'),
    ('provenance', 'producer_kind'), ('coverage',), ('now_utc',),
    *(('request', 'policy', *path) for path in _POLICY_PATHS)}


class _D02MetadataReadsV3:
    """One actual retained point set plus one temporary native decode peak."""
    def __init__(self, operation, db):
        self.operation, self.db = operation, db
        self.fixed_rows, self.volatile = {}, {}
        self.additional = None
        self.closed = False
        operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        from sys import getsizeof
        from .dispatch_current_inventory_v3 import _heap
        # Never recurse through the owning Graph/Authority/operation objects.
        return getsizeof(self) + getsizeof(self.__dict__) + _heap((
            self.fixed_rows, self.volatile, self.additional))

    @contextmanager
    def decode_peak(self, meter, amount):
        peak = amount * 8 + 4096
        if peak > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('D02 metadata requires its actual registered fragment decoder')
        self.operation.reserve_retained_state_growth_v3(self, peak)
        try:
            yield
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def _row(self, meter, table, columns, where, parameters, *, volatile=None):
        from .c09_paged_sql_v2 import _quote
        if (self.closed or self.operation.closed or runtime_storage_v3(self.db) is not self.operation.handle):
            raise AuthorityUnavailable('D02 metadata lost its actual operation/selected database')
        selector = table, tuple(columns), where, tuple(parameters)
        sql = 'SELECT ' + ','.join('length(CAST(' + _quote(column) + ' AS BLOB))' for column in columns)
        sql += ' FROM ' + _quote(table) + ' WHERE ' + where + ' LIMIT 1'
        meter.charge_encode(len(sql) + sum(len(str(value)) for value in parameters))
        lengths = self.db.execute(sql, parameters).fetchone()
        meter.charge_read(0 if lengths is None else 8 * len(lengths))
        amount = 0 if lengths is None else sum(size or 0 for size in lengths)
        meter.require_available(amount + 256)
        with self.decode_peak(meter, amount):
            row = None if lengths is None else meter.read_fixed_row(self.db, table, columns, where, parameters)
            if volatile is not None:
                self.volatile[volatile] = row
                return row
            if selector in self.fixed_rows:
                original = self.fixed_rows[selector]
                if row != original:
                    row = None
                    from ..contracts import StaleRead
                    raise StaleRead('D02 actual fixed metadata point changed after observation')
                # Return the original retained tuple, discarding the fresh copy
                # before releasing the actual temporary decoder peak.
                row = None
                return original
            self.fixed_rows[selector] = row
            return row

    def fixed(self, meter, table, columns, where, parameters):
        return self._row(meter, table, columns, where, parameters)

    def transient(self, label, meter, table, columns, where, parameters):
        # An attempt legitimately changes at its writer. It is measured but is
        # never added to the fixed currentness set.
        return self._row(meter, table, columns, where, parameters, volatile=label)

    def release(self):
        if self.closed:
            return
        self.closed = True
        self.fixed_rows.clear()
        self.volatile.clear()
        self.additional = None
        self.operation.unregister_retained_state_v3(self)


class _D02OriginPointsV3:
    """Exact actual dependencies of one initially verified immutable origin."""
    def __init__(self, cell, meter):
        self.cell = cell
        r = cell.r
        handle = r.operation.handle
        from ..runtime_storage_v3 import runtime_source_identity_v4
        identity = runtime_source_identity_v4(handle, meter=meter)
        source = (handle.host_binding if handle.host_binding is not None else
            handle.initial if identity.origin_kind == 'initial_segmented_v4' else handle.selected)
        self.basis_identity = (source, identity.origin_kind, identity.genesis_digest,
            identity.capture_scope_digest, identity.role, identity.instance,
            identity.member['resolved_path'], identity.selection_digest)
        self.selectors = []
        self._point(meter, 'sqlite_master', ('sql',),
            "type='table' AND name=?", ('runtime_cell_origins_v3',))
        if cell.origin is None:
            if (identity.origin_kind != 'selected_v3' or identity.capture_scope_digest is None
                    or cell.cell.header[7] != identity.capture_scope_digest):
                raise AuthorityUnavailable('D02 captured cell lost its actual selected capture origin')
            if self._point_value(0) is not None:
                row = self._point(meter, 'runtime_cell_origins_v3',
                    ('origin_digest','selection_digest','role','authority_id','installation_id','namespace_json',
                     'operation_id','event_digest','locator_json','read_proof_json'),
                    'origin_digest=?', (cell.cell.header[7],))
                if row is not None:
                    raise AuthorityUnavailable('D02 captured origin differs from its initial actual verifier')
            return
        origin = cell.origin
        if (origin.get('schema') != 'sylanne3.runtime-cell-origin.v3'
                or origin.get('producer_kind') is not None
                or origin['locator'].get('table') != 'graph_atoms'
                or origin['read_proof'].get('schema') is not None):
            raise AuthorityUnavailable('D02 cell requires its own exact registered actual producer witness')
        row = self._point(meter, 'runtime_cell_origins_v3',
            ('origin_digest','selection_digest','role','authority_id','installation_id','namespace_json',
             'operation_id','event_digest','locator_json','read_proof_json'),
            'origin_digest=?', (cell.cell.header[7],))
        if row is None:
            raise AuthorityUnavailable('D02 initially verified actual origin record disappeared')
        proof, locator = origin['read_proof'], origin['locator']
        self._point(meter, 'graph_events', ('digest','reads','epoch_reads'),
            'bot=? AND persona=? AND session=? AND event_id=?', tuple(proof['event_scope']))
        self._point(meter, 'graph_history',
            ('value_cell_id','dependencies','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=?', (locator['token'], locator['revision']))

    def _point(self, meter, table, columns, where, key):
        selector = table, columns, where, tuple(key)
        value = self.cell.r.metadata_reads.fixed(meter, *selector)
        self.selectors.append(selector)
        return value

    def _point_value(self, index):
        return self.cell.r.metadata_reads.fixed_rows[self.selectors[index]]

    def require(self, meter):
        r = self.cell.r
        handle = r.operation.handle
        from ..runtime_storage_v3 import runtime_source_identity_v4
        identity = runtime_source_identity_v4(handle, meter=meter)
        source = (handle.host_binding if handle.host_binding is not None else
            handle.initial if identity.origin_kind == 'initial_segmented_v4' else handle.selected)
        actual = (source, identity.origin_kind, identity.genesis_digest,
            identity.capture_scope_digest, identity.role, identity.instance,
            identity.member['resolved_path'], identity.selection_digest)
        if actual != self.basis_identity or identity.role != 'graph':
            raise AuthorityUnavailable('D02 actual installed origin lineage changed')
        handle.require_current(meter)
        # Both captured absence and runtime origin/FK rows are freshly observed.
        for selector in self.selectors:
            r.metadata_reads.fixed(meter, *selector)


class _Expected(RuntimeCanonicalStreamV3):
    def __init__(self, value, operation, ascii_codec):
        self.ascii_codec = ascii_codec
        super().__init__(value, operation)

    def _value(self, value, meter_getter=None):
        if type(value) is str:
            yield from self._quoted(value, meter_getter)
        else:
            yield from super()._value(value, meter_getter)

    def _quoted(self, value, meter_getter=None):
        yield b'"'
        for offset in range(0, len(value), 1024):
            meter = meter_getter() if meter_getter else None
            if meter is not None:
                meter.require_available(45056)
            raw = json.dumps(value[offset:offset + 1024], ensure_ascii=self.ascii_codec,
                separators=(',', ':')).encode('utf-8')
            if meter is not None:
                meter.charge_encode(len(raw) * 2)
            yield raw[1:-1]
        yield b'"'


class _Projection:
    """Canonical parser retaining only named control scalars and subtree hashes."""
    def __init__(self, operation, *, ascii_codec=True, paths=(), subtree=None):
        self.operation = operation
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=ascii_codec)
        self.paths = frozenset(paths)
        self.values = {}
        self.scalar = bytearray()
        self.subtree = subtree
        self.start = self.end = None
        self.subhash = sha256()
        self.reserved = 131072
        operation.retain(self.reserved)

    def emit(self, event):
        if event.path == self.subtree:
            if event.kind in ('object_start', 'array_start', 'scalar_start'):
                self.start = event.start_offset
            if event.kind in ('object_end', 'array_end', 'scalar_end'):
                self.end = event.end_offset
        if event.path not in self.paths:
            return
        if event.kind == 'scalar_start':
            self.scalar = bytearray()
        elif event.kind == 'scalar_chunk':
            self.operation.retain(len(event.raw) * 8)
            self.scalar.extend(event.raw)
        elif event.kind == 'scalar_end':
            self.values[event.path] = json.loads(self.scalar)
            self.scalar = bytearray()

    def feed(self, chunk, meter):
        offset = self.parser.byte_count
        meter.charge_encode(len(chunk))
        self.parser.feed(chunk, self.emit)
        if self.start is not None:
            lo = max(offset, self.start) - offset
            hi = min(offset + len(chunk), self.end if self.end is not None else offset + len(chunk)) - offset
            if hi > lo:
                self.subhash.update(chunk[lo:hi])

    def finish(self):
        result = self.parser.finish()
        if self.subtree is not None and (self.start is None or self.end is None):
            raise AuthorityUnavailable('D02 producer lacks its complete actual policy subtree')
        return result


class _Cell:
    """One physical cell, full canonical EOF; Body mode retains no decoded value."""
    def __init__(self, reader, cell_id, token, meter, *, expected=None, owner=False):
        self.r = reader
        self.cell = RuntimeCellReadV3(reader.operation.handle, cell_id,
            erasure_owner_ref=token, meter=meter)
        self.origin = read_runtime_cell_origin_v3(reader.db, cell_id,
            header=self.cell.header, meter=meter)
        self.origin_points = _D02OriginPointsV3(self, meter)
        if self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
            raise AuthorityUnavailable('D02 fixed point has another actual canonical codec')
        self.view = _Projection(reader.operation,
            ascii_codec=self.cell.header[0] == 'canonical-json.ascii.v1')
        self.expected = None if expected is None else _Expected(expected, reader.operation,
            self.cell.header[0] == 'canonical-json.ascii.v1')
        self.actual = self.wanted = b''
        self.ai = self.wi = 0
        self.owner_bytes = bytearray() if owner else None
        self.complete = False
        reader.operation.retain(131072)

    def require_header(self, meter):
        r = self.r
        current = r.metadata_reads.fixed(meter, 'segmented_cells_v1',
            ('codec_id', 'erasure_owner_ref', 'producer_operation_id', 'total_bytes',
             'segment_count', 'payload_sha256', 'ordered_segment_root', 'origin_scope_digest'),
            'cell_id=?', (self.cell.cell_id,))
        if current != self.cell.header:
            raise AuthorityUnavailable('D02 selected cell header changed after its actual EOF')
        self.origin_points.require(meter)

    def advance(self, meter):
        if self.ai < len(self.actual):
            if self.expected is not None and self.wi == len(self.wanted):
                if self.expected.complete:
                    raise ValueError('fixed body original differs from administrator expected canonical EOF')
                self.wanted = self.expected.read_fragment(meter) or b''
                self.wi = 0
                return
            amount = min(1024, len(self.actual) - self.ai)
            if self.expected is not None:
                amount = min(amount, len(self.wanted) - self.wi)
                if not amount or self.actual[self.ai:self.ai + amount] != self.wanted[self.wi:self.wi + amount]:
                    raise ValueError('additional policy cannot replace the original body definition')
                self.wi += amount
            chunk = self.actual[self.ai:self.ai + amount]
            self.view.feed(chunk, meter)
            if self.owner_bytes is not None:
                self.r.operation.retain(len(chunk) * 8)
                self.owner_bytes.extend(chunk)
            self.ai += amount
            return
        if self.cell.ordinal < self.cell.header[4]:
            self.actual = self.cell.read_fragment(meter=meter)
            self.ai = 0
            return
        if self.expected is not None and not self.expected.complete:
            if self.expected.read_fragment(meter):
                raise ValueError('fixed body original ended before administrator expected canonical EOF')
            return
        if self.expected is not None and self.wi != len(self.wanted):
            raise ValueError('fixed body original ended before expected bytes')
        parsed = self.view.finish()
        digest = self.cell.finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
            raise AuthorityUnavailable('D02 complete canonical EOF differs from actual sealed cell')
        self.require_header(meter)
        self.actual = self.wanted = b''
        self.expected = None
        self.complete = True


class _Inline:
    """Fixed-column canonical EOF, one SQLite BLOB substring per quantum."""
    def __init__(self, r, table, column, where, key, *, paths=(), subtree=None,
            expected=None, hmac_key=None):
        self.r, self.table, self.column, self.where, self.key = r, table, column, where, tuple(key)
        self.view = _Projection(r.operation, paths=paths, subtree=subtree)
        self.total = None
        self.offset = 0
        self.complete = False
        self.expected = None if expected is None else _Expected(expected, r.operation, True)
        self.actual = self.wanted = b''
        self.ai = self.wi = 0
        self.hmac = None if hmac_key is None else hmac.new(hmac_key,
            b'd02-fixed-body-policy.v1\n', sha256)
        r.operation.retain(131072)

    def length(self, meter):
        sql = 'SELECT length(CAST(' + self.column + ' AS BLOB)) FROM ' + self.table + ' WHERE ' + self.where
        meter.require_available(8192)
        meter.charge_encode(len(sql) + sum(len(str(x)) for x in self.key))
        value = self.r.db.execute(sql, self.key).fetchone()
        meter.charge_read(8 if value else 0)
        if value is None:
            raise AuthorityUnavailable('D02 actual producer column disappeared')
        return value[0]

    def advance(self, meter):
        if self.total is None:
            self.total = self.length(meter)
            return
        if self.ai < len(self.actual):
            if self.expected is not None and self.wi == len(self.wanted):
                if self.expected.complete:
                    raise AuthorityUnavailable('D02 signed policy exceeds its exact administrator configuration')
                self.wanted = self.expected.read_fragment(meter) or b''
                self.wi = 0
                return
            amount = min(1024, len(self.actual) - self.ai)
            if self.expected is not None:
                amount = min(amount, len(self.wanted) - self.wi)
                if not amount or self.actual[self.ai:self.ai + amount] != self.wanted[self.wi:self.wi + amount]:
                    raise AuthorityUnavailable('D02 signed producer policy differs from actual admin configuration')
                self.wi += amount
            chunk = self.actual[self.ai:self.ai + amount]
            self.view.feed(chunk, meter)
            if self.hmac is not None:
                self.hmac.update(chunk)
            self.ai += amount
            return
        if self.offset < self.total:
            meter.require_available(65536)
            sql = 'SELECT substr(CAST(' + self.column + ' AS BLOB),?,16384) FROM ' + self.table + ' WHERE ' + self.where
            params = (self.offset + 1, *self.key)
            meter.charge_encode(len(sql) + sum(len(str(x)) for x in params))
            value = self.r.db.execute(sql, params).fetchone()
            if value is None or not value[0] or len(value[0]) > 16384:
                raise AuthorityUnavailable('D02 bounded original fragment absent')
            self.actual, self.ai = value[0], 0
            meter.charge_read(len(self.actual))
            self.offset += len(self.actual)
            return
        if self.expected is not None and not self.expected.complete:
            if self.expected.read_fragment(meter):
                raise AuthorityUnavailable('D02 signed producer ended before expected canonical EOF')
            return
        if self.expected is not None and self.wi != len(self.wanted):
            raise AuthorityUnavailable('D02 signed producer ended before expected bytes')
        self.result = self.view.finish()
        if self.result.byte_count != self.total or self.length(meter) != self.total:
            raise AuthorityUnavailable('D02 immutable original complete EOF/length changed')
        self.complete = True
        self.expected = None
        self.actual = self.wanted = b''


class _Reader:
    def __init__(self, graph, bootstrap, authority, lease, operation_id, policy, request_digest,
            operation, fence, owner, session, now, mono, metadata_reads):
        self.graph, self.bootstrap, self.authority, self.lease = graph, bootstrap, authority, lease
        self.operation_id, self.policy, self.request_digest = operation_id, policy, request_digest
        self.operation, self.fence, self.owner, self.session = operation, fence, owner, session
        self.metadata_reads = metadata_reads
        self.namespace = authority.namespace
        self.store = graph._GraphCoordinator__store
        self.db = self.store._db
        self.selection = operation.selection_digest
        self.catalogue_hash = self.store._registry.catalogue_hash
        self.stamp = (fence.metadata, fence.epoch)
        self.thread = get_ident()
        self.deadline_mono = mono + policy.valid_until - now
        self.profile_write = BodyDomain.profile_write(policy.profile)
        self.state_write = BodyDomain.state_write(self.namespace, policy.initial_state)
        self.work = None
        self.phase = 'owner'
        self.points = {}
        metadata_reads.additional = self.points
        self.cells = []
        self.tasks = []
        self.owner_cell = None
        self.owner_json = None
        self.read_finished = self.complete = False
        self.capsule = None
        self.profile = self.state = self.initial = None
        self.producer = None
        self.replay = None
        operation.retain(262144)

    def identity(self):
        return (self.graph, self.bootstrap, id(self.authority), id(self.lease), self.operation_id,
            id(self.policy), self.request_digest, self.operation, self.fence, self.owner, self.session,
            self.selection, self.catalogue_hash, self.stamp, self.thread, self.deadline_mono, self.work, self.metadata_reads)

    def actual(self):
        if (_READERS.get(self) != self.identity() or self.operation.closed or self.thread != get_ident()
                or runtime_storage_v3(self.db) is not self.operation.handle
                or self.selection != self.operation.handle.selection_digest
                or type(self.work) is not GraphStorageWorkV3 or self.work.kind != WORK_KIND
                or self.work.state is not self or self.work.operation is not self.operation):
            raise AuthorityUnavailable('D02 comparison lost its exact private Work/selection/retention')
        self.work._require_invocation(self.graph)
        self.graph._admin(self.bootstrap)
        self.graph._authorize(self.lease, self.authority, frozenset(('d02',)), owner_read=True)
        if (self.graph._GraphCoordinator__owner_leases.get(self.lease) != self.owner
                or self.graph._GraphCoordinator__owner_session_proofs.get(self.lease) != self.session):
            raise AuthorityUnavailable('D02 original Owner/session lease changed')
        return self

    def clock(self, now=None):
        from .first_ingress_v2 import trusted_upper
        if now is None:
            now = trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
                self.graph._GraphCoordinator__scene_clock_policy))
        if not math.isfinite(now) or now >= self.policy.valid_until or time.monotonic() >= self.deadline_mono:
            raise AuthorityUnavailable('D02 fixed policy exceeded its sole original policy deadline')
        return now

    def point(self, name, table, columns, where, key, meter):
        value = self.metadata_reads.fixed(meter, table, columns, where, key)
        old = self.points.get(name)
        if old is not None and old[4] != value:
            raise AuthorityUnavailable('D02 exact current metadata point changed during comparison')
        if old is None:
            with self.metadata_reads.decode_peak(meter, 512):
                self.points[name] = (table, columns, where, tuple(key), value)
        return value

    def require_points(self, meter):
        self.operation.handle.require_current(meter)
        if (self.graph._v2_graph_stamp(self.namespace) != self.stamp
                or self.store._registry.catalogue_hash != self.catalogue_hash):
            from ..contracts import StaleRead
            raise StaleRead('D02 graph recovery/epoch changed before adoption')
        for table, columns, where, key, value in self.points.values():
            if self.metadata_reads.fixed(meter, table, columns, where, key) != value:
                from ..contracts import StaleRead
                raise StaleRead('D02 selected Owner/config/history/producer metadata changed')
        for cell in self.cells:
            cell.require_header(meter)

    def observe(self, scope):
        graph, authority, owner = self.graph, self.authority, self.owner
        port = graph._GraphCoordinator__content_fence_v2
        if (self.db.in_transaction or scope.namespace != self.namespace
                or scope.operation not in ('read', 'write')
                or scope.generation != authority.activation_generation
                or port.validate_fence(scope) != scope.permit
                or graph._current_owner_principal(authority.actor, self.namespace) != owner.principal):
            raise AuthorityUnavailable('D02 actual Owner observation lost current pairing/fence')
        token, request = self.session
        if request.principal != owner.principal:
            raise AuthorityUnavailable('D02 actual signed Owner session principal differs')
        current, permit = port.get_current_owner_authority_for_fence_v1(namespace=self.namespace,
            authority_namespace=scope.authority_namespace, permit=scope.permit,
            owner_actor_id=authority.actor, owner_session_token=token, owner_session_request=request)
        if (type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit
                or current.guard.namespace != self.namespace
                or current.guard.authority_id != scope.pinned_anchor.authority_id
                or current.guard.pending_revoke_operation_id is not None
                or current.guard.minimum_revocation_revision != 0):
            raise AuthorityUnavailable('D02 actual current Owner guard/session is unavailable')
        return current

    def qualify_owner(self, observation, meter):
        if self.owner_json is None or self.owner_cell is None or not self.owner_cell.complete:
            raise AuthorityUnavailable('D02 Owner grant requires its actual canonical complete EOF')
        atom = self.points['owner'][4]
        issue = self.points['issue'][4]
        epochs = self.points['authority_epochs'][4]
        if issue is None or epochs is None:
            raise AuthorityUnavailable('D02 actual Owner issue proof or authority epochs absent')
        self.owner_cell.require_header(meter)
        with self.metadata_reads.decode_peak(meter, self.owner_cell.cell.header[3] + len(issue[8])):
            owner = self.graph._owner_graph_binding_from_current_metadata_v3(self.authority,
                self.owner.principal, metadata=self.stamp[0], graph_epoch=self.stamp[1],
                atom=(atom[0], self.owner_json, atom[1]), proof_row=issue, epochs=epochs,
                target_admission=observation.target_admission, storage_admission=observation.storage_admission,
                current_guard=observation.guard)
        guard = observation.guard
        if (owner != self.owner or _CAPABILITY not in owner.capabilities
                or guard.authorization_revision != owner.authorization_revision
                or guard.authorization_head != owner.authorization_head
                or guard.minimum_revocation_epoch != owner.revocation_epoch
                or (observation.target_admission is None and observation.storage_admission is None
                    and guard.installation_id != self.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id)):
            raise AuthorityUnavailable('D02 current Owner grant/rights/location changed after its EOF')
        return guard, owner

    def advance_owner(self, observation, meter):
        if self.owner_cell is None:
            token = owner_grant_key(*self.namespace.as_tuple).token
            row = self.point('owner', 'graph_atoms', _HEAD, 'token=? AND bot=? AND persona=?',
                (token, *self.namespace.as_tuple), meter)
            if row is None or row[0] < 1 or row[1] != 1:
                raise AuthorityUnavailable('D02 current Owner fixed grant absent or invalid')
            self.point('authority_epochs', 'graph_authority_epochs', ('access_epoch', 'delete_epoch'),
                'bot=? AND persona=?', self.namespace.as_tuple, meter)
            self.owner_cell = _Cell(self, row[2], token, meter, owner=True)
            self.cells.append(self.owner_cell)
            return
        if not self.owner_cell.complete:
            self.owner_cell.advance(meter)
            return
        self.owner_json = self.owner_cell.owner_bytes.decode('utf-8')
        self.owner_cell.owner_bytes = None
        owner_grant = json.loads(self.owner_json)
        self.point('issue', 'graph_owner_issue_operations_v1', _ISSUE,
            'bot=? AND persona=? AND operation_id=?',
            (*self.namespace.as_tuple, owner_grant['issue_operation_id']), meter)
        self.qualify_owner(observation, meter)
        self.phase = 'replay' if self.replay is not None else 'heads'

    def heads(self, meter):
        p, s = self.profile_write.key.token, self.state_write.key.token
        self.profile = self.point('profile', 'graph_atoms', _HEAD,
            'token=? AND bot=? AND persona=?', (p, *self.namespace.as_tuple), meter)
        self.state = self.point('state', 'graph_atoms', _HEAD,
            'token=? AND bot=? AND persona=?', (s, *self.namespace.as_tuple), meter)
        if (self.profile is None) != (self.state is None):
            raise ValueError('body profile/state initialization is partial')
        if self.profile is None:
            self.phase = 'seal'
            return
        if self.profile[1] != 1 or self.state[1] != 1:
            raise ValueError('fixed policy cannot adopt invalid current body heads')
        self.initial = self.point('initial', 'graph_history', _HISTORY, 'token=? AND revision=?', (s, 1), meter)
        profile_history = self.point('profile_history', 'graph_history', _HISTORY,
            'token=? AND revision=?', (p, self.profile[0]), meter)
        if (self.initial is None or self.initial[:2] != (1, 1)
                or profile_history is None or profile_history[:3] != self.profile
                or profile_history[0] != 1 or profile_history[3:] != self.initial[3:]
                or self.initial[3:5] != self.namespace.as_tuple):
            raise AuthorityUnavailable('D02 original profile/state do not share their actual initialization producer')
        self.event_key = tuple(self.initial[3:])
        event = self.point('event', 'graph_events', _EVENT,
            'bot=? AND persona=? AND session=? AND event_id=?', self.event_key, meter)
        if event is None or event[5] > self.stamp[1].revision:
            raise AuthorityUnavailable('D02 initialization full event FK/actual epoch is unavailable')
        revisions = json.loads(event[3])
        if sorted(revisions) != sorted([[p, 1], [s, 1]]) or json.loads(event[4]) != []:
            raise AuthorityUnavailable('D02 initialization event did not actually create these two revisions')
        self.profile_cell = _Cell(self, self.profile[2], p, meter, expected=self.profile_write.value)
        self.initial_cell = _Cell(self, self.initial[2], s, meter, expected=self.state_write.value)
        self.cells.extend((self.profile_cell, self.initial_cell))
        self.tasks.extend((self.profile_cell, self.initial_cell))
        self.phase = 'bodies'

    def producer_start(self, meter):
        operation_id = self.event_key[3]
        fixed = self.point('producer_fixed_attempt', 'graph_owner_domain_attempts_v3', _ATTEMPT,
            'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, operation_id), meter)
        fixed_receipt = None if fixed is None or fixed[6] is None else json.loads(fixed[6])
        if fixed_receipt is not None and fixed_receipt.get('schema') == 'd02.fixed-work-policy-adoption.v1':
            if (fixed_receipt.get('operation_id') != operation_id or fixed_receipt.get('body_initialized') is not True
                    or self.event_key[2] != 'd02.fixed_work_policy.v1'):
                raise AuthorityUnavailable('D02 fixed initialization has no actual original command/commit')
            event = self.points['event'][4]
            receipt = GraphReceipt('committed',
                tuple(GraphVersion(self.profile_write.key if token == self.profile_write.key.token else self.state_write.key, revision)
                    for token, revision in json.loads(event[3])), (),
                NamespaceEpoch(*self.namespace.as_tuple, event[5]))
            if (fixed_receipt.get('graph_receipt_digest') != canonical_digest(receipt)
                    or event[5] != fixed[4] + 1):
                raise AuthorityUnavailable('D02 fixed initialization receipt differs from actual Graph revisions/epoch')
            self.producer = ('fixed', fixed_receipt)
            self.policy_key = (*self.namespace.as_tuple, fixed_receipt['policy_id'], fixed_receipt['policy_version'])
            self.phase = 'policy_scan'
            return
        columns = ('domain', 'operation_kind', 'request_digest', 'original_digest',
            'read_versions_json', 'bundle_digest', 'receipt_json', 'receipt_digest')
        original = self.point('producer_input', 'graph_domain_production_originals_v1', columns,
            'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, operation_id), meter)
        if original is None or original[:2] != ('d02', 'input:initialize_body'):
            raise AuthorityUnavailable('D02 actual initialization producer original is absent; HOLD')
        from .domain_production_originals_v1 import _receipt
        receipt = _receipt(json.loads(original[6]))
        bundle = self.point('producer_bundle', 'graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'),
            'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, operation_id), meter)
        event = self.points['event'][4]
        if (receipt.status != 'committed' or receipt.operation_id != operation_id
                or receipt.activity_id != self.event_key[2] or canonical_digest(receipt) != original[7]
                or receipt.operation_digest != original[5]
                or bundle is None or bundle[:4] != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq)
                or json.loads(bundle[4]).get('commit_seq') != receipt.commit_seq
                or json.loads(bundle[4]).get('ledger_refs') != list(receipt.ledger_refs)
                or json.loads(bundle[4]).get('outbox_refs') != list(receipt.outbox_refs)
                or sorted((v.key.token, v.revision) for v in receipt.write_versions) != sorted(
                    ((self.profile_write.key.token, 1), (self.state_write.key.token, 1)))
                or receipt.invalidated_epochs != (NamespaceEpoch(*self.namespace.as_tuple, event[5]),)
                or [[v.key.token, v.revision] for v in receipt.read_versions] != json.loads(original[4])):
            raise AuthorityUnavailable('D02 initialize_body original lost its actual same-commit bundle/Graph receipt')
        fence = self.point('producer_bundle_fence', 'graph_bundle_fences_v2',
            ('digest', 'pre_graph_epoch', 'post_graph_epoch'), 'bot=? AND persona=? AND operation_id=?',
            (*self.namespace.as_tuple, operation_id), meter)
        if (fence is None or fence[0] != receipt.operation_digest or fence[2] != event[5]
                or fence[2] != fence[1] + 1 or json.loads(event[2]) != []
                or json.loads(event[1]) != json.loads(original[4])):
            raise AuthorityUnavailable('D02 initialize_body actual bundle fence/event epoch/read closure differs')
        self.producer = ('input', original, receipt)
        self.input_task = _Inline(self, 'graph_domain_production_originals_v1', 'original_payload_json',
            'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, operation_id),
            paths=_INPUT_PATHS, subtree=('request', 'policy'))
        self.tasks.append(self.input_task)
        self.phase = 'input_original'

    def input_finish(self):
        task, original, receipt = self.input_task, self.producer[1], self.producer[2]
        values = task.view.values
        if (task.result.sha256 != original[3] or values.get(('schema',)) != 'd02.current-input:initialize_body.v1'
                or (values.get(('namespace', 'bot_id')), values.get(('namespace', 'persona_id'))) != self.namespace.as_tuple
                or values.get(('identity', 'operation_id')) != self.event_key[3]
                or values.get(('identity', 'activity_id')) != receipt.activity_id
                or values.get(('identity', 'effect_id')) != receipt.effect_id
                or values.get(('provenance', 'producer_kind')) != 'initialize_body'
                or values.get(('coverage',)) != 'complete'):
            raise AuthorityUnavailable('D02 initialize_body actual canonical input original differs')
        # Exact installed Owner ingress sets SourceQualification.learned_at and
        # frame.now_utc from the same trusted now (domain_production_runtime_v1).
        actual_event = Event(Scope(*self.namespace.as_tuple, receipt.activity_id), self.event_key[3],
            values[('now_utc',)], 'domain_bundle', {'bundle_digest': receipt.operation_digest})
        if actual_event.digest != self.points['event'][4][0]:
            raise AuthorityUnavailable('D02 initialize_body actual envelope/event digest differs')
        self.policy_key = (*self.namespace.as_tuple,
            values[('request', 'policy', 'policy_id')], values[('request', 'policy', 'version')])
        self.phase = 'policy_scan'

    def policy_start(self, meter):
        row = self.point('producer_policy', 'd02_fixed_body_policies_v1', ('signature', 'status'),
            'bot=? AND persona=? AND policy_id=? AND version=?', self.policy_key, meter)
        if row is None or row[1] != 'active':
            raise AuthorityUnavailable('D02 initialization actual signed policy original absent')
        signer = self.graph._GraphCoordinator__body_quote_authority
        self.policy_scan = _Inline(self, 'd02_fixed_body_policies_v1', 'policy_json',
            'bot=? AND persona=? AND policy_id=? AND version=?', self.policy_key,
            paths=_POLICY_PATHS, hmac_key=signer._key)
        self.tasks.append(self.policy_scan)
        self.phase = 'policy_scan_eof'

    def policy_scan_finish(self):
        task = self.policy_scan
        row = self.points['producer_policy'][4]
        if not hmac.compare_digest(task.hmac.hexdigest(), row[0]):
            raise AuthorityUnavailable('D02 actual initialization policy signature differs')
        values = task.view.values
        component = WorkComponent(**{name: values[('component', name)] for name in
            ('component_id', 'cost_category', 'fixed_cost', 'duration_rate')})
        original_policy = FixedBodyPolicyV1(values[('policy_id',)], values[('version',)],
            self.policy.profile, self.policy.initial_state, values[('work_kind',)], component, values[('valid_until',)])
        if self.policy_key[2:] != (original_policy.policy_id, original_policy.version):
            raise AuthorityUnavailable('D02 actual signed initialization policy PK differs')
        if self.producer[0] == 'fixed':
            receipt = self.producer[1]
            original_digest = canonical_digest(('d02.fixed-work-policy-adoption.v1', self.namespace,
                self.event_key[3], original_policy))
            fixed = self.points['producer_fixed_attempt'][4]
            if (receipt.get('policy_digest') != canonical_digest(original_policy)
                    or receipt.get('work_kind') != original_policy.work_kind or fixed[0] != original_digest
                    or fixed[1] != 'owner-domain-' + canonical_digest((self.namespace, self.event_key[3], original_digest))[:48]):
                raise AuthorityUnavailable('D02 fixed producer command does not bind its actual signed policy')
        else:
            values = self.input_task.view.values
            if any(values.get(('request', 'policy', *path)) != task.view.values[path] for path in _POLICY_PATHS):
                raise AuthorityUnavailable('D02 initialize_body input differs from actual signed policy metadata')
            if self.input_task.view.subhash.hexdigest() != task.result.sha256:
                raise AuthorityUnavailable('D02 initialize_body actual policy subtree is not its signed original')
        self.policy_compare = _Inline(self, 'd02_fixed_body_policies_v1', 'policy_json',
            'bot=? AND persona=? AND policy_id=? AND version=?', self.policy_key, expected=asdict(original_policy))
        self.tasks.append(self.policy_compare)
        self.phase = 'policy_compare'


def _receipt_metadata_v3(graph, operation, namespace, operation_id, request_digest, policy, saved, metadata_reads):
    """The installed command's saved metadata is never a fresh policy adoption."""
    db = graph._GraphCoordinator__store._db
    result = json.loads(saved[6])
    keys = {'schema', 'operation_id', 'policy_id', 'policy_version', 'policy_digest',
        'work_kind', 'body_initialized', 'graph_receipt_digest'}
    if (type(result) is not dict or set(result) != keys
            or result['schema'] != 'd02.fixed-work-policy-adoption.v1'
            or result['operation_id'] != operation_id or result['policy_id'] != policy.policy_id
            or result['policy_version'] != policy.version or result['policy_digest'] != canonical_digest(policy)
            or result['work_kind'] != policy.work_kind or type(result['body_initialized']) is not bool):
        raise AuthorityUnavailable('D02 saved receipt differs from its original schema/operation/policy')
    with bind_runtime_storage_operation_v3(operation, db), graph._GraphCoordinator__store._lock, runtime_storage_quantum_v3(db) as meter:
        event = metadata_reads.fixed(meter, 'graph_events', _EVENT,
            'bot=? AND persona=? AND session=? AND event_id=?', (*namespace.as_tuple, 'd02.fixed_work_policy.v1', operation_id))
        if event is None:
            raise AuthorityUnavailable('D02 saved receipt lacks its actual Graph event producer')
        revisions = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in json.loads(event[3]))
        invalidated = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in json.loads(event[4]))
        receipt = GraphReceipt('committed', revisions, invalidated, NamespaceEpoch(*namespace.as_tuple, event[5]))
        expected = ((BodyDomain.profile_write(policy.profile).key.token, 1),
            (BodyDomain.state_write(namespace, policy.initial_state).key.token, 1)) if result['body_initialized'] else ()
        if (tuple(sorted((v.key.token, v.revision) for v in revisions)) != tuple(sorted(expected))
                or invalidated or result['graph_receipt_digest'] != canonical_digest(receipt)):
            raise AuthorityUnavailable('D02 saved receipt does not describe its actual Graph revisions/epoch')
        for version in revisions:
            history = metadata_reads.fixed(meter, 'graph_history',
                ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id'),
                'token=? AND revision=?', (version.key.token, version.revision))
            if history != (1, *namespace.as_tuple, 'd02.fixed_work_policy.v1', operation_id):
                raise AuthorityUnavailable('D02 saved receipt Graph history lost its full actual producer FK')
    return result, event


def _attempt_preflight(graph, authority, operation_id, request_digest, policy, operation, metadata_reads):
    from ..authority_service.v2_contract import from_wire
    from ..runtime_contracts import FenceScope
    from .restore_anchor import RestoreAnchor
    db = graph._GraphCoordinator__store._db
    with bind_runtime_storage_operation_v3(operation, db), graph._GraphCoordinator__store._lock, runtime_storage_quantum_v3(db) as meter:
        saved = metadata_reads.transient('preflight_attempt', meter, 'graph_owner_domain_attempts_v3', _ATTEMPT,
            'bot=? AND persona=? AND operation_id=?', (*authority.namespace.as_tuple, operation_id))
        metadata, epoch = graph._v2_graph_stamp(authority.namespace)
    if saved is None:
        return None
    expected = 'owner-domain-' + canonical_digest((authority.namespace, operation_id, request_digest))[:48]
    if saved[:2] != (request_digest, expected):
        raise AuthorityUnavailable('D02 original operation changed its immutable request')
    port = graph._GraphCoordinator__content_fence_v2
    permit, state = port.get_fence_operation(namespace=authority.namespace,
        authority_namespace=metadata.requirements.authority_namespace, operation_id=expected)
    if saved[6] is None:
        if permit is not None or state != 'absent' or saved[5] is not None:
            raise AuthorityUnavailable('D02 original WRITE is active or unknown and lacks durable D02 seed; HOLD')
        if saved[3:5] != (metadata.graph_revision, epoch.revision):
            raise AuthorityUnavailable('D02 original absent permit lost its original Graph stamp; HOLD')
        return None
    result, event = _receipt_metadata_v3(graph, operation, authority.namespace, operation_id, request_digest, policy, saved, metadata_reads)
    anchor = RestoreAnchor(**json.loads(saved[2]))
    actual_anchor = port.current_anchor(namespace=authority.namespace,
        authority_namespace=metadata.requirements.authority_namespace)
    if (anchor != actual_anchor or not graph._anchor_matches(metadata.requirements, anchor)
            or saved[5] is None or permit != from_wire(json.loads(saved[5]))
            or state not in {'active', 'finished'} or permit.operation_id != expected
            or permit.operation != 'write' or permit.holder != graph._GraphCoordinator__holder
            or permit.pinned_anchor != anchor):
        raise AuthorityUnavailable('D02 saved receipt original permit/anchor differs; HOLD')
    scope = FenceScope(authority.namespace, metadata.requirements.authority_namespace,
        authority.activation_generation, 'write', expected, permit, anchor,
        NamespaceEpoch(*authority.namespace.as_tuple, saved[4]), saved[3])
    port.finish_fence(scope, request_id='finish:' + expected,
        request_digest='sha256:' + canonical_digest({'schema': 'w01.owner-domain-write.v3',
            'operation_id': operation_id, 'request_digest': request_digest, 'permit_token': permit.token}))
    actual, status = port.get_fence_operation(namespace=authority.namespace,
        authority_namespace=metadata.requirements.authority_namespace, operation_id=expected)
    if actual != permit or status != 'finished':
        raise AuthorityUnavailable('D02 saved receipt original WRITE finish remains unconfirmed; HOLD')
    return saved, result, event

def prepare_d02_fixed_policy_read_v3(graph, bootstrap, authority, lease, *, operation_id, policy, request_digest):
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    graph._admin(bootstrap)
    if (type(policy) is not FixedBodyPolicyV1 or policy.profile.namespace != authority.namespace
            or policy.work_kind not in {'d06.c04_internal_cpu.v1', 'd07.cognition'}
            or not math.isfinite(policy.valid_until)
            or graph._GraphCoordinator__body_quote_authority is None
            or request_digest != canonical_digest(('d02.fixed-work-policy-adoption.v1',
                authority.namespace, operation_id, policy))):
        raise ValueError('D02 comparison requires the exact supported administrator policy/request')
    graph._authorize(lease, authority, frozenset(('d02',)), owner_read=True)
    owner = graph._GraphCoordinator__owner_leases.get(lease)
    session = graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or session is None or _CAPABILITY not in owner.capabilities:
        raise AuthorityUnavailable('D02 comparison requires actual current signed Owner installation rights')
    # This single paired observation fixes the only monotonic deadline.
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
        graph._GraphCoordinator__scene_clock_policy))
    mono = time.monotonic()
    if not math.isfinite(now) or now >= policy.valid_until:
        raise AuthorityUnavailable('D02 policy deadline expired; retain any saved receipt for a formally authorized historical audit')
    read_id = 'd02-fixed-policy-read:' + uuid4().hex
    operation = begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db, read_id, policy.valid_until)
    fence = None
    metadata_reads = None
    try:
        metadata_reads = _D02MetadataReadsV3(operation, graph._GraphCoordinator__store._db)
        replay = _attempt_preflight(graph, authority, operation_id, request_digest, policy, operation, metadata_reads)
        with bind_runtime_storage_operation_v3(operation, graph._GraphCoordinator__store._db):
            fence = graph._begin_read_fence_v3(authority, operation_id=read_id, owner_session_proof=session)
            r = _Reader(graph, bootstrap, authority, lease, operation_id, policy, request_digest,
                operation, fence, owner, session, now, mono, metadata_reads)
            r.replay = replay
        work = create_graph_storage_work_v3(graph, kind=WORK_KIND, operation_id=operation_id,
            selection_digest=operation.selection_digest, deadline_utc=policy.valid_until, state=r, operation=operation)
        r.work = work
        _READERS[r] = r.identity()
        work._require_invocation(graph, initial=True)
        return work
    except BaseException:
        try:
            if fence is not None:
                graph._finish_read_fence_v3(fence)
        finally:
            if metadata_reads is not None:
                metadata_reads.release()
            finish_runtime_storage_operation_v3(operation)
        raise


class _D02FixedPolicyReadCapsuleV3:
    def __init__(self, r):
        if r.phase != 'seal' or not r.complete or r.capsule is not None:
            raise AuthorityUnavailable('D02 capsule requires its own exact complete comparison')
        self.reader = r
        self.write_observation = None
        self.consumed = False
        _CAPSULES[self] = r.identity()

    @property
    def is_replay_v3(self):
        return self.reader.replay is not None

    def replay_result_v3(self, graph, policy, *, operation_id, request_digest):
        r = self.reader
        self.require_invocation_v3(graph, authority=r.authority, lease=r.lease, operation_id=operation_id, request_digest=request_digest)
        if (_BOUND.get() is not self or policy is not r.policy or r.replay is None or self.consumed):
            raise AuthorityUnavailable('D02 saved result requires its exact current Owner metadata READ')
        r.clock()
        with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
            r.require_points(meter)
            saved = r.metadata_reads.transient('replay_attempt', meter, 'graph_owner_domain_attempts_v3', _ATTEMPT,
                'bot=? AND persona=? AND operation_id=?', (*r.namespace.as_tuple, operation_id))
            if saved != r.replay[0]:
                raise AuthorityUnavailable('D02 saved original receipt changed after current Owner metadata READ')
        self.consumed = True
        return json.loads(saved[6])

    def require_invocation_v3(self, graph, *, authority, lease, operation_id, request_digest,
            domains=('d02',), capability=_CAPABILITY):
        r = self.reader.actual()
        if (_CAPSULES.get(self) != r.identity() or graph is not r.graph or authority is not r.authority
                or lease is not r.lease or operation_id != r.operation_id or request_digest != r.request_digest
                or tuple(domains) != ('d02',) or capability != _CAPABILITY or not r.complete
                or r.capsule is not self or not r.read_finished):
            raise AuthorityUnavailable('D02 private comparison capsule crossed its exact invocation')
        return self

    def observe_write_v3(self, graph, authority, lease, scope, original_owner, session_proof, metadata, epoch):
        r = self.reader
        self.require_invocation_v3(graph, authority=authority, lease=lease,
            operation_id=r.operation_id, request_digest=r.request_digest)
        if (r.replay is not None or self.consumed or self.write_observation is not None or original_owner != r.owner
                or session_proof != r.session or (metadata, epoch) != r.stamp
                or scope.operation != 'write' or scope.graph_epoch != epoch
                or scope.graph_revision != metadata.graph_revision):
            raise AuthorityUnavailable('D02 fresh WRITE observation changed original Owner/session/stamp')
        r.clock()
        observation = r.observe(scope)
        with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
            r.require_points(meter)
            guard, owner = r.qualify_owner(observation, meter)
        self.write_observation = (scope, observation, guard, owner)
        return guard, owner

    def require_write_v3(self, graph, *, authority, lease, operation_id, request_digest,
            metadata, epoch, owner, guard, scope, now):
        r = self.reader
        self.require_invocation_v3(graph, authority=authority, lease=lease,
            operation_id=operation_id, request_digest=request_digest)
        observed = self.write_observation
        if (self.consumed or observed is None or observed[0] is not scope or observed[2:] != (guard, owner)
                or (metadata, epoch) != r.stamp or not r.db.in_transaction or not r.store._lock._is_owned()
                or scope.operation != 'write' or scope.namespace != r.namespace):
            raise AuthorityUnavailable('D02 actual Owner WRITE did not consume its own fresh exact observation')
        r.clock(now)
        with runtime_storage_quantum_v3(r.db) as meter:
            r.require_points(meter)
            if r.qualify_owner(observed[1], meter) != (guard, owner):
                raise AuthorityUnavailable('D02 actual current Owner rights changed inside WRITE')
        self.consumed = True
        return r.profile, r.state

    def require_bound_compare_v3(self, graph, policy, *, operation_id, request_digest):
        r = self.reader
        self.require_invocation_v3(graph, authority=r.authority, lease=r.lease,
            operation_id=operation_id, request_digest=request_digest)
        if (_BOUND.get() is not self or policy is not r.policy or not self.consumed
                or not r.db.in_transaction or not r.store._lock._is_owned()):
            raise AuthorityUnavailable('D02 comparison result is private to its exact actual adoption transaction')
        return r.profile, r.state

    def release_payload_v3(self):
        r = self.reader
        _CAPSULES.pop(self, None)
        _READERS.pop(r, None)
        r.points.clear()
        r.cells.clear()
        r.tasks.clear()
        r.owner_json = r.owner_cell = r.capsule = None
        r.producer = r.replay = None
        r.metadata_reads.release()
        self.write_observation = None


def bound_d02_fixed_policy_read_v3():
    return _BOUND.get()


@contextmanager
def bind_prepared_d02_fixed_policy_read_v3(capsule):
    if type(capsule) is not _D02FixedPolicyReadCapsuleV3 or capsule not in _CAPSULES:
        raise AuthorityUnavailable('D02 bound comparison requires its actually issued private capsule')
    r = capsule.reader
    capsule.require_invocation_v3(r.graph, authority=r.authority, lease=r.lease,
        operation_id=r.operation_id, request_digest=r.request_digest)
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        token = _BOUND.set(capsule)
        try:
            yield capsule
        finally:
            _BOUND.reset(token)


def read_current_d02_policy_attempt_v3(capsule, db):
    r = capsule.reader
    capsule.require_invocation_v3(r.graph, authority=r.authority, lease=r.lease,
        operation_id=r.operation_id, request_digest=r.request_digest)
    if db is not r.db or _BOUND.get() is not capsule:
        raise AuthorityUnavailable('D02 attempt lookup escaped its exact bound operation/database')
    with runtime_storage_quantum_v3(db) as meter:
        return r.metadata_reads.transient('writer_attempt', meter, 'graph_owner_domain_attempts_v3', _ATTEMPT,
            'bot=? AND persona=? AND operation_id=?', (*r.namespace.as_tuple, r.operation_id))


def advance_d02_fixed_policy_read_v3(graph, work):
    r = work.state.actual()
    if graph is not r.graph or r.read_finished or r.complete:
        raise AuthorityUnavailable('D02 comparison advance lost its original unfinished READ')
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        r.clock()
        observation = r.observe(r.fence.scope)
        graph._validate_read_fence_v3(r.fence)
        with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
            r.db.execute('BEGIN')
            try:
                r.require_points(meter)
                if r.phase == 'owner':
                    r.advance_owner(observation, meter)
                else:
                    r.qualify_owner(observation, meter)
                    if r.phase == 'replay':
                        result, event = _receipt_metadata_v3(graph, r.operation, r.namespace, r.operation_id, r.request_digest, r.policy, r.replay[0], r.metadata_reads)
                        if (result, event) != r.replay[1:]:
                            raise AuthorityUnavailable('D02 saved actual Graph producer changed during current Owner READ')
                        r.phase = 'seal'
                    elif r.phase == 'heads':
                        r.heads(meter)
                    elif (r.tasks and not r.tasks[-1].complete) or (r.phase == 'bodies' and r.tasks):
                        task = next((task for task in r.tasks if not task.complete), None)
                        if task is not None:
                            task.advance(meter)
                        elif r.phase == 'bodies':
                            r.phase = 'producer'
                    elif r.phase == 'producer':
                        r.producer_start(meter)
                    elif r.phase == 'input_original':
                        r.input_finish()
                    elif r.phase == 'policy_scan':
                        r.policy_start(meter)
                    elif r.phase == 'policy_scan_eof':
                        r.policy_scan_finish()
                    elif r.phase == 'policy_compare':
                        if r.policy_compare.result.sha256 != r.policy_scan.result.sha256:
                            raise AuthorityUnavailable('D02 producer policy changed across complete canonical EOF passes')
                        r.phase = 'seal'
                if r.phase == 'seal':
                    r.require_points(meter)
                    r.complete = True
                    capsule = _D02FixedPolicyReadCapsuleV3(r)
                    r.capsule = capsule
                else:
                    capsule = None
            finally:
                r.db.rollback()
        graph._validate_read_fence_v3(r.fence)
        r.clock()
    return GraphStorageStepV3('complete', capsule) if capsule is not None else GraphStorageStepV3('progress')


def finish_d02_fixed_policy_read_v3(graph, work, error):
    r = work.state
    if graph is not r.graph:
        raise AuthorityUnavailable('D02 comparison finish crossed its actual Graph')
    try:
        if not r.read_finished:
            graph._finish_read_fence_v3(r.fence)
            r.read_finished = True
        if error is None:
            if not r.complete or r.capsule is None:
                raise AuthorityUnavailable('D02 cannot close READ without its actual complete comparison')
            work.result_lease = r.operation
            return
    except BaseException:
        if r.capsule is not None:
            r.capsule.release_payload_v3()
        else:
            _READERS.pop(r, None)
        r.metadata_reads.release()
        finish_runtime_storage_operation_v3(r.operation)
        raise
    if r.capsule is not None:
        r.capsule.release_payload_v3()
    else:
        _READERS.pop(r, None)
    r.metadata_reads.release()
    finish_runtime_storage_operation_v3(r.operation)
