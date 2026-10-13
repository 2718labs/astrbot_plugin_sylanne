"""New v6 collector: bounded pages from one actual current Graph transaction."""
from dataclasses import dataclass, replace
from weakref import WeakKeyDictionary

from ..graph_types import AtomKey
from ..runtime_contracts import ConversationWindowProjectionV1, canonical_digest
from ..domains.d13.raw_slice import _merge_ranges
from .d13_current_window import _read_current_d13_window_for_authority_v1

_CONTEXT_KEY = object()

class _CurrentCollectorContextV6:
    def __init__(self, key, db, window):
        if key is not _CONTEXT_KEY:
            raise TypeError('collector context comes only from the actual current first page')
        self.db, self.window = db, window
        self.snapshot = _snapshot(db, window.namespace)
    def require_current(self, db, namespace, scene_ref, conversation_ref):
        if (db is not self.db or not db.in_transaction or namespace != self.window.namespace
                or conversation_ref != self.window.conversation_ref
                or AtomKey.from_token(self.window.scene_ref.ref).owner.subject != scene_ref
                or _snapshot(db, namespace) != self.snapshot):
            raise ValueError('v6 page crossed its actual current Graph snapshot/collector identity')
        ref = self.window.audience_ref
        row = db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?', (ref.ref,)).fetchone()
        if row != (ref.version, 1):
            raise ValueError('v6 current incoming audience account changed')

@dataclass(frozen=True, slots=True)
class CurrentD13PageV6:
    before_sequence: int | None
    max_slots: int
    first_sequence: int
    last_sequence: int
    window: ConversationWindowProjectionV1
    page_status: str
    expired_sequences: tuple[int, ...]
    unclosed_sequences: tuple[int, ...]

@dataclass(frozen=True, slots=True)
class CurrentD13CollectionV6:
    window: ConversationWindowProjectionV1
    pages: tuple[CurrentD13PageV6, ...]
    max_slots: int
    snapshot_commitment: str
    schema: str = 'd13.current-collection.v6'


def _snapshot(db, namespace):
    if not db.in_transaction:
        raise ValueError('v6 collection requires the same caller-owned current transaction')
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    bound,recovery=read_bound_authority_graph_attachment_v3(db,table='graph_recovery_metadata_v2',
        columns=('schema','requirements_json','graph_revision'),key_columns=('bot','persona'),key=namespace.as_tuple)
    if not bound:
        recovery = db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 '
            'WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
    epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
    if recovery is None or epoch is None:
        raise ValueError('v6 current Graph snapshot is unavailable')
    return recovery, epoch


def read_current_d13_collection_v6(db, namespace, scene_ref, conversation_ref, now_utc, *,
        expected_activation_generation, expected_owner_authorization_head=None, max_slots=256,before_sequence=None):
    if type(max_slots) is not int or not 1 <= max_slots <= 256:
        raise ValueError('v6 collection reads at most 256 actual slots, 64 per page')
    first_size = min(max_slots, 64)
    first_observation = {'expired': [], 'unclosed': []}
    first = _read_current_d13_window_for_authority_v1(db, namespace, scene_ref, conversation_ref, first_size, now_utc,
        before_sequence=before_sequence,expected_activation_generation=expected_activation_generation,
        expected_owner_authorization_head=expected_owner_authorization_head, _page_observation=first_observation)
    context = _CurrentCollectorContextV6(_CONTEXT_KEY, db, first)
    pages, remaining, before = [], max_slots, before_sequence
    end = first.order_watermark if before_sequence is None else min(first.order_watermark,before_sequence-1)
    while remaining and end >= 0:
        size = min(remaining, 64)
        start = max(0, end-size+1)
        observation = first_observation if not pages else {'expired': [], 'unclosed': []}
        page = first if not pages else _read_current_d13_window_for_authority_v1(
            db, namespace, scene_ref, conversation_ref, size, now_utc,
            before_sequence=before, expected_activation_generation=expected_activation_generation,
            expected_owner_authorization_head=expected_owner_authorization_head,
            _collector_context=context, _page_observation=observation)
        if any(getattr(page, name) != getattr(first, name) for name in ('namespace', 'owner_ref', 'conversation_ref',
                'scene_ref', 'audience_ref', 'order_watermark', 'trusted_utc', 'access_epoch', 'delete_epoch', 'activation_epoch')):
            raise ValueError('v6 pages disagree on current Owner/Source/order/epoch identity')
        status = 'available' if page.turns else 'empty_expired' if len(observation['expired']) == end-start+1 else 'empty_with_gaps'
        pages.append(CurrentD13PageV6(before, size, start, end, page, status,
            tuple(observation['expired']), tuple(observation['unclosed'])))
        remaining -= end-start+1
        before, end = start, start-1
        if start == 0:
            break
    context.require_current(db,namespace,scene_ref,conversation_ref)
    return _merge_current_d13_pages_v6(first,pages,max_slots,canonical_digest(context.snapshot))


def _merge_current_d13_pages_v6(first,pages,max_slots,snapshot_commitment):
    turns, reads, dependencies, gaps = {}, {}, {}, []
    for page in pages:
        for turn in page.window.turns:
            prior = turns.get(turn.sequence)
            if prior is not None and prior != turn:
                raise ValueError('v6 stable turn identity was reused')
            turns[turn.sequence] = turn
        for values, target in ((page.window.read_set, reads), (page.window.source_dependencies, dependencies)):
            for ref in values:
                if ref.ref in target and target[ref.ref] != ref:
                    raise ValueError('v6 pages crossed current versions')
                target[ref.ref] = ref
        for a,b in page.window.missing_ranges:
            a,b = max(a,page.first_sequence),min(b,page.last_sequence)
            if a <= b:
                gaps.append((a,b))
    lowest = pages[-1].first_sequence
    if lowest:
        gaps.append((0,lowest-1))
    if pages[0].last_sequence<first.order_watermark:
        gaps.append((pages[0].last_sequence+1,first.order_watermark))
    ordered = tuple(turns[key] for key in sorted(turns))
    if len(ordered) > 256 or sum(len(turn.text.encode('utf-8')) for turn in ordered) > 524288:
        raise ValueError('v6 collection exceeds its bounded local read; model admission is still independent')
    window = replace(first, turns=ordered, read_set=tuple(reads.values()), source_dependencies=tuple(dependencies.values()),
        missing_ranges=_merge_ranges(gaps))
    return CurrentD13CollectionV6(window, tuple(pages), max_slots, snapshot_commitment)


_AUTHORITY_COLLECTIONS_V6=WeakKeyDictionary()
_AUTHORITY_COLLECTION_ISSUER_V6=object()


class PreparedAuthorityD13CollectionV6:
    def __init__(self,issuer,reader):
        if issuer is not _AUTHORITY_COLLECTION_ISSUER_V6 or not reader.complete:
            raise TypeError('actual Authority collection record/page EOF required')
        self.reader,self.work,self.collection=reader,reader.work,reader.collection
        self.snapshot,self.scope,self.operation,self.selection_digest=(reader.context.snapshot,
            reader.work.scope,reader.work.operation,reader.work.selection_digest)
        _AUTHORITY_COLLECTIONS_V6[self]=(reader,self.work,self.collection,self.snapshot,self.scope,
            self.operation,self.selection_digest)
    def require_current_v6(self,work):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        if (_AUTHORITY_COLLECTIONS_V6.get(self)!=(self.reader,self.work,self.collection,self.snapshot,
                self.scope,self.operation,self.selection_digest)or self.work is not work
                or not self.reader.complete or self.reader.prepared is not self or not work.db.in_transaction):
            raise ValueError('Authority collection crossed actual Work/selection/page EOF')
        with runtime_storage_quantum_v3(work.db)as meter:
            work.require_current(meter=meter)
            self.reader.context.require_current(work.db,work.namespace,self.reader.scene_ref,self.reader.conversation_ref)
        return self.collection


class _AuthorityD13CollectionReadV6:
    def __init__(self,work,*,scene_ref,conversation_ref,now_utc,expected_activation_generation,
            expected_owner_authorization_head,max_slots,before_sequence):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
        if type(max_slots)is not int or not 1<=max_slots<=256:
            raise ValueError('Authority v6 collection retains at most 256 slots, 64 per page')
        self.work,self.scene_ref,self.conversation_ref=work,scene_ref,conversation_ref
        self.now_utc,self.expected_activation_generation=now_utc,expected_activation_generation
        self.expected_owner_authorization_head=expected_owner_authorization_head
        self.max_slots,self.remaining,self.before=max_slots,max_slots,before_sequence
        self.pages=[];self.context=self.first=self.page_program=None
        self.phase='page';self.complete=False;self.prepared=self.collection=None;self.reserved=0
        work.collection_readers.append(self)
    def _retain_v6(self):
        from .source_correction_read_v3 import _heap
        amount=_heap((self.pages,self.first,self.context,self.collection))+65536
        if amount>self.reserved:self.work.operation.retain(amount-self.reserved);self.reserved=amount
    def advance(self,meter):
        from .d13_current_window import _current_d13_window_program_v6
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
        self.work.require_current(meter=meter)
        if self.complete:return self
        if self.phase=='page':
            if self.page_program is None:
                self.observation={'expired':[],'unclosed':[]};self.page_size=min(self.remaining,64)
                self.page_program=_current_d13_window_program_v6(self.work.db,self.work.namespace,
                    self.scene_ref,self.conversation_ref,self.page_size,self.now_utc,
                    before_sequence=self.before,expected_activation_generation=self.expected_activation_generation,
                    expected_owner_authorization_head=self.expected_owner_authorization_head,
                    _collector_context=self.context,_page_observation=self.observation)
            try:
                dependency=next(self.page_program)
            except AuthorityGraphAttachmentRequiredV3:
                # Before the first record, pure preamble may request a not-yet-read original.
                self.page_program=None
                raise
            except StopIteration as finished:
                page=finished.value;self.page_program=None
                if self.first is None:
                    self.first=page;self.context=_CurrentCollectorContextV6(_CONTEXT_KEY,self.work.db,page)
                elif any(getattr(page,name)!=getattr(self.first,name)for name in
                        ('namespace','owner_ref','conversation_ref','scene_ref','audience_ref','order_watermark',
                         'trusted_utc','access_epoch','delete_epoch','activation_epoch')):
                    raise ValueError('Authority v6 pages changed original Owner/Source/order/epoch identity')
                end=page.order_watermark if self.before is None else min(page.order_watermark,self.before-1)
                start=max(0,end-self.page_size+1)
                status=('available'if page.turns else'empty_expired'if len(self.observation['expired'])==end-start+1 else'empty_with_gaps')
                self.pages.append(CurrentD13PageV6(self.before,self.page_size,start,end,page,status,
                    tuple(self.observation['expired']),tuple(self.observation['unclosed'])))
                self.remaining-=end-start+1;self.before=start
                if not self.remaining or start==0:self.phase='merge'
                self._retain_v6();return self
            if dependency is not None:raise dependency
            self._retain_v6();return self
        if self.phase=='merge':
            self.context.require_current(self.work.db,self.work.namespace,self.scene_ref,self.conversation_ref)
            from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
            self.snapshot_hash=_CanonicalComparisonV3(self.context.snapshot,operation=self.work.operation)
            self.phase='snapshot';return self
        if self.phase=='snapshot':
            if not self.snapshot_hash.advance(meter):return self
            self.collection=_merge_current_d13_pages_v6(self.first,self.pages,self.max_slots,self.snapshot_hash.digest)
            self._retain_v6();self.phase='seal';return self
        if self.phase=='seal':
            self.context.require_current(self.work.db,self.work.namespace,self.scene_ref,self.conversation_ref)
            self.complete=True;self.prepared=PreparedAuthorityD13CollectionV6(_AUTHORITY_COLLECTION_ISSUER_V6,self)
            return self
        raise ValueError('unregistered actual Authority v6 collection phase')


def begin_authority_d13_collection_read_v6(work,*,scene_ref,conversation_ref,now_utc,
        expected_activation_generation,expected_owner_authorization_head=None,max_slots=256,before_sequence=None):
    return _AuthorityD13CollectionReadV6(work,scene_ref=scene_ref,conversation_ref=conversation_ref,
        now_utc=now_utc,expected_activation_generation=expected_activation_generation,
        expected_owner_authorization_head=expected_owner_authorization_head,max_slots=max_slots,before_sequence=before_sequence)
