"""Installed C09 V2 recovery facts in the registered Graph candidate.

Only the installed session factory can create a producer/resolver. Source rows
are authenticated before their bodyless facts enter the durable keyed merge.
Five fact families and the journal, binding and model streams have compact seals.
Historical V1/V2 frames are re-read without whole-frame reconstruction.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack, closing
from dataclasses import asdict, dataclass, fields
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from time import monotonic_ns

from .contract import AuthorityUnavailable, JournalHead
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import (
    C09CaptureScopeV2, C09StreamIdentityV2, C09CaptureRecordV2, C09CountOriginalV2,
    C09PageCursorV2, C09CapturePageV2, C09CompleteStreamV2, C09SealedStreamLocatorV2,
    begin_c09_stream_v2, append_c09_page_v2, verify_c09_page_v2, seal_c09_stream_v2,
    verify_c09_complete_stream_v2, c09_paged_value_from_wire_v2,
    meter_c09_commitments_v2,
)
from ..runtime.c09_storage_rebase_contract_v1 import (
    SanitizedExecutionFactV4, SanitizedD02FactV4, SanitizedD11FactV4,
    SanitizedUnknownFactV4, SanitizedGraphFactV4,
)
from ..runtime.c09_storage_transition_v1 import C09ExecutionBindingV1
from .c09_model_budget_original_v1 import (
    C09ModelBudgetOriginalV1, read_frozen_model_budget_original_v2,
    model_budget_original_from_wire_v1, model_unit_fact_v4,
)

_FAMILIES = {
    'executions': (SanitizedExecutionFactV4, 'execution_id', 'execution_facts'),
    'd02_facts': (SanitizedD02FactV4, 'quote_id', 'd02_facts'),
    'd11_facts': (SanitizedD11FactV4, 'settlement_id', 'd11_facts'),
    'unknown_facts': (SanitizedUnknownFactV4, 'execution_id', 'unknown_facts'),
    'graph_facts': (SanitizedGraphFactV4, 'operation_id', 'graph_facts'),
}
_TOKEN = object()
RECOVERY_DDLS_V2 = {
    'c09_recovery_items_v2': "CREATE TABLE c09_recovery_items_v2 (scope_digest TEXT NOT NULL, family TEXT NOT NULL CHECK(family IN ('executions','d02_facts','d11_facts','unknown_facts','graph_facts','binding','model')), item_key TEXT NOT NULL, value_json TEXT NOT NULL, value_digest TEXT NOT NULL, origin_digest TEXT NOT NULL, PRIMARY KEY(scope_digest,family,item_key))",
    'c09_recovery_journal_index_v2': "CREATE TABLE c09_recovery_journal_index_v2 (scope_digest TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq>0), execution_id TEXT NOT NULL, business_operation_id TEXT NOT NULL, execution_kind TEXT NOT NULL, phase TEXT NOT NULL, binding_digest TEXT NOT NULL, claim_digest TEXT NOT NULL, row_commitment TEXT NOT NULL, mutation_id TEXT NOT NULL, chain_digest TEXT NOT NULL, PRIMARY KEY(scope_digest,seq), UNIQUE(scope_digest,mutation_id), UNIQUE(scope_digest,execution_id,phase))",
    'c09_recovery_progress_v2': "CREATE TABLE c09_recovery_progress_v2 (scope_digest TEXT NOT NULL, phase TEXT NOT NULL, progress_json TEXT NOT NULL, PRIMARY KEY(scope_digest,phase))",
    'c09_recovery_verification_v2': "CREATE TABLE c09_recovery_verification_v2 (scope_digest TEXT NOT NULL, family TEXT NOT NULL, item_key TEXT NOT NULL, verification_id TEXT NOT NULL, PRIMARY KEY(scope_digest,family,item_key))",
    'c09_recovery_family_seals_v2': "CREATE TABLE c09_recovery_family_seals_v2 (scope_digest TEXT NOT NULL, family TEXT NOT NULL, locator_json TEXT NOT NULL, locator_digest TEXT NOT NULL, PRIMARY KEY(scope_digest,family))",
}
RECOVERY_DDLS_V2.update({
    'c09_recovery_history_scopes_v2': "CREATE TABLE c09_recovery_history_scopes_v2 (scope_digest TEXT NOT NULL, historical_scope_digest TEXT NOT NULL, generation INTEGER NOT NULL, operation_id TEXT NOT NULL, prepared_digest TEXT NOT NULL, PRIMARY KEY(scope_digest,historical_scope_digest), UNIQUE(scope_digest,generation))",
    'c09_recovery_history_frames_v2': "CREATE TABLE c09_recovery_history_frames_v2 (scope_digest TEXT NOT NULL, generation INTEGER NOT NULL, operation_id TEXT NOT NULL, prepared_digest TEXT NOT NULL, facts_digest TEXT NOT NULL, bindings_digest TEXT NOT NULL, pin_digest TEXT NOT NULL, inventory_digest TEXT, manifest_digest TEXT NOT NULL, PRIMARY KEY(scope_digest,generation), UNIQUE(scope_digest,operation_id))",
    'c09_recovery_history_members_v2': "CREATE TABLE c09_recovery_history_members_v2 (scope_digest TEXT NOT NULL, generation INTEGER NOT NULL, family TEXT NOT NULL, item_key TEXT NOT NULL, value_digest TEXT NOT NULL, auxiliary_json TEXT NOT NULL, PRIMARY KEY(scope_digest,generation,family,item_key))",
    'c09_recovery_history_types_v2': "CREATE TABLE c09_recovery_history_types_v2 (scope_digest TEXT NOT NULL, generation INTEGER NOT NULL, cell_kind TEXT NOT NULL, byte_offset INTEGER NOT NULL, type_name TEXT NOT NULL, PRIMARY KEY(scope_digest,generation,cell_kind,byte_offset))",
})
RECOVERY_INDEXES_V2 = {
    'c09_recovery_execution_index_v2': 'CREATE INDEX c09_recovery_execution_index_v2 ON c09_recovery_journal_index_v2(scope_digest,execution_id,seq)',
    'c09_recovery_operation_index_v2': 'CREATE INDEX c09_recovery_operation_index_v2 ON c09_recovery_journal_index_v2(scope_digest,business_operation_id,seq)',
}
RECOVERY_TRIGGERS_V2 = {
    f'{table}_no_{action.lower()}': f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable C09 recovery original'); END"
    for table in ('c09_recovery_items_v2', 'c09_recovery_journal_index_v2', 'c09_recovery_family_seals_v2',
                  'c09_recovery_history_frames_v2', 'c09_recovery_history_members_v2', 'c09_recovery_history_types_v2', 'c09_recovery_history_scopes_v2')
    for action in ('UPDATE', 'DELETE')
}


class C09RecoveryQuantumExhaustedV2(AuthorityUnavailable):
    """The current actual batch cannot complete this indivisible codec."""


class C09RecoveryMeterV2:
    """Per-step diagnostics over the caller's sole actual reserved SQL meter."""
    __slots__=('max_bytes','parent','_start_read','_start_write','_start_encode','_start_mutations')
    def __init__(self,max_bytes,*,parent):
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2,current_c09_sql_meter_v2
        if (type(parent) is not C09SqlByteMeterV2 or parent is not current_c09_sql_meter_v2()
                or type(max_bytes) is not int or not 0<max_bytes<=parent.budget.max_bytes):
            raise ValueError('actual same-root C09 step reservation required')
        self.max_bytes=max_bytes;self.parent=parent
        self._start_read=parent.read_bytes;self._start_write=parent.written_bytes
        self._start_encode=parent.encoded_bytes;self._start_mutations=parent.sql_mutations
    @property
    def read_bytes(self):return self.parent.read_bytes-self._start_read
    @property
    def write_bytes(self):return self.parent.written_bytes-self._start_write
    @property
    def encoded_bytes(self):return self.parent.encoded_bytes-self._start_encode
    @property
    def sql_mutations(self):return self.parent.sql_mutations-self._start_mutations
    @property
    def remaining_bytes(self):return min(self.parent.remaining_bytes,self.max_bytes-self.read_bytes-self.write_bytes-self.encoded_bytes)
    def require_available(self,amount):
        if type(amount) is not int or amount<0:raise ValueError('invalid actual C09 byte reservation')
        if amount>self.remaining_bytes:raise C09RecoveryQuantumExhaustedV2('actual original exceeds the same reserved root')
        self.parent.require_available(amount)
    def charge_read(self,amount):self.require_available(amount);self.parent.charge_read(amount)
    def charge_write(self,amount):self.require_available(amount);self.parent.charge_write(amount)
    def charge_encode(self,amount):self.require_available(amount);self.parent.charge_encode(amount)
    def count_mutation(self):self.parent.count_mutation()


def _encoded(value, meter):
    return canonical_serialize(value)


def _bytes(row):
    return sum(0 if value is None else len(value) if type(value) is bytes else
               len(value.encode('utf-8')) if type(value) is str else
               8 for value in row)


class _BoundedCursorV2:
    def __init__(self, connection, statement, parameters, description, metadata):
        self.connection, self.statement, self.parameters = connection, statement, parameters
        self.description, self.metadata, self.cursor = description, metadata, None

    def fetchone(self):
        meta = self.metadata.fetchone()
        if meta is None:
            if self.cursor is not None and self.cursor.fetchone() is not None:
                raise AuthorityUnavailable('frozen point-query metadata/rows differ')
            return None
        self.connection.meter.charge_read(_bytes(meta))
        size = sum(0 if meta[index + 1] is None else meta[index + 1]
                   for index in range(0, len(meta), 2))
        if size > self.connection.meter.remaining_bytes:
            raise C09RecoveryQuantumExhaustedV2('actual original row exceeds remaining read reservation')
        if self.connection._natural_preflight_v3 is not None:
            self.connection._natural_preflight_v3(size)
        if self.cursor is None:
            self.cursor = self.connection.db.execute(self.statement, self.parameters)
        row = self.cursor.fetchone()
        if row is None or _bytes(row) != size:
            raise AuthorityUnavailable('frozen row differs from its measured storage classes/lengths')
        self.connection.meter.charge_read(size)
        return tuple(row)

    def fetchmany(self, size=1):
        if type(size) is not int or not 0 <= size <= 100:
            raise C09RecoveryQuantumExhaustedV2('unbounded fact-original cursor fetch')
        result = []
        for _ in range(size):
            row = self.fetchone()
            if row is None: break
            result.append(row)
        return result

    def fetchall(self):
        result = []
        while True:
            row = self.fetchone()
            if row is None: return result
            if len(result) == 100:
                raise C09RecoveryQuantumExhaustedV2('point-original result requires a paged producer')
            result.append(row)

    def __iter__(self): return self
    def __next__(self):
        row = self.fetchone()
        if row is None: raise StopIteration
        return row


class _BoundedReadConnectionV2:
    """Private read-only adapter for existing exact point-original verifiers.

    Metadata is selected before payloads. SQL comes only from installed readers;
    no request accepts a statement, table name or expression from a caller.
    """
    __slots__ = ('db', 'meter', '_natural_preflight_v3')

    def __init__(self, db, meter):
        self.db, self.meter = db, meter
        self._natural_preflight_v3 = None

    @property
    def in_transaction(self): return self.db.in_transaction

    def read_incremental_cell_v2(self,table,column,where,parameters,start,length):
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        with legacy_cell_read_transaction_v2(self.db):
            return read_legacy_sql_cell_fragment_v2(self.db,table=table,column=column,where=where,
                parameters=parameters,start=start,length=length,meter=self.meter)

    def execute(self, statement, parameters=()):
        sql = statement.strip().removesuffix(';')
        self.meter.charge_encode(len(sql.encode('utf-8')) + _bytes(parameters))
        if sql.upper().startswith('PRAGMA '):
            # Only these finite schema descriptors are used by the old readers.
            if not any(sql.upper().startswith('PRAGMA ' + name) for name in
                       ('TABLE_INFO(', 'TABLE_XINFO(', 'DATABASE_LIST', 'QUERY_ONLY')):
                raise AuthorityUnavailable('unregistered pragma in recovery-original reader')
            cursor = self.db.execute(sql, parameters)
            rows = cursor.fetchmany(101)
            if len(rows) > 100:
                raise C09RecoveryQuantumExhaustedV2('schema descriptor needs a registered paged codec')
            self.meter.charge_read(sum(_bytes(row) for row in rows))
            return _FiniteCursorV2(rows, cursor.description)
        if not sql.upper().startswith('SELECT '):
            raise AuthorityUnavailable('recovery original reader cannot mutate source storage')
        probe = self.db.execute('SELECT * FROM (' + sql + ') LIMIT 0', parameters)
        description = probe.description
        names = tuple('c' + str(index) for index in range(len(description)))
        observed = ','.join(f"typeof({name}),CASE WHEN typeof({name}) IN (\'integer\',\'real\') THEN 8 ELSE length(CAST({name} AS BLOB)) END" for name in names)
        metadata = self.db.execute('WITH c09_measured(' + ','.join(names) + ') AS (' + sql +
                                   ') SELECT ' + observed + ' FROM c09_measured', parameters)
        return _BoundedCursorV2(self, sql, parameters, description, metadata)


@dataclass(frozen=True,slots=True)
class _D13ContextEpochLocatorV3:
    """Private actual frozen-Source locators; rows are still unproved targets."""
    scope_digest: str
    source_original: object
    reference: object
    owner_subject: str | None
    value_kind: str
    epoch: int
    absent: bool
    history_metadata: object
    frozen_epoch: int
    birth_epoch: int | None
    head_revision: int | None
    successor_revision: int | None
    successor_epoch: int | None
    rows: tuple


class _C09ReadonlyPointMeterV3:
    """Borrow the caller's real remaining reservation; allocate no new budget."""
    def __init__(self,parent):self.parent=parent
    @property
    def budget(self):return self.parent.budget

    @property
    def remaining_bytes(self):return self.parent.remaining_bytes
    def charge_read(self,count):self.parent.charge_read(count)
    def charge_encode(self,count):self.parent.charge_encode(count)
    def require_available(self,count):
        if count>self.remaining_bytes:raise C09RecoveryQuantumExhaustedV2('actual point proof exceeds caller reservation')
    def charge_write(self,count):raise AuthorityUnavailable('post-mirror point proof cannot mutate storage')
    def count_mutation(self):raise AuthorityUnavailable('post-mirror point proof cannot mutate storage')
    def read_fixed_row(self,db,table,columns,where,args):
        from ..runtime.c09_paged_sql_v2 import _quote
        sql='SELECT '+','.join(_quote(name) for name in columns)+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1'
        return _read_one(db,sql,args,self.parent)
    def read_row(self,db,shape,key):
        from ..runtime.c09_paged_sql_v2 import _quote
        where=' AND '.join(_quote(name)+'=?' for name in shape.primary_key_columns)
        return self.read_fixed_row(db,shape.table,shape.columns,where,key)


class _FiniteCursorV2:
    def __init__(self, rows, description):
        self.rows, self.description, self.offset = rows, description, 0
    def fetchone(self):
        if self.offset == len(self.rows): return None
        value = self.rows[self.offset]; self.offset += 1; return value
    def fetchall(self):
        values = self.rows[self.offset:]; self.offset = len(self.rows); return values
    def __iter__(self): return iter(self.fetchall())


def _read_one(db, sql, parameters, meter):
    return _BoundedReadConnectionV2(db, meter).execute(sql, parameters).fetchone()


def _write(db, sql, parameters, meter):
    size = len(sql.encode('utf-8')) + _bytes(parameters)
    if size > meter.remaining_bytes:
        raise C09RecoveryQuantumExhaustedV2('actual fact write exceeds remaining reservation')
    meter.charge_write(size)
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    current_c09_sql_meter_v2().count_mutation()
    return db.execute(sql, parameters)


def _decode_fact(family, raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    value = json.loads(raw)
    if family == 'model': return model_budget_original_from_wire_v1(value)
    cls = C09ExecutionBindingV1 if family == 'binding' else _FAMILIES[family][0]
    return decode_typed_production_value_v1(value, cls)


def _fact_key(family, value):
    if family == 'binding': return value.execution_id
    if family == 'model': return value.call_id
    return getattr(value, _FAMILIES[family][1])


def _require_fact_type(family, value):
    expected = C09ExecutionBindingV1 if family == 'binding' else C09ModelBudgetOriginalV1 if family == 'model' else _FAMILIES[family][0]
    if type(value) is not expected:
        raise AuthorityUnavailable('recovery fact has another exact family type')


@dataclass(frozen=True, slots=True)
class C09PagedFactsCompletionV2:
    scope_digest: str
    facts_intent_digest: str
    old_journal_id: str
    old_seq: int
    old_digest: str
    source_seal_digest: str
    executions: C09SealedStreamLocatorV2
    d02_facts: C09SealedStreamLocatorV2
    d11_facts: C09SealedStreamLocatorV2
    unknown_facts: C09SealedStreamLocatorV2
    graph_facts: C09SealedStreamLocatorV2
    journal_stream: C09SealedStreamLocatorV2
    binding_stream: C09SealedStreamLocatorV2
    model_stream: C09SealedStreamLocatorV2
    schema: str = 'sylanne3.c09.paged-facts-completion.v2'

    def __post_init__(self):
        if self.schema != 'sylanne3.c09.paged-facts-completion.v2':
            raise AuthorityUnavailable('unknown paged facts completion schema')
        for name in ('scope_digest', 'facts_intent_digest', 'source_seal_digest'):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise AuthorityUnavailable('paged facts completion commitment differs')
        if (type(self.old_seq) is not int or self.old_seq < 0 or not self.old_journal_id
                or self.old_seq == 0 and self.old_digest != 'genesis'
                or self.old_seq > 0 and not self.old_digest.startswith('sha256:')):
            raise AuthorityUnavailable('paged facts execution head differs')
        for family in (*_FAMILIES, 'journal_stream', 'binding_stream', 'model_stream'):
            locator = getattr(self, family)
            if type(locator) is not C09SealedStreamLocatorV2 or locator.identity.scope_digest != self.scope_digest:
                raise AuthorityUnavailable('paged facts family crossed its actual scope')

    @property
    def pin_digest(self):
        return canonical_digest(self)


def _decode_completion(raw):
    value = dict(raw)
    if set(value) != {field.name for field in fields(C09PagedFactsCompletionV2)}:
        raise AuthorityUnavailable('paged facts completion fields differ')
    for family in (*_FAMILIES, 'journal_stream', 'binding_stream', 'model_stream'):
        value[family] = c09_paged_value_from_wire_v2(value[family], C09SealedStreamLocatorV2)
    return C09PagedFactsCompletionV2(**value)


def install_c09_paged_recovery_schema_v2(candidate):
    for kind, definitions in (('table', RECOVERY_DDLS_V2), ('index', RECOVERY_INDEXES_V2), ('trigger', RECOVERY_TRIGGERS_V2)):
        for name, ddl in definitions.items():
            found = candidate.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?', (kind, name)).fetchone()
            if found is None: candidate.execute(ddl)
            elif found != (ddl,): raise AuthorityUnavailable('registered recovery metadata schema differs: ' + name)


def _require_session_pair(session, pair):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2:
        raise AuthorityUnavailable('actual installed C09 session and role pair required')
    scope = session.require_current(); pair.require_current()
    if pair.source_original.scope_digest != scope.scope_digest or pair._producer.session is not session:
        raise AuthorityUnavailable('C09 role pair belongs to another real capture')
    return scope


class C09PagedRecoveryFactsResolverV2:
    __slots__ = ('_issuer', 'session', 'pair', 'scope', '_db', '_completion', '_owned_db', '_basis')

    def __init__(self, token, session, pair, db, completion, *, owned_db=False):
        if token is not _TOKEN:
            raise AuthorityUnavailable('facts resolver requires the actual installed factory')
        self._issuer, self.session, self.pair = token, session, pair
        self.scope = _require_session_pair(session, pair)
        self._db, self._completion, self._owned_db = db, completion, owned_db
        self._basis = None

    def require_complete(self, *, scope_digest, facts_pin_digest, graph_issue_digest=None):
        _require_session_pair(self.session, self.pair)
        completion = self._completion
        if (completion.scope_digest != scope_digest or completion.pin_digest != facts_pin_digest
                or scope_digest != self.scope.scope_digest):
            raise AuthorityUnavailable('facts resolver does not carry this complete actual pin')
        control = self.session._control.maintenance.control
        original = control.read_build_original_v1(operation_id=self.scope.operation_id, kind='capture_facts_complete_v2')
        if original is None or original['details'] != asdict(completion):
            raise AuthorityUnavailable('actual signed paged facts completion changed')
        if graph_issue_digest is not None:
            issued = self.session._control.require_graph_rebase_completion_v2(self.session)
            if issued.graph_issue_digest != graph_issue_digest or issued.facts_pin_digest != facts_pin_digest:
                raise AuthorityUnavailable('actual Graph issue does not bind these completed facts')
        return completion

    def _lookup(self, family, key, meter):
        self.require_complete(scope_digest=self.scope.scope_digest, facts_pin_digest=self._completion.pin_digest)
        row = _read_one(self._db, 'SELECT value_json,value_digest,origin_digest FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
                        (self.scope.scope_digest, family, key), meter)
        if row is None: return None
        value = _decode_fact(family, row[0]); _require_fact_type(family, value)
        if _fact_key(family, value) != key or canonical_digest(value) != row[1] or canonical_serialize(asdict(value)) != row[0]:
            raise AuthorityUnavailable('actual recovery item differs from its sealed typed commitment')
        return value

    def lookup_execution(self, execution_id, *, meter): return self._lookup('executions', execution_id, meter)
    def lookup_execution_binding(self, execution_id, *, meter): return self._lookup('binding', execution_id, meter)
    def lookup_unknown(self, execution_id, *, meter): return self._lookup('unknown_facts', execution_id, meter)
    def lookup_model_original(self, call_id, *, meter): return self._lookup('model', call_id, meter)
    def lookup_d02(self, quote_id, *, meter): return self._lookup('d02_facts', quote_id, meter)
    def lookup_d11(self, settlement_id, *, meter): return self._lookup('d11_facts', settlement_id, meter)
    def lookup_graph(self, operation_id, *, meter): return self._lookup('graph_facts', operation_id, meter)

    def next_family_page(self, family, *, after_key, limit, meter):
        if family not in _FAMILIES or type(limit) is not int or not 1 <= limit <= 100:
            raise AuthorityUnavailable('bounded named recovery family required')
        self.require_complete(scope_digest=self.scope.scope_digest, facts_pin_digest=self._completion.pin_digest)
        values = []; last = after_key
        cursor = _BoundedReadConnectionV2(self._db, meter).execute(
            'SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY > ? ORDER BY item_key COLLATE BINARY LIMIT ?',
            (self.scope.scope_digest, family, '' if after_key is None else after_key, limit))
        for (key,) in cursor:
            values.append((key, self._lookup(family, key, meter))); last = key
        eof = _read_one(self._db, 'SELECT 1 FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY > ? LIMIT 1',
                        (self.scope.scope_digest, family, '' if last is None else last), meter) is None
        return tuple(values), last, eof

    def _authority_basis(self):
        if self._basis is None:
            self._basis = mint_installed_authority_role_basis_v2(self.session, self.pair, _resolver=self)
        self._basis.require_current()
        return self._basis

    def worker_attempt_fence(self, attempt, *, meter): return self._authority_basis().worker_attempt_fence(attempt, meter=meter)
    def c4proof(self, attempt, *, meter): return self._authority_basis().c4proof(attempt, meter=meter)
    def foreground_fence(self, operation_id, row, *, meter): return self._authority_basis().foreground_fence(operation_id, row, meter=meter)
    def owner_reply_stop(self, key, row, *, meter): return self._authority_basis().owner_reply_stop(key, row, meter=meter)
    def current_singleton(self, table, *, meter): return self._authority_basis().current_singleton(table, meter=meter)
    def require_registered_core_schema(self, original): return self._authority_basis().require_registered_core_schema(original)
    def require_registered_core_row(self, table, columns, row, *, meter): return self._authority_basis().require_registered_core_row(table, columns, row, meter=meter)

    def require_execution_journal_row(self, source_original, columns, row, *, meter):
        if (source_original.scope_digest != self.scope.scope_digest or source_original.role != 'execution'
                or tuple(columns) != ('seq','mutation_id','request_digest','append_id','pending','previous_digest','chain_digest')):
            raise AuthorityUnavailable('execution source row is outside the actual pinned role')
        self.require_complete(scope_digest=self.scope.scope_digest, facts_pin_digest=self._completion.pin_digest)
        actual = _read_one(self._db, 'SELECT row_commitment,mutation_id,chain_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq=?',
            (self.scope.scope_digest, row[0]), meter)
        if actual != (_journal_commitment(row), row[1], row[6]) or not 1 <= row[0] <= self._completion.old_seq:
            raise AuthorityUnavailable('actual execution source row differs from its complete recovery stream')
        return True

    def require_execution_journal_stream_v3(self,source_original,columns,small,pending_sha256,*,meter):
        """Same pinned journal domain after the caller's complete BLOB EOF."""
        expected=('seq','mutation_id','request_digest','append_id','pending','previous_digest','chain_digest')
        if (source_original.scope_digest!=self.scope.scope_digest or source_original.role!='execution'
                or tuple(columns)!=expected or len(small)!=6
                or type(pending_sha256) is not str or len(pending_sha256)!=64
                or any(char not in '0123456789abcdef' for char in pending_sha256)):
            raise AuthorityUnavailable('execution stream is outside actual pinned role/complete BLOB digest')
        self.require_complete(scope_digest=self.scope.scope_digest,facts_pin_digest=self._completion.pin_digest)
        actual=_read_one(self._db,'SELECT row_commitment,mutation_id,chain_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq=?',
            (self.scope.scope_digest,small[0]),meter)
        value=(*small,pending_sha256)
        upper=16+sum(len(item)*12+2 if type(item) is str else 128 for item in value)
        meter.require_available(upper*2)
        # The runtime serializer and UTF8 copy are each actual outputs.
        from ..runtime_contracts import meter_canonical_outputs
        with meter_canonical_outputs(meter):text=canonical_serialize(value)
        raw=text.encode('utf-8');meter.charge_encode(len(raw));digest=sha256(raw).hexdigest()
        if actual!=(digest,small[1],small[5]) or not 1<=small[0]<=self._completion.old_seq:
            raise AuthorityUnavailable('actual journal stream differs from complete pinned recovery index')
        return True

    def close(self):
        if self._owned_db:
            self._db.close(); self._owned_db = False


def mint_installed_recovery_facts_resolver_v2(session, pair):
    scope = _require_session_pair(session, pair)
    control = session._control.maintenance.control
    original = control.read_build_original_v1(operation_id=scope.operation_id, kind='capture_facts_complete_v2')
    if original is None:
        raise AuthorityUnavailable('actual paged facts completion is not yet available')
    completion = _decode_completion(original['details'])
    if completion.scope_digest != scope.scope_digest or completion.facts_intent_digest != scope.facts_pin_intent_digest:
        raise AuthorityUnavailable('paged facts signed completion belongs to another actual intent')
    if pair.source_original.role == 'graph':
        db, owned = pair.candidate, False
    else:
        issued = session._control.require_graph_rebase_completion_v2(session)
        if issued.facts_pin_digest != completion.pin_digest:
            raise AuthorityUnavailable('actual post-Graph role has another recovery pin')
        intent = control.read_operation_event_v1(scope.operation_id, 'INTENT')
        target = Path(intent['details']['targets']['graph'])
        allocation = control.read_build_original_v1(operation_id=scope.operation_id, kind='allocation_graph')
        stat = target.stat()
        if allocation is None or (stat.st_dev, stat.st_ino) != (allocation['details']['device'], allocation['details']['file_id']):
            raise AuthorityUnavailable('actual Graph facts candidate inode changed')
        db = sqlite3.connect(target.as_uri() + '?mode=ro&immutable=1', uri=True, isolation_level=None)
        db.execute('PRAGMA query_only=ON'); owned = True
    return C09PagedRecoveryFactsResolverV2(_TOKEN, session, pair, db, completion, owned_db=owned)

@dataclass(frozen=True, slots=True)
class _FactsSourceV2:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    graph_role_source_digest: str
    facts_intent_digest: str
    writer_freeze_digest: str
    schema: str = 'sylanne3.c09.facts-logical-source.v2'

    @property
    def seal_digest(self): return canonical_digest(self)


class _OneExecutionOriginalsV2:
    """Reuse real original codecs over one independently indexed execution.

    Each family adapter contains zero or one execution. The old all-journal
    scanner and complete-family tuple producer are never called on all rows.
    """
    def __init__(self, token, producer, execution_id, kind, rows, core, graph, reader):
        if token is not _TOKEN or not 1 <= len(rows) <= 3:
            raise AuthorityUnavailable('one actual indexed execution required')
        self.producer, self.execution_id, self.kind, self.rows = producer, execution_id, kind, rows
        self.namespace_id = producer.maintenance.namespace_id
        port = producer.original_port
        self.resource_issuer, self.body_authority = port.resource_issuer, port.body_authority
        self.budget_job_issuer = port.budget_job_issuer
        self._snapshot = (producer.source, reader, rows, producer.source.seal_digest, graph, core)
        self._cache = {}
        self.internal_services = {}
        if kind == 'internal':
            binding, _, _ = reader._decode_internal_row(rows[0])
            self.internal_services[binding.algorithm_ref] = producer.session.require_fact_original_verifier_v2(
                'internal', core_db=core, business_db=graph, execution_reader=reader, algorithm=binding.algorithm_ref)

    def _current(self, namespace, operation_id):
        if (namespace, operation_id) != (self.producer.scope.authority_namespace, self.producer.scope.operation_id):
            raise AuthorityUnavailable('single execution codec crossed actual capture scope')
        return self._snapshot

    def _installed_verifier(self, kind, namespace):
        if namespace != self.producer.scope.authority_namespace or kind != self.kind:
            raise AuthorityUnavailable('single execution verifier kind/namespace differs')
        key = 'verifier:' + kind
        if key not in self._cache:
            self._cache[key] = self.producer.session.require_fact_original_verifier_v2(
                kind, core_db=self._snapshot[5], business_db=self._snapshot[4], execution_reader=self._snapshot[1])
        return self._cache[key]

    def _family(self, kind, method, namespace, operation_id):
        if self.kind != kind: return ()
        if kind not in self._cache:
            from .c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4
            result = getattr(InstalledC09RecoveryOriginalsV4, method)(self, namespace, operation_id)
            if len(result) != 1:
                raise AuthorityUnavailable('indexed one-execution codec returned another identity inventory')
            binding = result[0][0].numeric if kind == 'series' else result[0][0]
            if binding.execution_id != self.execution_id:
                raise AuthorityUnavailable('indexed execution codec returned another execution')
            self._cache[kind] = result
        return self._cache[kind]

    def _numeric_originals(self, namespace, operation_id): return self._family('numeric', '_numeric_originals', namespace, operation_id)
    def _series_originals(self, namespace, operation_id): return self._family('series', '_series_originals', namespace, operation_id)
    def _root_originals(self, namespace, operation_id): return self._family('authored_root', '_root_originals', namespace, operation_id)
    def _life_originals(self, namespace, operation_id): return self._family('life', '_life_originals', namespace, operation_id)
    def _offline_originals(self, namespace, operation_id): return self._family('offline_tick', '_offline_originals', namespace, operation_id)
    def _model_originals(self, namespace, operation_id):
        self._current(namespace, operation_id)
        return ()

    def _originals(self, namespace, operation_id):
        if 'base' in self._cache: return self._cache['base']
        source, reader, rows, _, _, core = self._current(namespace, operation_id)
        claims, terminals, proofs, phases, by_mutation = {}, {}, {}, {}, {}
        if self.kind == 'internal':
            from .internal_work_contract import InternalWorkTerminalProofV1
            binding, claim, terminal = reader._decode_internal_row(rows[0])
            if terminal is not None:
                raise AuthorityUnavailable('indexed internal first row is not its actual claim')
            claims[binding.binding_digest] = (binding, claim, rows[0])
            service = self.internal_services[binding.algorithm_ref]
            if binding.algorithm_build_digest != service.installed_build_digest:
                raise AuthorityUnavailable('internal source original has another installed build')
            if len(rows) == 2:
                last_binding, last_claim, terminal = reader._decode_internal_row(rows[1])
                if (last_binding, last_claim) != (binding, claim) or terminal is None:
                    raise AuthorityUnavailable('internal terminal crossed its original claim')
                if terminal.status != 'unknown' and not service.verify_installed_terminal(binding, claim, terminal):
                    raise AuthorityUnavailable('internal installed terminal signature differs')
                terminals[binding.binding_digest] = (binding, claim, terminal, rows[1])
                first = reader._internal_append_receipt(rows[0], binding, 'claim')
                last = reader._internal_append_receipt(rows[1], binding, 'terminal')
                proof = InternalWorkTerminalProofV1(binding, claim, terminal, first.receipt_ref,
                    first.content_digest, last.receipt_ref, last.content_digest,
                    JournalHead(reader.journal_id, rows[1][0], rows[1][6]))
                proofs[binding.operation_id] = (proof, service)
        elif self.kind == 'dispatch':
            from .v2_contract import decode_bytes
            pending = decode_bytes(rows[-1][4])
            if pending.permit.effect_id != self.execution_id:
                raise AuthorityUnavailable('indexed dispatch crossed the actual effect')
            phases[self.execution_id] = pending
            by_mutation[pending.mutation_id] = rows[-1]
        result = source, claims, terminals, proofs, phases, by_mutation, core
        self._cache['base'] = result
        return result

    def facts(self):
        from .c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4
        namespace, operation = self.producer.scope.authority_namespace, self.producer.scope.operation_id
        result = {}
        for family, method in (('executions', 'execution'), ('d02_facts', 'd02'),
                               ('d11_facts', 'd11'), ('unknown_facts', 'unknown')):
            result[family] = getattr(InstalledC09RecoveryOriginalsV4, 'read_current_' + method + '_originals_v4')(
                self, namespace=namespace, operation_id=operation)
        if len(result['executions']) != 1 or result['executions'][0].execution_id != self.execution_id:
            raise AuthorityUnavailable('single execution facts lost their actual source identity')
        return result


def _journal_identity(reader, row):
    from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES, decode_series_row_v1
    from .d04_numeric_journal_v3 import ENTRY_PREFIX as NUMERIC, decode_numeric_row_v3
    from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3 as ROOT, decode_root_execution_row_v3
    from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE, decode_life_row_v1
    from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE, decode_offline_tick_row_v1
    for prefix, kind, decode in ((SERIES, 'series', decode_series_row_v1),
            (NUMERIC, 'numeric', decode_numeric_row_v3), (ROOT, 'authored_root', decode_root_execution_row_v3),
            (LIFE, 'life', decode_life_row_v1), (OFFLINE, 'offline_tick', decode_offline_tick_row_v1)):
        if row[4].startswith(prefix):
            if reader._schema_version not in ('2', '4'):
                raise AuthorityUnavailable('typed execution appears in another journal schema')
            original, claim, terminal = decode(reader, row)
            binding = original.numeric if kind == 'series' else original
            return binding.execution_id, binding.operation_id, kind, 'claim' if terminal is None else 'terminal', canonical_digest(original), canonical_digest(claim), binding
    if row[4].startswith(b'{"binding":'):
        binding, claim, terminal = reader._decode_internal_row(row)
        return binding.execution_id, binding.operation_id, 'internal', 'claim' if terminal is None else 'terminal', canonical_digest(binding), canonical_digest(claim), binding
    from .v2_contract import PendingMutationV2, decode_bytes, canonical_bytes
    pending = decode_bytes(row[4])
    if (type(pending) is not PendingMutationV2 or pending.phase not in ('prepared', 'claimed', 'observed')
            or canonical_bytes(pending) != row[4] or pending.permit.namespace != reader.namespace
            or pending.expected_execution_journal_id != reader.journal_id
            or (pending.mutation_id, pending.request_digest, pending.expected_append_id) != row[1:4]
            or pending.before_anchor.execution_seq != row[0] - 1
            or pending.before_anchor.execution_digest != row[5]
            or pending.expected_append_digest != row[6] or reader.expected_digest(pending) != row[6]):
        raise AuthorityUnavailable('actual dispatch chain original differs')
    permit = pending.permit
    binding = canonical_digest((permit.authority_id, permit.namespace, permit.operation_id,
                                 permit.effect_id, permit.command_digest, permit.generation))
    return permit.effect_id, permit.operation_id, 'dispatch', pending.phase, binding, canonical_digest(permit), pending


def _journal_commitment(row):
    return canonical_digest((row[0], row[1], row[2], row[3], row[5], row[6], sha256(row[4]).hexdigest()))


class C09PagedRecoveryFactsProducerV2:
    def __init__(self, token, session, graph_pair):
        if token is not _TOKEN:
            raise AuthorityUnavailable('actual installed facts producer factory required')
        self.session, self.pair = session, graph_pair
        self.scope = _require_session_pair(session, graph_pair)
        if graph_pair.source_original.role != 'graph':
            raise AuthorityUnavailable('facts capture belongs to the registered pre-mirror Graph candidate')
        self.maintenance = session._control.maintenance
        self.control = self.maintenance.control
        from .c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4
        port = self.maintenance.core._execution_recovery_facts_ports_v4.get(self.scope.authority_namespace)
        if type(port) is not InstalledC09RecoveryOriginalsV4 or port.core is not self.maintenance.core:
            raise AuthorityUnavailable('actual installed original-verifier composition is absent')
        self.original_port = port
        intent = self.control.read_build_original_v1(operation_id=self.scope.operation_id, kind='capture_facts_intent_v2')
        if intent is None or intent['original_digest'] != self.scope.facts_pin_intent_digest:
            raise AuthorityUnavailable('actual immutable recovery intent differs')
        head = intent['details']['execution_anchor']
        self.source = _FactsSourceV2(self.scope.authority_id, self.scope.installation_id,
            self.scope.authority_namespace, self.scope.operation_id, *head,
            graph_pair.source_original.role_source_digest, self.scope.facts_pin_intent_digest,
            self.scope.writer_freeze_digest)
        self._last_phase = None
        self._verification = {}
        self._source_readback = {}
        self._history_active = None
        self._natural_model_active_v3 = None
        self._natural_model_connections_v3 = None
        self._natural_model_reservation_v3 = None
        self._readback_only = False
        from secrets import token_hex
        self._verification_id = token_hex(16)

    @contextmanager
    def _connections(self, meter):
        self.session.require_current(); self.pair.require_current()
        current, _ = self.session._control._current(self.scope.operation_id)
        members = {member['role']: member for member in current.manifest['members']}
        with ExitStack() as stack:
            core = stack.enter_context(closing(sqlite3.connect(Path(members['core']['resolved_path']).as_uri() + '?mode=ro', uri=True, isolation_level=None)))
            execution = stack.enter_context(closing(sqlite3.connect(Path(members['execution']['resolved_path']).as_uri() + '?mode=ro', uri=True, isolation_level=None)))
            for db in (core, execution):
                db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
                stack.callback(db.rollback)
            graph = self.pair.source
            if graph.in_transaction:
                raise AuthorityUnavailable('facts capture owns its short Graph read snapshot')
            graph.execute('BEGIN'); stack.callback(graph.rollback)
            bounded_core, bounded_graph, bounded_execution = (_BoundedReadConnectionV2(db, meter) for db in (core, graph, execution))
            from .c09_connection_state_v1 import anchor_in_tx_v1
            anchor = anchor_in_tx_v1(bounded_core, self.scope.authority_namespace)
            if (anchor.authority_id, anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest) != (
                    self.source.authority_id, self.source.execution_journal_id, self.source.execution_seq, self.source.execution_digest):
                raise AuthorityUnavailable('actual facts source execution anchor changed')
            from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
            reader = C09ExecutionOriginalsConnectionV1(db=bounded_execution, control=self.control, namespace=self.scope.authority_namespace)
            started = monotonic_ns()
            self._natural_model_connections_v3 = (bounded_core,bounded_graph,meter)
            try:
                yield bounded_core, bounded_graph, reader
            finally:
                self._natural_model_connections_v3 = None
                self._natural_model_reservation_v3 = None
            if monotonic_ns() - started > 250000000:
                raise C09RecoveryQuantumExhaustedV2('actual recovery read transaction exceeded the installed bound')
            for role in ('core', 'execution'): self.control.verify_member_v1(members[role], prepared=False)
        self.session.require_current(); self.pair.require_current()

    def _progress(self, phase, default, meter):
        if self._readback_only and phase in {'journal','executions','models','graph','history','integrity'}:
            return self._source_readback.get(phase, default)
        row = _read_one(self.pair.candidate,
            'SELECT progress_json FROM c09_recovery_progress_v2 WHERE scope_digest=? AND phase=?',
            (self.scope.scope_digest, phase), meter)
        return default if row is None else json.loads(row[0])

    def _save_progress(self, phase, value, meter):
        if self._readback_only and phase in {'journal','executions','models','graph','history','integrity'}:
            self._source_readback[phase] = value
            return
        encoded = _encoded(value, meter)
        _write(self.pair.candidate, 'INSERT INTO c09_recovery_progress_v2 VALUES (?,?,?) ON CONFLICT(scope_digest,phase) DO UPDATE SET progress_json=excluded.progress_json',
            (self.scope.scope_digest, phase, encoded), meter)

    def _merge(self, family, value, origin_digest, meter):
        _require_fact_type(family, value)
        key = _fact_key(family, value); encoded = _encoded(asdict(value), meter)
        digest = canonical_digest(value)
        prior = _read_one(self.pair.candidate, 'SELECT value_json,value_digest FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
            (self.scope.scope_digest, family, key), meter)
        if prior is not None:
            if prior != (encoded, digest):
                raise AuthorityUnavailable('historical/current recovery identity has conflicting actual originals')
            if self._readback_only:
                _write(self.pair.candidate, 'INSERT INTO c09_recovery_verification_v2 VALUES (?,?,?,?) ON CONFLICT(scope_digest,family,item_key) DO UPDATE SET verification_id=excluded.verification_id',
                    (self.scope.scope_digest, family, key, self._verification_id), meter)
            return
        if self._readback_only:
            raise AuthorityUnavailable('capture omitted an independently re-read actual recovery fact')
        _write(self.pair.candidate, 'INSERT INTO c09_recovery_items_v2 VALUES (?,?,?,?,?,?)',
            (self.scope.scope_digest, family, key, encoded, digest, origin_digest), meter)

    def _advance_journal(self, core, graph, reader, meter, budget):
        progress = self._progress('journal', {'seq': 0, 'chain': 'genesis', 'eof': False}, meter)
        if progress['eof']: return True
        started = monotonic_ns(); completed = 0
        while completed < budget.max_records and monotonic_ns() - started < budget.max_local_ns:
            row = reader._db.execute('SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest FROM authority_v2_execution_entries WHERE seq>? ORDER BY seq LIMIT 1',
                                      (progress['seq'],)).fetchone()
            if row is None:
                if (progress['seq'], progress['chain']) != (self.source.execution_seq, self.source.execution_digest):
                    raise AuthorityUnavailable('complete execution scan disagrees with the real Core source anchor')
                progress['eof'] = True; break
            if row[0] != progress['seq'] + 1 or row[5] != progress['chain']:
                raise AuthorityUnavailable('actual execution source has a gap or changed previous digest')
            execution, operation, kind, phase, binding_digest, claim_digest, _binding = _journal_identity(reader, row)
            prior = _read_one(self.pair.candidate,
                'SELECT business_operation_id,execution_kind,phase,binding_digest,claim_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND execution_id=? AND seq<? ORDER BY seq DESC LIMIT 1',
                (self.scope.scope_digest, execution, row[0]), meter)
            if kind != 'dispatch':
                if phase == 'claim' and prior is not None or phase == 'terminal' and prior != (operation, kind, 'claim', binding_digest, claim_digest):
                    raise AuthorityUnavailable('actual typed terminal has no unique matching preceding claim')
            elif prior is not None and (prior[:2] != (operation, kind) or prior[3:] != (binding_digest, claim_digest)):
                raise AuthorityUnavailable('actual dispatch phase crossed its original permit')
            indexed_values = (self.scope.scope_digest, row[0], execution, operation, kind, phase,
                              binding_digest, claim_digest, _journal_commitment(row), row[1], row[6])
            if self._readback_only:
                saved = _read_one(self.pair.candidate, 'SELECT * FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq=?',
                    (self.scope.scope_digest, row[0]), meter)
                if saved != indexed_values:
                    raise AuthorityUnavailable('independent actual journal re-read differs from capture index')
            else:
                _write(self.pair.candidate, 'INSERT INTO c09_recovery_journal_index_v2 VALUES (?,?,?,?,?,?,?,?,?,?,?)', indexed_values, meter)
            progress['seq'], progress['chain'] = row[0], row[6]; completed += 1
        self._save_progress('journal', progress, meter)
        return progress['eof']

    def _advance_execution(self, core, graph, reader, meter, budget):
        progress = self._progress('executions', {'after': '', 'eof': False}, meter)
        if progress['eof']: return True
        row = _read_one(self.pair.candidate, 'SELECT execution_id,execution_kind,business_operation_id FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND execution_id COLLATE BINARY>? ORDER BY execution_id COLLATE BINARY,seq LIMIT 1',
            (self.scope.scope_digest, progress['after']), meter)
        if row is None:
            progress['eof'] = True; self._save_progress('executions', progress, meter); return True
        execution, kind, operation = row
        indexed = _BoundedReadConnectionV2(self.pair.candidate, meter).execute(
            'SELECT seq,row_commitment FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND execution_id=? ORDER BY seq',
            (self.scope.scope_digest, execution)).fetchall()
        if not 1 <= len(indexed) <= (3 if kind == 'dispatch' else 2):
            raise AuthorityUnavailable('one execution source has an invalid claim/terminal inventory')
        rows = []
        for seq, commitment in indexed:
            actual = reader._db.execute('SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest FROM authority_v2_execution_entries WHERE seq=?', (seq,)).fetchone()
            if actual is None or _journal_commitment(actual) != commitment:
                raise AuthorityUnavailable('actual indexed execution original changed')
            rows.append(actual)
        one = _OneExecutionOriginalsV2(_TOKEN, self, execution, kind, tuple(rows), core, graph, reader)
        facts = one.facts(); original = _journal_identity(reader, rows[-1])[-1]
        generation = original.permit.generation if kind == 'dispatch' else original.activation_generation
        source_rows = tuple(sorted(commitment for _, commitment in indexed))
        origin = canonical_digest((self.source.seal_digest, source_rows))
        for family, values in facts.items():
            for value in values: self._merge(family, value, origin, meter)
        binding = C09ExecutionBindingV1(execution, operation, kind, facts['executions'][0].input_commitment,
            operation, self.source.execution_journal_id, source_rows,
            tuple(sorted(f.quote_id for f in facts['d02_facts'])),
            tuple(sorted(f.component_id for f in facts['d02_facts'])),
            tuple(sorted(f.settlement_id for f in facts['d11_facts'])), generation, None)
        self._merge('binding', binding, origin, meter)
        progress['after'] = execution; self._save_progress('executions', progress, meter)
        return False

    def read_indexed_producer_original_v4(self, execution_id, kind, *, meter, require_arena):
        """One actual frozen C04/Life journal chain; no current factory or writes."""
        from ..runtime.jobs import _identifier
        from ..runtime_contracts import meter_canonical_outputs
        _identifier(execution_id, 'producer execution')
        if kind not in {'internal', 'life'}:
            raise AuthorityUnavailable('only original C04 or Life producer journals are supported')
        self.session.require_current();self.pair.require_current()
        with self._connections(meter) as (core, graph, reader):
            index=_BoundedReadConnectionV2(self.pair.candidate,meter).execute(
                'SELECT seq,execution_kind,business_operation_id,row_commitment FROM c09_recovery_journal_index_v2 '
                'WHERE scope_digest=? AND execution_id=? ORDER BY seq LIMIT 3',
                (self.scope.scope_digest,execution_id)).fetchall()
            if (len(index)!=2 or any(item[1]!=kind for item in index)
                    or index[0][2]!=index[1][2]):
                raise AuthorityUnavailable('actual producer lacks one indexed claim and terminal')
            rows=[]
            with meter_canonical_outputs(meter):
                for seq, _, _, commitment in index:
                    actual=reader._db.execute('SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest '
                        'FROM authority_v2_execution_entries WHERE seq=?',(seq,)).fetchone()
                    if actual is None or _journal_commitment(actual)!=commitment:
                        raise AuthorityUnavailable('indexed producer source journal original changed')
                    rows.append(actual)
                require_arena(sum(len(item[4]) for item in rows)*32+65536)
                one=_OneExecutionOriginalsV2(_TOKEN,self,execution_id,kind,tuple(rows),core,graph,reader)
                if kind=='internal':
                    originals=one._originals(self.scope.authority_namespace,self.scope.operation_id)
                    saved=originals[3].get(index[0][2])
                    if saved is None or saved[0].terminal.status!='completed':
                        raise AuthorityUnavailable('actual C04 producer has no independently verified completed terminal')
                    value=saved[0]
                else:
                    originals=one._life_originals(self.scope.authority_namespace,self.scope.operation_id)
                    if (len(originals)!=1 or originals[0][0].execution_id!=execution_id
                            or originals[0][2] is None or originals[0][2].status!='completed'):
                        raise AuthorityUnavailable('actual Life producer has no verified completed terminal and cost originals')
                    value=originals[0]
        self.session.require_current();self.pair.require_current()
        return {'execution_id':execution_id,'kind':kind,'business_operation_id':index[0][2],
            'source_rows':tuple(item[3] for item in index),'original':value}

    def retain_verified_provider_scope_v3(self,proof,original,*,core,graph):
        from .c09_provider_scope_v3 import retain_verified_model_provider_scope_v3
        return retain_verified_model_provider_scope_v3(self,proof,original,core=core,graph=graph)

    def _advance_models(self, core, graph, reader, meter, budget):
        progress = self._progress('models', {'after': '', 'eof': False}, meter)
        if progress['eof']: return True
        exists = core.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone()
        row = None if exists is None else core.execute('SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? AND call_id COLLATE BINARY>? ORDER BY call_id COLLATE BINARY LIMIT 1',
            (self.scope.authority_namespace, progress['after'])).fetchone()
        if row is None:
            progress['eof'] = True; self._save_progress('models', progress, meter); return True
        call = row[0]
        self._natural_model_reservation_v3 = budget
        identity = core.execute('SELECT job_id FROM authority_model_original_identity_v2 WHERE call_id=? AND namespace=?',
            (call,self.scope.authority_namespace)).fetchone()
        kind = None if identity is None else graph.execute(
            'SELECT work_kind FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?',
            (identity[0],*self.maintenance.namespace_id.as_tuple)).fetchone()
        natural_proof = None
        if kind is not None and kind[0] in {'natural_generation','natural_review'}:
            from .c09_natural_model_original_v3 import NaturalModelGraphOriginalReaderV3
            active = self._natural_model_active_v3
            if active is None:
                self._natural_model_active_v3 = NaturalModelGraphOriginalReaderV3(self,call,identity[0],kind[0].removeprefix('natural_'))
                return False
            if (active.call_id!=call or active.job_id!=identity[0] or active.stage!=kind[0].removeprefix('natural_')):
                raise AuthorityUnavailable('active natural model proof crossed actual selected call/job/stage')
            if not active.complete:
                active.advance(core=core,graph=graph,meter=meter,budget=budget)
                return False
            active.require_current()
            natural_proof = active.issue(core=core,graph=graph,meter=meter,budget=budget)
        elif self._natural_model_active_v3 is not None:
            raise AuthorityUnavailable('active natural model lost its actual natural work kind')
        if natural_proof is None:
            original = read_frozen_model_budget_original_v2(core_db=core, business=graph,
                namespace_id=self.maintenance.namespace_id, seal=self.source,
                resource_issuer=self.original_port.resource_issuer, call_id=call,
                budget_job_issuer=self.original_port.budget_job_issuer,_provider_scope_sink=self)
        else:
            with self._natural_model_active_v3.common_read_scope(core=core,graph=graph,meter=meter,budget=budget):
                original = read_frozen_model_budget_original_v2(core_db=core, business=graph,
                    namespace_id=self.maintenance.namespace_id, seal=self.source,
                    resource_issuer=self.original_port.resource_issuer, call_id=call,
                    budget_job_issuer=self.original_port.budget_job_issuer,_natural_proof=natural_proof,_provider_scope_sink=self)
        if original is not None:
            if original.installation_id != self.scope.installation_id or original.namespace != self.scope.authority_namespace:
                raise AuthorityUnavailable('model recovery original crossed actual installation/namespace')
            origin = original.original_digest
            fact = SanitizedExecutionFactV4(original.call_id, original.request_digest,
                original.observation_digest_or_none, original.terminal_digest_or_none, origin,
                'completed' if original.provider_state == 'observed' else 'pending' if original.provider_state == 'prepared' else 'unknown', True)
            units = tuple(model_unit_fact_v4(original, unit) for unit in original.units if unit.actual_or_none is not None)
            binding = C09ExecutionBindingV1(original.call_id, original.model_operation_id, 'model',
                original.request_digest, original.model_operation_id, original.originating_journal_id,
                tuple(sorted({*original.source_row_commitments, origin})), (), (),
                tuple(sorted(unit.settlement_id for unit in units)), original.dispatch_generation, None)
            self._merge('model', original, origin, meter); self._merge('executions', fact, origin, meter)
            self._merge('binding', binding, origin, meter)
            for unit in units: self._merge('d11_facts', unit, origin, meter)
            if original.provider_state in {'dispatch_started', 'unknown'}:
                from ..runtime_journal import RecoveryConstraintFootprint
                footprint = RecoveryConstraintFootprint(self.scope.authority_namespace, original.job_id,
                    original.call_id, external_idempotency_ref=original.call_id,
                    external_query_ref=original.provider_query_ref_or_none,
                    conflict_keys=tuple(sorted({'model-call:' + call, 'model-job:' + original.job_id,
                                               'model-budget:' + original.parent_budget_id})))
                self._merge('unknown_facts', SanitizedUnknownFactV4(call, original.dispatch_generation,
                    original.provider_query_ref_or_none, 0, (), footprint), origin, meter)
        progress['after'] = call; self._save_progress('models', progress, meter)
        self._natural_model_active_v3 = None
        return False



    def _advance_graph(self, core, graph, reader, meter, budget):
        from ..runtime.c09_graph_originals_read_v5 import (
            read_next_current_graph_original_key_v5, read_current_graph_fact_v5,
            read_next_orphan_graph_operation_v5,
        )
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, C09BatchBudgetV2
        progress = self._progress('graph', {'after': '', 'eof': False}, meter)
        if progress['eof']: return True
        operation = read_next_current_graph_original_key_v5(graph, self.maintenance.namespace_id, progress['after'])
        if operation is None:
            orphan = read_next_orphan_graph_operation_v5(graph, self.maintenance.namespace_id, None)
            if orphan is not None:
                raise AuthorityUnavailable('actual Graph obligation has no committed event original: ' + orphan)
            progress['eof'] = True; self._save_progress('graph', progress, meter); return True
        remaining = meter.remaining_bytes
        if remaining < 32768:
            raise C09RecoveryQuantumExhaustedV2('Graph original needs its own reserved quantum')
        graph_budget = C09BatchBudgetV2(budget.max_records, remaining - 8192, budget.max_local_ns,
                                       budget.max_read_ns, budget.reserved_arena_bytes)
        graph_meter = C09SqlByteMeterV2(graph_budget)
        # This reader owns its finite raw-SQL metering. The surrounding Core
        # and key selection use our measured read adapter, never a second charge.
        fact = read_current_graph_fact_v5(graph.db, self.maintenance.namespace_id, operation, meter=graph_meter)
        meter.charge_read(graph_meter.read_bytes)
        meter.charge_write(graph_meter.written_bytes)
        meter.charge_encode(graph_meter.encoded_bytes)
        if fact is None:
            raise AuthorityUnavailable('actual committed Graph operation disappeared')
        self._merge('graph_facts', fact, canonical_digest((self.source.seal_digest, operation, fact)), meter)
        progress['after'] = operation; self._save_progress('graph', progress, meter)
        return False

    def _advance_history(self, core, graph, reader, meter, budget):
        progress = self._progress('history', {'eof': False}, meter)
        if progress['eof']: return True
        current, _ = self.session._control._current(self.scope.operation_id)
        if current.prepared_original is not None:
            return self._advance_authenticated_history(current, core, graph, reader, meter, budget)
        for table in ('authority_c09_recovery_fact_frames_v4', 'authority_c09_recovery_bindings_v1',
                      'authority_c09_originals_archive_v1', 'authority_c09_execution_source_seals_v4',
                      'authority_c09_execution_source_pins_v4', 'authority_c09_model_budget_originals_v1',
                      'authority_c09_contact_finish_originals_v1'):
            if core.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None:
                if core.execute('SELECT 1 FROM ' + table + ' WHERE namespace=? LIMIT 1',
                                (self.scope.authority_namespace,)).fetchone() is not None:
                    raise AuthorityUnavailable('historical recovery original is outside actual signed storage lineage')
        progress['eof'] = True; self._save_progress('history', progress, meter)
        return True

    def _advance_authenticated_history(self, current, core, graph, reader, meter, budget):
        progress=self._progress('history',{'generation':0,'prior':None,'manifest':None,'eof':False},meter)
        generation=progress.get('generation',0)
        if progress.get('phase')=='orphans':
            return self._advance_history_orphans(current,core,progress,meter)
        mode=self._readback_only
        if self._history_active is None or self._history_active[0:2]!=(mode,generation):
            scan=begin_next_authenticated_prepared_reader_v2(self.control,after_generation=generation,
                through_generation=current.storage_generation,meter=meter)
            if scan is None:
                if (generation!=current.storage_generation or progress.get('manifest')!=current.manifest_digest
                        or progress.get('next_journal')!=self.source.execution_journal_id):
                    raise AuthorityUnavailable('historical signed lineage does not reach this actual selected source')
                progress.update(phase='orphans',table=0,after=None)
                self._save_progress('history',progress,meter);return False
            self._history_active=(mode,generation,scan,None)
        _,_,scan,frame=self._history_active
        if frame is None:
            summary=scan.advance(meter=meter)
            if summary is None:return False
            if (summary['namespace']!=self.scope.authority_namespace
                    or summary['authority_id']!=self.scope.authority_id or summary['installation_id']!=self.scope.installation_id
                    or summary['prior_prepared_digest']!=progress.get('prior')
                    or progress.get('manifest') is not None and summary['old_manifest_digest']!=progress['manifest']):
                raise AuthorityUnavailable('actual historical PREPARED lineage or installed namespace differs')
            if generation==0:
                with self.control._db() as db:
                    first=_read_one(db,'SELECT manifest_digest FROM c09_storage_manifests_v1 '
                        'WHERE installation_id=? AND generation=0',(self.scope.installation_id,),meter)
                if first!=(summary['old_manifest_digest'],):
                    raise AuthorityUnavailable('historical lineage does not start at the actual installed generation zero')
            frame=(_PriorPagedRecoveryFrameV2(self,summary) if isinstance(summary, C09VerifiedPagedPreparedSummaryV2)
                   else _LegacyRecoveryFrameReaderV2(self,summary))
            self._history_active=(mode,generation,scan,frame)
            return False
        done=(frame.advance(core.db,graph.db,meter) if type(frame) is _PriorPagedRecoveryFrameV2 else frame.advance(core.db,meter))
        if not done:return False
        summary=frame.summary
        row=(self.scope.scope_digest,generation+1,summary['operation_id'],summary['prepared_digest'],
             frame.facts_digest,frame.bindings_digest,frame.pin_digest,
             frame.inventory_digest,summary['new_manifest_digest'])
        old=_read_one(self.pair.candidate,'SELECT scope_digest,generation,operation_id,prepared_digest,facts_digest,'
            'bindings_digest,pin_digest,inventory_digest,manifest_digest FROM c09_recovery_history_frames_v2 '
            'WHERE scope_digest=? AND generation=?',row[:2],meter)
        if old is None:
            _write(self.pair.candidate,'INSERT INTO c09_recovery_history_frames_v2 VALUES (?,?,?,?,?,?,?,?,?)',row,meter)
        elif old!=row:
            raise AuthorityUnavailable('completed historical frame changed on actual independent reread')
        progress.update(generation=generation+1,prior=summary['prepared_digest'],manifest=summary['new_manifest_digest'],
                        next_journal=frame.next_journal)
        self._save_progress('history',progress,meter);self._history_active=None
        return False

    def _advance_history_orphans(self,current,core,progress,meter):
        # The latest signed inventory must cover every surviving archive row;
        # historical rows are not authorized merely because their table exists.
        tables=(('authority_c09_recovery_fact_frames_v4',('operation_id',)),
                ('authority_c09_recovery_bindings_v1',('operation_id',)),
                ('authority_c09_originals_archive_v1',('operation_id','original_kind')),
                ('authority_c09_execution_source_seals_v4',('operation_id',)),
                ('authority_c09_execution_source_pins_v4',('operation_id',)),
                ('authority_c09_model_budget_originals_v1',('operation_id','call_id')),
                ('authority_c09_contact_finish_originals_v1',('operation_id','business_operation_id')))
        index=progress['table']
        if index==len(tables):
            progress['eof']=True;self._save_progress('history',progress,meter);return True
        table,keys=tables[index]
        if core.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:
            progress.update(table=index+1,after=None);self._save_progress('history',progress,meter);return False
        after=progress['after']; params=[self.scope.authority_namespace]
        where=''
        if after is not None:
            terms=[]
            for i,key in enumerate(keys):
                terms.append('('+' AND '.join([name+'=?' for name in keys[:i]]+[key+' COLLATE BINARY>?'])+')')
                params.extend((*after[:i],after[i]))
            where=' AND ('+' OR '.join(terms)+')'
        row=core.execute('SELECT '+','.join(keys)+' FROM '+table+' WHERE namespace=?'+where+
            ' ORDER BY '+','.join(k+' COLLATE BINARY' for k in keys)+' LIMIT 1',tuple(params)).fetchone()
        if row is None:
            progress.update(table=index+1,after=None);self._save_progress('history',progress,meter);return False
        frame=_read_one(self.pair.candidate,'SELECT generation FROM c09_recovery_history_frames_v2 '
            'WHERE scope_digest=? AND operation_id=?',(self.scope.scope_digest,row[0]),meter)
        if frame is None or not 1<=frame[0]<=current.storage_generation:
            raise AuthorityUnavailable('historical Core archive is outside actual authenticated storage lineage')
        if table=='authority_c09_contact_finish_originals_v1':
            actual=core.execute('SELECT original_json,original_digest FROM '+table+
                ' WHERE namespace=? AND operation_id=? AND business_operation_id=?',
                (self.scope.authority_namespace,*row)).fetchone()
            from .c09_contact_finish_original_v1 import C09ContactFinishOriginalV1
            from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            original=decode_typed_production_value_v1(json.loads(actual[0]),C09ContactFinishOriginalV1)
            latest=_read_one(self.pair.candidate,'SELECT value_digest FROM c09_recovery_history_members_v2 '
                "WHERE scope_digest=? AND generation=? AND family='contact' AND item_key=?",
                (self.scope.scope_digest,current.storage_generation,row[1]),meter)
            if latest!=(canonical_digest(original),) or original.original_digest!=actual[1]:
                raise AuthorityUnavailable('latest complete Contact inventory omits or changes an actual surviving archive')
        progress['after']=list(row);self._save_progress('history',progress,meter);return False

    def _advance_integrity(self, core, graph, reader, meter, budget):
        progress = self._progress('integrity', {'phase': 'mutations', 'after': '', 'eof': False}, meter)
        if progress['eof']: return True
        phase, after = progress['phase'], progress['after']
        if phase == 'mutations':
            row = core.execute("SELECT mutation_id,state FROM authority_v2_mutations WHERE namespace=? AND mutation_kind='execution' AND mutation_id COLLATE BINARY>? ORDER BY mutation_id COLLATE BINARY LIMIT 1",
                               (self.scope.authority_namespace, after)).fetchone()
            if row is not None:
                linked = _read_one(self.pair.candidate, 'SELECT 1 FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND mutation_id=?',
                                   (self.scope.scope_digest, row[0]), meter)
                if row[1] == 'pending' or row[1] == 'committed' and linked is None:
                    raise AuthorityUnavailable('actual Core execution mutation is absent from the complete journal')
                progress['after'] = row[0]
            else: progress.update(phase='effects', after='')
        elif phase == 'effects':
            row = core.execute('SELECT effect_id,state FROM authority_effects WHERE namespace=? AND effect_id COLLATE BINARY>? ORDER BY effect_id COLLATE BINARY LIMIT 1',
                               (self.scope.authority_namespace, after)).fetchone()
            if row is not None:
                fact = _read_one(self.pair.candidate, "SELECT value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='executions' AND item_key=?",
                                 (self.scope.scope_digest, row[0]), meter)
                if fact is None: raise AuthorityUnavailable('actual Core effect is missing from current or authenticated historical facts')
                value = _decode_fact('executions', fact[0])
                if value.status == 'unknown' and row[1] != 'unresolved':
                    raise AuthorityUnavailable('unknown actual effect lost its unresolved Core constraint')
                progress['after'] = row[0]
            else: progress.update(phase='executions', after='')
        elif phase == 'executions':
            row = _read_one(self.pair.candidate, "SELECT item_key,value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='executions' AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1",
                            (self.scope.scope_digest, after), meter)
            if row is not None:
                value = _decode_fact('executions', row[1])
                binding_row = _read_one(self.pair.candidate, "SELECT value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='binding' AND item_key=?",
                                        (self.scope.scope_digest, row[0]), meter)
                unknown = _read_one(self.pair.candidate, "SELECT 1 FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='unknown_facts' AND item_key=?",
                                    (self.scope.scope_digest, row[0]), meter)
                if binding_row is None or (value.status == 'unknown') != (unknown is not None):
                    raise AuthorityUnavailable('complete execution facts lack exact binding/unknown coverage')
                binding = _decode_fact('binding', binding_row[0])
                if binding.input_commitment != value.input_commitment:
                    raise AuthorityUnavailable('actual execution input and business binding differ')
                if binding.execution_kind == 'dispatch' and core.execute('SELECT 1 FROM authority_effects WHERE namespace=? AND effect_id=?',
                    (self.scope.authority_namespace, row[0])).fetchone() is None:
                    raise AuthorityUnavailable('actual dispatch has no Core effect original')
                for family, keys in (('d02_facts', binding.d02_quote_ids), ('d11_facts', binding.d11_settlement_ids)):
                    for key in keys:
                        if _read_one(self.pair.candidate, 'SELECT 1 FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
                                     (self.scope.scope_digest, family, key), meter) is None:
                            raise AuthorityUnavailable('execution binding lost a real accounting original')
                progress['after'] = row[0]
            else: progress.update(phase='unknown_facts', after='')
        elif phase == 'unknown_facts':
            row = _read_one(self.pair.candidate, "SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='unknown_facts' AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1",
                            (self.scope.scope_digest, after), meter)
            if row is not None:
                actual = _read_one(self.pair.candidate, "SELECT value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family='executions' AND item_key=?",
                                   (self.scope.scope_digest, row[0]), meter)
                if actual is None or _decode_fact('executions', actual[0]).status != 'unknown':
                    raise AuthorityUnavailable('orphan unknown constraint is not a real unknown execution')
                progress['after'] = row[0]
            else: progress['eof'] = True
        self._save_progress('integrity', progress, meter)
        return progress['eof']

    def _stream(self, family):
        if family == 'journal':
            kind, key, key_type = 'execution_journal', 'seq', 'integer'
        elif family == 'binding': kind, key, key_type = 'execution_bindings', 'item_key', 'text'
        elif family == 'model': kind, key, key_type = 'model_originals', 'item_key', 'text'
        else: kind, key, key_type = _FAMILIES[family][2], 'item_key', 'text'
        return C09StreamIdentityV2(self.scope.scope_digest, self.source.seal_digest, kind,
            'c09_recovery:' + family, canonical_digest(('sylanne3.c09.recovery-record-layout.v2', family)),
            (key,), (key_type,))

    def _next_record(self, family, after, meter):
        if family == 'journal':
            row = _read_one(self.pair.candidate, 'SELECT seq,row_commitment FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq>? ORDER BY seq LIMIT 1',
                (self.scope.scope_digest, 0 if after is None else after[0]), meter)
            return None if row is None else C09CaptureRecordV2((row[0],), row[1])
        row = _read_one(self.pair.candidate, 'SELECT item_key,value_digest,origin_digest FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',
            (self.scope.scope_digest, family, '' if after is None else after[0]), meter)
        return None if row is None else C09CaptureRecordV2((row[0],), canonical_digest((family, *row)))

    def _advance_source_readback(self, meter, budget):
        phases = ('journal', 'executions', 'models', 'graph', 'history', 'integrity')
        phase = next((name for name in phases if not self._source_readback.get(name, {}).get('eof')), None)
        if phase is not None:
            import copy
            before = copy.deepcopy(self._source_readback)
            self._readback_only = True
            try:
                with self._connections(meter) as (core, graph, reader):
                    getattr(self, '_advance_' + ('execution' if phase == 'executions' else phase))(core, graph, reader, meter, budget)
            except BaseException:
                self._source_readback = before
                raise
            finally:
                self._readback_only = False
            return False
        # Each independent source fact must have been observed in this private
        # pass; an extra durable fact cannot be justified by an old typed DTO.
        after = self._source_readback.get('extra_after')
        where = '' if after is None else ' AND (family COLLATE BINARY>? OR (family=? AND item_key COLLATE BINARY>?))'
        args = (self.scope.scope_digest,) if after is None else (self.scope.scope_digest, after[0], after[0], after[1])
        row = _read_one(self.pair.candidate, 'SELECT family,item_key FROM c09_recovery_items_v2 WHERE scope_digest=?' + where + ' ORDER BY family COLLATE BINARY,item_key COLLATE BINARY LIMIT 1', args, meter)
        if row is not None:
            seen = _read_one(self.pair.candidate, 'SELECT verification_id FROM c09_recovery_verification_v2 WHERE scope_digest=? AND family=? AND item_key=?',
                             (self.scope.scope_digest, *row), meter)
            if seen != (self._verification_id,):
                raise AuthorityUnavailable('sealed recovery capture contains an item absent from actual source re-read')
            self._source_readback['extra_after'] = row
            return False
        self._source_readback['complete'] = True
        return True

    def _advance_family(self, family, meter, budget):
        from ..runtime.c09_paged_sql_v2 import begin_capture_stream_v2
        stream = self._stream(family); db = self.pair.candidate
        progress = self._progress('seal:' + family,
            {'phase': 'census', 'count': 0, 'last': None,
             'chain': canonical_digest(('sylanne3.c09.recovery-census.v2', stream.stream_id)),
             'eof': None, 'census': None, 'data_eof': None}, meter)
        if progress['phase'] == 'sealed': return True
        begin_capture_stream_v2(db, stream)
        if progress['phase'] == 'census':
            started = monotonic_ns(); rows = 0
            last = None if progress['last'] is None else tuple(progress['last'])
            while rows < budget.max_records and meter.remaining_bytes > 32768 and monotonic_ns() - started < budget.max_local_ns:
                record = self._next_record(family, last, meter)
                if record is None:
                    eof = canonical_digest(('sylanne3.c09.recovery-census-eof.v2', stream.stream_id, progress['count'], last, progress['chain']))
                    census = C09CountOriginalV2(stream.stream_id, progress['count'], last, eof,
                        'c09-facts-count:' + stream.stream_id, canonical_digest((stream, progress['count'], last, progress['chain'], eof)))
                    progress.update(phase='data', eof=eof, census=asdict(census)); break
                progress['count'] += 1
                progress['chain'] = canonical_digest(('sylanne3.c09.recovery-census-record.v2', stream.stream_id,
                    progress['count'], progress['chain'], record))
                last = record.primary_key; progress['last'] = last; rows += 1
        else:
            saved = _read_one(db, "SELECT progress_json FROM c09_capture_progress_v2 WHERE stream_id=? AND phase='data'", (stream.stream_id,), meter)
            data = json.loads(saved[0]); cursor = c09_paged_value_from_wire_v2(data['cursor'], C09PageCursorV2)
            records = []; last = cursor.last_key; started = monotonic_ns()
            # Small batches reserve room for each actual repeated proof encoding
            # and SQL member write. Their complete count is never truncated.
            while len(records) < min(16, budget.max_records) and meter.remaining_bytes > 65536 and monotonic_ns() - started < budget.max_local_ns:
                record = self._next_record(family, last, meter)
                if record is None:
                    progress['data_eof'] = canonical_digest(('sylanne3.c09.recovery-data-eof.v2', stream.stream_id,
                        cursor.record_offset + len(records), last)); break
                records.append(record); last = record.primary_key
            if records:
                page = append_c09_page_v2(stream, cursor, tuple(records))
                _write(db, 'INSERT INTO c09_capture_pages_v2 VALUES (?,?,?,?)',
                    (stream.stream_id, page.page_index, _encoded(asdict(page), meter),
                     _encoded(tuple(asdict(record) for record in records), meter)), meter)
                for offset, record in enumerate(records, 1):
                    _write(db, 'INSERT INTO c09_capture_members_v2 VALUES (?,?,?,?,?,?)',
                        (stream.stream_id, cursor.record_offset + offset, canonical_digest(record.primary_key),
                         _encoded(record.primary_key, meter), record.commitment, page.page_index), meter)
                cursor = page.next_cursor
            data.update(cursor=asdict(cursor), eof=progress['data_eof'])
            _write(db, "UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
                (_encoded(data, meter), stream.stream_id), meter)
            if progress['data_eof'] is not None:
                census = c09_paged_value_from_wire_v2(progress['census'], C09CountOriginalV2)
                seal = seal_c09_stream_v2(stream, cursor, census, data_eof_observation_digest=progress['data_eof'])
                locator = C09SealedStreamLocatorV2('graph', stream, seal)
                _write(db, "UPDATE c09_capture_streams_v2 SET status='sealed',seal_json=? WHERE stream_id=?",
                    (_encoded(asdict(seal), meter), stream.stream_id), meter)
                _write(db, 'INSERT INTO c09_recovery_family_seals_v2 VALUES (?,?,?,?)',
                    (self.scope.scope_digest, family, _encoded(asdict(locator), meter), locator.digest), meter)
                progress['phase'] = 'sealed'
        self._save_progress('seal:' + family, progress, meter)
        return progress['phase'] == 'sealed'

    def _advance_verify_family(self, family, meter, budget):
        stream = self._stream(family)
        row = _read_one(self.pair.candidate, 'SELECT locator_json,locator_digest FROM c09_recovery_family_seals_v2 WHERE scope_digest=? AND family=?',
                        (self.scope.scope_digest, family), meter)
        if row is None: raise AuthorityUnavailable('complete recovery family seal absent')
        locator = c09_paged_value_from_wire_v2(json.loads(row[0]), C09SealedStreamLocatorV2)
        if locator.digest != row[1] or locator.identity != stream:
            raise AuthorityUnavailable('recovery family seal belongs to another exact source')
        state = self._verification.setdefault(family, {'cursor': begin_c09_stream_v2(stream), 'done': False})
        if state['done']: return True
        cursor = state['cursor']
        if cursor.page_index < locator.complete.page_count:
            page_row = _read_one(self.pair.candidate, 'SELECT descriptor_json,records_json FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index=?',
                (stream.stream_id, cursor.page_index), meter)
            if page_row is None: raise AuthorityUnavailable('recovery original page missing during independent re-read')
            page = c09_paged_value_from_wire_v2(json.loads(page_row[0]), C09CapturePageV2)
            raw = json.loads(page_row[1])
            if type(raw) is not list or not 1 <= len(raw) <= 100:
                raise AuthorityUnavailable('recovery original page has an invalid record census')
            records = tuple(c09_paged_value_from_wire_v2(value, C09CaptureRecordV2) for value in raw)
            actual_last = cursor.last_key
            for offset, record in enumerate(records, 1):
                actual = self._next_record(family, actual_last, meter)
                if actual != record: raise AuthorityUnavailable('sealed recovery page omitted, reordered or changed an actual source item')
                member = _read_one(self.pair.candidate, 'SELECT key_digest,primary_key_json,commitment,page_index FROM c09_capture_members_v2 WHERE stream_id=? AND record_ordinal=?',
                    (stream.stream_id, cursor.record_offset + offset), meter)
                if member != (canonical_digest(record.primary_key), canonical_serialize(record.primary_key), record.commitment, page.page_index):
                    raise AuthorityUnavailable('recovery page index differs from actual committed member')
                if family != 'journal':
                    body = _read_one(self.pair.candidate, 'SELECT value_json,value_digest FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
                        (self.scope.scope_digest, family, record.primary_key[0]), meter)
                    value = _decode_fact(family, body[0])
                    if canonical_digest(value) != body[1] or _fact_key(family, value) != record.primary_key[0]:
                        raise AuthorityUnavailable('actual recovery value does not match the sealed typed fact')
                actual_last = record.primary_key
            next_cursor = verify_c09_page_v2(stream, cursor, page, records)
            state['cursor'] = next_cursor
            return False
        if self._next_record(family, cursor.last_key, meter) is not None:
            raise AuthorityUnavailable('sealed recovery stream omitted a source suffix')
        if _read_one(self.pair.candidate, 'SELECT 1 FROM c09_capture_pages_v2 WHERE stream_id=? AND (page_index<0 OR page_index>=?) LIMIT 1',
                     (stream.stream_id, locator.complete.page_count), meter) is not None:
            raise AuthorityUnavailable('recovery stream includes an extra unsealed page')
        if _read_one(self.pair.candidate, 'SELECT 1 FROM c09_capture_members_v2 WHERE stream_id=? AND (record_ordinal<1 OR record_ordinal>?) LIMIT 1',
                     (stream.stream_id, locator.complete.record_count), meter) is not None:
            raise AuthorityUnavailable('recovery stream includes an extra unsealed membership')
        progress = self._progress('seal:' + family, None, meter)
        census = c09_paged_value_from_wire_v2(progress['census'], C09CountOriginalV2)
        verify_c09_complete_stream_v2(stream, cursor, census, locator.complete,
                                      data_eof_observation_digest=progress['data_eof'])
        if family == 'journal' and locator.complete.record_count != self.source.execution_seq:
            raise AuthorityUnavailable('complete journal recovery stream has another actual source length')
        state['done'] = True
        return True

    def advance(self):
        """Commit private verification progress with the actual capture transaction."""
        from copy import deepcopy
        before = deepcopy((self._source_readback, self._verification))
        try:
            return self._advance_quantum()
        except BaseException:
            self._source_readback, self._verification = before
            self._history_active = None
            self._natural_model_active_v3 = None
            raise

    def _advance_quantum(self):
        """One real installed quantum; no caller rows, counts, flags or paths."""
        from ..runtime.c09_paged_sql_v2 import capture_transaction_v2, install_c09_capture_schema_v2
        self.session.require_current(); self.pair.require_current()
        if not self.session.advance_d13_runtime_qualification_v3():
            return {'status':'progress','phase':'d13_installed_runtime_qualification'}
        started = monotonic_ns(); families = ('journal', *_FAMILIES, 'binding', 'model')
        with self.session.reserve_batch() as budget:
            from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
            meter = C09RecoveryMeterV2(budget.max_bytes,parent=require_c09_reserved_meter_v3(budget))
            from ..runtime.c09_paged_sql_v2 import c09_sql_meter_quantum_v2
            with c09_sql_meter_quantum_v2(meter.parent):
                with capture_transaction_v2(self.pair.candidate):
                    install_c09_capture_schema_v2(self.pair.candidate)
                    install_c09_paged_recovery_schema_v2(self.pair.candidate)
                    progress = self._progress('capture', {'phase': 'journal', 'family': 0}, meter)
                    phase = progress['phase']
                    if phase in {'journal', 'executions', 'models', 'graph', 'history', 'integrity'}:
                        with self._connections(meter) as (core, graph, reader):
                            done = getattr(self, '_advance_' + ('execution' if phase == 'executions' else phase))(core, graph, reader, meter, budget)
                        if done:
                            order = ('journal', 'executions', 'models', 'graph', 'history', 'integrity', 'source_verify')
                            progress['phase'] = order[order.index(phase) + 1]
                    elif phase == 'source_verify':
                        done = self._advance_source_readback(meter, budget)
                        if done: progress.update(phase='seals', family=0)
                    elif phase == 'seals':
                        family = families[progress['family']]
                        if self._advance_family(family, meter, budget):
                            progress['family'] += 1
                            if progress['family'] == len(families): progress.update(phase='verify', family=0)
                    elif phase == 'verify':
                        # A restarted producer discards diagnostic verify cursors;
                        # every actual page is independently re-read from zero.
                        family = next((name for name in families if not self._verification.get(name, {}).get('done')), None)
                        if family is None: progress['phase'] = 'provider_scopes'
                        else: self._advance_verify_family(family, meter, budget)
                    elif phase == 'provider_scopes':
                        from .c09_provider_scope_v3 import advance_capture_provider_scope_complete_v3
                        if advance_capture_provider_scope_complete_v3(self,meter=meter.parent):
                            progress['phase']='complete'
                    elif phase != 'complete':
                        raise AuthorityUnavailable('unknown persisted recovery capture phase')
                    self._save_progress('capture', progress, meter)
            elapsed = monotonic_ns() - started
        self.session.require_current(); self.pair.require_current()
        if progress['phase'] == 'complete':
            # Completion is issued only after this process actually verified all
            # pages. A mutable persisted phase alone cannot authorize a pin.
            if not self._source_readback.get('complete') or not all(self._verification.get(name, {}).get('done') for name in families):
                with self.session.reserve_batch() as recovery_budget:
                    recovery_meter = C09RecoveryMeterV2(recovery_budget.max_bytes,parent=require_c09_reserved_meter_v3(recovery_budget))
                    with meter_c09_commitments_v2(recovery_meter.parent), capture_transaction_v2(self.pair.candidate):
                        self._save_progress('capture', {'phase': 'source_verify', 'family': 0}, recovery_meter)
                return {'status': 'progress', 'phase': 'source_verify', 'elapsed_ns': elapsed}
            return self._issue_completion()
        return {'status': 'progress', 'phase': progress['phase'], 'read_bytes': meter.read_bytes,
                'written_bytes': meter.write_bytes, 'encoded_bytes': meter.encoded_bytes,
                'elapsed_ns': elapsed, 'resource_quantum_within_limit': elapsed <= budget.max_local_ns}

    def _issue_completion(self):
        with self.session.reserve_batch() as budget:
            from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
            meter = C09RecoveryMeterV2(budget.max_bytes,parent=require_c09_reserved_meter_v3(budget))
            with meter_c09_commitments_v2(meter.parent):
                return self._issue_reserved_completion(meter)

    def _issue_reserved_completion(self, meter):
        locators = {}
        for family in ('journal', *_FAMILIES, 'binding', 'model'):
            row = _read_one(self.pair.candidate, 'SELECT locator_json,locator_digest FROM c09_recovery_family_seals_v2 WHERE scope_digest=? AND family=?',
                (self.scope.scope_digest, family), meter)
            locator = c09_paged_value_from_wire_v2(json.loads(row[0]), C09SealedStreamLocatorV2)
            if locator.digest != row[1] or not self._verification[family]['done']:
                raise AuthorityUnavailable('actual recovery completion lost a verified family')
            locators[family] = locator
        completion = C09PagedFactsCompletionV2(self.scope.scope_digest, self.scope.facts_pin_intent_digest,
            self.source.execution_journal_id, self.source.execution_seq, self.source.execution_digest,
            self.source.seal_digest, *(locators[family] for family in _FAMILIES),
            locators['journal'], locators['binding'], locators['model'])
        if len(_encoded(asdict(completion), meter).encode('utf-8')) > 65536:
            raise AuthorityUnavailable('actual compact recovery pin exceeds its fixed descriptor limit')
        original = self.control.record_build_original_v1(operation_id=self.scope.operation_id,
            kind='capture_facts_complete_v2', details=asdict(completion))
        if original['details'] != asdict(completion):
            raise AuthorityUnavailable('actual recovery completion replay changed')
        return mint_installed_recovery_facts_resolver_v2(self.session, self.pair)


def begin_installed_c09_recovery_facts_v2(session, graph_pair):
    """Begin only from the real installed session and registered Graph pair."""
    return C09PagedRecoveryFactsProducerV2(_TOKEN, session, graph_pair)

class InstalledC09AuthorityRoleBasisV2:
    __slots__ = ('_issuer', 'session', 'pair', 'scope', 'facts', 'pin_digest',
                 'graph_issue_digest', 'accepted_receipt', 'new_core_path', '_completion')

    def __init__(self, token, session, pair, facts, completion, accepted, new_core_path):
        if token is not _TOKEN:
            raise AuthorityUnavailable('actual installed authority role basis required')
        self._issuer, self.session, self.pair = token, session, pair
        self.scope = _require_session_pair(session, pair)
        self.facts, self._completion = facts, completion
        self.pin_digest, self.graph_issue_digest = completion.facts_pin_digest, completion.graph_issue_digest
        self.accepted_receipt, self.new_core_path = accepted, new_core_path

    def require_current(self):
        _require_session_pair(self.session, self.pair)
        current = self.session._control.require_graph_rebase_completion_v2(self.session)
        if current != self._completion:
            raise AuthorityUnavailable('actual authority role issue/mirror basis changed')
        self.facts.require_complete(scope_digest=self.scope.scope_digest,
                                    facts_pin_digest=self.pin_digest, graph_issue_digest=self.graph_issue_digest)
        return self

    def record_source_qualified_natural_final_core_rows_v4(self,reader,*,meter):
        """Actual current Source consumer registers one immutable sparse obligation."""
        from .c09_natural_final_history_v4 import record_source_qualified_natural_final_core_row_v4
        self.require_current()
        from .c09_natural_final_authority_v3 import NaturalFinalAuthorityOriginalReadV3
        from .c09_natural_final_history_v4 import NaturalFinalHistoricalPermissionsReadV4
        if type(reader) is NaturalFinalAuthorityOriginalReadV3:builder=reader.builder
        elif type(reader) is NaturalFinalHistoricalPermissionsReadV4:builder=reader.capture.builder
        else:raise AuthorityUnavailable('actual final Source semantic reader required')
        if builder.basis is not self or builder.session is not self.session or builder.pair is not self.pair:
            raise AuthorityUnavailable('natural Core obligation crossed actual Source role basis')
        record_source_qualified_natural_final_core_row_v4(reader,meter=meter)
        self.require_current()

    def require_source_qualified_natural_final_core_row_v4(self,table,columns,row,*,meter):
        """Only a registered exact Source obligation can retain an otherwise retired row."""
        from .c09_natural_final_history_v4 import require_natural_final_core_obligation_schema_v4
        from . import c09_authority_storage_rebase as legacy
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        self.require_current();control=self.session._control.maintenance.control
        shape=read_c09_table_shape_v2(self.pair.source,table,meter=meter)
        if tuple(columns)!=shape.columns:raise AuthorityUnavailable('natural Core preservation Source shape changed')
        key=tuple(row[columns.index(name)] for name in shape.primary_key_columns)
        with control._db() as db:
            present=_read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_natural_final_core_required_v4'",(),meter)
            if present is None:return None
            require_natural_final_core_obligation_schema_v4(db,meter=meter)
            saved=_read_one(db,'SELECT source_json,source_commitment FROM c09_natural_final_core_required_v4 WHERE scope_digest=? AND table_name=? AND key_digest=?',
                (self.scope.scope_digest,table,canonical_digest(key)),meter)
        if saved is None:return None
        encoded=legacy._canonical((table,columns,tuple(legacy._cell(value) for value in row)));meter.charge_encode(len(encoded))
        commitment=sha256(encoded).hexdigest();value=json.loads(saved[0])
        if (sha256(saved[0].encode('ascii')).hexdigest()!=saved[1] or value['scope_digest']!=self.scope.scope_digest
                or value['core_source_original_digest']!=self.pair.source_original.role_source_digest or value['table']!=table
                or value['schema_digest']!=shape.schema_digest or tuple(value['primary_key'])!=key or value['key_digest']!=canonical_digest(key)
                or value['source_row_commitment']!=commitment or value['expected_target_row_commitment']!=commitment
                or value['required_disposition']!='preserved_exact'):
            raise AuthorityUnavailable('registered natural Core retention obligation differs from actual full Source row')
        self.require_current();return value['source_row_commitment']

    @contextmanager
    def _connections(self, meter):
        self.require_current()
        control = self.session._control.maintenance.control
        current, intent = self.session._control._current(self.scope.operation_id)
        members = {member['role']: member for member in current.manifest['members']}
        with ExitStack() as stack:
            connections = []
            for path in (members['core']['resolved_path'], members['graph']['resolved_path'], intent['details']['targets']['graph']):
                db = stack.enter_context(closing(sqlite3.connect(Path(path).as_uri() + '?mode=ro', uri=True, isolation_level=None)))
                db.execute('PRAGMA query_only=ON'); db.execute('BEGIN'); stack.callback(db.rollback)
                connections.append(_BoundedReadConnectionV2(db, meter))
            started = monotonic_ns()
            yield tuple(connections)
            if monotonic_ns() - started > 250000000:
                raise C09RecoveryQuantumExhaustedV2('authority basis read snapshot exceeded its installed limit')
            control.verify_member_v1(members['core'], prepared=False)
            control.verify_member_v1(members['graph'], prepared=False)
        self.require_current()

    def worker_attempt_fence(self, attempt, *, meter):
        from .v2_worker_model_result_attempts import require_worker_result_read_attempt_fence_v1
        if attempt.request.authority_namespace != self.scope.authority_namespace:
            # Other namespace originals must be checked under their own actual
            # installation; this erasure never grants that authority.
            return None
        with self._connections(meter) as (core, _graph, _target):
            return require_worker_result_read_attempt_fence_v1(core, attempt=attempt,
                authority_id=self.scope.authority_id, authority_namespace=self.scope.authority_namespace,
                installation_id=self.scope.installation_id)

    def c4proof(self, attempt, *, meter):
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadRequestV1
        if (attempt.request.authority_namespace != self.scope.authority_namespace
                or type(attempt.request) is not ArtifactDraftModelResultReadRequestV1):
            return None
        from .c09_authority_storage_rebase import _require_c4_read_attempt_core_original_v1
        with self._connections(meter) as (core, _graph, _target):
            _require_c4_read_attempt_core_original_v1(core, attempt)
        return True

    def _graph_disposition(self, graph, target, table, row, meter):
        """Consume actual post-mirror roots and exact source/target row members."""
        from ..runtime.c09_paged_sql_v2 import (read_c09_table_shape_v2,c09_row_commitment_v2,
            c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2)
        if row is None:raise AuthorityUnavailable('actual historical Graph source row is absent: '+table)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3()
        candidate=verified.require_current();source=verified.pair.source;db=verified._read_db
        for actual,expected in ((graph,verified.pair.source_original.source_path),(target,verified.pair.target_path)):
            path=actual.execute('PRAGMA database_list').fetchone()[2]
            if Path(path).resolve(strict=True)!=Path(expected).resolve(strict=True):
                raise AuthorityUnavailable('Graph disposition point proof crossed actual source/target')
        point=_C09ReadonlyPointMeterV3(meter)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,table,meter=point)
            if len(row)!=len(shape.columns):raise AuthorityUnavailable('actual Source row schema differs')
            key=tuple(row[shape.columns.index(name)] for name in shape.primary_key_columns)
            actual_source=point.read_row(source,shape,key)
            if actual_source!=tuple(row):raise AuthorityUnavailable('point source row differs from actual frozen original')
            old_commitment=c09_row_commitment_v2(tuple(actual_source));scope=self.scope.scope_digest
            result=self._graph_disposition_key_v3(verified,shape,key,point)
            if result.old_commitment!=old_commitment:
                raise AuthorityUnavailable('actual disposition lost bounded frozen Source commitment')
        verified.require_current();self.require_current()
        return result

    def _graph_disposition_original_v3(self,verified,shape,key,point):
        """Only the live full-Source cold verifier qualifies original page commitments."""
        from ..runtime.c09_storage_rebase_contract_v1 import GraphRowDispositionV1
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_row_commitment_v2,require_c09_capture_member_v2
        from ..runtime.c09_paged_capture_contract_v2 import C09CompleteStreamV2
        if verified is not self.session.require_actual_post_mirror_graph_v3():
            raise AuthorityUnavailable('Source member consumer lacks the actual retained cold verifier')
        if shape.table=='graph_domain_production_originals_v3' or (shape.table in {'graph_atoms','graph_history'} and 'value_cell_id' in shape.columns):
            actual=read_c09_table_shape_v2(verified.pair.source,shape.table,meter=point)
            if actual!=shape:raise AuthorityUnavailable('logical Source consumer changed the actual physical shape')
            result=verified.require_original_disposition_row_v3(shape.table,key,meter=point)
            verified.require_current();self.require_current();return result
        candidate=verified.require_current();db=verified._read_db;table=shape.table;scope=self.scope.scope_digest
        columns=('scope_digest','family','identity_json','complete_json')
        directory=point.read_fixed_row(db,'c09_graph_disposition_directory_v2',columns,
            'scope_digest=? AND family=?',(scope,table))
        if directory is None:raise AuthorityUnavailable('actual Graph disposition family is absent')
        outer=candidate.disposition_directory
        outer_shape=read_c09_table_shape_v2(db,'c09_graph_disposition_directory_v2',meter=point)
        if (outer.identity.family!='c09_graph_disposition_directory_v2'
                or outer.identity.schema_digest!=outer_shape.schema_digest
                or outer.identity.primary_key_columns!=outer_shape.primary_key_columns):
            raise AuthorityUnavailable('actual Graph disposition directory root schema differs')
        def member(stream,complete,primary_key,commitment):
            item=point.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
                'stream_id=? AND key_digest=?',(stream.stream_id,canonical_digest(primary_key)))
            if item is None or item[1]!=commitment or not 1<=item[0]<=complete.record_count:
                raise AuthorityUnavailable('actual post-mirror member is outside complete original bounds')
            require_c09_capture_member_v2(db,stream,item[0],primary_key,commitment,meter=point)
            return item[0]
        member(outer.identity,outer.complete,(scope,table),c09_row_commitment_v2(tuple(directory)))
        stream=c09_paged_value_from_wire_v2(json.loads(directory[2]),C09StreamIdentityV2)
        complete=c09_paged_value_from_wire_v2(json.loads(directory[3]),C09CompleteStreamV2)
        if (stream.scope_digest!=scope or stream.role_source_digest!=candidate.source.role_source_digest
                or stream.family!=table or stream.stream_kind!='row_dispositions'
                or stream.schema_digest!=shape.schema_digest or stream.primary_key_columns!=shape.primary_key_columns
                or stream.primary_key_types!=shape.primary_key_types or complete.stream_id!=stream.stream_id):
            raise AuthorityUnavailable('actual disposition stream crossed Source identity/schema/key')
        sealed=point.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,))
        if sealed is None or sealed[0]!='sealed' or c09_paged_value_from_wire_v2(json.loads(sealed[1]),C09CompleteStreamV2)!=complete:
            raise AuthorityUnavailable('actual disposition complete original differs')
        source_directory=point.read_fixed_row(db,'c09_graph_stream_directory_v2',('identity_json','complete_json'),
            'scope_digest=? AND directory_kind=? AND family=?',(scope,'source_originals',table))
        if source_directory is None:raise AuthorityUnavailable('actual source original family completion absent')
        origin=c09_paged_value_from_wire_v2(json.loads(source_directory[0]),C09StreamIdentityV2)
        origin_complete=c09_paged_value_from_wire_v2(json.loads(source_directory[1]),C09CompleteStreamV2)
        if (origin.scope_digest!=scope or origin.role_source_digest!=candidate.source.role_source_digest
                or origin.family!=table or origin.stream_kind!='graph_facts' or origin.schema_digest!=shape.schema_digest
                or origin.primary_key_columns!=shape.primary_key_columns or origin.primary_key_types!=shape.primary_key_types
                or origin_complete.stream_id!=origin.stream_id):
            raise AuthorityUnavailable('actual source original stream identity differs')
        origin_sealed=point.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(origin.stream_id,))
        if (origin_sealed is None or origin_sealed[0]!='sealed'
                or c09_paged_value_from_wire_v2(json.loads(origin_sealed[1]),C09CompleteStreamV2)!=origin_complete):
            raise AuthorityUnavailable('actual Source complete stream differs from original sealed state')
        original=point.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND key_digest=?',(origin.stream_id,canonical_digest(key)))
        if original is None:raise AuthorityUnavailable('actual full-Source cold member absent')
        old_commitment=original[1];origin_ordinal=member(origin,origin_complete,key,old_commitment)
        proof_columns=('scope_digest','table_name','key_digest','source_primary_key_json','old_commitment',
            'disposition','new_commitment','origin_stream_id','origin_record_ordinal')
        proof=point.read_fixed_row(db,'c09_graph_dispositions_v2',proof_columns,
            'scope_digest=? AND table_name=? AND key_digest=?',(scope,table,canonical_digest((table,key))))
        if (proof is None or proof[3]!=canonical_serialize(key) or proof[4]!=old_commitment
                or proof[7]!=origin.stream_id or proof[8]!=origin_ordinal):
            raise AuthorityUnavailable('actual disposition lost complete frozen Source member/ordinal')
        member(stream,complete,key,c09_row_commitment_v2(tuple(proof)))
        result=GraphRowDispositionV1(proof[2],proof[4],proof[5],proof[6])
        verified.require_current();self.require_current()
        return result

    def _graph_disposition_key_v3(self,verified,shape,key,point):
        """Complete existing point consumer, including actual target commitment."""
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_row_commitment_v2
        result=self._graph_disposition_original_v3(verified,shape,key,point)
        db=verified._read_db;table=shape.table
        target_shape=read_c09_table_shape_v2(db,table,meter=point)
        if (target_shape.primary_key_columns,target_shape.primary_key_types)!=(shape.primary_key_columns,shape.primary_key_types):
            raise AuthorityUnavailable('actual V3 target changed Source logical primary key contract')
        actual_target=point.read_row(db,target_shape,key)
        if result.disposition=='derived_removed':
            if actual_target is not None:raise AuthorityUnavailable('removed Graph original retained target row')
        elif shape.table=='graph_domain_production_originals_v3' or (shape.table in {'graph_atoms','graph_history'} and 'value_cell_id' in shape.columns):
            from .c09_authority_storage_rebase import _row_commitment
            if actual_target is None or _row_commitment(table,target_shape.columns,tuple(actual_target))!=result.new_commitment:
                raise AuthorityUnavailable('actual mapped V3 Graph physical target commitment differs')
        elif actual_target is None or c09_row_commitment_v2(tuple(actual_target))!=result.new_commitment:
            raise AuthorityUnavailable('actual V3 Graph target ref row commitment differs')
        verified.require_current();self.require_current()
        return result

    def read_installed_natural_model_authority_v3(self):
        """Actual protected installation; configuration is not execution permission."""
        from .deployment_config import AuthorityDeploymentConfig,InstalledNaturalModelAuthorityV2
        from ..host.authority_profile import AdminInstallationBundle
        from ..host.model_workflows_v7 import AdminModelWorkflowsV7
        self.require_current();maintenance=self.session._control.maintenance
        config=getattr(maintenance,'_installed_deployment_config_v2',None)
        if type(config) is not AuthorityDeploymentConfig:
            raise AuthorityUnavailable('actual C09 protected natural deployment configuration absent')
        model=(config.natural_model_authorities_v2 or {}).get(self.scope.authority_namespace)
        if type(model) is not InstalledNaturalModelAuthorityV2:
            raise AuthorityUnavailable('actual C09 natural authority namespace installation absent')
        bundle=model.installation_bundle
        if (type(bundle) is not AdminInstallationBundle or type(model.workflows) is not AdminModelWorkflowsV7
                or bundle.model_workflows is not model.workflows
                or model.d11_issuer is not getattr(maintenance,'_installed_d11_budget_job_issuer_v2',None)
                or model.d11_issuer.resource_issuer is not getattr(maintenance,'_installed_d02_resource_issuer_v2',None)):
            raise AuthorityUnavailable('actual C09 natural workflow/bundle/D11/D02 installation objects differ')
        policy=bundle.installation_policy;observer=config.installations_v2.get(model.observer_peer)
        if (observer is None or policy.namespace!=maintenance.namespace_id
                or policy.authority_namespace!=self.scope.authority_namespace
                or policy.expected_authority_id!=self.scope.authority_id
                or policy.installation_id!=observer.installation_id
                or config.namespace_bindings_v2.get((*model.observer_peer,policy.namespace))!=self.scope.authority_namespace):
            raise AuthorityUnavailable('actual C09 natural installation/observer/business scope differs')
        self.require_current();return model,observer

    def read_natural_historical_budget_v3(self,plan,*,source,meter):
        """Original signed grant versions and real leases; no renewal or new admission."""
        from ..domains.d08.natural_plan import AdoptedNaturalPlanV2
        from ..runtime.natural_reply_budget_v3 import _require_installed_root
        from ..runtime.budget import get_budget_lease
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2,c09_canonical_json_size_v3
        from .c09_authority_storage_rebase_v2 import _D13FrozenSourceV3
        if type(source) is not _D13FrozenSourceV3 or source.builder.basis is not self or source.kind!='natural':
            raise AuthorityUnavailable('actual historical budget needs the same named frozen Source arena')
        source.require_current()
        if type(plan) is not AdoptedNaturalPlanV2:
            raise AuthorityUnavailable('actual decoded natural plan required for historical budget')
        model,_observer=self.read_installed_natural_model_authority_v3();bundle=model.installation_bundle
        namespace=bundle.installation_policy.namespace;policy=bundle.installation_policy
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(verified.pair.source):
            db=_BoundedReadConnectionV2(verified.pair.source,point)
            owned=[]
            def heap(value):
                import sys
                from dataclasses import fields,is_dataclass
                total=sys.getsizeof(value)
                if type(value) is dict:total+=sum(heap(key)+heap(item) for key,item in value.items())
                elif type(value) in (tuple,list,set):total+=sum(heap(item) for item in value)
                elif is_dataclass(value) and not isinstance(value,type):total+=sum(heap(getattr(value,field.name)) for field in fields(value))
                return total
            def reserve(extra):
                # These decoded local objects are not yet attached to the
                # returned reader state, so include them with its real arena.
                source.require_arena(extra+heap(owned))
            def signed(lease_id,version):
                row=db.execute("SELECT length(CAST(grant_json AS BLOB)),length(grant_json),length(CAST(signature AS BLOB)) FROM runtime_budget_grants WHERE lease_id=? AND version=?",
                    (lease_id,version)).fetchone()
                if row is None:raise AuthorityUnavailable('actual historical signed grant size original absent')
                amount,characters,signature_bytes=row
                reserve(amount*36+characters*4+signature_bytes*4+65536)
                statement="SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?"
                # Cover the formal reader's SQL/parameters, two cell metadata
                # pairs and actual row transfer before its signature encoding.
                needed=len(statement)+_bytes((lease_id,version))+30+amount+signature_bytes+amount+len('budget-grant.v1\n')
                point.require_available(needed)
                grant,signature=model.d11_issuer.signed_budget_grant_at_version(db,lease_id,version)
                point.charge_encode(amount+len('budget-grant.v1\n'))
                owned.extend((grant,signature));return grant,signature
            def lease_size(lease_id):
                row=db.execute("SELECT length(CAST(limits_json AS BLOB))+length(CAST(used_json AS BLOB))+length(CAST(reserved_json AS BLOB))+length(CAST(unconfirmed_json AS BLOB)) FROM runtime_budget_leases WHERE lease_id=?",
                    (lease_id,)).fetchone()
                if row is None:raise AuthorityUnavailable('actual historical lease size original absent')
                reserve(row[0]*40+65536)
            root_grant,_root_signature=signed(policy.root_lease.lease_id,policy.root_grant.version)
            lease_size(policy.root_lease.lease_id)
            root_lease,_root_grant=_require_installed_root(db,namespace,bundle,root_grant);owned.append(root_lease)
            grant,_signature=signed(plan.parent_budget_lease_id,plan.budget_grant_version)
            lease_size(plan.parent_budget_lease_id);lease=get_budget_lease(db,plan.parent_budget_lease_id);owned.append(lease)
            encoded=c09_canonical_json_size_v3(grant,typed=True,exact=True)
            point.require_available(encoded*2);reserve(encoded*16+16384)
            wire=canonical_serialize(grant).encode('ascii');point.charge_encode(len(wire))
            if (sha256(wire).hexdigest()!=plan.budget_grant_digest
                    or (grant.bot_id,grant.persona_id)!=namespace.as_tuple
                    or (lease.bot_id,lease.persona_id)!=namespace.as_tuple):
                raise AuthorityUnavailable('actual natural historical signed grant/lease scope differs')
            dispositions=[]
            for table,key in (('runtime_budget_grants',(policy.root_lease.lease_id,policy.root_grant.version)),
                    ('runtime_budget_leases',(policy.root_lease.lease_id,)),
                    ('runtime_budget_grants',(grant.lease_id,grant.version)),
                    ('runtime_budget_leases',(plan.parent_budget_lease_id,))):
                shape=read_c09_table_shape_v2(verified.pair.source,table,meter=point)
                expected=('lease_id','version') if table=='runtime_budget_grants' else ('lease_id',)
                kinds=('text','integer') if table=='runtime_budget_grants' else ('text',)
                if shape.primary_key_columns!=expected or shape.primary_key_types!=kinds:
                    raise AuthorityUnavailable('actual natural budget original changed registered primary key/type')
                dispositions.append(self._graph_disposition_key_v3(verified,shape,key,point))
        verified.require_current();self.require_current()
        return lease,grant,root_lease,root_grant,tuple(dispositions)

    def read_d13_natural_preparation_source_original_v3(self,stage,operation_id,*,meter):
        """One actual immutable-stage preparation member, not a readiness flag."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        tables={'generation':'graph_natural_generation_preparations_v2','review':'graph_natural_review_preparations_v2'}
        if stage not in tables:raise AuthorityUnavailable('actual natural stage must be generation or review')
        _identifier(operation_id,'natural original operation')
        columns=('bot','persona','parent_original_id','job_id','original_operation_id','seal_json','frozen_json',
            'read_versions_json','query_epochs_json','graph_epoch','access_epoch','deletion_epoch','state','worker_fence',
            'typed_request_digest','typed_request_wire','terminal_receipt_digest','terminal_output_digest')
        large={'seal_json','frozen_json','read_versions_json','query_epochs_json','typed_request_wire'}
        names=tuple(name for name in columns if name not in large);ns=tuple(json.loads(self.scope.graph_namespace))
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(verified._read_db):
            shape=read_c09_table_shape_v2(source,tables[stage],meter=point)
            if shape.columns!=columns or shape.primary_key_columns!=columns[:3] or shape.primary_key_types!=('text','text','text'):
                raise AuthorityUnavailable('actual natural preparation changed exact Source schema/key')
            where='bot=? AND persona=? AND original_operation_id=?';args=(*ns,operation_id)
            row=point.read_fixed_row(source,shape.table,names,where,args)
            matches=_read_one(source,'SELECT count(*) FROM '+shape.table+' WHERE '+where,args,meter)
            if row is None or matches!=(1,) or row[:2]!=ns or row[4]!=operation_id:
                raise AuthorityUnavailable('actual natural preparation original absent or ambiguous')
            key=(*ns,row[2]);proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(names,row,strict=True)),shape,proof

    def read_d13_outbound_adoption_source_original_v3(self,slot_ref,observation_digest,*,meter):
        """Exactly one actual outbound observation member for this delivered turn."""
        from ..runtime.jobs import _digest
        from ..graph_types import AtomKey
        from ..runtime_contracts import NamespaceId
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _digest(observation_digest);meter.require_available(len(slot_ref))
        slot=AtomKey.from_token(slot_ref);meter.charge_encode(len(slot_ref));namespace=NamespaceId.from_key(slot)
        if (namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace))
                or slot.owner.kind!='scene' or slot.type_name!='d09.turn_slot.v1'):
            raise AuthorityUnavailable('outbound original crossed actual namespace/slot')
        columns=('bot','persona','final_operation_id','observation_digest','source_ref','slot_ref','batch_ref',
            'observation_json','original_json','original_digest')
        small_columns=tuple(name for name in columns if name not in {'observation_json','original_json'})
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_d13_outbound_observations_v1',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=columns[:4]
                    or shape.primary_key_types!=('text','text','text','text')):
                raise AuthorityUnavailable('actual outbound Source changed exact schema/key')
            where='bot=? AND persona=? AND slot_ref=? AND observation_digest=?'
            args=(*namespace.as_tuple,slot_ref,observation_digest)
            small=point.read_fixed_row(source,shape.table,small_columns,where,args)
            # count(*) is an expression, not a column; retain the bounded query.
            matches=_read_one(source,'SELECT count(*) FROM graph_d13_outbound_observations_v1 WHERE '+where,args,meter)
            if (small is None or matches!=(1,) or small[0:2]!=namespace.as_tuple
                    or small[3]!=observation_digest or small[5]!=slot_ref):
                raise AuthorityUnavailable('actual delivered outbound original absent or ambiguous')
            key=(*namespace.as_tuple,small[2],observation_digest)
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_inbound_attempt_source_original_v3(self,ingress_operation_id,*,meter):
        """Actual committed inbound-turn worker member, not the paid schedule worker."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(ingress_operation_id,'D13 inbound ingress')
        columns=('bot','persona','ingress_operation_id','c02_operation_id','attempt_id','anchor_json','pre_graph_revision',
            'pre_graph_epoch','permit_json','finish_request_id','finish_request_digest','receipt_json')
        small_columns=tuple(name for name in columns if name not in {'anchor_json','permit_json','receipt_json'})
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,ingress_operation_id)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_d13_inbound_turn_attempts_v1',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=columns[:3]
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual inbound Source changed exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,'bot=? AND persona=? AND ingress_operation_id=?',key)
            if small is None or small[:3]!=key:
                raise AuthorityUnavailable('actual inbound turn attempt original absent')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_schedule_bundle_source_original_v3(self,job_ref,*,meter):
        """The actual paid schedule bundle member, never another domain's receipt."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(job_ref,'paid schedule bundle')
        columns=('bot','persona','operation_id','digest','activity_id','effect_id','commit_seq','receipt_json')
        small_columns=columns[:-1]
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,job_ref)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_bundle_operations',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=columns[:3]
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual paid schedule bundle Source has another exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,'bot=? AND persona=? AND operation_id=?',key)
            if small is None or small[:3]!=key:
                raise AuthorityUnavailable('actual paid schedule bundle Source absent or another operation')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_schedule_input_source_original_v3(self,job_ref,*,meter):
        """Exact schedule input member; full frozen payload remains streamed."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(job_ref,'paid schedule job')
        columns=('bot','persona','job_ref','scene_ref','payload_json','payload_digest','pending')
        small_columns=tuple(name for name in columns if name!='payload_json')
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,job_ref)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_d13_paid_schedule_inputs_v1',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=columns[:3]
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual paid schedule input Source has another exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,'bot=? AND persona=? AND job_ref=?',key)
            if small is None or small[:3]!=key:
                raise AuthorityUnavailable('actual paid schedule input Source absent or another job')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_create_source_original_v3(self,job_ref,*,meter):
        """Actual create operation Source member; the complete job JSON is streamed."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(job_ref,'paid create job')
        columns=('bot_id','persona_id','operation_id','phase','digest','job_id','job_json')
        small_columns=columns[:-1]
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,job_ref,'create')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'runtime_job_operations',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=columns[:4]
                    or shape.primary_key_types!=('text','text','text','text')):
                raise AuthorityUnavailable('actual paid create Source has another exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,
                'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',key)
            if small is None or small[:4]!=key or small[5]!=job_ref:
                raise AuthorityUnavailable('actual paid create Source original absent or another job')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_lifecycle_event_source_original_v3(self,operation_id,*,meter):
        """Exact paid lifecycle event Source member; complete JSON cells remain streamed."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(operation_id,'paid acquire event')
        columns=('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')
        small_columns=('bot','persona','session','event_id','digest','epoch_revision')
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,'d13-paid',operation_id)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_events',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=('bot','persona','session','event_id')
                    or shape.primary_key_types!=('text','text','text','text')):
                raise AuthorityUnavailable('actual acquire event Source has another exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,'bot=? AND persona=? AND session=? AND event_id=?',key)
            if small is None or small[:4]!=key:raise AuthorityUnavailable('actual acquire Graph event original absent')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_worker_source_original_v3(self,operation_id,*,meter):
        """Named actual worker Source member; JSON bytes are streamed by its consumer."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(operation_id,'paid worker operation')
        columns=('bot','persona','operation_id','request_digest','attempt_id','anchor_json','pre_graph_revision',
            'pre_graph_epoch','permit_json','finish_request_id','finish_request_digest','receipt_json')
        small_columns=tuple(name for name in columns if name not in {'anchor_json','permit_json','receipt_json'})
        namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,operation_id)
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_d13_worker_attempts_v2',meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=('bot','persona','operation_id')
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual paid worker Source has another exact schema/key')
            small=point.read_fixed_row(source,shape.table,small_columns,'bot=? AND persona=? AND operation_id=?',key)
            if small is None or small[:3]!=key:raise AuthorityUnavailable('actual paid worker Source original absent')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return dict(zip(small_columns,small,strict=True)),shape,proof

    def read_d13_paid_identity_source_original_v3(self,job_ref,kind,*,meter):
        """Two exact immutable paid-original families, actual complete Source members."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(job_ref,'job_ref')
        families={'intent':('graph_d13_paid_intent_originals_v1','operation_id'),
            'call':('graph_d13_paid_call_originals_v1','call_id')}
        if kind not in families:raise AuthorityUnavailable('unsupported named D13 paid identity original')
        table,identity=families[kind];namespace=tuple(json.loads(self.scope.graph_namespace));key=(*namespace,job_ref)
        columns=('bot','persona','job_ref',identity,'original_json','original_digest')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,table,meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=('bot','persona','job_ref')
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual paid identity original changed registered table schema/key')
            small=point.read_fixed_row(source,table,(*columns[:4],columns[-1]),'bot=? AND persona=? AND job_ref=?',key)
            if small is None or small[:3]!=key:raise AuthorityUnavailable('actual immutable paid identity Source original absent')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return small,shape,proof


    def read_d13_core_wire_evidence_source_original_v3(self,key,*,meter):
        """Optional exact Graph import; absent import is not an invented missing Core fact."""
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2,require_c09_reserved_meter_v3
        from ..runtime.domain_production_erasure_v1 import TABLE_COLUMNS
        if type(key) is not tuple or len(key)!=3 or any(type(value)is not str or not value for value in key):
            raise AuthorityUnavailable('actual namespace/frame original primary key required')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        root=require_c09_reserved_meter_v3(meter.budget)
        if meter is not root:raise AuthorityUnavailable('Graph V7 original reader requires the actual reserved root')
        point=_C09ReadonlyPointMeterV3(root);source=verified.pair.source;db=verified._read_db
        table='graph_d13_core_wire_evidence_v1';columns=TABLE_COLUMNS[table]
        with c09_sql_meter_quantum_v2(root),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            exists=point.read_fixed_row(source,'sqlite_master',('name',),'type=? AND name=?',('table',table))
            shape=None;small=None;proof=None
            if exists is not None:
                shape=read_c09_table_shape_v2(source,table,meter=root)
                if (shape.columns!=columns or shape.primary_key_columns!=('bot','persona','frame_intent_id')
                        or shape.primary_key_types!=('text','text','text')):
                    raise AuthorityUnavailable('actual Graph V7 import Source changed exact columns/key')
                small=point.read_fixed_row(source,table,columns[:6],'bot=? AND persona=? AND frame_intent_id=?',key)
                if small is not None:
                    if small[:3]!=key:raise AuthorityUnavailable('actual Graph V7 import Source key differs')
                    proof=self._graph_disposition_original_v3(verified,shape,key,root)
        verified.require_current();self.require_current()
        return None if small is None else dict(zip(columns[:6],small,strict=True)),shape,proof

    def next_d13_core_wire_evidence_source_key_v3(self,after,*,meter):
        """Complete physical Graph import inventory, including other namespace rows."""
        from ..runtime.c09_paged_sql_v2 import (read_c09_table_shape_v2,read_c09_next_row_metadata_v2,
            c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2,require_c09_reserved_meter_v3)
        from ..runtime.domain_production_erasure_v1 import TABLE_COLUMNS
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        root=require_c09_reserved_meter_v3(meter.budget)
        if meter is not root:raise AuthorityUnavailable('Graph V7 original reader requires the actual reserved root')
        point=_C09ReadonlyPointMeterV3(root);source=verified.pair.source;table='graph_d13_core_wire_evidence_v1'
        with c09_sql_meter_quantum_v2(root),legacy_cell_read_transaction_v2(source):
            exists=point.read_fixed_row(source,'sqlite_master',('name',),'type=? AND name=?',('table',table))
            found=None
            if exists is not None:
                shape=read_c09_table_shape_v2(source,table,meter=root)
                if (shape.columns!=TABLE_COLUMNS[table] or shape.primary_key_columns!=('bot','persona','frame_intent_id')
                        or shape.primary_key_types!=('text','text','text')):
                    raise AuthorityUnavailable('actual Graph V7 import inventory changed exact columns/key')
                found=read_c09_next_row_metadata_v2(source,shape,after)
        verified.require_current();self.require_current()
        return None if found is None else found[0]

    def read_d13_derived_payload_source_original_v3(self,block_ref,*,meter):
        """Actual old payload member/descriptor; never reconstruct missing bytes."""
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        from ..runtime.domain_production_erasure_v1 import TABLE_COLUMNS
        if type(block_ref) is not str or not block_ref:raise AuthorityUnavailable('actual derived payload block locator required')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        table='graph_d11_derived_cache_payloads_v1';namespace=tuple(json.loads(self.scope.graph_namespace))
        key=(*namespace,block_ref);columns=TABLE_COLUMNS[table]
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,table,meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=('bot','persona','block_ref')
                    or shape.primary_key_types!=('text','text','text')):
                raise AuthorityUnavailable('actual derived payload Source has another registered row schema/key')
            small=point.read_fixed_row(source,table,columns[:-1],'bot=? AND persona=? AND block_ref=?',key)
            if small is None or small[:3]!=key:raise AuthorityUnavailable('actual old derived payload bytes source is absent')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return small,shape,proof

    def read_natural_final_source_original_v3(self,kind,operation_id,activity_id,admission_ref,*,meter):
        """Closed final/Owner source rows, selected by an already verified P2 origin."""
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(operation_id,'natural final operation');_identifier(activity_id,'natural final activity')
        namespace=tuple(json.loads(self.scope.graph_namespace))
        if kind=='bundle':
            table='graph_bundle_operations';columns=('bot','persona','operation_id','digest','activity_id','effect_id','commit_seq','receipt_json')
            primary=columns[:3];key=(*namespace,operation_id);large={'receipt_json'}
        elif kind=='event':
            table='graph_events';columns=('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')
            primary=columns[:4];key=(*namespace,activity_id,operation_id);large={'reads','epoch_reads','revisions','invalidated'}
        elif kind=='admission':
            _identifier(admission_ref,'natural final admission')
            table='graph_dispatch_admissions';columns=('bot','persona','admission_ref','operation_id','effect_id','admission_digest',
                'admission_json','graph_revision','graph_epoch','receipt_digest','request_json')
            primary=columns[:3];key=(*namespace,admission_ref);large={'admission_json','request_json'}
        elif kind=='owner_issue':
            table='graph_owner_issue_operations_v1';columns=('bot','persona','operation_id','request_digest','grant_id','grant_digest',
                'graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest','proof_json')
            primary=columns[:2];key=namespace;large={'proof_json'}
        else:raise AuthorityUnavailable('unknown named natural final original family')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source
        names=tuple(name for name in columns if name not in large);where=' AND '.join(name+'=?' for name in primary)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source):
            shape=read_c09_table_shape_v2(source,table,meter=point)
            if shape.columns!=columns or shape.primary_key_columns!=primary or shape.primary_key_types!=tuple('text' for _ in primary):
                raise AuthorityUnavailable('natural final original changed registered Source schema/key')
            row=point.read_fixed_row(source,table,names,where,key)
            if row is None:raise AuthorityUnavailable('actual natural final Source original absent')
            small=dict(zip(names,row,strict=True))
            if tuple(small[name] for name in primary)!=key:raise AuthorityUnavailable('natural final Source key changed')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return small,shape,proof

    def read_natural_acquire_source_original_v3(self,stage,kind,acquire_id,activity_id,job_ref,*,meter):
        """Four closed natural acquire families; no caller-controlled SQL family."""
        from ..runtime.jobs import _identifier
        from ..graph_types import AtomKey
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if stage not in {'generation','review'}:raise AuthorityUnavailable('unknown natural acquire stage')
        _identifier(acquire_id,'natural acquire operation');_identifier(activity_id,'natural acquire activity')
        namespace=tuple(json.loads(self.scope.graph_namespace))
        if kind=='acquire':
            table='graph_natural_'+stage+'_acquires_v2'
            columns=('bot','persona','acquire_operation_id','request_digest','attempt_id','anchor_json','graph_revision','graph_epoch','state')
            key=(*namespace,acquire_id);primary=columns[:3];where='bot=? AND persona=? AND acquire_operation_id=?';large={'anchor_json'}
        elif kind=='bundle':
            table='graph_bundle_operations';columns=('bot','persona','operation_id','digest','activity_id','effect_id','commit_seq','receipt_json')
            key=(*namespace,acquire_id);primary=columns[:3];where='bot=? AND persona=? AND operation_id=?';large={'receipt_json'}
        elif kind=='event':
            table='graph_events';columns=('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')
            key=(*namespace,activity_id,acquire_id);primary=columns[:4];where='bot=? AND persona=? AND session=? AND event_id=?'
            large={'reads','epoch_reads','revisions','invalidated'}
        elif kind in {'queued','running'}:
            meter.require_available(len(job_ref));atom=AtomKey.from_token(job_ref);meter.charge_encode(len(job_ref))
            if ((atom.owner.kind,atom.owner.bot,atom.owner.persona,atom.owner.subject,atom.type_name)!=
                    ('activity',*namespace,activity_id,'runtime.job')):
                raise AuthorityUnavailable('natural acquire history crossed actual activity job scope')
            table='graph_history';columns=('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id')
            key=(job_ref,1 if kind=='queued' else 2);primary=columns[:2];where='token=? AND revision=?';large={'value','dependencies'}
        else:raise AuthorityUnavailable('unknown named natural acquire original family')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source
        names=tuple(name for name in columns if name not in large)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source):
            shape=read_c09_table_shape_v2(source,table,meter=point)
            if (shape.columns!=columns or shape.primary_key_columns!=primary
                    or shape.primary_key_types!=tuple('integer' if name=='revision' else 'text' for name in primary)):
                raise AuthorityUnavailable('natural acquire original changed registered Source schema/key')
            row=point.read_fixed_row(source,table,names,where,key)
            if row is None:raise AuthorityUnavailable('actual natural acquire Source original absent')
            small=dict(zip(names,row,strict=True))
            if tuple(small[name] for name in primary)!=key:
                raise AuthorityUnavailable('natural acquire Source original changed key')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return small,shape,proof

    def read_natural_job_source_original_v3(self,stage,job_id,operation_id,*,meter):
        """Named natural job Source; D13's job==operation rule is not applicable."""
        from ..runtime.jobs import _identifier,_JOB_SELECT
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if stage not in {'generation','review'}:raise AuthorityUnavailable('unknown named natural job stage')
        _identifier(job_id,'job_id');_identifier(operation_id,'operation_id');self.require_current()
        verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source
        expected=tuple(_JOB_SELECT.split('SELECT ',1)[1].split(' FROM ',1)[0].split(','))
        large={'continuation_json','operator_versions_json','usage_json'};names=tuple(name for name in expected if name not in large)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source):
            shape=read_c09_table_shape_v2(source,'runtime_jobs',meter=point)
            if (shape.columns!=expected or shape.primary_key_columns!=('job_id',) or shape.primary_key_types!=('text',)):
                raise AuthorityUnavailable('actual natural job changed registered Source schema/key')
            row=point.read_fixed_row(source,'runtime_jobs',names,'job_id=?',(job_id,))
            if row is None:raise AuthorityUnavailable('actual natural job Source absent')
            small=dict(zip(names,row,strict=True))
            if ((small['job_id'],small['operation_id'],small['bot_id'],small['persona_id'],small['work_kind'])!=
                    (job_id,operation_id,*tuple(json.loads(self.scope.graph_namespace)),'natural_'+stage)
                    or small['phase']!='completed' or small['cancel_epoch']!=0):
                raise AuthorityUnavailable('actual natural job identity/terminal/cancellation state differs')
            proof=self._graph_disposition_original_v3(verified,shape,(job_id,),point)
        verified.require_current();self.require_current();return small,shape,proof

    def read_d13_paid_job_source_original_v3(self,job_ref,*,meter):
        """Actual complete Source member and small locator; target completion is separate."""
        from ..runtime.jobs import _identifier
        from ..runtime.d13_precompression_job import PAID_WORK_KIND
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        _identifier(job_ref,'job_ref');self.require_current()
        verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        columns=('job_id','operation_id','activity_id','bot_id','persona_id','work_kind')
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'runtime_jobs',meter=point)
            if shape.primary_key_columns!=('job_id',) or shape.primary_key_types!=('text',):
                raise AuthorityUnavailable('actual D13 paid job Source key differs')
            locator=point.read_fixed_row(source,'runtime_jobs',columns,'job_id=?',(job_ref,))
            if (locator is None or locator[:2]!=(job_ref,job_ref)
                    or locator[3:5]!=tuple(json.loads(self.scope.graph_namespace)) or locator[5]!=PAID_WORK_KIND):
                raise AuthorityUnavailable('actual D13 paid job Source locator crossed job/operation/namespace/work kind')
            proof=self._graph_disposition_original_v3(verified,shape,(job_ref,),point)
        verified.require_current();self.require_current()
        return dict(zip(columns,locator,strict=True)),shape,proof

    def read_d13_paid_job_history_reference_v3(self,job_ref,activity_id,graph_epoch,*,meter):
        """Only a real at-draft historical job locator; temporal proof remains separate."""
        from ..runtime_contracts import NamespaceId,VersionedRef
        from ..runtime.d11_types import runtime_job_key
        from ..runtime.jobs import _identifier
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        _identifier(job_ref,'job_ref');_identifier(activity_id,'activity_id')
        if type(graph_epoch) is not int or graph_epoch<0:raise AuthorityUnavailable('actual D13 paid job draft epoch required')
        namespace=NamespaceId(*json.loads(self.scope.graph_namespace))
        meter.require_available(4096)
        key=runtime_job_key(*namespace.as_tuple,activity_id,job_ref);token=key.token;meter.charge_encode(len(token))
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        source=verified.pair.source
        with legacy_cell_read_transaction_v2(source):
            row=meter.read_fixed_row(source,'graph_history',('revision',),
                'token=? AND revision=(SELECT MAX(h.revision) FROM graph_history h JOIN graph_events e '
                'ON e.bot=h.event_bot AND e.persona=h.event_persona AND e.session=h.event_session AND e.event_id=h.event_id '
                'WHERE h.token=? AND e.bot=? AND e.persona=? AND e.epoch_revision<=?)',
                (token,token,*namespace.as_tuple,graph_epoch))
        if row is None or type(row[0]) is not int or row[0]<1:
            raise AuthorityUnavailable('actual paid job had no positive Graph history by original draft epoch')
        verified.require_current();self.require_current();return VersionedRef(token,row[0])

    def require_d13_paid_job_at_draft_epoch_v3(self,reference,graph_epoch,*,meter):
        """Closed activity runtime-job temporal entrypoint; no paid admission."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..runtime.d11_types import runtime_job_key
        from ..graph_types import AtomKey
        if type(reference) is not VersionedRef or reference.version<1:raise AuthorityUnavailable('actual historical paid job revision required')
        meter.require_available(len(reference.ref));key=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        namespace=NamespaceId.from_key(key)
        if (namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace)) or key.owner.kind!='activity'
                or key!=runtime_job_key(*namespace.as_tuple,key.owner.subject,key.name)):
            raise AuthorityUnavailable('historical paid job reference crossed formal activity job key')
        return self._require_positive_reference_at_draft_epoch_v3(reference,graph_epoch,meter=meter)

    def require_historical_graph_reference_v3(self,reference,*,meter):
        """Actual historical SQL metadata and full-Source page proof; no body/current grant."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if type(reference) is not VersionedRef or reference.version<1:
            raise AuthorityUnavailable('historical Graph original requires an exact positive revision')
        namespace=NamespaceId.from_key(AtomKey.from_token(reference.ref))
        if namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace)):
            raise AuthorityUnavailable('historical Graph original crossed actual capture namespace')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_history',meter=point)
            if (shape.columns!=('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id')
                    or shape.primary_key_columns!=('token','revision') or shape.primary_key_types!=('text','integer')):
                raise AuthorityUnavailable('historical Graph original has another registered Source schema/key')
            columns=tuple(name for name in shape.columns if name not in {'value','dependencies'});key=(reference.ref,reference.version)
            actual=point.read_fixed_row(source,shape.table,columns,'token=? AND revision=?',key)
            if (actual is None or actual[:2]!=key or actual[2] not in (0,1)
                    or actual[3:5]!=namespace.as_tuple):
                raise AuthorityUnavailable('historical Graph metadata missing or outside exact Source revision/namespace')
            proof=self._graph_disposition_key_v3(verified,shape,key,point)
        verified.require_current();self.require_current()
        return dict(zip(columns,actual,strict=True)),proof

    def read_d13_context_epoch_locator_v3(self,reference,graph_epoch,*,meter):
        return self._read_d13_epoch_locator_v3(reference,graph_epoch,dispatch_claim=False,meter=meter)

    def read_d13_dispatch_claim_epoch_locator_v3(self,reference,graph_epoch,*,meter):
        """Only the formal immutable P2 claim; caller proves actual handoff."""
        return self._read_d13_epoch_locator_v3(reference,graph_epoch,dispatch_claim=True,meter=meter)

    def read_d13_outbox_epoch_locator_v3(self,reference,graph_epoch,*,meter):
        """Only formal activity-owned runtime outbox at the guarded epoch."""
        return self._read_d13_epoch_locator_v3(reference,graph_epoch,outbox=True,meter=meter)

    def read_d13_natural_batch_epoch_locator_v3(self,reference,graph_epoch,*,meter):
        """Only immutable formal natural V2/V3 batch, separately guarded."""
        return self._read_d13_epoch_locator_v3(reference,graph_epoch,natural_batch=True,meter=meter)

    def _read_d13_epoch_locator_v3(self,reference,graph_epoch,*,dispatch_claim=False,outbox=False,natural_batch=False,meter):
        """Closed Source/Access/completion/correction time locator, no target claim."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if type(reference) is not VersionedRef or type(graph_epoch) is not int or graph_epoch<0:
            raise AuthorityUnavailable('actual context reference and original epoch required')
        meter.require_available(len(reference.ref));key=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        namespace=NamespaceId.from_key(key)
        if namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace)):
            raise AuthorityUnavailable('historical context locator crossed actual capture namespace')
        correction=False
        if dispatch_claim:
            from ..runtime.dispatch_graph_claim import dispatch_claim_key
            if key!=dispatch_claim_key(namespace,key.name) or reference.version!=1:
                raise AuthorityUnavailable('historical dispatch locator is outside formal immutable claim')
        elif outbox:
            from ..runtime.d11_types import runtime_outbox_key
            if (key.owner.kind!='activity' or key!=runtime_outbox_key(*namespace.as_tuple,key.owner.subject,key.name)
                    or reference.version<1):
                raise AuthorityUnavailable('historical outbox locator is outside formal activity-owned family')
        elif natural_batch:
            from ..domains.d09.natural_batch import NATURAL_BATCH_SCHEMA_V2,NATURAL_BATCH_SCHEMA_V3
            from ..graph_types import Owner
            if (key.type_name not in {NATURAL_BATCH_SCHEMA_V2,NATURAL_BATCH_SCHEMA_V3}
                    or key!=AtomKey(Owner('activity',*namespace.as_tuple,key.owner.subject),key.type_name,key.name)
                    or reference.version!=1):
                raise AuthorityUnavailable('historical natural batch locator is outside immutable V2/V3 family')
        else:
            correction=key==source_correction_head_key(namespace,key.owner.subject)
            positive=(key in (source_key(*namespace.as_tuple,key.owner.subject),access_key(*namespace.as_tuple,key.owner.subject))
                or key.owner.kind=='scene' and key.type_name in {'d09.turn_completion.v1','d09.turn_slot.v1'})
            if not (correction and reference.version==0 or positive and reference.version>0):
                raise AuthorityUnavailable('historical context locator is outside its exact closed family')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        source=verified.pair.source;point=_C09ReadonlyPointMeterV3(meter);rows=[]
        expected={
            'graph_history':(('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id'),('token','revision'),('text','integer')),
            'graph_atoms':(('token','bot','persona','owner_kind','subject','type_name','name','revision','value','valid'),('token',),('text',)),
            'graph_events':(('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision'),('bot','persona','session','event_id'),('text','text','text','text')),
            'graph_epochs':(('bot','persona','revision'),('bot','persona'),('text','text'))}
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source):
            shapes={table:read_c09_table_shape_v2(source,table,meter=point) for table in expected}
            for table,shape in shapes.items():
                if (shape.columns,shape.primary_key_columns,shape.primary_key_types)!=expected[table]:
                    raise AuthorityUnavailable('actual context temporal Source changed registered schema/key')
            def retain(table,row_key):
                descriptor=(shapes[table],row_key)
                if descriptor not in rows:rows.append(descriptor)
            frozen=point.read_fixed_row(source,'graph_epochs',('revision',),'bot=? AND persona=?',namespace.as_tuple)
            if frozen is None or type(frozen[0]) is not int or frozen[0]<graph_epoch:
                raise AuthorityUnavailable('context epoch is beyond actual frozen Source')
            retain('graph_epochs',namespace.as_tuple)
            columns=('token','revision','valid','event_bot','event_persona','event_session','event_id')
            if correction:
                history=point.read_fixed_row(source,'graph_history',columns,'token=? ORDER BY revision',(reference.ref,))
            else:
                history=point.read_fixed_row(source,'graph_history',columns,'token=? AND revision=?',(reference.ref,reference.version))
            head=point.read_fixed_row(source,'graph_atoms',('revision',),'token=?',(reference.ref,))
            if head is not None:
                if type(head[0]) is not int or head[0]<1:raise AuthorityUnavailable('actual context frozen head revision differs')
                retain('graph_atoms',(reference.ref,))
            birth=None;following=None;successor=None
            if history is None:
                if not correction or head is not None:
                    raise AuthorityUnavailable('actual context history absent or head lacks complete first history')
            else:
                if (history[0]!=reference.ref or type(history[1]) is not int or history[3:5]!=namespace.as_tuple
                        or not correction and (history[1]!=reference.version or history[2]!=1)
                        or correction and history[1]!=1):
                    raise AuthorityUnavailable('actual context historical revision/validity/namespace differs')
                retain('graph_history',(reference.ref,history[1]))
                event_key=history[3:]
                event=point.read_fixed_row(source,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',event_key)
                if event is None or type(event[0]) is not int or not 0<=event[0]<=frozen[0]:
                    raise AuthorityUnavailable('actual context history lacks coherent birth event')
                birth=event[0];retain('graph_events',event_key)
                if correction:
                    if not graph_epoch<birth:raise AuthorityUnavailable('correction was present at the original context epoch')
                else:
                    if birth>graph_epoch or head is None or head[0]<reference.version:
                        raise AuthorityUnavailable('context revision not current by original epoch')
                    successor=point.read_fixed_row(source,'graph_history',('revision','event_bot','event_persona','event_session','event_id'),
                        'token=? AND revision>? ORDER BY revision',(reference.ref,reference.version))
                    if successor is None:
                        if head[0]!=reference.version:raise AuthorityUnavailable('context revision has missing successor')
                    else:
                        if successor[0]!=reference.version+1 or successor[1:3]!=namespace.as_tuple or head[0]<successor[0]:
                            raise AuthorityUnavailable('context successor has actual revision/namespace gap')
                        retain('graph_history',(reference.ref,successor[0]))
                        event=point.read_fixed_row(source,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',successor[1:])
                        if event is None or type(event[0]) is not int or not graph_epoch<event[0]<=frozen[0]:
                            raise AuthorityUnavailable('context revision was superseded by original epoch')
                        following=event[0];retain('graph_events',successor[1:])
        verified.require_current();self.require_current()
        return _D13ContextEpochLocatorV3(self.scope.scope_digest,verified.pair.source_original,reference,key.owner.subject,key.type_name,graph_epoch,
            correction,None if history is None else dict(zip(columns,history,strict=True)),frozen[0],birth,
            None if head is None else head[0],None if successor is None else successor[0],following,tuple(rows))

    def read_d13_context_epoch_row_original_v3(self,locator,index,*,meter):
        """One complete Source member per quantum, before any target row claim."""
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if (type(locator) is not _D13ContextEpochLocatorV3 or locator.scope_digest!=self.scope.scope_digest
                or type(index) is not int or not 0<=index<len(locator.rows)):
            raise AuthorityUnavailable('actual context epoch row locator required')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        if locator.source_original!=verified.pair.source_original:
            raise AuthorityUnavailable('context row locator lost its actual frozen Source origin')
        shape,key=locator.rows[index];point=_C09ReadonlyPointMeterV3(meter)
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(verified.pair.source),legacy_cell_read_transaction_v2(verified._read_db):
            actual=read_c09_table_shape_v2(verified.pair.source,shape.table,meter=point)
            if actual!=shape:raise AuthorityUnavailable('context row Source schema changed')
            proof=self._graph_disposition_original_v3(verified,shape,key,point)
        verified.require_current();self.require_current();return proof

    def require_root_reference_at_draft_epoch_v3(self,reference,graph_epoch,*,meter):
        """Only formal Root Source/Access; never current head permission."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey
        from ..memory_types import source_key,access_key
        if type(reference) is not VersionedRef or reference.version<1 or type(graph_epoch) is not int or graph_epoch<0:
            raise AuthorityUnavailable('actual Root original epoch locator required')
        meter.require_available(len(reference.ref))
        atom=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        namespace=NamespaceId.from_key(atom)
        expected=(source_key(*namespace.as_tuple,atom.owner.subject),access_key(*namespace.as_tuple,atom.owner.subject))
        if atom not in expected:raise AuthorityUnavailable('Root original epoch proof only covers formal Source/Access')
        return self._require_positive_reference_at_draft_epoch_v3(reference,graph_epoch,meter=meter)

    def require_d13_metadata_at_draft_epoch_v3(self,reference,graph_epoch,*,meter):
        """Closed before-metadata time proof; no paid or activation authority."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey,Owner

        if type(reference) is not VersionedRef or reference.version<1 or type(graph_epoch) is not int or graph_epoch<0:
            raise AuthorityUnavailable('actual D13 before metadata epoch locator required')
        meter.require_available(len(reference.ref)*2)
        atom=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        namespace=NamespaceId.from_key(atom)
        if (namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace))
                or atom.type_name not in('d13.derived_block_metadata.v1','d13.derived_block_metadata.v2')
                or atom!=AtomKey(Owner('persona',*namespace.as_tuple),atom.type_name,atom.name)):
            raise AuthorityUnavailable('D13 metadata epoch proof crossed actual persona metadata scope/key')
        return self._require_positive_reference_at_draft_epoch_v3(reference,graph_epoch,meter=meter)

    def _require_positive_reference_at_draft_epoch_v3(self,reference,graph_epoch,*,meter):
        """One actual temporal proof shared by the two closed family entrypoints."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if type(reference) is not VersionedRef or reference.version<1 or type(graph_epoch) is not int or graph_epoch<0:
            raise AuthorityUnavailable('actual positive original epoch locator required')
        meter.require_available(len(reference.ref))
        atom=AtomKey.from_token(reference.ref);meter.charge_encode(len(reference.ref))
        namespace=NamespaceId.from_key(atom)
        metadata,proof=self.require_historical_graph_reference_v3(reference,meter=meter)
        if metadata['valid']!=1:raise AuthorityUnavailable('Root original revision was not valid')
        verified=self.session.require_actual_post_mirror_graph_v3();point=_C09ReadonlyPointMeterV3(meter)
        source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            history=read_c09_table_shape_v2(source,'graph_history',meter=point)
            events=read_c09_table_shape_v2(source,'graph_events',meter=point)
            epochs=read_c09_table_shape_v2(source,'graph_epochs',meter=point)
            heads=read_c09_table_shape_v2(source,'graph_atoms',meter=point)
            actual_epoch=point.read_fixed_row(source,'graph_epochs',('revision',),'bot=? AND persona=?',namespace.as_tuple)
            if actual_epoch is None or type(actual_epoch[0]) is not int or actual_epoch[0]<graph_epoch:
                raise AuthorityUnavailable('Root draft epoch is beyond actual frozen Graph')
            self._graph_disposition_key_v3(verified,epochs,namespace.as_tuple,point)
            event_key=tuple(metadata[name] for name in ('event_bot','event_persona','event_session','event_id'))
            event=point.read_fixed_row(source,'graph_events',('epoch_revision',),
                'bot=? AND persona=? AND session=? AND event_id=?',event_key)
            if event is None or type(event[0]) is not int or not 0<=event[0]<=graph_epoch:
                raise AuthorityUnavailable('Root revision was not created by the original draft epoch')
            self._graph_disposition_key_v3(verified,events,event_key,point)
            head=point.read_fixed_row(source,'graph_atoms',('revision',),'token=?',(reference.ref,))
            if head is None or type(head[0]) is not int or head[0]<reference.version:
                raise AuthorityUnavailable('Root history has no coherent actual frozen head')
            self._graph_disposition_key_v3(verified,heads,(reference.ref,),point)
            next_row=point.read_fixed_row(source,'graph_history',('revision','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision>? ORDER BY revision',(reference.ref,reference.version))
            if next_row is None:
                if head[0]!=reference.version:raise AuthorityUnavailable('Root revision chain has a missing successor')
            else:
                if next_row[0]!=reference.version+1 or next_row[1:3]!=namespace.as_tuple or head[0]<next_row[0]:
                    raise AuthorityUnavailable('Root original history has a revision/namespace gap')
                self._graph_disposition_key_v3(verified,history,(reference.ref,next_row[0]),point)
                following=point.read_fixed_row(source,'graph_events',('epoch_revision',),
                    'bot=? AND persona=? AND session=? AND event_id=?',next_row[1:])
                if following is None or type(following[0]) is not int or not graph_epoch<following[0]<=actual_epoch[0]:
                    raise AuthorityUnavailable('Root revision was superseded by the original draft epoch')
                self._graph_disposition_key_v3(verified,events,next_row[1:],point)
        verified.require_current();self.require_current()
        return proof

    def require_historical_correction_absence_v3(self,reference,graph_epoch,*,meter):
        """Revision zero needs actual append-only Source history at the original epoch."""
        from ..runtime_contracts import VersionedRef,NamespaceId
        from ..graph_types import AtomKey
        from ..domains.d06 import source_correction_head_key
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if type(reference) is not VersionedRef or reference.version!=0 or type(graph_epoch) is not int or graph_epoch<0:
            raise AuthorityUnavailable('actual historical correction absence locator required')
        key=AtomKey.from_token(reference.ref);namespace=NamespaceId.from_key(key)
        if (namespace.as_tuple!=tuple(json.loads(self.scope.graph_namespace))
                or key!=source_correction_head_key(namespace,key.owner.subject)):
            raise AuthorityUnavailable('historical absence is not this Source correction head')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            epoch_shape=read_c09_table_shape_v2(source,'graph_epochs',meter=point)
            if epoch_shape.primary_key_columns!=('bot','persona') or epoch_shape.primary_key_types!=('text','text'):
                raise AuthorityUnavailable('actual frozen Graph epoch original key differs')
            actual_epoch=point.read_fixed_row(source,'graph_epochs',('revision',),'bot=? AND persona=?',namespace.as_tuple)
            if actual_epoch is None or type(actual_epoch[0]) is not int or actual_epoch[0]<graph_epoch:
                raise AuthorityUnavailable('historical absence epoch is beyond actual frozen Source')
            epoch_proof=self._graph_disposition_key_v3(verified,epoch_shape,namespace.as_tuple,point)
            first=point.read_fixed_row(source,'graph_history',('revision','event_bot','event_persona','event_session','event_id'),
                'token=? ORDER BY revision',(reference.ref,))
            history_proof=event_proof=None;first_epoch=None
            if first is None:
                head=point.read_fixed_row(source,'graph_atoms',('revision',),'token=?',(reference.ref,))
                if head is not None:raise AuthorityUnavailable('absence Source has a head without its complete first history')
            else:
                if first[0]!=1 or first[1:3]!=namespace.as_tuple:
                    raise AuthorityUnavailable('historical absence lost its actual first revision/namespace')
                history_shape=read_c09_table_shape_v2(source,'graph_history',meter=point)
                if history_shape.primary_key_columns!=('token','revision') or history_shape.primary_key_types!=('text','integer'):
                    raise AuthorityUnavailable('historical correction first revision key differs')
                history_proof=self._graph_disposition_key_v3(verified,history_shape,(reference.ref,1),point)
                event_shape=read_c09_table_shape_v2(source,'graph_events',meter=point)
                if event_shape.primary_key_columns!=('bot','persona','session','event_id'):
                    raise AuthorityUnavailable('historical correction event original key differs')
                event=point.read_fixed_row(source,'graph_events',('epoch_revision',),
                    'bot=? AND persona=? AND session=? AND event_id=?',first[1:])
                if event is None or type(event[0]) is not int or not graph_epoch<event[0]<=actual_epoch[0]:
                    raise AuthorityUnavailable('correction was not genuinely absent at the original draft epoch')
                first_epoch=event[0];event_proof=self._graph_disposition_key_v3(verified,event_shape,first[1:],point)
        verified.require_current();self.require_current()
        return {'reference':reference,'draft_epoch':graph_epoch,'frozen_source_epoch':actual_epoch[0],
            'first_history':first,'first_event_epoch':first_epoch,'epoch_original':epoch_proof,
            'first_history_original':history_proof,'first_event_original':event_proof}

    def require_historical_c02_plan_origin_v3(self,operation_id,*,meter):
        """Real C02 activity identity for an immutable prospective plan candidate."""
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2
        if type(operation_id) is not str or not operation_id:raise AuthorityUnavailable('actual C02 operation required')
        self.require_current();verified=self.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=_C09ReadonlyPointMeterV3(meter);source=verified.pair.source;db=verified._read_db
        ns=tuple(json.loads(self.scope.graph_namespace))
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_bundle_operations',meter=point)
            if shape.primary_key_columns!=('bot','persona','operation_id') or shape.primary_key_types!=('text','text','text'):
                raise AuthorityUnavailable('actual C02 bundle origin changed its registered primary key')
            columns=('bot','persona','operation_id','digest','activity_id','effect_id','commit_seq');key=(*ns,operation_id)
            row=point.read_fixed_row(source,shape.table,columns,'bot=? AND persona=? AND operation_id=?',key)
            if row is None or row[:3]!=key:raise AuthorityUnavailable('actual C02 bundle origin missing')
            proof=self._graph_disposition_key_v3(verified,shape,key,point)
        verified.require_current();self.require_current()
        return dict(zip(columns,row,strict=True)),proof

    def _require_preserved_graph_atom_payload_v3(self,row,*,meter):
        """Only the physical TEXT-to-ref migration may preserve this Stop carrier."""
        from ..runtime.c09_paged_sql_v2 import (read_c09_table_shape_v2,legacy_cell_read_transaction_v2,
            c09_sql_meter_quantum_v2)
        from .c09_segmented_census_v3 import require_segmented_target_row_v3
        verified=self.session.require_actual_post_mirror_graph_v3();point=_C09ReadonlyPointMeterV3(meter)
        source=verified.pair.source;db=verified._read_db
        with c09_sql_meter_quantum_v2(point),legacy_cell_read_transaction_v2(source),legacy_cell_read_transaction_v2(db):
            shape=read_c09_table_shape_v2(source,'graph_atoms',meter=point)
            original=dict(zip(shape.columns,row,strict=True))
            target_shape=read_c09_table_shape_v2(db,'graph_atoms',meter=point)
            target=point.read_row(db,target_shape,(original['token'],))
            if target is None:raise AuthorityUnavailable('actual rebuilt Stop carrier is absent')
            rebuilt=dict(zip(target_shape.columns,target,strict=True))
            if {name:value for name,value in rebuilt.items() if name!='value_cell_id'}!={name:value for name,value in original.items() if name!='value'}:
                raise AuthorityUnavailable('rebuilt Stop carrier changed original identity/revision/validity')
            columns=('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
                'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
            header=point.read_fixed_row(db,'segmented_cells_v1',columns,'cell_id=?',(rebuilt['value_cell_id'],))
            point.require_available(len(original['value']))
            body=original['value'].encode('utf-8');point.charge_encode(len(body))
            if (header is None or header[1]!='canonical-json.ascii.v1' or header[2]!=original['token']
                    or header[3]!=self.scope.operation_id or header[4]!=len(body)
                    or header[6]!=sha256(body).hexdigest() or header[8]!=self.scope.scope_digest):
                raise AuthorityUnavailable('rebuilt Stop carrier did not preserve complete original payload bytes')
            require_segmented_target_row_v3(verified.segmented_sweep_v3,'segmented_cells_v1',(header[0],),tuple(header),meter=point)
        verified.require_current();self.require_current()

    def foreground_fence(self, operation_id, row, *, meter):
        from ..runtime.c09_foreground_attempt_v1 import TABLE, require_foreground_core_finished_v1
        with self._connections(meter) as (core, graph, target):
            matches = graph.execute('SELECT * FROM ' + TABLE + ' WHERE attempt_id=? LIMIT 2', (operation_id,)).fetchall()
            if len(matches) != 1:
                raise AuthorityUnavailable('foreground Core fence has no unique actual Graph attempt')
            original = read_foreground_attempt_original_row_v2(graph, matches[0], meter=meter)
            actual = require_foreground_core_finished_v1(core, original)
            if actual != tuple(row) or original.permit.namespace != self.scope.authority_namespace:
                raise AuthorityUnavailable('foreground actual Core/Graph original crossed its scope')
            proof = self._graph_disposition(graph, target, TABLE, original.row, meter)
            if proof.disposition not in {'preserved_exact','derived_removed'}:
                raise AuthorityUnavailable('foreground fence has an unsupported certified disposition')
            return actual, proof.disposition

    def owner_reply_stop(self, key, row, *, meter):
        from .owner_stop_reply_v1 import (PLAN_SCHEMA, decode_owner_stop_reply_plan_v1,
            validate_owner_stop_reply_core_row_v1, owner_reply_cycle_retirement_commitment_v1)
        from ..runtime.owner_stop_reply_v1 import read_original_owner_reply_cycle_identity_v1
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        from ..runtime.domain_production_original_codec_v1 import decode_typed_production_value_v1
        from ..runtime.foreground_cycle_v1 import ForegroundResponsibilityV1
        from ..runtime.jobs import get_job
        from ..runtime.d11_types import job_graph_write
        from ..graph_types import AtomKey
        from .c09_authority_storage_rebase import _owner_stop_reply_child_carrier_v1
        from ..runtime.lifecycle_operations_v1 import decode_original
        validate_owner_stop_reply_core_row_v1(row)
        if tuple(row[:3]) != tuple(key) or row[0] != self.scope.authority_namespace:
            raise AuthorityUnavailable('actual StopReply row belongs to another scope')
        plan = json.loads(row[7])
        if plan.get('schema') != PLAN_SCHEMA:
            raise AuthorityUnavailable('actual StopReply original has another plan schema')
        request, _ = decode_owner_stop_reply_plan_v1(plan)
        if request.installation_id != self.scope.installation_id:
            raise AuthorityUnavailable('actual StopReply request crossed installation')
        with self._connections(meter) as (core, graph, target):
            actual = core.execute('SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND operation_id=? AND original_ref=?', key).fetchone()
            if actual != tuple(row):
                raise AuthorityUnavailable('actual selected Core StopReply original changed')
            identity, cycle = read_original_owner_reply_cycle_identity_v1(graph, namespace=request.namespace, request=request)
            if asdict(identity) != plan['scope']:
                raise AuthorityUnavailable('StopReply lost its actual historical C02/cycle/create identity')
            removed = False
            def observe(table, original_row):
                nonlocal removed
                proof = self._graph_disposition(graph, target, table, original_row, meter)
                if proof.disposition=='rebuilt_from_surviving_sources' and table=='graph_atoms':
                    self._require_preserved_graph_atom_payload_v3(original_row,meter=meter)
                elif proof.disposition not in {'preserved_exact','derived_removed'}:
                    raise AuthorityUnavailable('StopReply carrier has another certified disposition')
                removed = removed or proof.disposition == 'derived_removed'
            ns = request.namespace.as_tuple
            observe('runtime_jobs', graph.execute('SELECT * FROM runtime_jobs WHERE job_id=?', (cycle.job_id,)).fetchone())
            observe('graph_atoms', graph.execute('SELECT * FROM graph_atoms WHERE token=?', (request.cycle_job_ref,)).fetchone())
            create = read_adopted_domain_operation_v1(graph, request.namespace, cycle.operation_id)
            observe('graph_domain_production_originals_v1', graph.execute('SELECT * FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?', (*ns, cycle.operation_id)).fetchone())
            for producer in (cycle.operation_id, request.c02_operation_id):
                observe('graph_bundle_operations', graph.execute('SELECT * FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?', (*ns, producer)).fetchone())
            if identity.responsibility_ref is not None:
                responsibility = decode_typed_production_value_v1(create['payload']['provenance']['foreground_responsibility'], ForegroundResponsibilityV1)
                kind = 'foreground_post_c02_cause' if responsibility.mode == 'bounded_causal_window_v1' else 'draft_root_capability'
                observe('graph_d11_life_originals_v1', graph.execute('SELECT * FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?', (*ns, kind, responsibility.cause_original_ref)).fetchone())
            for job_ref, original_ref, original_digest in plan['child_originals']:
                child = get_job(graph, AtomKey.from_token(job_ref).name)
                if job_graph_write(child).key.token != job_ref or (child.bot_id, child.persona_id) != ns:
                    raise AuthorityUnavailable('StopReply child crossed its actual namespace/job')
                observe('runtime_jobs', graph.execute('SELECT * FROM runtime_jobs WHERE job_id=?', (child.job_id,)).fetchone())
                observe('graph_atoms', graph.execute('SELECT * FROM graph_atoms WHERE token=?', (job_ref,)).fetchone())
                for table, carrier in _owner_stop_reply_child_carrier_v1(graph, request.namespace, cycle, child, original_ref, original_digest):
                    observe(table, carrier)
            # A group is read as a metered iterator. No namespace-sized selected
            # list or dictionary can discard an initial/derived member.
            for sibling in core.execute('SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND operation_id=?', row[:2]):
                validate_owner_stop_reply_core_row_v1(sibling)
                if sibling[4:] != row[4:] or json.loads(sibling[7]) != plan:
                    raise AuthorityUnavailable('StopReply initial/derived group changed its original Owner scope')
                original = decode_original(json.loads(sibling[3]))
                for ref in original.result.domain_receipt_refs:
                    matches = graph.execute("SELECT * FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND domain='d11' AND substr(original_digest,1,48)=? LIMIT 2",
                        (*ns, ref.removeprefix('d11-current:'))).fetchall()
                    if len(matches) != 1:
                        raise AuthorityUnavailable('derived StopReply lost its unique actual Graph projection')
                    projection = read_adopted_domain_operation_v1(graph, request.namespace, matches[0][2])
                    if projection['operation_kind'] != 'owner_stop_reply_v1' or projection['payload']['provenance']['cycle_identity'] != plan['scope']:
                        raise AuthorityUnavailable('derived StopReply projection crossed its actual historical scope')
                    observe('graph_domain_production_originals_v1', matches[0])
        retirement = owner_reply_cycle_retirement_commitment_v1(row[0], request.cycle_job_ref, row[1])
        return tuple(row), 'derived_removed' if removed else 'preserved_exact', AtomKey.from_token(request.cycle_job_ref).name, retirement

    def current_singleton(self, table, *, meter):
        from .c09_originals_archive_v1 import SINGLETONS
        if table not in SINGLETONS:
            raise AuthorityUnavailable('unknown legacy singleton schema')
        self.require_current()
        # V2 has a new compact signed pin. Never synthesize a V4 all-facts JSON
        # or relabel a V2 issue as an old singleton. Existing originals are
        # separately archived and retain their original byte/signature domains.
        return None

    def require_registered_core_schema(self, original):
        self.require_current()
        # This file's metadata belongs to the registered Graph candidate only.
        # The actual Core issue producer owns its separately named fixed DDL.
        from .c09_graph_rebase_issue_v2 import require_registered_c09_core_schema_v2
        return require_registered_c09_core_schema_v2(self.session, original)

    def require_registered_core_row(self, table, columns, row, *, meter):
        self.require_current()
        from .c09_graph_rebase_issue_v2 import require_registered_c09_core_row_v2
        return require_registered_c09_core_row_v2(self.session, table, columns, row, meter=meter)

    def require_retired_source_seal(self, old, *, meter):
        from .erasure_closure_redaction_v3 import ExecutionRedactionPreparedV3, ExecutionRowCommitmentV3
        if len(old) != 3 or old[0] != self.scope.authority_namespace:
            raise AuthorityUnavailable('legacy source seal row identity differs')
        raw = json.loads(old[2])
        raw['rows'] = tuple(ExecutionRowCommitmentV3(**row) for row in raw['rows'])
        seal = ExecutionRedactionPreparedV3(**raw)
        if (seal.operation_id != old[1] or seal.execution_journal_id != self.facts._completion.old_journal_id
                or seal.execution_seq != self.facts._completion.old_seq
                or seal.execution_digest != self.facts._completion.old_digest):
            raise AuthorityUnavailable('legacy source seal does not bind the actual consumed execution head')
        for original in seal.rows:
            actual = _read_one(self.facts._db, 'SELECT mutation_id,chain_digest FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq=?',
                (self.scope.scope_digest, original.seq), meter)
            if actual != (original.mutation_id, original.chain_digest):
                raise AuthorityUnavailable('legacy source seal is not completely carried by actual recovery originals')
        return True

    def require_historical_capture_table(self, table, *, meter):
        self.require_current()
        from ..runtime.c09_paged_sql_v2 import CAPTURE_DDLS_V2
        from .c09_authority_storage_rebase_v2 import MANAGED_DDLS_V2
        expected=CAPTURE_DDLS_V2.get(table) or MANAGED_DDLS_V2.get(table)
        if expected is None:
            raise AuthorityUnavailable('historical capture table has no installed fixed schema')
        actual=_read_one(self.pair.source,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,),meter)
        if actual!=(expected,):
            raise AuthorityUnavailable('historical capture source schema differs')
        return True

    def require_historical_capture_row(self, table, columns, row, *, meter):
        # These rows are preserved exactly, never promoted to current proof.
        # Current proof comes from the independently verified current streams.
        self.require_historical_capture_table(table,meter=meter)
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        shape=read_c09_table_shape_v2(_BoundedReadConnectionV2(self.pair.source,meter),table)
        if tuple(columns)!=shape.columns or len(row)!=len(columns):
            raise AuthorityUnavailable('historical capture row actual column shape differs')
        keys=tuple(row[columns.index(name)] for name in shape.primary_key_columns)
        q=lambda name:'"'+name.replace('"','""')+'"'
        actual=_read_one(self.pair.source,'SELECT '+','.join(q(n) for n in columns)+' FROM '+q(table)+
            ' WHERE '+' AND '.join(q(n)+'=?' for n in shape.primary_key_columns),keys,meter)
        if actual!=tuple(row):
            raise AuthorityUnavailable('historical capture row is not the actual frozen source row')
        if 'scope_digest' in columns:
            historical_scope=row[columns.index('scope_digest')]
        elif 'stream_id' in columns:
            parent=_read_one(self.pair.source,'SELECT scope_digest FROM c09_capture_streams_v2 WHERE stream_id=?',
                (row[columns.index('stream_id')],),meter)
            if parent is None: raise AuthorityUnavailable('historical capture row has no actual parent stream')
            historical_scope=parent[0]
        else:
            raise AuthorityUnavailable('historical capture row lacks a fixed scope or stream linkage')
        if historical_scope==self.scope.scope_digest:
            raise AuthorityUnavailable('current capture row cannot be classified as historical')
        lineage=_read_one(self.facts._db,'SELECT generation,operation_id,prepared_digest FROM c09_recovery_history_scopes_v2 '
            'WHERE scope_digest=? AND historical_scope_digest=?',(self.scope.scope_digest,historical_scope),meter)
        if lineage is None:
            raise AuthorityUnavailable('historical capture scope is outside authenticated selected lineage')
        control=self.session._control.maintenance.control
        from .c09_prepared_storage_v2 import _build_original
        with control._db() as db:
            original=_read_one(db,'SELECT prepared_digest FROM c09_storage_operations_v2 '
                'WHERE installation_id=? AND operation_id=? AND generation=?',
                (self.scope.installation_id,lineage[1],lineage[0]),meter)
            scope_body=_build_original(control,_BoundedReadConnectionV2(db,meter),lineage[1],'capture_scope_v2')
        historical=c09_paged_value_from_wire_v2(scope_body,C09CaptureScopeV2)
        if (original!=(lineage[2],) or historical.scope_digest!=historical_scope
                or historical.authority_namespace!=self.scope.authority_namespace
                or historical.installation_id!=self.scope.installation_id or historical.authority_id!=self.scope.authority_id):
            raise AuthorityUnavailable('historical capture scope does not match its actual signed operation')
        return True


def mint_installed_authority_role_basis_v2(session, pair, *, _resolver=None):
    scope = _require_session_pair(session, pair)
    if pair.source_original.role not in {'core', 'execution', 'deletion'}:
        raise AuthorityUnavailable('authority role basis requires its actual post-Graph source role')
    completion = session._control.require_graph_rebase_completion_v2(session)
    facts = mint_installed_recovery_facts_resolver_v2(session, pair) if _resolver is None else _resolver
    if type(facts) is not C09PagedRecoveryFactsResolverV2 or facts.session is not session or facts.pair is not pair:
        raise AuthorityUnavailable('role basis requires the same actually minted recovery resolver')
    facts.require_complete(scope_digest=scope.scope_digest, facts_pin_digest=completion.facts_pin_digest,
                           graph_issue_digest=completion.graph_issue_digest)
    maintenance = session._control.maintenance
    from .erasure_closure_inventory import CleanupRunV2, _TABLES
    current, _ = session._control._current(scope.operation_id)
    member = next(item for item in current.manifest['members'] if item['role'] == 'core')
    maintenance.control.verify_member_v1(member, prepared=False)
    with closing(sqlite3.connect(Path(member['resolved_path']).as_uri() + '?mode=ro', uri=True, isolation_level=None)) as source:
        source.execute('PRAGMA query_only=ON'); source.execute('BEGIN')
        try:
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            db = _BoundedReadConnectionV2(source,current_c09_sql_meter_v2())
            run = maintenance.closure._read_record(db, _TABLES[1], scope.operation_id, CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable('actual accepted cleanup run disappeared')
            accepted = maintenance.closure._accepted_locked(db, run, maintenance.subject)
        finally:
            source.rollback()
    maintenance.control.verify_member_v1(member, prepared=False)
    if canonical_digest(accepted) != scope.accepted_receipt_digest or run.graph_barrier_receipt_digest != scope.barrier_digest:
        raise AuthorityUnavailable('authority role actual accepted/barrier original changed')
    intent = maintenance.control.read_operation_event_v1(scope.operation_id, 'INTENT')
    basis = InstalledC09AuthorityRoleBasisV2(_TOKEN, session, pair, facts, completion, accepted, intent['details']['targets']['core'])
    facts._basis = basis
    basis.require_current()
    return basis

def read_foreground_attempt_original_row_v2(db, row, *, meter):
    """Authenticate one real selected Graph attempt with the original V1 semantics."""
    import re
    from dataclasses import asdict
    from ..runtime_contracts import NamespaceId
    from ..runtime.c09_foreground_attempt_v1 import TABLE, COLUMNS, PREFIX, _RECEIPT_FIELDS, ForegroundAttemptOriginalV1
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1, _receipt_wire
    from ..runtime.restore_anchor import RestoreAnchor
    from .v2_contract import FencePermitV2, from_wire
    if not db.in_transaction or len(row) != len(COLUMNS):
        raise AuthorityUnavailable('actual one-row foreground source snapshot required')
    actual = db.execute('SELECT * FROM ' + TABLE + ' WHERE bot=? AND persona=? AND operation_id=?', row[:3]).fetchone()
    if actual is None or tuple(actual) != tuple(row):
        raise AuthorityUnavailable('foreground source row differs from the actual selected Graph')
    if tuple(item[1] for item in db.execute('PRAGMA table_info(' + TABLE + ')')) != COLUMNS:
        raise AuthorityUnavailable('actual foreground source schema differs')
    namespace = NamespaceId(row[0], row[1])
    operation, request_digest, attempt = row[2:5]
    if (type(request_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", request_digest) is None
            or attempt != PREFIX + request_digest[:48]
            or any(type(value) is not int or value < 0 for value in row[6:8])
            or row[8] is None or row[9] is None):
        raise AuthorityUnavailable("C09 foreground original is pending or has an invalid fixed identity; HOLD")
    permit = from_wire(json.loads(row[8]))
    anchor = RestoreAnchor(**json.loads(row[5]))
    recovery = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        namespace.as_tuple).fetchone()
    if recovery is None:
        raise AuthorityUnavailable("C09 foreground namespace has no real recovery identity")
    requirements = json.loads(recovery[0])
    if (type(permit) is not FencePermitV2 or permit.operation != "write" or permit.operation_id != attempt
            or permit.pinned_anchor != anchor or permit.generation != anchor.activation_generation
            or (permit.authority_id, permit.namespace) != (requirements["authority_id"], requirements["authority_namespace"])
            or canonical_serialize(asdict(anchor)) != row[5]
            or canonical_serialize(json.loads(row[8])) != row[8]):
        raise AuthorityUnavailable("C09 foreground original permit/anchor/namespace differs")
    original = read_adopted_domain_operation_v1(db, namespace, operation)
    saved = json.loads(row[9])
    if original is None or type(saved) is not dict or set(saved) != _RECEIPT_FIELDS:
        raise AuthorityUnavailable("C09 foreground saved receipt or actual adopted original is absent")
    from ..authority_service.current_foreground_activity_v1 import _DOMAINS
    receipt, payload = original["receipt"], original["payload"]
    if (_DOMAINS.get(original["operation_kind"]) != original["domain"]
            or saved["schema"] != "sylanne.domain-production-receipt.v1"
            or (saved["domain"], saved["operation_kind"], saved["operation_id"], saved["activity_id"])
                != (original["domain"], original["operation_kind"], operation, receipt.activity_id)
            or saved["original_ref"] != original["domain"] + "-current:" + original["original_digest"][:48]
            or saved["original_digest"] != original["original_digest"]
            or saved["receipt"] != _receipt_wire(receipt) or saved["receipt_digest"] != canonical_digest(receipt)
            or payload["authority"]["activation_generation"] != permit.generation
            or receipt.status != "committed" or canonical_serialize(saved) != row[9]):
        raise AuthorityUnavailable("C09 foreground receipt differs from its actual W01 adoption")
    finish = "sha256:" + canonical_digest({"schema": "w01.foreground-domain-write.v1",
        "operation_id": operation, "request_digest": request_digest, "permit_token": permit.token})
    fence = db.execute("SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,"
        "post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone()
    if fence != (receipt.operation_digest, row[8], row[6], row[7], row[6] + 1, row[7] + 1,
            "finish:" + attempt, finish):
        raise AuthorityUnavailable("C09 foreground real bundle fence or foreground finish schema differs")
    return ForegroundAttemptOriginalV1(namespace, operation, attempt, request_digest, permit, finish, tuple(row))


class C09CanonicalSqlCellReaderV2:
    """One immutable selected SQL cell; parser state never becomes an authority."""
    def __init__(self, table, column, where, parameters, *, ensure_ascii, observe=None):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.table, self.column, self.where = table, column, where
        self.parameters = tuple(parameters)
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=ensure_ascii)
        self.length = None
        self.spans, self.starts = {}, {}
        self.observe = observe
        self.complete = False

    def read(self, db, start, length, meter):
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        if type(db) is _BoundedReadConnectionV2:
            return db.read_incremental_cell_v2(self.table,self.column,self.where,self.parameters,start,length)[0]
        with legacy_cell_read_transaction_v2(db):
            value,total,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                where=self.where,parameters=self.parameters,start=start,length=length,meter=meter)
            if self.length is not None and total!=self.length or kind!='text':
                raise AuthorityUnavailable('actual historical canonical cell length or type changed')
            return value

    def value(self, db, path, meter):
        span = self.spans[path]
        if span[1] - span[0] > 65536:
            raise AuthorityUnavailable('historical fixed descriptor exceeds its exact bounded codec')
        return json.loads(self.read(db, span[0], span[1] - span[0], meter))

    def _event(self, event):
        if len(event.path) == 1:
            if event.kind in {'object_start', 'array_start', 'scalar_start'}:
                self.starts[event.path] = event.start_offset
            elif event.kind in {'object_end', 'array_end', 'scalar_end'}:
                self.spans[event.path] = (self.starts.pop(event.path), event.end_offset)
        if self.observe is not None:
            self.observe(event)

    def advance(self, db, meter):
        if self.complete: return True
        if self.length is None:
            from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
            if type(db) is _BoundedReadConnectionV2:
                value,total,kind=db.read_incremental_cell_v2(self.table,self.column,self.where,self.parameters,0,0)
            else:
                with legacy_cell_read_transaction_v2(db):
                    value,total,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=0,length=0,meter=meter)
            if kind!='text' or total<2:
                raise AuthorityUnavailable('actual historical canonical cell is absent or malformed')
            self.length=total
        remaining = self.length - self.parser.byte_count
        if remaining:
            size = min(1024, remaining)
            self.parser.feed(self.read(db, self.parser.byte_count, size, meter), self._event)
            return False
        result = self.parser.finish()
        if result.byte_count != self.length or self.starts:
            raise AuthorityUnavailable('historical canonical stream did not finish at actual SQL EOF')
        self.complete = True
        return True


class C09VerifiedLegacyPreparedSummaryV2:
    """A small view issued only after complete old PREPARED bytes authenticate."""
    __slots__ = ('_issuer', '_control', '_header', '_row', '_selection')

    def __init__(self, token, control, header, row, selection):
        if token is not _TOKEN:
            raise AuthorityUnavailable('actual streamed PREPARED verification required')
        from types import MappingProxyType
        self._issuer, self._control = token, control
        self._header, self._row = MappingProxyType(dict(header)), tuple(row)
        self._selection = tuple(selection)

    def __getitem__(self, name):
        from copy import deepcopy
        return deepcopy(self._header[name])
    def get(self, name, default=None):
        from copy import deepcopy
        return deepcopy(self._header.get(name, default))

    def require_current(self, *, meter):
        if self._issuer is not _TOKEN:
            raise AuthorityUnavailable('historical PREPARED summary issuer differs')
        with self._control._db() as db:
            current = self._control._current(db)
            selected = _read_one(db, 'SELECT generation FROM c09_storage_manifests_v1 WHERE manifest_digest=?',
                                 (current['current_manifest_digest'],), meter)
            if selected is None or (current['pointer_version'], current['current_manifest_digest'], selected[0]) != self._selection:
                raise AuthorityUnavailable('historical PREPARED summary selected pointer changed')
            row = _read_one(db, 'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,'
                'prepared_digest,key_id,signature FROM c09_storage_operations_v1 '
                'WHERE installation_id=? AND operation_id=?',
                (self._control.installation_id, self._header['operation_id']), meter)
        if row != self._row:
            raise AuthorityUnavailable('authenticated historical PREPARED source row changed')
        return self


_LEGACY_PREPARED_SUMMARY_FIELDS_V2 = frozenset((
    'schema','authority_id','installation_id','namespace','operation_id','maintenance_generation',
    'expected_pointer_version','old_manifest_digest','new_manifest_digest','prior_prepared_digest',
    'accepted_receipt_digest','barrier_receipt_digest','old_core_anchor_original','new_core_anchor_original',
    'anchor_transition_original','facts_pin_original','facts_digest','recovery_bindings_digest',
    'prepared_digest','key_id','signature',
))


class C09LegacyPreparedReaderV2:
    """Read one real installed historical row without materializing its large fields."""
    def __init__(self, token, control, row, selection):
        if token is not _TOKEN:
            raise AuthorityUnavailable('installed Control history factory required')
        self.control, self.row = control, tuple(row)
        self.selection = tuple(selection)
        self.cell = C09CanonicalSqlCellReaderV2('c09_storage_operations_v1', 'prepared_original_json',
            'installation_id=? AND operation_id=?', (control.installation_id, row[0]), ensure_ascii=False)
        self.phase = 'scan'; self.header = {}; self.fields = None
        self.index = self.offset = 0
        self.hasher = sha256(); self.hasher.update(b'{')
        self.result = None

    def advance(self, *, meter):
        if self.result is not None:
            return self.result.require_current(meter=meter)
        from .c09_storage_control_v1 import _PREPARED_FIELDS
        with self.control._db() as db:
            actual = _read_one(db, 'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,'
                'prepared_digest,key_id,signature FROM c09_storage_operations_v1 '
                'WHERE installation_id=? AND operation_id=?', (self.control.installation_id,self.row[0]), meter)
            if actual != self.row:
                raise AuthorityUnavailable('historical PREPARED row changed during streaming')
            if self.phase == 'scan':
                if not self.cell.advance(db, meter): return None
                if {p[0] for p in self.cell.spans} != _PREPARED_FIELDS:
                    raise AuthorityUnavailable('legacy PREPARED exact field set differs')
                self.fields = tuple(sorted(_PREPARED_FIELDS - {'prepared_digest','signature'}))
                self.phase = 'hash'
                return None
            if self.phase == 'hash':
                if self.index < len(self.fields):
                    name = self.fields[self.index]; start,end = self.cell.spans[(name,)]
                    if self.offset == 0:
                        prefix = (b',' if self.index else b'') + json.dumps(name,ensure_ascii=False).encode('utf-8') + b':'
                        meter.charge_encode(len(prefix)); self.hasher.update(prefix)
                    size = min(16384, end-start-self.offset)
                    raw = self.cell.read(db, start+self.offset, size, meter)
                    self.hasher.update(raw); self.offset += size
                    if self.offset == end-start: self.index += 1; self.offset = 0
                    return None
                meter.charge_encode(1); self.hasher.update(b'}')
                self.phase = 'header'; self.index = 0
                return None
            names = tuple(sorted(_LEGACY_PREPARED_SUMMARY_FIELDS_V2))
            if self.index < len(names):
                name = names[self.index]
                self.header[name] = self.cell.value(db, (name,), meter)
                self.index += 1
                return None
        h = self.header
        if (h['schema'] != 'sylanne3.c09.storage_prepared_original.v1'
                or (h['authority_id'],h['installation_id']) != (self.control.authority_id,self.control.installation_id)
                or (h['operation_id'],h['maintenance_generation'],h['old_manifest_digest'],h['new_manifest_digest'],
                    h['prepared_digest'],h['key_id'],h['signature']) != self.row
                or h['key_id'] != self.control.key_id or h['prepared_digest'] != self.hasher.hexdigest()):
            raise AuthorityUnavailable('streamed legacy PREPARED exact digest, identity or row differs')
        import hmac
        expected = hmac.new(self.control._key, (h['schema']+'\n'+h['prepared_digest']).encode('utf-8'), 'sha256').hexdigest()
        if not hmac.compare_digest(expected,h['signature']):
            raise AuthorityUnavailable('streamed legacy PREPARED installed HMAC differs')
        self.result = C09VerifiedLegacyPreparedSummaryV2(_TOKEN,self.control,h,self.row,self.selection)
        return self.result.require_current(meter=meter)


def begin_next_legacy_prepared_reader_v2(control, *, after_generation, through_generation, meter):
    """Select a real signed-history row; supplied cursors carry no proof."""
    from .c09_storage_control_v1 import InstalledC09StorageReaderV1, C09StorageControlV1
    if type(control) not in {InstalledC09StorageReaderV1, C09StorageControlV1}:
        raise AuthorityUnavailable('actual installed Control reader required')
    if type(after_generation) is not int or type(through_generation) is not int or not 0 <= after_generation <= through_generation:
        raise AuthorityUnavailable('historical generation cursor differs')
    with control._db() as db:
        current = control._current(db)
        manifest = control._read_manifest(db,current['current_manifest_digest'])
        if through_generation != manifest['generation']:
            raise AuthorityUnavailable('history upper bound is not the actual selected generation')
        row = _read_one(db, 'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,'
            'prepared_digest,key_id,signature FROM c09_storage_operations_v1 '
            'WHERE installation_id=? AND generation>? AND generation<=? ORDER BY generation LIMIT 1',
            (control.installation_id,after_generation,through_generation), meter)
    if row is None:
        if after_generation != through_generation:
            raise AuthorityUnavailable('actual signed storage history has a missing generation')
        return None
    if row[1] != after_generation + 1:
        raise AuthorityUnavailable('actual signed storage history is not consecutive')
    return C09LegacyPreparedReaderV2(_TOKEN,control,row,
        (current['pointer_version'],current['current_manifest_digest'],manifest['generation']))


def begin_selected_legacy_prepared_reader_v2(control, *, meter):
    """Installed V2 driver preflight, before a session needs the selected old header."""
    from .c09_storage_control_v1 import InstalledC09StorageReaderV1, C09StorageControlV1
    if type(control) not in {InstalledC09StorageReaderV1, C09StorageControlV1}:
        raise AuthorityUnavailable('actual installed Control reader required')
    with control._db() as db:
        current = control._current(db)
        manifest = control._read_manifest(db,current['current_manifest_digest'])
        if manifest['generation'] == 0: return None
        row = _read_one(db, 'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,'
            'prepared_digest,key_id,signature FROM c09_storage_operations_v1 '
            'WHERE installation_id=? AND new_manifest_digest=?',
            (control.installation_id,manifest['manifest_digest']), meter)
    if row is None or row[1] != manifest['generation']:
        raise AuthorityUnavailable('selected legacy PREPARED is missing or from another generation')
    return C09LegacyPreparedReaderV2(_TOKEN,control,row,
        (current['pointer_version'],current['current_manifest_digest'],manifest['generation']))


class C09TypedCanonicalSpanHashV2:
    """Mechanical old tuple reconstruction; callers still authenticate its result."""
    def __init__(self,cell,paths,*,next_type_annotation):
        self.cell=cell;self.paths=tuple(paths);self.next_type_annotation=next_type_annotation
        self.index=0;self.position=None;self.injected=-1
        self.hasher=sha256();self.hasher.update(b'[');self.result=None

    def advance(self,db,meter):
        if self.result is not None:return self.result
        if self.index==len(self.paths):
            meter.charge_encode(1);self.hasher.update(b']')
            self.result=self.hasher.hexdigest();return self.result
        start,end=self.cell.spans[self.paths[self.index]]
        if self.position is None:
            if self.index:meter.charge_encode(1);self.hasher.update(b',')
            self.position=start;self.injected=start-1
        row=self.next_type_annotation(self.position,self.injected,end,meter)
        stop=end if row is None else row[0]
        if row is not None and not self.position<=stop<end or row is not None and stop<=self.injected:
            raise AuthorityUnavailable('typed historical annotation is outside the current actual span')
        if self.position<stop:
            size=min(16384,stop-self.position)
            self.hasher.update(self.cell.read(db,self.position,size,meter));self.position+=size
            return None
        if row is not None:
            if type(row[1]) is not str or len(row[1].encode('utf-8'))>1024:
                raise AuthorityUnavailable('typed historical annotation name exceeds the fixed codec')
            injected=('"$type":'+json.dumps(row[1],ensure_ascii=True,separators=(',',':'))+',').encode('ascii')
            meter.charge_encode(len(injected));self.hasher.update(injected);self.injected=row[0]
            return None
        self.index+=1;self.position=None;return None


def _history_storage_db_v3(producer):
    """Actual capture candidate or the installed selected read-only history sink."""
    if type(producer) is C09PagedRecoveryFactsProducerV2:
        return producer.pair.candidate
    from .c09_selected_history_v3 import C09SelectedHistoryReadonlySinkV3
    if type(producer) is C09SelectedHistoryReadonlySinkV3:
        return producer.history_storage_db_v3()
    from .d12_managed_backup_cleanup_v2 import require_registered_backup_historical_sink_v3
    return require_registered_backup_historical_sink_v3(producer)


class _HistoricalTypedHashV2(C09TypedCanonicalSpanHashV2):
    def __init__(self,owner,cell,cell_kind,paths):
        self.owner,self.cell_kind=owner,cell_kind
        super().__init__(cell,paths,next_type_annotation=self._annotation)

    def _annotation(self,position,injected,end,meter):
        return _read_one(_history_storage_db_v3(self.owner.producer),
            'SELECT byte_offset,type_name FROM c09_recovery_history_types_v2 '
            'WHERE scope_digest=? AND generation=? AND cell_kind=? AND byte_offset>=? AND byte_offset>? '
            'AND byte_offset<? ORDER BY byte_offset LIMIT 1',
            (self.owner.scope,self.owner.generation,self.cell_kind,position,injected,end),meter)


class _LegacyRecoveryFrameReaderV2:
    @property
    def facts_digest(self): return self.summary['facts_digest']
    @property
    def bindings_digest(self): return self.summary['recovery_bindings_digest']
    @property
    def pin_digest(self): return self.pin.pin_digest
    @property
    def next_journal(self): return self.summary['new_core_anchor_original']['execution_journal_id']
    def __init__(self, producer, summary):
        self.producer,self.summary = producer,summary
        self.scope = producer.scope.scope_digest; self.generation = summary['maintenance_generation']
        self.operation = summary['operation_id']; self.namespace = summary['namespace']
        self.phase='locate'; self.facts=None; self.bindings=None; self.seal=None
        self.starts={}; self.last={}; self.counts={}; self.hashes=[]; self.hash_index=0
        self.header={}; self.header_keys=None; self.header_index=0; self.binding_header={}
        self.model_after=''; self.verify_after=None; self.contact_after=''; self.pin=None
        self.db=self.meter=None

    def _mark(self, family, key, digest, auxiliary=None):
        raw = _encoded({} if auxiliary is None else auxiliary,self.meter)
        db=_history_storage_db_v3(self.producer)
        prior=_read_one(db,'SELECT value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            'WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',
            (self.scope,self.generation,family,key),self.meter)
        if prior is None:
            _write(db,'INSERT INTO c09_recovery_history_members_v2 VALUES (?,?,?,?,?,?)',
                (self.scope,self.generation,family,key,digest,raw),self.meter)
        elif prior!=(digest,raw):
            raise AuthorityUnavailable('historical typed member differs on actual source replay')

    def _member(self, family, key):
        row=_read_one(_history_storage_db_v3(self.producer),'SELECT value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            'WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',
            (self.scope,self.generation,family,key),self.meter)
        return row

    def _type(self, cell_kind, event, cls):
        name=cls.__module__+'.'+cls.__qualname__
        db=_history_storage_db_v3(self.producer); key=(self.scope,self.generation,cell_kind,event.start_offset+1)
        prior=_read_one(db,'SELECT type_name FROM c09_recovery_history_types_v2 '
            'WHERE scope_digest=? AND generation=? AND cell_kind=? AND byte_offset=?',key,self.meter)
        if prior is None:
            _write(db,'INSERT INTO c09_recovery_history_types_v2 VALUES (?,?,?,?,?)',(*key,name),self.meter)
        elif prior!=(name,): raise AuthorityUnavailable('historical exact canonical type offset differs')

    def _record(self, cell, path, event, family):
        if event.kind in {'object_start','array_start','scalar_start'}:
            self.starts[path]=event.start_offset
        if event.kind not in {'object_end','array_end','scalar_end'}: return
        start=self.starts.pop(path); length=event.end_offset-start
        if length>65536:
            raise AuthorityUnavailable('historical fact exceeds the installed single-fact codec')
        raw=cell.read(self.db,start,length,self.meter)
        value=_decode_fact(family,raw)
        key=_fact_key(family,value)
        if key<=self.last.get(family,''):
            raise AuthorityUnavailable('historical facts are not strictly ordered and distinct')
        self.last[family]=key; self.counts[family]=self.counts.get(family,0)+1
        self.producer._merge(family,value,self.summary['prepared_digest'],self.meter)
        auxiliary={'status':value.status} if family=='executions' else {'execution_kind':value.execution_kind} if family=='binding' else None
        self._mark(family,key,canonical_digest(value),auxiliary)

    def _facts_event(self,event):
        from .c09_recovery_frame_v4 import C09RecoveryFactFrameV4
        from .c09_recovery_frame_v5 import ContactFinishInventoryV5,ContactFinishInventoryMemberV5,ContactFinishCarryV5
        from .c09_contact_finish_original_v1 import C09ContactFinishOriginalV1
        from ..runtime.restore_anchor import RestoreAnchor
        from ..runtime_journal import RecoveryConstraintFootprint,QuotaOccupancy,ReservationConstraint,BudgetConstraint
        p=event.path
        self._prior_event(self.facts,event,p[1:] if p and p[0]=='ordinary_facts' else p,'facts')
        if len(p)==2 and p[0] in {'ordinary_facts','contact_finish_inventory'}:
            if event.kind in {'object_start','array_start','scalar_start'}: self.starts[p]=event.start_offset
            elif event.kind in {'object_end','array_end','scalar_end'}:
                self.facts.spans[p]=(self.starts.pop(p),event.end_offset)
        base=p[1:] if p and p[0]=='ordinary_facts' else p
        family=base[0] if base and base[0] in _FAMILIES else None
        if family is not None and len(base)==2 and type(base[1]) is int:
            self._record(self.facts,p,event,family)
        if event.kind=='object_start':
            cls=None
            if p==('ordinary_facts',): cls=C09RecoveryFactFrameV4
            elif p==('contact_finish_inventory',): cls=ContactFinishInventoryV5
            elif family is not None and len(base)==2: cls=_FAMILIES[family][0]
            elif family=='unknown_facts' and len(base)==3 and base[2]=='footprint': cls=RecoveryConstraintFootprint
            elif family=='unknown_facts' and len(base)==5 and base[2]=='footprint':
                cls={'quota_occupancies':QuotaOccupancy,'reservations':ReservationConstraint,'budgets':BudgetConstraint}.get(base[3])
            elif p and p[0]=='contact_finish_inventory':
                if p==('contact_finish_inventory','observed_core_anchor'): cls=RestoreAnchor
                elif len(p)==3 and p[1]=='members': cls=ContactFinishInventoryMemberV5
                elif len(p)==4 and p[1]=='members': cls={'original':C09ContactFinishOriginalV1,'carry':ContactFinishCarryV5}.get(p[3])
                elif len(p)==5 and p[1]=='members' and p[3]=='original' and p[4] in {'pinned_anchor','observed_core_anchor'}: cls=RestoreAnchor
            if cls is not None: self._type('facts',event,cls)
        if len(p)==3 and p[:2]==('contact_finish_inventory','members'):
            if event.kind=='object_start': self.starts[p]=event.start_offset
            elif event.kind=='object_end':
                from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                start=self.starts.pop(p); size=event.end_offset-start
                if size>65536: raise AuthorityUnavailable('historical Contact member exceeds its exact descriptor codec')
                member=decode_typed_production_value_v1(json.loads(self.facts.read(self.db,start,size,self.meter)),ContactFinishInventoryMemberV5)
                locator=member.locator
                if self.last.get('contact') is not None and locator<=self.last['contact']:
                    raise AuthorityUnavailable('historical Contact inventory order or uniqueness differs')
                self.last['contact']=locator; self.counts['contact']=self.counts.get('contact',0)+1
                self._mark('contact',member.original.business_operation_id,canonical_digest(member.original),asdict(member))

    def _bindings_event(self,event):
        p=event.path
        self._prior_event(self.bindings,event,p,'bindings')
        if len(p)==2 and p[0]=='execution_bindings' and type(p[1]) is int:
            if event.kind=='object_start': self._type('bindings',event,C09ExecutionBindingV1)
            self._record(self.bindings,p,event,'binding')

    def _locate(self,core):
        ns,op=self.namespace,self.operation
        choices=(('authority_execution_recovery_facts_v4','facts_json','namespace=? AND operation_id=?',(ns,op)),
                 ('authority_c09_recovery_fact_frames_v4','facts_json','namespace=? AND operation_id=?',(ns,op)),
                 ('authority_c09_originals_archive_v1','original_json',"namespace=? AND operation_id=? AND original_kind='facts'",(ns,op)))
        for table,column,where,args in choices:
            exists=_read_one(core,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,),self.meter)
            if exists is not None and _read_one(core,'SELECT 1 FROM '+table+' WHERE '+where,args,self.meter) is not None:
                self.facts=C09CanonicalSqlCellReaderV2(table,column,where,args,ensure_ascii=True,observe=self._facts_event); break
        if self.facts is None: raise AuthorityUnavailable('signed historical facts have no actual selected Core cell')
        self.bindings=C09CanonicalSqlCellReaderV2('authority_c09_recovery_bindings_v1','bindings_json',
            'namespace=? AND operation_id=?',(ns,op),ensure_ascii=True,observe=self._bindings_event)
        self.phase='facts_scan'

    def _prepare_hashes(self):
        from .c09_recovery_frame_v4 import C09RecoveryFactFrameV4
        from .c09_recovery_frame_v5 import C09RecoveryFactFrameV5,ContactFinishInventoryV5
        from ..runtime.c09_storage_rebase_contract_v1 import SanitizedRecoveryFactsV4
        from ..runtime.c09_storage_transition_v1 import C09RecoveryBindingsV1
        self.schema=self.facts.value(self.db,('schema',),self.meter)
        if self.schema=='sylanne3.c09.recovery_fact_frame.v5':
            cls=C09RecoveryFactFrameV4; prefix=('ordinary_facts',)
            if {p[0] for p in self.facts.spans if len(p)==1}!={f.name for f in fields(C09RecoveryFactFrameV5)}:
                raise AuthorityUnavailable('historical V5 frame exact fields differ')
            if {p[1] for p in self.facts.spans if len(p)==2 and p[0]=='contact_finish_inventory'}!={f.name for f in fields(ContactFinishInventoryV5)}:
                raise AuthorityUnavailable('historical Contact inventory exact fields differ')
            inventory_paths=[('contact_finish_inventory',f.name) for f in fields(ContactFinishInventoryV5) if f.name!='inventory_digest']
            self.hashes.append((_HistoricalTypedHashV2(self,self.facts,'facts',inventory_paths),self.facts.value(self.db,('contact_finish_inventory','inventory_digest'),self.meter)))
            self.hashes.append((_HistoricalTypedHashV2(self,self.facts,'facts',(('ordinary_facts',),('contact_finish_inventory',),('schema',))),self.summary['facts_digest']))
        elif self.schema=='sylanne3.c09.recovery_fact_frame.v4': cls=C09RecoveryFactFrameV4; prefix=()
        elif self.schema=='sylanne3.authority.sanitized_recovery_facts.v4': cls=SanitizedRecoveryFactsV4; prefix=()
        else: raise AuthorityUnavailable('historical recovery frame has an unsupported exact schema')
        expected={f.name for f in fields(cls)}
        observed={p[-1] for p in self.facts.spans if len(p)==len(prefix)+1 and p[:len(prefix)]==prefix}
        if observed!=expected: raise AuthorityUnavailable('historical ordinary fact exact field set differs')
        self.prefix=prefix; self.fact_class=cls
        digest=self.facts.value(self.db,prefix+('facts_digest',),self.meter)
        if not prefix and digest!=self.summary['facts_digest']: raise AuthorityUnavailable('historical facts disagree with signed PREPARED')
        self.hashes.append((_HistoricalTypedHashV2(self,self.facts,'facts',[prefix+(f.name,) for f in fields(cls) if f.name!='facts_digest']),digest))
        if {p[0] for p in self.bindings.spans}!={f.name for f in fields(C09RecoveryBindingsV1)}:
            raise AuthorityUnavailable('historical binding exact fields differ')
        self.hashes.append((_HistoricalTypedHashV2(self,self.bindings,'bindings',[(f.name,) for f in fields(C09RecoveryBindingsV1) if f.name!='bindings_digest']),self.summary['recovery_bindings_digest']))
        scalar_fields=tuple(name for name in expected if name not in {*_FAMILIES,'prior_fact_frame_digests'})
        self.header_keys=tuple(sorted(scalar_fields)); self.phase='hashes'

    def advance(self,core,meter):
        self.db,self.meter=core,meter
        try:
            self.summary.require_current(meter=meter)
            if self.phase=='locate': self._locate(core); return False
            if self.phase=='facts_scan':
                if self.facts.advance(core,meter): self.phase='bindings_scan'
                return False
            if self.phase=='bindings_scan':
                if self.bindings.advance(core,meter): self.phase='prepare_hashes'
                return False
            if self.phase=='prepare_hashes': self._prepare_hashes(); return False
            if self.phase=='hashes':
                if self.hash_index<len(self.hashes):
                    hasher,expected=self.hashes[self.hash_index]
                    value=hasher.advance(core,meter)
                    if value is not None:
                        if value!=expected: raise AuthorityUnavailable('historical exact typed canonical commitment differs')
                        self.hash_index+=1
                    return False
                self.phase='headers'; return False
            if self.phase=='headers':
                if self.header_index<len(self.header_keys):
                    name=self.header_keys[self.header_index]
                    self.header[name]=self.facts.value(core,self.prefix+(name,),meter)
                    self.header_index+=1; return False
                return self._finish_headers(core,meter)
            if self.phase=='source_seal_scan':
                if self.seal.advance(core,meter):
                    from .c09_recovery_frame_v4 import C09ExecutionSourceSealV4
                    if {p[0] for p in self.seal.spans}!={f.name for f in fields(C09ExecutionSourceSealV4)}:
                        raise AuthorityUnavailable('historical exact source-seal fields differ')
                    self.seal_hash=_HistoricalTypedHashV2(self,self.seal,'seal',[(f.name,) for f in fields(C09ExecutionSourceSealV4) if f.name!='seal_digest'])
                    self.phase='source_seal_hash'
                return False
            if self.phase=='source_seal_hash':
                value=self.seal_hash.advance(core,meter)
                if value is not None:
                    self._finish_source_seal(value,core,meter); self.phase='models'
                return False
            if self.phase=='members': return self._verify_next_member(core,meter)
            if self.phase=='models': return self._verify_next_model(core,meter)
            if self.phase=='contacts': return self._verify_next_contact(core,meter)
            if self.phase=='complete': return True
            raise AuthorityUnavailable('historical frame private phase differs')
        finally:
            self.db=self.meter=None


    def _prior_event(self,cell,event,path,kind):
        if len(path)!=2 or path[0]!='prior_fact_frame_digests': return
        if event.kind=='scalar_start': self.starts[event.path]=event.start_offset
        elif event.kind=='scalar_end':
            start=self.starts.pop(event.path); size=event.end_offset-start
            if size!=66: raise AuthorityUnavailable('historical prior-frame digest codec differs')
            value=json.loads(cell.read(self.db,start,size,self.meter))
            row=_read_one(_history_storage_db_v3(self.producer),'SELECT facts_digest FROM c09_recovery_history_frames_v2 '
                'WHERE scope_digest=? AND generation=?',(self.scope,path[1]+1),self.meter)
            if row!=(value,) or path[1]>=self.generation-1:
                raise AuthorityUnavailable('historical prior-frame vector does not name actual prior signed frames')
            self.counts['prior_'+kind]=self.counts.get('prior_'+kind,0)+1

    def _finish_headers(self,core,meter):
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from .c09_recovery_frame_v4 import C09ExecutionSourcePinV4
        from .c09_recovery_frame_v5 import C09ExecutionSourcePinV5
        from .erasure_recovery_pin_v4 import ExecutionRecoveryFactsPinV4
        body=self.summary['facts_pin_original']; schema=body.get('schema')
        cls={'sylanne3.c09.execution_source_pin.v4':C09ExecutionSourcePinV4,
             'sylanne3.c09.execution_source_pin.v5':C09ExecutionSourcePinV5,
             'sylanne3.authority.execution_recovery_facts_pin.v4':ExecutionRecoveryFactsPinV4}.get(schema)
        if cls is None: raise AuthorityUnavailable('historical signed facts pin schema differs')
        self.pin=decode_typed_production_value_v1(body,cls)
        h=self.header;p=self.pin
        expected=(self.producer.scope.authority_id,self.producer.scope.installation_id,self.namespace,self.operation)
        if ((h['authority_id'],h['installation_id'],h['namespace'],h['operation_id'])!=expected
                or (p.authority_id,p.installation_id,p.namespace,p.operation_id)!=expected
                or (h['old_journal_id'],h.get('old_seq',p.old_seq),h['old_chain_head_digest'],h['verifier_commitment'])
                   !=(p.old_journal_id,p.old_seq,p.old_digest,p.verifier_commitment)
                or p.facts_digest!=self.summary['facts_digest']
                or self.facts.value(core,('facts_digest',),meter)!=self.summary['facts_digest']):
            raise AuthorityUnavailable('historical typed frame, pin and signed scope differ')
        if self.prefix and type(p) is not C09ExecutionSourcePinV5:
            raise AuthorityUnavailable('historical V5 frame requires its exact V5 pin')
        if not self.prefix and self.counts.get('graph_facts',0):
            raise AuthorityUnavailable('legacy V4 lacks authenticated complete historical Contact absence')
        for name in ('authority_id','installation_id','namespace','operation_id','prior_transition_digest_or_none','facts_digest','bindings_digest'):
            self.binding_header[name]=self.bindings.value(core,(name,),meter)
        b=self.binding_header
        if (tuple(b[name] for name in ('authority_id','installation_id','namespace','operation_id'))!=expected
                or b['facts_digest']!=self.summary['facts_digest'] or b['bindings_digest']!=self.summary['recovery_bindings_digest']
                or b['prior_transition_digest_or_none']!=self.summary['prior_prepared_digest']
                or self.counts.get('prior_bindings',0)!=self.generation-1
                or self.fact_class.__name__=='C09RecoveryFactFrameV4' and self.counts.get('prior_facts',0)!=self.generation-1):
            raise AuthorityUnavailable('historical full binding header or prior frame lineage differs')
        self.inventory_header={};self.inventory_digest=None
        if self.prefix:
            from ..runtime.restore_anchor import RestoreAnchor
            names=('authority_id','installation_id','namespace','operation_id','source_seal_digest','observed_core_anchor',
                   'verifier_commitment','business_namespace_digest','inventory_digest','schema')
            self.inventory_header={name:self.facts.value(core,('contact_finish_inventory',name),meter) for name in names}
            i=self.inventory_header; anchor=RestoreAnchor(**i['observed_core_anchor'])
            if (tuple(i[name] for name in ('authority_id','installation_id','namespace','operation_id'))!=expected
                    or i['schema']!='sylanne3.c09.contact_finish_inventory.v5'
                    or i['source_seal_digest']!=p.seal_digest or i['verifier_commitment']!=p.verifier_commitment
                    or i['inventory_digest']!=p.contact_finish_inventory_digest or anchor!=p.observed_core_anchor
                    or i['observed_core_anchor']!=self.summary['old_core_anchor_original']
                    or self.counts.get('contact',0)>1024):
                raise AuthorityUnavailable('historical complete Contact inventory header differs')
            self.inventory_digest=i['inventory_digest']
            transition=self.summary['anchor_transition_original']
            if (transition['before_anchor']!=self.summary['old_core_anchor_original']
                    or transition['after_anchor']!=self.summary['new_core_anchor_original']):
                raise AuthorityUnavailable('historical actual Core anchor transition differs')
            self.seal=C09CanonicalSqlCellReaderV2('authority_c09_execution_source_seals_v4','seal_json',
                'namespace=? AND operation_id=?',(self.namespace,self.operation),ensure_ascii=True,observe=self._seal_event)
            self.phase='source_seal_scan'
        else: self.phase='models'
        return False

    def _seal_event(self,event):
        if len(event.path)==2 and event.path[0]=='suffix_row_commitments':
            if event.kind=='scalar_start': self.starts[event.path]=event.start_offset
            elif event.kind=='scalar_end':
                start=self.starts.pop(event.path); size=event.end_offset-start
                if size!=66: raise AuthorityUnavailable('historical source-seal commitment codec differs')
                value=json.loads(self.seal.read(self.db,start,size,self.meter))
                if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                    raise AuthorityUnavailable('historical source-seal row commitment differs')
                self.counts['seal_rows']=self.counts.get('seal_rows',0)+1

    def _finish_source_seal(self,digest,core,meter):
        p=self.pin
        expected={'authority_id':p.authority_id,'installation_id':p.installation_id,'namespace':p.namespace,
            'operation_id':p.operation_id,'execution_journal_id':p.old_journal_id,'execution_seq':p.old_seq,
            'execution_digest':p.old_digest,'seal_digest':p.seal_digest,
            'prior_prefix_digest':p.prior_prefix_digest,'accepted_receipt_digest':self.summary['accepted_receipt_digest'],
            'schema':'sylanne3.c09.execution_source_seal.v4'}
        if digest!=p.seal_digest or self.counts.get('seal_rows',0)!=p.old_seq:
            raise AuthorityUnavailable('historical source-seal complete typed commitment or EOF count differs')
        for name,value in expected.items():
            if self.seal.value(core,(name,),meter)!=value:
                raise AuthorityUnavailable('historical source-seal actual signed field differs')

    def _lookup_fact(self,family,key):
        row=_read_one(_history_storage_db_v3(self.producer),'SELECT value_json,value_digest FROM c09_recovery_items_v2 '
            'WHERE scope_digest=? AND family=? AND item_key=?',(self.scope,family,key),self.meter)
        if row is None: return None
        value=_decode_fact(family,row[0])
        if canonical_digest(value)!=row[1]: raise AuthorityUnavailable('actual merged historical fact changed')
        return value

    def _verify_next_model(self,core,meter):
        from .c09_model_budget_original_v1 import TABLE,validate_c09_model_budget_row_v1
        exists=_read_one(core,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,),meter)
        row=None if exists is None else _read_one(core,'SELECT namespace,operation_id,call_id,original_json,original_digest FROM '+TABLE+
            ' WHERE namespace=? AND operation_id=? AND call_id COLLATE BINARY>? ORDER BY call_id COLLATE BINARY LIMIT 1',
            (self.namespace,self.operation,self.model_after),meter)
        if row is None: self.phase='members'; return False
        model=validate_c09_model_budget_row_v1(('namespace','operation_id','call_id','original_json','original_digest'),row)
        binding=self._lookup_fact('binding',model.call_id); fact=self._lookup_fact('executions',model.call_id)
        expected_units=tuple(model_unit_fact_v4(model,u) for u in model.units if u.actual_or_none is not None)
        if (binding is None or fact is None or self._member('binding',model.call_id) is None
                or binding.execution_kind!='model' or fact.signature_commitment!=model.original_digest
                or fact.input_commitment!=model.request_digest or fact.terminal_commitment!=model.terminal_digest_or_none
                or binding.business_operation_id!=model.model_operation_id or binding.originating_journal_id!=model.originating_journal_id
                or binding.source_row_commitments!=tuple(sorted({*model.source_row_commitments,model.original_digest}))
                or binding.d11_settlement_ids!=tuple(sorted(u.settlement_id for u in expected_units))
                or any(self._lookup_fact('d11_facts',u.settlement_id)!=u for u in expected_units)):
            raise AuthorityUnavailable('historical model obligation differs from actual signed facts and binding')
        if _read_one(core,'SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?',(model.call_id,),meter) is not None:
            raise AuthorityUnavailable('historical consumed model response body survives')
        for kind,item in (('model_call',model.call_id),('model_operation',model.model_operation_id),('model_job',model.job_id),
                          ('model_acquire',model.acquire_operation_id),('model_admission',model.admission_id_or_none)):
            if item is not None and _read_one(core,'SELECT original_commitment FROM authority_c09_consumed_execution_v1 '
                'WHERE namespace=? AND kind=? AND item_id=?',(self.namespace,kind,item),meter)!=(model.original_digest,):
                raise AuthorityUnavailable('historical model once-only consumption differs')
        self.producer._merge('model',model,self.summary['prepared_digest'],meter)
        self._mark('model',model.call_id,canonical_digest(model));self.model_after=model.call_id
        return False

    def _verify_next_member(self,core,meter):
        after=self.verify_after
        where='' if after is None else ' AND (family COLLATE BINARY>? OR (family=? AND item_key COLLATE BINARY>?))'
        args=(self.scope,self.generation) if after is None else (self.scope,self.generation,after[0],after[0],after[1])
        row=_read_one(_history_storage_db_v3(self.producer),'SELECT family,item_key,value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            'WHERE scope_digest=? AND generation=?'+where+' ORDER BY family COLLATE BINARY,item_key COLLATE BINARY LIMIT 1',args,meter)
        if row is None: self.phase='contacts';return False
        family,key,digest,raw=row;aux=json.loads(raw)
        if family=='executions':
            unknown=self._member('unknown_facts',key)
            if (unknown is not None)!=(aux['status']=='unknown'):
                raise AuthorityUnavailable('historical frame exact unknown coverage differs')
        elif family=='unknown_facts':
            execution=self._member('executions',key)
            if execution is None or json.loads(execution[1])['status']!='unknown':
                raise AuthorityUnavailable('historical unknown footprint has no same-frame unknown execution')
        elif family=='binding' and aux['execution_kind']=='model':
            if self._member('model',key) is None:
                raise AuthorityUnavailable('historical model binding has no same-frame actual model original')
        elif family=='model':
            if self._member('binding',key) is None: raise AuthorityUnavailable('orphan historical model archive')
        self.verify_after=(family,key);return False

    def _verify_next_contact(self,core,meter):
        from .c09_recovery_frame_v5 import ContactFinishInventoryMemberV5
        from .c09_contact_finish_original_v1 import TABLE,COLUMNS,validate_contact_finish_row_v1,contact_graph_fact_v1
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        row=_read_one(_history_storage_db_v3(self.producer),'SELECT item_key,value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            "WHERE scope_digest=? AND generation=? AND family='contact' AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1",
            (self.scope,self.generation,self.contact_after),meter)
        if row is None: self.phase='complete';return True
        member=decode_typed_production_value_v1(json.loads(row[2]),ContactFinishInventoryMemberV5)
        original=member.original;i=self.inventory_header;p=self.pin
        actual=_read_one(core,'SELECT namespace,operation_id,business_operation_id,original_json,original_digest FROM '+TABLE+
            ' WHERE namespace=? AND operation_id=? AND business_operation_id=?',
            (original.namespace,original.operation_id,original.business_operation_id),meter)
        if (actual is None or validate_contact_finish_row_v1(COLUMNS,actual)!=original or canonical_digest(original)!=row[1]
                or (original.authority_id,original.installation_id,original.namespace,original.business_namespace_digest)
                   !=(i['authority_id'],i['installation_id'],i['namespace'],i['business_namespace_digest'])
                or original.generation>i['observed_core_anchor']['activation_generation']
                or self._lookup_fact('graph_facts',original.business_operation_id)!=contact_graph_fact_v1(original)):
            raise AuthorityUnavailable('historical Contact archive differs from its authenticated inventory')
        if member.carry is None:
            if ((original.operation_id,original.source_seal_digest,original.verifier_commitment,asdict(original.observed_core_anchor))
                    !=(self.operation,i['source_seal_digest'],i['verifier_commitment'],i['observed_core_anchor'])
                    or (original.observed_journal_id,original.observed_execution_seq,original.observed_execution_digest)
                       !=(p.old_journal_id,p.old_seq,p.old_digest)):
                raise AuthorityUnavailable('historical new Contact is not the actual signed freeze observation')
            consumed=_read_one(core,'SELECT operation_id,original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 '
                "WHERE namespace=? AND kind='fence' AND item_id=?",(original.namespace,original.owner_attempt_id),meter)
            if consumed!=(original.owner_attempt_id,original.fence_row_commitment,p.pin_digest):
                raise AuthorityUnavailable('historical Contact consumed fence differs')
            if _read_one(core,'SELECT 1 FROM authority_v2_fences WHERE operation_id=?',(original.owner_attempt_id,),meter) is not None:
                raise AuthorityUnavailable('historical consumed Contact fence survives')
        else:
            c=member.carry
            prior=_read_one(_history_storage_db_v3(self.producer),'SELECT generation,facts_digest,inventory_digest,pin_digest,prepared_digest '
                'FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND operation_id=?',
                (self.scope,c.previous_frame_operation_id),meter)
            if (prior is None or prior[0]>=self.generation or prior[1:]!=(c.previous_frame_digest,c.previous_inventory_digest,c.previous_pin_digest,c.prepared_digest)
                    or c.consumed_fence_commitment!=original.fence_row_commitment or original.operation_id==self.operation):
                raise AuthorityUnavailable('historical Contact carry changes its actual prior signed frame')
            prior_member=_read_one(_history_storage_db_v3(self.producer),'SELECT value_digest FROM c09_recovery_history_members_v2 '
                "WHERE scope_digest=? AND generation=? AND family='contact' AND item_key=?",
                (self.scope,prior[0],original.business_operation_id),meter)
            consumed=_read_one(core,'SELECT original_commitment FROM authority_c09_consumed_execution_v1 '
                "WHERE namespace=? AND kind='fence' AND item_id=?",(original.namespace,original.owner_attempt_id),meter)
            if prior_member!=(canonical_digest(original),) or consumed!=(original.fence_row_commitment,):
                raise AuthorityUnavailable('historical Contact carry loses original membership or consumed fence')
        self.contact_after=row[0];return False


class C09VerifiedPagedPreparedSummaryV2(C09VerifiedLegacyPreparedSummaryV2):
    """The actual independent V2 schema; never an adapter claiming a V1 HMAC."""
    __slots__=()
    def require_current(self,*,meter):
        if self._issuer is not _TOKEN: raise AuthorityUnavailable('paged historical PREPARED issuer differs')
        with self._control._db() as db:
            current=self._control._current(db)
            selected=_read_one(db,'SELECT generation FROM c09_storage_manifests_v1 WHERE manifest_digest=?',
                (current['current_manifest_digest'],),meter)
            row=_read_one(db,'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,prepared_digest,key_id,signature '
                'FROM c09_storage_operations_v2 WHERE installation_id=? AND operation_id=?',
                (self._control.installation_id,self._header['operation_id']),meter)
        if (selected is None or (current['pointer_version'],current['current_manifest_digest'],selected[0])!=self._selection
                or row!=self._row):
            raise AuthorityUnavailable('paged historical PREPARED source or actual selection changed')
        return self


class _CompactPreparedReaderV2:
    def __init__(self,control,row,selection):
        self.control,self.row,self.selection=control,tuple(row),tuple(selection)
        self.result=None
    def advance(self,*,meter):
        if self.result is not None:return self.result.require_current(meter=meter)
        with self.control._db() as db:
            stored=_read_one(db,'SELECT prepared_original_json FROM c09_storage_operations_v2 '
                'WHERE installation_id=? AND operation_id=?',(self.control.installation_id,self.row[0]),meter)
            if stored is None or len(stored[0].encode('utf-8'))>65536:
                raise AuthorityUnavailable('actual compact historical PREPARED is absent or outside its descriptor codec')
            original=json.loads(stored[0])
            from .c09_storage_control_v1 import canonical as control_canonical
            if control_canonical(original)!=stored[0]:
                raise AuthorityUnavailable('actual compact historical PREPARED bytes differ')
            manifest=self.control._read_manifest(db,self.row[3])
            from .c09_prepared_storage_v2 import _verify_paged_prepared_original_v2, PREPARED_FIELDS_V2, SCHEMA_V2
            _verify_paged_prepared_original_v2(self.control, _BoundedReadConnectionV2(db, meter), original, manifest,
                expected_schema=SCHEMA_V2, expected_fields=PREPARED_FIELDS_V2)
        values=(original['operation_id'],original['maintenance_generation'],original['old_manifest_digest'],original['new_manifest_digest'],
                original['prepared_digest'],original['key_id'],original['signature'])
        if values!=self.row: raise AuthorityUnavailable('actual compact historical PREPARED row differs')
        self.result=C09VerifiedPagedPreparedSummaryV2(_TOKEN,self.control,original,self.row,self.selection)
        return self.result.require_current(meter=meter)


def begin_next_authenticated_prepared_reader_v2(control,*,after_generation,through_generation,meter):
    """Unique consecutive V1/V2 history, with each schema's real verifier."""
    from .c09_storage_control_v1 import InstalledC09StorageReaderV1,C09StorageControlV1
    if type(control) not in {InstalledC09StorageReaderV1,C09StorageControlV1}:
        raise AuthorityUnavailable('actual installed Control history reader required')
    if type(after_generation) is not int or type(through_generation) is not int or not 0<=after_generation<=through_generation:
        raise AuthorityUnavailable('historical generation cursor differs')
    with control._db() as db:
        current=control._current(db);manifest=control._read_manifest(db,current['current_manifest_digest'])
        if through_generation!=manifest['generation']:
            raise AuthorityUnavailable('history bound differs from actual selected storage generation')
        selected=[]
        for version in (1,2,3):
            table='c09_storage_operations_v'+str(version)
            if _read_one(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,),meter) is None:continue
            row=_read_one(db,'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,prepared_digest,key_id,signature FROM '+table+
                ' WHERE installation_id=? AND generation>? AND generation<=? ORDER BY generation LIMIT 1',
                (control.installation_id,after_generation,through_generation),meter)
            if row is not None:selected.append((version,row))
    if not selected:
        if after_generation!=through_generation:raise AuthorityUnavailable('actual signed history has a missing generation')
        return None
    selected.sort(key=lambda item:item[1][1]);version,row=selected[0]
    if row[1]!=after_generation+1 or len(selected)>1 and selected[1][1][1]==row[1]:
        raise AuthorityUnavailable('actual signed history has a missing or conflicting schema generation')
    selection=(current['pointer_version'],current['current_manifest_digest'],manifest['generation'])
    if version == 1:
        return C09LegacyPreparedReaderV2(_TOKEN, control, row, selection)
    if version == 2:
        return _CompactPreparedReaderV2(control, row, selection)
    from .c09_prepared_storage_v3 import _CompactPreparedReaderV3
    return _CompactPreparedReaderV3(control, row, selection)


class _PriorPagedRecoveryFrameV2:
    def __init__(self,producer,summary):
        self.producer,self.summary=producer,summary
        self.completion=None;self.family_index=0;self.cursor=None;self.page=None;self.records=None;self.record_index=0
        self.complete=False;self.inventory_digest=None
        self.core_header=None;self.directory_reader=None;self.contact_locator=None;self.contact_reader=None;self.directory_done=False
        self.families=('journal',*_FAMILIES,'binding','model')

    @property
    def facts_digest(self):return self.completion.pin_digest
    @property
    def bindings_digest(self):return self.completion.binding_stream.complete.digest
    @property
    def pin_digest(self):return self.completion.pin_digest
    @property
    def next_journal(self):return self.summary['anchor_transition_original']['after_anchor']['execution_journal_id']

    def _locator(self,family):
        return getattr(self.completion,{'journal':'journal_stream','binding':'binding_stream','model':'model_stream'}.get(family,family))

    def _next(self,graph,family,after,meter):
        scope=self.completion.scope_digest
        if family=='journal':
            row=_read_one(graph,'SELECT seq,row_commitment FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND seq>? ORDER BY seq LIMIT 1',
                (scope,0 if after is None else after[0]),meter)
            return None if row is None else C09CaptureRecordV2((row[0],),row[1])
        row=_read_one(graph,'SELECT item_key,value_digest,origin_digest FROM c09_recovery_items_v2 '
            'WHERE scope_digest=? AND family=? AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',
            (scope,family,'' if after is None else after[0]),meter)
        return None if row is None else C09CaptureRecordV2((row[0],),canonical_digest((family,*row)))

    def _begin(self,meter):
        from .c09_prepared_storage_v2 import _build_original
        control=self.producer.control;op=self.summary['operation_id']
        with control._db() as db:
            details=_build_original(control,_BoundedReadConnectionV2(db,meter),op,'capture_facts_complete_v2',self.summary['facts_complete_original_digest'])
        self.completion=_decode_completion(details)
        if (self.completion.scope_digest!=self.summary['capture_scope_digest'] or self.completion.pin_digest!=self.summary['facts_pin_digest']):
            raise AuthorityUnavailable('historical signed V2 facts completion differs')
        row=(self.producer.scope.scope_digest,self.completion.scope_digest,self.summary['maintenance_generation'],op,self.summary['prepared_digest'])
        prior=_read_one(_history_storage_db_v3(self.producer),'SELECT scope_digest,historical_scope_digest,generation,operation_id,prepared_digest '
            'FROM c09_recovery_history_scopes_v2 WHERE scope_digest=? AND historical_scope_digest=?',row[:2],meter)
        if prior is None:_write(_history_storage_db_v3(self.producer),'INSERT INTO c09_recovery_history_scopes_v2 VALUES (?,?,?,?,?)',row,meter)
        elif prior!=row:raise AuthorityUnavailable('historical V2 scope lineage changed')

    def advance(self,core,graph,meter):
        self.summary.require_current(meter=meter)
        if self.completion is None:self._begin(meter);return False
        if self.complete:return True
        if self.family_index==len(self.families):
            return self._advance_contact_directory(core,meter)
        family=self.families[self.family_index];locator=self._locator(family);stream=locator.identity
        if self.cursor is None:self.cursor=begin_c09_stream_v2(stream)
        if self.records is not None:
            record=self.records[self.record_index]
            actual=self._next(graph,family,self.actual_last,meter)
            if actual!=record:raise AuthorityUnavailable('prior paged recovery omits or changes an actual retained fact')
            ordinal=self.cursor.record_offset+self.record_index+1
            member=_read_one(graph,'SELECT key_digest,primary_key_json,commitment,page_index FROM c09_capture_members_v2 '
                'WHERE stream_id=? AND record_ordinal=?',(stream.stream_id,ordinal),meter)
            if member!=(canonical_digest(record.primary_key),canonical_serialize(record.primary_key),record.commitment,self.page.page_index):
                raise AuthorityUnavailable('prior paged recovery member index differs')
            if family!='journal':
                body=_read_one(graph,'SELECT value_json,value_digest FROM c09_recovery_items_v2 '
                    'WHERE scope_digest=? AND family=? AND item_key=?',(self.completion.scope_digest,family,record.primary_key[0]),meter)
                if body is None:raise AuthorityUnavailable('prior paged recovery typed fact is absent')
                value=_decode_fact(family,body[0])
                if _fact_key(family,value)!=record.primary_key[0] or canonical_digest(value)!=body[1]:
                    raise AuthorityUnavailable('prior paged recovery typed commitment differs')
                self.producer._merge(family,value,self.summary['prepared_digest'],meter)
            self.actual_last=record.primary_key;self.record_index+=1
            if self.record_index==len(self.records):
                self.cursor=verify_c09_page_v2(stream,self.cursor,self.page,self.records)
                self.records=self.page=None;self.record_index=0
            return False
        if self.cursor.page_index<locator.complete.page_count:
            row=_read_one(graph,'SELECT descriptor_json,records_json FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index=?',
                (stream.stream_id,self.cursor.page_index),meter)
            if row is None:raise AuthorityUnavailable('prior paged recovery committed page is missing')
            self.page=c09_paged_value_from_wire_v2(json.loads(row[0]),C09CapturePageV2)
            raw=json.loads(row[1])
            if type(raw) is not list or not 1<=len(raw)<=100:raise AuthorityUnavailable('prior paged recovery page shape differs')
            self.records=tuple(c09_paged_value_from_wire_v2(value,C09CaptureRecordV2) for value in raw)
            self.actual_last=self.cursor.last_key;return False
        if self._next(graph,family,self.cursor.last_key,meter) is not None:
            raise AuthorityUnavailable('prior paged recovery has an unsealed typed suffix')
        if _read_one(graph,'SELECT 1 FROM c09_capture_pages_v2 WHERE stream_id=? AND (page_index<0 OR page_index>=?) LIMIT 1',
                (stream.stream_id,locator.complete.page_count),meter) is not None:
            raise AuthorityUnavailable('prior paged recovery has an extra unsealed page')
        if _read_one(graph,'SELECT 1 FROM c09_capture_members_v2 WHERE stream_id=? AND (record_ordinal<1 OR record_ordinal>?) LIMIT 1',
                (stream.stream_id,locator.complete.record_count),meter) is not None:
            raise AuthorityUnavailable('prior paged recovery has an extra unsealed member')
        progress=_read_one(graph,'SELECT progress_json FROM c09_recovery_progress_v2 WHERE scope_digest=? AND phase=?',
            (self.completion.scope_digest,'seal:'+family),meter)
        if progress is None:raise AuthorityUnavailable('prior paged recovery census original is missing')
        original=json.loads(progress[0]);census=c09_paged_value_from_wire_v2(original['census'],C09CountOriginalV2)
        verify_c09_complete_stream_v2(stream,self.cursor,census,locator.complete,data_eof_observation_digest=original['data_eof'])
        if family=='journal' and self.cursor.record_offset!=self.completion.old_seq:
            raise AuthorityUnavailable('prior paged recovery journal EOF disagrees with its signed pin')
        self.family_index+=1;self.cursor=None;return False


    def _advance_contact_directory(self,core,meter):
        from .c09_prepared_storage_v2 import _build_original
        if self.core_header is None:
            with self.producer.control._db() as db:
                self.core_header=_build_original(self.producer.control,_BoundedReadConnectionV2(db,meter),
                    self.summary['operation_id'],'capture_role_complete_v2_core',
                    self.summary['four_role_complete_original_digests']['core'])
            if self.core_header['scope_digest']!=self.completion.scope_digest or self.core_header['role']!='core':
                raise AuthorityUnavailable('historical Core role completion has another signed scope')
            locator=c09_paged_value_from_wire_v2(self.core_header['stream_directory'],C09SealedStreamLocatorV2)
            self.directory_reader=C09HistoricalSealedStreamReaderV2(locator)
            return False
        if not self.directory_done:
            done=self.directory_reader.advance(core,meter,lambda record:self._directory_record(core,record,meter))
            if done:
                self.directory_done=True
                self.inventory_digest=self.directory_reader.locator.complete.digest
                if self.contact_locator is not None:self.contact_reader=C09HistoricalSealedStreamReaderV2(self.contact_locator)
            return False
        if self.contact_reader is not None:
            if not self.contact_reader.advance(core,meter,lambda record:self._contact_record(core,record,meter)):
                return False
            self.inventory_digest=self.contact_locator.complete.digest
        self.complete=True;return True

    def _directory_record(self,core,record,meter):
        table='authority_c09_role_streams_v2'
        columns=('scope_digest','role','table_name','stream_kind','stream_json','seal_json')
        if len(record.primary_key)!=4:raise AuthorityUnavailable('historical role directory key differs')
        row=_read_one(core,'SELECT '+','.join(columns)+' FROM '+table+
            ' WHERE scope_digest=? AND role=? AND table_name=? AND stream_kind=?',record.primary_key,meter)
        if row is None or canonical_digest(('sylanne3.c09.authority-directory-row.v2','control_metadata',table,record.primary_key,row))!=record.commitment:
            raise AuthorityUnavailable('historical signed role directory member changed')
        if row[:4]==(self.completion.scope_digest,'core','authority_c09_contact_finish_originals_v1','target_rows'):
            if self.contact_locator is not None:raise AuthorityUnavailable('historical Contact target stream is duplicated')
            stream=c09_paged_value_from_wire_v2(json.loads(row[4]),C09StreamIdentityV2)
            complete=c09_paged_value_from_wire_v2(json.loads(row[5]),C09CompleteStreamV2)
            self.contact_locator=C09SealedStreamLocatorV2('core',stream,complete)

    def _contact_record(self,core,record,meter):
        from .c09_contact_finish_original_v1 import TABLE,COLUMNS,validate_contact_finish_row_v1,contact_graph_fact_v1
        from .c09_authority_storage_rebase import _row_commitment
        if len(record.primary_key)!=3:raise AuthorityUnavailable('historical Contact archive key differs')
        row=_read_one(core,'SELECT '+','.join(COLUMNS)+' FROM '+TABLE+
            ' WHERE namespace=? AND operation_id=? AND business_operation_id=?',record.primary_key,meter)
        if row is None or canonical_digest(('sylanne3.c09.authority-target-row.v2',TABLE,record.primary_key,_row_commitment(TABLE,COLUMNS,row)))!=record.commitment:
            raise AuthorityUnavailable('historical signed Contact target is missing or changed')
        if row[0]!=self.producer.scope.authority_namespace:return
        original=validate_contact_finish_row_v1(COLUMNS,row)
        fact=_read_one(_history_storage_db_v3(self.producer),'SELECT value_json,value_digest FROM c09_recovery_items_v2 '
            "WHERE scope_digest=? AND family='graph_facts' AND item_key=?",
            (self.producer.scope.scope_digest,original.business_operation_id),meter)
        if (fact is None or _decode_fact('graph_facts',fact[0])!=contact_graph_fact_v1(original)
                or canonical_digest(contact_graph_fact_v1(original))!=fact[1]):
            raise AuthorityUnavailable('historical paged Contact archive is outside its signed compound Graph fact')
        consumed=_read_one(core,'SELECT original_commitment FROM authority_c09_consumed_execution_v1 '
            "WHERE namespace=? AND kind='fence' AND item_id=?",(original.namespace,original.owner_attempt_id),meter)
        if consumed!=(original.fence_row_commitment,):
            raise AuthorityUnavailable('historical paged Contact once-only fence changed')
        if _read_one(core,'SELECT 1 FROM authority_v2_fences WHERE operation_id=?',(original.owner_attempt_id,),meter) is not None:
            raise AuthorityUnavailable('historical paged Contact consumed fence survives')
        raw=_encoded({'original':asdict(original),'carry':None},meter)
        key=(self.producer.scope.scope_digest,self.summary['maintenance_generation'],'contact',original.business_operation_id)
        value=(canonical_digest(original),raw)
        prior=_read_one(_history_storage_db_v3(self.producer),'SELECT value_digest,auxiliary_json FROM c09_recovery_history_members_v2 '
            'WHERE scope_digest=? AND generation=? AND family=? AND item_key=?',key,meter)
        if prior is None:_write(_history_storage_db_v3(self.producer),'INSERT INTO c09_recovery_history_members_v2 VALUES (?,?,?,?,?,?)',(*key,*value),meter)
        elif prior!=value:raise AuthorityUnavailable('historical paged Contact inventory changed on independent reread')


class C09HistoricalSealedStreamReaderV2:
    """Re-read an already signed finite stream, one real member per quantum."""
    def __init__(self,locator):
        self.locator=locator;self.cursor=begin_c09_stream_v2(locator.identity)
        self.page=None;self.records=None;self.index=0;self.complete=False

    def advance(self,db,meter,observe):
        if self.complete:return True
        stream=self.locator.identity;seal=self.locator.complete
        if self.records is not None:
            record=self.records[self.index]
            member=_read_one(db,'SELECT key_digest,primary_key_json,commitment,page_index FROM c09_capture_members_v2 '
                'WHERE stream_id=? AND record_ordinal=?',(stream.stream_id,self.cursor.record_offset+self.index+1),meter)
            if member!=(canonical_digest(record.primary_key),canonical_serialize(record.primary_key),record.commitment,self.page.page_index):
                raise AuthorityUnavailable('historical signed stream member index differs')
            observe(record);self.index+=1
            if self.index==len(self.records):
                self.cursor=verify_c09_page_v2(stream,self.cursor,self.page,self.records)
                self.records=self.page=None;self.index=0
            return False
        if self.cursor.page_index<seal.page_count:
            row=_read_one(db,'SELECT descriptor_json,records_json FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index=?',
                (stream.stream_id,self.cursor.page_index),meter)
            if row is None:raise AuthorityUnavailable('historical signed stream lost a committed page')
            self.page=c09_paged_value_from_wire_v2(json.loads(row[0]),C09CapturePageV2)
            raw=json.loads(row[1])
            if type(raw) is not list or not 1<=len(raw)<=100:raise AuthorityUnavailable('historical signed stream page count differs')
            self.records=tuple(c09_paged_value_from_wire_v2(value,C09CaptureRecordV2) for value in raw)
            return False
        for table,index,bound in (('c09_capture_pages_v2','page_index',seal.page_count),('c09_capture_members_v2','record_ordinal',seal.record_count)):
            where=index+'<0 OR '+index+'>=?' if index=='page_index' else index+'<1 OR '+index+'>?'
            if _read_one(db,'SELECT 1 FROM '+table+' WHERE stream_id=? AND ('+where+') LIMIT 1',(stream.stream_id,bound),meter) is not None:
                raise AuthorityUnavailable('historical signed stream includes extra unsealed material')
        from ..runtime.c09_paged_sql_v2 import _load_census,_capture_data_state
        bounded=_BoundedReadConnectionV2(db,meter)
        census=_load_census(bounded,stream);data=_capture_data_state(bounded,stream)
        verify_c09_complete_stream_v2(stream,self.cursor,census,seal,data_eof_observation_digest=data['eof'])
        self.complete=True;return True
