"""Authority Core durable D13 use pins and the installed mTLS control facade.

The ledger holds no Source Body. Pin state survives permit finish, expiry and
process loss. Only an original consumer release closes an active obligation.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, fields
import json
import math
import sqlite3
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from .d13_cache_use_contract_v2 import (AdminD13CacheUseControlPolicyV2,
    D13CacheUseEntryV2, D13CacheUseObservationV2, D13CachePinReceiptV2,
    OBSERVATION_SCHEMA, PROTOCOL, cache_use_from_wire_v2, cache_use_to_wire_v2,
    payload_identity_v2, payload_key_v2, selected_payloads_v2, require_cache_policy_pair_v2,
    D13CounterFrameOwnerLocatorV3, D13OwnerRegistrationReceiptV3, D13OwnerCloseReceiptV3,
    D13OwnerRetentionReleaseReceiptV3, D13NaturalReviewVerdictReceiptV3, D13NaturalParentDispositionReceiptV3, D13NaturalParentInputReceiptV3, D13RetiredReceiverOriginalV3, D13ControlledSDKConsumerReadyReceiptV3, D13CounterFrameBirthReceiptV3, D13NaturalGenerationParseReceiptV3, D13NaturalPreReviewDispositionReceiptV3, D13UnusedCounterDispositionReceiptV3, D13AuthorityCoreBirthReceiptV4, D13RetiredCoreReceiverOriginalV4, CONTROLLED_SDK_READY_SCHEMA_V3, controlled_sdk_consumer_ready_operation_id_v3, RETENTION_SCHEMA_V3,
    OWNER_REGISTRATION_SCHEMA_V3, OWNER_CLOSE_SCHEMA_V3, owner_payloads_v3,
    owner_operation_id_v3, cache_use_result_from_wire_v3)
from .v2_contract import FencePermitV2, from_wire, to_wire, SCHEMA as RPC_PROTOCOL
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_v3, runtime_storage_operation_v3, runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3

_SCHEMA_VERSION = '3'
_USE_DOMAIN = 'd13-cache-use-control-policy.v3'
_MAINT_DOMAIN = 'd13-derived-cache-maintenance-policy.v2'
_METHOD_PREFIX = 'd13_cache_use_'
METHODS = frozenset(_METHOD_PREFIX + action + '_v3' for action in ('observe', 'acquire', 'transfer', 'release', 'inspect', 'reclaim', 'owner_register', 'owner_inspect', 'owner_close', 'natural_acquire', 'natural_inspect', 'natural_close_parent', 'natural_parent_inspect', 'unused_counter_close', 'unused_counter_inspect'))
_GUARDS = WeakKeyDictionary()
_PORTS = WeakKeyDictionary()

_OWNER_METADATA_V3 = ContextVar('d13_actual_owner_metadata_v3', default=None)


def _owner_metadata_heap_v3(value, seen=None):
    from dataclasses import is_dataclass, fields
    from sys import getsizeof
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    amount = getsizeof(value)
    if type(value) is dict:
        return amount + sum(_owner_metadata_heap_v3(key, seen) + _owner_metadata_heap_v3(item, seen) for key, item in value.items())
    if type(value) in (tuple, list):
        return amount + sum(_owner_metadata_heap_v3(item, seen) for item in value)
    if is_dataclass(value):
        return amount + sum(_owner_metadata_heap_v3(getattr(value, field.name), seen) for field in fields(value))
    return amount


class _OwnerMetadataV3:
    """Fixed action slots follow the actual operation; every read still queries Core."""
    def __init__(self, operation):
        self.operation, self.rows, self.decoded = operation, {}, {}
        operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return _owner_metadata_heap_v3((self.rows, self.decoded)) + 65536

    def fixed(self, db, meter, table, columns, where, parameters, slot):
        from ..runtime.c09_paged_sql_v2 import _quote
        lengths = db.execute('SELECT ' + ','.join('length(CAST(' + _quote(column) + ' AS BLOB))' for column in columns)
            + ' FROM ' + _quote(table) + ' WHERE ' + where + ' LIMIT 1', parameters).fetchone()
        if lengths is None:
            self.rows.pop(slot, None)
            self.decoded.pop(slot, None)
            self.operation.refresh_retained_state_v3(self)
            return None
        amount = sum(size or 0 for size in lengths)
        meter.require_available(amount + 256)
        growth = amount * 12 + 4096
        if growth > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('D13 actual fixed owner metadata exceeds its registered decode arena')
        self.operation.reserve_retained_state_growth_v3(self, growth)
        try:
            row = meter.read_fixed_row(db, table, columns, where, parameters)
            self.rows[slot] = row
            return row
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def decode(self, row, action, meter):
        cached = self.decoded.get(action)
        if cached is not None and cached[0] == row[2]:
            self.decoded[action] = (row[2], cached[1])
            self.operation.refresh_retained_state_v3(self)
            return cached[1]
        growth = len(row[2].encode('utf-8')) * 12 + 4096
        if growth > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('D13 actual owner original exceeds its registered canonical decode arena')
        self.operation.reserve_retained_state_growth_v3(self, growth)
        try:
            result = cache_use_result_from_wire_v3(json.loads(row[2]))
            self.decoded[action] = (row[2], result)
            return result
        finally:
            self.operation.finish_retained_state_growth_v3(self)


def _actual_owner_fixed_row_v3(db, meter, table, columns, where, parameters, *, slot):
    provider = _OWNER_METADATA_V3.get()
    if provider is None:
        return _runtime_bounded_fixed_row_v3(db, meter, table, columns, where, parameters)
    return provider.fixed(db, meter, table, columns, where, parameters, slot)


@contextmanager
def _bind_owner_metadata_v3(operation, provider):
    from ..runtime_storage_v3 import _OPERATION
    if provider.operation is not operation or _OPERATION.get() is not operation or operation.closed:
        raise AuthorityUnavailable('D13 actual metadata provider lost its same bound operation')
    token = _OWNER_METADATA_V3.set(provider)
    try:
        yield provider
    finally:
        _OWNER_METADATA_V3.reset(token)

CACHE_USE_DDLS_V2 = {
    'authority_d13_cache_use_policies_v2': '''CREATE TABLE authority_d13_cache_use_policies_v2(
 namespace TEXT NOT NULL,use_policy_ref TEXT NOT NULL,maintenance_policy_ref TEXT NOT NULL,
 installation_id TEXT NOT NULL,use_policy_digest TEXT NOT NULL,maintenance_policy_digest TEXT NOT NULL,
 use_policy_json TEXT NOT NULL,use_signature TEXT NOT NULL,maintenance_policy_json TEXT NOT NULL,
 maintenance_signature TEXT NOT NULL,coverage_ref TEXT NOT NULL,coverage_digest TEXT NOT NULL,
 coverage_state TEXT NOT NULL CHECK(coverage_state IN ('complete','legacy_unknown')),
 coverage_original_digest TEXT NOT NULL,PRIMARY KEY(namespace,use_policy_ref)) STRICT''',
    'authority_d13_cache_use_heads_v2': '''CREATE TABLE authority_d13_cache_use_heads_v2(
 namespace TEXT PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>=0)) STRICT''',
    'authority_d13_cache_use_pins_v2': '''CREATE TABLE authority_d13_cache_use_pins_v2(
 namespace TEXT NOT NULL,pin_id TEXT NOT NULL,payload_key TEXT NOT NULL,block_ref TEXT NOT NULL,
 payload_digest TEXT NOT NULL,initial_origin_scope_digest TEXT NOT NULL,observed_revision INTEGER NOT NULL CHECK(observed_revision>0),
 consumer_owner_ref TEXT NOT NULL,consumer_operation_id TEXT NOT NULL,consumer_kind TEXT NOT NULL,
 consumer_cohort_digest TEXT NOT NULL,subject TEXT NOT NULL,use_policy_ref TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','released','unknown')),acquire_operation_id TEXT NOT NULL,
 release_operation_id TEXT,successor_pin_id TEXT,acquire_permit_token TEXT NOT NULL,acquire_permit_digest TEXT NOT NULL,PRIMARY KEY(namespace,pin_id)) STRICT''',
    'authority_d13_cache_use_operations_v2': '''CREATE TABLE authority_d13_cache_use_operations_v2(
 namespace TEXT NOT NULL,operation_id TEXT NOT NULL,action TEXT NOT NULL,request_digest TEXT NOT NULL,
 result_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id)) STRICT''',
}
CACHE_USE_DDLS_V2['authority_d13_cache_reclaim_seals_v2'] = '''CREATE TABLE authority_d13_cache_reclaim_seals_v2(
 namespace TEXT NOT NULL,permit_token TEXT NOT NULL,payload_key TEXT NOT NULL,
 observation_digest TEXT NOT NULL,control_revision INTEGER NOT NULL CHECK(control_revision>=0),
 PRIMARY KEY(namespace,permit_token,payload_key)) STRICT'''
CACHE_USE_DDLS_V2['authority_d13_cache_use_totals_v2'] = '''CREATE TABLE authority_d13_cache_use_totals_v2(
 namespace TEXT NOT NULL,payload_key TEXT NOT NULL,active_count INTEGER NOT NULL CHECK(active_count>=0),
 unknown_count INTEGER NOT NULL CHECK(unknown_count>=0),PRIMARY KEY(namespace,payload_key)) STRICT'''
CACHE_USE_INDEXES_V2 = {
    'authority_d13_cache_use_payload_v2': 'CREATE INDEX authority_d13_cache_use_payload_v2 ON authority_d13_cache_use_pins_v2(namespace,payload_key,state)',
}
CACHE_USE_TRIGGERS_V2 = {
    'authority_d13_cache_use_operation_no_update_v2': "CREATE TRIGGER authority_d13_cache_use_operation_no_update_v2 BEFORE UPDATE ON authority_d13_cache_use_operations_v2 BEGIN SELECT RAISE(ABORT,'immutable D13 use operation'); END",
    'authority_d13_cache_use_operation_no_delete_v2': "CREATE TRIGGER authority_d13_cache_use_operation_no_delete_v2 BEFORE DELETE ON authority_d13_cache_use_operations_v2 BEGIN SELECT RAISE(ABORT,'immutable D13 use operation'); END",
    'authority_d13_cache_use_pin_no_delete_v2': "CREATE TRIGGER authority_d13_cache_use_pin_no_delete_v2 BEFORE DELETE ON authority_d13_cache_use_pins_v2 BEGIN SELECT RAISE(ABORT,'D13 obligation cannot disappear'); END",
    'authority_d13_cache_use_policy_no_delete_v2': "CREATE TRIGGER authority_d13_cache_use_policy_no_delete_v2 BEFORE DELETE ON authority_d13_cache_use_policies_v2 BEGIN SELECT RAISE(ABORT,'D13 policy original cannot disappear'); END",
}
_PIN_COLUMNS = ('pin_id','payload_key','block_ref','payload_digest','initial_origin_scope_digest','observed_revision',
    'consumer_owner_ref','consumer_operation_id','consumer_kind','consumer_cohort_digest','subject','use_policy_ref',
    'state','acquire_operation_id','release_operation_id','successor_pin_id','acquire_permit_token','acquire_permit_digest')
_POLICY_COLUMNS = ('maintenance_policy_ref','installation_id','use_policy_digest','maintenance_policy_digest',
    'use_policy_json','use_signature','maintenance_policy_json','maintenance_signature','coverage_ref','coverage_digest',
    'coverage_state','coverage_original_digest')


def cache_use_schema_objects_v2():
    return tuple((kind,name,ddl) for kind,objects in (('table',CACHE_USE_DDLS_V2),
        ('index',CACHE_USE_INDEXES_V2),('trigger',CACHE_USE_TRIGGERS_V2)) for name,ddl in objects.items())


def require_d13_cache_use_schema_v2(db):
    for kind,name,ddl in cache_use_schema_objects_v2():
        if db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone() != (ddl,):
            raise AuthorityUnavailable('D13 installed durable control schema differs: ' + name)
    if db.execute("SELECT value FROM authority_meta WHERE key='d13_cache_use_schema_version'").fetchone() != (_SCHEMA_VERSION,):
        raise AuthorityUnavailable('D13 durable use control requires explicit schema version 3 installation; existing version 2 is preserved and rejected')


def install_d13_cache_use_schema_in_transaction_v2(db):
    """Only explicit V3 administrator installation owns this transaction; no runtime migration."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise AuthorityUnavailable('D13 control schema requires the actual installer transaction')
    present = [db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(name,)).fetchone()
        for _,name,_ in cache_use_schema_objects_v2()]
    if any(present):
        require_d13_cache_use_schema_v2(db)
        return
    for _,_,ddl in cache_use_schema_objects_v2():
        db.execute(ddl)
    db.execute("INSERT INTO authority_meta(key,value) VALUES('d13_cache_use_schema_version',?)",(_SCHEMA_VERSION,))
    require_d13_cache_use_schema_v2(db)


def _prepare_d13_policy_pair_v3(*,core,credential,bundle,budget_issuer,coverage_installation=None):
    """Explicit install only; ordinary and cold factories never call this signer."""
    from .core import AuthorityServiceCore
    from ..host.authority_profile import AdminInstallationBundle
    from ..runtime.issuers import D11BudgetJobIssuer
    if type(core) is not AuthorityServiceCore or type(bundle) is not AdminInstallationBundle or type(budget_issuer) is not D11BudgetJobIssuer:
        raise AuthorityUnavailable('D13 cache install requires protected actual Core/bundle/D11 issuer')
    use,maintenance = require_cache_policy_pair_v2(bundle.d13_cache_use_control_v2,bundle.d13_derived_cache_maintenance_v2)
    core._require(credential,'d13_cache_use_install',use.authority_namespace)
    if (bundle.installation_policy.namespace != use.namespace
            or bundle.installation_policy.authority_namespace != use.authority_namespace
            or bundle.installation_policy.installation_id != use.installation_id):
        raise AuthorityUnavailable('D13 control policy pair crossed protected installation')
    coverage_ref,coverage_digest = maintenance.coverage_ref,maintenance.coverage_digest
    coverage_state = 'legacy_unknown'
    coverage_original = canonical_digest(('d13.cache-use.legacy-coverage-unresolved.v3',use.namespace,
        use.installation_id,use.consumer_cohort_digest))
    if coverage_installation is not None:
        from ..runtime.d13_cache_use_admission_v2 import require_d13_cache_use_coverage_installation_v2
        ref,digest,original = require_d13_cache_use_coverage_installation_v2(coverage_installation,
            policy=use,maintenance_policy=maintenance)
        if (ref,digest) != (coverage_ref,coverage_digest):
            raise AuthorityUnavailable('D13 actual complete coverage differs from signed pair')
        coverage_state,coverage_original = 'complete',original
    use_raw,maintenance_raw = canonical_serialize(asdict(use)),canonical_serialize(asdict(maintenance))
    values = (maintenance.link_ref,use.installation_id,use.digest,canonical_digest(asdict(maintenance)),
        use_raw,budget_issuer._signer.sign(_USE_DOMAIN,use_raw),maintenance_raw,
        budget_issuer._signer.sign(_MAINT_DOMAIN,maintenance_raw),coverage_ref,coverage_digest,coverage_state,coverage_original)
    return use, values


def _install_d13_policy_pair_in_tx_v3(db, use, values):
    install_d13_cache_use_schema_in_transaction_v2(db)
    prior = db.execute('SELECT '+','.join(_POLICY_COLUMNS)+' FROM authority_d13_cache_use_policies_v2 WHERE namespace=? AND use_policy_ref=?',
        (use.authority_namespace,use.policy_ref)).fetchone()
    head = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
        (use.authority_namespace,)).fetchone()
    if prior is None:
        existing = db.execute('SELECT 1 FROM authority_d13_cache_use_policies_v2 WHERE namespace=? LIMIT 1',
            (use.authority_namespace,)).fetchone()
        if head is None and existing is not None:
            raise AuthorityUnavailable('D13 existing control head absent; cannot recreate a zero revision')
        db.execute('INSERT INTO authority_d13_cache_use_policies_v2 VALUES('+','.join('?' for _ in range(14))+')',
            (use.authority_namespace,use.policy_ref,*values))
        if head is None:
            db.execute('INSERT INTO authority_d13_cache_use_heads_v2 VALUES(?,0)',(use.authority_namespace,))
        else:
            db.execute('UPDATE authority_d13_cache_use_heads_v2 SET revision=revision+1 WHERE namespace=?',
                (use.authority_namespace,))
    elif prior != values:
        raise AuthorityUnavailable('D13 signed policy/coverage original cannot be replaced')
    elif head is None:
        raise AuthorityUnavailable('D13 installed policy lost its actual control head')


def install_d13_cache_use_policy_pair_v2(*,core,credential,bundle,budget_issuer,coverage_installation=None):
    use, values = _prepare_d13_policy_pair_v3(core=core, credential=credential, bundle=bundle,
        budget_issuer=budget_issuer, coverage_installation=coverage_installation)
    with core._tx() as db:
        _install_d13_policy_pair_in_tx_v3(db, use, values)


class InstalledD13CacheUseControlServiceV2:
    """One real Core namespace; no callback reads a business Graph body."""
    def __init__(self,*,fences,bundle,budget_issuer,clock,_policy_installation_v3=None):
        from .v2_fence_service import AuthorityV2FenceService
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime.issuers import D11BudgetJobIssuer
        if (type(fences) is not AuthorityV2FenceService or type(bundle) is not AdminInstallationBundle
                or type(budget_issuer) is not D11BudgetJobIssuer or not callable(clock)):
            raise AuthorityUnavailable('D13 cache service requires actual protected installed composition')
        self.use_policy,self.maintenance_policy = require_cache_policy_pair_v2(
            bundle.d13_cache_use_control_v2,bundle.d13_derived_cache_maintenance_v2)
        self.core,self.fences,self.bundle,self.issuer,self.clock = fences.core,fences,bundle,budget_issuer,clock
        self.namespace = self.use_policy.namespace
        self.authority_namespace = self.use_policy.authority_namespace
        self.installation_id = self.use_policy.installation_id
        self.policy_digest = canonical_digest(asdict(self.maintenance_policy))
        if (fences.namespace != self.authority_namespace or bundle.installation_policy.namespace != self.namespace
                or bundle.installation_policy.installation_id != self.installation_id):
            raise AuthorityUnavailable('D13 control service crossed actual installed Core namespace')
        if _policy_installation_v3 is None:
            with self.core._tx() as db:
                self._policy(db,installed_open=True)
        else:
            with _fresh_d13_constructor_policy_read_v3(self, _policy_installation_v3):
                with self.core._tx() as db:
                    self._policy(db,installed_open=True)

    def _policy(self,db,*,installed_open=False):
        require_d13_cache_use_schema_v2(db)
        if installed_open:
            row = db.execute('SELECT '+','.join(_POLICY_COLUMNS)+' FROM authority_d13_cache_use_policies_v2 WHERE namespace=? AND use_policy_ref=?',
                (self.authority_namespace,self.use_policy.policy_ref)).fetchone()
        else:
            with runtime_storage_quantum_v3(db) as meter:
                row = _actual_owner_fixed_row_v3(db,meter,'authority_d13_cache_use_policies_v2',_POLICY_COLUMNS,
                    'namespace=? AND use_policy_ref=?',(self.authority_namespace,self.use_policy.policy_ref),slot='policy')
        if row is None:
            raise AuthorityUnavailable('D13 policies require explicit prior signed installation; no runtime upgrade')
        use_raw,maintenance_raw = canonical_serialize(asdict(self.use_policy)),canonical_serialize(asdict(self.maintenance_policy))
        if row[:5] != (self.maintenance_policy.link_ref,self.installation_id,self.use_policy.digest,self.policy_digest,use_raw) or row[6] != maintenance_raw:
            raise AuthorityUnavailable('D13 current signed control policy pair differs')
        self.issuer._signer.verify(_USE_DOMAIN,row[4],row[5])
        self.issuer._signer.verify(_MAINT_DOMAIN,row[6],row[7])
        if (row[8],row[9]) != (self.maintenance_policy.coverage_ref,self.maintenance_policy.coverage_digest):
            raise AuthorityUnavailable('D13 actual coverage original differs from signed installation pair')
        return row

    @contextmanager
    def _locked(self,*,credential,subject,permit,action):
        if type(permit) is not FencePermitV2 or permit.operation not in ('read','write','model_egress'):
            raise AuthorityUnavailable('D13 control requires the same real active consumer/maintenance permit')
        # This new named permission is independent of permit.operation.
        self.core._require(credential,'d13_cache_use_'+action,self.authority_namespace,permit.holder)
        if action in ('release','inspect','close_original','inspect_original'):
            with self.core._tx() as db:
                prior = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
                    (self.authority_namespace,permit.operation_id)).fetchone()
                from .v2_contract import decode_bytes
                if prior is None or decode_bytes(prior[0]) != permit or prior[1] not in ('active','finished') or permit.subject != subject:
                    raise AuthorityUnavailable('D13 cleanup lost its exact original consumer permit/subject')
                with runtime_storage_operation_v3(db,operation_id='d13-use-cleanup:'+permit.operation_id),runtime_storage_quantum_v3(db):
                    policy = self._policy(db)
                    yield db,policy
            return
        self.fences._require_permit(credential=credential,subject=subject,permit=permit)
        with self.fences._frozen() as (db,deletion,execution,_):
            anchor = self.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            if self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor) != permit:
                raise AuthorityUnavailable('D13 control permit changed before its durable point')
            with runtime_storage_operation_v3(db,operation_id='d13-use-control:'+permit.operation_id),runtime_storage_quantum_v3(db):
                policy = self._policy(db)
                yield db,policy

    def _storage(self):
        handle = runtime_storage_v3(self.core._db)
        if handle is None or handle.role != 'core':
            raise AuthorityUnavailable('D13 control requires actual selected Core storage')
        from ..runtime_storage_v3 import runtime_source_identity_v4
        with runtime_storage_quantum_v3(self.core._db) as meter:
            identity = runtime_source_identity_v4(handle, meter=meter)
        return identity.selection_digest, identity.storage_generation

    def observe_for_fence_v2(self,*,credential,subject,permit,policy_digest,expected_coverage,selected_payloads):
        selected = selected_payloads_v2(tuple(tuple(value) for value in selected_payloads))
        if policy_digest != self.policy_digest or tuple(expected_coverage) != (self.maintenance_policy.coverage_ref,self.maintenance_policy.coverage_digest):
            raise AuthorityUnavailable('D13 use observation changed its signed policy/coverage selector')
        with self._locked(credential=credential,subject=subject,permit=permit,action='observe') as (db,policy):
            selection,generation = self._storage()
            revision = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',(self.authority_namespace,)).fetchone()
            if revision is None:
                raise AuthorityUnavailable('D13 durable use-control head absent')
            entries = []
            for identity in selected:
                key = payload_key_v2(self.namespace,identity)
                active_count,unknown_count = self._counts(db,key)
                unresolved = 1 if policy[10] == 'legacy_unknown' else 0
                entries.append(D13CacheUseEntryV2(identity,active_count,unknown_count+unresolved,
                    policy[10],unresolved == 0))
            values = dict(schema=OBSERVATION_SCHEMA,namespace=self.namespace,authority_namespace=self.authority_namespace,
                installation_id=self.installation_id,policy_digest=self.policy_digest,permit_token=permit.token,
                permit_digest=canonical_digest(permit),anchor_digest=canonical_digest(permit.pinned_anchor),
                activation_generation=permit.generation,storage_generation=generation,selection_digest=selection,
                coverage_ref=policy[8],coverage_digest=policy[9],coverage_state=policy[10],control_revision=revision[0],
                selected_digest=canonical_digest(selected),entries=tuple(entries))
            values['observation_digest'] = canonical_digest({**values,'namespace':asdict(self.namespace),
                'entries':tuple(asdict(entry) for entry in entries)})
            return D13CacheUseObservationV2(**values)

    def _counts(self,db,key):
        with runtime_storage_quantum_v3(db) as meter:
            row = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_totals_v2',('active_count','unknown_count'),
                'namespace=? AND payload_key=?',(self.authority_namespace,key))
            if row is not None:
                return row
            existing = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_pins_v2',('pin_id',),
                'namespace=? AND payload_key=?',(self.authority_namespace,key))
            if existing is not None:
                raise AuthorityUnavailable('D13 actual pin aggregate missing; cannot infer zero use')
            return 0,0

    def _adjust_active(self,db,key,delta):
        with runtime_storage_quantum_v3(db) as meter:
            meter.charge_write(len(self.authority_namespace)+len(key)+16)
        if delta == 1:
            db.execute('INSERT INTO authority_d13_cache_use_totals_v2 VALUES(?,?,1,0) '
                'ON CONFLICT(namespace,payload_key) DO UPDATE SET active_count=active_count+1',
                (self.authority_namespace,key))
        else:
            db.execute('UPDATE authority_d13_cache_use_totals_v2 SET active_count=active_count-1 '
                'WHERE namespace=? AND payload_key=? AND active_count>0',(self.authority_namespace,key))
            if db.execute('SELECT changes()').fetchone() != (1,):
                raise AuthorityUnavailable('D13 original active pin aggregate cannot be decremented')

    def _prior(self,db,operation_id,action,digest):
        with runtime_storage_quantum_v3(db) as meter:
            row = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_operations_v2',
                ('action','request_digest','result_json'),'namespace=? AND operation_id=?',(self.authority_namespace,operation_id))
        if row is None:
            return None
        if row[:2] != (action,digest):
            raise AuthorityUnavailable('D13 original control operation changed its request')
        return cache_use_result_from_wire_v3(json.loads(row[2]))

    def _revision(self,db):
        with runtime_storage_quantum_v3(db) as meter:
            meter.charge_write(len(self.authority_namespace)+16)
        db.execute('UPDATE authority_d13_cache_use_heads_v2 SET revision=revision+1 WHERE namespace=?',(self.authority_namespace,))
        return db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',(self.authority_namespace,)).fetchone()[0]

    def _record(self,db,action,result):
        encoded = canonical_serialize(cache_use_to_wire_v2(result))
        with runtime_storage_quantum_v3(db) as meter:
            meter.charge_write(sum(len(value.encode('utf-8')) for value in (self.authority_namespace,result.operation_id,action,result.request_digest,encoded)))
        db.execute('INSERT INTO authority_d13_cache_use_operations_v2 VALUES(?,?,?,?,?)',
            (self.authority_namespace,result.operation_id,action,result.request_digest,encoded))
        return result

    def _receipt(self,row,*,operation_id,request_digest,revision):
        return D13CachePinReceiptV2(self.namespace,self.authority_namespace,self.installation_id,row[0],
            (row[2],row[3],row[4],row[5]),row[6],row[7],row[8],row[9],row[10],row[12],revision,
            operation_id,request_digest,row[16],row[17],row[15])

    def read_pending_natural_parent_closures_v3(self, *, credential, subject, namespace,
            after_operation_id='', limit=4):
        """Read at most four actual parse rows; a candidate confers no close permission."""
        from .d13_cache_use_contract_v2 import D13PendingNaturalParentClosuresV3, D13NaturalGenerationParseReceiptV3
        from .d13_original_owner_v3 import _actual_generation_parse_in_tx_v3
        if (type(namespace) is not NamespaceId or namespace != self.namespace
                or type(after_operation_id) is not str
                or len(after_operation_id) > 192 or type(limit) is not int or not 1 <= limit <= 4
                or subject != 'mtls:sha256:' + credential.certificate_sha256):
            raise AuthorityUnavailable('exact authenticated bounded natural metadata selector required')
        self.core._require(credential, 'd13_cache_use_inspect_original', self.authority_namespace)
        with self.core._lock:
            with runtime_storage_operation_v3(self.core._db,
                    operation_id='d13-parent-discovery:' + canonical_digest((subject, after_operation_id, limit))) as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), self.core._tx() as db, runtime_storage_quantum_v3(db) as meter:
                        self._policy(db)
                        current = self.core._row(db, self.authority_namespace)
                        cursor, scanned, candidates = after_operation_id, 0, []
                        for _ in range(limit):
                            row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                                ('operation_id', 'action', 'request_digest', 'result_json'),
                                "namespace=? AND action='owner_generation_parse' AND operation_id>? "
                                "ORDER BY operation_id COLLATE BINARY",
                                (self.authority_namespace, cursor), 'parent_discovery_parse')
                            if row is None:
                                break
                            cursor, scanned = row[0], scanned + 1
                            original = provider.decode(row[1:], 'owner_generation_parse', meter)
                            if (type(original) is not D13NaturalGenerationParseReceiptV3
                                    or original.operation_id != cursor
                                    or cursor != owner_operation_id_v3(self.namespace, original.owner_ref, 'owner_generation_parse')
                                    or original.namespace != self.namespace
                                    or original.authority_namespace != self.authority_namespace
                                    or original.installation_id != self.installation_id
                                    or row[1:3] != ('owner_generation_parse', original.request_digest)):
                                raise AuthorityUnavailable('natural metadata discovery found an unclassified immutable parse original')
                            actual, registration = _actual_generation_parse_in_tx_v3(self, db, original)
                            closed = self._owner_operation_v3(db, registration.owner_ref, 'owner_close')
                            if closed is not None:
                                if closed.registration_digest != registration.registration_digest:
                                    raise AuthorityUnavailable('natural parent close belongs to another actual parse registration')
                                continue
                            if actual.parse_outcome in ('no_reply_hold', 'output_rejected'):
                                candidates.append((actual.parent_original_id, actual.parse_digest,
                                    actual.owner_ref, actual.operation_id))
                        return D13PendingNaturalParentClosuresV3(self.namespace, self.authority_namespace,
                            self.core._id(db), self.installation_id, current[1], after_operation_id,
                            cursor, limit, scanned, scanned < limit, tuple(candidates))
                finally:
                    operation.unregister_retained_state_v3(provider)

    def read_natural_parent_closure_original_v3(self, *, credential, subject, namespace, candidate):
        from .d13_cache_use_contract_v2 import D13NaturalParentClosureOriginalV3
        from .d13_original_owner_v3 import _actual_generation_parse_in_tx_v3
        if (type(namespace) is not NamespaceId or namespace != self.namespace
                or type(candidate) is not tuple or len(candidate) != 4
                or any(type(value) is not str or not 1 <= len(value) <= 192 for value in candidate)
                or subject != 'mtls:sha256:' + credential.certificate_sha256):
            raise AuthorityUnavailable('exact authenticated natural parse metadata selector required')
        self.core._require(credential, 'd13_cache_use_inspect_original', self.authority_namespace)
        with self.core._lock:
            with runtime_storage_operation_v3(self.core._db,
                    operation_id='d13-parent-original:' + canonical_digest((subject, candidate))) as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), self.core._tx() as db, runtime_storage_quantum_v3(db):
                        self._policy(db)
                        original = self._owner_operation_v3(db, candidate[2], 'owner_generation_parse')
                        if original is None:
                            raise AuthorityUnavailable('natural parent parse original is not installed')
                        actual, registration = _actual_generation_parse_in_tx_v3(self, db, original)
                        return D13NaturalParentClosureOriginalV3(self.namespace, self.authority_namespace,
                            self.core._id(db), self.installation_id, self.core._row(db, self.authority_namespace)[1],
                            candidate, actual, registration)
                finally:
                    operation.unregister_retained_state_v3(provider)

    def _require_parent_progress_maintenance_v4(self, maintenance, credential, subject):
        from .natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
        if (type(maintenance) is not InstalledNaturalDispositionMaintenanceServiceV1
                or maintenance.owner.core is not self.core or maintenance.owner.namespace != self.authority_namespace
                or maintenance.owner.installation_id != self.installation_id
                or maintenance.originals.owner is not maintenance.owner):
            raise AuthorityUnavailable('V4 parent progress requires its actual installed same-Core natural metadata service')
        maintenance._paired(credential, subject)

    def read_pending_natural_parent_closures_v4(self, *, credential, subject, namespace, maintenance,
            after_operation_id='', limit=4):
        from .d13_cache_use_contract_v2 import (D13PendingNaturalParentClosuresV4,
            D13NaturalParentClosureCandidateV4, D13NaturalGenerationParseReceiptV3, D13NaturalParentInputReceiptV3)
        if (type(namespace) is not NamespaceId or namespace != self.namespace
                or type(after_operation_id) is not str or len(after_operation_id) > 192
                or type(limit) is not int or not 1 <= limit <= 4
                or subject != 'mtls:sha256:' + credential.certificate_sha256):
            raise AuthorityUnavailable('exact authenticated bounded V4 natural metadata selector required')
        self.core._require(credential, 'd13_cache_use_inspect_original', self.authority_namespace)
        self._require_parent_progress_maintenance_v4(maintenance, credential, subject)
        with self.core._lock:
            with runtime_storage_operation_v3(self.core._db,
                    operation_id='d13-parent-discovery-v4:' + canonical_digest((subject, after_operation_id, limit))) as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), self.core._tx() as db, runtime_storage_quantum_v3(db) as meter:
                        self._policy(db)
                        current = self.core._row(db, self.authority_namespace)
                        cursor, scanned, candidates = after_operation_id, 0, []
                        for _ in range(limit):
                            row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                                ('operation_id', 'action', 'request_digest', 'result_json'),
                                "namespace=? AND action IN ('owner_generation_parse','owner_parent_input') "
                                "AND operation_id>? ORDER BY operation_id COLLATE BINARY",
                                (self.authority_namespace, cursor), 'parent_discovery_union_v4')
                            if row is None:
                                break
                            cursor, scanned = row[0], scanned + 1
                            original = provider.decode(row[1:], row[1], meter)
                            if row[1] == 'owner_generation_parse':
                                if type(original) is not D13NaturalGenerationParseReceiptV3:
                                    raise AuthorityUnavailable('V4 discovery generation origin has another exact type')
                                kind, digest = 'generation_parse', original.parse_digest
                            else:
                                if type(original) is not D13NaturalParentInputReceiptV3:
                                    raise AuthorityUnavailable('V4 discovery parent input has another exact type')
                                kind, digest = 'parent_input', original.input_digest
                            if (original.operation_id != cursor
                                    or cursor != owner_operation_id_v3(self.namespace, original.owner_ref, row[1])
                                    or original.namespace != self.namespace or original.authority_namespace != self.authority_namespace
                                    or original.installation_id != self.installation_id or original.request_digest != row[2]):
                                raise AuthorityUnavailable('V4 discovery found an unclassified immutable natural origin')
                            registration = self._owner_operation_v3(db, original.owner_ref, 'owner_register')
                            if registration is None or registration.registration_digest != original.registration_digest:
                                raise AuthorityUnavailable('V4 natural origin has no actual registration; legacy_unknown')
                            closed = self._owner_operation_v3(db, registration.owner_ref, 'owner_close')
                            if closed is not None:
                                if closed.registration_digest != registration.registration_digest:
                                    raise AuthorityUnavailable('V4 natural close belongs to another actual registration')
                                continue
                            if kind == 'generation_parse' and original.parse_outcome not in ('no_reply_hold', 'output_rejected'):
                                continue
                            candidate = D13NaturalParentClosureCandidateV4(original.parent_original_id,
                                original.owner_ref, original.registration_digest, kind, original.operation_id, digest)
                            self._natural_parent_closure_detail_in_tx_v4(db, candidate, maintenance)
                            candidates.append(candidate)
                        return D13PendingNaturalParentClosuresV4(self.namespace, self.authority_namespace,
                            self.core._id(db), self.installation_id, current[1], after_operation_id,
                            cursor, limit, scanned, scanned < limit, tuple(candidates))
                finally:
                    operation.unregister_retained_state_v3(provider)

    def _natural_parent_progress_metadata_in_tx_v4(self, db, candidate, registration, origin, verdict, closed, maintenance):
        from .v2_contract import decode_bytes
        from .v2_model_egress_contract import ModelTerminalReceiptV2
        from .d13_original_owner_v3 import _actual_owner_stop_for_parent_in_tx_v3
        from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
        if closed is not None:
            return None, None, None
        provider = _OWNER_METADATA_V3.get()
        with runtime_storage_quantum_v3(db) as meter:
            def fixed(table, columns, where, parameters, slot):
                return provider.fixed(db, meter, table, columns, where, parameters, slot)
            def permit_value(row, slot):
                if row is None:
                    raise AuthorityUnavailable('V4 progress lost its actual Core fence original')
                provider.operation.reserve_retained_state_growth_v3(provider, len(row[0]) * 12 + 4096)
                try:
                    permit = decode_bytes(row[0])
                    provider.decoded[slot] = (row[0], permit)
                    return permit
                finally:
                    provider.operation.finish_retained_state_growth_v3(provider)
            def output_read(original, reason):
                row = fixed('authority_v2_fences', ('permit','state','pending'),
                    'namespace=? AND operation_id=?', (self.authority_namespace, original.producer_permit_operation_id),
                    'closure_output_read_v4')
                permit = permit_value(row, 'closure_output_permit_v4')
                if (permit.operation != 'read' or permit.operation_id != original.producer_permit_operation_id
                        or permit.namespace != self.authority_namespace or permit.subject != registration.subject
                        or canonical_digest(permit) != original.producer_permit_digest or row[2] is not None
                        or row[1] not in ('active','finished')):
                    raise AuthorityUnavailable('V4 progress Source delivery original is unknown or changed')
                if row[1] == 'active':
                    return reason, canonical_digest(('d13.actual-output-read-pending.v4',
                        candidate, permit, row[1])), None
                return None
            if candidate.origin_kind == 'generation_parse':
                waiting = output_read(origin, 'generation_output_read_open')
                return waiting if waiting is not None else (None, None, None)
            ids = natural_job_ids_v2(self.namespace, candidate.parent_original_id, 'review')
            model = fixed('authority_model_egress_v1', ('operation_id','namespace','subject','state','observation_digest'),
                'call_id=?', (ids[3],), 'closure_review_model_v4')
            identity = fixed('authority_model_original_identity_v2',
                ('authority_id','installation_id','namespace','job_id','operation_id','acquire_operation_id',
                    'request_digest','binding_digest'), 'call_id=?', (ids[3],), 'closure_review_identity_v4')
            binding = fixed('authority_model_egress_bindings_v1', ('operation_id','token'),
                'call_id=?', (ids[3],), 'closure_review_binding_v4')
            fence = None if binding is None else fixed('authority_v2_fences',
                ('permit','state','pending','finish_request_id','finish_request_digest'),
                'namespace=? AND operation_id=?', (self.authority_namespace,binding[0]), 'closure_review_fence_v4')
            permit = permit_value(fence, 'closure_review_permit_v4')
            if (model is None or identity is None or binding is None
                    or identity[:4] != (self.core._id(db),self.installation_id,self.authority_namespace,ids[0])
                    or identity[5] != ids[2] or model[:3] != (identity[4],self.authority_namespace,registration.subject)
                    or binding != (model[0],registration.permit_token)
                    or permit.operation_id != model[0] or permit.token != registration.permit_token
                    or permit.subject != registration.subject or canonical_digest(permit) != registration.permit_digest
                    or fence[2] is not None):
                raise AuthorityUnavailable('V4 progress has no exact actual review model/admission/fence lineage')
            from .d13_cache_use_contract_v2 import _sha
            _sha(identity[6], 'review_request_digest'); _sha(identity[7], 'review_binding_digest')
            permanent = _actual_owner_stop_for_parent_in_tx_v3(self,db,candidate.parent_original_id,permit.generation)
            if model[3] in ('prepared','dispatch_started') and fence[1] == 'active' and model[4] is None:
                return 'review_model_pending', canonical_digest(('d13.actual-review-model-pending.v4',
                    candidate,model,identity,binding,permit)), permanent
            if model[3] != 'observed':
                if permanent is not None and model[3] == 'prepared' and fence[1] == 'finished':
                    return None,None,permanent
                raise AuthorityUnavailable('V4 review progress is unknown; it is not ordinary waiting')
            admission = fixed('authority_model_admissions_v2', ('admission_id','report_digest','receipt_json'),
                'call_id=?',(ids[3],),'closure_review_terminal_v4')
            if admission is None or admission[2] is None:
                raise AuthorityUnavailable('V4 observed review has no actual bodyless terminal original')
            provider.operation.reserve_retained_state_growth_v3(provider,len(admission[2].encode())*12+4096)
            try:
                terminal = ModelTerminalReceiptV2(**json.loads(admission[2]))
                provider.decoded['closure_review_terminal_v4'] = (admission[2],terminal)
            finally:
                provider.operation.finish_retained_state_growth_v3(provider)
            if (canonical_serialize(asdict(terminal)) != admission[2]
                    or (terminal.call_id,terminal.request_digest,terminal.installation_id,
                        terminal.admission_id,terminal.report_digest,terminal.observation_digest) !=
                        (ids[3],identity[6],self.installation_id,admission[0],admission[1],model[4])
                    or fence[1] != 'finished' or fence[3:] != (ids[3],terminal.finish_digest)):
                raise AuthorityUnavailable('V4 observed review terminal/finish metadata differs from the actual Core original')
            if verdict is None:
                if permanent is not None:
                    return None,None,permanent
                return 'review_output_pending',canonical_digest(('d13.actual-review-output-pending.v4',
                    candidate,model,terminal)),None
            waiting = output_read(verdict,'review_output_read_open')
            if waiting is not None:
                return waiting
            if permanent is not None or verdict.verdict != 'pass':
                return None,None,permanent
            from .natural_disposition_maintenance_v1 import ORIGINAL_TABLE
            from ..domains.d09.natural_disposition_v1 import natural_disposition_from_wire_v1
            from .v2_contract import from_wire
            where = ("authority_namespace=? AND installation_id=? AND kind IN ('roster_prepared','maintenance_prepared') "
                "AND json_extract(payload_json,'$.parent_original_id')=? AND NOT EXISTS(SELECT 1 FROM "
                + ORIGINAL_TABLE + " c WHERE c.authority_namespace=" + ORIGINAL_TABLE + ".authority_namespace "
                "AND c.installation_id=" + ORIGINAL_TABLE + ".installation_id AND c.operation_id="
                + ORIGINAL_TABLE + ".operation_id AND c.kind IN ('roster_committed','maintenance_committed','rejected_no_commit'))")
            parameters = (self.authority_namespace,self.installation_id,candidate.parent_original_id)
            prepared_row = fixed(ORIGINAL_TABLE,('original_ref','payload_json','payload_digest','signature'),
                where + ' ORDER BY original_ref COLLATE BINARY',parameters,'closure_roster_prepared_v4')
            if prepared_row is None:
                return None,None,permanent
            another = fixed(ORIGINAL_TABLE,('original_ref',),
                where + ' AND original_ref>? ORDER BY original_ref COLLATE BINARY',
                (*parameters,prepared_row[0]),'closure_roster_prepared_extra_v4')
            if another is not None:
                raise AuthorityUnavailable('V4 parent has multiple unresolved signed roster preparations')
            provider.operation.reserve_retained_state_growth_v3(provider,len(prepared_row[1].encode())*12+4096)
            try:
                prepared = maintenance.originals._decode(prepared_row[1:])
                expected = natural_disposition_from_wire_v1(prepared.payload['expected_next_value'])
                writer = from_wire(prepared.payload['permit'])
                provider.decoded['closure_roster_prepared_v4'] = (prepared_row[1],prepared,expected,writer)
            finally:
                provider.operation.finish_retained_state_growth_v3(provider)
            if (prepared.original_ref != prepared_row[0] or prepared.parent_original_id != candidate.parent_original_id
                    or (expected.namespace,expected.installation_id,expected.parent_original_id,
                        expected.generation_original_operation_id,expected.generation_original_digest,
                        expected.review_original_operation_id,expected.review_original_digest,expected.whole_output_digest) !=
                        (origin.namespace,origin.installation_id,origin.parent_original_id,
                        origin.generation_original_id,origin.generation_original_digest,
                        origin.review_original_id,origin.review_original_digest,origin.whole_output_digest)
                    or tuple((c.index,c.operation_id,c.effect_id) for c in expected.children) != origin.child_identities):
                raise AuthorityUnavailable('V4 signed roster preparation differs from its actual parent input')
            writer_row = fixed('authority_v2_fences',('permit','state','pending'),
                'namespace=? AND operation_id=?',(self.authority_namespace,writer.operation_id),'closure_roster_writer_v4')
            actual_writer = permit_value(writer_row,'closure_roster_writer_permit_v4')
            if (actual_writer != writer or writer.operation != 'write' or writer.subject != registration.subject
                    or writer_row[1:] != ('active',None)):
                raise AuthorityUnavailable('V4 unresolved roster preparation has no exact active actual writer')
            return 'roster_write_open',canonical_digest(('d13.actual-roster-write-pending.v4',
                candidate,prepared.digest,writer,writer_row[1])),None

    def _natural_parent_closure_detail_in_tx_v4(self, db, candidate, maintenance):
        from .d13_cache_use_contract_v2 import (D13NaturalParentClosureCandidateV4,
            D13NaturalParentClosureOriginalV4, D13NaturalParentInputReceiptV3)
        from .d13_original_owner_v3 import (_actual_generation_parse_in_tx_v3, natural_stage_owner_ref_v3)
        from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
        if type(candidate) is not D13NaturalParentClosureCandidateV4:
            raise AuthorityUnavailable('exact V4 parent metadata candidate required')
        action = {'generation_parse': 'owner_generation_parse', 'parent_input': 'owner_parent_input'}[candidate.origin_kind]
        original = self._owner_operation_v3(db, candidate.owner_ref, action)
        registration = self._owner_operation_v3(db, candidate.owner_ref, 'owner_register')
        if (original is None or registration is None
                or original.operation_id != candidate.origin_operation_id
                or original.registration_digest != candidate.registration_digest
                or registration.registration_digest != candidate.registration_digest
                or original.parent_original_id != candidate.parent_original_id):
            raise AuthorityUnavailable('V4 parent selector differs from its actual immutable Core origin')
        closed = self._owner_operation_v3(db, candidate.owner_ref, 'owner_close')
        parse = capsule = transfer = verdict = None
        if candidate.origin_kind == 'generation_parse':
            parse, generation = _actual_generation_parse_in_tx_v3(self, db, original)
            if parse.parse_digest != candidate.origin_digest or parse.parse_outcome not in ('no_reply_hold', 'output_rejected'):
                raise AuthorityUnavailable('V4 pre-review candidate differs from its actual deterministic outcome')
            if closed is not None and closed.disposition_kind == 'transferred':
                raise AuthorityUnavailable('V4 generation candidate transferred; discover its actual review owner')
            arm = 'pre_review'
        else:
            capsule = original
            if type(capsule) is not D13NaturalParentInputReceiptV3 or capsule.input_digest != candidate.origin_digest:
                raise AuthorityUnavailable('V4 review parent has no actual matching parent input capsule')
            generation_job = natural_job_ids_v2(self.namespace, candidate.parent_original_id, 'generation')[0]
            review_job = natural_job_ids_v2(self.namespace, candidate.parent_original_id, 'review')[0]
            generation_ref = natural_stage_owner_ref_v3(self.namespace, generation_job)
            if (registration.owner_ref != natural_stage_owner_ref_v3(self.namespace, review_job)
                    or registration.original_locator.job_id != review_job):
                raise AuthorityUnavailable('V4 review registration is not its actual original stage')
            generation = self._owner_operation_v3(db, generation_ref, 'owner_register')
            transfer = self._owner_operation_v3(db, generation_ref, 'owner_close')
            verdict = self._owner_operation_v3(db, candidate.owner_ref, 'owner_review_verdict')
            if generation is None or transfer is None:
                raise AuthorityUnavailable('V4 review parent lacks its actual generation registration/transfer')
            arm = 'review_parent'
        waiting, waiting_digest, permanent = self._natural_parent_progress_metadata_in_tx_v4(
            db,candidate,registration,original,verdict,closed,maintenance)
        return D13NaturalParentClosureOriginalV4(self.namespace, self.authority_namespace,
            self.core._id(db), self.installation_id, self.core._row(db, self.authority_namespace)[1],
            candidate, arm, registration, generation, parse, capsule, transfer, verdict, closed,
            waiting, waiting_digest, permanent)

    def read_natural_parent_closure_original_v4(self, *, credential, subject, namespace, candidate, maintenance):
        from .d13_cache_use_contract_v2 import D13NaturalParentClosureCandidateV4
        if (type(namespace) is not NamespaceId or namespace != self.namespace
                or type(candidate) is not D13NaturalParentClosureCandidateV4
                or subject != 'mtls:sha256:' + credential.certificate_sha256):
            raise AuthorityUnavailable('exact authenticated V4 parent original selector required')
        self.core._require(credential, 'd13_cache_use_inspect_original', self.authority_namespace)
        self._require_parent_progress_maintenance_v4(maintenance, credential, subject)
        with self.core._lock:
            with runtime_storage_operation_v3(self.core._db,
                    operation_id='d13-parent-original-v4:' + canonical_digest((subject, candidate))) as operation:
                provider = _OwnerMetadataV3(operation)
                try:
                    with _bind_owner_metadata_v3(operation, provider), self.core._tx() as db, runtime_storage_quantum_v3(db):
                        self._policy(db)
                        return self._natural_parent_closure_detail_in_tx_v4(db, candidate, maintenance)
                finally:
                    operation.unregister_retained_state_v3(provider)

    def _owner_operation_v3(self, db, owner_ref, action):
        operation_id = owner_operation_id_v3(self.namespace, owner_ref, action)
        with runtime_storage_quantum_v3(db) as meter:
            row = _actual_owner_fixed_row_v3(db, meter, 'authority_d13_cache_use_operations_v2',
                ('action', 'request_digest', 'result_json'), 'namespace=? AND operation_id=?',
                (self.authority_namespace, operation_id),slot=action)
        if row is None:
            return None
        provider = _OWNER_METADATA_V3.get()
        if provider is None:
            result = cache_use_result_from_wire_v3(json.loads(row[2]))
        else:
            with runtime_storage_quantum_v3(db) as meter:
                result = provider.decode(row, action, meter)
        expected = {'owner_register': D13OwnerRegistrationReceiptV3, 'owner_close': D13OwnerCloseReceiptV3,
            'owner_retention_release': D13OwnerRetentionReleaseReceiptV3,
            'owner_review_verdict': D13NaturalReviewVerdictReceiptV3,
            'owner_parent_disposition': D13NaturalParentDispositionReceiptV3,
            'owner_parent_input': D13NaturalParentInputReceiptV3,
            'owner_peer_retirement': D13RetiredReceiverOriginalV3,
            'owner_counter_birth': D13CounterFrameBirthReceiptV3,
            'owner_generation_parse': D13NaturalGenerationParseReceiptV3,
            'owner_pre_review_disposition': D13NaturalPreReviewDispositionReceiptV3,
            'owner_unused_counter_disposition': D13UnusedCounterDispositionReceiptV3,
            'owner_core_birth': D13AuthorityCoreBirthReceiptV4,
            'owner_core_retirement': D13RetiredCoreReceiverOriginalV4}[action]
        if (type(result) is not expected or row[:2] != (action, result.request_digest)
                or result.namespace != self.namespace or result.authority_namespace != self.authority_namespace
                or result.installation_id != self.installation_id or result.owner_ref != owner_ref
                or result.operation_id != operation_id):
            raise AuthorityUnavailable('D13 actual immutable owner operation differs from its original namespace/producer')
        return result

    def _live_owner_v3(self, db, owner_ref):
        registration = self._owner_operation_v3(db, owner_ref, 'owner_register')
        if registration is None:
            raise AuthorityUnavailable('D13 original has no V3 owner registration; legacy_unknown remains HOLD')
        if (registration.use_policy_ref != self.use_policy.policy_ref
                or registration.use_policy_digest != self.use_policy.digest
                or registration.consumer_cohort_digest != self.use_policy.consumer_cohort_digest):
            raise AuthorityUnavailable('D13 original owner belongs to another signed V3 producer cohort')
        closure = self._owner_operation_v3(db, owner_ref, 'owner_close')
        if closure is not None:
            if closure.registration_digest != registration.registration_digest:
                raise AuthorityUnavailable('D13 owner closure differs from its original registration')
            raise AuthorityUnavailable('D13 immutable historical original has closed execution/retention ownership')
        return registration

    def _no_reclaim_v3(self, db):
        with runtime_storage_quantum_v3(db) as meter:
            meter.require_available(8192)
            row = db.execute("SELECT token FROM authority_v2_fences INDEXED BY authority_v2_one_active "
                "WHERE namespace=? AND state='active' AND EXISTS ("
                "SELECT 1 FROM authority_d13_cache_reclaim_seals_v2 AS seal "
                "WHERE seal.namespace=authority_v2_fences.namespace "
                "AND seal.permit_token=authority_v2_fences.token LIMIT 1) LIMIT 1",
                (self.authority_namespace,)).fetchone()
            if row is not None:
                meter.charge_read(len(row[0].encode('utf-8')))
                raise AuthorityUnavailable('D13 original owner mutation is blocked by the actual namespace reclaim seal')

    def register_original_owner_in_tx_v3(self, db, proof):
        from .d13_original_owner_v3 import require_d13_original_owner_proof_v3
        material, credential, permit = require_d13_original_owner_proof_v3(proof, service=self, db=db, action='register')
        from .d13_original_owner_v3 import require_actual_authority_source_locator_in_tx_v4
        require_actual_authority_source_locator_in_tx_v4(self, db, material['original_locator'])
        self.core._require(credential, 'd13_cache_use_register_original', self.authority_namespace, permit.holder)
        self._policy(db)
        self._storage()
        from .v2_contract import decode_bytes
        actual = db.execute('SELECT permit,state FROM authority_v2_fences WHERE namespace=? AND operation_id=?',
            (self.authority_namespace, permit.operation_id)).fetchone()
        if actual is None or decode_bytes(actual[0]) != permit or actual[1] != 'active' or material['subject'] != permit.subject:
            raise AuthorityUnavailable('D13 owner registration lost its actual current producer Source permit')
        operation_id = owner_operation_id_v3(self.namespace, material['owner_ref'], 'owner_register')
        request_digest = canonical_digest((PROTOCOL, 'owner_register', self.namespace, self.use_policy.digest, material))
        prior = self._owner_operation_v3(db, material['owner_ref'], 'owner_register')
        if prior is not None:
            if prior.request_digest != request_digest:
                raise AuthorityUnavailable('D13 owner registration attempted to replace its actual complete original')
            return self._live_owner_v3(db, material['owner_ref'])
        self._no_reclaim_v3(db)
        now = self.clock()
        now = now.timestamp() if hasattr(now, 'timestamp') else now
        if type(now) not in (int, float) or not math.isfinite(now) or now >= self.use_policy.valid_until:
            raise AuthorityUnavailable('D13 signed V3 owner cohort expired before new original publication')
        payloads = owner_payloads_v3(material['payload_identities'])
        values = dict(namespace=self.namespace, authority_namespace=self.authority_namespace,
            installation_id=self.installation_id, use_policy_ref=self.use_policy.policy_ref,
            use_policy_digest=self.use_policy.digest, consumer_cohort_digest=self.use_policy.consumer_cohort_digest,
            **material, payload_digest=canonical_digest(payloads), operation_id=operation_id,
            request_digest=request_digest, control_revision=self._revision(db), schema=OWNER_REGISTRATION_SCHEMA_V3)
        for field in ('peer_admission_digest', 'process_incarnation', 'producer_kind_version', 'retention_instance_ref'):
            values.setdefault(field, None)
        values['registration_digest'] = canonical_digest(values)
        registration = D13OwnerRegistrationReceiptV3(**values)
        for identity in payloads:
            key = payload_key_v2(self.namespace, identity)
            pin_id = 'd13-owner-pin-v3:' + canonical_digest((self.namespace, material['owner_ref'], key))
            row = (pin_id, key, *identity, material['owner_ref'], material['original_operation_id'],
                material['owner_kind'], self.use_policy.consumer_cohort_digest, material['subject'],
                self.use_policy.policy_ref, 'active', operation_id, None, None, permit.token, canonical_digest(permit))
            with runtime_storage_quantum_v3(db) as meter:
                meter.charge_write(sum(len(str(value).encode('utf-8')) for value in (self.authority_namespace, *row)))
            db.execute('INSERT INTO authority_d13_cache_use_pins_v2 VALUES(' + ','.join('?' for _ in range(19)) + ')',
                (self.authority_namespace, *row))
            self._adjust_active(db, key, 1)
        return self._record(db, 'owner_register', registration)

    def require_original_execution_use_in_tx_v3(self, db, proof):
        from .d13_original_owner_v3 import bind_actual_counter_owner_metadata_v3
        with bind_actual_counter_owner_metadata_v3(proof, service=self, db=db):
            from .d13_original_owner_v3 import require_d13_original_owner_proof_v3
            material, credential, _ = require_d13_original_owner_proof_v3(proof, service=self, db=db, action='execute')
            self.core._require(credential, 'read', self.authority_namespace)
            self._policy(db)
            registration = self._live_owner_v3(db, material['owner_ref'])
            row = db.execute('SELECT payload_digest FROM authority_d13_counter_originals_v1 '
                "WHERE namespace=? AND counter_operation_id=? AND phase='draft'",
                (self.authority_namespace, material['original_operation_id'])).fetchone()
            locator = registration.original_locator
            if (registration.owner_kind != 'counter_frame_draft' or type(locator) is not D13CounterFrameOwnerLocatorV3
                    or locator.counter_operation_id != material['original_operation_id']
                    or registration.original_operation_id != material['original_operation_id']
                    or row != (registration.original_commitment,)):
                raise AuthorityUnavailable('D13 Counter execution has no exact registered actual immutable draft')
            for identity in registration.payload_identities:
                pin_id = 'd13-owner-pin-v3:' + canonical_digest((self.namespace, registration.owner_ref, payload_key_v2(self.namespace, identity)))
                state = db.execute('SELECT state,consumer_owner_ref FROM authority_d13_cache_use_pins_v2 WHERE namespace=? AND pin_id=?',
                    (self.authority_namespace, pin_id)).fetchone()
                if state != ('active', registration.owner_ref):
                    raise AuthorityUnavailable('D13 original execution lost its actual durable payload ownership')
            return registration

    def record_original_owner_retention_in_tx_v3(self, db, proof):
        from .d13_original_owner_v3 import require_d13_owner_retention_release_v3
        registration, material, credential = require_d13_owner_retention_release_v3(proof, service=self, db=db)
        self.core._require(credential, 'd13_cache_use_close_original', self.authority_namespace)
        self._policy(db)
        actual = self._owner_operation_v3(db, registration.owner_ref, 'owner_register')
        if actual != registration:
            raise AuthorityUnavailable('D13 actual retention event belongs to another registered original owner')
        operation_id = owner_operation_id_v3(self.namespace, registration.owner_ref, 'owner_retention_release')
        request_digest = canonical_digest((PROTOCOL, 'owner_retention_release', registration.registration_digest, material))
        prior = self._owner_operation_v3(db, registration.owner_ref, 'owner_retention_release')
        if prior is not None:
            if prior.request_digest != request_digest:
                raise AuthorityUnavailable('D13 actual retention original cannot be replaced by another scope event')
            return prior
        values = dict(namespace=self.namespace, authority_namespace=self.authority_namespace,
            installation_id=self.installation_id, owner_ref=registration.owner_ref,
            registration_digest=registration.registration_digest, **material,
            operation_id=operation_id, request_digest=request_digest, control_revision=self._revision(db),
            schema=RETENTION_SCHEMA_V3)
        values['retention_digest'] = canonical_digest(values)
        return self._record(db, 'owner_retention_release', D13OwnerRetentionReleaseReceiptV3(**values))

    def close_original_owner_in_tx_v3(self, db, proof):
        from .d13_original_owner_v3 import require_d13_owner_closure_proof_v3, require_d13_owner_close_authorization_v3
        original, material, credential = require_d13_owner_closure_proof_v3(proof, service=self, db=db)
        require_d13_owner_close_authorization_v3(proof, service=self, db=db, credential=credential)
        self._policy(db)
        operation_id = owner_operation_id_v3(self.namespace, original.owner_ref, 'owner_close')
        request_digest = canonical_digest((PROTOCOL, 'owner_close', original.registration_digest, material))
        prior = self._owner_operation_v3(db, original.owner_ref, 'owner_close')
        if prior is not None:
            if prior.registration_digest != original.registration_digest or prior.request_digest != request_digest:
                raise AuthorityUnavailable('D13 original close replay changed its actual disposition or final retention release')
            return prior
        actual = self._live_owner_v3(db, original.owner_ref)
        if actual != original:
            raise AuthorityUnavailable('D13 actual final disposition belongs to another original owner')
        self._no_reclaim_v3(db)
        values = dict(namespace=self.namespace, authority_namespace=self.authority_namespace,
            installation_id=self.installation_id, owner_ref=original.owner_ref,
            registration_digest=original.registration_digest, **material,
            operation_id=operation_id, request_digest=request_digest, control_revision=self._revision(db),
            schema=OWNER_CLOSE_SCHEMA_V3)
        values.setdefault('retention_original', None)
        values['close_digest'] = canonical_digest(values)
        closed = D13OwnerCloseReceiptV3(**values)
        for identity in original.payload_identities:
            key = payload_key_v2(self.namespace, identity)
            pin_id = 'd13-owner-pin-v3:' + canonical_digest((self.namespace, original.owner_ref, key))
            row = db.execute('SELECT state,consumer_owner_ref FROM authority_d13_cache_use_pins_v2 WHERE namespace=? AND pin_id=?',
                (self.authority_namespace, pin_id)).fetchone()
            if row != ('active', original.owner_ref):
                raise AuthorityUnavailable('D13 final close lost an actual active original payload obligation')
            with runtime_storage_quantum_v3(db) as meter:
                meter.charge_write(len(operation_id) + len(self.authority_namespace) + len(pin_id) + 16)
            db.execute("UPDATE authority_d13_cache_use_pins_v2 SET state='released',release_operation_id=? "
                "WHERE namespace=? AND pin_id=?", (operation_id, self.authority_namespace, pin_id))
            self._adjust_active(db, key, -1)
        return self._record(db, 'owner_close', closed)

    def mutate_for_fence_v2(self,*,credential,subject,permit,action,operation_id,binding,identity,pin_id=None,successor_binding=None):
        if action not in ('acquire','transfer','release','inspect'):
            raise AuthorityUnavailable('D13 named consumer control action required')
        payload_identity_v2(identity)
        required = {'consumer_owner_ref','consumer_operation_id','consumer_kind','consumer_cohort_digest'}
        if type(binding) is not dict or set(binding) != required or binding['consumer_cohort_digest'] != self.use_policy.consumer_cohort_digest:
            raise AuthorityUnavailable('D13 consumer binding differs from signed installed cohort')
        for value in (operation_id,*binding.values()):
            if type(value) is not str or not value or len(value.encode('utf-8')) > 4096:
                raise AuthorityUnavailable('D13 bounded original consumer control identity required')
        digest = canonical_digest((PROTOCOL,action,self.namespace,operation_id,binding,identity,pin_id,successor_binding))
        with self._locked(credential=credential,subject=subject,permit=permit,action=action) as (db,policy):
            self._storage()
            prior = self._prior(db,operation_id,action,digest)
            if prior is not None:
                if prior.subject != subject or prior.permit_digest != canonical_digest(permit):
                    raise AuthorityUnavailable('D13 original control result belongs to another original permit/subject')
                if action in ('acquire','transfer'):
                    with runtime_storage_quantum_v3(db) as meter:
                        active = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_pins_v2',('state',),
                            'namespace=? AND pin_id=?',(self.authority_namespace,prior.pin_id))
                    if active != ('active',):
                        raise AuthorityUnavailable('D13 a released original acquisition cannot authorize renewed Body use')
                return prior
            if action in ('acquire','transfer','release'):
                # A live namespace seal freezes the exact eligible FIFO census.
                # Finished seals remain audit originals and impose no barrier.
                with runtime_storage_quantum_v3(db) as meter:
                    meter.require_available(8192)
                    blocking = db.execute(
                        "SELECT token FROM authority_v2_fences INDEXED BY authority_v2_one_active "
                        "WHERE namespace=? AND state='active' AND EXISTS ("
                        "SELECT 1 FROM authority_d13_cache_reclaim_seals_v2 AS seal "
                        "WHERE seal.namespace=authority_v2_fences.namespace "
                        "AND seal.permit_token=authority_v2_fences.token LIMIT 1) LIMIT 1",
                        (self.authority_namespace,)).fetchone()
                    if blocking is not None:
                        meter.charge_read(len(blocking[0].encode('utf-8')))
                        raise AuthorityUnavailable('D13 namespace reclaim is active; retain original pin and cleanup operation')
            if action in ('acquire','transfer'):
                if db.execute('SELECT 1 FROM authority_d13_cache_reclaim_seals_v2 WHERE namespace=? AND permit_token=? AND payload_key=?',
                        (self.authority_namespace,permit.token,payload_key_v2(self.namespace,identity))).fetchone() is not None:
                    raise AuthorityUnavailable('D13 same-permit use cannot reopen a payload sealed for actual reclamation')
                now = self.clock()
                now = now.timestamp() if hasattr(now,'timestamp') else now
                if type(now) not in (int,float) or not math.isfinite(now) or now >= self.use_policy.valid_until:
                    raise AuthorityUnavailable('D13 original use policy expired before acquiring new use')
            owner_registration = self._live_owner_v3(db, binding['consumer_owner_ref']) if action in ('acquire', 'transfer') else self._owner_operation_v3(db, binding['consumer_owner_ref'], 'owner_register')
            if (owner_registration is None or identity not in owner_registration.payload_identities
                    or owner_registration.original_operation_id != binding['consumer_operation_id']
                    or owner_registration.owner_kind != binding['consumer_kind']):
                raise AuthorityUnavailable('D13 pin operation lacks its exact registered original owner payload set')
            if action == 'release':
                closed = self._owner_operation_v3(db, owner_registration.owner_ref, 'owner_close')
                if closed is None or closed.registration_digest != owner_registration.registration_digest:
                    raise AuthorityUnavailable('D13 actual owner disposition and final retention release must precede pin release')
            key = payload_key_v2(self.namespace,identity)
            if action == 'acquire':
                pin_id = 'd13-owner-pin-v3:' + canonical_digest((self.namespace,owner_registration.owner_ref,key))
                with runtime_storage_quantum_v3(db) as meter:
                    row = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_pins_v2',_PIN_COLUMNS,
                        'namespace=? AND pin_id=?',(self.authority_namespace,pin_id))
                if (row is None or row[12] != 'active' or row[6:11] !=
                        (binding['consumer_owner_ref'],binding['consumer_operation_id'],binding['consumer_kind'],
                            binding['consumer_cohort_digest'],subject)
                        or row[16:] != (permit.token,canonical_digest(permit))):
                    raise AuthorityUnavailable('D13 acquire cannot synthesize or revive an unregistered original owner pin')
                revision = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
                    (self.authority_namespace,)).fetchone()[0]
                return self._record(db,action,self._receipt(row,operation_id=operation_id,request_digest=digest,revision=revision))
            with runtime_storage_quantum_v3(db) as meter:
                row = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_pins_v2',_PIN_COLUMNS,
                    'namespace=? AND pin_id=?',(self.authority_namespace,pin_id))
            if (row is None or row[1] != key or row[6:11] != (binding['consumer_owner_ref'],binding['consumer_operation_id'],
                    binding['consumer_kind'],binding['consumer_cohort_digest'],subject)
                    or (action in ('release','inspect') and row[16:] != (permit.token,canonical_digest(permit))) or row[11] != self.use_policy.policy_ref):
                raise AuthorityUnavailable('D13 pin mutation lacks its original consumer ownership')
            if action == 'inspect':
                revision = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',(self.authority_namespace,)).fetchone()[0]
                return self._receipt(row,operation_id=operation_id,request_digest=digest,revision=revision)
            if action == 'release' and row[12] == 'released' and row[14] == closed.operation_id:
                revision = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',
                    (self.authority_namespace,)).fetchone()[0]
                return self._record(db,action,self._receipt(row,operation_id=operation_id,request_digest=digest,revision=revision))
            if row[12] != 'active':
                raise AuthorityUnavailable('D13 original pin is not an active owned obligation')
            if action == 'release':
                with runtime_storage_quantum_v3(db) as meter:
                    meter.charge_write(len(operation_id)+len(self.authority_namespace)+len(pin_id)+16)
                db.execute("UPDATE authority_d13_cache_use_pins_v2 SET state='released',release_operation_id=? WHERE namespace=? AND pin_id=? AND state='active'",
                    (operation_id,self.authority_namespace,pin_id))
                self._adjust_active(db,key,-1)
                row = (*row[:12],'released',row[13],operation_id,*row[15:])
                return self._record(db,action,self._receipt(row,operation_id=operation_id,request_digest=digest,revision=self._revision(db)))
            if (type(successor_binding) is not dict or set(successor_binding) != required
                    or successor_binding['consumer_cohort_digest'] != self.use_policy.consumer_cohort_digest
                    or any(type(value) is not str or not value or len(value.encode('utf-8'))>4096 for value in successor_binding.values())
                    or row[15] is not None):
                raise AuthorityUnavailable('D13 transfer lacks its exact fresh successor ownership')
            successor_owner = self._live_owner_v3(db, successor_binding['consumer_owner_ref'])
            if (identity not in successor_owner.payload_identities
                    or successor_owner.original_operation_id != successor_binding['consumer_operation_id']
                    or successor_owner.owner_kind != successor_binding['consumer_kind']):
                raise AuthorityUnavailable('D13 transfer requires its confirmed exact successor owner registration')
            successor_id = 'd13-owner-pin-v3:' + canonical_digest((self.namespace,successor_owner.owner_ref,key))
            with runtime_storage_quantum_v3(db) as meter:
                successor = _runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_pins_v2',_PIN_COLUMNS,
                    'namespace=? AND pin_id=?',(self.authority_namespace,successor_id))
            if (successor is None or successor[12] != 'active' or successor_id == pin_id
                    or successor[6:11] != (successor_binding['consumer_owner_ref'],successor_binding['consumer_operation_id'],
                        successor_binding['consumer_kind'],successor_binding['consumer_cohort_digest'],subject)
                    or successor[16:] != (permit.token,canonical_digest(permit))):
                raise AuthorityUnavailable('D13 successor payload ownership has not actually been registered')
            with runtime_storage_quantum_v3(db) as meter:
                meter.charge_write(len(successor_id)+len(self.authority_namespace)+len(pin_id))
            db.execute('UPDATE authority_d13_cache_use_pins_v2 SET successor_pin_id=? WHERE namespace=? AND pin_id=?',
                (successor_id,self.authority_namespace,pin_id))
            # Both registered owners retain their real obligations until proven final release.
            return self._record(db,action,self._receipt(successor,operation_id=operation_id,request_digest=digest,revision=self._revision(db)))

    def seal_reclaim_for_fence_v2(self,*,credential,subject,permit,observation):
        if (type(observation) is not D13CacheUseObservationV2 or permit.operation != 'write'
                or observation.namespace != self.namespace or observation.policy_digest != self.policy_digest
                or observation.permit_digest != canonical_digest(permit)
                or observation.anchor_digest != canonical_digest(permit.pinned_anchor)
                or observation.coverage_state != 'complete'
                or any(entry.active_count or entry.unknown_count or not entry.query_complete for entry in observation.entries)
                or not (self.maintenance_policy.capacity_eviction_enabled or self.maintenance_policy.cold_maintenance_enabled)):
            raise AuthorityUnavailable('D13 reclaim requires the actual independent maintenance WRITE and complete zero use')
        with self._locked(credential=credential,subject=subject,permit=permit,action='reclaim') as (db,policy):
            selection,generation = self._storage()
            current = db.execute('SELECT revision FROM authority_d13_cache_use_heads_v2 WHERE namespace=?',(self.authority_namespace,)).fetchone()
            if (current != (observation.control_revision,) or selection != observation.selection_digest
                    or generation != observation.storage_generation or policy[10] != 'complete'
                    or (policy[8],policy[9]) != (observation.coverage_ref,observation.coverage_digest)):
                raise AuthorityUnavailable('D13 use control/selection/coverage changed before actual reclaim seal')
            for entry in observation.entries:
                key = payload_key_v2(self.namespace,entry.identity)
                if self._counts(db,key) != (0,0):
                    raise AuthorityUnavailable('D13 actual outstanding use blocks reclamation')
                prior = db.execute('SELECT observation_digest,control_revision FROM authority_d13_cache_reclaim_seals_v2 WHERE namespace=? AND permit_token=? AND payload_key=?',
                    (self.authority_namespace,permit.token,key)).fetchone()
                if prior is None:
                    with runtime_storage_quantum_v3(db) as meter:
                        meter.charge_write(len(self.authority_namespace)+len(permit.token)+len(key)+len(observation.observation_digest)+8)
                    db.execute('INSERT INTO authority_d13_cache_reclaim_seals_v2 VALUES(?,?,?,?,?)',
                        (self.authority_namespace,permit.token,key,observation.observation_digest,observation.control_revision))
                elif prior != (observation.observation_digest,observation.control_revision):
                    raise AuthorityUnavailable('D13 original same-permit reclaim seal changed')
            return {'schema':'sylanne3.d13.cache-reclaim-seal.v3','observation_digest':observation.observation_digest,
                'permit_digest':observation.permit_digest,'selection_digest':selection,
                'control_revision':observation.control_revision,'selected_digest':observation.selected_digest}


class D13CacheReclaimGuardV2:
    """Private, once-only W01 consumption of a real Core reclaim seal."""
    def __init__(self,issuer,port,observation,permit,admission,seal):
        if issuer is not _GUARD_ISSUER:
            raise AuthorityUnavailable('D13 reclaim guard requires the actual installed control factory')
        _GUARDS[self] = (port,observation,permit,admission,seal)

    def require_v2(self,*,namespace,policy_digest,permit,selection_digest,selected_payloads,
            coverage_ref,coverage_digest,maintenance_admission):
        state = _GUARDS.get(self)
        if state is None:
            raise AuthorityUnavailable('D13 reclaim guard was not issued or was already consumed')
        port,observation,original_permit,admission,seal = state
        port._actual()
        from ..runtime.d13_maintenance_read_v2 import require_d13_maintenance_control_admission_v2
        require_d13_maintenance_control_admission_v2(maintenance_admission,namespace=namespace,
            policy_digest=policy_digest,permit=permit,selection_digest=selection_digest,
            selected_payloads=selected_payloads)
        if (maintenance_admission is not admission or permit is not original_permit
                or observation.namespace != namespace or observation.policy_digest != policy_digest
                or observation.permit_digest != canonical_digest(permit) or permit.operation != 'write'
                or observation.selection_digest != selection_digest
                or tuple(entry.identity for entry in observation.entries) != tuple(selected_payloads)
                or (observation.coverage_ref,observation.coverage_digest) != (coverage_ref,coverage_digest)
                or seal['observation_digest'] != observation.observation_digest
                or seal['selected_digest'] != observation.selected_digest):
            raise AuthorityUnavailable('D13 reclaim guard crossed its actual W01/policy/selection/admission')
        _GUARDS.pop(self)


_GUARD_ISSUER = object()
_LEASE_ISSUER = object()
_LEASES = WeakKeyDictionary()


class _D13CachePinLeaseV2:
    """Ownership follows retained content; no destructor silently releases a pin."""
    def __init__(self,issuer,port,receipt,permit,binding):
        if issuer is not _LEASE_ISSUER or receipt.state != 'active':
            raise AuthorityUnavailable('D13 retained pin lease requires its actual durable acquire acknowledgement')
        self.receipt,self.original_permit = receipt,permit
        _LEASES[self] = (port,receipt,permit,dict(binding))

    @property
    def pin_id(self):
        return self.receipt.pin_id


class InstalledD13CacheUseControlPortV2:
    def __init__(self,*,fence_port,bundle):
        from ..host.v2_fence_port import V2FencePort
        from ..host.authority_profile import AdminInstallationBundle
        if type(fence_port) is not V2FencePort or type(bundle) is not AdminInstallationBundle:
            raise AuthorityUnavailable('D13 use control facade requires the actual installed mTLS fence port/bundle')
        use,maintenance = require_cache_policy_pair_v2(bundle.d13_cache_use_control_v2,bundle.d13_derived_cache_maintenance_v2)
        _,grant = fence_port._identity()
        if (grant.installation_id != use.installation_id or bundle.installation_policy.namespace != use.namespace
                or bundle.installation_policy.authority_namespace != use.authority_namespace):
            raise AuthorityUnavailable('D13 use control facade crossed actual installed identity')
        self.fence_port,self.bundle,self.use_policy,self.maintenance_policy = fence_port,bundle,use,maintenance
        _PORTS[self] = (fence_port,bundle,use,maintenance)

    def _actual(self):
        if _PORTS.get(self) != (self.fence_port,self.bundle,self.use_policy,self.maintenance_policy):
            raise AuthorityUnavailable('D13 use controller lost its private installed identity')
        return self

    def _rpc(self,action,*,namespace,authority_namespace,permit,**values):
        self._actual()
        if (namespace != self.use_policy.namespace or authority_namespace != self.use_policy.authority_namespace
                or type(permit) is not FencePermitV2 or permit.namespace != authority_namespace):
            raise AuthorityUnavailable('D13 control call crossed its installed exact namespace')
        port = self.fence_port
        async def send():
            await port._mapped(namespace,authority_namespace)
            handshake,grant = port._identity()
            if (permit.subject != grant.subject or permit.authority_id != grant.authority_id
                    or permit.holder != grant.administrator_holder):
                raise AuthorityUnavailable('D13 pin control crossed actual authenticated subject/holder')
            response = await port._transport._content_rpc(port._request,handshake,
                _METHOD_PREFIX+action+'_v3',{'namespace':authority_namespace,'permit':to_wire(permit),**values},protocol=RPC_PROTOCOL)
            field = ('owner' if action in ('owner_register', 'owner_inspect', 'natural_acquire', 'natural_inspect') else 'closure' if action in ('owner_close', 'natural_close_parent', 'natural_parent_inspect', 'unused_counter_close', 'unused_counter_inspect')
                else 'observation' if action == 'observe' else 'seal' if action == 'reclaim' else 'pin')
            if (type(response) is not dict or set(response) != {field,'channel_binding_sha256'}
                    or response['channel_binding_sha256'] != handshake.channel_binding_sha256):
                raise AuthorityUnavailable('D13 use control response changed actual mTLS channel binding')
            if action == 'reclaim':
                return response['seal']
            if action in ('owner_inspect', 'natural_inspect', 'natural_parent_inspect', 'unused_counter_inspect') and response[field] is None:
                return None
            if action in ('natural_close_parent', 'unused_counter_close') and response[field] is None:
                from .d13_original_owner_v3 import D13NaturalRosterNotTerminalV3
                raise D13NaturalRosterNotTerminalV3('D13 actual complete parent is not terminal or its retention is unresolved')
            return cache_use_result_from_wire_v3(response[field])
        # Outcome unknown propagates. A consumer must inspect the same operation;
        # it never invents another acquire identity or begins reading the body.
        return port._submit(port._with_session_repair(send))

    def observe_for_fence_v2(self,*,namespace,authority_namespace,permit,policy_digest,expected_coverage,selected_payloads):
        selected = selected_payloads_v2(tuple(selected_payloads))
        value = self._rpc('observe',namespace=namespace,authority_namespace=authority_namespace,permit=permit,
            policy_digest=policy_digest,expected_coverage=tuple(expected_coverage),selected_payloads=selected)
        if (value.namespace != namespace or value.authority_namespace != authority_namespace
                or value.installation_id != self.use_policy.installation_id or value.policy_digest != policy_digest
                or value.permit_token != permit.token or value.permit_digest != canonical_digest(permit)
                or value.anchor_digest != canonical_digest(permit.pinned_anchor)
                or value.activation_generation != permit.generation
                or value.selected_digest != canonical_digest(selected)
                or tuple(entry.identity for entry in value.entries) != selected
                or (value.coverage_ref,value.coverage_digest) != tuple(expected_coverage)):
            raise AuthorityUnavailable('D13 observation differs from actual installed selected payload request')
        return value

    def require_reclaim_for_fence_v2(self,observation,*,maintenance_admission):
        self._actual()
        from ..runtime.d13_maintenance_read_v2 import require_d13_maintenance_control_admission_v2
        scope = maintenance_admission.scope
        if scope is None:
            raise AuthorityUnavailable('D13 reclamation has no actual fresh maintenance WRITE')
        selected = tuple(entry.identity for entry in observation.entries)
        require_d13_maintenance_control_admission_v2(maintenance_admission,namespace=observation.namespace,
            policy_digest=observation.policy_digest,permit=scope.permit,selection_digest=observation.selection_digest,
            selected_payloads=selected)
        seal = self._rpc('reclaim',namespace=observation.namespace,authority_namespace=observation.authority_namespace,
            permit=scope.permit,observation=cache_use_to_wire_v2(observation))
        expected = {'schema':'sylanne3.d13.cache-reclaim-seal.v3','observation_digest':observation.observation_digest,
            'permit_digest':observation.permit_digest,'selection_digest':observation.selection_digest,
            'control_revision':observation.control_revision,'selected_digest':observation.selected_digest}
        if seal != expected:
            raise AuthorityUnavailable('D13 actual Core reclaim seal acknowledgement differs')
        return D13CacheReclaimGuardV2(_GUARD_ISSUER,self,observation,scope.permit,maintenance_admission,seal)

    def _require_owner_receipt_v3(self, receipt, material, permit):
        if (type(receipt) is not D13OwnerRegistrationReceiptV3
                or receipt.namespace != self.use_policy.namespace
                or receipt.authority_namespace != self.use_policy.authority_namespace
                or receipt.installation_id != self.use_policy.installation_id
                or receipt.use_policy_ref != self.use_policy.policy_ref
                or receipt.use_policy_digest != self.use_policy.digest
                or receipt.consumer_cohort_digest != self.use_policy.consumer_cohort_digest
                or receipt.permit_digest != canonical_digest(permit)
                or any(getattr(receipt, name) != value for name, value in material.items())):
            raise AuthorityUnavailable('D13 owner acknowledgement differs from its actual immutable Source receiver producer')
        return receipt

    def register_original_owner_for_fence_v3(self, *, namespace, authority_namespace, permit, owner_admission):
        from ..runtime.d13_cache_use_admission_v2 import require_d13_source_receiver_client_v3
        material = require_d13_source_receiver_client_v3(owner_admission, port=self, permit=permit, action='register')
        if (namespace, authority_namespace) != (self.use_policy.namespace, self.use_policy.authority_namespace):
            raise AuthorityUnavailable('D13 Source receiver registration crossed its installed namespace')
        if type(self) is _InstalledD13CacheUseControlLocalPortV2:
            with self.service._locked(credential=self.credential, subject=self.subject, permit=permit,
                    action='register_original') as (db, _):
                receipt = self.service.register_original_owner_in_tx_v3(db, owner_admission)
        else:
            wire = {**material, 'original_locator': asdict(material['original_locator'])}
            receipt = self._rpc('owner_register', namespace=namespace, authority_namespace=authority_namespace,
                permit=permit, owner_material=wire)
        return self._require_owner_receipt_v3(receipt, material, permit)

    def inspect_original_owner_for_fence_v3(self, *, namespace, authority_namespace, permit, owner_admission):
        from ..runtime.d13_cache_use_admission_v2 import require_d13_source_receiver_client_v3
        material = require_d13_source_receiver_client_v3(owner_admission, port=self, permit=permit, action='inspect')
        if (namespace, authority_namespace) != (self.use_policy.namespace, self.use_policy.authority_namespace):
            raise AuthorityUnavailable('D13 same-original receiver inspection crossed its installed namespace')
        if type(self) is _InstalledD13CacheUseControlLocalPortV2:
            with self.service._locked(credential=self.credential, subject=self.subject, permit=permit,
                    action='inspect_original') as (db, _):
                receipt = self.service._owner_operation_v3(db, material['owner_ref'], 'owner_register')
        else:
            receipt = self._rpc('owner_inspect', namespace=namespace, authority_namespace=authority_namespace,
                permit=permit, owner_ref=material['owner_ref'])
        return None if receipt is None else self._require_owner_receipt_v3(receipt, material, permit)


    def close_unused_counter_for_fence_v3(self, *, namespace, authority_namespace, permit,
            parent_original_id, counter_operation_id):
        return self._unused_counter_closure_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id, counter_operation_id=counter_operation_id,
            action='unused_counter_close')

    def inspect_unused_counter_closure_for_fence_v3(self, *, namespace, authority_namespace, permit,
            parent_original_id, counter_operation_id):
        return self._unused_counter_closure_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id, counter_operation_id=counter_operation_id,
            action='unused_counter_inspect')

    def _unused_counter_closure_v3(self, *, namespace, authority_namespace, permit,
            parent_original_id, counter_operation_id, action):
        from .d13_original_owner_v3 import counter_frame_owner_ref_v3
        self._actual()
        result = self._rpc(action, namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id, counter_operation_id=counter_operation_id)
        if result is None and action == 'unused_counter_inspect':
            return None
        expected = counter_frame_owner_ref_v3(namespace, counter_operation_id)
        if (type(result) is not D13OwnerCloseReceiptV3 or result.namespace != namespace
                or result.authority_namespace != authority_namespace or result.installation_id != self.use_policy.installation_id
                or result.owner_ref != expected or result.disposition_kind not in ('terminal', 'never_started')
                or result.disposition_ref != owner_operation_id_v3(namespace, expected, 'owner_unused_counter_disposition')):
            raise AuthorityUnavailable('D13 unused Counter close lacks its exact actual permanent disposition acknowledgement')
        return result

    def close_natural_parent_for_fence_v3(self, *, namespace, authority_namespace, permit, parent_original_id):
        return self._natural_parent_closure_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id, action='natural_close_parent')

    def inspect_natural_parent_closure_for_fence_v3(self, *, namespace, authority_namespace, permit, parent_original_id):
        return self._natural_parent_closure_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id, action='natural_parent_inspect')

    def _natural_parent_closure_v3(self, *, namespace, authority_namespace, permit, parent_original_id, action):
        from .d13_original_owner_v3 import natural_stage_owner_ref_v3
        from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
        self._actual()
        result = self._rpc(action, namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, parent_original_id=parent_original_id)
        if result is None and action == 'natural_parent_inspect':
            return None
        expected = {natural_stage_owner_ref_v3(namespace,
            natural_job_ids_v2(namespace, parent_original_id, stage)[0]) for stage in ('generation', 'review')}
        if (type(result) is not D13OwnerCloseReceiptV3 or result.namespace != namespace
                or result.authority_namespace != authority_namespace or result.installation_id != self.use_policy.installation_id
                or result.owner_ref not in expected or result.disposition_kind not in ('terminal', 'never_started')):
            raise AuthorityUnavailable('D13 natural parent closure lacks its exact actual final original acknowledgement')
        return result

    def acquire_natural_original_for_fence_v3(self, *, namespace, authority_namespace, permit, natural_admission):
        return self._natural_original_for_fence_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, natural_admission=natural_admission, action='natural_acquire')

    def inspect_natural_original_for_fence_v3(self, *, namespace, authority_namespace, permit, natural_admission):
        return self._natural_original_for_fence_v3(namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, natural_admission=natural_admission, action='natural_inspect')

    def _natural_original_for_fence_v3(self, *, namespace, authority_namespace, permit, natural_admission, action):
        from ..runtime.d13_natural_original_use_v3 import require_actual_graph_natural_owner_v3
        from .d13_original_owner_v3 import natural_receiver_owner_ref_v3
        from .d13_cache_use_contract_v2 import D13NaturalReceiverOwnerLocatorV3
        self._actual()
        material = require_actual_graph_natural_owner_v3(natural_admission, port=self, permit=permit,
            action='register' if action == 'natural_acquire' else 'inspect')
        if type(self) is not InstalledD13CacheUseControlPortV2:
            raise AuthorityUnavailable('D13 natural original receiver requires its actual installed Graph mTLS port')
        receipt = self._rpc(action, namespace=namespace, authority_namespace=authority_namespace,
            permit=permit, natural_material=material)
        if receipt is None and action == 'natural_inspect':
            return None
        locator = None if type(receipt) is not D13OwnerRegistrationReceiptV3 else receipt.original_locator
        if (type(locator) is not D13NaturalReceiverOwnerLocatorV3
                or receipt.namespace != namespace or receipt.authority_namespace != authority_namespace
                or receipt.installation_id != self.use_policy.installation_id
                or receipt.consumer_cohort_digest != self.use_policy.consumer_cohort_digest
                or receipt.owner_ref != natural_receiver_owner_ref_v3(namespace, permit,
                    material['retention_instance_ref'], material['selection_digest'])
                or receipt.permit_token != permit.token or receipt.permit_digest != canonical_digest(permit)
                or locator.parent_original_id != material['parent_original_id']
                or locator.generation_job_id != material['generation_job_id']
                or locator.generation_original_id != material['generation_original_id']
                or locator.generation_call_id != material['generation_call_id']
                or locator.generation_frozen_input_digest != material['generation_frozen_input_digest']
                or material['review_job_id'] is not None and
                    (locator.review_job_id, locator.review_original_id) !=
                        (material['review_job_id'], material['review_original_id'])
                or locator.retention_id != material['retention_instance_ref']
                or locator.selection_digest != material['selection_digest']):
            raise AuthorityUnavailable('D13 natural receiver lost its exact authenticated original acknowledgement')
        return receipt

    def close_original_owner_v3(self, registration, *, close_admission):
        from ..runtime.d13_cache_use_admission_v2 import (_source_receiver_closure_v3,
            require_d13_source_receiver_release_client_v3)
        from ..runtime.d13_natural_original_use_v3 import (
            D13GraphNaturalOriginalReleaseProofV3, require_actual_graph_natural_release_v3)
        natural_release = type(close_admission) is D13GraphNaturalOriginalReleaseProofV3
        if natural_release:
            original, permit, release = require_actual_graph_natural_release_v3(close_admission, port=self)
        else:
            owner, _, original, _ = _source_receiver_closure_v3(close_admission, port=self)
            permit = owner.permit
        if original is not registration:
            raise AuthorityUnavailable('D13 close cannot replace its actual acknowledged original owner')
        if type(self) is _InstalledD13CacheUseControlLocalPortV2:
            with self.service._locked(credential=self.credential, subject=self.subject, permit=permit,
                    action='close_original') as (db, _):
                receipt = self.service.close_original_owner_in_tx_v3(db, close_admission)
        else:
            if not natural_release:
                release = require_d13_source_receiver_release_client_v3(close_admission, port=self)
            receipt = self._rpc('owner_close', namespace=registration.namespace,
                authority_namespace=registration.authority_namespace, permit=permit,
                release_original=asdict(release))
        if (type(receipt) is not D13OwnerCloseReceiptV3 or receipt.namespace != registration.namespace
                or receipt.authority_namespace != registration.authority_namespace
                or receipt.installation_id != registration.installation_id or receipt.owner_ref != registration.owner_ref
                or receipt.registration_digest != registration.registration_digest):
            raise AuthorityUnavailable('D13 final receiver close lacks its exact durable original acknowledgement')
        return receipt

    def _binding(self,admission,*,permit,selected,action):
        from ..runtime.d13_cache_use_admission_v2 import require_d13_cache_use_consumer_admission_v2
        return require_d13_cache_use_consumer_admission_v2(admission,port=self,permit=permit,
            selected_payloads=selected,action=action)

    def acquire_for_fence_v2(self,*,namespace,authority_namespace,permit,operation_id,selected_payloads,consumer_admission):
        selected = selected_payloads_v2(tuple(selected_payloads))
        binding = self._binding(consumer_admission,permit=permit,selected=selected,action='acquire')
        result = []
        for identity in selected:
            original = operation_id+':'+payload_key_v2(namespace,identity)
            receipt = self._rpc('acquire',namespace=namespace,authority_namespace=authority_namespace,permit=permit,
                operation_id=original,binding=binding,identity=identity)
            self._require_receipt(receipt,identity,binding,permit,original)
            result.append(_D13CachePinLeaseV2(_LEASE_ISSUER,self,receipt,permit,binding))
        return tuple(result)

    def _require_receipt(self,receipt,identity,binding,permit,operation_id):
        if (receipt.namespace != self.use_policy.namespace or receipt.authority_namespace != self.use_policy.authority_namespace
                or receipt.installation_id != self.use_policy.installation_id or receipt.payload_identity != identity
                or receipt.operation_id != operation_id or receipt.consumer_owner_ref != binding['consumer_owner_ref']
                or receipt.consumer_operation_id != binding['consumer_operation_id'] or receipt.consumer_kind != binding['consumer_kind']
                or receipt.consumer_cohort_digest != self.use_policy.consumer_cohort_digest or receipt.subject != permit.subject
                or receipt.permit_token != permit.token or receipt.permit_digest != canonical_digest(permit)):
            raise AuthorityUnavailable('D13 acknowledged pin differs from actual original consumer acquisition')

    def inspect_acquisition_v2(self,*,namespace,authority_namespace,permit,operation_id,selected_payloads,consumer_admission):
        selected = selected_payloads_v2(tuple(selected_payloads))
        binding = self._binding(consumer_admission,permit=permit,selected=selected,action='inspect')
        result = []
        for identity in selected:
            original = operation_id+':'+payload_key_v2(namespace,identity)
            pin_id = 'd13-owner-pin-v3:'+canonical_digest((namespace,binding['consumer_owner_ref'],payload_key_v2(namespace,identity)))
            query = 'd13-use-inspect:'+canonical_digest((original,pin_id))
            receipt = self._rpc('inspect',namespace=namespace,authority_namespace=authority_namespace,permit=permit,
                operation_id=query,binding=binding,identity=identity,pin_id=pin_id)
            self._require_receipt(receipt,identity,binding,permit,query)
            result.append(_D13CachePinLeaseV2(_LEASE_ISSUER,self,receipt,permit,binding) if receipt.state=='active' else receipt)
        return tuple(result)

    def transfer_for_fence_v2(self,pin,*,permit,operation_id,consumer_admission,successor_admission):
        state = _LEASES.get(pin)
        if state is None or state[0] is not self:
            raise AuthorityUnavailable('D13 transfer requires its actual retained original pin')
        identity = state[1].payload_identity
        old = self._binding(consumer_admission,permit=permit,selected=(identity,),action='transfer')
        successor = self._binding(successor_admission,permit=permit,selected=(identity,),action='acquire')
        if old != state[3]:
            raise AuthorityUnavailable('D13 transfer original owner differs')
        receipt = self._rpc('transfer',namespace=self.use_policy.namespace,authority_namespace=self.use_policy.authority_namespace,
            permit=permit,operation_id=operation_id,binding=old,identity=identity,pin_id=pin.pin_id,successor_binding=successor)
        self._require_receipt(receipt,identity,successor,permit,operation_id)
        return _D13CachePinLeaseV2(_LEASE_ISSUER,self,receipt,permit,successor)

    def release_v2(self,pin,*,operation_id,consumer_admission):
        return self._cleanup(pin,operation_id,consumer_admission,'release')

    def inspect_v2(self,pin,*,operation_id,consumer_admission):
        return self._cleanup(pin,operation_id,consumer_admission,'inspect')

    def _cleanup(self,pin,operation_id,admission,action):
        state = _LEASES.get(pin)
        if state is None or state[0] is not self:
            raise AuthorityUnavailable('D13 cleanup requires its actual original retained pin ownership')
        _,original,permit,binding = state
        if self._binding(admission,permit=permit,selected=(original.payload_identity,),action=action) != binding:
            raise AuthorityUnavailable('D13 cleanup changed original retained consumer owner')
        receipt = self._rpc(action,namespace=original.namespace,authority_namespace=original.authority_namespace,permit=permit,
            operation_id=operation_id,binding=binding,identity=original.payload_identity,pin_id=original.pin_id)
        self._require_receipt(receipt,original.payload_identity,binding,permit,operation_id)
        if action == 'release':
            if receipt.state != 'released':
                raise AuthorityUnavailable('D13 release was not durably acknowledged')
            _LEASES.pop(pin)
        return receipt


def install_d13_cache_use_rpc_service_v2(server,namespace,service):
    if (type(service) is not InstalledD13CacheUseControlServiceV2 or service.core is not server._core
            or service.fences is not server._v2_fences.get(namespace) or service.authority_namespace != namespace):
        raise AuthorityUnavailable('D13 use-control RPC must reuse actual server Core/fence installation')
    key = (namespace,service.installation_id)
    if server._d13_cache_use_controls_v2.get(key,service) is not service:
        raise AuthorityUnavailable('D13 use-control service identity is already installed')
    server._d13_cache_use_controls_v2[key] = service


def dispatch_d13_cache_use_control_v2(server,method,command,*,credential,profile_id,manifest_digest):
    if method not in METHODS or type(command) is not dict or 'namespace' not in command:
        raise AuthorityUnavailable('D13 exact named control RPC required')
    namespace = command['namespace']
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installation = server._installations_v2[(credential.certificate_sha256,profile_id)]
    service = server._d13_cache_use_controls_v2.get((namespace,installation.installation_id))
    if service is None:
        raise AuthorityUnavailable('D13 explicit signed use-control installation unavailable')
    action = method[len(_METHOD_PREFIX):-3]

    if action in ('unused_counter_close', 'unused_counter_inspect'):
        if set(command) != {'namespace', 'permit', 'parent_original_id', 'counter_operation_id'}:
            raise AuthorityUnavailable('D13 exact unused Counter metadata closure scope required')
        from .d13_original_owner_v3 import (close_authenticated_d13_unused_counter_v3,
            counter_frame_owner_ref_v3, D13NaturalRosterNotTerminalV3, _actual_peer_admission_v3)
        parent, counted = command['parent_original_id'], command['counter_operation_id']
        if any(type(value) is not str or not 1 <= len(value) <= 192 for value in (parent, counted)):
            raise AuthorityUnavailable('D13 exact bounded parent/Counter identity required')
        permit = from_wire(command['permit'])
        if action == 'unused_counter_close':
            try:
                result = close_authenticated_d13_unused_counter_v3(server, service,
                    credential=credential, profile_id=profile_id, manifest_digest=manifest_digest,
                    permit=permit, parent_original_id=parent, counter_operation_id=counted)
            except D13NaturalRosterNotTerminalV3:
                return {'closure': None}
        else:
            _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
            subject = 'mtls:sha256:' + credential.certificate_sha256
            with service._locked(credential=credential, subject=subject, permit=permit, action='inspect_original') as (db, _):
                ref = counter_frame_owner_ref_v3(service.namespace, counted)
                birth = service._owner_operation_v3(db, ref, 'owner_counter_birth')
                disposition = service._owner_operation_v3(db, ref, 'owner_unused_counter_disposition')
                if birth is None or birth.parent_original_id != parent:
                    raise AuthorityUnavailable('D13 unused Counter query has no same-parent actual birth')
                result = None if disposition is None else service._owner_operation_v3(db, ref, 'owner_close')
        return {'closure': None if result is None else cache_use_to_wire_v2(result)}
    if action in ('natural_close_parent', 'natural_parent_inspect'):
        if set(command) != {'namespace', 'permit', 'parent_original_id'}:
            raise AuthorityUnavailable('D13 exact natural parent metadata scope required')
        from .d13_original_owner_v3 import (close_authenticated_d13_natural_roster_v3,
            natural_stage_owner_ref_v3, D13NaturalRosterNotTerminalV3, _actual_peer_admission_v3)
        from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
        parent = command['parent_original_id']
        if type(parent) is not str or not 1 <= len(parent) <= 192:
            raise AuthorityUnavailable('D13 exact finite natural parent identity required')
        permit = from_wire(command['permit'])
        subject = 'mtls:sha256:' + credential.certificate_sha256
        if action == 'natural_close_parent':
            try:
                result = close_authenticated_d13_natural_roster_v3(server, service,
                    credential=credential, profile_id=profile_id, manifest_digest=manifest_digest,
                    permit=permit, parent_original_id=parent)
            except D13NaturalRosterNotTerminalV3:
                return {'closure': None}
        else:
            _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
            with service._locked(credential=credential, subject=subject, permit=permit, action='inspect_original') as (db, _):
                from .d13_original_owner_v3 import actual_natural_parent_closure_in_tx_v3
                result = actual_natural_parent_closure_in_tx_v3(service, db, parent)
        return {'closure': None if result is None else cache_use_to_wire_v2(result)}
    if action in ('natural_acquire', 'natural_inspect'):
        if set(command) != {'namespace', 'permit', 'natural_material'}:
            raise AuthorityUnavailable('D13 exact natural-original receiver RPC fields differ')
        from .d13_original_owner_v3 import (prepare_authenticated_d13_natural_receiver_in_tx_v3,
            natural_receiver_owner_ref_v3, _actual_peer_admission_v3)
        permit = from_wire(command['permit'])
        subject = 'mtls:sha256:' + credential.certificate_sha256
        fields = {'parent_original_id', 'generation_job_id', 'generation_original_id',
            'review_job_id', 'review_original_id', 'generation_call_id', 'generation_frozen_input_digest',
            'retention_instance_ref', 'selection_digest'}
        material = command['natural_material']
        if type(material) is not dict or set(material) != fields or permit.operation not in ('read', 'write'):
            raise AuthorityUnavailable('D13 natural original requires its exact actual READ receiver scope')
        with service._locked(credential=credential, subject=subject, permit=permit,
                action='register_original' if action == 'natural_acquire' else 'inspect_original') as (db, _):
            if action == 'natural_acquire':
                proof = prepare_authenticated_d13_natural_receiver_in_tx_v3(server, service, db,
                    credential=credential, profile_id=profile_id, manifest_digest=manifest_digest,
                    permit=permit, natural_material=material)
                result = service.register_original_owner_in_tx_v3(db, proof)
            else:
                admission = _actual_peer_admission_v3(server, service, credential, profile_id, manifest_digest, permit)
                owner_ref = natural_receiver_owner_ref_v3(service.namespace, permit,
                    material['retention_instance_ref'], material['selection_digest'])
                result = service._owner_operation_v3(db, owner_ref, 'owner_register')
                if result is not None and (result.subject != subject or result.permit_digest != canonical_digest(permit)
                        or result.peer_admission_digest != admission['admission_digest']):
                    raise AuthorityUnavailable('D13 natural receiver inspection crossed its actual original peer/permit')
        return {'owner': None if result is None else cache_use_to_wire_v2(result)}
    if action in ('owner_register', 'owner_inspect', 'owner_close'):
        from .d13_original_owner_v3 import (prepare_authenticated_d13_source_receiver_v3,
            prepare_authenticated_d13_retention_release_v3)
        from .d13_cache_use_contract_v2 import retention_release_from_wire_v3
        expected = {'namespace', 'permit', {'owner_register': 'owner_material',
            'owner_inspect': 'owner_ref', 'owner_close': 'release_original'}[action]}
        if set(command) != expected:
            raise AuthorityUnavailable('D13 exact original receiver RPC fields differ')
        permit = from_wire(command['permit'])
        subject = 'mtls:sha256:' + credential.certificate_sha256
        if action == 'owner_register':
            proof = prepare_authenticated_d13_source_receiver_v3(server, service, credential=credential,
                profile_id=profile_id, manifest_digest=manifest_digest, permit=permit,
                owner_material=command['owner_material'])
            with service._locked(credential=credential, subject=subject, permit=permit, action='register_original') as (db, _):
                result = service.register_original_owner_in_tx_v3(db, proof)
            return {'owner': cache_use_to_wire_v2(result)}
        if action == 'owner_inspect':
            with service._locked(credential=credential, subject=subject, permit=permit, action='inspect_original') as (db, _):
                result = service._owner_operation_v3(db, command['owner_ref'], 'owner_register')
                if result is not None and (result.subject != subject or result.permit_digest != canonical_digest(permit)):
                    raise AuthorityUnavailable('D13 original owner query crossed its actual authenticated Source permit')
            return {'owner': None if result is None else cache_use_to_wire_v2(result)}
        release = retention_release_from_wire_v3(command['release_original'])
        proof = prepare_authenticated_d13_retention_release_v3(server, service, credential=credential,
            profile_id=profile_id, manifest_digest=manifest_digest, permit=permit, release_original=release)
        with service._locked(credential=credential, subject=subject, permit=permit, action='close_original') as (db, _):
            result = service.close_original_owner_in_tx_v3(db, proof)
        return {'closure': cache_use_to_wire_v2(result)}
    fields = {'namespace','permit','policy_digest','expected_coverage','selected_payloads'} if action == 'observe' else (
        {'namespace','permit','observation'} if action == 'reclaim' else {'namespace','permit','operation_id','binding','identity'})
    if action in ('release','transfer','inspect'):
        fields.add('pin_id')
    if action == 'transfer':
        fields.add('successor_binding')
    if set(command) != fields:
        raise AuthorityUnavailable('D13 exact control RPC fields differ')
    permit = from_wire(command['permit'])
    subject = 'mtls:sha256:'+credential.certificate_sha256
    if action == 'observe':
        value = service.observe_for_fence_v2(credential=credential,subject=subject,permit=permit,
            policy_digest=command['policy_digest'],expected_coverage=command['expected_coverage'],selected_payloads=command['selected_payloads'])
        return {'observation':cache_use_to_wire_v2(value)}
    if action == 'reclaim':
        observation = cache_use_from_wire_v2(command['observation'],D13CacheUseObservationV2)
        return {'seal':service.seal_reclaim_for_fence_v2(credential=credential,subject=subject,permit=permit,observation=observation)}
    value = service.mutate_for_fence_v2(credential=credential,subject=subject,permit=permit,action=action,
        operation_id=command['operation_id'],binding=command['binding'],identity=tuple(command['identity']),
        pin_id=command.get('pin_id'),successor_binding=command.get('successor_binding'))
    return {'pin':cache_use_to_wire_v2(value)}

class _InstalledD13CacheUseControlLocalPortV2(InstalledD13CacheUseControlPortV2):
    """Same control ABI for an Authority reader's real authenticated request."""
    def __init__(self,*,service,credential,subject):
        if type(service) is not InstalledD13CacheUseControlServiceV2 or type(subject) is not str or not subject:
            raise AuthorityUnavailable('D13 local controller requires its actual installed Core request service')
        self.service,self.credential,self.subject = service,credential,subject
        self.bundle,self.use_policy,self.maintenance_policy = service.bundle,service.use_policy,service.maintenance_policy
        _PORTS[self] = (service,credential,subject,self.bundle,self.use_policy,self.maintenance_policy)

    def _actual(self):
        if _PORTS.get(self) != (self.service,self.credential,self.subject,self.bundle,self.use_policy,self.maintenance_policy):
            raise AuthorityUnavailable('D13 local controller lost its original authenticated service request')
        return self

    def _rpc(self,action,*,namespace,authority_namespace,permit,**values):
        self._actual()
        if (namespace != self.use_policy.namespace or authority_namespace != self.use_policy.authority_namespace
                or type(permit) is not FencePermitV2 or permit.subject != self.subject):
            raise AuthorityUnavailable('D13 local use call crossed its actual original subject/namespace')
        if action == 'observe':
            return self.service.observe_for_fence_v2(credential=self.credential,subject=self.subject,permit=permit,**values)
        if action == 'reclaim':
            observation = cache_use_from_wire_v2(values['observation'],D13CacheUseObservationV2)
            return self.service.seal_reclaim_for_fence_v2(credential=self.credential,subject=self.subject,
                permit=permit,observation=observation)
        return self.service.mutate_for_fence_v2(credential=self.credential,subject=self.subject,permit=permit,action=action,**values)


def installed_d13_cache_use_local_port_v2(*,service,credential,subject):
    return _InstalledD13CacheUseControlLocalPortV2(service=service,credential=credential,subject=subject)


def validate_d13_cache_use_core_schema_v2(kind,name,sql):
    expected = {(k,n):ddl for k,n,ddl in cache_use_schema_objects_v2()}
    if expected.get((kind,name)) != sql:
        raise AuthorityUnavailable('D13 C09 registered durable control object differs')


def validate_d13_cache_use_core_row_v2(table,columns,row):
    """Closed content-free rows are preserved verbatim, including unknown pins."""
    expected = {
        'authority_d13_cache_use_policies_v2':('namespace','use_policy_ref',*_POLICY_COLUMNS),
        'authority_d13_cache_use_heads_v2':('namespace','revision'),
        'authority_d13_cache_use_pins_v2':('namespace',*_PIN_COLUMNS),
        'authority_d13_cache_use_operations_v2':('namespace','operation_id','action','request_digest','result_json'),
        'authority_d13_cache_reclaim_seals_v2':('namespace','permit_token','payload_key','observation_digest','control_revision'),
        'authority_d13_cache_use_totals_v2':('namespace','payload_key','active_count','unknown_count'),
    }
    if table not in expected or tuple(columns) != expected[table] or len(row) != len(columns):
        raise AuthorityUnavailable('D13 C09 durable control row shape differs')
    data = dict(zip(columns,row))
    if type(data['namespace']) is not str or not data['namespace']:
        raise AuthorityUnavailable('D13 C09 original authority namespace missing')
    if table == 'authority_d13_cache_use_policies_v2':
        from .d13_cache_use_contract_v2 import use_policy_from_payload_v2
        raw = json.loads(data['use_policy_json'])
        use = use_policy_from_payload_v2(raw)
        maintenance = json.loads(data['maintenance_policy_json'])
        if (canonical_serialize(raw) != data['use_policy_json'] or use.digest != data['use_policy_digest']
                or canonical_serialize(maintenance) != data['maintenance_policy_json']
                or canonical_digest(maintenance) != data['maintenance_policy_digest']
                or use.policy_ref != data['use_policy_ref'] or use.authority_namespace != data['namespace']
                or use.installation_id != data['installation_id']
                or data['coverage_state'] not in ('complete','legacy_unknown')):
            raise AuthorityUnavailable('D13 C09 signed policy original metadata differs')
    elif table == 'authority_d13_cache_use_pins_v2':
        payload_identity_v2((data['block_ref'],data['payload_digest'],data['initial_origin_scope_digest'],data['observed_revision']))
        if (data['state'] not in ('active','released','unknown') or type(data['acquire_permit_token']) is not str
                or len(data['acquire_permit_digest']) != 64
                or (data['state']=='released') != (data['release_operation_id'] is not None)):
            raise AuthorityUnavailable('D13 C09 original consumer pin state/ownership differs')
    elif table == 'authority_d13_cache_use_operations_v2':
        value = cache_use_result_from_wire_v3(json.loads(data['result_json']))
        actions = {D13CachePinReceiptV2: ('acquire','release','transfer'),
            D13OwnerRegistrationReceiptV3: ('owner_register',), D13OwnerCloseReceiptV3: ('owner_close',),
            D13OwnerRetentionReleaseReceiptV3: ('owner_retention_release',),
            D13NaturalReviewVerdictReceiptV3: ('owner_review_verdict',),
            D13NaturalParentDispositionReceiptV3: ('owner_parent_disposition',),
            D13NaturalParentInputReceiptV3: ('owner_parent_input',),
            D13RetiredReceiverOriginalV3: ('owner_peer_retirement',),
            D13ControlledSDKConsumerReadyReceiptV3: ('controlled_sdk_consumer_ready',),
            D13CounterFrameBirthReceiptV3: ('owner_counter_birth',),
            D13NaturalGenerationParseReceiptV3: ('owner_generation_parse',),
            D13NaturalPreReviewDispositionReceiptV3: ('owner_pre_review_disposition',),
            D13UnusedCounterDispositionReceiptV3: ('owner_unused_counter_disposition',),
            D13AuthorityCoreBirthReceiptV4: ('owner_core_birth',),
            D13RetiredCoreReceiverOriginalV4: ('owner_core_retirement',)}
        if (canonical_serialize(cache_use_to_wire_v2(value)) != data['result_json']
                or value.authority_namespace != data['namespace'] or value.operation_id != data['operation_id']
                or value.request_digest != data['request_digest'] or data['action'] not in actions.get(type(value), ())):
            raise AuthorityUnavailable('D13 C09 original control transition differs')
    elif table == 'authority_d13_cache_use_totals_v2':
        if any(type(data[name]) is not int or data[name]<0 for name in ('active_count','unknown_count')):
            raise AuthorityUnavailable('D13 C09 actual use totals are invalid')
    else:
        value = data['revision'] if table == 'authority_d13_cache_use_heads_v2' else data['control_revision']
        if type(value) is not int or value < 0:
            raise AuthorityUnavailable('D13 C09 actual control revision invalid')
    return tuple(row)


_FRESH_INSTALL_ISSUER_V3 = object()
_FRESH_INSTALLATIONS_V3 = WeakKeyDictionary()
_FRESH_CONSTRUCTOR_READ_V3 = ContextVar('d13_fresh_constructor_policy_read_v3', default=None)


class _FreshD13PolicyInstallationV3:
    def __init__(self, issuer, *, core, credential, bundle, budget_issuer, coverage):
        if issuer is not _FRESH_INSTALL_ISSUER_V3:
            raise AuthorityUnavailable('actual fresh D13 policy installation issuer required')
        import threading
        self.core, self.db, self.credential = core, core._db, credential
        self.bundle, self.budget_issuer, self.coverage = bundle, budget_issuer, coverage
        self.manifest, self.gate = coverage.manifest, coverage.gate
        self.hold = self.gate._pending_start_bootstrap_hold_v3
        self.thread, self.nonce, self.authorizer = threading.get_ident(), object(), core._authorize_callback
        self.phase, self.finished, self.failed = 'installing', False, False
        self.constructing, self.borrowing, self.read_consumed = False, False, False
        self.service, self.finalized = None, None
        _FRESH_INSTALLATIONS_V3[self] = (self.core, self.db, self.bundle, self.budget_issuer,
            self.coverage, self.manifest, self.gate, self.hold, self.thread, self.nonce, self.authorizer)

    def require_v3(self):
        import threading
        if (_FRESH_INSTALLATIONS_V3.get(self) != (self.core, self.db, self.bundle, self.budget_issuer,
                self.coverage, self.manifest, self.gate, self.hold, self.thread, self.nonce, self.authorizer)
                or self.finished or self.failed or self.thread != threading.get_ident()
                or self.core._db is not self.db or not self.db.in_transaction
                or not self.core._lock._is_owned() or self.core._authorize_callback is not self.authorizer
                or self.gate._pending_start_bootstrap_hold_v3 is not self.hold
                or self.gate._operation is not None or self.gate._active):
            raise AuthorityUnavailable('D13 fresh installation lost its exact Core/transaction/thread/continuous Gate')
        with self.coverage.control._resource_sql_quantum_v3() as meter:
            if self.gate.require_pending_start_bootstrap_scope_v3(meter=meter) is not self.hold:
                raise AuthorityUnavailable('D13 fresh installation lost its actual Root bootstrap hold')
        return self

    def create_service_v3(self, *, fences, clock):
        self.require_v3()
        if self.phase != 'installing' or self.constructing or self.service is not None or fences.core is not self.core:
            raise AuthorityUnavailable('D13 fresh service constructor is a single exact actual installation step')
        self.constructing = True
        try:
            service = InstalledD13CacheUseControlServiceV2(fences=fences, bundle=self.bundle,
                budget_issuer=self.budget_issuer, clock=clock, _policy_installation_v3=self)
            if self.service is not service or not self.read_consumed:
                raise AuthorityUnavailable('D13 fresh service did not consume its exact constructor policy read')
            return service
        except BaseException:
            self.failed = True
            raise
        finally:
            self.constructing = False

    def finalize_actual_consumers_v3(self, *, server, daemon):
        self.require_v3()
        if self.phase != 'installing' or self.service is None or self.constructing or self.finalized is not None:
            raise AuthorityUnavailable('D13 final consumers require the actual completed fresh service constructor')
        self.finalized = self.manifest.finalize_actual_consumers_v3(server=server, daemon=daemon)
        self.require_finalized_v3()
        return self.finalized

    def require_finalized_v3(self):
        from ..runtime.d13_consumer_manifest_v3 import require_finalized_d13_consumer_installation_v3
        self.require_v3()
        if self.service is None or self.finalized is None or self.constructing or self.borrowing:
            raise AuthorityUnavailable('D13 fresh policy cannot commit before actual consumer installation')
        require_finalized_d13_consumer_installation_v3(self.finalized, manifest=self.manifest,
            core=self.core, bundle=self.bundle, db=self.db)


@contextmanager
def _fresh_d13_constructor_policy_read_v3(service, installation):
    if type(installation) is not _FreshD13PolicyInstallationV3:
        raise AuthorityUnavailable('D13 constructor requires its exact private fresh installer')
    installation.require_v3()
    if (installation.phase != 'installing' or not installation.constructing
            or installation.service is not None or installation.read_consumed
            or type(service) is not InstalledD13CacheUseControlServiceV2
            or service.core is not installation.core or service.bundle is not installation.bundle
            or service.issuer is not installation.budget_issuer
            or _FRESH_CONSTRUCTOR_READ_V3.get() is not None):
        raise AuthorityUnavailable('D13 constructor cannot borrow an unrelated or recursive Core transaction')
    installation.service, installation.phase = service, 'constructor_policy_read'
    token = _FRESH_CONSTRUCTOR_READ_V3.set(installation)
    try:
        yield
        if not installation.read_consumed or installation.borrowing:
            raise AuthorityUnavailable('D13 constructor did not finish its exact read-only policy validation')
    except BaseException:
        installation.failed = True
        raise
    finally:
        _FRESH_CONSTRUCTOR_READ_V3.reset(token)
        installation.phase = 'installing'


def _borrow_fresh_d13_constructor_transaction_v3(core):
    installation = _FRESH_CONSTRUCTOR_READ_V3.get()
    if installation is None:
        return None
    installation.require_v3()
    if (installation.core is not core or installation.phase != 'constructor_policy_read'
            or not installation.constructing or installation.borrowing or installation.read_consumed
            or type(installation.service) is not InstalledD13CacheUseControlServiceV2):
        raise AuthorityUnavailable('D13 exact constructor transaction borrow is unavailable or already consumed')
    installation.borrowing = True
    return installation


def _finish_fresh_d13_constructor_transaction_v3(installation, *, failed):
    if _FRESH_CONSTRUCTOR_READ_V3.get() is not installation or not installation.borrowing:
        raise AuthorityUnavailable('D13 constructor transaction borrow lost its exact private context')
    installation.borrowing = False
    installation.read_consumed = True
    if failed:
        installation.failed = True


@contextmanager
def fresh_d13_policy_installation_v3(*, core, credential, bundle, budget_issuer, coverage_installation):
    """Final signed pair and actual consumer installation commit as one fresh Core transaction."""
    from .core import AuthorityServiceCore
    from ..runtime.d13_cache_use_admission_v2 import _D13CacheUseCoverageInstallationV2
    if type(core) is not AuthorityServiceCore or type(coverage_installation) is not _D13CacheUseCoverageInstallationV2:
        raise AuthorityUnavailable('fresh D13 installation requires actual Core and private complete coverage producer')
    # The empty metadata EOF and Root coverage check finish before BEGIN. They
    # cannot borrow the constructor-only read domain or open nested transactions.
    use, values = _prepare_d13_policy_pair_v3(core=core, credential=credential, bundle=bundle,
        budget_issuer=budget_issuer, coverage_installation=coverage_installation)
    if (coverage_installation.policy is not use or coverage_installation.manifest.core is not core
            or coverage_installation.manifest.installation is not bundle.installation_policy):
        raise AuthorityUnavailable('D13 fresh coverage crossed its exact actual Core/installation')
    with core._lock:
        if core._db is None or core._db.in_transaction:
            raise AuthorityUnavailable('D13 fresh installation requires its own outer Core transaction')
        core._db.execute('BEGIN IMMEDIATE')
        installation = _FreshD13PolicyInstallationV3(_FRESH_INSTALL_ISSUER_V3,
            core=core, credential=credential, bundle=bundle, budget_issuer=budget_issuer, coverage=coverage_installation)
        try:
            installation.require_v3()
            _install_d13_policy_pair_in_tx_v3(installation.db, use, values)
            yield installation
            installation.require_finalized_v3()
            installation.db.execute('COMMIT')
        except BaseException:
            installation.failed = True
            if installation.db.in_transaction:
                installation.db.execute('ROLLBACK')
            raise
        finally:
            if installation.failed and installation.service is not None:
                from .d13_original_owner_v3 import revoke_uncommitted_d13_core_birth_v4
                revoke_uncommitted_d13_core_birth_v4(installation.service)
            installation.finished = True
            _FRESH_INSTALLATIONS_V3.pop(installation, None)


def retain_controlled_sdk_d13_consumer_ready_v3(service, *, credential, proof):
    """Retain one actual same-process SDK consumer EOF; it grants no Body permit."""
    from ..runtime.d13_consumer_manifest_v3 import (
        require_actual_controlled_sdk_consumer_ready_material_v3,
        require_actual_controlled_sdk_consumer_ready_control_v3)
    from .c09_storage_control_v1 import C09StorageControlV1
    from .c09_writer_peer_originals_v3 import _bounded, require_writer_peer_schema_v3
    if type(service) is not InstalledD13CacheUseControlServiceV2:
        raise AuthorityUnavailable('actual installed D13 Core use-control service required for SDK readiness')
    service.core._require(credential, 'd13_cache_use_install', service.authority_namespace)
    with service.core._tx() as db:
        with runtime_storage_operation_v3(db, operation_id='d13-controlled-sdk-consumer-ready') as operation:
            provider = _OwnerMetadataV3(operation)
            try:
                with _bind_owner_metadata_v3(operation, provider), runtime_storage_quantum_v3(db) as meter:
                    service._policy(db)
                    control = require_actual_controlled_sdk_consumer_ready_control_v3(proof, service=service, db=db)
                    material = require_actual_controlled_sdk_consumer_ready_material_v3(proof, service=service, db=db)
                    required = {field.name for field in fields(D13ControlledSDKConsumerReadyReceiptV3)} - {
                        'operation_id', 'request_digest', 'control_revision', 'key_id', 'ready_digest', 'signature', 'schema'}
                    if (type(control) is not C09StorageControlV1 or type(material) is not dict or set(material) != required
                            or material['namespace'] != service.namespace
                            or material['authority_namespace'] != service.authority_namespace
                            or material['installation_id'] != service.installation_id
                            or material['authority_id'] != control.authority_id
                            or material['control_store_id'] != control.control_store_id
                            or material['use_policy_ref'] != service.use_policy.policy_ref
                            or material['use_policy_digest'] != service.use_policy.digest
                            or material['consumer_cohort_digest'] != service.use_policy.consumer_cohort_digest):
                        raise AuthorityUnavailable('D13 SDK ready producer differs from its actual installed policy/Core/Control')
                    with control._resource_sql_quantum_v3() as control_meter:
                        with control._db() as control_db:
                            require_writer_peer_schema_v3(control, control_db)
                            stored = _bounded(control_db, control_meter).execute('SELECT admission_json '
                                'FROM c09_writer_peer_admissions_v3 WHERE admission_digest=?',
                                (material['peer_admission_digest'],)).fetchone()
                        if stored is None:
                            raise AuthorityUnavailable('D13 SDK ready producer has no actual signed peer admission')
                        admission = json.loads(stored[0])
                        control.verify_original_v1(admission, 'admission_digest')
                        if (admission['schema'] != 'sylanne3.c09.writer-peer-admission.v3'
                                or admission['admission_digest'] != material['peer_admission_digest']
                                or admission['peer'] != [material['peer_certificate_sha256'], material['profile_id']]
                                or admission['namespace'] != service.authority_namespace
                                or admission['installation_id'] != service.installation_id
                                or admission['authority_id'] != control.authority_id
                                or admission['process_incarnation'] != material['process_incarnation']
                                or canonical_digest(admission['process_original']) != material['process_original_digest']
                                or (admission['manifest_digest'], admission['pointer_version'], admission['storage_generation']) !=
                                   (material['selected_manifest_digest'], material['pointer_version'], material['storage_generation'])):
                            raise AuthorityUnavailable('D13 SDK ready process/peer/selection differs from its actual Control admission')
                    operation_id = controlled_sdk_consumer_ready_operation_id_v3(service.namespace,
                        material['peer_admission_digest'], material['consumer_cohort_digest'])
                    request_digest = canonical_digest((PROTOCOL, 'controlled_sdk_consumer_ready', material))
                    row = provider.fixed(db, meter, 'authority_d13_cache_use_operations_v2',
                        ('action', 'request_digest', 'result_json'), 'namespace=? AND operation_id=?',
                        (service.authority_namespace, operation_id), 'controlled_sdk_consumer_ready')
                    if row is not None:
                        prior = provider.decode(row, 'controlled_sdk_consumer_ready', meter)
                        if (type(prior) is not D13ControlledSDKConsumerReadyReceiptV3
                                or row[:2] != ('controlled_sdk_consumer_ready', request_digest)
                                or prior.request_digest != request_digest or prior.operation_id != operation_id
                                or prior.namespace != service.namespace or prior.authority_namespace != service.authority_namespace
                                or prior.installation_id != service.installation_id):
                            raise AuthorityUnavailable('D13 SDK ready same-admission replay changed its actual consumer/resource original')
                        control.verify_original_v1(asdict(prior), 'ready_digest')
                        return prior
                    values = dict(material, operation_id=operation_id, request_digest=request_digest,
                        control_revision=service._revision(db), schema=CONTROLLED_SDK_READY_SCHEMA_V3)
                    # Control owns the installed key. Namespace is serialized by
                    # the same exact typed codec used by C09 and the saved receipt.
                    wire = dict(values, namespace=asdict(service.namespace))
                    signed = control.sign_original_v1(CONTROLLED_SDK_READY_SCHEMA_V3, wire, 'ready_digest')
                    result = cache_use_from_wire_v2(signed, D13ControlledSDKConsumerReadyReceiptV3)
                    control.verify_original_v1(asdict(result), 'ready_digest')
                    if require_actual_controlled_sdk_consumer_ready_material_v3(proof, service=service, db=db) != material:
                        raise AuthorityUnavailable('D13 actual SDK consumer/resource scope changed before its durable ready point')
                    return service._record(db, 'controlled_sdk_consumer_ready', result)
            finally:
                operation.unregister_retained_state_v3(provider)
