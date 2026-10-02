"""Independent Contact-complete C09 frame; every V4 wire remains unchanged.

An inventory DTO is not an issuer. The actual private freeze enumerates it,
including the empty case, and the signed PREPARED frame binds the whole value.
Observation positions are real freeze positions, never invented finish events.
"""
from dataclasses import dataclass, fields, asdict
import json
import sqlite3
from weakref import WeakValueDictionary

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable
from .c09_recovery_frame_v4 import C09RecoveryFactFrameV4, C09ExecutionSourcePinV4, C09ExecutionSourceSealV4, make_source_pin_v4
from .c09_contact_finish_original_v1 import C09ContactFinishOriginalV1, _hash

SCHEMA = 'sylanne3.c09.recovery_fact_frame.v5'
PIN_SCHEMA = 'sylanne3.c09.execution_source_pin.v5'
INVENTORY_SCHEMA = 'sylanne3.c09.contact_finish_inventory.v5'
MAX_CONTACT_FINISHES = 1024
_ISSUED_INVENTORIES = WeakValueDictionary()


def _commitment(value, field):
    if not _hash(value): raise AuthorityUnavailable('C09 V5 exact ' + field + ' commitment differs')


@dataclass(frozen=True, slots=True)
class ContactFinishCarryV5:
    previous_frame_operation_id: str
    previous_frame_digest: str
    previous_inventory_digest: str
    previous_pin_digest: str
    prepared_digest: str
    consumed_fence_commitment: str
    schema: str = 'sylanne3.c09.contact_finish_carry.v5'

    def __post_init__(self):
        if self.schema != 'sylanne3.c09.contact_finish_carry.v5' or not self.previous_frame_operation_id:
            raise AuthorityUnavailable('C09 V5 carry identity differs')
        for name in ('previous_frame_digest', 'previous_inventory_digest', 'previous_pin_digest',
                     'prepared_digest', 'consumed_fence_commitment'):
            _commitment(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class ContactFinishInventoryMemberV5:
    original: C09ContactFinishOriginalV1
    carry: ContactFinishCarryV5 | None

    def __post_init__(self):
        if (type(self.original) is not C09ContactFinishOriginalV1
                or self.carry is not None and type(self.carry) is not ContactFinishCarryV5):
            raise AuthorityUnavailable('C09 V5 finish inventory member is not a closed original')

    @property
    def locator(self):
        o = self.original
        return o.namespace, o.operation_id, o.business_operation_id, o.original_digest


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContactFinishInventoryV5:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    source_seal_digest: str
    observed_core_anchor: RestoreAnchor
    verifier_commitment: str
    business_namespace_digest: str
    members: tuple[ContactFinishInventoryMemberV5, ...]
    inventory_digest: str
    schema: str = INVENTORY_SCHEMA

    def __post_init__(self):
        if (self.schema != INVENTORY_SCHEMA or type(self.observed_core_anchor) is not RestoreAnchor
                or (self.observed_core_anchor.authority_id, self.observed_core_anchor.namespace) != (self.authority_id, self.namespace)
                or not self.installation_id or not self.operation_id
                or type(self.members) is not tuple or len(self.members) > MAX_CONTACT_FINISHES
                or any(type(m) is not ContactFinishInventoryMemberV5 for m in self.members)
                or tuple(m.locator for m in self.members) != tuple(sorted({m.locator for m in self.members}))
                or len({m.original.business_operation_id for m in self.members}) != len(self.members)):
            raise AuthorityUnavailable('C09 V5 complete bounded unique finish inventory differs')
        for name in ('source_seal_digest', 'verifier_commitment', 'business_namespace_digest', 'inventory_digest'):
            _commitment(getattr(self, name), name)
        for member in self.members:
            original = member.original
            if ((original.authority_id, original.installation_id, original.namespace, original.business_namespace_digest) !=
                    (self.authority_id, self.installation_id, self.namespace, self.business_namespace_digest)
                    or original.generation > self.observed_core_anchor.activation_generation):
                raise AuthorityUnavailable('C09 V5 finish member scope/generation differs')
            if member.carry is None:
                if ((original.operation_id, original.source_seal_digest, original.verifier_commitment, original.observed_core_anchor) !=
                        (self.operation_id, self.source_seal_digest, self.verifier_commitment, self.observed_core_anchor)):
                    raise AuthorityUnavailable('C09 V5 new finish is not observed by this actual freeze')
            elif original.operation_id == self.operation_id:
                raise AuthorityUnavailable('C09 V5 current finish cannot masquerade as a historical carry')
        if self.inventory_digest != canonical_digest(tuple(getattr(self,f.name) for f in fields(self) if f.name != 'inventory_digest')):
            raise AuthorityUnavailable('C09 V5 complete finish inventory digest differs')


@dataclass(frozen=True, slots=True)
class C09RecoveryFactFrameV5:
    ordinary_facts: C09RecoveryFactFrameV4
    contact_finish_inventory: ContactFinishInventoryV5
    facts_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        f, inventory = self.ordinary_facts, self.contact_finish_inventory
        if (self.schema != SCHEMA or type(f) is not C09RecoveryFactFrameV4
                or type(inventory) is not ContactFinishInventoryV5
                or (f.authority_id, f.installation_id, f.namespace, f.operation_id, f.verifier_commitment) !=
                    (inventory.authority_id, inventory.installation_id, inventory.namespace, inventory.operation_id, inventory.verifier_commitment)
                or (f.old_journal_id, f.old_seq, f.old_chain_head_digest) !=
                    (inventory.observed_core_anchor.execution_journal_id, inventory.observed_core_anchor.execution_seq,
                     inventory.observed_core_anchor.execution_digest)
                or any(item.operation_id.startswith('c09-contact-finish-inventory:') for item in f.graph_facts)):
            raise AuthorityUnavailable('C09 V5 exact frozen frame/inventory scope differs')
        if self.facts_digest != canonical_digest((f, inventory, SCHEMA)):
            raise AuthorityUnavailable('C09 V5 full facts/inventory commitment differs')

    def __getattr__(self, name):
        if name in C09RecoveryFactFrameV4.__dataclass_fields__ and name not in {'schema', 'facts_digest'}:
            return getattr(self.ordinary_facts, name)
        raise AttributeError(name)


@dataclass(frozen=True, slots=True)
class C09ExecutionSourcePinV5:
    source_pin: C09ExecutionSourcePinV4
    contact_finish_inventory_digest: str
    observed_core_anchor: RestoreAnchor
    pin_digest: str
    schema: str = PIN_SCHEMA

    def __post_init__(self):
        p = self.source_pin
        if (self.schema != PIN_SCHEMA or type(p) is not C09ExecutionSourcePinV4
                or type(self.observed_core_anchor) is not RestoreAnchor
                or (p.authority_id, p.namespace, p.old_journal_id, p.old_seq, p.old_digest) !=
                    (self.observed_core_anchor.authority_id, self.observed_core_anchor.namespace,
                     self.observed_core_anchor.execution_journal_id, self.observed_core_anchor.execution_seq,
                     self.observed_core_anchor.execution_digest)):
            raise AuthorityUnavailable('C09 V5 source pin observation differs')
        _commitment(self.contact_finish_inventory_digest, 'inventory')
        if self.pin_digest != canonical_digest((p, self.contact_finish_inventory_digest, self.observed_core_anchor, PIN_SCHEMA)):
            raise AuthorityUnavailable('C09 V5 source pin complete commitment differs')

    def __getattr__(self, name):
        if name in C09ExecutionSourcePinV4.__dataclass_fields__ and name not in {'schema', 'pin_digest'}:
            return getattr(self.source_pin, name)
        raise AttributeError(name)


def decode_c09_frame_v5(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, C09RecoveryFactFrameV5)


def decode_c09_pin_v5(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, C09ExecutionSourcePinV5)


def _make_issued_frame_v5(port, *, ordinary_facts, inventory, seal):
    from .c09_contact_finish_original_v1 import _PORTS
    if _PORTS.get(id(port)) is not port:
        raise AuthorityUnavailable('C09 V5 caller inventory is not an installed private freeze')
    issued = _ISSUED_INVENTORIES.get(id(inventory))
    snapshot = port._current(seal.namespace, seal.operation_id)
    if (issued is not inventory or getattr(port, '_contact_finish_inventory_v5', None) is not inventory
            or snapshot[0] is not seal or not snapshot[4].in_transaction or not snapshot[5].in_transaction):
        raise AuthorityUnavailable('C09 V5 caller inventory is not this actual active private freeze')
    facts = C09RecoveryFactFrameV5(ordinary_facts, inventory,
        canonical_digest((ordinary_facts, inventory, SCHEMA)))
    base = make_source_pin_v4(seal=seal, facts=facts)
    pin = C09ExecutionSourcePinV5(base, inventory.inventory_digest, inventory.observed_core_anchor,
        canonical_digest((base, inventory.inventory_digest, inventory.observed_core_anchor, PIN_SCHEMA)))
    return facts, pin


def _issue_contact_finish_inventory_v5(port, *, namespace, operation_id):
    """Bounded full enumeration under the actual installed Core/business freeze."""
    from .c09_contact_finish_original_v1 import _PORTS, TABLE, COLUMNS, require_contact_finish_archive_schema_v1, validate_contact_finish_row_v1
    from .c09_connection_state_v1 import anchor_in_tx_v1
    if _PORTS.get(id(port)) is not port:
        raise AuthorityUnavailable('C09 V5 inventory requires the registered actual installation port')
    seal, _old, _rows, verifier, business, core_db = port._current(namespace, operation_id)
    if not business.in_transaction or not core_db.in_transaction:
        raise AuthorityUnavailable('C09 V5 inventory snapshots are not pinned')
    anchor = anchor_in_tx_v1(core_db, namespace)
    if (anchor.authority_id, anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest) != (
            seal.authority_id, seal.execution_journal_id, seal.execution_seq, seal.execution_digest):
        raise AuthorityUnavailable('C09 V5 actual Core observation differs from verified freeze seal')
    originals = ()
    if core_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone():
        require_contact_finish_archive_schema_v1(core_db)
        rows = core_db.execute(f'SELECT * FROM {TABLE} WHERE namespace=? ORDER BY operation_id,business_operation_id LIMIT ?',
            (namespace, MAX_CONTACT_FINISHES + 1)).fetchall()
        if len(rows) > MAX_CONTACT_FINISHES:
            raise AuthorityUnavailable('C09 V5 complete finish inventory exceeds bound; HOLD')
        originals = tuple(validate_contact_finish_row_v1(COLUMNS, row) for row in rows)
    # Full current business enumeration is independently compared, including
    # true zero rows; archive absence alone is never an absence proof.
    from ..runtime.domain_production_originals_v1 import TABLE as BUSINESS
    operations = ()
    if business.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (BUSINESS,)).fetchone():
        rows = business.execute(f'SELECT operation_id FROM {BUSINESS} WHERE bot=? AND persona=? '
            "AND domain='d08' AND operation_kind IN ('prepare_contact_dispatch','prepare_contact_dispatch_v3') ORDER BY operation_id LIMIT ?",
            (*port.namespace_id.as_tuple, MAX_CONTACT_FINISHES + 1)).fetchall()
        if len(rows) > MAX_CONTACT_FINISHES: raise AuthorityUnavailable('C09 V5 current Contact inventory exceeds bound; HOLD')
        operations = tuple(row[0] for row in rows)
    active = tuple(getattr(getattr(port, '_contact_finish_scope', None), 'originals', ()))
    if {o.business_operation_id for o in active} != set(operations):
        raise AuthorityUnavailable('C09 V5 current Contact originals are missing from actual authenticated enumeration')
    # Batch facts are a second independent inventory: an orphan/legacy batch
    # cannot silently become an authenticated empty Contact inventory.
    from ..domains.d09.contact_batch_v1 import CONTACT_BATCH_SCHEMA_V1
    from ..domains.d09.contact_batch_v2 import KINDS as CONTACT_V2_KINDS
    from ..domains.d09.contact_batch_v3 import KINDS as CONTACT_V3_KINDS
    contact_types = (CONTACT_BATCH_SCHEMA_V1, *sorted(CONTACT_V2_KINDS), *sorted(CONTACT_V3_KINDS))
    batch_operations = set()
    for table in ('graph_atoms', 'graph_history'):
        if business.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            raise AuthorityUnavailable('C09 V5 complete actual Graph inventory is absent')
        if table == 'graph_atoms':
            rows = business.execute('SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name IN (?,?,?,?,?,?,?) LIMIT ?',
                (*port.namespace_id.as_tuple, *contact_types, MAX_CONTACT_FINISHES+1)).fetchall()
            tokens = tuple(row[0] for row in rows)
            history = []
            for token in tokens:
                chunk = business.execute('SELECT event_id FROM graph_history WHERE token=? ORDER BY revision LIMIT ?',
                    (token, MAX_CONTACT_FINISHES - len(history) + 1)).fetchall()
                history.extend(chunk)
                if len(history) > MAX_CONTACT_FINISHES:
                    raise AuthorityUnavailable('C09 V5 complete actual batch history exceeds bound; HOLD')
        else:
            rows = business.execute('SELECT token,event_id FROM graph_history WHERE event_bot=? AND event_persona=? '
                "AND json_extract(token,'$[4]') IN (?,?,?,?,?,?,?) ORDER BY token,revision LIMIT ?",
                (*port.namespace_id.as_tuple, *contact_types, MAX_CONTACT_FINISHES+1)).fetchall()
            history = [row[1:] for row in rows]
        if len(history) > MAX_CONTACT_FINISHES or len(rows) > MAX_CONTACT_FINISHES and table == 'graph_atoms':
            raise AuthorityUnavailable('C09 V5 complete actual batch history exceeds bound; HOLD')
        batch_operations.update(row[0] for row in history)
    if not batch_operations <= {o.business_operation_id for o in originals}:
        raise AuthorityUnavailable('C09 V5 historical/current batch lacks its complete authenticated finished original; HOLD')
    durable = _durable_contact_batch_operations_v5(business, port.namespace_id)
    _require_durable_contact_finishes_v5(durable, originals)
    members = []
    for original in originals:
        if original.operation_id == operation_id:
            if original not in active: raise AuthorityUnavailable('C09 V5 new archive is not this authenticated current business original')
            carry = None
        else:
            carry = _authenticate_contact_finish_carry_v5(core_db, port=port, original=original)
        members.append(ContactFinishInventoryMemberV5(original, carry))
    if not set(active) <= set(originals):
        raise AuthorityUnavailable('C09 V5 actual current finished originals are omitted from Core archive')
    body = dict(authority_id=seal.authority_id, installation_id=seal.installation_id, namespace=namespace,
        operation_id=operation_id, source_seal_digest=seal.seal_digest, observed_core_anchor=anchor,
        verifier_commitment=verifier, business_namespace_digest=canonical_digest(port.namespace_id),
        members=tuple(sorted(members, key=lambda member:member.locator)), schema=INVENTORY_SCHEMA)
    digest = canonical_digest(tuple(body[field.name] for field in fields(ContactFinishInventoryV5) if field.name != 'inventory_digest'))
    inventory = ContactFinishInventoryV5(**body, inventory_digest=digest)
    _ISSUED_INVENTORIES[id(inventory)] = inventory
    port._contact_finish_inventory_v5 = inventory
    return inventory


def _durable_contact_batch_operations_v5(db, namespace):
    """Read the real typed event/bundle commitments even if all bodies vanish."""
    from ..domains.d09.contact_batch_v1 import CONTACT_BATCH_SCHEMA_V1
    from ..domains.d09.contact_batch_v2 import KINDS as CONTACT_V2_KINDS
    from ..domains.d09.contact_batch_v3 import KINDS as CONTACT_V3_KINDS
    contact_types = (CONTACT_BATCH_SCHEMA_V1, *sorted(CONTACT_V2_KINDS), *sorted(CONTACT_V3_KINDS))
    type_parameters = ','.join('?' for _ in contact_types)
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise AuthorityUnavailable('C09 V5 durable inventory needs actual namespace SQL snapshot')
    operations = set()
    for table, column, operation_column in (('graph_events', 'revisions', 'event_id'),
            ('graph_bundle_operations', 'receipt_json', 'operation_id')):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            raise AuthorityUnavailable('C09 V5 complete durable business inventory table is missing')
        # The actual bundle ledger stores ledger_refs/outbox_refs plus closed
        # operation-specific members, not a universal write_versions field.
        # Inspect typed token leaves throughout that durable receipt. The
        # separate event revisions authenticate positive write versions.
        try:
            rows = db.execute(f'SELECT {operation_column},{column} FROM {table} WHERE bot=? AND persona=? '
                f"AND EXISTS(SELECT 1 FROM json_tree({column}) AS leaf WHERE leaf.type='text' "
                f"AND CASE WHEN json_valid(leaf.atom) THEN json_extract(leaf.atom,'$[4]') END IN ({type_parameters})) "
                f'ORDER BY {operation_column} LIMIT ?',
                (*namespace.as_tuple,*contact_types,MAX_CONTACT_FINISHES+1)).fetchall()
        except sqlite3.DatabaseError as exc:
            raise AuthorityUnavailable('C09 V5 durable business JSON inventory is malformed; HOLD') from exc
        if len(rows)>MAX_CONTACT_FINISHES:
            raise AuthorityUnavailable('C09 V5 complete durable Contact receipt inventory exceeds bound; HOLD')
        for operation,encoded in rows:
            raw=json.loads(encoded)
            if table == 'graph_events':
                if type(raw) is not list:
                    raise AuthorityUnavailable('C09 V5 durable event write inventory shape differs')
                for pair in raw:
                    if type(pair) is not list or len(pair)!=2:
                        raise AuthorityUnavailable('C09 V5 durable event write pair differs')
                    ref,revision=pair
                    key=AtomKey.from_token(ref)
                    if NamespaceId.from_key(key)!=namespace or type(revision) is not int or revision<1:
                        raise AuthorityUnavailable('C09 V5 durable typed write crosses namespace or changes revision')
                    if key.type_name in contact_types:operations.add(operation)
            else:
                if type(raw) is not dict:
                    raise AuthorityUnavailable('C09 V5 durable bundle receipt shape differs')
                leaves=db.execute("SELECT atom FROM json_tree(?) WHERE type='text' "
                    f"AND CASE WHEN json_valid(atom) THEN json_extract(atom,'$[4]') END IN ({type_parameters}) LIMIT ?",
                    (encoded,*contact_types,MAX_CONTACT_FINISHES+1)).fetchall()
                if len(leaves)>MAX_CONTACT_FINISHES:
                    raise AuthorityUnavailable('C09 V5 complete durable receipt token inventory exceeds bound; HOLD')
                for (ref,) in leaves:
                    key=AtomKey.from_token(ref)
                    if NamespaceId.from_key(key)!=namespace:
                        raise AuthorityUnavailable('C09 V5 durable bundle token crosses namespace')
                    operations.add(operation)
    return operations


def _require_durable_contact_finishes_v5(operations, originals):
    if not operations <= {o.business_operation_id for o in originals}:
        raise AuthorityUnavailable('C09 V5 durable batch receipt lacks its complete authenticated finished original; HOLD')


def _authenticate_contact_finish_carry_v5(db, *, port, original):
    """Reauthenticate stable old original without rewriting its observation."""
    from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
    # This resolver owns the actual authenticated selected-Core/control chain;
    # no ordinary supplied frame or business status can issue a carry.
    context, frames = InstalledSanitizedRecoveryResolverV4(storage_reader=port._contact_control).read_verified_frames_v4()
    from pathlib import Path
    selected = next(item for item in context.manifest['members'] if item['role'] == 'core')
    if Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve() != Path(selected['resolved_path']).resolve():
        raise AuthorityUnavailable('C09 V5 carry actual selected Core differs')
    found = None
    for prepared, facts, _bindings in frames:
        if type(facts) is not C09RecoveryFactFrameV5: continue
        matches = tuple(member for member in facts.contact_finish_inventory.members if member.original == original)
        if len(matches) == 1:
            from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked
            pin = read_execution_recovery_facts_pin_v4_locked(db, facts.namespace, operation_id=facts.operation_id)
            found = ContactFinishCarryV5(facts.operation_id, facts.facts_digest,
                facts.contact_finish_inventory.inventory_digest, pin.pin_digest, prepared['prepared_digest'], original.fence_row_commitment)
    if found is None: raise AuthorityUnavailable('C09 V5 old finish lacks its complete signed historical inventory; HOLD')
    return found


def verify_contact_finish_inventory_restore_v5(db, *, facts, pin, prepared, verified_prior):
    """Typed SQL joins under the resolver's actual signed PREPARED chain."""
    from .c09_contact_finish_original_v1 import read_contact_finish_originals_v1, verify_contact_finish_recovery_v1
    if type(facts) is not C09RecoveryFactFrameV5 or type(pin) is not C09ExecutionSourcePinV5:
        raise AuthorityUnavailable('C09 V5 restoration requires its exact typed frame and pin')
    inventory = facts.contact_finish_inventory
    if (prepared['facts_digest'] != facts.facts_digest or prepared['facts_pin_original'] != asdict(pin)
            or pin.contact_finish_inventory_digest != inventory.inventory_digest
            or pin.observed_core_anchor != inventory.observed_core_anchor
            or (prepared['namespace'], prepared['operation_id']) != (inventory.namespace, inventory.operation_id)
            or prepared['old_core_anchor_original'] != asdict(inventory.observed_core_anchor)
            or prepared['anchor_transition_original']['before_anchor'] != prepared['old_core_anchor_original']
            or prepared['anchor_transition_original']['after_anchor'] != prepared['new_core_anchor_original']):
        raise AuthorityUnavailable('C09 V5 signed PREPARED complete inventory/actual transition differs')
    for member in inventory.members:
        original = member.original
        saved = read_contact_finish_originals_v1(db, namespace=original.namespace, operation_id=original.operation_id)
        if original not in saved: raise AuthorityUnavailable('C09 V5 complete stable archived finish is missing or changed')
        if member.carry is None:
            verify_contact_finish_recovery_v1(db, original=original, facts=facts, pin=pin, prepared=prepared)
        else:
            carry = member.carry
            prior = tuple((p,f,b) for p,f,b in verified_prior if type(f) is C09RecoveryFactFrameV5
                and f.operation_id == carry.previous_frame_operation_id)
            if len(prior) != 1: raise AuthorityUnavailable('C09 V5 carried finish historical frame missing/ambiguous')
            p, f, _b = prior[0]
            if (f.facts_digest != carry.previous_frame_digest
                    or f.contact_finish_inventory.inventory_digest != carry.previous_inventory_digest
                    or p['facts_pin_original']['pin_digest'] != carry.previous_pin_digest
                    or p['prepared_digest'] != carry.prepared_digest
                    or carry.consumed_fence_commitment != original.fence_row_commitment
                    or original not in tuple(m.original for m in f.contact_finish_inventory.members)):
                raise AuthorityUnavailable('C09 V5 carry replaces or rewrites authenticated historical observation')
            row = db.execute('SELECT original_commitment FROM authority_c09_consumed_execution_v1 '
                "WHERE namespace=? AND kind='fence' AND item_id=?", (original.namespace,original.owner_attempt_id)).fetchone()
            if row != (original.fence_row_commitment,):
                raise AuthorityUnavailable('C09 V5 carried once-only fence commitment changed')
    return inventory
